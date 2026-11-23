#![cfg(feature = "ef_tests")]

use std::{fs, path::Path};

mod ef_common;

use ef_common::{
    LoadedState, compare_states, iter_test_cases, load_state, load_state_gloas, pq_config,
    preset_tests_dir, snappy_decode,
};
use silver_beacon_state::{
    error::ExecutionPayloadBidError,
    ssz_hash::PayloadRoots,
    stf::{self, ShufflingRef},
};
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, Payload, SLOTS_PER_EPOCH, SpecConfig,
    bls::SigBatch, hash_tree_root_block_header,
};
use silver_common::ssz_view::{
    AttestationPqView, BEACON_BLOCK_BODY_FIXED, BeaconBlockBodyFuluView, BeaconBlockBodyPqView,
    PTC_AGGREGATION_BITS_SIZE, SignedExecutionPayloadBidView,
};

fn operations_handler(
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    operations_handler_fork("fulu", handler_name, operation_file, detects_reject, run);
}

/// One integer key of the case's `config.yaml`. The whole file does not load:
/// it writes values wider than any YAML number type.
fn config_u64(dir: &Path, key: &str) -> Option<u64> {
    let yaml = fs::read_to_string(dir.join("config.yaml")).ok()?;
    yaml.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|value| value.trim().parse().ok())
}

fn gloas_cfg() -> silver_beacon_state_data::SpecConfig {
    let mut cfg = SpecConfig::reference();
    cfg.gloas_fork_epoch = 0;
    cfg
}

fn operations_handler_fork(
    fork: &str,
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    operations_handler_cases(fork, handler_name, operation_file, detects_reject, |_, s, op| {
        run(s, op)
    });
}

/// `run` also gets the case directory, for cases whose `config.yaml` departs
/// from `gloas_cfg`.
fn operations_handler_cases(
    fork: &str,
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&Path, &mut LoadedState, &[u8]) -> bool,
) {
    let base = preset_tests_dir().join(fork).join("operations").join(handler_name);
    let loader = if fork == "gloas" { load_state_gloas } else { load_state };
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{handler_name}: no test cases, skipping");
        return;
    }

    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        let op_path = dir.join(format!("{operation_file}.ssz_snappy"));

        if !op_path.exists() {
            skip += 1;
            continue;
        }

        let mut pre = loader(&pre_path);
        let op_ssz = snappy_decode(&op_path);

        if !post_path.exists() {
            if !detects_reject {
                skip += 1;
                continue;
            }
            // Expected-reject case: op must be rejected and pre-state
            // must not be mutated past the rejection point.
            let mut pre_snapshot = loader(&pre_path);
            let accepted = run(dir, &mut pre, &op_ssz);
            if accepted {
                fail += 1;
                eprintln!("{name}: expected reject, but op was accepted");
                continue;
            }
            let diffs = compare_states(name, &mut pre, &mut pre_snapshot);
            if diffs.is_empty() {
                pass += 1;
            } else {
                fail += 1;
                eprintln!("{name}: rejected but pre-state was mutated");
                for d in &diffs {
                    eprintln!("{d}");
                }
            }
            continue;
        }

        let accepted = run(dir, &mut pre, &op_ssz);
        if !accepted {
            fail += 1;
            eprintln!("{name}: expected accept, but op was rejected");
            continue;
        }
        let mut post = loader(&post_path);
        let diffs = compare_states(name, &mut pre, &mut post);
        if diffs.is_empty() {
            pass += 1;
        } else {
            fail += 1;
            for d in &diffs {
                eprintln!("{d}");
            }
        }
    }
    eprintln!("{handler_name}: {pass} passed, {fail} failed, {skip} skipped");
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

fn run_proposer_slashing(s: &mut LoadedState, op: &[u8]) -> bool {
    let mut batch = SigBatch::new();
    let sid = s.state_id;
    {
        let (p, eg, _) = s.view();
        let ev = eg.view_opt(sid.epoch_idx);
        if stf::collect_sigs_proposer_slashings(p.imm, &ev, &p.validators.reader(), op, &mut batch)
            .is_err()
        {
            return false;
        }
    }
    // A Gloas vector's churn follows EIP-8061, which only an active Gloas fork
    // selects.
    let cfg = if s.bs.is_finalized_post_gloas() { gloas_cfg() } else { SpecConfig::reference() };
    if !batch.verify_all() {
        return false;
    }
    s.with_view_and_epoch(|view, e| stf::process_proposer_slashings(view, *e, &cfg, op).is_ok())
}

#[test]
fn fulu_proposer_slashing() {
    operations_handler("proposer_slashing", "proposer_slashing", true, run_proposer_slashing);
}

#[test]
fn gloas_proposer_slashing() {
    operations_handler_fork(
        "gloas",
        "proposer_slashing",
        "proposer_slashing",
        true,
        run_proposer_slashing,
    );
}

#[test]
fn fulu_attester_slashing() {
    operations_handler("attester_slashing", "attester_slashing", true, move |s, op| {
        // The op SSZ here is a single AttesterSlashing; wrap as a List[1].
        let mut list = Vec::with_capacity(4 + op.len());
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        let sid = s.state_id;
        {
            let (p, eg, _) = s.view();
            let ev = eg.view_opt(sid.epoch_idx);
            if stf::collect_sigs_attester_slashings(
                p.imm,
                &ev,
                &p.validators.reader(),
                &list,
                &mut active_scratch,
                &mut batch,
            )
            .is_err()
            {
                return false;
            }
        }
        let cfg = SpecConfig::reference();
        if !batch.verify_all() {
            return false;
        }
        s.with_view_and_epoch(|view, e| {
            stf::process_attester_slashings(view, *e, &cfg, &list, &mut Vec::new(), None).is_ok()
        })
    });
}

fn run_attestation(s: &mut LoadedState, op: &[u8]) -> bool {
    process_attestation(s, op, true)
}

/// A single operation SSZ wrapped as a one-element list.
fn as_list(op: &[u8]) -> Vec<u8> {
    let mut list = Vec::with_capacity(4 + op.len());
    list.extend_from_slice(&4u32.to_le_bytes());
    list.extend_from_slice(op);
    list
}

fn process_attestation(s: &mut LoadedState, op: &[u8], checks_bls: bool) -> bool {
    let list = as_list(op);
    let block_slot = s.slot();
    let curr_epoch = block_slot / SLOTS_PER_EPOCH;

    let proposer_index;
    let mut curr_active = Vec::new();
    let mut prev_active = Vec::new();
    let sref = {
        let sid = s.state_id;
        let (mut v, epoch, longtail) = s.view();
        let rv = v.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
        proposer_index =
            rv.epoch.proposer_at((block_slot % SLOTS_PER_EPOCH) as usize).unwrap() as u32;
        ShufflingRef::build(&rv, curr_epoch, &mut curr_active, &mut prev_active)
    };
    let mut votes_sink = stf::VoteBatch::default();
    let mut scratch = stf::StfScratch::new(0);
    let mut batch = SigBatch::new();
    let sid = s.state_id;
    if checks_bls {
        let (p, eg, _) = s.view();
        let ev = eg.view_opt(sid.epoch_idx);
        if stf::collect_sigs_attestations(
            p.imm,
            &ev,
            &p.validators.reader(),
            &list,
            block_slot,
            &sref,
            &mut batch,
        )
        .is_err() ||
            !batch.verify_all()
        {
            return false;
        }
    }
    // A PQ attestation proves one statement per committee it names.
    let mut stark = (!checks_bls).then(|| {
        let mut claims = stf::StarkClaims::default();
        claims.begin(&list);
        claims
    });
    let processed = s.with_view_and_epoch(|view, e| {
        let parent_slot =
            e.post_gloas_fork(view.imm).then(|| view.slot.state().latest_block_header.slot);
        stf::BlockAttestations::new(view, *e, block_slot, parent_slot, &sref)
            .process_body(
                view,
                &list,
                proposer_index,
                &mut votes_sink,
                &mut scratch.active,
                stark.as_mut(),
            )
            .is_ok()
    });
    if let Some(claims) = stark.filter(|_| processed) {
        let committees: u32 =
            AttestationPqView::committee_bits(op).iter().map(|byte| byte.count_ones()).sum();
        assert_eq!(claims.statement_count(), committees as usize, "one statement per committee");
    }
    processed
}

#[test]
fn fulu_attestation() {
    operations_handler("attestation", "attestation", true, run_attestation);
}

#[test]
fn gloas_attestation() {
    operations_handler_fork("gloas", "attestation", "attestation", true, run_attestation);
}

#[test]
fn fulu_voluntary_exit() {
    operations_handler("voluntary_exit", "voluntary_exit", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let (p, _, _) = s.view();
            stf::collect_sigs_voluntary_exits(p.imm, &p.validators.reader(), op, &mut batch);
        }
        let cfg = SpecConfig::reference();
        if !batch.verify_all() {
            return false;
        }
        s.with_view(|view| stf::process_voluntary_exits(view, &cfg, op).is_ok())
    });
}

#[test]
fn fulu_bls_to_execution_change() {
    operations_handler("bls_to_execution_change", "address_change", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let (p, _, _) = s.view();
            if stf::collect_sigs_bls_to_execution_changes(
                p.imm,
                &p.validators.reader(),
                op,
                &mut batch,
            )
            .is_err()
            {
                return false;
            }
        }
        if !batch.verify_all() {
            return false;
        }
        s.with_view(|p| stf::process_bls_to_execution_changes(&mut p.validators, op).is_ok())
    });
}

#[test]
fn fulu_sync_aggregate() {
    operations_handler("sync_aggregate", "sync_aggregate", true, move |s, op| {
        let block_slot = s.slot();
        let proposer_index;
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        {
            let sid = s.state_id;
            let (mut p, epoch, longtail) = s.view();
            let rv = p.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
            proposer_index =
                rv.epoch.proposer_at((block_slot % SLOTS_PER_EPOCH) as usize).unwrap() as u32;
            stf::collect_sigs_sync_aggregate(&rv, op, block_slot, &mut active_scratch, &mut batch);
        }
        if !batch.verify_all() {
            return false;
        }
        let sid = s.state_id;
        let (mut view, _, longtail) = s.view();
        let longtail_view = longtail.view_opt(sid.longtail_idx);
        let ok = stf::process_sync_aggregate(&mut view, longtail_view, op, proposer_index).is_ok();
        s.state_id = view.commit(sid.epoch_idx, sid.longtail_idx);
        ok
    });
}

#[test]
fn fulu_deposit_request() {
    operations_handler("deposit_request", "deposit_request", false, |s, op| {
        s.with_view(|view| stf::process_deposit_requests(view, op));
        true
    });
}

#[test]
fn fulu_withdrawal_request() {
    let cfg = SpecConfig::reference();
    operations_handler("withdrawal_request", "withdrawal_request", false, move |s, op| {
        s.with_view(|view| stf::process_withdrawal_requests(view, &cfg, op));
        true
    });
}

#[test]
fn fulu_consolidation_request() {
    let cfg = SpecConfig::reference();
    operations_handler("consolidation_request", "consolidation_request", false, move |s, op| {
        s.with_view(|view| stf::process_consolidation_requests(view, &cfg, op));
        true
    });
}

#[test]
fn fulu_withdrawals() {
    operations_handler("withdrawals", "execution_payload", true, |s, op| {
        s.with_view(|view| {
            Payload::new(op)
                .is_ok_and(|payload| stf::process_withdrawals_fulu(view, payload).is_ok())
        })
    });
}

#[test]
fn fulu_execution_payload() {
    let cfg = SpecConfig::reference();
    operations_handler("execution_payload", "body", false, move |s, op| {
        if op.len() < BEACON_BLOCK_BODY_FIXED {
            return true;
        }
        let exec_off = BeaconBlockBodyFuluView::execution_payload_offset(op) as usize;
        let bls_off = BeaconBlockBodyFuluView::bls_to_execution_changes_offset(op) as usize;
        let commitments = BeaconBlockBodyFuluView::blob_kzg_commitments(op).unwrap_or_default();
        if exec_off < bls_off &&
            bls_off <= op.len() &&
            let Ok(payload) = Payload::new(&op[exec_off..bls_off])
        {
            let block_slot = s.slot();
            s.with_view(|view| {
                let roots = PayloadRoots::of(payload);
                let _ = stf::process_execution_payload(
                    view,
                    &cfg,
                    payload,
                    commitments,
                    block_slot,
                    roots,
                );
            });
        }
        true
    });
}

/// Since Capella the parent-hash assert holds even when the latest header
/// is the empty pre-merge one (`block_number == 0`).
#[test]
fn fulu_first_payload_with_bad_parent_hash_is_rejected() {
    let dir = preset_tests_dir().join(
        "fulu/operations/execution_payload/pyspec_tests/invalid_bad_parent_hash_first_payload",
    );
    if !dir.exists() {
        eprintln!("fulu_first_payload_with_bad_parent_hash_is_rejected: no vector, skipping");
        return;
    }
    let cfg = SpecConfig::reference();
    let mut s = load_state(&dir.join("pre.ssz_snappy"));
    let body = snappy_decode(&dir.join("body.ssz_snappy"));
    let payload = Payload::new(
        &body[BeaconBlockBodyFuluView::execution_payload_offset(&body) as usize..
            BeaconBlockBodyFuluView::bls_to_execution_changes_offset(&body) as usize],
    )
    .unwrap();
    let commitments = BeaconBlockBodyFuluView::blob_kzg_commitments(&body).unwrap();
    let block_slot = s.slot();
    let result = s.with_view(|view| {
        stf::process_execution_payload(
            view,
            &cfg,
            payload,
            commitments,
            block_slot,
            PayloadRoots::of(payload),
        )
    });
    assert!(result.is_err());
}

#[test]
fn gloas_builder_deposit_request() {
    operations_handler_fork(
        "gloas",
        "builder_deposit_request",
        "builder_deposit_request",
        false,
        run_builder_deposit_request,
    );
}

fn run_builder_deposit_request(s: &mut LoadedState, op: &[u8]) -> bool {
    let cfg = gloas_cfg();
    s.with_view(|view| stf::process_builder_deposit_request(view, &cfg, op));
    true
}

#[test]
fn gloas_builder_exit_request() {
    operations_handler_fork(
        "gloas",
        "builder_exit_request",
        "builder_exit_request",
        false,
        run_builder_exit_request,
    );
}

fn run_builder_exit_request(s: &mut LoadedState, op: &[u8]) -> bool {
    let sid = s.state_id;
    let finalized_epoch = {
        let (_, epoch, _) = s.view();
        epoch.view_opt(sid.epoch_idx).state().finalized_checkpoint.epoch
    };
    let cfg = gloas_cfg();
    s.with_view(|view| stf::process_builder_exit_request(view, &cfg, finalized_epoch, op));
    true
}

#[test]
fn gloas_execution_payload_bid() {
    let cfg = SpecConfig::reference();
    operations_handler_fork(
        "gloas",
        "execution_payload_bid",
        "execution_payload_bid",
        true,
        move |s, op| {
            let current_epoch = s.slot() / SLOTS_PER_EPOCH;
            let mut batch = SigBatch::new();
            let sid = s.state_id;
            let batch_ok = {
                let (p, eg, _) = s.view();
                let ev = eg.view_opt(sid.epoch_idx);
                let builders = p.builders.reader();
                if stf::collect_sigs_execution_payload_bid(
                    p.imm,
                    &ev,
                    &builders,
                    op,
                    current_epoch,
                    &mut batch,
                )
                .is_err()
                {
                    return false;
                }
                let batch_ok = batch.verify_all();
                // The gossip path verifies the same bid singly; it must agree.
                let bid = stf::decode_bid(op).unwrap();
                let signature = SignedExecutionPayloadBidView::signature(op);
                match stf::verify_execution_payload_bid_signature(
                    p.imm, &ev, &builders, &bid, signature,
                ) {
                    Err(ExecutionPayloadBidError::SelfBuildUnsigned) => {}
                    single => {
                        assert_eq!(single.is_ok(), batch_ok, "single and batch bid verify disagree")
                    }
                }
                batch_ok
            };
            if !batch_ok {
                return false;
            }
            s.with_view_and_epoch(|view, e| {
                stf::process_execution_payload_bid(view, e, &cfg, op).is_ok()
            })
        },
    );
}

#[test]
fn gloas_withdrawals() {
    withdrawals_fork("gloas", load_state_gloas);
}

/// Post-Gloas `process_withdrawals` takes no payload; the EF case carries only
/// pre/post, so this runs like an epoch handler.
fn withdrawals_fork(fork: &str, loader: fn(&Path) -> LoadedState) {
    let base = preset_tests_dir().join(format!("{fork}/operations/withdrawals"));
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{fork} withdrawals: no test cases, skipping");
        return;
    }
    let mut fail = 0;
    for (name, dir) in &cases {
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }
        let mut pre = loader(&dir.join("pre.ssz_snappy"));
        pre.with_view(|view| stf::process_withdrawals_gloas(view));
        let mut post = loader(&post_path);
        let diffs = compare_states(name, &mut pre, &mut post);
        if !diffs.is_empty() {
            fail += 1;
            for d in &diffs {
                eprintln!("{d}");
            }
        }
    }
    assert_eq!(fail, 0, "{fork} withdrawals: {fail} test(s) failed");
}

#[test]
fn gloas_parent_execution_payload() {
    let cfg = gloas_cfg();
    operations_handler_fork("gloas", "parent_execution_payload", "block", true, move |s, op| {
        process_parent_execution_payload(&cfg, s, op)
    });
}

/// `op` is a BeaconBlock: the body offset sits at [80..84).
fn process_parent_execution_payload(cfg: &SpecConfig, s: &mut LoadedState, op: &[u8]) -> bool {
    if op.len() < 84 {
        return false;
    }
    let body_off = u32::from_le_bytes(op[80..84].try_into().unwrap()) as usize;
    if body_off > op.len() {
        return false;
    }
    let body = &op[body_off..];
    s.with_view_and_epoch(|view, e| {
        let fork = if e.is_pq(view.imm) { BodyFork::Pq } else { BodyFork::Gloas };
        let Ok(body) = BodyOffsets::validated(body, fork) else { return false };
        let parent_slot = view.slot.state().latest_block_header.slot;
        stf::process_parent_execution_payload(view, e, cfg, &body, parent_slot).is_ok()
    })
}

#[test]
fn gloas_payload_attestation() {
    operations_handler_cases(
        "gloas",
        "payload_attestation",
        "payload_attestation",
        true,
        |dir, s, op| {
            let gloas_fork_epoch = config_u64(dir, "GLOAS_FORK_EPOCH").unwrap_or(0);
            let state_slot = s.slot();
            let mut batch = SigBatch::new();
            {
                let sid = s.state_id;
                let (p, epoch, _) = s.view();
                let epoch_view = epoch.view_opt(sid.epoch_idx);
                if stf::collect_sigs_payload_attestations(
                    p.imm,
                    &p.validators.reader(),
                    &epoch_view,
                    gloas_fork_epoch,
                    state_slot,
                    op,
                    &mut batch,
                )
                .is_err()
                {
                    return false;
                }
            }
            if !batch.verify_all() {
                return false;
            }
            // Validation only — no state mutation, so no commit.
            let (p, _, _) = s.view();
            stf::process_payload_attestations(&p, op).is_ok()
        },
    );
}

/// The attestation slot is block input; `u64::MAX` must reject rather than
/// overflow `slot + 1` (a panic under overflow checks).
#[test]
fn gloas_payload_attestation_rejects_max_slot() {
    let dir = preset_tests_dir().join("gloas/operations/payload_attestation/pyspec_tests/process_payload_attestation_payload_present");
    if !dir.exists() {
        eprintln!("gloas_payload_attestation_rejects_max_slot: no vector, skipping");
        return;
    }
    let mut s = load_state_gloas(&dir.join("pre.ssz_snappy"));
    let mut op = snappy_decode(&dir.join("payload_attestation.ssz_snappy"));
    let slot_at = PTC_AGGREGATION_BITS_SIZE + 32;
    op[slot_at..slot_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let (p, _, _) = s.view();
    assert!(stf::process_payload_attestations(&p, &op).is_err());
}

#[test]
fn fulu_block_header() {
    operations_handler("block_header", "block", true, |s, op| {
        process_block_header(s, op, silver_beacon_state::ssz_hash::hash_tree_root_body_fulu)
    });
}

/// `op` is a BeaconBlock SSZ: slot(8) + proposer_index(8) + parent_root(32) +
/// state_root(32) + body_offset(4) + body(...).
fn process_block_header(s: &mut LoadedState, op: &[u8], body_root: fn(&[u8]) -> B256) -> bool {
    if op.len() < 84 {
        return false;
    }
    let slot = u64::from_le_bytes(op[0..8].try_into().unwrap());
    let proposer_index = u64::from_le_bytes(op[8..16].try_into().unwrap());
    let parent_root = op[16..48].try_into().unwrap();
    let body_off = u32::from_le_bytes(op[80..84].try_into().unwrap()) as usize;
    let body = if body_off <= op.len() { &op[body_off..] } else { &[] };
    let header = BeaconBlockHeader {
        slot,
        proposer_index,
        parent_root,
        state_root: [0; 32],
        body_root: body_root(body),
    };
    let block_root = hash_tree_root_block_header(&header);
    s.with_view_and_epoch(|view, e| stf::process_block_header(view, e, &header, block_root).is_ok())
}

/// PQ vectors stub XMSS, since an XMSS key takes minutes to generate: every
/// signature and STARK proof verifies, so these run without signature checks.
fn pq_handler(
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    operations_handler_fork("pq", handler_name, operation_file, detects_reject, run);
}

#[test]
fn pq_attestation() {
    pq_handler("attestation", "attestation", true, |s, op| process_attestation(s, op, false));
}

#[test]
fn pq_attester_slashing() {
    let cfg = pq_config();
    pq_handler("attester_slashing", "attester_slashing", true, move |s, op| {
        let list = as_list(op);
        let mut claims = stf::StarkClaims::default();
        claims.begin(&list);
        let processed = s.with_view_and_epoch(|view, e| {
            stf::process_attester_slashings(
                view,
                *e,
                &cfg,
                &list,
                &mut Vec::new(),
                Some(&mut claims),
            )
            .is_ok()
        });
        if processed {
            assert_eq!(claims.statement_count(), 2, "one statement per slashed attestation");
        }
        processed
    });
}

#[test]
fn pq_block_header() {
    pq_handler("block_header", "block", true, |s, op| {
        process_block_header(s, op, BeaconBlockBodyPqView::hash_tree_root)
    });
}

#[test]
fn pq_builder_deposit_request() {
    pq_handler(
        "builder_deposit_request",
        "builder_deposit_request",
        false,
        run_builder_deposit_request,
    );
}

#[test]
fn pq_builder_exit_request() {
    pq_handler("builder_exit_request", "builder_exit_request", false, run_builder_exit_request);
}

#[test]
fn pq_consolidation_request() {
    let cfg = pq_config();
    pq_handler("consolidation_request", "consolidation_request", false, move |s, op| {
        s.with_view(|view| stf::process_consolidation_requests(view, &cfg, op));
        true
    });
}

#[test]
fn pq_deposit_request() {
    pq_handler("deposit_request", "deposit_request", false, |s, op| {
        s.with_view(|view| stf::process_deposit_requests(view, op));
        true
    });
}

#[test]
fn pq_execution_payload_bid() {
    let cfg = pq_config();
    pq_handler("execution_payload_bid", "execution_payload_bid", true, move |s, op| {
        s.with_view_and_epoch(|view, e| {
            stf::process_execution_payload_bid(view, e, &cfg, op).is_ok()
        })
    });
}

#[test]
fn pq_parent_execution_payload() {
    let cfg = pq_config();
    pq_handler("parent_execution_payload", "block", true, move |s, op| {
        process_parent_execution_payload(&cfg, s, op)
    });
}

#[test]
fn pq_proposer_slashing() {
    let cfg = pq_config();
    pq_handler("proposer_slashing", "proposer_slashing", true, move |s, op| {
        s.with_view_and_epoch(|view, e| stf::process_proposer_slashings(view, *e, &cfg, op).is_ok())
    });
}

#[test]
fn pq_randao() {
    pq_handler("randao", "body", true, |s, body| {
        let slot = s.slot();
        s.with_view_and_epoch(|view, e| {
            let proposer_index = e.proposer_at((slot % SLOTS_PER_EPOCH) as usize).unwrap() as u32;
            stf::process_randao_pq(view, body, proposer_index, slot).is_ok()
        })
    });
}

#[test]
fn pq_validator_preregistration_request() {
    pq_handler(
        "validator_preregistration_request",
        "validator_preregistration_request",
        false,
        |s, op| {
            s.with_view(|view| stf::process_validator_preregistration_requests(view, op));
            true
        },
    );
}

#[test]
fn pq_builder_preregistration_request() {
    pq_handler(
        "builder_preregistration_request",
        "builder_preregistration_request",
        false,
        |s, op| {
            s.with_view(|view| stf::process_builder_preregistration_requests(view, op));
            true
        },
    );
}

#[test]
fn pq_voluntary_exit_request() {
    let cfg = pq_config();
    pq_handler("voluntary_exit_request", "voluntary_exit_request", false, move |s, op| {
        s.with_view(|view| stf::process_voluntary_exit_requests(view, &cfg, op));
        true
    });
}

#[test]
fn pq_withdrawal_request() {
    let cfg = pq_config();
    pq_handler("withdrawal_request", "withdrawal_request", false, move |s, op| {
        s.with_view(|view| stf::process_withdrawal_requests(view, &cfg, op));
        true
    });
}

#[test]
fn pq_withdrawals() {
    withdrawals_fork("pq", load_state);
}
