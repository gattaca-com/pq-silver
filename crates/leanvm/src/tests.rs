//! The tile on the spine. The real-prover tests are ignored: they start
//! leanVM's pool on the cores in `LEANVM_TEST_CORES` (e.g. `0,1,2,3`), pin
//! the test thread to the first, and prove for a while.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use lean_vm::{
    AggregateClaims, AggregateProof,
    lean_xmss::{self, LeanXmssPublicKey, LeanXmssSignature},
};
use silver_common::{
    LeanVmReady, LeanVmReq, LeanVmResp, RefusalCode, SilverSpine, TCache, TCacheId, TCacheProducer,
    TCacheRead, TCacheReader, TCacheTable, TProducer, TReadMode,
    leanvm::{
        MAX_PROOFS, MAX_SIGNATURES, ProofBody, ProofLen, RequestBody, SIGNED_CLAIM_SIZE,
        SignedClaim,
    },
    test_util::ShmemDir,
};

use super::{LeanVmTile, MAX_QUEUED_AGGREGATES, Prover, decode_claim, read_request};

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

struct Rig {
    _base: ShmemDir,
    _spine: Box<SilverSpine>,
    tile: LeanVmTile,
    adapter: SpineAdapter<SilverSpine>,
    injector: SpineAdapter<SilverSpine>,
    handoff: TProducer,
    responses: TCacheReader,
    answers: Vec<(u64, Answer)>,
    ready_events: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Proven(ProofLen, Vec<u8>),
    Refused(RefusalCode),
    NoAnswer,
}

impl Rig {
    fn new(cores: Vec<usize>) -> Self {
        let base = ShmemDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
        let handoff = TCache::producer(TCacheId::BeaconStateHandoff, 1 << 24);
        let out = TCache::producer(TCacheId::LeanVmProcessing, 1 << 24);
        let out_ref = out.cache_ref();
        let tcaches = TCacheTable::from_iter([handoff.cache_ref(), out_ref]);
        let mut tile = LeanVmTile::new(cores, tcaches, out);
        let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
        tile.on_attach(&mut adapter);
        let mut injector = SpineAdapter::connect_tile(&Injector, &mut *spine);
        injector.consume(|_: LeanVmResp, _| {});
        injector.consume(|_: LeanVmReady, _| {});
        assert!(tile.try_init(&mut adapter));
        let responses = TCacheReader::single(out_ref, "test", TReadMode::Sliding).unwrap();
        Self {
            _base: base,
            _spine: spine,
            tile,
            adapter,
            injector,
            handoff,
            responses,
            answers: Vec::new(),
            ready_events: 0,
        }
    }

    fn warm_without_proving() -> Self {
        let mut rig = Self::new(Vec::new());
        rig.tile.prover = Prover::Warm;
        rig
    }

    fn crank(&mut self) {
        self.tile.loop_body(&mut self.adapter);
        self.read_answers();
    }

    fn read_answers(&mut self) {
        let Self { injector, responses, answers, ready_events, .. } = self;
        injector.consume(|resp: LeanVmResp, _| {
            let answer = match resp {
                LeanVmResp::Proven { claims, proof, body, .. } => {
                    let acquired = responses.acquire(body);
                    Answer::Proven(
                        ProofLen { claims, proof },
                        acquired.buffer().unwrap().0.to_vec(),
                    )
                }
                LeanVmResp::Refused { reason, .. } => Answer::Refused(reason),
                LeanVmResp::NoAnswer { .. } => Answer::NoAnswer,
            };
            answers.push((resp.request_id(), answer));
        });
        injector.consume(|_: LeanVmReady, _| *ready_events += 1);
    }

    fn prepare(
        &mut self,
        request_id: u64,
        signatures: &[SignedClaim],
        proofs: &[(ProofLen, &[u8])],
    ) -> LeanVmReq {
        let mut children = [ProofLen::default(); MAX_PROOFS];
        for (next, &(len, _)) in children.iter_mut().zip(proofs) {
            *next = len;
        }
        let bytes =
            size_of_val(signatures) + proofs.iter().map(|(len, _)| len.bytes()).sum::<usize>();
        let body = self
            .handoff
            .write_with(bytes, |out| {
                RequestBody::write(out, signatures, proofs.iter().map(|&(_, bytes)| bytes));
            })
            .unwrap();
        self.handoff.loop_start();
        LeanVmReq {
            request_id,
            signatures: signatures.len() as u16,
            proofs: proofs.len() as u8,
            children,
            body,
        }
    }

    fn lap(&mut self, read: TCacheRead) {
        for _ in 0..5 {
            self.handoff.write_with(1 << 22, |out| out.fill(0)).unwrap();
            self.handoff.loop_start();
            // The reader takes the producer's floor snapshot, then applies it on the next
            // pass.
            self.crank();
            self.crank();
        }
        assert!(self.handoff.read_buffer(read).is_err());
    }

    fn answer(&mut self, request_id: u64) -> Answer {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if let Some(index) = self.answers.iter().position(|(id, _)| *id == request_id) {
                return self.answers.swap_remove(index).1;
            }
            assert!(Instant::now() < deadline, "no answer to {request_id}");
            self.crank();
        }
    }
}

#[test]
fn without_a_prover_every_request_is_answered_none() {
    let mut rig = Rig::new(Vec::new());
    for request_id in [1, 2] {
        let request = rig.prepare(request_id, &[[0; SIGNED_CLAIM_SIZE]], &[]);
        rig.injector.produce(request);
    }
    assert_eq!(rig.answer(1), Answer::NoAnswer);
    assert_eq!(rig.answer(2), Answer::NoAnswer);
    assert_eq!(rig.ready_events, 0);
}

#[test]
fn signatures_of_a_request_reach_lean_vm_unchanged() {
    let (secret, key) = lean_xmss::key_gen(&[7; lean_xmss::SECRET_KEY_LEN]);
    let message = [8; lean_xmss::MESSAGE_LEN];
    secret.prepare(7);
    let signature = lean_xmss::sign(&secret, &message, 7);
    let mut rig = Rig::new(Vec::new());
    let request = rig.prepare(1, &[signed_claim(key, message, &signature)], &[]);
    let decoded = read_request(&mut rig.tile.reader, request).unwrap();

    assert!(decoded.children.is_empty());
    let [(decoded_key, decoded_message, decoded_signature)] = decoded.signatures.as_slice() else {
        panic!("expected one signature");
    };
    assert_eq!((*decoded_key, *decoded_message), (key, message));
    assert_eq!(decoded_signature.to_bytes(), signature.to_bytes());
}

#[test]
fn a_child_that_is_no_proof_is_refused() {
    let len = ProofLen { claims: 1, proof: 1 };
    let mut child = vec![0; len.bytes()];
    ProofBody::write(&mut child, [[7; 64]].into_iter(), b"p");
    let mut rig = Rig::warm_without_proving();
    let request = rig.prepare(1, &[], &[(len, &child)]);
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::Refused(RefusalCode::InvalidChild));
}

#[test]
fn a_forged_count_is_refused_without_reading_the_body() {
    let mut rig = Rig::warm_without_proving();
    let mut request = rig.prepare(1, &[[0; SIGNED_CLAIM_SIZE]], &[]);
    rig.lap(request.body);
    request.proofs = MAX_PROOFS as u8 + 1;
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::Refused(RefusalCode::Malformed));

    let request = LeanVmReq { request_id: 2, signatures: 0, proofs: 0, ..request };
    rig.injector.produce(request);
    assert_eq!(rig.answer(2), Answer::Refused(RefusalCode::InvalidInput));
}

#[test]
fn a_truncated_request_is_refused() {
    let len = ProofLen { claims: 1, proof: 1 };
    let mut child = vec![0; len.bytes()];
    ProofBody::write(&mut child, [[7; 64]].into_iter(), b"p");
    let mut rig = Rig::warm_without_proving();
    let mut request = rig.prepare(1, &[], &[(len, &child)]);
    request.children[0].proof += 1;
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::Refused(RefusalCode::Malformed));
}

#[test]
fn unsorted_child_claims_are_refused() {
    let len = ProofLen { claims: 2, proof: 1 };
    let mut child = vec![0; len.bytes()];
    ProofBody::write(&mut child, [[2; 64], [1; 64]].into_iter(), b"p");
    let mut rig = Rig::warm_without_proving();
    let request = rig.prepare(1, &[], &[(len, &child)]);
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::Refused(RefusalCode::Malformed));
}

#[test]
fn lapped_and_unopened_requests_get_no_answer() {
    let mut rig = Rig::warm_without_proving();
    let request = rig.prepare(1, &[[0; SIGNED_CLAIM_SIZE]], &[]);
    rig.lap(request.body);
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::NoAnswer);

    let body = rig.tile.producer.write_with(SIGNED_CLAIM_SIZE, |out| out.fill(0)).unwrap();
    rig.injector.produce(LeanVmReq { request_id: 2, body, ..request });
    assert_eq!(rig.answer(2), Answer::NoAnswer);
}

#[test]
fn a_request_past_the_queue_cap_gets_no_answer() {
    let mut rig = Rig::warm_without_proving();
    let extra = MAX_QUEUED_AGGREGATES as u64 + 1;
    for request_id in 1..=extra {
        let request = rig.prepare(request_id, &[[0; SIGNED_CLAIM_SIZE]], &[]);
        rig.injector.produce(request);
    }
    rig.tile.intake(&mut rig.adapter);
    rig.tile.publish(&mut rig.adapter);
    rig.read_answers();
    assert_eq!(rig.answers, [(extra, Answer::NoAnswer)]);
}

#[test]
fn a_refusal_needs_no_response_tcache() {
    let mut rig = Rig::warm_without_proving();
    let capacity = rig.tile.producer.cache_ref().max_payload_len();
    let _held = rig.tile.producer.reserve(capacity, false).unwrap();
    assert!(rig.tile.producer.reserve(1, false).is_none());

    let mut request = rig.prepare(1, &[[0; SIGNED_CLAIM_SIZE]], &[]);
    request.signatures = MAX_SIGNATURES as u16 + 1;
    rig.injector.produce(request);
    assert_eq!(rig.answer(1), Answer::Refused(RefusalCode::Malformed));
}

#[test]
fn the_response_body_carries_only_claims_and_proof() {
    let mut rig = Rig::new(Vec::new());
    let key = lean_xmss::LeanXmssPublicKey::from_bytes(&[1; lean_xmss::PUB_KEY_SIZE]);
    let claims = AggregateClaims {
        lean_xmss: vec![(key, [2; lean_xmss::MESSAGE_LEN])],
        ..AggregateClaims::default()
    };
    let LeanVmResp::Proven { request_id: 7, claims, proof, body } =
        rig.tile.write_proven(7, &claims, b"proof")
    else {
        panic!("expected a proven response");
    };
    let acquired = rig.responses.acquire(body);
    let (bytes, _) = acquired.buffer().unwrap();
    let split = ProofLen { claims, proof }.split(bytes).unwrap();
    assert_eq!(split.claims().as_flattened(), [&[1; 32][..], &[2; 32]].concat());
    assert_eq!(split.proof(), b"proof");
}

#[test]
fn output_outside_the_response_format_is_refused() {
    use lean_vm::lean_sphincs::LeanSphincsPublicKey;
    use silver_common::leanvm::{MAX_PROOF_CLAIMS, MAX_STARK_PROOF_SIZE};

    let mut rig = Rig::new(Vec::new());
    let mut claims = AggregateClaims { da_commitment: Some([1; 32]), ..AggregateClaims::default() };
    let refused = |response| {
        assert!(matches!(response, LeanVmResp::Refused {
            request_id: 7,
            reason: RefusalCode::ProvingFailed
        }));
    };
    refused(rig.tile.write_proven(7, &claims, b"proof"));
    claims.da_commitment = None;
    claims.lean_sphincs.push((LeanSphincsPublicKey::from_bytes(&[1; 32]), [2; 32]));
    refused(rig.tile.write_proven(7, &claims, b"proof"));
    claims.lean_sphincs.clear();

    let key = lean_xmss::LeanXmssPublicKey::from_bytes(&[1; lean_xmss::PUB_KEY_SIZE]);
    claims.lean_xmss = vec![(key, [2; 32]); MAX_PROOF_CLAIMS + 1];
    refused(rig.tile.write_proven(7, &claims, b"proof"));
    claims.lean_xmss.truncate(1);
    refused(rig.tile.write_proven(7, &claims, &vec![0; MAX_STARK_PROOF_SIZE + 1]));
}

/// Whatever the machine, one CPU per physical core, none below `first`.
#[test]
fn physical_cores_take_one_thread_per_core_from_first_on() {
    let all = super::physical_cores(0);
    assert!(!all.is_empty());
    let allowed = flux::core_affinity::get_core_ids().unwrap();
    let physical: HashSet<_> = allowed.iter().map(|core| super::first_sibling(core.id)).collect();
    assert_eq!(all.len(), physical.len());
    let from_two = super::physical_cores(2);
    let expected: Vec<_> = all.into_iter().filter(|&cpu| super::first_sibling(cpu) >= 2).collect();
    assert_eq!(from_two, expected);
}

fn test_cores() -> Vec<usize> {
    let cores = std::env::var("LEANVM_TEST_CORES").expect("LEANVM_TEST_CORES, e.g. 0,1,2,3");
    cores.split(',').map(|core| core.trim().parse().unwrap()).collect()
}

/// An `aggregate` response's claims and proof.
fn proof_parts(len: ProofLen, bytes: &[u8]) -> (AggregateClaims, &[u8]) {
    let body = len.split(bytes).unwrap();
    let lean_xmss = body.claims().iter().map(decode_claim).collect();
    (AggregateClaims { lean_xmss, ..AggregateClaims::default() }, body.proof())
}

fn signed_claim(
    key: LeanXmssPublicKey,
    message: lean_xmss::Message,
    signature: &LeanXmssSignature,
) -> SignedClaim {
    let mut record = [0; SIGNED_CLAIM_SIZE];
    let (key_bytes, rest) = record.split_at_mut(lean_xmss::PUB_KEY_SIZE);
    let (message_bytes, signature_bytes) = rest.split_at_mut(lean_xmss::MESSAGE_LEN);
    key_bytes.copy_from_slice(&key.to_bytes());
    message_bytes.copy_from_slice(&message);
    signature_bytes.copy_from_slice(&signature.to_bytes());
    record
}

/// Four keys sign one message; the tile proves two of them, then merges that
/// proof with the other two. Each proof verifies against its claims, and not
/// against one claim short.
#[test]
#[ignore = "proves with the real prover: set LEANVM_TEST_CORES"]
fn the_tile_proves_and_merges() {
    let message = [7; lean_xmss::MESSAGE_LEN];
    let signatures: Vec<_> = (0..4u8)
        .map(|k| {
            let (secret_key, public_key) = lean_xmss::key_gen(&[k; lean_xmss::SECRET_KEY_LEN]);
            secret_key.prepare(7);
            signed_claim(public_key, message, &lean_xmss::sign(&secret_key, &message, 7))
        })
        .collect();
    let mut rig = Rig::new(test_cores());
    rig.crank();
    assert_eq!(rig.ready_events, 1);

    let request = rig.prepare(1, &signatures[..2], &[]);
    rig.injector.produce(request);
    let Answer::Proven(first_len, first) = rig.answer(1) else { panic!("expected a proof") };
    let (claims, proof) = proof_parts(first_len, &first);
    assert_eq!(claims.lean_xmss.len(), 2);

    let request = rig.prepare(2, &signatures[2..], &[(first_len, &first)]);
    let decoded = read_request(&mut rig.tile.reader, request).unwrap();
    let [(child_claims, child_proof)] = decoded.children.as_slice() else {
        panic!("expected one child");
    };
    assert_eq!(child_claims, &claims);
    assert_eq!(child_proof.to_bytes(), proof);
    rig.injector.produce(request);
    let Answer::Proven(merged_len, merged) = rig.answer(2) else {
        panic!("expected a merge proof")
    };
    let (union, merged_proof) = proof_parts(merged_len, &merged);
    assert_eq!(union.lean_xmss.len(), 4);

    eprintln!("leaf proof {} bytes, merge proof {} bytes", proof.len(), merged_proof.len());
    for (claims, proof) in [(claims, proof), (union, merged_proof)] {
        let proof = AggregateProof::from_bytes(proof).expect("a proof");
        assert!(proof.verify(&claims));
        let mut fewer = claims;
        fewer.lean_xmss.pop();
        assert!(!proof.verify(&fewer), "a claim short");
    }
}
