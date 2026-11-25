#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{
    LoadedState, compare_states, iter_test_cases, load_state, load_state_gloas, pq_config,
    preset_tests_dir,
};
use silver_beacon_state::stf::{self, HISTORICAL_SUMMARY_PERIOD};
use silver_beacon_state_data::{EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SpecConfig};
/// Gloas EF config: mainnet preset with Gloas active from genesis, so the
/// `cfg.is_gloas_at(epoch)`-gated STF branches fire on the loaded Gloas states.
fn gloas_cfg() -> SpecConfig {
    let mut cfg = SpecConfig::reference();
    cfg.gloas_fork_epoch = 0;
    cfg
}

fn epoch_handler(handler_name: &str, run: impl Fn(&mut LoadedState)) {
    epoch_handler_fork("fulu", handler_name, run);
}

fn epoch_handler_fork(fork: &str, handler_name: &str, run: impl Fn(&mut LoadedState)) {
    let base = preset_tests_dir().join(fork).join("epoch_processing").join(handler_name);
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{handler_name}: no test cases at {}, skipping", base.display());
        return;
    }

    let loader = if fork == "gloas" { load_state_gloas } else { load_state };

    let mut pass = 0;
    let mut fail = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }

        let mut pre = loader(&pre_path);
        run(&mut pre);
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
    eprintln!(
        "{handler_name}: {pass} passed, {fail} failed, {} skipped",
        cases.len() - pass - fail
    );
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

type Runner = fn(&SpecConfig, &mut LoadedState);

fn fulu_handler(handler_name: &str, run: Runner) {
    let cfg = SpecConfig::reference();
    epoch_handler(handler_name, |s| run(&cfg, s));
}

fn gloas_handler(handler_name: &str, run: Runner) {
    let cfg = gloas_cfg();
    epoch_handler_fork("gloas", handler_name, |s| run(&cfg, s));
}

#[test]
fn fulu_justification_and_finalization() {
    fulu_handler("justification_and_finalization", run_justification_and_finalization);
}

#[test]
fn fulu_inactivity_updates() {
    fulu_handler("inactivity_updates", run_inactivity_updates);
}

#[test]
fn fulu_rewards_and_penalties() {
    fulu_handler("rewards_and_penalties", run_rewards_and_penalties);
}

#[test]
fn fulu_registry_updates() {
    fulu_handler("registry_updates", run_registry_updates);
}

#[test]
fn fulu_slashings() {
    fulu_handler("slashings", run_slashings);
}

#[test]
fn fulu_eth1_data_reset() {
    fulu_handler("eth1_data_reset", run_eth1_data_reset);
}

#[test]
fn fulu_pending_deposits() {
    fulu_handler("pending_deposits", run_pending_deposits);
}

#[test]
fn fulu_pending_consolidations() {
    fulu_handler("pending_consolidations", run_pending_consolidations);
}

#[test]
fn fulu_effective_balance_updates() {
    fulu_handler("effective_balance_updates", run_effective_balance_updates);
}

#[test]
fn fulu_slashings_reset() {
    fulu_handler("slashings_reset", run_slashings_reset);
}

#[test]
fn fulu_randao_mixes_reset() {
    fulu_handler("randao_mixes_reset", run_randao_mixes_reset);
}

#[test]
fn fulu_historical_summaries_update() {
    fulu_handler("historical_summaries_update", run_historical_summaries_update);
}

#[test]
fn fulu_participation_flag_updates() {
    fulu_handler("participation_flag_updates", run_participation_flag_updates);
}

#[test]
fn fulu_sync_committee_updates() {
    fulu_handler("sync_committee_updates", run_sync_committee_updates);
}

#[test]
fn fulu_proposer_lookahead() {
    fulu_handler("proposer_lookahead", run_proposer_lookahead);
}

#[test]
fn gloas_pending_deposits() {
    gloas_handler("pending_deposits", run_pending_deposits);
}

#[test]
fn gloas_pending_deposits_churn() {
    gloas_handler("pending_deposits_churn", run_pending_deposits);
}

#[test]
fn gloas_builder_pending_payments() {
    gloas_handler("builder_pending_payments", run_builder_pending_payments);
}

#[test]
fn gloas_proposer_lookahead() {
    gloas_handler("proposer_lookahead", run_proposer_lookahead);
}

#[test]
fn gloas_ptc_window() {
    gloas_handler("ptc_window", run_ptc_window);
}

/// Every epoch step the PQ vectors cover, the two new ones among them.
#[test]
fn pq_epoch_processing() {
    let cfg = pq_config();
    let handlers: [(&str, Runner); 18] = [
        ("justification_and_finalization", run_justification_and_finalization),
        ("inactivity_updates", run_inactivity_updates),
        ("rewards_and_penalties", run_rewards_and_penalties),
        ("registry_updates", run_registry_updates),
        ("slashings", run_slashings),
        ("pending_deposits", run_pending_deposits),
        ("pending_deposits_churn", run_pending_deposits),
        ("pending_consolidations", run_pending_consolidations),
        ("builder_pending_payments", run_builder_pending_payments),
        ("effective_balance_updates", run_effective_balance_updates),
        ("slashings_reset", run_slashings_reset),
        ("randao_mixes_reset", run_randao_mixes_reset),
        ("historical_summaries_update", run_historical_summaries_update),
        ("participation_flag_updates", run_participation_flag_updates),
        ("proposer_lookahead", run_proposer_lookahead),
        ("ptc_window", run_ptc_window),
        ("aggregation_committee_window", run_aggregation_committee_window),
        ("preregistration_expiry", run_preregistration_expiry),
    ];
    for (handler_name, run) in handlers {
        epoch_handler_fork("pq", handler_name, |s| run(&cfg, s));
    }
}

fn run_justification_and_finalization(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (mut view, epoch, _) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
    stf::process_justification_and_finalization(&mut view, &mut epoch_w, current_epoch);
    s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
}

fn run_inactivity_updates(cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view_and_epoch(|view, e| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_inactivity_updates(cfg, view, e, current_epoch);
    });
}

fn run_rewards_and_penalties(cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view_and_epoch(|view, e| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_rewards_and_penalties(cfg, view, e, current_epoch);
    });
}

fn run_registry_updates(cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view_and_epoch(|view, e| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_registry_updates(cfg, view, e, current_epoch);
    });
}

fn run_slashings(cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_slashings(cfg, view, current_epoch);
    });
}

fn run_eth1_data_reset(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_eth1_data_reset(&mut view.eth1, current_epoch);
    });
}

fn run_pending_deposits(cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (mut view, epoch, _) = s.view();
    let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
    stf::process_pending_deposits(cfg, &mut view, &mut epoch_w, &mut Vec::new());
    s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
}

fn run_pending_consolidations(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| stf::process_pending_consolidations(view));
}

fn run_effective_balance_updates(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| stf::process_effective_balance_updates(view, &mut Vec::new()));
}

fn run_slashings_reset(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| stf::process_slashings_reset(view));
}

fn run_randao_mixes_reset(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_randao_mixes_reset(view, current_epoch);
    });
}

fn run_historical_summaries_update(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (mut view, _, longtail) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    // The hub's rotation gate: no-op vectors never roll the longtail.
    if !(current_epoch + 1).is_multiple_of(HISTORICAL_SUMMARY_PERIOD) {
        return;
    }
    let mut longtail_w = longtail.roll_inheriting(sid.longtail_idx);
    stf::process_historical_summaries_update(&mut view, &mut longtail_w);
    s.state_id = view.commit(sid.epoch_idx, Some(longtail_w.commit()));
}

fn run_participation_flag_updates(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| stf::process_participation_flag_updates(view));
}

fn run_sync_committee_updates(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (mut view, _, longtail) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    // The hub's rotation gate: no-op vectors never roll the longtail.
    if !(current_epoch + 1).is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
        return;
    }
    let mut longtail_w = longtail.roll_inheriting(sid.longtail_idx);
    stf::process_sync_committee_updates(
        &mut view,
        &mut longtail_w,
        current_epoch,
        &mut Vec::new(),
        &mut Vec::new(),
    );
    s.state_id = view.commit(sid.epoch_idx, Some(longtail_w.commit()));
}

fn run_proposer_lookahead(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (mut view, epoch, _) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
    stf::process_proposer_lookahead(
        &mut view,
        &mut epoch_w,
        current_epoch,
        &mut Vec::new(),
        &mut Vec::new(),
    );
    s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
}

fn run_builder_pending_payments(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| {
        let current_epoch = view.slot.reader().current_epoch();
        stf::process_builder_pending_payments(view, current_epoch);
    });
}

fn run_ptc_window(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (view, epoch, _) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
    let mut buf = Vec::new();
    let lookahead = stf::EpochShuffling::lookahead(&view, current_epoch, &mut buf);
    stf::process_ptc_window(&view, &mut epoch_w, current_epoch, &lookahead);
    s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
}

fn run_aggregation_committee_window(_cfg: &SpecConfig, s: &mut LoadedState) {
    let sid = s.state_id;
    let (view, epoch, _) = s.view();
    let current_epoch = view.slot.reader().current_epoch();
    let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
    let mut buf = Vec::new();
    let lookahead = stf::EpochShuffling::lookahead(&view, current_epoch, &mut buf);
    stf::process_aggregation_committee_window(&view, &mut epoch_w, current_epoch, &lookahead);
    s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
}

fn run_preregistration_expiry(_cfg: &SpecConfig, s: &mut LoadedState) {
    s.with_view(|view| stf::process_preregistration_expiry(view));
}
