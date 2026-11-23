//! A PQ `BeaconState` from the spec's SSZ library (`fixtures/pq`), until
//! consensus-spec-tests ship PQ.

#[path = "support/loaded_state.rs"]
mod loaded_state;

use std::path::Path;

use loaded_state::{load_state, snappy_decode};
use silver_beacon_state::{ssz_hash::hash_tree_root_state, stf};
use silver_beacon_state_data::{BeaconState, SpecConfig, pq::KeyScheme};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pq/state.ssz_snappy");
const ROOT: &str = "bef140f4b21b68ed75ab5bb7f565b845a5f143988fcc5eaf1479a185f33d5b14";

/// A 64-validator PQ genesis from the spec's helpers, and its roots after each
/// of three epoch transitions (`fixtures/pq/gen_genesis_epochs.py`).
const GENESIS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pq/genesis.ssz_snappy");
const EPOCH_ROOTS: [(u64, &str); 3] = [
    (32, "0e055a71b0beb79cd1fc13ff47fda209a4b16fbac6ea77fde29b267b559cc029"),
    (64, "55c0adc16892f7ec4d4c0f4ad187549e8fa4468a9777f9d631f127efefbb5ef8"),
    (96, "ae99d2a7ce551f1b2c816db7287367cfc1435a42ad0c4cf6c32cba3044ff1618"),
];

#[test]
fn state_root_matches_reference() {
    let mut state = load_state(Path::new(FIXTURE));
    assert!(state.bs.is_finalized_post_gloas());
    assert_eq!(state.bs.validators.finalized().scheme(), KeyScheme::Xmss);
    assert_eq!(state.bs.builders.finalized().scheme(), KeyScheme::Xmss);

    let state_id = state.state_id;
    let (mut view, epoch, longtail) = state.view();
    let rv =
        view.read(epoch.view_opt(state_id.epoch_idx), longtail.view_opt(state_id.longtail_idx));
    assert!(rv.is_pq());
    assert_eq!(hex::encode(hash_tree_root_state(&rv)), ROOT);
}

#[test]
fn state_encodes_back_to_its_ssz() {
    let ssz = snappy_decode(Path::new(FIXTURE));
    let state = BeaconState::decompose(&ssz, &SpecConfig::reference(), None).unwrap();
    assert_eq!(state.ssz_len(), ssz.len());
    let mut encoded = Vec::with_capacity(ssz.len());
    state.encode_ssz(&mut encoded).unwrap();
    assert!(encoded == ssz, "PQ encode round-trip mismatch");
}

/// Covers the PQ epoch steps: no sync committee rotation, and the aggregation
/// committee window and preregistration expiry after the PTC window.
#[test]
fn epoch_transitions_match_the_spec() {
    let mut state = load_state(Path::new(GENESIS));
    let cfg = SpecConfig {
        gloas_fork_epoch: 0,
        eip8483_fork_epoch: 0,
        pq_fork_epoch: 0,
        ..SpecConfig::reference()
    };
    let mut scratch = stf::StfScratch::new(0);
    for (slot, expected) in EPOCH_ROOTS {
        let mut fork = state.bs.fork_writer(state.state_id);
        stf::process_slots(&cfg, &mut fork, slot, &mut scratch);
        let root = hash_tree_root_state(&fork.read());
        state.state_id = fork.commit();
        assert_eq!(hex::encode(root), expected, "state root at slot {slot}");
    }
}
