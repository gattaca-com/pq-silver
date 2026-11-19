//! A PQ `BeaconState` from the spec's SSZ library (`fixtures/pq`), until
//! consensus-spec-tests ship PQ.

#[path = "support/loaded_state.rs"]
mod loaded_state;

use std::path::Path;

use loaded_state::{load_state, snappy_decode};
use silver_beacon_state::ssz_hash::hash_tree_root_state;
use silver_beacon_state_data::{BeaconState, SpecConfig, pq::KeyScheme};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pq/state.ssz_snappy");
const ROOT: &str = "bef140f4b21b68ed75ab5bb7f565b845a5f143988fcc5eaf1479a185f33d5b14";

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
    let state = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();
    assert_eq!(state.ssz_len(), ssz.len());
    let mut encoded = Vec::with_capacity(ssz.len());
    state.encode_ssz(&mut encoded).unwrap();
    assert!(encoded == ssz, "PQ encode round-trip mismatch");
}
