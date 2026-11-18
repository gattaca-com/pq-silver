use silver_ssz::{
    merkle::FixedContainer,
    ssz_hash_pq::ExecutionRequestsPqView,
    ssz_view::{
        AttestationPqView, AttesterSlashingPqView, BeaconBlockBodyPqView, IndexedAttestationPqView,
        PROPOSER_SLASHING_PQ_SIZE, ProposerSlashingPqView, SIGNED_PQ_FIXED,
        SignedAggregateAndProofPqView, SignedExecutionPayloadBidPqView,
    },
};

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

/// `(serialized, root)` of every vector of `type_name`.
fn vectors(type_name: &str) -> Vec<(Vec<u8>, [u8; 32])> {
    let cases: Vec<_> = include_str!("fixtures/pq/reference_vectors.txt")
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(' ');
            (parts.next()? == type_name).then(|| {
                let serialized = decode_hex(parts.next().unwrap());
                let root = decode_hex(parts.next().unwrap()).try_into().unwrap();
                (serialized, root)
            })
        })
        .collect();
    assert!(!cases.is_empty(), "no {type_name} vectors");
    cases
}

#[test]
fn attestation() {
    for (ssz, root) in vectors("Attestation") {
        assert!(AttestationPqView::check_canonical(&ssz));
        assert_eq!(AttestationPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn indexed_attestation() {
    for (ssz, root) in vectors("IndexedAttestation") {
        assert!(IndexedAttestationPqView::check_size(&ssz));
        assert_eq!(IndexedAttestationPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn attester_slashing() {
    for (ssz, root) in vectors("AttesterSlashing") {
        assert!(AttesterSlashingPqView::check_size(&ssz));
        assert_eq!(AttesterSlashingPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn aggregate_and_proof() {
    for (message, root) in vectors("AggregateAndProof") {
        let mut signed = (SIGNED_PQ_FIXED as u32).to_le_bytes().to_vec();
        signed.resize(SIGNED_PQ_FIXED, 0);
        signed.extend_from_slice(&message);
        assert!(SignedAggregateAndProofPqView::check_size(&signed));
        assert_eq!(SignedAggregateAndProofPqView::message_root(&signed), root);
    }
}

#[test]
fn proposer_slashing() {
    for (ssz, root) in vectors("ProposerSlashing") {
        assert_eq!(ssz.len(), PROPOSER_SLASHING_PQ_SIZE);
        assert_eq!(ProposerSlashingPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn aggregate_signing_root() {
    let genesis_root = std::array::from_fn(|i| i as u8);
    let domain = silver_ssz::ssz_hash::compute_domain(6, [0xe0, 0, 0, 0], &genesis_root);
    for (message, expected) in vectors("AggregateSigningRoot") {
        let mut signed = (SIGNED_PQ_FIXED as u32).to_le_bytes().to_vec();
        signed.resize(SIGNED_PQ_FIXED, 0);
        signed.extend_from_slice(&message);
        assert!(SignedAggregateAndProofPqView::check_size(&signed));
        let root = SignedAggregateAndProofPqView::message_root(&signed);
        assert_eq!(silver_ssz::ssz_hash::compute_signing_root(&root, &domain), expected);
    }
}

#[test]
fn signed_execution_payload_bid() {
    for (ssz, root) in vectors("SignedExecutionPayloadBid") {
        assert!(SignedExecutionPayloadBidPqView::check_canonical(&ssz));
        assert_eq!(SignedExecutionPayloadBidPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn execution_requests() {
    for (ssz, root) in vectors("ExecutionRequests") {
        assert!(ExecutionRequestsPqView::check_canonical(&ssz));
        assert_eq!(ExecutionRequestsPqView::check_counts(&ssz), Ok(()));
        assert_eq!(ExecutionRequestsPqView::hash_tree_root(&ssz), root);
    }
}

#[test]
fn beacon_block_body() {
    for (ssz, root) in vectors("BeaconBlockBody") {
        assert!(BeaconBlockBodyPqView::check_canonical(&ssz));
        assert!(BeaconBlockBodyPqView::check_operation_limits(&ssz).is_ok());
        assert_eq!(BeaconBlockBodyPqView::hash_tree_root(&ssz), root);
    }
}
