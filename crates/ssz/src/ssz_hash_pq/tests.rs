use super::ExecutionRequestsPqView;
use crate::{
    body_offsets::{BlockBodyError, OperationKind},
    merkle::{
        B256, FixedContainer, ZERO_HASH, ZERO_HASHES, hash_concat, hash_fixed_bytes,
        merkleize_padded, mix_in_length, uint64_chunk,
    },
    progressive::active_fields,
    ssz_hash::{hash_attestation_data, hash_eth1_data_bytes},
    ssz_hash_gloas::RequestCountOutOfBounds,
    ssz_view::{
        AttestationPqView, AttesterSlashingPqView, BEACON_BLOCK_BODY_PQ_FIXED,
        BeaconBlockBodyPqView, COMMITTEE_BITS_SIZE_PQ, EXECUTION_PAYLOAD_BID_MIN,
        ExecutionPayloadBidView, IndexedAttestationPqView, MAX_COMMITTEES_PER_SLOT_PQ,
        PROPOSER_SLASHING_PQ_SIZE, ProposerSlashingPqView, SignedAggregateAndProofPqView,
        SignedExecutionPayloadBidPqView, VRF_PROOF_SIZE, VoluntaryExitRequestView,
        XMSS_SIGNATURE_SIZE,
    },
};

enum Field {
    Fixed(Vec<u8>),
    Variable(Vec<u8>),
}

/// SSZ container serialization: fixed parts and offsets, then variable parts.
fn encode(fields: &[Field]) -> Vec<u8> {
    let fixed_len: usize = fields
        .iter()
        .map(|f| match f {
            Field::Fixed(b) => b.len(),
            Field::Variable(_) => 4,
        })
        .sum();
    let mut fixed = Vec::new();
    let mut variable = Vec::new();
    for field in fields {
        match field {
            Field::Fixed(b) => fixed.extend_from_slice(b),
            Field::Variable(b) => {
                fixed.extend_from_slice(&((fixed_len + variable.len()) as u32).to_le_bytes());
                variable.extend_from_slice(b);
            }
        }
    }
    fixed.extend(variable);
    fixed
}

/// `List` of variable-size elements: offset table, then elements.
fn encode_list(elements: &[Vec<u8>]) -> Vec<u8> {
    let fields: Vec<_> = elements.iter().map(|e| Field::Variable(e.clone())).collect();
    encode(&fields)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// EIP-7916 `merkleize_progressive`, transcribed from the pseudocode.
fn merkleize_progressive_ref(chunks: &[B256], num_leaves: usize) -> B256 {
    if chunks.is_empty() {
        return ZERO_HASH;
    }
    let split = chunks.len().min(num_leaves);
    hash_concat(
        &merkleize_padded(&chunks[..split], num_leaves),
        &merkleize_progressive_ref(&chunks[split..], num_leaves * 4),
    )
}

/// EIP-7495 root: inactive fields are skipped, so `active` lists the field
/// index of each root in `roots`.
fn progressive_container_ref(width: usize, active: &[usize], roots: &[B256]) -> B256 {
    let mut chunks = vec![ZERO_HASH; width];
    let mut mask = ZERO_HASH;
    for (&i, root) in active.iter().zip(roots) {
        chunks[i] = *root;
        mask[i / 8] |= 1 << (i % 8);
    }
    hash_concat(&merkleize_progressive_ref(&chunks, 1), &mask)
}

/// `ByteList[2**20]` root with a 2**15-chunk tree.
fn proof_root_ref(proof: &[u8]) -> B256 {
    let mut chunks: Vec<B256> = proof
        .chunks(32)
        .map(|c| {
            let mut chunk = ZERO_HASH;
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect();
    chunks.resize(chunks.len().next_power_of_two().max(1), ZERO_HASH);
    let mut depth = chunks.len().trailing_zeros() as usize;
    let mut root = merkleize_padded(&chunks, chunks.len());
    while depth < 15 {
        root = hash_concat(&root, &ZERO_HASHES[depth]);
        depth += 1;
    }
    mix_in_length(&root, proof.len())
}

/// Names committee 1.
fn committee_bits() -> Vec<u8> {
    let mut bits = vec![0; COMMITTEE_BITS_SIZE_PQ];
    bits[0] = 0b10;
    bits
}

fn attestation(bits: &[u8]) -> Vec<u8> {
    encode(&[
        Field::Variable(bits.to_vec()),
        Field::Fixed(pattern(128, 1)),
        Field::Fixed(committee_bits()),
    ])
}

fn indexed_attestation(indices: &[u64], proof: &[u8]) -> Vec<u8> {
    encode(&[
        Field::Variable(indices.iter().flat_map(|i| i.to_le_bytes()).collect()),
        Field::Fixed(pattern(128, 3)),
        Field::Variable(proof.to_vec()),
    ])
}

fn execution_requests(lists: [Vec<u8>; 8]) -> Vec<u8> {
    encode(&lists.map(Field::Variable))
}

fn signed_bid() -> Vec<u8> {
    let mut bid = pattern(EXECUTION_PAYLOAD_BID_MIN, 4);
    bid[188..192].copy_from_slice(&(EXECUTION_PAYLOAD_BID_MIN as u32).to_le_bytes());
    encode(&[Field::Variable(bid), Field::Fixed(pattern(XMSS_SIGNATURE_SIZE, 5))])
}

struct Body {
    proposer_slashings: Vec<u8>,
    attestations: Vec<Vec<u8>>,
    deposits: Vec<u8>,
    requests: Vec<u8>,
    proof: Vec<u8>,
}

impl Body {
    fn new() -> Self {
        Self {
            proposer_slashings: pattern(PROPOSER_SLASHING_PQ_SIZE, 6),
            attestations: vec![attestation(&[0b1010_0101, 0b1])],
            deposits: Vec::new(),
            requests: execution_requests(Default::default()),
            proof: pattern(100, 7),
        }
    }

    fn encode(&self) -> Vec<u8> {
        encode(&[
            Field::Fixed(pattern(VRF_PROOF_SIZE, 8)),
            Field::Fixed(pattern(72, 9)),
            Field::Fixed(pattern(32, 10)),
            Field::Variable(self.proposer_slashings.clone()),
            Field::Variable(Vec::new()),
            Field::Variable(encode_list(&self.attestations)),
            Field::Variable(self.deposits.clone()),
            Field::Variable(signed_bid()),
            Field::Variable(self.requests.clone()),
            Field::Variable(self.proof.clone()),
        ])
    }
}

#[test]
fn active_fields_clear_gaps() {
    assert_eq!(active_fields(4, &[2])[..2], [0b1011, 0]);
    assert_eq!(active_fields(10, &[5, 6])[..2], [0b1001_1111, 0b11]);
    assert_eq!(active_fields(14, &[7, 8, 9, 11])[..2], [0b0111_1111, 0b0011_0100]);
}

#[test]
fn attestation_drops_signature_slot() {
    let bits = [0xFF, 0b10];
    let att = attestation(&bits);
    assert!(AttestationPqView::check_canonical(&att));
    assert_eq!(AttestationPqView::aggregation_bits(&att), bits);

    let mut committee_chunk = ZERO_HASH;
    committee_chunk[..COMMITTEE_BITS_SIZE_PQ].copy_from_slice(&committee_bits());
    let mut bits_chunk = ZERO_HASH;
    bits_chunk[0] = 0xFF;
    let bits_root = mix_in_length(&merkleize_progressive_ref(&[bits_chunk], 1), 9);
    let expected = progressive_container_ref(4, &[0, 1, 3], &[
        bits_root,
        hash_attestation_data(&pattern(128, 1)),
        committee_chunk,
    ]);
    assert_eq!(AttestationPqView::hash_tree_root(&att), expected);

    assert!(!AttestationPqView::check_canonical(&attestation(&[0xFF, 0])));
}

#[test]
fn committee_attestation_round_trips_through_the_view() {
    let data = [7u8; 128];
    let committee = MAX_COMMITTEES_PER_SLOT_PQ - 1;
    let att = AttestationPqView::encode_one_committee(&data, committee, 10, [0, 3, 9]).unwrap();
    assert!(AttestationPqView::check_canonical(&att));
    assert_eq!(AttestationPqView::data(&att).as_bytes(), &data);
    let mut expected_committee_bits = [0; COMMITTEE_BITS_SIZE_PQ];
    expected_committee_bits[committee / 8] = 1 << (committee % 8);
    assert_eq!(AttestationPqView::committee_bits(&att), &expected_committee_bits);
    assert_eq!(AttestationPqView::aggregation_bits(&att), [0b0000_1001, 0b110]);
    let (index, positions) = AttestationPqView::one_committee_positions(&att).unwrap();
    assert_eq!((index, positions.collect::<Vec<_>>()), (committee, vec![0, 3, 9]));

    let empty = AttestationPqView::encode_one_committee(&data, 0, 0, []).unwrap();
    assert!(AttestationPqView::check_canonical(&empty));
    assert_eq!(AttestationPqView::aggregation_bits(&empty), [1]);
}

#[test]
fn committee_attestation_refuses_out_of_range_input() {
    let data = [0u8; 128];
    assert!(
        AttestationPqView::encode_one_committee(&data, MAX_COMMITTEES_PER_SLOT_PQ, 4, [0])
            .is_none()
    );
    assert!(AttestationPqView::encode_one_committee(&data, 0, 2049, [0]).is_none());
    assert!(AttestationPqView::encode_one_committee(&data, 0, 4, [4]).is_none());
}

#[test]
fn attester_slashing_splits_indexed_attestations() {
    let proof = pattern(70, 11);
    let att_1 = indexed_attestation(&[1, 5, 9], &proof);
    let att_2 = indexed_attestation(&[2], &[]);
    let slashing = encode(&[Field::Variable(att_1.clone()), Field::Variable(att_2.clone())]);
    assert!(AttesterSlashingPqView::check_size(&slashing));
    assert_eq!(AttesterSlashingPqView::attestation_1(&slashing), att_1);
    assert_eq!(AttesterSlashingPqView::attestation_2(&slashing), att_2);
    assert_eq!(IndexedAttestationPqView::proof(&att_1), proof);
    assert_eq!(IndexedAttestationPqView::attesting_indices(&att_1).len(), 24);

    let indices = [1u64, 5, 9].map(uint64_chunk);
    let packed: B256 = {
        let mut chunk = ZERO_HASH;
        for (i, index) in indices.iter().enumerate() {
            chunk[i * 8..i * 8 + 8].copy_from_slice(&index[..8]);
        }
        chunk
    };
    let expected_1 = progressive_container_ref(3, &[0, 1, 2], &[
        mix_in_length(&merkleize_progressive_ref(&[packed], 1), 3),
        hash_attestation_data(&pattern(128, 3)),
        proof_root_ref(&proof),
    ]);
    assert_eq!(IndexedAttestationPqView::hash_tree_root(&att_1), expected_1);
    assert_eq!(
        AttesterSlashingPqView::hash_tree_root(&slashing),
        hash_concat(&expected_1, &IndexedAttestationPqView::hash_tree_root(&att_2)),
    );

    let misaligned = encode(&[
        Field::Variable(pattern(9, 0)),
        Field::Fixed(pattern(128, 3)),
        Field::Variable(Vec::new()),
    ]);
    assert!(!IndexedAttestationPqView::check_size(&misaligned));
}

#[test]
fn signed_aggregate_and_proof_reads_its_fields() {
    let att = attestation(&[0b1100_0001, 0b1]);
    let proof = pattern(40, 12);
    let message = encode(&[
        Field::Fixed(42u64.to_le_bytes().to_vec()),
        Field::Variable(att.clone()),
        Field::Variable(proof.clone()),
    ]);
    let signature = pattern(XMSS_SIGNATURE_SIZE, 14);
    let signed = encode(&[Field::Variable(message), Field::Fixed(signature.clone())]);

    assert!(SignedAggregateAndProofPqView::check_size(&signed));
    assert_eq!(SignedAggregateAndProofPqView::signature(&signed)[..], signature);
    assert_eq!(SignedAggregateAndProofPqView::aggregator_index(&signed), 42);
    assert_eq!(SignedAggregateAndProofPqView::aggregate(&signed), att);
    assert_eq!(SignedAggregateAndProofPqView::agg_aggregation_bits(&signed), [0b1100_0001, 1]);
    assert_eq!(SignedAggregateAndProofPqView::agg_committee_bits(&signed)[..], committee_bits());
    assert_eq!(SignedAggregateAndProofPqView::proof(&signed), proof);

    let expected = merkleize_padded(
        &[uint64_chunk(42), AttestationPqView::hash_tree_root(&att), proof_root_ref(&proof)],
        4,
    );
    assert_eq!(SignedAggregateAndProofPqView::message_root(&signed), expected);

    let obsolete = encode(&[
        Field::Fixed(42u64.to_le_bytes().to_vec()),
        Field::Variable(att),
        Field::Fixed(pattern(VRF_PROOF_SIZE, 13)),
        Field::Variable(proof),
    ]);
    let obsolete = encode(&[Field::Variable(obsolete), Field::Fixed(signature)]);
    assert!(!SignedAggregateAndProofPqView::check_size(&obsolete));

    let mut bad_offset = signed.clone();
    bad_offset[0] += 1;
    assert!(!SignedAggregateAndProofPqView::check_size(&bad_offset));
}

#[test]
fn canonical_network_maxima() {
    use crate::ssz_view::{MAX_ATTESTING_INDICES_PQ, MAX_STARK_PROOF_SIZE};

    let mut bits = vec![0xff; MAX_ATTESTING_INDICES_PQ / 8];
    bits.push(1);
    let proof = vec![0x42; MAX_STARK_PROOF_SIZE];
    let message = encode(&[
        Field::Fixed(vec![0; 8]),
        Field::Variable(attestation(&bits)),
        Field::Variable(proof.clone()),
    ]);
    let mut signed =
        encode(&[Field::Variable(message), Field::Fixed(vec![0; XMSS_SIGNATURE_SIZE])]);
    assert_eq!(signed.len(), 1_055_231);
    assert!(SignedAggregateAndProofPqView::check_size(&signed));
    signed.push(0);
    assert!(!SignedAggregateAndProofPqView::check_size(&signed));
    *bits.last_mut().unwrap() = 2;
    assert!(!AttestationPqView::check_canonical(&attestation(&bits)));

    let indexed = indexed_attestation(&vec![0; MAX_ATTESTING_INDICES_PQ], &proof);
    let mut slashing = encode(&[Field::Variable(indexed.clone()), Field::Variable(indexed)]);
    assert_eq!(slashing.len(), 2_621_720);
    assert!(AttesterSlashingPqView::check_size(&slashing));
    slashing.push(0);
    assert!(!AttesterSlashingPqView::check_size(&slashing));

    let mut bid = signed_bid();
    bid.resize(199_240, 0);
    assert!(SignedExecutionPayloadBidPqView::check_canonical(&bid));
    bid.push(0);
    assert!(!SignedExecutionPayloadBidPqView::check_canonical(&bid));
}

#[test]
fn execution_requests_skip_registration_slots() {
    let exit_requests = pattern(64, 15);
    let validator_preregistrations = pattern(96, 16);
    let mut lists: [Vec<u8>; 8] = Default::default();
    lists[5] = validator_preregistrations.clone();
    lists[7] = exit_requests.clone();
    let requests = execution_requests(lists);

    assert!(ExecutionRequestsPqView::check_canonical(&requests));
    assert_eq!(ExecutionRequestsPqView::check_counts(&requests), Ok(()));
    assert_eq!(ExecutionRequestsPqView::sections(&requests)[7], exit_requests);

    let empty_list = mix_in_length(&ZERO_HASH, 0);
    let exit_roots: Vec<B256> =
        exit_requests.chunks(32).map(VoluntaryExitRequestView::hash_tree_root).collect();
    let vp_root = merkleize_padded(
        &[
            validator_preregistrations[..32].try_into().unwrap(),
            validator_preregistrations[32..64].try_into().unwrap(),
            validator_preregistrations[64..].try_into().unwrap(),
        ],
        4,
    );
    let expected = progressive_container_ref(10, &[0, 1, 2, 3, 4, 7, 8, 9], &[
        empty_list,
        empty_list,
        empty_list,
        empty_list,
        empty_list,
        mix_in_length(&merkleize_progressive_ref(&[vp_root], 1), 1),
        empty_list,
        mix_in_length(&merkleize_progressive_ref(&exit_roots, 1), 2),
    ]);
    assert_eq!(ExecutionRequestsPqView::hash_tree_root(&requests), expected);

    let mut lists: [Vec<u8>; 8] = Default::default();
    lists[6] = pattern(5 * 64, 17);
    assert_eq!(
        ExecutionRequestsPqView::check_counts(&execution_requests(lists)),
        Err(RequestCountOutOfBounds { kind: "builder_preregistration", count: 5, max: 4 }),
    );

    let mut lists: [Vec<u8>; 8] = Default::default();
    lists[7] = pattern(33, 18);
    assert!(!ExecutionRequestsPqView::check_canonical(&execution_requests(lists)));
}

#[test]
fn block_body_reads_and_hashes_active_fields() {
    let body = Body::new();
    let encoded = body.encode();
    assert!(BeaconBlockBodyPqView::check_canonical(&encoded));
    assert!(BeaconBlockBodyPqView::check_operation_limits(&encoded).is_ok());
    assert_eq!(BeaconBlockBodyPqView::randao_reveal(&encoded)[..], pattern(VRF_PROOF_SIZE, 8));
    let first_offset = u32::from_le_bytes(encoded[1128..1132].try_into().unwrap());
    assert_eq!(first_offset as usize, BEACON_BLOCK_BODY_PQ_FIXED);
    assert_eq!(BeaconBlockBodyPqView::proof(&encoded), body.proof);
    assert_eq!(BeaconBlockBodyPqView::signed_execution_payload_bid(&encoded), signed_bid());

    let bid = signed_bid();
    let bid_root = merkleize_padded(
        &[
            ExecutionPayloadBidView::hash_tree_root(SignedExecutionPayloadBidPqView::message(&bid)),
            hash_fixed_bytes(SignedExecutionPayloadBidPqView::signature(&bid)),
        ],
        2,
    );
    let empty_list = mix_in_length(&ZERO_HASH, 0);
    let expected = progressive_container_ref(14, &[0, 1, 2, 3, 4, 5, 6, 10, 12, 13], &[
        hash_fixed_bytes(&pattern(VRF_PROOF_SIZE, 8)),
        hash_eth1_data_bytes(&pattern(72, 9)),
        pattern(32, 10).try_into().unwrap(),
        mix_in_length(
            &merkleize_progressive_ref(
                &[ProposerSlashingPqView::hash_tree_root(&body.proposer_slashings)],
                1,
            ),
            1,
        ),
        empty_list,
        mix_in_length(
            &merkleize_progressive_ref(
                &[AttestationPqView::hash_tree_root(&body.attestations[0])],
                1,
            ),
            1,
        ),
        empty_list,
        bid_root,
        ExecutionRequestsPqView::hash_tree_root(&body.requests),
        proof_root_ref(&body.proof),
    ]);
    assert_eq!(BeaconBlockBodyPqView::hash_tree_root(&encoded), expected);
}

#[test]
fn block_body_enforces_operation_limits() {
    let mut body = Body::new();
    body.attestations = vec![attestation(&[1]); 17];
    assert!(matches!(
        BeaconBlockBodyPqView::check_operation_limits(&body.encode()),
        Err(BlockBodyError::OperationCountOutOfBounds {
            op: OperationKind::Attestations,
            count: 17,
            max: 16,
        })
    ));

    let mut body = Body::new();
    body.deposits = pattern(1240, 19);
    assert!(matches!(
        BeaconBlockBodyPqView::check_operation_limits(&body.encode()),
        Err(BlockBodyError::OperationCountOutOfBounds { op: OperationKind::Deposits, .. })
    ));

    let mut lists: [Vec<u8>; 8] = Default::default();
    lists[7] = pattern(17 * 32, 20);
    let mut body = Body::new();
    body.requests = execution_requests(lists);
    assert!(matches!(
        BeaconBlockBodyPqView::check_operation_limits(&body.encode()),
        Err(BlockBodyError::RequestCountOutOfBounds { kind: "voluntary_exit", .. })
    ));

    let mut body = Body::new();
    body.proposer_slashings.push(0);
    assert!(!BeaconBlockBodyPqView::check_canonical(&body.encode()));
}
