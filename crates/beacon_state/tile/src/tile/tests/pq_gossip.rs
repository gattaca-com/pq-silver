use silver_beacon_state_data::{
    AGGREGATORS_PER_COMMITTEE, BUILDER_INDEX_SELF_BUILD, EpochState, FinalizedValidators, Fork,
    HashFormat, ValidatorsGroup,
    pq::PQ_FORK_VERSION,
    xmss::{
        LeafOffset, SignatureCheck, compute_xmss_attestation_leaf_index, compute_xmss_leaf_index,
    },
};
use silver_common::{
    ForkName, GossipDomain, LeanVmReq, ProposerPreparation, SlotSubnets,
    compute_subnet_for_attestation,
    ssz_hash::hash_attestation_data,
    ssz_view::{
        BEACON_BLOCK_HEADER_SIZE, EXECUTION_PAYLOAD_ENVELOPE_MIN, EXECUTION_PAYLOAD_FIXED_GLOAS,
        PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE, PROPOSER_PREFERENCES_SIZE, PROPOSER_SLASHING_PQ_SIZE,
        SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE, SIGNED_PQ_FIXED, SIGNED_PROPOSER_PREFERENCES_PQ_SIZE,
        SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE, XMSSPubkey,
    },
};
use silver_crypto_simd::xmss::SecretKey;
use silver_slashing::Selection;
use silver_ssz::ssz_view::{AttestationPqView, SingleAttestationPqView};

use super::*;
use crate::tile::leanvm_verifier::LeanVmVerifier;

const VALIDATORS: usize = 128;

fn pq_spec() -> SpecConfig {
    SpecConfig {
        fulu_fork_epoch: 0,
        gloas_fork_epoch: 0,
        pq_fork_epoch: 0,
        ..SpecConfig::mainnet()
    }
}

fn xmss_validator(pubkey: &XMSSPubkey) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(pubkey);
    record.extend_from_slice(&[0; 32 + 32]);
    record.extend_from_slice(&MAX_EFFECTIVE_BALANCE.to_le_bytes());
    record.push(0);
    for epoch in [0, 0, u64::MAX, u64::MAX] {
        record.extend_from_slice(&epoch.to_le_bytes());
    }
    record
}

fn pq_tile(
    pubkey: &XMSSPubkey,
    slot: Slot,
    wall_slot: Slot,
) -> (BeaconStateTile, TProducer, TestSpine, SpineAdapter<SilverSpine>) {
    let (mut tile, gossip, _rpc, spine, adapter) =
        tile_with_producers_on(wall_slot, BeaconState::empty_test(0), pq_spec());
    let checkpoint = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
    let epoch_base = EpochStateFinalized::from_state(EpochState {
        fork: Fork {
            previous_version: PQ_FORK_VERSION,
            current_version: PQ_FORK_VERSION,
            epoch: 0,
        },
        current_justified_checkpoint: checkpoint,
        finalized_checkpoint: checkpoint,
        ..Default::default()
    });
    let (_, seeds) = build_seed_finalized(VALIDATORS, false);
    let mut state = BeaconState::for_test(epoch_base, &seeds, slot);
    state.validators = ValidatorsGroup::new(
        FinalizedValidators::try_new_xmss(&xmss_validator(pubkey).repeat(VALIDATORS)).unwrap(),
        HashFormat::Progressive,
    );
    arm_tile_state(&mut tile, state, &seeds, slot);
    (tile, gossip, spine, adapter)
}

fn pq_gossip_msg(
    tile: &BeaconStateTile,
    gossip: &mut TProducer,
    bytes: &[u8],
    topic: GossipTopic,
) -> NewGossipMsg {
    let mut msg = gossip_msg(gossip, bytes, topic);
    msg.domain = GossipDomain::new(tile.spec.fork_digest_at(0, &[0; 32]), ForkName::Pq);
    msg
}

fn domain(domain_type: u32) -> B256 {
    bls::compute_domain(domain_type, PQ_FORK_VERSION, &[0; 32])
}

fn gossip_verdicts(adapter: &mut SpineAdapter<SilverSpine>) -> (usize, usize) {
    let mut verdicts = (0, 0);
    adapter.consume(|event: PeerEvent, _| match event {
        PeerEvent::SendGossip { .. } => verdicts.0 += 1,
        PeerEvent::P2pGossipInvalidMsg { .. } => verdicts.1 += 1,
        _ => {}
    });
    verdicts
}

#[test]
fn preferences_are_accepted_only_at_their_own_leaf() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, 0, 0);
    adapter.consume(|_: PeerEvent, _| {});

    let mut signed = [0u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE];
    signed[..32].copy_from_slice(&ANCHOR_ROOT);
    signed[32..40].copy_from_slice(&1u64.to_le_bytes());
    let domain = domain(bls::DOMAIN_PROPOSER_PREFERENCES);
    let check = SignatureCheck::proposer_preferences(&signed, &pubkey, &domain);
    let (own_leaf, signing_root) = (check.leaf_index, check.signing_root);
    let bottom = key.bottom_tree((own_leaf >> 16) as u32);

    let proposer_leaf = compute_xmss_leaf_index(1, LeafOffset::BeaconProposer);
    for (leaf, accepted) in [(proposer_leaf, false), (own_leaf, true)] {
        signed[PROPOSER_PREFERENCES_SIZE..].copy_from_slice(&key.sign(
            &bottom,
            &signing_root,
            leaf as u32,
        ));
        let msg = pq_gossip_msg(&tile, &mut gossip, &signed, GossipTopic::ProposerPreferences);
        tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);

        assert_eq!(tile.seen_proposer_preferences.contains(1, &ANCHOR_ROOT), accepted);
        let verdicts = gossip_verdicts(&mut adapter);
        assert_eq!(verdicts, if accepted { (1, 0) } else { (0, 1) });
    }
}

/// `validator`'s vote for `block_root`, with the anchor as its target, signed
/// at the attestation leaf of `leaf_epoch`, and its subnet.
fn signed_attestation(
    tile: &BeaconStateTile,
    key: &SecretKey,
    validator: u32,
    leaf_epoch: Epoch,
    block_root: B256,
) -> ([u8; SINGLE_ATT_PQ_SIZE], u64) {
    let (att_slot, committee, _, _) = find_committee_for(tile, validator);
    let mut buf = [0u8; SINGLE_ATT_PQ_SIZE];
    buf[..8].copy_from_slice(&(committee as u64).to_le_bytes());
    buf[8..16].copy_from_slice(&u64::from(validator).to_le_bytes());
    buf[16..24].copy_from_slice(&att_slot.to_le_bytes());
    buf[32..64].copy_from_slice(&block_root);
    buf[112..144].copy_from_slice(&ANCHOR_ROOT);
    let signing_root = bls::compute_signing_root(
        &hash_attestation_data(&buf[16..144]),
        &domain(bls::DOMAIN_BEACON_ATTESTER),
    );
    let leaf = compute_xmss_attestation_leaf_index(leaf_epoch);
    let bottom = key.bottom_tree((leaf >> 16) as u32);
    buf[144..].copy_from_slice(&key.sign(&bottom, &signing_root, leaf as u32));

    let view = tile.state.read_view(tile.canonical_state_id());
    let mut indices = Vec::new();
    let shuffling = stf::EpochShuffling::from_state(&view, 0, &mut indices);
    let subnet = compute_subnet_for_attestation(
        ForkName::Pq,
        shuffling.committees_per_slot as u64,
        att_slot,
        committee as u64,
    );
    (buf, subnet)
}

#[test]
fn batched_votes_count_only_when_signed_at_their_leaf() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, 0, 31);
    adapter.consume(|_: PeerEvent, _| {});
    let root = tile.head_block_root();
    assert_eq!(root, ANCHOR_ROOT);

    for (validator, leaf_epoch) in [(0, 0), (1, 1)] {
        let (bytes, subnet) = signed_attestation(&tile, &key, validator, leaf_epoch, root);
        let topic = GossipTopic::BeaconAttestation(subnet);
        let msg = pq_gossip_msg(&tile, &mut gossip, &bytes, topic);
        tile.on_gossip(msg, &mut adapter.producers);
    }
    assert_eq!(gossip_verdicts(&mut adapter), (0, 0), "votes wait for the flush");

    tile.flush_votes(&mut adapter.producers);
    assert_eq!(gossip_verdicts(&mut adapter), (1, 1));
    assert!(tile.seen_attesters.contains(0, 0) && !tile.seen_attesters.contains(0, 1));
    assert_eq!(voted_weight(&mut tile, root), MAX_EFFECTIVE_BALANCE);
}

#[test]
fn accepted_local_vote_is_announced_with_its_slot_and_block() {
    let key = SecretKey::new(&[7; 32]);
    let (mut tile, mut gossip, mut spine, mut adapter) = pq_tile(&key.public_key(), 0, 31);
    let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
    sink.consume(|_: BeaconStateEvent, _| {});
    let root = tile.head_block_root();

    let mut local_slot = 0;
    for (validator, local) in [(0, false), (1, true)] {
        let (bytes, subnet) = signed_attestation(&tile, &key, validator, 0, root);
        let topic = GossipTopic::BeaconAttestation(subnet);
        let mut msg = pq_gossip_msg(&tile, &mut gossip, &bytes, topic);
        if local {
            msg.stream_id = LOCAL_GOSSIP_STREAM_ID;
            local_slot = SingleAttestationPqView::data(&bytes).slot();
        }
        tile.on_gossip(msg, &mut adapter.producers);
    }
    tile.flush_votes(&mut adapter.producers);

    let mut announced = Vec::new();
    sink.consume(|event: BeaconStateEvent, _| {
        if let BeaconStateEvent::LocalAttestation { slot, block_root } = event {
            announced.push((slot, block_root));
        }
    });
    assert_eq!(announced, [(local_slot, root)], "only the local vote");
}

/// A vote counts against the peer that delivered it once half of its slot
/// has passed. A local vote has no peer.
#[test]
fn vote_past_half_of_its_slot_is_reported_late_for_its_peer() {
    let key = SecretKey::new(&[7; 32]);
    let late_events = |ms_into_slot: u64, local: bool| {
        let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&key.public_key(), 0, 31);
        adapter.consume(|_: PeerEvent, _| {});
        let root = tile.head_block_root();
        let (bytes, subnet) = signed_attestation(&tile, &key, 0, 0, root);
        let slot = SingleAttestationPqView::data(&bytes).slot();
        tile.ticker.set_since_genesis_ms(slot * 12_000 + ms_into_slot);
        let mut msg =
            pq_gossip_msg(&tile, &mut gossip, &bytes, GossipTopic::BeaconAttestation(subnet));
        if local {
            msg.stream_id = LOCAL_GOSSIP_STREAM_ID;
        }
        let peer = msg.stream_id.peer();
        tile.on_gossip(msg, &mut adapter.producers);
        tile.flush_votes(&mut adapter.producers);
        let mut late = Vec::new();
        adapter.consume(|event: PeerEvent, _| {
            if let PeerEvent::LateAttestation { p2p_peer } = event {
                late.push(p2p_peer == peer);
            }
        });
        late
    };
    assert!(late_events(6_000, false).is_empty(), "half a slot in is still on time");
    assert_eq!(late_events(6_001, false), [true]);
    assert!(late_events(6_001, true).is_empty(), "a local vote");
}

#[test]
fn payload_attestation_is_accepted_only_at_its_own_leaf() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let slot = 31;
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, slot, slot);
    adapter.consume(|_: PeerEvent, _| {});

    let mut message = [0u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE];
    message[8..40].copy_from_slice(&tile.head_block_root());
    message[40..48].copy_from_slice(&slot.to_le_bytes());
    let domain = domain(bls::DOMAIN_PTC_ATTESTER);
    let check = SignatureCheck::payload_attestation_message(&message, &pubkey, &domain);
    let (own_leaf, signing_root) = (check.leaf_index, check.signing_root);
    let bottom = key.bottom_tree((own_leaf >> 16) as u32);

    let proposer_leaf = compute_xmss_leaf_index(slot, LeafOffset::BeaconProposer);
    for (leaf, accepted) in [(proposer_leaf, false), (own_leaf, true)] {
        message[50..].copy_from_slice(&key.sign(&bottom, &signing_root, leaf as u32));
        let msg =
            pq_gossip_msg(&tile, &mut gossip, &message, GossipTopic::PayloadAttestationMessage);
        tile.on_gossip(msg, &mut adapter.producers);
        tile.flush_votes(&mut adapter.producers);
        assert_eq!(gossip_verdicts(&mut adapter), if accepted { (1, 0) } else { (0, 1) });
        assert_eq!(tile.seen_ptc.contains(slot, 0), accepted);
    }
}

#[test]
fn proposer_slashing_needs_both_signatures() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, 0, 0);
    adapter.consume(|_: PeerEvent, _| {});

    let mut slashing = [0u8; PROPOSER_SLASHING_PQ_SIZE];
    slashing[SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE + 16] = 1;
    let checks =
        SignatureCheck::proposer_slashing(&slashing, &pubkey, &domain(bls::DOMAIN_BEACON_PROPOSER));
    let bottom = key.bottom_tree((checks[0].leaf_index >> 16) as u32);
    let [first, second] =
        checks.map(|check| key.sign(&bottom, &check.signing_root, check.leaf_index as u32));

    for (second, accepted) in [(first, false), (second, true)] {
        slashing[BEACON_BLOCK_HEADER_SIZE..][..XMSS_SIGNATURE_SIZE].copy_from_slice(&first);
        slashing[SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE + BEACON_BLOCK_HEADER_SIZE..]
            .copy_from_slice(&second);
        let msg = pq_gossip_msg(&tile, &mut gossip, &slashing, GossipTopic::ProposerSlashing);
        tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
        assert_eq!(gossip_verdicts(&mut adapter), if accepted { (1, 0) } else { (0, 1) });
        assert_eq!(tile.seen_proposer_slashings.contains(0), accepted);
    }

    let mut selection = Selection::default();
    tile.slashing_pool.select(&tile.state.read_view(tile.canonical_state_id()), &mut selection);
    assert_eq!(selection.proposer_slashings(), slashing, "pooled for a block");
}

/// A vote for a block not yet seen waits for it unrelayed, then counts in
/// fork choice and reaches the aggregator of its subnet.
#[test]
fn unknown_root_vote_is_merged_once_its_block_imports() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let wall_slot = 31;
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, 0, wall_slot);
    let now = tile.ticker.slot_start(wall_slot).as_millis_u64() + 1_000;
    tile.ticker.set_since_genesis_ms(now);
    tile.unknown_root_pq_votes.on_slot(wall_slot);
    adapter.consume(|_: PeerEvent, _| {});
    adapter.consume(|_: SyncNeed, _| {});
    adapter.consume(|_: LeanVmReq, _| {});
    let validator = (0..VALIDATORS as u32)
        .find(|&validator| find_committee_for(&tile, validator).0 == wall_slot)
        .expect("a validator attests at the wall slot");
    let late = [0x42; 32];
    let (bytes, subnet) = signed_attestation(&tile, &key, validator, 0, late);
    let mut subscription = [0; SlotSubnets::SIZE];
    let aggregator_positions = SlotSubnets::position_bit(subnet, 0);
    SlotSubnets {
        slot: wall_slot,
        attesting: 1 << subnet,
        aggregating: 1 << subnet,
        aggregator_positions,
    }
    .encode(&mut subscription);
    tile.aggregator_subnets.record(&subscription);
    tile.pq_aggregator.on_prover_ready();

    let msg = pq_gossip_msg(&tile, &mut gossip, &bytes, GossipTopic::BeaconAttestation(subnet));
    tile.on_gossip(msg, &mut adapter.producers);
    tile.flush_votes(&mut adapter.producers);
    assert_eq!(gossip_verdicts(&mut adapter), (0, 0), "held, neither relayed nor rejected");
    let buffered =
        |tile: &BeaconStateTile| tile.unknown_root_pq_votes.next_with_known_block(0, |_| true);
    assert!(buffered(&tile).is_some());
    let mut needs = Vec::new();
    adapter.consume(|need: SyncNeed, _| needs.push(need));
    assert_eq!(needs, [SyncNeed::missing_block(late, wall_slot)]);
    let mut requests = 0;
    adapter.consume(|_: LeanVmReq, _| requests += 1);
    assert_eq!(requests, 0);

    tile.fork_choice
        .on_block(BlockImport { slot: wall_slot, ..anchor_child(late, tile.last_applied) });
    tile.promote_unknown_root_votes(&mut adapter.producers);
    tile.pq_aggregator.send_next(&tile.ticker, &mut tile.events_producer, &mut adapter.producers);
    let validator_count = tile.head_validator_count();
    tile.fork_choice.drain_pending_votes(validator_count, wall_slot + 1);
    assert_eq!(voted_weight(&mut tile, late), MAX_EFFECTIVE_BALANCE);
    assert!(buffered(&tile).is_none(), "promoted once");
    adapter.consume(|_: LeanVmReq, _| requests += 1);
    assert_eq!(requests, 1, "the vote goes to the prover");
}

const AGGREGATE_SLOT: Slot = 2 * SLOTS_PER_EPOCH;
/// In a `SignedAggregateAndProof`: its message, the aggregate's offset, then
/// the attestation data.
const SOURCE_ROOT_AT: usize = SIGNED_PQ_FIXED + 16 + 4 + 56;

struct PqAggregate {
    signed: Vec<u8>,
    aggregator: usize,
    attesters: u64,
    block_root: B256,
}

impl PqAggregate {
    fn of_committee_zero(tile: &mut BeaconStateTile) -> Self {
        Self::of_committee_zero_votes(tile, usize::MAX)
    }

    /// The first `votes` positions of committee zero, or all it has.
    fn of_committee_zero_votes(tile: &mut BeaconStateTile, votes: usize) -> Self {
        let stub = tile.last_applied;
        let state_id = tile.epoch_start_state(stub, AGGREGATE_SLOT);
        let view = tile.state.read_view(state_id);
        let root = ShufflingId::from_state(&view, 2).unwrap().dependent_root;
        // The anchor as an import leaves it: its header's root is its latest
        // block root.
        let anchor = {
            let mut state = tile.state.write();
            let mut slot_state = state.slot_states.roll_from(stub.slot_idx);
            slot_state.state_mut().latest_block_root = root;
            StateId { slot_idx: slot_state.commit(), ..stub }
        };
        let state_id = tile.epoch_start_state(anchor, AGGREGATE_SLOT);
        let view = tile.state.read_view(state_id);
        let checkpoint = Checkpoint { epoch: 0, root };
        tile.fork_choice = ForkChoice::init(
            checkpoint,
            checkpoint,
            0,
            root,
            ANCHOR_STATE_ROOT,
            [0; 32],
            false,
            anchor,
            VALIDATORS,
        );
        let aggregator = (0..VALIDATORS as u64)
            .find(|&validator| view.is_aggregator(AGGREGATE_SLOT, 0, validator) == Some(true))
            .expect("committee zero has an aggregator");
        let mut indices = Vec::new();
        let epoch = AGGREGATE_SLOT / SLOTS_PER_EPOCH;
        let shuffling = stf::EpochShuffling::from_state(&view, epoch, &mut indices);
        let committee_len = shuffling.committee(AGGREGATE_SLOT, 0).len();

        let mut data = [0u8; 128];
        data[..8].copy_from_slice(&AGGREGATE_SLOT.to_le_bytes());
        data[16..48].copy_from_slice(&root);
        data[56..88].copy_from_slice(&ANCHOR_ROOT);
        data[88..96].copy_from_slice(&epoch.to_le_bytes());
        data[96..].copy_from_slice(&root);
        let votes = votes.min(committee_len);
        let aggregate =
            AttestationPqView::encode_one_committee(&data, 0, committee_len, 0..votes).unwrap();

        let mut signed = vec![0; SIGNED_PQ_FIXED];
        signed[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
        signed.extend_from_slice(&aggregator.to_le_bytes());
        signed.extend_from_slice(&16u32.to_le_bytes());
        signed.extend_from_slice(&(16 + aggregate.len() as u32).to_le_bytes());
        signed.extend_from_slice(&aggregate);
        signed.extend_from_slice(b"proof");
        Self { signed, aggregator: aggregator as usize, attesters: votes as u64, block_root: root }
    }

    fn sign(&mut self, key: &SecretKey, leaf_offset: LeafOffset) {
        let pubkey = key.public_key();
        let domain = domain(bls::DOMAIN_AGGREGATE_AND_PROOF);
        let signing_root =
            SignatureCheck::aggregate_and_proof(&self.signed, &pubkey, &domain).signing_root;
        let leaf = compute_xmss_leaf_index(AGGREGATE_SLOT, leaf_offset);
        let bottom = key.bottom_tree((leaf >> 16) as u32);
        self.signed[4..SIGNED_PQ_FIXED].copy_from_slice(&key.sign(
            &bottom,
            &signing_root,
            leaf as u32,
        ));
    }
}

/// A local proposal can take a proven aggregate as its block proof.
/// This includes aggregates published by this node.
#[test]
fn a_proven_aggregate_serves_a_local_proposal() {
    let key = SecretKey::new(&[7; 32]);
    let block = AGGREGATE_SLOT + 2;
    let cases =
        [(true, false, true), (false, false, true), (true, true, true), (true, false, false)];
    for (local, published_here, justified_source) in cases {
        let (mut tile, mut gossip, _spine, mut adapter) =
            pq_tile(&key.public_key(), 0, AGGREGATE_SLOT + 1);
        adapter.consume(|_: LeanVmReq, _| {});
        let mut aggregate = PqAggregate::of_committee_zero_votes(&mut tile, 1);
        if !justified_source {
            aggregate.signed[SOURCE_ROOT_AT] ^= 1;
        }
        aggregate.sign(&key, LeafOffset::AggregateAndProof);
        tile.last_applied = tile.epoch_start_state(tile.last_applied, AGGREGATE_SLOT);
        let proposer = tile.proposer_on_head(block).expect("within the lookahead");
        if local {
            let mut preparation = [0; ProposerPreparation::SIZE];
            ProposerPreparation { validator_index: proposer, fee_recipient: [1; 20] }
                .encode(&mut preparation);
            tile.proposer_preparations.record(&preparation, 2);
            tile.set_pq_local_proposals();
        } else {
            // The target exists, so only the claims not kept leave it empty.
            tile.pq_aggregator.set_local_proposals(&[block], false, &tile.ticker);
        }

        assert_eq!(tile.proposes_locally(block), local);

        let signed = &aggregate.signed;
        let topic = GossipTopic::BeaconAggregateAndProof;
        let mut msg = pq_gossip_msg(&tile, &mut gossip, signed, topic);
        if published_here {
            msg.stream_id = LOCAL_GOSSIP_STREAM_ID;
        }
        tile.leanvm_verifier = LeanVmVerifier::Fixed(true);
        tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
        adapter.consume(|_: LeanVmReq, _| {});

        tile.pq_aggregator.on_prover_ready();
        let tcache = &mut tile.events_producer;
        tile.pq_aggregator.send_next(&tile.ticker, tcache, &mut adapter.producers);
        let mut requests = 0;
        adapter.consume(|_: LeanVmReq, _| requests += 1);
        assert_eq!(requests, 0, "one aggregate needs no request");
        let proof = tile.pq_aggregator.block_proof(block);
        assert_eq!(
            proof.is_some(),
            local && justified_source,
            "local {local}, published here {published_here}, justified source {justified_source}"
        );
        if let Some((attestations, proof)) = proof {
            assert_eq!((attestations.len(), proof), (1, &b"proof"[..]));
        }
    }
}

#[test]
fn aggregate_counts_only_once_signed_and_proven() {
    let key = SecretKey::new(&[7; 32]);
    let (mut tile, mut gossip, _spine, mut adapter) =
        pq_tile(&key.public_key(), 0, AGGREGATE_SLOT + 1);
    adapter.consume(|_: PeerEvent, _| {});
    let mut aggregate = PqAggregate::of_committee_zero(&mut tile);
    let mut send = |tile: &mut BeaconStateTile, adapter: &mut SpineAdapter<_>, signed: &[u8]| {
        let msg = pq_gossip_msg(tile, &mut gossip, signed, GossipTopic::BeaconAggregateAndProof);
        tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
        gossip_verdicts(adapter)
    };

    tile.leanvm_verifier = LeanVmVerifier::Fixed(true);
    aggregate.sign(&key, LeafOffset::BeaconProposer);
    let sent = send(&mut tile, &mut adapter, &aggregate.signed);
    assert_eq!(sent, (0, 1), "signed at another duty's leaf");

    aggregate.sign(&key, LeafOffset::AggregateAndProof);
    for valid in [false, true] {
        tile.leanvm_verifier = LeanVmVerifier::Fixed(valid);
        let verdicts = send(&mut tile, &mut adapter, &aggregate.signed);
        assert_eq!(verdicts, if valid { (1, 0) } else { (0, 1) });
        assert_eq!(tile.seen_aggregators.contains(2, aggregate.aggregator), valid);
        let weight = if valid { aggregate.attesters * MAX_EFFECTIVE_BALANCE } else { 0 };
        assert_eq!(voted_weight(&mut tile, aggregate.block_root), weight);
    }
    let resent = send(&mut tile, &mut adapter, &aggregate.signed);
    assert_eq!(resent, (0, 0), "already seen");

    aggregate.signed[SOURCE_ROOT_AT] ^= 1;
    aggregate.sign(&key, LeafOffset::AggregateAndProof);
    let second = send(&mut tile, &mut adapter, &aggregate.signed);
    assert_eq!(second, (0, 0), "aggregator already seen");
}

/// A PQ envelope that arrives before its block parks only once its signer's
/// XMSS signature verifies against the parent's registry.
#[test]
fn envelope_for_an_unseen_block_parks_only_with_its_signature() {
    let key = SecretKey::new(&[7; 32]);
    let pubkey = key.public_key();
    let (mut tile, mut gossip, _spine, mut adapter) = pq_tile(&pubkey, 0, 1);
    adapter.consume(|_: PeerEvent, _| {});

    let slot: Slot = 1;
    let block_root = [0xB1; 32];
    let requests_start = EXECUTION_PAYLOAD_ENVELOPE_MIN + EXECUTION_PAYLOAD_FIXED_GLOAS;
    let mut signed = vec![0; SIGNED_PQ_FIXED + requests_start + 8 * 4];
    signed[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
    let message = &mut signed[SIGNED_PQ_FIXED..];
    message[..4].copy_from_slice(&(EXECUTION_PAYLOAD_ENVELOPE_MIN as u32).to_le_bytes());
    message[4..8].copy_from_slice(&(requests_start as u32).to_le_bytes());
    message[8..16].copy_from_slice(&BUILDER_INDEX_SELF_BUILD.to_le_bytes());
    message[16..48].copy_from_slice(&block_root);
    message[48..80].copy_from_slice(&ANCHOR_ROOT);
    let payload = &mut message[EXECUTION_PAYLOAD_ENVELOPE_MIN..requests_start];
    for pos in [436, 504, 508, 528] {
        payload[pos..][..4].copy_from_slice(&(EXECUTION_PAYLOAD_FIXED_GLOAS as u32).to_le_bytes());
    }
    payload[532..540].copy_from_slice(&slot.to_le_bytes());
    for offset in message[requests_start..].chunks_exact_mut(4) {
        offset.copy_from_slice(&32u32.to_le_bytes());
    }

    let domain = domain(bls::DOMAIN_BEACON_BUILDER);
    let check = SignatureCheck::execution_payload_envelope(&signed, slot, &pubkey, &domain)
        .expect("a canonical PQ envelope");
    let (leaf, signing_root) = (check.leaf_index, check.signing_root);
    let bottom = key.bottom_tree((leaf >> 16) as u32);
    let wrong_leaf = compute_xmss_leaf_index(slot, LeafOffset::BeaconProposer);
    for (leaf, parked) in [(wrong_leaf, false), (leaf, true)] {
        signed[4..SIGNED_PQ_FIXED].copy_from_slice(&key.sign(&bottom, &signing_root, leaf as u32));
        let read = tile.reader.acquire(tcache_write(&mut gossip, &signed));
        let feedback = tile.handle_execution_payload_envelope(
            read,
            &signed,
            BlockSource::Gossip,
            &mut adapter.producers,
        );
        assert_eq!(matches!(feedback, Feedback::Reject { .. }), !parked);
        assert_eq!(tile.pending_envelopes.holds(&block_root), parked);
    }
}

/// A verified vote with no aggregator duty and an optional local block target.
/// A validator registered here proposes either way.
struct GapVote {
    tile: BeaconStateTile,
    adapter: SpineAdapter<SilverSpine>,
    _gossip: TProducer,
    _spine: TestSpine,
}

impl GapVote {
    const SLOT: Slot = 31;
    /// A block that may include the votes of `SLOT`.
    const WANTS_SLOT: Slot = Self::SLOT + 2;
    const UNKNOWN_ROOT: B256 = [0x42; 32];

    fn new(block: Option<Slot>, unknown_root: bool) -> Self {
        let key = SecretKey::new(&[7; 32]);
        let (mut tile, mut gossip, spine, mut adapter) = pq_tile(&key.public_key(), 0, Self::SLOT);
        tile.unknown_root_pq_votes.on_slot(Self::SLOT);
        adapter.consume(|_: PeerEvent, _| {});
        adapter.consume(|_: SyncNeed, _| {});
        adapter.consume(|_: LeanVmReq, _| {});
        let mut preparation = [0; ProposerPreparation::SIZE];
        ProposerPreparation { validator_index: 0, fee_recipient: [1; 20] }.encode(&mut preparation);
        tile.proposer_preparations.record(&preparation, 2);
        if let Some(block) = block {
            tile.pq_aggregator.set_local_proposals(&[block], false, &tile.ticker);
        }

        let validator = (0..VALIDATORS as u32)
            .find(|&validator| find_committee_for(&tile, validator).0 == Self::SLOT)
            .expect("a validator attests at the wall slot");
        let root = if unknown_root { Self::UNKNOWN_ROOT } else { tile.head_block_root() };
        let (bytes, subnet) = signed_attestation(&tile, &key, validator, 0, root);
        let msg = pq_gossip_msg(&tile, &mut gossip, &bytes, GossipTopic::BeaconAttestation(subnet));
        tile.on_gossip(msg, &mut adapter.producers);
        tile.flush_votes(&mut adapter.producers);
        Self { tile, adapter, _gossip: gossip, _spine: spine }
    }

    fn import_the_unknown_block(&mut self) {
        let tile = &mut self.tile;
        let block =
            BlockImport { slot: Self::SLOT, ..anchor_child(Self::UNKNOWN_ROOT, tile.last_applied) };
        tile.fork_choice.on_block(block);
        tile.promote_unknown_root_votes(&mut self.adapter.producers);
    }

    fn assert_buffered_attester_only(&mut self) {
        let buffer = &mut self.tile.unknown_root_pq_votes;
        let votes =
            buffer.take(buffer.next_with_known_block(0, |_| true).expect("a buffered vote"));
        assert_eq!(votes.attesters.len(), 1);
        assert!(votes.aggregated.is_empty());
    }

    fn requests_at_the_vote_gate(&mut self) -> usize {
        let tile = &mut self.tile;
        let gate = tile.ticker.pq_aggregate_due(Self::SLOT, AGGREGATORS_PER_COMMITTEE as u64 - 1);
        tile.ticker.set_since_genesis_ms(gate.as_millis_u64());
        tile.pq_aggregator.on_prover_ready();
        let tcache = &mut tile.events_producer;
        tile.pq_aggregator.send_next(&tile.ticker, tcache, &mut self.adapter.producers);
        let mut requests = 0;
        self.adapter.consume(|_: LeanVmReq, _| requests += 1);
        requests
    }
}

#[test]
fn a_vote_with_no_duty_is_stored_for_a_local_block_that_wants_its_slot() {
    let wants = Some(GapVote::WANTS_SLOT);
    assert_eq!(GapVote::new(wants, false).requests_at_the_vote_gate(), 1);
    let no_block = GapVote::new(None, false).requests_at_the_vote_gate();
    assert_eq!(no_block, 0, "no local block wants the slot");
}

#[test]
fn a_buffered_vote_with_no_duty_is_stored_once_its_block_imports() {
    let mut gap_vote = GapVote::new(Some(GapVote::WANTS_SLOT), true);
    gap_vote.import_the_unknown_block();
    assert_eq!(gap_vote.requests_at_the_vote_gate(), 1);
}

#[test]
fn the_buffer_keeps_no_vote_with_no_duty_without_a_block_that_can_include_it() {
    for proposal in [None, Some(GapVote::SLOT + 1)] {
        GapVote::new(proposal, true).assert_buffered_attester_only();
    }
}
