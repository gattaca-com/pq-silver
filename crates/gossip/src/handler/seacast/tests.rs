//! Two handlers, each the other's peer 1, exchanging the frames they emit.

use std::time::{Duration, Instant};

use buffa::{MessageView, encoding::decode_varint};
use seacast_codec::build_merkle_layers;
use seacast_gossipsub::{build_chunk, group_key};
use silver_common::{
    ForkName, GossipDomain, GossipTopic, PeerControl, TCache, TCacheId, TCacheProducer,
    TCacheTable, TProducer,
    ssz_view::{
        ATTESTATION_PQ_FIXED, EXECUTION_PAYLOAD_ENVELOPE_MIN, SIGNED_PQ_FIXED,
        SignedAggregateAndProofPqView, SignedExecutionPayloadEnvelopePqView,
    },
};

use super::*;

const DOMAIN: GossipDomain = GossipDomain::new([7; 4], ForkName::Pq);
const PEER: usize = 1;
const SLOT: u64 = 9;
const BLOCK_ROOT: [u8; 32] = [0xb1; 32];

struct Node {
    handler: GossipHandler,
    /// What the handler emitted and has not been taken.
    events: Vec<GossipHandlerEvent>,
    _incoming: TProducer,
}

impl Node {
    fn new(now: Instant) -> Self {
        let incoming = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
        let protobuf = TCache::producer(TCacheId::ControlGossip, 1 << 26);
        let mut handler = GossipHandler::new(
            TCacheTable::from_iter([incoming.cache_ref(), protobuf.cache_ref()]),
            TCache::producer(TCacheId::ControlProcessing, 1 << 26),
            protobuf,
            Some(DOMAIN),
        )
        .unwrap();
        handler.open_tcaches().unwrap();
        handler.seacast.peers.insert(PEER, [PEER as u8; 32]);
        handler.set_subscriptions(KINDS.map(|kind| (kind.segments, DOMAIN.digest())));
        let mut node = Self { handler, events: Vec::new(), _incoming: incoming };
        node.tick(now);
        node.handler.seacast_clock(SLOT, now, Duration::from_secs(12));
        // The subscriptions announced at connection, and our GRAFT.
        node.handler.handle_peer_control(PeerControl::P2pGossipAnnounceSubscriptions {
            p2p_connection: PEER,
        });
        for kind in &KINDS {
            node.handler.seacast_mesh(PEER, kind.segments, DOMAIN.digest(), true);
        }
        node
    }

    fn tick(&mut self, now: Instant) {
        let events = &mut self.events;
        self.handler.seacast_tick(now, &mut |e| events.push(e));
    }

    /// The frames emitted since the last call, each without its length.
    fn frames(&mut self) -> Vec<Vec<u8>> {
        while let Some(event) = self.handler.pop_event() {
            self.events.push(event);
        }
        let mut frames = Vec::new();
        self.events.retain(|event| {
            let GossipHandlerEvent::SendGossip(out) = event else {
                return true;
            };
            assert_eq!(out.peer_id, PEER);
            let mut bytes = self.handler.mcache_publish.read_buffer(out.tcache).unwrap();
            let len = decode_varint(&mut bytes).unwrap() as usize;
            assert_eq!(bytes.len(), len);
            frames.push(bytes.to_vec());
            false
        });
        frames
    }

    fn receive(&mut self, frame: &[u8], now: Instant) {
        let rpc = RPCView::decode_view(frame).unwrap();
        let events = &mut self.events;
        self.handler.seacast_rpc(PEER, &rpc, now, &mut |e| events.push(e));
    }

    /// The bodies handed on as received on `topic`, and whether each is to
    /// be forwarded whole.
    fn delivered(&mut self, topic: GossipTopic) -> Vec<(Vec<u8>, bool)> {
        let mut bodies = Vec::new();
        self.events.retain(|event| {
            let GossipHandlerEvent::NewGossip(msg) = event else {
                return true;
            };
            assert_eq!(msg.topic, topic);
            let ssz = self.handler.incoming_gossip_publish.read_buffer(msg.ssz).unwrap().to_vec();
            bodies.push((ssz, msg.protobuf.is_some()));
            false
        });
        bodies
    }

    fn penalties(&self) -> usize {
        self.events.iter().filter(|e| matches!(e, GossipHandlerEvent::PeerEvent(_))).count()
    }
}

/// Bytes that do not compress.
fn noise(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// A PQ envelope of `len` bytes for the block at `SLOT`: the rest of its
/// message is the payload, and the execution requests are empty.
fn envelope(len: usize) -> Vec<u8> {
    let mut ssz = noise(len);
    ssz[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
    let message = &mut ssz[SIGNED_PQ_FIXED..];
    let requests_at = message.len() as u32;
    message[..4].copy_from_slice(&(EXECUTION_PAYLOAD_ENVELOPE_MIN as u32).to_le_bytes());
    message[4..8].copy_from_slice(&requests_at.to_le_bytes());
    message[16..48].copy_from_slice(&BLOCK_ROOT);
    let slot_at = EXECUTION_PAYLOAD_ENVELOPE_MIN + EXECUTION_PAYLOAD_FIXED_GLOAS - 8;
    message[slot_at..slot_at + 8].copy_from_slice(&SLOT.to_le_bytes());
    assert!(SignedExecutionPayloadEnvelopePqView::check_size(&ssz));
    assert_eq!(envelope_context(&ssz), Some(context(SLOT, &BLOCK_ROOT)));
    ssz
}

/// A PQ signed aggregate of `len` bytes for the block at `SLOT`: its
/// attestation sets no bit, and its proof is the rest.
fn aggregate(len: usize) -> Vec<u8> {
    aggregate_of(len, 1)
}

/// The same with `bits` as its `aggregation_bits`, delimiter included.
fn aggregate_of(len: usize, bits: u8) -> Vec<u8> {
    let mut attestation = vec![0; ATTESTATION_PQ_FIXED + 1];
    attestation[..4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
    attestation[4..12].copy_from_slice(&SLOT.to_le_bytes());
    attestation[20..52].copy_from_slice(&BLOCK_ROOT);
    attestation[ATTESTATION_PQ_FIXED] = bits;
    let (fixed, proof_at) = (8 + 4 + 4, 8 + 4 + 4 + attestation.len());
    let mut ssz = noise(len);
    ssz[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
    let message = &mut ssz[SIGNED_PQ_FIXED..];
    message[8..12].copy_from_slice(&(fixed as u32).to_le_bytes());
    message[12..16].copy_from_slice(&(proof_at as u32).to_le_bytes());
    message[fixed..proof_at].copy_from_slice(&attestation);
    assert!(SignedAggregateAndProofPqView::check_size(&ssz));
    let claim = claim_of(&aggregate_meta(&ssz).unwrap());
    assert_eq!((&claim[..8], claim[VOTES_AT]), (&SLOT.to_le_bytes()[..], bits));
    assert!(claim[VOTES_AT + 1..].iter().all(|&bits| bits == 0));
    ssz
}

/// Runs both nodes for a part of the slot. `keep` says
/// whether a frame from the source arrives.
fn run(a: &mut Node, b: &mut Node, start: Instant, mut keep: impl FnMut(&[u8]) -> bool) -> Instant {
    let mut now = start;
    for _ in 0..60 {
        now += Duration::from_millis(50);
        a.tick(now);
        b.tick(now);
        let (to_b, to_a) = (a.frames(), b.frames());
        for frame in &to_b {
            if keep(frame) {
                b.receive(frame, now);
            }
        }
        for frame in &to_a {
            a.receive(frame, now);
        }
    }
    now
}

fn is_chunk(frame: &[u8]) -> bool {
    RPCView::decode_view(frame).is_ok_and(|rpc| (&rpc.publish).into_iter().next().is_some())
}

/// The chunks a frame carries, decompressed.
fn chunks(frame: &[u8]) -> Vec<Vec<u8>> {
    let Ok(rpc) = RPCView::decode_view(frame) else {
        return Vec::new();
    };
    let mut decoder = snap::raw::Decoder::new();
    (&rpc.publish)
        .into_iter()
        .filter_map(|message| message.data)
        .map(|data| decoder.decompress_vec(data).unwrap())
        .collect()
}

/// An envelope of `len` bytes from one node to the other, as chunks alone.
fn crosses(len: usize, keep: impl FnMut(&[u8]) -> bool) {
    body_crosses(GossipTopic::ExecutionPayload, envelope(len), false, keep);
}

/// `ssz` of `topic` from one node to the other. `whole`: it is also to be
/// sent and forwarded whole.
fn body_crosses(
    topic: GossipTopic,
    ssz: Vec<u8>,
    whole: bool,
    mut keep: impl FnMut(&[u8]) -> bool,
) {
    let start = Instant::now();
    let (mut a, mut b) = (Node::new(start), Node::new(start));
    let now = run(&mut a, &mut b, start, |_| true);

    assert_eq!(a.handler.seacast_publish(topic, &ssz), !whole);
    // A payload's chunk carries the body's context, and the group key at its
    // slot (`seacast-lite.md` §1, §2). An aggregate's carries none: its claim
    // goes before the first frame to the peer, and before no other.
    let kind = KINDS.iter().find(|kind| kind.whole == topic).unwrap();
    let context = (kind.context)(&ssz).unwrap();
    let claim = kind.meta.map(|meta| meta(&ssz).unwrap());
    let (mut named, mut claims) = (0, 0);
    run(&mut a, &mut b, now, |frame| {
        for chunk in chunks(frame) {
            let (attachment, chunk) = match kind.layout {
                Layout::Payload => (&[][..], &chunk[..]),
                Layout::Attached => split_attached(&chunk).unwrap(),
            };
            let f = kind.layout.split(chunk, &[]).unwrap();
            let context = &context[..kind.layout.context_len()];
            assert_eq!(&chunk[..context.len()], context);
            assert_eq!(f.group, kind.layout.group_key(&group_id(&f.descriptor), context));
            if !attachment.is_empty() {
                assert_eq!(Some(attachment), claim.as_ref().map(|claim| &claim[..]));
                assert_eq!(named, 0);
                claims += 1;
            }
            named += 1;
        }
        keep(frame)
    });
    assert!(named > 0);
    assert_eq!(claims, claim.is_some() as usize);

    let delivered = b.delivered(topic);
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].0 == ssz);
    assert_eq!(delivered[0].1, whole);
    assert!(a.delivered(topic).is_empty());
    assert_eq!((a.penalties(), b.penalties()), (0, 0));
}

#[test]
fn a_coded_envelope_crosses_a_link() {
    crosses(300_000, |_| true);
}

/// Over the size that is coded, the envelope travels as its segments alone.
#[test]
fn an_uncoded_envelope_crosses_a_link() {
    crosses(3_000_000, |_| true);
}

/// An aggregate travels as chunks on its own topic, and whole beside them.
#[test]
fn an_aggregate_crosses_a_link() {
    body_crosses(GossipTopic::BeaconAggregateAndProof, aggregate(200_000), true, |_| true);
}

/// An aggregate whose votes one taken has is held, and taken once it is
/// whole and passes level 2. So is one with a vote more.
#[test]
fn a_covered_aggregate_is_taken_once_whole() {
    let topic = GossipTopic::BeaconAggregateAndProof;
    let start = Instant::now();
    let (mut a, mut b) = (Node::new(start), Node::new(start));
    let mut now = run(&mut a, &mut b, start, |_| true);
    // One vote, the same vote from another aggregator, then two votes. The
    // second is not ours to send: its frames are another's.
    for (len, bits, ours) in [(200_000, 0b11, true), (200_001, 0b11, false), (200_002, 0b111, true)]
    {
        let ssz = aggregate_of(len, bits);
        let mut sent = !ours;
        if ours {
            a.handler.seacast_publish(topic, &ssz);
        } else {
            for frame in aggregate_frames(&mut a, &ssz, false).0 {
                b.receive(&frame, now);
            }
        }
        now = run(&mut a, &mut b, now, |frame| {
            sent |= is_chunk(frame);
            true
        });
        assert!(sent);
        let delivered = b.delivered(topic);
        assert_eq!(delivered.len(), 1);
        assert!(delivered[0].0 == ssz);
        assert_eq!((a.penalties(), b.penalties()), (0, 0));
    }
}

/// With the aggregates' kind off the node has no topic for it: an aggregate
/// goes whole, its segment topic is left unsubscribed and its whole topic is
/// not.
#[test]
fn aggregates_off_go_whole() {
    let start = Instant::now();
    let mut node = Node::new(start);
    node.handler.set_seacast_aggregates(false);
    node.handler.seacast.core = None;
    node.tick(start);
    let topics = &node.handler.seacast.core.as_ref().unwrap().topics;
    assert_eq!(topics.len(), AGGREGATES);
    assert_eq!(topics[PAYLOADS].kind.segments, GossipTopic::ExecutionPayloadSegment);
    assert!(
        !node.handler.seacast_publish(GossipTopic::BeaconAggregateAndProof, &aggregate(200_000))
    );
    node.tick(start + Duration::from_millis(50));
    assert!(!node.frames().iter().any(|frame| is_chunk(frame)));
    assert!(node.handler.seacast_skips(GossipTopic::BeaconAggregateAndProofSegment));
    assert!(!node.handler.seacast_skips(GossipTopic::BeaconAggregateAndProof));
    assert!(node.handler.seacast_skips(GossipTopic::ExecutionPayload));
    assert!(!node.handler.seacast_skips(GossipTopic::ExecutionPayloadSegment));
}

/// A body whose slot and block cannot be read goes whole, as chunks never.
#[test]
fn an_envelope_without_its_block_goes_whole() {
    let mut ssz = envelope(300_000);
    let payload_at = SIGNED_PQ_FIXED..SIGNED_PQ_FIXED + 4;
    ssz[payload_at].copy_from_slice(&(EXECUTION_PAYLOAD_ENVELOPE_MIN as u32 + 1).to_le_bytes());
    let start = Instant::now();
    let mut node = Node::new(start);
    assert!(!node.handler.seacast_publish(GossipTopic::ExecutionPayload, &ssz));
    node.tick(start + Duration::from_millis(50));
    assert!(!node.frames().iter().any(|frame| is_chunk(frame)));
}

/// An envelope and an aggregate of one slot cross in the one node, with
/// every third chunk message lost: an ask and a holding name no topic, and
/// each is taken for the type whose store has its group.
#[test]
fn two_kinds_cross_in_one_node() {
    let start = Instant::now();
    let (mut a, mut b) = (Node::new(start), Node::new(start));
    let now = run(&mut a, &mut b, start, |_| true);
    let (envelope, aggregate) = (envelope(300_000), aggregate(200_000));
    a.handler.seacast_publish(GossipTopic::ExecutionPayload, &envelope);
    a.handler.seacast_publish(GossipTopic::BeaconAggregateAndProof, &aggregate);
    let mut seen = 0;
    run(&mut a, &mut b, now, |frame| {
        seen += is_chunk(frame) as usize;
        !is_chunk(frame) || seen % 3 != 0
    });
    let mut bodies = Vec::new();
    b.events.retain(|event| {
        let GossipHandlerEvent::NewGossip(msg) = event else {
            return true;
        };
        let ssz = b.handler.incoming_gossip_publish.read_buffer(msg.ssz).unwrap().to_vec();
        bodies.push((msg.topic, ssz));
        false
    });
    bodies.sort_by_key(|(topic, _)| *topic != GossipTopic::ExecutionPayload);
    assert_eq!(bodies, [
        (GossipTopic::ExecutionPayload, envelope),
        (GossipTopic::BeaconAggregateAndProof, aggregate)
    ]);
    assert_eq!((a.penalties(), b.penalties()), (0, 0));
}

/// Every third chunk message is lost: the receiver decodes from what
/// arrives, parity among it.
#[test]
fn a_coded_envelope_is_decoded_under_loss() {
    let mut seen = 0;
    crosses(300_000, |frame| {
        seen += is_chunk(frame) as usize;
        !is_chunk(frame) || seen % 3 != 0
    });
}

/// A chunk that names a block known at another slot is its sender's fault,
/// and its group is not assembled.
#[test]
fn a_chunk_for_a_block_of_another_slot_is_rejected() {
    for (block_slot, taken) in [(SLOT, true), (SLOT + 1, false)] {
        let start = Instant::now();
        let (mut a, mut b) = (Node::new(start), Node::new(start));
        let now = run(&mut a, &mut b, start, |_| true);
        b.handler.seacast_block(BLOCK_ROOT, block_slot);
        a.handler.seacast_publish(GossipTopic::ExecutionPayload, &envelope(300_000));
        run(&mut a, &mut b, now, |_| true);
        assert_eq!(b.delivered(GossipTopic::ExecutionPayload).len(), taken as usize);
        assert_eq!(b.penalties() == 0, taken);
    }
}

/// A group whose chunks name another slot than its body's completes and is
/// not handed on. No chunk of it is at fault.
#[test]
fn a_body_of_another_slot_than_its_chunks_is_not_delivered() {
    for (named, delivered) in [(SLOT, 1), (SLOT + 1, 0)] {
        let start = Instant::now();
        let mut node = Node::new(start);
        let ssz = envelope(300_000);
        let (d, shards) =
            build_group::<Vec<u8>, _, _>(&ssz, &mut VecBufferPool, &SnappyBlockCompressor);
        let context = context(named, &BLOCK_ROOT);
        let key = group_key(&group_id(&d), named);
        let topic = wire_topic(DOMAIN, GossipTopic::ExecutionPayloadSegment);
        let mut encoder = snap::raw::Encoder::new();
        for shard in &shards {
            let chunk = build_chunk(&context, &key, &d, shard.index, &shard.proof, &shard.data);
            let snappy = encoder.compress_vec(&chunk).unwrap();
            let publish = &mut node.handler.mcache_publish;
            let read = copy_compressed_to_protobuf_output(publish, &snappy, &topic).unwrap();
            let mut frame = publish.read_buffer(read).unwrap();
            decode_varint(&mut frame).unwrap();
            let frame = frame.to_vec();
            node.receive(&frame, start);
        }
        node.tick(start + Duration::from_millis(50));
        assert_eq!(node.delivered(GossipTopic::ExecutionPayload).len(), delivered);
        assert_eq!(node.penalties(), 0);
    }
}

/// The chunks of `ssz` as frames on the aggregates' topic, and the group's
/// key. `spoil`: one parity segment is not the code's, under a root that
/// commits to it.
fn aggregate_frames(node: &mut Node, ssz: &[u8], spoil: bool) -> (Vec<Vec<u8>>, [u8; 32]) {
    let (mut d, shards) =
        build_group::<Vec<u8>, _, _>(ssz, &mut VecBufferPool, &SnappyBlockCompressor);
    let mut segments: Vec<Vec<u8>> = shards.iter().map(|shard| shard.data.clone()).collect();
    if spoil {
        segments.last_mut().unwrap()[0] ^= 1;
    }
    let tree = build_merkle_layers(&segments);
    d.root = tree.root();
    let claim = aggregate_meta(ssz).unwrap();
    let layout = Layout::Attached;
    let key = layout.group_key(&group_id(&d), &[]);
    let topic = wire_topic(DOMAIN, GossipTopic::BeaconAggregateAndProofSegment);
    let mut encoder = snap::raw::Encoder::new();
    let frame = |(index, data): (usize, &Vec<u8>)| {
        let mut chunk = Vec::new();
        seacast_gossipsub::attach(&claim, &mut chunk);
        chunk.extend(layout.build(&[], &key, &d, index as u32, &tree.proof(index), data));
        let snappy = encoder.compress_vec(&chunk).unwrap();
        let publish = &mut node.handler.mcache_publish;
        let read = copy_compressed_to_protobuf_output(publish, &snappy, &topic).unwrap();
        let mut frame = publish.read_buffer(read).unwrap();
        decode_varint(&mut frame).unwrap();
        frame.to_vec()
    };
    (segments.iter().enumerate().map(frame).collect(), key)
}

fn held(node: &Node, key: &[u8; 32]) -> Option<bool> {
    node.handler.seacast.core.as_ref().unwrap().catalog.types[AGGREGATES].codec.store.held(key)
}

/// Of the aggregates of a slot and committee one is forwarded: the first,
/// until one with strictly more of the votes comes.
#[test]
fn the_aggregate_with_the_most_votes_is_forwarded() {
    let start = Instant::now();
    let mut node = Node::new(start);
    let bodies = [(0, 0b011), (1, 0b110), (2, 0b111), (3, 0b111)]
        .map(|(len, bits)| aggregate_of(200_000 + len, bits));
    let [first, other, more, same] =
        bodies.each_ref().map(|ssz| aggregate_frames(&mut node, ssz, false));
    node.receive(&first.0[0], start);
    node.receive(&other.0[0], start);
    assert_eq!([&first, &other].map(|(_, key)| held(&node, key)), [Some(false), Some(true)]);
    node.receive(&more.0[0], start);
    node.receive(&same.0[0], start);
    let groups = [&first, &other, &more, &same];
    assert_eq!(groups.map(|(_, key)| held(&node, key)), [true, true, false, true].map(Some));
}

/// When the aggregate forwarded fails level 2, the held one with the most
/// votes is forwarded in its place.
#[test]
fn the_next_best_aggregate_is_forwarded_when_the_best_fails() {
    let topic = GossipTopic::BeaconAggregateAndProof;
    let start = Instant::now();
    let mut node = Node::new(start);
    let bodies = [0b111, 0b001, 0b011].map(|bits| aggregate_of(200_000 + bits, bits as u8));
    let (best, best_key) = aggregate_frames(&mut node, &bodies[0], true);
    let (least, least_key) = aggregate_frames(&mut node, &bodies[1], false);
    let (next, next_key) = aggregate_frames(&mut node, &bodies[2], false);

    // The best is left one data segment short, for the code to compute from
    // the spoiled parity.
    node.receive(&best[1], start);
    node.receive(&least[0], start);
    node.receive(&next[0], start);
    let held_of = |node: &Node| [best_key, least_key, next_key].map(|key| held(node, &key));
    assert_eq!(held_of(&node), [false, true, true].map(Some));

    for frame in &best[2..] {
        node.receive(frame, start);
    }
    node.tick(start + Duration::from_millis(50));
    assert_eq!(held_of(&node), [true, true, false].map(Some));
    assert!(node.delivered(topic).is_empty());

    for frame in &next[1..] {
        node.receive(frame, start + Duration::from_millis(50));
    }
    node.tick(start + Duration::from_millis(100));
    let delivered = node.delivered(topic);
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].0 == bodies[2]);
}

/// When the aggregate forwarded passes level 2 it stands for its slot and
/// committee: no held one is forwarded in its place before its own level 2.
#[test]
fn no_aggregate_takes_the_place_of_one_that_passed() {
    let start = Instant::now();
    let mut node = Node::new(start);
    let bodies = [0b011, 0b110].map(|bits| aggregate_of(200_000 + bits, bits as u8));
    let (first, first_key) = aggregate_frames(&mut node, &bodies[0], false);
    let (other, other_key) = aggregate_frames(&mut node, &bodies[1], false);
    node.receive(&first[0], start);
    node.receive(&other[0], start);
    for frame in &first[1..] {
        node.receive(frame, start);
    }
    node.tick(start + Duration::from_millis(50));
    assert_eq!(node.delivered(GossipTopic::BeaconAggregateAndProof).len(), 1);
    assert_eq!([first_key, other_key].map(|key| held(&node, &key)), [false, true].map(Some));
}

/// An aggregate of ours is not sent as chunks where one held whole has its
/// votes. One with a vote more is.
#[test]
fn our_aggregate_is_not_sent_under_one_that_has_its_votes() {
    let topic = GossipTopic::BeaconAggregateAndProof;
    let start = Instant::now();
    let (mut a, mut b) = (Node::new(start), Node::new(start));
    let mut now = run(&mut a, &mut b, start, |_| true);
    for frame in aggregate_frames(&mut b, &aggregate_of(200_000, 0b0111), false).0 {
        a.receive(&frame, now);
    }
    now = run(&mut a, &mut b, now, |_| true);
    assert_eq!(a.delivered(topic).len(), 1);
    for (len, bits, ours) in
        [(200_001, 0b0011, false), (200_002, 0b0111, false), (200_003, 0b1111, true)]
    {
        a.handler.seacast_publish(topic, &aggregate_of(len, bits));
        let mut sent = false;
        now = run(&mut a, &mut b, now, |frame| {
            sent |= is_chunk(frame);
            true
        });
        assert_eq!(sent, ours, "{bits:b}");
    }
}

/// A held aggregate that is whole is decoded where it lies, and handed on
/// once it passes level 2. One that fails stays held.
#[test]
fn a_held_aggregate_is_taken_once_it_passes_level_2() {
    let topic = GossipTopic::BeaconAggregateAndProof;
    for (spoil, taken) in [(false, true), (true, false)] {
        let start = Instant::now();
        let mut node = Node::new(start);
        let (best, covered) = (aggregate_of(200_000, 0b111), aggregate_of(200_001, 0b011));
        let (best, _) = aggregate_frames(&mut node, &best, false);
        let (frames, key) = aggregate_frames(&mut node, &covered, spoil);
        node.receive(&best[0], start);
        // Without its first data segment, which the code computes.
        for frame in &frames[1..] {
            node.receive(frame, start);
        }
        node.tick(start + Duration::from_millis(50));
        assert_eq!(held(&node, &key), Some(!taken));
        let delivered = node.delivered(topic);
        assert_eq!(delivered.len(), taken as usize);
        assert!(delivered.iter().all(|(body, _)| *body == covered));
    }
}

/// A chunk's write is put off while its group is held, and made once the
/// group passes level 2. Failed, it is never made.
#[test]
fn the_writes_of_a_held_group_wait_for_its_level_2() {
    for passed in [true, false] {
        let start = Instant::now();
        let mut node = Node::new(start);
        let (best, covered) = (aggregate_of(200_000, 0b111), aggregate_of(200_001, 0b011));
        let (best, _) = aggregate_frames(&mut node, &best, false);
        let (frames, key) = aggregate_frames(&mut node, &covered, false);
        node.receive(&best[0], start);
        node.receive(&frames[3], start);

        let core = node.handler.seacast.core.as_mut().unwrap();
        let store = &mut core.catalog.types[AGGREGATES].codec.store;
        let at = store.find(&key).unwrap();
        let chunk = store.chunk(at, 3).unwrap();
        assert!(store.withheld(&chunk));
        store.defer(&chunk, PEER);
        assert_eq!(store.pop_deferred(), None);
        store.settle(at, passed);
        assert_eq!(store.pop_deferred(), passed.then_some((PEER, chunk)));
        assert_eq!(store.pop_deferred(), None);
    }
}

/// An aggregate that passes level 2 after one that has its votes passed is
/// handed on to Beacon State and never forwarded. One with a vote more is
/// forwarded.
#[test]
fn an_aggregate_a_valid_one_covers_is_never_forwarded() {
    let topic = GossipTopic::BeaconAggregateAndProof;
    let start = Instant::now();
    let mut node = Node::new(start);
    let bodies = [(0, 0b0111), (1, 0b0011), (2, 0b0111), (3, 0b1001)]
        .map(|(len, bits)| aggregate_of(200_000 + len, bits));
    let mut now = start;
    let mut forwarded = Vec::new();
    for ssz in &bodies {
        let (frames, key) = aggregate_frames(&mut node, ssz, false);
        for frame in &frames[1..] {
            node.receive(frame, now);
        }
        now += Duration::from_millis(50);
        node.tick(now);
        let delivered = node.delivered(topic);
        assert_eq!(delivered.len(), 1);
        assert!(delivered[0].0 == *ssz);
        forwarded.push(held(&node, &key) == Some(false));
    }
    assert_eq!(forwarded, [true, false, false, true]);
}
