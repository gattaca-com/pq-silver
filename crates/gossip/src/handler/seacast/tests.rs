//! Two handlers, each the other's peer 1, exchanging the frames they emit.

use std::time::{Duration, Instant};

use buffa::{MessageView, encoding::decode_varint};
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
    let mut attestation = vec![0; ATTESTATION_PQ_FIXED + 1];
    attestation[..4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
    attestation[4..12].copy_from_slice(&SLOT.to_le_bytes());
    attestation[20..52].copy_from_slice(&BLOCK_ROOT);
    // An empty bitlist is its delimiter bit.
    attestation[ATTESTATION_PQ_FIXED] = 1;
    let (fixed, proof_at) = (8 + 4 + 4, 8 + 4 + 4 + attestation.len());
    let mut ssz = noise(len);
    ssz[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
    let message = &mut ssz[SIGNED_PQ_FIXED..];
    message[8..12].copy_from_slice(&(fixed as u32).to_le_bytes());
    message[12..16].copy_from_slice(&(proof_at as u32).to_le_bytes());
    message[fixed..proof_at].copy_from_slice(&attestation);
    assert!(SignedAggregateAndProofPqView::check_size(&ssz));
    assert_eq!(aggregate_context(&ssz), Some(context(SLOT, &BLOCK_ROOT)));
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
    // Every chunk names the body's slot and block, and the group key at that
    // slot (`seacast-lite.md` §1, §2).
    let mut named = 0;
    run(&mut a, &mut b, now, |frame| {
        for chunk in chunks(frame) {
            let f = split_chunk(&chunk).unwrap();
            assert_eq!((f.slot, f.beacon_block_root), (SLOT, &BLOCK_ROOT[..]));
            assert_eq!(f.group, group_key(&group_id(&f.descriptor), SLOT));
            named += 1;
        }
        keep(frame)
    });
    assert!(named > 0);

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
