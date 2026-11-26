//! SEACAST on gossipsub (`seacast-bindings.md` §4) for the execution payload
//! envelope and the signed aggregate: a body is cut into Reed-Solomon coded
//! chunks, each a message on its chunk topic, and offers, holdings and asks
//! travel as strings among the ids of IHAVE, IDONTWANT and IWANT. The
//! payload's topic is Prysm's (`seacast-devnet`); the chunk's frame and the
//! group's key are `seacast-lite.md`'s `Chunk` and `group_key`. The
//! aggregates' topic has the same frame.
//!
//! One `seacast_core::SeacastNode` runs every chunk topic, each a type of its
//! own, on the control tile's thread with level 1 and level 2 inline. A chunk,
//! an IHAVE and a subscription name their topic, which gives the type; an
//! IWANT and an IDONTWANT entry name none and are of the type whose store has
//! the group. The mesh is the peer manager's: a peer is pushed to while it is
//! in the mesh of the chunk topic and subscribed to it. A decoded body is
//! handed on as a message received on the topic it is whole on.

mod host;
mod store;
mod wire;

use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use seacast_codec::{
    ChunkBytes, SnappyBlockCompressor, VecBufferPool, build_group, group_id, leaf_hash,
};
use seacast_core::{
    BoundedDeferredStore, ChunkId, ChunkMsg, DispatchOutcome, GroupId, NodeConfig, NodeId, PeerId,
    PenaltyReason, PreallocVec, Rpc, RuntimeEnv, SeacastNode, Shape, SourceOffers, SplitMix64,
    TimerEvent, TypeCodec, TypeId, ValidationResult,
};
use seacast_gossipsub::{
    CONTEXT_BYTES, Inbound, Layout, MAX_CHUNK_BYTES, MESSAGE_ID_BYTES, PayloadCatalog,
    PayloadCodec, TopicCatalogs, chunk_id_on, is_seacast, read_holding, read_offer, read_want,
    split_attached, topic_group, topic_join, write_entry,
};
use silver_common::{
    BroadcastValidation, ForkName, GossipDomain, GossipTopic, LOCAL_GOSSIP_STREAM_ID, MessageId,
    Nanos, NewGossipMsg, PeerEvent, SszCache, TCacheId, TCacheProducer, msg_id_valid_snappy,
    ssz_view::{
        ATTESTATION_DATA_SIZE, COMMITTEE_BITS_SIZE_PQ, EXECUTION_PAYLOAD_FIXED_GLOAS,
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, MAX_VALIDATORS_PER_COMMITTEE,
        SignedAggregateAndProofPqView, SignedExecutionPayloadEnvelopePqView, XMSS_SIGNATURE_SIZE,
    },
};

use self::{
    host::{Env, Host},
    store::{Buf, NoPool, Store, StoreCodec},
    wire::{Out, Scratch},
};
use super::GossipHandler;
use crate::{GossipHandlerEvent, generated::RPCView, message::copy_compressed_to_protobuf_output};

/// A kind of body that travels as chunks.
struct Kind {
    /// The chunks' topic, and the topic the body is a message of.
    segments: GossipTopic,
    whole: GossipTopic,
    cache: TCacheId,
    store_bytes: usize,
    /// Groups admitted in a slot. The store has room for one more, ours.
    groups_per_slot: usize,
    layout: Layout,
    /// The head of the frame of a local body's chunks, where the layout has
    /// one.
    context: fn(&[u8]) -> Option<Context>,
    /// What a local body's chunks carry beside the frame.
    meta: Option<fn(&[u8]) -> Option<Meta>>,
    /// The groups are ranked by their claims: of those of a slot and
    /// committee one is forwarded.
    covers: bool,
}

/// The head of a payload chunk's frame: `slot | beacon_block_root`.
pub(super) type Context = [u8; CONTEXT_BYTES];

/// What an aggregate's chunks carry beside the frame, to a peer that is not
/// known to have it: the aggregator's claim, as
///
/// ```text
///   version            uint8, = 1
///   aggregator_index   uint64
///   data               AttestationData
///   committee_bits     Bitvector[MAX_COMMITTEES_PER_SLOT_PQ]
///   aggregation_bits   the bitlist of one committee, zero padded
///   signature          the aggregate's own
/// ```
///
/// It is not part of a chunk. Nothing in it is verified here yet: it is its
/// sender's word until level 2, as the group's rank is. To hold it to the
/// aggregator the signature is to be checked over the message these fields
/// and the root of the proof give, by the tile that has the keys.
pub(super) const META_BYTES: usize =
    1 + 8 + ATTESTATION_DATA_SIZE + COMMITTEE_BITS_SIZE_PQ + META_BITS + XMSS_SIGNATURE_SIZE;
pub(super) type Meta = [u8; META_BYTES];
const META_VERSION: u8 = 1;
const META_BITS: usize = MAX_VALIDATORS_PER_COMMITTEE / 8 + 1;
const META_DATA_AT: usize = 1 + 8;
const META_COMMITTEE_AT: usize = META_DATA_AT + ATTESTATION_DATA_SIZE;
const META_SIGNATURE_AT: usize = META_COMMITTEE_AT + COMMITTEE_BITS_SIZE_PQ + META_BITS;

/// What ranks an aggregate: `slot | committee_bits | aggregation_bits`.
pub(super) const CLAIM_BYTES: usize = 8 + COMMITTEE_BITS_SIZE_PQ + META_BITS;
pub(super) type Claim = [u8; CLAIM_BYTES];
/// A message of the chunk topics at its longest.
const MAX_MESSAGE: usize = MAX_CHUNK_BYTES + 2 + META_BYTES;

fn context(slot: u64, block_root: &[u8; 32]) -> Context {
    let mut context = [0; CONTEXT_BYTES];
    context[..8].copy_from_slice(&slot.to_le_bytes());
    context[8..].copy_from_slice(block_root);
    context
}

/// An envelope's slot is its payload's `slot_number`, which the state
/// transition holds to the block's slot.
fn envelope_context(ssz: &[u8]) -> Option<Context> {
    if !SignedExecutionPayloadEnvelopePqView::check_size(ssz) {
        return None;
    }
    let message = SignedExecutionPayloadEnvelopePqView::message(ssz);
    if !ExecutionPayloadEnvelopeView::check_size(message) {
        return None;
    }
    let payload = ExecutionPayloadEnvelopeView::payload(message);
    (payload.len() >= EXECUTION_PAYLOAD_FIXED_GLOAS).then(|| {
        let block_root = ExecutionPayloadEnvelopeView::beacon_block_root(message);
        context(ExecutionPayloadView::slot_number(payload), block_root)
    })
}

/// An aggregate's frames have no context.
fn no_context(ssz: &[u8]) -> Option<Context> {
    SignedAggregateAndProofPqView::check_size(ssz).then_some([0; CONTEXT_BYTES])
}

/// The claim of a local aggregate. `None`: its votes are of more than one
/// committee, which a claim has no room for.
fn aggregate_meta(ssz: &[u8]) -> Option<Meta> {
    if !SignedAggregateAndProofPqView::check_size(ssz) {
        return None;
    }
    let bits = SignedAggregateAndProofPqView::agg_aggregation_bits(ssz);
    let mut meta = [0; META_BYTES];
    meta[0] = META_VERSION;
    meta[1..META_DATA_AT]
        .copy_from_slice(&SignedAggregateAndProofPqView::aggregator_index(ssz).to_le_bytes());
    // `Attestation`: the offset of its bits, then its data.
    let data = SignedAggregateAndProofPqView::aggregate(ssz).get(4..4 + ATTESTATION_DATA_SIZE)?;
    meta[META_DATA_AT..META_COMMITTEE_AT].copy_from_slice(data);
    let committee_end = META_COMMITTEE_AT + COMMITTEE_BITS_SIZE_PQ;
    meta[META_COMMITTEE_AT..committee_end]
        .copy_from_slice(SignedAggregateAndProofPqView::agg_committee_bits(ssz));
    meta[committee_end..META_SIGNATURE_AT].get_mut(..bits.len())?.copy_from_slice(bits);
    meta[META_SIGNATURE_AT..].copy_from_slice(SignedAggregateAndProofPqView::signature(ssz));
    Some(meta)
}

/// A received claim. `None`: not one of this version.
fn read_meta(attachment: &[u8]) -> Option<&Meta> {
    <&Meta>::try_from(attachment).ok().filter(|meta| meta[0] == META_VERSION)
}

/// The slot is the first field of `AttestationData`.
fn claim_of(meta: &Meta) -> Claim {
    let mut claim = [0; CLAIM_BYTES];
    claim[..8].copy_from_slice(&meta[META_DATA_AT..META_DATA_AT + 8]);
    claim[8..].copy_from_slice(&meta[META_COMMITTEE_AT..META_SIGNATURE_AT]);
    claim
}

/// Where the `aggregation_bits` start in a claim.
const VOTES_AT: usize = 8 + COMMITTEE_BITS_SIZE_PQ;

/// Whether the aggregate of `held` has every vote of the aggregate of `new`,
/// on the same slot and committee.
pub(super) fn covers(held: &Claim, new: &Claim) -> bool {
    held[..VOTES_AT] == new[..VOTES_AT] &&
        new[VOTES_AT..].iter().any(|&bits| bits != 0) &&
        held[VOTES_AT..].iter().zip(&new[VOTES_AT..]).all(|(held, new)| new & !held == 0)
}

const PAYLOADS: usize = 0;
const AGGREGATES: usize = 1;
const KINDS: [Kind; 2] = [
    Kind {
        segments: GossipTopic::ExecutionPayloadSegment,
        whole: GossipTopic::ExecutionPayload,
        cache: TCacheId::ControlSeacast,
        store_bytes: 128 << 20,
        groups_per_slot: 2,
        layout: Layout::Payload,
        context: envelope_context,
        meta: None,
        covers: false,
    },
    // An aggregate of every aggregator of every subnet.
    Kind {
        segments: GossipTopic::BeaconAggregateAndProofSegment,
        whole: GossipTopic::BeaconAggregateAndProof,
        cache: TCacheId::ControlSeacastAggregates,
        store_bytes: 512 << 20,
        groups_per_slot: 16 * 4,
        layout: Layout::Attached,
        context: no_context,
        meta: Some(aggregate_meta),
        covers: true,
    },
];
const _: () = assert!(
    silver_common::PAYLOAD_SEGMENT_MIN == seacast_gossipsub::CHUNK_FIXED &&
        silver_common::PAYLOAD_SEGMENT_MAX == MAX_CHUNK_BYTES
);
/// Connection indices the node has a slot for.
const MAX_PEERS: usize = 1280;
/// Queue entries written in one pass, over all peers.
const WRITE_BUDGET: usize = 4096;
const MAX_N: usize = seacast_codec::MAX_PLAIN_CHUNKS;

type Catalog = TopicCatalogs<Host, StoreCodec>;

/// The handler's SEACAST state. The node is made when the fork digest is
/// known, since a chunk topic and its chunk ids bind it.
pub(super) struct Seacast {
    /// The connections, for the node made after them.
    peers: FxHashMap<usize, NodeId>,
    core: Option<Box<Core>>,
    /// An envelope sent as chunks is not sent whole, and one decoded from
    /// chunks is not forwarded whole. An aggregate goes both ways.
    payload_only: bool,
    /// The whole topic of each kind is not subscribed.
    segments_only: bool,
    /// Off: aggregates travel whole only, and their segment topic is unused.
    aggregates: bool,
}

impl Seacast {
    fn enabled(&self, kind: usize) -> bool {
        kind != AGGREGATES || self.aggregates
    }
}

impl Default for Seacast {
    fn default() -> Self {
        Self {
            peers: FxHashMap::default(),
            core: None,
            payload_only: true,
            segments_only: true,
            aggregates: true,
        }
    }
}

/// A chunk topic of the node. Its type's id is its place in `Core::topics`,
/// which is its kind's in `KINDS`.
struct Topic {
    kind: &'static Kind,
    /// The topic's wire name.
    name: String,
    /// By connection: in the topic's mesh, subscribed to it.
    meshed: Vec<bool>,
    joined: Vec<bool>,
}

struct Core {
    topics: Vec<Topic>,
    node: SeacastNode<Buf>,
    catalog: Catalog,
    env: Env,
    rng: SplitMix64,
    deferred: BoundedDeferredStore,
    domain: GossipDomain,
    start: Instant,
    heartbeat: f64,
    /// A received chunk, decompressed.
    frame: Vec<u8>,
    decoder: snap::raw::Decoder,
    out: Scratch,
    rebuilt: PreallocVec<ChunkMsg<Buf>>,
    unwanted: Vec<ChunkId>,
}

/// The group key in a message id, or in an offer, holding or ask string.
fn entry_key(entry: &[u8]) -> Option<&[u8; 32]> {
    match entry.len() {
        MESSAGE_ID_BYTES => entry.first_chunk(),
        _ => entry.get(5..).and_then(|rest| rest.first_chunk()),
    }
}

fn wire_topic(domain: GossipDomain, topic: GossipTopic) -> String {
    topic.to_wire(&hex::encode(domain.digest()))
}

fn node_id(peer: &silver_common::PeerId) -> NodeId {
    seacast_codec::sha256(peer.as_bytes())
}

impl Core {
    fn new(kinds: &'static [Kind], domain: GossipDomain, now: Instant) -> Self {
        let mut config = NodeConfig::default();
        config.capacities.max_peers = MAX_PEERS;
        // No write is acknowledged to this tile.
        config.source_offers = SourceOffers::Publish;
        let heartbeat = config.heartbeat;
        let mut env = Env::new();
        env.schedule_after(heartbeat, TimerEvent::Heartbeat);
        let topic = |kind: &'static Kind| Topic {
            kind,
            name: wire_topic(domain, kind.segments),
            meshed: vec![false; MAX_PEERS],
            joined: vec![false; MAX_PEERS],
        };
        let topics: Vec<Topic> = kinds.iter().map(topic).collect();
        let of = |(t, topic): (usize, &Topic)| {
            let (object_type, kind) = (TypeId(t as u8), topic.kind);
            let codec = StoreCodec {
                inner: PayloadCodec::with_layout(
                    object_type,
                    kind.layout,
                    NoPool,
                    topic.name.as_bytes(),
                ),
                store: Store::new(
                    kind.cache,
                    kind.store_bytes,
                    kind.groups_per_slot + 1,
                    kind.covers,
                ),
                object_type,
            };
            let host = Host::new(MAX_PEERS, kind.groups_per_slot);
            PayloadCatalog::of(object_type, host, codec, domain.digest())
        };
        let catalog = TopicCatalogs::new(topics.iter().enumerate().map(of).collect());
        Self {
            topics,
            node: SeacastNode::new(config),
            catalog,
            env,
            rng: SplitMix64::new(Nanos::now().0),
            deferred: BoundedDeferredStore::with_capacity(MAX_PEERS, 256, 4096),
            domain,
            start: now,
            heartbeat,
            frame: vec![0; MAX_MESSAGE],
            decoder: snap::raw::Decoder::new(),
            out: Scratch::default(),
            rebuilt: PreallocVec::with_capacity(MAX_N),
            unwanted: Vec::with_capacity(64),
        }
    }

    fn connect(&mut self, peer: usize, id: NodeId) {
        if peer < MAX_PEERS {
            for of in &mut self.catalog.types {
                of.host.set_node_id(peer as PeerId, id);
            }
            self.node.connect_peer(peer as PeerId, true, &mut self.env, &self.catalog);
        }
    }

    fn disconnect(&mut self, peer: usize) {
        if peer < MAX_PEERS {
            self.node.disconnect_peer(peer as PeerId, &mut self.env, &mut self.deferred);
            for topic in &mut self.topics {
                (topic.meshed[peer], topic.joined[peer]) = (false, false);
            }
        }
    }

    /// A part of a received frame, to the node.
    fn part(&mut self, peer: PeerId) -> impl FnMut(Rpc<Buf>, bool) -> bool + '_ {
        let Self { node, env, catalog, rng, deferred, .. } = self;
        move |rpc, offered| node.on_frame_part(peer, rpc, offered, env, catalog, rng, deferred)
    }

    /// The topic named `name`, as its type's place.
    fn topic(&self, name: Option<&str>) -> Option<usize> {
        self.topics.iter().position(|topic| name == Some(topic.name.as_str()))
    }

    /// The relation with `peer` on topic `t` follows the mesh, for a peer
    /// that is linked.
    fn relate(&mut self, peer: usize, t: usize) {
        let (related, object_type) =
            (self.topics[t].meshed[peer] && self.topics[t].joined[peer], TypeId(t as u8));
        if related {
            let (env, catalog) = (&mut self.env, &self.catalog);
            self.node.relation_added(peer as PeerId, object_type, 0, 0, env, catalog);
        } else {
            self.node.relation_removed(peer as PeerId, object_type, 0, 0);
        }
    }

    fn mesh(&mut self, peer: usize, t: usize, meshed: bool) {
        if peer < MAX_PEERS && self.topics[t].meshed[peer] != meshed {
            self.topics[t].meshed[peer] = meshed;
            self.relate(peer, t);
        }
    }

    /// A message on chunk topic `t`: level 1 in full, then the chunk in its
    /// place in its group's assembly. `None`: not to be given to the node.
    fn read_chunk(&mut self, peer: usize, t: usize, snappy: &[u8]) -> Option<ChunkMsg<Buf>> {
        let bad = |env: &mut Env| {
            env.penalties.push((peer as PeerId, PenaltyReason::InvalidChunkLevel1));
            None
        };
        let len = snap::raw::decompress_len(snappy).ok().filter(|&len| len <= MAX_MESSAGE);
        let Some(len) = len.filter(|_| self.decoder.decompress(snappy, &mut self.frame).is_ok())
        else {
            return bad(&mut self.env);
        };
        let message = &self.frame[..len];
        let layout = self.topics[t].kind.layout;
        let PayloadCatalog { host, codec, .. } = &mut self.catalog.types[t];
        // An aggregate's message is its claim, where the sender sends it, then
        // the frame.
        let (attachment, frame) = match layout {
            Layout::Payload => (&[][..], message),
            Layout::Attached => match split_attached(message) {
                Some(parts) => parts,
                None => return bad(&mut self.env),
            },
        };
        let read = codec.inner.read_frame(Buf::scratch(frame), snappy.len() as u32);
        let Some(chunk) = read.filter(|chunk| {
            codec.inner.check(chunk) && codec.inner.check_proof(chunk) == ValidationResult::Accept
        }) else {
            return bad(&mut self.env);
        };
        let f = layout.split(frame, &[])?;
        let context: Context = match layout {
            Layout::Payload => frame[..CONTEXT_BYTES].try_into().ok()?,
            Layout::Attached => [0; CONTEXT_BYTES],
        };
        // A block's root fixes its slot. An aggregate's frame names no block.
        if t == PAYLOADS && host.block_slot(f.beacon_block_root).is_some_and(|slot| slot != f.slot)
        {
            return bad(&mut self.env);
        }
        // A group's slot is the wall slot at its first chunk.
        let (key, slot) = (f.group, host.wall_slot);
        let store = &mut codec.store;
        let meta = read_meta(attachment);
        let at = match store.find(&key) {
            Some(at) => at,
            None => {
                // An aggregate's group opens with its claim. A chunk without
                // one is of a sender that took this node to have it: not
                // taken, and no fault of the sender.
                if layout == Layout::Attached && meta.is_none() {
                    return None;
                }
                let at = store.open(&key, slot, layout, &context, meta, &f.descriptor)?;
                // The claim is the sender's word until level 2.
                store.rank(at);
                at
            }
        };
        // A peer that has a chunk of the group has its claim.
        store.note_told(at, peer);
        // The key binds the descriptor, and the payload's the chunk's slot,
        // which level 1 checked.
        debug_assert_eq!(store.descriptor(at), Some(&f.descriptor));
        // It does not bind the block root: the first chunk's stands.
        if store.context(at) != Some(&context) {
            return None;
        }
        let len = frame.len();
        let (index, head) = (f.index as usize, &frame[..len - f.data.len()]);
        match store.head(at, index) {
            // Another copy of the chunk held.
            Some(held) if held == head => {}
            Some(_) => return None,
            None => {
                store.put(at, index, head, f.data, &chunk.memo, &chunk.cached_id)?;
                store.note_sender(at, peer);
            }
        }
        Some(ChunkMsg { frame: store.chunk(at, index)?, ..chunk })
    }

    /// The parts of a received `RPC` that are SEACAST's, in the order the node
    /// takes a frame: the JOIN, the chunks, the offers, the asks, the
    /// holdings.
    fn on_rpc(&mut self, peer: usize, rpc: &RPCView<'_>) {
        if peer >= MAX_PEERS {
            return;
        }
        let id = peer as PeerId;
        let mut frame = Inbound::new();
        for subscription in &rpc.subscriptions {
            let Some(t) = self.topic(subscription.topic_id) else {
                continue;
            };
            match subscription.subscribe {
                Some(true) => {
                    self.topics[t].joined[peer] = true;
                    let join = topic_join(TypeId(t as u8), self.domain.digest());
                    frame.join(join, &mut self.part(id));
                }
                Some(false) => {
                    self.topics[t].joined[peer] = false;
                    self.node.on_leave(id, TypeId(t as u8));
                }
                None => continue,
            }
            self.relate(peer, t);
        }
        let control = rpc.control.as_option();
        if let Some(control) = control {
            for graft in &control.graft {
                if let Some(t) = self.topic(graft.topic_id) {
                    self.mesh(peer, t, true);
                }
            }
            for prune in &control.prune {
                if let Some(t) = self.topic(prune.topic_id) {
                    self.mesh(peer, t, false);
                }
            }
        }
        for message in &rpc.publish {
            if let Some(t) = self.topic(Some(message.topic)) &&
                let Some(snappy) = message.data &&
                let Some(chunk) = self.read_chunk(peer, t, snappy)
            {
                frame.chunk(chunk, &mut self.part(id));
            }
        }
        if let Some(control) = control {
            let route_hops = self.catalog.types[0].params.route_hops;
            for ihave in &control.ihave {
                let Some(t) = self.topic(ihave.topic_id) else {
                    continue;
                };
                for entry in &ihave.message_ids {
                    if let Some(mut offer) = read_offer(entry) {
                        offer.group.type_id = TypeId(t as u8);
                        frame.offer(offer, &mut self.part(id));
                    }
                }
            }
            // An ask and a holding name no topic: their type is that of the
            // group on record, and one of no such group is not the node's.
            for iwant in &control.iwant {
                for entry in &iwant.message_ids {
                    if let Some(t) = self.holds(entry) &&
                        let Some(mut want) = read_want(entry, route_hops)
                    {
                        want.group.type_id = t;
                        frame.want(want, &mut self.part(id));
                    }
                }
            }
            for idontwant in &control.idontwant {
                for entry in &idontwant.message_ids {
                    let Some(t) = self.holds(entry).filter(|_| is_seacast(entry)) else {
                        continue;
                    };
                    if let Some(mut holding) = read_holding(entry) {
                        holding.group.type_id = t;
                        // A peer that holds a chunk of the group has its claim.
                        let store = &mut self.catalog.types[t.0 as usize].codec.store;
                        if let Some(at) = store.find(&holding.group.key) {
                            store.note_told(at, peer);
                        }
                        frame.holding(holding, &mut self.part(id));
                    } else if let Some(chunk) = chunk_id_on(t, entry) {
                        self.unwanted.push(chunk);
                    }
                }
            }
        }
        frame.finish(&mut self.part(id));
        for chunk in self.unwanted.drain(..) {
            self.node.note_unwanted(id, chunk);
        }
        self.decode();
    }

    /// The type of the group an IWANT or IDONTWANT entry names: the topic
    /// whose store has an assembly of it.
    fn holds(&self, entry: &[u8]) -> Option<TypeId> {
        let key = entry_key(entry)?;
        let t = self.catalog.types.iter().position(|of| of.codec.store.find(key).is_some())?;
        Some(TypeId(t as u8))
    }

    /// Level 2 of the groups the node asked for, in place.
    fn decode(&mut self) {
        while let Some((group, shape)) = self.env.to_decode.pop() {
            let Some(of) = self.catalog.types.get(group.type_id.0 as usize) else {
                continue;
            };
            let codec = &of.codec;
            // An assembly freed since: the group ends at its deadline.
            let Some(first) = codec
                .store
                .find(&group.key)
                .and_then(|at| codec.chunk_msg(at, codec.store.first(at)?, [0; 32]))
            else {
                continue;
            };
            self.rebuilt.clear();
            let object = self.catalog.decode(&group, &[first], &shape, &mut self.rebuilt);
            let failed = object.is_none();
            self.node.on_decoded(
                group,
                object,
                self.rebuilt.as_slice(),
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
            );
            self.settle(&group, !failed);
        }
    }

    /// Level 2 of `group` ran. Where it failed and so leaves its slot and
    /// committee with no group forwarded, the next best held is. Passed, the
    /// group stands for its slot and committee and none takes its place.
    fn settle(&mut self, group: &GroupId, passed: bool) {
        let t = group.type_id.0 as usize;
        let store = &mut self.catalog.types[t].codec.store;
        let Some(at) = store.find(&group.key) else {
            return;
        };
        store.settle(at, passed);
        if !passed {
            store.promote(at);
        }
    }

    fn timers(&mut self, now: Instant) {
        self.env.now = now.duration_since(self.start).as_secs_f64();
        for of in &mut self.catalog.types {
            of.codec.store.loop_start();
        }
        while let Some(event) = self.env.pop_due() {
            if event == TimerEvent::Heartbeat {
                self.env.schedule_after(self.heartbeat, TimerEvent::Heartbeat);
            }
            self.node.on_timer(
                event,
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
                &mut self.deferred,
            );
        }
        self.decode();
    }

    fn clock(&mut self, wall_slot: u64, slot_start: Instant, slot: Duration) {
        let slot_start = match slot_start.checked_duration_since(self.start) {
            Some(since) => since.as_secs_f64(),
            None => -self.start.duration_since(slot_start).as_secs_f64(),
        };
        for PayloadCatalog { host, codec, .. } in &mut self.catalog.types {
            if host.wall_slot != wall_slot {
                codec.store.expire(wall_slot);
            }
            host.wall_slot = wall_slot;
            host.slot_secs = slot.as_secs_f64();
            host.slot_start = slot_start;
        }
    }

    /// Publishes a local body as its source. `false`: its chunks do not go
    /// out.
    fn publish(&mut self, t: usize, ssz: &[u8]) -> bool {
        let kind = self.topics[t].kind;
        let (format, whole) = (self.domain.format(), kind.whole);
        if format != ForkName::Pq ||
            ssz.len() < whole.min_uncompressed_size(format) ||
            ssz.len() > whole.max_uncompressed_size(format).min(seacast_codec::MAX_PLAIN_BODY)
        {
            return false;
        }
        let Some(context) = (kind.context)(ssz) else {
            return false;
        };
        let (layout, meta) = (kind.layout, kind.meta.map(|meta| meta(ssz)));
        if meta == Some(None) {
            return false;
        }
        let meta = meta.flatten();
        let context_bytes = &context[..layout.context_len()];
        let PayloadCatalog { host, codec, .. } = &mut self.catalog.types[t];
        // An aggregate of ours adds nothing to one held whole that has its
        // votes: it is not sent as chunks.
        if meta.as_ref().is_some_and(|meta| codec.store.covered(&claim_of(meta))) {
            return false;
        }
        let slot = host.wall_slot;
        let (d, shards) =
            build_group::<Vec<u8>, _, _>(ssz, &mut VecBufferPool, &SnappyBlockCompressor);
        let key = layout.group_key(&group_id(&d), context_bytes);
        let group = topic_group(TypeId(t as u8), key);
        if codec.store.find(&key).is_some() {
            return true;
        }
        let opened = codec.store.open(&key, slot, layout, &context, meta.as_ref(), &d);
        let Some(at) = opened else {
            silver_log::warn!(slot, topic = %kind.whole, "seacast: no room to publish");
            return false;
        };
        self.rebuilt.clear();
        for shard in &shards {
            let head = layout.build(context_bytes, &key, &d, shard.index, &shard.proof, &[]);
            let id = codec.inner.chunk_id(&group, shard.index, &head, &shard.data);
            let leaf = leaf_hash(&shard.data);
            let index = shard.index as usize;
            if codec.store.put(at, index, &head, &shard.data, &leaf, &id).is_none() {
                return false;
            }
            self.rebuilt.push(codec.chunk_msg(at, index, leaf).expect("stored"));
        }
        // Our own group: authentic without the domain's word, and level 2
        // holds by construction.
        codec.store.settle_ours(at);
        host.admit(group);
        self.node.publish(
            group,
            Shape { n: d.n(), k: d.k() },
            self.rebuilt.as_slice(),
            &mut self.env,
            &self.catalog,
            &mut self.rng,
        );
        true
    }
}

impl GossipHandler {
    pub fn set_seacast_payload_only(&mut self, payload_only: bool) {
        self.seacast.payload_only = payload_only;
    }

    pub fn set_seacast_segments_only(&mut self, segments_only: bool) {
        self.seacast.segments_only = segments_only;
    }

    pub fn set_seacast_aggregates(&mut self, aggregates: bool) {
        self.seacast.aggregates = aggregates;
    }

    /// Whether `topic` is left unsubscribed: the segment topic of a kind that
    /// is off, or a whole topic whose bodies come as segments, on a domain
    /// that has the segment topic.
    pub fn seacast_skips(&self, topic: GossipTopic) -> bool {
        let Some(format) = self.current_domain().map(|domain| domain.format()) else {
            return false;
        };
        KINDS.iter().enumerate().any(|(index, kind)| match self.seacast.enabled(index) {
            false => kind.segments == topic,
            true => {
                self.seacast.segments_only &&
                    kind.whole == topic &&
                    kind.segments.supports_format(format)
            }
        })
    }

    /// The node exists once the current domain is known. A later change of
    /// digest is not followed: the node keeps the topics it was made with.
    fn seacast_core(&mut self, now: Instant) -> Option<&mut Core> {
        if self.seacast.core.is_none() &&
            let Some(domain) = self.domains.current_domain()
        {
            // The aggregates' kind is the last: off, it has no topic.
            let kinds = match self.seacast.aggregates {
                true => &KINDS[..],
                false => &KINDS[..AGGREGATES],
            };
            let mut core = Box::new(Core::new(kinds, domain, now));
            for (&peer, &id) in &self.seacast.peers {
                core.connect(peer, id);
            }
            self.seacast.core = Some(core);
        }
        self.seacast.core.as_deref_mut()
    }

    /// Our GRAFT or PRUNE of `peer` on `topic`.
    pub(super) fn seacast_mesh(
        &mut self,
        peer: usize,
        topic: GossipTopic,
        digest: [u8; 4],
        meshed: bool,
    ) {
        if let Some(core) = self.seacast.core.as_deref_mut() &&
            core.domain.digest() == digest &&
            let Some(t) = core.topics.iter().position(|of| of.kind.segments == topic)
        {
            core.mesh(peer, t, meshed);
        }
    }

    pub(super) fn seacast_rpc(
        &mut self,
        peer: usize,
        rpc: &RPCView<'_>,
        now: Instant,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) {
        if let Some(core) = self.seacast_core(now) {
            core.on_rpc(peer, rpc);
        }
        self.seacast_flush(emit);
    }

    pub(super) fn seacast_tick(&mut self, now: Instant, emit: &mut impl FnMut(GossipHandlerEvent)) {
        if let Some(core) = self.seacast_core(now) {
            core.timers(now);
        }
        self.seacast_flush(emit);
    }

    /// Publishes a local body as chunks. `true`: they go out and the body
    /// is not to be sent whole.
    pub(super) fn seacast_publish(&mut self, topic: GossipTopic, ssz: &[u8]) -> bool {
        let only = self.seacast.payload_only && topic == KINDS[PAYLOADS].whole;
        let published = self.seacast_core(Instant::now()).is_some_and(|core| {
            let t = core.topics.iter().position(|of| of.kind.whole == topic);
            t.is_some_and(|t| core.publish(t, ssz))
        });
        published && only
    }

    /// Connections open and close.
    pub fn seacast_peer_event(&mut self, event: &PeerEvent) {
        match *event {
            PeerEvent::P2pNewConnection { p2p_peer_id, ref peer_id_full, .. } => {
                let id = node_id(peer_id_full);
                self.seacast.peers.insert(p2p_peer_id, id);
                if let Some(core) = self.seacast.core.as_deref_mut() {
                    core.connect(p2p_peer_id, id);
                }
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => {
                self.seacast.peers.remove(&p2p_peer);
                if let Some(core) = self.seacast.core.as_deref_mut() {
                    core.disconnect(p2p_peer);
                }
            }
            _ => {}
        }
    }

    /// A block Beacon State announced.
    pub fn seacast_block(&mut self, block_root: [u8; 32], slot: u64) {
        if let Some(core) = self.seacast.core.as_deref_mut() {
            core.catalog.types[PAYLOADS].host.note_block(block_root, slot);
        }
    }

    /// The slot clock: the wall slot, its start and a slot's length.
    pub fn seacast_clock(&mut self, wall_slot: u64, slot_start: Instant, slot: Duration) {
        if let Some(core) = self.seacast.core.as_deref_mut() {
            core.clock(wall_slot, slot_start, slot);
        }
    }

    /// Writes what the node has queued, reports its penalties and hands on the
    /// bodies it decoded.
    fn seacast_flush(&mut self, emit: &mut impl FnMut(GossipHandlerEvent)) {
        let Some(core) = self.seacast.core.as_deref_mut() else {
            return;
        };
        let mut budget = WRITE_BUDGET;
        let mut peers = std::mem::take(&mut core.env.to_write);
        peers.retain(|&peer| {
            macro_rules! out {
                () => {
                    Out {
                        peer: peer as usize,
                        topics: &core.topics,
                        types: &mut core.catalog.types,
                        producer: &mut self.mcache_publish,
                        reader: &mut self.reader,
                        scratch: &mut core.out,
                        emit: &mut *emit,
                    }
                };
            }
            let mut done = false;
            while budget > 0 && !done {
                match core.node.next_to_send(peer, &mut core.env, &core.catalog) {
                    DispatchOutcome::Send(entry) => {
                        budget -= 1;
                        write_entry(&entry, &mut out!());
                    }
                    DispatchOutcome::Wait | DispatchOutcome::Empty => done = true,
                }
            }
            out!().flush();
            !done
        });
        // The chunks of the groups let go since they were held back.
        for t in 0..core.catalog.types.len() {
            while let Some((peer, chunk)) = core.catalog.types[t].codec.store.pop_deferred() {
                let mut out = Out {
                    peer,
                    topics: &core.topics,
                    types: &mut core.catalog.types,
                    producer: &mut self.mcache_publish,
                    reader: &mut self.reader,
                    scratch: &mut core.out,
                    emit: &mut *emit,
                };
                out.chunk(t, &chunk);
            }
        }
        // Peers woken by the writes above come after those left over.
        peers.append(&mut core.env.to_write);
        core.env.to_write = peers;

        for (peer, reason) in core.env.penalties.drain(..) {
            silver_log::debug!(peer, ?reason, "seacast penalty");
            emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidControl {
                p2p_peer: peer as usize,
            }));
        }
        let domain = core.domain;
        let mut delivered = std::mem::take(&mut core.env.delivered);
        delivered.retain(|(t, body)| core.catalog.types[*t as usize].codec.store.live(body));
        for (t, body) in delivered.drain(..) {
            let kind = t as usize;
            match self.seacast_deliver(kind, domain, &body, emit) {
                Ok(new) => {
                    let core = self.seacast.core.as_ref();
                    let store = core.map(|core| &core.catalog.types[kind].codec.store);
                    let Some((slot, block, d, received, peers)) =
                        store.and_then(|store| store.origin(&body))
                    else {
                        continue;
                    };
                    let (root, block) = (hex::encode(d.root), hex::encode(block));
                    let (k, n) = (d.k(), d.n());
                    match kind {
                        PAYLOADS => silver_log::info!(
                            slot,
                            root,
                            block,
                            k,
                            n,
                            received,
                            peers = ?peers,
                            new,
                            "seacast: envelope from segments"
                        ),
                        _ => silver_log::debug!(
                            slot,
                            root,
                            block,
                            k,
                            n,
                            received,
                            peers = ?peers,
                            new,
                            "seacast: aggregate from segments"
                        ),
                    }
                }
                Err(e) => silver_log::warn!(?e, "seacast: decoded body not delivered"),
            }
        }
        if let Some(core) = &mut self.seacast.core {
            core.env.delivered = delivered;
        }
    }

    /// A decoded body, as a message received on the topic it is whole on: the
    /// SSZ to the incoming tcache, the message for forwarding to the outgoing
    /// one. `body` is the segmented body; where it was compressed before it
    /// was segmented it is the message's data as it stands. `false`: a copy
    /// that came whole was handed on before.
    fn seacast_deliver(
        &mut self,
        kind: usize,
        domain: GossipDomain,
        body: &Buf,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) -> Result<bool, silver_common::Error> {
        use silver_common::Error;
        let topic = KINDS[kind].whole;
        let wire = wire_topic(domain, topic);
        let segmented = body.as_bytes();
        let coded = body.index() == 1;
        let len = match coded {
            true => snap::raw::decompress_len(segmented).map_err(|_| Error::InvalidSnappy)?,
            false => segmented.len(),
        };
        if len > topic.max_uncompressed_size(domain.format()) {
            return Err(Error::GossipPayloadTooLarge);
        }
        let mut reservation =
            self.incoming_gossip_publish.reserve(len, false).ok_or(Error::BufferTooSmall)?;
        let ssz = &mut self.incoming_gossip_publish.reservation_buffer(&mut reservation)?[..len];
        let compressed = match coded {
            true => {
                snap::raw::Decoder::new().decompress(segmented, ssz)?;
                segmented
            }
            false => {
                ssz.copy_from_slice(segmented);
                let n = self.compress(segmented)?;
                &self.snap_scratch[..n]
            }
        };
        // The group's key binds the slot its chunks name, not the body's.
        let core = self.seacast.core.as_ref();
        let named = core.and_then(|core| core.catalog.types[kind].codec.store.named_slot(body));
        if (KINDS[kind].context)(ssz).is_none_or(|of_body| Some(&of_body[..8]) != named) {
            return Err(Error::SeacastSlotMismatch);
        }
        let msg_hash: MessageId = msg_id_valid_snappy(&wire, ssz);
        reservation.increment_offset(len);
        // A copy that came as a full message has been handed on already.
        let Ok(fast) = self.dedup_cache.contains_fast(&wire, compressed) else {
            return Ok(false);
        };
        if !self.dedup_cache.insert(fast, msg_hash) {
            return Ok(false);
        }
        let protobuf = match self.seacast.payload_only && kind == PAYLOADS {
            true => None,
            false => {
                copy_compressed_to_protobuf_output(&mut self.mcache_publish, compressed, &wire).ok()
            }
        };
        let ssz = reservation.read();
        std::io::Write::flush(&mut reservation)?;
        emit(GossipHandlerEvent::NewGossip(NewGossipMsg {
            stream_id: LOCAL_GOSSIP_STREAM_ID,
            topic,
            domain,
            ssz_cache: SszCache::Gossip,
            msg_hash,
            recv_ts: Nanos::now(),
            ssz,
            protobuf,
            validation: BroadcastValidation::Gossip,
        }));
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
