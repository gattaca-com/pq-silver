//! SEACAST on gossipsub (`seacast-bindings.md` §4) for the execution payload
//! envelope and the signed aggregate: a body is cut into Reed-Solomon coded
//! chunks, each a message on its chunk topic, and offers, holdings and asks
//! travel as strings among the ids of IHAVE, IDONTWANT and IWANT. The
//! payload's topic is Prysm's (`seacast-devnet`); the chunk's frame and the
//! group's key are `seacast-lite.md`'s `Chunk` and `group_key`. The
//! aggregates' topic has the same frame.
//!
//! A kind of body has its own `seacast_core::SeacastNode`, run here on the
//! control tile's thread with level 1 and level 2 inline. The mesh is the peer
//! manager's: a peer is pushed to while it is in the mesh of the chunk topic
//! and subscribed to it. A decoded body is handed on as a message received on
//! the topic it is whole on.

mod host;
mod store;
mod wire;

use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use seacast_codec::{
    ChunkBytes, SnappyBlockCompressor, VecBufferPool, build_group, group_id, leaf_hash,
};
use seacast_core::{
    BoundedDeferredStore, ChunkId, ChunkMsg, DispatchOutcome, NodeConfig, NodeId, PeerId,
    PenaltyReason, PreallocVec, Rpc, RuntimeEnv, SeacastNode, Shape, SourceOffers, SplitMix64,
    TimerEvent, TypeCodec, ValidationResult,
};
use seacast_gossipsub::{
    CONTEXT_BYTES, Inbound, MAX_CHUNK_BYTES, MESSAGE_ID_BYTES, PAYLOAD, PayloadCatalog,
    PayloadCodec, build_chunk, chunk_id_of, group_key, is_seacast, payload_group, payload_join,
    read_holding, read_offer, read_want, split_chunk, write_entry,
};
use silver_common::{
    BroadcastValidation, ForkName, GossipDomain, GossipTopic, GossipTraffic,
    LOCAL_GOSSIP_STREAM_ID, MessageId, Nanos, NewGossipMsg, PeerEvent, SszCache, TCacheId,
    TCacheProducer, msg_id_valid_snappy,
    ssz_view::{
        EXECUTION_PAYLOAD_FIXED_GLOAS, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        SignedAggregateAndProofPqView, SignedExecutionPayloadEnvelopePqView,
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
    /// The slot and block a local body is of, which its chunks name.
    context: fn(&[u8]) -> Option<Context>,
}

/// `slot | beacon_block_root`, the head of a chunk's frame.
type Context = [u8; CONTEXT_BYTES];

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

/// The slot and block the aggregate's attestation votes for.
fn aggregate_context(ssz: &[u8]) -> Option<Context> {
    SignedAggregateAndProofPqView::check_size(ssz).then(|| {
        let data = SignedAggregateAndProofPqView::agg_data(ssz);
        context(data.slot(), data.beacon_block_root())
    })
}

const PAYLOADS: usize = 0;
const KINDS: [Kind; 2] = [
    Kind {
        segments: GossipTopic::ExecutionPayloadSegment,
        whole: GossipTopic::ExecutionPayload,
        cache: TCacheId::ControlSeacast,
        store_bytes: 128 << 20,
        groups_per_slot: 2,
        context: envelope_context,
    },
    // An aggregate of every aggregator of every subnet.
    Kind {
        segments: GossipTopic::BeaconAggregateAndProofSegment,
        whole: GossipTopic::BeaconAggregateAndProof,
        cache: TCacheId::ControlSeacastAggregates,
        store_bytes: 512 << 20,
        groups_per_slot: 16 * 4,
        context: aggregate_context,
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

type Catalog = PayloadCatalog<Host, StoreCodec>;

/// The handler's SEACAST state. The nodes are made when the fork digest is
/// known, since a chunk topic and its chunk ids bind it.
pub(super) struct Seacast {
    /// The connections, for the nodes made after them.
    peers: FxHashMap<usize, NodeId>,
    /// By kind.
    cores: [Option<Box<Core>>; KINDS.len()],
    /// An envelope sent as chunks is not sent whole, and one decoded from
    /// chunks is not forwarded whole. An aggregate goes both ways.
    payload_only: bool,
}

impl Default for Seacast {
    fn default() -> Self {
        Self { peers: FxHashMap::default(), cores: [None, None], payload_only: true }
    }
}

struct Core {
    kind: &'static Kind,
    node: SeacastNode<Buf>,
    catalog: Catalog,
    env: Env,
    rng: SplitMix64,
    deferred: BoundedDeferredStore,
    domain: GossipDomain,
    /// The chunk topic's wire name.
    chunk_topic: String,
    start: Instant,
    heartbeat: f64,
    /// By connection: in the mesh of the chunk topic, subscribed to it.
    meshed: Vec<bool>,
    joined: Vec<bool>,
    /// A received chunk, decompressed.
    frame: Vec<u8>,
    decoder: snap::raw::Decoder,
    out: Scratch,
    rebuilt: PreallocVec<ChunkMsg<Buf>>,
    unwanted: Vec<ChunkId>,
}

fn wire_topic(domain: GossipDomain, topic: GossipTopic) -> String {
    topic.to_wire(&hex::encode(domain.digest()))
}

fn node_id(peer: &silver_common::PeerId) -> NodeId {
    seacast_codec::sha256(peer.as_bytes())
}

impl Core {
    fn new(kind: &'static Kind, domain: GossipDomain, now: Instant) -> Self {
        let mut config = NodeConfig::default();
        config.capacities.max_peers = MAX_PEERS;
        // No write is acknowledged to this tile.
        config.source_offers = SourceOffers::Publish;
        let heartbeat = config.heartbeat;
        let chunk_topic = wire_topic(domain, kind.segments);
        let codec = StoreCodec {
            inner: PayloadCodec::new(NoPool, chunk_topic.as_bytes()),
            store: Store::new(kind.cache, kind.store_bytes, kind.groups_per_slot + 1),
        };
        let mut env = Env::new();
        env.schedule_after(heartbeat, TimerEvent::Heartbeat);
        let host = Host::new(MAX_PEERS, kind.groups_per_slot);
        Self {
            kind,
            node: SeacastNode::new(config),
            catalog: PayloadCatalog::new(host, codec, domain.digest()),
            env,
            rng: SplitMix64::new(Nanos::now().0),
            deferred: BoundedDeferredStore::with_capacity(MAX_PEERS, 256, 4096),
            domain,
            chunk_topic,
            start: now,
            heartbeat,
            meshed: vec![false; MAX_PEERS],
            joined: vec![false; MAX_PEERS],
            frame: vec![0; MAX_CHUNK_BYTES],
            decoder: snap::raw::Decoder::new(),
            out: Scratch::default(),
            rebuilt: PreallocVec::with_capacity(MAX_N),
            unwanted: Vec::with_capacity(64),
        }
    }

    fn connect(&mut self, peer: usize, id: NodeId) {
        if peer < MAX_PEERS {
            self.catalog.host.set_node_id(peer as PeerId, id);
            self.node.connect_peer(peer as PeerId, true, &mut self.env, &self.catalog);
        }
    }

    fn disconnect(&mut self, peer: usize) {
        if peer < MAX_PEERS {
            self.node.disconnect_peer(peer as PeerId, &mut self.env, &mut self.deferred);
            (self.meshed[peer], self.joined[peer]) = (false, false);
        }
    }

    /// A part of a received frame, to the node.
    fn part(&mut self, peer: PeerId) -> impl FnMut(Rpc<Buf>, bool) -> bool + '_ {
        let Self { node, env, catalog, rng, deferred, .. } = self;
        move |rpc, offered| node.on_frame_part(peer, rpc, offered, env, catalog, rng, deferred)
    }

    /// The relation with `peer` follows the mesh, for a peer that is linked.
    fn relate(&mut self, peer: usize) {
        if self.meshed[peer] && self.joined[peer] {
            self.node.relation_added(peer as PeerId, PAYLOAD, 0, 0, &mut self.env, &self.catalog);
        } else {
            self.node.relation_removed(peer as PeerId, PAYLOAD, 0, 0);
        }
    }

    fn mesh(&mut self, peer: usize, meshed: bool) {
        if peer < MAX_PEERS && self.meshed[peer] != meshed {
            self.meshed[peer] = meshed;
            self.relate(peer);
        }
    }

    /// A message on the chunk topic: level 1 in full, then the chunk in its
    /// place in its group's assembly. `None`: not to be given to the node.
    fn read_chunk(&mut self, peer: usize, snappy: &[u8]) -> Option<ChunkMsg<Buf>> {
        let bad = |env: &mut Env| {
            env.penalties.push((peer as PeerId, PenaltyReason::InvalidChunkLevel1));
            None
        };
        let len = snap::raw::decompress_len(snappy).ok().filter(|&len| len <= MAX_CHUNK_BYTES);
        let Some(len) = len.filter(|_| self.decoder.decompress(snappy, &mut self.frame).is_ok())
        else {
            return bad(&mut self.env);
        };
        let frame = &self.frame[..len];
        let codec = &mut self.catalog.codec;
        let read = codec.inner.read_message(snappy, |_, _| Some(Buf::scratch(frame)));
        let Some(chunk) = read.filter(|chunk| {
            codec.inner.check(chunk) && codec.inner.check_proof(chunk) == ValidationResult::Accept
        }) else {
            return bad(&mut self.env);
        };
        let f = split_chunk(frame)?;
        let context: &Context = frame[..CONTEXT_BYTES].try_into().ok()?;
        // A group's slot is the wall slot at its first chunk.
        let (key, slot) = (f.group, self.catalog.host.wall_slot);
        let store = &mut codec.store;
        let at = store.find(&key).or_else(|| store.open(&key, slot, context, &f.descriptor))?;
        // The key binds the descriptor and the chunk's slot, which level 1 checked.
        debug_assert_eq!(store.descriptor(at), Some(&f.descriptor));
        // It does not bind the block root: the first chunk's stands.
        if store.context(at) != Some(context) {
            return None;
        }
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
            if subscription.topic_id != Some(self.chunk_topic.as_str()) {
                continue;
            }
            match subscription.subscribe {
                Some(true) => {
                    self.joined[peer] = true;
                    let join = payload_join(self.domain.digest());
                    frame.join(join, &mut self.part(id));
                }
                Some(false) => {
                    self.joined[peer] = false;
                    self.node.on_leave(id, PAYLOAD);
                }
                None => continue,
            }
            self.relate(peer);
        }
        let control = rpc.control.as_option();
        if let Some(control) = control {
            for graft in &control.graft {
                if graft.topic_id == Some(self.chunk_topic.as_str()) {
                    self.mesh(peer, true);
                }
            }
            for prune in &control.prune {
                if prune.topic_id == Some(self.chunk_topic.as_str()) {
                    self.mesh(peer, false);
                }
            }
        }
        for message in &rpc.publish {
            if message.topic == self.chunk_topic &&
                let Some(snappy) = message.data &&
                let Some(chunk) = self.read_chunk(peer, snappy)
            {
                frame.chunk(chunk, &mut self.part(id));
            }
        }
        if let Some(control) = control {
            let route_hops = self.catalog.params.route_hops;
            for ihave in &control.ihave {
                if ihave.topic_id != Some(self.chunk_topic.as_str()) {
                    continue;
                }
                for entry in &ihave.message_ids {
                    if let Some(offer) = read_offer(entry) {
                        frame.offer(offer, &mut self.part(id));
                    }
                }
            }
            // An ask and a holding name no topic: they are this node's where
            // it has the group.
            for iwant in &control.iwant {
                for entry in &iwant.message_ids {
                    if self.holds(entry) &&
                        let Some(want) = read_want(entry, route_hops)
                    {
                        frame.want(want, &mut self.part(id));
                    }
                }
            }
            for idontwant in &control.idontwant {
                for entry in &idontwant.message_ids {
                    if !is_seacast(entry) || !self.holds(entry) {
                        continue;
                    }
                    if let Some(holding) = read_holding(entry) {
                        frame.holding(holding, &mut self.part(id));
                    } else if let Some(chunk) = chunk_id_of(entry) {
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

    /// Whether the group an IWANT or IDONTWANT entry names has an assembly.
    fn holds(&self, entry: &[u8]) -> bool {
        let key = match entry.len() {
            MESSAGE_ID_BYTES => entry.first_chunk::<32>(),
            _ => entry.get(5..).and_then(|rest| rest.first_chunk::<32>()),
        };
        key.is_some_and(|key| self.catalog.codec.store.find(key).is_some())
    }

    /// Level 2 of the groups the node asked for, in place.
    fn decode(&mut self) {
        while let Some((group, shape)) = self.env.to_decode.pop() {
            let codec = &self.catalog.codec;
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
            self.node.on_decoded(
                group,
                object,
                self.rebuilt.as_slice(),
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
            );
        }
    }

    fn timers(&mut self, now: Instant) {
        self.env.now = now.duration_since(self.start).as_secs_f64();
        self.catalog.codec.store.loop_start();
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
        let host = &mut self.catalog.host;
        if host.wall_slot != wall_slot {
            self.catalog.codec.store.expire(wall_slot);
        }
        host.wall_slot = wall_slot;
        host.slot_secs = slot.as_secs_f64();
        host.slot_start = match slot_start.checked_duration_since(self.start) {
            Some(since) => since.as_secs_f64(),
            None => -self.start.duration_since(slot_start).as_secs_f64(),
        };
    }

    /// Publishes a local body as its source. `false`: its chunks do not go
    /// out.
    fn publish(&mut self, ssz: &[u8]) -> bool {
        let (format, whole) = (self.domain.format(), self.kind.whole);
        if format != ForkName::Pq ||
            ssz.len() < whole.min_uncompressed_size(format) ||
            ssz.len() > whole.max_uncompressed_size(format).min(seacast_codec::MAX_PLAIN_BODY)
        {
            return false;
        }
        let Some(context) = (self.kind.context)(ssz) else {
            return false;
        };
        let slot = self.catalog.host.wall_slot;
        let (d, shards) =
            build_group::<Vec<u8>, _, _>(ssz, &mut VecBufferPool, &SnappyBlockCompressor);
        let chunk_slot = u64::from_le_bytes(context[..8].try_into().unwrap());
        let key = group_key(&group_id(&d), chunk_slot);
        let group = payload_group(key);
        let codec = &mut self.catalog.codec;
        if codec.store.find(&key).is_some() {
            return true;
        }
        let Some(at) = codec.store.open(&key, slot, &context, &d) else {
            silver_log::warn!(slot, topic = %self.kind.whole, "seacast: no room to publish");
            return false;
        };
        self.rebuilt.clear();
        for shard in &shards {
            let head = build_chunk(&context, &key, &d, shard.index, &shard.proof, &[]);
            let id = codec.inner.chunk_id(&group, shard.index, &head, &shard.data);
            let leaf = leaf_hash(&shard.data);
            let index = shard.index as usize;
            if codec.store.put(at, index, &head, &shard.data, &leaf, &id).is_none() {
                return false;
            }
            self.rebuilt.push(codec.chunk_msg(at, index, leaf).expect("stored"));
        }
        // Our own group: authentic without the domain's word.
        self.catalog.host.admit(group);
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

    /// The nodes exist once the current domain is known. A later change of
    /// digest is not followed: a node keeps the topic it was made with.
    fn seacast_cores(&mut self, now: Instant) -> impl Iterator<Item = &mut Core> {
        if self.seacast.cores[PAYLOADS].is_none() &&
            let Some(domain) = self.domains.current_domain()
        {
            for (kind, slot) in KINDS.iter().zip(&mut self.seacast.cores) {
                let mut core = Box::new(Core::new(kind, domain, now));
                for (&peer, &id) in &self.seacast.peers {
                    core.connect(peer, id);
                }
                *slot = Some(core);
            }
        }
        self.seacast.cores.iter_mut().flatten().map(|core| &mut **core)
    }

    /// Our GRAFT or PRUNE of `peer` on `topic`.
    pub(super) fn seacast_mesh(
        &mut self,
        peer: usize,
        topic: GossipTopic,
        digest: [u8; 4],
        meshed: bool,
    ) {
        for core in self.seacast.cores.iter_mut().flatten() {
            if core.kind.segments == topic && core.domain.digest() == digest {
                core.mesh(peer, meshed);
            }
        }
    }

    pub(super) fn seacast_rpc(
        &mut self,
        peer: usize,
        rpc: &RPCView<'_>,
        now: Instant,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) {
        self.seacast_cores(now).for_each(|core| core.on_rpc(peer, rpc));
        self.seacast_flush(emit);
    }

    pub(super) fn seacast_tick(&mut self, now: Instant, emit: &mut impl FnMut(GossipHandlerEvent)) {
        self.seacast_cores(now).for_each(|core| core.timers(now));
        self.seacast_flush(emit);
    }

    /// Publishes a local body as chunks. `true`: they go out and the body
    /// is not to be sent whole.
    pub(super) fn seacast_publish(&mut self, topic: GossipTopic, ssz: &[u8]) -> bool {
        let only = self.seacast.payload_only && topic == KINDS[PAYLOADS].whole;
        let mut cores = self.seacast_cores(Instant::now());
        cores.find(|core| core.kind.whole == topic).is_some_and(|core| core.publish(ssz)) && only
    }

    /// Connections open and close.
    pub fn seacast_peer_event(&mut self, event: &PeerEvent) {
        match *event {
            PeerEvent::P2pNewConnection { p2p_peer_id, ref peer_id_full, .. } => {
                let id = node_id(peer_id_full);
                self.seacast.peers.insert(p2p_peer_id, id);
                for core in self.seacast.cores.iter_mut().flatten() {
                    core.connect(p2p_peer_id, id);
                }
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => {
                self.seacast.peers.remove(&p2p_peer);
                for core in self.seacast.cores.iter_mut().flatten() {
                    core.disconnect(p2p_peer);
                }
            }
            _ => {}
        }
    }

    /// The slot clock: the wall slot, its start and a slot's length.
    pub fn seacast_clock(&mut self, wall_slot: u64, slot_start: Instant, slot: Duration) {
        for core in self.seacast.cores.iter_mut().flatten() {
            core.clock(wall_slot, slot_start, slot);
        }
    }

    fn seacast_flush(&mut self, emit: &mut impl FnMut(GossipHandlerEvent)) {
        for kind in 0..KINDS.len() {
            self.seacast_flush_kind(kind, emit);
        }
    }

    /// Writes what a node has queued, reports its penalties and hands on the
    /// bodies it decoded.
    fn seacast_flush_kind(&mut self, kind: usize, emit: &mut impl FnMut(GossipHandlerEvent)) {
        let Some(core) = self.seacast.cores[kind].as_deref_mut() else {
            return;
        };
        let mut budget = WRITE_BUDGET;
        let mut peers = std::mem::take(&mut core.env.to_write);
        peers.retain(|&peer| {
            macro_rules! out {
                () => {
                    Out {
                        peer: peer as usize,
                        traffic: GossipTraffic::of(core.kind.segments),
                        topic: &core.chunk_topic,
                        producer: &mut self.mcache_publish,
                        reader: &mut self.reader,
                        store: &mut core.catalog.codec.store,
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
        delivered.retain(|body| core.catalog.codec.store.live(body));
        for body in delivered.drain(..) {
            match self.seacast_deliver(kind, domain, &body, emit) {
                Ok(new) => {
                    let store = self.seacast.cores[kind].as_ref().map(|c| &c.catalog.codec.store);
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
        if let Some(core) = &mut self.seacast.cores[kind] {
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
