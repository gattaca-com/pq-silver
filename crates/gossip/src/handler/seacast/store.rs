//! Where a group's chunks are kept: one open reservation of the store's
//! tcache per group, written in place.
//!
//! ```text
//!   data     K segments of `segment_size`, end to end: the segmented body
//!   parity   N - K segments, laid out the same way
//!   heads    N frame heads (fixed part and proof), `head_len` each
//!   leaves   N leaf digests
//! ```
//!
//! A chunk is stored only once its proof holds, so an index has one writer.
//! Level 2 computes what is missing into its place
//! (`seacast_codec::complete_in_place`), after which `data` is the body as it
//! was segmented.

use std::{ptr::NonNull, slice};

use seacast_codec::{BufferPool, ChunkBytes, MerkleTree, SegmentDescriptor, complete_in_place};
use seacast_core::{
    Bytes32, ChunkBuffer, ChunkId, ChunkMsg, GroupId, PreallocVec, Shape, TypeCodec, TypeId,
    ValidationResult,
};
use seacast_gossipsub::{CONTEXT_BYTES, Layout, PayloadCodec, topic_group};
use silver_common::{AcquiredRead, TCache, TCacheId, TCacheProducer, TProducer, TReservation};

use super::{CLAIM_BYTES, Claim, MAX_PEERS, Meta, VOTES_AT, claim_of, covers};

/// A coded group has at most 256 chunks, an uncoded one this many.
const MAX_N: usize = seacast_codec::MAX_PLAIN_CHUNKS;
const NO_ASSEMBLY: u16 = u16::MAX;
/// Senders of a group that are kept for the log.
const SENDERS: usize = 8;
/// Writes kept of a group that is held; the rest are left to its offers.
const DEFERRED: usize = 1024;

/// A chunk's frame, or a body, where it lies. A chunk of an assembly is cut
/// at its data: the head is in `heads`, the data in `data` or `parity`.
///
/// The pointers are into the store's tcache, which outlives the node. What
/// they point at is the chunk's only until its assembly is freed:
/// [`Store::live`] tells, and nothing is written to a peer without asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Buf {
    head: NonNull<u8>,
    data: NonNull<u8>,
    head_len: u32,
    data_len: u32,
    assembly: u16,
    index: u16,
    generation: u32,
}

// SAFETY: the bytes are in a tcache ring the store owns, and the store moves
// with the handles: the node, its catalog and the store are one tile's.
unsafe impl Send for Buf {}

impl Buf {
    pub(super) const EMPTY: Self = Self {
        head: NonNull::dangling(),
        data: NonNull::dangling(),
        head_len: 0,
        data_len: 0,
        assembly: NO_ASSEMBLY,
        index: 0,
        generation: 0,
    };

    /// A whole frame in the caller's scratch, for the checks before it is
    /// stored. Not to be kept.
    pub(super) fn scratch(frame: &[u8]) -> Self {
        Self { head: NonNull::from(frame).cast(), head_len: frame.len() as u32, ..Self::EMPTY }
    }

    pub(super) fn index(&self) -> usize {
        self.index as usize
    }
}

impl ChunkBuffer for Buf {
    #[inline]
    fn len(&self) -> usize {
        (self.head_len + self.data_len) as usize
    }
}

impl ChunkBytes for Buf {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: see `Buf`.
        unsafe { slice::from_raw_parts(self.head.as_ptr(), self.head_len as usize) }
    }

    #[inline]
    fn tail(&self) -> &[u8] {
        // SAFETY: see `Buf`.
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.data_len as usize) }
    }
}

struct Assembly {
    /// Never committed: it holds the bytes, and no other tile reads them.
    _reservation: TReservation,
    base: NonNull<u8>,
    key: Bytes32,
    slot: u64,
    /// `slot | beacon_block_root` of the first chunk. The key binds the slot,
    /// not the block root: every chunk kept names this block, and so do the
    /// chunks rebuilt.
    context: [u8; CONTEXT_BYTES],
    layout: Layout,
    /// What ranks the group: of its claim, or nothing.
    claim: Claim,
    /// The claim as it travels beside a chunk, and the peers that have it.
    meta: Option<Meta>,
    told: [u64; MAX_PEERS / 64],
    /// Not forwarded: no chunk of it is written to a peer, and it is not
    /// offered. The node has its chunks all the same, and asks for the rest.
    held: bool,
    /// Level 2 ran. Failed, the group is held; passed, it is unless one that
    /// passed before has its votes.
    settled: bool,
    d: SegmentDescriptor,
    head_len: usize,
    have: [u64; MAX_N / 64],
    /// Chunks taken from peers, and the first peers they came from.
    received: u16,
    from: [u16; SENDERS],
    senders: u8,
}

// SAFETY: `base` is the reservation's buffer, which moves with it.
unsafe impl Send for Assembly {}

impl Assembly {
    fn n(&self) -> usize {
        self.d.n() as usize
    }

    fn size(&self) -> usize {
        self.d.segment_size as usize
    }

    fn has(&self, index: usize) -> bool {
        self.have[index / 64] >> (index % 64) & 1 == 1
    }

    fn data_len(&self, index: usize) -> usize {
        match index < self.d.k() as usize {
            true => self.d.segment_length(index as u32),
            false => self.size(),
        }
    }

    fn heads_at(&self) -> usize {
        self.n() * self.size()
    }

    fn leaves_at(&self) -> usize {
        self.heads_at() + self.n() * self.head_len
    }

    fn len(&self) -> usize {
        self.leaves_at() + self.n() * 32
    }

    /// SAFETY of the three below: the ranges are within the reservation, and
    /// the store hands out no reference that outlives its own borrow.
    fn bytes(&self, at: usize, len: usize) -> &[u8] {
        debug_assert!(at + len <= self.len());
        unsafe { slice::from_raw_parts(self.base.as_ptr().add(at), len) }
    }

    fn bytes_mut(&mut self, at: usize, len: usize) -> &mut [u8] {
        debug_assert!(at + len <= self.len());
        unsafe { slice::from_raw_parts_mut(self.base.as_ptr().add(at), len) }
    }

    fn at(&self, at: usize) -> NonNull<u8> {
        unsafe { self.base.add(at) }
    }

    fn head(&self, index: usize) -> &[u8] {
        self.bytes(self.heads_at() + index * self.head_len, self.head_len)
    }

    fn votes(&self) -> u32 {
        self.claim[VOTES_AT..].iter().map(|bits| bits.count_ones()).sum()
    }

    /// An aggregate of the slot and committee of `claim`. One with no vote is
    /// not ranked.
    fn ranks_with(&self, claim: &Claim) -> bool {
        self.claim[..VOTES_AT] == claim[..VOTES_AT] && self.votes() > 0
    }

    /// The one group of its slot and committee that is forwarded before its
    /// level 2.
    fn primary(&self) -> bool {
        !self.held && !self.settled
    }

    fn passed(&self) -> bool {
        self.settled && !self.held
    }
}

struct Slot {
    assembly: Option<Assembly>,
    /// Counts the assemblies the slot has held: a handle of an earlier one is
    /// not live.
    generation: u32,
    ids: Box<[ChunkId; MAX_N]>,
    /// The writes of chunks held back, as peer and index: made once the
    /// group is let go.
    deferred: Vec<(u16, u16)>,
    /// A chunk's message as written for a peer, pinned for the next.
    wire: Vec<Option<AcquiredRead>>,
}

pub(super) struct Store {
    producer: TProducer,
    slots: Vec<Slot>,
    /// Groups of one slot assembled at once.
    per_slot: usize,
    /// The bodies are aggregates whose contexts carry their votes: of those
    /// of one slot and committee, one is forwarded before its level 2.
    ranked: bool,
}

impl Store {
    /// Room for the groups of two slots: an assembly is freed at the first
    /// clock reading past its slot.
    pub(super) fn new(cache: TCacheId, bytes: usize, per_slot: usize, ranked: bool) -> Self {
        let slots = (0..2 * per_slot)
            .map(|_| Slot {
                assembly: None,
                generation: 0,
                ids: Box::new([[0; 59]; MAX_N]),
                deferred: Vec::with_capacity(DEFERRED),
                wire: (0..MAX_N).map(|_| None).collect(),
            })
            .collect();
        Self { producer: TCache::producer(cache, bytes), slots, per_slot, ranked }
    }

    pub(super) fn loop_start(&mut self) {
        self.producer.loop_start();
    }

    pub(super) fn find(&self, key: &Bytes32) -> Option<usize> {
        self.slots.iter().position(|s| s.assembly.as_ref().is_some_and(|a| a.key == *key))
    }

    /// An assembly for the group `key` of `slot`, whose chunks carry
    /// `context`. `None`: no slot is free, the slot has its share, or the
    /// tcache has no room.
    pub(super) fn open(
        &mut self,
        key: &Bytes32,
        slot: u64,
        layout: Layout,
        context: &[u8; CONTEXT_BYTES],
        meta: Option<&Meta>,
        d: &SegmentDescriptor,
    ) -> Option<usize> {
        let of_slot = |s: &&Slot| s.assembly.as_ref().is_some_and(|a| a.slot == slot);
        if self.slots.iter().filter(of_slot).count() >= self.per_slot {
            return None;
        }
        let free = self.slots.iter().position(|s| s.assembly.is_none())?;
        let head_len = layout.fixed() + 32 * d.proof_len();
        let (n, k, size) = (d.n() as usize, d.k() as usize, d.segment_size as usize);
        let len = n * (size + head_len + 32);
        let reservation = self.producer.reserve(len, false)?;
        let base = NonNull::from(reservation.buffer().ok()?.get_mut(..len)?).cast();
        let mut assembly = Assembly {
            _reservation: reservation,
            base,
            key: *key,
            slot,
            context: *context,
            layout,
            claim: meta.map_or([0; CLAIM_BYTES], claim_of),
            meta: meta.copied(),
            told: [0; MAX_PEERS / 64],
            held: false,
            settled: false,
            d: *d,
            head_len,
            have: [0; MAX_N / 64],
            received: 0,
            from: [0; SENDERS],
            senders: 0,
        };
        // The last data segment is coded padded with zeros.
        assembly.bytes_mut((k - 1) * size, size).fill(0);
        let slot = &mut self.slots[free];
        slot.generation = slot.generation.wrapping_add(1);
        slot.assembly = Some(assembly);
        Some(free)
    }

    fn assembly(&self, at: usize) -> Option<&Assembly> {
        self.slots.get(at)?.assembly.as_ref()
    }

    /// The handle of the chunk at `index`, if it is there.
    pub(super) fn chunk(&self, at: usize, index: usize) -> Option<Buf> {
        let a = self.assembly(at).filter(|a| index < a.n() && a.has(index))?;
        Some(Buf {
            head: a.at(a.heads_at() + index * a.head_len),
            data: a.at(index * a.size()),
            head_len: a.head_len as u32,
            data_len: a.data_len(index) as u32,
            assembly: at as u16,
            index: index as u16,
            generation: self.slots[at].generation,
        })
    }

    /// The descriptor the assembly was opened with, which its chunks carry.
    pub(super) fn descriptor(&self, at: usize) -> Option<&SegmentDescriptor> {
        self.assembly(at).map(|a| &a.d)
    }

    pub(super) fn context(&self, at: usize) -> Option<&[u8; CONTEXT_BYTES]> {
        self.assembly(at).map(|a| &a.context)
    }

    pub(super) fn id(&self, at: usize, index: usize) -> &ChunkId {
        &self.slots[at].ids[index]
    }

    /// The lowest index that is there.
    pub(super) fn first(&self, at: usize) -> Option<usize> {
        let a = self.assembly(at)?;
        (0..a.n()).find(|&index| a.has(index))
    }

    pub(super) fn head(&self, at: usize, index: usize) -> Option<&[u8]> {
        self.assembly(at).filter(|a| index < a.n() && a.has(index)).map(|a| a.head(index))
    }

    /// Stores a proved chunk in its place. The caller checked the frame
    /// against the assembly's descriptor, so the lengths are the layout's.
    pub(super) fn put(
        &mut self,
        at: usize,
        index: usize,
        head: &[u8],
        data: &[u8],
        leaf: &Bytes32,
        id: &ChunkId,
    ) -> Option<Buf> {
        let slot = self.slots.get_mut(at)?;
        let a = slot.assembly.as_mut()?;
        if index >= a.n() || head.len() != a.head_len || data.len() != a.data_len(index) {
            return None;
        }
        let (size, heads_at, leaves_at) = (a.size(), a.heads_at(), a.leaves_at());
        a.bytes_mut(index * size, data.len()).copy_from_slice(data);
        a.bytes_mut(heads_at + index * head.len(), head.len()).copy_from_slice(head);
        a.bytes_mut(leaves_at + index * 32, 32).copy_from_slice(leaf);
        a.have[index / 64] |= 1 << (index % 64);
        slot.ids[index] = *id;
        self.chunk(at, index)
    }

    /// A chunk of the assembly `at` came from `peer`.
    pub(super) fn note_sender(&mut self, at: usize, peer: usize) {
        let Some(a) = self.slots.get_mut(at).and_then(|s| s.assembly.as_mut()) else {
            return;
        };
        a.received += 1;
        let known = &a.from[..a.senders as usize];
        if !known.contains(&(peer as u16)) && known.len() < SENDERS {
            a.from[known.len()] = peer as u16;
            a.senders += 1;
        }
    }

    fn ranked(&self, claim: &Claim) -> impl Iterator<Item = (usize, &Assembly)> {
        let held = self.slots.iter().enumerate();
        let assemblies = held.filter_map(|(at, slot)| Some((at, slot.assembly.as_ref()?)));
        assemblies.filter(move |(_, a)| self.ranked && a.ranks_with(claim))
    }

    fn assembly_mut(&mut self, at: usize) -> Option<&mut Assembly> {
        self.slots.get_mut(at)?.assembly.as_mut()
    }

    /// Ranks the assembly `at`, just opened for a group from a peer. It is
    /// forwarded if its votes are a strict superset of those of the group
    /// forwarded so far, which is then held, or if there is none and no
    /// group that passed level 2 has its votes. Otherwise it is held.
    pub(super) fn rank(&mut self, at: usize) {
        let Some(new) = self.assembly(at).map(|a| a.claim) else {
            return;
        };
        if self.ranked(&new).all(|(ranked, _)| ranked != at) {
            return;
        }
        let others = || self.ranked(&new).filter(|&(other, _)| other != at);
        let primary = others().find(|(_, a)| a.primary()).map(|(at, a)| (at, a.claim));
        let (held, demoted) = match primary {
            Some((primary, of)) if covers(&new, &of) && new != of => (false, Some(primary)),
            Some(_) => (true, None),
            None => (others().any(|(_, a)| a.passed() && covers(&a.claim, &new)), None),
        };
        if let Some(a) = demoted.and_then(|demoted| self.assembly_mut(demoted)) {
            a.held = true;
        }
        if let Some(a) = self.assembly_mut(at) {
            a.held = held;
        }
    }

    /// Whether a group that passed level 2 has every vote of `claim`.
    pub(super) fn covered(&self, claim: &Claim) -> bool {
        self.ranked(claim).any(|(_, a)| a.passed() && covers(&a.claim, claim))
    }

    /// Whether the group `key` is held. `None`: no assembly of it.
    pub(super) fn held(&self, key: &Bytes32) -> Option<bool> {
        self.find(key).and_then(|at| self.assembly(at)).map(|a| a.held)
    }

    /// Level 2 of the assembly `at` ran. Passed, the group is forwarded
    /// unless one that passed before has its votes.
    pub(super) fn settle(&mut self, at: usize, passed: bool) {
        let Some(of) = self.assembly(at).map(|a| a.claim) else {
            return;
        };
        let covering = |&(other, by): &(usize, &Assembly)| {
            other != at && by.passed() && covers(&by.claim, &of)
        };
        let held = !passed || self.ranked(&of).any(|other| covering(&other));
        if let Some(a) = self.assembly_mut(at) {
            (a.settled, a.held) = (true, held);
        }
        if held {
            self.slots[at].deferred.clear();
        }
    }

    /// The assembly `at` is of a body of ours: level 2 holds by
    /// construction, and its chunks go out whatever its votes.
    pub(super) fn settle_ours(&mut self, at: usize) {
        if let Some(a) = self.assembly_mut(at) {
            a.settled = true;
        }
    }

    /// Where no group of the slot and committee of the assembly `at` is
    /// forwarded before its level 2, the held one with the most votes is,
    /// unless a group that passed has its votes.
    pub(super) fn promote(&mut self, at: usize) {
        let Some(like) = self.assembly(at).map(|a| a.claim) else {
            return;
        };
        if self.ranked(&like).any(|(_, a)| a.primary()) {
            return;
        }
        let covered = |a: &Assembly| {
            self.ranked(&like).any(|(_, by)| by.passed() && covers(&by.claim, &a.claim))
        };
        let waiting = self.ranked(&like).filter(|(_, a)| a.held && !a.settled && !covered(a));
        let next = waiting.max_by_key(|(_, a)| a.votes()).map(|(next, _)| next);
        if let Some(a) = next.and_then(|next| self.assembly_mut(next)) {
            a.held = false;
        }
    }

    /// The write of the held chunk `buf` to `peer` is put off.
    pub(super) fn defer(&mut self, buf: &Buf, peer: usize) {
        let slot = &mut self.slots[buf.assembly as usize];
        if slot.assembly.as_ref().is_some_and(|a| !a.settled) && slot.deferred.len() < DEFERRED {
            slot.deferred.push((peer as u16, buf.index));
        }
    }

    /// A write put off of a group no longer held: the peer and the chunk.
    pub(super) fn pop_deferred(&mut self) -> Option<(usize, Buf)> {
        let due = |s: &Slot| !s.deferred.is_empty() && s.assembly.as_ref().is_some_and(|a| !a.held);
        let at = self.slots.iter().position(due)?;
        let (peer, index) = self.slots[at].deferred.pop()?;
        Some((peer as usize, self.chunk(at, index as usize)?))
    }

    /// Of the group `buf` is of: its slot, the block its chunks name, its
    /// descriptor, the chunks taken from peers and the first peers they came
    /// from.
    pub(super) fn origin(
        &self,
        buf: &Buf,
    ) -> Option<(u64, &[u8], &SegmentDescriptor, u16, &[u16])> {
        let a = self.assembly(buf.assembly as usize)?;
        Some((a.slot, &a.context[8..], &a.d, a.received, &a.from[..a.senders as usize]))
    }

    /// The slot the chunks of `buf`'s group name, as their frames carry it.
    pub(super) fn named_slot(&self, buf: &Buf) -> Option<&[u8]> {
        self.assembly(buf.assembly as usize).map(|a| &a.context[..8])
    }

    /// Whether `buf` is of an assembly that is still held.
    pub(super) fn live(&self, buf: &Buf) -> bool {
        self.slots
            .get(buf.assembly as usize)
            .is_some_and(|s| s.assembly.is_some() && s.generation == buf.generation)
    }

    /// `peer` has the claim of the assembly `at`: it sent a chunk of the
    /// group, or holds one.
    pub(super) fn note_told(&mut self, at: usize, peer: usize) {
        if let Some(a) = self.assembly_mut(at) &&
            let Some(word) = a.told.get_mut(peer / 64)
        {
            *word |= 1 << (peer % 64);
        }
    }

    /// The claim to send with the chunk `buf` to `peer`: that of an aggregate
    /// whose claim the peer is not known to have. The peer then is.
    pub(super) fn claim_for(&mut self, buf: &Buf, peer: usize) -> Option<&Meta> {
        let a = self.assembly_mut(buf.assembly as usize)?;
        let word = a.told.get_mut(peer / 64)?;
        let told = *word >> (peer % 64) & 1 == 1;
        *word |= 1 << (peer % 64);
        a.meta.as_ref().filter(|_| !told)
    }

    /// The layout of the frames of `buf`'s group.
    pub(super) fn layout(&self, buf: &Buf) -> Option<Layout> {
        self.assembly(buf.assembly as usize).map(|a| a.layout)
    }

    /// Whether `buf` is of a group that is not forwarded.
    pub(super) fn withheld(&self, buf: &Buf) -> bool {
        self.assembly(buf.assembly as usize).is_some_and(|a| a.held)
    }

    /// The pinned message of a live chunk.
    pub(super) fn wire(&mut self, buf: &Buf) -> &mut Option<AcquiredRead> {
        &mut self.slots[buf.assembly as usize].wire[buf.index()]
    }

    /// Frees the assemblies of the slots before `wall_slot`: an assembly is
    /// held to the end of its slot.
    pub(super) fn expire(&mut self, wall_slot: u64) {
        for slot in &mut self.slots {
            if slot.assembly.as_ref().is_some_and(|a| a.slot < wall_slot) {
                slot.assembly = None;
                slot.deferred.clear();
                slot.wire.iter_mut().for_each(|read| *read = None);
            }
        }
    }

    /// Level 2 in place: every chunk not there is computed, and the tree over
    /// all of them has the committed root. `None`: the group is inconsistent.
    fn complete(&mut self, at: usize) -> Option<MerkleTree> {
        let a = self.slots.get_mut(at)?.assembly.as_mut()?;
        let (d, n, k, size) = (a.d, a.n(), a.d.k() as usize, a.size());
        let have = a.have;
        let leaves_at = a.leaves_at();
        // SAFETY: three disjoint ranges of the reservation.
        let total = usize::try_from(d.total_length).ok()?;
        let (data, parity, leaves) = unsafe {
            let base = a.base.as_ptr();
            (
                slice::from_raw_parts_mut(base, k * size),
                slice::from_raw_parts_mut(base.add(k * size), (n - k) * size),
                slice::from_raw_parts(base.add(leaves_at), n * 32),
            )
        };
        let (leaves, []) = leaves.as_chunks::<32>() else {
            return None;
        };
        let tree =
            complete_in_place(&d, data, parity, |i| have[i / 64] >> (i % 64) & 1 == 1, leaves)?;
        // The pad of the last data segment is zero whichever chunks it was
        // computed from (`seacast-lite.md` §3, level 2).
        data.get(total..)?.iter().all(|&b| b == 0).then_some(tree)
    }

    /// The segmented body of a complete assembly. Its `index` is the
    /// descriptor's `encoding`.
    fn body(&self, at: usize) -> Option<Buf> {
        let a = self.assembly(at)?;
        Some(Buf {
            head: a.base,
            head_len: u32::try_from(a.d.total_length).ok()?,
            index: a.d.encoding as u16,
            assembly: at as u16,
            generation: self.slots[at].generation,
            ..Buf::EMPTY
        })
    }
}

/// The pool of the codec the store's codec is built over. That codec makes no
/// chunk: the store builds and rebuilds them in place.
pub(super) struct NoPool;

impl BufferPool<Buf> for NoPool {
    fn alloc_from_slice(&mut self, _data: &[u8]) -> Buf {
        Buf::EMPTY
    }
}

/// The payload's codec over the store. Level 1 is the binding's, run before a
/// chunk is stored; level 2 is the store's.
pub(super) struct StoreCodec {
    pub(super) inner: PayloadCodec<NoPool, Buf>,
    pub(super) store: Store,
    /// The type of the topic's groups, as `inner` has it.
    pub(super) object_type: TypeId,
}

impl StoreCodec {
    /// The chunk at `index` of the assembly `at`, as the node holds it.
    pub(super) fn chunk_msg(
        &self,
        at: usize,
        index: usize,
        leaf: Bytes32,
    ) -> Option<ChunkMsg<Buf>> {
        let a = self.store.assembly(at)?;
        Some(ChunkMsg {
            group: topic_group(self.object_type, a.key),
            index: index as u32,
            cached_id: *self.store.id(at, index),
            frame: self.store.chunk(at, index)?,
            memo: leaf,
            wire_len: 0,
        })
    }
}

impl TypeCodec<Buf> for StoreCodec {
    fn shape(&self, chunk: &ChunkMsg<Buf>) -> Option<Shape> {
        self.inner.shape(chunk)
    }

    fn check(&self, chunk: &ChunkMsg<Buf>) -> bool {
        self.inner.check(chunk)
    }

    /// A chunk is stored once its proof holds.
    fn check_proof(&mut self, _chunk: &ChunkMsg<Buf>) -> ValidationResult {
        ValidationResult::Accept
    }

    fn header_id(&self, chunk: &ChunkMsg<Buf>) -> Bytes32 {
        self.inner.header_id(chunk)
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<Buf>) -> &'a [u8] {
        self.inner.context(chunk)
    }

    /// The object returned is the segmented body, as it lies in the assembly.
    fn decode(
        &mut self,
        group: &GroupId,
        _available: &[ChunkMsg<Buf>],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<Buf>>,
    ) -> Option<Buf> {
        let at = self.store.find(&group.key)?;
        let (d, had, key, context, layout) = {
            let a = self.store.assembly(at)?;
            (a.d, a.have, a.key, a.context, a.layout)
        };
        let context = &context[..layout.context_len()];
        let tree = self.store.complete(at)?;
        for index in 0..d.n() as usize {
            if had[index / 64] >> (index % 64) & 1 == 0 {
                let head = layout.build(context, &key, &d, index as u32, &tree.proof(index), &[]);
                let (data, len) = {
                    let a = self.store.assembly(at)?;
                    (a.at(index * a.size()), a.data_len(index))
                };
                // SAFETY: the segment just computed, within the reservation.
                let data = unsafe { slice::from_raw_parts(data.as_ptr(), len) };
                let id = self.inner.chunk_id(group, index as u32, &head, data);
                // The head is all that is written: the data is in its place.
                let slot = &mut self.store.slots[at];
                let a = slot.assembly.as_mut()?;
                let (heads_at, leaves_at) = (a.heads_at(), a.leaves_at());
                a.bytes_mut(heads_at + index * head.len(), head.len()).copy_from_slice(&head);
                a.bytes_mut(leaves_at + index * 32, 32).copy_from_slice(&tree.leaf(index));
                a.have[index / 64] |= 1 << (index % 64);
                slot.ids[index] = id;
            }
            out_rebuilt.push(self.chunk_msg(at, index, tree.leaf(index))?);
        }
        self.store.body(at)
    }

    fn wire_size(&self, chunk: &ChunkMsg<Buf>, first_of_group: bool) -> usize {
        self.inner.wire_size(chunk, first_of_group)
    }
}
