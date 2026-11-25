//! The node's host: the groups it admits, the slot clock, timers, and what the
//! node hands back to be done after a call.

use std::{cmp::Ordering, collections::BinaryHeap};

use seacast_core::{
    Bytes32, DecodeJob, GroupId, NodeId, PeerId, PenaltyReason, RuntimeEnv, Shape, TimerEvent,
    Timestamp, ValidationResult,
};
use seacast_gossipsub::PayloadHost;

use super::store::Buf;

const ACCEPTED: usize = 256;

/// The domain, as a stand-in: the bid commits no descriptor yet, so the first
/// groups seen in a slot are taken as authentic, as Prysm's interim authority
/// takes them. The slot and block a chunk names are not looked up.
/// A group's slot is the wall slot at its first chunk. Whether the body is a
/// block's payload is Beacon State's to say, of the envelope decoded.
pub(super) struct Host {
    /// The groups admitted, newest last written, each with its slot.
    accepted: [(GroupId, u64); ACCEPTED],
    next_accepted: usize,
    /// Groups admitted in one slot of our clock.
    groups_per_slot: usize,
    node_ids: Vec<NodeId>,
    pub(super) wall_slot: u64,
    /// The start of `wall_slot` on the node's clock, and a slot's length.
    pub(super) slot_start: Timestamp,
    pub(super) slot_secs: f64,
}

impl Host {
    pub(super) fn new(max_peers: usize, groups_per_slot: usize) -> Self {
        Self {
            accepted: [(GroupId::default(), u64::MAX); ACCEPTED],
            next_accepted: 0,
            groups_per_slot,
            node_ids: vec![[0; 32]; max_peers],
            wall_slot: 0,
            slot_start: 0.0,
            slot_secs: 0.0,
        }
    }

    pub(super) fn set_node_id(&mut self, peer: PeerId, id: NodeId) {
        if let Some(slot) = self.node_ids.get_mut(peer as usize) {
            *slot = id;
        }
    }

    fn slot_of(&self, group: &GroupId) -> Option<u64> {
        self.accepted.iter().find(|(g, slot)| g == group && *slot != u64::MAX).map(|&(_, s)| s)
    }

    /// Admits `group` in the wall slot. Our own group is admitted whatever
    /// the slot holds.
    pub(super) fn admit(&mut self, group: GroupId) {
        if self.slot_of(&group).is_none() {
            self.accepted[self.next_accepted] = (group, self.wall_slot);
            self.next_accepted = (self.next_accepted + 1) % ACCEPTED;
        }
    }
}

impl PayloadHost for Host {
    fn authenticate(
        &mut self,
        group: &GroupId,
        _header_id: &Bytes32,
        _context: &[u8],
    ) -> ValidationResult {
        if self.slot_of(group).is_some() {
            return ValidationResult::Accept;
        }
        let slot = self.wall_slot;
        // No fault of the sender: two peers that disagree prove nothing.
        if self.accepted.iter().filter(|(_, of)| *of == slot).count() >= self.groups_per_slot {
            return ValidationResult::Ignore;
        }
        self.admit(*group);
        ValidationResult::Accept
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.slot_of(group).is_some()
    }

    /// The end of the group's slot, when its assembly is freed.
    fn deadline(&self, group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        let slot = self.slot_of(group).unwrap_or(self.wall_slot);
        let slots = (slot + 1) as f64 - self.wall_slot as f64;
        Some(self.slot_start + slots * self.slot_secs)
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        self.node_ids.get(peer as usize).copied().unwrap_or_default()
    }
}

struct Timer {
    due: Timestamp,
    seq: u64,
    event: TimerEvent,
}

impl PartialEq for Timer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Timer {}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Earliest first out of a max-heap, in the order scheduled among equals.
impl Ord for Timer {
    fn cmp(&self, other: &Self) -> Ordering {
        other.due.total_cmp(&self.due).then(other.seq.cmp(&self.seq))
    }
}

pub(super) struct Env {
    pub(super) now: Timestamp,
    timers: BinaryHeap<Timer>,
    seq: u64,
    /// Peers the node has something to send to.
    pub(super) to_write: Vec<PeerId>,
    pub(super) to_decode: Vec<(GroupId, Shape)>,
    pub(super) delivered: Vec<Buf>,
    pub(super) penalties: Vec<(PeerId, PenaltyReason)>,
}

impl Env {
    pub(super) fn new() -> Self {
        Self {
            now: 0.0,
            timers: BinaryHeap::with_capacity(4096),
            seq: 0,
            to_write: Vec::with_capacity(256),
            to_decode: Vec::with_capacity(16),
            delivered: Vec::with_capacity(16),
            penalties: Vec::with_capacity(64),
        }
    }

    pub(super) fn pop_due(&mut self) -> Option<TimerEvent> {
        (self.timers.peek()?.due <= self.now).then(|| self.timers.pop().unwrap().event)
    }
}

impl RuntimeEnv<Buf> for Env {
    fn now(&self) -> Timestamp {
        self.now
    }

    fn schedule_after(&mut self, delay: f64, event: TimerEvent) {
        self.seq += 1;
        self.timers.push(Timer { due: self.now + delay, seq: self.seq, event });
    }

    fn wake_writer(&mut self, peer: PeerId) {
        if !self.to_write.contains(&peer) {
            self.to_write.push(peer);
        }
    }

    /// Level 2 runs in place in the store, after the node's call returns: the
    /// job's chunks are the assembly's.
    fn start_decode(&mut self, group: GroupId, job: DecodeJob<'_, Buf>) {
        self.to_decode.push((group, *job.shape));
    }

    fn deliver(&mut self, _group: GroupId, object: Buf) {
        self.delivered.push(object);
    }

    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.penalties.push((peer, reason));
    }
}
