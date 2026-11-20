use std::{collections::VecDeque, mem};

use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, Nanos, TCacheProducer, TCacheRead, TCacheReader,
    TProducer, ssz_view::MAX_VALIDATORS_PER_COMMITTEE, ticker::SlotTicker,
};

use super::{
    Aggregate, Aggregation, VerifiedVote,
    claims::VerifiedClaims,
    leaf::{LeafAggregation, LeafKey},
    merge::MergeAggregation,
    strategy::Batch,
};
use crate::tile::Producers;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AggregationKey {
    Leaf(LeafKey),
    Merge(Slot),
}

impl AggregationKey {
    fn slot(&self) -> Slot {
        match self {
            Self::Leaf(leaf) => leaf.slot,
            Self::Merge(slot) => *slot,
        }
    }
}

/// The leanVM sidecar as the aggregator sees it: one request at a time, and
/// none while it is down.
#[derive(Default)]
enum LeanVm {
    #[default]
    Down,
    Idle,
    Busy {
        request_id: u64,
        key: AggregationKey,
        batch: Batch,
    },
}

impl LeanVm {
    fn up(&mut self) {
        if let Self::Down = self {
            *self = Self::Idle;
        }
    }

    /// The batch that was in flight, now lost.
    fn down(&mut self) -> Option<(AggregationKey, Batch)> {
        match mem::take(self) {
            Self::Busy { key, batch, .. } => Some((key, batch)),
            Self::Down | Self::Idle => None,
        }
    }

    /// Becomes idle if `request_id` is in flight, handing back its batch.
    fn take_answered(&mut self, request_id: u64) -> Option<(AggregationKey, Batch)> {
        match mem::take(self) {
            Self::Busy { request_id: id, key, batch } if id == request_id => {
                *self = Self::Idle;
                Some((key, batch))
            }
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Every aggregation this node runs. One `LeanVmReq` is in flight at a time,
/// across all aggregations.
#[derive(Default)]
pub struct PqAggregator {
    leaves: FxHashMap<LeafKey, LeafAggregation>,
    merges: FxHashMap<Slot, MergeAggregation>,
    /// Aggregations that may have a batch, oldest first, each at most once.
    /// Merges are taken before leaves.
    queue: VecDeque<AggregationKey>,
    leanvm: LeanVm,
    next_request_id: u64,
}

impl PqAggregator {
    pub fn add_vote(
        &mut self,
        vote: VerifiedVote,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        let leaf = LeafKey::new(&vote);
        if vote.committee_position >= vote.committee_len.min(MAX_VALIDATORS_PER_COMMITTEE) {
            let (committee_position, committee_len) = (vote.committee_position, vote.committee_len);
            silver_log::error!(
                slot = leaf.slot,
                committee_position,
                committee_len,
                "vote outside committee"
            );
            return;
        }
        // TODO: the aggregate due time stands in for the VC's pull. A VC that
        // pulls later gets a proof frozen at the due time. Consider ending on
        // the last local aggregator's pull instead.
        let deadline = ticker.aggregate_due(leaf.slot);
        if ticker.since_genesis() >= deadline {
            silver_log::debug!(slot = leaf.slot, "vote after the aggregation deadline");
            return;
        }
        let aggregation =
            self.leaves.entry(leaf).or_insert_with(|| LeafAggregation::new(&vote, deadline));
        let added = aggregation.add(&vote);
        debug_assert!(added, "the position was checked against the largest committee");
        self.enqueue(AggregationKey::Leaf(leaf));
        self.send_next(ticker, tcache, producers);
    }

    /// `aggregate` is verified, for the block of `slot`. A merge refuses it
    /// once it holds too many committees.
    pub fn add_aggregate(
        &mut self,
        slot: Slot,
        aggregate: Aggregate,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        if !self.merges.entry(slot).or_insert_with(MergeAggregation::new).add(aggregate) {
            silver_log::warn!(slot, "aggregate dropped: the merge holds too many committees");
            return;
        }
        self.enqueue(AggregationKey::Merge(slot));
        self.send_next(ticker, tcache, producers);
    }

    /// A response to a request that is not in flight is ignored. A body that
    /// cannot be read counts as no answer.
    pub fn on_response(
        &mut self,
        resp: LeanVmResp,
        reader: &mut TCacheReader,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        let acquired = resp.body.map(|read| reader.acquire(read));
        let body = acquired.as_ref().and_then(|acquired| acquired.buffer().ok());
        if body.is_none() && acquired.is_some() {
            silver_log::error!(request_id = resp.request_id, "leanvm response unreadable");
        }
        let Some((key, batch)) = self.leanvm.take_answered(resp.request_id) else { return };
        self.finish(key, batch, body.map(|(body, _)| body));
        self.enqueue(key);
        self.send_next(ticker, tcache, producers);
    }

    /// A leanVM sidecar that goes down fails the batch in flight at once. The
    /// transport's `None` answer for it comes later and is ignored.
    pub fn on_health(
        &mut self,
        health: LeanVmHealthEvent,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        if health.ready {
            self.leanvm.up();
        } else if let Some((key, batch)) = self.leanvm.down() {
            self.finish(key, batch, None);
            self.enqueue(key);
        }
        self.send_next(ticker, tcache, producers);
    }

    /// Drops the aggregations of slots before `floor`. The request in flight
    /// for one still occupies the leanVM sidecar until its response arrives.
    pub fn prune_before(&mut self, floor: Slot) {
        self.leaves.retain(|leaf, _| leaf.slot >= floor);
        self.merges.retain(|&slot, _| slot >= floor);
        self.queue.retain(|key| key.slot() >= floor);
    }

    pub fn aggregate_ssz(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<Vec<u8>> {
        self.leaves.get(&LeafKey { slot, committee_index, data_root })?.attestation(committee_index)
    }

    pub fn block_proof(&self, slot: Slot) -> Option<(Vec<&[u8]>, &[u8])> {
        self.merges.get(&slot)?.block_proof()
    }

    /// A pruned aggregation drops `batch`.
    fn finish(&mut self, key: AggregationKey, batch: Batch, body: Option<&[u8]>) {
        match key {
            AggregationKey::Leaf(leaf) => {
                if let Some(aggregation) = self.leaves.get_mut(&leaf) {
                    settle(&mut aggregation.core, leaf.slot, batch, body);
                }
            }
            AggregationKey::Merge(slot) => {
                if let Some(aggregation) = self.merges.get_mut(&slot) {
                    settle(&mut aggregation.core, slot, batch, body);
                }
            }
        }
    }

    fn enqueue(&mut self, key: AggregationKey) {
        if !self.queue.contains(&key) {
            self.queue.push_back(key);
        }
    }

    fn pop_next(&mut self) -> Option<AggregationKey> {
        let merge = self.queue.iter().position(|key| matches!(key, AggregationKey::Merge(_)));
        self.queue.remove(merge.unwrap_or(0))
    }

    /// Sends the first batch the queue offers, if the leanVM sidecar is idle.
    /// An aggregation without a batch leaves the queue until its next event; a
    /// pruned one is skipped. One that meets a full tcache keeps its place,
    /// and the pass stops.
    fn send_next(
        &mut self,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        if !matches!(self.leanvm, LeanVm::Idle) {
            return;
        }
        let now = ticker.since_genesis();
        while let Some(key) = self.pop_next() {
            let next = match key {
                AggregationKey::Leaf(leaf) => (self.leaves.get_mut(&leaf))
                    .and_then(|leaf| next_request(&mut leaf.core, now, tcache)),
                AggregationKey::Merge(slot) => (self.merges.get_mut(&slot))
                    .and_then(|merge| next_request(&mut merge.core, now, tcache)),
            };
            let Some((batch, body)) = next else { continue };
            let Some(body) = body else {
                silver_log::error!(slot = key.slot(), "beacon_state tcache full; batch not sent");
                self.finish(key, batch, None);
                self.queue.push_front(key);
                return;
            };
            let request_id = self.next_request_id;
            self.next_request_id += 1;
            self.leanvm = LeanVm::Busy { request_id, key, batch };
            producers.produce(LeanVmReq { request_id, body });
            return;
        }
    }
}

fn settle<C: VerifiedClaims>(
    core: &mut Aggregation<C>,
    slot: Slot,
    batch: Batch,
    body: Option<&[u8]>,
) {
    if let Err(reason) = core.finish(batch, body) {
        silver_log::warn!(slot, reason, "aggregation batch failed");
        if core.is_stopped() {
            silver_log::warn!(slot, "aggregation stopped after repeated failures");
        }
    }
}

/// The next batch of `core`, with its request written to `tcache`. The request
/// is `None` when the tcache is full.
fn next_request<C: VerifiedClaims>(
    core: &mut Aggregation<C>,
    now: Nanos,
    tcache: &mut TProducer,
) -> Option<(Batch, Option<TCacheRead>)> {
    let batch = core.next_batch(now)?;
    let request = core.request(&batch);
    let body = tcache.write_with(request.len(), |out| request.write(out));
    Some((batch, body))
}
