use std::ops::Range;

use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, B256, Epoch, Slot};
use silver_common::{NewGossipMsg, TRead};
use silver_ssz::ssz_view::MAX_COMMITTEES_PER_SLOT_PQ;

use super::leanvm_verifier::ProofVerdict;
use crate::stf::VoteTarget;

const MAX_AWAITING: usize = 2 * MAX_COMMITTEES_PER_SLOT_PQ * AGGREGATORS_PER_COMMITTEE;

pub(super) struct AggregateAwaitingProof {
    pub target: VoteTarget,
    pub attesters: Vec<u32>,
    pub committee_index: u64,
    pub data_root: B256,
    pub aggregator_index: usize,
    /// The message its attesters signed, when this node merges it into a
    /// block proof.
    pub merge_message: Option<[u8; 32]>,
}

pub(super) enum GossipAwaitingProof {
    Aggregate(AggregateAwaitingProof),
    AttesterSlashing,
}

pub(super) struct AwaitingProofs {
    pub msg: NewGossipMsg,
    pub pin: TRead,
    pub gossip: GossipAwaitingProof,
    parked_at: Slot,
    requests: Range<u64>,
    unverified: usize,
}

#[derive(Default)]
pub(super) struct GossipProofs {
    awaiting: Vec<AwaitingProofs>,
}

impl GossipProofs {
    pub(super) fn is_full(&self) -> bool {
        self.awaiting.len() >= MAX_AWAITING
    }

    pub(super) fn awaits_aggregator(&self, target_epoch: Epoch, aggregator_index: usize) -> bool {
        self.awaiting.iter().any(|awaiting| match &awaiting.gossip {
            GossipAwaitingProof::Aggregate(aggregate) => {
                aggregate.target.target_epoch == target_epoch &&
                    aggregate.aggregator_index == aggregator_index
            }
            GossipAwaitingProof::AttesterSlashing => false,
        })
    }

    pub(super) fn park(
        &mut self,
        msg: NewGossipMsg,
        pin: TRead,
        gossip: GossipAwaitingProof,
        parked_at: Slot,
        requests: Range<u64>,
    ) {
        debug_assert!(!requests.is_empty() && !self.is_full());
        let unverified = (requests.end - requests.start) as usize;
        self.awaiting.push(AwaitingProofs { msg, pin, gossip, parked_at, requests, unverified });
    }

    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.awaiting.retain(|awaiting| awaiting.parked_at >= floor);
    }

    pub(super) fn awaits(&self, request_id: u64) -> bool {
        self.awaiting.iter().any(|awaiting| awaiting.requests.contains(&request_id))
    }

    pub(super) fn on_verdict(
        &mut self,
        request_id: u64,
        verdict: ProofVerdict,
    ) -> Option<AwaitingProofs> {
        let index =
            self.awaiting.iter().position(|awaiting| awaiting.requests.contains(&request_id))?;
        if verdict == ProofVerdict::Valid {
            let awaiting = &mut self.awaiting[index];
            awaiting.unverified -= 1;
            if awaiting.unverified > 0 {
                return None;
            }
        }
        Some(self.awaiting.swap_remove(index))
    }
}
