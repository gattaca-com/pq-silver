use rustc_hash::{FxHashMap, FxHashSet};
use silver_beacon_state_data::{Slot, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use silver_common::ssz_view::{AttestationPqView, MAX_COMMITTEES_PER_SLOT_PQ};

use super::{
    claims::{Claim, Group, Member},
    strategy::MAX_GROUPS,
    wire::{AggregateRequest, AggregateResponse},
};

/// Attestation slots the rolling proof spans. A merge tells `MAX_GROUPS`
/// committees apart, and a proposal then includes votes 2 to 5 slots old,
/// the range that still earns the timely-source flag.
pub(super) const POOL_SLOTS: Slot = (MAX_GROUPS / MAX_COMMITTEES_PER_SLOT_PQ) as Slot;

const LOG_INV_RATE: u8 = 2;

/// A proof and the votes it proves: `claims` is exactly the claims of
/// `groups`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Proved {
    /// One per committee and attestation data.
    groups: Vec<Group>,
    /// Sorted, without repeats.
    claims: Vec<Claim>,
    proof: Vec<u8>,
}

impl Proved {
    /// `claims` and `proof` are for the votes of `groups`. Groups of one
    /// committee and data are united.
    pub(super) fn new(
        groups: impl IntoIterator<Item = Group>,
        claims: Vec<Claim>,
        proof: Vec<u8>,
    ) -> Self {
        Self { groups: united(groups), claims, proof }
    }

    fn newest_slot(&self) -> Slot {
        self.groups.iter().map(|group| group.slot).max().unwrap_or(0)
    }

    fn attestations(&self) -> Vec<Vec<u8>> {
        on_chain_attestations(&self.groups)
    }
}

/// Spec `compute_on_chain_aggregate`, per attestation data: its committees in
/// index order. `groups` holds one group per committee and data.
pub(super) fn on_chain_attestations(groups: &[Group]) -> Vec<Vec<u8>> {
    let mut data_order: Vec<&Group> = Vec::new();
    for group in groups {
        if !data_order.iter().any(|first| first.committee.data == group.committee.data) {
            data_order.push(group);
        }
    }
    let attestation = |first: &&Group| {
        let data = &first.committee.data;
        let mut committees: Vec<_> = (groups.iter())
            .filter(|group| group.committee.data == *data)
            .map(|group| (group.committee.index, group.bitlist()))
            .collect();
        committees.sort_unstable_by_key(|(index, _)| *index);
        let committees = committees.iter().map(|(index, votes)| (*index, votes.as_slice()));
        AttestationPqView::encode_committees(data, committees)
            .expect("committees of one data ascend in range")
    };
    data_order.iter().map(attestation).collect()
}

pub(super) fn united(groups: impl IntoIterator<Item = Group>) -> Vec<Group> {
    let mut united: Vec<Group> = Vec::new();
    for group in groups {
        match united.iter_mut().find(|held| held.committee == group.committee) {
            Some(held) => {
                held.members.extend(group.members);
                held.members.sort_unstable_by_key(|member| member.position);
                held.members.dedup_by_key(|member| member.position);
            }
            None => united.push(group),
        }
    }
    united
}

pub(super) fn claims_of(groups: &[Group]) -> Vec<Claim> {
    let mut claims: Vec<Claim> =
        groups.iter().flat_map(|group| &group.members).map(|member| member.claim).collect();
    claims.sort_unstable();
    claims.dedup();
    claims
}

/// A request in flight that changes the rolling proof.
pub(super) enum RollingJob {
    /// Takes in the proof of attestation slot `slot`.
    Roll { slot: Slot, taken: Proved },
    /// Proves only `groups`, a part of what the rolling proof covers.
    Reduce { groups: Vec<Group> },
}

/// One proof of the pooled votes not yet on chain, kept ready for a local
/// proposal. Each slot it takes in the proof of the newest sealed slot, and
/// it is proved again without the votes a block included or that grew old.
#[derive(Default)]
pub(super) struct Rolling {
    current: Option<Proved>,
    /// The proof before the last roll. A proposal that may not yet include
    /// the newest slot uses it.
    previous: Option<Proved>,
    /// The newest attestation slot taken in.
    rolled_through: Option<Slot>,
    /// Validators whose vote of a slot a block included.
    on_chain: FxHashMap<Slot, FxHashSet<u32>>,
    /// Votes of slots before this are too old to keep.
    floor: Slot,
}

impl Rolling {
    pub(super) fn include_on_chain(&mut self, slot: Slot, validators: &[u32]) {
        if slot >= self.floor {
            self.on_chain.entry(slot).or_default().extend(validators);
        }
    }

    pub(super) fn expire_before(&mut self, floor: Slot) {
        self.floor = self.floor.max(floor);
        self.on_chain.retain(|&slot, _| slot >= self.floor);
    }

    pub(super) fn claims_len(&self) -> usize {
        self.current.as_ref().map_or(0, |current| current.claims.len())
    }

    /// Whether the proof of attestation slot `slot` is still to take in.
    pub(super) fn awaits(&self, slot: Slot) -> bool {
        slot >= self.floor && self.rolled_through.is_none_or(|through| through < slot)
    }

    /// The attestations and proof for the body of the block at `block_slot`:
    /// the newest proof whose votes are all old enough to include.
    pub(super) fn block_proof(&self, block_slot: Slot) -> Option<(Vec<Vec<u8>>, &[u8])> {
        let includable = |proved: &&Proved| {
            proved.newest_slot() + MIN_ATTESTATION_INCLUSION_DELAY_PQ <= block_slot
        };
        let proved = [&self.current, &self.previous].into_iter().flatten().find(includable)?;
        Some((proved.attestations(), &proved.proof))
    }

    /// The votes of the current proof that are neither on chain nor too old,
    /// when that leaves some out.
    fn reduced(&self) -> Option<Vec<Group>> {
        let current = self.current.as_ref()?;
        let kept = |group: &Group| {
            let included = self.on_chain.get(&group.slot);
            let members: Vec<Member> = (group.members.iter())
                .filter(|member| included.is_none_or(|set| !set.contains(&member.validator)))
                .copied()
                .collect();
            (group.slot >= self.floor && !members.is_empty())
                .then(|| Group { members, ..group.clone() })
        };
        let groups: Vec<Group> = current.groups.iter().filter_map(kept).collect();
        (groups != current.groups).then_some(groups)
    }

    /// Drops what needs no proof: a current proof reduced to nothing. Returns
    /// the reduction that does need one.
    pub(super) fn next_reduction(&mut self) -> Option<Vec<Group>> {
        let groups = self.reduced()?;
        if groups.is_empty() {
            self.current = None;
            return None;
        }
        Some(groups)
    }

    /// The request that proves only `groups` out of the current proof.
    pub(super) fn reduce_request<'a>(&'a self, kept: &'a [Claim]) -> Option<AggregateRequest<'a>> {
        let current = self.current.as_ref()?;
        Some(AggregateRequest {
            log_inv_rate: LOG_INV_RATE,
            proofs: vec![(current.claims.as_slice(), current.proof.as_slice())],
            signatures: Vec::new(),
            output: Some(kept),
        })
    }

    /// Takes `taken` in with no request when there is no current proof.
    /// Otherwise returns the request that proves both.
    pub(super) fn roll_request<'a>(&'a self, taken: &'a Proved) -> Option<AggregateRequest<'a>> {
        let current = self.current.as_ref()?;
        Some(AggregateRequest {
            log_inv_rate: LOG_INV_RATE,
            proofs: vec![
                (current.claims.as_slice(), current.proof.as_slice()),
                (taken.claims.as_slice(), taken.proof.as_slice()),
            ],
            signatures: Vec::new(),
            output: None,
        })
    }

    /// `taken`, the proof of attestation slot `slot`, becomes the current
    /// proof: there was none to merge it with.
    pub(super) fn start_with(&mut self, slot: Slot, taken: Proved) {
        debug_assert!(self.current.is_none());
        self.previous = None;
        self.current = Some(taken);
        self.rolled_through = Some(slot);
    }

    /// Settles `job` with the leanVM sidecar's response body, or `None`
    /// without an answer. The response's proof is adopted only if it proves
    /// exactly the claims the job asked for. A slot whose roll fails is not
    /// tried again.
    pub(super) fn finish(
        &mut self,
        job: RollingJob,
        body: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        let current = self.current.take().ok_or("the rolling proof is gone")?;
        let (groups, rolled) = match job {
            RollingJob::Roll { slot, taken } => {
                self.rolled_through = Some(slot);
                (united(current.groups.iter().cloned().chain(taken.groups)), true)
            }
            RollingJob::Reduce { groups } => (groups, false),
        };
        let proved = body.ok_or("no answer").and_then(AggregateResponse::decode).and_then(
            |AggregateResponse { claims, proof }| {
                (claims == claims_of(&groups))
                    .then(|| Proved { groups, claims, proof: proof.to_vec() })
                    .ok_or("the proof covers other claims")
            },
        );
        match proved {
            Ok(proved) => {
                if rolled {
                    self.previous = Some(current);
                }
                self.current = Some(proved);
                Ok(())
            }
            Err(reason) => {
                self.current = Some(current);
                Err(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests;
