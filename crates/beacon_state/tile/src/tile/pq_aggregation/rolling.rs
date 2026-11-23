use rustc_hash::{FxHashMap, FxHashSet};
use silver_beacon_state_data::{Slot, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationPqView, MAX_COMMITTEES_PER_SLOT_PQ,
};

use super::{
    claims::{Claim, Group, Member},
    strategy::MAX_GROUPS,
    wire::{AggregateRequest, AggregateResponse},
};

/// Attestation slots the rolling proof spans. A merge tells `MAX_GROUPS`
/// committees apart, and a proposal then includes votes 2 to 5 slots old,
/// the range that still earns the timely-source flag.
pub(super) const POOL_SLOTS: Slot = (MAX_GROUPS / MAX_COMMITTEES_PER_SLOT_PQ) as Slot;

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

    fn on_chain(&self) -> OnChainAttestations<'_> {
        OnChainAttestations { groups: &self.groups, covered: None }
    }

    /// `self` and `taken`, the proof of attestation slot `slot`, as proved
    /// together by `response`.
    fn rolled(
        &self,
        slot: Slot,
        taken: Proved,
        response: AggregateResponse,
    ) -> Result<Proved, &'static str> {
        // Attestation data names its slot, so no committee of `taken` is in
        // `self`: the union is the concatenation.
        debug_assert!(self.groups.iter().all(|group| group.slot < slot));
        debug_assert!(taken.groups.iter().all(|group| group.slot == slot));
        if !is_union(&response.claims, &self.claims, &taken.claims) {
            return Err("the proof covers other claims");
        }
        let mut groups = Vec::with_capacity(self.groups.len() + taken.groups.len());
        groups.extend(self.groups.iter().cloned());
        groups.extend(taken.groups);
        Ok(Proved { groups, claims: response.claims, proof: response.proof.to_vec() })
    }

    /// `groups`, of `claims`, as proved alone by `response`.
    fn reduced(
        groups: Vec<Group>,
        claims: Vec<Claim>,
        response: AggregateResponse,
    ) -> Result<Proved, &'static str> {
        if response.claims != claims {
            return Err("the proof covers other claims");
        }
        Ok(Proved { groups, claims, proof: response.proof.to_vec() })
    }
}

/// The block body's attestations for some groups: spec
/// `compute_on_chain_aggregate`, one per attestation data in first-seen
/// order, its committees in index order. Groups of one committee are united.
pub struct OnChainAttestations<'a> {
    pub(super) groups: &'a [Group],
    /// Ascending indices into `groups`; `None` for all of them.
    pub(super) covered: Option<&'a [usize]>,
}

impl<'a> OnChainAttestations<'a> {
    pub fn len(&self) -> usize {
        self.first_of_each_data().count()
    }

    /// Appends them to `out` as an SSZ `List[AttestationPq]`. `None`, with
    /// `out` partly written, when groups of one committee disagree on its
    /// size.
    pub fn write_list(&self, out: &mut Vec<u8>) -> Option<()> {
        let start = out.len();
        out.resize(start + 4 * self.len(), 0);
        for (i, first) in self.first_of_each_data().enumerate() {
            let offset = (out.len() - start) as u32;
            out[start + 4 * i..start + 4 * (i + 1)].copy_from_slice(&offset.to_le_bytes());
            self.write_attestation(out, &first.committee.data)?;
        }
        Some(())
    }

    fn write_attestation(
        &self,
        out: &mut Vec<u8>,
        data: &[u8; ATTESTATION_DATA_SIZE],
    ) -> Option<()> {
        let of_data = self.groups().filter(move |group| group.committee.data == *data);
        let of_committee =
            move |index| of_data.clone().filter(move |group| group.committee.index == index);
        let (mut committee_bits, mut bits_len) = (0u16, 0);
        for index in 0..MAX_COMMITTEES_PER_SLOT_PQ {
            let mut lens = of_committee(index).map(|group| group.committee_len);
            let Some(len) = lens.next() else { continue };
            if lens.any(|other| other != len) {
                return None;
            }
            committee_bits |= 1 << index;
            bits_len += len;
        }
        let bits = AttestationPqView::append_unvoted(out, data, committee_bits, bits_len);
        let mut committee_start = 0;
        for index in 0..MAX_COMMITTEES_PER_SLOT_PQ {
            let mut groups = of_committee(index).peekable();
            let Some(len) = groups.peek().map(|group| group.committee_len) else { continue };
            for member in groups.flat_map(|group| &group.members) {
                let at = committee_start + member.position;
                out[bits + at / 8] |= 1 << (at % 8);
            }
            committee_start += len;
        }
        Some(())
    }

    fn groups(&self) -> impl Iterator<Item = &'a Group> + Clone {
        let covered = self.covered;
        let is_covered =
            move |index: &usize| covered.is_none_or(|covered| covered.binary_search(index).is_ok());
        let groups = self.groups;
        (0..groups.len()).filter(is_covered).map(move |index| &groups[index])
    }

    #[cfg(test)]
    pub(in crate::tile) fn encoded(&self) -> Vec<Vec<u8>> {
        let mut list = Vec::new();
        self.write_list(&mut list).expect("committees agree on their sizes");
        silver_common::ssz_view::variable_list_items(&list).map(<[u8]>::to_vec).collect()
    }

    fn first_of_each_data(&self) -> impl Iterator<Item = &'a Group> {
        let groups = self.groups();
        groups.clone().enumerate().filter_map(move |(at, group)| {
            let data = &group.committee.data;
            let seen = groups.clone().take(at).any(|earlier| earlier.committee.data == *data);
            (!seen).then_some(group)
        })
    }
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
    /// Proves only `groups`, a part of what the rolling proof covers, whose
    /// claims are `claims`.
    Reduce { groups: Vec<Group>, claims: Vec<Claim> },
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
    /// The current proof may cover votes it no longer needs.
    stale: bool,
}

impl Rolling {
    pub(super) fn include_on_chain(&mut self, slot: Slot, validators: &[u32]) {
        if slot >= self.floor {
            self.on_chain.entry(slot).or_default().extend(validators);
            self.stale = true;
        }
    }

    pub(super) fn expire_before(&mut self, floor: Slot) {
        self.stale |= floor > self.floor;
        self.floor = self.floor.max(floor);
        self.on_chain.retain(|&slot, _| slot >= self.floor);
    }

    /// Whether the proof of attestation slot `slot` is still to take in.
    pub(super) fn awaits(&self, slot: Slot) -> bool {
        slot >= self.floor && self.rolled_through.is_none_or(|through| through < slot)
    }

    /// The attestations and proof for the body of the block at `block_slot`:
    /// the newest proof whose votes are all old enough to include.
    pub(super) fn block_proof(&self, block_slot: Slot) -> Option<(OnChainAttestations<'_>, &[u8])> {
        let includable = |proved: &&Proved| {
            proved.newest_slot() + MIN_ATTESTATION_INCLUSION_DELAY_PQ <= block_slot
        };
        let proved = [&self.current, &self.previous].into_iter().flatten().find(includable)?;
        Some((proved.on_chain(), &proved.proof))
    }

    fn is_needed(&self, group: &Group, member: &Member) -> bool {
        let on_chain = self.on_chain.get(&group.slot);
        group.slot >= self.floor && on_chain.is_none_or(|set| !set.contains(&member.validator))
    }

    /// The votes of the current proof that are neither on chain nor too old,
    /// when that leaves some out.
    fn reduced(&self) -> Option<Vec<Group>> {
        let current = self.current.as_ref()?;
        let needed =
            |group: &Group| group.members.iter().all(|member| self.is_needed(group, member));
        if current.groups.iter().all(needed) {
            return None;
        }
        let kept = |group: &Group| {
            let members: Vec<_> = (group.members.iter())
                .filter(|member| self.is_needed(group, member))
                .copied()
                .collect();
            let Group { committee, slot, committee_len, .. } = *group;
            (!members.is_empty()).then_some(Group { committee, slot, committee_len, members })
        };
        Some(current.groups.iter().filter_map(kept).collect())
    }

    /// Drops what needs no proof: a current proof reduced to nothing. Returns
    /// the reduction that does need one.
    pub(super) fn next_reduction(&mut self) -> Option<Vec<Group>> {
        if !self.stale {
            return None;
        }
        let Some(groups) = self.reduced() else {
            self.stale = false;
            return None;
        };
        if groups.is_empty() {
            self.current = None;
            self.stale = false;
            return None;
        }
        Some(groups)
    }

    /// The request that proves only `groups` out of the current proof.
    pub(super) fn reduce_request<'a>(&'a self, kept: &'a [Claim]) -> Option<AggregateRequest<'a>> {
        let current = self.current.as_ref()?;
        Some(AggregateRequest {
            proofs: vec![(current.claims.as_slice(), current.proof.as_slice())],
            signatures: Vec::new(),
            output: Some(kept),
        })
    }

    /// The request that proves the current proof and a taken one, of
    /// `claims` and `proof`. `None` without a current proof: the taken proof
    /// then starts it with no request.
    pub(super) fn roll_request<'a>(
        &'a self,
        claims: &'a [Claim],
        proof: &'a [u8],
    ) -> Option<AggregateRequest<'a>> {
        let current = self.current.as_ref()?;
        Some(AggregateRequest {
            proofs: vec![(current.claims.as_slice(), current.proof.as_slice()), (claims, proof)],
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
        self.stale = true;
    }

    /// Settles `job` with the leanVM sidecar's response body, or `None`
    /// without an answer. The response's proof is adopted only if it proves
    /// exactly the claims the job asked for. A slot whose roll fails is not
    /// tried again. A failed reduction waits for the next change to the
    /// pool, so it cannot hold the leanVM sidecar in a retry loop.
    pub(super) fn finish(
        &mut self,
        job: RollingJob,
        body: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        let current = self.current.as_ref().ok_or("the rolling proof is gone")?;
        let response = body.ok_or("no answer").and_then(AggregateResponse::decode);
        match job {
            RollingJob::Roll { slot, taken } => {
                self.rolled_through = Some(slot);
                let rolled = current.rolled(slot, taken, response?)?;
                self.previous = self.current.replace(rolled);
            }
            RollingJob::Reduce { groups, claims } => {
                let reduced =
                    response.and_then(|response| Proved::reduced(groups, claims, response));
                match reduced {
                    Ok(reduced) => self.current = Some(reduced),
                    Err(reason) => {
                        self.stale = false;
                        return Err(reason);
                    }
                }
            }
        }
        self.stale = true;
        Ok(())
    }
}

/// Whether strictly ascending `claims` is the union of strictly ascending `a`
/// and `b`.
fn is_union(claims: &[Claim], a: &[Claim], b: &[Claim]) -> bool {
    let (mut a, mut b) = (a.iter().peekable(), b.iter().peekable());
    for claim in claims {
        let from_a = a.next_if_eq(&claim).is_some();
        let from_b = b.next_if_eq(&claim).is_some();
        if !from_a && !from_b {
            return false;
        }
    }
    a.next().is_none() && b.next().is_none()
}

#[cfg(test)]
mod tests;
