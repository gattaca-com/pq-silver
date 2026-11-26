use silver_common::{
    leanvm::ProofBody,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView, ProvedAttestationView},
};

use super::{
    bits::Bits,
    claims::{Claim, ClaimCheck, Committee, MAX_GROUPS},
    proof_store::{ProofId, ProofStore},
    proved::on_chain_attestations,
    segments::Segments,
};

/// Failed merges in a row that stop a target.
const MAX_FAILURES: u8 = 3;

pub(super) const MEMBER_BYTES: usize = size_of::<u32>() + size_of::<u16>();

pub(super) type VisitMember<'a> = dyn FnMut(&Committee, usize, usize, &Claim) -> bool + 'a;

#[derive(Clone, Copy)]
pub(super) struct ProvedGroup {
    pub committee: Committee,
    pub committee_len: usize,
    pub positions: Bits,
}

impl ProvedGroup {
    pub(super) fn bitlist(&self) -> Vec<u8> {
        let mut bits = vec![0; self.committee_len / 8 + 1];
        for position in self.positions.iter() {
            bits[position / 8] |= 1 << (position % 8);
        }
        bits[self.committee_len / 8] |= 1 << (self.committee_len % 8);
        bits
    }

    pub(super) fn records<'a>(
        &'a self,
        proofs: &'a ProofStore,
        proof: ProofId,
    ) -> impl Iterator<Item = (usize, u32, &'a Claim)> {
        let claims = proofs.claims(proof);
        let tail = proofs.tail(proof, claims.len() * MEMBER_BYTES);
        self.positions.iter().zip(tail.as_chunks::<MEMBER_BYTES>().0).map(|(position, record)| {
            let validator = u32::from_le_bytes(record.first_chunk().copied().unwrap());
            let rank = u16::from_le_bytes(record.last_chunk().copied().unwrap());
            (position, validator, &claims[usize::from(rank)])
        })
    }
}

type ProvedGroups = Segments<ProvedGroup, { MAX_GROUPS.div_ceil(4) }, 4>;

/// A failed merge leaves the proof of the target as it was.
#[derive(Default)]
pub(super) struct RunningProof {
    pub id: Option<ProofId>,
    groups: ProvedGroups,
    failures: u8,
}

impl RunningProof {
    pub(super) fn groups(&self) -> impl ExactSizeIterator<Item = &ProvedGroup> + Clone {
        (0..self.groups.len()).map(|index| self.groups.get(index))
    }

    pub(super) fn covered(&self, committee: &Committee) -> Bits {
        self.groups()
            .find(|group| group.committee == *committee)
            .map_or_else(Bits::default, |group| group.positions)
    }

    fn include(&mut self, committee: &Committee, committee_len: usize, position: usize) {
        let index = self.groups().position(|group| group.committee == *committee);
        let index = index.unwrap_or_else(|| {
            self.groups.push(ProvedGroup {
                committee: *committee,
                committee_len,
                positions: Bits::default(),
            })
        });
        let group = self.groups.get_mut(index);
        // A held position keeps its member, as fixed by the verified committee mapping.
        group.positions.insert(position);
    }

    pub(super) fn settle(
        &mut self,
        response: Result<ProofBody<'_>, &'static str>,
        running: Option<ProofId>,
        proofs: &mut ProofStore,
        allow_new: bool,
        check: &mut ClaimCheck,
        visit: impl Fn(&ProofStore, &mut VisitMember<'_>) -> bool,
    ) -> Result<(), &'static str> {
        let proved = response.and_then(|response| {
            let claims = response.claims();
            check.reset(claims.len());
            let mut replies = claims.iter().enumerate();
            let mut held = running.into_iter().flat_map(|id| proofs.claims(id));
            let held_matches = held.all(|claim| {
                let Some((index, found)) = replies.find(|&(_, found)| found >= claim) else {
                    return false;
                };
                if found != claim {
                    return false;
                }
                check.mark(index);
                true
            });
            let mut mark = |_: &Committee, _, _, claim: &Claim| {
                let Ok(index) = claims.binary_search(claim) else { return false };
                check.mark(index);
                true
            };
            if !held_matches || !visit(proofs, &mut mark) || !check.complete() {
                return Err("the proof covers other claims");
            }
            if !allow_new && self.id.is_none() {
                return Err("too many aggregate proofs");
            }
            Ok(response)
        });
        match proved {
            Ok(response) => {
                // A bare block target can take a seed while its vote merge runs.
                if self.id != running {
                    self.groups.clear();
                }
                visit(proofs, &mut |committee, len, position, _| {
                    self.include(committee, len, position);
                    true
                });
                self.id = Some(proofs.replace_response(self.id, running, response));
                self.failures = 0;
                Ok(())
            }
            Err(reason) => {
                self.failures = self.failures.saturating_add(1);
                Err(reason)
            }
        }
    }

    pub(super) fn take_aggregate(
        &mut self,
        id: ProofId,
        group: ProvedGroup,
        proofs: &mut ProofStore,
    ) {
        debug_assert!(self.id.is_none(), "only a target without a proof takes an aggregate");
        proofs.share(id);
        self.id = Some(id);
        self.groups.push(group);
    }

    pub(super) fn block_attestations<'a>(
        &self,
        proofs: &'a ProofStore,
    ) -> Option<(Vec<Vec<u8>>, &'a [u8])> {
        let id = self.id?;
        Some((on_chain_attestations(self.groups()), proofs.proof(id)))
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// The proof as the aggregate of its one committee. `None` without a
    /// proof, or with votes of more than one committee.
    pub(super) fn aggregate<'a>(&'a self, proofs: &'a ProofStore) -> Option<ProvedAggregate<'a>> {
        let id = self.id?;
        let mut groups = self.groups();
        if groups.len() != 1 {
            return None;
        }
        let group = groups.next().unwrap();
        let positions = group.positions.iter().collect();
        let Committee { data, index } = &group.committee;
        ProvedAggregate::new(data, *index, group.committee_len, positions, proofs.proof(id))
    }
}

/// A proof of votes of one committee, as a `ProvedAttestationView`.
pub struct ProvedAggregate<'a> {
    data: &'a [u8; ATTESTATION_DATA_SIZE],
    committee_index: usize,
    committee_len: usize,
    attestation_len: usize,
    /// Each below `committee_len`.
    positions: Vec<usize>,
    proof: &'a [u8],
}

impl<'a> ProvedAggregate<'a> {
    /// `None` for a committee index or length out of range.
    pub(super) fn new(
        data: &'a [u8; ATTESTATION_DATA_SIZE],
        committee_index: usize,
        committee_len: usize,
        positions: Vec<usize>,
        proof: &'a [u8],
    ) -> Option<Self> {
        let attestation_len = AttestationPqView::one_committee_len(committee_index, committee_len)?;
        Some(Self { data, committee_index, committee_len, attestation_len, positions, proof })
    }

    pub fn ssz_len(&self) -> usize {
        ProvedAttestationView::FIXED + self.attestation_len + self.proof.len()
    }

    pub fn write_ssz(&self, out: &mut [u8]) {
        ProvedAttestationView::write_offsets(out, self.attestation_len);
        let (attestation, proof) =
            out[ProvedAttestationView::FIXED..].split_at_mut(self.attestation_len);
        let written = AttestationPqView::write_one_committee(
            attestation,
            self.data,
            self.committee_index,
            self.committee_len,
            self.positions.iter().copied(),
        );
        debug_assert!(written, "votes are checked against their committee on arrival");
        proof.copy_from_slice(self.proof);
    }
}

#[cfg(test)]
mod tests;
