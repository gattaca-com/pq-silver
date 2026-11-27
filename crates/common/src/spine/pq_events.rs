use flux::{timing::Nanos, type_hash_derive::TypeHash};

use crate::{RefusalCode, ssz_view::MAX_VALIDATORS_PER_COMMITTEE};

/// What the PQ aggregator saw and did, for surfer's Attestations tab. Each
/// event's time is its publish time.
#[derive(Clone, Copy, Debug, TypeHash)]
#[repr(C)]
pub enum PqEvent {
    /// A vote passed gossip validation.
    Vote {
        slot: u64,
        committee: u16,
        position: u16,
        committee_len: u16,
        validator: u32,
    },
    /// An aggregate passed its STARK check. `arrival` names it in later
    /// merges; `None` when no local block wants it.
    Aggregate {
        slot: u64,
        committee: u16,
        aggregator: u32,
        /// Among the committee's aggregators, which sets its due time.
        position: u8,
        attesters: u16,
        committee_len: u16,
        arrival: Option<u64>,
    },
    /// A local aggregator's proof for a committee opened.
    AggregateDuty {
        slot: u64,
        committee: u16,
        position: u8,
        due: Nanos,
    },
    /// A local proposal's block proof opened.
    BlockDuty {
        block_slot: u64,
    },
    MergeSent {
        request_id: u64,
        target: PqTarget,
        proofs: u16,
        signatures: u16,
        claims_in: u32,
        predicted: Nanos,
        idle: bool,
    },
    /// A received aggregate merged by `request_id`. `new_votes` are the
    /// positions it adds to the merge.
    MergeProof {
        request_id: u64,
        arrival: u64,
        new_votes: u16,
    },
    MergeSettled {
        request_id: u64,
        claims: u32,
        failure: Option<PqMergeFailure>,
    },
    /// The VC asked for an aggregate proof, or block production for a block
    /// proof; `claims` is what the proof held.
    ProofRead {
        target: PqTarget,
        claims: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, TypeHash)]
#[repr(C)]
pub enum PqTarget {
    Aggregate { slot: u64, committee: u16 },
    Block { slot: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(C)]
pub enum PqMergeFailure {
    NoAnswer,
    ProverRefused {
        code: RefusalCode,
    },
    MalformedAnswer,
    /// The proof covers other claims than the merge asked for.
    OtherClaims,
    TooManyAggregateProofs,
    TargetPruned,
}

impl PqMergeFailure {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoAnswer => "no answer",
            Self::ProverRefused { .. } => "rejected by the leanvm prover",
            Self::MalformedAnswer => "malformed response",
            Self::OtherClaims => "the proof covers other claims",
            Self::TooManyAggregateProofs => "too many aggregate proofs",
            Self::TargetPruned => "the target was pruned",
        }
    }
}

/// The votes one merge takes from one committee, by position. Kept apart from
/// `PqEvent` so its bitmap does not size every event.
#[derive(Clone, Copy, Debug, TypeHash)]
#[repr(C)]
pub struct PqMergeVotes {
    pub request_id: u64,
    pub slot: u64,
    pub committee: u16,
    pub positions: [u64; MAX_VALIDATORS_PER_COMMITTEE / 64],
}
