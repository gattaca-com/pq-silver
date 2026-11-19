use std::sync::LazyLock;

use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, merkleize},
    progressive::{ProgressiveContainer, active_fields},
    ssz_hash_gloas::{
        RequestCountOutOfBounds,
        request_lists::{RequestList, RequestLists},
    },
    ssz_view::{
        BUILDER_PREREGISTRATION_REQUEST_SIZE, BuilderDepositRequestView, BuilderExitRequestView,
        BuilderPreregistrationRequestView, ConsolidationRequestView, DepositRequestView,
        MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        VALIDATOR_PREREGISTRATION_REQUEST_SIZE, VOLUNTARY_EXIT_REQUEST_SIZE,
        ValidatorPreregistrationRequestView, VoluntaryExitRequestView, WithdrawalRequestView,
    },
};

pub static EMPTY_EXECUTION_REQUESTS_PQ_ROOT: LazyLock<B256> =
    LazyLock::new(|| ExecutionRequestsPqView::hash_tree_root(&[]));

/// PQ `ExecutionRequests`: eight ProgressiveLists, serialized in field order
/// with the two removed EIP-8483 registration lists skipped.
pub struct ExecutionRequestsPqView;

impl ProgressiveContainer for ExecutionRequestsPqView {
    const ACTIVE_FIELDS: B256 = active_fields(10, &[5, 6]);
}

impl ExecutionRequestsPqView {
    /// Deposits are unbounded per consensus-specs #5436.
    const LISTS: RequestLists<8> = RequestLists([
        RequestList::of::<DepositRequestView>("deposit", usize::MAX),
        RequestList::of::<WithdrawalRequestView>("withdrawal", MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD),
        RequestList::of::<ConsolidationRequestView>(
            "consolidation",
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        ),
        RequestList::of::<BuilderDepositRequestView>(
            "builder_deposit",
            MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        ),
        RequestList::of::<BuilderExitRequestView>(
            "builder_exit",
            MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        ),
        RequestList::of::<ValidatorPreregistrationRequestView>(
            "validator_preregistration",
            MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        ),
        RequestList::of::<BuilderPreregistrationRequestView>(
            "builder_preregistration",
            MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        ),
        RequestList::of::<VoluntaryExitRequestView>(
            "voluntary_exit",
            MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD,
        ),
    ]);

    /// The eight list bodies in serialization order: deposits, withdrawals,
    /// consolidations, builder deposits, builder exits, validator
    /// preregistrations, builder preregistrations, voluntary exits.
    pub fn sections(data: &[u8]) -> [&[u8]; 8] {
        Self::LISTS.sections(data)
    }

    pub fn check_canonical(data: &[u8]) -> bool {
        Self::LISTS.check_canonical(data)
    }

    /// Spec `verify_execution_requests_limits`.
    pub fn check_counts(data: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        Self::LISTS.check_counts(data)
    }

    #[timed]
    pub fn hash_tree_root(data: &[u8]) -> B256 {
        Self::root_of_active_fields(&Self::LISTS.roots(data))
    }
}

impl FixedContainer for ValidatorPreregistrationRequestView {
    const SSZ_SIZE: usize = VALIDATOR_PREREGISTRATION_REQUEST_SIZE;

    /// Every field is a `Bytes32`, so the serialization is the field chunks.
    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let (fields, []) = bytes.as_chunks() else { unreachable!("whole chunks") };
        merkleize(fields)
    }
}

impl FixedContainer for BuilderPreregistrationRequestView {
    const SSZ_SIZE: usize = BUILDER_PREREGISTRATION_REQUEST_SIZE;

    /// Every field is a `Bytes32`, so the serialization is the field chunks.
    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let (fields, []) = bytes.as_chunks() else { unreachable!("whole chunks") };
        merkleize(fields)
    }
}

impl FixedContainer for VoluntaryExitRequestView {
    const SSZ_SIZE: usize = VOLUNTARY_EXIT_REQUEST_SIZE;

    /// A single-field container's root is its field's root.
    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        *Self::pubkey(bytes.try_into().unwrap())
    }
}
