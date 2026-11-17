use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, merkleize},
    progressive::{ProgressiveContainer, ProgressiveHasher, active_fields},
    ssz_hash_gloas::RequestCountOutOfBounds,
    ssz_view::{
        BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE,
        BUILDER_PREREGISTRATION_REQUEST_SIZE, BuilderDepositRequestView, BuilderExitRequestView,
        BuilderPreregistrationRequestView, CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView,
        DEPOSIT_REQUEST_SIZE, DepositRequestView, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD, MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        VALIDATOR_PREREGISTRATION_REQUEST_SIZE, VOLUNTARY_EXIT_REQUEST_SIZE,
        ValidatorPreregistrationRequestView, VoluntaryExitRequestView, WITHDRAWAL_REQUEST_SIZE,
        WithdrawalRequestView, fixed_list_ok, offsets_ok, variable_field,
    },
};

/// PQ `ExecutionRequests`: eight ProgressiveLists, serialized in field order
/// with the two removed EIP-8483 registration lists skipped.
pub struct ExecutionRequestsPqView;

impl ProgressiveContainer for ExecutionRequestsPqView {
    const ACTIVE_FIELDS: B256 = active_fields(10, &[5, 6]);
}

#[derive(Clone, Copy)]
struct RequestList {
    kind: &'static str,
    element_size: usize,
    max: usize,
}

impl ExecutionRequestsPqView {
    const FIXED: usize = 8 * 4;
    const OFFSETS: [usize; 8] = [0, 4, 8, 12, 16, 20, 24, 28];
    /// Deposits are unbounded per consensus-specs #5436.
    const LISTS: [RequestList; 8] = [
        RequestList { kind: "deposit", element_size: DEPOSIT_REQUEST_SIZE, max: usize::MAX },
        RequestList {
            kind: "withdrawal",
            element_size: WITHDRAWAL_REQUEST_SIZE,
            max: MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "consolidation",
            element_size: CONSOLIDATION_REQUEST_SIZE,
            max: MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "builder_deposit",
            element_size: BUILDER_DEPOSIT_REQUEST_SIZE,
            max: MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "builder_exit",
            element_size: BUILDER_EXIT_REQUEST_SIZE,
            max: MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "validator_preregistration",
            element_size: VALIDATOR_PREREGISTRATION_REQUEST_SIZE,
            max: MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "builder_preregistration",
            element_size: BUILDER_PREREGISTRATION_REQUEST_SIZE,
            max: MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        },
        RequestList {
            kind: "voluntary_exit",
            element_size: VOLUNTARY_EXIT_REQUEST_SIZE,
            max: MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD,
        },
    ];

    /// The eight list bodies in serialization order: deposits, withdrawals,
    /// consolidations, builder deposits, builder exits, validator
    /// preregistrations, builder preregistrations, voluntary exits. Empty on
    /// a malformed offset table.
    pub fn sections(data: &[u8]) -> [&[u8]; 8] {
        if data.len() < Self::FIXED || !offsets_ok(data, &Self::OFFSETS, Self::FIXED) {
            return [&[]; 8];
        }
        std::array::from_fn(|i| variable_field(data, &Self::OFFSETS, i))
    }

    pub fn check_canonical(data: &[u8]) -> bool {
        data.len() >= Self::FIXED &&
            offsets_ok(data, &Self::OFFSETS, Self::FIXED) &&
            Self::LISTS.iter().enumerate().all(|(i, list)| {
                fixed_list_ok(
                    variable_field(data, &Self::OFFSETS, i),
                    list.element_size,
                    usize::MAX,
                )
            })
    }

    /// Spec `verify_execution_requests_limits`.
    pub fn check_counts(data: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        for (list, section) in Self::LISTS.iter().zip(Self::sections(data)) {
            let count = section.len() / list.element_size;
            if count > list.max {
                return Err(RequestCountOutOfBounds { kind: list.kind, count, max: list.max });
            }
        }
        Ok(())
    }

    #[timed]
    pub fn hash_tree_root(data: &[u8]) -> B256 {
        let [
            deposits,
            withdrawals,
            consolidations,
            builder_deposits,
            builder_exits,
            validator_preregistrations,
            builder_preregistrations,
            voluntary_exits,
        ] = Self::sections(data);
        Self::progressive_root(&[
            DepositRequestView::hash_list(ProgressiveHasher::new(), deposits),
            WithdrawalRequestView::hash_list(ProgressiveHasher::new(), withdrawals),
            ConsolidationRequestView::hash_list(ProgressiveHasher::new(), consolidations),
            BuilderDepositRequestView::hash_list(ProgressiveHasher::new(), builder_deposits),
            BuilderExitRequestView::hash_list(ProgressiveHasher::new(), builder_exits),
            ZERO_HASH,
            ZERO_HASH,
            ValidatorPreregistrationRequestView::hash_list(
                ProgressiveHasher::new(),
                validator_preregistrations,
            ),
            BuilderPreregistrationRequestView::hash_list(
                ProgressiveHasher::new(),
                builder_preregistrations,
            ),
            VoluntaryExitRequestView::hash_list(ProgressiveHasher::new(), voluntary_exits),
        ])
    }
}

impl FixedContainer for ValidatorPreregistrationRequestView {
    const SSZ_SIZE: usize = VALIDATOR_PREREGISTRATION_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; VALIDATOR_PREREGISTRATION_REQUEST_SIZE] = bytes.try_into().unwrap();
        merkleize(&[*Self::pubkey(d), *Self::withdrawal_credentials(d), *Self::vrf_root(d)])
    }
}

impl FixedContainer for BuilderPreregistrationRequestView {
    const SSZ_SIZE: usize = BUILDER_PREREGISTRATION_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; BUILDER_PREREGISTRATION_REQUEST_SIZE] = bytes.try_into().unwrap();
        merkleize(&[*Self::pubkey(d), *Self::withdrawal_credentials(d)])
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
