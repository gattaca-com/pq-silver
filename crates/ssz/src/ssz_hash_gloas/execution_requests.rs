use std::sync::LazyLock;

use flux_profiler::timed;

use super::request_lists::{RequestList, RequestLists};
use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, hash_fixed_bytes, merkleize, uint64_chunk},
    progressive::{ProgressiveContainer, packed_active_fields},
    ssz_view::{
        BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE, BuilderDepositRequestView,
        BuilderExitRequestView, ConsolidationRequestView, DepositRequestView,
        MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        WithdrawalRequestView,
    },
};

/// A request list longer than its `MAX_*_REQUESTS_PER_PAYLOAD` preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCountOutOfBounds {
    pub kind: &'static str,
    pub count: usize,
    pub max: usize,
}

/// `ExecutionRequests` (five ProgressiveLists) has no wire-view type; this unit
/// struct owns splitting the container into its list bodies and hashing them.
pub struct ExecutionRequestsView;

impl ProgressiveContainer for ExecutionRequestsView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(5);
}

/// SSZ `ExecutionRequests()`: five offsets, each to the end of the fixed part.
pub const EMPTY_EXECUTION_REQUESTS: [u8; 20] = {
    let mut ssz = [0; 20];
    let mut at = 0;
    while at < ssz.len() {
        ssz[at] = 20;
        at += 4;
    }
    ssz
};

/// `hash_tree_root(ExecutionRequests())` — a program constant (empty-parent
/// checks and the fork block's placeholder bid both compare against it).
pub static EMPTY_EXECUTION_REQUESTS_ROOT: LazyLock<B256> =
    LazyLock::new(|| ExecutionRequestsView::hash_tree_root(&[]));

impl ExecutionRequestsView {
    /// Deposits are unbounded per consensus-specs #5436.
    const LISTS: RequestLists<5> = RequestLists([
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
    ]);

    /// Spec `verify_execution_requests_limits`. EIP-7688 progressive lists
    /// carry no type-level bound, so the presets are enforced here.
    pub fn check_counts(data: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        Self::LISTS.check_counts(data)
    }

    /// The five list bodies: deposits, withdrawals, consolidations, builder
    /// deposits, builder exits.
    pub fn sections(data: &[u8]) -> [&[u8]; 5] {
        Self::LISTS.sections(data)
    }

    pub fn check_canonical(data: &[u8]) -> bool {
        Self::LISTS.check_canonical(data)
    }

    #[timed]
    pub fn hash_tree_root(data: &[u8]) -> B256 {
        Self::progressive_root(&Self::LISTS.field_roots::<Self, 5>(data))
    }
}

impl FixedContainer for BuilderDepositRequestView {
    const SSZ_SIZE: usize = BUILDER_DEPOSIT_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; BUILDER_DEPOSIT_REQUEST_SIZE] = bytes.try_into().unwrap();
        merkleize(&[
            hash_fixed_bytes(Self::pubkey(d)),
            *Self::withdrawal_credentials(d),
            uint64_chunk(Self::amount(d)),
            hash_fixed_bytes(Self::signature(d)),
        ])
    }
}

impl FixedContainer for BuilderExitRequestView {
    const SSZ_SIZE: usize = BUILDER_EXIT_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; BUILDER_EXIT_REQUEST_SIZE] = bytes.try_into().unwrap();
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(Self::source_address(d));
        merkleize(&[addr, hash_fixed_bytes(Self::pubkey(d))])
    }
}
