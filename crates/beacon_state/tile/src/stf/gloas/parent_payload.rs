use silver_beacon_state_data::{
    B256, BodyFork, BodyOffsets, BuilderPendingWithdrawal, EpochView, SLOTS_PER_EPOCH, Slot,
    SpecConfig, StateWriterView,
};
use silver_common::{
    ssz_hash_gloas::{
        EMPTY_EXECUTION_REQUESTS, EMPTY_EXECUTION_REQUESTS_ROOT, ExecutionRequestsView,
        RequestCountOutOfBounds,
    },
    ssz_hash_pq::{
        EMPTY_EXECUTION_REQUESTS_PQ, EMPTY_EXECUTION_REQUESTS_PQ_ROOT, ExecutionRequestsPqView,
    },
    ssz_view::ExecutionPayloadBidView,
};

use super::{
    bid::bid_message,
    builders::{
        BUILDER_DEPOSIT_SSZ, BUILDER_EXIT_SSZ, process_builder_deposit_request,
        process_builder_exit_request, process_builder_preregistration_requests,
        settle_builder_payment,
    },
};
use crate::{
    error::ParentExecutionPayloadError as E,
    stf::{
        process_consolidation_requests, process_deposit_requests,
        process_validator_preregistration_requests, process_voluntary_exit_requests,
        process_withdrawal_requests,
    },
};

const SPE: usize = SLOTS_PER_EPOCH as usize;

/// Validate and apply the parent block's execution payload. The
/// child's bid declares the parent FULL (matching `parent_block_hash`) or
/// EMPTY; FULL applies the parent's deferred execution requests and settles its
/// builder payment, EMPTY must carry no requests.
pub fn process_parent_execution_payload(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    body: &BodyOffsets,
    parent_slot: Slot,
) -> Result<(), E> {
    let is_pq = body.fork() == BodyFork::Pq;
    let bid = body.signed_bid().and_then(|bid| bid_message(bid, is_pq)).ok_or(E::Malformed)?;
    let requests = body.parent_execution_requests();
    let layout = RequestsLayout::for_fork(is_pq);
    let bid_parent_block_hash: [u8; 32] = *ExecutionPayloadBidView::parent_block_hash(bid);
    let parent_bid_block_hash = view.slot.state().latest_execution_payload_bid.block_hash;

    if bid_parent_block_hash != parent_bid_block_hash {
        // Parent was EMPTY: no execution requests may be carried.
        if layout.hash_tree_root(requests) != layout.empty_root() {
            return Err(E::EmptyParentHasRequests);
        }
        return Ok(());
    }

    // Parent was FULL: the carried requests must match the parent bid's commitment.
    let expected = view.slot.state().latest_execution_payload_bid.execution_requests_root;
    let got = layout.hash_tree_root(requests);
    if got != expected {
        return Err(E::RequestsRootMismatch { expected, got });
    }
    layout.check_counts(requests)?;
    apply_parent_execution_payload(view, epoch, cfg, requests, parent_slot);
    Ok(())
}

/// Gloas `ExecutionRequests` or PQ's, which adds preregistration and
/// voluntary exit requests.
#[derive(Clone, Copy)]
pub(crate) enum RequestsLayout {
    Gloas,
    Pq,
}

impl RequestsLayout {
    pub(crate) fn for_fork(is_pq: bool) -> Self {
        if is_pq { Self::Pq } else { Self::Gloas }
    }

    pub(crate) fn hash_tree_root(self, requests: &[u8]) -> B256 {
        match self {
            Self::Gloas => ExecutionRequestsView::hash_tree_root(requests),
            Self::Pq => ExecutionRequestsPqView::hash_tree_root(requests),
        }
    }

    pub(crate) fn empty(self) -> &'static [u8] {
        match self {
            Self::Gloas => &EMPTY_EXECUTION_REQUESTS,
            Self::Pq => &EMPTY_EXECUTION_REQUESTS_PQ,
        }
    }

    pub(crate) fn empty_root(self) -> B256 {
        match self {
            Self::Gloas => *EMPTY_EXECUTION_REQUESTS_ROOT,
            Self::Pq => *EMPTY_EXECUTION_REQUESTS_PQ_ROOT,
        }
    }

    pub(crate) fn check_canonical(self, requests: &[u8]) -> bool {
        match self {
            Self::Gloas => ExecutionRequestsView::check_canonical(requests),
            Self::Pq => ExecutionRequestsPqView::check_canonical(requests),
        }
    }

    pub(crate) fn check_counts(self, requests: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        match self {
            Self::Gloas => ExecutionRequestsView::check_counts(requests),
            Self::Pq => ExecutionRequestsPqView::check_counts(requests),
        }
    }

    /// The eight PQ request lists; Gloas has no lists past builder exits.
    pub(crate) fn sections(self, requests: &[u8]) -> [&[u8]; 8] {
        match self {
            Self::Gloas => {
                let [deposits, withdrawals, consolidations, builder_deposits, builder_exits] =
                    ExecutionRequestsView::sections(requests);
                [
                    deposits,
                    withdrawals,
                    consolidations,
                    builder_deposits,
                    builder_exits,
                    &[],
                    &[],
                    &[],
                ]
            }
            Self::Pq => ExecutionRequestsPqView::sections(requests),
        }
    }
}

pub(crate) fn apply_parent_execution_payload(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    requests: &[u8],
    parent_slot: Slot,
) {
    let (parent_value, parent_fee_recipient, parent_builder_index, parent_block_hash) = {
        let pb = &view.slot.state().latest_execution_payload_bid;
        (pb.value, pb.fee_recipient, pb.builder_index, pb.block_hash)
    };
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
    let finalized_epoch = epoch.state().finalized_checkpoint.epoch;

    // Settled before the requests, so a builder exit sees the payment still
    // pending. The window entry is used, or a direct withdrawal once it aged out.
    if parent_epoch == current_epoch {
        settle_builder_payment(view, SPE + (parent_slot % SLOTS_PER_EPOCH) as usize);
    } else if current_epoch > 0 && parent_epoch == current_epoch - 1 {
        settle_builder_payment(view, (parent_slot % SLOTS_PER_EPOCH) as usize);
    } else if parent_value > 0 {
        view.pending.builder_withdrawals.push(BuilderPendingWithdrawal {
            fee_recipient: parent_fee_recipient,
            amount: parent_value,
            builder_index: parent_builder_index,
        });
    }

    // The parent's deferred execution requests apply at this (child) slot.
    let [
        deposits,
        withdrawals,
        consolidations,
        builder_deposits,
        builder_exits,
        validator_preregistrations,
        builder_preregistrations,
        voluntary_exits,
    ] = RequestsLayout::for_fork(epoch.is_pq(view.imm)).sections(requests);
    process_deposit_requests(view, deposits);
    process_withdrawal_requests(view, cfg, withdrawals);
    process_consolidation_requests(view, cfg, consolidations);
    for i in 0..builder_deposits.len() / BUILDER_DEPOSIT_SSZ {
        process_builder_deposit_request(
            view,
            &builder_deposits[i * BUILDER_DEPOSIT_SSZ..][..BUILDER_DEPOSIT_SSZ],
        );
    }
    for i in 0..builder_exits.len() / BUILDER_EXIT_SSZ {
        process_builder_exit_request(
            view,
            finalized_epoch,
            &builder_exits[i * BUILDER_EXIT_SSZ..][..BUILDER_EXIT_SSZ],
        );
    }
    process_validator_preregistration_requests(view, validator_preregistrations);
    process_builder_preregistration_requests(view, builder_preregistrations);
    process_voluntary_exit_requests(view, cfg, voluntary_exits);

    let slot = view.slot.state_mut();
    slot.set_payload_available(parent_slot, true);
    slot.latest_block_hash = parent_block_hash;
}
