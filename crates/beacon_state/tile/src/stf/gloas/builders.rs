use flux_profiler::timed;
use silver_beacon_state_data::{
    Builder, BuilderPendingPayment, BuilderPreregistration, BuilderRegistry, Epoch,
    FAR_FUTURE_EPOCH, PAYLOAD_BUILDER_VERSION, PREREGISTRATION_EXPIRY_SLOTS, SLOTS_PER_EPOCH,
    SpecConfig, StateWriterView, Withdrawals,
    pq::{KeyScheme, xmss_pubkey, xmss_pubkey_padded},
};
use silver_common::ssz_view::{
    BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE, BUILDER_PREREGISTRATION_REQUEST_SIZE,
    BuilderDepositRequestView, BuilderExitRequestView, BuilderPreregistrationRequestView,
};

use crate::stf::is_valid_builder_deposit_signature;

/// `2**40` — tags a `ValidatorIndex` as referring to the builder registry.
const BUILDER_INDEX_FLAG: u64 = 1 << 40;

#[inline]
pub(crate) fn is_builder_index(validator_index: u64) -> bool {
    validator_index & BUILDER_INDEX_FLAG != 0
}

#[inline]
pub(crate) fn convert_builder_index_to_validator_index(builder_index: u64) -> u64 {
    builder_index | BUILDER_INDEX_FLAG
}

#[inline]
pub(crate) fn convert_validator_index_to_builder_index(validator_index: u64) -> u64 {
    validator_index & !BUILDER_INDEX_FLAG
}
/// A builder payment settles at the epoch boundary only if its
/// accrued same-slot attestation weight reaches this fraction of the per-slot
/// stake.
const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 6;
const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 10;
const SPE: usize = SLOTS_PER_EPOCH as usize;

pub(crate) const BUILDER_DEPOSIT_SSZ: usize = BUILDER_DEPOSIT_REQUEST_SIZE;
pub(crate) const BUILDER_EXIT_SSZ: usize = BUILDER_EXIT_REQUEST_SIZE;

pub fn get_builder_payment_quorum_threshold(view: &StateWriterView, current_epoch: Epoch) -> u64 {
    let per_slot = view.slot.total_active_balance(current_epoch) / SLOTS_PER_EPOCH;
    per_slot * BUILDER_PAYMENT_THRESHOLD_NUMERATOR / BUILDER_PAYMENT_THRESHOLD_DENOMINATOR
}

pub(crate) fn settle_builder_payment(view: &mut StateWriterView, payment_index: usize) {
    let payment = view.slot.state().builder_pending_payments[payment_index];
    if payment.withdrawal.amount > 0 {
        view.pending.builder_withdrawals.push(payment.withdrawal);
    }
    view.slot.state_mut().builder_pending_payments[payment_index] =
        BuilderPendingPayment::default();
}

/// Settle the previous epoch's builder payments (weight ≥ quorum) into
/// `builder_pending_withdrawals`, then shift the two-epoch payment window
/// forward by one epoch and clear the now-current half.
pub fn process_builder_pending_payments(view: &mut StateWriterView, current_epoch: Epoch) {
    let quorum = get_builder_payment_quorum_threshold(view, current_epoch);

    for i in 0..SPE {
        let payment = view.slot.state().builder_pending_payments[i];
        if payment.weight >= quorum {
            view.pending.builder_withdrawals.push(payment.withdrawal);
        }
    }

    let payments = &mut view.slot.state_mut().builder_pending_payments;
    payments.copy_within(SPE.., 0);
    payments[SPE..].fill(BuilderPendingPayment::default());
}

pub fn process_builder_deposit_request(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    request: &[u8],
) {
    let request: &[u8; BUILDER_DEPOSIT_REQUEST_SIZE] = request.try_into().unwrap();
    let pubkey = *BuilderDepositRequestView::pubkey(request);
    let credentials = Withdrawals(*BuilderDepositRequestView::withdrawal_credentials(request));
    let amount = BuilderDepositRequestView::amount(request);
    let signature = *BuilderDepositRequestView::signature(request);

    // Deposits with unexpected withdrawal credential prefixes are ignored.
    if !credentials.has_builder_credential() {
        return;
    }

    let state = view.slot.state();
    let (current_epoch, parent_slot) =
        (state.slot / SLOTS_PER_EPOCH, state.latest_execution_payload_bid.slot);
    let scheme = view.builders.reader().scheme();
    let registry_pubkey = scheme.deposit_pubkey(&pubkey);
    if scheme == KeyScheme::Xmss &&
        !view.preregistrations.builders().admit_deposit(
            xmss_pubkey(&registry_pubkey),
            parent_slot,
            |binding| binding.withdrawal_credentials == credentials.0,
        )
    {
        return;
    }

    match view.builders.reader().find_by_pubkey(&registry_pubkey) {
        // A PQ deposit carries no signature to verify.
        None if scheme == KeyScheme::Xmss => {
            let builder_index =
                add_builder_to_registry(view, registry_pubkey, &credentials, amount, current_epoch);
            if scheme.is_legacy(&pubkey) {
                initiate_builder_exit(view, cfg, builder_index);
            }
        }
        None => {
            if is_valid_builder_deposit_signature(
                view.imm.genesis_fork_version,
                &pubkey,
                &credentials,
                amount,
                &signature,
            ) {
                add_builder_to_registry(view, pubkey, &credentials, amount, current_epoch);
            }
        }
        Some(builder_index) => {
            // An exited-and-swept builder re-enters the withdrawal sweep.
            let b = *view.builders.reader().get(builder_index).unwrap();
            if b.withdrawable_epoch != FAR_FUTURE_EPOCH && b.balance == 0 {
                view.builders.set_withdrawable_epoch(
                    builder_index,
                    current_epoch + cfg.min_builder_withdrawability_delay,
                );
            }
            view.builders.add_balance(builder_index, amount);
        }
    }
}

#[timed]
pub fn process_builder_preregistration_requests(view: &mut StateWriterView, data: &[u8]) {
    let state = view.slot.state();
    let (expiry_slot, parent_slot) =
        (state.slot + PREREGISTRATION_EXPIRY_SLOTS, state.latest_execution_payload_bid.slot);
    for request in data.chunks_exact(BUILDER_PREREGISTRATION_REQUEST_SIZE) {
        let request = request.try_into().unwrap();
        let pubkey = *BuilderPreregistrationRequestView::pubkey(request);
        if view.builders.reader().find_by_pubkey(&xmss_pubkey_padded(&pubkey)).is_some() {
            continue;
        }
        view.preregistrations.builders().admit(
            BuilderPreregistration {
                pubkey,
                withdrawal_credentials: *BuilderPreregistrationRequestView::withdrawal_credentials(
                    request,
                ),
                expiry_slot,
            },
            parent_slot,
        );
    }
}

fn add_builder_to_registry(
    view: &mut StateWriterView,
    pubkey: [u8; 48],
    credentials: &Withdrawals,
    amount: u64,
    current_epoch: u64,
) -> usize {
    let builder = Builder {
        pubkey,
        version: PAYLOAD_BUILDER_VERSION,
        execution_address: *credentials.execution_address(),
        balance: amount,
        deposit_epoch: current_epoch,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };
    match get_index_for_new_builder(view, current_epoch) {
        Some(builder_index) => {
            view.builders.set_builder(builder_index, builder);
            builder_index
        }
        None => {
            view.builders.push(builder);
            view.builders.len() - 1
        }
    }
}

fn get_index_for_new_builder(view: &StateWriterView, current_epoch: u64) -> Option<usize> {
    let builders = view.builders.reader();
    (0..builders.len()).find(|&i| {
        let b = builders.get(i).unwrap();
        b.withdrawable_epoch <= current_epoch && b.balance == 0
    })
}

pub fn process_builder_exit_request(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    finalized_epoch: u64,
    request: &[u8],
) {
    let request: &[u8; BUILDER_EXIT_REQUEST_SIZE] = request.try_into().unwrap();
    let source_address = *BuilderExitRequestView::source_address(request);
    let pubkey = *BuilderExitRequestView::pubkey(request);

    let registry_pubkey = view.builders.reader().scheme().request_pubkey(&pubkey);
    let Some(builder_index) = view.builders.reader().find_by_pubkey(&registry_pubkey) else {
        return;
    };
    let builder = *view.builders.reader().get(builder_index).unwrap();
    if !builder.is_active(finalized_epoch) {
        return;
    }
    if builder.execution_address != source_address {
        return;
    }
    if BuilderRegistry::of_writer(view).pending_balance_to_withdraw(builder_index as u64) != 0 {
        return;
    }
    initiate_builder_exit(view, cfg, builder_index);
}

fn initiate_builder_exit(view: &mut StateWriterView, cfg: &SpecConfig, builder_index: usize) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    view.builders.set_withdrawable_epoch(
        builder_index,
        current_epoch + cfg.min_builder_withdrawability_delay,
    );
}
