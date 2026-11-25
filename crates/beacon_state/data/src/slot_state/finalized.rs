use super::{delta::SlotStateDelta, epoch_balances::EpochBalances};
use crate::{
    DecomposeError, PayloadWithdrawals,
    decompose::{
        common::{
            F2, F4, F8, F10, F25, F26, F28, F30, F31, F32, F33, Offsets, b256, checked_count,
            u64_le,
        },
        gloas::{
            G_BUILDER_PENDING_PAYMENTS, G_CONSOLIDATION_BALANCE_TO_CONSUME,
            G_DEPOSIT_REQUESTS_START_INDEX, G_EARLIEST_CONSOLIDATION_EPOCH, G_EARLIEST_EXIT_EPOCH,
            G_EXECUTION_PAYLOAD_AVAILABILITY, G_EXIT_BALANCE_TO_CONSUME, G_LATEST_BLOCK_HASH,
            G_NEXT_WITHDRAWAL_BUILDER_INDEX, G_NEXT_WITHDRAWAL_INDEX,
            G_NEXT_WITHDRAWAL_VALIDATOR_INDEX, GloasOffsets,
        },
    },
    gloas::{
        BUILDER_PENDING_PAYMENT_SSZ, BUILDER_PENDING_PAYMENTS_LEN, BuilderPendingPayment,
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, ExecutionPayloadBid, Withdrawal,
    },
    types::{
        BeaconBlockHeader, Eth1Data, ExecutionPayloadHeader, MAX_WITHDRAWALS_PER_PAYLOAD, SlotState,
    },
};

// SSZ-serialised sizes of the Gloas fixed-width records.
const WITHDRAWAL_SSZ: usize = 44;

// size: ~1 KB inline — the `SlotState` scalars.
#[derive(Default)]
pub struct SlotStateFinalized {
    pub(super) slot: SlotState,
    pub(super) epoch_balances: EpochBalances,
}

impl Clone for SlotStateFinalized {
    fn clone(&self) -> Self {
        Self { slot: self.slot.clone(), epoch_balances: self.epoch_balances }
    }

    fn clone_from(&mut self, source: &Self) {
        self.slot.clone_from(&source.slot);
        self.epoch_balances = source.epoch_balances;
    }
}

impl SlotStateFinalized {
    pub fn new(slot: SlotState) -> Self {
        Self { slot, epoch_balances: Default::default() }
    }

    #[inline]
    pub(crate) fn state(&self) -> &SlotState {
        &self.slot
    }

    pub(crate) fn with_epoch_balances(mut self, epoch_balances: EpochBalances) -> Self {
        self.epoch_balances = epoch_balances;
        self
    }

    /// Adopt a fork's delta as the base — the data half of finalization.
    pub(super) fn promote(&mut self, delta: &SlotStateDelta) {
        self.slot.clone_from(&delta.slot);
        self.epoch_balances = delta.epoch_balances;
    }

    pub(crate) fn from_ssz_fulu(ssz: &[u8], o: &Offsets) -> Result<Self, DecomposeError> {
        let mut slot = SlotState {
            slot: u64_le(ssz, F2),
            latest_block_header: BeaconBlockHeader::from_ssz(&ssz[F4..]),
            eth1_data: Eth1Data::from_ssz(&ssz[F8..]),
            eth1_deposit_index: u64_le(ssz, F10),
            next_withdrawal_index: u64_le(ssz, F25),
            next_withdrawal_validator_index: u64_le(ssz, F26),
            deposit_requests_start_index: u64_le(ssz, F28),
            exit_balance_to_consume: u64_le(ssz, F30),
            earliest_exit_epoch: u64_le(ssz, F31),
            consolidation_balance_to_consume: u64_le(ssz, F32),
            earliest_consolidation_epoch: u64_le(ssz, F33),
            ..Default::default()
        };

        slot.latest_execution_payload_header =
            ExecutionPayloadHeader::from_ssz(&ssz[o.eph..o.hist_summaries])?;

        Ok(Self::new(slot))
    }

    pub(crate) fn from_ssz_gloas(ssz: &[u8], off: &GloasOffsets) -> Result<Self, DecomposeError> {
        let at = |gloas_position| off.layout.at(gloas_position);
        let slot = SlotState {
            slot: u64_le(ssz, F2),
            latest_block_header: BeaconBlockHeader::from_ssz(&ssz[F4..]),
            eth1_data: Eth1Data::from_ssz(&ssz[F8..]),
            eth1_deposit_index: u64_le(ssz, F10),
            latest_block_hash: b256(ssz, at(G_LATEST_BLOCK_HASH)),
            next_withdrawal_index: u64_le(ssz, at(G_NEXT_WITHDRAWAL_INDEX)),
            next_withdrawal_validator_index: u64_le(ssz, at(G_NEXT_WITHDRAWAL_VALIDATOR_INDEX)),
            deposit_requests_start_index: u64_le(ssz, at(G_DEPOSIT_REQUESTS_START_INDEX)),
            exit_balance_to_consume: u64_le(ssz, at(G_EXIT_BALANCE_TO_CONSUME)),
            earliest_exit_epoch: u64_le(ssz, at(G_EARLIEST_EXIT_EPOCH)),
            consolidation_balance_to_consume: u64_le(ssz, at(G_CONSOLIDATION_BALANCE_TO_CONSUME)),
            earliest_consolidation_epoch: u64_le(ssz, at(G_EARLIEST_CONSOLIDATION_EPOCH)),
            next_withdrawal_builder_index: u64_le(ssz, at(G_NEXT_WITHDRAWAL_BUILDER_INDEX)),
            execution_payload_availability: read_availability(
                ssz,
                at(G_EXECUTION_PAYLOAD_AVAILABILITY),
            ),
            builder_pending_payments: read_pending_payments(ssz, at(G_BUILDER_PENDING_PAYMENTS)),
            latest_execution_payload_bid: ExecutionPayloadBid::from_ssz(
                &ssz[off.latest_execution_payload_bid..off.payload_expected_withdrawals],
            )?,
            payload_expected_withdrawals: read_expected_withdrawals(ssz, off)?,
            // `latest_execution_payload_header` has no Gloas SSZ field.
            ..Default::default()
        };

        Ok(Self::new(slot))
    }
}

fn read_availability(ssz: &[u8], at: usize) -> [u8; EXECUTION_PAYLOAD_AVAILABILITY_BYTES] {
    ssz[at..at + EXECUTION_PAYLOAD_AVAILABILITY_BYTES].try_into().unwrap()
}

fn read_pending_payments(
    ssz: &[u8],
    at: usize,
) -> [BuilderPendingPayment; BUILDER_PENDING_PAYMENTS_LEN] {
    std::array::from_fn(|i| {
        BuilderPendingPayment::from_ssz(&ssz[at + i * BUILDER_PENDING_PAYMENT_SSZ..])
    })
}

fn read_expected_withdrawals(
    ssz: &[u8],
    off: &GloasOffsets,
) -> Result<PayloadWithdrawals, DecomposeError> {
    let body = &ssz[off.payload_expected_withdrawals..off.validator_preregistrations];
    let count = checked_count(
        body.len(),
        WITHDRAWAL_SSZ,
        "payload_expected_withdrawals",
        MAX_WITHDRAWALS_PER_PAYLOAD,
    )?;
    let mut withdrawals = PayloadWithdrawals::default();
    (0..count).for_each(|i| withdrawals.push(Withdrawal::from_ssz(&body[i * WITHDRAWAL_SSZ..])));
    Ok(withdrawals)
}
