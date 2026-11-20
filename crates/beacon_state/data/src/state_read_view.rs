use silver_ssz::ssz_view::XMSSPubkey;

use crate::{
    BalancesReader, BlockRoots, BuildersView, Current, EpochReadView, InactivityView,
    LongtailReadView, ParticipationView, Previous, RandaoMixesView, RootsView, SlashingsView,
    SlotStateView, StateRoots, ValidatorsView,
    pq::xmss_pubkey,
    tree::{BuildersHash, TreeView, ValidatorsHash},
    types::{Immutable, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, Slot},
};

/// The optimistic reader surface excludes collections whose allocations can be
/// freed during a read. Owner-side reads use [`StateView`](crate::StateView) to
/// access those collections.
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn eth1(reader: &BeaconStateReader) {
///     reader.read(|view| view.eth1.iter().count());
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn pending(reader: &BeaconStateReader) {
///     reader.read_pinned(reader.pin().unwrap(), |view| view.pending.deposits.len());
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn increments(reader: &BeaconStateReader) {
///     reader.read(|view| view.epoch.increments().get(0));
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn historical_summary(reader: &BeaconStateReader) {
///     reader.read(|view| view.longtail.historical_summary(0));
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn longtail_state(reader: &BeaconStateReader) {
///     reader.read(|view| view.longtail.state().clone());
/// }
/// ```
///
/// Helpers that inspect pending queues also require the owner-side view.
///
/// ```compile_fail
/// # use silver_beacon_state_data::{BeaconStateReader, BuilderRegistry};
/// fn builder_withdrawals(reader: &BeaconStateReader) {
///     reader.read(|view| BuilderRegistry::of_reader(&view).pending_balance_to_withdraw(0));
/// }
/// ```
pub struct StateReadView<'a> {
    pub imm: &'a Immutable,
    pub balances: BalancesReader<'a>,
    pub epoch: EpochReadView<'a>,
    pub longtail: LongtailReadView<'a>,
    pub previous_participation: ParticipationView<'a, Previous>,
    pub current_participation: ParticipationView<'a, Current>,
    pub inactivity: InactivityView<'a>,
    pub slashings: SlashingsView<'a>,
    pub block_roots: RootsView<'a, BlockRoots>,
    pub state_roots: RootsView<'a, StateRoots>,
    pub randao_mixes: RandaoMixesView<'a>,
    pub slot: SlotStateView<'a>,
    pub validators: ValidatorsView<'a>,
    pub validators_hash: TreeView<'a, ValidatorsHash>,
    pub builders: BuildersView<'a>,
    pub builders_hash: TreeView<'a, BuildersHash>,
}

impl StateReadView<'_> {
    #[inline]
    pub fn post_gloas_fork(&self) -> bool {
        self.epoch.post_gloas_fork(self.imm)
    }

    #[inline]
    pub fn is_pq(&self) -> bool {
        self.epoch.is_pq(self.imm)
    }

    pub fn is_aggregator(
        &self,
        slot: Slot,
        committee_index: usize,
        validator_index: u64,
    ) -> Option<bool> {
        let window_epoch = (slot / SLOTS_PER_EPOCH + 1).checked_sub(self.slot.current_epoch())?;
        if window_epoch > MIN_SEED_LOOKAHEAD + 1 {
            return None;
        }
        let window_slot = (window_epoch * SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH) as usize;
        let mut aggregators =
            self.epoch.aggregation_committee_window().aggregators(window_slot, committee_index);
        Some(aggregators.any(|aggregator| aggregator == validator_index))
    }

    #[inline]
    pub fn validator_xmss_pubkey(&self, validator_index: usize) -> Option<&XMSSPubkey> {
        debug_assert!(validator_index < self.validators.count());
        self.is_pq().then(|| xmss_pubkey(self.validators.pubkey(validator_index)))
    }
}
