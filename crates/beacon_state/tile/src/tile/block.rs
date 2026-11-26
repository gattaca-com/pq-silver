use flux::{spine::SpineProducers, timing::Nanos};
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, Checkpoint, Epoch, ForkWriter, SLOTS_PER_EPOCH,
    Slot, StateId, StateReadView, StateView, bls, hash_tree_root_block_header,
    xmss::{LeafOffset, SignatureCheck, compute_xmss_leaf_index},
};
use silver_common::{
    BeaconStateEvent, BlockSource, BlockStage, EngineFcuReq, EngineNewPayloadReq, EngineReq,
    SignedBlockLayout, StfGate, StfStamp, SyncNeed, SyncUpdate, TCacheRead, TRead, hex32,
    ssz_hash::{BlockFork, HashedBody},
    ssz_view::{self, SignedBeaconBlockPqView, SignedBeaconBlockView},
};

use super::{
    BeaconStateTile, Feedback, MAXIMUM_GOSSIP_CLOCK_DISPARITY, Producers,
    gossip::EnvelopeCheck,
    pending_envelopes::{ParkedEnvelope, ParkedKind},
};
use crate::{
    Error,
    error::{BlockError, PrecheckError, RejectReason},
    fork_choice::{BlockImport, ExecutionStatus, ForkChoiceNode, PayloadStatus},
    stf::{self, BlockInput},
};

/// Fulu proposer selection via `proposer_lookahead`, fixed at the state's
/// prior epoch boundary. `None` outside its current and next epoch.
pub(super) fn lookahead_proposer(rv: &StateView<'_>, block_slot: Slot) -> Option<u64> {
    let state_epoch = rv.slot.slot_number() / SLOTS_PER_EPOCH;
    let lookahead_idx = block_slot.checked_sub(state_epoch * SLOTS_PER_EPOCH)?;
    rv.epoch.proposer_at(lookahead_idx as usize)
}

pub(super) struct ParsedBlock {
    pub(super) layout: SignedBlockLayout,
    pub(super) header: BeaconBlockHeader,
    pub(super) block_root: B256,
    pub(super) has_data_columns: bool,
    pub(super) parent_state_id: StateId,
    pub(super) fork: BlockFork,
    pub(super) parent_payload_status: PayloadStatus,
    pub(super) relay_eligible: bool,
}

pub(super) struct AppliedBlock {
    id: StateId,
    justified: Checkpoint,
    unrealized: (Checkpoint, Checkpoint),
    execution_block_hash: B256,
    bid_block_hash: B256,
    votes: stf::BlockVotes,
}

impl AppliedBlock {
    /// Snapshots what the import reads off the live fork, then commits it.
    pub(super) fn commit(
        fork: ForkWriter<'_>,
        header: &BeaconBlockHeader,
        block_fork: BlockFork,
        votes: stf::BlockVotes,
    ) -> Self {
        let es = fork.epoch_view().state();
        let justified = es.current_justified_checkpoint;
        // Spec `compute_pulled_up_tip`: the j/f this post-state would realize at
        // its epoch boundary, read-only on the live view.
        let unrealized = stf::unrealized_checkpoints(&fork.view, es, header.slot / SLOTS_PER_EPOCH);
        let slot_state = fork.view.slot.state();
        let execution_block_hash = if block_fork.post_gloas_fork() {
            slot_state.latest_block_hash
        } else {
            slot_state.latest_execution_payload_header.block_hash
        };
        let bid_block_hash = slot_state.latest_execution_payload_bid.block_hash;

        Self {
            id: fork.commit(),
            justified,
            unrealized,
            execution_block_hash,
            bid_block_hash,
            votes,
        }
    }

    pub(super) fn state_id_mut(&mut self) -> &mut StateId {
        &mut self.id
    }

    /// Gwei.
    pub(super) fn proposer_reward(&self) -> u64 {
        self.votes.proposer_reward
    }
}

/// A block whose post-state is committed but which waits for its data columns
/// before entering fork choice. The pin keeps its bytes until import.
pub(super) struct StagedBlock {
    pub(super) parsed: ParsedBlock,
    applied: AppliedBlock,
    pub(super) ssz: TRead,
    pub(super) source: BlockSource,
    pub(super) el_valid: bool,
}

impl StagedBlock {
    pub(super) fn state_id_mut(&mut self) -> &mut StateId {
        &mut self.applied.id
    }

    #[cfg(test)]
    pub(super) fn with_state_id(
        parsed: ParsedBlock,
        id: StateId,
        ssz: TRead,
        source: BlockSource,
    ) -> Self {
        let applied = AppliedBlock {
            id,
            justified: Checkpoint::default(),
            unrealized: Default::default(),
            execution_block_hash: [0u8; 32],
            bid_block_hash: [0u8; 32],
            votes: stf::BlockVotes::default(),
        };
        Self { parsed, applied, ssz, source, el_valid: false }
    }
}

/// What an applied block waits on before it enters fork choice. The pin keeps
/// the bytes of a block that waits.
pub(super) enum ImportGate {
    Now,
    DataColumns(TRead, BlockSource),
}

/// When a block's transition passed, and what its import waited on.
pub(super) struct StfDone {
    at: Nanos,
    gate: StfGate,
}

impl BeaconStateTile {
    pub fn try_apply_block(&mut self, data: &[u8], emit: impl FnMut(BeaconStateEvent)) -> Feedback {
        match self.parse_and_verify_block(data, false) {
            Ok(parsed) => {
                let feedback = match self.apply_or_reject(&parsed, data) {
                    Ok((applied, _)) => {
                        let block_root = parsed.block_root;
                        self.import_block(parsed, applied, data, emit);
                        Feedback::BlockImported(block_root)
                    }
                    Err(feedback) => feedback,
                };
                self.maybe_finalize();
                feedback
            }
            Err(err) => err.feedback(),
        }
    }

    /// The timer spans the post-publication work too, so it is not the
    /// tick-to-attestable latency.
    #[timed]
    pub(super) fn apply_block(
        &mut self,
        data: &[u8],
        ssz: &TRead,
        source: BlockSource,
        pre_verified: bool,
        producers: &mut Producers,
        mut send_gossip: impl FnMut(B256, &mut Producers),
    ) -> Feedback {
        let layout = match self.block_layout(data) {
            Ok(layout) => layout,
            Err(e) => {
                silver_log::warn!(?source, "{e}");
                return e.feedback();
            }
        };

        let slot = layout.slot(data);
        let validated_at;
        let parsed = match self.parse_and_verify_block(data, pre_verified) {
            Ok(parsed) => {
                validated_at = Nanos::now();
                if parsed.relay_eligible {
                    send_gossip(parsed.block_root, producers);
                }
                parsed
            }
            Err(PrecheckError::AwaitingData { block_root }) => {
                return self.still_held(data, block_root, source, producers);
            }
            Err(e) => {
                let f = e.feedback();
                if let Feedback::BlockKnown(block_root) = f {
                    self.emit_block_received(
                        data,
                        block_root,
                        BlockStage::AlreadyKnown,
                        source,
                        None,
                        producers,
                    );
                    producers.produce(BeaconStateEvent::PersistBlock {
                        ssz: ssz.to_read(),
                        source,
                        slot,
                        block_root,
                    });
                }
                return f;
            }
        };

        let gate = if self.waits_for_columns(&parsed) {
            if self.held_is_full(self.held.staged_len()) {
                return Feedback::Ignore;
            }
            ImportGate::DataColumns(ssz.clone(), source)
        } else {
            ImportGate::Now
        };

        if !parsed.fork.post_gloas_fork() {
            producers.produce(EngineReq::NewPayload(EngineNewPayloadReq {
                data: ssz.to_read(),
                block_root: parsed.block_root,
                slot,
                block_source: source,
            }));
        }

        let block_root = parsed.block_root;
        let f = match self.apply_and_import(parsed, data, gate, producers) {
            Ok(StfDone { at, gate: StfGate::Data }) => {
                let stf = Some(StfStamp { validated_at, applied_at: at, gate: StfGate::Data });
                let stage = BlockStage::AwaitData;
                self.emit_block_received(data, block_root, stage, source, stf, producers);
                Feedback::AwaitData(block_root)
            }
            Ok(StfDone { at, gate }) => {
                let stf = Some(StfStamp { validated_at, applied_at: at, gate });
                let stage = BlockStage::Applied;
                self.emit_block_received(data, block_root, stage, source, stf, producers);
                self.announce_imported(block_root, slot, ssz.to_read(), source, producers);
                Feedback::BlockImported(block_root)
            }
            Err(feedback) => {
                producers.produce(BeaconStateEvent::BlockRejected { block_root, source });
                feedback
            }
        };
        silver_log::info!(
            ?source,
            head_slot = self.head_state_slot(),
            slot,
            wall_slot = self.ticker.current_slot(),
            time_into_slot = ?self.ticker.slot_time_elapsed(),
            "applied block: {:?}",
            f
        );
        f
    }

    fn held_is_full(&self, held: usize) -> bool {
        if held < self.pending_bounds.max_dc {
            return false;
        }
        silver_log::warn!(held, "too many blocks held before import; dropped");
        true
    }

    /// A re-fetch of a staged block: sync learns its transition ran.
    fn still_held(
        &self,
        data: &[u8],
        block_root: B256,
        source: BlockSource,
        producers: &mut Producers,
    ) -> Feedback {
        if source == BlockSource::Rpc {
            let stage = BlockStage::AwaitData;
            self.emit_block_received(data, block_root, stage, source, None, producers);
        }
        Feedback::AwaitData(block_root)
    }

    /// Everything the rest of the node learns from an import after its
    /// `Applied` stage, in the order it needs it: the bytes to persist, the
    /// FCU, the head, the storage rebase onto new finality (before any other
    /// block imports, so pruned branches can no longer be built on), the
    /// blocks that waited on this one, and last the work the next block would
    /// otherwise do inline. A parked envelope decides the head's payload
    /// resolution, so it is applied before the Status that carries it; orphans
    /// only extend beyond the head, so they follow it.
    fn announce_imported(
        &mut self,
        block_root: B256,
        slot: Slot,
        ssz: TCacheRead,
        source: BlockSource,
        producers: &mut Producers,
    ) {
        producers.produce(BeaconStateEvent::PersistBlock { ssz, source, slot, block_root });

        self.send_fcu(producers);

        self.promote_unknown_root_votes(producers);
        self.drain_pending_envelope(block_root, slot, producers);
        self.publish_status(producers);
        self.maybe_finalize();

        self.replay_orphans(block_root, producers);
        self.precompute_for_next_block();
    }

    fn send_fcu(&mut self, producers: &mut Producers) {
        let fcu = self.fork_choice_update();
        self.sent_fcu = Some(forkchoice_hashes(&fcu));
        producers.produce(EngineReq::Fcu(fcu));
    }

    pub(super) fn send_fcu_on_change(&mut self, producers: &mut Producers) {
        let fcu = self.fork_choice_update();
        let hashes = Some(forkchoice_hashes(&fcu));
        if self.sent_fcu != hashes {
            self.sent_fcu = hashes;
            producers.produce(EngineReq::Fcu(fcu));
        }
    }

    pub(super) fn fork_choice_update(&self) -> EngineFcuReq {
        let hashes = self.fork_choice.fcu_execution_hashes();
        EngineFcuReq {
            block_root: hashes.head_payload_root,
            head_block_hash: hashes.head_block_hash,
            safe_block_hash: hashes.safe_block_hash,
            finalized_block_hash: hashes.finalized_block_hash,
            is_gloas: self
                .fork_choice
                .find_node_idx(&hashes.head_root)
                .is_some_and(|idx| self.fork_choice.node(idx).payload.is_gloas),
        }
    }

    /// Work the next block would otherwise do inline, run off the newest
    /// applied block once every consumer has been told about it.
    fn precompute_for_next_block(&mut self) {
        let block_slot = self.last_applied_block_slot();
        self.precompute_next_epoch_shuffling(block_slot / SLOTS_PER_EPOCH);
        self.precompute_epoch_start(block_slot + 1);
        self.precompute_justified_balances();
    }

    /// Warm epoch `block_epoch + 1`'s attester shuffling and committee
    /// aggregates on the head post-state: its inputs (the `E-1` randao mix,
    /// the active set) are fixed once `block_epoch` begins, so the boundary
    /// block's shuffling lookup becomes a cache hit and every block's
    /// `collect_sigs` gets the aggregate-subtract path.
    pub(super) fn precompute_next_epoch_shuffling(&mut self, block_epoch: Epoch) {
        let view = self.state.read_view(self.last_applied);
        self.shuffling_cache.precompute(&view, block_epoch + 1);
    }

    pub(super) fn da_required(&self) -> bool {
        !matches!(self.sync_target, SyncUpdate::SyncingFinalized { .. })
    }

    /// Gloas checks data availability on the payload envelope, not the block.
    pub(super) fn waits_for_columns(&self, parsed: &ParsedBlock) -> bool {
        !parsed.fork.post_gloas_fork() &&
            parsed.has_data_columns &&
            self.columns_pending(&parsed.block_root)
    }

    pub(super) fn columns_pending(&self, block_root: &B256) -> bool {
        self.da_required() && !self.held.is_available(block_root)
    }

    pub(super) fn replay_block(&mut self, read: TCacheRead, emit: impl FnMut(BeaconStateEvent)) {
        let acquired = self.reader.acquire(read);
        let Some((data, _)) = acquired.buffer().ok() else {
            return;
        };

        let Ok(layout) = self.block_layout(data) else {
            silver_log::error!(len = data.len(), "replayed on-disk block malformed");
            return;
        };

        let block_slot = layout.slot(data);
        let feedback = self.try_apply_block(data, emit);

        match feedback {
            Feedback::Reject { block_root, reason } => silver_log::error!(
                block_slot,
                block_root = ?block_root.map(|r| hex32(&r)),
                reason,
                "replayed block rejected",
            ),
            _ => silver_log::info!(
                head_slot = self.head_state_slot(),
                block_slot,
                "replayed block: {:?}",
                feedback
            ),
        }

        if matches!(feedback, Feedback::BlockImported(_)) {
            self.precompute_next_epoch_shuffling(block_slot / SLOTS_PER_EPOCH);
        }
    }

    pub(super) fn replay_envelope(&mut self, read: TCacheRead, emit: impl FnMut(BeaconStateEvent)) {
        let acquired = self.reader.acquire(read);
        self.apply_disk_envelope(acquired, emit);
    }

    pub(super) fn apply_disk_envelope(
        &mut self,
        acquired: TRead,
        emit: impl FnMut(BeaconStateEvent),
    ) {
        let Some((data, _)) = acquired.buffer().ok() else {
            return;
        };

        match self.validate_execution_payload_envelope(data) {
            EnvelopeCheck::Ready { block_root, state_id } => {
                let rv = self.state.read_view(state_id);
                if !stf::envelope_withdrawals_match_expected(&rv, data) {
                    silver_log::warn!("replayed on-disk envelope has unexpected withdrawals");
                    return;
                }
                self.mark_envelope_verified(block_root, data);
                self.recompute_head(emit);
            }
            EnvelopeCheck::AwaitBlock(block_root) => {
                silver_log::info!(
                    block = hex32(&block_root),
                    "replayed envelope parked until its block imports"
                );
                let parked = ParkedEnvelope { read: acquired, kind: ParkedKind::FromDisk };
                self.pending_envelopes.park(block_root, parked);
            }
            EnvelopeCheck::Ignore | EnvelopeCheck::Reject => {
                silver_log::warn!("replayed on-disk envelope rejected")
            }
        }
    }

    #[timed]
    pub(super) fn parse_and_verify_block(
        &mut self,
        data: &[u8],
        pre_verified: bool,
    ) -> Result<ParsedBlock, PrecheckError> {
        let parsed = match self.precheck_block(data) {
            Ok(p) => p,
            Err(err) => {
                let err = self.check_parking_proposer(data, err);
                silver_log::warn!(head_slot = self.head_state_slot(), "{err}");
                return Err(err);
            }
        };

        if !pre_verified &&
            !self.verify_block_signature(
                parsed.layout,
                data,
                parsed.parent_state_id,
                &parsed.block_root,
            )
        {
            silver_log::warn!(
                head_slot = self.head_state_slot(),
                block_root = ?hex32(&parsed.block_root),
                "block BLS proposer signature invalid"
            );
            return Err(PrecheckError::InvalidSignature { block_root: parsed.block_root });
        }

        Ok(parsed)
    }

    /// The STF, then the fork-choice import, unless `gate` holds the applied
    /// block back.
    #[timed]
    fn apply_and_import(
        &mut self,
        parsed: ParsedBlock,
        data: &[u8],
        gate: ImportGate,
        producers: &mut Producers,
    ) -> Result<StfDone, Feedback> {
        let (applied, done) = self.apply_or_reject(&parsed, data)?;
        match gate {
            ImportGate::Now => {
                self.import_block(parsed, applied, data, |event| producers.produce(event));
                Ok(done)
            }
            ImportGate::DataColumns(ssz, source) => {
                self.held.stage(StagedBlock { parsed, applied, ssz, source, el_valid: false });
                Ok(StfDone { gate: StfGate::Data, ..done })
            }
        }
    }

    #[timed]
    fn apply_or_reject(
        &mut self,
        parsed: &ParsedBlock,
        data: &[u8],
    ) -> Result<(AppliedBlock, StfDone), Feedback> {
        match self.apply_stf_and_commit(parsed, data) {
            Ok(applied) => Ok(applied),
            Err(e) => {
                silver_log::error!(
                    error = %e,
                    block_slot = %parsed.header.slot,
                    head_slot = self.head_state_slot(),
                    "block rejected"
                );
                let reason = RejectReason::FailedTransition;
                self.held.reject(parsed.block_root, parsed.header.slot, reason);
                Err(Feedback::reject_block(parsed.block_root, "block failed transition"))
            }
        }
    }

    pub(super) fn handle_data_columns_available(
        &mut self,
        block_root: B256,
        slot: Slot,
        producers: &mut Producers,
    ) {
        let Some(staged) = self.held.mark_available(block_root, slot) else {
            silver_log::debug!(block = hex32(&block_root), slot, "DataColumnsAvailable received");
            self.drain_pending_envelope(block_root, slot, producers);
            self.publish_status(producers);
            return;
        };
        self.import_held(staged, producers);
    }

    fn import_held(&mut self, held: StagedBlock, producers: &mut Producers) {
        let StagedBlock { parsed, applied, ssz, source, el_valid } = held;
        let (block_root, slot) = (parsed.block_root, parsed.header.slot);

        // Only lag eviction of the pin can lose the bytes; counted as a fault.
        let Ok((data, _)) = ssz.buffer() else {
            silver_log::error!(
                block = hex32(&block_root),
                slot,
                "held block evicted from the tcache before its import; re-requesting"
            );
            producers.produce(SyncNeed::missing_block(block_root, slot));
            self.stf_scratch.votes.recycle(applied.votes);
            return;
        };

        self.import_block(parsed, applied, data, |event| producers.produce(event));
        if el_valid {
            self.fork_choice.on_payload_valid(&block_root);
        }
        self.emit_block_received(data, block_root, BlockStage::Applied, source, None, producers);
        self.announce_imported(block_root, slot, ssz.to_read(), source, producers);
    }

    /// Run the per-block STF against a COW child of the parent post-state,
    /// verify the block's STARK proofs, and commit it. Holds the `&mut
    /// self.state` borrow for the whole transition (ending at `commit`).
    #[timed]
    fn apply_stf_and_commit(
        &mut self,
        parsed: &ParsedBlock,
        data: &[u8],
    ) -> crate::Result<(AppliedBlock, StfDone)> {
        let pq = parsed.fork == BlockFork::Pq;
        if let Some(applied) = self.block_production.take_produced_state(&parsed.block_root) {
            // Its proofs are this node's own, so none is verified.
            let gate = if pq { StfGate::OwnBlock } else { StfGate::Now };
            return Ok((applied, StfDone { at: Nanos::now(), gate }));
        }
        let block_epoch = parsed.header.slot / SLOTS_PER_EPOCH;

        // The parent's epoch-start state when the block crossed a boundary;
        // `apply_block` bridges the rest.
        let parent = self.epoch_start_state(parsed.parent_state_id, parsed.header.slot);

        // Per-block attester shuffling against the pre-block state (active set
        // + seed for an epoch are fixed at its prior boundary). Done before
        // the held-writer view takes the `&mut self.state` borrow. Reuse the
        // branch-aware cache so consecutive same-epoch blocks skip the
        // O(rounds·n) shuffle.
        let sref = {
            let view = self.state.read_view(parent);
            self.shuffling_cache.for_block(&view, block_epoch).ok_or_else(|| {
                silver_log::error!(
                    block_epoch,
                    state_epoch = view.slot.current_epoch(),
                    "block shuffling unavailable from the parent state"
                );
                Error::invalid_block(parsed.header.state_root, BlockError::SlotStateMismatch {
                    block: parsed.header.slot,
                    state: view.slot.slot_number(),
                })
            })?
        };

        let body = BodyOffsets::validated(parsed.layout.body(data), parsed.fork.body_fork())
            .map_err(|e| Error::invalid_block(parsed.header.state_root, e.into()))?;
        let mut fork = self.state.apply_block_view(parent);
        let mut votes = self.stf_scratch.votes.take();
        let input = BlockInput {
            header: &parsed.header,
            block_root: parsed.block_root,
            body,
            fork: parsed.fork,
            shuffling: &sref,
        };
        let stubbed = self.xmss_stubbed && pq;
        let transition = stf::apply_block(
            &self.spec,
            &mut fork,
            &input,
            &mut self.stf_scratch,
            (!stubbed).then_some(&mut self.sig_batch),
            &mut votes,
        );
        if let Err(e) = transition {
            self.stf_scratch.votes.recycle(votes);
            return Err(e);
        }
        let at = Nanos::now();

        let gate = if !pq {
            StfGate::Now
        } else {
            // The STF collected the claims only for a PQ block it verified.
            let proofs = if stubbed {
                Some(0)
            } else {
                let validators = &fork.read().validators;
                self.leanvm_verifier.stark_proofs_valid(&self.stf_scratch.stark, data, validators)
            };
            match proofs {
                Some(0) => StfGate::NoAttestations,
                Some(_) => StfGate::Verify,
                None => {
                    silver_log::warn!(
                        block = hex32(&parsed.block_root),
                        "leanVM rejected the block's STARK proofs"
                    );
                    self.stf_scratch.votes.recycle(votes);
                    return Err(Error::StarkProofInvalid);
                }
            }
        };

        let applied = AppliedBlock::commit(fork, &parsed.header, parsed.fork, votes);
        Ok((applied, StfDone { at, gate }))
    }

    /// Fork-choice import and head publish; the tick-to-attestable window
    /// ends when this returns.
    #[timed]
    fn import_block(
        &mut self,
        parsed: ParsedBlock,
        applied: AppliedBlock,
        block_data: &[u8],
        mut emit: impl FnMut(BeaconStateEvent),
    ) {
        let AppliedBlock {
            id: new_id,
            justified,
            unrealized,
            execution_block_hash,
            bid_block_hash,
            votes,
        } = applied;

        self.pq_aggregator.on_block_imported(parsed.header.slot);
        let is_gloas = parsed.fork.post_gloas_fork();
        let (parent_payload_status, bid_block_hash, payload_verified) = if is_gloas {
            (parsed.parent_payload_status, bid_block_hash, false)
        } else {
            (PayloadStatus::Full, execution_block_hash, true)
        };

        let current_slot = self.ticker.current_slot();
        self.fork_choice.on_tick(current_slot);

        // Fold block-included attestations into the LMD vote tracker.
        let n = self.head_validator_count();
        for (target, validators) in votes.votes.iter() {
            self.fork_choice.record_votes(target, validators, n);
            self.pq_aggregator.on_chain(target.attestation_slot, validators);
        }

        // Spec `on_block` takes the head before the new block joins the store.
        let head_before = self.fork_choice.find_head();
        self.fork_choice.on_block(BlockImport {
            slot: parsed.header.slot,
            block_root: parsed.block_root,
            state_root: parsed.header.state_root,
            parent_root: parsed.header.parent_root,
            execution_block_hash,
            justified,
            unrealized_justified: unrealized.0,
            unrealized_finalized: unrealized.1,
            state_id: new_id,
            bid_block_hash,
            parent_payload_status,
            payload_verified,
            is_gloas,
        });

        // Block-included attester slashings: mark the slashed validators
        // equivocating (spec `on_attester_slashing`), removing any live LMD
        // weight on the next recompute.
        for &idx in &votes.slashed {
            self.fork_choice.mark_equivocating(idx as usize);
        }
        self.stf_scratch.votes.recycle(votes);

        // Spec `update_proposer_boost_root`: the FIRST current-slot block that
        // arrived before the attesting deadline gets a transient weight bonus,
        // expired at the next slot boundary by the fork-choice tick, and only
        // when it shares the head's shuffling dependent root, so a block whose
        // proposer was chosen on another branch cannot pull the head over. Set
        // before `recompute_head` so `apply_score_changes` folds it in.
        let before_deadline = self.ticker.is_before_attesting_interval(is_gloas);
        let same_dependent_root = || {
            let epoch = current_slot / SLOTS_PER_EPOCH;
            self.fork_choice.shuffling_dependent_root(&head_before, epoch) ==
                self.fork_choice.shuffling_dependent_root(&parsed.block_root, epoch)
        };

        if parsed.header.slot == current_slot &&
            before_deadline &&
            self.fork_choice.proposer_boost_root == [0u8; 32] &&
            same_dependent_root()
        {
            self.refresh_justified_balances();
            self.fork_choice.set_proposer_boost(parsed.block_root);
        }

        // Adopt the new block before recompute so `lift_checkpoints` reads ITS
        // post-state checkpoints — an epoch-boundary block's justified advance
        // lands this import, not one recompute later. Recompute moves
        // `last_applied` back to the head if this block lost.
        self.last_applied = new_id;

        if parsed.fork == BlockFork::Gloas {
            self.notify_ptc_from_block(block_data);
        }

        self.recompute_head(&mut emit);
        if self.last_applied == new_id {
            self.publish_head_state(emit);
        }
        self.fork_choice.lift_finalized(self.head_finalized_checkpoint());
    }

    pub(super) fn block_layout(&self, data: &[u8]) -> Result<SignedBlockLayout, PrecheckError> {
        if let Some(layout) = SignedBlockLayout::of(&self.spec, data) {
            return Ok(layout);
        }
        if SignedBeaconBlockView::check_size(data) {
            return Err(PrecheckError::SignatureForkMismatch {
                slot: SignedBeaconBlockView::slot(data),
            });
        }
        if SignedBeaconBlockPqView::check_size(data) {
            return Err(PrecheckError::SignatureForkMismatch {
                slot: SignedBeaconBlockPqView::slot(data),
            });
        }
        Err(PrecheckError::SizeMismatch {
            expected_min: ssz_view::SIGNED_BEACON_BLOCK_MIN,
            expected_max: ssz_view::SIGNED_BEACON_BLOCK_MAX,
            got: data.len(),
        })
    }

    fn precheck_block(&mut self, data: &[u8]) -> Result<ParsedBlock, PrecheckError> {
        let layout = self.block_layout(data)?;

        let block_slot = layout.slot(data);
        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let proposer_index = layout.proposer_index(data);
        let parent_root = layout.parent_root(data);
        let state_root = layout.state_root(data);

        let body = layout.body(data);
        if !layout.check_canonical(data) {
            return Err(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() });
        }

        let post_gloas = layout != SignedBlockLayout::Fulu;
        let offsets = BodyOffsets::validated(body, layout.body_fork())
            .map_err(|kind| PrecheckError::BodyOverLimits { block_slot, kind })?;
        let HashedBody { root: body_root, fork } =
            self.built_body_hash(block_slot, body).unwrap_or_else(|| HashedBody::of(&offsets));

        let block_header = BeaconBlockHeader {
            slot: block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        };

        let block_root = hash_tree_root_block_header(&block_header);
        if self.fork_choice.find_node_idx(&block_root).is_some() {
            return Err(PrecheckError::BlockKnown { block_root });
        }
        if self.held.is_staged(&block_root) {
            return Err(PrecheckError::AwaitingData { block_root });
        }
        if let Some(reason) = self.held.rejected_reason(&block_root) {
            return Err(PrecheckError::Rejected { block_root, reason });
        }

        let finalized_slot = self.fork_choice.finalized_checkpoint().epoch * SLOTS_PER_EPOCH;
        if block_slot <= finalized_slot {
            return Err(PrecheckError::PreFinalized { block_slot, finalized_slot });
        }

        if let Some(reason) = self.held.rejected_reason(&parent_root) {
            return Err(PrecheckError::ParentRejected { parent_root, block_root, reason });
        }
        let Some(parent_idx) = self.fork_choice.find_node_idx(&parent_root) else {
            let last_applied_slot = self.head_state_slot();
            return Err(PrecheckError::ParentMissing {
                parent_root,
                block_root,
                last_applied_slot,
                block_slot,
            });
        };

        let parent_node = self.fork_choice.node(parent_idx);
        let parent_state_id = parent_node.state_id;

        let rv = self.state.read_view(parent_state_id);
        let parent_slot = rv.slot.slot_number();

        let parent_payload_status = if post_gloas {
            let bid = layout
                .bid(data)
                .ok_or(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() })?;
            self.precheck_gloas_bid(bid, parent_node, &rv, block_epoch, parent_root, block_root)?
        } else {
            PayloadStatus::Full
        };

        if parent_payload_status == PayloadStatus::Full &&
            parent_node.execution_status == ExecutionStatus::Invalid
        {
            let reason = RejectReason::InvalidPayload;
            return Err(PrecheckError::ParentRejected { parent_root, block_root, reason });
        }

        // A block must strictly extend its parent's slot.
        if block_slot <= parent_slot {
            return Err(PrecheckError::PastSlot { block_slot, parent_slot });
        }

        if block_slot > self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Err(PrecheckError::FutureSlot {
                block_slot,
                wall_slot: self.ticker.current_slot(),
            });
        }

        let relay_eligible = match lookahead_proposer(&rv, block_slot) {
            Some(expected) if proposer_index != expected => {
                return Err(PrecheckError::ProposerLookaheadMismatch {
                    expected,
                    got: proposer_index,
                    block_root,
                });
            }
            Some(_) => true,
            None => {
                silver_log::debug!(
                    block_slot,
                    parent_slot,
                    "proposer lookahead does not reach this block — not relayed"
                );
                false
            }
        };

        let validator_count = rv.validators.count();
        if proposer_index as usize >= validator_count {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_count,
                block_root,
            });
        }

        if !post_gloas {
            self.precheck_fulu_payload(body, block_slot, block_epoch, &rv, block_root)?;
        }

        let has_data_columns = layout != SignedBlockLayout::Pq &&
            SignedBeaconBlockView::has_data_columns(data, post_gloas);

        Ok(ParsedBlock {
            layout,
            header: block_header,
            block_root,
            has_data_columns,
            parent_state_id,
            fork,
            parent_payload_status,
            relay_eligible,
        })
    }

    /// The Fulu gossip rules require the execution timestamp and the active
    /// blob limit before propagation. The STF re-checks both, but that runs
    /// after the relay has already gone out.
    fn precheck_fulu_payload(
        &self,
        body: &[u8],
        block_slot: Slot,
        block_epoch: Epoch,
        rv: &StateReadView<'_>,
        block_root: B256,
    ) -> Result<(), PrecheckError> {
        let Ok(offsets) = BodyOffsets::new(body, BodyFork::Fulu) else {
            return Err(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() });
        };
        let expected = rv.imm.genesis_time + block_slot * self.spec.seconds_per_slot();
        let got = ssz_view::ExecutionPayloadView::timestamp(offsets.payload().bytes());
        if got != expected {
            return Err(PrecheckError::PayloadTimestamp { expected, got, block_root });
        }

        let max = self.spec.blob_params_at(block_epoch).max_blobs_per_block as usize;
        let got = offsets.blob_commitments_fulu().len() / ssz_view::BYTES_PER_KZG_COMMITMENT;
        if got > max {
            return Err(PrecheckError::TooManyCommitments { got, max, block_root });
        }

        Ok(())
    }

    /// The proposer's key is read from `state_id`, where its index must exist.
    fn verify_block_signature(
        &self,
        layout: SignedBlockLayout,
        data: &[u8],
        state_id: StateId,
        block_root: &B256,
    ) -> bool {
        let block_slot = layout.slot(data);
        let rv = self.state.read_view(state_id);
        let fork_version = self.spec.fork_version_at(block_slot / SLOTS_PER_EPOCH);
        let proposer_index = layout.proposer_index(data) as usize;
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            fork_version,
            &rv.imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(block_root, &domain);
        if layout != SignedBlockLayout::Pq {
            let proposer_pubkey = rv.validators.pubkey_decompressed(proposer_index);
            return bls::verify_one(
                proposer_pubkey,
                SignedBeaconBlockView::signature(data),
                &signing_root,
            );
        }
        if self.xmss_stubbed {
            return true;
        }
        let Some(public_key) = rv.validator_xmss_pubkey(proposer_index) else { return false };
        SignatureCheck {
            public_key,
            leaf_index: compute_xmss_leaf_index(block_slot, LeafOffset::BeaconProposer),
            signing_root,
            signature: SignedBeaconBlockPqView::signature(data),
        }
        .verify()
    }

    /// A block that parks on `err` pins its bytes, and precheck returned before
    /// the proposer checks. Without the parent the head state stands in: its
    /// registry is the same up to recent deposits, and its lookahead is the
    /// same unless the fork predates it.
    fn check_parking_proposer(&self, data: &[u8], err: PrecheckError) -> PrecheckError {
        let (PrecheckError::ParentMissing { block_root, .. } |
        PrecheckError::UnverifiedParentPayload { block_root, .. }) = err
        else {
            return err;
        };
        let Ok(layout) = self.block_layout(data) else { return err };
        let parent_root = layout.parent_root(data);
        let state_id = self
            .fork_choice
            .find_node_idx(&parent_root)
            .map_or(self.last_applied, |idx| self.fork_choice.node(idx).state_id);
        let rv = self.state.read_view(state_id);

        let block_slot = layout.slot(data);
        let proposer_index = layout.proposer_index(data);
        let unconfirmed = PrecheckError::UnconfirmedProposer { proposer_index, block_root };
        if proposer_index as usize >= rv.validators.count() {
            return unconfirmed;
        }
        let expected = lookahead_proposer(&rv, block_slot);
        if expected.is_some_and(|expected| expected != proposer_index) {
            return unconfirmed;
        }

        if !self.verify_block_signature(layout, data, state_id, &block_root) {
            return PrecheckError::InvalidSignature { block_root };
        }
        err
    }

    /// The Gloas gossip rules on the bid: blob count, parent root, and, for a
    /// block declaring its parent EMPTY, that it builds on the parent's
    /// execution head. Returns the parent payload status the bid declares.
    fn precheck_gloas_bid(
        &self,
        bid: &[u8],
        parent_node: &ForkChoiceNode,
        rv: &StateReadView<'_>,
        block_epoch: Epoch,
        parent_root: B256,
        block_root: B256,
    ) -> Result<PayloadStatus, PrecheckError> {
        let max = self.spec.blob_params_at(block_epoch).max_blobs_per_block as usize;
        let got = ssz_view::ExecutionPayloadBidView::blob_kzg_commitments(bid).len() /
            ssz_view::BYTES_PER_KZG_COMMITMENT;
        if got > max {
            return Err(PrecheckError::TooManyCommitments { got, max, block_root });
        }
        if *ssz_view::ExecutionPayloadBidView::parent_block_root(bid) != parent_root {
            return Err(PrecheckError::BidParentRootMismatch { block_root });
        }

        let parent_block_hash = *ssz_view::ExecutionPayloadBidView::parent_block_hash(bid);
        let full = parent_block_hash == parent_node.payload.bid_block_hash;
        if full && !parent_node.payload.verified {
            return Err(PrecheckError::UnverifiedParentPayload { parent_root, block_root });
        }
        if !full && parent_block_hash != rv.slot.state().latest_block_hash {
            return Err(PrecheckError::BidNotOnExecutionHead { block_root });
        }
        if full { Ok(PayloadStatus::Full) } else { Ok(PayloadStatus::Empty) }
    }
}

fn forkchoice_hashes(fcu: &EngineFcuReq) -> [B256; 3] {
    [fcu.head_block_hash, fcu.safe_block_hash, fcu.finalized_block_hash]
}
