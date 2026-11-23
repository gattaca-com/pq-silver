use std::{
    fmt::{self, Display},
    ops::Range,
};

use flux::spine::SpineProducers;
use silver_beacon_state_data::{
    B256, BLSPubkey, BidBuilderError, BuilderRegistry, Epoch, ExecutionPayloadBid, ForkName,
    MIN_SEED_LOOKAHEAD, ParsedAggregateAndProof, SLOTS_PER_EPOCH, SYNC_SUBCOMMITTEE_MASK_WORDS,
    SYNC_SUBCOMMITTEE_SIZE, ShufflingId, Slot, SpecConfig, StateId, StateReadView,
    SyncSubcommittee,
    bls::{self, CheckedSignature, PublicKey, Signature, VerifiedSingleAttestation},
    gloas::PTC_SIZE,
    pq::{MIN_ATTESTATION_INCLUSION_DELAY_PQ, xmss_pubkey},
    xmss::SignatureCheck,
};
use silver_common::{
    BeaconStateEvent, BlockSource, BroadcastValidation, EngineNewPayloadEnvelopeReq, EngineReq,
    GossipTopic, LOCAL_GOSSIP_STREAM_ID, LocalGossipFailure, MAX_BLOBS_PER_BLOCK, Nanos,
    NewGossipMsg, PayloadValidationStatus, PeerEvent, SignedBlockLayout, SyncNeed, TCacheRead,
    TRead, compute_subnet_for_attestation, hex32,
    metrics::timed,
    ssz_view::{
        AttestationDataView, AttesterSlashingView, BeaconBlockHeaderView, BuilderExitRequestView,
        ExecutionPayloadEnvelopeView as Envelope, ExecutionPayloadView,
        PAYLOAD_ATTESTATION_MESSAGE_SIZE, PROPOSER_PREFERENCES_SIZE, PROPOSER_SLASHING_PQ_SIZE,
        PROPOSER_SLASHING_SIZE, PayloadAttestationDataView, PayloadAttestationMessageView,
        ProposerPreferencesView as Prefs, ProposerSlashingPqView, ProposerSlashingView,
        SIGNED_BLS_CHANGE_SIZE, SIGNED_CONTRIBUTION_AND_PROOF_SIZE,
        SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, SIGNED_PROPOSER_PREFERENCES_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SYNC_COMMITTEE_MSG_SIZE,
        SignedBlsToExecutionChangeView, SignedProposerPreferencesPqView,
        SignedProposerPreferencesView, SignedSyncCommitteeProofView, SignedVoluntaryExitView,
        SingleAttestationView, SyncCommitteeView,
    },
};
use silver_ssz::ssz_view::{
    PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE, SINGLE_ATT_PQ_SIZE, SignedAggregateAndProofPqView,
    SignedExecutionPayloadBidPqView, SignedExecutionPayloadBidView, SingleAttestationPqView,
    XMSSPubkey,
};

use super::{
    BeaconStateTile, Feedback, MAXIMUM_GOSSIP_CLOCK_DISPARITY, Producers,
    attestation_pool::{InsertOutcome, Participants},
    block::lookahead_proposer,
    fork_data_roots::ForkDataRoots,
    gossip_proofs::{AggregateAwaitingProof, AwaitingProofs, GossipAwaitingProof},
    held_blocks::BlockSourceMsg,
    leanvm_verifier::ProofVerdict,
    pending_envelopes::{BLOCK_WAIT_SLOTS, ParkedEnvelope, ParkedKind, UnverifiedEnvelope},
    pq_aggregation::{Aggregate, VerifiedVote, claim},
    seen_aggregates::Coverage,
    seen_proposer_preferences::ProposerPreferences,
    shuffling_cache::ShufflingRequest,
};
use crate::{
    counters::BeaconStateCounters,
    error::{EnvelopeError, VoluntaryExitError},
    fork_choice::{
        ExecutionStatus, PayloadAxis, compute_shuffling_dependent_slot,
        compute_shuffling_lookahead_start_slot,
    },
    merkle, ssz_hash,
    stf::{
        self, RequestsLayout, decode_bid_message, is_gas_limit_target_compatible,
        verify_execution_payload_bid_signature,
    },
    validate,
};

pub(super) const VOTE_BATCH_CAP: usize = 1024;

pub(super) const PTC_MASK_WORDS: usize = PTC_SIZE.div_ceil(64);

#[derive(Clone, Copy)]
pub(super) enum BidSignature<'a> {
    Bls(&'a [u8; 96]),
    Xmss { signed_bid: &'a [u8] },
}

enum SignedPreferences<'a> {
    Bls(&'a [u8; SIGNED_PROPOSER_PREFERENCES_SIZE]),
    Xmss(&'a [u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE]),
}

impl<'a> SignedPreferences<'a> {
    fn parse(data: &'a [u8], format: ForkName) -> Option<Self> {
        if format == ForkName::Pq {
            data.try_into().ok().map(Self::Xmss)
        } else {
            data.try_into().ok().map(Self::Bls)
        }
    }

    fn message(&self) -> &'a [u8; PROPOSER_PREFERENCES_SIZE] {
        match self {
            Self::Bls(signed) => SignedProposerPreferencesView::message(signed),
            Self::Xmss(signed) => SignedProposerPreferencesPqView::message(signed),
        }
    }
}

pub(super) struct PreparedAttestation {
    buf: [u8; SINGLE_ATT_SIZE],
    committee_position: usize,
    committee_len: usize,
    pubkey: PublicKey,
    signing_root: B256,
    data_root: B256,
    attester: u32,
    target: stf::VoteTarget,
    attested: AttestedBlock,
    /// The head shuffling the committee position was read from.
    shuffling: ShufflingId,
}

impl PreparedAttestation {
    fn signature(&self) -> &[u8; 96] {
        SingleAttestationView::signature(&self.buf)
    }
}

pub(super) struct PreparedSyncMessage {
    slot: Slot,
    subnet: u64,
    validator: u64,
    block_root: B256,
    positions: [u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
    pubkey: PublicKey,
    signing_root: B256,
    signature: [u8; 96],
}

pub(crate) struct PtcVote {
    pub block_root: B256,
    pub slot: Slot,
    pub validator: u64,
    pub ptc_positions: [u64; PTC_MASK_WORDS],
    pub present: bool,
    pub da: bool,
}

pub(crate) struct PreparedPtc {
    pub vote: PtcVote,
    pub pubkey: PublicKey,
    pub signing_root: B256,
    pub signature: [u8; 96],
}

pub(crate) struct PreparedPqPtc {
    pub message: [u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE],
    pub pubkey: XMSSPubkey,
    pub domain: B256,
    pub vote: PtcVote,
}

#[derive(Clone, Copy)]
struct CheckedAttestation {
    committee_position: usize,
    committee_len: usize,
    attester: u32,
    target: stf::VoteTarget,
    attested: AttestedBlock,
    shuffling: ShufflingId,
    committee_state: StateId,
}

pub(crate) struct PreparedPqAttestation {
    buf: [u8; SINGLE_ATT_PQ_SIZE],
    pubkey: XMSSPubkey,
    signing_root: B256,
    data_root: B256,
    subnet: u64,
    checked: CheckedAttestation,
    received: Nanos,
}

impl PreparedPqAttestation {
    fn verified_vote(&self) -> VerifiedVote<'_> {
        VerifiedVote {
            single: &self.buf,
            data_root: self.data_root,
            message: self.signing_root,
            pubkey: self.pubkey,
            committee_position: self.checked.committee_position,
            committee_len: self.checked.committee_len,
            received: self.received,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(super) enum PreparedPqVote {
    Attestation(PreparedPqAttestation),
    Ptc(PreparedPqPtc),
}

impl PreparedPqVote {
    fn signature_check(&self) -> SignatureCheck<'_> {
        match self {
            Self::Attestation(p) => {
                SignatureCheck::single_attestation(&p.buf, &p.pubkey, p.signing_root)
            }
            Self::Ptc(p) => {
                SignatureCheck::payload_attestation_message(&p.message, &p.pubkey, &p.domain)
            }
        }
    }

    fn message(&self) -> &[u8] {
        match self {
            Self::Attestation(p) => &p.buf,
            Self::Ptc(p) => &p.message,
        }
    }

    fn is_seen(&self, tile: &BeaconStateTile) -> bool {
        match self {
            Self::Attestation(p) => tile
                .seen_attesters
                .contains(p.checked.target.target_epoch, p.checked.attester as usize),
            Self::Ptc(p) => tile.seen_ptc.contains(p.vote.slot, p.vote.validator as usize),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(super) enum PreparedVote {
    Attestation(PreparedAttestation),
    SyncMessage(PreparedSyncMessage),
    Ptc(PreparedPtc),
}

impl PreparedVote {
    fn pubkey_and_root(&self) -> (&PublicKey, &B256) {
        match self {
            Self::Attestation(p) => (&p.pubkey, &p.signing_root),
            Self::SyncMessage(p) => (&p.pubkey, &p.signing_root),
            Self::Ptc(p) => (&p.pubkey, &p.signing_root),
        }
    }

    fn signature(&self) -> &[u8; 96] {
        match self {
            Self::Attestation(p) => p.signature(),
            Self::SyncMessage(p) => &p.signature,
            Self::Ptc(p) => &p.signature,
        }
    }

    fn signature_malformed(&self) -> &'static str {
        match self {
            Self::Attestation(_) => "attestation signature malformed",
            Self::SyncMessage(_) => "sync message signature malformed",
            Self::Ptc(_) => "ptc signature malformed",
        }
    }

    /// Only attestations keep their bytes past preparation.
    fn message(&self) -> &[u8] {
        match self {
            Self::Attestation(p) => &p.buf,
            Self::SyncMessage(_) | Self::Ptc(_) => &[],
        }
    }

    fn is_seen(&self, tile: &BeaconStateTile) -> bool {
        match self {
            Self::Attestation(p) => {
                tile.seen_attesters.contains(p.target.target_epoch, p.attester as usize)
            }
            Self::SyncMessage(p) => {
                tile.seen_sync_msgs[p.subnet as usize].contains(p.slot, p.validator as usize)
            }
            Self::Ptc(p) => tile.seen_ptc.contains(p.vote.slot, p.vote.validator as usize),
        }
    }

    fn dedup_key(&self) -> (u8, u64, u64, u64) {
        match self {
            Self::Attestation(p) => (0, p.attester as u64, p.target.target_epoch, 0),
            Self::SyncMessage(p) => (1, p.validator, p.slot, p.subnet),
            Self::Ptc(p) => (2, p.vote.validator, p.vote.slot, 0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AttestedBlock {
    Ready {
        payload_present: bool,
    },
    /// Imported, but the payload the vote names is not yet valid.
    AwaitingPayload,
    Unknown,
}

enum Promotion {
    Promoted,
    Waiting,
    Dropped,
}

impl AttestedBlock {
    fn is_ready(self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// A failed committee check. Committees come from the head's shuffling,
    /// which an unknown block may not share.
    fn committee_reject(self, reason: &'static str) -> Feedback {
        match self {
            Self::Unknown => Feedback::Ignore,
            Self::Ready { .. } | Self::AwaitingPayload => Feedback::reject(reason),
        }
    }
}

pub(super) enum EnvelopeCheck {
    Ready { block_root: B256, state_id: StateId },
    AwaitBlock(B256),
    Ignore,
    Reject,
}

pub(super) struct BatchedVote {
    pub vote: NewGossipMsg,
    pub pin: TRead,
}

impl BeaconStateTile {
    #[timed]
    pub(super) fn handle_attestation(&mut self, data: &[u8], subnet: u64) -> Feedback {
        let prepared = match self.prepare_attestation(data, subnet) {
            Ok(prepared) => prepared,
            Err(feedback) => return feedback,
        };
        let Some(signature) = CheckedSignature::parse(prepared.signature()) else {
            return Feedback::reject("attestation signature malformed");
        };
        if !bls::verify_one_checked(&prepared.pubkey, &signature, &prepared.signing_root) {
            return Feedback::reject("attestation bad signature");
        }
        self.commit_attestation(&prepared, &signature)
    }

    /// Everything up to (but excluding) the signature check and the pairing:
    /// structural checks, dedup, committee membership, roots. The pairing runs
    /// either singly (`handle_attestation`) or batched
    /// (`flush_attestations`).
    fn prepare_attestation(
        &mut self,
        data: &[u8],
        subnet: u64,
    ) -> Result<PreparedAttestation, Feedback> {
        // Exact size: trailing bytes parse fine here (fixed-size prefix) but
        // strict-SSZ peers reject the relayed message — their P4 lands on us,
        // not the originator.
        if data.len() != SINGLE_ATT_SIZE {
            return Err(Feedback::reject("attestation size"));
        }
        let buf: &[u8; SINGLE_ATT_SIZE] = data[..SINGLE_ATT_SIZE].try_into().unwrap();
        let data = SingleAttestationView::data(buf);
        if self.spec.is_pq_at_slot(data.slot()) {
            return Err(Feedback::reject("BLS attestation for a PQ slot"));
        }
        let checked = self.check_attestation(
            SingleAttestationView::committee_index(buf) as usize,
            SingleAttestationView::attester_index(buf) as usize,
            data,
            subnet,
        )?;

        let view = self.state.read_view(checked.committee_state);
        let (data_root, signing_root) = self.attestation_root_memo.roots(
            data.as_bytes(),
            &Self::attester_domain(&self.spec, &mut self.fork_data_roots, &view, data),
        );
        Ok(PreparedAttestation {
            buf: *buf,
            committee_position: checked.committee_position,
            committee_len: checked.committee_len,
            pubkey: *view.validators.pubkey_decompressed(checked.attester as usize),
            signing_root,
            data_root,
            attester: checked.attester,
            target: checked.target,
            attested: checked.attested,
            shuffling: checked.shuffling,
        })
    }

    fn prepare_pq_attestation(
        &mut self,
        data: &[u8],
        subnet: u64,
        received: Nanos,
    ) -> Result<PreparedPqAttestation, Feedback> {
        let buf: &[u8; SINGLE_ATT_PQ_SIZE] = data.try_into().expect("checked PQ attestation size");
        let data = SingleAttestationPqView::data(buf);
        if !self.spec.is_pq_at_slot(data.slot()) {
            return Err(Feedback::reject("XMSS attestation before the PQ fork"));
        }
        let checked = self.check_attestation(
            SingleAttestationPqView::committee_index(buf) as usize,
            SingleAttestationPqView::attester_index(buf) as usize,
            data,
            subnet,
        )?;

        let view = self.state.read_view(checked.committee_state);
        let Some(pubkey) = view.validator_xmss_pubkey(checked.attester as usize) else {
            return Err(Feedback::Ignore);
        };
        let (data_root, signing_root) = self.attestation_root_memo.roots(
            data.as_bytes(),
            &Self::attester_domain(&self.spec, &mut self.fork_data_roots, &view, data),
        );
        Ok(PreparedPqAttestation {
            buf: *buf,
            pubkey: *pubkey,
            signing_root,
            data_root,
            subnet,
            checked,
            received,
        })
    }

    fn attester_domain(
        spec: &SpecConfig,
        fork_data_roots: &mut ForkDataRoots,
        view: &StateReadView,
        data: AttestationDataView<'_>,
    ) -> B256 {
        bls::domain_from_fork_data(
            bls::DOMAIN_BEACON_ATTESTER,
            &fork_data_roots
                .root(spec.fork_version_at(data.target_epoch()), &view.imm.genesis_validators_root),
        )
    }

    fn check_attestation(
        &mut self,
        committee_index: usize,
        attester_index: usize,
        data: AttestationDataView<'_>,
        subnet: u64,
    ) -> Result<CheckedAttestation, Feedback> {
        let block_root = *data.beacon_block_root();
        let target_epoch = data.target_epoch();
        let att_slot = data.slot();

        if !self.attestation_slot_is_open(att_slot) {
            return Err(self.slot_window_miss(att_slot));
        }

        self.seen_attesters.rotate_to(self.seen_window_epoch());
        if self.seen_attesters.contains(target_epoch, attester_index) {
            return Err(Feedback::AlreadySeen);
        }

        // Pre-Gloas single attestations encode the committee in
        // `committee_index`, so `AttestationData.index` must be 0. Gloas widens
        // it to a payload-status bit (`index == 1` ⇒ payload present).
        let is_gloas = self.spec.is_gloas_at(target_epoch);
        if !validate::attestation_index_ok(is_gloas, data.index()) {
            return Err(Feedback::reject("attestation data index"));
        }

        let canon_id = self.epoch_start_state(self.canonical_state_id(), att_slot);
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        // Validate committee membership against the canonical head.
        let view = self.state.read_view(canon_id);
        let Some(request) = ShufflingRequest::new(&view, att_epoch) else {
            return Err(Feedback::Ignore);
        };
        let shuffling_id = request.id();
        let attested = self.check_attested_block(data, shuffling_id)?;
        let shuffling = self.shuffling_cache.get(request);
        if committee_index >= shuffling.committees_per_slot {
            return Err(attested.committee_reject("attestation committee index out of range"));
        }
        if subnet !=
            compute_subnet_for_attestation(
                self.spec.fork_at_slot(att_slot),
                shuffling.committees_per_slot as u64,
                att_slot,
                committee_index as u64,
            )
        {
            return Err(attested.committee_reject("attestation wrong subnet"));
        }
        let committee = shuffling.committee(att_slot, committee_index);
        let Some(committee_position) = committee.iter().position(|&v| v == attester_index as u32)
        else {
            return Err(attested.committee_reject("attester not in committee"));
        };
        let committee_len = committee.len();
        if attester_index >= view.validators.count() {
            return Err(Feedback::reject("attester index out of range"));
        }

        Ok(CheckedAttestation {
            committee_position,
            committee_len,
            attester: attester_index as u32,
            target: stf::VoteTarget {
                block_root,
                target_epoch,
                attestation_slot: att_slot,
                payload_present: attested == AttestedBlock::Ready { payload_present: true },
            },
            attested,
            shuffling: shuffling_id,
            committee_state: canon_id,
        })
    }

    /// A vote waiting for its block or payload is buffered until it arrives.
    fn commit_attestation(
        &mut self,
        p: &PreparedAttestation,
        signature: &CheckedSignature,
    ) -> Feedback {
        self.seen_attesters.mark(p.target.target_epoch, p.attester as usize);
        if !p.attested.is_ready() {
            let new_data = self.unknown_root_votes.insert(
                SingleAttestationView::data(&p.buf),
                SingleAttestationView::committee_index(&p.buf),
                p.data_root,
                p.committee_len,
                Participants::Single(p.committee_position),
                p.shuffling,
                &signature.into_sig(),
            );
            return self.buffered_vote_feedback(
                new_data,
                p.attested,
                &p.target.block_root,
                p.target.attestation_slot,
            );
        }

        let verified =
            VerifiedSingleAttestation { data_root: p.data_root, signature: signature.into_sig() };
        let outcome = self.attestation_pool.insert_verified(
            &p.buf,
            p.committee_position,
            p.committee_len,
            &verified,
        );
        debug_assert!(outcome != InsertOutcome::Invalid);
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::AttestationPoolFull.inc();
            silver_log::debug!(
                slot = p.target.attestation_slot,
                committee = SingleAttestationView::committee_index(&p.buf),
                "attestation pool full"
            );
        }

        self.record_votes(p.target, std::slice::from_ref(&p.attester));
        Feedback::Accept
    }

    fn commit_vote(&mut self, p: &PreparedVote, signature: &CheckedSignature) -> Feedback {
        match p {
            PreparedVote::Attestation(p) => self.commit_attestation(p, signature),
            PreparedVote::SyncMessage(p) => {
                self.commit_sync_message(p, signature);
                Feedback::Accept
            }
            PreparedVote::Ptc(p) => {
                self.commit_ptc(p, signature);
                Feedback::Accept
            }
        }
    }

    /// Only the first vote buffered for its data asks for what it waits on.
    fn buffered_vote_feedback(
        &self,
        new_data: bool,
        attested: AttestedBlock,
        block_root: &B256,
        att_slot: Slot,
    ) -> Feedback {
        match self.awaited_need(attested, block_root, att_slot) {
            Some(need) if new_data => Feedback::Request(need),
            _ => Feedback::Ignore,
        }
    }

    /// What a vote waiting on `attested` needs fetched; `None` once it is
    /// held or verified here.
    fn awaited_need(
        &self,
        attested: AttestedBlock,
        block_root: &B256,
        att_slot: Slot,
    ) -> Option<SyncNeed> {
        match attested {
            AttestedBlock::Ready { .. } => None,
            AttestedBlock::Unknown => (!self.held.holds(block_root))
                .then(|| SyncNeed::missing_block(*block_root, att_slot)),
            AttestedBlock::AwaitingPayload => (!self.fork_choice.is_payload_verified(block_root) &&
                !self.pending_envelopes.holds(block_root))
            .then(|| SyncNeed::missing_envelope(*block_root, att_slot)),
        }
    }

    /// Buffered votes whose block is known take the checks that needed it,
    /// then count as if they had just arrived. Those whose payload is not yet
    /// valid stay buffered.
    pub(super) fn promote_unknown_root_votes(&mut self, producers: &mut Producers) {
        let mut from = 0;
        while let Some(id) = self.unknown_root_votes.next_with_known_block(from, |block_root| {
            self.fork_choice.find_node_idx(block_root).is_some()
        }) {
            from = id + 1;
            let counter = match self.promote_buffered_candidate(id, producers) {
                Promotion::Waiting => continue,
                Promotion::Promoted => BeaconStateCounters::UnknownRootVotesPromoted,
                Promotion::Dropped => BeaconStateCounters::UnknownRootVotesDropped,
            };
            counter.add(self.unknown_root_votes.vote_count(id));
            self.unknown_root_votes.close(id);
        }
        self.promote_unknown_root_pq_votes(producers);
    }

    /// The target of buffered votes for `data`, once the block and payload
    /// they name are ready; until then, what they wait on is requested.
    fn buffered_vote_target(
        &self,
        data: AttestationDataView<'_>,
        shuffling: ShufflingId,
        producers: &mut Producers,
    ) -> Result<stf::VoteTarget, Promotion> {
        let block_root = *data.beacon_block_root();
        let payload_present = match self.check_attested_block(data, shuffling) {
            Ok(AttestedBlock::Ready { payload_present }) => payload_present,
            Ok(attested) => {
                if let Some(need) = self.awaited_need(attested, &block_root, data.slot()) {
                    producers.produce(need);
                }
                return Err(Promotion::Waiting);
            }
            Err(_) => return Err(Promotion::Dropped),
        };
        Ok(stf::VoteTarget {
            block_root,
            target_epoch: data.target_epoch(),
            attestation_slot: data.slot(),
            payload_present,
        })
    }

    fn promote_buffered_candidate(&mut self, id: usize, producers: &mut Producers) -> Promotion {
        let data = self.unknown_root_votes.data(id);
        let shuffling_id = self.unknown_root_votes.shuffling(id);
        let target = match self.buffered_vote_target(data, shuffling_id, producers) {
            Ok(target) => target,
            Err(promotion) => return promotion,
        };
        let att_slot = target.attestation_slot;

        let Some(shuffling) = self.shuffling_cache.find(shuffling_id) else {
            return Promotion::Dropped;
        };
        let validator_count = self.head_validator_count();

        if !self.unknown_root_votes.promote_into(id, &mut self.attestation_pool) {
            BeaconStateCounters::AttestationPoolFull.inc();
        }

        let current_slot = self.ticker.current_slot();
        for (index, positions) in self.unknown_root_votes.committees(id) {
            let members = shuffling.committee(att_slot, index);
            let attesters = &mut self.stf_scratch.active;
            attesters.clear();
            attesters.extend(positions.map(|position| members[position]));
            self.fork_choice.record_or_defer_votes(
                target,
                attesters,
                validator_count,
                current_slot,
            );
        }
        Promotion::Promoted
    }

    pub(super) fn defer_vote(&mut self, vote: NewGossipMsg, producers: &mut Producers) {
        let pin = self.reader.acquire(vote.ssz);
        let batch = if vote.domain.format() == ForkName::Pq {
            &mut self.votes.pq_batch
        } else {
            &mut self.votes.batch
        };
        batch.push(BatchedVote { vote, pin });
        if batch.len() >= VOTE_BATCH_CAP {
            self.flush_votes(producers);
        }
    }

    pub(super) fn flush_votes(&mut self, producers: &mut Producers) {
        if !self.votes.batch.is_empty() {
            self.verify_and_commit_votes(producers);
        }
        if !self.votes.pq_batch.is_empty() {
            self.verify_and_commit_pq_votes(producers);
        }
    }

    #[timed]
    fn verify_and_commit_pq_votes(&mut self, producers: &mut Producers) {
        BeaconStateCounters::VoteBatchSize.set(self.votes.pq_batch.len() as u64);
        self.prepare_pq_votes(producers);

        let mut prepared = std::mem::take(&mut self.votes.pq_prepared);
        let mut valid = std::mem::take(&mut self.votes.pq_valid);
        valid.clear();
        valid.resize(prepared.len(), false);
        SignatureCheck::verify_batch(prepared.iter().map(|(_, p)| p.signature_check()), &mut valid);

        let mut accepted = false;
        let mut committed_ptc = false;
        for ((m, p), valid) in prepared.drain(..).zip(valid.drain(..)) {
            if p.is_seen(self) {
                Self::local_verdict(&m, Feedback::AlreadySeen, producers);
                continue;
            }
            if !valid {
                self.reject_gossip(&m, p.message(), "vote bad signature", producers);
                continue;
            }
            let feedback = match p {
                PreparedPqVote::Attestation(p) => self.commit_pq_attestation(p),
                PreparedPqVote::Ptc(p) => {
                    committed_ptc |= self.record_pq_ptc_vote(&p.vote);
                    Feedback::Accept
                }
            };
            accepted |= Self::conclude_vote(&m, feedback, producers);
        }
        self.votes.pq_prepared = prepared;
        self.votes.pq_valid = valid;

        if committed_ptc {
            self.recompute_head(|event| producers.produce(event));
        }
        if accepted {
            self.publish_status(producers);
        }
    }

    fn prepare_pq_votes(&mut self, producers: &mut Producers) {
        debug_assert!(self.votes.pq_prepared.is_empty());
        let mut batch = std::mem::take(&mut self.votes.pq_batch);
        let received = self.ticker.since_genesis();
        for BatchedVote { vote, pin } in batch.drain(..) {
            let Some(data) = pin.buffer().ok().map(|(d, _)| d) else {
                Self::local_verdict(&vote, Feedback::Ignore, producers);
                continue;
            };
            let prepared =
                self.precheck_pq_gossip(vote.topic, data).and_then(|()| match vote.topic {
                    GossipTopic::BeaconAttestation(subnet) => self
                        .prepare_pq_attestation(data, subnet, received)
                        .map(PreparedPqVote::Attestation),
                    GossipTopic::PayloadAttestationMessage => {
                        self.prepare_pq_ptc(data).map(PreparedPqVote::Ptc)
                    }
                    _ => Err(Feedback::Ignore),
                });
            match prepared {
                Ok(p) => self.votes.pq_prepared.push((vote, p)),
                Err(Feedback::Reject { reason, .. }) => {
                    self.reject_gossip(&vote, data, reason, producers)
                }
                Err(feedback) => Self::local_verdict(&vote, feedback, producers),
            }
        }
        self.votes.pq_batch = batch;
    }

    /// A vote waiting for its block or payload is buffered until it arrives.
    /// A local aggregator on the vote's subnet also proves it.
    fn commit_pq_attestation(&mut self, p: PreparedPqAttestation) -> Feedback {
        let checked = p.checked;
        let target = checked.target;
        self.seen_attesters.mark(target.target_epoch, checked.attester as usize);
        let position = (self.aggregator_subnets.get(target.attestation_slot))
            .and_then(|held| held.last_aggregator_position(p.subnet));
        if checked.attested.is_ready() {
            self.record_votes(target, std::slice::from_ref(&checked.attester));
            if let Some(position) = position {
                self.pq_aggregator.add_vote(p.verified_vote(), position, &self.ticker);
            }
            return Feedback::Accept;
        }

        let data = *SingleAttestationPqView::data(&p.buf).as_bytes();
        let data_root = p.data_root;
        let new_data = self.unknown_root_pq_votes.insert(
            AttestationDataView::new(&data),
            data_root,
            checked.shuffling,
            checked.attester,
            position.is_some().then_some(p),
        );
        self.buffered_vote_feedback(
            new_data,
            checked.attested,
            &target.block_root,
            target.attestation_slot,
        )
    }

    fn aggregate_buffered_pq_vote(&mut self, p: &PreparedPqAttestation) {
        let slot = p.checked.target.attestation_slot;
        let held = self.aggregator_subnets.get(slot);
        let Some(position) = held.and_then(|held| held.last_aggregator_position(p.subnet)) else {
            return;
        };
        self.pq_aggregator.add_vote(p.verified_vote(), position, &self.ticker);
    }

    fn record_votes(&mut self, target: stf::VoteTarget, attesters: &[u32]) {
        let n = self.head_validator_count();
        let slot = self.ticker.current_slot();
        self.fork_choice.record_or_defer_votes(target, attesters, n, slot);
    }

    /// Relays an accepted vote; otherwise requests what it waits on and
    /// answers a local submitter. True when accepted.
    fn conclude_vote(m: &NewGossipMsg, feedback: Feedback, producers: &mut Producers) -> bool {
        if feedback == Feedback::Accept {
            Self::relay_gossip(m, None, producers);
            return true;
        }
        if let Feedback::Request(need) = feedback {
            producers.produce(need);
        }
        Self::local_verdict(m, feedback, producers);
        false
    }

    /// Buffered PQ votes whose block is known take the checks that needed
    /// it, then count as if they had just arrived.
    fn promote_unknown_root_pq_votes(&mut self, producers: &mut Producers) {
        let mut from = 0;
        while let Some(id) = self.unknown_root_pq_votes.next_with_known_block(from, |block_root| {
            self.fork_choice.find_node_idx(block_root).is_some()
        }) {
            from = id + 1;
            let data = self.unknown_root_pq_votes.data(id);
            let shuffling = self.unknown_root_pq_votes.shuffling(id);
            let target = self.buffered_vote_target(data, shuffling, producers);
            if let Err(Promotion::Waiting) = target {
                continue;
            }
            let votes = self.unknown_root_pq_votes.take(id);
            let count = votes.attesters.len() as u64;
            match target {
                Ok(target) => {
                    BeaconStateCounters::UnknownRootVotesPromoted.add(count);
                    self.record_votes(target, &votes.attesters);
                    for vote in &votes.aggregated {
                        self.aggregate_buffered_pq_vote(vote);
                    }
                }
                Err(_) => BeaconStateCounters::UnknownRootVotesDropped.add(count),
            }
            self.unknown_root_pq_votes.recycle(id, votes);
        }
    }

    /// Apply the deferred votes (attestations, sync committee messages, PTC
    /// attestations): sequential cheap validation in arrival order, then one
    /// multi-pairing verify for the survivors. A failed batch falls back to
    /// per-message verification so only the culprits are rejected.
    #[timed]
    fn verify_and_commit_votes(&mut self, producers: &mut Producers) {
        debug_assert!(!self.votes.batch.is_empty());
        BeaconStateCounters::VoteBatchSize.set(self.votes.batch.len() as u64);

        self.prepare_votes(producers);

        let batch_ok = self.sig_batch.verify_all();
        if !batch_ok && !self.votes.pending.is_empty() {
            BeaconStateCounters::VoteBatchFallback.inc();
        }

        let mut accepted = false;
        let mut committed_ptc = false;
        self.votes.pending.reverse();
        while let Some((m, p, sig)) = self.votes.pending.pop() {
            // Deduplicate only against votes whose signatures have already
            // verified and been committed. An invalid earlier arrival with
            // the same key must not suppress a later valid vote.
            if p.is_seen(self) {
                Self::local_verdict(&m, Feedback::AlreadySeen, producers);
                continue;
            }
            let (pk, root) = p.pubkey_and_root();
            let valid =
                m.is_api_verified() || batch_ok || self.sig_batch.verify_one(pk, &sig, root);
            if !valid {
                self.reject_gossip(&m, p.message(), "vote bad signature", producers);
                continue;
            }
            committed_ptc |= matches!(p, PreparedVote::Ptc(_));
            accepted |= Self::conclude_vote(&m, self.commit_vote(&p, &sig), producers);
        }

        // PTC votes all dirty the same fork-choice structure; fold the whole
        // flush in one head recomputation rather than once per message.
        if committed_ptc {
            self.recompute_head(|event| producers.produce(event));
        }

        if accepted {
            self.publish_status(producers);
        }
    }

    /// Prepares every vote, decompresses and subgroup-checks all their
    /// signatures in one batch, then pairs the survivors into `sig_batch`.
    #[timed]
    fn prepare_votes(&mut self, producers: &mut Producers) {
        self.sig_batch.clear();
        debug_assert!(
            self.votes.prepared.is_empty() &&
                self.votes.checked.is_empty() &&
                self.votes.pending.is_empty()
        );

        let mut batch = std::mem::take(&mut self.votes.batch);
        for BatchedVote { vote, pin } in batch.drain(..) {
            let Some(data) = pin.buffer().ok().map(|(d, _)| d) else {
                Self::local_verdict(&vote, Feedback::Ignore, producers);
                continue;
            };
            let prepared = match vote.topic {
                GossipTopic::BeaconAttestation(subnet) => {
                    self.prepare_attestation(data, subnet).map(PreparedVote::Attestation)
                }
                GossipTopic::SyncCommittee(subnet) => {
                    self.prepare_sync_message(data, subnet).map(PreparedVote::SyncMessage)
                }
                GossipTopic::PayloadAttestationMessage => {
                    self.prepare_ptc(data).map(PreparedVote::Ptc)
                }
                _ => continue,
            };
            match prepared {
                Ok(p) => self.votes.prepared.push((BatchedVote { vote, pin }, p)),
                Err(Feedback::Reject { reason, .. }) => {
                    self.reject_gossip(&vote, data, reason, producers)
                }
                Err(feedback) => Self::local_verdict(&vote, feedback, producers),
            }
        }
        self.votes.batch = batch;

        let mut prepared = std::mem::take(&mut self.votes.prepared);
        let mut checked = std::mem::take(&mut self.votes.checked);
        self.votes
            .checker
            .check_all(prepared.iter().map(|(_, p)| p.signature()), |s| checked.push(s));
        for ((BatchedVote { vote, pin }, p), sig) in prepared.drain(..).zip(checked.drain(..)) {
            let Some(sig) = sig else {
                let data = pin.buffer().ok().map_or(&[][..], |(d, _)| d);
                self.reject_gossip(&vote, data, p.signature_malformed(), producers);
                continue;
            };
            // Pair only the first candidate for each dedup key, but retain
            // later candidates. If that representative makes the batch fail,
            // fallback verification can still find a later valid candidate
            // for the same key. A sync message on several subnets carries one
            // signature, paired once.
            let key = p.dedup_key();
            let (pk, root) = p.pubkey_and_root();
            let paired = self.votes.pending.iter().any(|(_, q, _)| q.dedup_key() == key) ||
                matches!(p, PreparedVote::SyncMessage(_)) &&
                    self.sig_batch.contains(pk, sig, root);
            if !paired && !vote.is_api_verified() {
                self.sig_batch.push_parsed(pk, sig, *root);
            }
            self.votes.pending.push((vote, p, sig));
        }
        self.votes.prepared = prepared;
        self.votes.checked = checked;
    }

    pub(super) fn prepare_sync_message(
        &mut self,
        data: &[u8],
        subnet: u64,
    ) -> Result<PreparedSyncMessage, Feedback> {
        if data.len() != SYNC_COMMITTEE_MSG_SIZE {
            return Err(Feedback::reject("sync message size"));
        }
        let buf: &[u8; SYNC_COMMITTEE_MSG_SIZE] =
            data[..SYNC_COMMITTEE_MSG_SIZE].try_into().unwrap();
        let slot = SyncCommitteeView::slot(buf);
        let validator = SyncCommitteeView::validator_index(buf);

        if subnet >= silver_common::SYNC_COMMITTEE_SUBNETS as u64 {
            return Err(Feedback::reject("sync message subnet out of range"));
        }
        if !self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Err(self.slot_window_miss(slot));
        }

        let seen = &mut self.seen_sync_msgs[subnet as usize];
        seen.rotate_to(self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY));
        if seen.contains(slot, validator as usize) {
            return Err(Feedback::AlreadySeen);
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        if validator as usize >= view.validators.count() {
            return Err(Feedback::reject("sync message validator out of range"));
        }

        let committee = SyncSubcommittee::of(&view, subnet as usize);
        let positions = committee.positions(validator as usize, &view.validators);
        if positions.iter().all(|&word| word == 0) {
            return Err(Feedback::reject("sync message validator not in subcommittee"));
        }

        let block_root = *SyncCommitteeView::beacon_block_root(buf);
        let fork_version = self.spec.fork_version_at(slot / SLOTS_PER_EPOCH);
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_SYNC_COMMITTEE,
            &self.fork_data_roots.root(fork_version, &view.imm.genesis_validators_root),
        );
        let signing_root = bls::compute_signing_root(&block_root, &domain);
        let signature = *SyncCommitteeView::signature(buf);

        Ok(PreparedSyncMessage {
            slot,
            subnet,
            validator,
            block_root,
            positions,
            pubkey: *view.validators.pubkey_decompressed(validator as usize),
            signing_root,
            signature,
        })
    }

    fn commit_sync_message(&mut self, p: &PreparedSyncMessage, signature: &CheckedSignature) {
        let outcome = self.sync_contribution_pool.insert_verified(
            p.slot,
            p.subnet,
            p.block_root,
            &p.positions,
            &signature.into_sig(),
        );
        debug_assert!(outcome != InsertOutcome::Invalid);
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::SyncContributionPoolFull.inc();
            silver_log::debug!(
                slot = p.slot,
                subcommittee = p.subnet,
                block = hex32(&p.block_root),
                "sync contribution pool full"
            );
        }
        self.seen_sync_msgs[p.subnet as usize].mark(p.slot, p.validator as usize);
    }

    #[timed]
    pub(super) fn handle_sync_contribution(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_CONTRIBUTION_AND_PROOF_SIZE {
            return Feedback::reject("contribution size");
        }
        let buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE] =
            data[..SIGNED_CONTRIBUTION_AND_PROOF_SIZE].try_into().unwrap();
        let slot = SignedSyncCommitteeProofView::slot(buf);
        let subcommittee = SignedSyncCommitteeProofView::subcommittee_index(buf);
        let aggregator = SignedSyncCommitteeProofView::aggregator_index(buf);
        let block_root = *SignedSyncCommitteeProofView::beacon_block_root(buf);
        let bits = SignedSyncCommitteeProofView::aggregation_bits(buf);

        if subcommittee >= silver_common::SYNC_COMMITTEE_SUBNETS as u64 {
            return Feedback::reject("contribution subcommittee out of range");
        }
        if !self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return self.slot_window_miss(slot);
        }

        let seen = &mut self.seen_contribution_aggregators[subcommittee as usize];
        seen.rotate_to(self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY));
        if seen.contains(slot, aggregator as usize) {
            return Feedback::AlreadySeen;
        }
        let coverage = self.seen_aggregates.coverage(slot, subcommittee, block_root, bits);
        if coverage == Coverage::BySuperset {
            return Feedback::AlreadySeen;
        }

        if !is_sync_aggregator(SignedSyncCommitteeProofView::selection_proof(buf)) {
            return Feedback::reject("contribution aggregator not selected");
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let count = view.validators.count();
        if aggregator as usize >= count {
            return Feedback::reject("contribution aggregator out of range");
        }
        let committee = SyncSubcommittee::of(&view, subcommittee as usize);
        if !committee.contains(aggregator as usize, &view.validators) {
            return Feedback::reject("contribution aggregator not in subcommittee");
        }

        let fv = self.spec.fork_version_at(slot / SLOTS_PER_EPOCH);
        let fork_data_root = self.fork_data_roots.root(fv, &view.imm.genesis_validators_root);
        let domain = |ty| bls::domain_from_fork_data(ty, &fork_data_root);

        let sr_sp = bls::compute_signing_root(
            &ssz_hash::hash_tree_root_sync_selection_data(slot, subcommittee),
            &domain(bls::DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF),
        );
        let contribution_root = ssz_hash::hash_tree_root_sync_contribution(
            slot,
            &block_root,
            subcommittee,
            bits,
            SignedSyncCommitteeProofView::contribution_signature(buf),
        );
        let cap_root = ssz_hash::hash_tree_root_contribution_and_proof(
            aggregator,
            &contribution_root,
            SignedSyncCommitteeProofView::selection_proof(buf),
        );
        let sr_outer =
            bls::compute_signing_root(&cap_root, &domain(bls::DOMAIN_CONTRIBUTION_AND_PROOF));
        let sr_agg = bls::compute_signing_root(&block_root, &domain(bls::DOMAIN_SYNC_COMMITTEE));

        let mut participants = 0usize;
        let mut unknown = false;
        self.sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(aggregator as usize);
        self.sig_batch.push_one(
            aggregator_pk,
            SignedSyncCommitteeProofView::selection_proof(buf),
            sr_sp,
        );
        self.sig_batch.push_one(
            aggregator_pk,
            SignedSyncCommitteeProofView::signature(buf),
            sr_outer,
        );
        self.sig_batch.push_aggregate(
            (0..SYNC_SUBCOMMITTEE_SIZE).filter_map(|i| {
                if bits[i / 8] & (1 << (i % 8)) == 0 {
                    return None;
                }
                participants += 1;
                let Some(vi) = committee.validator_at(i, &view.validators) else {
                    unknown = true;
                    return None;
                };
                Some(view.validators.pubkey_decompressed(vi))
            }),
            SignedSyncCommitteeProofView::contribution_signature(buf),
            sr_agg,
        );
        if unknown || participants == 0 || !self.sig_batch.verify_all() {
            return Feedback::reject("contribution bad signature");
        }

        self.seen_aggregates.record(slot, subcommittee, block_root, bits);
        self.seen_contribution_aggregators[subcommittee as usize].mark(slot, aggregator as usize);
        let outcome = self.sync_contribution_pool.insert_received(
            slot,
            subcommittee,
            block_root,
            bits,
            SignedSyncCommitteeProofView::contribution_signature(buf),
        );
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::SyncContributionPoolFull.inc();
            silver_log::debug!(
                slot,
                subcommittee,
                block = hex32(&block_root),
                "sync contribution pool full"
            );
        }
        Feedback::Accept
    }

    #[timed]
    fn handle_execution_payload_bid(&mut self, signed_bid: &[u8], format: ForkName) -> Feedback {
        let (message, signature) = if format == ForkName::Pq {
            (SignedExecutionPayloadBidPqView::message(signed_bid), BidSignature::Xmss {
                signed_bid,
            })
        } else {
            if !SignedExecutionPayloadBidView::check_size(signed_bid) {
                return Feedback::reject("bid malformed");
            }
            (
                SignedExecutionPayloadBidView::message(signed_bid),
                BidSignature::Bls(SignedExecutionPayloadBidView::signature(signed_bid)),
            )
        };
        let Ok(bid) = decode_bid_message(message) else {
            return Feedback::reject("bid malformed");
        };
        if self.spec.is_pq_at_slot(bid.slot) != (format == ForkName::Pq) {
            return Feedback::reject("bid signature scheme does not match the slot's fork");
        }

        if !self.payload_bids_pool.is_candidate(&bid) {
            return Feedback::Ignore;
        }
        let is_current =
            |slot| self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY);
        let current_or_next = is_current(bid.slot) || (bid.slot > 0 && is_current(bid.slot - 1));
        if !current_or_next {
            return Feedback::Ignore;
        }
        // In-protocol bids pay only through `value`; the pool also ranks
        // out-of-protocol bids, so this belongs to gossip, not the pool.
        if bid.execution_payment != 0 {
            return Feedback::reject("bid has execution payment");
        }
        if let Err(feedback) = self.check_bid_on_parent(&bid, signature, |_| true) {
            return feedback;
        }
        self.payload_bids_pool.add(bid, signed_bid);
        Feedback::Accept
    }

    /// What a bid must pass however it arrived: its parent, its builder's
    /// standing, then `accepts_builder`, then its signature.
    pub(super) fn check_bid_on_parent(
        &mut self,
        bid: &ExecutionPayloadBid,
        signature: BidSignature<'_>,
        accepts_builder: impl Fn(&BLSPubkey) -> bool,
    ) -> Result<(), Feedback> {
        if bid.block_hash == bid.parent_block_hash {
            return Err(Feedback::reject("bid block hash equals parent"));
        }
        let bid_epoch = bid.slot / SLOTS_PER_EPOCH;
        let max_blobs = self.spec.blob_params_at(bid_epoch).max_blobs_per_block as usize;
        if bid.blob_kzg_commitments.len() > max_blobs {
            return Err(Feedback::reject("bid too many blob commitments"));
        }

        let Some(idx) = self.fork_choice.find_node_idx(&bid.parent_block_root) else {
            return Err(Feedback::Ignore);
        };
        let node = self.fork_choice.node(idx);
        if bid.slot <= node.slot {
            return Err(Feedback::reject("bid slot not after parent"));
        }
        let (parent_slot, parent_state, parent_payload) = (node.slot, node.state_id, node.payload);
        let full = self.check_bid_against_parent_payload(
            bid,
            parent_state,
            &parent_payload,
            bid_epoch,
            idx,
        )?;

        // The spec checks the builder on `process_slots(parent, bid.slot)`.
        // Only epoch processing moves what those checks read (finalization,
        // pending payments); `process_slot` touches none of it. So the
        // epoch-start state of the bid's epoch is exact, and it is the cached
        // one the slot tick reuses rather than a fork-choice advance.
        let at_bid = self.epoch_start_state(parent_state, bid.slot);
        let view = self.state.read_view(at_bid);

        let finalized_epoch = view.epoch.state().finalized_checkpoint.epoch;
        let builder = match BuilderRegistry::of_reader(&view).check_bid(
            finalized_epoch,
            bid.builder_index,
            bid.value,
        ) {
            Ok(builder) => builder,
            Err(e @ BidBuilderError::InsufficientBalance { .. }) => {
                silver_log::debug!(?e, "execution payload bid ignored");
                return Err(Feedback::Ignore);
            }
            Err(e) => {
                silver_log::debug!(?e, "invalid execution payload bid");
                return Err(Feedback::reject("bid invalid"));
            }
        };
        // The parent payload's exits apply only in the bid's own block, so the
        // state above still shows the builder active.
        if full {
            let layout = RequestsLayout::for_fork(self.spec.is_pq_at_slot(parent_slot));
            let mut exits =
                self.payload_execution_requests.builder_exits(&bid.parent_block_root, layout);
            if exits.any(|request| {
                *BuilderExitRequestView::pubkey(request) == builder.pubkey &&
                    *BuilderExitRequestView::source_address(request) == builder.execution_address
            }) {
                return Err(Feedback::Ignore);
            }
        }
        if !accepts_builder(&builder.pubkey) {
            return Err(Feedback::Ignore);
        }

        // Last of the checks: a pairing costs more than all of them together.
        let valid = match signature {
            BidSignature::Bls(signature) => verify_execution_payload_bid_signature(
                view.imm,
                &view.epoch,
                &view.builders,
                bid,
                signature,
            )
            .inspect_err(|e| silver_log::debug!(?e, "execution payload bid signature rejected"))
            .is_ok(),
            BidSignature::Xmss { signed_bid } => {
                if !view.is_pq() {
                    return Err(Feedback::Ignore);
                }
                let domain = bls::compute_domain(
                    bls::DOMAIN_BEACON_BUILDER,
                    view.epoch.fork_version_at(bid_epoch),
                    &view.imm.genesis_validators_root,
                );
                SignatureCheck::execution_payload_bid(
                    signed_bid,
                    xmss_pubkey(&builder.pubkey),
                    &domain,
                )
                .is_some_and(|check| check.verify())
            }
        };
        if !valid {
            return Err(Feedback::reject("bid bad signature"));
        }

        Ok(())
    }

    /// Retunrs whetehr the parent payload was full or not.
    fn check_bid_against_parent_payload(
        &self,
        bid: &ExecutionPayloadBid,
        parent_state: StateId,
        parent_payload: &PayloadAxis,
        bid_epoch: u64,
        idx: usize,
    ) -> Result<bool, Feedback> {
        let parent = self.state.read_view(parent_state);
        let parent_epoch = parent.slot.state().slot / SLOTS_PER_EPOCH;
        if bid_epoch > parent_epoch + MIN_SEED_LOOKAHEAD {
            return Err(Feedback::Ignore);
        }

        let Some(dependent_root) =
            self.fork_choice.shuffling_dependent_root(&bid.parent_block_root, bid_epoch)
        else {
            return Err(Feedback::Ignore);
        };
        let Some(prefs) = self.seen_proposer_preferences.get(bid.slot, &dependent_root) else {
            return Err(Feedback::Ignore);
        };
        if bid.fee_recipient != prefs.fee_recipient {
            return Err(Feedback::Ignore);
        }

        // Full: the bid builds on the parent's own payload. Empty: on the
        // payload the parent itself built on, committed by an ancestor.
        let full = bid.parent_block_hash == parent_payload.bid_block_hash;
        if !full && bid.parent_block_hash != parent.slot.state().latest_block_hash {
            return Err(Feedback::Ignore);
        }
        let Some(owner_idx) = self.fork_choice.payload_owner(idx, &bid.parent_block_hash) else {
            return Err(Feedback::Ignore);
        };
        let owner = self.fork_choice.node(owner_idx);
        if !owner.payload.verified {
            return Err(Feedback::Ignore);
        }
        // Envelope verification pins a payload's gas limit to its block's
        // committed bid; pre-Gloas the block carries the payload itself.
        let owner_state = self.state.read_view(owner.state_id);
        let owner_slot = owner_state.slot.state();
        let parent_gas_limit = if owner.payload.is_gloas {
            owner_slot.latest_execution_payload_bid.gas_limit
        } else {
            owner_slot.latest_execution_payload_header.gas_limit
        };
        if !is_gas_limit_target_compatible(parent_gas_limit, bid.gas_limit, prefs.target_gas_limit)
        {
            return Err(Feedback::Ignore);
        }

        if !self.is_bid_compatible_with_head(bid) {
            return Err(Feedback::Ignore);
        }

        if bid.prev_randao != parent.randao_mixes.at_epoch(parent_epoch) {
            return Err(Feedback::reject("bid prev_randao mismatch"));
        }
        Ok(full)
    }

    /// Spec `is_bid_compatible_with_head`.
    fn is_bid_compatible_with_head(&self, bid: &ExecutionPayloadBid) -> bool {
        let Some(head_idx) = self.fork_choice.find_node_idx(&self.fork_choice.find_head()) else {
            return false;
        };
        let head = self.fork_choice.node(head_idx);
        let head_state = self.state.read_view(head.state_id);
        let head_slot = head_state.slot.state();
        // Pre-Gloas the head block carries its payload, which the header holds.
        let head_parent_hash = if head.payload.is_gloas {
            head_slot.latest_execution_payload_bid.parent_block_hash
        } else {
            head_slot.latest_execution_payload_header.parent_hash
        };

        let builds_on_parent_payload = bid.parent_block_hash == head_parent_hash;
        if bid.parent_block_root == head_slot.latest_block_header.parent_root &&
            builds_on_parent_payload
        {
            return true;
        }
        if bid.parent_block_root != head.block_root {
            return false;
        }
        if self.fork_choice.should_build_on_full(head_idx, bid.slot) {
            bid.parent_block_hash == head.payload.bid_block_hash
        } else {
            builds_on_parent_payload
        }
    }

    #[timed]
    fn handle_proposer_preferences(
        &mut self,
        data: &[u8],
        format: ForkName,
        local: bool,
    ) -> Feedback {
        let Some(signed) = SignedPreferences::parse(data, format) else {
            return Feedback::reject("proposer preferences size");
        };
        let prefs = signed.message();
        let proposal_slot = Prefs::proposal_slot(prefs);
        if self.spec.is_pq_at_slot(proposal_slot) != matches!(signed, SignedPreferences::Xmss(_)) {
            return Feedback::reject("preferences signature scheme does not match the slot's fork");
        }
        let dependent_root = *Prefs::dependent_root(prefs);

        let seen = self.seen_proposer_preferences.contains(proposal_slot, &dependent_root);
        // Local duplicates still need authentication before enabling payload
        // preparation.
        if seen && !local {
            return Feedback::AlreadySeen;
        }
        let proposal_epoch = proposal_slot / SLOTS_PER_EPOCH;
        if !self.spec.is_gloas_at(proposal_epoch) {
            return Feedback::Ignore;
        }
        if self.ticker.is_past_slot(proposal_slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Feedback::Ignore;
        }
        let lookahead_start = compute_shuffling_lookahead_start_slot(proposal_epoch);
        if self.ticker.is_future_slot(lookahead_start, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Feedback::Ignore;
        }

        let Some(idx) = self.fork_choice.find_node_idx(&dependent_root) else {
            return Feedback::Ignore;
        };
        let dependent_slot = compute_shuffling_dependent_slot(proposal_epoch);
        if self.fork_choice.node(idx).slot > dependent_slot {
            return Feedback::reject("proposer preferences dependent root too late");
        }
        if !self.fork_choice.is_valid_dependent_root(idx, dependent_slot) {
            return Feedback::Ignore;
        }

        let at_lookahead =
            self.epoch_start_state(self.fork_choice.node(idx).state_id, lookahead_start);
        let view = self.state.read_view(at_lookahead);
        let validator_index = Prefs::validator_index(prefs);
        let lookahead_idx = (proposal_slot - lookahead_start) as usize;
        if view.epoch.proposer_at(lookahead_idx) != Some(validator_index) {
            return Feedback::reject("proposer preferences wrong proposer");
        }

        let domain = bls::compute_domain(
            bls::DOMAIN_PROPOSER_PREFERENCES,
            self.spec.fork_version_at(proposal_epoch),
            &view.imm.genesis_validators_root,
        );
        let valid = match signed {
            SignedPreferences::Bls(signed) => bls::verify_one(
                view.validators.pubkey_decompressed(validator_index as usize),
                SignedProposerPreferencesView::signature(signed),
                &bls::compute_signing_root(&Prefs::hash_tree_root(prefs), &domain),
            ),
            SignedPreferences::Xmss(signed) => {
                let Some(pubkey) = view.validator_xmss_pubkey(validator_index as usize) else {
                    return Feedback::Ignore;
                };
                SignatureCheck::proposer_preferences(signed, pubkey, &domain).verify()
            }
        };
        if !valid {
            return Feedback::reject("proposer preferences bad signature");
        }

        self.seen_proposer_preferences.insert(
            proposal_slot,
            dependent_root,
            ProposerPreferences {
                fee_recipient: *Prefs::fee_recipient(prefs),
                target_gas_limit: Prefs::target_gas_limit(prefs),
            },
            local,
        );
        if seen { Feedback::AlreadySeen } else { Feedback::Accept }
    }

    /// EF `fork_choice` vector path only: production gossip reaches the same
    /// work through `handle_attestation` / `handle_aggregate_and_proof`, which
    /// have already resolved the committee by the time votes are recorded.
    #[cfg(feature = "ef_tests")]
    pub(super) fn apply_attestation(&mut self, att: &[u8]) -> Feedback {
        use silver_common::ssz_view::AttestationView;

        let data = AttestationView::data(att);
        match self.validate_attestation_target(data) {
            Ok(Some(_)) => {}
            Ok(None) => return Feedback::Ignore,
            Err(f) => return f,
        }

        let canon_id = self.epoch_start_state(self.canonical_state_id(), data.slot());
        let att_epoch = data.slot() / SLOTS_PER_EPOCH;
        {
            let view = self.state.read_view(canon_id);
            let n = view.validators.count();
            let Some(request) = ShufflingRequest::new(&view, att_epoch) else {
                return Feedback::Ignore;
            };
            if !self.fork_choice.shares_shuffling(data.beacon_block_root(), request.id()) {
                return Feedback::Ignore;
            }
            let shuffling = self.shuffling_cache.get(request);
            let is_pq = self.spec.is_pq_at_slot(data.slot());
            if stf::AttestedCommittees::new(att, is_pq, &shuffling)
                .and_then(|c| c.attesters_into(n, &mut self.stf_scratch.active))
                .is_err()
            {
                return Feedback::reject("attestation committees invalid");
            }
            if self.stf_scratch.active.is_empty() {
                return Feedback::reject("attestation has no attesters");
            }
        }

        let n = self.state.read_view(canon_id).validators.count();
        self.record_attester_votes(data, n);
        Feedback::Accept
    }

    fn record_attester_votes(&mut self, data: AttestationDataView<'_>, validator_count: usize) {
        let target = stf::VoteTarget {
            block_root: *data.beacon_block_root(),
            target_epoch: data.target_epoch(),
            attestation_slot: data.slot(),
            payload_present: data.index() == 1,
        };
        self.fork_choice.record_or_defer_votes(
            target,
            &self.stf_scratch.active,
            validator_count,
            self.ticker.current_slot(),
        );
    }

    #[timed]
    pub(super) fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        let Some(parsed) = ParsedAggregateAndProof::try_from(data) else {
            return Feedback::reject("aggregate malformed");
        };
        if self.spec.is_pq_at_slot(parsed.agg_slot) {
            return Feedback::reject("BLS aggregate for a PQ slot");
        }

        // Gossip-rule checks (no state access). Pre-Gloas requires index 0;
        // Gloas widens it to the payload-status bit (`index < 2`).
        let is_gloas = self.spec.is_gloas_at(parsed.att_epoch);
        let index_ok = validate::attestation_index_ok(is_gloas, parsed.agg_data_index);
        if !index_ok || parsed.agg_data.target_epoch() != parsed.att_epoch {
            return Feedback::reject("aggregate data index");
        }
        if !self.attestation_slot_is_open(parsed.agg_slot) {
            return self.slot_window_miss(parsed.agg_slot);
        }

        if parsed.committee_bits.count_ones() != 1 {
            return Feedback::reject("aggregate committee bits");
        }
        let committee_index = parsed.committee_bits.trailing_zeros() as usize;

        let data_root = self.attestation_root_memo.data_root(parsed.agg_data.as_bytes());
        let coverage = match self.unseen_aggregate_coverage(
            parsed.agg_slot,
            parsed.att_epoch,
            committee_index as u64,
            parsed.aggregator_index,
            data_root,
            parsed.aggregation_bits,
        ) {
            Ok(coverage) => coverage,
            Err(feedback) => return feedback,
        };

        let canon_id = self.epoch_start_state(self.canonical_state_id(), parsed.agg_slot);
        let view = self.state.read_view(canon_id);
        let count = view.validators.count();
        if parsed.aggregator_index >= count {
            return Feedback::reject("aggregator index out of range");
        }

        let Some(request) = ShufflingRequest::new(&view, parsed.att_epoch) else {
            return Feedback::Ignore;
        };
        let shuffling_id = request.id();
        let attested = match self.check_attested_block(parsed.agg_data, shuffling_id) {
            Ok(attested) => attested,
            Err(f) => return f,
        };
        let shuffling = self.shuffling_cache.get(request);
        if committee_index >= shuffling.committees_per_slot {
            return attested.committee_reject("aggregate committee index out of range");
        }
        let committee = shuffling.committee(parsed.agg_slot, committee_index);
        if !committee.contains(&(parsed.aggregator_index as u32)) {
            return attested.committee_reject("aggregator not in committee");
        }
        let committee_len = committee.len();

        let Ok(committees) =
            stf::AttestedCommittees::new(parsed.aggregate_bytes, false, &shuffling)
        else {
            return attested.committee_reject("aggregate committees invalid");
        };
        if committees.attesters_into(count, &mut self.stf_scratch.active).is_err() ||
            self.stf_scratch.active.is_empty()
        {
            return attested.committee_reject("aggregate has no attesters");
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return attested.committee_reject("aggregator not selected");
        }

        let Some(signature) = Self::verify_aggregate_and_proof_sigs(
            &view,
            self.spec.fork_version_at(parsed.agg_data.target_epoch()),
            &parsed,
            &committees,
            data_root,
            &mut self.fork_data_roots,
            &mut self.sig_batch,
        ) else {
            return attested.committee_reject("aggregate bad signature");
        };
        self.seen_aggregates.record(
            parsed.agg_slot,
            committee_index as u64,
            data_root,
            parsed.aggregation_bits,
        );
        self.seen_aggregators.mark(parsed.att_epoch, parsed.aggregator_index);
        if !attested.is_ready() {
            let new_data = self.unknown_root_votes.insert(
                parsed.agg_data,
                committee_index as u64,
                data_root,
                committee_len,
                Participants::Aggregate(parsed.aggregation_bits),
                shuffling_id,
                &signature,
            );
            return self.buffered_vote_feedback(
                new_data,
                attested,
                parsed.agg_data.beacon_block_root(),
                parsed.agg_slot,
            );
        }
        let outcome = self.attestation_pool.insert_verified_aggregate(
            parsed.agg_data,
            committee_index as u64,
            data_root,
            committee_len,
            parsed.aggregation_bits,
            &signature,
        );
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::AttestationPoolFull.inc();
            silver_log::debug!(
                slot = parsed.agg_slot,
                committee = committee_index,
                "attestation pool full"
            );
        }

        // A union-covered aggregate's votes are all already folded; it still
        // relays — union coverage must never gate forwarding.
        if coverage != Coverage::ByUnion {
            self.record_attester_votes(parsed.agg_data, count);
        }
        Feedback::Accept
    }

    pub(super) fn validate_execution_payload_envelope(&self, ssz: &[u8]) -> EnvelopeCheck {
        let Some((layout, envelope)) = [SignedBlockLayout::Gloas, SignedBlockLayout::Pq]
            .into_iter()
            .find_map(|layout| layout.envelope_message(ssz).map(|envelope| (layout, envelope)))
        else {
            return EnvelopeCheck::Reject;
        };
        let block_root = *Envelope::beacon_block_root(envelope);
        let Some(idx) = self.fork_choice.find_node_idx(&block_root) else {
            return EnvelopeCheck::AwaitBlock(block_root);
        };
        let node = self.fork_choice.node(idx);
        if SignedBlockLayout::at_slot(&self.spec, node.slot) != layout {
            return EnvelopeCheck::Reject;
        }
        if node.slot < self.fork_choice.finalized_checkpoint().epoch * SLOTS_PER_EPOCH {
            return EnvelopeCheck::Ignore;
        }
        let state_id = node.state_id;
        let rv = self.state.read_view(state_id);
        let verify_xmss = !self.xmss_stubbed;
        if let Err(e) =
            stf::verify_execution_payload_envelope(&rv, &self.spec, layout, ssz, verify_xmss)
        {
            silver_log::info!(error = %e, "execution_payload_envelope rejected");
            return EnvelopeCheck::Reject;
        }
        EnvelopeCheck::Ready { block_root, state_id }
    }

    /// `signed` passed `verify_execution_payload_envelope`.
    pub(super) fn mark_envelope_verified(&mut self, block_root: B256, signed: &[u8]) {
        self.fork_choice.mark_payload_verified(&block_root);
        self.payload_execution_requests
            .insert(block_root, stf::envelope_execution_requests(signed));
    }

    /// Consensus checks cannot tie an envelope's body to its block hash, so a
    /// rejected body says nothing about the committed payload: another
    /// envelope may carry it.
    pub(super) fn refetch_forged_envelope(
        &mut self,
        block_root: B256,
        envelope: &UnverifiedEnvelope,
        producers: &mut Producers,
    ) {
        self.el_rejected_envelopes.insert(envelope.signature_digest, block_root);
        self.pending_envelopes.request(block_root, envelope.slot, producers);
    }

    /// The spec stores a payload only once the EL has verified it, SYNCING and
    /// ACCEPTED optimistically, so it counts as verified from here on. One that
    /// failed execution is verified too: it is judged, so its copies and votes
    /// meet that verdict instead of fetching it again.
    pub(super) fn release_el_verified_envelope(
        &mut self,
        block_root: B256,
        envelope: UnverifiedEnvelope,
        status: PayloadValidationStatus,
        producers: &mut Producers,
    ) {
        let UnverifiedEnvelope { read, source, slot, .. } = envelope;
        self.fork_choice.mark_payload_verified(&block_root);
        if status != PayloadValidationStatus::Invalid {
            Self::emit_envelope_available(&read, source, slot, block_root, true, producers);
        }
        self.drain_awaiting_payload(block_root, producers);
        self.recompute_head(|event| producers.produce(event));
    }

    fn emit_envelope_available(
        acquired: &TRead,
        source: BlockSource,
        slot: u64,
        block_root: B256,
        newly_verified: bool,
        producers: &mut Producers,
    ) {
        producers.produce(BeaconStateEvent::EnvelopeAvailable {
            ssz: acquired.to_read(),
            source,
            slot,
            block_root,
            newly_verified,
        });
    }

    #[timed]
    pub(super) fn handle_execution_payload_envelope(
        &mut self,
        acquired: TRead,
        ssz: &[u8],
        source: BlockSource,
        producers: &mut Producers,
    ) -> Feedback {
        // BLS and XMSS signatures are deterministic: a rejected one either
        // repeats the rejected envelope or fails verification.
        if envelope_signature_digest(ssz)
            .is_some_and(|digest| self.el_rejected_envelopes.contains_key(&digest))
        {
            return Feedback::Ignore;
        }
        let (block_root, state_id) = match self.validate_execution_payload_envelope(ssz) {
            EnvelopeCheck::Ready { block_root, state_id } => (block_root, state_id),
            EnvelopeCheck::AwaitBlock(block_root) => {
                return self.park_signed_envelope(block_root, acquired, ssz);
            }
            EnvelopeCheck::Ignore => return Feedback::Ignore,
            EnvelopeCheck::Reject => return Feedback::reject("envelope invalid"),
        };
        self.submit_verified_envelope(acquired, ssz, block_root, state_id, source, producers)
    }

    /// `ssz` passed `verify_execution_payload_envelope` against `state_id`, the
    /// state of `block_root`.
    fn submit_verified_envelope(
        &mut self,
        acquired: TRead,
        ssz: &[u8],
        block_root: B256,
        state_id: StateId,
        source: BlockSource,
        producers: &mut Producers,
    ) -> Feedback {
        let signature_digest =
            envelope_signature_digest(ssz).expect("a verified envelope fits its layout");

        let rv = self.state.read_view(state_id);
        let slot = rv.slot.slot_number();
        self.envelope_arrivals.record(block_root, slot, self.ticker.millis_since_genesis());
        if !stf::envelope_withdrawals_match_expected(&rv, ssz) {
            silver_log::error!(
                block = hex32(&block_root),
                "envelope withdrawals are not the expected ones"
            );
            return Feedback::Accept;
        }
        let slot_state = rv.slot;

        let verified = self.fork_choice.is_payload_verified(&block_root);
        if verified || self.pending_envelopes.awaits_verdict(&block_root) {
            producers.produce(SyncNeed::envelope_arrived(block_root, slot));
            // The copy awaiting its verdict is announced once judged, and an
            // invalid payload is never announced.
            if verified && !self.fork_choice.is_payload_invalid(&block_root) {
                Self::emit_envelope_available(
                    &acquired, source, slot, block_root, false, producers,
                );
            }
            return Feedback::AlreadySeen;
        }

        // Versioned hashes come from the committed bid's KZG commitments — the
        // envelope does not carry them.
        let mut versioned_hashes = [[0u8; 32]; MAX_BLOBS_PER_BLOCK];
        let hash_count = match slot_state.bid_versioned_hashes_len(&mut versioned_hashes) {
            Some(n) => n as u8,
            None => return Feedback::reject("envelope bid versioned hashes"),
        };

        if hash_count > 0 && self.columns_pending(&block_root) {
            let parked = ParkedEnvelope { read: acquired, kind: ParkedKind::Verified };
            self.pending_envelopes.park(block_root, parked);
            return Feedback::Accept;
        }

        self.payload_execution_requests.insert(block_root, stf::envelope_execution_requests(ssz));
        producers.produce(SyncNeed::envelope_arrived(block_root, slot));
        producers.produce(EngineReq::NewPayloadEnvelope(EngineNewPayloadEnvelopeReq {
            data: acquired.to_read(),
            block_root,
            block_source: source,
            hash_count,
            versioned_hashes,
        }));
        self.pending_envelopes.await_verdict(block_root, UnverifiedEnvelope {
            read: acquired,
            source,
            slot,
            signature_digest,
        });

        Feedback::Accept
    }

    /// The spec only ignores an envelope for an unseen block. Checking its
    /// signature first keeps a peer without the signer's key from displacing
    /// the real envelope, or from filling the buffer.
    fn park_signed_envelope(&mut self, block_root: B256, acquired: TRead, ssz: &[u8]) -> Feedback {
        let Some(layout) = stf::envelope_layout(ssz) else {
            return Feedback::reject("envelope malformed");
        };
        let envelope = layout.envelope_message(ssz).expect("a canonical envelope");
        let slot = ExecutionPayloadView::slot_number(Envelope::payload(envelope));
        if SignedBlockLayout::at_slot(&self.spec, slot) != layout {
            return Feedback::reject("envelope signed for another fork");
        }
        let builder_index = Envelope::builder_index(envelope);
        let awaits_block = self.ticker.is_within_slot_range(
            slot,
            BLOCK_WAIT_SLOTS - 1,
            MAXIMUM_GOSSIP_CLOCK_DISPARITY,
        );
        if !awaits_block || !self.pending_envelopes.admits_signed(&block_root, slot, builder_index)
        {
            return Feedback::Ignore;
        }

        // The block's own state is unknown; its parent's has the same signer
        // keys unless the parent's payload itself registered this builder.
        let Some(parent_idx) =
            self.fork_choice.find_node_idx(Envelope::parent_beacon_block_root(envelope))
        else {
            return Feedback::Ignore;
        };
        let rv = self.state.read_view(self.fork_choice.node(parent_idx).state_id);
        let fork_version = self.spec.fork_version_at(slot / SLOTS_PER_EPOCH);
        let proposer = lookahead_proposer(&rv, slot);
        match stf::verify_envelope_signature(&rv, layout, ssz, fork_version, proposer) {
            Ok(()) => {}
            Err(EnvelopeError::BuilderOutOfRange { .. }) => return Feedback::Ignore,
            Err(e) => {
                silver_log::info!(
                    error = %e,
                    block = hex32(&block_root),
                    "envelope for an unseen block rejected"
                );
                return Feedback::reject("envelope signature");
            }
        }

        let parked =
            ParkedEnvelope { read: acquired, kind: ParkedKind::Signed { slot, builder_index } };
        self.pending_envelopes.park(block_root, parked);
        Feedback::Ignore
    }

    pub(super) fn drain_pending_envelope(
        &mut self,
        block_root: B256,
        slot: Slot,
        producers: &mut Producers,
    ) {
        let Some(parked) = self.pending_envelopes.take(&block_root) else {
            return;
        };

        let Some((ssz, _)) = parked.read.buffer().ok() else {
            silver_log::warn!(
                block = hex32(&block_root),
                slot,
                "parked envelope lapped; refetching"
            );
            self.pending_envelopes.request(block_root, slot, producers);
            return;
        };

        let feedback = match parked.kind {
            ParkedKind::FromDisk => {
                return self.apply_disk_envelope(parked.read, |event| producers.produce(event));
            }
            // Its block's state checks the signer again: the block can change
            // the builder registry the parking check read.
            ParkedKind::Signed { .. } => {
                let read = parked.read.clone();
                self.handle_execution_payload_envelope(read, ssz, BlockSource::Gossip, producers)
            }
            ParkedKind::Verified => {
                let Some(idx) = self.fork_choice.find_node_idx(&block_root) else { return };
                let state_id = self.fork_choice.node(idx).state_id;
                let (read, source) = (parked.read.clone(), BlockSource::Gossip);
                self.submit_verified_envelope(read, ssz, block_root, state_id, source, producers)
            }
        };
        // Its signer can still have signed a body the bid does not commit to,
        // and the honest copy was not parked beside it.
        if matches!(feedback, Feedback::Reject { .. }) {
            silver_log::info!(
                block = hex32(&block_root),
                slot,
                "parked envelope rejected; refetching"
            );
            self.pending_envelopes.request(block_root, slot, producers);
        }
    }

    /// The vote's checks that need its block, its committees read from
    /// `shuffling`.
    fn check_attested_block(
        &self,
        data: AttestationDataView<'_>,
        shuffling: ShufflingId,
    ) -> Result<AttestedBlock, Feedback> {
        let Some(idx) = self.validate_attestation_target(data)? else {
            return Ok(AttestedBlock::Unknown);
        };
        let block_root = data.beacon_block_root();
        if !self.fork_choice.shares_shuffling(block_root, shuffling) {
            return Err(Feedback::Ignore);
        }
        if !self.spec.is_gloas_at(data.target_epoch()) || data.index() != 1 {
            return Ok(AttestedBlock::Ready { payload_present: false });
        }
        if self.fork_choice.node(idx).slot == data.slot() {
            return Err(Feedback::reject("payload present for same-slot block"));
        }
        if !self.fork_choice.is_payload_verified(block_root) {
            return Ok(AttestedBlock::AwaitingPayload);
        }
        // Spec `verify_attestation_payload_status`: the EL's verdict on the
        // attested payload decides, an outstanding one defers the vote.
        match self.fork_choice.node(idx).execution_status {
            ExecutionStatus::Valid => Ok(AttestedBlock::Ready { payload_present: true }),
            ExecutionStatus::Optimistic => Ok(AttestedBlock::AwaitingPayload),
            ExecutionStatus::Invalid => Err(Feedback::reject("attested payload invalid")),
        }
    }

    /// Spec `is_future_slot` and Deneb's `is_current_or_previous_epoch`
    /// (EIP-7045 widened the window from 32 slots to the whole previous
    /// epoch), both with clock disparity.
    pub(super) fn slot_window_miss(&self, slot: Slot) -> Feedback {
        if self.ticker.is_future_slot(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            Feedback::Future
        } else {
            Feedback::TooOld
        }
    }

    fn attestation_slot_is_open(&self, slot: Slot) -> bool {
        let epoch_open = |epoch: Epoch| {
            self.ticker.is_within_slot_range(
                epoch * SLOTS_PER_EPOCH,
                SLOTS_PER_EPOCH - 1,
                MAXIMUM_GOSSIP_CLOCK_DISPARITY,
            )
        };
        let epoch = slot / SLOTS_PER_EPOCH;
        !self.ticker.is_future_slot(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) &&
            (epoch_open(epoch) || epoch_open(epoch + 1))
    }

    /// The epoch the per-epoch seen-caches rotate to: the newest one a vote can
    /// legitimately carry right now, so an early next-epoch vote has a lane.
    fn seen_window_epoch(&self) -> Epoch {
        self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY) / SLOTS_PER_EPOCH
    }

    fn unseen_aggregate_coverage(
        &mut self,
        slot: Slot,
        target_epoch: Epoch,
        committee_index: u64,
        aggregator_index: usize,
        data_root: B256,
        bits: &[u8],
    ) -> Result<Coverage, Feedback> {
        self.seen_aggregators.rotate_to(self.seen_window_epoch());
        if self.seen_aggregators.contains(target_epoch, aggregator_index) {
            return Err(Feedback::AlreadySeen);
        }
        match self.seen_aggregates.coverage(slot, committee_index, data_root, bits) {
            Coverage::BySuperset => Err(Feedback::AlreadySeen),
            coverage => Ok(coverage),
        }
    }

    /// The attested block's fork-choice index; `None` while it is unknown.
    fn validate_attestation_target(
        &self,
        data: AttestationDataView<'_>,
    ) -> Result<Option<usize>, Feedback> {
        let att_slot = data.slot();
        let target_epoch = data.target_epoch();
        if target_epoch != att_slot / SLOTS_PER_EPOCH {
            return Err(Feedback::reject("attestation target epoch mismatch"));
        }
        let Some(idx) = self.fork_choice.find_node_idx(data.beacon_block_root()) else {
            if self.held.rejected_reason(data.beacon_block_root()).is_some() {
                return Err(Feedback::Ignore);
            }
            BeaconStateCounters::AttestationUnknownRoot.inc();
            return Ok(None);
        };
        match self.fork_choice.checkpoint_block_of(idx, target_epoch * SLOTS_PER_EPOCH) {
            Some(r) if r == *data.target_root() => {}
            Some(_) => return Err(Feedback::reject("attestation target root mismatch")),
            None => return Err(Feedback::Ignore),
        }
        if self.fork_choice.node(idx).slot <= att_slot {
            Ok(Some(idx))
        } else {
            Err(Feedback::reject("attestation block newer than slot"))
        }
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateReadView,
        fork_version: [u8; 4],
        parsed: &ParsedAggregateAndProof<'_>,
        committees: &stf::AttestedCommittees<'_>,
        data_root: B256,
        fork_data_roots: &mut ForkDataRoots,
        sig_batch: &mut bls::SigBatch,
    ) -> Option<Signature> {
        let fork_data_root = fork_data_roots.root(fork_version, &view.imm.genesis_validators_root);
        let domain = |ty| bls::domain_from_fork_data(ty, &fork_data_root);

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = merkle::uint64_chunk(parsed.agg_slot);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain(bls::DOMAIN_SELECTION_PROOF));

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            parsed.aggregator_index as u64,
            parsed.aggregate_bytes,
            data_root,
            parsed.selection_proof,
            fork_version == view.imm.gloas_fork_version,
        );
        let sr_aap =
            bls::compute_signing_root(&agg_proof_root, &domain(bls::DOMAIN_AGGREGATE_AND_PROOF));

        // (3) inner aggregate signature over AttestationData.
        let sr_att = bls::compute_signing_root(&data_root, &domain(bls::DOMAIN_BEACON_ATTESTER));

        sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(parsed.aggregator_index);
        sig_batch.push_one(aggregator_pk, parsed.selection_proof, sr_sp);
        sig_batch.push_one(aggregator_pk, parsed.outer_sig, sr_aap);
        committees.push_aggregate_sig(&view.validators, parsed.agg_sig, sr_att, sig_batch);
        if !sig_batch.verify_all() {
            return None;
        }
        sig_batch.last_signature()
    }

    #[timed]
    pub(super) fn handle_voluntary_exit(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_VOLUNTARY_EXIT_SIZE {
            return Feedback::reject("exit size");
        }
        let buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            data[..SIGNED_VOLUNTARY_EXIT_SIZE].try_into().unwrap();
        let exit_epoch = SignedVoluntaryExitView::epoch(buf);
        let vi = SignedVoluntaryExitView::validator_index(buf);

        if self.seen_exits.contains(vi as usize) {
            return Feedback::AlreadySeen;
        }
        let exit_start = exit_epoch.saturating_mul(SLOTS_PER_EPOCH);
        if self.ticker.is_future_slot(exit_start, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Feedback::Ignore;
        }
        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let current_epoch = view.slot.current_epoch();
        match validate::validate_exit_eligibility(&self.spec, &view.validators, vi, current_epoch) {
            Ok(()) => {}
            Err(VoluntaryExitError::AlreadyExiting { .. }) => return Feedback::Ignore,
            Err(e) => {
                silver_log::debug!(error = %e, "voluntary_exit gossip rejected");
                return Feedback::reject("exit invalid");
            }
        }

        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(view.validators.pubkey_decompressed(vi as usize), sig, &signing_root) {
            return Feedback::reject("exit bad signature");
        }
        self.seen_exits.mark(vi as usize);
        self.exit_pool.insert(buf);
        Feedback::Accept
    }

    pub(super) fn handle_proposer_slashing(&mut self, data: &[u8]) -> Feedback {
        if data.len() != PROPOSER_SLASHING_SIZE {
            return Feedback::reject("proposer slashing size");
        }
        let buf: &[u8; PROPOSER_SLASHING_SIZE] = data[..PROPOSER_SLASHING_SIZE].try_into().unwrap();
        if let Err(e) = validate::validate_proposer_slashing(buf) {
            silver_log::debug!(error = %e, "proposer_slashing gossip rejected");
            return Feedback::reject("proposer slashing invalid");
        }

        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if self.seen_proposer_slashings.contains(proposer_index) {
            return Feedback::AlreadySeen;
        }
        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let current_epoch = view.slot.current_epoch();
        if proposer_index >= view.validators.count() {
            return Feedback::reject("proposer slashing index out of range");
        }
        if !view.validators.is_slashable(proposer_index, current_epoch) {
            return Feedback::reject("proposer not slashable");
        }

        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let fv = view.epoch.fork_version_at(h1_epoch);
        let domain =
            bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fv, &view.imm.genesis_validators_root);
        let sr1 = stf::signing_root_for_block_header(&buf[0..208], &domain);
        let sr2 = stf::signing_root_for_block_header(&buf[208..416], &domain);
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = view.validators.pubkey_decompressed(proposer_index);

        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, sig1, sr1);
        self.sig_batch.push_one(pubkey, sig2, sr2);
        if !self.sig_batch.verify_all() {
            return Feedback::reject("proposer slashing bad signature");
        }
        self.seen_proposer_slashings.mark(proposer_index);
        let admission =
            self.slashing_pool.insert_proposer_slashing(buf, &view, &mut self.events_producer);
        silver_log::info!(proposer_index, ?admission, "proposer slashing pooled");
        Feedback::Accept
    }

    pub(super) fn handle_attester_slashing(&mut self, data: &[u8]) -> Feedback {
        if !AttesterSlashingView::check_size(data) {
            return Feedback::reject("attester slashing size");
        }
        let canon_id = self.canonical_state_id();
        let slashed = &mut self.stf_scratch.active;
        let feedback = {
            let view = self.state.read_view(canon_id);
            // Spec order: no validator left to slash is an IGNORE before any
            // validity REJECT.
            let seen = |vi| self.seen_attester_slashed.contains(vi);
            match stf::attester_slashing_names_unseen(data, seen) {
                None => Feedback::reject("attester slashing invalid"),
                Some(false) => Feedback::Ignore,
                Some(true) => {
                    let valid = stf::validate_attester_slashing_for_gossip(
                        &view,
                        data,
                        slashed,
                        &mut self.sig_batch,
                    );
                    if valid {
                        Feedback::Accept
                    } else {
                        Feedback::reject("attester slashing bad signature")
                    }
                }
            }
        };
        // Mark the equivocators (spec `on_attester_slashing`) so fork choice
        // excludes them. Idempotent; removes any live LMD weight next recompute.
        if feedback == Feedback::Accept {
            for &idx in slashed.iter() {
                self.fork_choice.mark_equivocating(idx as usize);
                self.seen_attester_slashed.mark(idx as usize);
            }
            let view = self.state.read_view(canon_id);
            let admission = self.slashing_pool.insert_attester_slashing(
                data,
                slashed,
                &view,
                &mut self.events_producer,
            );
            silver_log::info!(offenders = slashed.len(), ?admission, "attester slashing pooled");
        }
        feedback
    }

    #[timed]
    pub(super) fn handle_bls_to_execution_change(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_BLS_CHANGE_SIZE {
            return Feedback::reject("bls change size");
        }
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] = data[..SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if self.seen_bls_changes.contains(vi) {
            return Feedback::AlreadySeen;
        }
        if vi >= view.validators.count() {
            return Feedback::reject("bls change validator out of range");
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) =
            validate::validate_bls_to_execution_change(&view.validators, vi_u, from_pubkey)
        {
            silver_log::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return Feedback::reject("bls change invalid");
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedBlsToExecutionChangeView::signature(buf);
        // Signer is the message's `from_bls_pubkey`, not a cached key.
        if !bls::verify_one_compressed(from_pubkey, sig, &signing_root) {
            return Feedback::reject("bls change bad signature");
        }
        self.seen_bls_changes.mark(vi);
        self.bls_change_pool.insert(buf);
        Feedback::Accept
    }

    fn precheck_pq_gossip(&self, topic: GossipTopic, bytes: &[u8]) -> Result<(), Feedback> {
        use silver_common::ssz_view::{
            BeaconBlockHeaderView as Header, ProposerSlashingPqView as Slashing,
            SignedAggregateAndProofPqView as Aggregate, SingleAttestationPqView as Attestation,
        };

        if let Err(reason) = topic.check_pq_signed_message(bytes) {
            return Err(Feedback::reject(reason));
        }
        match topic {
            GossipTopic::BeaconAttestation(_) => {
                let attestation = bytes.try_into().expect("checked PQ attestation size");
                let data = Attestation::data(attestation);
                if data.index() > 1 {
                    return Err(Feedback::reject("attestation data index"));
                }
            }
            GossipTopic::BeaconAggregateAndProof => {
                if Aggregate::agg_data(bytes).index() > 1 {
                    return Err(Feedback::reject("aggregate data index"));
                }
                if u16::from_le_bytes(*Aggregate::agg_committee_bits(bytes)).count_ones() != 1 {
                    return Err(Feedback::reject("aggregate committee bits"));
                }
            }
            GossipTopic::ProposerSlashing => {
                let slashing = bytes.try_into().expect("checked PQ slashing size");
                let a = Slashing::header_1(slashing);
                let b = Slashing::header_2(slashing);
                if a == b ||
                    Header::slot(a) != Header::slot(b) ||
                    Header::proposer_index(a) != Header::proposer_index(b)
                {
                    return Err(Feedback::reject("proposer slashing headers do not conflict"));
                }
                let expected = silver_common::xmss::SlotDuty::BeaconProposer.leaf(Header::slot(a));
                for sig in [Slashing::signature_1(slashing), Slashing::signature_2(slashing)] {
                    if expected != Some(silver_crypto_simd::xmss::leaf_index(sig)) {
                        return Err(Feedback::reject("incorrect XMSS proposer slashing leaf"));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_pq_gossip(
        &mut self,
        m: &NewGossipMsg,
        pin: &TRead,
        data: &[u8],
        producers: &mut Producers,
    ) -> Option<Feedback> {
        if let Err(feedback) = self.precheck_pq_gossip(m.topic, data) {
            return Some(feedback);
        }
        let feedback = match m.topic {
            GossipTopic::ProposerPreferences => self.handle_proposer_preferences(
                data,
                ForkName::Pq,
                m.stream_id == LOCAL_GOSSIP_STREAM_ID,
            ),
            GossipTopic::ExecutionPayloadBid => {
                self.handle_execution_payload_bid(data, ForkName::Pq)
            }
            GossipTopic::ProposerSlashing => {
                self.handle_pq_proposer_slashing(data.try_into().expect("checked PQ slashing size"))
            }
            GossipTopic::ExecutionPayload => self.handle_execution_payload_envelope(
                pin.clone(),
                data,
                BlockSource::Gossip,
                producers,
            ),
            GossipTopic::BeaconAggregateAndProof => {
                let (request_id, aggregate) = match self.send_pq_aggregate_proof(data, producers) {
                    Ok(sent) => sent,
                    Err(feedback) => return Some(feedback),
                };
                let gossip = GossipAwaitingProof::Aggregate(aggregate);
                let slot = self.ticker.current_slot();
                self.gossip_proofs.park(*m, pin.clone(), gossip, slot, request_id..request_id + 1);
                return None;
            }
            GossipTopic::AttesterSlashing => {
                let requests = match self.send_pq_attester_slashing_proofs(data, producers) {
                    Ok(requests) => requests,
                    Err(feedback) => return Some(feedback),
                };
                let gossip = GossipAwaitingProof::AttesterSlashing;
                let slot = self.ticker.current_slot();
                self.gossip_proofs.park(*m, pin.clone(), gossip, slot, requests);
                return None;
            }
            _ => Feedback::Ignore,
        };
        Some(feedback)
    }

    fn aggregate_state(&mut self, slot: Slot) -> StateId {
        let head = self.canonical_state_id();
        let head_epoch = self.slot_state_at(head).slot / SLOTS_PER_EPOCH;
        if head_epoch + MIN_SEED_LOOKAHEAD < slot / SLOTS_PER_EPOCH {
            self.epoch_start_state(head, slot)
        } else {
            head
        }
    }

    fn send_pq_aggregate_proof(
        &mut self,
        signed: &[u8],
        producers: &mut Producers,
    ) -> Result<(u64, AggregateAwaitingProof), Feedback> {
        let (state_id, mut aggregate) = self.check_pq_aggregate(signed)?;
        self.verify_pq_aggregator(signed, state_id, &aggregate)?;
        let block_slot = aggregate.target.attestation_slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ;
        let merges = self.proposes_locally(block_slot);

        let data = SignedAggregateAndProofPqView::agg_data(signed);
        let view = self.state.read_view(state_id);
        let domain = Self::attester_domain(&self.spec, &mut self.fork_data_roots, &view, data);
        let (_, message) = self.attestation_root_memo.roots(data.as_bytes(), &domain);
        let claims = aggregate.attesters.iter().map(|&attester| {
            claim(xmss_pubkey(view.validators.pubkey(attester as usize)), &message)
        });
        let proof = SignedAggregateAndProofPqView::proof(signed);
        let request_id = self
            .leanvm_verifier
            .send(claims, proof, &mut self.events_producer, producers)
            .ok_or(Feedback::Ignore)?;
        aggregate.merge_message = merges.then_some(message);
        Ok((request_id, aggregate))
    }

    fn check_pq_aggregate(
        &mut self,
        signed: &[u8],
    ) -> Result<(StateId, AggregateAwaitingProof), Feedback> {
        let data = SignedAggregateAndProofPqView::agg_data(signed);
        let slot = data.slot();
        let target_epoch = data.target_epoch();
        if !self.spec.is_pq_at_slot(slot) {
            return Err(Feedback::reject("XMSS aggregate before the PQ fork"));
        }
        if target_epoch != slot / SLOTS_PER_EPOCH {
            return Err(Feedback::reject("aggregate target epoch mismatch"));
        }
        if !self.attestation_slot_is_open(slot) {
            return Err(self.slot_window_miss(slot));
        }

        let committee_bits =
            u16::from_le_bytes(*SignedAggregateAndProofPqView::agg_committee_bits(signed));
        let committee_index = committee_bits.trailing_zeros() as usize;
        let bits = SignedAggregateAndProofPqView::agg_aggregation_bits(signed);
        let data_root = self.attestation_root_memo.data_root(data.as_bytes());
        let aggregator_index = SignedAggregateAndProofPqView::aggregator_index(signed) as usize;
        self.unseen_aggregate_coverage(
            slot,
            target_epoch,
            committee_index as u64,
            aggregator_index,
            data_root,
            bits,
        )?;
        if self.gossip_proofs.is_full() ||
            self.gossip_proofs.awaits_aggregator(target_epoch, aggregator_index)
        {
            return Err(Feedback::Ignore);
        }

        let state_id = self.aggregate_state(slot);
        let view = self.state.read_view(state_id);
        let count = view.validators.count();
        if aggregator_index >= count {
            return Err(Feedback::reject("aggregator index out of range"));
        }
        let Some(request) = ShufflingRequest::new(&view, target_epoch) else {
            return Err(Feedback::Ignore);
        };
        let AttestedBlock::Ready { payload_present } =
            self.check_attested_block(data, request.id())?
        else {
            return Err(Feedback::Ignore);
        };

        let shuffling = self.shuffling_cache.get(request);
        if committee_index >= shuffling.committees_per_slot {
            return Err(Feedback::reject("aggregate committee index out of range"));
        }
        if merkle::bitlist_len(bits) != shuffling.committee(slot, committee_index).len() {
            return Err(Feedback::reject("aggregate bits do not match committee size"));
        }
        let mut attesters = Vec::new();
        let aggregate = SignedAggregateAndProofPqView::aggregate(signed);
        if stf::AttestedCommittees::new(aggregate, true, &shuffling)
            .and_then(|committees| committees.attesters_into(count, &mut attesters))
            .is_err() ||
            attesters.is_empty()
        {
            return Err(Feedback::reject("aggregate has no attesters"));
        }

        Ok((state_id, AggregateAwaitingProof {
            target: stf::VoteTarget {
                block_root: *data.beacon_block_root(),
                target_epoch,
                attestation_slot: slot,
                payload_present,
            },
            attesters,
            committee_index: committee_index as u64,
            data_root,
            aggregator_index,
            merge_message: None,
        }))
    }

    fn verify_pq_aggregator(
        &mut self,
        signed: &[u8],
        state_id: StateId,
        aggregate: &AggregateAwaitingProof,
    ) -> Result<(), Feedback> {
        let target = aggregate.target;
        let view = self.state.read_view(state_id);
        match view.is_aggregator(
            target.attestation_slot,
            aggregate.committee_index as usize,
            aggregate.aggregator_index as u64,
        ) {
            Some(true) => {}
            Some(false) => return Err(Feedback::reject("aggregator not selected")),
            None => return Err(Feedback::Ignore),
        }
        let Some(pubkey) = view.validator_xmss_pubkey(aggregate.aggregator_index) else {
            return Err(Feedback::Ignore);
        };
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_AGGREGATE_AND_PROOF,
            &self.fork_data_roots.root(
                self.spec.fork_version_at(target.target_epoch),
                &view.imm.genesis_validators_root,
            ),
        );
        if !SignatureCheck::aggregate_and_proof(signed, pubkey, &domain).verify() {
            return Err(Feedback::reject("aggregate bad signature"));
        }
        Ok(())
    }

    fn send_pq_attester_slashing_proofs(
        &mut self,
        slashing: &[u8],
        producers: &mut Producers,
    ) -> Result<Range<u64>, Feedback> {
        if self.gossip_proofs.is_full() {
            return Err(Feedback::Ignore);
        }
        let state_id = self.canonical_state_id();
        let view = self.state.read_view(state_id);
        if !view.is_pq() {
            return Err(Feedback::Ignore);
        }
        let seen = |vi| self.seen_attester_slashed.contains(vi);
        let claims = &mut self.stf_scratch.stark;
        match stf::validate_pq_attester_slashing_for_gossip(&view, slashing, seen, claims) {
            Ok(true) => {}
            Ok(false) => return Err(Feedback::Ignore),
            Err(e) => {
                silver_log::debug!(error = %e, "attester_slashing gossip rejected");
                return Err(Feedback::reject("attester slashing invalid"));
            }
        }
        self.send_stark_proofs(slashing, state_id, producers).ok_or(Feedback::Ignore)
    }

    pub(super) fn settle_gossip_proofs(
        &mut self,
        awaiting: AwaitingProofs,
        verdict: ProofVerdict,
        producers: &mut Producers,
    ) {
        let AwaitingProofs { msg, pin, gossip, .. } = awaiting;
        let Some(data) = pin.buffer().ok().map(|(data, _)| data) else {
            return Self::local_verdict(&msg, Feedback::Ignore, producers);
        };
        let feedback = match (verdict, gossip) {
            (ProofVerdict::Unanswered, _) => Feedback::Ignore,
            (ProofVerdict::Invalid, _) => Feedback::reject("STARK proof invalid"),
            (ProofVerdict::Valid, GossipAwaitingProof::Aggregate(aggregate)) => {
                self.commit_pq_aggregate(data, aggregate)
            }
            (ProofVerdict::Valid, GossipAwaitingProof::AttesterSlashing) => {
                self.commit_pq_attester_slashing(data)
            }
        };
        match feedback {
            Feedback::Accept => {
                Self::relay_gossip(&msg, None, producers);
                self.publish_status(producers);
            }
            Feedback::Reject { reason, .. } => self.reject_gossip(&msg, data, reason, producers),
            feedback => Self::local_verdict(&msg, feedback, producers),
        }
    }

    fn commit_pq_aggregate(
        &mut self,
        signed: &[u8],
        aggregate: AggregateAwaitingProof,
    ) -> Feedback {
        let target = aggregate.target;
        let (slot, committee_index) = (target.attestation_slot, aggregate.committee_index);
        let bits = SignedAggregateAndProofPqView::agg_aggregation_bits(signed);
        let coverage = match self.unseen_aggregate_coverage(
            slot,
            target.target_epoch,
            committee_index,
            aggregate.aggregator_index,
            aggregate.data_root,
            bits,
        ) {
            Ok(coverage) => coverage,
            Err(feedback) => return feedback,
        };
        self.seen_aggregates.record(slot, committee_index, aggregate.data_root, bits);
        self.seen_aggregators.mark(target.target_epoch, aggregate.aggregator_index);

        if coverage != Coverage::ByUnion {
            self.fork_choice.record_or_defer_votes(
                target,
                &aggregate.attesters,
                self.head_validator_count(),
                self.ticker.current_slot(),
            );
        }
        if let Some(message) = aggregate.merge_message {
            self.merge_pq_aggregate(signed, slot, &aggregate.attesters, &message);
        }
        Feedback::Accept
    }

    /// The attesters are active, so the head holds their pubkeys.
    fn merge_pq_aggregate(
        &mut self,
        signed: &[u8],
        slot: Slot,
        attesters: &[u32],
        message: &[u8; 32],
    ) {
        let view = self.state.read_view(self.canonical_state_id());
        let claims = &mut self.pq_merge_claims;
        claims.clear();
        claims.extend(attesters.iter().map(|&attester| {
            claim(xmss_pubkey(view.validators.pubkey(attester as usize)), message)
        }));
        let proof = SignedAggregateAndProofPqView::proof(signed);
        let attestation = SignedAggregateAndProofPqView::aggregate(signed);
        match Aggregate::new(claims, proof, attestation) {
            Some(merged) => {
                let block_slot = slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ;
                self.pq_aggregator.add_aggregate(block_slot, merged, &self.ticker);
            }
            None => silver_log::error!(slot, "verified aggregate does not fit a merge"),
        }
    }

    fn commit_pq_attester_slashing(&mut self, slashing: &[u8]) -> Feedback {
        let validator_count = self.head_validator_count();
        let equivocators = &mut self.stf_scratch.active;
        if stf::attester_slashing_equivocators(slashing, validator_count, equivocators).is_err() {
            return Feedback::Ignore;
        }
        for &index in equivocators.iter() {
            self.fork_choice.mark_equivocating(index as usize);
            self.seen_attester_slashed.mark(index as usize);
        }
        Feedback::Accept
    }

    fn handle_pq_proposer_slashing(
        &mut self,
        slashing: &[u8; PROPOSER_SLASHING_PQ_SIZE],
    ) -> Feedback {
        let header = ProposerSlashingPqView::header_1(slashing);
        let proposer_index = BeaconBlockHeaderView::proposer_index(header) as usize;
        if self.seen_proposer_slashings.contains(proposer_index) {
            return Feedback::AlreadySeen;
        }
        let view = self.state.read_view(self.canonical_state_id());
        if proposer_index >= view.validators.count() {
            return Feedback::reject("proposer slashing index out of range");
        }
        if !view.validators.is_slashable(proposer_index, view.slot.current_epoch()) {
            return Feedback::reject("proposer not slashable");
        }
        let Some(pubkey) = view.validator_xmss_pubkey(proposer_index) else {
            return Feedback::Ignore;
        };

        let header_epoch = BeaconBlockHeaderView::slot(header) / SLOTS_PER_EPOCH;
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            view.epoch.fork_version_at(header_epoch),
            &view.imm.genesis_validators_root,
        );
        let checks = SignatureCheck::proposer_slashing(slashing, pubkey, &domain);
        let mut valid = [false; 2];
        SignatureCheck::verify_batch(checks, &mut valid);
        if valid != [true; 2] {
            return Feedback::reject("proposer slashing bad signature");
        }
        self.seen_proposer_slashings.mark(proposer_index);
        let admission =
            self.slashing_pool.insert_proposer_slashing(slashing, &view, &mut self.events_producer);
        silver_log::info!(proposer_index, ?admission, "proposer slashing pooled");
        Feedback::Accept
    }

    /// False when the ring lapped `read` before it could be handled.
    pub(super) fn handle_gossip(
        &mut self,
        read: TCacheRead,
        m: NewGossipMsg,
        mut do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) -> bool {
        if matches!(m.topic, GossipTopic::DataColumnSidecar(_)) {
            return true;
        }
        let acquired = self.reader.acquire(read);
        let Some(data) = acquired.buffer().ok().map(|(d, _)| d) else { return false };
        let pre_verified = pre_verified || m.is_api_verified();

        let feedback = match m.topic {
            _ if m.domain.format() == ForkName::Pq && m.topic != GossipTopic::BeaconBlock => {
                match self.handle_pq_gossip(&m, &acquired, data, producers) {
                    Some(feedback) => feedback,
                    None => return true,
                }
            }
            GossipTopic::BeaconBlock if self.sync_target.is_syncing() => {
                match self.parse_and_verify_block(data, pre_verified) {
                    Ok(parsed) if do_relay && parsed.relay_eligible => {
                        Self::relay_gossip(&m, Some(parsed.block_root), producers)
                    }
                    Err(err) if matches!(err.feedback(), Feedback::Reject { .. }) => producers
                        .produce(PeerEvent::P2pGossipInvalidMsg {
                            p2p_peer: m.stream_id.peer(),
                            topic: m.topic,
                            hash: m.msg_hash,
                        }),
                    _ => {}
                }
                return true;
            }
            GossipTopic::BeaconBlock => {
                let relay_once_parsed = m.validation == BroadcastValidation::Gossip;
                let mut relayed = false;
                let feedback = self.apply_block(
                    data,
                    &acquired,
                    BlockSource::Gossip,
                    pre_verified,
                    producers,
                    |block_root, p| {
                        if do_relay && relay_once_parsed {
                            Self::relay_gossip(&m, Some(block_root), p);
                            relayed = true;
                        }
                    },
                );
                if do_relay && !relayed && m.stream_id == LOCAL_GOSSIP_STREAM_ID {
                    self.relay_once_applied(&m, data, feedback, producers);
                }
                do_relay = false; // relayed on callback or once applied.
                feedback
            }
            GossipTopic::BeaconAttestation(subnet) => self.handle_attestation(data, subnet),
            GossipTopic::BeaconAggregateAndProof => self.handle_aggregate_and_proof(data),
            GossipTopic::VoluntaryExit => self.handle_voluntary_exit(data),
            GossipTopic::ProposerSlashing => self.handle_proposer_slashing(data),
            GossipTopic::AttesterSlashing => self.handle_attester_slashing(data),
            GossipTopic::BlsToExecutionChange => self.handle_bls_to_execution_change(data),
            GossipTopic::ExecutionPayload => self.handle_execution_payload_envelope(
                acquired.clone(),
                data,
                BlockSource::Gossip,
                producers,
            ),
            GossipTopic::SyncCommitteeContributionAndProof => self.handle_sync_contribution(data),
            GossipTopic::ExecutionPayloadBid => {
                self.handle_execution_payload_bid(data, m.domain.format())
            }
            GossipTopic::ProposerPreferences => {
                let local = m.stream_id == LOCAL_GOSSIP_STREAM_ID;
                self.handle_proposer_preferences(data, m.domain.format(), local)
            }
            _ => return true,
        };
        match feedback {
            Feedback::Reject { reason, .. } => self.reject_gossip(&m, data, reason, producers),
            Feedback::Accept => {
                if do_relay {
                    Self::relay_gossip(&m, None, producers);
                }
                self.publish_status(producers);
            }
            Feedback::RequestParent { .. } => self.park_block(
                feedback,
                BlockSourceMsg::Gossip(m, acquired.clone()),
                data,
                producers,
            ),
            Feedback::AwaitParentPayload { block_root, .. } => {
                if do_relay {
                    Self::relay_gossip(&m, Some(block_root), producers);
                }
                self.park_block(
                    feedback,
                    BlockSourceMsg::Gossip(m, acquired.clone()),
                    data,
                    producers,
                );
            }
            Feedback::Request(need) => {
                producers.produce(need);
                Self::local_verdict(&m, feedback, producers);
            }
            Feedback::Ignore | Feedback::AlreadySeen | Feedback::TooOld | Feedback::Future => {
                Self::local_verdict(&m, feedback, producers)
            }
            Feedback::BlockKnown(_) => Self::local_verdict(&m, feedback, producers),
            Feedback::BlockImported(_) | Feedback::AwaitData(_) | Feedback::AwaitVerify(_) => {}
        }
        true
    }

    /// A local block the parse did not relay, held by a `consensus` level or
    /// staged before it arrived, is relayed once its transition has passed; a
    /// block waiting on its columns or its STARK verdict has passed it.
    pub(super) fn relay_once_applied(
        &self,
        m: &NewGossipMsg,
        data: &[u8],
        feedback: Feedback,
        producers: &mut Producers,
    ) {
        let (Feedback::BlockImported(block_root) |
        Feedback::AwaitData(block_root) |
        Feedback::AwaitVerify(block_root)) = feedback
        else {
            return;
        };
        let Ok(layout) = self.block_layout(data) else { return };
        let slot = layout.slot(data);
        let proposer_index = layout.proposer_index(data);
        if m.validation == BroadcastValidation::ConsensusAndEquivocation &&
            self.equivocates(slot, proposer_index, &block_root)
        {
            let result = Err(LocalGossipFailure::ConflictingProposal);
            let hash = m.msg_hash;
            producers.produce(BeaconStateEvent::LocalGossipVerdict {
                hash,
                result,
                block_root: None,
            });
            return;
        }
        Self::relay_gossip(m, Some(block_root), producers);
    }

    /// Another block in fork choice from the same proposer for the same slot.
    pub(super) fn equivocates(&self, slot: Slot, proposer_index: u64, block_root: &B256) -> bool {
        if self.held.holds_other_proposal(slot, proposer_index, block_root) {
            return true;
        }
        self.fork_choice.nodes.iter().any(|node| {
            node.slot == slot &&
                node.block_root != *block_root &&
                self.state
                    .read_view(node.state_id)
                    .slot
                    .state()
                    .latest_block_header
                    .proposer_index ==
                    proposer_index
        })
    }

    fn relay_gossip(m: &NewGossipMsg, block_root: Option<B256>, producers: &mut Producers) {
        if let Some(protobuf) = m.protobuf {
            producers.produce(PeerEvent::SendGossip {
                originator_stream_id: m.stream_id,
                topic: m.topic,
                domain: m.domain,
                ssz_cache: m.ssz_cache,
                msg_hash: m.msg_hash,
                recv_ts: m.recv_ts,
                protobuf,
                ssz: m.ssz,
            });
        }
        if m.stream_id == LOCAL_GOSSIP_STREAM_ID {
            let hash = m.msg_hash;
            producers.produce(BeaconStateEvent::LocalGossipVerdict {
                hash,
                result: Ok(()),
                block_root,
            });
        }
    }

    fn reject_gossip(
        &self,
        m: &NewGossipMsg,
        data: &[u8],
        reason: &'static str,
        producers: &mut Producers,
    ) {
        if m.stream_id == LOCAL_GOSSIP_STREAM_ID {
            return Self::local_verdict(m, Feedback::reject(reason), producers);
        }
        silver_log::warn!(
            p2p_peer = m.stream_id.peer(),
            topic = ?m.topic,
            reason,
            message = %GossipFields { topic: m.topic, format: m.domain.format(), data },
            head_slot = self.head_state_slot(),
            wall_slot = self.ticker.current_slot(),
            time_into_slot = ?self.ticker.slot_time_elapsed(),
            justified_epoch = self.fork_choice.justified_checkpoint.epoch,
            finalized_epoch = self.fork_choice.finalized_checkpoint().epoch,
            "gossip rejected"
        );
        producers.produce(PeerEvent::P2pGossipInvalidMsg {
            p2p_peer: m.stream_id.peer(),
            topic: m.topic,
            hash: m.msg_hash,
        });
    }

    /// Network gossip ignores are deliberately silent, except a slot window
    /// miss: it costs the sender, as nothing else bounds such messages. A
    /// local API request needs a terminal verdict so Control can complete it.
    pub(super) fn local_verdict(m: &NewGossipMsg, feedback: Feedback, producers: &mut Producers) {
        if m.stream_id != LOCAL_GOSSIP_STREAM_ID {
            if matches!(feedback, Feedback::TooOld | Feedback::Future) {
                producers.produce(PeerEvent::P2pGossipOutOfRange {
                    p2p_peer: m.stream_id.peer(),
                    topic: m.topic,
                });
            }
            return;
        }
        let result = match feedback {
            Feedback::Accept => Ok(()),
            Feedback::Reject { .. } => Err(LocalGossipFailure::Invalid),
            // Already on the network is published, as fallback validator
            // clients that submit to several nodes rely on.
            Feedback::AlreadySeen | Feedback::BlockKnown(_) => Ok(()),
            Feedback::TooOld => Err(LocalGossipFailure::TooOld),
            Feedback::Future => Err(LocalGossipFailure::Future),
            _ => Err(LocalGossipFailure::Unverifiable),
        };
        let block_root = match feedback {
            Feedback::BlockKnown(block_root) => Some(block_root),
            _ => None,
        };
        producers.produce(BeaconStateEvent::LocalGossipVerdict {
            hash: m.msg_hash,
            result,
            block_root,
        });
    }
}

pub(super) fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = merkle::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

pub(super) fn is_sync_aggregator(selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;
    let modulo = (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
    let h = merkle::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

/// EF `gossip_validation` entry points for the batched vote topics: one
/// message at a time, verified alone and committed, as the batch path does for
/// each survivor.
#[cfg(feature = "ef_tests")]
impl BeaconStateTile {
    pub fn ef_gossip_proposer_preferences(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_proposer_preferences(ssz, ForkName::Gloas, false)
    }

    pub fn ef_gossip_execution_payload_bid(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_execution_payload_bid(ssz, ForkName::Gloas)
    }

    pub fn ef_gossip_sync_committee_message(&mut self, ssz: &[u8], subnet: u64) -> Feedback {
        let prepared = match self.prepare_sync_message(ssz, subnet) {
            Ok(p) => PreparedVote::SyncMessage(p),
            Err(feedback) => return feedback,
        };
        self.ef_verify_and_commit(prepared)
    }

    pub fn ef_gossip_payload_attestation(&mut self, ssz: &[u8]) -> Feedback {
        let prepared = match self.prepare_ptc(ssz) {
            Ok(p) => PreparedVote::Ptc(p),
            Err(feedback) => return feedback,
        };
        self.ef_verify_and_commit(prepared)
    }

    fn ef_verify_and_commit(&mut self, prepared: PreparedVote) -> Feedback {
        let Some(sig) = CheckedSignature::parse(prepared.signature()) else {
            return Feedback::reject(prepared.signature_malformed());
        };
        let (pk, root) = prepared.pubkey_and_root();
        if !bls::verify_one_checked(pk, &sig, root) {
            return Feedback::reject("vote bad signature");
        }
        let feedback = self.commit_vote(&prepared, &sig);
        self.recompute_head(|_| {});
        feedback
    }
}

/// A rejected message's identifying fields, decoded only when logged.
struct GossipFields<'a> {
    format: silver_common::ForkName,
    topic: GossipTopic,
    data: &'a [u8],
}

impl Display for GossipFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.data;
        if self.format == silver_common::ForkName::Pq {
            return write!(f, "PQ len={}", data.len());
        }
        match self.topic {
            GossipTopic::BeaconAttestation(_) if data.len() == SINGLE_ATT_SIZE => {
                let buf = data[..SINGLE_ATT_SIZE].try_into().unwrap();
                let d = SingleAttestationView::data(buf);
                write!(
                    f,
                    "slot={} committee={} attester={} index={} block_root={} source_epoch={} \
                     target={}/{}",
                    d.slot(),
                    SingleAttestationView::committee_index(buf),
                    SingleAttestationView::attester_index(buf),
                    d.index(),
                    hex32(d.beacon_block_root()),
                    d.source_epoch(),
                    d.target_epoch(),
                    hex32(d.target_root()),
                )
            }
            GossipTopic::BeaconAggregateAndProof => match ParsedAggregateAndProof::try_from(data) {
                Some(p) => write!(
                    f,
                    "slot={} aggregator={} committee_bits={:#x} index={} block_root={} \
                     source_epoch={} target={}/{}",
                    p.agg_slot,
                    p.aggregator_index,
                    p.committee_bits,
                    p.agg_data_index,
                    hex32(p.agg_data.beacon_block_root()),
                    p.agg_data.source_epoch(),
                    p.agg_data.target_epoch(),
                    hex32(p.agg_data.target_root()),
                ),
                None => write!(f, "len={}", data.len()),
            },
            GossipTopic::SyncCommittee(_) if data.len() == SYNC_COMMITTEE_MSG_SIZE => {
                let buf = data[..SYNC_COMMITTEE_MSG_SIZE].try_into().unwrap();
                write!(
                    f,
                    "slot={} validator={} block_root={}",
                    SyncCommitteeView::slot(buf),
                    SyncCommitteeView::validator_index(buf),
                    hex32(SyncCommitteeView::beacon_block_root(buf)),
                )
            }
            GossipTopic::PayloadAttestationMessage
                if data.len() == PAYLOAD_ATTESTATION_MESSAGE_SIZE =>
            {
                let buf = data[..PAYLOAD_ATTESTATION_MESSAGE_SIZE].try_into().unwrap();
                let d = PayloadAttestationMessageView::data(buf);
                write!(
                    f,
                    "slot={} validator={} block_root={} present={} blob_data_available={}",
                    PayloadAttestationDataView::slot(d),
                    PayloadAttestationMessageView::validator_index(buf),
                    hex32(PayloadAttestationDataView::beacon_block_root(d)),
                    PayloadAttestationDataView::payload_present(d),
                    PayloadAttestationDataView::blob_data_available(d),
                )
            }
            _ => write!(f, "len={}", data.len()),
        }
    }
}

/// The key a rejected envelope is remembered by: the signature itself is too
/// large to hold under XMSS.
fn envelope_signature_digest(ssz: &[u8]) -> Option<B256> {
    [SignedBlockLayout::Gloas, SignedBlockLayout::Pq]
        .into_iter()
        .find_map(|layout| layout.envelope_signature(ssz))
        .map(merkle::sha256)
}
