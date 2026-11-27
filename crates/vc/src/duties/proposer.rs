use silver_beacon_state_data::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER,
    bls::{DOMAIN_BEACON_PROPOSER, DOMAIN_PROPOSER_PREFERENCES},
};
use silver_common::{
    ssz_hash::hash_beacon_block_header_bytes,
    ssz_hash_pq::ExecutionRequestsPqView,
    ssz_view::{
        BEACON_BLOCK_HEADER_SIZE, BeaconBlockBodyPqView, BeaconBlockHeaderView,
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, PROPOSER_PREFERENCES_SIZE,
        ProposerPreferencesView, XMSSSignature,
    },
    vc_spine::SignPurpose,
    xmss::SlotDuty,
};

use crate::{
    beacon_link::{BeaconRequests, ProducedBlock, RequestId},
    block_contents::BlockContents,
    config::ProposalConfig,
    duties::{
        schedule::{DutySchedule, Fetch, Reveal},
        validators::Validators,
    },
    signing::{SignRequests, SigningDomains},
};

const BEACON_BLOCK_FIXED: usize = 8 + 8 + 32 + 32 + 4;
const HEADER_BEFORE_BODY_ROOT: usize = BEACON_BLOCK_HEADER_SIZE - 32;

/// The last block produced, with its envelope when the payload is included.
#[derive(Default)]
struct Produced {
    ssz: Vec<u8>,
    payload_included: bool,
}

impl Produced {
    fn replace(&mut self, block: &ProducedBlock<'_>) {
        self.ssz.clear();
        self.ssz.extend_from_slice(block.ssz);
        self.payload_included = block.payload_included;
    }

    fn contents(&self) -> Option<Result<BlockContents<'_>, &'static str>> {
        self.payload_included.then(|| BlockContents::parse(&self.ssz).ok_or("contents misframed"))
    }

    fn block(&self) -> &[u8] {
        match self.contents() {
            Some(contents) => contents.expect("checked when produced").block,
            None => &self.ssz,
        }
    }

    /// The block's header, once the block and any envelope are well-formed.
    fn header(&self) -> Result<[u8; BEACON_BLOCK_HEADER_SIZE], &'static str> {
        if let Some(contents) = self.contents() {
            let envelope = contents?.envelope;
            let envelope_ok = ExecutionPayloadEnvelopeView::check_size(envelope) &&
                ExecutionPayloadView::check_canonical_gloas(
                    ExecutionPayloadEnvelopeView::payload(envelope),
                ) &&
                ExecutionRequestsPqView::check_canonical(
                    ExecutionPayloadEnvelopeView::execution_requests(envelope),
                );
            if !envelope_ok {
                return Err("envelope malformed");
            }
        }
        let block = self.block();
        let fixed = block.get(..BEACON_BLOCK_FIXED).ok_or("block too short")?;
        let body_at = fixed[HEADER_BEFORE_BODY_ROOT..].try_into().map(u32::from_le_bytes);
        if body_at.expect("4 bytes") as usize != BEACON_BLOCK_FIXED {
            return Err("block body offset is not canonical");
        }
        let body = &block[BEACON_BLOCK_FIXED..];
        if !BeaconBlockBodyPqView::check_canonical(body) {
            return Err("block body malformed");
        }
        let mut header = [0; BEACON_BLOCK_HEADER_SIZE];
        header[..HEADER_BEFORE_BODY_ROOT].copy_from_slice(&fixed[..HEADER_BEFORE_BODY_ROOT]);
        header[HEADER_BEFORE_BODY_ROOT..]
            .copy_from_slice(&BeaconBlockBodyPqView::hash_tree_root(body));
        Ok(header)
    }
}

/// The slot's proposal. The envelope is signed once its block is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proposal {
    Idle,
    /// Produced once the slot's duty and its RANDAO reveal are known.
    Due,
    Producing(RequestId),
    SigningBlock {
        key: usize,
    },
    PublishingBlock {
        id: RequestId,
        key: usize,
    },
    SigningEnvelope,
    PublishingEnvelope(RequestId),
}

pub struct Proposer {
    config: ProposalConfig,
    slot: u64,
    proposal: Proposal,
    produced: Produced,
    preparation: Fetch,
    /// Preferences are signed once per proposal slot, in slot order: the slot
    /// fixes their XMSS leaf.
    preferences_through: u64,
}

impl Proposer {
    pub fn new(config: ProposalConfig) -> Self {
        Self {
            config,
            slot: 0,
            proposal: Proposal::Idle,
            produced: Produced::default(),
            preparation: Fetch::Due { from_slot: 0 },
            preferences_through: 0,
        }
    }

    pub fn prepare_again(&mut self) {
        self.preparation = Fetch::Due { from_slot: 0 };
    }

    pub fn slot_started(&mut self, slot: u64) {
        self.slot = slot;
        self.proposal = Proposal::Due;
    }

    pub fn on_prepared(&mut self, id: RequestId) {
        if self.preparation == Fetch::InFlight(id) {
            self.preparation = Fetch::Done;
        }
    }

    pub fn on_prepare_failed(&mut self, id: RequestId, slot: u64) {
        if self.preparation == Fetch::InFlight(id) {
            self.preparation = Fetch::Due { from_slot: slot + 1 };
        }
    }

    pub fn prepare(&mut self, slot: u64, validators: &Validators, requests: &mut BeaconRequests) {
        if let Fetch::Due { from_slot } = self.preparation &&
            from_slot <= slot &&
            validators.any_index_known()
        {
            let id =
                requests.prepare_proposers(&self.config.fee_recipient, validators.known_indices());
            self.preparation = Fetch::InFlight(id);
        }
    }

    pub fn send_preferences(
        &mut self,
        slot: u64,
        schedule: &DutySchedule,
        validators: &Validators,
        domains: &SigningDomains,
        signs: &mut SignRequests,
    ) {
        let after = self.preferences_through.max(slot);
        for (duty, dependent_root) in schedule.proposals().filter(|(duty, _)| duty.slot > after) {
            self.preferences_through = self.preferences_through.max(duty.slot);
            let Some(leaf) = SlotDuty::ProposerPreferences.leaf(duty.slot) else {
                silver_log::error!(slot = duty.slot, "no XMSS leaf for proposer preferences");
                continue;
            };
            let message = self.preferences(duty.slot, duty.validator_index, dependent_root);
            let root = ProposerPreferencesView::hash_tree_root(&message);
            let signing_root = domains.signing_root(DOMAIN_PROPOSER_PREFERENCES, duty.slot, &root);
            let purpose = SignPurpose::ProposerPreferences {
                validator_index: duty.validator_index,
                dependent_root: *dependent_root,
            };
            signs.sign(duty.slot, purpose, validators.pubkey(duty.key), leaf, signing_root);
        }
    }

    pub fn publish_preferences(
        &self,
        slot: u64,
        validator_index: u64,
        dependent_root: &[u8; 32],
        signature: &XMSSSignature,
        requests: &mut BeaconRequests,
    ) {
        let message = self.preferences(slot, validator_index, dependent_root);
        requests.publish_proposer_preferences(&message, signature);
    }

    fn preferences(
        &self,
        slot: u64,
        validator_index: u64,
        dependent_root: &[u8; 32],
    ) -> [u8; PROPOSER_PREFERENCES_SIZE] {
        let mut message = [0; PROPOSER_PREFERENCES_SIZE];
        message[0..32].copy_from_slice(dependent_root);
        message[32..40].copy_from_slice(&slot.to_le_bytes());
        message[40..48].copy_from_slice(&validator_index.to_le_bytes());
        message[48..68].copy_from_slice(&self.config.fee_recipient);
        message[68..76].copy_from_slice(&self.config.gas_limit.to_le_bytes());
        message
    }

    pub fn propose(&mut self, slot: u64, schedule: &DutySchedule, requests: &mut BeaconRequests) {
        if self.slot != slot || self.proposal != Proposal::Due {
            return;
        }
        let Some(duty) = schedule.proposer_at(slot) else { return };
        match &duty.randao {
            Reveal::Proved(randao) => {
                let id = requests.produce_block(slot, randao, &self.config.graffiti);
                self.proposal = Proposal::Producing(id);
            }
            Reveal::Refused => self.missed("RANDAO reveal refused"),
            Reveal::Unasked | Reveal::Asked => {}
        }
    }

    pub fn on_block(
        &mut self,
        id: RequestId,
        block: &ProducedBlock<'_>,
        schedule: &DutySchedule,
        validators: &Validators,
        domains: &SigningDomains,
        signs: &mut SignRequests,
    ) {
        if self.proposal != Proposal::Producing(id) {
            return;
        }
        self.produced.replace(block);
        match self.sign_block(schedule, validators, domains, signs) {
            Ok(key) => self.proposal = Proposal::SigningBlock { key },
            Err(reason) => self.missed(reason),
        }
    }

    /// Returns the proposer's key.
    fn sign_block(
        &self,
        schedule: &DutySchedule,
        validators: &Validators,
        domains: &SigningDomains,
        signs: &mut SignRequests,
    ) -> Result<usize, &'static str> {
        let slot = self.slot;
        let duty = schedule.proposer_at(slot).ok_or("duty gone before signing")?;
        let header = self.produced.header()?;
        if BeaconBlockHeaderView::slot(&header) != slot ||
            BeaconBlockHeaderView::proposer_index(&header) != duty.validator_index
        {
            return Err("block for another slot or proposer");
        }
        let block_root = hash_beacon_block_header_bytes(&header);
        if let Some(contents) = self.produced.contents() {
            let envelope = contents?.envelope;
            if ExecutionPayloadEnvelopeView::beacon_block_root(envelope) != &block_root ||
                ExecutionPayloadEnvelopeView::builder_index(envelope) != BUILDER_INDEX_SELF_BUILD
            {
                return Err("envelope for another block");
            }
        }
        let leaf = SlotDuty::BeaconProposer.leaf(slot).ok_or("no XMSS leaf for the slot")?;
        let signing_root = domains.signing_root(DOMAIN_BEACON_PROPOSER, slot, &block_root);
        signs.sign(slot, SignPurpose::Block, validators.pubkey(duty.key), leaf, signing_root);
        Ok(duty.key)
    }

    pub fn on_produce_failed(&mut self, id: RequestId) {
        if self.proposal == Proposal::Producing(id) {
            self.missed("no block produced");
        }
    }

    pub fn on_block_signed(
        &mut self,
        slot: u64,
        signature: Option<&XMSSSignature>,
        requests: &mut BeaconRequests,
    ) {
        let Proposal::SigningBlock { key } = self.proposal else { return };
        if self.slot != slot {
            return;
        }
        match signature {
            Some(signature) => {
                let id = requests.publish_block(self.produced.block(), signature);
                self.proposal = Proposal::PublishingBlock { id, key };
            }
            None => self.missed("block not signed"),
        }
    }

    pub fn on_block_answered(
        &mut self,
        id: RequestId,
        accepted: bool,
        validators: &Validators,
        domains: &SigningDomains,
        signs: &mut SignRequests,
    ) {
        let Proposal::PublishingBlock { id: sent, key } = self.proposal else { return };
        if sent != id {
            return;
        }
        if !accepted {
            return self.missed("block not published");
        }
        silver_log::info!(slot = self.slot, "block published");
        let signing = self.sign_envelope(key, validators, domains, signs);
        self.proposal = if signing { Proposal::SigningEnvelope } else { Proposal::Idle };
    }

    /// False when the block came without its envelope, or it cannot be signed.
    fn sign_envelope(
        &self,
        key: usize,
        validators: &Validators,
        domains: &SigningDomains,
        signs: &mut SignRequests,
    ) -> bool {
        let Some(contents) = self.produced.contents() else { return false };
        let envelope = contents.expect("checked when produced").envelope;
        let Some(leaf) = SlotDuty::ExecutionPayloadEnvelope.leaf(self.slot) else {
            silver_log::error!(slot = self.slot, "no XMSS leaf for the envelope");
            return false;
        };
        let root = ExecutionPayloadEnvelopeView::hash_tree_root_pq(envelope);
        let signing_root = domains.signing_root(DOMAIN_BEACON_BUILDER, self.slot, &root);
        signs.sign(self.slot, SignPurpose::Envelope, validators.pubkey(key), leaf, signing_root);
        true
    }

    pub fn on_envelope_signed(
        &mut self,
        slot: u64,
        signature: Option<&XMSSSignature>,
        requests: &mut BeaconRequests,
    ) {
        if self.slot != slot || self.proposal != Proposal::SigningEnvelope {
            return;
        }
        let Some(signature) = signature else {
            silver_log::warn!(slot, "envelope not signed");
            self.proposal = Proposal::Idle;
            return;
        };
        let contents = self.produced.contents().expect("signed with its envelope");
        let id = requests.publish_envelope(&contents.expect("checked when produced"), signature);
        self.proposal = Proposal::PublishingEnvelope(id);
    }

    pub fn on_envelope_answered(&mut self, id: RequestId, accepted: bool) {
        if self.proposal != Proposal::PublishingEnvelope(id) {
            return;
        }
        match accepted {
            true => silver_log::info!(slot = self.slot, "envelope published"),
            false => silver_log::warn!(slot = self.slot, "envelope not published"),
        }
        self.proposal = Proposal::Idle;
    }

    fn missed(&mut self, reason: &'static str) {
        silver_log::warn!(slot = self.slot, reason, "proposal missed");
        self.proposal = Proposal::Idle;
    }
}
