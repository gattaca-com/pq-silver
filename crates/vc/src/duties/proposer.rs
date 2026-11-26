use silver_beacon_state_data::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER,
    bls::{DOMAIN_BEACON_PROPOSER, DOMAIN_PROPOSER_PREFERENCES},
};
use silver_chain_spec::SpecConfig;
use silver_common::{
    ForkName, SLOTS_PER_EPOCH,
    ssz_hash::{compute_domain, compute_signing_root, hash_beacon_block_header_bytes},
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        BEACON_BLOCK_HEADER_SIZE, BeaconBlockBodyGloasView, BeaconBlockHeaderView,
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, PROPOSER_PREFERENCES_SIZE,
        ProposerPreferencesView, XMSSSignature,
    },
    xmss::SlotDuty,
};

use crate::{
    beacon_link::{BeaconRequests, ChainInfo, ProducedBlock, RequestId},
    block_contents::GloasBlockContents,
    config::ProposalConfig,
    duties::{
        round::{Data, DataRound, Stage},
        schedule::{DutySchedule, Fetch, ProposerDuty, Signing},
        validators::Validators,
    },
    signing::SignPurpose,
};

const BEACON_BLOCK_FIXED: usize = 8 + 8 + 32 + 32 + 4;
const HEADER_BEFORE_BODY_ROOT: usize = BEACON_BLOCK_HEADER_SIZE - 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Produced {
    header: [u8; BEACON_BLOCK_HEADER_SIZE],
    payload_included: bool,
}

impl Produced {
    fn of(block: &ProducedBlock<'_>) -> Result<Self, &'static str> {
        let beacon_block = match block.payload_included {
            false => block.ssz,
            true => {
                let contents = GloasBlockContents::parse(block.ssz).ok_or("contents misframed")?;
                let envelope = contents.envelope;
                let envelope_ok = ExecutionPayloadEnvelopeView::check_size(envelope) &&
                    ExecutionPayloadView::check_canonical_gloas(
                        ExecutionPayloadEnvelopeView::payload(envelope),
                    ) &&
                    ExecutionRequestsView::check_canonical(
                        ExecutionPayloadEnvelopeView::execution_requests(envelope),
                    );
                if !envelope_ok {
                    return Err("envelope malformed");
                }
                contents.block
            }
        };
        let fixed = beacon_block.get(..BEACON_BLOCK_FIXED).ok_or("block too short")?;
        let body_at = fixed[HEADER_BEFORE_BODY_ROOT..].try_into().map(u32::from_le_bytes);
        if body_at.expect("4 bytes") as usize != BEACON_BLOCK_FIXED {
            return Err("block body offset is not canonical");
        }
        let body = &beacon_block[BEACON_BLOCK_FIXED..];
        if !BeaconBlockBodyGloasView::check_canonical(body) {
            return Err("block body malformed");
        }
        let body_root = BeaconBlockBodyGloasView::hash_tree_root(body);
        let mut header = [0; BEACON_BLOCK_HEADER_SIZE];
        header[..HEADER_BEFORE_BODY_ROOT].copy_from_slice(&fixed[..HEADER_BEFORE_BODY_ROOT]);
        header[HEADER_BEFORE_BODY_ROOT..].copy_from_slice(&body_root);
        Ok(Self { header, payload_included: block.payload_included })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Envelope {
    None,
    Signing(RequestId),
    Signed(Box<XMSSSignature>),
    Publishing(RequestId),
}

pub struct Proposer {
    config: ProposalConfig,
    pub block_round: DataRound<Produced, ProposerDuty>,
    block: Vec<u8>,
    block_accepted: bool,
    envelope: Envelope,
    preparation: Fetch,
}

impl Proposer {
    pub fn new(config: ProposalConfig) -> Self {
        Self {
            config,
            block_round: DataRound::new("block"),
            block: Vec::new(),
            block_accepted: false,
            envelope: Envelope::None,
            preparation: Fetch::Due { from_slot: 0 },
        }
    }

    pub fn prepare_again(&mut self) {
        self.preparation = Fetch::Due { from_slot: 0 };
    }

    pub fn epoch_started(&mut self) {
        self.prepare_again();
    }

    pub fn slot_started(&mut self, slot: u64) {
        self.block_round.due(slot);
        self.block_accepted = false;
        self.envelope = Envelope::None;
    }

    pub fn on_block(&mut self, id: RequestId, block: &ProducedBlock<'_>) {
        if self.block_round.data != Data::Awaiting(id) {
            return;
        }
        let produced = Produced::of(block);
        if produced.is_ok() {
            self.block.clear();
            self.block.extend_from_slice(block.ssz);
        }
        self.block_round.on_data(id, produced);
    }

    pub fn on_block_accepted(&mut self, id: RequestId) {
        self.block_round.round.on_accepted(id);
        self.block_accepted = self.block_round.round.stage() == Stage::Done;
    }

    pub fn on_envelope_signed(&mut self, id: RequestId, signature: Option<Box<XMSSSignature>>) {
        if self.envelope != Envelope::Signing(id) {
            return;
        }
        self.envelope = match signature {
            Some(signature) => Envelope::Signed(signature),
            None => {
                silver_log::warn!(slot = self.block_round.round.slot(), "envelope not signed");
                Envelope::None
            }
        };
    }

    pub fn on_envelope_answered(&mut self, id: RequestId, accepted: bool) {
        if self.envelope != Envelope::Publishing(id) {
            return;
        }
        let slot = self.block_round.round.slot();
        match accepted {
            true => silver_log::info!(slot, "envelope published"),
            false => silver_log::warn!(slot, "envelope not published"),
        }
        self.envelope = Envelope::None;
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
        &self,
        slot: u64,
        spec: &SpecConfig,
        schedule: &mut DutySchedule,
        validators: &Validators,
        chain: &ChainInfo,
        requests: &mut BeaconRequests,
    ) {
        let gvr = chain.genesis_validators_root;
        schedule.ask_preferences(|duty, dependent_root| {
            if duty.slot <= slot || !spec.is_gloas_at_slot(duty.slot) {
                return None;
            }
            let Some(leaf) = SlotDuty::ProposerPreferences.leaf(duty.slot) else {
                silver_log::error!(slot = duty.slot, "no XMSS leaf for proposer preferences");
                return None;
            };
            let message = self.preferences(duty, dependent_root);
            let version = spec.fork_version_at(duty.slot / SLOTS_PER_EPOCH);
            let domain = compute_domain(DOMAIN_PROPOSER_PREFERENCES, version, &gvr);
            let root =
                compute_signing_root(&ProposerPreferencesView::hash_tree_root(&message), &domain);
            let pubkey = validators.pubkey(duty.key);
            Some(requests.sign(pubkey, SignPurpose::ProposerPreferences, leaf, &root))
        });
        schedule.publish_preferences(|duty, root| self.preferences(duty, root), requests);
    }

    fn preferences(
        &self,
        duty: &ProposerDuty,
        dependent_root: &[u8; 32],
    ) -> [u8; PROPOSER_PREFERENCES_SIZE] {
        let mut message = [0; PROPOSER_PREFERENCES_SIZE];
        message[0..32].copy_from_slice(dependent_root);
        message[32..40].copy_from_slice(&duty.slot.to_le_bytes());
        message[40..48].copy_from_slice(&duty.validator_index.to_le_bytes());
        message[48..68].copy_from_slice(&self.config.fee_recipient);
        message[68..76].copy_from_slice(&self.config.gas_limit.to_le_bytes());
        message
    }

    pub fn propose(
        &mut self,
        slot: u64,
        spec: &SpecConfig,
        schedule: &DutySchedule,
        validators: &Validators,
        chain: &ChainInfo,
        requests: &mut BeaconRequests,
    ) {
        let round = &mut self.block_round;
        if round.round.slot() != slot {
            return;
        }
        let fork = spec.fork_at_slot(slot);
        match (round.round.stage(), round.data) {
            (Stage::Due, Data::Unasked) => {
                let Some(duty) = schedule.proposer_at(slot) else { return };
                if fork < ForkName::Gloas {
                    silver_log::warn!(slot, "proposal missed: only Gloas blocks are produced");
                    return round.round.abandon();
                }
                match &duty.randao {
                    Signing::Signed(randao) => {
                        let graffiti = &self.config.graffiti;
                        let id = requests.produce_block(fork, slot, randao, graffiti);
                        round.data = Data::Awaiting(id);
                        round.round.working();
                    }
                    Signing::Done => {
                        silver_log::warn!(slot, "proposal missed: RANDAO reveal refused");
                        round.round.abandon();
                    }
                    Signing::Unasked | Signing::Asked(_) => {}
                }
            }
            (Stage::Working, Data::Ready(produced)) => {
                let Some(duty) = schedule.proposer_at(slot) else {
                    silver_log::warn!(slot, "proposal missed: duty gone before signing");
                    return round.round.abandon();
                };
                let header = &produced.header;
                if BeaconBlockHeaderView::slot(header) != slot ||
                    BeaconBlockHeaderView::proposer_index(header) != duty.validator_index
                {
                    silver_log::warn!(slot, "proposal missed: block for another slot or proposer");
                    return round.round.abandon();
                }
                let block_root = hash_beacon_block_header_bytes(header);
                let envelope = produced.payload_included.then(|| {
                    GloasBlockContents::parse(&self.block).expect("checked when served").envelope
                });
                if let Some(envelope) = envelope &&
                    (ExecutionPayloadEnvelopeView::beacon_block_root(envelope) != &block_root ||
                        ExecutionPayloadEnvelopeView::builder_index(envelope) !=
                            BUILDER_INDEX_SELF_BUILD)
                {
                    silver_log::warn!(slot, "proposal missed: envelope for another block");
                    return round.round.abandon();
                }

                let (Some(block_leaf), Some(envelope_leaf)) = (
                    SlotDuty::BeaconProposer.leaf(slot),
                    SlotDuty::ExecutionPayloadEnvelope.leaf(slot),
                ) else {
                    silver_log::error!(slot, "proposal missed: no XMSS leaf for the slot");
                    return round.round.abandon();
                };

                let gvr = chain.genesis_validators_root;
                let version = spec.fork_version_at(slot / SLOTS_PER_EPOCH);
                let pubkey = validators.pubkey(duty.key);
                let domain = compute_domain(DOMAIN_BEACON_PROPOSER, version, &gvr);
                let signing_root = compute_signing_root(&block_root, &domain);
                let id = requests.sign(pubkey, SignPurpose::Block, block_leaf, &signing_root);
                round.round.sign(id, duty.clone());
                round.data = Data::Signing(produced);

                if let Some(envelope) = envelope {
                    let domain = compute_domain(DOMAIN_BEACON_BUILDER, version, &gvr);
                    let root = ExecutionPayloadEnvelopeView::hash_tree_root(envelope);
                    let signing_root = compute_signing_root(&root, &domain);
                    let id =
                        requests.sign(pubkey, SignPurpose::Envelope, envelope_leaf, &signing_root);
                    self.envelope = Envelope::Signing(id);
                }
            }
            (Stage::Working, Data::Signing(produced)) if round.round.all_signatures_answered() => {
                let block = &self.block;
                round.round.publish(|round| {
                    let (_, signature) = round.signed().next().expect("published only if signed");
                    requests.publish_block(fork, produced.payload_included, block, signature)
                });
            }
            _ => {}
        }
        if self.block_accepted &&
            let Envelope::Signed(signature) = &self.envelope
        {
            self.envelope = Envelope::Publishing(requests.publish_envelope(&self.block, signature));
        }
    }
}
