mod aggregations;
mod proposer;
mod round;
mod schedule;
mod validators;

use silver_beacon_state_data::bls::{
    DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
};
use silver_chain_spec::SpecConfig;
use silver_common::{
    SLOTS_PER_EPOCH,
    merkle::uint64_chunk,
    ssz_hash::{compute_domain, compute_signing_root, hash_attestation_data},
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationDataView, PAYLOAD_ATTESTATION_DATA_SIZE,
        PayloadAttestationDataView,
    },
};

use self::{
    aggregations::Aggregations,
    proposer::Proposer,
    round::{Data, DataRound, Stage},
    schedule::{AttesterDuty, DutySchedule, PtcDuty},
    validators::Validators,
};
use crate::{
    beacon_link::{
        BeaconEvent, BeaconRequest, BeaconRequests, ChainInfo, ForkInfo, IndexedSignature,
        RequestId, SignBody, SignPurpose, SignedAttestation, SignerKeys,
    },
    clock::{DutyClock, DutyPhase, Tick},
    config::Config,
};

/// Bounds the key listing; it is parsed once, at startup.
const MAX_SIGNER_KEYS: usize = 1 << 20;

pub struct Duties {
    spec: SpecConfig,
    clock: Option<DutyClock>,
    validators: Validators,
    schedule: DutySchedule,
    attestations: DataRound<[u8; ATTESTATION_DATA_SIZE], AttesterDuty>,
    aggregations: Aggregations,
    payload_attestations: DataRound<[u8; PAYLOAD_ATTESTATION_DATA_SIZE], PtcDuty>,
    proposer: Option<Proposer>,
}

impl Duties {
    pub fn new(config: &Config) -> Self {
        Self {
            spec: config.spec.clone(),
            clock: None,
            validators: Validators::new(Vec::new()),
            schedule: DutySchedule::new(config.proposals.is_some(), config.spec.gloas_fork_epoch),
            attestations: DataRound::new("attestations"),
            aggregations: Aggregations::new("aggregates"),
            payload_attestations: DataRound::new("payload attestations"),
            proposer: config.proposals.map(Proposer::new),
        }
    }

    pub fn on_beacon_event(&mut self, event: BeaconEvent<'_>) {
        let slot = self.clock.as_ref().map_or(0, DutyClock::current_slot);
        match event {
            BeaconEvent::ValidatorIndices { id, validators } => {
                if self.validators.on_indices(id, &validators) {
                    self.indices_learned();
                }
            }
            BeaconEvent::AttesterDuties { id, duties } => {
                self.schedule.on_duties(id, &duties, &self.validators, slot)
            }
            BeaconEvent::AttestationData { id, data } => {
                self.attestations.on_data(id, data.to_ssz())
            }
            BeaconEvent::AggregateAttestation { id, aggregate } => {
                self.aggregations.on_aggregate(id, &aggregate)
            }
            BeaconEvent::ProposerDuties { id, duties } => {
                self.schedule.on_proposer_duties(id, &duties, &self.validators, slot)
            }
            BeaconEvent::ProducedBlock { id, block } => {
                if let Some(proposer) = &mut self.proposer {
                    proposer.on_block(id, &block);
                }
            }
            BeaconEvent::PtcDuties { id, duties } => {
                self.schedule.on_ptc_duties(id, &duties, &self.validators, slot)
            }
            BeaconEvent::PayloadAttestationData { id, data } => {
                self.payload_attestations.on_data(id, data.to_ssz())
            }
            BeaconEvent::Signed { id, purpose, signature } => match purpose {
                SignPurpose::Attestation => self.attestations.round.on_signed(id, signature),
                SignPurpose::SelectionProof => self.schedule.on_selection(id, signature),
                SignPurpose::Aggregate => self.aggregations.round.on_signed(id, signature),
                SignPurpose::Randao => self.schedule.on_randao(id, Some(signature)),
                SignPurpose::PayloadAttestation => {
                    self.payload_attestations.round.on_signed(id, signature)
                }
                SignPurpose::ProposerPreferences => {
                    self.schedule.on_preferences(id, Some(signature))
                }
                SignPurpose::Block | SignPurpose::Envelope => {
                    self.on_proposer_signed(id, purpose, Some(signature))
                }
            },
            BeaconEvent::Accepted { id, request } => match request {
                BeaconRequest::PublishAttestations(_) => self.attestations.round.on_accepted(id),
                BeaconRequest::CommitteeSubscriptions => self.schedule.on_subscribed(id),
                BeaconRequest::PublishAggregates(_) => self.aggregations.round.on_accepted(id),
                BeaconRequest::PublishPayloadAttestations => {
                    self.payload_attestations.round.on_accepted(id)
                }
                BeaconRequest::PrepareProposers |
                BeaconRequest::PublishBlock(_) |
                BeaconRequest::PublishEnvelope => self.on_proposer_accepted(id, request),
                _ => {}
            },
            BeaconEvent::Failed { id, request } => self.on_failed(id, request, slot),
            BeaconEvent::SignerKeys(keys) => self.on_signer_keys(&keys),
            BeaconEvent::Head(head) => {
                silver_log::debug!(slot = head.slot, block = %hex::encode(head.block), "head");
                self.schedule.on_head(&head);
                if head.slot == slot {
                    self.attestations.due(slot);
                }
            }
        }
    }

    pub fn on_tick(&mut self, chain: &ChainInfo, requests: &mut BeaconRequests) {
        if self.clock.is_none() {
            self.clock = DutyClock::start(chain.genesis_time, &self.spec);
        }
        let Some(clock) = &mut self.clock else { return };
        let tick = clock.tick();
        let slot = clock.current_slot();
        if let Some(Tick { slot, phase }) = tick {
            self.on_phase(slot, phase, requests);
        }

        self.schedule.request_due(slot, &self.validators, requests);
        self.attest(slot, chain, requests);
        self.ask_selection_proofs(chain, requests);
        self.schedule.subscriptions_due(slot, requests);
        self.aggregate(slot, chain, requests);
        self.attest_payload(slot, chain, requests);

        if self.proposer.is_some() {
            self.ask_randao(chain, requests);
        }
        let Self { spec, validators, schedule, proposer, .. } = self;
        if let Some(proposer) = proposer {
            proposer.prepare(slot, validators, requests);
            proposer.send_preferences(slot, spec, schedule, validators, chain, requests);
            proposer.propose(slot, spec, schedule, validators, chain, requests);
        }
    }

    fn on_phase(&mut self, slot: u64, phase: DutyPhase, requests: &mut BeaconRequests) {
        match phase {
            DutyPhase::SlotStart => {
                let epoch = slot / SLOTS_PER_EPOCH;
                self.validators.request_indices(epoch, requests);
                self.schedule.roll(epoch);
                if let Some(proposer) = &mut self.proposer {
                    if slot.is_multiple_of(SLOTS_PER_EPOCH) {
                        proposer.epoch_started();
                    }
                    proposer.slot_started(slot);
                }
            }
            DutyPhase::AttestationDue => self.attestations.due(slot),
            DutyPhase::AggregateDue => self.aggregations.due(slot),
            DutyPhase::PayloadAttestationDue => {
                if self.spec.is_gloas_at_slot(slot) {
                    self.payload_attestations.due(slot);
                }
            }
        }
    }

    fn attest_payload(&mut self, slot: u64, chain: &ChainInfo, requests: &mut BeaconRequests) {
        let round = &mut self.payload_attestations;
        if round.round.slot() != slot {
            return;
        }
        match (round.round.stage(), round.data) {
            (Stage::Due, Data::Unasked) if !self.schedule.ptc_at(slot).is_empty() => {
                round.data = Data::Awaiting(requests.payload_attestation_data(slot));
                round.round.working();
            }
            (Stage::Working, Data::Ready(data)) => {
                if PayloadAttestationDataView::slot(&data) != slot {
                    silver_log::warn!(slot, "payload attestation data for another slot");
                    return round.round.abandon();
                }
                let gvr = chain.genesis_validators_root;
                let fork_info = ForkInfo::new(&self.spec, slot / SLOTS_PER_EPOCH, gvr);
                let domain = compute_domain(DOMAIN_PTC_ATTESTER, fork_info.current_version, &gvr);
                let root = PayloadAttestationDataView::hash_tree_root(&data);
                let signing_root = compute_signing_root(&root, &domain);
                let body = requests.payload_attestation_sign_body(&fork_info, &signing_root, &data);
                for duty in self.schedule.ptc_at(slot) {
                    let pubkey = self.validators.pubkey(duty.key);
                    let id = requests.sign(pubkey, &body, SignPurpose::PayloadAttestation);
                    round.round.sign(id, *duty);
                }
                round.data = Data::Signing(data);
            }
            (Stage::Working, Data::Signing(data)) if round.round.all_signatures_answered() => {
                round.round.publish(|round| {
                    let signed = round.signed().map(|(duty, signature)| IndexedSignature {
                        validator_index: duty.validator_index,
                        signature,
                    });
                    requests.publish_payload_attestations(&data, signed)
                });
            }
            _ => {}
        }
    }

    fn on_proposer_signed(
        &mut self,
        id: RequestId,
        purpose: SignPurpose,
        signature: Option<[u8; 96]>,
    ) {
        let Some(proposer) = &mut self.proposer else { return };
        match (purpose, signature) {
            (SignPurpose::Block, Some(signature)) => {
                proposer.block_round.round.on_signed(id, signature)
            }
            (SignPurpose::Block, None) => proposer.block_round.round.on_sign_failed(id),
            (SignPurpose::Envelope, _) => proposer.on_envelope_signed(id, signature),
            _ => {}
        }
    }

    fn on_proposer_accepted(&mut self, id: RequestId, request: BeaconRequest) {
        let Some(proposer) = &mut self.proposer else { return };
        match request {
            BeaconRequest::PrepareProposers => proposer.on_prepared(id),
            BeaconRequest::PublishBlock(_) => proposer.on_block_accepted(id),
            BeaconRequest::PublishEnvelope => proposer.on_envelope_answered(id, true),
            _ => {}
        }
    }

    fn on_proposer_failed(&mut self, id: RequestId, request: BeaconRequest, slot: u64) {
        let Some(proposer) = &mut self.proposer else { return };
        match request {
            BeaconRequest::PrepareProposers => proposer.on_prepare_failed(id, slot),
            BeaconRequest::ProduceBlock(_) => proposer.block_round.on_data_failed(id),
            BeaconRequest::PublishBlock(_) => proposer.block_round.round.on_publish_failed(id),
            BeaconRequest::PublishEnvelope => proposer.on_envelope_answered(id, false),
            _ => {}
        }
    }

    fn on_failed(&mut self, id: RequestId, request: BeaconRequest, slot: u64) {
        match request {
            BeaconRequest::ValidatorIndices => self.validators.on_failed(id),
            BeaconRequest::AttesterDuties => self.schedule.on_failed(id, slot),
            BeaconRequest::CommitteeSubscriptions => self.schedule.on_subscription_failed(id, slot),
            BeaconRequest::AttestationData => self.attestations.on_data_failed(id),
            BeaconRequest::PublishAttestations(_) => self.attestations.round.on_publish_failed(id),
            BeaconRequest::AggregateAttestation => self.aggregations.on_fetch_failed(id),
            BeaconRequest::PublishAggregates(_) => self.aggregations.round.on_publish_failed(id),
            BeaconRequest::Sign(SignPurpose::Attestation) => {
                self.attestations.round.on_sign_failed(id)
            }
            BeaconRequest::Sign(SignPurpose::SelectionProof) => {
                self.schedule.on_selection_failed(id)
            }
            BeaconRequest::Sign(SignPurpose::Aggregate) => {
                self.aggregations.round.on_sign_failed(id)
            }
            BeaconRequest::ProposerDuties => self.schedule.on_failed(id, slot),
            BeaconRequest::Sign(SignPurpose::Randao) => self.schedule.on_randao(id, None),
            BeaconRequest::Sign(purpose @ (SignPurpose::Block | SignPurpose::Envelope)) => {
                self.on_proposer_signed(id, purpose, None)
            }
            BeaconRequest::PtcDuties => self.schedule.on_failed(id, slot),
            BeaconRequest::PayloadAttestationData => self.payload_attestations.on_data_failed(id),
            BeaconRequest::PublishPayloadAttestations => {
                self.payload_attestations.round.on_publish_failed(id)
            }
            BeaconRequest::Sign(SignPurpose::PayloadAttestation) => {
                self.payload_attestations.round.on_sign_failed(id)
            }
            BeaconRequest::Sign(SignPurpose::ProposerPreferences) => {
                self.schedule.on_preferences(id, None)
            }
            BeaconRequest::PublishProposerPreferences => {}
            BeaconRequest::PrepareProposers |
            BeaconRequest::ProduceBlock(_) |
            BeaconRequest::PublishBlock(_) |
            BeaconRequest::PublishEnvelope => self.on_proposer_failed(id, request, slot),
        }
    }

    /// web3signer's keys replace the empty set the client starts with.
    fn on_signer_keys(&mut self, keys: &SignerKeys<'_>) {
        let mut pubkeys = Vec::new();
        if let Err(error) = keys.for_each(MAX_SIGNER_KEYS, |pubkey| pubkeys.push(*pubkey)) {
            silver_log::error!(error, "web3signer keys unusable");
            return;
        }
        pubkeys.sort_unstable();
        pubkeys.dedup();
        silver_log::info!(keys = pubkeys.len(), "web3signer keys");
        self.validators = Validators::new(pubkeys);
    }

    /// Duties are kept only for keys with an index.
    fn indices_learned(&mut self) {
        self.schedule.refetch_all();
        if let Some(proposer) = &mut self.proposer {
            proposer.prepare_again();
        }
    }

    /// Requests the data once due, has every duty signed, then publishes, all
    /// in the slot it was due.
    fn attest(&mut self, slot: u64, chain: &ChainInfo, requests: &mut BeaconRequests) {
        let attestations = &mut self.attestations;
        if attestations.round.slot() != slot {
            return;
        }
        match (attestations.round.stage(), attestations.data) {
            (Stage::Due, Data::Unasked) if !self.schedule.attesters_at(slot).is_empty() => {
                attestations.data = Data::Awaiting(requests.attestation_data(slot));
                attestations.round.working();
            }
            (Stage::Working, Data::Ready(data)) => {
                self.request_signatures(slot, data, chain, requests)
            }
            (Stage::Working, Data::Signing(data))
                if attestations.round.all_signatures_answered() =>
            {
                let fork = self.spec.fork_at_slot(slot);
                attestations.round.publish(|round| {
                    let signed = round.signed().map(|(duty, signature)| SignedAttestation {
                        committee_index: duty.committee_index,
                        attester_index: duty.validator_index,
                        signature,
                    });
                    requests.publish_attestations(fork, AttestationDataView::new(&data), signed)
                });
            }
            _ => {}
        }
    }

    fn request_signatures(
        &mut self,
        slot: u64,
        data: [u8; ATTESTATION_DATA_SIZE],
        chain: &ChainInfo,
        requests: &mut BeaconRequests,
    ) {
        let view = AttestationDataView::new(&data);
        let epoch = slot / SLOTS_PER_EPOCH;
        if view.slot() != slot || view.target_epoch() != epoch {
            silver_log::warn!(slot, data_slot = view.slot(), "attestation data for another slot");
            return self.attestations.round.abandon();
        }
        let fork_info = ForkInfo::new(&self.spec, epoch, chain.genesis_validators_root);
        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER,
            fork_info.current_version,
            &chain.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&hash_attestation_data(&data), &domain);

        let body = requests.attestation_sign_body(&fork_info, &signing_root, view);
        for duty in self.schedule.attesters_at(slot) {
            let pubkey = self.validators.pubkey(duty.key);
            let id = requests.sign(pubkey, &body, SignPurpose::Attestation);
            self.attestations.round.sign(id, *duty);
        }
        self.attestations.data = Data::Signing(data);
    }

    /// One body per slot, shared by every duty at it.
    fn ask_selection_proofs(&mut self, chain: &ChainInfo, requests: &mut BeaconRequests) {
        let Self { spec, validators, schedule, .. } = self;
        let gvr = chain.genesis_validators_root;
        let mut body: Option<(u64, SignBody)> = None;
        schedule.ask_selections(|duty| {
            let body = match &body {
                Some((slot, body)) if *slot == duty.slot => body.clone(),
                _ => {
                    let fork_info = ForkInfo::new(spec, duty.slot / SLOTS_PER_EPOCH, gvr);
                    let domain =
                        compute_domain(DOMAIN_SELECTION_PROOF, fork_info.current_version, &gvr);
                    let root = compute_signing_root(&uint64_chunk(duty.slot), &domain);
                    let fresh = requests.selection_sign_body(&fork_info, &root, duty.slot);
                    body = Some((duty.slot, fresh.clone()));
                    fresh
                }
            };
            requests.sign(validators.pubkey(duty.key), &body, SignPurpose::SelectionProof)
        });
    }

    fn ask_randao(&mut self, chain: &ChainInfo, requests: &mut BeaconRequests) {
        let Self { spec, validators, schedule, .. } = self;
        let gvr = chain.genesis_validators_root;
        let mut body: Option<(u64, SignBody)> = None;
        schedule.ask_randao(|duty| {
            let epoch = duty.slot / SLOTS_PER_EPOCH;
            let body = match &body {
                Some((at, body)) if *at == epoch => body.clone(),
                _ => {
                    let fork_info = ForkInfo::new(spec, epoch, gvr);
                    let domain = compute_domain(DOMAIN_RANDAO, fork_info.current_version, &gvr);
                    let root = compute_signing_root(&uint64_chunk(epoch), &domain);
                    let fresh = requests.randao_sign_body(&fork_info, &root, epoch);
                    body = Some((epoch, fresh.clone()));
                    fresh
                }
            };
            requests.sign(validators.pubkey(duty.key), &body, SignPurpose::Randao)
        });
    }

    /// At 2/3, fetches each aggregator's aggregate of what this slot attested,
    /// has them signed, then publishes them together.
    fn aggregate(&mut self, slot: u64, chain: &ChainInfo, requests: &mut BeaconRequests) {
        if self.aggregations.round.slot() != slot {
            return;
        }
        match self.aggregations.round.stage() {
            Stage::Due => {
                let Some(data) = self.attestations.signed_data(slot) else {
                    return self.aggregations.round.abandon();
                };
                let data_root = hash_attestation_data(data);
                let fetches = self.schedule.aggregators_at(slot).map(|(duty, proof)| {
                    (requests.aggregate_attestation(slot, duty.committee, &data_root), duty, proof)
                });
                self.aggregations.fetching(fetches);
            }
            Stage::Working => {
                let fork = self.spec.fork_at_slot(slot);
                let epoch = slot / SLOTS_PER_EPOCH;
                let fork_info = ForkInfo::new(&self.spec, epoch, chain.genesis_validators_root);
                let validators = &self.validators;
                self.aggregations.sign_served(|duty, proof, aggregate| {
                    let body = requests.aggregate_sign_body(
                        &fork_info,
                        fork,
                        duty.validator_index,
                        aggregate,
                        proof,
                    );
                    requests.sign(validators.pubkey(duty.key), &body, SignPurpose::Aggregate)
                });
                if self.aggregations.all_answered() {
                    self.aggregations.publish(|signed| requests.publish_aggregates(fork, signed));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use silver_beacon_state_data::{DOMAIN_BEACON_BUILDER, bls::DOMAIN_BEACON_PROPOSER};
    use silver_common::{
        ForkName, block_root_gloas,
        envelope_contents::SignedEnvelopeContents,
        ssz_view::ExecutionPayloadEnvelopeView,
        test_util::{SynthBid, SynthBlock, empty_signed_envelope},
    };

    use super::{schedule::is_aggregator, *};
    use crate::{
        beacon_link::{
            Aggregate, AttestationData, AttesterDuties, PayloadAttestationData, ProducedBlock,
            RequestId, SlotDuties, ValidatorIndices,
        },
        config::ProposalConfig,
    };

    const SLOT: u64 = 65;
    const FEE_RECIPIENT: [u8; 20] = [0xfe; 20];
    const PUBKEY_A: [u8; 48] = [0xaa; 48];
    const PUBKEY_B: [u8; 48] = [0xbb; 48];

    fn gloas_spec() -> SpecConfig {
        let mut spec = SpecConfig::mainnet();
        spec.gloas_fork_epoch = 0;
        spec
    }

    fn duties_on(spec: SpecConfig) -> Duties {
        let config = Config {
            spec,
            genesis_validators_root: [0x9e; 32],
            beacon_node: "http://localhost:5052".into(),
            web3signer_url: "http://localhost:9000".into(),
            proposals: Some(ProposalConfig {
                fee_recipient: FEE_RECIPIENT,
                graffiti: [0x67; 32],
                gas_limit: 60_000_000,
            }),
        };
        Duties::new(&config)
    }

    fn chain(genesis_time: u64) -> ChainInfo {
        ChainInfo { genesis_time, genesis_validators_root: [0x9e; 32] }
    }

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn pubkey_hex(pubkey: [u8; 48]) -> String {
        format!("0x{}", hex::encode(pubkey))
    }

    fn sent(requests: &mut BeaconRequests) -> Vec<(RequestId, String, Value)> {
        let mut sent = Vec::new();
        requests.drain(|id, _, path, body| {
            let body =
                if body.is_empty() { Value::Null } else { serde_json::from_slice(body).unwrap() };
            sent.push((id, path.to_owned(), body))
        });
        sent
    }

    fn leaked(value: Value) -> &'static [u8] {
        value.to_string().leak().as_bytes()
    }

    /// Two web3signer keys, indices 7 and 9, attesting in committees 3 and 4
    /// at `SLOT`. One request queue throughout, as in the tile, so ids stay
    /// unique.
    fn attesters() -> (Duties, BeaconRequests) {
        attesters_on(SpecConfig::mainnet())
    }

    fn attesters_on(spec: SpecConfig) -> (Duties, BeaconRequests) {
        let mut duties = duties_on(spec);
        let keys = json!([pubkey_hex(PUBKEY_B), pubkey_hex(PUBKEY_A)]);
        duties.on_beacon_event(BeaconEvent::SignerKeys(SignerKeys(leaked(keys))));
        let mut requests = BeaconRequests::default();

        duties.validators.request_indices(0, &mut requests);
        let id = sent(&mut requests)[0].0;
        let indices = json!({"data": [
            {"index": "7", "validator": {"pubkey": pubkey_hex(PUBKEY_A)}},
            {"index": "9", "validator": {"pubkey": pubkey_hex(PUBKEY_B)}},
        ]});
        let validators = ValidatorIndices(leaked(indices));
        duties.on_beacon_event(BeaconEvent::ValidatorIndices { id, validators });

        duties.schedule.roll(SLOT / SLOTS_PER_EPOCH);
        duties.schedule.request_due(SLOT, &duties.validators, &mut requests);
        let id = sent(&mut requests)[0].0;
        let duty = |pubkey, index: &str, committee: &str| {
            json!({
                "pubkey": pubkey_hex(pubkey),
                "validator_index": index,
                "committee_index": committee,
                "committee_length": "128",
                "committees_at_slot": "8",
                "slot": SLOT.to_string(),
            })
        };
        let answer = json!({
            "dependent_root": hex32(0xd0),
            "data": [duty(PUBKEY_A, "7", "3"), duty(PUBKEY_B, "9", "4")],
        });
        duties.on_beacon_event(BeaconEvent::AttesterDuties {
            id,
            duties: AttesterDuties(leaked(answer)),
        });
        (duties, requests)
    }

    fn data_json(slot: u64, target_epoch: u64) -> Value {
        json!({
            "slot": slot.to_string(),
            "index": "0",
            "beacon_block_root": hex32(0x11),
            "source": {"epoch": "1", "root": hex32(0x22)},
            "target": {"epoch": target_epoch.to_string(), "root": hex32(0x33)},
        })
    }

    /// Marks `SLOT` due, answers its data request with `data`, and returns the
    /// sign requests that follow.
    fn sign_requests(
        duties: &mut Duties,
        requests: &mut BeaconRequests,
        data: Value,
    ) -> Vec<(RequestId, String, Value)> {
        duties.attestations.due(SLOT);
        duties.attest(SLOT, &chain(0), requests);
        let asked = sent(requests);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1, "/eth/v1/validator/attestation_data?slot=65&committee_index=0");

        let data = AttestationData(leaked(json!({"data": data})));
        duties.on_beacon_event(BeaconEvent::AttestationData { id: asked[0].0, data });
        duties.attest(SLOT, &chain(0), requests);
        sent(requests)
    }

    fn published(
        duties: &mut Duties,
        requests: &mut BeaconRequests,
    ) -> Vec<(RequestId, String, Value)> {
        duties.attest(SLOT, &chain(0), requests);
        sent(requests)
    }

    #[test]
    fn each_duty_is_signed_remotely_then_published_once() {
        let (mut duties, mut requests) = attesters();
        let signing =
            sign_requests(&mut duties, &mut requests, data_json(SLOT, SLOT / SLOTS_PER_EPOCH));
        let paths = signing.iter().map(|(_, path, _)| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, [
            format!("/api/v1/eth2/sign/{}", pubkey_hex(PUBKEY_A)),
            format!("/api/v1/eth2/sign/{}", pubkey_hex(PUBKEY_B)),
        ]);

        let spec = SpecConfig::mainnet();
        let epoch = SLOT / SLOTS_PER_EPOCH;
        let mut ssz = [0; ATTESTATION_DATA_SIZE];
        ssz[0..8].copy_from_slice(&SLOT.to_le_bytes());
        ssz[16..48].fill(0x11);
        ssz[48..56].copy_from_slice(&1u64.to_le_bytes());
        ssz[56..88].fill(0x22);
        ssz[88..96].copy_from_slice(&epoch.to_le_bytes());
        ssz[96..128].fill(0x33);
        let domain =
            compute_domain(DOMAIN_BEACON_ATTESTER, spec.fork_version_at(epoch), &[0x9e; 32]);
        let signing_root = compute_signing_root(&hash_attestation_data(&ssz), &domain);
        let version = format!("0x{}", hex::encode(spec.fork_version_at(epoch)));
        let expected_body = json!({
            "type": "ATTESTATION",
            "fork_info": {
                "fork": {"previous_version": version, "current_version": version, "epoch": "0"},
                "genesis_validators_root": hex32(0x9e),
            },
            "signingRoot": format!("0x{}", hex::encode(signing_root)),
            "attestation": data_json(SLOT, epoch),
        });
        assert!(signing.iter().all(|(_, _, body)| *body == expected_body));

        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[0].0,
            purpose: SignPurpose::Attestation,
            signature: [0xc1; 96],
        });
        assert!(published(&mut duties, &mut requests).is_empty());
        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[1].0,
            purpose: SignPurpose::Attestation,
            signature: [0xc2; 96],
        });
        let publish = published(&mut duties, &mut requests);
        assert_eq!(publish.len(), 1);
        assert_eq!(publish[0].1, "/eth/v2/beacon/pool/attestations");
        let entries = publish[0].2.as_array().unwrap();
        let summary = entries
            .iter()
            .map(|entry| {
                (
                    entry["attester_index"].clone(),
                    entry["committee_index"].clone(),
                    entry["signature"].clone(),
                )
            })
            .collect::<Vec<_>>();
        let signature = |byte: &str| Value::from(format!("0x{}", byte.repeat(96)));
        assert_eq!(summary, [
            (Value::from("7"), Value::from("3"), signature("c1")),
            (Value::from("9"), Value::from("4"), signature("c2")),
        ]);
        assert!(entries.iter().all(|entry| entry["data"] == data_json(SLOT, epoch)));

        duties.on_beacon_event(BeaconEvent::Accepted {
            id: publish[0].0,
            request: BeaconRequest::PublishAttestations(ForkName::Gloas),
        });
        duties.attestations.due(SLOT);
        duties.attest(SLOT, &chain(0), &mut requests);
        assert!(sent(&mut requests).is_empty());
    }

    #[test]
    fn refused_signature_drops_only_its_attestation() {
        let (mut duties, mut requests) = attesters();
        let signing =
            sign_requests(&mut duties, &mut requests, data_json(SLOT, SLOT / SLOTS_PER_EPOCH));
        duties.on_beacon_event(BeaconEvent::Failed {
            id: signing[0].0,
            request: BeaconRequest::Sign(SignPurpose::Attestation),
        });
        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[1].0,
            purpose: SignPurpose::Attestation,
            signature: [0xc2; 96],
        });
        let publish = published(&mut duties, &mut requests);
        let entries = publish[0].2.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["attester_index"], "9");
    }

    #[test]
    fn nothing_signed_publishes_nothing() {
        let (mut duties, mut requests) = attesters();
        let signing =
            sign_requests(&mut duties, &mut requests, data_json(SLOT, SLOT / SLOTS_PER_EPOCH));
        for (id, _, _) in &signing {
            duties.on_beacon_event(BeaconEvent::Failed {
                id: *id,
                request: BeaconRequest::Sign(SignPurpose::Attestation),
            });
        }
        assert!(published(&mut duties, &mut requests).is_empty());
        assert_eq!(duties.attestations.round.stage(), Stage::Done);
    }

    #[test]
    fn data_for_another_slot_is_not_signed() {
        let (mut duties, mut requests) = attesters();
        assert!(
            sign_requests(&mut duties, &mut requests, data_json(SLOT + 1, SLOT / SLOTS_PER_EPOCH))
                .is_empty()
        );
        let (mut duties, mut requests) = attesters();
        assert!(
            sign_requests(&mut duties, &mut requests, data_json(SLOT, SLOT / SLOTS_PER_EPOCH + 1))
                .is_empty()
        );
    }

    #[test]
    fn slot_without_duties_asks_for_no_data() {
        let (mut duties, mut requests) = attesters();
        duties.attestations.due(SLOT + 1);
        duties.attest(SLOT + 1, &chain(0), &mut requests);
        assert!(sent(&mut requests).is_empty());
    }

    #[test]
    fn fork_info_names_the_previous_version_after_a_fork() {
        let spec = SpecConfig::mainnet();
        let epoch = spec.fork_epoch(ForkName::Fulu) + 3;
        let fork_info = ForkInfo::new(&spec, epoch, [0x9e; 32]);
        assert_eq!(fork_info.epoch, spec.fork_epoch(ForkName::Fulu));
        assert_eq!(fork_info.current_version, spec.fork_version(ForkName::Fulu));
        assert_eq!(fork_info.previous_version, spec.fork_version(ForkName::Electra));
    }

    /// A selection proof that makes, or does not make, a member of a
    /// 128-validator committee aggregate.
    fn selection_proof(aggregates: bool) -> [u8; 96] {
        (0..=u8::MAX)
            .map(|byte| [byte; 96])
            .find(|proof| is_aggregator(128, proof) == aggregates)
            .unwrap()
    }

    fn signing_root_hex(body: &Value) -> String {
        body["signingRoot"].as_str().unwrap().to_owned()
    }

    #[test]
    fn aggregator_fetches_signs_and_publishes_its_aggregate() {
        let (mut duties, mut requests) = attesters();
        let gvr = [0x9e; 32];
        let spec = SpecConfig::mainnet();
        let epoch = SLOT / SLOTS_PER_EPOCH;

        duties.ask_selection_proofs(&chain(0), &mut requests);
        let selections = sent(&mut requests);
        assert_eq!(selections.len(), 2);
        let domain = compute_domain(DOMAIN_SELECTION_PROOF, spec.fork_version_at(epoch), &gvr);
        let root = compute_signing_root(&uint64_chunk(SLOT), &domain);
        assert_eq!(selections[0].2["type"], "AGGREGATION_SLOT");
        assert_eq!(signing_root_hex(&selections[0].2), format!("0x{}", hex::encode(root)));

        let proof = selection_proof(true);
        duties.on_beacon_event(BeaconEvent::Signed {
            id: selections[0].0,
            purpose: SignPurpose::SelectionProof,
            signature: proof,
        });
        duties.on_beacon_event(BeaconEvent::Signed {
            id: selections[1].0,
            purpose: SignPurpose::SelectionProof,
            signature: selection_proof(false),
        });
        duties.schedule.subscriptions_due(SLOT, &mut requests);
        let subscription = sent(&mut requests);
        assert_eq!(subscription[0].1, "/eth/v1/validator/beacon_committee_subscriptions");

        let signing = sign_requests(&mut duties, &mut requests, data_json(SLOT, epoch));
        for (id, _, _) in &signing {
            duties.on_beacon_event(BeaconEvent::Signed {
                id: *id,
                purpose: SignPurpose::Attestation,
                signature: [0xc1; 96],
            });
        }
        sent(&mut requests);

        duties.aggregations.due(SLOT);
        duties.aggregate(SLOT, &chain(0), &mut requests);
        let fetch = sent(&mut requests);
        let mut data = [0; ATTESTATION_DATA_SIZE];
        let view_json = AttestationData(leaked(json!({"data": data_json(SLOT, epoch)})));
        data.copy_from_slice(&view_json.to_ssz().unwrap());
        let data_root = hash_attestation_data(&data);
        assert_eq!(fetch.len(), 1);
        assert_eq!(
            fetch[0].1,
            format!(
                "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{}&slot=65&committee_index=3",
                hex::encode(data_root)
            )
        );

        let aggregate = json!({
            "aggregation_bits": "0x0b",
            "data": data_json(SLOT, epoch),
            "signature": format!("0x{}", "d1".repeat(96)),
            "committee_bits": "0x0800000000000000",
        });
        let answer = Aggregate(leaked(json!({"version": "fulu", "data": aggregate})));
        duties.on_beacon_event(BeaconEvent::AggregateAttestation {
            id: fetch[0].0,
            aggregate: answer,
        });
        duties.aggregate(SLOT, &chain(0), &mut requests);
        let signing = sent(&mut requests);
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].1, format!("/api/v1/eth2/sign/{}", pubkey_hex(PUBKEY_A)));

        assert_eq!(
            signing[0].2,
            json!({
                "type": "AGGREGATE_AND_PROOF_V2",
                "fork_info": signing[0].2["fork_info"].clone(),
                "aggregate_and_proof": {
                    "version": spec.fork_at_slot(SLOT).name().to_ascii_uppercase(),
                    "data": {
                        "aggregator_index": "7",
                        "aggregate": aggregate,
                        "selection_proof": format!("0x{}", hex::encode(proof)),
                    },
                },
            })
        );

        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[0].0,
            purpose: SignPurpose::Aggregate,
            signature: [0xe1; 96],
        });
        duties.aggregate(SLOT, &chain(0), &mut requests);
        let publish = sent(&mut requests);
        assert_eq!(publish.len(), 1);
        assert_eq!(publish[0].1, "/eth/v2/validator/aggregate_and_proofs");
        assert_eq!(
            publish[0].2,
            json!([{
                "message": {
                    "aggregator_index": "7",
                    "aggregate": aggregate,
                    "selection_proof": format!("0x{}", hex::encode(proof)),
                },
                "signature": format!("0x{}", "e1".repeat(96)),
            }])
        );

        duties.on_beacon_event(BeaconEvent::Accepted {
            id: publish[0].0,
            request: BeaconRequest::PublishAggregates(ForkName::Gloas),
        });
        assert_eq!(duties.aggregations.round.stage(), Stage::Done);
    }

    #[test]
    fn slot_without_own_attestation_aggregates_nothing() {
        let (mut duties, mut requests) = attesters();
        duties.aggregations.due(SLOT);
        duties.aggregate(SLOT, &chain(0), &mut requests);
        assert!(sent(&mut requests).is_empty());
        assert_eq!(duties.aggregations.round.stage(), Stage::Done);
    }

    fn sent_raw(requests: &mut BeaconRequests) -> Vec<(RequestId, String, Vec<u8>)> {
        let mut sent = Vec::new();
        requests.drain(|id, _, path, body| sent.push((id, path.to_owned(), body.to_vec())));
        sent
    }

    /// Index 7 proposes at `SLOT`; index 100 is not ours.
    fn proposal_duty(duties: &mut Duties, requests: &mut BeaconRequests) {
        duties.schedule.refetch_all();
        duties.schedule.request_due(SLOT, &duties.validators, requests);
        let fetches = sent(requests);
        let (id, ..) = fetches
            .iter()
            .find(|(_, path, _)| path == "/eth/v2/validator/duties/proposer/2")
            .expect("proposer duties for the slot's epoch");
        let answer = json!({"dependent_root": hex32(0xd0), "data": [
            {"pubkey": pubkey_hex(PUBKEY_A), "validator_index": "7", "slot": SLOT.to_string()},
            {"pubkey": pubkey_hex([0xcc; 48]), "validator_index": "100", "slot": "66"},
        ]});
        duties.on_beacon_event(BeaconEvent::ProposerDuties {
            id: *id,
            duties: SlotDuties(leaked(answer)),
        });
    }

    fn propose(duties: &mut Duties, requests: &mut BeaconRequests) {
        let Duties { spec, validators, schedule, proposer, .. } = duties;
        let proposer = proposer.as_mut().unwrap();
        proposer.propose(SLOT, spec, schedule, validators, &chain(0), requests);
    }

    /// A Gloas block produced without its payload, signed by `proposer_index`.
    fn gloas_block(proposer_index: u64) -> Vec<u8> {
        let mut signed_block = SynthBlock::gloas(SLOT, SynthBid::new(&[])).into_bytes();
        signed_block[108..116].copy_from_slice(&proposer_index.to_le_bytes());
        signed_block
    }

    #[test]
    fn proposal_for_another_proposer_is_not_signed() {
        let (mut duties, mut requests) = attesters_on(gloas_spec());
        proposal_duty(&mut duties, &mut requests);
        duties.ask_randao(&chain(0), &mut requests);
        let randao = sent(&mut requests)[0].0;
        let signed =
            BeaconEvent::Signed { id: randao, purpose: SignPurpose::Randao, signature: [0x7a; 96] };
        duties.on_beacon_event(signed);
        duties.proposer.as_mut().unwrap().slot_started(SLOT);
        propose(&mut duties, &mut requests);
        let produce = sent_raw(&mut requests)[0].0;

        let ssz = gloas_block(8)[100..].to_vec().leak();
        let block = ProducedBlock { payload_included: false, ssz };
        duties.on_beacon_event(BeaconEvent::ProducedBlock { id: produce, block });
        propose(&mut duties, &mut requests);
        assert!(sent(&mut requests).is_empty());
        assert_eq!(duties.proposer.unwrap().block_round.round.stage(), Stage::Done);
    }

    #[test]
    fn known_indices_are_prepared_each_epoch() {
        let (mut duties, mut requests) = attesters();
        sent(&mut requests);
        let Duties { validators, proposer, .. } = &mut duties;
        let proposer = proposer.as_mut().unwrap();
        proposer.prepare(SLOT, validators, &mut requests);
        let prepared = sent(&mut requests);
        assert_eq!(prepared[0].1, "/eth/v1/validator/prepare_beacon_proposer");
        let fee_recipient = format!("0x{}", "fe".repeat(20));
        assert_eq!(
            prepared[0].2,
            json!([
                {"validator_index": "7", "fee_recipient": fee_recipient},
                {"validator_index": "9", "fee_recipient": fee_recipient},
            ])
        );

        proposer.on_prepared(prepared[0].0);
        proposer.prepare(SLOT, validators, &mut requests);
        assert!(sent(&mut requests).is_empty());
        proposer.epoch_started();
        proposer.prepare(SLOT + 1, validators, &mut requests);
        assert_eq!(sent(&mut requests).len(), 1);
    }

    fn answer_duties(
        duties: &mut Duties,
        requests: &mut BeaconRequests,
        path: &str,
        answer: Value,
    ) {
        duties.schedule.refetch_all();
        duties.schedule.request_due(SLOT, &duties.validators, requests);
        let fetches = sent(requests);
        let (id, ..) = fetches.iter().find(|(_, sent, _)| sent == path).expect("duties fetched");
        let duties_answer = SlotDuties(leaked(answer));
        let event = if path.contains("ptc") {
            BeaconEvent::PtcDuties { id: *id, duties: duties_answer }
        } else {
            BeaconEvent::ProposerDuties { id: *id, duties: duties_answer }
        };
        duties.on_beacon_event(event);
    }

    fn own_slot_duty() -> Value {
        json!({"dependent_root": hex32(0xd0), "data": [
            {"pubkey": pubkey_hex(PUBKEY_A), "validator_index": "7", "slot": SLOT.to_string()},
        ]})
    }

    #[test]
    fn ptc_members_sign_the_served_payload_attestation_data() {
        let spec = gloas_spec();
        let (mut duties, mut requests) = attesters_on(spec.clone());
        answer_duties(
            &mut duties,
            &mut requests,
            "/eth/v1/validator/duties/ptc/2",
            own_slot_duty(),
        );

        duties.payload_attestations.due(SLOT);
        duties.attest_payload(SLOT, &chain(0), &mut requests);
        let fetch = sent(&mut requests);
        assert_eq!(fetch[0].1, "/eth/v1/validator/payload_attestation_data?slot=65");
        let data = json!({
            "beacon_block_root": hex32(0x11),
            "slot": "65",
            "payload_present": true,
            "blob_data_available": false,
        });
        let answer = PayloadAttestationData(leaked(json!({"version": "gloas", "data": data})));
        duties
            .on_beacon_event(BeaconEvent::PayloadAttestationData { id: fetch[0].0, data: answer });

        duties.attest_payload(SLOT, &chain(0), &mut requests);
        let signing = sent(&mut requests);
        assert_eq!(signing[0].2["type"], "PAYLOAD_ATTESTATION_MESSAGE");
        assert_eq!(
            signing[0].2["payload_attestation_message"],
            json!({"version": "GLOAS", "data": data})
        );
        let mut ssz = [0; PAYLOAD_ATTESTATION_DATA_SIZE];
        ssz[..32].fill(0x11);
        ssz[32..40].copy_from_slice(&SLOT.to_le_bytes());
        ssz[40] = 1;
        let version = spec.fork_version_at(SLOT / SLOTS_PER_EPOCH);
        let domain = compute_domain(DOMAIN_PTC_ATTESTER, version, &[0x9e; 32]);
        let root = compute_signing_root(&PayloadAttestationDataView::hash_tree_root(&ssz), &domain);
        assert_eq!(signing_root_hex(&signing[0].2), format!("0x{}", hex::encode(root)));

        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[0].0,
            purpose: SignPurpose::PayloadAttestation,
            signature: [0xa1; 96],
        });
        duties.attest_payload(SLOT, &chain(0), &mut requests);
        let publish = sent(&mut requests);
        assert_eq!(publish[0].1, "/eth/v1/beacon/pool/payload_attestations");
        assert_eq!(
            publish[0].2,
            json!([{
                "validator_index": "7",
                "data": data,
                "signature": format!("0x{}", "a1".repeat(96)),
            }])
        );
    }

    #[test]
    fn upcoming_gloas_proposals_publish_signed_preferences_once() {
        let (mut duties, mut requests) = attesters_on(gloas_spec());
        answer_duties(
            &mut duties,
            &mut requests,
            "/eth/v2/validator/duties/proposer/2",
            own_slot_duty(),
        );
        let send = |duties: &mut Duties, requests: &mut BeaconRequests| {
            let Duties { spec, validators, schedule, proposer, .. } = duties;
            let proposer = proposer.as_ref().unwrap();
            proposer.send_preferences(SLOT - 1, spec, schedule, validators, &chain(0), requests);
        };

        send(&mut duties, &mut requests);
        let signing = sent(&mut requests);
        let message = json!({
            "dependent_root": hex32(0xd0),
            "proposal_slot": "65",
            "validator_index": "7",
            "fee_recipient": format!("0x{}", "fe".repeat(20)),
            "target_gas_limit": "60000000",
        });
        assert_eq!(signing[0].2["type"], "PROPOSER_PREFERENCES");
        assert_eq!(signing[0].2["proposer_preferences"]["data"], message);

        duties.on_beacon_event(BeaconEvent::Signed {
            id: signing[0].0,
            purpose: SignPurpose::ProposerPreferences,
            signature: [0xb2; 96],
        });
        send(&mut duties, &mut requests);
        let publish = sent(&mut requests);
        assert_eq!(publish[0].1, "/eth/v1/validator/proposer_preferences");
        assert_eq!(
            publish[0].2,
            json!([{"message": message, "signature": format!("0x{}", "b2".repeat(96))}])
        );
        send(&mut duties, &mut requests);
        assert!(sent(&mut requests).is_empty());
    }

    #[test]
    fn gloas_proposal_publishes_the_block_then_its_envelope() {
        let spec = gloas_spec();
        let (mut duties, mut requests) = attesters_on(spec.clone());
        proposal_duty(&mut duties, &mut requests);
        duties.ask_randao(&chain(0), &mut requests);
        let randao = sent(&mut requests)[0].0;
        duties.on_beacon_event(BeaconEvent::Signed {
            id: randao,
            purpose: SignPurpose::Randao,
            signature: [0x7a; 96],
        });
        duties.proposer.as_mut().unwrap().slot_started(SLOT);
        propose(&mut duties, &mut requests);
        let produce = sent_raw(&mut requests);
        assert!(produce[0].1.starts_with("/eth/v4/validator/blocks/65?"));
        assert!(produce[0].1.ends_with("&include_payload=true"));
        let boost_zero =
            [&0u64.to_le_bytes()[..], &0u64.to_le_bytes(), &20u32.to_le_bytes()].concat();
        assert_eq!(produce[0].2, boost_zero);

        let mut signed_block = gloas_block(7);
        let block_root = block_root_gloas(&signed_block);
        let mut envelope = empty_signed_envelope(SLOT, block_root).split_off(100);
        envelope[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let block = &signed_block[100..];
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let end = 16 + block.len() + envelope.len();
        let contents =
            [&at(16)[..], &at(16 + block.len()), &at(end), &at(end), block, &envelope].concat();
        let produced = ProducedBlock { payload_included: true, ssz: contents.leak() };
        duties.on_beacon_event(BeaconEvent::ProducedBlock { id: produce[0].0, block: produced });

        propose(&mut duties, &mut requests);
        let signing = sent(&mut requests);
        assert_eq!(signing[0].2["beacon_block"]["version"], "GLOAS");
        assert_eq!(signing[1].2["type"], "EXECUTION_PAYLOAD_ENVELOPE");
        let version = spec.fork_version_at(SLOT / SLOTS_PER_EPOCH);
        let gvr = [0x9e; 32];
        let block_signing_root = compute_signing_root(
            &block_root,
            &compute_domain(DOMAIN_BEACON_PROPOSER, version, &gvr),
        );
        assert_eq!(
            signing_root_hex(&signing[0].2),
            format!("0x{}", hex::encode(block_signing_root))
        );
        let envelope_root = compute_signing_root(
            &ExecutionPayloadEnvelopeView::hash_tree_root(&envelope),
            &compute_domain(DOMAIN_BEACON_BUILDER, version, &gvr),
        );
        assert_eq!(signing_root_hex(&signing[1].2), format!("0x{}", hex::encode(envelope_root)));

        let signed = |id, purpose, signature| BeaconEvent::Signed { id, purpose, signature };
        duties.on_beacon_event(signed(signing[0].0, SignPurpose::Block, [0xb1; 96]));
        duties.on_beacon_event(signed(signing[1].0, SignPurpose::Envelope, [0xe1; 96]));
        propose(&mut duties, &mut requests);
        let publish = sent_raw(&mut requests);
        assert_eq!(publish.len(), 1, "the envelope waits for the block");
        assert_eq!(publish[0].1, "/eth/v2/beacon/blocks");
        signed_block[4..100].copy_from_slice(&[0xb1; 96]);
        assert_eq!(publish[0].2, signed_block);

        duties.on_beacon_event(BeaconEvent::Accepted {
            id: publish[0].0,
            request: BeaconRequest::PublishBlock(ForkName::Gloas),
        });
        propose(&mut duties, &mut requests);
        let envelope_publish = sent_raw(&mut requests);
        assert_eq!(envelope_publish[0].1, "/eth/v1/beacon/execution_payload_envelopes");
        let published = SignedEnvelopeContents::parse(&envelope_publish[0].2).expect("contents");
        assert_eq!(&published.signed_envelope[4..100], &[0xe1; 96]);
        assert_eq!(&published.signed_envelope[100..], &envelope[..]);
    }
}
