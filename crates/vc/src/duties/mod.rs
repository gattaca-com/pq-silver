mod aggregations;
mod proposer;
mod round;
mod schedule;
mod validators;

use silver_beacon_state_data::bls::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER,
};
use silver_common::{
    SLOTS_PER_EPOCH,
    ssz_hash::hash_attestation_data,
    ssz_view::{AttestationDataView, PayloadAttestationDataView, XMSSPubkey},
    vc_spine::{SignAnswer, SignPurpose, SignRequest},
    xmss::{SlotDuty, attestation_leaf},
};

use self::{
    aggregations::Aggregations, proposer::Proposer, round::DataRound, schedule::DutySchedule,
    validators::Validators,
};
use crate::{
    beacon_link::{
        Aggregate, AttestationData, BeaconEvent, BeaconRequest, BeaconRequests,
        PayloadAttestationData, RequestId,
    },
    clock::{DutyClock, DutyPhase, Tick},
    config::Config,
    signing::{SignRequests, SigningDomains},
};

pub struct Duties {
    domains: SigningDomains,
    slot_duration_ms: u64,
    clock: Option<DutyClock>,
    validators: Validators,
    schedule: DutySchedule,
    attestations: DataRound,
    aggregations: Aggregations,
    payload_attestations: DataRound,
    proposer: Option<Proposer>,
}

impl Duties {
    /// `pubkeys` sorted.
    pub fn new(config: &Config, pubkeys: Vec<XMSSPubkey>) -> Self {
        Self {
            domains: SigningDomains::new(&config.spec, config.genesis_validators_root),
            slot_duration_ms: config.spec.slot_duration_ms(),
            clock: None,
            validators: Validators::new(pubkeys),
            schedule: DutySchedule::new(config.proposals.is_some()),
            attestations: DataRound::new("attestations"),
            aggregations: Aggregations::new(),
            payload_attestations: DataRound::new("payload attestations"),
            proposer: config.proposals.map(Proposer::new),
        }
    }

    pub fn key_loaded(&mut self, pubkey: XMSSPubkey) {
        self.validators.add(pubkey);
    }

    pub fn on_beacon_event(&mut self, event: BeaconEvent<'_>, signs: &mut SignRequests) {
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
            BeaconEvent::AttestationData { id, data } => self.sign_attestations(id, &data, signs),
            BeaconEvent::AggregateAttestation { id, aggregate } => {
                self.sign_aggregate(id, &aggregate, signs)
            }
            BeaconEvent::ProposerDuties { id, duties } => {
                self.schedule.on_proposer_duties(id, &duties, &self.validators, slot)
            }
            BeaconEvent::ProducedBlock { id, block } => {
                let Self { domains, validators, schedule, proposer, .. } = self;
                if let Some(proposer) = proposer {
                    proposer.on_block(id, &block, schedule, validators, domains, signs);
                }
            }
            BeaconEvent::PtcDuties { id, duties } => {
                self.schedule.on_ptc_duties(id, &duties, &self.validators, slot)
            }
            BeaconEvent::PayloadAttestationData { id, data } => {
                self.sign_payload_attestations(id, &data, signs)
            }
            BeaconEvent::Accepted { id, request } => self.on_answered(id, request, true, signs),
            BeaconEvent::Failed { id, request } => self.on_failed(id, request, slot, signs),
            BeaconEvent::NoContent { id, request } => match request {
                BeaconRequest::AttestationData => self.attestations.on_no_data(id),
                BeaconRequest::PayloadAttestationData => self.payload_attestations.on_no_data(id),
                _ => self.on_failed(id, request, slot, signs),
            },
            BeaconEvent::PayloadAvailable { slot: payload_slot } => {
                // The spec asks for the PTC vote as soon as the payload is
                // seen; the due time is only the deadline.
                if payload_slot == slot {
                    self.payload_attestations.due(slot);
                }
            }
            BeaconEvent::Head(head) => {
                silver_log::debug!(slot = head.slot, block = %hex::encode(head.block), "head");
                self.schedule.on_head(&head);
                if head.slot == slot {
                    self.attestations.due(slot);
                }
            }
        }
    }

    /// Publishes each signature as it is answered; `requests` joins those of
    /// one kind and slot into one request.
    pub fn on_signed(
        &mut self,
        request: &SignRequest,
        answer: &SignAnswer,
        requests: &mut BeaconRequests,
    ) {
        let slot = request.slot;
        let signature = match answer {
            SignAnswer::Signature(signature) => Some(signature),
            SignAnswer::VrfProof(_) | SignAnswer::Refused => None,
        };
        match request.purpose {
            SignPurpose::Attestation { validator_index, committee_index } => {
                if let (Some(signature), Some(data)) =
                    (signature, self.attestations.signed_json(slot))
                {
                    requests.publish_attestation(
                        slot,
                        committee_index,
                        validator_index,
                        data,
                        signature,
                    );
                }
            }
            SignPurpose::Aggregate { validator_index, served } => {
                if let (Some(signature), Some(proved)) =
                    (signature, self.aggregations.served(slot, served))
                {
                    requests.publish_aggregate(slot, validator_index, proved, signature);
                }
            }
            SignPurpose::PayloadAttestation { validator_index } => {
                if let (Some(signature), Some(data)) =
                    (signature, self.payload_attestations.signed_json(slot))
                {
                    requests.publish_payload_attestation(slot, validator_index, data, signature);
                }
            }
            SignPurpose::ProposerPreferences { validator_index, dependent_root } => {
                if let (Some(signature), Some(proposer)) = (signature, &self.proposer) {
                    proposer.publish_preferences(
                        slot,
                        validator_index,
                        &dependent_root,
                        signature,
                        requests,
                    );
                }
            }
            SignPurpose::Randao { validator_index } => {
                let proof = match answer {
                    SignAnswer::VrfProof(proof) => Some(proof),
                    SignAnswer::Signature(_) | SignAnswer::Refused => None,
                };
                self.schedule.on_randao(slot, validator_index, proof);
            }
            SignPurpose::Block => {
                if let Some(proposer) = &mut self.proposer {
                    proposer.on_block_signed(slot, signature, requests);
                }
            }
            SignPurpose::Envelope => {
                if let Some(proposer) = &mut self.proposer {
                    proposer.on_envelope_signed(slot, signature, requests);
                }
            }
        }
    }

    pub fn current_slot(&self) -> Option<u64> {
        self.clock.as_ref().map(DutyClock::current_slot)
    }

    pub fn on_tick(
        &mut self,
        genesis_time: u64,
        requests: &mut BeaconRequests,
        signs: &mut SignRequests,
    ) {
        if self.clock.is_none() {
            self.clock = DutyClock::start(genesis_time, self.slot_duration_ms);
        }
        let Some(clock) = &mut self.clock else { return };
        let slot = match clock.tick() {
            Some(Tick { slot, phase }) => {
                self.on_phase(slot, phase, requests);
                slot
            }
            None => clock.current_slot(),
        };

        self.schedule.request_due(slot, &self.validators, requests);
        self.schedule.subscriptions_due(slot, requests);
        self.fetch_due_data(slot, requests);

        let Self { domains, validators, schedule, proposer, .. } = self;
        schedule.ask_randao(|duty| {
            signs.vrf_proof(duty.slot, duty.validator_index, validators.pubkey(duty.key))
        });
        if let Some(proposer) = proposer {
            proposer.prepare(slot, validators, requests);
            proposer.send_preferences(slot, schedule, validators, domains, signs);
            proposer.propose(slot, schedule, requests);
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
                        proposer.prepare_again();
                    }
                    proposer.slot_started(slot);
                }
            }
            DutyPhase::AttestationDue => self.attestations.due(slot),
            DutyPhase::AggregateDue { position } => self.fetch_aggregates(slot, position, requests),
            DutyPhase::PayloadAttestationDue => self.payload_attestations.due(slot),
        }
    }

    /// A round due with no duties yet waits within its slot for them.
    fn fetch_due_data(&mut self, slot: u64, requests: &mut BeaconRequests) {
        if self.attestations.is_due(slot) && !self.schedule.attesters_at(slot).is_empty() {
            self.attestations.fetching(requests.attestation_data(slot));
        }
        if self.payload_attestations.is_due(slot) && !self.schedule.ptc_at(slot).is_empty() {
            self.payload_attestations.fetching(requests.payload_attestation_data(slot));
        }
    }

    fn on_answered(
        &mut self,
        id: RequestId,
        request: BeaconRequest,
        accepted: bool,
        signs: &mut SignRequests,
    ) {
        let Self { domains, validators, schedule, proposer, .. } = self;
        match (request, proposer) {
            (BeaconRequest::Publish(batch), _) => match accepted {
                true => silver_log::info!(
                    slot = batch.slot,
                    count = batch.count,
                    kind = ?batch.kind,
                    "published"
                ),
                false => silver_log::warn!(
                    slot = batch.slot,
                    count = batch.count,
                    kind = ?batch.kind,
                    "not published"
                ),
            },
            (BeaconRequest::CommitteeSubscriptions, _) if accepted => schedule.on_subscribed(id),
            (BeaconRequest::PrepareProposers, Some(proposer)) if accepted => {
                proposer.on_prepared(id)
            }
            (BeaconRequest::PublishBlock, Some(proposer)) => {
                proposer.on_block_answered(id, accepted, validators, domains, signs)
            }
            (BeaconRequest::PublishEnvelope { .. }, Some(proposer)) => {
                proposer.on_envelope_answered(id, accepted)
            }
            _ => {}
        }
    }

    fn on_failed(
        &mut self,
        id: RequestId,
        request: BeaconRequest,
        slot: u64,
        signs: &mut SignRequests,
    ) {
        match request {
            BeaconRequest::ValidatorIndices => self.validators.on_failed(id),
            BeaconRequest::AttesterDuties |
            BeaconRequest::ProposerDuties |
            BeaconRequest::PtcDuties => self.schedule.on_failed(id, slot),
            BeaconRequest::CommitteeSubscriptions => self.schedule.on_subscription_failed(id, slot),
            BeaconRequest::AttestationData => self.attestations.on_fetch_failed(id),
            BeaconRequest::PayloadAttestationData => self.payload_attestations.on_fetch_failed(id),
            BeaconRequest::AggregateAttestation => {}
            BeaconRequest::PrepareProposers => {
                if let Some(proposer) = &mut self.proposer {
                    proposer.on_prepare_failed(id, slot);
                }
            }
            BeaconRequest::ProduceBlock => {
                if let Some(proposer) = &mut self.proposer {
                    proposer.on_produce_failed(id);
                }
            }
            BeaconRequest::Publish(_) |
            BeaconRequest::PublishBlock |
            BeaconRequest::PublishEnvelope { .. } => self.on_answered(id, request, false, signs),
        }
    }

    /// Duties are kept only for keys with an index.
    fn indices_learned(&mut self) {
        self.schedule.refetch_all();
        if let Some(proposer) = &mut self.proposer {
            proposer.prepare_again();
        }
    }

    fn sign_attestations(
        &mut self,
        id: RequestId,
        data: &AttestationData<'_>,
        signs: &mut SignRequests,
    ) {
        let Self { domains, validators, schedule, attestations, .. } = self;
        attestations.on_data(id, data.parse(), |slot, data| {
            let view = AttestationDataView::new(data);
            let epoch = slot / SLOTS_PER_EPOCH;
            if view.slot() != slot || view.target_epoch() != epoch {
                return Err("attestation data for another slot");
            }
            let leaf = attestation_leaf(epoch).ok_or("no XMSS leaf for the epoch")?;
            let data_root = hash_attestation_data(data);
            let signing_root = domains.signing_root(DOMAIN_BEACON_ATTESTER, slot, &data_root);
            for duty in schedule.attesters_at(slot) {
                let purpose = SignPurpose::Attestation {
                    validator_index: duty.validator_index,
                    committee_index: duty.committee_index,
                };
                signs.sign(slot, purpose, validators.pubkey(duty.key), leaf, signing_root);
            }
            Ok(data_root)
        });
    }

    fn sign_payload_attestations(
        &mut self,
        id: RequestId,
        data: &PayloadAttestationData<'_>,
        signs: &mut SignRequests,
    ) {
        let Self { domains, validators, schedule, payload_attestations, .. } = self;
        payload_attestations.on_data(id, data.parse(), |slot, data| {
            if PayloadAttestationDataView::slot(data) != slot {
                return Err("payload attestation data for another slot");
            }
            let leaf = SlotDuty::PtcAttester.leaf(slot).ok_or("no XMSS leaf for the slot")?;
            let data_root = PayloadAttestationDataView::hash_tree_root(data);
            let signing_root = domains.signing_root(DOMAIN_PTC_ATTESTER, slot, &data_root);
            for duty in schedule.ptc_at(slot) {
                let purpose =
                    SignPurpose::PayloadAttestation { validator_index: duty.validator_index };
                signs.sign(slot, purpose, validators.pubkey(duty.key), leaf, signing_root);
            }
            Ok(data_root)
        });
    }

    /// Fetches the aggregate of what this slot attested, once per aggregator
    /// at `position`, which the node proved for that position's cutoff.
    fn fetch_aggregates(&mut self, slot: u64, position: u8, requests: &mut BeaconRequests) {
        let Some(data_root) = self.attestations.signed_root(slot) else { return };
        let fetches = self.schedule.aggregators_at(slot, position).map(|duty| {
            let id =
                requests.aggregate_attestation(slot, duty.committee_index, position, data_root);
            (id, *duty)
        });
        self.aggregations.fetching(slot, fetches);
    }

    fn sign_aggregate(
        &mut self,
        id: RequestId,
        aggregate: &Aggregate<'_>,
        signs: &mut SignRequests,
    ) {
        let Some((aggregator, root, served)) = self.aggregations.on_aggregate(id, aggregate) else {
            return;
        };
        let slot = aggregator.slot;
        let Some(leaf) = SlotDuty::AggregateAndProof.leaf(slot) else {
            silver_log::error!(slot, "no XMSS leaf for aggregates");
            return;
        };
        let signing_root = self.domains.signing_root(DOMAIN_AGGREGATE_AND_PROOF, slot, &root);
        let purpose =
            SignPurpose::Aggregate { validator_index: aggregator.validator_index, served };
        signs.sign(slot, purpose, self.validators.pubkey(aggregator.key), leaf, signing_root);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use silver_beacon_state_data::{DOMAIN_BEACON_BUILDER, bls::DOMAIN_BEACON_PROPOSER};
    use silver_chain_spec::SpecConfig;
    use silver_common::{
        block_root_pq,
        ssz_hash::{compute_domain, compute_signing_root},
        ssz_hash_pq::hash_tree_root_aggregate_and_proof,
        ssz_view::{
            ATTESTATION_DATA_SIZE, ATTESTATION_PQ_FIXED, ExecutionPayloadEnvelopeView,
            PAYLOAD_ATTESTATION_DATA_SIZE, VRF_PROOF_SIZE, XMSS_SIGNATURE_SIZE,
        },
        test_util::{SynthBid, SynthBlock, empty_signed_envelope_pq},
        vc_spine::KeyWork,
    };

    use super::*;
    use crate::{
        beacon_link::{AttesterDuties, ProducedBlock, SlotDuties, ValidatorIndices},
        config::{ProposalConfig, SignerConfig},
    };

    const SLOT: u64 = 65;
    const FEE_RECIPIENT: [u8; 20] = [0xfe; 20];
    const PUBKEY_A: XMSSPubkey = [0xaa; 32];
    const PUBKEY_B: XMSSPubkey = [0xbb; 32];
    const GVR: [u8; 32] = [0x9e; 32];

    struct Harness {
        duties: Duties,
        requests: BeaconRequests,
        signs: SignRequests,
    }

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn pubkey_hex(pubkey: XMSSPubkey) -> String {
        format!("0x{}", hex::encode(pubkey))
    }

    fn signature_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; XMSS_SIGNATURE_SIZE]))
    }

    fn leaked(value: Value) -> &'static [u8] {
        value.to_string().leak().as_bytes()
    }

    fn signing_root(domain_type: u32, root: &[u8; 32]) -> [u8; 32] {
        let version = SpecConfig::mainnet().fork_version_at(SLOT / SLOTS_PER_EPOCH);
        compute_signing_root(root, &compute_domain(domain_type, version, &GVR))
    }

    impl Harness {
        /// Two keys, indices 7 and 9, attesting in committees 3 and 4 at
        /// `SLOT`. Index 7 is the first of its committee's aggregators.
        fn attesters() -> Self {
            let config = Config {
                spec: SpecConfig::mainnet(),
                genesis_validators_root: GVR,
                beacon_node: "http://localhost:5052".into(),
                signer: SignerConfig::default(),
                signer_tiles: 1,
                proposals: Some(ProposalConfig {
                    fee_recipient: FEE_RECIPIENT,
                    graffiti: [0x67; 32],
                    gas_limit: 60_000_000,
                }),
            };
            let mut this = Self {
                duties: Duties::new(&config, vec![PUBKEY_A, PUBKEY_B]),
                requests: BeaconRequests::default(),
                signs: SignRequests::default(),
            };

            this.duties.validators.request_indices(0, &mut this.requests);
            let id = this.sent()[0].0;
            let indices = json!({"data": [
                {"index": "7", "validator": {"pubkey": pubkey_hex(PUBKEY_A)}},
                {"index": "9", "validator": {"pubkey": pubkey_hex(PUBKEY_B)}},
            ]});
            this.event(BeaconEvent::ValidatorIndices {
                id,
                validators: ValidatorIndices(leaked(indices)),
            });

            this.duties.schedule.roll(SLOT / SLOTS_PER_EPOCH);
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
            let mut aggregator = duty(PUBKEY_A, "7", "3");
            aggregator["is_aggregator"] = true.into();
            aggregator["aggregator_position"] = "1".into();
            let answer = json!({
                "dependent_root": hex32(0xd0),
                "data": [aggregator, duty(PUBKEY_B, "9", "4")],
            });
            let id = this.fetched("/eth/v1/validator/duties/attester/2");
            this.event(BeaconEvent::AttesterDuties { id, duties: AttesterDuties(leaked(answer)) });
            this
        }

        fn event(&mut self, event: BeaconEvent<'_>) {
            self.duties.on_beacon_event(event, &mut self.signs);
        }

        /// Requests the schedule has due, and the id of the one at `path`.
        fn fetched(&mut self, path: &str) -> RequestId {
            let Self { duties, requests, .. } = self;
            duties.schedule.request_due(SLOT, &duties.validators, requests);
            let sent = self.sent();
            sent.iter().find(|(_, sent, _)| sent == path).expect("fetched").0
        }

        fn sent(&mut self) -> Vec<(RequestId, String, Vec<u8>)> {
            let mut sent = Vec::new();
            self.requests
                .drain(|id, _, path, body| sent.push((id, path.to_owned(), body.to_vec())));
            sent
        }

        fn sent_json(&mut self) -> Vec<(RequestId, String, Value)> {
            let parse = |body: Vec<u8>| {
                if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() }
            };
            self.sent().into_iter().map(|(id, path, body)| (id, path, parse(body))).collect()
        }

        fn signing(&mut self) -> Vec<SignRequest> {
            let mut queued = Vec::new();
            self.signs.drain(|request| queued.push(request));
            queued
        }

        fn sign(&mut self, request: &SignRequest, byte: u8) {
            let signature = [byte; XMSS_SIGNATURE_SIZE];
            let answer = SignAnswer::Signature(signature);
            self.duties.on_signed(request, &answer, &mut self.requests);
        }

        fn refuse(&mut self, request: &SignRequest) {
            self.duties.on_signed(request, &SignAnswer::Refused, &mut self.requests);
        }

        fn accept(&mut self, id: RequestId, request: BeaconRequest) {
            self.event(BeaconEvent::Accepted { id, request });
        }

        /// Marks `SLOT` due, answers its data request with `data`, and returns
        /// the sign requests that follow.
        fn attest(&mut self, data: Value) -> Vec<SignRequest> {
            self.duties.attestations.due(SLOT);
            self.duties.fetch_due_data(SLOT, &mut self.requests);
            let asked = self.sent();
            assert_eq!(asked.len(), 1);
            assert_eq!(asked[0].1, "/eth/v1/validator/attestation_data?slot=65&committee_index=0");
            let data = AttestationData(leaked(json!({"data": data})));
            self.event(BeaconEvent::AttestationData { id: asked[0].0, data });
            self.signing()
        }

        fn answer_slot_duties(&mut self, path: &str, answer: Value) {
            self.duties.schedule.refetch_all();
            let id = self.fetched(path);
            let duties = SlotDuties(leaked(answer));
            let event = if path.contains("ptc") {
                BeaconEvent::PtcDuties { id, duties }
            } else {
                BeaconEvent::ProposerDuties { id, duties }
            };
            self.event(event);
        }

        fn proposer(&mut self) -> &mut Proposer {
            self.duties.proposer.as_mut().unwrap()
        }

        fn propose(&mut self) {
            let Self { duties, requests, .. } = self;
            duties.proposer.as_mut().unwrap().propose(SLOT, &duties.schedule, requests);
        }

        /// Our proposal at `SLOT`, its RANDAO reveal proved, and the slot
        /// started.
        fn proposal(&mut self) {
            self.answer_slot_duties("/eth/v2/validator/duties/proposer/2", proposer_duties());
            let Self { duties, signs, .. } = self;
            let Duties { schedule, validators, .. } = duties;
            schedule.ask_randao(|duty| {
                signs.vrf_proof(duty.slot, duty.validator_index, validators.pubkey(duty.key))
            });
            let reveal = self.signing();
            assert_eq!(reveal.len(), 1, "only our proposal");
            assert_eq!((reveal[0].slot, reveal[0].work), (SLOT, KeyWork::VrfProof));
            let proof = [0x7a; VRF_PROOF_SIZE];
            let answer = SignAnswer::VrfProof(proof);
            self.duties.on_signed(&reveal[0], &answer, &mut self.requests);
            self.proposer().slot_started(SLOT);
        }
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

    /// Index 7 proposes at `SLOT`; index 100 is not ours.
    fn proposer_duties() -> Value {
        json!({"dependent_root": hex32(0xd0), "data": [
            {"pubkey": pubkey_hex(PUBKEY_A), "validator_index": "7", "slot": SLOT.to_string()},
            {"pubkey": pubkey_hex([0xcc; 32]), "validator_index": "100", "slot": "66"},
        ]})
    }

    const EPOCH: u64 = SLOT / SLOTS_PER_EPOCH;

    #[test]
    fn each_duty_is_signed_at_its_epoch_leaf_and_published_together() {
        let mut harness = Harness::attesters();
        let signing = harness.attest(data_json(SLOT, EPOCH));

        let mut ssz = [0; ATTESTATION_DATA_SIZE];
        ssz[0..8].copy_from_slice(&SLOT.to_le_bytes());
        ssz[16..48].fill(0x11);
        ssz[48..56].copy_from_slice(&1u64.to_le_bytes());
        ssz[56..88].fill(0x22);
        ssz[88..96].copy_from_slice(&EPOCH.to_le_bytes());
        ssz[96..128].fill(0x33);
        let work = KeyWork::Sign {
            leaf_index: attestation_leaf(EPOCH).unwrap(),
            signing_root: signing_root(DOMAIN_BEACON_ATTESTER, &hash_attestation_data(&ssz)),
        };
        let asked = signing.iter().map(|request| (request.pubkey, request.purpose));
        assert!(asked.eq([
            (PUBKEY_A, SignPurpose::Attestation { validator_index: 7, committee_index: 3 }),
            (PUBKEY_B, SignPurpose::Attestation { validator_index: 9, committee_index: 4 }),
        ]));
        assert!(signing.iter().all(|request| request.work == work && request.slot == SLOT));

        harness.sign(&signing[0], 0xc1);
        harness.sign(&signing[1], 0xc2);
        let publish = harness.sent_json();
        assert_eq!(publish.len(), 1, "answered together, published together");
        assert_eq!(publish[0].1, "/eth/v2/beacon/pool/attestations");
        let entry = |attester: &str, committee: &str, byte| {
            json!({
                "committee_index": committee,
                "attester_index": attester,
                "data": data_json(SLOT, EPOCH),
                "signature": signature_hex(byte),
            })
        };
        assert_eq!(publish[0].2, json!([entry("7", "3", 0xc1), entry("9", "4", 0xc2)]));

        harness.duties.attestations.due(SLOT);
        harness.duties.fetch_due_data(SLOT, &mut harness.requests);
        assert!(harness.sent().is_empty(), "fetched once per slot");
    }

    #[test]
    fn refused_signature_drops_only_its_attestation() {
        let mut harness = Harness::attesters();
        let signing = harness.attest(data_json(SLOT, EPOCH));
        harness.refuse(&signing[0]);
        harness.sign(&signing[1], 0xc2);
        let publish = harness.sent_json();
        let entries = publish[0].2.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["attester_index"], "9");
    }

    #[test]
    fn nothing_signed_publishes_nothing() {
        let mut harness = Harness::attesters();
        for request in &harness.attest(data_json(SLOT, EPOCH)) {
            harness.refuse(request);
        }
        assert!(harness.sent().is_empty());
    }

    #[test]
    fn signature_for_a_past_slot_is_not_published() {
        let mut harness = Harness::attesters();
        let signing = harness.attest(data_json(SLOT, EPOCH));
        harness.duties.attestations.due(SLOT + 1);
        harness.sign(&signing[0], 0xc1);
        assert!(harness.sent().is_empty());
    }

    #[test]
    fn data_for_another_slot_is_not_signed() {
        assert!(Harness::attesters().attest(data_json(SLOT + 1, EPOCH)).is_empty());
        assert!(Harness::attesters().attest(data_json(SLOT, EPOCH + 1)).is_empty());
    }

    #[test]
    fn a_slot_the_node_has_no_data_for_signs_nothing() {
        let mut harness = Harness::attesters();
        harness.duties.attestations.due(SLOT);
        harness.duties.fetch_due_data(SLOT, &mut harness.requests);
        let id = harness.sent()[0].0;
        harness.event(BeaconEvent::NoContent { id, request: BeaconRequest::AttestationData });
        assert!(harness.signing().is_empty());
        harness.duties.fetch_due_data(SLOT, &mut harness.requests);
        assert!(harness.sent().is_empty(), "the slot's round ended");
    }

    #[test]
    fn slot_without_duties_asks_for_no_data() {
        let mut harness = Harness::attesters();
        harness.duties.attestations.due(SLOT + 1);
        harness.duties.fetch_due_data(SLOT + 1, &mut harness.requests);
        assert!(harness.sent().is_empty());
    }

    #[test]
    fn an_aggregator_subscribes_then_signs_the_proved_aggregate() {
        let mut harness = Harness::attesters();
        harness.duties.schedule.subscriptions_due(SLOT, &mut harness.requests);
        let subscription = harness.sent_json();
        assert_eq!(subscription[0].1, "/eth/v1/validator/beacon_committee_subscriptions");
        let flags =
            subscription[0].2.as_array().unwrap().iter().map(|s| s["is_aggregator"].clone());
        assert!(flags.eq([Value::Bool(true), Value::Bool(false)]));

        for request in &harness.attest(data_json(SLOT, EPOCH)) {
            harness.sign(request, 0xc1);
        }
        harness.sent();

        harness.duties.fetch_aggregates(SLOT, 0, &mut harness.requests);
        assert!(harness.sent().is_empty(), "not its position");
        harness.duties.fetch_aggregates(SLOT, 1, &mut harness.requests);
        let fetch = harness.sent();
        let data = AttestationData(leaked(json!({"data": data_json(SLOT, EPOCH)})));
        let (data, _) = data.parse().unwrap();
        assert_eq!(fetch.len(), 1);
        assert_eq!(
            fetch[0].1,
            format!(
                "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{}&slot=65&committee_index=3&aggregator_position=1",
                hex::encode(hash_attestation_data(&data))
            )
        );

        let aggregate = json!({
            "aggregation_bits": "0x0b",
            "data": data_json(SLOT, EPOCH),
            "committee_bits": "0x0800",
        });
        let proved = json!({"aggregate": aggregate, "proof": "0xc0ffee"});
        let answer = Aggregate(leaked(json!({"version": "pq", "data": proved})));
        harness.event(BeaconEvent::AggregateAttestation { id: fetch[0].0, aggregate: answer });
        let signing = harness.signing();
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].pubkey, PUBKEY_A);
        let attestation =
            [&(ATTESTATION_PQ_FIXED as u32).to_le_bytes()[..], &data, &[0x08, 0x00], &[0x0b]]
                .concat();
        let root = hash_tree_root_aggregate_and_proof(7, &attestation, &[0xc0, 0xff, 0xee]);
        assert_eq!(signing[0].work, KeyWork::Sign {
            leaf_index: SlotDuty::AggregateAndProof.leaf(SLOT).unwrap(),
            signing_root: signing_root(DOMAIN_AGGREGATE_AND_PROOF, &root),
        });

        harness.sign(&signing[0], 0xe1);
        let publish = harness.sent_json();
        assert_eq!(publish.len(), 1);
        assert_eq!(publish[0].1, "/eth/v2/validator/aggregate_and_proofs");
        assert_eq!(
            publish[0].2,
            json!([{
                "message": {"aggregator_index": "7", "aggregate": aggregate, "proof": "0xc0ffee"},
                "signature": signature_hex(0xe1),
            }])
        );
    }

    #[test]
    fn slot_without_own_attestation_aggregates_nothing() {
        let mut harness = Harness::attesters();
        harness.duties.fetch_aggregates(SLOT, 1, &mut harness.requests);
        assert!(harness.sent().is_empty());
    }

    #[test]
    fn known_indices_are_prepared_each_epoch() {
        let mut harness = Harness::attesters();
        let Harness { duties, requests, .. } = &mut harness;
        let Duties { validators, proposer, .. } = duties;
        let proposer = proposer.as_mut().unwrap();
        proposer.prepare(SLOT, validators, requests);
        let prepared = harness.sent_json();
        assert_eq!(prepared[0].1, "/eth/v1/validator/prepare_beacon_proposer");
        let fee_recipient = format!("0x{}", "fe".repeat(20));
        assert_eq!(
            prepared[0].2,
            json!([
                {"validator_index": "7", "fee_recipient": fee_recipient},
                {"validator_index": "9", "fee_recipient": fee_recipient},
            ])
        );

        let prepare = |harness: &mut Harness, slot| {
            let Harness { duties, requests, .. } = harness;
            duties.proposer.as_mut().unwrap().prepare(slot, &duties.validators, requests);
            harness.sent().len()
        };
        harness.accept(prepared[0].0, BeaconRequest::PrepareProposers);
        assert_eq!(prepare(&mut harness, SLOT), 0);
        harness.proposer().prepare_again();
        assert_eq!(prepare(&mut harness, SLOT + 1), 1);
    }

    #[test]
    fn a_payload_seen_in_the_slot_starts_the_ptc_vote_before_its_deadline() {
        let mut harness = Harness::attesters();
        harness.answer_slot_duties(
            "/eth/v1/validator/duties/ptc/2",
            json!({"dependent_root": hex32(0xd0), "data": [
                {"pubkey": pubkey_hex(PUBKEY_A), "validator_index": "7", "slot": SLOT.to_string()},
            ]}),
        );
        harness.duties.clock = DutyClock::start(0, 12_000);
        let now = harness.duties.clock.as_ref().unwrap().current_slot();
        harness.event(BeaconEvent::PayloadAvailable { slot: now - 1 });
        assert!(!harness.duties.payload_attestations.is_due(now - 1), "a past slot's payload");
        harness.event(BeaconEvent::PayloadAvailable { slot: now });
        assert!(harness.duties.payload_attestations.is_due(now));
    }

    #[test]
    fn ptc_members_sign_the_served_payload_attestation_data() {
        let mut harness = Harness::attesters();
        harness.answer_slot_duties(
            "/eth/v1/validator/duties/ptc/2",
            json!({"dependent_root": hex32(0xd0), "data": [
                {"pubkey": pubkey_hex(PUBKEY_A), "validator_index": "7", "slot": SLOT.to_string()},
            ]}),
        );

        harness.duties.payload_attestations.due(SLOT);
        harness.duties.fetch_due_data(SLOT, &mut harness.requests);
        let fetch = harness.sent();
        assert_eq!(fetch[0].1, "/eth/v1/validator/payload_attestation_data?slot=65");
        let data = json!({
            "beacon_block_root": hex32(0x11),
            "slot": "65",
            "payload_present": true,
            "blob_data_available": false,
        });
        let answer = PayloadAttestationData(leaked(json!({"version": "pq", "data": data})));
        harness.event(BeaconEvent::PayloadAttestationData { id: fetch[0].0, data: answer });

        let signing = harness.signing();
        let mut ssz = [0; PAYLOAD_ATTESTATION_DATA_SIZE];
        ssz[..32].fill(0x11);
        ssz[32..40].copy_from_slice(&SLOT.to_le_bytes());
        ssz[40] = 1;
        let root = PayloadAttestationDataView::hash_tree_root(&ssz);
        assert_eq!(signing[0].purpose, SignPurpose::PayloadAttestation { validator_index: 7 });
        assert_eq!(signing[0].work, KeyWork::Sign {
            leaf_index: SlotDuty::PtcAttester.leaf(SLOT).unwrap(),
            signing_root: signing_root(DOMAIN_PTC_ATTESTER, &root),
        });

        harness.sign(&signing[0], 0xa1);
        let publish = harness.sent_json();
        assert_eq!(publish[0].1, "/eth/v1/beacon/pool/payload_attestations");
        assert_eq!(
            publish[0].2,
            json!([{"validator_index": "7", "data": data, "signature": signature_hex(0xa1)}])
        );
    }

    #[test]
    fn upcoming_proposals_publish_preferences_signed_once() {
        let mut harness = Harness::attesters();
        harness.answer_slot_duties("/eth/v2/validator/duties/proposer/2", proposer_duties());
        let send = |harness: &mut Harness| {
            let Harness { duties, signs, .. } = harness;
            let Duties { domains, validators, schedule, proposer, .. } = duties;
            let proposer = proposer.as_mut().unwrap();
            proposer.send_preferences(SLOT - 1, schedule, validators, domains, signs);
            harness.signing()
        };

        let signing = send(&mut harness);
        assert_eq!(signing.len(), 1, "only our proposal");
        assert_eq!(signing[0].purpose, SignPurpose::ProposerPreferences {
            validator_index: 7,
            dependent_root: [0xd0; 32],
        });
        let KeyWork::Sign { leaf_index, .. } = signing[0].work else { panic!("a signature") };
        assert_eq!(leaf_index, SlotDuty::ProposerPreferences.leaf(SLOT).unwrap());

        harness.sign(&signing[0], 0xb2);
        let publish = harness.sent_json();
        assert_eq!(publish[0].1, "/eth/v1/validator/proposer_preferences");
        let message = json!({
            "dependent_root": hex32(0xd0),
            "proposal_slot": "65",
            "validator_index": "7",
            "fee_recipient": format!("0x{}", "fe".repeat(20)),
            "target_gas_limit": "60000000",
        });
        assert_eq!(publish[0].2, json!([{"message": message, "signature": signature_hex(0xb2)}]));

        assert!(send(&mut harness).is_empty());
        harness.answer_slot_duties("/eth/v2/validator/duties/proposer/2", proposer_duties());
        assert!(send(&mut harness).is_empty(), "a refetch does not sign the leaf again");
    }

    /// A block produced with its payload, signed by `proposer_index`, and its
    /// envelope.
    fn produced(proposer_index: u64) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        const SIGNED_PQ_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;
        let mut signed_block = SynthBlock::pq(SLOT, SynthBid::new(&[])).into_bytes();
        signed_block[SIGNED_PQ_FIXED + 8..][..8].copy_from_slice(&proposer_index.to_le_bytes());
        let block_root = block_root_pq(&signed_block);
        let mut envelope = empty_signed_envelope_pq(SLOT, block_root).split_off(SIGNED_PQ_FIXED);
        envelope[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let block = &signed_block[SIGNED_PQ_FIXED..];
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let end = 16 + block.len() + envelope.len();
        let contents =
            [&at(16)[..], &at(16 + block.len()), &at(end), &at(end), block, &envelope].concat();
        (contents, block_root, envelope)
    }

    #[test]
    fn proposal_for_another_proposer_is_not_signed() {
        let mut harness = Harness::attesters();
        harness.proposal();
        harness.propose();
        let produce = harness.sent()[0].0;

        let (contents, ..) = produced(8);
        let block = ProducedBlock { payload_included: true, ssz: contents.leak() };
        harness.event(BeaconEvent::ProducedBlock { id: produce, block });
        assert!(harness.signing().is_empty());
        harness.propose();
        assert!(harness.sent().is_empty(), "the slot's proposal ended");
    }

    #[test]
    fn proposal_publishes_the_block_then_signs_and_publishes_its_envelope() {
        let mut harness = Harness::attesters();
        harness.proposal();
        harness.propose();
        let produce = harness.sent();
        assert!(produce[0].1.starts_with("/eth/v4/validator/blocks/65?randao_reveal=0x7a7a"));
        assert!(produce[0].1.ends_with("&include_payload=true"));

        let (contents, block_root, envelope) = produced(7);
        let block = contents[16..contents.len() - envelope.len()].to_vec();
        let produced = ProducedBlock { payload_included: true, ssz: contents.leak() };
        harness.event(BeaconEvent::ProducedBlock { id: produce[0].0, block: produced });

        let signing = harness.signing();
        assert_eq!(signing.len(), 1, "the envelope waits for its block");
        assert_eq!(signing[0].work, KeyWork::Sign {
            leaf_index: SlotDuty::BeaconProposer.leaf(SLOT).unwrap(),
            signing_root: signing_root(DOMAIN_BEACON_PROPOSER, &block_root),
        });
        harness.sign(&signing[0], 0xb1);
        let publish = harness.sent();
        assert_eq!(publish[0].1, "/eth/v2/beacon/blocks");
        let signed_at = (4 + XMSS_SIGNATURE_SIZE) as u32;
        let expected =
            [&signed_at.to_le_bytes()[..], &[0xb1; XMSS_SIGNATURE_SIZE], &block].concat();
        assert_eq!(publish[0].2, expected);

        harness.accept(publish[0].0, BeaconRequest::PublishBlock);
        let signing = harness.signing();
        let envelope_root = ExecutionPayloadEnvelopeView::hash_tree_root_pq(&envelope);
        assert_eq!(signing[0].work, KeyWork::Sign {
            leaf_index: SlotDuty::ExecutionPayloadEnvelope.leaf(SLOT).unwrap(),
            signing_root: signing_root(DOMAIN_BEACON_BUILDER, &envelope_root),
        });
        harness.sign(&signing[0], 0xe1);
        let envelope_publish = harness.sent();
        assert_eq!(envelope_publish[0].1, "/eth/v1/beacon/execution_payload_envelopes");
        let signed_envelope = &envelope_publish[0].2;
        assert_eq!(&signed_envelope[..4], &signed_at.to_le_bytes());
        assert_eq!(&signed_envelope[4..4 + XMSS_SIGNATURE_SIZE], &[0xe1; XMSS_SIGNATURE_SIZE]);
        assert_eq!(&signed_envelope[4 + XMSS_SIGNATURE_SIZE..], &envelope[..]);
    }
}
