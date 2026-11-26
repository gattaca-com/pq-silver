use std::{
    fmt::{self, Arguments, Write as _},
    io::Write as _,
    ops::Range,
    str,
};

use flux_network::http::HttpResponse;
use silver_chain_spec::SpecConfig;
use silver_common::{
    ForkName,
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        AttestationDataView, BEACON_BLOCK_HEADER_SIZE, BUILDER_DEPOSIT_REQUEST_SIZE,
        BUILDER_EXIT_REQUEST_SIZE, BeaconBlockHeaderView, BuilderDepositRequestView,
        BuilderExitRequestView, CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView,
        DEPOSIT_REQUEST_SIZE, DepositRequestView, ExecutionPayloadEnvelopeView,
        ExecutionPayloadView, PAYLOAD_ATTESTATION_DATA_SIZE, PROPOSER_PREFERENCES_SIZE,
        PayloadAttestationDataView, ProposerPreferencesView, WITHDRAWAL_REQUEST_SIZE,
        WITHDRAWAL_SIZE, WithdrawalRequestView, variable_list_items,
    },
};

use crate::{
    beacon_link::{
        endpoint::{JSON, SSZ},
        events::{
            Aggregate, AttestationData, AttesterDuties, BeaconEvent, PayloadAttestationData,
            ProducedBlock, SlotDuties, ValidatorIndices, parse_signature,
        },
    },
    block_contents::GloasBlockContents,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId(u64);

#[derive(Clone, Copy, Debug)]
pub enum BeaconRequest {
    ValidatorIndices,
    AttesterDuties,
    AttestationData,
    PublishAttestations(ForkName),
    CommitteeSubscriptions,
    AggregateAttestation,
    PublishAggregates(ForkName),
    ProposerDuties,
    PrepareProposers,
    ProduceBlock(ForkName),
    PublishBlock(ForkName),
    PtcDuties,
    PayloadAttestationData,
    PublishPayloadAttestations,
    PublishProposerPreferences,
    PublishEnvelope,
    Sign(SignPurpose),
}

impl BeaconRequest {
    pub fn method(self) -> &'static str {
        match self {
            Self::AttestationData |
            Self::AggregateAttestation |
            Self::ProposerDuties |
            Self::PayloadAttestationData => "GET",
            Self::ValidatorIndices |
            Self::AttesterDuties |
            Self::PublishAttestations(_) |
            Self::CommitteeSubscriptions |
            Self::PublishAggregates(_) |
            Self::PrepareProposers |
            Self::PublishBlock(_) |
            Self::ProduceBlock(_) |
            Self::PtcDuties |
            Self::PublishPayloadAttestations |
            Self::PublishProposerPreferences |
            Self::PublishEnvelope |
            Self::Sign(_) => "POST",
        }
    }

    pub fn consensus_version(self) -> Option<&'static str> {
        match self {
            Self::PublishAttestations(fork) |
            Self::PublishAggregates(fork) |
            Self::ProduceBlock(fork) |
            Self::PublishBlock(fork) => Some(fork.name()),
            Self::PublishPayloadAttestations |
            Self::PublishProposerPreferences |
            Self::PublishEnvelope => Some(ForkName::Gloas.name()),
            Self::ValidatorIndices |
            Self::AttesterDuties |
            Self::AttestationData |
            Self::CommitteeSubscriptions |
            Self::AggregateAttestation |
            Self::ProposerDuties |
            Self::PrepareProposers |
            Self::PtcDuties |
            Self::PayloadAttestationData |
            Self::Sign(_) => None,
        }
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::ProduceBlock(_) | Self::PublishBlock(_) | Self::PublishEnvelope => SSZ,
            _ => JSON,
        }
    }

    pub fn extra_header(self) -> Option<(&'static str, &'static str)> {
        matches!(self, Self::PublishEnvelope).then_some(("Eth-Blob-Data-Included", "true"))
    }

    pub fn is_signing(self) -> bool {
        matches!(self, Self::Sign(_))
    }

    pub fn answered<'a>(self, id: RequestId, response: &HttpResponse<'a>) -> BeaconEvent<'a> {
        let body = response.body;
        match self {
            Self::ValidatorIndices => {
                BeaconEvent::ValidatorIndices { id, validators: ValidatorIndices(body) }
            }
            Self::AttesterDuties => {
                BeaconEvent::AttesterDuties { id, duties: AttesterDuties(body) }
            }
            Self::AttestationData => {
                BeaconEvent::AttestationData { id, data: AttestationData(body) }
            }
            Self::AggregateAttestation => {
                BeaconEvent::AggregateAttestation { id, aggregate: Aggregate(body) }
            }
            Self::ProposerDuties => BeaconEvent::ProposerDuties { id, duties: SlotDuties(body) },
            Self::PtcDuties => BeaconEvent::PtcDuties { id, duties: SlotDuties(body) },
            Self::PayloadAttestationData => {
                BeaconEvent::PayloadAttestationData { id, data: PayloadAttestationData(body) }
            }
            Self::ProduceBlock(_) => {
                let payload_included = response
                    .header("Eth-Execution-Payload-Included")
                    .is_some_and(|got| got.eq_ignore_ascii_case(b"true"));
                let block = ProducedBlock { payload_included, ssz: body };
                BeaconEvent::ProducedBlock { id, block }
            }
            Self::PublishAttestations(_) |
            Self::CommitteeSubscriptions |
            Self::PublishAggregates(_) |
            Self::PrepareProposers |
            Self::PublishBlock(_) |
            Self::PublishPayloadAttestations |
            Self::PublishProposerPreferences |
            Self::PublishEnvelope => BeaconEvent::Accepted { id, request: self },
            Self::Sign(purpose) => match parse_signature(body) {
                Some(signature) => BeaconEvent::Signed { id, purpose, signature },
                None => {
                    silver_log::warn!(?purpose, "malformed web3signer signature");
                    BeaconEvent::Failed { id, request: self }
                }
            },
        }
    }
}

/// What a web3signer signature is for, so its answer finds its duty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPurpose {
    Attestation,
    SelectionProof,
    Aggregate,
    Randao,
    Block,
    PayloadAttestation,
    ProposerPreferences,
    Envelope,
}

pub struct SignedAttestation {
    pub committee_index: u64,
    pub attester_index: u64,
    pub signature: [u8; 96],
}

pub struct CommitteeSubscription {
    pub validator_index: u64,
    pub committee_index: u64,
    pub committees_at_slot: u64,
    pub slot: u64,
    pub is_aggregator: bool,
}

pub struct IndexedSignature {
    pub validator_index: u64,
    pub signature: [u8; 96],
}

pub struct SignedPreferences {
    pub message: [u8; PROPOSER_PREFERENCES_SIZE],
    pub signature: [u8; 96],
}

pub struct SignedAggregate<'a> {
    pub aggregator_index: u64,
    /// The aggregate's JSON object as the beacon node served it.
    pub aggregate: &'a str,
    pub selection_proof: [u8; 96],
    pub signature: [u8; 96],
}

/// web3signer's `Fork`: the fork in force at the signed epoch.
pub struct ForkInfo {
    pub previous_version: [u8; 4],
    pub current_version: [u8; 4],
    pub epoch: u64,
    pub genesis_validators_root: [u8; 32],
}

impl ForkInfo {
    /// The fork in force at `epoch`, as a beacon state's `fork` field holds it.
    pub fn new(spec: &SpecConfig, epoch: u64, genesis_validators_root: [u8; 32]) -> Self {
        let fork_epoch = spec.fork_epoch(spec.fork_at(epoch));
        let current_version = spec.fork_version_at(epoch);
        let previous_version = fork_epoch
            .checked_sub(1)
            .map_or(current_version, |before| spec.fork_version_at(before));
        Self { previous_version, current_version, epoch: fork_epoch, genesis_validators_root }
    }
}

/// A sign body written once and shared by every key's request; valid until the
/// next drain.
#[derive(Clone)]
pub struct SignBody(Range<usize>);

struct QueuedRequest {
    id: RequestId,
    request: BeaconRequest,
    path: Range<usize>,
    body: Range<usize>,
}

/// Paths and bodies are written into two buffers reused across loops.
#[derive(Default)]
pub struct BeaconRequests {
    next_id: u64,
    queued: Vec<QueuedRequest>,
    paths: String,
    bodies: Vec<u8>,
}

impl BeaconRequests {
    pub fn validator_indices<'a>(
        &mut self,
        pubkeys: impl IntoIterator<Item = &'a [u8; 48]>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/beacon/states/head/validators"));
        let start = self.bodies.len();
        self.bodies.extend_from_slice(b"{\"ids\":");
        self.push_array(pubkeys, |this, pubkey| this.push_hex(pubkey));
        self.bodies.push(b'}');
        self.push(BeaconRequest::ValidatorIndices, path, start)
    }

    pub fn attester_duties(
        &mut self,
        epoch: u64,
        validator_indices: impl IntoIterator<Item = u64>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/duties/attester/{epoch}"));
        self.duties(BeaconRequest::AttesterDuties, path, validator_indices)
    }

    /// Electra on: one attestation data serves every committee of the slot.
    pub fn attestation_data(&mut self, slot: u64) -> RequestId {
        let path = self
            .path(format_args!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=0"));
        let start = self.bodies.len();
        self.push(BeaconRequest::AttestationData, path, start)
    }

    pub fn publish_attestations(
        &mut self,
        fork: ForkName,
        data: AttestationDataView<'_>,
        attestations: impl IntoIterator<Item = SignedAttestation>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v2/beacon/pool/attestations"));
        let start = self.bodies.len();
        let mut data_json = None;
        self.push_array(attestations, |this, attestation| {
            write!(
                this.bodies,
                "{{\"committee_index\":\"{}\",\"attester_index\":\"{}\",\"data\":",
                attestation.committee_index, attestation.attester_index
            )
            .expect("writes to a Vec");
            match data_json.clone() {
                Some(written) => this.bodies.extend_from_within(written),
                None => {
                    let at = this.bodies.len();
                    this.push_attestation_data(data);
                    data_json = Some(at..this.bodies.len());
                }
            }
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(&attestation.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishAttestations(fork), path, start)
    }

    pub fn committee_subscriptions(
        &mut self,
        subscriptions: impl IntoIterator<Item = CommitteeSubscription>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/beacon_committee_subscriptions"));
        let start = self.bodies.len();
        self.push_array(subscriptions, |this, sub| {
            write!(
                this.bodies,
                "{{\"validator_index\":\"{}\",\"committee_index\":\"{}\",\"committees_at_slot\":\"{}\",\"slot\":\"{}\",\"is_aggregator\":{}}}",
                sub.validator_index, sub.committee_index, sub.committees_at_slot, sub.slot, sub.is_aggregator
            )
            .expect("writes to a Vec");
        });
        self.push(BeaconRequest::CommitteeSubscriptions, path, start)
    }

    pub fn aggregate_attestation(
        &mut self,
        slot: u64,
        committee_index: u64,
        attestation_data_root: &[u8; 32],
    ) -> RequestId {
        let root = Hex(attestation_data_root);
        let path = self.path(format_args!(
            "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{root}&slot={slot}&committee_index={committee_index}"
        ));
        let start = self.bodies.len();
        self.push(BeaconRequest::AggregateAttestation, path, start)
    }

    pub fn publish_aggregates<'a>(
        &mut self,
        fork: ForkName,
        aggregates: impl IntoIterator<Item = SignedAggregate<'a>>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v2/validator/aggregate_and_proofs"));
        let start = self.bodies.len();
        self.push_array(aggregates, |this, signed| {
            this.bodies.extend_from_slice(b"{\"message\":");
            this.push_aggregate_and_proof(
                signed.aggregator_index,
                signed.aggregate,
                &signed.selection_proof,
            );
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(&signed.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishAggregates(fork), path, start)
    }

    pub fn proposer_duties(&mut self, epoch: u64) -> RequestId {
        let path = self.path(format_args!("/eth/v2/validator/duties/proposer/{epoch}"));
        let start = self.bodies.len();
        self.push(BeaconRequest::ProposerDuties, path, start)
    }

    pub fn prepare_proposers(
        &mut self,
        fee_recipient: &[u8; 20],
        validator_indices: impl IntoIterator<Item = u64>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/prepare_beacon_proposer"));
        let start = self.bodies.len();
        self.push_array(validator_indices, |this, index| {
            write!(this.bodies, "{{\"validator_index\":\"{index}\",\"fee_recipient\":")
                .expect("writes to a Vec");
            this.push_hex(fee_recipient);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PrepareProposers, path, start)
    }

    pub fn produce_block(
        &mut self,
        fork: ForkName,
        slot: u64,
        randao_reveal: &[u8; 96],
        graffiti: &[u8; 32],
    ) -> RequestId {
        const LOCAL_ONLY_BOOST: u64 = 0;
        let (randao, graffiti) = (Hex(randao_reveal), Hex(graffiti));
        let start = self.bodies.len();
        let empty_entries_at = 8 + 8 + 4u32;
        self.bodies.extend_from_slice(&0u64.to_le_bytes());
        self.bodies.extend_from_slice(&LOCAL_ONLY_BOOST.to_le_bytes());
        self.bodies.extend_from_slice(&empty_entries_at.to_le_bytes());
        let path = self.path(format_args!(
            "/eth/v4/validator/blocks/{slot}?randao_reveal=0x{randao}&graffiti=0x{graffiti}&include_payload=true"
        ));
        self.push(BeaconRequest::ProduceBlock(fork), path, start)
    }

    pub fn publish_block(
        &mut self,
        fork: ForkName,
        payload_included: bool,
        produced: &[u8],
        signature: &[u8; 96],
    ) -> RequestId {
        const SIGNED_BLOCK_FIXED: usize = 4 + 96;
        let path = self.path(format_args!("/eth/v2/beacon/blocks"));
        let start = self.bodies.len();
        let block = match payload_included {
            true => GloasBlockContents::parse(produced).expect("checked when served").block,
            false => produced,
        };
        self.bodies.extend_from_slice(&(SIGNED_BLOCK_FIXED as u32).to_le_bytes());
        self.bodies.extend_from_slice(signature);
        self.bodies.extend_from_slice(block);
        self.push(BeaconRequest::PublishBlock(fork), path, start)
    }

    pub fn publish_envelope(&mut self, produced: &[u8], signature: &[u8; 96]) -> RequestId {
        const SIGNED_ENVELOPE_FIXED: usize = 4 + 96;
        let path = self.path(format_args!("/eth/v1/beacon/execution_payload_envelopes"));
        let start = self.bodies.len();
        let contents = GloasBlockContents::parse(produced).expect("checked when served");
        let proofs_at = 3 * 4 + SIGNED_ENVELOPE_FIXED + contents.envelope.len();
        let blobs_at = proofs_at + contents.kzg_proofs.len();
        for offset in [3 * 4, proofs_at, blobs_at] {
            self.bodies.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        self.bodies.extend_from_slice(&(SIGNED_ENVELOPE_FIXED as u32).to_le_bytes());
        self.bodies.extend_from_slice(signature);
        self.bodies.extend_from_slice(contents.envelope);
        self.bodies.extend_from_slice(contents.kzg_proofs);
        self.bodies.extend_from_slice(contents.blobs);
        self.push(BeaconRequest::PublishEnvelope, path, start)
    }

    pub fn ptc_duties(
        &mut self,
        epoch: u64,
        validator_indices: impl IntoIterator<Item = u64>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/duties/ptc/{epoch}"));
        self.duties(BeaconRequest::PtcDuties, path, validator_indices)
    }

    pub fn payload_attestation_data(&mut self, slot: u64) -> RequestId {
        let path =
            self.path(format_args!("/eth/v1/validator/payload_attestation_data?slot={slot}"));
        let start = self.bodies.len();
        self.push(BeaconRequest::PayloadAttestationData, path, start)
    }

    pub fn publish_payload_attestations(
        &mut self,
        data: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE],
        attestations: impl IntoIterator<Item = IndexedSignature>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/beacon/pool/payload_attestations"));
        let start = self.bodies.len();
        self.push_array(attestations, |this, attestation| {
            write!(
                this.bodies,
                "{{\"validator_index\":\"{}\",\"data\":",
                attestation.validator_index
            )
            .expect("writes to a Vec");
            this.push_payload_attestation_data(data);
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(&attestation.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishPayloadAttestations, path, start)
    }

    pub fn publish_proposer_preferences(
        &mut self,
        preferences: impl IntoIterator<Item = SignedPreferences>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/proposer_preferences"));
        let start = self.bodies.len();
        self.push_array(preferences, |this, signed| {
            this.bodies.extend_from_slice(b"{\"message\":");
            this.push_preferences(&signed.message);
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(&signed.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishProposerPreferences, path, start)
    }

    pub fn attestation_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        data: AttestationDataView<'_>,
    ) -> SignBody {
        let start = self.begin_sign_body("ATTESTATION", fork_info, Some(signing_root));
        self.bodies.extend_from_slice(b",\"attestation\":");
        self.push_attestation_data(data);
        self.bodies.push(b'}');
        SignBody(start..self.bodies.len())
    }

    pub fn selection_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        slot: u64,
    ) -> SignBody {
        let start = self.begin_sign_body("AGGREGATION_SLOT", fork_info, Some(signing_root));
        write!(self.bodies, ",\"aggregation_slot\":{{\"slot\":\"{slot}\"}}}}")
            .expect("writes to a Vec");
        SignBody(start..self.bodies.len())
    }

    /// web3signer reads an unversioned aggregate as phase0, so it is sent
    /// versioned; it derives the signing root itself.
    pub fn aggregate_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        fork: ForkName,
        aggregator_index: u64,
        aggregate: &str,
        selection_proof: &[u8; 96],
    ) -> SignBody {
        let start = self.begin_sign_body("AGGREGATE_AND_PROOF_V2", fork_info, None);
        self.bodies.extend_from_slice(b",\"aggregate_and_proof\":{\"version\":\"");
        self.bodies.extend(fork.name().bytes().map(|byte| byte.to_ascii_uppercase()));
        self.bodies.extend_from_slice(b"\",\"data\":");
        self.push_aggregate_and_proof(aggregator_index, aggregate, selection_proof);
        self.bodies.extend_from_slice(b"}}");
        SignBody(start..self.bodies.len())
    }

    pub fn randao_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        epoch: u64,
    ) -> SignBody {
        let start = self.begin_sign_body("RANDAO_REVEAL", fork_info, Some(signing_root));
        write!(self.bodies, ",\"randao_reveal\":{{\"epoch\":\"{epoch}\"}}}}")
            .expect("writes to a Vec");
        SignBody(start..self.bodies.len())
    }

    pub fn block_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        fork: ForkName,
        signing_root: &[u8; 32],
        header: &[u8; BEACON_BLOCK_HEADER_SIZE],
    ) -> SignBody {
        let start = self.begin_sign_body("BLOCK_V2", fork_info, Some(signing_root));
        self.bodies.extend_from_slice(b",\"beacon_block\":{\"version\":\"");
        self.bodies.extend(fork.name().bytes().map(|byte| byte.to_ascii_uppercase()));
        write!(
            self.bodies,
            "\",\"block_header\":{{\"slot\":\"{}\",\"proposer_index\":\"{}\",\"parent_root\":",
            BeaconBlockHeaderView::slot(header),
            BeaconBlockHeaderView::proposer_index(header),
        )
        .expect("writes to a Vec");
        self.push_hex(BeaconBlockHeaderView::parent_root(header));
        self.bodies.extend_from_slice(b",\"state_root\":");
        self.push_hex(BeaconBlockHeaderView::state_root(header));
        self.bodies.extend_from_slice(b",\"body_root\":");
        self.push_hex(BeaconBlockHeaderView::body_root(header));
        self.bodies.extend_from_slice(b"}}}");
        SignBody(start..self.bodies.len())
    }

    pub fn payload_attestation_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        data: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE],
    ) -> SignBody {
        let start =
            self.begin_sign_body("PAYLOAD_ATTESTATION_MESSAGE", fork_info, Some(signing_root));
        self.bodies.extend_from_slice(
            b",\"payload_attestation_message\":{\"version\":\"GLOAS\",\"data\":",
        );
        self.push_payload_attestation_data(data);
        self.bodies.extend_from_slice(b"}}");
        SignBody(start..self.bodies.len())
    }

    pub fn preferences_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        preferences: &[u8; PROPOSER_PREFERENCES_SIZE],
    ) -> SignBody {
        let start = self.begin_sign_body("PROPOSER_PREFERENCES", fork_info, Some(signing_root));
        self.bodies
            .extend_from_slice(b",\"proposer_preferences\":{\"version\":\"GLOAS\",\"data\":");
        self.push_preferences(preferences);
        self.bodies.extend_from_slice(b"}}");
        SignBody(start..self.bodies.len())
    }

    pub fn envelope_sign_body(
        &mut self,
        fork_info: &ForkInfo,
        signing_root: &[u8; 32],
        envelope: &[u8],
    ) -> SignBody {
        let start =
            self.begin_sign_body("EXECUTION_PAYLOAD_ENVELOPE", fork_info, Some(signing_root));
        self.bodies.extend_from_slice(
            b",\"execution_payload_envelope\":{\"version\":\"GLOAS\",\"data\":{\"payload\":",
        );
        self.push_payload(ExecutionPayloadEnvelopeView::payload(envelope));
        self.bodies.extend_from_slice(b",\"execution_requests\":");
        self.push_execution_requests(ExecutionPayloadEnvelopeView::execution_requests(envelope));
        write!(
            self.bodies,
            ",\"builder_index\":\"{}\",\"beacon_block_root\":",
            ExecutionPayloadEnvelopeView::builder_index(envelope)
        )
        .expect("writes to a Vec");
        self.push_hex(ExecutionPayloadEnvelopeView::beacon_block_root(envelope));
        self.bodies.extend_from_slice(b",\"parent_beacon_block_root\":");
        self.push_hex(ExecutionPayloadEnvelopeView::parent_beacon_block_root(envelope));
        self.bodies.extend_from_slice(b"}}}");
        SignBody(start..self.bodies.len())
    }

    pub fn sign(&mut self, pubkey: &[u8; 48], body: &SignBody, purpose: SignPurpose) -> RequestId {
        let path = self.path(format_args!("/api/v1/eth2/sign/0x{}", Hex(pubkey)));
        let id = RequestId(self.next_id);
        self.next_id += 1;
        let request = BeaconRequest::Sign(purpose);
        self.queued.push(QueuedRequest { id, request, path, body: body.0.clone() });
        id
    }

    pub fn drain(&mut self, mut send: impl FnMut(RequestId, BeaconRequest, &str, &[u8])) {
        for queued in &self.queued {
            let path = &self.paths[queued.path.clone()];
            send(queued.id, queued.request, path, &self.bodies[queued.body.clone()]);
        }
        self.queued.clear();
        self.paths.clear();
        self.bodies.clear();
    }

    fn path(&mut self, path: Arguments<'_>) -> Range<usize> {
        let start = self.paths.len();
        self.paths.write_fmt(path).expect("writes to a String");
        start..self.paths.len()
    }

    fn push(&mut self, request: BeaconRequest, path: Range<usize>, body_start: usize) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        let body = body_start..self.bodies.len();
        self.queued.push(QueuedRequest { id, request, path, body });
        id
    }

    fn push_hex(&mut self, bytes: &[u8]) {
        self.bodies.extend_from_slice(b"\"0x");
        let at = self.bodies.len();
        self.bodies.resize(at + 2 * bytes.len(), 0);
        hex::encode_to_slice(bytes, &mut self.bodies[at..]).expect("sized for the hex");
        self.bodies.push(b'"');
    }

    /// Opens a web3signer body up to its optional `signingRoot`; the caller
    /// adds the signed object and closes it.
    fn begin_sign_body(
        &mut self,
        kind: &str,
        fork_info: &ForkInfo,
        signing_root: Option<&[u8; 32]>,
    ) -> usize {
        let start = self.bodies.len();
        write!(
            self.bodies,
            "{{\"type\":\"{kind}\",\"fork_info\":{{\"fork\":{{\"previous_version\":"
        )
        .expect("writes to a Vec");
        self.push_hex(&fork_info.previous_version);
        self.bodies.extend_from_slice(b",\"current_version\":");
        self.push_hex(&fork_info.current_version);
        write!(self.bodies, ",\"epoch\":\"{}\"}},\"genesis_validators_root\":", fork_info.epoch)
            .expect("writes to a Vec");
        self.push_hex(&fork_info.genesis_validators_root);
        self.bodies.push(b'}');
        if let Some(root) = signing_root {
            self.bodies.extend_from_slice(b",\"signingRoot\":");
            self.push_hex(root);
        }
        start
    }

    fn duties(
        &mut self,
        request: BeaconRequest,
        path: Range<usize>,
        validator_indices: impl IntoIterator<Item = u64>,
    ) -> RequestId {
        let start = self.bodies.len();
        self.push_quoted(validator_indices);
        self.push(request, path, start)
    }

    fn push_array<T>(
        &mut self,
        items: impl IntoIterator<Item = T>,
        mut push: impl FnMut(&mut Self, T),
    ) {
        self.bodies.push(b'[');
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                self.bodies.push(b',');
            }
            push(self, item);
        }
        self.bodies.push(b']');
    }

    fn push_payload_attestation_data(&mut self, data: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) {
        self.bodies.extend_from_slice(b"{\"beacon_block_root\":");
        self.push_hex(PayloadAttestationDataView::beacon_block_root(data));
        write!(
            self.bodies,
            ",\"slot\":\"{}\",\"payload_present\":{},\"blob_data_available\":{}}}",
            PayloadAttestationDataView::slot(data),
            PayloadAttestationDataView::payload_present(data),
            PayloadAttestationDataView::blob_data_available(data),
        )
        .expect("writes to a Vec");
    }

    fn push_preferences(&mut self, preferences: &[u8; PROPOSER_PREFERENCES_SIZE]) {
        self.bodies.extend_from_slice(b"{\"dependent_root\":");
        self.push_hex(ProposerPreferencesView::dependent_root(preferences));
        write!(
            self.bodies,
            ",\"proposal_slot\":\"{}\",\"validator_index\":\"{}\",\"fee_recipient\":",
            ProposerPreferencesView::proposal_slot(preferences),
            ProposerPreferencesView::validator_index(preferences),
        )
        .expect("writes to a Vec");
        self.push_hex(ProposerPreferencesView::fee_recipient(preferences));
        write!(
            self.bodies,
            ",\"target_gas_limit\":\"{}\"}}",
            ProposerPreferencesView::target_gas_limit(preferences)
        )
        .expect("writes to a Vec");
    }

    fn push_payload(&mut self, payload: &[u8]) {
        type View = ExecutionPayloadView;
        self.bodies.extend_from_slice(b"{\"parent_hash\":");
        self.push_hex(View::parent_hash(payload));
        self.bodies.extend_from_slice(b",\"fee_recipient\":");
        self.push_hex(View::fee_recipient(payload));
        self.bodies.extend_from_slice(b",\"state_root\":");
        self.push_hex(View::state_root(payload));
        self.bodies.extend_from_slice(b",\"receipts_root\":");
        self.push_hex(View::receipts_root(payload));
        self.bodies.extend_from_slice(b",\"logs_bloom\":");
        self.push_hex(View::logs_bloom(payload));
        self.bodies.extend_from_slice(b",\"prev_randao\":");
        self.push_hex(View::prev_randao(payload));
        write!(
            self.bodies,
            ",\"block_number\":\"{}\",\"gas_limit\":\"{}\",\"gas_used\":\"{}\",\"timestamp\":\"{}\",\"extra_data\":",
            View::block_number(payload),
            View::gas_limit(payload),
            View::gas_used(payload),
            View::timestamp(payload),
        )
        .expect("writes to a Vec");
        self.push_hex(View::extra_data(payload));
        write!(
            self.bodies,
            ",\"base_fee_per_gas\":\"{}\",\"block_hash\":",
            Uint256Decimal::new(View::base_fee_per_gas(payload))
        )
        .expect("writes to a Vec");
        self.push_hex(View::block_hash(payload));
        self.bodies.extend_from_slice(b",\"transactions\":");
        self.push_array(variable_list_items(View::transactions(payload)), Self::push_hex);
        self.bodies.extend_from_slice(b",\"withdrawals\":");
        let withdrawals = View::withdrawals_gloas(payload).chunks_exact(WITHDRAWAL_SIZE);
        self.push_array(withdrawals, |this, withdrawal| {
            let number =
                |at: usize| u64::from_le_bytes(withdrawal[at..at + 8].try_into().expect("8 bytes"));
            write!(
                this.bodies,
                "{{\"index\":\"{}\",\"validator_index\":\"{}\",\"address\":",
                number(0),
                number(8)
            )
            .expect("writes to a Vec");
            this.push_hex(&withdrawal[16..36]);
            write!(this.bodies, ",\"amount\":\"{}\"}}", number(36)).expect("writes to a Vec");
        });
        write!(
            self.bodies,
            ",\"blob_gas_used\":\"{}\",\"excess_blob_gas\":\"{}\",\"block_access_list\":",
            View::blob_gas_used(payload),
            View::excess_blob_gas(payload),
        )
        .expect("writes to a Vec");
        self.push_hex(View::block_access_list(payload));
        write!(self.bodies, ",\"slot_number\":\"{}\"}}", View::slot_number(payload))
            .expect("writes to a Vec");
    }

    fn push_execution_requests(&mut self, requests: &[u8]) {
        let [deposits, withdrawals, consolidations, builder_deposits, builder_exits] =
            ExecutionRequestsView::sections(requests);
        self.bodies.extend_from_slice(b"{\"deposits\":");
        self.push_array(deposits.chunks_exact(DEPOSIT_REQUEST_SIZE), |this, deposit| {
            let deposit = deposit.try_into().expect("sized chunk");
            this.bodies.extend_from_slice(b"{\"pubkey\":");
            this.push_hex(DepositRequestView::pubkey(deposit));
            this.bodies.extend_from_slice(b",\"withdrawal_credentials\":");
            this.push_hex(DepositRequestView::withdrawal_credentials(deposit));
            write!(
                this.bodies,
                ",\"amount\":\"{}\",\"signature\":",
                DepositRequestView::amount(deposit)
            )
            .expect("writes to a Vec");
            this.push_hex(DepositRequestView::signature(deposit));
            write!(this.bodies, ",\"index\":\"{}\"}}", DepositRequestView::index(deposit))
                .expect("writes to a Vec");
        });
        self.bodies.extend_from_slice(b",\"withdrawals\":");
        self.push_array(withdrawals.chunks_exact(WITHDRAWAL_REQUEST_SIZE), |this, request| {
            let request = request.try_into().expect("sized chunk");
            this.bodies.extend_from_slice(b"{\"source_address\":");
            this.push_hex(WithdrawalRequestView::source_address(request));
            this.bodies.extend_from_slice(b",\"validator_pubkey\":");
            this.push_hex(WithdrawalRequestView::validator_pubkey(request));
            write!(this.bodies, ",\"amount\":\"{}\"}}", WithdrawalRequestView::amount(request))
                .expect("writes to a Vec");
        });
        self.bodies.extend_from_slice(b",\"consolidations\":");
        self.push_array(
            consolidations.chunks_exact(CONSOLIDATION_REQUEST_SIZE),
            |this, request| {
                let request = request.try_into().expect("sized chunk");
                this.bodies.extend_from_slice(b"{\"source_address\":");
                this.push_hex(ConsolidationRequestView::source_address(request));
                this.bodies.extend_from_slice(b",\"source_pubkey\":");
                this.push_hex(ConsolidationRequestView::source_pubkey(request));
                this.bodies.extend_from_slice(b",\"target_pubkey\":");
                this.push_hex(ConsolidationRequestView::target_pubkey(request));
                this.bodies.push(b'}');
            },
        );
        self.bodies.extend_from_slice(b",\"builder_deposits\":");
        self.push_array(
            builder_deposits.chunks_exact(BUILDER_DEPOSIT_REQUEST_SIZE),
            |this, deposit| {
                let deposit = deposit.try_into().expect("sized chunk");
                this.bodies.extend_from_slice(b"{\"pubkey\":");
                this.push_hex(BuilderDepositRequestView::pubkey(deposit));
                this.bodies.extend_from_slice(b",\"withdrawal_credentials\":");
                this.push_hex(BuilderDepositRequestView::withdrawal_credentials(deposit));
                write!(
                    this.bodies,
                    ",\"amount\":\"{}\",\"signature\":",
                    BuilderDepositRequestView::amount(deposit)
                )
                .expect("writes to a Vec");
                this.push_hex(BuilderDepositRequestView::signature(deposit));
                this.bodies.push(b'}');
            },
        );
        self.bodies.extend_from_slice(b",\"builder_exits\":");
        self.push_array(builder_exits.chunks_exact(BUILDER_EXIT_REQUEST_SIZE), |this, exit| {
            let exit = exit.try_into().expect("sized chunk");
            this.bodies.extend_from_slice(b"{\"source_address\":");
            this.push_hex(BuilderExitRequestView::source_address(exit));
            this.bodies.extend_from_slice(b",\"pubkey\":");
            this.push_hex(BuilderExitRequestView::pubkey(exit));
            this.bodies.push(b'}');
        });
        self.bodies.push(b'}');
    }

    fn push_quoted(&mut self, values: impl IntoIterator<Item = u64>) {
        self.push_array(values, |this, value| {
            write!(this.bodies, "\"{value}\"").expect("writes to a Vec")
        });
    }

    fn push_aggregate_and_proof(
        &mut self,
        aggregator_index: u64,
        aggregate: &str,
        selection_proof: &[u8; 96],
    ) {
        write!(self.bodies, "{{\"aggregator_index\":\"{aggregator_index}\",\"aggregate\":{aggregate},\"selection_proof\":")
            .expect("writes to a Vec");
        self.push_hex(selection_proof);
        self.bodies.push(b'}');
    }

    fn push_attestation_data(&mut self, data: AttestationDataView<'_>) {
        write!(
            self.bodies,
            "{{\"slot\":\"{}\",\"index\":\"{}\",\"beacon_block_root\":",
            data.slot(),
            data.index()
        )
        .expect("writes to a Vec");
        self.push_hex(data.beacon_block_root());
        write!(self.bodies, ",\"source\":{{\"epoch\":\"{}\",\"root\":", data.source_epoch())
            .expect("writes to a Vec");
        self.push_hex(data.source_root());
        write!(self.bodies, "}},\"target\":{{\"epoch\":\"{}\",\"root\":", data.target_epoch())
            .expect("writes to a Vec");
        self.push_hex(data.target_root());
        self.bodies.extend_from_slice(b"}}");
    }
}

/// A little-endian `Uint256` in decimal, as the JSON schemas spell it.
struct Uint256Decimal {
    digits: [u8; Self::MAX_DIGITS],
    start: usize,
}

impl Uint256Decimal {
    const MAX_DIGITS: usize = 78;

    fn new(little_endian: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (limb, bytes) in limbs.iter_mut().zip(little_endian.chunks_exact(8)) {
            *limb = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        }
        let mut digits = [0u8; Self::MAX_DIGITS];
        let mut start = Self::MAX_DIGITS;
        loop {
            let mut remainder = 0u128;
            for limb in limbs.iter_mut().rev() {
                let current = (remainder << 64) | u128::from(*limb);
                *limb = (current / 10) as u64;
                remainder = current % 10;
            }
            start -= 1;
            digits[start] = b'0' + remainder as u8;
            if limbs == [0; 4] {
                break;
            }
        }
        Self { digits, start }
    }
}

impl fmt::Display for Uint256Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(str::from_utf8(&self.digits[self.start..]).expect("ascii digits"))
    }
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hex = [0; 2 * 48];
        for chunk in self.0.chunks(48) {
            let hex = &mut hex[..2 * chunk.len()];
            hex::encode_to_slice(chunk, hex).expect("sized for the hex");
            f.write_str(str::from_utf8(hex).expect("hex is ASCII"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::{Value, json};
    use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

    use super::*;

    pub fn attestation_data_ssz() -> [u8; ATTESTATION_DATA_SIZE] {
        let mut ssz = [0; ATTESTATION_DATA_SIZE];
        ssz[0..8].copy_from_slice(&65u64.to_le_bytes());
        ssz[16..48].fill(0x11);
        ssz[48..56].copy_from_slice(&1u64.to_le_bytes());
        ssz[56..88].fill(0x22);
        ssz[88..96].copy_from_slice(&2u64.to_le_bytes());
        ssz[96..128].fill(0x33);
        ssz
    }

    pub fn attestation_data_json() -> Value {
        json!({
            "slot": "65",
            "index": "0",
            "beacon_block_root": format!("0x{}", "11".repeat(32)),
            "source": {"epoch": "1", "root": format!("0x{}", "22".repeat(32))},
            "target": {"epoch": "2", "root": format!("0x{}", "33".repeat(32))},
        })
    }

    fn drained(requests: &mut BeaconRequests) -> Vec<(RequestId, &'static str, String, String)> {
        let mut sent = Vec::new();
        requests.drain(|id, request, path, body| {
            sent.push((
                id,
                request.method(),
                path.to_owned(),
                String::from_utf8(body.to_vec()).unwrap(),
            ))
        });
        sent
    }

    #[test]
    fn validator_indices_body_lists_pubkeys_as_ids() {
        let mut requests = BeaconRequests::default();
        let first = requests.validator_indices([&[0xaa; 48], &[0xbb; 48]]);
        let second = requests.validator_indices([]);
        assert_ne!(first, second);

        let path = "/eth/v1/beacon/states/head/validators";
        let ids = format!(r#"{{"ids":["0x{}","0x{}"]}}"#, "aa".repeat(48), "bb".repeat(48));
        assert_eq!(drained(&mut requests), [
            (first, "POST", path.into(), ids),
            (second, "POST", path.into(), r#"{"ids":[]}"#.into())
        ]);
        assert!(drained(&mut requests).is_empty());
    }

    #[test]
    fn duties_and_data_requests_carry_epoch_and_slot() {
        let mut requests = BeaconRequests::default();
        let duties = requests.attester_duties(7, [3, 12]);
        let data = requests.attestation_data(230);
        assert_eq!(drained(&mut requests), [
            (duties, "POST", "/eth/v1/validator/duties/attester/7".into(), r#"["3","12"]"#.into()),
            (
                data,
                "GET",
                "/eth/v1/validator/attestation_data?slot=230&committee_index=0".into(),
                String::new()
            ),
        ]);
    }

    #[test]
    fn published_attestations_share_one_data_object() {
        let ssz = attestation_data_ssz();
        let mut requests = BeaconRequests::default();
        let signed = |committee_index, attester_index, byte| SignedAttestation {
            committee_index,
            attester_index,
            signature: [byte; 96],
        };
        requests.publish_attestations(ForkName::Fulu, AttestationDataView::new(&ssz), [
            signed(4, 100, 0xc1),
            signed(9, 200, 0xc2),
        ]);

        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.consensus_version(), Some("fulu"));
            sent.push((path.to_owned(), serde_json::from_slice::<Value>(body).unwrap()));
        });
        let entry = |committee: &str, attester: &str, byte: &str| {
            json!({
                "committee_index": committee,
                "attester_index": attester,
                "data": attestation_data_json(),
                "signature": format!("0x{}", byte.repeat(96)),
            })
        };
        assert_eq!(sent, [(
            "/eth/v2/beacon/pool/attestations".to_owned(),
            json!([entry("4", "100", "c1"), entry("9", "200", "c2")])
        )]);
    }

    fn fork_info() -> ForkInfo {
        ForkInfo {
            previous_version: [1; 4],
            current_version: [2; 4],
            epoch: 3,
            genesis_validators_root: [0x9e; 32],
        }
    }

    fn fork_info_json() -> Value {
        json!({
            "fork": {"previous_version": "0x01010101", "current_version": "0x02020202", "epoch": "3"},
            "genesis_validators_root": format!("0x{}", "9e".repeat(32)),
        })
    }

    fn bodies(requests: &mut BeaconRequests) -> Vec<(String, Value)> {
        let mut sent = Vec::new();
        requests.drain(|_, _, path, body| {
            let body =
                if body.is_empty() { Value::Null } else { serde_json::from_slice(body).unwrap() };
            sent.push((path.to_owned(), body))
        });
        sent
    }

    #[test]
    fn subscriptions_and_aggregate_fetch_follow_the_beacon_api() {
        let mut requests = BeaconRequests::default();
        requests.committee_subscriptions([CommitteeSubscription {
            validator_index: 7,
            committee_index: 3,
            committees_at_slot: 8,
            slot: 65,
            is_aggregator: true,
        }]);
        requests.aggregate_attestation(65, 3, &[0xab; 32]);
        assert_eq!(bodies(&mut requests), [
            (
                "/eth/v1/validator/beacon_committee_subscriptions".to_owned(),
                json!([{"validator_index": "7", "committee_index": "3", "committees_at_slot": "8", "slot": "65", "is_aggregator": true}])
            ),
            (
                format!(
                    "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{}&slot=65&committee_index=3",
                    "ab".repeat(32)
                ),
                Value::Null
            ),
        ]);
    }

    #[test]
    fn selection_and_aggregate_sign_bodies_follow_web3signer() {
        let mut requests = BeaconRequests::default();
        let aggregate = r#"{"aggregation_bits":"0x03","data":{"slot":"65"},"signature":"0x00","committee_bits":"0x08"}"#;
        let selection = requests.selection_sign_body(&fork_info(), &[0x5a; 32], 65);
        requests.sign(&[0xaa; 48], &selection, SignPurpose::SelectionProof);
        let body =
            requests.aggregate_sign_body(&fork_info(), ForkName::Fulu, 7, aggregate, &[0xc1; 96]);
        requests.sign(&[0xaa; 48], &body, SignPurpose::Aggregate);

        let aggregate = serde_json::from_str::<Value>(aggregate).unwrap();
        assert_eq!(bodies(&mut requests), [
            (
                format!("/api/v1/eth2/sign/0x{}", "aa".repeat(48)),
                json!({
                    "type": "AGGREGATION_SLOT",
                    "fork_info": fork_info_json(),
                    "signingRoot": format!("0x{}", "5a".repeat(32)),
                    "aggregation_slot": {"slot": "65"},
                })
            ),
            (
                format!("/api/v1/eth2/sign/0x{}", "aa".repeat(48)),
                json!({
                    "type": "AGGREGATE_AND_PROOF_V2",
                    "fork_info": fork_info_json(),
                    "aggregate_and_proof": {
                        "version": "FULU",
                        "data": {
                            "aggregator_index": "7",
                            "aggregate": aggregate,
                            "selection_proof": format!("0x{}", "c1".repeat(96)),
                        },
                    },
                })
            ),
        ]);
    }

    #[test]
    fn published_aggregates_carry_message_and_signature() {
        let mut requests = BeaconRequests::default();
        let aggregate = r#"{"aggregation_bits":"0x03"}"#;
        requests.publish_aggregates(ForkName::Fulu, [SignedAggregate {
            aggregator_index: 7,
            aggregate,
            selection_proof: [0xc1; 96],
            signature: [0xc2; 96],
        }]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.consensus_version(), Some("fulu"));
            sent.push((path.to_owned(), serde_json::from_slice::<Value>(body).unwrap()));
        });
        assert_eq!(sent, [(
            "/eth/v2/validator/aggregate_and_proofs".to_owned(),
            json!([{
                "message": {
                    "aggregator_index": "7",
                    "aggregate": {"aggregation_bits": "0x03"},
                    "selection_proof": format!("0x{}", "c1".repeat(96)),
                },
                "signature": format!("0x{}", "c2".repeat(96)),
            }])
        )]);
    }

    #[test]
    fn proposal_requests_follow_the_beacon_api() {
        let mut requests = BeaconRequests::default();
        requests.proposer_duties(2);
        requests.prepare_proposers(&[0xfe; 20], [7, 9]);
        let fee_recipient = format!("0x{}", "fe".repeat(20));
        assert_eq!(bodies(&mut requests), [
            ("/eth/v2/validator/duties/proposer/2".to_owned(), Value::Null),
            (
                "/eth/v1/validator/prepare_beacon_proposer".to_owned(),
                json!([
                    {"validator_index": "7", "fee_recipient": fee_recipient},
                    {"validator_index": "9", "fee_recipient": fee_recipient},
                ])
            ),
        ]);

        requests.produce_block(ForkName::Gloas, 65, &[0x7a; 96], &[0x67; 32]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.method(), "POST");
            assert_eq!(request.consensus_version(), Some("gloas"));
            sent.push((path.to_owned(), body.to_vec()))
        });
        let path = format!(
            "/eth/v4/validator/blocks/65?randao_reveal=0x{}&graffiti=0x{}&include_payload=true",
            "7a".repeat(96),
            "67".repeat(32)
        );
        let builder_config = [&0u64.to_le_bytes()[..], &0u64.to_le_bytes(), &20u32.to_le_bytes()];
        assert_eq!(sent, [(path, builder_config.concat())]);
    }

    #[test]
    fn proposal_sign_bodies_follow_web3signer() {
        let mut requests = BeaconRequests::default();
        let randao = requests.randao_sign_body(&fork_info(), &[0x5a; 32], 2);
        requests.sign(&[0xaa; 48], &randao, SignPurpose::Randao);
        let mut header = [0; BEACON_BLOCK_HEADER_SIZE];
        header[..8].copy_from_slice(&65u64.to_le_bytes());
        header[8..16].copy_from_slice(&7u64.to_le_bytes());
        header[16..48].fill(0x01);
        header[48..80].fill(0x02);
        header[80..].fill(0x03);
        let block = requests.block_sign_body(&fork_info(), ForkName::Gloas, &[0x5b; 32], &header);
        requests.sign(&[0xaa; 48], &block, SignPurpose::Block);

        let bodies = bodies(&mut requests).into_iter().map(|(_, body)| body).collect::<Vec<_>>();
        let root = |byte: &str| format!("0x{}", byte.repeat(32));
        assert_eq!(bodies, [
            json!({
                "type": "RANDAO_REVEAL",
                "fork_info": fork_info_json(),
                "signingRoot": root("5a"),
                "randao_reveal": {"epoch": "2"},
            }),
            json!({
                "type": "BLOCK_V2",
                "fork_info": fork_info_json(),
                "signingRoot": root("5b"),
                "beacon_block": {"version": "GLOAS", "block_header": {
                    "slot": "65",
                    "proposer_index": "7",
                    "parent_root": root("01"),
                    "state_root": root("02"),
                    "body_root": root("03"),
                }},
            }),
        ]);
    }

    #[test]
    fn uint256_decimal_renders_every_limb() {
        assert_eq!(Uint256Decimal::new(&[0; 32]).to_string(), "0");
        let mut two_ether = [0; 32];
        two_ether[..8].copy_from_slice(&2_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(Uint256Decimal::new(&two_ether).to_string(), "2000000000000000000");
        let mut two_to_64 = [0; 32];
        two_to_64[8] = 1;
        assert_eq!(Uint256Decimal::new(&two_to_64).to_string(), "18446744073709551616");
        assert_eq!(Uint256Decimal::new(&[0xff; 32]).to_string().len(), 78);
    }

    fn gloas_envelope() -> Vec<u8> {
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let mut payload = vec![0u8; 540];
        payload[..32].fill(0x01);
        payload[404..412].copy_from_slice(&9u64.to_le_bytes());
        payload[440..448].copy_from_slice(&7u64.to_le_bytes());
        payload[532..540].copy_from_slice(&65u64.to_le_bytes());
        let transactions = [&at(8)[..], &at(10), &[0x01, 0x02], &[0x03]].concat();
        let mut withdrawal = [0u8; WITHDRAWAL_SIZE];
        withdrawal[..8].copy_from_slice(&4u64.to_le_bytes());
        withdrawal[8..16].copy_from_slice(&5u64.to_le_bytes());
        withdrawal[16..36].fill(0xaa);
        withdrawal[36..44].copy_from_slice(&6u64.to_le_bytes());
        let transactions_at = 540 + 1;
        let withdrawals_at = transactions_at + transactions.len();
        let access_list_at = withdrawals_at + WITHDRAWAL_SIZE;
        for (position, offset) in
            [(436, 540), (504, transactions_at), (508, withdrawals_at), (528, access_list_at)]
        {
            payload[position..position + 4].copy_from_slice(&at(offset));
        }
        payload.extend_from_slice(&[0xab]);
        payload.extend_from_slice(&transactions);
        payload.extend_from_slice(&withdrawal);
        payload.extend_from_slice(&[0xcd]);

        let consolidation = [0x11u8; CONSOLIDATION_REQUEST_SIZE];
        let after = 20 + CONSOLIDATION_REQUEST_SIZE;
        let requests =
            [&at(20)[..], &at(20), &at(20), &at(after), &at(after), &consolidation].concat();

        let mut envelope = [&at(80)[..], &at(80 + payload.len())].concat();
        envelope.extend_from_slice(&u64::MAX.to_le_bytes());
        envelope.extend_from_slice(&[0x22; 32]);
        envelope.extend_from_slice(&[0x33; 32]);
        envelope.extend_from_slice(&payload);
        envelope.extend_from_slice(&requests);
        envelope
    }

    #[test]
    fn envelope_sign_body_spells_the_whole_payload() {
        let mut requests = BeaconRequests::default();
        let envelope = gloas_envelope();
        let body = requests.envelope_sign_body(&fork_info(), &[0x5d; 32], &envelope);
        requests.sign(&[0xaa; 48], &body, SignPurpose::Envelope);
        let sent = bodies(&mut requests).pop().unwrap().1;
        assert_eq!(sent["type"], "EXECUTION_PAYLOAD_ENVELOPE");
        let wrapped = &sent["execution_payload_envelope"];
        assert_eq!(wrapped["version"], "GLOAS");
        let data = &wrapped["data"];
        assert_eq!(data["builder_index"], u64::MAX.to_string());
        assert_eq!(data["beacon_block_root"], format!("0x{}", "22".repeat(32)));
        assert_eq!(data["parent_beacon_block_root"], format!("0x{}", "33".repeat(32)));
        let payload = &data["payload"];
        assert_eq!(payload["parent_hash"], format!("0x{}", "01".repeat(32)));
        assert_eq!(payload["block_number"], "9");
        assert_eq!(payload["base_fee_per_gas"], "7");
        assert_eq!(payload["extra_data"], "0xab");
        assert_eq!(payload["transactions"], json!(["0x0102", "0x03"]));
        assert_eq!(
            payload["withdrawals"],
            json!([{
                "index": "4",
                "validator_index": "5",
                "address": format!("0x{}", "aa".repeat(20)),
                "amount": "6",
            }])
        );
        assert_eq!(payload["block_access_list"], "0xcd");
        assert_eq!(payload["slot_number"], "65");
        let execution_requests = &data["execution_requests"];
        assert_eq!(execution_requests["deposits"], json!([]));
        assert_eq!(execution_requests["builder_exits"], json!([]));
        assert_eq!(
            execution_requests["consolidations"],
            json!([{
                "source_address": format!("0x{}", "11".repeat(20)),
                "source_pubkey": format!("0x{}", "11".repeat(48)),
                "target_pubkey": format!("0x{}", "11".repeat(48)),
            }])
        );
    }

    #[test]
    fn gloas_envelope_publishes_with_its_blob_flag() {
        let mut requests = BeaconRequests::default();
        let block = [0x0b; 84];
        let envelope = gloas_envelope();
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let end = 16 + block.len() + envelope.len();
        let produced =
            [&at(16)[..], &at(16 + block.len()), &at(end), &at(end), &block, &envelope].concat();
        requests.publish_block(ForkName::Gloas, true, &produced, &[0xc1; 96]);
        requests.publish_envelope(&produced, &[0xc2; 96]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            sent.push((path.to_owned(), request.extra_header(), body.to_vec()))
        });
        let signed_block = [&at(100)[..], &[0xc1; 96], &block].concat();
        assert_eq!(sent[0], ("/eth/v2/beacon/blocks".to_owned(), None, signed_block));
        assert_eq!(sent[1].0, "/eth/v1/beacon/execution_payload_envelopes");
        assert_eq!(sent[1].1, Some(("Eth-Blob-Data-Included", "true")));
        let signed_envelope = [&at(100)[..], &[0xc2; 96], &envelope].concat();
        let end = 12 + signed_envelope.len();
        assert_eq!(sent[1].2, [&at(12)[..], &at(end), &at(end), &signed_envelope].concat());
    }
}
