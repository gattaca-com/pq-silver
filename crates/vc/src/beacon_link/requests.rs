use std::{
    fmt::{self, Arguments, Write as _},
    io::Write as _,
    ops::Range,
    str,
};

use flux_network::http::HttpResponse;
use silver_common::{
    ForkName,
    ssz_view::{
        AttestationDataView, PAYLOAD_ATTESTATION_DATA_SIZE, PROPOSER_PREFERENCES_SIZE,
        PayloadAttestationDataView, ProposerPreferencesView, VRFProof, XMSS_SIGNATURE_SIZE,
        XMSSPubkey, XMSSSignature,
    },
};

use crate::{
    beacon_link::{
        endpoint::{JSON, SSZ},
        events::{
            Aggregate, AttestationData, AttesterDuties, BeaconEvent, PayloadAttestationData,
            ProducedBlock, SlotDuties, ValidatorIndices,
        },
    },
    block_contents::GloasBlockContents,
    signing::{KeyWork, SignPurpose, SignRequest},
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
            Self::PublishEnvelope => "POST",
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
            Self::PublishEnvelope => Some(ForkName::Pq.name()),
            Self::ValidatorIndices |
            Self::AttesterDuties |
            Self::AttestationData |
            Self::CommitteeSubscriptions |
            Self::AggregateAttestation |
            Self::ProposerDuties |
            Self::PrepareProposers |
            Self::PtcDuties |
            Self::PayloadAttestationData => None,
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
        }
    }
}

pub struct SignedAttestation<'a> {
    pub committee_index: u64,
    pub attester_index: u64,
    pub signature: &'a XMSSSignature,
}

pub struct CommitteeSubscription {
    pub validator_index: u64,
    pub committee_index: u64,
    pub committees_at_slot: u64,
    pub slot: u64,
    pub is_aggregator: bool,
}

pub struct IndexedSignature<'a> {
    pub validator_index: u64,
    pub signature: &'a XMSSSignature,
}

pub struct SignedPreferences<'a> {
    pub message: [u8; PROPOSER_PREFERENCES_SIZE],
    pub signature: &'a XMSSSignature,
}

pub struct SignedAggregate<'a> {
    pub aggregator_index: u64,
    /// The served `{"aggregate": …, "proof": …}` object, passed on untouched.
    pub proved: &'a str,
    pub signature: &'a XMSSSignature,
}

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
    signing: Vec<SignRequest>,
    paths: String,
    bodies: Vec<u8>,
}

impl BeaconRequests {
    pub fn validator_indices<'a>(
        &mut self,
        pubkeys: impl IntoIterator<Item = &'a XMSSPubkey>,
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

    pub fn publish_attestations<'a>(
        &mut self,
        fork: ForkName,
        data: AttestationDataView<'_>,
        attestations: impl IntoIterator<Item = SignedAttestation<'a>>,
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
            this.push_hex(attestation.signature);
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
            let fields = signed.proved.strip_prefix('{').expect("served as a JSON object");
            write!(
                this.bodies,
                "{{\"message\":{{\"aggregator_index\":\"{}\",{fields},\"signature\":",
                signed.aggregator_index
            )
            .expect("writes to a Vec");
            this.push_hex(signed.signature);
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
        randao_reveal: &VRFProof,
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
        signature: &XMSSSignature,
    ) -> RequestId {
        const SIGNED_BLOCK_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;
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

    pub fn publish_envelope(&mut self, produced: &[u8], signature: &XMSSSignature) -> RequestId {
        const SIGNED_ENVELOPE_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;
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

    pub fn publish_payload_attestations<'a>(
        &mut self,
        data: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE],
        attestations: impl IntoIterator<Item = IndexedSignature<'a>>,
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
            this.push_hex(attestation.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishPayloadAttestations, path, start)
    }

    pub fn publish_proposer_preferences<'a>(
        &mut self,
        preferences: impl IntoIterator<Item = SignedPreferences<'a>>,
    ) -> RequestId {
        let path = self.path(format_args!("/eth/v1/validator/proposer_preferences"));
        let start = self.bodies.len();
        self.push_array(preferences, |this, signed| {
            this.bodies.extend_from_slice(b"{\"message\":");
            this.push_preferences(&signed.message);
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(signed.signature);
            this.bodies.push(b'}');
        });
        self.push(BeaconRequest::PublishProposerPreferences, path, start)
    }

    pub fn sign(
        &mut self,
        pubkey: &XMSSPubkey,
        purpose: SignPurpose,
        leaf_index: u32,
        signing_root: &[u8; 32],
    ) -> RequestId {
        let work = KeyWork::Sign { leaf_index, signing_root: *signing_root };
        self.push_signing(pubkey, purpose, work)
    }

    pub fn vrf_proof(&mut self, pubkey: &XMSSPubkey, slot: u64) -> RequestId {
        self.push_signing(pubkey, SignPurpose::Randao, KeyWork::VrfProof { slot })
    }

    pub fn drain_signing(&mut self, send: impl FnMut(SignRequest)) {
        self.signing.drain(..).for_each(send);
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
        let id = self.next_id();
        let body = body_start..self.bodies.len();
        self.queued.push(QueuedRequest { id, request, path, body });
        id
    }

    fn push_signing(
        &mut self,
        pubkey: &XMSSPubkey,
        purpose: SignPurpose,
        work: KeyWork,
    ) -> RequestId {
        let id = self.next_id();
        self.signing.push(SignRequest { id, purpose, pubkey: *pubkey, work });
        id
    }

    /// Shared by beacon and signing requests, so a duty's ids ascend across
    /// both.
    fn next_id(&mut self) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        id
    }

    fn push_hex(&mut self, bytes: &[u8]) {
        self.bodies.extend_from_slice(b"\"0x");
        let at = self.bodies.len();
        self.bodies.resize(at + 2 * bytes.len(), 0);
        hex::encode_to_slice(bytes, &mut self.bodies[at..]).expect("sized for the hex");
        self.bodies.push(b'"');
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

    fn push_quoted(&mut self, values: impl IntoIterator<Item = u64>) {
        self.push_array(values, |this, value| {
            write!(this.bodies, "\"{value}\"").expect("writes to a Vec")
        });
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
    use silver_common::ssz_view::{ATTESTATION_DATA_SIZE, VRF_PROOF_SIZE};

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
        let first = requests.validator_indices([&[0xaa; 32], &[0xbb; 32]]);
        let second = requests.validator_indices([]);
        assert_ne!(first, second);

        let path = "/eth/v1/beacon/states/head/validators";
        let ids = format!(r#"{{"ids":["0x{}","0x{}"]}}"#, "aa".repeat(32), "bb".repeat(32));
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
        let signatures = [[0xc1; XMSS_SIGNATURE_SIZE], [0xc2; XMSS_SIGNATURE_SIZE]];
        let signed = |committee_index, attester_index, signature| SignedAttestation {
            committee_index,
            attester_index,
            signature,
        };
        requests.publish_attestations(ForkName::Pq, AttestationDataView::new(&ssz), [
            signed(4, 100, &signatures[0]),
            signed(9, 200, &signatures[1]),
        ]);

        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.consensus_version(), Some("pq"));
            sent.push((path.to_owned(), serde_json::from_slice::<Value>(body).unwrap()));
        });
        let entry = |committee: &str, attester: &str, byte: &str| {
            json!({
                "committee_index": committee,
                "attester_index": attester,
                "data": attestation_data_json(),
                "signature": format!("0x{}", byte.repeat(XMSS_SIGNATURE_SIZE)),
            })
        };
        assert_eq!(sent, [(
            "/eth/v2/beacon/pool/attestations".to_owned(),
            json!([entry("4", "100", "c1"), entry("9", "200", "c2")])
        )]);
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
    fn published_aggregates_carry_the_served_object_and_signature() {
        let mut requests = BeaconRequests::default();
        let proved = r#"{"aggregate":{"aggregation_bits":"0x03"},"proof":"0xc0ffee"}"#;
        let signature = [0xc2; XMSS_SIGNATURE_SIZE];
        requests.publish_aggregates(ForkName::Pq, [SignedAggregate {
            aggregator_index: 7,
            proved,
            signature: &signature,
        }]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.consensus_version(), Some("pq"));
            sent.push((path.to_owned(), serde_json::from_slice::<Value>(body).unwrap()));
        });
        assert_eq!(sent, [(
            "/eth/v2/validator/aggregate_and_proofs".to_owned(),
            json!([{
                "message": {
                    "aggregator_index": "7",
                    "aggregate": {"aggregation_bits": "0x03"},
                    "proof": "0xc0ffee",
                },
                "signature": format!("0x{}", "c2".repeat(XMSS_SIGNATURE_SIZE)),
            }])
        )]);
    }

    #[test]
    fn signing_requests_queue_apart_and_share_ids() {
        let mut requests = BeaconRequests::default();
        let fetch = requests.attestation_data(65);
        let signed = requests.sign(&[0xaa; 32], SignPurpose::Attestation, 7, &[0x5a; 32]);
        let reveal = requests.vrf_proof(&[0xbb; 32], 66);
        assert!(fetch < signed && signed < reveal);
        assert_eq!(drained(&mut requests).len(), 1);

        let mut queued = Vec::new();
        requests.drain_signing(|request| queued.push(request));
        assert_eq!(queued, [
            SignRequest {
                id: signed,
                purpose: SignPurpose::Attestation,
                pubkey: [0xaa; 32],
                work: KeyWork::Sign { leaf_index: 7, signing_root: [0x5a; 32] },
            },
            SignRequest {
                id: reveal,
                purpose: SignPurpose::Randao,
                pubkey: [0xbb; 32],
                work: KeyWork::VrfProof { slot: 66 },
            },
        ]);
        requests.drain_signing(|_| unreachable!("drained"));
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

        requests.produce_block(ForkName::Pq, 65, &[0x7a; VRF_PROOF_SIZE], &[0x67; 32]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.method(), "POST");
            assert_eq!(request.consensus_version(), Some("pq"));
            sent.push((path.to_owned(), body.to_vec()))
        });
        let path = format!(
            "/eth/v4/validator/blocks/65?randao_reveal=0x{}&graffiti=0x{}&include_payload=true",
            "7a".repeat(VRF_PROOF_SIZE),
            "67".repeat(32)
        );
        let builder_config = [&0u64.to_le_bytes()[..], &0u64.to_le_bytes(), &20u32.to_le_bytes()];
        assert_eq!(sent, [(path, builder_config.concat())]);
    }

    #[test]
    fn block_and_envelope_publish_signed_over_ssz() {
        let mut requests = BeaconRequests::default();
        let block = [0x0b; 84];
        let envelope = [0x0e; 60];
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let end = 16 + block.len() + envelope.len();
        let produced =
            [&at(16)[..], &at(16 + block.len()), &at(end), &at(end), &block, &envelope].concat();
        let signatures = [[0xc1; XMSS_SIGNATURE_SIZE], [0xc2; XMSS_SIGNATURE_SIZE]];
        requests.publish_block(ForkName::Pq, true, &produced, &signatures[0]);
        requests.publish_envelope(&produced, &signatures[1]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            sent.push((path.to_owned(), request.extra_header(), body.to_vec()))
        });
        let signed_at = 4 + XMSS_SIGNATURE_SIZE;
        let signed_block = [&at(signed_at)[..], &signatures[0], &block].concat();
        assert_eq!(sent[0], ("/eth/v2/beacon/blocks".to_owned(), None, signed_block));
        assert_eq!(sent[1].0, "/eth/v1/beacon/execution_payload_envelopes");
        assert_eq!(sent[1].1, Some(("Eth-Blob-Data-Included", "true")));
        let signed_envelope = [&at(signed_at)[..], &signatures[1], &envelope].concat();
        let end = 12 + signed_envelope.len();
        assert_eq!(sent[1].2, [&at(12)[..], &at(end), &at(end), &signed_envelope].concat());
    }
}
