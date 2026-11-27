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
        PROPOSER_PREFERENCES_SIZE, ProposerPreferencesView, VRFProof, XMSS_SIGNATURE_SIZE,
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
    block_contents::BlockContents,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconRequest {
    ValidatorIndices,
    AttesterDuties,
    AttestationData,
    CommitteeSubscriptions,
    AggregateAttestation,
    ProposerDuties,
    PrepareProposers,
    ProduceBlock,
    PublishBlock,
    PtcDuties,
    PayloadAttestationData,
    /// With its blobs, or bare.
    PublishEnvelope {
        blobs: bool,
    },
    Publish(Batch),
}

/// Signed objects of one kind and slot, published in one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Batch {
    pub kind: Published,
    pub slot: u64,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    Attestations,
    Aggregates,
    PayloadAttestations,
    ProposerPreferences,
}

impl Published {
    fn path(self) -> &'static str {
        match self {
            Self::Attestations => "/eth/v2/beacon/pool/attestations",
            Self::Aggregates => "/eth/v2/validator/aggregate_and_proofs",
            Self::PayloadAttestations => "/eth/v1/beacon/pool/payload_attestations",
            Self::ProposerPreferences => "/eth/v1/validator/proposer_preferences",
        }
    }
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
            Self::CommitteeSubscriptions |
            Self::PrepareProposers |
            Self::ProduceBlock |
            Self::PublishBlock |
            Self::PtcDuties |
            Self::PublishEnvelope { .. } |
            Self::Publish(_) => "POST",
        }
    }

    pub fn consensus_version(self) -> Option<&'static str> {
        match self {
            Self::ProduceBlock |
            Self::PublishBlock |
            Self::PublishEnvelope { .. } |
            Self::Publish(_) => Some(ForkName::Pq.name()),
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
            Self::ProduceBlock | Self::PublishBlock | Self::PublishEnvelope { .. } => SSZ,
            _ => JSON,
        }
    }

    pub fn extra_header(self) -> Option<(&'static str, &'static str)> {
        let Self::PublishEnvelope { blobs } = self else { return None };
        Some(("Eth-Blob-Data-Included", if blobs { "true" } else { "false" }))
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
            Self::ProduceBlock => {
                let payload_included = response
                    .header("Eth-Execution-Payload-Included")
                    .is_some_and(|got| got.eq_ignore_ascii_case(b"true"));
                let block = ProducedBlock { payload_included, ssz: body };
                BeaconEvent::ProducedBlock { id, block }
            }
            Self::CommitteeSubscriptions |
            Self::PrepareProposers |
            Self::PublishBlock |
            Self::PublishEnvelope { .. } |
            Self::Publish(_) => BeaconEvent::Accepted { id, request: self },
        }
    }
}

pub struct CommitteeSubscription {
    pub validator_index: u64,
    pub committee_index: u64,
    pub committees_at_slot: u64,
    pub slot: u64,
    pub is_aggregator: bool,
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

    pub fn publish_attestation(
        &mut self,
        slot: u64,
        committee_index: u64,
        attester_index: u64,
        data_json: &str,
        signature: &XMSSSignature,
    ) {
        self.append(Published::Attestations, slot, |this| {
            write!(
                this.bodies,
                "{{\"committee_index\":\"{committee_index}\",\"attester_index\":\"{attester_index}\",\"data\":{data_json},\"signature\":"
            )
            .expect("writes to a Vec");
            this.push_hex(signature);
            this.bodies.push(b'}');
        });
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
        aggregator_position: u8,
        attestation_data_root: &[u8; 32],
    ) -> RequestId {
        let root = Hex(attestation_data_root);
        let path = self.path(format_args!(
            "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{root}&slot={slot}&committee_index={committee_index}&aggregator_position={aggregator_position}"
        ));
        let start = self.bodies.len();
        self.push(BeaconRequest::AggregateAttestation, path, start)
    }

    /// `proved` is the served `{"aggregate": …, "proof": …}` object, passed on
    /// untouched.
    pub fn publish_aggregate(
        &mut self,
        slot: u64,
        aggregator_index: u64,
        proved: &str,
        signature: &XMSSSignature,
    ) {
        let fields = proved.strip_prefix('{').expect("served as a JSON object");
        self.append(Published::Aggregates, slot, |this| {
            write!(
                this.bodies,
                "{{\"message\":{{\"aggregator_index\":\"{aggregator_index}\",{fields},\"signature\":"
            )
            .expect("writes to a Vec");
            this.push_hex(signature);
            this.bodies.push(b'}');
        });
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
        self.push(BeaconRequest::ProduceBlock, path, start)
    }

    pub fn publish_block(&mut self, block: &[u8], signature: &XMSSSignature) -> RequestId {
        const SIGNED_BLOCK_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;
        let path = self.path(format_args!("/eth/v2/beacon/blocks"));
        let start = self.bodies.len();
        self.bodies.extend_from_slice(&(SIGNED_BLOCK_FIXED as u32).to_le_bytes());
        self.bodies.extend_from_slice(signature);
        self.bodies.extend_from_slice(block);
        self.push(BeaconRequest::PublishBlock, path, start)
    }

    /// The signed envelope alone when it has no blobs, else with its blobs
    /// and their proofs.
    pub fn publish_envelope(
        &mut self,
        contents: &BlockContents<'_>,
        signature: &XMSSSignature,
    ) -> RequestId {
        const SIGNED_ENVELOPE_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;
        let path = self.path(format_args!("/eth/v1/beacon/execution_payload_envelopes"));
        let start = self.bodies.len();
        let blobs = !contents.blobs.is_empty();
        if blobs {
            let proofs_at = 3 * 4 + SIGNED_ENVELOPE_FIXED + contents.envelope.len();
            let blobs_at = proofs_at + contents.kzg_proofs.len();
            for offset in [3 * 4, proofs_at, blobs_at] {
                self.bodies.extend_from_slice(&(offset as u32).to_le_bytes());
            }
        }
        self.bodies.extend_from_slice(&(SIGNED_ENVELOPE_FIXED as u32).to_le_bytes());
        self.bodies.extend_from_slice(signature);
        self.bodies.extend_from_slice(contents.envelope);
        if blobs {
            self.bodies.extend_from_slice(contents.kzg_proofs);
            self.bodies.extend_from_slice(contents.blobs);
        }
        self.push(BeaconRequest::PublishEnvelope { blobs }, path, start)
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

    pub fn publish_payload_attestation(
        &mut self,
        slot: u64,
        validator_index: u64,
        data_json: &str,
        signature: &XMSSSignature,
    ) {
        self.append(Published::PayloadAttestations, slot, |this| {
            write!(
                this.bodies,
                "{{\"validator_index\":\"{validator_index}\",\"data\":{data_json},\"signature\":"
            )
            .expect("writes to a Vec");
            this.push_hex(signature);
            this.bodies.push(b'}');
        });
    }

    pub fn publish_proposer_preferences(
        &mut self,
        message: &[u8; PROPOSER_PREFERENCES_SIZE],
        signature: &XMSSSignature,
    ) {
        let slot = ProposerPreferencesView::proposal_slot(message);
        self.append(Published::ProposerPreferences, slot, |this| {
            this.bodies.extend_from_slice(b"{\"message\":");
            this.push_preferences(message);
            this.bodies.extend_from_slice(b",\"signature\":");
            this.push_hex(signature);
            this.bodies.push(b'}');
        });
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

    /// Joins the last queued request when it publishes the same kind and
    /// slot, so signatures answered together go out in one request.
    fn append(&mut self, kind: Published, slot: u64, push_entry: impl FnOnce(&mut Self)) {
        let joins = matches!(
            self.queued.last(),
            Some(QueuedRequest { request: BeaconRequest::Publish(batch), .. })
                if batch.kind == kind && batch.slot == slot
        );
        let start = self.bodies.len();
        if joins {
            debug_assert_eq!(self.bodies.last(), Some(&b']'));
            *self.bodies.last_mut().expect("an array") = b',';
        } else {
            self.bodies.push(b'[');
        }
        push_entry(self);
        self.bodies.push(b']');

        if !joins {
            let path = self.path(format_args!("{}", kind.path()));
            self.push(BeaconRequest::Publish(Batch { kind, slot, count: 1 }), path, start);
            return;
        }
        let last = self.queued.last_mut().expect("joined");
        last.body.end = self.bodies.len();
        if let BeaconRequest::Publish(batch) = &mut last.request {
            batch.count += 1;
        }
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
        self.push_array(validator_indices, |this, value| {
            write!(this.bodies, "\"{value}\"").expect("writes to a Vec")
        });
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

    fn published(requests: &mut BeaconRequests) -> Vec<(BeaconRequest, String, Value)> {
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            assert_eq!(request.consensus_version(), Some("pq"));
            sent.push((request, path.to_owned(), serde_json::from_slice::<Value>(body).unwrap()));
        });
        sent
    }

    #[test]
    fn attestations_of_a_slot_join_one_request() {
        let data = attestation_data_json().to_string();
        let mut requests = BeaconRequests::default();
        let signatures = [[0xc1; XMSS_SIGNATURE_SIZE], [0xc2; XMSS_SIGNATURE_SIZE]];
        requests.publish_attestation(65, 4, 100, &data, &signatures[0]);
        requests.publish_attestation(65, 9, 200, &data, &signatures[1]);
        requests.publish_attestation(66, 9, 200, &data, &signatures[1]);

        let entry = |committee: &str, attester: &str, byte: &str| {
            json!({
                "committee_index": committee,
                "attester_index": attester,
                "data": attestation_data_json(),
                "signature": format!("0x{}", byte.repeat(XMSS_SIGNATURE_SIZE)),
            })
        };
        let batch = |slot, count| {
            BeaconRequest::Publish(Batch { kind: Published::Attestations, slot, count })
        };
        let path = "/eth/v2/beacon/pool/attestations".to_owned();
        assert_eq!(published(&mut requests), [
            (batch(65, 2), path.clone(), json!([entry("4", "100", "c1"), entry("9", "200", "c2")])),
            (batch(66, 1), path, json!([entry("9", "200", "c2")])),
        ]);
    }

    #[test]
    fn a_request_between_publishes_starts_a_new_batch() {
        let data = attestation_data_json().to_string();
        let signature = [0xc1; XMSS_SIGNATURE_SIZE];
        let mut requests = BeaconRequests::default();
        requests.publish_attestation(65, 4, 100, &data, &signature);
        requests.attestation_data(66);
        requests.publish_attestation(65, 4, 101, &data, &signature);
        let bodies = drained(&mut requests).into_iter().map(|(.., body)| body);
        let lengths =
            bodies.map(|body| Some(serde_json::from_str::<Value>(&body).ok()?.as_array()?.len()));
        assert!(lengths.eq([Some(1), None, Some(1)]));
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
        requests.aggregate_attestation(65, 3, 2, &[0xab; 32]);
        assert_eq!(bodies(&mut requests), [
            (
                "/eth/v1/validator/beacon_committee_subscriptions".to_owned(),
                json!([{"validator_index": "7", "committee_index": "3", "committees_at_slot": "8", "slot": "65", "is_aggregator": true}])
            ),
            (
                format!(
                    "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{}&slot=65&committee_index=3&aggregator_position=2",
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
        requests.publish_aggregate(65, 7, proved, &signature);
        let sent = published(&mut requests);
        assert_eq!(sent[0].1, "/eth/v2/validator/aggregate_and_proofs");
        assert_eq!(
            sent[0].2,
            json!([{
                "message": {
                    "aggregator_index": "7",
                    "aggregate": {"aggregation_bits": "0x03"},
                    "proof": "0xc0ffee",
                },
                "signature": format!("0x{}", "c2".repeat(XMSS_SIGNATURE_SIZE)),
            }])
        );
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

        requests.produce_block(65, &[0x7a; VRF_PROOF_SIZE], &[0x67; 32]);
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
        let contents = BlockContents::parse(&produced).unwrap();
        let signatures = [[0xc1; XMSS_SIGNATURE_SIZE], [0xc2; XMSS_SIGNATURE_SIZE]];
        requests.publish_block(contents.block, &signatures[0]);
        requests.publish_envelope(&contents, &signatures[1]);
        let mut sent = Vec::new();
        requests.drain(|_, request, path, body| {
            sent.push((path.to_owned(), request.extra_header(), body.to_vec()))
        });
        let signed_at = 4 + XMSS_SIGNATURE_SIZE;
        let signed_block = [&at(signed_at)[..], &signatures[0], &block].concat();
        assert_eq!(sent[0], ("/eth/v2/beacon/blocks".to_owned(), None, signed_block));
        assert_eq!(sent[1].0, "/eth/v1/beacon/execution_payload_envelopes");
        assert_eq!(sent[1].1, Some(("Eth-Blob-Data-Included", "false")), "no blobs");
        let signed_envelope = [&at(signed_at)[..], &signatures[1], &envelope].concat();
        assert_eq!(sent[1].2, signed_envelope, "the signed envelope alone");
    }

    #[test]
    fn an_envelope_with_blobs_publishes_them_with_it() {
        let mut requests = BeaconRequests::default();
        let (block, envelope, proofs, blobs) = ([0x0b; 84], [0x0e; 60], [0x0f; 48], [0x0a; 64]);
        let at = |offset: usize| (offset as u32).to_le_bytes();
        let proofs_at = 16 + block.len() + envelope.len();
        let blobs_at = proofs_at + proofs.len();
        let produced = [
            &at(16)[..],
            &at(16 + block.len()),
            &at(proofs_at),
            &at(blobs_at),
            &block,
            &envelope,
            &proofs,
            &blobs,
        ]
        .concat();
        let contents = BlockContents::parse(&produced).unwrap();
        let signature = [0xc2; XMSS_SIGNATURE_SIZE];
        requests.publish_envelope(&contents, &signature);
        let mut sent = Vec::new();
        requests.drain(|_, request, _, body| sent.push((request.extra_header(), body.to_vec())));
        assert_eq!(sent[0].0, Some(("Eth-Blob-Data-Included", "true")));
        let signed_envelope = [&at(4 + XMSS_SIGNATURE_SIZE)[..], &signature, &envelope].concat();
        let proofs_at = 12 + signed_envelope.len();
        let blobs_at = proofs_at + proofs.len();
        let expected =
            [&at(12)[..], &at(proofs_at), &at(blobs_at), &signed_envelope, &proofs, &blobs]
                .concat();
        assert_eq!(sent[0].1, expected);
    }
}
