use serde::Deserialize;
use serde_json::value::RawValue;
use silver_common::{
    json_fields::{BoundedHex, HexBytes, bytes, each_array_entry, uint64},
    ssz_view::{
        ATTESTATION_DATA_SIZE, ATTESTATION_PQ_FIXED, COMMITTEE_BITS_SIZE_PQ, MAX_STARK_PROOF_SIZE,
        MAX_VALIDATORS_PER_COMMITTEE, PAYLOAD_ATTESTATION_DATA_SIZE, XMSSPubkey,
    },
};

use crate::beacon_link::{
    event_stream::Head,
    requests::{BeaconRequest, RequestId},
};

pub enum BeaconEvent<'a> {
    ValidatorIndices {
        id: RequestId,
        validators: ValidatorIndices<'a>,
    },
    AttesterDuties {
        id: RequestId,
        duties: AttesterDuties<'a>,
    },
    AttestationData {
        id: RequestId,
        data: AttestationData<'a>,
    },
    AggregateAttestation {
        id: RequestId,
        aggregate: Aggregate<'a>,
    },
    ProposerDuties {
        id: RequestId,
        duties: SlotDuties<'a>,
    },
    PtcDuties {
        id: RequestId,
        duties: SlotDuties<'a>,
    },
    PayloadAttestationData {
        id: RequestId,
        data: PayloadAttestationData<'a>,
    },
    ProducedBlock {
        id: RequestId,
        block: ProducedBlock<'a>,
    },
    Accepted {
        id: RequestId,
        request: BeaconRequest,
    },
    Failed {
        id: RequestId,
        request: BeaconRequest,
    },
    /// A 204: the node has nothing to give, such as payload attestation data
    /// for a slot without a block.
    NoContent {
        id: RequestId,
        request: BeaconRequest,
    },
    Head(Head),
    /// The slot's payload envelope arrived.
    PayloadAvailable {
        slot: u64,
    },
}

pub struct ValidatorIndices<'a>(pub(crate) &'a [u8]);

pub struct AttesterDuties<'a>(pub(crate) &'a [u8]);

pub struct AttestationData<'a>(pub(crate) &'a [u8]);

pub struct Aggregate<'a>(pub(crate) &'a [u8]);

pub struct SlotDuties<'a>(pub(crate) &'a [u8]);

pub struct PayloadAttestationData<'a>(pub(crate) &'a [u8]);

pub struct ProducedBlock<'a> {
    pub payload_included: bool,
    pub ssz: &'a [u8],
}

#[derive(Deserialize)]
struct DataBody<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
}

#[derive(Deserialize)]
struct ValidatorEntry {
    #[serde(deserialize_with = "uint64")]
    index: u64,
    validator: Validator,
}

#[derive(Deserialize)]
struct Validator {
    #[serde(deserialize_with = "bytes")]
    pubkey: XMSSPubkey,
}

impl ValidatorIndices<'_> {
    /// Entries before a malformed one have already been handed over when the
    /// error returns.
    pub fn for_each(
        &self,
        max: usize,
        mut each: impl FnMut(&XMSSPubkey, u64),
    ) -> Result<usize, &'static str> {
        let body = serde_json::from_slice::<DataBody>(self.0)
            .map_err(|_| "validators answer is not a data object")?;
        each_array_entry(body.data.get().as_bytes(), max, |_, entry: ValidatorEntry| {
            each(&entry.validator.pubkey, entry.index)
        })
        .map_err(|_| "validators answer has a malformed or surplus entry")
    }
}

#[derive(Deserialize)]
struct DutiesBody<'a> {
    #[serde(deserialize_with = "bytes")]
    dependent_root: [u8; 32],
    #[serde(borrow)]
    data: &'a RawValue,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct AttesterDuty {
    #[serde(deserialize_with = "bytes")]
    pub pubkey: XMSSPubkey,
    #[serde(deserialize_with = "uint64")]
    pub validator_index: u64,
    #[serde(deserialize_with = "uint64")]
    pub committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    pub committees_at_slot: u64,
    #[serde(deserialize_with = "uint64")]
    pub slot: u64,
    #[serde(default)]
    is_aggregator: Option<bool>,
    /// Present only for a member of its committee's aggregation committee.
    #[serde(default, deserialize_with = "optional_uint64")]
    aggregator_position: Option<u64>,
}

impl AttesterDuty {
    /// Its place in the order its committee's aggregators broadcast in. A
    /// node that flags an aggregator without a position puts it first.
    pub fn aggregator_position(&self) -> Option<u64> {
        match (self.aggregator_position, self.is_aggregator) {
            (Some(position), _) => Some(position),
            (None, Some(true)) => Some(0),
            (None, _) => None,
        }
    }
}

fn optional_uint64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    uint64(deserializer).map(Some)
}

impl AttesterDuties<'_> {
    /// Returns the dependent root. Duties before a malformed one have already
    /// been handed over when the error returns.
    pub fn for_each(
        &self,
        max: usize,
        each: impl FnMut(AttesterDuty),
    ) -> Result<[u8; 32], &'static str> {
        for_each_duty(self.0, max, each)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct SlotDuty {
    #[serde(deserialize_with = "bytes")]
    pub pubkey: XMSSPubkey,
    #[serde(deserialize_with = "uint64")]
    pub validator_index: u64,
    #[serde(deserialize_with = "uint64")]
    pub slot: u64,
}

impl SlotDuties<'_> {
    pub fn for_each(
        &self,
        max: usize,
        each: impl FnMut(SlotDuty),
    ) -> Result<[u8; 32], &'static str> {
        for_each_duty(self.0, max, each)
    }
}

#[derive(Deserialize)]
struct PayloadAttestationDataJson {
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    payload_present: bool,
    blob_data_available: bool,
}

impl<'a> PayloadAttestationData<'a> {
    /// The data as SSZ, and its served JSON.
    pub fn parse(&self) -> Result<([u8; PAYLOAD_ATTESTATION_DATA_SIZE], &'a str), &'static str> {
        let malformed = "payload attestation data answer is malformed";
        let DataBody { data: json } = serde_json::from_slice(self.0).map_err(|_| malformed)?;
        let data = serde_json::from_str::<PayloadAttestationDataJson>(json.get())
            .map_err(|_| malformed)?;
        let mut ssz = [0; PAYLOAD_ATTESTATION_DATA_SIZE];
        ssz[0..32].copy_from_slice(&data.beacon_block_root);
        ssz[32..40].copy_from_slice(&data.slot.to_le_bytes());
        ssz[40] = data.payload_present as u8;
        ssz[41] = data.blob_data_available as u8;
        Ok((ssz, json.get()))
    }
}

fn for_each_duty<'a, T: Deserialize<'a>>(
    body: &'a [u8],
    max: usize,
    mut each: impl FnMut(T),
) -> Result<[u8; 32], &'static str> {
    let body = serde_json::from_slice::<DutiesBody>(body)
        .map_err(|_| "duties answer lacks dependent_root or data")?;
    each_array_entry(body.data.get().as_bytes(), max, |_, duty| each(duty))
        .map_err(|_| "duties answer has a malformed or surplus entry")?;
    Ok(body.dependent_root)
}

#[derive(Deserialize)]
struct AttestationDataJson {
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    #[serde(deserialize_with = "uint64")]
    index: u64,
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    source: CheckpointJson,
    target: CheckpointJson,
}

#[derive(Deserialize)]
struct CheckpointJson {
    #[serde(deserialize_with = "uint64")]
    epoch: u64,
    #[serde(deserialize_with = "bytes")]
    root: [u8; 32],
}

impl AttestationDataJson {
    fn write_ssz(&self, ssz: &mut [u8; ATTESTATION_DATA_SIZE]) {
        ssz[0..8].copy_from_slice(&self.slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.index.to_le_bytes());
        ssz[16..48].copy_from_slice(&self.beacon_block_root);
        ssz[48..56].copy_from_slice(&self.source.epoch.to_le_bytes());
        ssz[56..88].copy_from_slice(&self.source.root);
        ssz[88..96].copy_from_slice(&self.target.epoch.to_le_bytes());
        ssz[96..128].copy_from_slice(&self.target.root);
    }
}

impl<'a> AttestationData<'a> {
    /// The data as SSZ, and its served JSON.
    pub fn parse(&self) -> Result<([u8; ATTESTATION_DATA_SIZE], &'a str), &'static str> {
        let malformed = "attestation data answer is malformed";
        let DataBody { data: json } = serde_json::from_slice(self.0).map_err(|_| malformed)?;
        let data =
            serde_json::from_str::<AttestationDataJson>(json.get()).map_err(|_| malformed)?;
        let mut ssz = [0; ATTESTATION_DATA_SIZE];
        data.write_ssz(&mut ssz);
        Ok((ssz, json.get()))
    }
}

#[derive(Deserialize)]
struct ProvedJson<'a> {
    aggregate: AggregateJson,
    #[serde(borrow)]
    proof: HexBytes<'a, MAX_STARK_PROOF_SIZE>,
}

#[derive(Deserialize)]
struct AggregateJson {
    aggregation_bits: BoundedHex<{ MAX_VALIDATORS_PER_COMMITTEE / 8 + 1 }>,
    data: AttestationDataJson,
    #[serde(deserialize_with = "bytes")]
    committee_bits: [u8; COMMITTEE_BITS_SIZE_PQ],
}

impl<'a> Aggregate<'a> {
    /// Writes the aggregate's PQ `Attestation` SSZ and its proof's bytes, and
    /// returns the served `{"aggregate", "proof"}` JSON.
    pub fn parse(
        &self,
        attestation: &mut Vec<u8>,
        proof_bytes: &mut Vec<u8>,
    ) -> Result<&'a str, &'static str> {
        let DataBody { data } =
            serde_json::from_slice(self.0).map_err(|_| "aggregate answer lacks data")?;
        let ProvedJson { aggregate, proof } =
            serde_json::from_str(data.get()).map_err(|_| "aggregate answer is malformed")?;

        let bits = aggregate.aggregation_bits.as_bytes();
        attestation.clear();
        attestation.resize(ATTESTATION_PQ_FIXED + bits.len(), 0);
        attestation[..4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        let data_ssz = (&mut attestation[4..4 + ATTESTATION_DATA_SIZE]).try_into().expect("sized");
        aggregate.data.write_ssz(data_ssz);
        attestation[4 + ATTESTATION_DATA_SIZE..ATTESTATION_PQ_FIXED]
            .copy_from_slice(&aggregate.committee_bits);
        attestation[ATTESTATION_PQ_FIXED..].copy_from_slice(bits);

        proof_bytes.clear();
        proof_bytes.resize(proof.byte_len(), 0);
        proof.decode_into(proof_bytes);
        Ok(data.get())
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;
    use crate::beacon_link::requests::tests::{attestation_data_json, attestation_data_ssz};

    pub const PUBKEY_A: XMSSPubkey = [0xaa; 32];
    pub const PUBKEY_B: XMSSPubkey = [0xbb; 32];

    pub fn validators_json(entries: &[(XMSSPubkey, u64)]) -> String {
        let data = entries
            .iter()
            .map(|(pubkey, index)| {
                format!(
                    r#"{{"index":"{index}","balance":"32000000000","status":"active_ongoing","validator":{{"pubkey":"0x{}","slashed":false}}}}"#,
                    hex::encode(pubkey)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"execution_optimistic":false,"finalized":false,"data":[{data}]}}"#)
    }

    pub fn duties_json(dependent_root: u8, duties: &[(XMSSPubkey, u64, u64, u64)]) -> String {
        let data = duties
            .iter()
            .map(|(pubkey, validator_index, committee_index, slot)| {
                json!({
                    "pubkey": format!("0x{}", hex::encode(pubkey)),
                    "validator_index": validator_index.to_string(),
                    "committee_index": committee_index.to_string(),
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "5",
                    "slot": slot.to_string(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "dependent_root": format!("0x{}", hex::encode([dependent_root; 32])),
            "execution_optimistic": false,
            "data": data,
        })
        .to_string()
    }

    #[test]
    fn validator_indices_answer_yields_pubkey_and_index() {
        let json = validators_json(&[(PUBKEY_A, 7), (PUBKEY_B, 9)]);
        let mut seen = Vec::new();
        let count = ValidatorIndices(json.as_bytes())
            .for_each(2, |pubkey, index| seen.push((*pubkey, index)))
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(seen, [(PUBKEY_A, 7), (PUBKEY_B, 9)]);
    }

    #[test]
    fn malformed_or_surplus_validator_answers_are_errors() {
        let two = validators_json(&[(PUBKEY_A, 7), (PUBKEY_B, 9)]);
        assert!(ValidatorIndices(two.as_bytes()).for_each(1, |_, _| {}).is_err());
        for body in [r#"{"data":{}}"#, r#"{"data":[{"index":"x"}]}"#, "[]", ""] {
            assert!(ValidatorIndices(body.as_bytes()).for_each(2, |_, _| {}).is_err(), "{body}");
        }
    }

    #[test]
    fn attester_duties_answer_yields_duties_and_dependent_root() {
        let json = duties_json(0xd1, &[(PUBKEY_A, 7, 3, 65), (PUBKEY_B, 9, 0, 70)]);
        let mut seen = Vec::new();
        let root = AttesterDuties(json.as_bytes()).for_each(2, |duty| seen.push(duty)).unwrap();
        assert_eq!(root, [0xd1; 32]);
        let duty = |pubkey, validator_index, committee_index, slot| AttesterDuty {
            pubkey,
            validator_index,
            committee_index,
            committees_at_slot: 64,
            slot,
            is_aggregator: None,
            aggregator_position: None,
        };
        assert_eq!(seen, [duty(PUBKEY_A, 7, 3, 65), duty(PUBKEY_B, 9, 0, 70)]);
        assert_eq!(seen[0].aggregator_position(), None);

        assert!(AttesterDuties(json.as_bytes()).for_each(1, |_| {}).is_err());
        assert!(AttesterDuties(br#"{"data":[]}"#).for_each(1, |_| {}).is_err());
    }

    #[test]
    fn an_aggregator_is_named_by_its_position() {
        let duty = |extra: &str| {
            let json = format!(
                r#"{{"pubkey":"0x{}","validator_index":"7","committee_index":"3","committees_at_slot":"1","slot":"65"{extra}}}"#,
                hex::encode(PUBKEY_A)
            );
            serde_json::from_str::<AttesterDuty>(&json).unwrap().aggregator_position()
        };
        assert_eq!(duty(""), None);
        assert_eq!(duty(r#","is_aggregator":false"#), None);
        assert_eq!(duty(r#","aggregator_position":"2""#), Some(2), "as lighthouse serves");
        assert_eq!(
            duty(r#","is_aggregator":true,"aggregator_position":"3""#),
            Some(3),
            "as silver serves"
        );
        assert_eq!(duty(r#","is_aggregator":true"#), Some(0), "no position");
    }

    #[test]
    fn attestation_data_answer_becomes_ssz() {
        let json = json!({"data": attestation_data_json()}).to_string();
        let (ssz, served) = AttestationData(json.as_bytes()).parse().unwrap();
        assert_eq!(ssz, attestation_data_ssz());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(served).unwrap(),
            attestation_data_json()
        );
        assert!(AttestationData(br#"{"data":{"slot":"1"}}"#).parse().is_err());
    }

    #[test]
    fn proved_aggregate_answer_yields_its_json_and_ssz() {
        let proved = json!({
            "aggregate": {
                "aggregation_bits": "0x0b",
                "data": attestation_data_json(),
                "committee_bits": "0x0800",
            },
            "proof": "0xc0ffee",
        });
        let body = json!({"version": "pq", "data": proved}).to_string();
        let (mut attestation, mut proof) = (vec![0xff; 1000], Vec::new());
        let json = Aggregate(body.as_bytes()).parse(&mut attestation, &mut proof).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(json).unwrap(), proved);
        let expected = [
            &(ATTESTATION_PQ_FIXED as u32).to_le_bytes()[..],
            &attestation_data_ssz(),
            &[0x08, 0x00],
            &[0x0b],
        ]
        .concat();
        assert_eq!(attestation, expected);
        assert_eq!(proof, [0xc0, 0xff, 0xee]);
        assert!(Aggregate(b"{}").parse(&mut attestation, &mut proof).is_err());
    }
}
