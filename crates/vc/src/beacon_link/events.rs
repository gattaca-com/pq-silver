use serde::Deserialize;
use serde_json::value::RawValue;
use silver_common::{
    json_fields::{bytes, each_array_entry, uint64},
    ssz_view::{ATTESTATION_DATA_SIZE, PAYLOAD_ATTESTATION_DATA_SIZE},
};

use crate::beacon_link::{
    head_stream::Head,
    requests::{BeaconRequest, RequestId, SignPurpose},
};

pub enum BeaconEvent<'a> {
    ValidatorIndices { id: RequestId, validators: ValidatorIndices<'a> },
    AttesterDuties { id: RequestId, duties: AttesterDuties<'a> },
    AttestationData { id: RequestId, data: AttestationData<'a> },
    AggregateAttestation { id: RequestId, aggregate: Aggregate<'a> },
    ProposerDuties { id: RequestId, duties: SlotDuties<'a> },
    PtcDuties { id: RequestId, duties: SlotDuties<'a> },
    PayloadAttestationData { id: RequestId, data: PayloadAttestationData<'a> },
    ProducedBlock { id: RequestId, block: ProducedBlock<'a> },
    Accepted { id: RequestId, request: BeaconRequest },
    Signed { id: RequestId, purpose: SignPurpose, signature: [u8; 96] },
    SignerKeys(SignerKeys<'a>),
    Failed { id: RequestId, request: BeaconRequest },
    Head(Head),
}

pub struct ValidatorIndices<'a>(pub(crate) &'a [u8]);

pub struct AttesterDuties<'a>(pub(crate) &'a [u8]);

pub struct AttestationData<'a>(pub(crate) &'a [u8]);

pub struct Aggregate<'a>(pub(crate) &'a [u8]);

pub struct SignerKeys<'a>(pub(crate) &'a [u8]);

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
    pubkey: [u8; 48],
}

impl ValidatorIndices<'_> {
    /// Entries before a malformed one have already been handed over when the
    /// error returns.
    pub fn for_each(
        &self,
        max: usize,
        mut each: impl FnMut(&[u8; 48], u64),
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
struct Pubkey(#[serde(deserialize_with = "bytes")] [u8; 48]);

impl SignerKeys<'_> {
    /// web3signer answers a bare JSON array of pubkeys.
    pub fn for_each(
        &self,
        max: usize,
        mut each: impl FnMut(&[u8; 48]),
    ) -> Result<usize, &'static str> {
        each_array_entry(self.0, max, |_, Pubkey(pubkey)| each(&pubkey))
            .map_err(|_| "web3signer key listing is malformed or too long")
    }
}

#[derive(Deserialize)]
struct SignatureBody {
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

/// web3signer's JSON answer to a sign request, as `Accept: application/json`
/// asks for.
pub fn parse_signature(body: &[u8]) -> Option<[u8; 96]> {
    serde_json::from_slice::<SignatureBody>(body).ok().map(|body| body.signature)
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
    pub pubkey: [u8; 48],
    #[serde(deserialize_with = "uint64")]
    pub validator_index: u64,
    #[serde(deserialize_with = "uint64")]
    pub committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    pub committee_length: u64,
    #[serde(deserialize_with = "uint64")]
    pub committees_at_slot: u64,
    #[serde(deserialize_with = "uint64")]
    pub slot: u64,
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
    pub pubkey: [u8; 48],
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
struct PayloadAttestationDataBody {
    data: PayloadAttestationDataJson,
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

impl PayloadAttestationData<'_> {
    pub fn to_ssz(&self) -> Result<[u8; PAYLOAD_ATTESTATION_DATA_SIZE], &'static str> {
        let PayloadAttestationDataBody { data } = serde_json::from_slice(self.0)
            .map_err(|_| "payload attestation data answer is malformed")?;
        let mut ssz = [0; PAYLOAD_ATTESTATION_DATA_SIZE];
        ssz[0..32].copy_from_slice(&data.beacon_block_root);
        ssz[32..40].copy_from_slice(&data.slot.to_le_bytes());
        ssz[40] = data.payload_present as u8;
        ssz[41] = data.blob_data_available as u8;
        Ok(ssz)
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
struct AttestationDataBody {
    data: AttestationDataJson,
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

impl AttestationData<'_> {
    pub fn to_ssz(&self) -> Result<[u8; ATTESTATION_DATA_SIZE], &'static str> {
        let AttestationDataBody { data } =
            serde_json::from_slice(self.0).map_err(|_| "attestation data answer is malformed")?;
        let mut ssz = [0; ATTESTATION_DATA_SIZE];
        data.write_ssz(&mut ssz);
        Ok(ssz)
    }
}

impl<'a> Aggregate<'a> {
    /// The aggregate's JSON object, passed on to the signer and the publish
    /// untouched.
    pub fn json(&self) -> Result<&'a str, &'static str> {
        let DataBody { data } =
            serde_json::from_slice(self.0).map_err(|_| "aggregate answer lacks data")?;
        Ok(data.get())
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;
    use crate::beacon_link::requests::tests::{attestation_data_json, attestation_data_ssz};

    pub const PUBKEY_A: [u8; 48] = [0xaa; 48];
    pub const PUBKEY_B: [u8; 48] = [0xbb; 48];

    pub fn validators_json(entries: &[([u8; 48], u64)]) -> String {
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

    pub fn duties_json(dependent_root: u8, duties: &[([u8; 48], u64, u64, u64)]) -> String {
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
            committee_length: 128,
            committees_at_slot: 64,
            slot,
        };
        assert_eq!(seen, [duty(PUBKEY_A, 7, 3, 65), duty(PUBKEY_B, 9, 0, 70)]);

        assert!(AttesterDuties(json.as_bytes()).for_each(1, |_| {}).is_err());
        assert!(AttesterDuties(br#"{"data":[]}"#).for_each(1, |_| {}).is_err());
    }

    #[test]
    fn signer_keys_and_signatures_parse() {
        let json = format!(r#"["0x{}","0x{}"]"#, hex::encode(PUBKEY_A), hex::encode(PUBKEY_B));
        let mut seen = Vec::new();
        SignerKeys(json.as_bytes()).for_each(2, |pubkey| seen.push(*pubkey)).unwrap();
        assert_eq!(seen, [PUBKEY_A, PUBKEY_B]);
        assert!(SignerKeys(json.as_bytes()).for_each(1, |_| {}).is_err());
        assert!(SignerKeys(br#"{"keys":[]}"#).for_each(2, |_| {}).is_err());

        let signature = format!(r#"{{"signature":"0x{}"}}"#, "c1".repeat(96));
        assert_eq!(parse_signature(signature.as_bytes()), Some([0xc1; 96]));
        assert_eq!(parse_signature(format!("0x{}", "c1".repeat(96)).as_bytes()), None);
    }

    #[test]
    fn attestation_data_answer_becomes_ssz() {
        let json = json!({"data": attestation_data_json()}).to_string();
        assert_eq!(AttestationData(json.as_bytes()).to_ssz().unwrap(), attestation_data_ssz());
        assert!(AttestationData(br#"{"data":{"slot":"1"}}"#).to_ssz().is_err());
    }

    #[test]
    fn aggregate_answer_yields_its_json() {
        let aggregate = json!({"aggregation_bits": "0x0b", "data": attestation_data_json()});
        let body = json!({"version": "fulu", "data": aggregate}).to_string();
        let json = Aggregate(body.as_bytes()).json().unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(json).unwrap(), aggregate);
        assert!(Aggregate(b"{}").json().is_err());
    }
}
