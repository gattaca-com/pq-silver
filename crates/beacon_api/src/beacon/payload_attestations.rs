use serde::Deserialize;
use silver_common::{
    GossipTopic,
    json_fields::{bytes, uint64},
    ssz_view::{PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE, XMSSSignature},
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{SubmittedEntry, post_ssz_submission, post_submission},
};

pub(crate) fn post_payload_attestation_messages(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if req.eth_consensus_version != Some("pq") {
        resp.error(400, "Eth-Consensus-Version must name pq");
        return;
    }
    if req.body_is_ssz() {
        let topic = GossipTopic::PayloadAttestationMessage;
        return post_ssz_submission(req, ctx, resp, topic, PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE);
    }
    post_submission::<SubmittedPayloadAttestationMessage>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedPayloadAttestationMessage {
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    data: PayloadAttestationData,
    #[serde(deserialize_with = "bytes")]
    signature: XMSSSignature,
}

#[derive(Deserialize)]
struct PayloadAttestationData {
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    payload_present: bool,
    blob_data_available: bool,
}

impl SubmittedEntry for SubmittedPayloadAttestationMessage {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::PayloadAttestationMessage])
    }

    fn ssz_len(&self) -> usize {
        PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let data = &self.data;
        ssz[0..8].copy_from_slice(&self.validator_index.to_le_bytes());
        ssz[8..40].copy_from_slice(&data.beacon_block_root);
        ssz[40..48].copy_from_slice(&data.slot.to_le_bytes());
        ssz[48] = data.payload_present as u8;
        ssz[49] = data.blob_data_available as u8;
        ssz[50..].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_common::{
        TCacheProducer,
        ssz_view::{PayloadAttestationDataView, PayloadAttestationMessagePqView},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::ctx,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/beacon/pool/payload_attestations";

    pub(crate) fn message(validator_index: u64) -> String {
        format!(
            "{{\"validator_index\":\"{validator_index}\",\"data\":{{\"beacon_block_root\":\"0x{}\",\
             \"slot\":\"40\",\"payload_present\":true,\"blob_data_available\":false}},\
             \"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "44".repeat(size_of::<XMSSSignature>()),
        )
    }

    fn versioned<'a>(body: &'a str, version: Option<&'a str>) -> ParsedRequest<'a> {
        ParsedRequest { eth_consensus_version: version, ..posting(PATH, body) }
    }

    #[test]
    fn accepted_messages_carry_their_index_topic_and_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!("[{},{}]", message(7), message(9));
        let posted = versioned(&body, Some("pq"));
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the messages defer")
        };
        let [_, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::PayloadAttestationMessage));

        let ssz: &[u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE] =
            submissions.read_buffer(second.ssz).unwrap().try_into().unwrap();
        assert_eq!(PayloadAttestationMessagePqView::validator_index(ssz), 9);
        let data = PayloadAttestationMessagePqView::data(ssz);
        assert_eq!(PayloadAttestationDataView::beacon_block_root(data), &[0x11; 32]);
        assert_eq!(PayloadAttestationDataView::slot(data), 40);
        assert!(PayloadAttestationDataView::payload_present(data));
        assert!(!PayloadAttestationDataView::blob_data_available(data));
        assert_eq!(
            PayloadAttestationMessagePqView::signature(ssz),
            &[0x44; size_of::<XMSSSignature>()]
        );
    }

    #[test]
    fn messages_name_pq_and_come_as_a_non_empty_array() {
        let ctx = ctx();
        let body = format!("[{}]", message(7));
        for version in [None, Some("gloas")] {
            let response = dispatch(&ctx, &versioned(&body, version)).1;
            assert_eq!(status_code(&response), "400", "{version:?}");
        }
        for body in ["", "[]", "{}", &message(7)] {
            let response = dispatch(&ctx, &versioned(body, Some("pq"))).1;
            assert_eq!(status_code(&response), "400", "{body:?}");
        }
    }

    /// The SSZ of `message(validator_index)`.
    fn message_ssz(validator_index: u64) -> Vec<u8> {
        let mut ssz = vec![0x44; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE];
        ssz[0..8].copy_from_slice(&validator_index.to_le_bytes());
        ssz[8..40].fill(0x11);
        ssz[40..48].copy_from_slice(&40u64.to_le_bytes());
        ssz[48..50].copy_from_slice(&[1, 0]);
        ssz
    }

    fn ssz_posting(body: &[u8]) -> ParsedRequest<'_> {
        ParsedRequest {
            body,
            content_type: Some("application/octet-stream"),
            ..versioned("", Some("pq"))
        }
    }

    #[test]
    fn ssz_messages_are_published_as_sent() {
        let body = [message_ssz(7), message_ssz(9)].concat();
        let mut submissions = submissions();
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx(), &ssz_posting(&body), &mut submissions).0
        else {
            panic!("the messages defer")
        };
        let [first, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::PayloadAttestationMessage));
        assert_eq!(submissions.read_buffer(first.ssz).unwrap(), message_ssz(7));
        assert_eq!(submissions.read_buffer(second.ssz).unwrap(), message_ssz(9));
    }

    #[test]
    fn malformed_ssz_is_refused() {
        let mut not_a_bool = message_ssz(7);
        not_a_bool[48] = 2;
        let body = [message_ssz(7), not_a_bool].concat();
        let Outcome::AwaitingVerdicts(submission) = dispatch(&ctx(), &ssz_posting(&body)).0 else {
            panic!("the well-formed message defers")
        };
        assert_eq!(submission.accepted.len(), 1);
        assert_eq!(submission.failures[0].body_index, 1);

        let truncated = &body[..body.len() - 1];
        for body in [&[][..], truncated] {
            assert_eq!(status_code(&dispatch(&ctx(), &ssz_posting(body)).1), "400");
        }
    }

    #[test]
    fn another_media_type_is_a_415() {
        let body = format!("[{}]", message(7));
        let posted =
            ParsedRequest { content_type: Some("text/plain"), ..versioned(&body, Some("pq")) };
        assert_eq!(status_code(&dispatch(&ctx(), &posted).1), "415");
    }
}
