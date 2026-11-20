use silver_common::{
    ForkName, GossipTopic,
    envelope_contents::SignedEnvelopeContents,
    ssz_view::{
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, SignedExecutionPayloadEnvelopePqView,
    },
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{EnvelopePublication, requested_validation},
};

pub(crate) fn post_payload_envelope(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    if req.eth_consensus_version != Some(ForkName::Pq.name()) {
        return resp.error(400, "Eth-Consensus-Version must name pq");
    }
    let blob_data_included = match req.eth_blob_data_included {
        Some("true") => true,
        Some("false") => false,
        _ => return resp.error(400, "Eth-Blob-Data-Included must be true or false"),
    };
    let Some(validation) = requested_validation(req) else {
        return resp.error(400, "invalid broadcast_validation");
    };
    let signed = if blob_data_included {
        let Some(contents) = SignedEnvelopeContents::parse(req.body) else {
            return resp.error(400, "invalid SignedExecutionPayloadEnvelopeContents");
        };
        contents.signed_envelope
    } else {
        req.body
    };
    if let Err(reason) = GossipTopic::ExecutionPayload.check_pq_signed_message(signed) {
        return resp.error(400, reason);
    }
    let envelope = SignedExecutionPayloadEnvelopePqView::message(signed);
    let slot = ExecutionPayloadView::slot_number(ExecutionPayloadEnvelopeView::payload(envelope));
    if !ctx.spec.is_pq_at_slot(slot) {
        return resp.error(400, "the envelope's slot precedes the PQ fork");
    }
    resp.await_payload_envelope(req.body, EnvelopePublication { blob_data_included }, validation);
}

#[cfg(test)]
mod tests {
    use silver_common::{
        BroadcastValidation, TCache, TCacheId, TCacheProducer,
        ssz_view::{BYTES_PER_BLOB, SIGNED_PQ_FIXED},
        test_util::{empty_signed_envelope, empty_signed_envelope_pq},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::ApiCtx,
        http::router::{Outcome, SSZ_MEDIA_TYPE},
        submission::tests::{SLOT, ctx},
        testing::{dispatch, dispatch_into, posting, status_code},
    };

    const PATH: &str = "/eth/v1/beacon/execution_payload_envelopes";

    fn request(body: &[u8], included: bool) -> ParsedRequest<'_> {
        ParsedRequest {
            body,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some("pq"),
            eth_blob_data_included: Some(if included { "true" } else { "false" }),
            from_web_page: false,
            ..posting(PATH, "")
        }
    }

    fn pq_ctx() -> ApiCtx {
        let mut ctx = ctx();
        ctx.spec.gloas_fork_epoch = 0;
        ctx.spec.pq_fork_epoch = 0;
        ctx
    }

    fn contents(signed: &[u8]) -> Vec<u8> {
        let proofs = 12 + signed.len();
        let blobs = proofs + 128 * 48;
        let mut body = [12, proofs, blobs].map(|n| (n as u32).to_le_bytes()).concat();
        body.extend_from_slice(signed);
        body.resize(blobs + BYTES_PER_BLOB, 0);
        body
    }

    #[test]
    fn both_publication_forms_wait_for_validation() {
        let ctx = pq_ctx();
        let signed = empty_signed_envelope_pq(SLOT, [3; 32]);
        for (included, body) in [(false, signed.clone()), (true, contents(&signed))] {
            let mut producer = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
            let (outcome, response) = dispatch_into(&ctx, &request(&body, included), &mut producer);
            assert!(response.is_empty());
            let Outcome::AwaitingVerdicts(submission) = outcome else {
                panic!("await publication")
            };
            assert_eq!(
                submission.envelope,
                Some(EnvelopePublication { blob_data_included: included })
            );
            assert_eq!(submission.validation, BroadcastValidation::Gossip);
            assert_eq!(producer.read_buffer(submission.accepted[0].ssz).unwrap(), body);
        }
    }

    /// `BeaconClient::publish_execution_payload_envelope` in helix.
    #[test]
    fn helix_reveal_publishes_contents_under_consensus_and_equivocation() {
        let ctx = pq_ctx();
        let body = contents(&empty_signed_envelope_pq(SLOT, [3; 32]));
        let req = ParsedRequest {
            query: "broadcast_validation=consensus_and_equivocation",
            ..request(&body, true)
        };
        let mut producer = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
        let (outcome, response) = dispatch_into(&ctx, &req, &mut producer);
        assert!(response.is_empty(), "answered only once validation settles");
        let Outcome::AwaitingVerdicts(submission) = outcome else { panic!("await publication") };
        assert_eq!(submission.envelope, Some(EnvelopePublication { blob_data_included: true }));
        assert_eq!(submission.validation, BroadcastValidation::ConsensusAndEquivocation);
        assert_eq!(producer.read_buffer(submission.accepted[0].ssz).unwrap(), body);
    }

    #[test]
    fn publication_checks_headers_fork_and_requested_validation() {
        let signed = empty_signed_envelope_pq(SLOT, [3; 32]);
        let gloas = empty_signed_envelope(SLOT, [3; 32]);
        let mut ctx = pq_ctx();
        ctx.spec.pq_fork_epoch = u64::MAX;
        assert_eq!(status_code(&dispatch(&ctx, &request(&signed, false)).1), "400");
        let ctx = pq_ctx();
        for req in [
            request(&gloas, false),
            ParsedRequest { eth_consensus_version: Some("gloas"), ..request(&signed, false) },
            ParsedRequest { eth_blob_data_included: None, ..request(&signed, false) },
            ParsedRequest { eth_blob_data_included: Some("yes"), ..request(&signed, false) },
            ParsedRequest { eth_consensus_version: None, ..request(&signed, false) },
            ParsedRequest { eth_consensus_version: Some("fulu"), ..request(&signed, false) },
            ParsedRequest { query: "broadcast_validation=invalid", ..request(&signed, false) },
        ] {
            assert_eq!(status_code(&dispatch(&ctx, &req).1), "400");
        }
        let req = ParsedRequest {
            query: "broadcast_validation=consensus_and_equivocation",
            ..request(&signed, false)
        };
        let Outcome::AwaitingVerdicts(submission) = dispatch(&ctx, &req).0 else {
            panic!("await publication")
        };
        assert_eq!(submission.validation, BroadcastValidation::ConsensusAndEquivocation);
        let req =
            ParsedRequest { content_type: Some("application/json"), ..request(&signed, false) };
        assert_eq!(status_code(&dispatch(&ctx, &req).1), "415");
    }

    #[test]
    fn malformed_payloads_and_bundles_are_rejected_before_submission() {
        let ctx = pq_ctx();
        let valid = empty_signed_envelope_pq(SLOT, [3; 32]);
        let message = SIGNED_PQ_FIXED;
        let payload = message + 80;
        for at in [
            0,
            message,
            message + 4,
            payload + 436,
            payload + 504,
            payload + 508,
            payload + 528,
            valid.len() - 32,
        ] {
            let mut signed = valid.clone();
            signed[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(
                status_code(&dispatch(&ctx, &request(&signed, false)).1),
                "400",
                "offset {at}"
            );
        }
        let mut bytes = contents(&valid);
        bytes.pop();
        assert_eq!(status_code(&dispatch(&ctx, &request(&bytes, true)).1), "400");
        assert_eq!(status_code(&dispatch(&ctx, &request(&valid, true)).1), "400");
        assert_eq!(status_code(&dispatch(&ctx, &request(&contents(&valid), false)).1), "400");
    }
}
