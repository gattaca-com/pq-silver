use serde::Deserialize;
use silver_common::{
    GossipTopic,
    json_fields::{bytes, uint64},
    ssz_view::{PROPOSER_PREFERENCES_SIZE, SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, XMSSSignature},
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{SubmittedEntry, post_ssz_submission, post_submission},
};

pub(crate) fn post_proposer_preferences(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if req.eth_consensus_version != Some("pq") {
        resp.error(400, "Eth-Consensus-Version must name pq");
        return;
    }
    if req.body_is_ssz() {
        let topic = GossipTopic::ProposerPreferences;
        return post_ssz_submission(req, ctx, resp, topic, SIGNED_PROPOSER_PREFERENCES_PQ_SIZE);
    }
    post_submission::<SubmittedProposerPreferences>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedProposerPreferences {
    message: ProposerPreferences,
    #[serde(deserialize_with = "bytes")]
    signature: XMSSSignature,
}

#[derive(Deserialize)]
struct ProposerPreferences {
    #[serde(deserialize_with = "bytes")]
    dependent_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    proposal_slot: u64,
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    #[serde(deserialize_with = "bytes")]
    fee_recipient: [u8; 20],
    #[serde(deserialize_with = "uint64")]
    target_gas_limit: u64,
}

impl SubmittedEntry for SubmittedProposerPreferences {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::ProposerPreferences])
    }

    fn ssz_len(&self) -> usize {
        SIGNED_PROPOSER_PREFERENCES_PQ_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let message = &self.message;
        ssz[0..32].copy_from_slice(&message.dependent_root);
        ssz[32..40].copy_from_slice(&message.proposal_slot.to_le_bytes());
        ssz[40..48].copy_from_slice(&message.validator_index.to_le_bytes());
        ssz[48..68].copy_from_slice(&message.fee_recipient);
        ssz[68..76].copy_from_slice(&message.target_gas_limit.to_le_bytes());
        ssz[PROPOSER_PREFERENCES_SIZE..].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCacheProducer,
        ssz_view::{ProposerPreferencesView, SignedProposerPreferencesPqView},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::ctx,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/validator/proposer_preferences";

    fn preferences(proposal_slot: u64) -> String {
        format!(
            "{{\"message\":{{\"dependent_root\":\"0x{}\",\"proposal_slot\":\"{proposal_slot}\",\
             \"validator_index\":\"9\",\"fee_recipient\":\"0x{}\",\
             \"target_gas_limit\":\"60000000\"}},\"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(20),
            "44".repeat(size_of::<XMSSSignature>()),
        )
    }

    fn versioned<'a>(body: &'a str, version: Option<&'a str>) -> ParsedRequest<'a> {
        ParsedRequest { eth_consensus_version: version, ..posting(PATH, body) }
    }

    #[test]
    fn accepted_preferences_carry_their_index_topic_and_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!("[{},{}]", preferences(40), preferences(41));
        let posted = versioned(&body, Some("pq"));
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the preferences defer")
        };
        let [_, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::ProposerPreferences));

        let ssz: &[u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE] =
            submissions.read_buffer(second.ssz).unwrap().try_into().unwrap();
        let message = SignedProposerPreferencesPqView::message(ssz);
        assert_eq!(ProposerPreferencesView::dependent_root(message), &[0x11; 32]);
        assert_eq!(ProposerPreferencesView::proposal_slot(message), 41);
        assert_eq!(ProposerPreferencesView::validator_index(message), 9);
        assert_eq!(ProposerPreferencesView::fee_recipient(message), &[0x22; 20]);
        assert_eq!(ProposerPreferencesView::target_gas_limit(message), 60_000_000);
        assert_eq!(
            SignedProposerPreferencesPqView::signature(ssz),
            &[0x44; size_of::<XMSSSignature>()]
        );
    }

    #[test]
    fn preferences_name_pq_and_come_as_a_non_empty_array() {
        let ctx = ctx();
        let body = format!("[{}]", preferences(40));
        for version in [None, Some("gloas")] {
            let response = dispatch(&ctx, &versioned(&body, version)).1;
            assert_eq!(status_code(&response), "400", "{version:?}");
        }
        for body in ["", "[]", "{}", &preferences(40)] {
            let response = dispatch(&ctx, &versioned(body, Some("pq"))).1;
            assert_eq!(status_code(&response), "400", "{body:?}");
        }
    }

    /// Lighthouse posts the SSZ list; it publishes what the JSON spelling
    /// encodes to.
    #[test]
    fn ssz_preferences_are_published_as_sent() {
        let json = format!("[{},{}]", preferences(40), preferences(41));
        let mut submissions = submissions();
        let Outcome::AwaitingVerdicts(from_json) =
            dispatch_into(&ctx(), &versioned(&json, Some("pq")), &mut submissions).0
        else {
            panic!("the preferences defer")
        };
        let encoded: Vec<_> = from_json
            .accepted
            .iter()
            .map(|accepted| submissions.read_buffer(accepted.ssz).unwrap().to_vec())
            .collect();

        let body = encoded.concat();
        let posted = ParsedRequest {
            body: &body,
            content_type: Some("application/octet-stream"),
            ..versioned("", Some("pq"))
        };
        let Outcome::AwaitingVerdicts(from_ssz) =
            dispatch_into(&ctx(), &posted, &mut submissions).0
        else {
            panic!("the preferences defer")
        };
        let published: Vec<_> = from_ssz
            .accepted
            .iter()
            .map(|accepted| (accepted.topic, submissions.read_buffer(accepted.ssz).unwrap()))
            .collect();
        assert_eq!(published, [
            (GossipTopic::ProposerPreferences, &encoded[0][..]),
            (GossipTopic::ProposerPreferences, &encoded[1][..]),
        ]);

        let truncated = ParsedRequest { body: &body[..body.len() - 1], ..posted };
        assert_eq!(status_code(&dispatch(&ctx(), &truncated).1), "400");
    }
}
