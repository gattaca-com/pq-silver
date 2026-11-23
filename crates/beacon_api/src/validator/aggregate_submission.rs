use serde::Deserialize;
use silver_common::{
    GossipTopic,
    json_fields::{BoundedHex, HexBytes, bytes, uint64},
    ssz_view::{
        ATTESTATION_PQ_FIXED, COMMITTEE_BITS_SIZE_PQ, MAX_STARK_PROOF_SIZE,
        MAX_VALIDATORS_PER_COMMITTEE, SIGNED_AGG_PROOF_PQ_MIN, SIGNED_PQ_FIXED, XMSSSignature,
        bitvector_word,
    },
    xmss::SlotDuty,
};
use silver_crypto_simd::xmss::leaf_index;

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{SubmittedEntry, post_submission},
    validator::attestation_data::AttestationData,
};

/// A bitlist over one committee: its members and the terminator.
const MAX_AGGREGATION_BITS_LEN: usize = MAX_VALIDATORS_PER_COMMITTEE / 8 + 1;

/// Past `aggregator_index` and the aggregate and proof offsets.
const AGGREGATE_IN_MESSAGE: usize = 8 + 4 + 4;
const _: () = assert!(
    SIGNED_PQ_FIXED + AGGREGATE_IN_MESSAGE + ATTESTATION_PQ_FIXED + 1 == SIGNED_AGG_PROOF_PQ_MIN
);

pub(crate) fn post_aggregate_and_proofs(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_submission::<SubmittedAggregate>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedAggregate<'a> {
    #[serde(borrow)]
    message: SubmittedAggregateAndProof<'a>,
    #[serde(deserialize_with = "bytes")]
    signature: XMSSSignature,
}

#[derive(Deserialize)]
struct SubmittedAggregateAndProof<'a> {
    #[serde(deserialize_with = "uint64")]
    aggregator_index: u64,
    aggregate: SubmittedAggregateAttestation,
    #[serde(borrow)]
    proof: HexBytes<'a, MAX_STARK_PROOF_SIZE>,
}

#[derive(Deserialize)]
struct SubmittedAggregateAttestation {
    aggregation_bits: BoundedHex<MAX_AGGREGATION_BITS_LEN>,
    data: AttestationData,
    #[serde(deserialize_with = "bytes")]
    committee_bits: [u8; COMMITTEE_BITS_SIZE_PQ],
}

impl SubmittedAggregate<'_> {
    fn attestation_len(&self) -> usize {
        ATTESTATION_PQ_FIXED + self.message.aggregate.aggregation_bits.as_bytes().len()
    }
}

impl SubmittedEntry for SubmittedAggregate<'_> {
    fn accept(&self, _ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        let aggregate = &self.message.aggregate;
        if bitvector_word(&aggregate.committee_bits).count_ones() != 1 {
            return Err("committee_bits must name exactly one committee");
        }
        let bits = aggregate.aggregation_bits.as_bytes();
        if bits.last().is_none_or(|&last| last == 0) {
            return Err("aggregation_bits is not a bitlist over one committee");
        }
        if SlotDuty::AggregateAndProof.leaf(aggregate.data.slot) !=
            Some(leaf_index(&self.signature))
        {
            return Err("incorrect XMSS aggregate and proof leaf");
        }
        Ok([GossipTopic::BeaconAggregateAndProof])
    }

    fn ssz_len(&self) -> usize {
        SIGNED_PQ_FIXED +
            AGGREGATE_IN_MESSAGE +
            self.attestation_len() +
            self.message.proof.byte_len()
    }

    fn encode(&self, ssz: &mut [u8]) {
        let aggregate = &self.message.aggregate;
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
        ssz[4..SIGNED_PQ_FIXED].copy_from_slice(&self.signature);

        let message = &mut ssz[SIGNED_PQ_FIXED..];
        let proof_at = AGGREGATE_IN_MESSAGE + self.attestation_len();
        message[0..8].copy_from_slice(&self.message.aggregator_index.to_le_bytes());
        message[8..12].copy_from_slice(&(AGGREGATE_IN_MESSAGE as u32).to_le_bytes());
        message[12..16].copy_from_slice(&(proof_at as u32).to_le_bytes());

        let attestation = &mut message[AGGREGATE_IN_MESSAGE..proof_at];
        attestation[0..4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        aggregate.data.encode((&mut attestation[4..132]).try_into().expect("128 bytes"));
        attestation[132..ATTESTATION_PQ_FIXED].copy_from_slice(&aggregate.committee_bits);
        attestation[ATTESTATION_PQ_FIXED..].copy_from_slice(aggregate.aggregation_bits.as_bytes());
        self.message.proof.decode_into(&mut message[proof_at..]);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{TCacheProducer, ssz_view::SignedAggregateAndProofPqView};

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, ctx},
        testing::{body, dispatch, dispatch_into, posting, status_code, submissions},
    };

    fn signature(leaf: u32) -> String {
        let mut signature = [0x66; size_of::<XMSSSignature>()];
        signature[..4].copy_from_slice(&leaf.to_le_bytes());
        hex::encode(signature)
    }

    fn own_leaf() -> u32 {
        SlotDuty::AggregateAndProof.leaf(SLOT).unwrap()
    }

    /// One entry of the array a validator client posts, spelled as the
    /// schemas do.
    fn entry(aggregation_bits: &str, committee_bits: &str, leaf: u32) -> String {
        format!(
            "{{\"message\":{{\"aggregator_index\":\"7\",\"aggregate\":{{\
             \"aggregation_bits\":\"0x{aggregation_bits}\",\
             \"data\":{{\"slot\":\"{SLOT}\",\"index\":\"0\",\
             \"beacon_block_root\":\"0x{}\",\
             \"source\":{{\"epoch\":\"298\",\"root\":\"0x{}\"}},\
             \"target\":{{\"epoch\":\"300\",\"root\":\"0x{}\"}}}},\
             \"committee_bits\":\"0x{committee_bits}\"}},\
             \"proof\":\"0xabcdef\"}},\"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            signature(leaf),
        )
    }

    fn submit(ctx: &ApiCtx, body: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &posting("/eth/v2/validator/aggregate_and_proofs", body))
    }

    #[test]
    fn accepted_aggregate_encodes_as_the_gossip_message() {
        let entries = format!("[{}]", entry("1a05", "0400", own_leaf()));
        let mut submissions = submissions();
        let posted = posting("/eth/v2/validator/aggregate_and_proofs", &entries);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx(), &posted, &mut submissions).0
        else {
            panic!("the aggregate defers")
        };
        let [accepted] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!(accepted.topic, GossipTopic::BeaconAggregateAndProof);
        let ssz = submissions.read_buffer(accepted.ssz).unwrap();
        assert!(SignedAggregateAndProofPqView::check_size(ssz));
        assert_eq!(leaf_index(SignedAggregateAndProofPqView::signature(ssz)), own_leaf());
        assert_eq!(SignedAggregateAndProofPqView::aggregator_index(ssz), 7);
        let data = SignedAggregateAndProofPqView::agg_data(ssz);
        assert_eq!(data.slot(), SLOT);
        assert_eq!(data.beacon_block_root(), &[0x11; 32]);
        assert_eq!(data.source_root(), &[0x22; 32]);
        assert_eq!(data.target_epoch(), 300);
        assert_eq!(SignedAggregateAndProofPqView::agg_committee_bits(ssz), &[0x04, 0]);
        assert_eq!(SignedAggregateAndProofPqView::agg_aggregation_bits(ssz), &[0x1a, 0x05]);
        assert_eq!(SignedAggregateAndProofPqView::proof(ssz), &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn malformed_entries_fail_by_index() {
        let ctx = ctx();
        let entries = format!(
            "[{},{},{},{},{}]",
            entry("1a05", "0400", own_leaf()),
            entry("1a00", "0400", own_leaf()),
            entry("", "0400", own_leaf()),
            entry("1a05", "0600", own_leaf()),
            entry("1a05", "0400", own_leaf() - 1),
        );
        let Outcome::AwaitingVerdicts(submission) = submit(&ctx, &entries).0 else {
            panic!("the well-formed entry defers")
        };
        assert_eq!(submission.accepted.len(), 1);
        assert_eq!(submission.accepted[0].body_index, 0);
        let failed: Vec<_> =
            submission.failures.iter().map(|f| (f.body_index, f.message)).collect();
        let bitlist = "aggregation_bits is not a bitlist over one committee";
        assert_eq!(failed, [
            (1, bitlist),
            (2, bitlist),
            (3, "committee_bits must name exactly one committee"),
            (4, "incorrect XMSS aggregate and proof leaf"),
        ]);

        let (outcome, response) = submit(&ctx, &format!("[{}]", entry("1a05", "0000", own_leaf())));
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&response), "400");
        let parsed: serde_json::Value = serde_json::from_slice(body(&response)).unwrap();
        assert_eq!(parsed["failures"][0]["index"], 0);
        assert_eq!(
            parsed["failures"][0]["message"],
            "committee_bits must name exactly one committee"
        );
    }

    /// Fields the PQ container dropped, or a committee_bits of the old
    /// width, make the body malformed.
    #[test]
    fn pre_pq_shapes_are_a_malformed_body() {
        let too_long = "01".repeat(MAX_AGGREGATION_BITS_LEN + 1);
        let old_width = entry("1a05", "0400000000000000", own_leaf());
        let odd_proof = entry("1a05", "0400", own_leaf()).replace("0xabcdef", "0xabcde");
        for entry in [entry(&too_long, "0400", own_leaf()), old_width, odd_proof] {
            let (outcome, response) = submit(&ctx(), &format!("[{entry}]"));
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&response), "400");
        }
    }
}
