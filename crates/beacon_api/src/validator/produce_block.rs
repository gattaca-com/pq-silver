use flux_profiler::timed;
use serde::{Deserialize, de::IgnoredAny};
use silver_beacon_state_data::{Slot, SpecConfig};
use silver_common::{
    BeaconApiRequest, BidPolicy, ForkName, PayloadFrame, ProduceBlockFailure, ProducedBlock,
    RandaoReveal, TCacheReader,
    json_fields::{parse_hex, parse_uint64, uint64},
    ssz_view::VRF_PROOF_SIZE,
};
use silver_pbs::BuilderConfig;

use crate::{
    ctx::ApiCtx,
    http::{
        json::wei_decimal,
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

pub(crate) fn produce_block_v4(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(slot) = req.params.get("slot").and_then(parse_uint64) else {
        return resp.error(400, "invalid slot");
    };
    if !ctx.spec.is_pq_at_slot(slot) {
        return resp.error(400, "produceBlockV4 serves PQ slots only");
    }
    if req.eth_consensus_version != Some(ForkName::Pq.name()) {
        return resp.error(400, "Eth-Consensus-Version must name pq");
    }
    let include_payload = match req.query_value("include_payload").as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => return resp.error(400, "include_payload is a required boolean query parameter"),
    };
    let Some(bid_policy) = bid_policy(req, resp) else {
        return;
    };
    let Some((randao_reveal, graffiti)) = proposal_query(req, resp) else {
        return;
    };
    resp.defer(Outcome::AwaitingProducedBlock(ProduceBlockRequest {
        slot,
        randao_reveal,
        graffiti,
        bid_policy,
        include_payload,
        ssz_response: req.accepts_ssz(),
    }));
}

/// The `BuilderConfig` body, in SSZ or JSON, as the p2p bid terms. `None`
/// having answered: PQ blocks are built locally, so naming a builder is an
/// error.
fn bid_policy(req: &Request<'_>, resp: &mut Response<'_>) -> Option<BidPolicy> {
    let (bid_policy, names_builders) = if req.body_is_ssz() {
        let Some(config) = BuilderConfig::parse(req.body) else {
            resp.error(400, "invalid BuilderConfig");
            return None;
        };
        let bid_policy = BidPolicy {
            min_bid: config.min_bid(),
            builder_boost_factor: config.builder_boost_factor(),
        };
        (bid_policy, config.entries().next().is_some())
    } else if req.body_is_json() {
        let Ok(config) = serde_json::from_slice::<JsonBuilderConfig>(req.body) else {
            resp.error(400, "invalid BuilderConfig");
            return None;
        };
        let bid_policy = BidPolicy {
            min_bid: config.min_bid,
            builder_boost_factor: config.builder_boost_factor,
        };
        (bid_policy, !config.builders.is_empty())
    } else {
        resp.error(415, "only an SSZ or JSON BuilderConfig body is read");
        return None;
    };
    if names_builders {
        resp.error(400, "PQ blocks are built locally; the BuilderConfig names builders");
        return None;
    }
    Some(bid_policy)
}

#[derive(Deserialize)]
struct JsonBuilderConfig {
    #[serde(deserialize_with = "uint64")]
    min_bid: u64,
    #[serde(deserialize_with = "uint64")]
    builder_boost_factor: u64,
    builders: Vec<IgnoredAny>,
}

/// The reveal, a `VRFProof` too wide for a spine message, is held in the
/// submissions tcache.
fn proposal_query(req: &Request<'_>, resp: &mut Response<'_>) -> Option<(RandaoReveal, [u8; 32])> {
    let graffiti = match req.query_value("graffiti") {
        None => [0; 32],
        Some(text) => match parse_graffiti(&text) {
            Some(graffiti) => graffiti,
            None => {
                resp.error(400, "invalid graffiti");
                return None;
            }
        },
    };
    let Some(proof) =
        req.query_value("randao_reveal").and_then(|text| parse_hex::<VRF_PROOF_SIZE>(&text))
    else {
        resp.error(400, "randao_reveal is a required VRFProof query parameter");
        return None;
    };
    Some((RandaoReveal::Vrf(resp.hold(&proof)?), graffiti))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProduceBlockRequest {
    slot: Slot,
    randao_reveal: RandaoReveal,
    graffiti: [u8; 32],
    bid_policy: BidPolicy,
    include_payload: bool,
    ssz_response: bool,
}

/// What a produced block is answered with beside the block, as headers and,
/// in JSON, as the body's top-level fields.
pub(crate) struct ProducedBlockMetadata {
    pub(crate) version: &'static str,
    pub(crate) payload_included: bool,
    pub(crate) execution_payload_value: String,
    pub(crate) consensus_block_value: String,
}

impl ProducedBlockMetadata {
    fn new(block: &ProducedBlock, version: &'static str, payload_included: bool) -> Self {
        Self {
            version,
            payload_included,
            execution_payload_value: wei_decimal(&block.execution_payload_value),
            consensus_block_value: wei_decimal(&block.consensus_block_value),
        }
    }

    fn headers(&self) -> [(&str, &str); 4] {
        [
            ("Eth-Consensus-Version", self.version),
            (
                "Eth-Execution-Payload-Included",
                if self.payload_included { "true" } else { "false" },
            ),
            ("Eth-Execution-Payload-Value", &self.execution_payload_value),
            ("Eth-Consensus-Block-Value", &self.consensus_block_value),
        ]
    }
}

impl ProduceBlockRequest {
    pub(crate) fn state_request(&self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::ProduceBlock {
            request_id,
            slot: self.slot,
            randao_reveal: self.randao_reveal,
            graffiti: self.graffiti,
            bid_policy: self.bid_policy,
            builder_config_hash: None,
        }
    }

    #[timed]
    pub(crate) fn respond(
        &self,
        resp: &mut Response<'_>,
        block: Result<ProducedBlock, ProduceBlockFailure>,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let block = match block {
            Ok(block) => block,
            Err(ProduceBlockFailure::SlotNotProposable) => {
                return resp.error(400, "the slot does not follow the head");
            }
            Err(ProduceBlockFailure::InvalidRandaoReveal) => {
                return resp.error(400, "randao_reveal does not verify for the slot's proposer");
            }
            Err(ProduceBlockFailure::NoFeeRecipient) => {
                return resp.error(400, "no fee recipient was prepared for the slot's proposer");
            }
            Err(ProduceBlockFailure::PayloadUnavailable) => {
                return resp.error(503, "the execution client built no payload");
            }
            Err(ProduceBlockFailure::Invalid | ProduceBlockFailure::Internal) => {
                return resp.error(500, "the block could not be produced");
            }
        };
        let version = spec.fork_at_slot(self.slot).name();
        let payload = block.payload.filter(|_| self.include_payload);
        let Some(payload) = payload else {
            return self.respond_without_payload(resp, &block, reader, version);
        };
        let header = reader.acquire(block.header);
        let payload = reader.acquire(payload);
        let (Ok((head, _)), Ok((payload, _))) = (header.buffer(), payload.buffer()) else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let Some(payload) = PayloadFrame::parse(payload) else {
            silver_log::error!(slot = self.slot, "produced block's payload frame is misframed");
            return resp.error(500, "the block could not be read");
        };
        let Some(envelope) = &block.envelope_header else {
            return resp.error(500, "the local envelope is unavailable");
        };
        let metadata = ProducedBlockMetadata::new(&block, version, true);
        if !self.ssz_response {
            return resp.json_with_headers(&metadata.headers(), |json| {
                json.produced_block(&metadata, |json| {
                    json.pq_block_and_envelope(head, envelope, &payload)
                })
            });
        }
        let envelope_at = 4 * 4 + head.len();
        let proofs_at = envelope_at +
            envelope.len() +
            payload.execution_payload.len() +
            payload.execution_requests.len();
        let blobs_at = proofs_at + payload.cell_proofs.len();
        let offsets = [16u32, envelope_at as u32, proofs_at as u32, blobs_at as u32]
            .map(u32::to_le_bytes)
            .concat();
        resp.send(200, Some(SSZ_MEDIA_TYPE), &metadata.headers(), &[
            &offsets,
            head,
            envelope,
            payload.execution_payload,
            payload.execution_requests,
            payload.cell_proofs,
            payload.blobs,
        ]);
    }

    /// A `BeaconBlock` whose bid commits to the payload, which is not
    /// included.
    fn respond_without_payload(
        &self,
        resp: &mut Response<'_>,
        block: &ProducedBlock,
        reader: &mut TCacheReader,
        version: &'static str,
    ) {
        let acquired = reader.acquire(block.header);
        let Ok((beacon_block, _)) = acquired.buffer() else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let metadata = ProducedBlockMetadata::new(block, version, false);
        if self.ssz_response {
            resp.send(200, Some(SSZ_MEDIA_TYPE), &metadata.headers(), &[beacon_block]);
        } else {
            resp.json_with_headers(&metadata.headers(), |json| {
                json.produced_block(&metadata, |json| json.beacon_block_pq(beacon_block))
            });
        }
    }
}

/// Prysm sends graffiti from proposer settings unpadded; the block carries
/// it zero-padded on the right.
fn parse_graffiti(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("0x")?;
    let mut graffiti = [0; 32];
    hex::decode_to_slice(hex, graffiti.get_mut(..hex.len() / 2)?).ok()?;
    Some(graffiti)
}

#[cfg(test)]
mod tests {
    use silver_common::{TCacheProducer, TProducer};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, pq_ctx},
        testing::{dispatch, dispatch_into, request, status_code, submissions},
    };

    const BUILDER_CONFIG_FIXED: usize = 8 + 8 + 4;

    /// A framed `BuilderEntry` with an empty URL and auth data.
    fn builder_entry() -> Vec<u8> {
        let message = [12u32.to_le_bytes().as_slice(), &(SLOT + 1).to_le_bytes()].concat();
        let auth = [100u32.to_le_bytes().as_slice(), &[0; 96], &message].concat();
        let offsets = [36, 36, 36 + auth.len() as u32].map(u32::to_le_bytes).concat();
        [offsets, vec![0; 24], auth].concat()
    }

    fn builder_config(min_bid: u64, boost: u64, builders: &[u8]) -> Vec<u8> {
        let mut ssz = min_bid.to_le_bytes().to_vec();
        ssz.extend_from_slice(&boost.to_le_bytes());
        ssz.extend_from_slice(&(BUILDER_CONFIG_FIXED as u32).to_le_bytes());
        ssz.extend_from_slice(builders);
        ssz
    }

    fn randao() -> String {
        format!("randao_reveal=0x{}", "11".repeat(VRF_PROOF_SIZE))
    }

    fn query() -> String {
        format!("{}&include_payload=false", randao())
    }

    fn post_v4(
        ctx: &ApiCtx,
        query: &str,
        version: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
        submissions: &mut TProducer,
    ) -> (Outcome, Vec<u8>) {
        let path = format!("/eth/v4/validator/blocks/{}", SLOT + 1);
        let req = ParsedRequest {
            query,
            accept: Some(SSZ_MEDIA_TYPE),
            content_type,
            eth_consensus_version: version,
            body,
            ..request("POST", &path)
        };
        dispatch_into(ctx, &req, submissions)
    }

    fn refused(ctx: &ApiCtx, query: &str, version: Option<&str>, body: &[u8]) -> String {
        let ssz = Some(SSZ_MEDIA_TYPE);
        let (outcome, out) = post_v4(ctx, query, version, ssz, body, &mut submissions());
        assert_eq!(outcome, Outcome::Response(None), "{query} {version:?}");
        status_code(&out).to_owned()
    }

    #[test]
    fn request_defers_with_the_query_and_the_bid_terms() {
        let query = format!("{}&graffiti=0x6869", query());
        let body = builder_config(7, 150, &[]);
        let mut submissions = submissions();
        let ssz = Some(SSZ_MEDIA_TYPE);
        let (outcome, out) = post_v4(&pq_ctx(), &query, Some("pq"), ssz, &body, &mut submissions);
        assert!(out.is_empty());
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        let RandaoReveal::Vrf(reveal) = request.randao_reveal else { panic!("a PQ reveal") };
        let reveal = submissions.read_buffer(reveal).unwrap();
        assert_eq!(reveal, &[0x11; VRF_PROOF_SIZE]);
        let mut graffiti = [0; 32];
        graffiti[..2].copy_from_slice(b"hi");
        assert_eq!(request, ProduceBlockRequest {
            slot: SLOT + 1,
            randao_reveal: request.randao_reveal,
            graffiti,
            bid_policy: BidPolicy { min_bid: 7, builder_boost_factor: 150 },
            include_payload: false,
            ssz_response: true,
        });
    }

    #[test]
    fn proposals_name_no_builder() {
        let entry = builder_entry();
        let body = builder_config(0, 100, &[8u32.to_le_bytes().as_slice(), &entry].concat());
        assert_eq!(refused(&pq_ctx(), &query(), Some("pq"), &body), "400");
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        let ctx = pq_ctx();
        let body = builder_config(0, 100, &[]);
        let short = &body[..BUILDER_CONFIG_FIXED - 1];
        let misplaced = [&body[..16], &21u32.to_le_bytes()].concat();
        let pq = Some("pq");
        for (query, version, body) in [
            (query(), pq, short),
            (query(), pq, &misplaced[..]),
            (query(), None, &body[..]),
            (query(), Some("gloas"), &body[..]),
            (format!("randao_reveal=0x{}&include_payload=false", "11".repeat(96)), pq, &body),
            (randao(), pq, &body),
            (format!("{}&include_payload=yes", randao()), pq, &body),
            (format!("{}&graffiti=0x{}", query(), "22".repeat(33)), pq, &body),
        ] {
            assert_eq!(refused(&ctx, &query, version, body), "400", "{query} {version:?}");
        }

        let text = Some("text/plain");
        let (_, out) = post_v4(&ctx, &query(), pq, text, &body, &mut submissions());
        assert_eq!(status_code(&out), "415");
    }

    /// Lighthouse's PQ client: a JSON `BuilderConfig`, and a JSON answer.
    #[test]
    fn json_request_defers_for_a_json_answer() {
        let path = format!("/eth/v4/validator/blocks/{}", SLOT + 1);
        let config = r#"{"min_bid":"7","builder_boost_factor":"150","builders":[]}"#;
        let query = query();
        let req = |body: &'static str| ParsedRequest {
            query: &query,
            accept: Some("application/json"),
            content_type: Some("application/json"),
            eth_consensus_version: Some("pq"),
            body: body.as_bytes(),
            ..request("POST", &path)
        };
        let (outcome, out) = dispatch(&pq_ctx(), &req(config));
        assert!(out.is_empty());
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        assert!(!request.ssz_response);
        assert_eq!(request.bid_policy, BidPolicy { min_bid: 7, builder_boost_factor: 150 });

        let naming_a_builder = r#"{"min_bid":"0","builder_boost_factor":"100","builders":[{}]}"#;
        for body in [naming_a_builder, r#"{"min_bid":7}"#, ""] {
            let (outcome, out) = dispatch(&pq_ctx(), &req(body));
            assert_eq!(outcome, Outcome::Response(None), "{body}");
            assert_eq!(status_code(&out), "400", "{body}");
        }
    }

    #[test]
    fn slots_before_pq_are_a_400() {
        let mut ctx = pq_ctx();
        ctx.spec.pq_fork_epoch = u64::MAX;
        assert_eq!(refused(&ctx, &query(), Some("pq"), &builder_config(0, 100, &[])), "400");
    }
}
