use flux_profiler::timed;
use silver_beacon_state_data::{Slot, SpecConfig};
use silver_common::{
    BeaconApiRequest, BidPolicy, ForkName, PayloadFrame, ProduceBlockFailure, ProducedBlock,
    RandaoReveal, TCacheReader,
    json_fields::{parse_hex, parse_uint64},
    ssz_view::VRF_PROOF_SIZE,
};
use silver_pbs::BuilderConfig;

use crate::{
    ctx::ApiCtx,
    http::{
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

pub(crate) fn produce_block_v4(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(slot) = proposal_slot(req, resp) else {
        return;
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
    if !req.body_is_ssz() {
        return resp.error(415, "only an SSZ BuilderConfig body is read");
    }
    let Some(builder_config) = BuilderConfig::parse(req.body) else {
        return resp.error(400, "invalid BuilderConfig");
    };
    if builder_config.entries().next().is_some() {
        return resp.error(400, "PQ blocks are built locally; the BuilderConfig names builders");
    }
    let Some((randao_reveal, graffiti)) = proposal_query(req, resp) else {
        return;
    };
    let bid_policy = BidPolicy {
        min_bid: builder_config.min_bid(),
        builder_boost_factor: builder_config.builder_boost_factor(),
    };
    resp.defer(Outcome::AwaitingProducedBlock(ProduceBlockRequest {
        slot,
        randao_reveal,
        graffiti,
        bid_policy,
        include_payload,
    }));
}

fn proposal_slot(req: &Request<'_>, resp: &mut Response<'_>) -> Option<Slot> {
    if !req.accepts_ssz() {
        resp.error(406, "only application/octet-stream is served");
        return None;
    }
    let slot = req.params.get("slot").expect("{slot} in the route pattern");
    let slot = parse_uint64(slot);
    if slot.is_none() {
        resp.error(400, "invalid slot");
    }
    slot
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
        let payload = block.payload.filter(|_| self.include_payload);
        let Some(payload) = payload else {
            return self.respond_without_payload(resp, &block, reader, spec);
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
        let envelope_at = 4 * 4 + head.len();
        let proofs_at = envelope_at +
            envelope.len() +
            payload.execution_payload.len() +
            payload.execution_requests.len();
        let blobs_at = proofs_at + payload.cell_proofs.len();
        let offsets = [16u32, envelope_at as u32, proofs_at as u32, blobs_at as u32]
            .map(u32::to_le_bytes)
            .concat();
        let payload_value = wei_decimal(&block.execution_payload_value);
        let block_value = wei_decimal(&block.consensus_block_value);
        let headers = [
            ("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name()),
            ("Eth-Execution-Payload-Included", "true"),
            ("Eth-Execution-Payload-Value", payload_value.as_str()),
            ("Eth-Consensus-Block-Value", block_value.as_str()),
        ];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &[
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
        spec: &SpecConfig,
    ) {
        let acquired = reader.acquire(block.header);
        let Ok((beacon_block, _)) = acquired.buffer() else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let payload_value = wei_decimal(&block.execution_payload_value);
        let block_value = wei_decimal(&block.consensus_block_value);
        let headers = [
            ("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name()),
            ("Eth-Execution-Payload-Included", "false"),
            ("Eth-Execution-Payload-Value", payload_value.as_str()),
            ("Eth-Consensus-Block-Value", block_value.as_str()),
        ];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &[beacon_block]);
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

fn wei_decimal(little_endian: &[u8; 32]) -> String {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(little_endian.chunks_exact(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
    }
    let mut digits = Vec::new();
    loop {
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let current = (remainder << 64) | u128::from(*limb);
            *limb = (current / 10) as u64;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
        if limbs == [0; 4] {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
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

        let json = Some("application/json");
        let (_, out) = post_v4(&ctx, &query(), pq, json, &body, &mut submissions());
        assert_eq!(status_code(&out), "415");
    }

    #[test]
    fn json_only_client_is_a_406() {
        let path = format!("/eth/v4/validator/blocks/{}", SLOT + 1);
        let req = ParsedRequest {
            query: &query(),
            accept: Some("application/json"),
            ..request("POST", &path)
        };
        assert_eq!(status_code(&dispatch(&pq_ctx(), &req).1), "406");
    }

    #[test]
    fn slots_before_pq_are_a_400() {
        let mut ctx = pq_ctx();
        ctx.spec.pq_fork_epoch = u64::MAX;
        assert_eq!(refused(&ctx, &query(), Some("pq"), &builder_config(0, 100, &[])), "400");
    }

    #[test]
    fn wei_decimal_renders_every_limb() {
        assert_eq!(wei_decimal(&[0; 32]), "0");
        let mut two_ether = [0; 32];
        two_ether[..8].copy_from_slice(&2_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(wei_decimal(&two_ether), "2000000000000000000");
        let mut two_to_64 = [0; 32];
        two_to_64[8] = 1;
        assert_eq!(wei_decimal(&two_to_64), "18446744073709551616");
    }
}
