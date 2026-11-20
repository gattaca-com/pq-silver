use std::time::Instant;

use silver_beacon_state_data::{B256, BodyFork, BodyOffsets, SLOTS_PER_EPOCH, bls, xmss};
use silver_common::{
    ForkName, GossipTopic, ProducedBlock, TCacheReader, TRead,
    ssz_hash::HashedBody,
    ssz_view::{ExecutionPayloadHeaderFuluView, SignedBeaconBlockPqView, SignedBeaconBlockView},
    xmss::SlotDuty,
};
use silver_crypto_simd::xmss::leaf_index;

use crate::{
    ctx::ApiCtx,
    entry_signatures::{signing_key, xmss_signing_key},
    http::{response::Response, router::Request},
    submission::{Integration, requested_validation},
};

pub(crate) fn post_block_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    let Some(validation) = requested_validation(req) else {
        return resp.error(400, "invalid broadcast_validation");
    };
    if req.eth_consensus_version != Some(ForkName::Pq.name()) {
        return resp.error(400, "Eth-Consensus-Version must name pq");
    }
    let body = req.body;
    if let Err(reason) = GossipTopic::BeaconBlock.check_pq_signed_message(body) {
        return resp.error(400, reason);
    }
    let slot = SignedBeaconBlockPqView::slot(body);
    if ctx.spec.fork_at_slot(slot) != ForkName::Pq {
        return resp.error(400, "PQ block slot precedes the PQ fork");
    }
    let signature = SignedBeaconBlockPqView::signature(body);
    if SlotDuty::BeaconProposer.leaf(slot) != Some(leaf_index(signature)) {
        return resp.error(400, "incorrect XMSS proposer leaf");
    }
    let Ok(offsets) = BodyOffsets::validated(SignedBeaconBlockPqView::body(body), BodyFork::Pq)
    else {
        return resp.error(400, "invalid block body");
    };
    let hashed = match verify_xmss_proposer_signature(ctx, body, &offsets) {
        Ok(hashed) => hashed,
        Err(message) => return resp.error(400, message),
    };
    let import = Integration::import_of_block(slot, &ctx.spec, Instant::now());
    resp.await_block(body, validation, import, hashed);
}

pub(crate) fn post_blinded_block_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.has_sidecar {
        return resp.error(500, "no sidecar is configured to reveal the payload");
    }
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    // The relay broadcasts the revealed block, so the level is checked but
    // not applied here.
    if requested_validation(req).is_none() {
        return resp.error(400, "invalid broadcast_validation");
    }
    let block = req.body;
    if !SignedBeaconBlockView::check_size(block) {
        return resp.error(400, "invalid SignedBlindedBeaconBlock");
    }
    let slot = SignedBeaconBlockView::slot(block);
    if ctx.spec.is_gloas_at_slot(slot) {
        return resp.error(400, "only Fulu blinded blocks are published");
    }
    if req.eth_consensus_version != Some(ctx.spec.fork_at_slot(slot).name()) {
        return resp.error(400, "Eth-Consensus-Version must name the block's fork");
    }
    let body = BodyOffsets::validated(SignedBeaconBlockView::body(block), BodyFork::FuluBlinded);
    let Some(body) = body
        .ok()
        .filter(|body| ExecutionPayloadHeaderFuluView::check_canonical(body.payload_header()))
    else {
        return resp.error(400, "invalid SignedBlindedBeaconBlock");
    };
    if let Err(message) = verify_proposer_signature(ctx, block, &body) {
        return resp.error(400, message);
    }
    resp.await_blinded_block_lock(block);
}

/// The block this node last produced, pinned in the tcache for a slot.
/// Comparing a submitted body with it costs microseconds; hashing the body
/// costs about a millisecond.
#[derive(Default)]
pub(crate) struct ProducedBody(Option<HeldBlock>);

struct HeldBlock {
    block: ProducedBlock,
    header: TRead,
    payload: Option<TRead>,
    release_at: Instant,
}

impl ProducedBody {
    pub(crate) fn hold(
        &mut self,
        block: ProducedBlock,
        reader: &mut TCacheReader,
        release_at: Instant,
    ) {
        let header = reader.acquire(block.header);
        let payload = block.payload.map(|payload| reader.acquire(payload));
        self.0 = Some(HeldBlock { block, header, payload, release_at });
    }

    pub(crate) fn release_expired(&mut self, now: Instant) {
        if self.0.as_ref().is_some_and(|held| now >= held.release_at) {
            self.0 = None;
        }
    }

    fn root_of(&self, body: &[u8]) -> Option<B256> {
        let HeldBlock { block, header, payload, .. } = self.0.as_ref()?;
        let header = header.buffer().ok()?.0;
        let payload = payload.as_ref().map(TRead::buffer).transpose().ok()?;
        block.has_body(header, payload.map(|(payload, _)| payload), body).then_some(block.body_root)
    }
}

/// The hashed body, unless the body is the one this node produced.
fn verify_proposer_signature(
    ctx: &ApiCtx,
    signed_block: &[u8],
    body: &BodyOffsets<'_>,
) -> Result<Option<HashedBody>, &'static str> {
    let proposer = SignedBeaconBlockView::proposer_index(signed_block);
    let pubkey = ctx
        .read_state(|view| signing_key(&view, proposer))
        .ok_or("proposer_index is past the validator count")?;
    let epoch = SignedBeaconBlockView::slot(signed_block) / SLOTS_PER_EPOCH;
    let domain = ctx.domain(bls::DOMAIN_BEACON_PROPOSER, epoch);
    let (body_root, hashed) = body_root(ctx, SignedBeaconBlockView::body(signed_block), body);
    if !bls::verify_block_signature(signed_block, &pubkey, &body_root, &domain) {
        return Err("invalid block signature");
    }
    Ok(hashed)
}

/// [`verify_proposer_signature`] of a PQ block.
fn verify_xmss_proposer_signature(
    ctx: &ApiCtx,
    signed_block: &[u8],
    body: &BodyOffsets<'_>,
) -> Result<Option<HashedBody>, &'static str> {
    let proposer = SignedBeaconBlockPqView::proposer_index(signed_block);
    let pubkey = ctx
        .read_state(|view| xmss_signing_key(&view, proposer))
        .ok_or("proposer_index names no XMSS validator")?;
    let epoch = SignedBeaconBlockPqView::slot(signed_block) / SLOTS_PER_EPOCH;
    let domain = ctx.domain(bls::DOMAIN_BEACON_PROPOSER, epoch);
    let (body_root, hashed) = body_root(ctx, SignedBeaconBlockPqView::body(signed_block), body);
    let verified = xmss::SignatureCheck::block(signed_block, &pubkey, &body_root, &domain)
        .is_some_and(|check| check.verify());
    if !verified {
        return Err("invalid block signature");
    }
    Ok(hashed)
}

/// The hashed body, unless the body is the one this node produced.
fn body_root(ctx: &ApiCtx, body: &[u8], offsets: &BodyOffsets<'_>) -> (B256, Option<HashedBody>) {
    match ctx.produced_body.root_of(body) {
        Some(root) => (root, None),
        None => {
            let hashed = HashedBody::of(offsets);
            (hashed.root, Some(hashed))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use silver_beacon_state_data::{BeaconBlockHeader, SpecConfig, hash_tree_root_block_header};
    use silver_common::{
        BroadcastValidation, GossipTopic, TCache, TCacheId, TCacheProducer, TCacheTable, TProducer,
        TReadMode,
        ssz_view::{
            BEACON_BLOCK_BODY_FIXED, BEACON_BLOCK_FIXED, EXECUTION_PAYLOAD_HEADER_FIXED,
            SIGNED_PQ_FIXED,
        },
        test_util::{SynthBid, SynthBlock},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::{Outcome, SSZ_MEDIA_TYPE},
        submission::tests::{SLOT, ctx, pq_ctx, validator_signature, xmss_signature},
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v2/beacon/blocks";

    fn gloas_spec() -> SpecConfig {
        SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() }
    }

    fn signed_by_proposer(mut block: Vec<u8>, body_fork: BodyFork, spec: &SpecConfig) -> Vec<u8> {
        let body = SignedBeaconBlockView::body(&block);
        let header = BeaconBlockHeader {
            slot: SignedBeaconBlockView::slot(&block),
            proposer_index: SignedBeaconBlockView::proposer_index(&block),
            parent_root: *SignedBeaconBlockView::parent_root(&block),
            state_root: *SignedBeaconBlockView::state_root(&block),
            body_root: HashedBody::of(&BodyOffsets::validated(body, body_fork).unwrap()).root,
        };
        let signature = validator_signature(
            spec,
            header.proposer_index,
            bls::DOMAIN_BEACON_PROPOSER,
            header.slot / SLOTS_PER_EPOCH,
            &hash_tree_root_block_header(&header),
        );
        block[4..100].copy_from_slice(&signature);
        block
    }

    /// A PQ block of validator 0, which every [`pq_ctx`] validator's key signs.
    pub(crate) fn pq_block() -> Vec<u8> {
        let mut block = SynthBlock::pq(SLOT + 1, SynthBid::new(&[])).into_bytes();
        let body = SignedBeaconBlockPqView::body(&block);
        let header = BeaconBlockHeader {
            slot: SLOT + 1,
            body_root: HashedBody::of(&BodyOffsets::validated(body, BodyFork::Pq).unwrap()).root,
            ..BeaconBlockHeader::default()
        };
        let leaf = xmss::compute_xmss_leaf_index(SLOT + 1, xmss::LeafOffset::BeaconProposer);
        let signature = xmss_signature(
            bls::DOMAIN_BEACON_PROPOSER,
            &hash_tree_root_block_header(&header),
            leaf,
        );
        block[4..4 + signature.len()].copy_from_slice(&signature);
        block
    }

    #[test]
    fn pq_block_signed_by_its_proposer_is_submitted_with_its_hashed_body() {
        let ctx = pq_ctx();
        let block = pq_block();
        let mut submissions = submissions();
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &publishing(&block, "pq"), &mut submissions).0
        else {
            panic!("the block defers")
        };
        let [entry] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!(entry.topic, GossipTopic::BeaconBlock);
        assert_eq!(submissions.read_buffer(entry.ssz).unwrap(), block);
        assert!(submission.hashed_body.is_some(), "hashed once, here");

        let mut forged = block;
        forged[100] ^= 1;
        let (outcome, out) = dispatch(&ctx, &publishing(&forged, "pq"));
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "400");
    }

    fn publishing<'a>(body: &'a [u8], fork: &'static str) -> ParsedRequest<'a> {
        ParsedRequest {
            body,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(fork),
            ..posting(PATH, "")
        }
    }

    fn post(body: &[u8], content_type: &str) -> (Outcome, Vec<u8>) {
        dispatch(&pq_ctx(), &ParsedRequest {
            body,
            content_type: Some(content_type),
            ..posting(PATH, "")
        })
    }

    /// A cache holding `message`, an unsigned block, as this node's produced
    /// block with `body_root`.
    struct Production {
        reader: TCacheReader,
        block: ProducedBlock,
        _cache: TProducer,
    }

    impl Production {
        fn new(message: &[u8], body_root: B256) -> Self {
            let mut cache = TCache::producer(TCacheId::BeaconStateHandoff, 1 << 20);
            let mut reader = TCacheReader::new(TCacheTable::from_iter([cache.cache_ref()]));
            reader.open(TCacheId::BeaconStateHandoff, "test", TReadMode::Sliding).unwrap();
            let header = cache.write_with(message.len(), |out| out.copy_from_slice(message));
            cache.loop_start();
            let block = ProducedBlock {
                header: header.unwrap(),
                payload_at: message.len() as u32,
                payload: None,
                envelope_header: None,
                execution_payload_value: [0; 32],
                consensus_block_value: [0; 32],
                builder_entry: None,
                body_root,
            };
            Self { reader, block, _cache: cache }
        }

        fn held(&mut self, release_at: Instant) -> ProducedBody {
            let mut body = ProducedBody::default();
            body.hold(self.block, &mut self.reader, release_at);
            body
        }
    }

    #[test]
    fn held_block_names_its_root_until_released() {
        let block = gloas_block();
        let mut production = Production::new(&block[100..], [5; 32]);
        let now = Instant::now();
        let mut held = production.held(now + Duration::from_secs(1));

        let body = SignedBeaconBlockView::body(&block);
        assert_eq!(held.root_of(body), Some([5; 32]));
        assert_eq!(held.root_of(&body[1..]), None, "another body is hashed");
        held.release_expired(now);
        assert_eq!(held.root_of(body), Some([5; 32]));
        held.release_expired(now + Duration::from_secs(1));
        assert_eq!(held.root_of(body), None, "a released block is hashed");
    }

    /// The produced root stands in for the hash only when the bodies match,
    /// so a wrong root fails the check only then.
    #[test]
    fn produced_root_is_used_only_for_the_produced_body() {
        let block = pq_block();
        let message = &block[SIGNED_PQ_FIXED..];
        let mut other = message.to_vec();
        other[BEACON_BLOCK_FIXED] ^= 1;
        for (message, accepted) in [(message, false), (&other[..], true)] {
            let mut production = Production::new(message, [9; 32]);
            let mut ctx = pq_ctx();
            ctx.produced_body = production.held(Instant::now() + Duration::from_secs(12));
            let (outcome, _) = dispatch_into(&ctx, &publishing(&block, "pq"), &mut submissions());
            assert_eq!(matches!(outcome, Outcome::AwaitingVerdicts(_)), accepted, "{outcome:?}");
        }
    }

    /// A blinded block another key signed never reaches its proposer's lock.
    #[test]
    fn blinded_block_not_signed_by_its_proposer_is_a_400() {
        let mut blinded = blinded_block();
        blinded[4..100].copy_from_slice(&gloas_block()[4..100]);
        let ctx = sidecar_ctx();
        let (outcome, out) = dispatch(&ctx, &ParsedRequest {
            body: &blinded,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(ctx.spec.fork_at_slot(SLOT + 1).name()),
            ..posting(BLINDED_PATH, "")
        });
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "400");
    }

    #[test]
    fn publication_carries_its_validation_level() {
        let ctx = pq_ctx();
        let body = pq_block();
        let request = |query| ParsedRequest { query, ..publishing(&body, "pq") };
        for (query, validation) in [
            (
                "broadcast_validation=consensus_and_equivocation",
                BroadcastValidation::ConsensusAndEquivocation,
            ),
            ("broadcast_validation=consensus", BroadcastValidation::Consensus),
            ("", BroadcastValidation::Gossip),
        ] {
            let (outcome, _) = dispatch_into(&ctx, &request(query), &mut submissions());
            let Outcome::AwaitingVerdicts(submission) = outcome else {
                panic!("{query}: awaits its verdict")
            };
            assert_eq!(submission.validation, validation, "{query}");
        }
    }

    #[test]
    fn unknown_level_or_a_missing_or_wrong_version_is_a_400() {
        let ctx = pq_ctx();
        let body = pq_block();
        let request = publishing(&body, "pq");
        for refused in [
            ParsedRequest { query: "broadcast_validation=full", ..request },
            ParsedRequest { eth_consensus_version: Some("gloas"), ..request },
            ParsedRequest { eth_consensus_version: None, ..request },
        ] {
            assert_eq!(status_code(&dispatch(&ctx, &refused).1), "400");
        }
    }

    #[test]
    fn json_body_is_a_415() {
        let (outcome, out) = post(b"{}", "application/json");
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "415");
    }

    pub(crate) fn gloas_block() -> Vec<u8> {
        let block = SynthBlock::gloas(SLOT + 1, SynthBid::new(&[])).into_bytes();
        signed_by_proposer(block, BodyFork::Gloas, &gloas_spec())
    }

    #[test]
    fn block_framed_for_another_fork_is_a_400() {
        let mut truncated = pq_block();
        truncated.truncate(truncated.len() - 1);
        for body in [gloas_block(), truncated] {
            let (outcome, out) = dispatch(&pq_ctx(), &publishing(&body, "pq"));
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&out), "400");
        }
    }

    const BLINDED_PATH: &str = "/eth/v2/beacon/blinded_blocks";

    /// A Fulu `SignedBlindedBeaconBlock` with no operations: the header and
    /// three empty request lists.
    pub(crate) fn blinded_block() -> Vec<u8> {
        let header_end = BEACON_BLOCK_BODY_FIXED + EXECUTION_PAYLOAD_HEADER_FIXED;
        let mut block = vec![0; 184 + header_end];
        block[..4].copy_from_slice(&100u32.to_le_bytes());
        block[100..108].copy_from_slice(&(SLOT + 1).to_le_bytes());
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        let body = &mut block[184..];
        for at in [200, 204, 208, 212, 216, 380] {
            body[at..at + 4].copy_from_slice(&(BEACON_BLOCK_BODY_FIXED as u32).to_le_bytes());
        }
        for at in [384, 388, 392] {
            body[at..at + 4].copy_from_slice(&(header_end as u32).to_le_bytes());
        }
        let header = &mut body[BEACON_BLOCK_BODY_FIXED..];
        header[436..440].copy_from_slice(&(EXECUTION_PAYLOAD_HEADER_FIXED as u32).to_le_bytes());
        block.extend_from_slice(&[12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0]);
        signed_by_proposer(block, BodyFork::FuluBlinded, &SpecConfig::mainnet())
    }

    fn post_blinded(ctx: &ApiCtx, body: &[u8], content_type: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &ParsedRequest {
            body,
            content_type: Some(content_type),
            ..posting(BLINDED_PATH, "")
        })
    }

    fn sidecar_ctx() -> ApiCtx {
        let mut ctx = ctx();
        ctx.has_sidecar = true;
        ctx
    }

    #[test]
    fn blinded_block_waits_on_its_proposal_lock() {
        let body = blinded_block();
        let ctx = sidecar_ctx();
        let fork = ctx.spec.fork_at_slot(SignedBeaconBlockView::slot(&body)).name();
        let request = ParsedRequest {
            body: &body,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(fork),
            ..posting(BLINDED_PATH, "")
        };
        let mut submissions = submissions();
        let (outcome, out) = dispatch_into(&ctx, &request, &mut submissions);
        assert!(out.is_empty(), "answered once the sidecar has");
        let Outcome::AwaitingBlindedBlockLock { ssz } = outcome else { panic!("{outcome:?}") };
        assert_eq!(submissions.read_buffer(ssz).unwrap(), body);

        for refused in [
            ParsedRequest { query: "broadcast_validation=full", ..request },
            ParsedRequest { eth_consensus_version: Some("gloas"), ..request },
            ParsedRequest { eth_consensus_version: None, ..request },
        ] {
            assert_eq!(status_code(&dispatch(&ctx, &refused).1), "400");
        }
    }

    #[test]
    fn blinded_block_is_refused_where_it_cannot_be_revealed() {
        let mut gloas = sidecar_ctx();
        gloas.spec.gloas_fork_epoch = 0;
        let mut short_header = blinded_block();
        short_header.truncate(short_header.len() - 13);
        for (ctx, body, content_type, code) in [
            (sidecar_ctx(), blinded_block(), "application/json", "415"),
            (ctx(), blinded_block(), SSZ_MEDIA_TYPE, "500"),
            (gloas, blinded_block(), SSZ_MEDIA_TYPE, "400"),
            (sidecar_ctx(), short_header, SSZ_MEDIA_TYPE, "400"),
        ] {
            let (outcome, out) = post_blinded(&ctx, &body, content_type);
            assert_eq!(outcome, Outcome::Response(None), "{code}");
            assert_eq!(status_code(&out), code);
        }
    }
}
