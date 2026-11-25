use serde::Deserialize;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, bls};
use silver_common::{
    GossipTopic, compute_subnet_for_attestation,
    json_fields::{HexBytes, bytes, uint64},
    ssz_view::{
        ATTESTATION_DATA_SIZE, INDEXED_ATTESTATION_PQ_FIXED, MAX_ATTESTING_INDICES_PQ,
        MAX_STARK_PROOF_SIZE, PROPOSER_SLASHING_PQ_SIZE, SINGLE_ATT_PQ_SIZE, XMSSSignature,
    },
    xmss::attestation_leaf,
};
use silver_crypto_simd::xmss::leaf_index;

use crate::{
    ctx::ApiCtx,
    entry_signatures::{SignatureCheck, xmss_signing_key},
    http::{ids::uint64_list, response::Response, router::Request},
    submission::{SubmittedEntry, post_single_submission, post_submission},
    validator::attestation_data::AttestationData,
};

pub(crate) fn post_attestations(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    silver_log::info!("attestation: received signed attestations");
    resp.answer_on_dispatch();
    post_submission::<SubmittedAttestation>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedAttestation {
    #[serde(deserialize_with = "uint64")]
    committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    attester_index: u64,
    data: AttestationData,
    #[serde(deserialize_with = "bytes")]
    signature: XMSSSignature,
}

impl SubmittedEntry for SubmittedAttestation {
    fn accept(&self, ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        let slot = self.data.slot;
        let committees_per_slot = ctx
            .read_state(|view| ctx.shufflings.committees_per_slot(&view, slot / SLOTS_PER_EPOCH))
            .ok_or("no committee shuffling for the attestation's epoch")?;
        if self.committee_index >= committees_per_slot {
            return Err("committee_index is past the epoch's committee count");
        }
        let subnet = compute_subnet_for_attestation(
            ctx.spec.fork_at_slot(slot),
            committees_per_slot,
            slot,
            self.committee_index,
        );
        Ok([GossipTopic::BeaconAttestation(subnet)])
    }

    fn signature_check(&self, ctx: &ApiCtx) -> Result<Option<SignatureCheck>, &'static str> {
        let epoch = self.data.target.epoch;
        let leaf_index = leaf_index(&self.signature);
        if attestation_leaf(epoch) != Some(leaf_index) {
            return Err("incorrect XMSS attestation leaf");
        }
        let pubkey = ctx
            .read_state(|view| xmss_signing_key(&view, self.attester_index))
            .ok_or("attester_index names no XMSS validator")?;
        let domain = ctx.domain(bls::DOMAIN_BEACON_ATTESTER, epoch);
        Ok(Some(SignatureCheck {
            validator: self.attester_index,
            epoch,
            leaf_index,
            pubkey,
            signing_root: bls::compute_signing_root(&self.data.hash_tree_root(), &domain),
            signature: self.signature,
        }))
    }

    fn ssz_len(&self) -> usize {
        SINGLE_ATT_PQ_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.committee_index.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.attester_index.to_le_bytes());
        self.data.encode((&mut ssz[16..144]).try_into().expect("128 bytes"));
        ssz[144..].copy_from_slice(&self.signature);
    }
}

pub(crate) fn post_proposer_slashing(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_single_submission::<SubmittedProposerSlashing>(req, ctx, resp);
}

pub(crate) fn post_attester_slashing(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if req.eth_consensus_version != Some("pq") {
        resp.error(400, "Eth-Consensus-Version must name pq");
        return;
    }
    post_single_submission::<SubmittedAttesterSlashing>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedProposerSlashing {
    signed_header_1: SubmittedSignedHeader,
    signed_header_2: SubmittedSignedHeader,
}

#[derive(Deserialize)]
struct SubmittedSignedHeader {
    message: SubmittedHeader,
    #[serde(deserialize_with = "bytes")]
    signature: XMSSSignature,
}

#[derive(Deserialize)]
struct SubmittedHeader {
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    #[serde(deserialize_with = "uint64")]
    proposer_index: u64,
    #[serde(deserialize_with = "bytes")]
    parent_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    state_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    body_root: [u8; 32],
}

impl SubmittedSignedHeader {
    const SIZE: usize = PROPOSER_SLASHING_PQ_SIZE / 2;

    fn encode(&self, ssz: &mut [u8]) {
        let header = &self.message;
        ssz[0..8].copy_from_slice(&header.slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&header.proposer_index.to_le_bytes());
        ssz[16..48].copy_from_slice(&header.parent_root);
        ssz[48..80].copy_from_slice(&header.state_root);
        ssz[80..112].copy_from_slice(&header.body_root);
        ssz[112..Self::SIZE].copy_from_slice(&self.signature);
    }
}

impl SubmittedEntry for SubmittedProposerSlashing {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::ProposerSlashing])
    }

    fn ssz_len(&self) -> usize {
        PROPOSER_SLASHING_PQ_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let (first, second) = ssz.split_at_mut(SubmittedSignedHeader::SIZE);
        self.signed_header_1.encode(first);
        self.signed_header_2.encode(second);
    }
}

#[derive(Deserialize)]
struct SubmittedAttesterSlashing<'a> {
    #[serde(borrow)]
    attestation_1: IndexedAttestation<'a>,
    #[serde(borrow)]
    attestation_2: IndexedAttestation<'a>,
}

#[derive(Deserialize)]
struct IndexedAttestation<'a> {
    #[serde(deserialize_with = "uint64_list")]
    attesting_indices: Vec<u64>,
    data: AttestationData,
    #[serde(borrow)]
    proof: HexBytes<'a, MAX_STARK_PROOF_SIZE>,
}

impl IndexedAttestation<'_> {
    fn proof_at(&self) -> usize {
        INDEXED_ATTESTATION_PQ_FIXED + 8 * self.attesting_indices.len()
    }

    fn ssz_len(&self) -> usize {
        self.proof_at() + self.proof.byte_len()
    }

    fn encode(&self, ssz: &mut [u8]) {
        let proof_at = self.proof_at();
        ssz[0..4].copy_from_slice(&(INDEXED_ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        let data = &mut ssz[4..4 + ATTESTATION_DATA_SIZE];
        self.data.encode(data.try_into().expect("ATTESTATION_DATA_SIZE bytes"));
        ssz[4 + ATTESTATION_DATA_SIZE..INDEXED_ATTESTATION_PQ_FIXED]
            .copy_from_slice(&(proof_at as u32).to_le_bytes());
        let indices = ssz[INDEXED_ATTESTATION_PQ_FIXED..proof_at].chunks_exact_mut(8);
        for (chunk, index) in indices.zip(&self.attesting_indices) {
            chunk.copy_from_slice(&index.to_le_bytes());
        }
        self.proof.decode_into(&mut ssz[proof_at..]);
    }
}

impl SubmittedEntry for SubmittedAttesterSlashing<'_> {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        let attestations = [&self.attestation_1, &self.attestation_2];
        if attestations.iter().any(|a| a.attesting_indices.len() > MAX_ATTESTING_INDICES_PQ) {
            return Err("attesting_indices exceeds MAX_ATTESTING_INDICES_PQ");
        }
        Ok([GossipTopic::AttesterSlashing])
    }

    fn ssz_len(&self) -> usize {
        8 + self.attestation_1.ssz_len() + self.attestation_2.ssz_len()
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let second_at = 8 + self.attestation_1.ssz_len();
        ssz[0..4].copy_from_slice(&8u32.to_le_bytes());
        ssz[4..8].copy_from_slice(&(second_at as u32).to_le_bytes());
        self.attestation_1.encode(&mut ssz[8..second_at]);
        self.attestation_2.encode(&mut ssz[second_at..]);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::LazyLock;

    use silver_beacon_state_data::xmss::compute_xmss_attestation_leaf_index;
    use silver_common::{
        TCacheProducer,
        ssz_hash::hash_attestation_data,
        ssz_view::{
            AttesterSlashingPqView, BEACON_BLOCK_HEADER_SIZE, BeaconBlockHeaderView,
            IndexedAttestationPqView, ProposerSlashingPqView, SingleAttestationPqView,
        },
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::{
            MAX_SUBMISSION_ENTRIES, SubmissionFailure,
            tests::{PQ_ACTIVE, SLOT, ctx, posted_committees, pq_ctx, xmss_signature},
        },
        testing::{body, dispatch, dispatch_into, posting, status_code, submissions},
    };

    const TARGET_EPOCH: u64 = 300;

    /// Every validator's, as they share one key and attest to the same data.
    static SIGNATURE: LazyLock<XMSSSignature> = LazyLock::new(|| signature_targeting(TARGET_EPOCH));

    /// One entry of the array a validator client posts, spelled as the
    /// schemas do.
    pub(crate) fn entry(attester_index: u64, committee_index: u64) -> String {
        entry_signed(TARGET_EPOCH, attester_index, committee_index, &SIGNATURE)
    }

    fn forged_entry(attester_index: u64, committee_index: u64) -> String {
        let mut signature = *SIGNATURE;
        signature[100] ^= 1;
        entry_signed(TARGET_EPOCH, attester_index, committee_index, &signature)
    }

    fn entry_signed(
        target_epoch: u64,
        attester_index: u64,
        committee_index: u64,
        signature: &XMSSSignature,
    ) -> String {
        format!(
            "{{\"committee_index\":\"{committee_index}\",\"attester_index\":\"{attester_index}\",\
             \"data\":{{\"slot\":\"{SLOT}\",\"index\":\"0\",\
             \"beacon_block_root\":\"0x{}\",\
             \"source\":{{\"epoch\":\"298\",\"root\":\"0x{}\"}},\
             \"target\":{{\"epoch\":\"{target_epoch}\",\"root\":\"0x{}\"}}}},\
             \"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            hex::encode(signature),
        )
    }

    pub(crate) fn signature() -> XMSSSignature {
        *SIGNATURE
    }

    fn signature_targeting(target_epoch: u64) -> XMSSSignature {
        let mut data = [0; ATTESTATION_DATA_SIZE];
        data[0..8].copy_from_slice(&SLOT.to_le_bytes());
        data[16..48].copy_from_slice(&[0x11; 32]);
        data[48..56].copy_from_slice(&298u64.to_le_bytes());
        data[56..88].copy_from_slice(&[0x22; 32]);
        data[88..96].copy_from_slice(&target_epoch.to_le_bytes());
        data[96..128].copy_from_slice(&[0x33; 32]);
        let leaf = compute_xmss_attestation_leaf_index(target_epoch);
        xmss_signature(bls::DOMAIN_BEACON_ATTESTER, &hash_attestation_data(&data), leaf)
    }

    fn submit(ctx: &ApiCtx, body: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &posting("/eth/v2/beacon/pool/attestations", body))
    }

    fn json_failures(response: &[u8]) -> Vec<serde_json::Value> {
        assert_eq!(status_code(response), "400");
        let parsed: serde_json::Value = serde_json::from_slice(body(response)).unwrap();
        parsed["failures"].as_array().unwrap().clone()
    }

    #[test]
    fn accepted_attestation_carries_its_subnet_and_the_ssz() {
        let ctx = pq_ctx();
        let body = format!("[{}]", entry(2, 0));
        let mut submissions = submissions();
        let posted = posting("/eth/v2/beacon/pool/attestations", &body);
        let Outcome::Dispatched(submission) = dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the attestation is dispatched")
        };
        let [attestation] = submission.accepted.as_slice() else { panic!("one accepted") };

        assert_eq!(attestation.body_index, 0);
        let subnet = compute_subnet_for_attestation(
            ctx.spec.fork_at_slot(SLOT),
            posted_committees(&ctx),
            SLOT,
            0,
        );
        assert_eq!(attestation.topic, GossipTopic::BeaconAttestation(subnet));

        let ssz: &[u8; SINGLE_ATT_PQ_SIZE] =
            submissions.read_buffer(attestation.ssz).unwrap().try_into().unwrap();
        assert_eq!(SingleAttestationPqView::committee_index(ssz), 0);
        assert_eq!(SingleAttestationPqView::attester_index(ssz), 2);
        let data = SingleAttestationPqView::data(ssz);
        assert_eq!(data.slot(), SLOT);
        assert_eq!(data.beacon_block_root(), &[0x11; 32]);
        assert_eq!(data.source_epoch(), 298);
        assert_eq!(data.source_root(), &[0x22; 32]);
        assert_eq!(data.target_epoch(), 300);
        assert_eq!(data.target_root(), &[0x33; 32]);
        assert_eq!(SingleAttestationPqView::signature(ssz), &signature());
    }

    /// A forged signature fails its entry alone, before it can take the
    /// attester's lock.
    #[test]
    fn forged_signature_fails_its_entry_while_the_others_are_published() {
        let ctx = pq_ctx();
        let body = format!("[{},{},{}]", entry(1, 0), forged_entry(2, 0), entry(3, 0));
        let Outcome::Dispatched(submission) = submit(&ctx, &body).0 else {
            panic!("the genuine entries defer")
        };
        let accepted: Vec<_> = submission.accepted.iter().map(|entry| entry.body_index).collect();
        assert_eq!(accepted, [0, 2]);
        assert_eq!(submission.failures, [SubmissionFailure {
            body_index: 1,
            message: "invalid signature"
        }]);
    }

    #[test]
    fn unknown_attester_fails_its_entry() {
        let response = submit(&pq_ctx(), &format!("[{}]", entry(PQ_ACTIVE as u64, 0))).1;
        let failures = json_failures(&response);
        assert_eq!(failures[0]["message"], "attester_index names no XMSS validator");
    }

    /// The leaf is checked before the registry is read or the signature
    /// verified.
    #[test]
    fn signature_at_another_epoch_s_leaf_fails_its_entry() {
        let body = format!("[{}]", entry_signed(TARGET_EPOCH, 1, 0, &signature_targeting(299)));
        let response = submit(&pq_ctx(), &body).1;
        assert_eq!(json_failures(&response)[0]["message"], "incorrect XMSS attestation leaf");
    }

    #[test]
    fn body_past_the_submission_entry_cap_is_a_400() {
        let ctx = pq_ctx();
        let at_cap = format!("[{}]", vec![entry(1, 0); MAX_SUBMISSION_ENTRIES].join(","));
        assert!(matches!(submit(&ctx, &at_cap).0, Outcome::Dispatched(_)));

        let past_cap = format!("[{}]", vec![entry(1, 0); MAX_SUBMISSION_ENTRIES + 1].join(","));
        let (outcome, response) = submit(&ctx, &past_cap);
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&response), "400");
        assert_eq!(
            body(&response),
            b"{\"code\":400,\"message\":\"too many entries in request body\"}"
        );
    }

    /// Entries the posted shuffling cannot place are reported by their place
    /// in the body, and the rest of the submission still goes out.
    #[test]
    fn unresolvable_entries_fail_by_index_while_the_others_are_published() {
        let ctx = pq_ctx();
        let past_the_count = posted_committees(&ctx);
        let body =
            format!("[{},{},{}]", entry(1, past_the_count), entry(1, 0), entry(2, past_the_count),);
        let Outcome::Dispatched(submission) = submit(&ctx, &body).0 else {
            panic!("the resolvable entry is dispatched")
        };
        assert_eq!(submission.accepted.len(), 1);
        assert_eq!(submission.accepted[0].body_index, 1);
        let message = "committee_index is past the epoch's committee count";
        assert_eq!(submission.failures, [
            SubmissionFailure { body_index: 0, message },
            SubmissionFailure { body_index: 2, message },
        ]);
    }

    /// With nothing left to publish the 400 is written straight away, naming
    /// every entry and why it failed.
    #[test]
    fn submission_that_resolves_nothing_is_an_indexed_400() {
        let ctx = pq_ctx();
        let body = format!("[{}]", entry(1, posted_committees(&ctx)));
        let (outcome, response) = submit(&ctx, &body);
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&response), "400");

        let failures = json_failures(&response);
        assert_eq!(failures[0]["index"], 0);
        assert_eq!(failures[0]["message"], "committee_index is past the epoch's committee count");
    }

    #[test]
    fn attestations_for_an_unposted_epoch_fail_by_index() {
        let mut ctx = pq_ctx();
        ctx.shufflings = Default::default();
        let response = submit(&ctx, &format!("[{}]", entry(1, 0))).1;
        let failures = json_failures(&response);
        assert_eq!(failures[0]["message"], "no committee shuffling for the attestation's epoch");
    }

    const PROPOSER_SLASHINGS: &str = "/eth/v1/beacon/pool/proposer_slashings";
    const ATTESTER_SLASHINGS: &str = "/eth/v2/beacon/pool/attester_slashings";

    fn signed_header(body_root: &str) -> String {
        format!(
            "{{\"message\":{{\"slot\":\"{SLOT}\",\"proposer_index\":\"3\",\
             \"parent_root\":\"0x{}\",\"state_root\":\"0x{}\",\"body_root\":\"0x{body_root}\"}},\
             \"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(32),
            "44".repeat(size_of::<XMSSSignature>()),
        )
    }

    fn indexed_attestation(indices: &[u64], target_root: &str) -> String {
        let indices: Vec<_> = indices.iter().map(|i| format!("\"{i}\"")).collect();
        format!(
            "{{\"attesting_indices\":[{}],\
             \"data\":{{\"slot\":\"{SLOT}\",\"index\":\"0\",\"beacon_block_root\":\"0x{}\",\
             \"source\":{{\"epoch\":\"298\",\"root\":\"0x{}\"}},\
             \"target\":{{\"epoch\":\"300\",\"root\":\"0x{target_root}\"}}}},\
             \"proof\":\"0x{}\"}}",
            indices.join(","),
            "11".repeat(32),
            "22".repeat(32),
            "44".repeat(indices.len()),
        )
    }

    fn attester_slashing() -> String {
        format!(
            "{{\"attestation_1\":{},\"attestation_2\":{}}}",
            indexed_attestation(&[1, 4, 9], &"33".repeat(32)),
            indexed_attestation(&[4], &"55".repeat(32)),
        )
    }

    fn versioned<'a>(path: &'a str, body: &'a str, version: Option<&'a str>) -> ParsedRequest<'a> {
        ParsedRequest { eth_consensus_version: version, ..posting(path, body) }
    }

    #[test]
    fn accepted_proposer_slashing_carries_its_topic_and_the_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!(
            "{{\"signed_header_1\":{},\"signed_header_2\":{}}}",
            signed_header(&"33".repeat(32)),
            signed_header(&"55".repeat(32)),
        );
        let posted = posting(PROPOSER_SLASHINGS, &body);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the slashing defers")
        };
        let [slashing] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!((slashing.body_index, slashing.topic), (0, GossipTopic::ProposerSlashing));

        let ssz: &[u8; PROPOSER_SLASHING_PQ_SIZE] =
            submissions.read_buffer(slashing.ssz).unwrap().try_into().unwrap();
        let header: &[u8; BEACON_BLOCK_HEADER_SIZE] = ProposerSlashingPqView::header_1(ssz);
        assert_eq!(BeaconBlockHeaderView::slot(header), SLOT);
        assert_eq!(BeaconBlockHeaderView::proposer_index(header), 3);
        assert_eq!(BeaconBlockHeaderView::parent_root(header), &[0x11; 32]);
        assert_eq!(BeaconBlockHeaderView::state_root(header), &[0x22; 32]);
        assert_eq!(BeaconBlockHeaderView::body_root(header), &[0x33; 32]);
        assert_eq!(
            BeaconBlockHeaderView::body_root(ProposerSlashingPqView::header_2(ssz)),
            &[0x55; 32]
        );
        for signature in
            [ProposerSlashingPqView::signature_1(ssz), ProposerSlashingPqView::signature_2(ssz)]
        {
            assert_eq!(signature, &[0x44; size_of::<XMSSSignature>()]);
        }
    }

    #[test]
    fn accepted_attester_slashing_encodes_both_variable_attestations() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = attester_slashing();
        let posted = versioned(ATTESTER_SLASHINGS, &body, Some("pq"));
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the slashing defers")
        };
        let [slashing] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!((slashing.body_index, slashing.topic), (0, GossipTopic::AttesterSlashing));

        let ssz = submissions.read_buffer(slashing.ssz).unwrap();
        assert!(AttesterSlashingPqView::check_size(ssz), "gossip framing accepts it");
        let indices = |bytes: &[u8]| -> Vec<u64> {
            bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
        };
        let (first, second) = (
            AttesterSlashingPqView::attestation_1(ssz),
            AttesterSlashingPqView::attestation_2(ssz),
        );
        assert_eq!(indices(IndexedAttestationPqView::attesting_indices(first)), [1, 4, 9]);
        assert_eq!(indices(IndexedAttestationPqView::attesting_indices(second)), [4]);
        assert_eq!(IndexedAttestationPqView::data(first).target_root(), &[0x33; 32]);
        assert_eq!(IndexedAttestationPqView::data(second).slot(), SLOT);
        assert_eq!(IndexedAttestationPqView::proof(first), &[0x44; 3]);
        assert_eq!(IndexedAttestationPqView::proof(second), &[0x44; 1]);
    }

    #[test]
    fn attester_slashings_name_pq() {
        let ctx = ctx();
        let body = attester_slashing();
        for version in [None, Some("fulu"), Some("gloas")] {
            let posted = versioned(ATTESTER_SLASHINGS, &body, version);
            assert_eq!(status_code(&dispatch(&ctx, &posted).1), "400", "{version:?}");
        }
    }

    #[test]
    fn slashings_are_posted_one_object_at_a_time() {
        let ctx = ctx();
        let header = signed_header(&"33".repeat(32));
        let proposer = format!("[{{\"signed_header_1\":{header},\"signed_header_2\":{header}}}]");
        assert_eq!(status_code(&dispatch(&ctx, &posting(PROPOSER_SLASHINGS, &proposer)).1), "400");
        let attester = format!("[{}]", attester_slashing());
        let posted = versioned(ATTESTER_SLASHINGS, &attester, Some("pq"));
        assert_eq!(status_code(&dispatch(&ctx, &posted).1), "400");
    }

    #[test]
    fn malformed_empty_and_non_json_bodies_are_rejected() {
        let ctx = pq_ctx();
        for body in ["", "{}", "[]", "[0]", &entry(1, 0)] {
            assert_eq!(status_code(&submit(&ctx, body).1), "400", "{body:?}");
        }

        let ssz_body = ParsedRequest {
            content_type: Some("application/octet-stream"),
            ..posting("/eth/v2/beacon/pool/attestations", "")
        };
        assert_eq!(status_code(&dispatch(&ctx, &ssz_body).1), "415");
    }
}
