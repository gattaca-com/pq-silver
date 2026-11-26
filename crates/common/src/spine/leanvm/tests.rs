use std::sync::OnceLock;

use super::*;
use crate::{TCache, TCacheId, TCacheProducer};

fn request(signatures: u16, lengths: &[ProofLen]) -> LeanVmReq {
    static BODY: OnceLock<TCacheRead> = OnceLock::new();
    let body = *BODY.get_or_init(|| {
        TCache::producer(TCacheId::BeaconStateHandoff, 4096)
            .write_with(1, |out| out[0] = 0)
            .unwrap()
    });
    let mut children = [ProofLen::default(); MAX_PROOFS];
    children[..lengths.len()].copy_from_slice(lengths);
    LeanVmReq { request_id: 0, signatures, proofs: lengths.len() as u8, children, body }
}

fn proof_bytes(claims: &[Claim], proof: &[u8]) -> Vec<u8> {
    let len = ProofLen { claims: claims.len() as u32, proof: proof.len() as u32 };
    let mut body = vec![0; len.bytes()];
    ProofBody::write(&mut body, claims.iter(), proof);
    body
}

fn numbered_proof(len: ProofLen) -> Vec<u8> {
    let claims = (0..len.claims).map(|index| {
        let mut claim = [0; size_of::<Claim>()];
        claim[..4].copy_from_slice(&index.to_be_bytes());
        claim
    });
    let mut body = vec![0; len.bytes()];
    ProofBody::write(&mut body, claims, &vec![0xa5; len.proof as usize]);
    body
}

fn request_bytes<'a>(
    req: &LeanVmReq,
    signatures: &'a [SignedClaim],
    children: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<u8> {
    let mut bytes = vec![0; req.body_len().unwrap()];
    RequestBody::write(&mut bytes, signatures, children);
    bytes
}

#[test]
fn request_body_is_signed_claims_followed_by_children() {
    let signatures = [[0x11; SIGNED_CLAIM_SIZE], [0x22; SIGNED_CLAIM_SIZE]];
    let first = proof_bytes(&[[0x33; 64]], b"\xde\xad");
    let second = proof_bytes(&[[0x44; 64]], b"\xbe");
    let req = request(2, &[ProofLen { claims: 1, proof: 2 }, ProofLen { claims: 1, proof: 1 }]);
    let bytes = request_bytes(&req, &signatures, [first.as_slice(), second.as_slice()]);
    let expected =
        [&[0x11; 2468][..], &[0x22; 2468], &[0x33; 64], b"\xde\xad", &[0x44; 64], b"\xbe"].concat();
    assert_eq!(bytes, expected);

    let split = req.split(&bytes).unwrap();
    assert_eq!(split.signatures, &signatures);
    let [first, second] = split.children() else { panic!("expected two children") };
    assert_eq!(first.claims(), &[[0x33; 64]]);
    assert_eq!(first.proof(), b"\xde\xad");
    assert_eq!(second.claims(), &[[0x44; 64]]);
    assert_eq!(second.proof(), b"\xbe");
}

#[test]
fn request_and_response_byte_caps() {
    assert_eq!(MAX_REQUEST_LEN, 27_131_904);
    assert_eq!(MAX_RESPONSE_LEN, 9_437_184);
}

#[test]
fn proof_at_both_caps_is_accepted() {
    let len = ProofLen { claims: MAX_PROOF_CLAIMS as u32, proof: MAX_STARK_PROOF_SIZE as u32 };
    assert_eq!(len.bytes(), MAX_RESPONSE_LEN);
    let body = numbered_proof(len);

    let split = len.split(&body).unwrap();
    assert_eq!(split.claims().len(), MAX_PROOF_CLAIMS);
    assert_eq!(split.proof().len(), MAX_STARK_PROOF_SIZE);
    assert!(split.proof().iter().all(|&byte| byte == 0xa5));
}

#[test]
fn proof_caps_are_checked_before_the_body_length() {
    for claims in [MAX_PROOF_CLAIMS as u32 + 1, u32::MAX] {
        let len = ProofLen { claims, proof: u32::MAX };
        assert_eq!(len.split(&[]).err(), Some(Malformed::TooManyClaims));
    }
    for proof in [MAX_STARK_PROOF_SIZE as u32 + 1, u32::MAX] {
        let len = ProofLen { claims: 0, proof };
        assert_eq!(len.split(&[]).err(), Some(Malformed::ProofTooLarge));
    }
}

#[test]
fn proof_body_must_match_the_declared_length() {
    let len = ProofLen { claims: 1, proof: 2 };
    let mut body = proof_bytes(&[[0; 64]], &[0; 2]);
    body.push(0);
    for body in [&body[..len.bytes() - 1], &body[..], &[]] {
        assert_eq!(len.split(body).err(), Some(Malformed::LengthMismatch));
    }
}

#[test]
fn proof_claims_must_be_strictly_ascending() {
    let len = ProofLen { claims: 2, proof: 0 };
    for claims in [[[2; 64], [1; 64]], [[1; 64], [1; 64]]] {
        let body = proof_bytes(&claims, &[]);
        assert_eq!(len.split(&body).err(), Some(Malformed::ClaimsNotAscending));
        let req = request(0, &[len]);
        let bytes = request_bytes(&req, &[], [body.as_slice()]);
        assert_eq!(req.split(&bytes).err(), Some(Malformed::ClaimsNotAscending));
    }
}

#[test]
fn request_counts_are_checked_before_reading_children() {
    let mut req = request(u16::MAX, &[]);
    for proofs in [MAX_PROOFS as u8 + 1, u8::MAX] {
        req.proofs = proofs;
        assert_eq!(req.body_len(), Err(Malformed::TooManyProofs));
    }
    req.proofs = 0;
    for signatures in [MAX_SIGNATURES as u16 + 1, u16::MAX] {
        req.signatures = signatures;
        assert_eq!(req.body_len(), Err(Malformed::TooManySignatures));
    }
}

#[test]
fn request_child_caps_are_checked_without_the_body() {
    let mut req = request(0, &[ProofLen::default()]);
    for claims in [MAX_PROOF_CLAIMS as u32 + 1, u32::MAX] {
        req.children[0] = ProofLen { claims, proof: u32::MAX };
        assert_eq!(req.body_len(), Err(Malformed::TooManyClaims));
    }
    for proof in [MAX_STARK_PROOF_SIZE as u32 + 1, u32::MAX] {
        req.children[0] = ProofLen { claims: 0, proof };
        assert_eq!(req.body_len(), Err(Malformed::ProofTooLarge));
    }
}

#[test]
fn capped_children_can_exceed_the_total_request_cap() {
    let len = ProofLen { claims: MAX_PROOF_CLAIMS as u32, proof: MAX_STARK_PROOF_SIZE as u32 };
    let req = request(0, &[len; MAX_PROOFS]);
    assert_eq!(req.body_len(), Err(Malformed::TooLong));
}

#[test]
fn request_body_must_match_the_declared_length() {
    let req = request(1, &[ProofLen { claims: 1, proof: 2 }]);
    let child = proof_bytes(&[[5; 64]], b"ok");
    let mut bytes = request_bytes(&req, &[[8; SIGNED_CLAIM_SIZE]], [child.as_slice()]);
    bytes.push(0);
    for body in [&bytes[..bytes.len() - 2], &bytes[..], &[]] {
        assert_eq!(req.split(body).err(), Some(Malformed::LengthMismatch));
    }
}

#[test]
fn the_largest_proof_with_committee_children_fills_the_request_cap() {
    let largest = ProofLen { claims: MAX_PROOF_CLAIMS as u32, proof: MAX_STARK_PROOF_SIZE as u32 };
    let committee = ProofLen {
        claims: MAX_VALIDATORS_PER_COMMITTEE as u32,
        proof: MAX_STARK_PROOF_SIZE as u32,
    };
    let mut lengths = [committee; MAX_PROOFS];
    lengths[0] = largest;
    let req = request(0, &lengths);
    assert_eq!(req.body_len(), Ok(MAX_REQUEST_LEN));

    let best = numbered_proof(largest);
    let child = numbered_proof(committee);
    let children = std::iter::once(best.as_slice())
        .chain(std::iter::repeat_n(child.as_slice(), MAX_PROOFS - 1));
    let bytes = request_bytes(&req, &[], children);
    assert_eq!(req.split(&bytes).unwrap().children().len(), MAX_PROOFS);
}

#[test]
fn the_largest_proof_with_max_signatures_fits() {
    let largest = ProofLen { claims: MAX_PROOF_CLAIMS as u32, proof: MAX_STARK_PROOF_SIZE as u32 };
    let req = request(MAX_SIGNATURES as u16, &[largest]);
    assert!(req.body_len().unwrap() < MAX_REQUEST_LEN);

    let signatures = vec![[8; SIGNED_CLAIM_SIZE]; MAX_SIGNATURES];
    let child = numbered_proof(largest);
    let bytes = request_bytes(&req, &signatures, [child.as_slice()]);
    assert_eq!(req.split(&bytes).unwrap().signatures, signatures);
}

#[test]
fn a_response_body_is_a_request_child_and_unused_lengths_are_ignored() {
    let len = ProofLen { claims: 2, proof: 3 };
    let response = proof_bytes(&[[1; 64], [2; 64]], b"123");
    let parsed = len.split(&response).unwrap();
    let mut req = request(0, &[len]);
    let bytes = request_bytes(&req, &[], [response.as_slice()]);
    assert_eq!(bytes, response);

    for unused in [ProofLen::default(), ProofLen { claims: u32::MAX, proof: u32::MAX }] {
        req.children[1..].fill(unused);
        assert_eq!(req.body_len(), Ok(len.bytes()));
        let split = req.split(&bytes).unwrap();
        let [child] = split.children() else { panic!("expected one child") };
        assert_eq!(child.claims(), parsed.claims());
        assert_eq!(child.proof(), parsed.proof());
    }
}
