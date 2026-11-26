use std::borrow::Borrow;

use flux::type_hash_derive::TypeHash;

use super::TCacheRead;
use crate::ssz_view::{MAX_COMMITTEES_PER_SLOT_PQ, MAX_VALIDATORS_PER_COMMITTEE};
pub use crate::ssz_view::{MAX_STARK_PROOF_SIZE, XMSS_SIGNATURE_SIZE};

/// `pubkey | message`, in leanVM's claim order.
pub type Claim = [u8; 64];
pub type SignedClaim = [u8; SIGNED_CLAIM_SIZE];

pub const SIGNED_CLAIM_SIZE: usize = size_of::<Claim>() + XMSS_SIGNATURE_SIZE;
pub const MAX_PROOFS: usize = 16;
pub const MAX_SIGNATURES: usize = 2048;
pub const MAX_PROOF_CLAIMS: usize = 4 * MAX_COMMITTEES_PER_SLOT_PQ * MAX_VALIDATORS_PER_COMMITTEE;
pub const MAX_RESPONSE_LEN: usize =
    ProofLen { claims: MAX_PROOF_CLAIMS as u32, proof: MAX_STARK_PROOF_SIZE as u32 }.bytes();

pub const MAX_REQUEST_LEN: usize = {
    let committee = ProofLen {
        claims: MAX_VALIDATORS_PER_COMMITTEE as u32,
        proof: MAX_STARK_PROOF_SIZE as u32,
    };
    let with_proofs = MAX_RESPONSE_LEN + (MAX_PROOFS - 1) * committee.bytes();
    let with_signatures = MAX_RESPONSE_LEN + MAX_SIGNATURES * SIGNED_CLAIM_SIZE;
    if with_proofs > with_signatures { with_proofs } else { with_signatures }
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TypeHash)]
#[repr(C)]
pub struct ProofLen {
    pub claims: u32,
    pub proof: u32,
}

impl ProofLen {
    pub const fn bytes(self) -> usize {
        self.claims as usize * size_of::<Claim>() + self.proof as usize
    }

    pub fn split(self, body: &[u8]) -> Result<ProofBody<'_>, Malformed> {
        self.check_caps()?;
        if body.len() != self.bytes() {
            return Err(Malformed::LengthMismatch);
        }
        self.split_body(body)
    }

    fn check_caps(self) -> Result<(), Malformed> {
        if self.claims as usize > MAX_PROOF_CLAIMS {
            return Err(Malformed::TooManyClaims);
        }
        if self.proof as usize > MAX_STARK_PROOF_SIZE {
            return Err(Malformed::ProofTooLarge);
        }
        Ok(())
    }

    fn split_body(self, body: &[u8]) -> Result<ProofBody<'_>, Malformed> {
        let proof = ProofBody { body, claims: self.claims };
        if !proof.claims().is_sorted_by(|left, right| left < right) {
            return Err(Malformed::ClaimsNotAscending);
        }
        Ok(proof)
    }
}

#[derive(Clone, Copy, Debug, TypeHash)]
#[repr(C)]
pub struct LeanVmReq {
    pub request_id: u64,
    pub signatures: u16,
    pub proofs: u8,
    /// Entries at or above `proofs` are ignored on receipt.
    pub children: [ProofLen; MAX_PROOFS],
    /// Signed claims, then each child's claims and proof.
    pub body: TCacheRead,
}

impl LeanVmReq {
    pub fn body_len(&self) -> Result<usize, Malformed> {
        let proofs = usize::from(self.proofs);
        if proofs > MAX_PROOFS {
            return Err(Malformed::TooManyProofs);
        }
        let signatures = usize::from(self.signatures);
        if signatures > MAX_SIGNATURES {
            return Err(Malformed::TooManySignatures);
        }
        let mut bytes = signatures * SIGNED_CLAIM_SIZE;
        for &child in &self.children[..proofs] {
            child.check_caps()?;
            bytes += child.bytes();
        }
        if bytes > MAX_REQUEST_LEN {
            return Err(Malformed::TooLong);
        }
        Ok(bytes)
    }

    pub fn split<'a>(&self, body: &'a [u8]) -> Result<RequestBody<'a>, Malformed> {
        if body.len() != self.body_len()? {
            return Err(Malformed::LengthMismatch);
        }
        let (signatures, mut rest) =
            body.split_at(usize::from(self.signatures) * SIGNED_CLAIM_SIZE);
        let (signatures, _) = signatures.as_chunks();
        let mut children = [const { ProofBody { body: &[], claims: 0 } }; MAX_PROOFS];
        let proofs = usize::from(self.proofs);
        for (child, &len) in children.iter_mut().zip(&self.children[..proofs]) {
            let (bytes, tail) = rest.split_at(len.bytes());
            *child = len.split_body(bytes)?;
            rest = tail;
        }
        Ok(RequestBody { signatures, children, proofs })
    }
}

pub struct RequestBody<'a> {
    pub signatures: &'a [SignedClaim],
    children: [ProofBody<'a>; MAX_PROOFS],
    proofs: usize,
}

impl<'a> RequestBody<'a> {
    pub fn children(&self) -> &[ProofBody<'a>] {
        &self.children[..self.proofs]
    }

    pub fn write(
        mut out: &mut [u8],
        signatures: impl IntoIterator<Item = &'a SignedClaim>,
        children: impl IntoIterator<Item = &'a [u8]>,
    ) {
        for bytes in signatures.into_iter().map(SignedClaim::as_slice).chain(children) {
            let (target, rest) = out.split_at_mut(bytes.len());
            target.copy_from_slice(bytes);
            out = rest;
        }
        assert!(out.is_empty(), "aggregate request shorter than its slice");
    }
}

pub struct ProofBody<'a> {
    body: &'a [u8],
    claims: u32,
}

impl<'a> ProofBody<'a> {
    pub fn claims(&self) -> &'a [Claim] {
        self.body[..self.claim_bytes()].as_chunks().0
    }

    pub fn proof(&self) -> &'a [u8] {
        &self.body[self.claim_bytes()..]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.body
    }

    pub fn lengths(&self) -> ProofLen {
        ProofLen { claims: self.claims, proof: self.proof().len() as u32 }
    }

    fn claim_bytes(&self) -> usize {
        self.claims as usize * size_of::<Claim>()
    }

    pub fn write(
        out: &mut [u8],
        claims: impl ExactSizeIterator<Item = impl Borrow<Claim>>,
        proof: &[u8],
    ) {
        let (out_claims, out_proof) = out.split_at_mut(claims.len() * size_of::<Claim>());
        let (out_claims, _) = out_claims.as_chunks_mut();
        for (out, claim) in out_claims.iter_mut().zip(claims) {
            *out = *claim.borrow();
        }
        out_proof.copy_from_slice(proof);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(u8)]
pub enum RefusalCode {
    InvalidInput,
    InvalidSignature,
    InvalidChild,
    ProvingFailed,
    Malformed,
}

#[derive(Clone, Copy, Debug, TypeHash)]
#[repr(C, u8)]
pub enum LeanVmResp {
    /// Claims followed by proof bytes in the LeanVmProcessing tcache.
    Proven {
        request_id: u64,
        claims: u32,
        proof: u32,
        body: TCacheRead,
    },
    Refused {
        request_id: u64,
        reason: RefusalCode,
    },
    NoAnswer {
        request_id: u64,
    },
}

impl LeanVmResp {
    pub fn request_id(&self) -> u64 {
        match self {
            Self::Proven { request_id, .. } |
            Self::Refused { request_id, .. } |
            Self::NoAnswer { request_id } => *request_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    TooManyProofs,
    TooManySignatures,
    TooManyClaims,
    ProofTooLarge,
    TooLong,
    LengthMismatch,
    ClaimsNotAscending,
}

#[cfg(test)]
mod tests;
