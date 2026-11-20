use std::ops::Range;

use silver_beacon_state_data::{B256, EpochView, Immutable};
use silver_common::ssz_view::AttestationDataView;

use crate::stf::attestation::attester_signing_root;

/// Spec `XMSSAggregateStatement`, its public keys held as validator indices
/// into [`StarkClaims::signers`]. A leanVM sidecar claim carries no leaf
/// index, so none is kept.
struct Statement {
    message: B256,
    signers: Range<usize>,
}

/// A proof, as a byte range of the block body, and the statements it proves,
/// in order.
struct ProofClaim {
    statements: Range<usize>,
    proof: Range<usize>,
}

/// Every `stark.VerifyAggregates` call a PQ block makes: its `proof` over the
/// statements of its attestations, and each attester-slashing attestation's
/// `proof` over its one statement. Proofs stay in the block body, so only
/// their positions are kept. The buffers are reused block to block.
#[derive(Default)]
pub struct StarkClaims {
    /// Addresses of the body the proofs are read from.
    body: Range<usize>,
    signers: Vec<u32>,
    statements: Vec<Statement>,
    claims: Vec<ProofClaim>,
}

impl StarkClaims {
    pub fn begin(&mut self, body: &[u8]) {
        let body = body.as_ptr_range();
        self.body = body.start as usize..body.end as usize;
        self.signers.clear();
        self.statements.clear();
        self.claims.clear();
    }

    #[inline]
    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub(crate) fn attestation(
        &mut self,
        imm: &Immutable,
        epoch: &EpochView,
        data: AttestationDataView,
    ) -> AttestationStatements<'_> {
        AttestationStatements { message: attester_signing_root(imm, epoch, data), claims: self }
    }

    /// Claims `proof`, a slice of the body, proves the statements pushed
    /// since `first_statement`.
    pub(crate) fn push_proof(&mut self, first_statement: usize, proof: &[u8]) {
        let proof = self.body_range(proof);
        self.claims.push(ProofClaim { statements: first_statement..self.statements.len(), proof });
    }

    /// Each proof, a slice of `block`, with the `(signer, message)` pairs
    /// its statements claim. `block` holds the body [`Self::begin`] saw.
    pub fn proofs<'a>(
        &'a self,
        block: &'a [u8],
    ) -> impl Iterator<Item = (impl Iterator<Item = (u32, &'a B256)>, &'a [u8])> {
        let start = block.as_ptr() as usize;
        assert!(
            start <= self.body.start && self.body.end <= start + block.len(),
            "the block holds the body its claims were collected from"
        );
        let body = &block[self.body.start - start..self.body.end - start];
        self.claims.iter().map(move |claim| {
            let statements = &self.statements[claim.statements.clone()];
            let signed = statements.iter().flat_map(|statement| {
                let signers = &self.signers[statement.signers.clone()];
                signers.iter().map(|&signer| (signer, &statement.message))
            });
            (signed, &body[claim.proof.clone()])
        })
    }

    fn body_range(&self, part: &[u8]) -> Range<usize> {
        if part.is_empty() {
            return 0..0;
        }
        let start = part.as_ptr() as usize;
        assert!(
            self.body.start <= start && start + part.len() <= self.body.end,
            "a proof is a slice of the block body"
        );
        let offset = start - self.body.start;
        offset..offset + part.len()
    }
}

pub(crate) struct AttestationStatements<'a> {
    claims: &'a mut StarkClaims,
    message: B256,
}

impl AttestationStatements<'_> {
    pub(crate) fn push(&mut self, signers: impl IntoIterator<Item = u32>) {
        let claims = &mut *self.claims;
        let start = claims.signers.len();
        claims.signers.extend(signers);
        claims
            .statements
            .push(Statement { message: self.message, signers: start..claims.signers.len() });
    }
}

#[cfg(test)]
mod tests {
    use super::{AttestationStatements, StarkClaims};

    #[test]
    fn each_proof_comes_with_its_statements_signers() {
        let block = [9, 1, 2, 3];
        let body = &block[1..];
        let mut claims = StarkClaims::default();
        claims.begin(body);
        AttestationStatements { claims: &mut claims, message: [1; 32] }.push([4, 5]);
        claims.push_proof(0, &body[..2]);
        AttestationStatements { claims: &mut claims, message: [2; 32] }.push([6]);
        claims.push_proof(1, &body[2..]);

        let proofs: Vec<_> = claims
            .proofs(&block)
            .map(|(signed, proof)| {
                (signed.map(|(signer, message)| (signer, *message)).collect(), proof)
            })
            .collect::<Vec<(Vec<_>, _)>>();
        let expected =
            [(vec![(4, [1; 32]), (5, [1; 32])], &[1, 2][..]), (vec![(6, [2; 32])], &[3][..])];
        assert_eq!(proofs, expected);
    }
}
