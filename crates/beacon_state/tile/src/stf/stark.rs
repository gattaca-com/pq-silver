use std::ops::Range;

use silver_beacon_state_data::{
    B256, Epoch, Immutable, Version, xmss::compute_xmss_attestation_leaf_index,
};
#[cfg(test)]
use silver_beacon_state_data::{ValidatorsView, pq::xmss_pubkey, xmss::SignatureCheck};
use silver_common::ssz_view::AttestationDataView;
#[cfg(test)]
use silver_common::ssz_view::XMSS_SIGNATURE_SIZE;

use crate::stf::attestation::attester_signing_root;

/// Spec `XMSSAggregateStatement`, its public keys held as validator indices
/// into [`StarkClaims::signers`].
struct Statement {
    #[cfg_attr(not(test), allow(dead_code, reason = "a leanVM sidecar claim has no leaf index"))]
    leaf_index: u64,
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

    /// `fork` is the state's `fork_descriptor`.
    pub(crate) fn attestation(
        &mut self,
        imm: &Immutable,
        fork: (Epoch, Version, Version),
        data: AttestationDataView,
    ) -> AttestationStatements<'_> {
        AttestationStatements {
            leaf_index: compute_xmss_attestation_leaf_index(data.target_epoch()),
            message: attester_signing_root(imm, fork, data),
            claims: self,
        }
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

    /// The spec's reference `stark.VerifyAggregates`, which proves statements
    /// by concatenating their signatures in statement order, then key order.
    #[cfg(test)]
    pub fn verify_reference(&self, body: &[u8], validators: &ValidatorsView) -> bool {
        self.claims.iter().all(|claim| {
            let mut signatures = body[claim.proof.clone()].chunks(XMSS_SIGNATURE_SIZE);
            let statements = &self.statements[claim.statements.clone()];
            let all_verify = statements.iter().all(|statement| {
                self.signers[statement.signers.clone()].iter().all(|&signer| {
                    signatures.next().and_then(|signature| signature.try_into().ok()).is_some_and(
                        |signature| {
                            SignatureCheck {
                                public_key: xmss_pubkey(validators.pubkey(signer as usize)),
                                leaf_index: statement.leaf_index,
                                signing_root: statement.message,
                                signature,
                            }
                            .verify()
                        },
                    )
                })
            });
            all_verify && signatures.next().is_none()
        })
    }
}

pub(crate) struct AttestationStatements<'a> {
    claims: &'a mut StarkClaims,
    leaf_index: u64,
    message: B256,
}

impl AttestationStatements<'_> {
    pub(crate) fn push(&mut self, signers: impl IntoIterator<Item = u32>) {
        let claims = &mut *self.claims;
        let start = claims.signers.len();
        claims.signers.extend(signers);
        claims.statements.push(Statement {
            leaf_index: self.leaf_index,
            message: self.message,
            signers: start..claims.signers.len(),
        });
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        FinalizedValidators, HashFormat, ValidatorsGroup, xmss::compute_xmss_attestation_leaf_index,
    };
    use silver_crypto_simd::xmss::SecretKey;

    use super::{AttestationStatements, StarkClaims};

    /// A one-validator XMSS registry: pubkey, VRF root, then the shared fields.
    fn registry(pubkey: &[u8; 32]) -> ValidatorsGroup {
        let mut record = pubkey.to_vec();
        record.resize(32 + 32 + 32 + 8 + 1 + 4 * 8, 0);
        ValidatorsGroup::new(FinalizedValidators::try_new_xmss(&record).unwrap(), HashFormat::Fixed)
    }

    /// Validator 0's statement of `message` at `leaf_index`.
    fn push_statement(claims: &mut StarkClaims, leaf_index: u64, message: [u8; 32]) {
        AttestationStatements { claims, leaf_index, message }.push([0]);
    }

    #[test]
    fn reference_proof_concatenates_signatures_in_statement_order() {
        let key = SecretKey::new(&[1; 32]);
        let mut group = registry(&key.public_key());
        let validators = group.roll_fresh();
        let validators = validators.reader();

        let leaf = compute_xmss_attestation_leaf_index(3);
        let bottom = key.bottom_tree(0);
        let messages = [[1; 32], [2; 32]];
        let [first, second] = messages.map(|message| key.sign(&bottom, &message, leaf as u32));

        let verifies = |body: &[u8], leaf: u64| {
            let mut claims = StarkClaims::default();
            claims.begin(body);
            push_statement(&mut claims, leaf, messages[0]);
            push_statement(&mut claims, leaf, messages[1]);
            claims.push_proof(0, body);
            claims.verify_reference(body, &validators)
        };
        assert!(verifies(&[first, second].concat(), leaf));
        assert!(!verifies(&[second, first].concat(), leaf));
        assert!(!verifies(&first, leaf), "a signature missing");
        assert!(!verifies(&[&first[..], &second, &[0]].concat(), leaf), "trailing bytes");
        assert!(!verifies(&[first, second].concat(), leaf + 1));
    }

    #[test]
    fn each_proof_comes_with_its_statements_signers() {
        let block = [9, 1, 2, 3];
        let body = &block[1..];
        let mut claims = StarkClaims::default();
        claims.begin(body);
        AttestationStatements { claims: &mut claims, leaf_index: 0, message: [1; 32] }.push([4, 5]);
        claims.push_proof(0, &body[..2]);
        AttestationStatements { claims: &mut claims, leaf_index: 0, message: [2; 32] }.push([6]);
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

    #[test]
    fn no_statements_need_an_empty_proof() {
        let mut group = registry(&[0; 32]);
        let validators = group.roll_fresh();
        let body = [7, 0];
        let mut claims = StarkClaims::default();
        claims.begin(&body);
        claims.push_proof(0, &body[..0]);
        assert!(claims.verify_reference(&body, &validators.reader()));
        claims.push_proof(0, &body[1..]);
        assert!(!claims.verify_reference(&body, &validators.reader()));
    }
}
