use std::collections::HashSet;

use silver_beacon_state_data::{B256, StateReadView, bls::PublicKey, xmss};
use silver_common::ssz_view::{XMSSPubkey, XMSSSignature};
use silver_crypto_simd::xmss::LANES;

pub(crate) struct SignatureCheck {
    /// A body may hold one entry per validator and epoch.
    pub(crate) validator: u64,
    pub(crate) epoch: u64,
    pub(crate) leaf_index: u32,
    pub(crate) pubkey: XMSSPubkey,
    pub(crate) signing_root: B256,
    pub(crate) signature: XMSSSignature,
}

/// Only active validators sign duties, and activation waits on finality, so
/// every state names the same key at their index.
pub(crate) fn signing_key(view: &StateReadView<'_>, index: u64) -> Option<PublicKey> {
    let index = usize::try_from(index).ok().filter(|&index| index < view.validators.count())?;
    Some(*view.validators.pubkey_decompressed(index))
}

pub(crate) fn xmss_signing_key(view: &StateReadView<'_>, index: u64) -> Option<XMSSPubkey> {
    let index = usize::try_from(index).ok().filter(|&index| index < view.validators.count())?;
    view.validator_xmss_pubkey(index).copied()
}

/// XMSS signatures verify one by one, so checks run a lane group at a time as
/// they are pushed rather than held for the whole body.
pub(crate) struct EntrySignatures {
    pending: Vec<PendingCheck>,
    /// Validator and epoch of every check pushed for this body.
    seen: HashSet<(u64, u64)>,
    repeated: Vec<usize>,
    forged: Vec<usize>,
}

struct PendingCheck {
    body_index: usize,
    check: SignatureCheck,
}

/// Body indices in the order they were pushed.
pub(crate) struct Refused<'a> {
    /// Not verified: an earlier entry has the same validator and epoch.
    pub(crate) repeated: &'a [usize],
    pub(crate) forged: &'a [usize],
}

impl EntrySignatures {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::with_capacity(LANES),
            seen: HashSet::new(),
            repeated: Vec::new(),
            forged: Vec::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.seen.clear();
        self.repeated.clear();
        self.forged.clear();
    }

    pub(crate) fn push(&mut self, body_index: usize, check: SignatureCheck) {
        if !self.seen.insert((check.validator, check.epoch)) {
            self.repeated.push(body_index);
            return;
        }
        self.pending.push(PendingCheck { body_index, check });
        if self.pending.len() == LANES {
            self.verify_pending();
        }
    }

    pub(crate) fn verify(&mut self) -> Refused<'_> {
        self.verify_pending();
        Refused { repeated: &self.repeated, forged: &self.forged }
    }

    fn verify_pending(&mut self) {
        let mut valid = [false; LANES];
        let valid = &mut valid[..self.pending.len()];
        let checks = self.pending.iter().map(|PendingCheck { check, .. }| xmss::SignatureCheck {
            public_key: &check.pubkey,
            leaf_index: check.leaf_index.into(),
            signing_root: check.signing_root,
            signature: &check.signature,
        });
        xmss::SignatureCheck::verify_batch(checks, valid);
        let forged = self.pending.drain(..).zip(valid).filter(|(_, valid)| !**valid);
        self.forged.extend(forged.map(|(pending, _)| pending.body_index));
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::xmss::compute_xmss_attestation_leaf_index;
    use silver_crypto_simd::xmss::{BottomTree, SecretKey};

    use super::*;

    /// Attestation leaves of the first epochs share the first bottom tree.
    fn signer() -> (SecretKey, BottomTree) {
        let key = SecretKey::new(&[7; 32]);
        let bottom = key.bottom_tree(0);
        (key, bottom)
    }

    fn check(
        (key, bottom): &(SecretKey, BottomTree),
        signed_epoch: u64,
        epoch: u64,
        validator: u64,
    ) -> SignatureCheck {
        let signing_root = [epoch as u8; 32];
        let leaf = compute_xmss_attestation_leaf_index(signed_epoch) as u32;
        SignatureCheck {
            validator,
            epoch,
            leaf_index: compute_xmss_attestation_leaf_index(epoch) as u32,
            pubkey: key.public_key(),
            signing_root,
            signature: key.sign(bottom, &signing_root, leaf),
        }
    }

    fn verified(signatures: &mut EntrySignatures, checks: Vec<SignatureCheck>) -> [Vec<usize>; 2] {
        signatures.clear();
        for (body_index, check) in checks.into_iter().enumerate() {
            signatures.push(body_index, check);
        }
        let Refused { repeated, forged } = signatures.verify();
        [repeated.to_vec(), forged.to_vec()]
    }

    #[test]
    fn a_body_holds_one_entry_per_validator_and_epoch() {
        let key = signer();
        let mut signatures = EntrySignatures::new();
        let body = || vec![check(&key, 1, 1, 0), check(&key, 1, 1, 0), check(&key, 2, 2, 0)];
        assert_eq!(verified(&mut signatures, body()), [vec![1], vec![]]);
        assert_eq!(verified(&mut signatures, body()), [vec![1], vec![]], "the next body");
    }

    /// Past one lane group, so a forgery in either group is found.
    #[test]
    fn only_entries_signed_at_another_leaf_are_forged() {
        let key = signer();
        let body = (0..LANES as u64 + 3)
            .map(|epoch| {
                let signed_epoch = if epoch == 2 || epoch == LANES as u64 + 1 { 0 } else { epoch };
                check(&key, signed_epoch, epoch, 0)
            })
            .collect();
        assert_eq!(verified(&mut EntrySignatures::new(), body), [vec![], vec![2, LANES + 1]]);
    }
}
