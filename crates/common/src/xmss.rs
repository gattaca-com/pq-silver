//! leanXMSS verification for the PQ consensus fork. The public key is the
//! 16-byte tree root followed by the 16-byte public parameter.
use leanvm_signatures::lean_xmss::{self, LeanXmssPublicKey, LeanXmssSignature};

use crate::ssz_view::{XMSSPubkey, XMSSSignature};

const RESERVED: u64 = 1 << 15;
const ATTESTATION_LEAVES: u64 = 1 << 29;
const BID_START: u64 = RESERVED + ATTESTATION_LEAVES;
const SLOT_START: u64 = BID_START + (1 << 30);

#[derive(Clone, Copy)]
pub enum SlotDuty {
    BeaconProposer = 0,
    AggregateAndProof = 1,
    PtcAttester = 2,
    ProposerPreferences = 3,
    ExecutionPayloadEnvelope = 4,
}

impl SlotDuty {
    pub fn leaf(self, slot: u64) -> Option<u32> {
        u32::try_from(slot.checked_mul(8)?.checked_add(SLOT_START + self as u64)?).ok()
    }
}

pub fn attestation_leaf(epoch: u64) -> Option<u32> {
    (epoch < ATTESTATION_LEAVES).then(|| (RESERVED + epoch) as u32)
}

pub fn builder_bid_leaf(signature: &XMSSSignature) -> Option<u32> {
    let index = leaf_index(signature);
    (BID_START..SLOT_START).contains(&u64::from(index)).then_some(index)
}

pub fn leaf_index(signature: &XMSSSignature) -> u32 {
    u32::from_le_bytes(signature[..4].try_into().unwrap())
}

/// Verify an upstream leanXMSS signature at the leaf assigned to this duty.
pub fn verify(
    pubkey: &XMSSPubkey,
    leaf: u32,
    message: &[u8; 32],
    signature: &XMSSSignature,
) -> bool {
    let signature = LeanXmssSignature::from_bytes(signature);
    signature.leaf_index == leaf &&
        lean_xmss::verify(&LeanXmssPublicKey::from_bytes(pubkey), message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_are_disjoint_at_duty_boundaries() {
        assert_eq!(attestation_leaf(0), Some(1 << 15));
        assert_eq!(attestation_leaf((1 << 29) - 1), Some(BID_START as u32 - 1));
        assert_eq!(attestation_leaf(1 << 29), None);
        let mut signature = [0; size_of::<XMSSSignature>()];
        for (leaf, valid) in
            [(BID_START - 1, false), (BID_START, true), (SLOT_START - 1, true), (SLOT_START, false)]
        {
            signature[..4].copy_from_slice(&(leaf as u32).to_le_bytes());
            assert_eq!(builder_bid_leaf(&signature), valid.then_some(leaf as u32));
        }
        for (i, duty) in [
            SlotDuty::BeaconProposer,
            SlotDuty::AggregateAndProof,
            SlotDuty::PtcAttester,
            SlotDuty::ProposerPreferences,
            SlotDuty::ExecutionPayloadEnvelope,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(duty.leaf(2), Some(SLOT_START as u32 + 16 + i as u32));
            assert_eq!(duty.leaf(u64::MAX), None);
        }
    }
    #[test]
    fn consensus_spec_known_answer() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/xmss_kat.json")).unwrap();
        let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let pk: XMSSPubkey = decode("pubkey").try_into().unwrap();
        let mut message: [u8; 32] = decode("message").try_into().unwrap();
        let mut signature: XMSSSignature = decode("signature").try_into().unwrap();
        let leaf = vector["leaf_index"].as_u64().unwrap() as u32;
        assert!(verify(&pk, leaf, &message, &signature));
        assert!(!verify(&pk, leaf + 1, &message, &signature));
        assert!(!verify(&[0; 32], leaf, &message, &signature));
        message[0] ^= 1;
        assert!(!verify(&pk, leaf, &message, &signature));
        message[0] ^= 1;
        signature[2403] ^= 1;
        assert!(!verify(&pk, leaf, &message, &signature));
    }
}
