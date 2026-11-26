use silver_common::ssz_view::{VRFProof, XMSSPubkey, XMSSSignature};

use crate::beacon_link::RequestId;

/// What a signature is for, so its answer finds its duty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPurpose {
    Attestation,
    Aggregate,
    Randao,
    Block,
    PayloadAttestation,
    ProposerPreferences,
    Envelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWork {
    Sign {
        leaf_index: u32,
        signing_root: [u8; 32],
    },
    /// The RANDAO reveal, which PQ makes a VRF proof rather than a signature.
    VrfProof {
        slot: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub id: RequestId,
    pub purpose: SignPurpose,
    pub pubkey: XMSSPubkey,
    pub work: KeyWork,
}

pub enum SignAnswer {
    #[cfg_attr(not(test), expect(dead_code, reason = "answered by the leanVM signer"))]
    Signature(Box<XMSSSignature>),
    #[cfg_attr(not(test), expect(dead_code, reason = "answered by the VRF prover"))]
    VrfProof(Box<VRFProof>),
    Refused,
}
