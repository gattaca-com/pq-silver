use flux::{
    communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo,
    type_hash_derive::TypeHash,
};

use crate::ssz_view::{VRFProof, XMSSPubkey, XMSSSignature};

/// The VC's duty tile and its signer tiles, each owning a share of the keys.
/// A signer loop can take ~0.3 s on a bottom tree, so each queue holds a few
/// slots of every key's requests.
#[from_spine("silver_vc")]
#[derive(Debug)]
pub struct VcSpine {
    pub tile_info: ShmemData<TileInfo>,
    #[queue(size(2usize.pow(14)))]
    pub signer_requests: SpineQueue<SignerRequest>,
    #[queue(size(2usize.pow(13)))]
    pub signer_events: SpineQueue<SignerEvent>,
}

#[derive(Clone, Copy, Debug, TypeHash)]
#[repr(C, u8)]
pub enum SignerRequest {
    Sign(SignRequest),
    /// The wall clock reached `slot`: the trees it signs in are prepared.
    PrepareFor {
        slot: u64,
    },
}

#[derive(Clone, Copy, Debug, TypeHash)]
#[expect(clippy::large_enum_variant, reason = "carried by value in a spine queue slot")]
#[repr(C, u8)]
pub enum SignerEvent {
    /// Each of a signer tile's keys, then `Ready`, before any answer.
    KeyLoaded(XMSSPubkey),
    Ready,
    Signed {
        request: SignRequest,
        answer: SignAnswer,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(C)]
pub struct SignRequest {
    pub slot: u64,
    pub purpose: SignPurpose,
    pub pubkey: XMSSPubkey,
    pub work: KeyWork,
}

/// What a signature is for, carrying what its publish needs, so an answer is
/// published without finding its duty again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(C, u8)]
pub enum SignPurpose {
    Attestation { validator_index: u64, committee_index: u64 },
    Aggregate { validator_index: u64, served: ServedAggregate },
    PayloadAttestation { validator_index: u64 },
    ProposerPreferences { validator_index: u64, dependent_root: [u8; 32] },
    Randao { validator_index: u64 },
    Block,
    Envelope,
}

/// Where a served `{"aggregate", "proof"}` object sits in the duty tile's
/// buffer of its slot's aggregates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(C)]
pub struct ServedAggregate {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeHash)]
#[repr(C, u8)]
pub enum KeyWork {
    Sign {
        leaf_index: u32,
        signing_root: [u8; 32],
    },
    /// The RANDAO reveal, which PQ makes a VRF proof of the slot rather than a
    /// signature.
    VrfProof,
}

#[derive(Clone, Copy, Debug, TypeHash)]
#[expect(clippy::large_enum_variant, reason = "carried by value in a spine queue slot")]
#[repr(C, u8)]
pub enum SignAnswer {
    Signature(XMSSSignature),
    VrfProof(VRFProof),
    Refused,
}
