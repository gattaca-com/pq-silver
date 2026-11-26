use silver_chain_spec::SpecConfig;
use silver_common::{
    SLOTS_PER_EPOCH,
    ssz_hash::{compute_domain, compute_signing_root},
    ssz_view::{VRFProof, XMSSPubkey, XMSSSignature},
};

use crate::duties::ServedAggregate;

/// What a signature is for, carrying what its publish needs, so an answer is
/// published without finding its duty again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPurpose {
    Attestation { validator_index: u64, committee_index: u64 },
    Aggregate { validator_index: u64, served: ServedAggregate },
    PayloadAttestation { validator_index: u64 },
    ProposerPreferences { validator_index: u64, dependent_root: [u8; 32] },
    Randao { validator_index: u64 },
    Block,
    Envelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWork {
    Sign {
        leaf_index: u32,
        signing_root: [u8; 32],
    },
    /// The RANDAO reveal, which PQ makes a VRF proof of the slot rather than a
    /// signature.
    VrfProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub slot: u64,
    pub purpose: SignPurpose,
    pub pubkey: XMSSPubkey,
    pub work: KeyWork,
}

pub enum SignAnswer<'a> {
    #[cfg_attr(not(test), expect(dead_code, reason = "answered by the leanVM signer"))]
    Signature(&'a XMSSSignature),
    #[cfg_attr(not(test), expect(dead_code, reason = "answered by the VRF prover"))]
    VrfProof(&'a VRFProof),
    Refused,
}

#[derive(Default)]
pub struct SignRequests(Vec<SignRequest>);

impl SignRequests {
    pub fn sign(
        &mut self,
        slot: u64,
        purpose: SignPurpose,
        pubkey: &XMSSPubkey,
        leaf_index: u32,
        signing_root: [u8; 32],
    ) {
        let work = KeyWork::Sign { leaf_index, signing_root };
        self.0.push(SignRequest { slot, purpose, pubkey: *pubkey, work });
    }

    pub fn vrf_proof(&mut self, slot: u64, validator_index: u64, pubkey: &XMSSPubkey) {
        let purpose = SignPurpose::Randao { validator_index };
        self.0.push(SignRequest { slot, purpose, pubkey: *pubkey, work: KeyWork::VrfProof });
    }

    pub fn drain(&mut self, send: impl FnMut(SignRequest)) {
        self.0.drain(..).for_each(send);
    }
}

pub struct SigningDomains {
    spec: SpecConfig,
    genesis_validators_root: [u8; 32],
}

impl SigningDomains {
    pub fn new(spec: &SpecConfig, genesis_validators_root: [u8; 32]) -> Self {
        Self { spec: spec.clone(), genesis_validators_root }
    }

    pub fn signing_root(&self, domain_type: u32, slot: u64, object_root: &[u8; 32]) -> [u8; 32] {
        let version = self.spec.fork_version_at(slot / SLOTS_PER_EPOCH);
        let domain = compute_domain(domain_type, version, &self.genesis_validators_root);
        compute_signing_root(object_root, &domain)
    }
}
