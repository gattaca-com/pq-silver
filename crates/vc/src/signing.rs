use silver_chain_spec::SpecConfig;
use silver_common::{
    SLOTS_PER_EPOCH,
    ssz_hash::{compute_domain, compute_signing_root},
    ssz_view::XMSSPubkey,
    vc_spine::{KeyWork, SignPurpose, SignRequest},
};

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
