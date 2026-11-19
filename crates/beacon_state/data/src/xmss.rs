use silver_crypto_simd::xmss::{Item, leaf_index, verify, verify_batch};
use silver_ssz::{
    ssz_hash::{compute_signing_root, hash_beacon_block_header_bytes},
    ssz_view::{
        BeaconBlockHeaderView, ExecutionPayloadBidView, ExecutionPayloadEnvelopeView,
        PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE, PROPOSER_SLASHING_PQ_SIZE, PayloadAttestationDataView,
        PayloadAttestationMessagePqView, ProposerPreferencesView, ProposerSlashingPqView,
        SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, SINGLE_ATT_PQ_SIZE, SignedBeaconBlockPqView,
        SignedExecutionPayloadBidPqView, SignedExecutionPayloadEnvelopePqView,
        SignedProposerPreferencesPqView, SingleAttestationPqView, XMSSPubkey, XMSSSignature,
    },
};

use crate::{
    hash_tree_root_block_header,
    types::{B256, BeaconBlockHeader, Epoch, Slot},
};

#[cfg(test)]
mod tests;

pub const XMSS_RESERVED_LEAVES: u64 = 1 << 15;
pub const XMSS_ATTESTATION_LEAVES: u64 = 1 << 29;
pub const XMSS_BUILDER_BID_LEAVES: u64 = 1 << 30;
pub const XMSS_LEAVES_PER_SLOT: u64 = 1 << 3;

const FIRST_BUILDER_BID_LEAF: u64 = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES;
const FIRST_SLOT_LEAF: u64 = FIRST_BUILDER_BID_LEAF + XMSS_BUILDER_BID_LEAVES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafOffset {
    BeaconProposer,
    AggregateAndProof,
    PtcAttester,
    ProposerPreferences,
    ExecutionPayloadEnvelope,
}

const _: () = assert!((LeafOffset::ExecutionPayloadEnvelope as u64) < XMSS_LEAVES_PER_SLOT);

pub fn compute_xmss_attestation_leaf_index(epoch: Epoch) -> u64 {
    XMSS_RESERVED_LEAVES.saturating_add(epoch)
}

pub fn compute_xmss_leaf_index(slot: Slot, leaf_offset: LeafOffset) -> u64 {
    slot.saturating_mul(XMSS_LEAVES_PER_SLOT)
        .saturating_add(FIRST_SLOT_LEAF)
        .saturating_add(leaf_offset as u64)
}

pub fn is_builder_bid_leaf_index(leaf_index: u64) -> bool {
    (FIRST_BUILDER_BID_LEAF..FIRST_SLOT_LEAF).contains(&leaf_index)
}

pub struct SignatureCheck<'a> {
    pub public_key: &'a XMSSPubkey,
    pub leaf_index: u64,
    pub signing_root: B256,
    pub signature: &'a XMSSSignature,
}

impl<'a> SignatureCheck<'a> {
    pub fn single_attestation(
        attestation: &'a [u8; SINGLE_ATT_PQ_SIZE],
        attester_pubkey: &'a XMSSPubkey,
        signing_root: B256,
    ) -> Self {
        let target_epoch = SingleAttestationPqView::data(attestation).target_epoch();
        Self {
            public_key: attester_pubkey,
            leaf_index: compute_xmss_attestation_leaf_index(target_epoch),
            signing_root,
            signature: SingleAttestationPqView::signature(attestation),
        }
    }

    pub fn block(
        block_ssz: &'a [u8],
        proposer_pubkey: &'a XMSSPubkey,
        body_root: &B256,
        domain: &B256,
    ) -> Option<Self> {
        if !SignedBeaconBlockPqView::check_size(block_ssz) {
            return None;
        }
        let slot = SignedBeaconBlockPqView::slot(block_ssz);
        let header = BeaconBlockHeader {
            slot,
            proposer_index: SignedBeaconBlockPqView::proposer_index(block_ssz),
            parent_root: *SignedBeaconBlockPqView::parent_root(block_ssz),
            state_root: *SignedBeaconBlockPqView::state_root(block_ssz),
            body_root: *body_root,
        };
        Some(Self {
            public_key: proposer_pubkey,
            leaf_index: compute_xmss_leaf_index(slot, LeafOffset::BeaconProposer),
            signing_root: compute_signing_root(&hash_tree_root_block_header(&header), domain),
            signature: SignedBeaconBlockPqView::signature(block_ssz),
        })
    }

    pub fn execution_payload_bid(
        signed_bid: &'a [u8],
        builder_pubkey: &'a XMSSPubkey,
        domain: &B256,
    ) -> Option<Self> {
        if !SignedExecutionPayloadBidPqView::check_canonical(signed_bid) {
            return None;
        }
        let signature = SignedExecutionPayloadBidPqView::signature(signed_bid);
        let leaf_index = u64::from(leaf_index(signature));
        if !is_builder_bid_leaf_index(leaf_index) {
            return None;
        }
        let bid = SignedExecutionPayloadBidPqView::message(signed_bid);
        Some(Self {
            public_key: builder_pubkey,
            leaf_index,
            signing_root: compute_signing_root(
                &ExecutionPayloadBidView::hash_tree_root(bid),
                domain,
            ),
            signature,
        })
    }

    pub fn execution_payload_envelope(
        signed_envelope: &'a [u8],
        block_slot: Slot,
        pubkey: &'a XMSSPubkey,
        domain: &B256,
    ) -> Option<Self> {
        if !SignedExecutionPayloadEnvelopePqView::check_canonical(signed_envelope) {
            return None;
        }
        let envelope = SignedExecutionPayloadEnvelopePqView::message(signed_envelope);
        Some(Self {
            public_key: pubkey,
            leaf_index: compute_xmss_leaf_index(block_slot, LeafOffset::ExecutionPayloadEnvelope),
            signing_root: compute_signing_root(
                &ExecutionPayloadEnvelopeView::hash_tree_root_pq(envelope),
                domain,
            ),
            signature: SignedExecutionPayloadEnvelopePqView::signature(signed_envelope),
        })
    }

    pub fn proposer_slashing(
        slashing: &'a [u8; PROPOSER_SLASHING_PQ_SIZE],
        proposer_pubkey: &'a XMSSPubkey,
        domain: &B256,
    ) -> [Self; 2] {
        [
            (
                ProposerSlashingPqView::header_1(slashing),
                ProposerSlashingPqView::signature_1(slashing),
            ),
            (
                ProposerSlashingPqView::header_2(slashing),
                ProposerSlashingPqView::signature_2(slashing),
            ),
        ]
        .map(|(header, signature)| Self {
            public_key: proposer_pubkey,
            leaf_index: compute_xmss_leaf_index(
                BeaconBlockHeaderView::slot(header),
                LeafOffset::BeaconProposer,
            ),
            signing_root: compute_signing_root(&hash_beacon_block_header_bytes(header), domain),
            signature,
        })
    }

    pub fn payload_attestation_message(
        message: &'a [u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE],
        pubkey: &'a XMSSPubkey,
        domain: &B256,
    ) -> Self {
        let data = PayloadAttestationMessagePqView::data(message);
        Self {
            public_key: pubkey,
            leaf_index: compute_xmss_leaf_index(
                PayloadAttestationDataView::slot(data),
                LeafOffset::PtcAttester,
            ),
            signing_root: compute_signing_root(
                &PayloadAttestationDataView::hash_tree_root(data),
                domain,
            ),
            signature: PayloadAttestationMessagePqView::signature(message),
        }
    }

    pub fn proposer_preferences(
        signed_preferences: &'a [u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE],
        proposer_pubkey: &'a XMSSPubkey,
        domain: &B256,
    ) -> Self {
        let preferences = SignedProposerPreferencesPqView::message(signed_preferences);
        Self {
            public_key: proposer_pubkey,
            leaf_index: compute_xmss_leaf_index(
                ProposerPreferencesView::proposal_slot(preferences),
                LeafOffset::ProposerPreferences,
            ),
            signing_root: compute_signing_root(
                &ProposerPreferencesView::hash_tree_root(preferences),
                domain,
            ),
            signature: SignedProposerPreferencesPqView::signature(signed_preferences),
        }
    }

    pub fn verify(&self) -> bool {
        verify(self.public_key, self.leaf_index, &self.signing_root, self.signature)
    }

    pub fn verify_batch(checks: &[Self], valid: &mut [bool]) {
        let items: Vec<_> = checks
            .iter()
            .map(|check| Item {
                public_key: check.public_key,
                leaf_index: check.leaf_index,
                message: &check.signing_root,
                signature: check.signature,
            })
            .collect();
        verify_batch(&items, valid);
    }
}
