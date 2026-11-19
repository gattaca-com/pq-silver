use silver_beacon_state_data::{ForkName, SpecConfig};

use crate::{
    block_root::{block_root_fulu, block_root_gloas, block_root_pq},
    merkle::B256,
    ssz_view::{
        BeaconBlockBodyFuluView, BeaconBlockBodyGloasView, BeaconBlockBodyPqView,
        ExecutionPayloadEnvelopeView, SignedBeaconBlockPqView, SignedBeaconBlockView,
        SignedExecutionPayloadEnvelopePqView, SignedExecutionPayloadEnvelopeView,
    },
};

/// Where a `SignedBeaconBlock`'s fields sit: the signature scheme moves the
/// message, and the fork shapes the body. Accessors expect a block whose size
/// [`Self::of`] has checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedBlockLayout {
    Fulu,
    Gloas,
    Pq,
}

impl SignedBlockLayout {
    pub fn at_slot(spec: &SpecConfig, slot: u64) -> Self {
        match spec.fork_at_slot(slot) {
            ForkName::Pq => Self::Pq,
            ForkName::Gloas => Self::Gloas,
            _ => Self::Fulu,
        }
    }

    /// `None` when `block` is too short for its accessors, or its signature
    /// scheme is not the one its slot's fork signs with.
    pub fn of(spec: &SpecConfig, block: &[u8]) -> Option<Self> {
        if SignedBeaconBlockView::check_size(block) {
            let layout = Self::at_slot(spec, SignedBeaconBlockView::slot(block));
            return (layout != Self::Pq).then_some(layout);
        }
        let pq = SignedBeaconBlockPqView::check_size(block) &&
            Self::at_slot(spec, SignedBeaconBlockPqView::slot(block)) == Self::Pq;
        pq.then_some(Self::Pq)
    }

    #[inline]
    pub fn slot(self, block: &[u8]) -> u64 {
        match self {
            Self::Fulu | Self::Gloas => SignedBeaconBlockView::slot(block),
            Self::Pq => SignedBeaconBlockPqView::slot(block),
        }
    }

    #[inline]
    pub fn parent_root(self, block: &[u8]) -> B256 {
        match self {
            Self::Fulu | Self::Gloas => *SignedBeaconBlockView::parent_root(block),
            Self::Pq => *SignedBeaconBlockPqView::parent_root(block),
        }
    }

    pub fn block_root(self, block: &[u8]) -> B256 {
        match self {
            Self::Fulu => block_root_fulu(block),
            Self::Gloas => block_root_gloas(block),
            Self::Pq => block_root_pq(block),
        }
    }

    pub fn check_canonical(self, block: &[u8]) -> bool {
        match self {
            Self::Fulu => {
                BeaconBlockBodyFuluView::check_canonical(SignedBeaconBlockView::body(block))
            }
            Self::Gloas => {
                BeaconBlockBodyGloasView::check_canonical(SignedBeaconBlockView::body(block))
            }
            Self::Pq => {
                BeaconBlockBodyPqView::check_canonical(SignedBeaconBlockPqView::body(block))
            }
        }
    }

    /// The `ExecutionPayloadEnvelope` in `envelope`, signed with this layout's
    /// scheme: `None` before Gloas, or when the envelope is out of bounds.
    pub fn envelope_message(self, envelope: &[u8]) -> Option<&[u8]> {
        let message = match self {
            Self::Fulu => None,
            Self::Gloas => SignedExecutionPayloadEnvelopeView::check_size(envelope)
                .then(|| SignedExecutionPayloadEnvelopeView::message(envelope)),
            Self::Pq => SignedExecutionPayloadEnvelopePqView::check_size(envelope)
                .then(|| SignedExecutionPayloadEnvelopePqView::message(envelope)),
        }?;
        ExecutionPayloadEnvelopeView::check_size(message).then_some(message)
    }

    /// The serialized `ExecutionPayloadBid`: `None` before Gloas, or when the
    /// bid is out of bounds.
    pub fn bid(self, block: &[u8]) -> Option<&[u8]> {
        match self {
            Self::Fulu => None,
            Self::Gloas => SignedBeaconBlockView::check_gloas_size(block)
                .then(|| SignedBeaconBlockView::gloas_bid(block)),
            Self::Pq => SignedBeaconBlockPqView::check_bid_size(block)
                .then(|| SignedBeaconBlockPqView::bid(block)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{merkleize, uint64_chunk},
        ssz_view::{
            BEACON_BLOCK_BODY_FIXED, BEACON_BLOCK_BODY_PQ_FIXED, BEACON_BLOCK_FIXED,
            SIGNED_PQ_FIXED,
        },
    };

    const GLOAS_EPOCH: u64 = 5;
    const PQ_EPOCH: u64 = 10;

    fn spec() -> SpecConfig {
        SpecConfig {
            gloas_fork_epoch: GLOAS_EPOCH,
            pq_fork_epoch: PQ_EPOCH,
            ..SpecConfig::mainnet()
        }
    }

    /// A signed block whose message starts after `signature_len` bytes.
    fn block(signature_len: usize, body_len: usize, slot: u64) -> Vec<u8> {
        let message_at = 4 + signature_len;
        let mut block = vec![0; message_at + BEACON_BLOCK_FIXED + body_len];
        block[..4].copy_from_slice(&(message_at as u32).to_le_bytes());
        block[message_at..message_at + 8].copy_from_slice(&slot.to_le_bytes());
        block[message_at + 16..message_at + 48].fill(0xAB);
        let body_offset = message_at + BEACON_BLOCK_FIXED - 4;
        block[body_offset..body_offset + 4]
            .copy_from_slice(&(BEACON_BLOCK_FIXED as u32).to_le_bytes());
        block
    }

    fn bls_block(slot: u64) -> Vec<u8> {
        block(96, BEACON_BLOCK_BODY_FIXED, slot)
    }

    fn pq_block(slot: u64) -> Vec<u8> {
        block(SIGNED_PQ_FIXED - 4, BEACON_BLOCK_BODY_PQ_FIXED, slot)
    }

    #[test]
    fn of_reads_each_layout_from_its_own_offsets() {
        let (fulu, gloas, pq) = (32, GLOAS_EPOCH * 32, PQ_EPOCH * 32);
        for (block, slot, layout) in [
            (bls_block(fulu), fulu, SignedBlockLayout::Fulu),
            (bls_block(gloas), gloas, SignedBlockLayout::Gloas),
            (pq_block(pq), pq, SignedBlockLayout::Pq),
        ] {
            assert_eq!(SignedBlockLayout::of(&spec(), &block), Some(layout));
            assert_eq!(layout.slot(&block), slot);
            assert_eq!(layout.parent_root(&block), [0xAB; 32]);
        }
    }

    #[test]
    fn of_refuses_a_signature_scheme_its_slot_does_not_use() {
        assert_eq!(SignedBlockLayout::of(&spec(), &bls_block(PQ_EPOCH * 32)), None);
        assert_eq!(SignedBlockLayout::of(&spec(), &pq_block(GLOAS_EPOCH * 32)), None);
    }

    /// Each reference body's root comes from the spec's SSZ library, so the
    /// block root checks the PQ offsets and body hashing independently.
    #[test]
    fn pq_block_root_and_bid_read_the_reference_bodies() {
        let vectors = include_str!("../../ssz/tests/fixtures/pq/reference_vectors.txt");
        let slot = PQ_EPOCH * 32;
        for line in vectors.lines().filter(|line| line.starts_with("BeaconBlockBody ")) {
            let mut fields = line.split(' ').skip(1).map(|field| hex::decode(field).unwrap());
            let (body, body_root) = (fields.next().unwrap(), fields.next().unwrap());
            let mut block = pq_block(slot);
            block.truncate(SIGNED_PQ_FIXED + BEACON_BLOCK_FIXED);
            block.extend_from_slice(&body);

            let layout = SignedBlockLayout::of(&spec(), &block).unwrap();
            assert!(layout.check_canonical(&block));
            assert!(layout.bid(&block).is_some());
            let header_root = merkleize(&[
                uint64_chunk(slot),
                uint64_chunk(0),
                [0xAB; 32],
                [0; 32],
                body_root.try_into().unwrap(),
            ]);
            assert_eq!(layout.block_root(&block), header_root);
        }
    }
}
