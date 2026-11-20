use silver_beacon_state_data::{BodyFork, ForkName, SpecConfig};

use crate::{
    block_root::{block_root_fulu, block_root_gloas, block_root_pq},
    merkle::B256,
    ssz_view::{
        BeaconBlockBodyFuluView, BeaconBlockBodyGloasView, BeaconBlockBodyPqView,
        ExecutionPayloadEnvelopeView, SIGNED_BLS_FIXED, SIGNED_PQ_FIXED, SignedBeaconBlockPqView,
        SignedBeaconBlockView, SignedExecutionPayloadEnvelopePqView,
        SignedExecutionPayloadEnvelopeView,
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
    pub fn body_fork(self) -> BodyFork {
        match self {
            Self::Fulu => BodyFork::Fulu,
            Self::Gloas => BodyFork::Gloas,
            Self::Pq => BodyFork::Pq,
        }
    }

    #[inline]
    pub fn slot(self, block: &[u8]) -> u64 {
        match self {
            Self::Fulu | Self::Gloas => SignedBeaconBlockView::slot(block),
            Self::Pq => SignedBeaconBlockPqView::slot(block),
        }
    }

    #[inline]
    pub fn proposer_index(self, block: &[u8]) -> u64 {
        match self {
            Self::Fulu | Self::Gloas => SignedBeaconBlockView::proposer_index(block),
            Self::Pq => SignedBeaconBlockPqView::proposer_index(block),
        }
    }

    #[inline]
    pub fn state_root(self, block: &[u8]) -> B256 {
        match self {
            Self::Fulu | Self::Gloas => *SignedBeaconBlockView::state_root(block),
            Self::Pq => *SignedBeaconBlockPqView::state_root(block),
        }
    }

    #[inline]
    pub fn body(self, block: &[u8]) -> &[u8] {
        match self {
            Self::Fulu | Self::Gloas => SignedBeaconBlockView::body(block),
            Self::Pq => SignedBeaconBlockPqView::body(block),
        }
    }

    /// The bytes [`Self::parent_root`] reads, from the start of the block.
    #[inline]
    pub const fn parent_root_end(self) -> usize {
        let message_at = match self {
            Self::Fulu | Self::Gloas => SIGNED_BLS_FIXED,
            Self::Pq => SIGNED_PQ_FIXED,
        };
        let (slot, proposer_index) = (size_of::<u64>(), size_of::<u64>());
        message_at + slot + proposer_index + size_of::<B256>()
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

    /// The signature over `envelope`, in this layout's scheme: `None` before
    /// Gloas, or when the envelope is out of bounds.
    pub fn envelope_signature(self, envelope: &[u8]) -> Option<&[u8]> {
        match self {
            Self::Fulu => None,
            Self::Gloas => SignedExecutionPayloadEnvelopeView::check_size(envelope)
                .then(|| &SignedExecutionPayloadEnvelopeView::signature(envelope)[..]),
            Self::Pq => SignedExecutionPayloadEnvelopePqView::check_size(envelope)
                .then(|| &SignedExecutionPayloadEnvelopePqView::signature(envelope)[..]),
        }
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
        ssz_view::BEACON_BLOCK_FIXED,
        test_util::{SynthBid, SynthBlock},
    };

    const GLOAS_EPOCH: u64 = 5;
    const PQ_EPOCH: u64 = 10;
    const PARENT_ROOT: B256 = [0xAB; 32];

    fn spec() -> SpecConfig {
        SpecConfig {
            gloas_fork_epoch: GLOAS_EPOCH,
            pq_fork_epoch: PQ_EPOCH,
            ..SpecConfig::mainnet()
        }
    }

    fn bls_block(slot: u64) -> Vec<u8> {
        SynthBlock::gloas(slot, SynthBid::new(&[])).parent_root(PARENT_ROOT).into_bytes()
    }

    fn pq_block(slot: u64) -> Vec<u8> {
        SynthBlock::pq(slot, SynthBid::new(&[])).parent_root(PARENT_ROOT).into_bytes()
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
            assert_eq!(layout.proposer_index(&block), 0);
            assert_eq!(layout.state_root(&block), [0; 32]);
            assert_eq!(layout.parent_root(&block), PARENT_ROOT);
            assert_eq!(layout.parent_root(&block[..layout.parent_root_end()]), PARENT_ROOT);
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
                PARENT_ROOT,
                [0; 32],
                body_root.try_into().unwrap(),
            ]);
            assert_eq!(layout.block_root(&block), header_root);
        }
    }
}
