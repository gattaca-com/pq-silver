mod pending;

pub(super) use pending::{Pending, VerifiedColumns, envelope_block_root, sidecar_head};
use silver_beacon_state_data::SpecConfig;
use silver_common::{
    SignedBlockLayout,
    merkle::B256,
    ssz_view::{ExecutionPayloadBidView, SignedBeaconBlockView},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PayloadFacts {
    pub(super) has_blobs: bool,
    pub(super) payload_hash: B256,
    pub(super) parent_payload_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Needs {
    pub(super) columns: bool,
    pub(super) envelope: bool,
}

impl PayloadFacts {
    pub(in crate::store) fn of(block: &[u8], layout: SignedBlockLayout) -> Self {
        if layout == SignedBlockLayout::Fulu {
            let has_blobs = SignedBeaconBlockView::has_data_columns_fulu(block);
            return Self { has_blobs, ..Self::default() };
        }

        let Some(bid) = layout.bid(block) else {
            silver_log::error!(
                slot = layout.slot(block),
                "block bid out of bounds; taken as missing nothing"
            );
            return Self::default();
        };
        Self {
            has_blobs: !ExecutionPayloadBidView::blob_kzg_commitments(bid).is_empty(),
            payload_hash: *ExecutionPayloadBidView::block_hash(bid),
            parent_payload_hash: *ExecutionPayloadBidView::parent_block_hash(bid),
        }
    }

    pub(in crate::store) fn needs(
        &self,
        is_gloas: bool,
        child_payload_parent: Option<B256>,
    ) -> Needs {
        let revealed =
            !is_gloas || child_payload_parent.is_none_or(|parent| parent == self.payload_hash);
        Needs { columns: self.has_blobs && revealed, envelope: is_gloas && revealed }
    }
}

/// What a block's bytes say about it, kept once the bytes are gone.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockFacts {
    pub(super) slot: u64,
    pub(super) block_root: B256,
    pub(super) parent_root: B256,
    pub(super) payload: PayloadFacts,
}

impl BlockFacts {
    pub(in crate::store) fn of(buffer: &[u8], spec: &SpecConfig) -> Option<Self> {
        let Some(layout) = SignedBlockLayout::of(spec, buffer) else {
            silver_log::warn!(len = buffer.len(), "backfill block has invalid size");
            return None;
        };
        let slot = layout.slot(buffer);
        // the root hashes some malformed bodies like a valid one, so linkage alone does
        // not pin the bytes
        if !layout.check_canonical(buffer) {
            silver_log::warn!(slot, "backfill block has non-canonical body");
            return None;
        }
        Some(Self {
            slot,
            block_root: layout.block_root(buffer),
            parent_root: layout.parent_root(buffer),
            payload: PayloadFacts::of(buffer, layout),
        })
    }

    pub(in crate::store) fn needs(
        &self,
        spec: &SpecConfig,
        child_payload_parent: Option<B256>,
    ) -> Needs {
        self.payload.needs(spec.is_gloas_at_slot(self.slot), child_payload_parent)
    }
}

#[cfg(test)]
pub(in crate::store) mod fixtures {
    use std::{
        io::Write,
        sync::{Arc, LazyLock},
    };

    use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
    use silver_common::{
        TCache, TCacheProducer, TRead, body_root, column_util,
        merkle::B256,
        ssz_hash::kzg_commitments_inclusion_proof,
        ssz_view::{EXECUTION_PAYLOAD_FIXED_GLOAS, NUMBER_OF_COLUMNS, SIGNED_PQ_FIXED},
        test_util::{SynthBid, SynthBlock},
    };

    pub(in crate::store) const GLOAS_FORK_EPOCH: u64 = 1;
    pub(in crate::store) const GLOAS_FORK_SLOT: u64 = GLOAS_FORK_EPOCH * SLOTS_PER_EPOCH;

    pub(in crate::store) const BID_BLOCK_HASH: B256 = [0xB1; 32];
    pub(in crate::store) const BID_PREV_RANDAO: B256 = [0xD1; 32];
    pub(in crate::store) const BID_GAS_LIMIT: u64 = 30_000_000;
    pub(in crate::store) const BID_BUILDER_INDEX: u64 = 77;

    pub(in crate::store) fn spec() -> Arc<SpecConfig> {
        crate::store::test_spec(GLOAS_FORK_EPOCH)
    }

    pub(in crate::store) fn block_bytes(slot: u64, parent_root: B256) -> Vec<u8> {
        SynthBlock::fulu(slot, &[]).parent_root(parent_root).into_bytes()
    }

    fn gloas_bid(commitments: &[u8]) -> SynthBid {
        SynthBid::new(commitments)
            .block_hash(BID_BLOCK_HASH)
            .prev_randao(BID_PREV_RANDAO)
            .gas_limit(BID_GAS_LIMIT)
            .builder_index(BID_BUILDER_INDEX)
    }

    pub(in crate::store) fn gloas_block_bytes(slot: u64, commitments: &[u8]) -> Vec<u8> {
        SynthBlock::gloas(slot, gloas_bid(commitments)).into_bytes()
    }

    /// A gloas block in a chain: its parent is `parent_root`, and its bid
    /// builds on `BID_BLOCK_HASH`, which every gloas block here reveals, so a
    /// child says its parent's payload was revealed.
    pub(in crate::store) fn gloas_chain_block(
        slot: u64,
        parent_root: B256,
        commitments: &[u8],
    ) -> Vec<u8> {
        SynthBlock::gloas(slot, gloas_bid(commitments).parent_block_hash(BID_BLOCK_HASH))
            .parent_root(parent_root)
            .into_bytes()
    }

    /// [`gloas_chain_block`]'s PQ twin: the same bid, XMSS-signed.
    pub(in crate::store) fn pq_chain_block(
        slot: u64,
        parent_root: B256,
        commitments: &[u8],
    ) -> Vec<u8> {
        SynthBlock::pq(slot, gloas_bid(commitments).parent_block_hash(BID_BLOCK_HASH))
            .parent_root(parent_root)
            .into_bytes()
    }

    pub(in crate::store) fn fulu_blob_block(
        slot: u64,
        parent_root: B256,
        commitments: &[u8],
    ) -> Vec<u8> {
        SynthBlock::fulu(slot, commitments).parent_root(parent_root).into_bytes()
    }

    /// Two zero blobs through c-kzg once: their commitments, and per column
    /// the concatenated cells and proofs. Every blob block in the tests
    /// carries these, so one computation serves them all.
    pub(in crate::store) struct Kzg {
        pub(in crate::store) commitments: Vec<u8>,
        cells: Vec<Vec<u8>>,
        proofs: Vec<Vec<u8>>,
    }

    pub(in crate::store) static KZG: LazyLock<Kzg> = LazyLock::new(|| {
        let settings = c_kzg::ethereum_kzg_settings(0);
        let blob = c_kzg::Blob::new([0u8; 131072]);
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap().to_bytes().into_inner();
        let (blob_cells, blob_proofs) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
        let mut commitments = Vec::new();
        let mut cells = vec![Vec::new(); NUMBER_OF_COLUMNS];
        let mut proofs = vec![Vec::new(); NUMBER_OF_COLUMNS];
        for _ in 0..2 {
            commitments.extend_from_slice(&commitment);
            for j in 0..NUMBER_OF_COLUMNS {
                cells[j].extend_from_slice(&blob_cells[j].to_bytes());
                proofs[j].extend_from_slice(&blob_proofs[j].to_bytes().into_inner());
            }
        }
        Kzg { commitments, cells, proofs }
    });

    impl Kzg {
        /// The fulu sidecar of `column` for `block`, whose header is the
        /// block's own so `block_root_from_sidecar` matches.
        pub(in crate::store) fn fulu_sidecar(&self, block: &[u8], column: u64) -> Vec<u8> {
            let body = &block[184..];
            let mut header = [0u8; 208];
            header[..80].copy_from_slice(&block[100..180]);
            header[80..112].copy_from_slice(&body_root(body));
            header[112..].copy_from_slice(&block[4..100]);
            let n = self.commitments.len() / 48;
            let mut out = Vec::new();
            out.extend_from_slice(&column_util::data_column_sidecar_prefix_fulu(
                column,
                n,
                &header,
                &kzg_commitments_inclusion_proof(body),
            ));
            out.extend_from_slice(&self.cells[column as usize]);
            out.extend_from_slice(&self.commitments);
            out.extend_from_slice(&self.proofs[column as usize]);
            out
        }
    }

    /// `SignedExecutionPayloadEnvelope`: fixed 100B prefix, then the envelope,
    /// payload offset at [0..4), builder_index at [8..16), beacon_block_root at
    /// [16..48). The payload itself carries prev_randao/gas_limit/block_hash.
    pub(in crate::store) fn envelope_bytes(
        block_root: B256,
        builder_index: u64,
        block_hash: B256,
    ) -> Vec<u8> {
        const ENVELOPE_FIXED: usize = 80;

        let mut payload = vec![0u8; EXECUTION_PAYLOAD_FIXED_GLOAS];
        payload[372..404].copy_from_slice(&BID_PREV_RANDAO);
        payload[412..420].copy_from_slice(&BID_GAS_LIMIT.to_le_bytes());
        payload[472..504].copy_from_slice(&block_hash);

        let mut envelope = vec![0u8; ENVELOPE_FIXED];
        envelope[0..4].copy_from_slice(&(ENVELOPE_FIXED as u32).to_le_bytes());
        envelope[4..8].copy_from_slice(&((ENVELOPE_FIXED + payload.len()) as u32).to_le_bytes());
        envelope[8..16].copy_from_slice(&builder_index.to_le_bytes());
        envelope[16..48].copy_from_slice(&block_root);
        envelope.extend_from_slice(&payload);

        let mut signed = vec![0u8; 100];
        signed[0..4].copy_from_slice(&100u32.to_le_bytes());
        signed.extend_from_slice(&envelope);
        signed
    }

    pub(in crate::store) fn envelope_for(block_root: B256) -> Vec<u8> {
        envelope_bytes(block_root, BID_BUILDER_INDEX, BID_BLOCK_HASH)
    }

    /// `signed` with its BLS signature swapped for an XMSS-sized one.
    pub(in crate::store) fn xmss_signed(signed: &[u8]) -> Vec<u8> {
        let mut xmss_signed = vec![0; SIGNED_PQ_FIXED];
        xmss_signed[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
        xmss_signed.extend_from_slice(&signed[100..]);
        xmss_signed
    }

    /// Producer + reader pair turning bytes into acquired `TRead`s. Declared
    /// reader-after-producer so parked reads (which dereference the reader on
    /// release) drop first.
    pub(in crate::store) struct Tc {
        producer: silver_common::TProducer,
        consumer: silver_common::TCacheReader,
    }

    impl Tc {
        pub(in crate::store) fn new(name: &'static str, size: usize) -> Self {
            let producer = TCache::producer(silver_common::TCacheId::NetworkProcessing, size);
            let consumer = silver_common::TCacheReader::single(
                producer.cache_ref(),
                name,
                silver_common::TReadMode::Sliding,
            )
            .unwrap();
            Self { producer, consumer }
        }

        pub(in crate::store) fn tread(&mut self, bytes: &[u8]) -> TRead {
            let mut res = self.producer.reserve(bytes.len(), true).unwrap();
            res.write_all(bytes).unwrap();
            res.flush().unwrap();
            let handle = res.read();
            self.consumer.acquire(handle)
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::block_root_pq;

    use super::{
        fixtures::{
            BID_BLOCK_HASH, GLOAS_FORK_SLOT, block_bytes, gloas_block_bytes, pq_chain_block,
        },
        *,
    };

    /// A builder that never revealed its payload left no envelope and no
    /// columns behind. The child's bid builds on the last revealed payload, so
    /// it is what says which. Without a child the payload is taken as revealed.
    #[test]
    fn withheld_payload_needs_neither_envelope_nor_columns() {
        let commitments = [0x11u8; 48];
        let block = gloas_block_bytes(GLOAS_FORK_SLOT, &commitments);
        let facts = PayloadFacts::of(&block, SignedBlockLayout::Gloas);
        assert_eq!(facts.payload_hash, BID_BLOCK_HASH);
        assert!(facts.has_blobs);

        let revealed = Needs { columns: true, envelope: true };
        let withheld = Needs { columns: false, envelope: false };
        assert_eq!(facts.needs(true, Some(BID_BLOCK_HASH)), revealed, "the child builds on it");
        assert_eq!(facts.needs(true, Some([0xFF; 32])), withheld, "the child builds past it");
        assert_eq!(facts.needs(true, None), revealed, "no child to ask");

        let fulu = PayloadFacts::of(&block_bytes(1, [0; 32]), SignedBlockLayout::Fulu);
        assert!(!fulu.needs(false, None).envelope, "no envelopes before the fork");
    }

    #[test]
    fn pq_block_facts_read_its_xmss_offsets_and_bid() {
        let spec = SpecConfig { gloas_fork_epoch: 0, pq_fork_epoch: 1, ..SpecConfig::mainnet() };
        let commitments = [0x11u8; 48];
        let block = pq_chain_block(32, [0x31; 32], &commitments);

        let facts = BlockFacts::of(&block, &spec).expect("a canonical PQ block");
        assert_eq!(facts.slot, 32);
        assert_eq!(facts.parent_root, [0x31; 32]);
        assert_eq!(facts.block_root, block_root_pq(&block));
        assert_eq!(facts.payload.payload_hash, BID_BLOCK_HASH);
        assert_eq!(facts.payload.parent_payload_hash, BID_BLOCK_HASH);
        assert!(facts.payload.has_blobs);
        assert!(BlockFacts::of(&block, &SpecConfig { pq_fork_epoch: 2, ..spec }).is_none());
    }
}
