use common::{F3, F11_OFF, F12_OFF, OFFSET, u32_le};
use flux_profiler::timed;
use gloas::GloasLayout;
use silver_ssz::ssz_view::XMSSPubkey;

use crate::{
    BeaconState, SpecConfig, ValidatorsDecodeError, decode_checkpoint_pubkeys,
    validators::VALIDATOR_PQ_SSZ_SIZE,
};

pub(crate) mod common;
mod fulu;
pub(crate) mod gloas;
mod indices;

pub use common::DecomposeError;
pub(crate) use common::{FULU_FIXED_PART, u64_le};

impl BeaconState {
    pub fn from_checkpoint(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkey_sidecar: &[u8],
    ) -> Result<Self, DecomposeError> {
        if !pubkey_sidecar.is_empty() {
            if let Ok(pubkeys) = decode_checkpoint_pubkeys(pubkey_sidecar) &&
                let Ok(state) = Self::decompose(ssz, cfg, Some(&pubkeys))
            {
                state.check_indices()?;
                return Ok(state);
            }
            silver_log::warn!("checkpoint pubkey sidecar unusable; decompressing from SSZ");
        }
        let state = Self::decompose(ssz, cfg, None)?;
        state.check_indices()?;
        Ok(state)
    }

    #[timed]
    pub fn decompose(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
    ) -> Result<Self, DecomposeError> {
        // `fork.current_version` sits at F3 + 4 (after `previous_version`).
        let current_version = ssz.get(F3 + 4..F3 + 8);
        if current_version == Some(cfg.pq_fork_version.as_slice()) {
            return gloas::decompose(ssz, cfg, None, GloasLayout::PQ);
        }
        if current_version == Some(cfg.gloas_fork_version.as_slice()) {
            return gloas::decompose(ssz, cfg, pubkeys, GloasLayout::GLOAS);
        }
        Self::decompose_fulu(ssz, cfg, pubkeys)
    }

    /// Force the Gloas decoder regardless of the SSZ `fork.current_version`.
    #[doc(hidden)]
    pub fn decompose_gloas(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
    ) -> Result<Self, DecomposeError> {
        gloas::decompose(ssz, cfg, pubkeys, GloasLayout::GLOAS)
    }
}

/// Each validator's XMSS pubkey and VRF root in a PQ state's SSZ, in index
/// order, read without decomposing the state: a devnet's `genesis.ssz` so
/// names its genesis registry.
pub fn pq_validator_keys(
    ssz: &[u8],
) -> Result<impl Iterator<Item = (&XMSSPubkey, &[u8; 32])>, DecomposeError> {
    let need = F12_OFF + OFFSET;
    if ssz.len() < need {
        return Err(DecomposeError::TruncatedFixedPart { len: ssz.len(), need });
    }
    let (start, end) = (u32_le(ssz, F11_OFF) as usize, u32_le(ssz, F12_OFF) as usize);
    if start > end {
        return Err(DecomposeError::NonMonotonicOffsets { i: 0, a: start, b: end });
    }
    let records =
        ssz.get(start..end).ok_or(DecomposeError::OffsetPastEnd { off: end, len: ssz.len() })?;
    if !records.len().is_multiple_of(VALIDATOR_PQ_SSZ_SIZE) {
        let error = ValidatorsDecodeError::LenNotMultiple {
            len: records.len(),
            size: VALIDATOR_PQ_SSZ_SIZE,
        };
        return Err(error.into());
    }
    Ok(records.as_chunks::<VALIDATOR_PQ_SSZ_SIZE>().0.iter().map(|record| {
        let (pubkey, rest) = record.split_first_chunk().expect("a record starts with its pubkey");
        (pubkey, rest.first_chunk().expect("then its VRF root"))
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{F11_OFF, F12_OFF, pq_validator_keys};
    use crate::validators::VALIDATOR_PQ_SSZ_SIZE;

    #[test]
    fn pq_validator_keys_reads_each_record_and_refuses_misframing() {
        let start = F12_OFF + 4;
        let mut ssz = vec![0; start + 2 * VALIDATOR_PQ_SSZ_SIZE];
        ssz[F11_OFF..F11_OFF + 4].copy_from_slice(&(start as u32).to_le_bytes());
        let end = ssz.len() as u32;
        ssz[F12_OFF..F12_OFF + 4].copy_from_slice(&end.to_le_bytes());
        ssz[start..start + 32].fill(0xaa);
        ssz[start + 32..start + 64].fill(0xa1);
        ssz[start + VALIDATOR_PQ_SSZ_SIZE..][..32].fill(0xbb);
        let keys = pq_validator_keys(&ssz).unwrap().map(|(k, r)| (*k, *r)).collect::<Vec<_>>();
        assert_eq!(keys, [([0xaa; 32], [0xa1; 32]), ([0xbb; 32], [0; 32])]);

        ssz.pop();
        assert!(pq_validator_keys(&ssz).is_err(), "the list now ends past the state");
        assert!(pq_validator_keys(&ssz[..F12_OFF]).is_err());
    }

    use super::common::{F2, FULU_FIXED_PART, u64_le};
    use crate::{BeaconState, SpecConfig, types::SLOTS_PER_EPOCH};

    // EF fixture: a known-valid Fulu pre-state from sanity/blocks tests.
    // Path is relative to `crates/common/`; gracefully skipped when the
    // consensus-spec-tests checkout is missing.
    const EF_PRE_STATE: &str = concat!(
        "../beacon_state/consensus-spec-tests/tests/mainnet/fulu/sanity/blocks/",
        "pyspec_tests/deposit_top_up/pre.ssz_snappy",
    );

    #[test]
    fn decompose_ef_sanity_pre_state() {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), EF_PRE_STATE].iter().collect();
        let Ok(compressed) = std::fs::read(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };
        let ssz = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy decode");
        assert!(ssz.len() >= FULU_FIXED_PART);

        let cfg = SpecConfig::mainnet();
        let bs = BeaconState::decompose(&ssz, &cfg, None).expect("decompose");
        let imm = &bs.immutable;
        let epoch = bs.epoch.finalized();
        let longtail = bs.longtail.finalized();
        let validators = bs.validators.finalized();

        // Re-read the raw slot from the SSZ fixed part to cross-check.
        let raw_slot = u64_le(&ssz, F2);
        let slot_view = bs.slot_states.finalized_view();
        assert_eq!(slot_view.slot_number(), raw_slot);
        let cur_epoch = raw_slot / SLOTS_PER_EPOCH;

        // Validator columnar arrays should be populated and consistent.
        let n = validators.validator_count();
        assert!(n > 0, "no validators decoded");
        assert_eq!(validators.index_len(), n);

        // Spec invariant: finalized ≤ previous_justified ≤ current_justified
        //                          ≤ current_epoch.
        let est = &epoch.state;
        assert!(est.finalized_checkpoint.epoch <= est.previous_justified_checkpoint.epoch);
        assert!(est.previous_justified_checkpoint.epoch <= est.current_justified_checkpoint.epoch);
        assert!(est.current_justified_checkpoint.epoch <= cur_epoch);

        // Sync-committee indices either resolve to a real validator or are
        // sentinel u32::MAX (committee pubkey not in the registry).
        let committees = longtail.sync_committees();
        for (i, idx) in committees.indices().iter().enumerate() {
            if *idx != u32::MAX {
                assert!((*idx as usize) < n);
                let pk = &committees.current().pubkeys[i];
                assert_eq!(validators.find_by_pubkey(pk).map(|i| i as u32), Some(*idx));
            }
        }

        // Decompose is deterministic.
        let bs2 = BeaconState::decompose(&ssz, &cfg, None).expect("decompose 2");
        let imm2 = &bs2.immutable;
        assert_eq!(bs2.slot_states.finalized_view().slot_number(), slot_view.slot_number());
        assert_eq!(bs2.validators.finalized().validator_count(), n);
        assert_eq!(imm2.genesis_validators_root, imm.genesis_validators_root);
        assert_eq!(imm2.historical_roots_hash, imm.historical_roots_hash);
    }
}
