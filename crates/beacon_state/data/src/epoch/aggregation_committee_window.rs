use std::io::{self, Write};

use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    decompose::common::u32_le,
    merkle::{B256, ZERO_HASHES, const_hash_concat, hash_uint64_list, merkleize, mix_in_length},
    progressive::ProgressiveHasher,
    types::{MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH},
};

pub const AGGREGATION_COMMITTEE_WINDOW_LEN: usize =
    (MIN_SEED_LOOKAHEAD as usize + 2) * SLOTS_PER_EPOCH as usize;

/// `aggregation_committee_window: Vector[ProgressiveList[ProgressiveList[
/// ValidatorIndex]], AGGREGATION_COMMITTEE_WINDOW_LEN]`: per slot, the
/// aggregators of each of its beacon committees. Held as its SSZ encoding, so
/// a racing checkpoint read copies bytes without walking offsets. The root is
/// cached because the window changes only at epoch boundaries.
#[derive(Debug, PartialEq, Eq)]
pub struct AggregationCommitteeWindow {
    ssz: RetainedVec<u8>,
    root: B256,
}

// Manual so `clone_from` keeps the retained allocation.
impl Clone for AggregationCommitteeWindow {
    fn clone(&self) -> Self {
        Self { ssz: self.ssz.clone(), root: self.root }
    }

    fn clone_from(&mut self, source: &Self) {
        self.ssz.clone_from(&source.ssz);
        self.root = source.root;
    }
}

impl Default for AggregationCommitteeWindow {
    fn default() -> Self {
        Self { ssz: RetainedVec::from(&EMPTY_SSZ[..]), root: EMPTY_ROOT }
    }
}

/// Every slot's committee list is empty, so every offset is the table's length.
const EMPTY_SSZ: [u8; AGGREGATION_COMMITTEE_WINDOW_LEN * 4] = {
    let table_len = ((AGGREGATION_COMMITTEE_WINDOW_LEN * 4) as u32).to_le_bytes();
    let mut ssz = [0; AGGREGATION_COMMITTEE_WINDOW_LEN * 4];
    let mut i = 0;
    while i < ssz.len() {
        ssz[i] = table_len[i % 4];
        i += 1;
    }
    ssz
};

/// An empty list's root is `ZERO_HASHES[1]`. The 96 of them pad to 128 leaves,
/// which fold to a 64-leaf full subtree beside one of 32 full and 32 zero
/// leaves.
const EMPTY_ROOT: B256 = {
    const _: () = assert!(AGGREGATION_COMMITTEE_WINDOW_LEN == 64 + 32);
    let right = const_hash_concat(&ZERO_HASHES[6], &ZERO_HASHES[5]);
    const_hash_concat(&ZERO_HASHES[7], &right)
};

impl AggregationCommitteeWindow {
    pub(crate) fn from_ssz(ssz: &[u8]) -> Result<Self, DecomposeError> {
        let mut slot_roots = [B256::default(); AGGREGATION_COMMITTEE_WINDOW_LEN];
        let slots = elements(ssz, Some(AGGREGATION_COMMITTEE_WINDOW_LEN))?;
        for (root, slot) in slot_roots.iter_mut().zip(slots) {
            let mut hasher = ProgressiveHasher::new();
            let mut committees = 0;
            for committee in elements(slot?, None)? {
                hasher.push_chunk(committee_root(committee?)?);
                committees += 1;
            }
            *root = mix_in_length(&hasher.finalize(), committees);
        }
        Ok(Self { ssz: ssz.into(), root: merkleize(&slot_roots) })
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.root
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.ssz.len()
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.ssz)
    }
}

fn committee_root(ssz: &[u8]) -> Result<B256, DecomposeError> {
    if !ssz.len().is_multiple_of(8) {
        return Err(DecomposeError::AggregationCommitteeWindow("committee not whole indices"));
    }
    Ok(hash_uint64_list(ProgressiveHasher::new(), ssz, ssz.len() / 8))
}

/// The elements of a sequence of variable-size SSZ values behind an offset
/// table. A vector passes its `len`; a list's length is read from its table.
fn elements(
    ssz: &[u8],
    len: Option<usize>,
) -> Result<impl Iterator<Item = Result<&[u8], DecomposeError>>, DecomposeError> {
    let malformed = DecomposeError::AggregationCommitteeWindow;
    let count = if len.is_none() && ssz.is_empty() {
        0
    } else {
        if ssz.len() < 4 {
            return Err(malformed("offset table truncated"));
        }
        let table_len = u32_le(ssz, 0) as usize;
        let count = len.unwrap_or(table_len / 4);
        if count == 0 || table_len != count * 4 || table_len > ssz.len() {
            return Err(malformed("first offset is not the offset table's length"));
        }
        count
    };

    Ok((0..count).map(move |i| {
        let start = u32_le(ssz, i * 4) as usize;
        let end = if i + 1 < count { u32_le(ssz, (i + 1) * 4) as usize } else { ssz.len() };
        if start > end || end > ssz.len() {
            return Err(malformed("offsets decrease or run past the end"));
        }
        Ok(&ssz[start..end])
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offset_table(element_lens: &[usize]) -> Vec<u8> {
        let mut offset = element_lens.len() * 4;
        let mut table = Vec::new();
        for len in element_lens {
            table.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += len;
        }
        table
    }

    /// Slot 0 holds committees `[1, 2, 3]` and `[]`; every other slot is empty.
    fn window_ssz() -> Vec<u8> {
        let mut slot0 = offset_table(&[24, 0]);
        for index in [1u64, 2, 3] {
            slot0.extend_from_slice(&index.to_le_bytes());
        }
        let mut slot_lens = vec![0; AGGREGATION_COMMITTEE_WINDOW_LEN];
        slot_lens[0] = slot0.len();
        let mut ssz = offset_table(&slot_lens);
        ssz.extend_from_slice(&slot0);
        ssz
    }

    #[test]
    fn round_trips_its_ssz() {
        let ssz = window_ssz();
        let window = AggregationCommitteeWindow::from_ssz(&ssz).unwrap();
        let mut encoded = Vec::new();
        window.write_ssz(&mut encoded).unwrap();
        assert_eq!(encoded, ssz);
        assert_ne!(window.hash_root(), AggregationCommitteeWindow::default().hash_root());
    }

    #[test]
    fn default_is_the_decoded_empty_window() {
        let decoded = AggregationCommitteeWindow::from_ssz(&EMPTY_SSZ).unwrap();
        assert_eq!(decoded, AggregationCommitteeWindow::default());
    }

    #[test]
    fn rejects_a_committee_of_partial_indices() {
        let mut ssz = window_ssz();
        ssz.pop();
        assert!(AggregationCommitteeWindow::from_ssz(&ssz).is_err());
    }
}
