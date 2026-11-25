use std::io::{self, Write};

use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    decompose::common::u32_le,
    merkle::{B256, ZERO_HASHES, const_hash_concat, hash_uint64_list, merkleize, mix_in_length},
    progressive::ProgressiveHasher,
    types::{Epoch, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, Slot},
};

pub const AGGREGATION_COMMITTEE_WINDOW_LEN: usize =
    (MIN_SEED_LOOKAHEAD as usize + 2) * SLOTS_PER_EPOCH as usize;
pub const AGGREGATORS_PER_COMMITTEE: usize = 4;

const SPE: usize = SLOTS_PER_EPOCH as usize;
const TABLE_LEN: usize = AGGREGATION_COMMITTEE_WINDOW_LEN * 4;
/// An empty list's root.
const EMPTY_SLOT_ROOT: B256 = ZERO_HASHES[1];

/// Spec `AggregationCommittee`: the aggregators of one beacon committee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AggregationCommittee {
    members: [u64; AGGREGATORS_PER_COMMITTEE],
    len: usize,
}

impl AggregationCommittee {
    #[inline]
    pub fn push(&mut self, validator_index: u64) {
        self.members[self.len] = validator_index;
        self.len += 1;
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == AGGREGATORS_PER_COMMITTEE
    }

    #[inline]
    pub fn as_slice(&self) -> &[u64] {
        &self.members[..self.len]
    }
}

/// `aggregation_committee_window: Vector[ProgressiveList[ProgressiveList[
/// ValidatorIndex]], AGGREGATION_COMMITTEE_WINDOW_LEN]`: per slot, the
/// aggregators of each of its beacon committees. Held as its SSZ encoding, so
/// a racing checkpoint read copies bytes without walking offsets. The roots
/// are cached because the window changes only at epoch boundaries.
#[derive(Debug, PartialEq, Eq)]
pub struct AggregationCommitteeWindow {
    ssz: RetainedVec<u8>,
    slot_roots: [B256; AGGREGATION_COMMITTEE_WINDOW_LEN],
    root: B256,
}

// Manual so `clone_from` keeps the retained allocation.
impl Clone for AggregationCommitteeWindow {
    fn clone(&self) -> Self {
        Self { ssz: self.ssz.clone(), slot_roots: self.slot_roots, root: self.root }
    }

    fn clone_from(&mut self, source: &Self) {
        self.ssz.clone_from(&source.ssz);
        self.slot_roots = source.slot_roots;
        self.root = source.root;
    }
}

impl Default for AggregationCommitteeWindow {
    fn default() -> Self {
        Self {
            ssz: RetainedVec::from(&EMPTY_SSZ[..]),
            slot_roots: [EMPTY_SLOT_ROOT; AGGREGATION_COMMITTEE_WINDOW_LEN],
            root: EMPTY_ROOT,
        }
    }
}

/// Every slot's committee list is empty, so every offset is the table's length.
const EMPTY_SSZ: [u8; TABLE_LEN] = {
    let table_len = (TABLE_LEN as u32).to_le_bytes();
    let mut ssz = [0; TABLE_LEN];
    let mut i = 0;
    while i < ssz.len() {
        ssz[i] = table_len[i % 4];
        i += 1;
    }
    ssz
};

const EMPTY_ROOT: B256 = empty_slots_root(
    AGGREGATION_COMMITTEE_WINDOW_LEN,
    AGGREGATION_COMMITTEE_WINDOW_LEN.next_power_of_two().trailing_zeros() as usize,
);

/// Root of a subtree of `height` whose first `len` leaves are
/// `EMPTY_SLOT_ROOT` and the rest zero. A full subtree of either kind is a
/// `ZERO_HASHES` entry, so only the boundary path is hashed.
const fn empty_slots_root(len: usize, height: usize) -> B256 {
    if len == 0 {
        return ZERO_HASHES[height];
    }
    if len == 1 << height {
        return ZERO_HASHES[height + 1];
    }
    let half = 1 << (height - 1);
    if len <= half {
        const_hash_concat(&empty_slots_root(len, height - 1), &ZERO_HASHES[height - 1])
    } else {
        const_hash_concat(&ZERO_HASHES[height], &empty_slots_root(len - half, height - 1))
    }
}

impl AggregationCommitteeWindow {
    pub(crate) fn from_ssz(ssz: &[u8]) -> Result<Self, DecomposeError> {
        let mut slot_roots = [B256::default(); AGGREGATION_COMMITTEE_WINDOW_LEN];
        let slots = elements(ssz, Some(AGGREGATION_COMMITTEE_WINDOW_LEN))?;
        for (root, slot) in slot_roots.iter_mut().zip(slots) {
            *root = slot_root(slot?)?;
        }
        Ok(Self { ssz: ssz.into(), root: merkleize(&slot_roots), slot_roots })
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.root
    }

    /// Spec `get_aggregation_committee` read from a state at `state_epoch`.
    /// `None` for a slot outside the window or an index past its committees.
    pub fn committee(
        &self,
        state_epoch: Epoch,
        slot: Slot,
        index: usize,
    ) -> Option<impl Iterator<Item = u64> + '_> {
        let window_epoch = (slot / SLOTS_PER_EPOCH + 1).checked_sub(state_epoch)?;
        let window_slot =
            usize::try_from(window_epoch).ok()? * SPE + (slot % SLOTS_PER_EPOCH) as usize;
        if window_slot >= AGGREGATION_COMMITTEE_WINDOW_LEN {
            return None;
        }
        let slot_ssz = elements(&self.ssz, Some(AGGREGATION_COMMITTEE_WINDOW_LEN))
            .ok()?
            .nth(window_slot)?
            .ok()?;
        let members = elements(slot_ssz, None).ok()?.nth(index)?.ok()?;
        Some(members.chunks_exact(8).map(|member| u64::from_le_bytes(member.try_into().unwrap())))
    }

    /// Drops the oldest epoch and appends the next, whose slots each hold
    /// `committees_per_slot` committees: `committee(slot_in_epoch, index)`.
    /// The kept epochs slide down in place; only the new one is hashed.
    pub(crate) fn rotate(
        &mut self,
        committees_per_slot: usize,
        mut committee: impl FnMut(usize, usize) -> AggregationCommittee,
    ) {
        self.drop_oldest_epoch();
        for slot_in_epoch in 0..SPE {
            let slot = AGGREGATION_COMMITTEE_WINDOW_LEN - SPE + slot_in_epoch;
            self.append_slot(slot, committees_per_slot, |index| committee(slot_in_epoch, index));
        }
        self.root = merkleize(&self.slot_roots);
    }

    /// Leaves the last epoch's offsets stale until it is appended.
    fn drop_oldest_epoch(&mut self) {
        let ssz = &mut self.ssz;
        let kept_start = u32_le(ssz, SPE * 4) as usize;
        let shift = kept_start - TABLE_LEN;
        for slot in 0..AGGREGATION_COMMITTEE_WINDOW_LEN - SPE {
            let offset = u32_le(ssz, (slot + SPE) * 4) as usize - shift;
            write_offset(ssz, slot * 4, offset);
        }
        let kept_end = ssz.len();
        ssz.copy_within(kept_start..kept_end, TABLE_LEN);
        ssz.resize(kept_end - shift, 0);
        self.slot_roots.copy_within(SPE.., 0);
    }

    fn append_slot(
        &mut self,
        slot: usize,
        committees_per_slot: usize,
        mut committee: impl FnMut(usize) -> AggregationCommittee,
    ) {
        let ssz = &mut self.ssz;
        let slot_start = ssz.len();
        write_offset(ssz, slot * 4, slot_start);
        ssz.resize(slot_start + committees_per_slot * 4, 0);
        for index in 0..committees_per_slot {
            let offset = ssz.len() - slot_start;
            write_offset(ssz, slot_start + index * 4, offset);
            for member in committee(index).as_slice() {
                ssz.extend(member.to_le_bytes());
            }
        }
        self.slot_roots[slot] = slot_root(&ssz[slot_start..]).expect("a written slot is valid SSZ");
    }

    pub fn aggregators(&self, slot: usize, index: usize) -> impl Iterator<Item = u64> + '_ {
        let committees = element(&self.ssz, slot, AGGREGATION_COMMITTEE_WINDOW_LEN);
        let count = if committees.is_empty() { 0 } else { u32_le(committees, 0) as usize / 4 };
        let committee = if index < count { element(committees, index, count) } else { &[] };
        committee.chunks_exact(8).map(|member| u64::from_le_bytes(member.try_into().unwrap()))
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.ssz.len()
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.ssz)
    }
}

fn element(ssz: &[u8], i: usize, count: usize) -> &[u8] {
    let start = u32_le(ssz, i * 4) as usize;
    let end = if i + 1 < count { u32_le(ssz, (i + 1) * 4) as usize } else { ssz.len() };
    &ssz[start..end]
}

fn write_offset(ssz: &mut [u8], at: usize, offset: usize) {
    ssz[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
}

fn slot_root(ssz: &[u8]) -> Result<B256, DecomposeError> {
    let mut hasher = ProgressiveHasher::new();
    let mut committees = 0;
    for committee in elements(ssz, None)? {
        hasher.push_chunk(committee_root(committee?)?);
        committees += 1;
    }
    Ok(mix_in_length(&hasher.finalize(), committees))
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

    fn encode_slot(committees: &[&[u64]]) -> Vec<u8> {
        let lens: Vec<_> = committees.iter().map(|committee| committee.len() * 8).collect();
        let mut ssz = offset_table(&lens);
        for index in committees.iter().copied().flatten() {
            ssz.extend_from_slice(&index.to_le_bytes());
        }
        ssz
    }

    /// `committees` at `slot` of a window whose other slots hold `others`.
    fn window_with(slot: usize, committees: &[&[u64]], others: &[&[u64]]) -> Vec<u8> {
        let slots: Vec<_> = (0..AGGREGATION_COMMITTEE_WINDOW_LEN)
            .map(|i| encode_slot(if i == slot { committees } else { others }))
            .collect();
        let lens: Vec<_> = slots.iter().map(Vec::len).collect();
        let mut ssz = offset_table(&lens);
        ssz.extend(slots.concat());
        ssz
    }

    fn committee(members: &[u64]) -> AggregationCommittee {
        let mut committee = AggregationCommittee::default();
        members.iter().for_each(|&member| committee.push(member));
        committee
    }

    #[test]
    fn round_trips_its_ssz() {
        let ssz = window_with(0, &[&[1, 2, 3], &[]], &[]);
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

    /// The window's first epoch is the one before the state's.
    #[test]
    fn committee_reads_the_previous_through_the_lookahead_epoch() {
        let state_epoch = 10;
        let marked = SPE + 3;
        let window =
            AggregationCommitteeWindow::from_ssz(&window_with(marked, &[&[4, 5], &[6]], &[&[7]]))
                .unwrap();
        let members = |slot, index| {
            window.committee(state_epoch, slot, index).map(Iterator::collect::<Vec<_>>)
        };

        let marked_slot = state_epoch * SLOTS_PER_EPOCH + 3;
        assert_eq!(members(marked_slot, 0), Some(vec![4, 5]));
        assert_eq!(members(marked_slot, 1), Some(vec![6]));
        assert_eq!(members(marked_slot, 2), None);
        assert_eq!(members((state_epoch - 1) * SLOTS_PER_EPOCH, 0), Some(vec![7]));
        assert_eq!(members((state_epoch + 2) * SLOTS_PER_EPOCH - 1, 0), Some(vec![7]));
        assert_eq!(members((state_epoch - 1) * SLOTS_PER_EPOCH - 1, 0), None);
        assert_eq!(members((state_epoch + 2) * SLOTS_PER_EPOCH, 0), None);
    }

    #[test]
    fn rejects_a_committee_of_partial_indices() {
        let mut ssz = window_with(0, &[&[1, 2, 3], &[]], &[]);
        ssz.pop();
        assert!(AggregationCommitteeWindow::from_ssz(&ssz).is_err());
    }

    /// Rotation matches decoding the shifted window, with every slot of the
    /// new epoch holding `[slot, index]` for each of its two committees.
    #[test]
    fn rotation_shifts_an_epoch_and_appends_the_next() {
        let marked = SPE + 3;
        let mut window =
            AggregationCommitteeWindow::from_ssz(&window_with(marked, &[&[4, 5], &[6]], &[&[7]]))
                .unwrap();
        window.rotate(2, |slot, index| committee(&[slot as u64, index as u64]));

        let mut expected: Vec<Vec<u8>> = (0..AGGREGATION_COMMITTEE_WINDOW_LEN)
            .map(|i| match i {
                i if i == marked - SPE => encode_slot(&[&[4, 5], &[6]]),
                i if i < AGGREGATION_COMMITTEE_WINDOW_LEN - SPE => encode_slot(&[&[7]]),
                i => {
                    let slot = (i - (AGGREGATION_COMMITTEE_WINDOW_LEN - SPE)) as u64;
                    encode_slot(&[&[slot, 0], &[slot, 1]])
                }
            })
            .collect();
        let lens: Vec<_> = expected.iter().map(Vec::len).collect();
        let mut ssz = offset_table(&lens);
        ssz.extend(expected.drain(..).flatten());
        assert_eq!(window, AggregationCommitteeWindow::from_ssz(&ssz).unwrap());
    }
}
