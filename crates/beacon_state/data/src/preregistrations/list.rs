use std::io::{self, Write};

use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    decompose::common::checked_count,
    merkle::{B256, mix_in_length},
    progressive::ProgressiveHasher,
};

pub const PREREGISTRATIONS_LIMIT: usize = 1 << 19;

pub trait Record: Copy {
    const SSZ_SIZE: usize;

    fn from_ssz(ssz: &[u8]) -> Self;

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()>;

    fn hash_tree_root(&self) -> B256;
}

/// `hasher` has folded every record's root, so a fork starts from it instead
/// of rehashing the list.
pub struct FinalizedList<T: Record> {
    records: RetainedVec<T>,
    hasher: ProgressiveHasher,
}

impl<T: Record> Default for FinalizedList<T> {
    fn default() -> Self {
        Self { records: RetainedVec::default(), hasher: ProgressiveHasher::new() }
    }
}

impl<T: Record> FinalizedList<T> {
    /// The lists are unbounded: `PREREGISTRATIONS_LIMIT` caps only the active
    /// records at admission, and expired ones stay until the epoch sweep.
    pub(crate) fn from_ssz(ssz: &[u8], field: &'static str) -> Result<Self, DecomposeError> {
        const UNCAPPED: usize = usize::MAX;
        let count = checked_count(ssz.len(), T::SSZ_SIZE, field, UNCAPPED)?;
        let mut list = Self { records: RetainedVec::with_capacity(count), ..Self::default() };
        for record in ssz.chunks_exact(T::SSZ_SIZE).map(T::from_ssz) {
            list.hasher.push_chunk(record.hash_tree_root());
            list.records.push(record);
        }
        Ok(list)
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.records
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.records.len() * T::SSZ_SIZE
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.records.iter().try_for_each(|record| record.write_ssz(w))
    }

    /// Adopts the effective list `delta` folded, so nothing is rehashed.
    pub(super) fn promote(&mut self, delta: &ListDelta<T>) {
        if delta.keeps_base() {
            self.records.extend(delta.records.iter().copied());
        } else {
            self.records.copy_from_slice(&delta.records);
        }
        self.hasher = delta.hasher;
    }
}

/// One fork's change to a list. `rewrites` counts the fork's overwrites and
/// removals. While it is zero, `records` holds the appends after the finalized
/// list; after a rewrite it holds the whole list, standing alone.
///
/// `hasher` folds the effective list's record roots. It is keyed by that
/// sequence, not by base positions, so a rebase leaves it untouched.
#[derive(Clone)]
pub(crate) struct ListDelta<T> {
    rewrites: u32,
    records: Vec<T>,
    hasher: ProgressiveHasher,
}

impl<T> Default for ListDelta<T> {
    fn default() -> Self {
        Self { rewrites: 0, records: Vec::new(), hasher: ProgressiveHasher::new() }
    }
}

impl<T: Record> ListDelta<T> {
    #[inline]
    fn keeps_base(&self) -> bool {
        self.rewrites == 0
    }

    pub(super) fn reset_onto(&mut self, base: &FinalizedList<T>) {
        self.rewrites = 0;
        self.records.clear();
        self.hasher = base.hasher;
    }

    pub(super) fn reset_from(&mut self, other: &Self) {
        self.rewrites = other.rewrites;
        self.records.clone_from(&other.records);
        self.hasher = other.hasher;
    }

    /// Drop the inherited prefix that the promoted `winner` folded into the
    /// base, or keep standing alone if this fork rewrote after the winner.
    pub(super) fn rebase(&mut self, winner: &Self) {
        debug_assert!(self.rewrites >= winner.rewrites, "descendant rewrote less than the winner");
        if self.rewrites == winner.rewrites {
            self.records.drain(..winner.records.len());
            self.rewrites = 0;
        } else {
            self.rewrites -= winner.rewrites;
        }
    }
}

#[derive(Clone, Copy)]
pub struct ListView<'a, T: Record> {
    base: &'a FinalizedList<T>,
    delta: &'a ListDelta<T>,
}

impl<'a, T: Record> ListView<'a, T> {
    pub(super) fn new(base: &'a FinalizedList<T>, delta: &'a ListDelta<T>) -> Self {
        Self { base, delta }
    }

    #[inline]
    fn kept_base(&self) -> &'a [T] {
        if self.delta.keeps_base() { &self.base.records } else { &[] }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.kept_base().len() + self.delta.records.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'a T> + use<'a, T> {
        self.kept_base().iter().chain(self.delta.records.iter())
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        mix_in_length(&self.delta.hasher.root(), self.len())
    }
}

pub struct ListWriter<'a, T: Record> {
    base: &'a FinalizedList<T>,
    delta: &'a mut ListDelta<T>,
}

impl<'a, T: Record> ListWriter<'a, T> {
    pub(super) fn new(base: &'a FinalizedList<T>, delta: &'a mut ListDelta<T>) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn reader(&self) -> ListView<'_, T> {
        ListView { base: self.base, delta: self.delta }
    }

    #[inline]
    pub fn push(&mut self, record: T) {
        self.delta.hasher.push_chunk(record.hash_tree_root());
        self.delta.records.push(record);
    }

    /// Any change but an append: an overwrite or a removal. The first one in
    /// a fork copies the finalized records in; each rehashes the whole list.
    pub fn rewrite(&mut self, edit: impl FnOnce(&mut Vec<T>)) {
        let delta = &mut *self.delta;
        if delta.keeps_base() {
            delta.records.splice(0..0, self.base.records.iter().copied());
        }
        edit(&mut delta.records);
        delta.rewrites += 1;
        delta.hasher = ProgressiveHasher::new();
        for record in &delta.records {
            delta.hasher.push_chunk(record.hash_tree_root());
        }
    }
}
