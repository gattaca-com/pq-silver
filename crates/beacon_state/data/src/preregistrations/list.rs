use std::io::{self, Write};

use rustc_hash::FxHashMap;
use silver_ssz::ssz_view::XMSSPubkey;
use silver_state_memory::RetainedVec;

use super::{PreregistrationRoots, records::Preregistration};
use crate::{
    DecomposeError,
    decompose::common::checked_count,
    tree::{TreeView, TreeWriteView},
    types::{B256, PREREGISTRATIONS_LIMIT, Slot},
};

pub struct FinalizedList<T: Preregistration> {
    records: RetainedVec<T>,
    positions: FxHashMap<XMSSPubkey, u32>,
}

impl<T: Preregistration> Default for FinalizedList<T> {
    fn default() -> Self {
        Self { records: RetainedVec::default(), positions: FxHashMap::default() }
    }
}

impl<T: Preregistration> FinalizedList<T> {
    /// The lists are unbounded: `PREREGISTRATIONS_LIMIT` caps only the active
    /// records at admission, and expired ones stay until the epoch sweep.
    pub(crate) fn from_ssz(ssz: &[u8], field: &'static str) -> Result<Self, DecomposeError> {
        const UNCAPPED: usize = usize::MAX;
        let count = checked_count(ssz.len(), T::SSZ_SIZE, field, UNCAPPED)?;
        let mut list = Self { records: RetainedVec::with_capacity(count), ..Self::default() };
        for record in ssz.chunks_exact(T::SSZ_SIZE).map(T::from_ssz) {
            list.append(record);
        }
        Ok(list)
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.records
    }

    #[inline]
    fn len(&self) -> usize {
        self.records.len()
    }

    pub(super) fn leaf_roots(&self) -> impl Iterator<Item = B256> + '_ {
        self.records.iter().map(T::hash_tree_root)
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.records.len() * T::SSZ_SIZE
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.records.iter().try_for_each(|record| record.write_ssz(w))
    }

    fn append(&mut self, record: T) {
        self.positions.insert(*record.pubkey(), self.records.len() as u32);
        self.records.push(record);
    }

    pub(super) fn promote(&mut self, delta: &ListDelta<T>) {
        for &(position, record) in &delta.overwritten {
            self.records[position as usize] = record;
        }
        if !delta.removed.is_empty() {
            for &position in &delta.removed {
                self.positions.remove(self.records[position as usize].pubkey());
            }
            self.compact(&delta.removed);
            for position in self.positions.values_mut() {
                *position -= rank(&delta.removed, *position) as u32;
            }
        }
        for &record in &delta.appended {
            self.append(record);
        }
    }

    fn compact(&mut self, removed: &[u32]) {
        let mut removed = removed.iter().copied().peekable();
        let mut kept = 0;
        for position in 0..self.records.len() {
            if removed.next_if_eq(&(position as u32)).is_some() {
                continue;
            }
            self.records[kept] = self.records[position];
            kept += 1;
        }
        self.records.resize(kept, T::default());
    }
}

#[inline]
fn rank(removed: &[u32], position: u32) -> usize {
    removed.partition_point(|&p| p < position)
}

#[derive(Clone, Copy)]
enum Location {
    Base(u32),
    Appended(usize),
}

/// One fork's changes to a finalized list: the base positions it removed and
/// those it overwrote, both sorted, and the records it appended, which it
/// edits in place. Rolling a fork copies only these.
#[derive(Clone)]
pub(crate) struct ListDelta<T> {
    removed: Vec<u32>,
    overwritten: Vec<(u32, T)>,
    appended: Vec<T>,
}

impl<T> Default for ListDelta<T> {
    fn default() -> Self {
        Self { removed: Vec::new(), overwritten: Vec::new(), appended: Vec::new() }
    }
}

impl<T: Preregistration> ListDelta<T> {
    pub(super) fn clear(&mut self) {
        self.removed.clear();
        self.overwritten.clear();
        self.appended.clear();
    }

    pub(super) fn reset_from(&mut self, other: &Self) {
        self.removed.clone_from(&other.removed);
        self.overwritten.clone_from(&other.overwritten);
        self.appended.clone_from(&other.appended);
    }

    /// Re-expresses this survivor's changes against `base` once `winner` is
    /// promoted into it. A survivor descends from the winner: it removed all
    /// the winner removed, and its appended records begin with the winner's
    /// that it kept, in order. Keys are unique, so matching them in order
    /// rebuilds the survivor's list exactly.
    pub(super) fn rebase(&mut self, winner: &Self, base: &FinalizedList<T>) {
        let shift = |position: u32| position - rank(&winner.removed, position) as u32;
        self.removed.retain(|position| winner.removed.binary_search(position).is_err());
        self.removed.iter_mut().for_each(|position| *position = shift(*position));
        self.overwritten.retain(|entry| {
            match winner.overwritten.binary_search_by_key(&entry.0, |&(p, _)| p) {
                Ok(i) => winner.overwritten[i] != *entry,
                Err(_) => true,
            }
        });
        self.overwritten.iter_mut().for_each(|(position, _)| *position = shift(*position));

        let promoted_start = (base.len() - winner.removed.len()) as u32;
        let mut kept = 0;
        for (offset, promoted) in winner.appended.iter().enumerate() {
            let position = promoted_start + offset as u32;
            match self.appended.get(kept) {
                Some(own) if own.pubkey() == promoted.pubkey() => {
                    if own != promoted {
                        self.overwritten.push((position, *own));
                    }
                    kept += 1;
                }
                _ => self.removed.push(position),
            }
        }
        self.appended.drain(..kept);
    }

    #[inline]
    fn base_record(&self, base: &FinalizedList<T>, position: u32) -> T {
        match self.overwritten.binary_search_by_key(&position, |&(p, _)| p) {
            Ok(i) => self.overwritten[i].1,
            Err(_) => base.records[position as usize],
        }
    }
}

pub struct ListView<'a, T: Preregistration> {
    base: &'a FinalizedList<T>,
    delta: &'a ListDelta<T>,
    roots: TreeView<'a, PreregistrationRoots>,
}

impl<'a, T: Preregistration> ListView<'a, T> {
    pub(super) fn new(
        base: &'a FinalizedList<T>,
        delta: &'a ListDelta<T>,
        roots: TreeView<'a, PreregistrationRoots>,
    ) -> Self {
        Self { base, delta, roots }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.base.len() - self.delta.removed.len() + self.delta.appended.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = T> + use<'a, T> {
        let Self { base, delta, .. } = *self;
        (0..base.len() as u32)
            .filter(|position| delta.removed.binary_search(position).is_err())
            .map(|position| delta.base_record(base, position))
            .chain(delta.appended.iter().copied())
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.roots.hash_root()
    }

    fn find(&self, pubkey: &XMSSPubkey) -> Option<(Location, T)> {
        let delta = self.delta;
        if let Some(i) = delta.appended.iter().position(|record| record.pubkey() == pubkey) {
            return Some((Location::Appended(i), delta.appended[i]));
        }
        let position = *self.base.positions.get(pubkey)?;
        if delta.removed.binary_search(&position).is_ok() {
            return None;
        }
        Some((Location::Base(position), delta.base_record(self.base, position)))
    }

    #[inline]
    fn effective_index(&self, location: Location) -> u32 {
        let index = match location {
            Location::Base(position) => position as usize - rank(&self.delta.removed, position),
            Location::Appended(i) => self.base.len() - self.delta.removed.len() + i,
        };
        index as u32
    }

    fn active_count(&self, parent_slot: Slot) -> usize {
        self.iter().filter(|record| record.is_active(parent_slot)).count()
    }
}

pub struct ListWriter<'w, 'a, T: Preregistration> {
    base: &'w FinalizedList<T>,
    delta: &'w mut ListDelta<T>,
    roots: &'w mut TreeWriteView<'a, PreregistrationRoots>,
}

impl<'w, 'a, T: Preregistration> ListWriter<'w, 'a, T> {
    pub(super) fn new(
        base: &'w FinalizedList<T>,
        delta: &'w mut ListDelta<T>,
        roots: &'w mut TreeWriteView<'a, PreregistrationRoots>,
    ) -> Self {
        Self { base, delta, roots }
    }

    /// The records; the root is stale until the fork is read hashed.
    #[inline]
    pub fn reader(&self) -> ListView<'_, T> {
        ListView { base: self.base, delta: self.delta, roots: self.roots.reader() }
    }

    pub(super) fn push(&mut self, record: T) {
        self.delta.appended.push(record);
        let index = self.roots.append_empty();
        self.roots.set(index, record.hash_tree_root());
    }

    fn set(&mut self, location: Location, record: T) {
        let index = self.reader().effective_index(location);
        let delta = &mut *self.delta;
        match location {
            Location::Base(position) => {
                match delta.overwritten.binary_search_by_key(&position, |&(p, _)| p) {
                    Ok(i) => delta.overwritten[i].1 = record,
                    Err(i) => delta.overwritten.insert(i, (position, record)),
                }
            }
            Location::Appended(i) => delta.appended[i] = record,
        }
        self.roots.set(index, record.hash_tree_root());
    }

    fn remove(&mut self, location: Location) {
        let index = self.reader().effective_index(location);
        let delta = &mut *self.delta;
        match location {
            Location::Base(position) => {
                if let Ok(i) = delta.overwritten.binary_search_by_key(&position, |&(p, _)| p) {
                    delta.overwritten.remove(i);
                }
                let i = delta.removed.binary_search(&position).unwrap_err();
                delta.removed.insert(i, position);
            }
            Location::Appended(i) => {
                delta.appended.remove(i);
            }
        }
        self.roots.remove(index);
    }

    pub fn retain(&mut self, keep: impl Fn(&T) -> bool) {
        let Self { base, delta, roots } = self;
        let removed_before = delta.removed.len();
        let (mut read, mut write) = (0u32, 0u32);
        let mut slide = |kept: bool| {
            if kept {
                if read != write {
                    let root = roots.get(read as usize);
                    roots.set(write, root);
                }
                write += 1;
            }
            read += 1;
        };
        for position in 0..base.len() as u32 {
            if delta.removed[..removed_before].binary_search(&position).is_ok() {
                continue;
            }
            let kept = keep(&delta.base_record(base, position));
            if !kept {
                delta.removed.push(position);
            }
            slide(kept);
        }
        delta.appended.retain(|record| {
            let kept = keep(record);
            slide(kept);
            kept
        });
        if read == write {
            return;
        }

        delta.removed.sort_unstable();
        let ListDelta { removed, overwritten, .. } = &mut **delta;
        overwritten.retain(|(position, _)| removed.binary_search(position).is_err());
        for _ in write..read {
            roots.pop();
        }
    }

    /// Spec preregistration admission, once the registry has no record of the
    /// key. A no-op while the key holds an active binding, or while
    /// `PREREGISTRATIONS_LIMIT` bindings are active. An expired binding of the
    /// key is replaced in place, as the state root commits to the order.
    pub fn admit(&mut self, record: T, parent_slot: Slot) {
        let reader = self.reader();
        let existing = reader.find(record.pubkey());
        if existing.is_some_and(|(_, binding)| binding.is_active(parent_slot)) {
            return;
        }
        // Fewer records than the limit cannot hold the limit's active ones.
        if reader.len() >= PREREGISTRATIONS_LIMIT &&
            reader.active_count(parent_slot) >= PREREGISTRATIONS_LIMIT
        {
            return;
        }
        match existing {
            Some((location, _)) => self.set(location, record),
            None => self.push(record),
        }
    }

    /// Whether a deposit for `pubkey` may proceed. A key with an active
    /// binding admits only a deposit that `matches` it, which consumes it.
    pub fn admit_deposit(
        &mut self,
        pubkey: &XMSSPubkey,
        parent_slot: Slot,
        matches: impl FnOnce(&T) -> bool,
    ) -> bool {
        let Some((location, binding)) = self.reader().find(pubkey) else {
            return true;
        };
        if !binding.is_active(parent_slot) {
            return true;
        }
        if !matches(&binding) {
            return false;
        }
        self.remove(location);
        true
    }
}
