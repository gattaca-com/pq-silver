use silver_common::ssz_view::MAX_VALIDATORS_PER_COMMITTEE;

/// Positions in one committee, one bit each.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bits([u64; MAX_VALIDATORS_PER_COMMITTEE / 64]);

impl Bits {
    /// `false` if `position` was set already. Panics at or above
    /// `MAX_VALIDATORS_PER_COMMITTEE`.
    pub fn insert(&mut self, position: usize) -> bool {
        let (word, bit) = (&mut self.0[position / 64], 1 << (position % 64));
        let fresh = *word & bit == 0;
        *word |= bit;
        fresh
    }

    pub fn contains(&self, position: usize) -> bool {
        self.0[position / 64] >> (position % 64) & 1 == 1
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> {
        self.0.iter().enumerate().flat_map(|(index, &word)| {
            let mut word = word;
            std::iter::from_fn(move || {
                if word == 0 {
                    return None;
                }
                let bit = word.trailing_zeros() as usize;
                word &= word - 1;
                Some(index * 64 + bit)
            })
        })
    }

    /// How many of these `have` lacks.
    pub fn count_outside(&self, have: &Bits) -> usize {
        let outside = self.0.iter().zip(&have.0).map(|(word, have)| word & !have);
        outside.map(|word| word.count_ones() as usize).sum()
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|word| word.count_ones() as usize).sum()
    }

    pub(super) fn outside(mut self, held: &Self) -> Self {
        self.0.iter_mut().zip(&held.0).for_each(|(word, held)| *word &= !held);
        self
    }

    pub fn union_with(&mut self, other: &Bits) {
        self.0.iter_mut().zip(&other.0).for_each(|(word, other)| *word |= other);
    }
}

/// Panics at a position at or above `MAX_VALIDATORS_PER_COMMITTEE`.
impl FromIterator<usize> for Bits {
    fn from_iter<I: IntoIterator<Item = usize>>(positions: I) -> Self {
        let mut bits = Self::default();
        positions.into_iter().for_each(|position| {
            bits.insert(position);
        });
        bits
    }
}
