use super::RequestCountOutOfBounds;
use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH},
    progressive::{ProgressiveContainer, ProgressiveHasher},
    ssz_view::{fixed_list_ok, offsets_ok, variable_field},
};

/// One `ProgressiveList` of fixed-size requests in `ExecutionRequests`.
pub(crate) struct RequestList {
    kind: &'static str,
    element_size: usize,
    max: usize,
    root: fn(&[u8]) -> B256,
}

impl RequestList {
    pub(crate) const fn of<T: FixedContainer>(kind: &'static str, max: usize) -> Self {
        Self { kind, element_size: T::SSZ_SIZE, max, root: progressive_list_root::<T> }
    }
}

fn progressive_list_root<T: FixedContainer>(bytes: &[u8]) -> B256 {
    T::hash_list(ProgressiveHasher::new(), bytes)
}

/// An `ExecutionRequests` serialization: `N` request lists behind an offset
/// table, in field order.
pub(crate) struct RequestLists<const N: usize>(pub(crate) [RequestList; N]);

impl<const N: usize> RequestLists<N> {
    const FIXED: usize = 4 * N;
    const OFFSETS: [usize; N] = {
        let mut offsets = [0; N];
        let mut i = 0;
        while i < N {
            offsets[i] = 4 * i;
            i += 1;
        }
        offsets
    };

    /// Each list's bytes; a list behind a malformed offset pair is empty.
    pub(crate) fn sections<'a>(&self, data: &'a [u8]) -> [&'a [u8]; N] {
        if data.len() < Self::FIXED {
            return [&[]; N];
        }
        let offset = |i: usize| u32::from_le_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
        std::array::from_fn(|i| {
            let start = offset(i) as usize;
            let end = if i + 1 < N { offset(i + 1) as usize } else { data.len() };
            if start <= end && end <= data.len() { &data[start..end] } else { &[] }
        })
    }

    pub(crate) fn check_canonical(&self, data: &[u8]) -> bool {
        data.len() >= Self::FIXED &&
            offsets_ok(data, &Self::OFFSETS, Self::FIXED) &&
            self.0.iter().enumerate().all(|(i, list)| {
                fixed_list_ok(
                    variable_field(data, &Self::OFFSETS, i),
                    list.element_size,
                    usize::MAX,
                )
            })
    }

    pub(crate) fn check_counts(&self, data: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        for (list, section) in self.0.iter().zip(self.sections(data)) {
            let count = section.len() / list.element_size;
            if count > list.max {
                return Err(RequestCountOutOfBounds { kind: list.kind, count, max: list.max });
            }
        }
        Ok(())
    }

    /// The `W` field roots of container `C`: each list's root at its active
    /// field, zero in the gaps.
    pub(crate) fn field_roots<C: ProgressiveContainer, const W: usize>(
        &self,
        data: &[u8],
    ) -> [B256; W] {
        let mut lists = self.0.iter().zip(self.sections(data));
        let mut roots = [ZERO_HASH; W];
        for (i, root) in roots.iter_mut().enumerate() {
            if C::ACTIVE_FIELDS[i / 8] >> (i % 8) & 1 == 1 {
                let (list, section) = lists.next().expect("a list per active field");
                *root = (list.root)(section);
            }
        }
        debug_assert!(lists.next().is_none(), "an active field per list");
        roots
    }
}
