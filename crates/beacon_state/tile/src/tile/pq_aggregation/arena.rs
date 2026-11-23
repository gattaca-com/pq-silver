/// Runs of `T` back to back in one buffer, each read back by its index.
/// `clear` keeps the capacity, so a reused arena stops allocating.
pub struct Arena<T> {
    items: Vec<T>,
    ends: Vec<usize>,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self { items: Vec::new(), ends: Vec::new() }
    }
}

impl<T: Copy> Arena<T> {
    pub fn push(&mut self, run: &[T]) {
        self.items.extend_from_slice(run);
        self.ends.push(self.items.len());
    }

    pub fn get(&self, index: usize) -> &[T] {
        let start = index.checked_sub(1).map_or(0, |previous| self.ends[previous]);
        &self.items[start..self.ends[index]]
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.ends.clear();
    }
}
