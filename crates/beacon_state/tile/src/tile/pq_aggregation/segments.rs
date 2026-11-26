pub(super) struct Segments<T, const BLOCKS: usize, const BLOCK_LEN: usize = 128> {
    blocks: [Vec<T>; BLOCKS],
    len: usize,
}

impl<T, const BLOCKS: usize, const BLOCK_LEN: usize> Default for Segments<T, BLOCKS, BLOCK_LEN> {
    fn default() -> Self {
        Self { blocks: [const { Vec::new() }; BLOCKS], len: 0 }
    }
}

impl<T, const BLOCKS: usize, const BLOCK_LEN: usize> Segments<T, BLOCKS, BLOCK_LEN> {
    pub(super) const fn blocks(rows: usize) -> usize {
        rows.div_ceil(BLOCK_LEN)
    }

    pub(super) fn push(&mut self, row: T) -> usize {
        let index = self.len;
        let block = &mut self.blocks[index / BLOCK_LEN];
        if block.capacity() == 0 {
            *block = Vec::with_capacity(BLOCK_LEN);
        }
        block.push(row);
        self.len += 1;
        index
    }

    pub(super) fn get(&self, index: usize) -> &T {
        assert!(index < self.len);
        &self.blocks[index / BLOCK_LEN][index % BLOCK_LEN]
    }

    pub(super) fn get_mut(&mut self, index: usize) -> &mut T {
        assert!(index < self.len);
        &mut self.blocks[index / BLOCK_LEN][index % BLOCK_LEN]
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn clear(&mut self) {
        for block in &mut self.blocks[..Self::blocks(self.len)] {
            block.clear();
        }
        self.len = 0;
    }
}
