//! Verification of up to `LANES` signatures in lockstep, each permutation
//! 8-way. Every codeword leaves `CHAIN_STEPS` chain steps, so each lane walks
//! its own chains and none idles. A short group repeats its first item on the
//! spare lanes.

use crate::xmss::{
    BOTTOM_LAYER, CHAINS, Digest, HEIGHT, LAYER_SIG_LEN, MSG, NODE, PATH_AT, SIGNATURE_LEN,
    TOP_LAYER, VALUES_AT, address, hi,
    lanes::{LANES, absorb, digest, pad, permutation_lanes},
    leaf_index,
    ots_lanes::{chain_step, leaf_hashes, p_words},
    wots::{CHAIN_STEPS, LAST_POSITION, codeword},
};

pub struct Item<'a> {
    pub public_key: &'a [u8; 32],
    pub leaf_index: u64,
    pub message: &'a [u8; 32],
    pub signature: &'a [u8; SIGNATURE_LEN],
}

/// `out[i]` is whether `items[i]` verifies. One signature costs the scalar
/// `verify` less; two or more cost less here.
pub fn verify_batch(items: &[Item], out: &mut [bool]) {
    assert_eq!(items.len(), out.len());
    for (items, out) in items.chunks(LANES).zip(out.chunks_mut(LANES)) {
        let lane_items: [&Item; LANES] = std::array::from_fn(|l| &items[l.min(items.len() - 1)]);
        let ok = Group::new(lane_items).verify();
        out.copy_from_slice(&ok[..items.len()]);
    }
}

struct Group<'a> {
    items: [&'a Item<'a>; LANES],
    p: [Digest; LANES],
    ok: [bool; LANES],
}

impl<'a> Group<'a> {
    fn new(items: [&'a Item<'a>; LANES]) -> Group<'a> {
        let p = std::array::from_fn(|l| items[l].public_key[16..].try_into().unwrap());
        let ok = std::array::from_fn(|l| {
            u64::from(leaf_index(items[l].signature)) == items[l].leaf_index
        });
        Group { items, p, ok }
    }

    fn verify(mut self) -> [bool; LANES] {
        let messages: [[u8; 32]; LANES] = std::array::from_fn(|l| *self.items[l].message);
        let e: [u32; LANES] = std::array::from_fn(|l| leaf_index(self.items[l].signature));
        let bottom_roots = self.layer_roots(BOTTOM_LAYER, &e, &messages, 32, 4);

        let roots_as_m: [[u8; 32]; LANES] = std::array::from_fn(|l| {
            let mut m = [0u8; 32];
            m[..16].copy_from_slice(&bottom_roots[l]);
            m
        });
        let b: [u32; LANES] = std::array::from_fn(|l| e[l] >> HEIGHT);
        let top_roots = self.layer_roots(TOP_LAYER, &b, &roots_as_m, 16, 4 + LAYER_SIG_LEN);

        for (ok, (root, item)) in self.ok.iter_mut().zip(top_roots.iter().zip(&self.items)) {
            *ok &= *root == item.public_key[..16];
        }
        self.ok
    }

    /// Root each lane's layer signature (at `sig_at`) of `m[..m_len]` by key
    /// `e` reaches. Lanes whose digest is not a codeword are marked and
    /// walk arbitrary values.
    fn layer_roots(
        &mut self,
        layer: u32,
        e: &[u32; LANES],
        m: &[[u8; 32]; LANES],
        m_len: usize,
        sig_at: usize,
    ) -> [Digest; LANES] {
        let sig = |l: usize| &self.items[l].signature[sig_at..sig_at + LAYER_SIG_LEN];

        let mut lanes = [[0u64; LANES]; 25];
        for l in 0..LANES {
            absorb(&mut lanes, l, 0, &self.p[l]);
            absorb(&mut lanes, l, 2, &address(MSG, 0, hi(layer, 0), e[l]));
            absorb(&mut lanes, l, 4, &m[l][..m_len]);
            absorb(&mut lanes, l, 4 + m_len / 8, &sig(l)[..VALUES_AT]);
        }
        pad(&mut lanes, 32 + m_len + 16);
        permutation_lanes(&mut lanes);
        let mut x = [[0u8; CHAINS]; LANES];
        for (l, x) in x.iter_mut().enumerate() {
            match codeword(&digest(&lanes, l, 0)) {
                Some(digits) => *x = digits,
                None => self.ok[l] = false,
            }
        }

        let mut values = [[[0u8; 16]; LANES]; CHAINS];
        for (l, item) in self.items.iter().enumerate() {
            let sig = &item.signature[sig_at + VALUES_AT..sig_at + PATH_AT];
            for (chain, value) in values.iter_mut().zip(sig.as_chunks::<16>().0) {
                chain[l] = *value;
            }
        }
        // A lane that is not a codeword walks a prefix of its all-zero digits.
        let mut chain = [[0u8; LANES]; CHAIN_STEPS];
        let mut position = [[0u8; LANES]; CHAIN_STEPS];
        for (l, x) in x.iter().enumerate() {
            let steps = (0..CHAINS).flat_map(|i| (x[i]..LAST_POSITION).map(move |mu| (i, mu)));
            for (k, (i, mu)) in steps.take(CHAIN_STEPS).enumerate() {
                chain[k][l] = i as u8;
                position[k][l] = mu;
            }
        }
        let words = p_words(&self.p);
        for (chain, position) in chain.iter().zip(&position) {
            let mut value = std::array::from_fn(|l| values[chain[l] as usize][l]);
            chain_step(&words, layer, e, chain, position, &mut value);
            for (l, value) in value.into_iter().enumerate() {
                values[chain[l] as usize][l] = value;
            }
        }

        let mut current = leaf_hashes(&self.p, layer, e, &values);

        for level in 0..HEIGHT {
            let mut lanes = [[0u64; LANES]; 25];
            for l in 0..LANES {
                let sibling = &sig(l)[PATH_AT + 16 * level..PATH_AT + 16 * (level + 1)];
                let (left, right) = if (e[l] >> level) & 1 == 0 {
                    (&current[l][..], sibling)
                } else {
                    (sibling, &current[l][..])
                };
                let a = address(NODE, 0, hi(layer, level as u32 + 1), e[l] >> (level + 1));
                absorb(&mut lanes, l, 0, &self.p[l]);
                absorb(&mut lanes, l, 2, &a);
                absorb(&mut lanes, l, 4, left);
                absorb(&mut lanes, l, 6, right);
            }
            pad(&mut lanes, 64);
            permutation_lanes(&mut lanes);
            current = std::array::from_fn(|l| digest(&lanes, l, 0));
        }
        current
    }
}
