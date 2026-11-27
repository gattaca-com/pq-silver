use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use silver_beacon_state_data::pq_validator_keys;
use silver_common::ssz_view::{VRF_PROOF_SIZE, VRFProof, XMSSPubkey};
use silver_crypto_simd::xmss::keccak::keccak256;
use zeroize::Zeroize;

type Node = [u8; 32];

const DEPTH: usize = 31;
/// A validator derives these leaves itself. The published state holds the
/// siblings above them, which no one could hash: the full tree has 2^31.
const POPULATED_DEPTH: usize = 20;
/// The roots of subtrees this deep are kept, 32 KiB a key, so a proof
/// hashes one subtree of 2^10 leaves.
const SUBTREE_DEPTH: usize = 10;
const SUBTREE_LEAVES: usize = 1 << SUBTREE_DEPTH;
const SUBTREES: usize = 1 << (POPULATED_DEPTH - SUBTREE_DEPTH);
const UPPER: usize = DEPTH - POPULATED_DEPTH;
const CACHE_LEN: usize = (SUBTREES + UPPER) * 32;
/// The published state: a root, a slot (zero), and the slot's 31 siblings
/// from leaf to root.
const RECORD_LEN: usize = 32 + 4 + DEPTH * 32;
const MAX_RECORDS: usize = 20_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const VRF_SECRET_DOMAIN: &[u8] = b"VRF_SECRET";
const VRF_LEAF_DOMAIN: &[u8] = b"VRF_LEAF";

const _: () = assert!(VRF_PROOF_SIZE == (1 + DEPTH) * 32);

/// A validator's VRF tree as pq-devnet-1 builds it (consensus-specs
/// `b5d422b25`): leaf `i` commits to the secret for slot `i`, a node is
/// `keccak(left ‖ right)`, and a RANDAO reveal is the slot's secret and its
/// leaf's 31 siblings, which reveal no other secret.
pub struct VrfTree {
    subtree_roots: Box<[Node; SUBTREES]>,
    upper: [Node; UPPER],
}

impl VrfTree {
    /// Hashes the 2^20 leaves a key proves at.
    pub fn build(seed: &[u8; 32], upper: [Node; UPPER]) -> Self {
        let mut subtree_roots = Box::new([[0; 32]; SUBTREES]);
        let mut leaves = [[0; 32]; SUBTREE_LEAVES];
        let mut hasher = VrfHasher::new(seed);
        for (subtree, root) in subtree_roots.iter_mut().enumerate() {
            hasher.fill_leaves(subtree, &mut leaves);
            *root = reduce(&mut leaves, 0, |_| {});
        }
        Self { subtree_roots, upper }
    }

    pub fn root(&self) -> Node {
        let populated = reduce(&mut self.subtree_root_parents(), 0, |_| {});
        self.upper.iter().fold(populated, |node, sibling| hash_pair(&node, sibling))
    }

    /// The level above the subtree roots, hashed into a half-size buffer so
    /// the roots themselves are never copied.
    fn subtree_root_parents(&self) -> [Node; SUBTREES / 2] {
        let mut parents = [[0; 32]; SUBTREES / 2];
        for (parent, [left, right]) in parents.iter_mut().zip(self.subtree_roots.as_chunks().0) {
            *parent = hash_pair(left, right);
        }
        parents
    }

    /// `None` past the populated leaves, whose proofs no one can make.
    pub fn proof(&self, seed: &[u8; 32], slot: u64) -> Option<VRFProof> {
        let index =
            usize::try_from(slot).ok().filter(|&index| index < SUBTREES * SUBTREE_LEAVES)?;
        let (subtree, at) = (index / SUBTREE_LEAVES, index % SUBTREE_LEAVES);
        let mut proof = [0; VRF_PROOF_SIZE];
        let mut nodes = proof.as_chunks_mut::<32>().0.iter_mut();
        let mut push = |node: &Node| *nodes.next().expect("a node per level") = *node;

        let mut hasher = VrfHasher::new(seed);
        let mut secret = hasher.secret(slot);
        push(&secret);
        secret.zeroize();
        let mut leaves = [[0; 32]; SUBTREE_LEAVES];
        hasher.fill_leaves(subtree, &mut leaves);
        reduce(&mut leaves, at, &mut push);
        push(&self.subtree_roots[subtree ^ 1]);
        reduce(&mut self.subtree_root_parents(), subtree / 2, &mut push);
        self.upper.iter().for_each(push);
        Some(proof)
    }

    /// The tree cached at `path`, if it hashes to `root`: then it is the key's.
    pub fn cached(root: &Node, path: &Path) -> Option<Self> {
        Self::read(path).filter(|tree| tree.root() == *root)
    }

    pub fn build_cached(seed: &[u8; 32], upper: [Node; UPPER], path: &Path) -> Self {
        let tree = Self::build(seed, upper);
        let partial = path.with_extension("vrf.partial");
        let written = File::create(&partial)
            .and_then(|mut file| {
                file.write_all(tree.subtree_roots.as_flattened())?;
                file.write_all(tree.upper.as_flattened())
            })
            .and_then(|()| fs::rename(&partial, path));
        if let Err(error) = written {
            silver_log::warn!(%error, path = %path.display(), "VRF tree not cached");
        }
        tree
    }

    fn read(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        if file.metadata().ok()?.len() != CACHE_LEN as u64 {
            return None;
        }
        let mut tree =
            Self { subtree_roots: Box::new([[0; 32]; SUBTREES]), upper: [[0; 32]; UPPER] };
        file.read_exact(tree.subtree_roots.as_flattened_mut()).ok()?;
        file.read_exact(tree.upper.as_flattened_mut()).ok()?;
        Some(tree)
    }
}

/// Spec `compute_vrf_secret` and `compute_vrf_leaf` for one seed. Only the
/// index and secret change between leaves, so the keccak inputs are reused.
struct VrfHasher {
    secret_input: [u8; VRF_SECRET_DOMAIN.len() + 32 + 8],
    leaf_input: [u8; VRF_LEAF_DOMAIN.len() + 32 + 8],
}

impl Drop for VrfHasher {
    fn drop(&mut self) {
        self.secret_input.zeroize();
        self.leaf_input.zeroize();
    }
}

impl VrfHasher {
    fn new(seed: &[u8; 32]) -> Self {
        let mut secret_input = [0; VRF_SECRET_DOMAIN.len() + 32 + 8];
        let (domain, rest) = secret_input.split_at_mut(VRF_SECRET_DOMAIN.len());
        domain.copy_from_slice(VRF_SECRET_DOMAIN);
        rest[..32].copy_from_slice(seed);
        let mut leaf_input = [0; VRF_LEAF_DOMAIN.len() + 32 + 8];
        leaf_input[..VRF_LEAF_DOMAIN.len()].copy_from_slice(VRF_LEAF_DOMAIN);
        Self { secret_input, leaf_input }
    }

    fn secret(&mut self, index: u64) -> Node {
        *self.secret_input.last_chunk_mut().expect("8 bytes") = index.to_le_bytes();
        keccak256(&self.secret_input)
    }

    fn leaf(&mut self, index: u64) -> Node {
        *self.secret_input.last_chunk_mut().expect("8 bytes") = index.to_le_bytes();
        let rest = &mut self.leaf_input[VRF_LEAF_DOMAIN.len()..];
        *rest.first_chunk_mut().expect("32 bytes") = keccak256(&self.secret_input);
        *rest.last_chunk_mut().expect("8 bytes") = index.to_le_bytes();
        keccak256(&self.leaf_input)
    }

    fn fill_leaves(&mut self, subtree: usize, leaves: &mut [Node; SUBTREE_LEAVES]) {
        for (offset, leaf) in leaves.iter_mut().enumerate() {
            *leaf = self.leaf((subtree * SUBTREE_LEAVES + offset) as u64);
        }
    }
}

fn hash_pair(left: &Node, right: &Node) -> Node {
    let mut input = [0; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    keccak256(&input)
}

/// Hashes `nodes`, a power of two of them, to their root in place, handing
/// over the sibling of the node at `index` at each level, from the bottom.
fn reduce(nodes: &mut [Node], mut index: usize, mut sibling: impl FnMut(&Node)) -> Node {
    let mut len = nodes.len();
    while len > 1 {
        sibling(&nodes[index ^ 1]);
        for parent in 0..len / 2 {
            nodes[parent] = hash_pair(&nodes[2 * parent], &nodes[2 * parent + 1]);
        }
        len /= 2;
        index /= 2;
    }
    nodes[0]
}

/// What a key proves RANDAO with. Its tree is read from its cache or built on
/// its first proof, as the slot's proposer duty arrives an epoch or more
/// ahead.
pub struct VrfKey {
    registered_root: Option<Node>,
    cache: PathBuf,
    tree: Option<VrfTree>,
}

impl VrfKey {
    pub fn new(pubkey: &XMSSPubkey, source: Option<&VrfSource>, data_dir: &Path) -> Self {
        let registered_root = source.and_then(|source| source.roots.get(pubkey).copied());
        let cache = data_dir.join(format!("0x{}.vrf", hex::encode(pubkey)));
        Self { registered_root, cache, tree: None }
    }

    /// A cached tree needs only its registered root; building one needs the
    /// published state too.
    pub fn proof(
        &mut self,
        seed: &[u8; 32],
        slot: u64,
        source: Option<&mut VrfSource>,
    ) -> Result<VRFProof, &'static str> {
        let tree = match &mut self.tree {
            Some(tree) => tree,
            tree @ None => {
                tree.insert(Self::load(&self.cache, self.registered_root, seed, source)?)
            }
        };
        tree.proof(seed, slot).ok_or("slot past the provable leaves")
    }

    fn load(
        cache: &Path,
        registered_root: Option<Node>,
        seed: &[u8; 32],
        source: Option<&mut VrfSource>,
    ) -> Result<VrfTree, &'static str> {
        let root = &registered_root.ok_or("no registered VRF root")?;
        let started = Instant::now();
        if let Some(tree) = VrfTree::cached(root, cache) {
            silver_log::info!(elapsed = ?started.elapsed(), "VRF tree read from its cache");
            return Ok(tree);
        }
        let upper = source.and_then(|source| source.upper(root)).ok_or("no published VRF state")?;
        let tree = VrfTree::build_cached(seed, upper, cache);
        if tree.root() != *root {
            return Err("the tree does not hash to the registered root");
        }
        silver_log::info!(elapsed = ?started.elapsed(), "VRF tree built");
        Ok(tree)
    }
}

/// Each key's registered VRF root, from the network's genesis registry, and
/// the published state (`--vrf-state-url`) that completes a tree being
/// built. The state is fetched once, when a tree is first built, so a
/// restart with every tree cached never needs it.
pub struct VrfSource {
    roots: HashMap<XMSSPubkey, Node>,
    state_url: Option<String>,
    states: Option<VrfStates>,
}

impl VrfSource {
    pub fn new(registry: &[(XMSSPubkey, Node)], state_url: Option<String>) -> Self {
        let roots = registry.iter().copied().collect();
        Self { roots, state_url, states: None }
    }

    /// Keeps only `ours`' roots, so the published state keeps only their
    /// records.
    pub fn for_keys(mut self, ours: impl Fn(&XMSSPubkey) -> bool) -> Self {
        self.roots.retain(|pubkey, _| ours(pubkey));
        self.roots.shrink_to_fit();
        self
    }

    /// A failed fetch is tried again by the next tree to be built.
    fn upper(&mut self, root: &Node) -> Option<[Node; UPPER]> {
        if self.states.is_none() {
            let url = self.state_url.as_deref()?;
            match VrfStates::fetch(url, |root| self.roots.values().any(|ours| ours == root)) {
                Ok(fetched) => self.states = Some(fetched),
                Err(error) => silver_log::warn!(url, error, "VRF states not fetched"),
            }
        }
        self.states.as_ref()?.upper(root).copied()
    }
}

/// Each genesis validator's XMSS pubkey and VRF root, in index order.
pub fn genesis_registry(genesis_state: &Path) -> Result<Vec<(XMSSPubkey, Node)>, String> {
    let state = fs::read(genesis_state).map_err(|e| format!("{}: {e}", genesis_state.display()))?;
    let keys = pq_validator_keys(&state).map_err(|e| format!("genesis registry: {e}"))?;
    Ok(keys.map(|(pubkey, root)| (*pubkey, *root)).collect())
}

/// The published slot-zero VRF records (`--vrf-state-url`): the siblings
/// above each key's populated leaves, by the root they complete. A tree is
/// used only if it hashes to its key's registered root.
pub struct VrfStates(HashMap<Node, [Node; UPPER]>);

impl VrfStates {
    /// Reads the whole artifact once: an HTTP(S) URL, or a local path.
    /// Keeps only the records of roots `wanted`.
    pub fn fetch(source: &str, wanted: impl Fn(&Node) -> bool) -> Result<Self, String> {
        let max = RECORD_LEN * MAX_RECORDS;
        let bytes = match source.strip_prefix("file://") {
            Some(path) => fs::read(path).map_err(|e| format!("{path}: {e}"))?,
            None if !source.contains("://") => {
                fs::read(source).map_err(|e| format!("{source}: {e}"))?
            }
            None => {
                let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
                let response = agent.get(source).call().map_err(|e| e.to_string())?;
                let mut bytes = Vec::new();
                let mut reader = response.into_reader().take(max as u64 + 1);
                reader.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                bytes
            }
        };
        if bytes.len() > max {
            return Err(format!("more than {MAX_RECORDS} records"));
        }
        let (records, []) = bytes.as_chunks::<RECORD_LEN>() else {
            return Err(format!("not whole {RECORD_LEN}-byte records"));
        };
        let mut states = HashMap::new();
        for record in records {
            let (root, rest) = record.split_first_chunk::<32>().expect("a root");
            let (slot, branch) = rest.split_first_chunk::<4>().expect("a slot");
            if *slot != [0; 4] {
                return Err("a record not of slot zero".into());
            }
            if wanted(root) {
                let upper = branch.as_chunks::<32>().0[POPULATED_DEPTH..].try_into();
                states.insert(*root, upper.expect("UPPER"));
            }
        }
        Ok(Self(states))
    }

    pub fn upper(&self, root: &Node) -> Option<&[Node; UPPER]> {
        self.0.get(root)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Spec `is_valid_vrf_proof` (consensus-specs `b5d422b25`).
    pub fn is_valid_vrf_proof(proof: &VRFProof, slot: u64, root: &Node) -> bool {
        let (secret, branch) = proof.split_first_chunk::<32>().unwrap();
        let mut node = keccak256(&[&b"VRF_LEAF"[..], secret, &slot.to_le_bytes()].concat());
        for (height, sibling) in branch.as_chunks::<32>().0.iter().enumerate() {
            node = if (slot >> height) & 1 == 1 {
                hash_pair(sibling, &node)
            } else {
                hash_pair(&node, sibling)
            };
        }
        node == *root
    }

    pub const SEED: [u8; 32] = [0x5e; 32];

    pub fn upper() -> [Node; UPPER] {
        std::array::from_fn(|i| [i as u8 + 1; 32])
    }

    #[test]
    fn proofs_verify_under_the_beacon_nodes_rule_for_their_slot_only() {
        let tree = VrfTree::build(&SEED, upper());
        let root = tree.root();
        for slot in [0, 1, 1023, 1024, 65, 777_777, (1 << 20) - 1] {
            let proof = tree.proof(&SEED, slot).unwrap();
            assert!(is_valid_vrf_proof(&proof, slot, &root), "slot {slot}");
            assert!(!is_valid_vrf_proof(&proof, slot + 1, &root));
        }
        assert!(tree.proof(&SEED, 1 << 20).is_none(), "past the populated leaves");

        let secret = keccak256(&[&b"VRF_SECRET"[..], &SEED, &5u64.to_le_bytes()].concat());
        assert_eq!(tree.proof(&SEED, 5).unwrap()[..32], secret, "the reveal opens with its secret");
    }

    #[test]
    fn a_cache_is_used_only_for_its_registered_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.vrf");
        let built = VrfTree::build_cached(&SEED, upper(), &path);
        assert_eq!(fs::read(&path).unwrap().len(), CACHE_LEN);
        let root = built.root();
        assert_eq!(VrfTree::cached(&root, &path).unwrap().root(), root);
        assert!(VrfTree::cached(&[0; 32], &path).is_none(), "another key's root");

        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(VrfTree::cached(&root, &path).is_none(), "a tampered cache");
    }

    #[test]
    fn states_give_each_root_its_upper_siblings() {
        let tree = VrfTree::build(&SEED, upper());
        let proof = tree.proof(&SEED, 0).unwrap();
        let mut record = tree.root().to_vec();
        record.extend([0; 4]);
        record.extend(&proof[32..]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.vrf");
        fs::write(&path, &record).unwrap();

        let states = VrfStates::fetch(path.to_str().unwrap(), |_| true).unwrap();
        assert_eq!(states.upper(&tree.root()), Some(&upper()));
        record[32] = 1;
        fs::write(&path, &record).unwrap();
        assert!(
            VrfStates::fetch(&format!("file://{}", path.display()), |_| true).is_err(),
            "slot one"
        );
    }
}
