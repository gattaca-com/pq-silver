mod leaf_guard;
mod load;
mod remote_cache;
mod tile;
mod times;
mod vrf;

use std::{
    collections::VecDeque,
    fs::{self, File},
    os::unix::fs::DirBuilderExt,
    panic::{self, AssertUnwindSafe},
    path::Path,
    time::Instant,
};

use lean_xmss::{PUB_KEY_SIZE, SIG_SIZE};
use silver_common::{
    Error, SLOTS_PER_EPOCH,
    ssz_view::{XMSS_PUBKEY_SIZE, XMSS_SIGNATURE_SIZE, XMSSPubkey},
    vc_spine::{KeyWork, SignAnswer, SignRequest},
    xmss::{SlotDuty, attestation_leaf},
};

pub use self::tile::SignerTile;
use self::{
    leaf_guard::LeafGuard,
    load::{CacheFile, LoadedKey},
    remote_cache::RemoteCache,
    times::SigningTimes,
    vrf::{VrfKey, VrfSource},
};
use crate::keys::ValidatorKey;

const _: () = assert!(PUB_KEY_SIZE == XMSS_PUBKEY_SIZE && SIG_SIZE == XMSS_SIGNATURE_SIZE);

const TREE_LEAVES_LOG2: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submitted {
    Queued,
    Refused,
    /// Another signer tile's key.
    NotOurs,
}

struct SigningKey {
    loaded: LoadedKey,
    leaf_record: File,
    cache: CacheFile,
    vrf: VrfKey,
}

/// Signs with leanXMSS, one job per call. Signatures and RANDAO reveals go
/// before bottom trees, which cost about as much as 18 signatures each.
/// Each key signs at most one root per leaf (`LeafGuard`).
pub struct Signer {
    /// Sorted by pubkey.
    keys: Box<[SigningKey]>,
    vrf_source: Option<VrfSource>,
    guard: LeafGuard,
    /// Each with when it was queued.
    signs: VecDeque<(usize, SignRequest, Instant)>,
    /// A leaf of each bottom tree every key prepares, front first.
    trees: VecDeque<u32>,
    /// The next key to prepare the front tree for.
    next_key: usize,
    /// The highest attestation and slot-duty trees queued for preparing.
    prepared_trees: [Option<u32>; 2],
    times: SigningTimes,
}

impl Signer {
    /// Expands every key (`load`). Each key's leaf record, expanded-key cache
    /// and VRF tree live in `data_dir`; a missing leaf record is created only
    /// if `init_leaf_records`. Without `vrf_source`, RANDAO reveals are
    /// refused.
    pub fn load(
        keys: &[ValidatorKey],
        data_dir: &Path,
        remote: Option<&RemoteCache>,
        vrf_source: Option<VrfSource>,
        init_leaf_records: bool,
    ) -> Result<Self, Error> {
        // It holds the leaf records, so only its owner may write to it.
        fs::DirBuilder::new().recursive(true).mode(0o700).create(data_dir)?;
        let mut loaded = load::load(keys, data_dir, remote)?;
        loaded.sort_unstable_by_key(|(key, _)| key.pubkey);
        if let Some(twice) = loaded.windows(2).find(|pair| pair[0].0.pubkey == pair[1].0.pubkey) {
            let pubkey = hex::encode(twice[0].0.pubkey);
            return Err(Error::ConfigError(format!("key 0x{pubkey} listed twice")));
        }
        let records = loaded
            .iter()
            .map(|(key, _)| data_dir.join(format!("0x{}.leaves", hex::encode(key.pubkey))));
        let (guard, leaf_records) = LeafGuard::open(records, init_leaf_records)?;
        let vrf_source = vrf_source.map(|source| {
            source.for_keys(|pubkey| {
                loaded.binary_search_by_key(pubkey, |(key, _)| key.pubkey).is_ok()
            })
        });
        let keys = loaded
            .into_iter()
            .zip(leaf_records)
            .map(|((loaded, cache), leaf_record)| {
                let vrf = VrfKey::new(&loaded.pubkey, vrf_source.as_ref(), data_dir);
                SigningKey { loaded, leaf_record, cache, vrf }
            })
            .collect();
        Ok(Self {
            keys,
            vrf_source,
            guard,
            signs: VecDeque::new(),
            trees: VecDeque::new(),
            next_key: 0,
            prepared_trees: [None; 2],
            times: SigningTimes::default(),
        })
    }

    /// Sorted.
    pub fn pubkeys(&self) -> impl ExactSizeIterator<Item = &XMSSPubkey> {
        self.keys.iter().map(|key| &key.loaded.pubkey)
    }

    /// Queues the signature or VRF proof, or refuses it at once.
    pub fn submit(&mut self, request: &SignRequest) -> Submitted {
        let Ok(key) = self.keys.binary_search_by_key(&request.pubkey, |key| key.loaded.pubkey)
        else {
            return Submitted::NotOurs;
        };
        if let KeyWork::Sign { leaf_index, signing_root } = request.work {
            let leaf_record = &self.keys[key].leaf_record;
            if !self.guard.admit(key, leaf_index, &signing_root, leaf_record) {
                return Submitted::Refused;
            }
        }
        self.signs.push_back((key, *request, Instant::now()));
        Submitted::Queued
    }

    /// Queues, for every key, the attestation and slot-duty trees `slot`
    /// signs in, then the tree after each. A slot-duty tree lasts 8192 slots,
    /// so a boundary finds its tree long built.
    pub fn prepare_for(&mut self, slot: u64) {
        self.times.slot_started(slot);
        let leaves =
            [attestation_leaf(slot / SLOTS_PER_EPOCH), SlotDuty::BeaconProposer.leaf(slot)];
        for ahead in [0, 1] {
            for (prepared, leaf) in self.prepared_trees.iter_mut().zip(leaves) {
                let Some(tree) = leaf.map(|leaf| (leaf >> TREE_LEAVES_LOG2) + ahead) else {
                    continue;
                };
                if prepared.is_some_and(|prepared| prepared >= tree) {
                    continue;
                }
                *prepared = Some(tree);
                silver_log::info!(keys = self.keys.len(), tree, "preparing bottom trees");
                self.trees.push_back(tree << TREE_LEAVES_LOG2);
            }
        }
    }

    /// Does the next job, a signature or proof before a bottom tree, and
    /// hands over its answer. False with nothing to do.
    pub fn work(&mut self, answered: impl FnOnce(&SignRequest, SignAnswer)) -> bool {
        if let Some((key, request, queued)) = self.signs.pop_front() {
            let started = Instant::now();
            let answer = self.sign(key, &request);
            self.times.answered(&request, started - queued, started.elapsed());
            answered(&request, answer);
            return true;
        }
        let Some(&leaf) = self.trees.front() else { return false };
        let SigningKey { loaded, cache, .. } = &mut self.keys[self.next_key];
        if survive_panic(leaf, || loaded.xmss.prepare(leaf)).is_some() {
            cache.persist(loaded);
        }
        self.next_key += 1;
        if self.next_key == self.keys.len() {
            self.next_key = 0;
            self.trees.pop_front();
            silver_log::info!(tree = leaf >> TREE_LEAVES_LOG2, "bottom trees prepared");
        }
        true
    }

    fn sign(&mut self, key: usize, request: &SignRequest) -> SignAnswer {
        let SigningKey { loaded, leaf_record, vrf, .. } = &mut self.keys[key];
        match request.work {
            KeyWork::Sign { leaf_index, signing_root } => {
                let Some(signature) = survive_panic(leaf_index, || {
                    lean_xmss::sign(&loaded.xmss, &signing_root, leaf_index).to_bytes()
                }) else {
                    return SignAnswer::Refused;
                };
                match leaf_record.sync_data() {
                    Ok(()) => SignAnswer::Signature(signature),
                    Err(error) => {
                        silver_log::error!(%error, leaf_index, "not signed: leaf record not synced");
                        SignAnswer::Refused
                    }
                }
            }
            KeyWork::VrfProof => {
                let slot = request.slot;
                match vrf.proof(&loaded.vrf_seed, slot, self.vrf_source.as_mut()) {
                    Ok(proof) => SignAnswer::VrfProof(proof),
                    Err(reason) => {
                        silver_log::warn!(slot, reason, "no RANDAO reveal");
                        SignAnswer::Refused
                    }
                }
            }
        }
    }
}

/// leanVM panics only on a poisoned cache lock or an inadmissible encoding.
/// Either costs that one call, never the worker, so every request is still
/// answered. Under `panic = "abort"` the process stops instead.
fn survive_panic<T>(leaf: u32, call: impl FnOnce() -> T) -> Option<T> {
    let caught = panic::catch_unwind(AssertUnwindSafe(call));
    caught.inspect_err(|_| silver_log::error!(leaf, "leanVM panicked")).ok()
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use silver_common::vc_spine::SignPurpose;

    use super::*;

    const SLOT: u64 = 65;

    /// A key as a keystore gives it: seeds only, its pubkey derived on load.
    pub fn key(seed: u8) -> ValidatorKey {
        ValidatorKey {
            privkey: Box::new([seed; 32]),
            vrf_seed: Box::new([0x22; 32]),
            pubkey: None,
            source: PathBuf::from(format!("{seed}.json")),
        }
    }

    fn signer(seeds: &[u8], data_dir: &Path) -> Signer {
        let keys: Vec<_> = seeds.iter().map(|&seed| key(seed)).collect();
        Signer::load(&keys, data_dir, None, None, true).unwrap()
    }

    fn request(pubkey: XMSSPubkey, leaf_index: u32, signing_root: [u8; 32]) -> SignRequest {
        SignRequest {
            slot: SLOT,
            purpose: SignPurpose::Attestation { validator_index: 7, committee_index: 3 },
            pubkey,
            work: KeyWork::Sign { leaf_index, signing_root },
        }
    }

    /// Works until `count` answers are in.
    fn answers(signer: &mut Signer, count: usize) -> Vec<(SignRequest, SignAnswer)> {
        let mut answered = Vec::new();
        while answered.len() < count {
            assert!(signer.work(|request, answer| answered.push((*request, answer))), "idle");
        }
        answered
    }

    #[test]
    fn signatures_verify_under_the_beacon_nodes_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let mut signer = signer(&[1, 2], dir.path());
        let leaf = attestation_leaf(SLOT / SLOTS_PER_EPOCH).unwrap();
        let pubkeys = signer.pubkeys().copied().collect::<Vec<_>>();
        for (pubkey, root) in pubkeys.into_iter().zip([[0x5a; 32], [0x5b; 32]]) {
            assert_eq!(signer.submit(&request(pubkey, leaf, root)), Submitted::Queued);
        }
        for (request, answer) in answers(&mut signer, 2) {
            let KeyWork::Sign { leaf_index, signing_root } = request.work else { unreachable!() };
            let SignAnswer::Signature(signature) = answer else { panic!("signed") };
            assert!(silver_crypto_simd::xmss::verify(
                &request.pubkey,
                u64::from(leaf_index),
                &signing_root,
                &signature
            ));
        }
    }

    #[test]
    fn signatures_overtake_bottom_trees() {
        let dir = tempfile::tempdir().unwrap();
        let mut signer = signer(&[1, 2], dir.path());
        signer.prepare_for(SLOT);
        let leaf = attestation_leaf(SLOT / SLOTS_PER_EPOCH).unwrap();
        let pubkey = *signer.pubkeys().nth(1).unwrap();
        assert_eq!(signer.submit(&request(pubkey, leaf, [1; 32])), Submitted::Queued);
        let mut answered = None;
        assert!(signer.work(|request, _| answered = Some(*request)));
        assert_eq!(answered.map(|request| request.pubkey), Some(pubkey));
        while signer.work(|_, _| unreachable!("only trees left")) {}
        assert!(signer.trees.is_empty());
    }

    #[test]
    fn a_reveal_verifies_under_the_spec_rule() {
        use crate::signer::vrf::tests::is_valid_vrf_proof;

        let dir = tempfile::tempdir().unwrap();
        let keys = [key(7)];
        let pubkey = lean_xmss::key_gen(&keys[0].privkey).1.to_bytes();
        let tree = vrf::VrfTree::build(&keys[0].vrf_seed, vrf::tests::upper());
        let proof = tree.proof(&keys[0].vrf_seed, 0).unwrap();
        let mut record = tree.root().to_vec();
        record.extend([0; 4]);
        record.extend(&proof[32..]);
        let states_path = dir.path().join("keys.vrf");
        std::fs::write(&states_path, record).unwrap();
        let registry = [(pubkey, tree.root())];
        let source = VrfSource::new(&registry, Some(states_path.to_str().unwrap().to_owned()));

        let mut signer = Signer::load(&keys, dir.path(), None, Some(source), true).unwrap();
        let reveal = SignRequest {
            slot: SLOT,
            purpose: SignPurpose::Randao { validator_index: 7 },
            pubkey,
            work: KeyWork::VrfProof,
        };
        assert_eq!(signer.submit(&reveal), Submitted::Queued);
        let SignAnswer::VrfProof(proof) = answers(&mut signer, 1)[0].1 else { panic!("a proof") };
        assert!(is_valid_vrf_proof(&proof, SLOT, &tree.root()));
        assert!(dir.path().join(format!("0x{}.vrf", hex::encode(pubkey))).exists(), "cached");
        drop(signer);

        // A restart without the published state proves from the cache.
        std::fs::remove_file(&states_path).unwrap();
        let source = VrfSource::new(&registry, None);
        let mut signer = Signer::load(&keys, dir.path(), None, Some(source), false).unwrap();
        assert_eq!(signer.submit(&SignRequest { slot: SLOT + 1, ..reveal }), Submitted::Queued);
        let SignAnswer::VrfProof(proof) = answers(&mut signer, 1)[0].1 else {
            panic!("a proof from the cache")
        };
        assert!(is_valid_vrf_proof(&proof, SLOT + 1, &tree.root()));
    }

    #[test]
    fn a_used_leaf_or_unknown_key_is_refused_at_once_and_a_reveal_without_a_source() {
        let dir = tempfile::tempdir().unwrap();
        let mut signer = signer(&[3], dir.path());
        let pubkey = *signer.pubkeys().next().unwrap();
        let leaf = SlotDuty::BeaconProposer.leaf(SLOT).unwrap();

        assert_eq!(signer.submit(&request(pubkey, leaf, [1; 32])), Submitted::Queued);
        assert_eq!(
            signer.submit(&request(pubkey, leaf, [2; 32])),
            Submitted::Refused,
            "another root"
        );
        assert_eq!(signer.submit(&request([0xee; 32], leaf, [1; 32])), Submitted::NotOurs);
        let reveal = SignRequest { work: KeyWork::VrfProof, ..request(pubkey, leaf, [1; 32]) };
        assert_eq!(
            signer.submit(&reveal),
            Submitted::Queued,
            "refused later, for want of a source"
        );
        let answered = answers(&mut signer, 2);
        assert!(matches!(answered[1], (request, SignAnswer::Refused) if request == reveal));
    }

    #[test]
    fn a_panic_costs_its_answer_only() {
        assert_eq!(survive_panic(7, || 1), Some(1));
        assert_eq!(survive_panic(7, || -> u8 { panic!("inadmissible encoding") }), None);
    }

    #[test]
    fn a_wrong_stated_pubkey_or_a_key_listed_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let load = |keys: &[ValidatorKey]| Signer::load(keys, dir.path(), None, None, true);
        let mut stated_wrongly = key(4);
        stated_wrongly.pubkey = Some([0xee; 32]);
        assert!(matches!(load(&[stated_wrongly]), Err(Error::ConfigError(_))));
        assert!(matches!(load(&[key(5), key(5)]), Err(Error::ConfigError(_))));
    }

    #[test]
    fn a_missing_data_dir_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("a/b");
        Signer::load(&[key(8)], &data_dir, None, None, true).unwrap();
        let mode = fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert_eq!(fs::read_dir(&data_dir).unwrap().count(), 2, "the key's cache and leaf record");
    }

    #[test]
    fn a_key_without_a_leaf_record_needs_init() {
        let dir = tempfile::tempdir().unwrap();
        let load = |init| Signer::load(&[key(6)], dir.path(), None, None, init);
        assert!(matches!(load(false), Err(Error::ConfigError(_))));
        assert!(load(true).is_ok());
        assert!(load(false).is_ok(), "its record now exists");
    }
}
