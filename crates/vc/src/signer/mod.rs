mod leaf_guard;
mod load;
mod remote_cache;

use std::{
    collections::VecDeque,
    fs::File,
    mem,
    panic::{self, AssertUnwindSafe},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    thread,
};

use lean_xmss::{PUB_KEY_SIZE, SIG_SIZE};
use silver_common::{
    Error, SLOTS_PER_EPOCH,
    ssz_view::{XMSS_PUBKEY_SIZE, XMSS_SIGNATURE_SIZE, XMSSPubkey, XMSSSignature},
    xmss::{SlotDuty, attestation_leaf},
};

pub use self::remote_cache::RemoteCache;
use self::{leaf_guard::LeafGuard, load::LoadedKey};
use crate::{
    keys::ValidatorKey,
    signing::{KeyWork, SignRequest},
};

const _: () = assert!(PUB_KEY_SIZE == XMSS_PUBKEY_SIZE && SIG_SIZE == XMSS_SIGNATURE_SIZE);

const TREE_LEAVES_LOG2: u32 = 16;

type Answer = (SignRequest, Option<XMSSSignature>);

struct SigningKey {
    loaded: LoadedKey,
    leaf_record: File,
}

/// Signatures go first, and one worker at a time prepares a tree, so the
/// others stay free to sign: a tree costs about as much as 18 signatures.
#[derive(Default)]
struct Jobs {
    signs: VecDeque<(usize, SignRequest)>,
    prepares: VecDeque<(usize, u32)>,
    preparing: bool,
}

enum Job {
    Sign(usize, SignRequest),
    Prepare(usize, u32),
}

struct Pool {
    keys: Box<[SigningKey]>,
    jobs: Mutex<Jobs>,
    work: Condvar,
    /// Swapped with `Signer::answered` on each drain, so answering allocates
    /// nothing once both have grown. Only the first answer since a drain
    /// wakes the loop: that drain takes every answer pushed before it.
    answers: Mutex<Vec<Answer>>,
}

/// Signs with leanXMSS on its own threads, so the duty loop never waits for
/// a signature. Each key signs at most one root per leaf (`LeafGuard`).
pub struct Signer {
    /// Sorted, in the order of `Pool::keys`.
    pubkeys: Box<[XMSSPubkey]>,
    pool: Arc<Pool>,
    guard: LeafGuard,
    answered: Vec<Answer>,
    /// The highest attestation and slot-duty trees queued for preparing.
    prepared_trees: [Option<u32>; 2],
}

impl Signer {
    /// Expands every key on `threads` threads (`load`), then starts that many
    /// signing threads. Each key's leaf record and expanded-key cache live in
    /// `data_dir`; a missing leaf record is created only if
    /// `init_leaf_records`. `wake` ends the duty loop's wait once a
    /// signature is ready.
    pub fn new(
        keys: &[ValidatorKey],
        data_dir: &Path,
        remote: Option<&RemoteCache>,
        init_leaf_records: bool,
        threads: usize,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, Error> {
        let mut loaded = load::load(keys, data_dir, remote, threads)?;
        loaded.sort_unstable_by_key(|key| key.pubkey);
        if let Some(twice) = loaded.windows(2).find(|pair| pair[0].pubkey == pair[1].pubkey) {
            let pubkey = hex::encode(twice[0].pubkey);
            return Err(Error::ConfigError(format!("key 0x{pubkey} listed twice")));
        }
        let records =
            loaded.iter().map(|key| data_dir.join(format!("0x{}.leaves", hex::encode(key.pubkey))));
        let (guard, leaf_records) = LeafGuard::open(records, init_leaf_records)?;
        let pubkeys = loaded.iter().map(|key| key.pubkey).collect();
        let keys = loaded
            .into_iter()
            .zip(leaf_records)
            .map(|(loaded, leaf_record)| SigningKey { loaded, leaf_record })
            .collect();
        let pool = Arc::new(Pool {
            keys,
            jobs: Mutex::default(),
            work: Condvar::new(),
            answers: Mutex::default(),
        });

        let wake = Arc::new(wake);
        for worker in 0..threads {
            let (pool, wake) = (Arc::clone(&pool), Arc::clone(&wake));
            thread::Builder::new()
                .name(format!("vc-signer-{worker}"))
                .spawn(move || pool.work(&*wake))?;
        }
        Ok(Self { pubkeys, pool, guard, answered: Vec::new(), prepared_trees: [None; 2] })
    }

    /// Sorted.
    pub fn pubkeys(&self) -> &[XMSSPubkey] {
        &self.pubkeys
    }

    /// Queues the signature, or refuses it at once.
    pub fn submit(&mut self, request: &SignRequest) -> bool {
        let KeyWork::Sign { leaf_index, signing_root } = request.work else {
            silver_log::warn!(slot = request.slot, "no RANDAO reveal: no VRF prover yet");
            return false;
        };
        let Ok(key) = self.pubkeys.binary_search(&request.pubkey) else {
            silver_log::error!(pubkey = %hex::encode(request.pubkey), "no key to sign with");
            return false;
        };
        let leaf_record = &self.pool.keys[key].leaf_record;
        if !self.guard.admit(key, leaf_index, &signing_root, leaf_record) {
            return false;
        }
        self.pool.jobs.lock().expect("signer lock").signs.push_back((key, *request));
        self.pool.work.notify_one();
        true
    }

    /// Hands over each answer that is ready; `None` for a failed signature.
    pub fn drain(&mut self, mut each: impl FnMut(&SignRequest, Option<&XMSSSignature>)) {
        mem::swap(&mut *self.pool.answers.lock().expect("signer lock"), &mut self.answered);
        for (request, signature) in self.answered.drain(..) {
            each(&request, signature.as_ref());
        }
    }

    /// Queues, for every key, the attestation and slot-duty trees `slot`
    /// signs in, then the tree after each. A slot-duty tree lasts 8192 slots,
    /// so a boundary finds its tree long built.
    pub fn prepare_for(&mut self, slot: u64) {
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
                self.pool.prepare_all(tree << TREE_LEAVES_LOG2);
            }
        }
    }
}

impl Pool {
    fn prepare_all(&self, leaf: u32) {
        let keys = self.keys.len();
        silver_log::info!(keys, tree = leaf >> TREE_LEAVES_LOG2, "preparing bottom trees");
        self.jobs.lock().expect("signer lock").prepares.extend((0..keys).map(|key| (key, leaf)));
        self.work.notify_one();
    }

    fn next_job(&self) -> Job {
        let mut jobs = self.jobs.lock().expect("signer lock");
        loop {
            if let Some((key, request)) = jobs.signs.pop_front() {
                return Job::Sign(key, request);
            }
            if !jobs.preparing &&
                let Some((key, leaf)) = jobs.prepares.pop_front()
            {
                jobs.preparing = true;
                return Job::Prepare(key, leaf);
            }
            jobs = self.work.wait(jobs).expect("signer lock");
        }
    }

    /// Runs for the life of the process.
    fn work(&self, wake: &dyn Fn()) -> ! {
        loop {
            match self.next_job() {
                Job::Sign(key, request) => {
                    let KeyWork::Sign { leaf_index, signing_root } = request.work else {
                        unreachable!("only signatures are queued");
                    };
                    let key = &self.keys[key];
                    let signature = survive_panic(leaf_index, || {
                        lean_xmss::sign(&key.loaded.xmss, &signing_root, leaf_index).to_bytes()
                    });
                    let synced = key.leaf_record.sync_data().inspect_err(|error| {
                        silver_log::error!(%error, leaf_index, "not signed: leaf record not synced");
                    });
                    let signature = signature.filter(|_| synced.is_ok());
                    let mut answers = self.answers.lock().expect("signer lock");
                    let first = answers.is_empty();
                    answers.push((request, signature));
                    drop(answers);
                    if first {
                        wake();
                    }
                }
                Job::Prepare(key, leaf) => {
                    let loaded = &self.keys[key].loaded;
                    if survive_panic(leaf, || loaded.xmss.prepare(leaf)).is_some() {
                        loaded.persist();
                    }
                    let mut jobs = self.jobs.lock().expect("signer lock");
                    jobs.preparing = false;
                    if jobs.prepares.front().is_none_or(|&(_, next)| next != leaf) {
                        silver_log::info!(tree = leaf >> TREE_LEAVES_LOG2, "bottom trees prepared");
                    }
                }
            }
        }
    }
}

/// `each` over `items` across `threads`, in order.
fn in_parallel<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    each: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let chunk = items.len().div_ceil(threads.max(1)).max(1);
    thread::scope(|scope| {
        let workers: Vec<_> = items
            .chunks(chunk)
            .map(|chunk| scope.spawn(|| chunk.iter().map(&each).collect::<Vec<_>>()))
            .collect();
        workers.into_iter().flat_map(|worker| worker.join().expect("worker panicked")).collect()
    })
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
    use std::{path::PathBuf, time::Duration};

    use mio::{Events, Poll, Token, Waker};

    use super::*;
    use crate::signing::SignPurpose;

    const SLOT: u64 = 65;

    /// A key as a keystore gives it: seeds only, its pubkey derived on load.
    pub fn key(seed: u8) -> ValidatorKey {
        ValidatorKey {
            privkey: [seed; 32],
            vrf_seed: [0x22; 32],
            pubkey: None,
            source: PathBuf::from(format!("{seed}.json")),
        }
    }

    fn signer(seeds: &[u8], data_dir: &Path, poll: &Poll) -> Signer {
        let keys: Vec<_> = seeds.iter().map(|&seed| key(seed)).collect();
        let waker = Waker::new(poll.registry(), Token(0)).unwrap();
        Signer::new(&keys, data_dir, None, true, 2, move || waker.wake().unwrap()).unwrap()
    }

    fn request(pubkey: XMSSPubkey, leaf_index: u32, signing_root: [u8; 32]) -> SignRequest {
        SignRequest {
            slot: SLOT,
            purpose: SignPurpose::Attestation { validator_index: 7, committee_index: 3 },
            pubkey,
            work: KeyWork::Sign { leaf_index, signing_root },
        }
    }

    /// Waits on `poll`, as the duty loop does, until `count` answers are in.
    fn answers(signer: &mut Signer, poll: &mut Poll, count: usize) -> Vec<Answer> {
        let mut events = Events::with_capacity(4);
        let mut answered = Vec::new();
        while answered.len() < count {
            poll.poll(&mut events, Some(Duration::from_secs(10))).unwrap();
            assert!(!events.is_empty(), "no answer within 10 s");
            signer.drain(|request, signature| answered.push((*request, signature.copied())));
        }
        answered
    }

    #[test]
    fn signatures_verify_under_the_beacon_nodes_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let mut poll = Poll::new().unwrap();
        let mut signer = signer(&[1, 2], dir.path(), &poll);
        signer.prepare_for(SLOT);

        let leaf = attestation_leaf(SLOT / SLOTS_PER_EPOCH).unwrap();
        let pubkeys = signer.pubkeys().to_vec();
        for (pubkey, root) in pubkeys.into_iter().zip([[0x5a; 32], [0x5b; 32]]) {
            assert!(signer.submit(&request(pubkey, leaf, root)));
        }
        let answered = answers(&mut signer, &mut poll, 2);
        for (request, signature) in answered {
            let KeyWork::Sign { leaf_index, signing_root } = request.work else { unreachable!() };
            let signature = signature.expect("signed");
            assert!(silver_crypto_simd::xmss::verify(
                &request.pubkey,
                u64::from(leaf_index),
                &signing_root,
                &signature
            ));
        }
    }

    #[test]
    fn a_used_leaf_unknown_key_or_vrf_proof_is_refused_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut poll = Poll::new().unwrap();
        let mut signer = signer(&[3], dir.path(), &poll);
        let pubkey = signer.pubkeys()[0];
        let leaf = SlotDuty::BeaconProposer.leaf(SLOT).unwrap();

        assert!(signer.submit(&request(pubkey, leaf, [1; 32])));
        assert!(!signer.submit(&request(pubkey, leaf, [2; 32])), "another root");
        assert!(!signer.submit(&request([0xee; 32], leaf, [1; 32])), "unknown key");
        let reveal = SignRequest { work: KeyWork::VrfProof, ..request(pubkey, leaf, [1; 32]) };
        assert!(!signer.submit(&reveal));
        assert_eq!(answers(&mut signer, &mut poll, 1).len(), 1);
    }

    #[test]
    fn signatures_overtake_trees_and_one_tree_builds_at_a_time() {
        let pool = Pool {
            keys: Box::new([]),
            jobs: Mutex::default(),
            work: Condvar::new(),
            answers: Mutex::default(),
        };
        pool.jobs.lock().unwrap().prepares.extend([(0, 1 << 16), (1, 1 << 16)]);
        assert!(matches!(pool.next_job(), Job::Prepare(0, _)));

        let leaf = attestation_leaf(1).unwrap();
        pool.jobs.lock().unwrap().signs.push_back((0, request([0xaa; 32], leaf, [1; 32])));
        assert!(matches!(pool.next_job(), Job::Sign(0, _)), "a signature first");
        let jobs = pool.jobs.lock().unwrap();
        assert!(jobs.preparing && jobs.prepares.len() == 1, "the second tree waits");
    }

    #[test]
    fn a_panic_costs_its_answer_only() {
        assert_eq!(survive_panic(7, || 1), Some(1));
        assert_eq!(survive_panic(7, || -> u8 { panic!("inadmissible encoding") }), None);
    }

    #[test]
    fn a_wrong_stated_pubkey_or_a_key_listed_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let new = |keys: &[ValidatorKey]| Signer::new(keys, dir.path(), None, true, 1, || {});
        let mut stated_wrongly = key(4);
        stated_wrongly.pubkey = Some([0xee; 32]);
        assert!(matches!(new(&[stated_wrongly]), Err(Error::ConfigError(_))));
        assert!(matches!(new(&[key(5), key(5)]), Err(Error::ConfigError(_))));
    }

    #[test]
    fn a_key_without_a_leaf_record_needs_init() {
        let dir = tempfile::tempdir().unwrap();
        let new = |init| Signer::new(&[key(6)], dir.path(), None, init, 1, || {});
        assert!(matches!(new(false), Err(Error::ConfigError(_))));
        assert!(new(true).is_ok());
        assert!(new(false).is_ok(), "its record now exists");
    }
}
