mod leaf_guard;

use std::{
    collections::VecDeque,
    fs::File,
    mem,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

use lean_xmss::{LeanXmssExpandedSecretKey, PUB_KEY_SIZE, SIG_SIZE};
use mio::Waker;
use silver_common::{
    Error, SLOTS_PER_EPOCH,
    ssz_view::{XMSS_PUBKEY_SIZE, XMSS_SIGNATURE_SIZE, XMSSPubkey, XMSSSignature},
    xmss::{SlotDuty, attestation_leaf},
};

use self::leaf_guard::LeafGuard;
use crate::{
    keys::ValidatorKey,
    signing::{KeyWork, SignRequest},
};

const _: () = assert!(PUB_KEY_SIZE == XMSS_PUBKEY_SIZE && SIG_SIZE == XMSS_SIGNATURE_SIZE);

const TREE_LEAVES_LOG2: u32 = 16;

type Answer = (SignRequest, Option<XMSSSignature>);

struct SigningKey {
    xmss: LeanXmssExpandedSecretKey,
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
    /// nothing once both have grown.
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
    /// Expands every key on `threads` threads, checking each against its
    /// pubkey, then starts that many signing threads. `waker` ends the duty
    /// loop's wait once a signature is ready.
    pub fn new(keys: &[ValidatorKey], threads: usize, waker: Waker) -> Result<Self, Error> {
        debug_assert!(keys.is_sorted_by_key(|key| key.pubkey));
        let (guard, leaf_records) = LeafGuard::open(keys.iter().map(|key| key.path.as_path()))?;
        let expanded = expand(keys, threads)?;
        let keys_pubkeys = keys.iter().map(|key| key.pubkey).collect();
        let keys = expanded
            .into_iter()
            .zip(leaf_records)
            .map(|(xmss, leaf_record)| SigningKey { xmss, leaf_record })
            .collect();
        let pool = Arc::new(Pool {
            keys,
            jobs: Mutex::default(),
            work: Condvar::new(),
            answers: Mutex::default(),
        });

        let waker = Arc::new(waker);
        for worker in 0..threads {
            let (pool, waker) = (Arc::clone(&pool), Arc::clone(&waker));
            thread::Builder::new()
                .name(format!("vc-signer-{worker}"))
                .spawn(move || pool.work(&waker))?;
        }
        Ok(Self {
            pubkeys: keys_pubkeys,
            pool,
            guard,
            answered: Vec::new(),
            prepared_trees: [None; 2],
        })
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
    fn work(&self, waker: &Waker) -> ! {
        loop {
            match self.next_job() {
                Job::Sign(key, request) => {
                    let KeyWork::Sign { leaf_index, signing_root } = request.work else {
                        unreachable!("only signatures are queued");
                    };
                    let key = &self.keys[key];
                    let signature = survive_panic(leaf_index, || {
                        lean_xmss::sign(&key.xmss, &signing_root, leaf_index).to_bytes()
                    });
                    let synced = key.leaf_record.sync_data().inspect_err(|error| {
                        silver_log::error!(%error, leaf_index, "not signed: leaf record not synced");
                    });
                    let signature = signature.filter(|_| synced.is_ok());
                    self.answers.lock().expect("signer lock").push((request, signature));
                    if let Err(error) = waker.wake() {
                        silver_log::error!(%error, "signer waker");
                    }
                }
                Job::Prepare(key, leaf) => {
                    survive_panic(leaf, || self.keys[key].xmss.prepare(leaf));
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

/// leanVM panics only on a poisoned cache lock or an inadmissible encoding.
/// Either costs that one call, never the worker, so every request is still
/// answered. Under `panic = "abort"` the process stops instead.
fn survive_panic<T>(leaf: u32, call: impl FnOnce() -> T) -> Option<T> {
    let caught = panic::catch_unwind(AssertUnwindSafe(call));
    caught.inspect_err(|_| silver_log::error!(leaf, "leanVM panicked")).ok()
}

/// Builds each key's top tree, the slow part of loading it, across `threads`.
fn expand(keys: &[ValidatorKey], threads: usize) -> Result<Vec<LeanXmssExpandedSecretKey>, Error> {
    let started = Instant::now();
    silver_log::info!(keys = keys.len(), threads, "expanding keys");
    let chunk = keys.len().div_ceil(threads.max(1)).max(1);
    let expanded = thread::scope(|scope| {
        let workers: Vec<_> = keys
            .chunks(chunk)
            .map(|chunk| {
                scope.spawn(|| {
                    chunk.iter().map(|key| lean_xmss::key_gen(&key.privkey)).collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("key expansion"))
            .collect::<Vec<_>>()
    });
    for (key, (_, derived)) in keys.iter().zip(&expanded) {
        if derived.to_bytes() != key.pubkey {
            let path = key.path.display();
            return Err(Error::ConfigError(format!(
                "key file {path}: privkey does not derive pubkey"
            )));
        }
    }
    silver_log::info!(keys = keys.len(), elapsed = ?started.elapsed(), "keys expanded");
    Ok(expanded.into_iter().map(|(xmss, _)| xmss).collect())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, Permissions},
        os::unix::fs::PermissionsExt,
        path::Path,
        time::Duration,
    };

    use mio::{Events, Poll, Token};

    use super::*;
    use crate::{keys::load_keys, signing::SignPurpose};

    const SLOT: u64 = 65;

    /// Writes a key file per seed, its pubkey derived as leanVM derives it.
    fn key_dir(seeds: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for &seed in seeds {
            let pubkey = lean_xmss::key_gen(&[seed; 32]).1.to_bytes();
            let json = format!(
                r#"{{"pubkey":"0x{}","privkey":"0x{}","vrf_seed":"0x{}"}}"#,
                hex::encode(pubkey),
                hex::encode([seed; 32]),
                hex::encode([0x22; 32])
            );
            let path = dir.path().join(format!("{seed}.json"));
            fs::write(&path, json).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }

    fn signer(dir: &Path, poll: &Poll) -> (Signer, Vec<ValidatorKey>) {
        let keys = load_keys(dir).unwrap();
        let waker = Waker::new(poll.registry(), Token(0)).unwrap();
        (Signer::new(&keys, 2, waker).unwrap(), keys)
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
        let dir = key_dir(&[1, 2]);
        let mut poll = Poll::new().unwrap();
        let (mut signer, keys) = signer(dir.path(), &poll);
        signer.prepare_for(SLOT);

        let leaf = attestation_leaf(SLOT / SLOTS_PER_EPOCH).unwrap();
        for (key, root) in keys.iter().zip([[0x5a; 32], [0x5b; 32]]) {
            assert!(signer.submit(&request(key.pubkey, leaf, root)));
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
        let dir = key_dir(&[3]);
        let mut poll = Poll::new().unwrap();
        let (mut signer, keys) = signer(dir.path(), &poll);
        let leaf = SlotDuty::BeaconProposer.leaf(SLOT).unwrap();

        assert!(signer.submit(&request(keys[0].pubkey, leaf, [1; 32])));
        assert!(!signer.submit(&request(keys[0].pubkey, leaf, [2; 32])), "another root");
        assert!(!signer.submit(&request([0xee; 32], leaf, [1; 32])), "unknown key");
        let reveal =
            SignRequest { work: KeyWork::VrfProof, ..request(keys[0].pubkey, leaf, [1; 32]) };
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
    fn a_privkey_that_does_not_derive_its_pubkey_is_refused() {
        let dir = key_dir(&[4]);
        let path = dir.path().join("4.json");
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace(&hex::encode([4; 32]), &hex::encode([5; 32]));
        fs::write(&path, text).unwrap();
        let keys = load_keys(dir.path()).unwrap();
        let poll = Poll::new().unwrap();
        let waker = Waker::new(poll.registry(), Token(0)).unwrap();
        assert!(matches!(Signer::new(&keys, 1, waker), Err(Error::ConfigError(_))));
    }
}
