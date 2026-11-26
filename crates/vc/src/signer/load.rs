use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey,
    internals::{CACHED_BOTTOM_SIZE, CACHED_TREE_SIZE, public_param, scheme_seed},
};
use silver_common::{Error, ssz_view::XMSSPubkey};

use super::{in_parallel, remote_cache::RemoteCache};
use crate::keys::ValidatorKey;

pub struct LoadedKey {
    pub pubkey: XMSSPubkey,
    pub xmss: LeanXmssExpandedSecretKey,
    /// Its expanded-key cache in the data directory.
    cache: PathBuf,
    /// The bottom trees the cache file holds, sorted; `None` before the
    /// file is written.
    persisted: Mutex<Option<Vec<u32>>>,
}

/// Expands every key across `threads`: from its cache in `data_dir`, else
/// from `remote`, else by building its top tree. A cache loads in ~50 µs; a
/// build takes ~0.3 s, and ~0.3 s more for each bottom tree it then signs in.
pub fn load(
    keys: &[ValidatorKey],
    data_dir: &Path,
    remote: Option<&RemoteCache>,
    threads: usize,
) -> Result<Vec<LoadedKey>, Error> {
    let started = Instant::now();
    let caches = keys.iter().map(|key| Cache::of(key, data_dir)).collect::<Vec<_>>();
    let mut loaded = in_parallel(&caches, threads, |cache| cache.load_local());
    let local = loaded.iter().flatten().count();

    let missing = (0..keys.len()).filter(|&i| loaded[i].is_none()).collect::<Vec<_>>();
    let mut fetched = vec![None; missing.len()];
    if let Some(remote) = remote {
        let parameters = missing.iter().map(|&i| caches[i].parameter).collect::<Vec<_>>();
        let runs = remote.runs(&parameters);
        for run in
            in_parallel(&runs, threads, |run| remote.fetch(run).map(Iterator::collect::<Vec<_>>))
        {
            match run {
                Ok(records) => records
                    .into_iter()
                    .for_each(|(at, pubkey, bytes)| fetched[at] = Some((pubkey, bytes))),
                Err(error) => silver_log::warn!(error, "remote expanded keys not fetched"),
            }
        }
    }

    let jobs = missing.iter().copied().zip(fetched).collect::<Vec<_>>();
    let finished = in_parallel(&jobs, threads, |(i, fetched)| {
        caches[*i].load_remote_or_build(&keys[*i], fetched.as_ref())
    });
    let (mut remote, mut built) = (0, 0);
    for ((i, _), result) in jobs.iter().zip(finished) {
        let (key, from_remote) = result?;
        if from_remote {
            remote += 1
        } else {
            built += 1
        }
        loaded[*i] = Some(key);
    }
    silver_log::info!(local, remote, built, elapsed = ?started.elapsed(), "keys expanded");
    Ok(loaded.into_iter().map(|key| key.expect("every key loaded")).collect())
}

/// Where a key's expanded-key cache lives, named by its public parameter:
/// a keystore's pubkey is unknown until the key loads.
struct Cache<'a> {
    key: &'a ValidatorKey,
    parameter: [u8; 16],
    path: PathBuf,
}

impl<'a> Cache<'a> {
    fn of(key: &'a ValidatorKey, data_dir: &Path) -> Self {
        let parameter = public_param(&scheme_seed(&key.privkey));
        let path = data_dir.join(format!("0x{}.xmss", hex::encode(parameter)));
        Self { key, parameter, path }
    }

    fn stated(&self, pubkey: &XMSSPubkey) -> bool {
        self.key.pubkey.is_none_or(|stated| stated == *pubkey)
    }

    /// A cache file is the pubkey, then leanVM's `cache_to_bytes`. It holds no
    /// secret, and loads only through `from_cache_bytes`.
    fn load_local(&self) -> Option<LoadedKey> {
        let file = fs::read(&self.path).ok()?;
        let (pubkey, bytes) = file.split_first_chunk::<32>()?;
        let xmss = self.stated(pubkey).then(|| from_cache(&self.key.privkey, pubkey, bytes))??;
        let persisted = Mutex::new(Some(cached_trees(bytes)));
        Some(LoadedKey { pubkey: *pubkey, xmss, cache: self.path.clone(), persisted })
    }

    /// Whether it loaded from `fetched`.
    fn load_remote_or_build(
        &self,
        key: &ValidatorKey,
        fetched: Option<&(XMSSPubkey, Vec<u8>)>,
    ) -> Result<(LoadedKey, bool), Error> {
        let source = key.source.display();
        let remote = fetched.and_then(|(pubkey, bytes)| {
            if !self.stated(pubkey) {
                silver_log::warn!(%source, "remote key differs from the stated one");
                return None;
            }
            let xmss = from_cache(&key.privkey, pubkey, bytes);
            if xmss.is_none() {
                silver_log::warn!(%source, "remote expanded key refused");
            }
            Some((*pubkey, xmss?))
        });
        let from_remote = remote.is_some();
        let (pubkey, xmss) = match remote {
            Some(loaded) => loaded,
            None => {
                let (xmss, pubkey) = lean_xmss::key_gen(&key.privkey);
                (pubkey.to_bytes(), xmss)
            }
        };
        if !self.stated(&pubkey) {
            return Err(Error::ConfigError(format!(
                "key file {source}: privkey does not derive pubkey"
            )));
        }
        let key = LoadedKey { pubkey, xmss, cache: self.path.clone(), persisted: Mutex::default() };
        key.persist();
        Ok((key, from_remote))
    }
}

impl LoadedKey {
    /// Rewrites the cache file when the key holds trees the file lacks, so a
    /// restart signs without building them again. The file is replaced whole:
    /// a crash leaves the old one or the new one.
    pub fn persist(&self) {
        let bytes = self.xmss.cache_to_bytes();
        let trees = cached_trees(&bytes);
        let mut persisted = self.persisted.lock().expect("cache lock");
        if persisted.as_ref() == Some(&trees) {
            return;
        }
        let partial = self.cache.with_extension("xmss.partial");
        let written = fs::write(&partial, [&self.pubkey[..], &bytes].concat())
            .and_then(|()| fs::rename(&partial, &self.cache));
        match written {
            Ok(()) => *persisted = Some(trees),
            Err(error) => {
                silver_log::warn!(%error, path = %self.cache.display(), "expanded key not cached")
            }
        }
    }
}

fn from_cache(
    privkey: &[u8; 32],
    pubkey: &XMSSPubkey,
    bytes: &[u8],
) -> Option<LeanXmssExpandedSecretKey> {
    LeanXmssExpandedSecretKey::from_cache_bytes(
        privkey,
        &LeanXmssPublicKey::from_bytes(pubkey),
        bytes,
    )
}

/// The indices of the bottom trees in `cache_to_bytes` output, sorted: each
/// tree's record starts with its index.
fn cached_trees(cache: &[u8]) -> Vec<u32> {
    let bottoms = cache.get(CACHED_TREE_SIZE..).unwrap_or_default();
    let mut trees = bottoms
        .chunks_exact(CACHED_BOTTOM_SIZE)
        .map(|tree| u32::from_le_bytes(*tree.first_chunk().expect("4 bytes")))
        .collect::<Vec<_>>();
    trees.sort_unstable();
    trees
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::Arc,
        thread,
    };

    use super::*;
    use crate::signer::{remote_cache::RECORD_LEN, tests::key};

    const FIRST_SLOT_TREE: u32 = 24_576 << 16;

    /// The devnet record of `seed`'s key: its top tree and bottom trees 0 and
    /// 24576.
    fn record(seed: u8) -> (XMSSPubkey, Vec<u8>) {
        let (xmss, pubkey) = lean_xmss::key_gen(&[seed; 32]);
        xmss.prepare(1 << 15);
        xmss.prepare(FIRST_SLOT_TREE);
        let bytes = xmss.cache_to_bytes();
        assert_eq!(bytes.len(), RECORD_LEN);
        (pubkey.to_bytes(), bytes)
    }

    /// Serves `/keys.bin` whole and `/keys.xmss` by byte range.
    fn serve(metadata: Vec<u8>, records: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/keys.xmss", listener.local_addr().unwrap());
        let files = Arc::new((metadata, records));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let (mut stream, files) = (stream.unwrap(), Arc::clone(&files));
                thread::spawn(move || {
                    let mut lines = BufReader::new(stream.try_clone().unwrap()).lines();
                    let path = lines.next().unwrap().unwrap().split(' ').nth(1).unwrap().to_owned();
                    let mut range = None;
                    for line in lines.map(Result::unwrap).take_while(|line| !line.is_empty()) {
                        if let Some(bytes) = line.strip_prefix("Range: bytes=") {
                            let (start, end) = bytes.split_once('-').unwrap();
                            range = Some(
                                start.parse::<usize>().unwrap()..end.parse::<usize>().unwrap() + 1,
                            );
                        }
                    }
                    let (status, body) = match (path.as_str(), range) {
                        ("/keys.bin", None) => ("200 OK", files.0.clone()),
                        ("/keys.xmss", Some(range)) if range.end <= files.1.len() => {
                            ("206 Partial Content", files.1[range].to_vec())
                        }
                        _ => ("404 Not Found", Vec::new()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(head.as_bytes()).unwrap();
                    stream.write_all(&body).unwrap();
                });
            }
        });
        url
    }

    fn load_alone(key: &ValidatorKey, dir: &Path, remote: Option<&RemoteCache>) -> LoadedKey {
        load(std::slice::from_ref(key), dir, remote, 1).unwrap().pop().unwrap()
    }

    #[test]
    fn a_built_key_is_cached_and_reloads_from_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let built = load_alone(&key(1), dir.path(), None);
        let local = Cache::of(&key(1), dir.path()).load_local().expect("cached");
        assert_eq!(local.pubkey, built.pubkey);

        fs::write(&built.cache, [0; 40]).unwrap();
        assert!(Cache::of(&key(1), dir.path()).load_local().is_none(), "a refused cache");
        assert_eq!(load_alone(&key(1), dir.path(), None).pubkey, built.pubkey);
    }

    #[test]
    fn a_cache_is_rewritten_only_for_a_new_tree() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_alone(&key(1), dir.path(), None);
        loaded.xmss.prepare(1 << 15);
        loaded.persist();
        assert_eq!(*loaded.persisted.lock().unwrap(), Some(vec![0]));

        fs::remove_file(&loaded.cache).unwrap();
        loaded.xmss.prepare((1 << 15) + 1);
        loaded.persist();
        assert!(!loaded.cache.exists(), "the same tree is not written again");
        loaded.xmss.prepare(FIRST_SLOT_TREE);
        loaded.persist();
        assert_eq!(Cache::of(&key(1), dir.path()).load_local().unwrap().pubkey, loaded.pubkey);
    }

    #[test]
    fn a_genesis_key_loads_its_remote_record_by_public_parameter() {
        let (pubkeys, records): (Vec<_>, Vec<_>) = [2, 3].map(record).into_iter().unzip();
        let metadata =
            pubkeys.iter().flat_map(|pubkey| [&pubkey[..], &[0x77; 32]].concat()).collect();
        let url = serve(metadata, records.concat());
        let remote = RemoteCache::with_registry(&url, pubkeys.iter().copied()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let three = key(3);
        let fetched = Cache::of(&three, dir.path());
        let runs = remote.runs(&[fetched.parameter]);
        let (_, pubkey, bytes) = remote.fetch(&runs[0]).unwrap().next().unwrap();
        assert_eq!(pubkey, pubkeys[1]);
        let (loaded, from_remote) =
            fetched.load_remote_or_build(&key(3), Some(&(pubkey, bytes))).unwrap();
        assert!(from_remote);
        assert_eq!(loaded.pubkey, pubkeys[1]);
        assert!(fetched.load_local().is_some(), "the record was cached locally");

        assert_eq!(load_alone(&key(2), dir.path(), Some(&remote)).pubkey, pubkeys[0]);
        assert!(remote.runs(&[Cache::of(&key(4), dir.path()).parameter]).is_empty());
        let mut stated = key(2);
        stated.pubkey = Some([0xee; 32]);
        let fresh = tempfile::tempdir().unwrap();
        assert!(load(&[stated], fresh.path(), Some(&remote), 1).is_err());
    }

    #[test]
    fn a_listed_key_outside_genesis_is_not_fetched() {
        let (pubkey, record) = record(5);
        let metadata = [&pubkey[..], &[0x77; 32]].concat();
        let url = serve(metadata, record);
        let remote = RemoteCache::with_registry(&url, [[0x55; 32]].into_iter()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        assert!(remote.runs(&[Cache::of(&key(5), dir.path()).parameter]).is_empty());
    }

    #[test]
    fn a_cache_url_must_name_an_xmss_file() {
        assert!(
            RemoteCache::with_registry("http://127.0.0.1:1/keys.bin", std::iter::empty()).is_err()
        );
    }
}
