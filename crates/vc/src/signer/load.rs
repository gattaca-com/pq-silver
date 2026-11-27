use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey,
    internals::{CACHED_BOTTOM_SIZE, CACHED_TREE_SIZE, public_param, scheme_seed},
};
use silver_common::{Error, ssz_view::XMSSPubkey};
use zeroize::Zeroize;

use super::remote_cache::RemoteCache;
use crate::keys::ValidatorKey;

pub struct LoadedKey {
    pub pubkey: XMSSPubkey,
    pub xmss: LeanXmssExpandedSecretKey,
    pub vrf_seed: Box<[u8; 32]>,
}

/// A key's expanded-key cache in the data directory.
pub struct CacheFile {
    path: PathBuf,
    /// The bottom trees the file holds, sorted; `None` before it is written.
    trees: Option<Vec<u32>>,
}

/// Expands every key: from its cache in `data_dir`, else from `remote`, else
/// by building its top tree. A cache loads in ~50 µs; a build takes ~0.3 s,
/// and ~0.3 s more for each bottom tree it then signs in.
pub fn load(
    keys: &[ValidatorKey],
    data_dir: &Path,
    remote: Option<&RemoteCache>,
) -> Result<Vec<(LoadedKey, CacheFile)>, Error> {
    let started = Instant::now();
    let caches = keys.iter().map(|key| Cache::of(key, data_dir)).collect::<Vec<_>>();
    let mut loaded = caches.iter().map(Cache::load_local).collect::<Vec<_>>();
    let local = loaded.iter().flatten().count();

    let mut remote_loaded = 0;
    if let Some(remote) = remote {
        let missing = (0..keys.len()).filter(|&i| loaded[i].is_none()).collect::<Vec<_>>();
        let parameters = missing.iter().map(|&i| caches[i].parameter).collect::<Vec<_>>();
        for run in remote.runs(&parameters) {
            let bytes = match remote.fetch(&run) {
                Ok(bytes) => bytes,
                Err(error) => {
                    silver_log::warn!(error, "remote expanded keys not fetched");
                    continue;
                }
            };
            for (at, pubkey, record) in run.records(&bytes) {
                let i = missing[at];
                loaded[i] = caches[i].load_remote(pubkey, record);
                remote_loaded += usize::from(loaded[i].is_some());
            }
        }
    }

    let mut built = 0;
    for (cache, key) in caches.iter().zip(&mut loaded).filter(|(_, key)| key.is_none()) {
        *key = Some(cache.build()?);
        built += 1;
    }
    silver_log::info!(local, remote = remote_loaded, built, elapsed = ?started.elapsed(), "keys expanded");
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
    fn load_local(&self) -> Option<(LoadedKey, CacheFile)> {
        let file = fs::read(&self.path).ok()?;
        let (pubkey, bytes) = file.split_first_chunk::<32>()?;
        let xmss = self.stated(pubkey).then(|| from_cache(&self.key.privkey, pubkey, bytes))??;
        let vrf_seed = self.key.vrf_seed.clone();
        let cache = CacheFile { path: self.path.clone(), trees: Some(cached_trees(bytes)) };
        Some((LoadedKey { pubkey: *pubkey, xmss, vrf_seed }, cache))
    }

    /// A refused record leaves the key to be built.
    fn load_remote(&self, pubkey: &XMSSPubkey, bytes: &[u8]) -> Option<(LoadedKey, CacheFile)> {
        let source = self.key.source.display();
        if !self.stated(pubkey) {
            silver_log::warn!(%source, "remote key differs from the stated one");
            return None;
        }
        let Some(xmss) = from_cache(&self.key.privkey, pubkey, bytes) else {
            silver_log::warn!(%source, "remote expanded key refused");
            return None;
        };
        Some(self.persisted(*pubkey, xmss))
    }

    fn build(&self) -> Result<(LoadedKey, CacheFile), Error> {
        let (xmss, pubkey) = lean_xmss::key_gen(&self.key.privkey);
        let pubkey = pubkey.to_bytes();
        if !self.stated(&pubkey) {
            let source = self.key.source.display();
            return Err(Error::ConfigError(format!(
                "key file {source}: privkey does not derive pubkey"
            )));
        }
        Ok(self.persisted(pubkey, xmss))
    }

    fn persisted(
        &self,
        pubkey: XMSSPubkey,
        xmss: LeanXmssExpandedSecretKey,
    ) -> (LoadedKey, CacheFile) {
        let key = LoadedKey { pubkey, xmss, vrf_seed: self.key.vrf_seed.clone() };
        let mut cache = CacheFile { path: self.path.clone(), trees: None };
        cache.persist(&key);
        (key, cache)
    }
}

impl Drop for LoadedKey {
    fn drop(&mut self) {
        self.vrf_seed.zeroize();
    }
}

impl CacheFile {
    /// Rewrites the file when `key` holds trees the file lacks, so a restart
    /// signs without building them again. The file is replaced whole: a
    /// crash leaves the old one or the new one.
    pub fn persist(&mut self, key: &LoadedKey) {
        let bytes = key.xmss.cache_to_bytes();
        let trees = cached_trees(&bytes);
        if self.trees.as_ref() == Some(&trees) {
            return;
        }
        let partial = self.path.with_extension("xmss.partial");
        let written = File::create(&partial)
            .and_then(|mut file| {
                file.write_all(&key.pubkey)?;
                file.write_all(&bytes)
            })
            .and_then(|()| fs::rename(&partial, &self.path));
        match written {
            Ok(()) => self.trees = Some(trees),
            Err(error) => {
                silver_log::warn!(%error, path = %self.path.display(), "expanded key not cached")
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
        .as_chunks::<CACHED_BOTTOM_SIZE>()
        .0
        .iter()
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

    fn load_alone(
        key: &ValidatorKey,
        dir: &Path,
        remote: Option<&RemoteCache>,
    ) -> (LoadedKey, CacheFile) {
        load(std::slice::from_ref(key), dir, remote).unwrap().pop().unwrap()
    }

    #[test]
    fn a_built_key_is_cached_and_reloads_from_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (built, cache) = load_alone(&key(1), dir.path(), None);
        let (local, _) = Cache::of(&key(1), dir.path()).load_local().expect("cached");
        assert_eq!(local.pubkey, built.pubkey);

        fs::write(&cache.path, [0; 40]).unwrap();
        assert!(Cache::of(&key(1), dir.path()).load_local().is_none(), "a refused cache");
        assert_eq!(load_alone(&key(1), dir.path(), None).0.pubkey, built.pubkey);
    }

    #[test]
    fn a_cache_is_rewritten_only_for_a_new_tree() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, mut cache) = load_alone(&key(1), dir.path(), None);
        loaded.xmss.prepare(1 << 15);
        cache.persist(&loaded);
        assert_eq!(cache.trees, Some(vec![0]));

        fs::remove_file(&cache.path).unwrap();
        loaded.xmss.prepare((1 << 15) + 1);
        cache.persist(&loaded);
        assert!(!cache.path.exists(), "the same tree is not written again");
        loaded.xmss.prepare(FIRST_SLOT_TREE);
        cache.persist(&loaded);
        let (reloaded, _) = Cache::of(&key(1), dir.path()).load_local().unwrap();
        assert_eq!(reloaded.pubkey, loaded.pubkey);
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
        let bytes = remote.fetch(&runs[0]).unwrap();
        let (_, pubkey, record) = runs[0].records(&bytes).next().unwrap();
        assert_eq!(*pubkey, pubkeys[1]);
        let (loaded, _) = fetched.load_remote(pubkey, record).expect("from the remote record");
        assert_eq!(loaded.pubkey, pubkeys[1]);
        assert!(fetched.load_local().is_some(), "the record was cached locally");

        assert_eq!(load_alone(&key(2), dir.path(), Some(&remote)).0.pubkey, pubkeys[0]);
        assert!(remote.runs(&[Cache::of(&key(4), dir.path()).parameter]).is_empty());
        let mut stated = key(2);
        stated.pubkey = Some([0xee; 32]);
        let fresh = tempfile::tempdir().unwrap();
        assert!(load(&[stated], fresh.path(), Some(&remote)).is_err());
    }

    #[test]
    fn a_local_cache_path_loads_records_like_a_url() {
        let (pubkeys, records): (Vec<_>, Vec<_>) = [2, 3].map(record).into_iter().unzip();
        let metadata: Vec<u8> =
            pubkeys.iter().flat_map(|pubkey| [&pubkey[..], &[0x77; 32]].concat()).collect();
        let files = tempfile::tempdir().unwrap();
        fs::write(files.path().join("keys.bin"), metadata).unwrap();
        fs::write(files.path().join("keys.xmss"), records.concat()).unwrap();
        let path = files.path().join("keys.xmss").display().to_string();

        for location in [path.clone(), format!("file://{path}")] {
            let remote = RemoteCache::with_registry(&location, pubkeys.iter().copied()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let runs = remote.runs(&[Cache::of(&key(3), dir.path()).parameter]);
            assert_eq!(remote.fetch(&runs[0]).unwrap(), records[1]);
            assert_eq!(load_alone(&key(3), dir.path(), Some(&remote)).0.pubkey, pubkeys[1]);
        }
        assert!(
            RemoteCache::with_registry("/nonexistent/keys.xmss", pubkeys.iter().copied()).is_err()
        );
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
