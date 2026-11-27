mod json;
mod keystore;

use std::{
    fs,
    path::{Path, PathBuf},
};

use silver_common::{Error, ssz_view::XMSSPubkey};
use zeroize::Zeroize;

use crate::config::SignerConfig;

/// One validator's secrets, named as `specs/_features/pq/validator.md` names
/// them: the XMSS `privkey` seed and the `vrf_seed`.
/// The seeds are boxed so moving a key leaves no copy of them behind.
pub struct ValidatorKey {
    pub privkey: Box<[u8; 32]>,
    pub vrf_seed: Box<[u8; 32]>,
    /// Stated by a JSON key file. A keystore's is derived as its key loads.
    pub pubkey: Option<XMSSPubkey>,
    /// Where it was read from.
    pub source: PathBuf,
}

impl Drop for ValidatorKey {
    fn drop(&mut self) {
        self.privkey.zeroize();
        self.vrf_seed.zeroize();
    }
}

/// One of `count` signer tiles. Each takes every `count`-th file of a key
/// directory, in name order, so no key is read or decrypted twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    pub index: usize,
    pub count: usize,
}

impl Shard {
    #[cfg(test)]
    pub const WHOLE: Self = Self { index: 0, count: 1 };

    /// The entries of `dir` this shard reads, in name order.
    fn entries(self, dir: &Path) -> Result<impl Iterator<Item = PathBuf>, Error> {
        let mut paths = fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort_unstable();
        Ok(paths.into_iter().skip(self.index).step_by(self.count))
    }
}

/// This shard's keys of the configured sources: JSON key files, EIP-2335
/// keystores, or both.
pub fn load_keys(config: &SignerConfig, shard: Shard) -> Result<Vec<ValidatorKey>, Error> {
    let mut keys = Vec::new();
    if let Some(dir) = &config.keys_dir {
        keys.extend(json::load(shard.entries(dir)?)?);
    }
    if let Some(dir) = &config.keystores_dir {
        let secrets = config.secrets_dir.as_deref().expect("clap requires it with keystores");
        keys.extend(keystore::load(shard.entries(dir)?, secrets)?);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shards_split_a_directory_without_overlap() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["e", "a", "c", "b", "d"] {
            fs::write(dir.path().join(name), "").unwrap();
        }
        let shard = |index| {
            let entries = Shard { index, count: 2 }.entries(dir.path()).unwrap();
            entries.map(|path| path.file_name().unwrap().to_owned()).collect::<Vec<_>>()
        };
        assert_eq!(shard(0), ["a", "c", "e"]);
        assert_eq!(shard(1), ["b", "d"]);
        assert_eq!(Shard::WHOLE.entries(dir.path()).unwrap().count(), 5);
    }
}
