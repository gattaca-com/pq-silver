use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use serde::Deserialize;
use silver_common::{Error, json_fields::bytes, ssz_view::XMSSPubkey};

/// One validator's key material, named as `specs/_features/pq/validator.md`
/// names it: the XMSS `privkey` seed and the `vrf_seed`.
#[derive(Deserialize)]
pub struct ValidatorKey {
    #[serde(deserialize_with = "bytes")]
    pub pubkey: XMSSPubkey,
    #[serde(deserialize_with = "bytes")]
    #[expect(dead_code, reason = "read by the leanVM signer")]
    privkey: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    #[expect(dead_code, reason = "read by the VRF prover")]
    vrf_seed: [u8; 32],
}

/// Every `*.json` file in `dir`, sorted by pubkey. A file others can read is
/// refused: it holds the seeds in the clear.
pub fn load_keys(dir: &Path) -> Result<Vec<ValidatorKey>, Error> {
    let unreadable = |path: &Path, why: String| {
        Error::ConfigError(format!("key file {}: {why}", path.display()))
    };
    let mut keys = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let mode = fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(unreadable(&path, format!("mode {:o} lets others read it", mode & 0o777)));
        }
        let text = fs::read(&path)?;
        let key = serde_json::from_slice::<ValidatorKey>(&text)
            .map_err(|e| unreadable(&path, e.to_string()))?;
        keys.push(key);
    }
    keys.sort_unstable_by_key(|key| key.pubkey);
    if let Some(twice) = keys.windows(2).find(|pair| pair[0].pubkey == pair[1].pubkey) {
        let pubkey = hex::encode(twice[0].pubkey);
        return Err(Error::ConfigError(format!("key 0x{pubkey} listed twice")));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;

    use super::*;

    fn key_json(byte: u8) -> String {
        format!(
            r#"{{"pubkey":"0x{}","privkey":"0x{}","vrf_seed":"0x{}"}}"#,
            hex::encode([byte; 32]),
            hex::encode([0x11; 32]),
            hex::encode([0x22; 32])
        )
    }

    fn write(dir: &Path, name: &str, text: &str, mode: u32) {
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn loads_json_files_sorted_by_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.json", &key_json(0xbb), 0o600);
        write(dir.path(), "a.json", &key_json(0xaa), 0o400);
        write(dir.path(), "notes.txt", "ignored", 0o644);
        let pubkeys =
            load_keys(dir.path()).unwrap().iter().map(|key| key.pubkey).collect::<Vec<_>>();
        assert_eq!(pubkeys, [[0xaa; 32], [0xbb; 32]]);
    }

    #[test]
    fn refuses_readable_malformed_or_duplicate_keys() {
        let readable = tempfile::tempdir().unwrap();
        write(readable.path(), "a.json", &key_json(0xaa), 0o644);
        assert!(matches!(load_keys(readable.path()), Err(Error::ConfigError(_))));

        let malformed = tempfile::tempdir().unwrap();
        write(malformed.path(), "a.json", r#"{"pubkey":"0xaa"}"#, 0o600);
        assert!(matches!(load_keys(malformed.path()), Err(Error::ConfigError(_))));

        let twice = tempfile::tempdir().unwrap();
        write(twice.path(), "a.json", &key_json(0xaa), 0o600);
        write(twice.path(), "b.json", &key_json(0xaa), 0o600);
        assert!(matches!(load_keys(twice.path()), Err(Error::ConfigError(_))));
    }
}
