use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use serde::Deserialize;
use silver_common::{Error, json_fields::bytes, ssz_view::XMSSPubkey};

use crate::keys::ValidatorKey;

#[derive(Deserialize)]
struct KeyFile {
    #[serde(deserialize_with = "bytes")]
    pubkey: XMSSPubkey,
    #[serde(deserialize_with = "bytes")]
    privkey: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    vrf_seed: [u8; 32],
}

/// Every `*.json` file in `dir`: `{"pubkey", "privkey", "vrf_seed"}`. A file
/// others can read is refused: it holds the seeds in the clear.
pub fn load(dir: &Path) -> Result<Vec<ValidatorKey>, Error> {
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
        let KeyFile { pubkey, privkey, vrf_seed } =
            serde_json::from_slice(&text).map_err(|e| unreadable(&path, e.to_string()))?;
        keys.push(ValidatorKey { privkey, vrf_seed, pubkey: Some(pubkey), source: path });
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
    fn loads_every_json_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.json", &key_json(0xbb), 0o600);
        write(dir.path(), "a.json", &key_json(0xaa), 0o400);
        write(dir.path(), "notes.txt", "ignored", 0o644);
        let mut pubkeys =
            load(dir.path()).unwrap().iter().map(|key| key.pubkey).collect::<Vec<_>>();
        pubkeys.sort_unstable();
        assert_eq!(pubkeys, [Some([0xaa; 32]), Some([0xbb; 32])]);
    }

    #[test]
    fn refuses_readable_or_malformed_keys() {
        let readable = tempfile::tempdir().unwrap();
        write(readable.path(), "a.json", &key_json(0xaa), 0o644);
        assert!(matches!(load(readable.path()), Err(Error::ConfigError(_))));

        let malformed = tempfile::tempdir().unwrap();
        write(malformed.path(), "a.json", r#"{"pubkey":"0xaa"}"#, 0o600);
        assert!(matches!(load(malformed.path()), Err(Error::ConfigError(_))));
    }
}
