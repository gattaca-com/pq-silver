use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use silver_common::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::keys::ValidatorKey;

/// The genesis tool's domains (`eth-beacon-genesis`, `validators/`): each
/// seed hashes its domain with the validator's BLS secret key.
const XMSS_SEED_DOMAIN: &[u8] = b"leanxmss-seed";
const VRF_SEED_DOMAIN: &[u8] = b"vrf-seed";
const LIGHTHOUSE_KEYSTORE: &str = "voting-keystore.json";

/// Every EIP-2335 keystore of `entries`, either `*.json` or the Lighthouse
/// layout `<0xpubkey>/voting-keystore.json`, each opened with the password in
/// `secrets/<0xpubkey>`. Both seeds derive from the BLS secret key, as the
/// devnet genesis derives them.
pub fn load(
    entries: impl Iterator<Item = PathBuf>,
    secrets: &Path,
) -> Result<Vec<ValidatorKey>, Error> {
    let mut keys = Vec::new();
    let mut readable_passwords = 0;
    for path in entries {
        let keystore = match path.is_dir() {
            true => path.join(LIGHTHOUSE_KEYSTORE),
            false if path.extension().is_some_and(|extension| extension == "json") => path,
            false => continue,
        };
        if !keystore.is_file() {
            continue;
        }
        let (bls_secret, readable) = open(&keystore, secrets)
            .map_err(|why| Error::ConfigError(format!("keystore {}: {why}", keystore.display())))?;
        readable_passwords += usize::from(readable);
        keys.push(derive(&bls_secret, keystore));
    }
    if readable_passwords > 0 {
        silver_log::warn!(
            readable_passwords,
            dir = %secrets.display(),
            "keystore passwords others can read"
        );
    }
    Ok(keys)
}

/// The seeds are hashed straight into the key, so no copy of them is left.
fn derive(bls_secret: &[u8; 32], source: PathBuf) -> ValidatorKey {
    let mut key = ValidatorKey {
        privkey: Box::new([0; 32]),
        vrf_seed: Box::new([0; 32]),
        pubkey: None,
        source,
    };
    for (domain, seed) in
        [(XMSS_SEED_DOMAIN, &mut *key.privkey), (VRF_SEED_DOMAIN, &mut *key.vrf_seed)]
    {
        Sha256::new().chain_update(domain).chain_update(bls_secret).finalize_into(seed.into());
    }
    key
}

#[derive(Deserialize)]
struct Keystore {
    crypto: Crypto,
    pubkey: String,
    version: u32,
}

#[derive(Deserialize)]
struct Crypto {
    kdf: Module<KdfParams>,
    checksum: Module<serde::de::IgnoredAny>,
    cipher: Module<CipherParams>,
}

#[derive(Deserialize)]
struct Module<P> {
    function: String,
    params: P,
    message: String,
}

#[derive(Deserialize)]
struct KdfParams {
    dklen: usize,
    #[serde(default)]
    c: u32,
    #[serde(default)]
    prf: String,
    salt: String,
}

#[derive(Deserialize)]
struct CipherParams {
    iv: String,
}

/// The BLS secret key, and whether others can read its password file.
fn open(keystore: &Path, secrets: &Path) -> Result<(Zeroizing<[u8; 32]>, bool), String> {
    let text = fs::read(keystore).map_err(|e| e.to_string())?;
    let keystore: Keystore = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
    if keystore.version != 4 {
        return Err(format!("version {}, expected 4", keystore.version));
    }
    let pubkey = keystore.pubkey.trim_start_matches("0x");
    let candidates = [secrets.join(format!("0x{pubkey}")), secrets.join(pubkey)];
    let path = candidates
        .iter()
        .find(|path| path.is_file())
        .ok_or_else(|| format!("no password for 0x{pubkey} in {}", secrets.display()))?;
    let password = Zeroizing::new(fs::read_to_string(path).map_err(|e| e.to_string())?);
    let readable = fs::metadata(path).map_err(|e| e.to_string())?.permissions().mode() & 0o077 != 0;
    Ok((decrypt(&keystore.crypto, &normalised(&password))?, readable))
}

/// EIP-2335's password processing: NFKD, then without the C0, C1 and Delete
/// control codes.
fn normalised(password: &str) -> Zeroizing<Vec<u8>> {
    let control = |c: &char| matches!(*c as u32, 0x00..=0x1f | 0x7f..=0x9f);
    let mut bytes = Zeroizing::new(Vec::with_capacity(password.len()));
    let mut utf8 = [0; 4];
    for c in password.nfkd().filter(|c| !control(c)) {
        bytes.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
    }
    bytes
}

fn decrypt(crypto: &Crypto, password: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let Crypto { kdf, checksum, cipher } = crypto;
    if kdf.function != "pbkdf2" || kdf.params.prf != "hmac-sha256" || kdf.params.dklen != 32 {
        return Err(format!("kdf {} is not pbkdf2 with hmac-sha256 to 32 bytes", kdf.function));
    }
    if kdf.params.c == 0 {
        return Err("pbkdf2 with no rounds".into());
    }
    if checksum.function != "sha256" || cipher.function != "aes-128-ctr" {
        return Err(format!(
            "{} and {} are not sha256 and aes-128-ctr",
            checksum.function, cipher.function
        ));
    }
    let hex = |field: &str, text: &str| {
        hex::decode(text.trim_start_matches("0x")).map_err(|_| format!("{field} is not hex"))
    };
    let salt = hex("salt", &kdf.params.salt)?;
    let iv: [u8; 16] =
        hex("iv", &cipher.params.iv)?.try_into().map_err(|_| "iv is not 16 bytes")?;
    let expected = hex("checksum", &checksum.message)?;
    let mut secret = Zeroizing::new(
        <[u8; 32]>::try_from(hex("cipher message", &cipher.message)?)
            .map_err(|_| "secret is not 32 bytes")?,
    );

    let key = pbkdf2_sha256(password, &salt, kdf.params.c);
    let sum = Sha256::new().chain_update(&key[16..]).chain_update(*secret).finalize();
    if sum[..] != expected[..] {
        return Err("wrong password: checksum mismatch".into());
    }
    let key: &[u8; 16] = key[..16].try_into().expect("16 bytes");
    ctr::Ctr128BE::<Aes128>::new(key.into(), &iv.into()).apply_keystream(&mut *secret);
    Ok(secret)
}

/// PBKDF2 for a 32-byte key: exactly one HMAC-SHA256 block.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 32]> {
    let prf = Hmac::<Sha256>::new_from_slice(password).expect("HMAC takes any key length");
    let mut u: [u8; 32] = prf
        .clone()
        .chain_update(salt)
        .chain_update(1u32.to_be_bytes())
        .finalize()
        .into_bytes()
        .into();
    let mut key = Zeroizing::new(u);
    for _ in 1..rounds {
        u = prf.clone().chain_update(u).finalize().into_bytes().into();
        key.iter_mut().zip(u).for_each(|(k, u)| *k ^= u);
    }
    u.fill(0);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Shard;

    /// The EIP-2335 PBKDF2 test vector. Its password, `𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑`, is
    /// `testpassword🔑` once NFKD-normalised.
    const VECTOR: &str = r#"{
        "crypto": {
            "kdf": {"function": "pbkdf2", "params": {"dklen": 32, "c": 262144, "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}, "message": ""},
            "checksum": {"function": "sha256", "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},
            "cipher": {"function": "aes-128-ctr", "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}
        },
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "version": 4
    }"#;
    const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    #[test]
    fn decrypts_the_eip_2335_pbkdf2_vector() {
        let keystore: Keystore = serde_json::from_str(VECTOR).unwrap();
        let secret = decrypt(&keystore.crypto, "testpassword🔑".as_bytes()).unwrap();
        assert_eq!(hex::encode(*secret), SECRET);
        let as_written = normalised("𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑");
        assert_eq!(hex::encode(*decrypt(&keystore.crypto, &as_written).unwrap()), SECRET);
        assert!(decrypt(&keystore.crypto, b"wrong").unwrap_err().contains("checksum"));

        let no_rounds: Keystore =
            serde_json::from_str(&VECTOR.replace(r#""c": 262144, "#, "")).unwrap();
        assert!(
            decrypt(&no_rounds.crypto, "testpassword🔑".as_bytes()).unwrap_err().contains("rounds")
        );
    }

    #[test]
    fn normalises_the_password_as_eip_2335_asks() {
        assert_eq!(*normalised("pass\x7fword\u{85}\n"), b"password");
        let composed = "caf\u{e9}";
        assert_eq!(*normalised(composed), "cafe\u{301}".as_bytes(), "NFKD decomposes");
        assert_eq!(*normalised("\u{fb01}"), b"fi", "and folds compatibility forms");
    }

    #[test]
    fn loads_the_lighthouse_layout_and_derives_both_seeds() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, secrets) = (dir.path().join("keys"), dir.path().join("secrets"));
        let pubkey = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        fs::create_dir_all(keys.join(pubkey)).unwrap();
        fs::create_dir_all(&secrets).unwrap();
        fs::write(keys.join(pubkey).join(LIGHTHOUSE_KEYSTORE), VECTOR).unwrap();
        fs::write(secrets.join(pubkey), "testpassword🔑\n").unwrap();

        let loaded = load(Shard::WHOLE.entries(&keys).unwrap(), &secrets).unwrap();
        assert_eq!(loaded.len(), 1);
        let bls_secret: [u8; 32] = hex::decode(SECRET).unwrap().try_into().unwrap();
        let expect =
            |domain: &[u8]| -> [u8; 32] { Sha256::digest([domain, &bls_secret].concat()).into() };
        assert_eq!(*loaded[0].privkey, expect(b"leanxmss-seed"));
        assert_eq!(*loaded[0].vrf_seed, expect(b"vrf-seed"));
        assert_eq!(loaded[0].pubkey, None);

        fs::write(secrets.join(pubkey), "wrong").unwrap();
        assert!(matches!(
            load(Shard::WHOLE.entries(&keys).unwrap(), &secrets),
            Err(Error::ConfigError(_))
        ));
    }
}
