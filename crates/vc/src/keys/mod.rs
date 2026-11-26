mod json;
mod keystore;

use std::path::PathBuf;

use silver_common::{Error, ssz_view::XMSSPubkey};
use zeroize::Zeroize;

use crate::config::Config;

/// One validator's secrets, named as `specs/_features/pq/validator.md` names
/// them: the XMSS `privkey` seed and the `vrf_seed`.
pub struct ValidatorKey {
    pub privkey: [u8; 32],
    pub vrf_seed: [u8; 32],
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

/// Every key of the configured sources: JSON key files, EIP-2335 keystores,
/// or both.
pub fn load_keys(config: &Config) -> Result<Vec<ValidatorKey>, Error> {
    let mut keys = Vec::new();
    if let Some(dir) = &config.keys_dir {
        keys.extend(json::load(dir)?);
    }
    if let Some(dir) = &config.keystores_dir {
        let secrets = config.secrets_dir.as_deref().expect("clap requires it with keystores");
        keys.extend(keystore::load(dir, secrets)?);
    }
    Ok(keys)
}
