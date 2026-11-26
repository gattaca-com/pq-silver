use std::{num::NonZeroUsize, path::PathBuf, thread};

use clap::{ArgGroup, Parser};
use silver_common::Error;
use silver_config::{BootSource, Network};

use crate::config::{Config, ProposalConfig};

/// Silver validator client.
#[derive(Debug, Parser)]
#[command(version, group(ArgGroup::new("keys").required(true).multiple(true)))]
pub struct Args {
    /// `mainnet`, `hoodi`, `sepolia`, or a devnet's metadata directory
    /// holding its `config.yaml`.
    #[arg(long, default_value = "mainnet")]
    network: Network,
    #[arg(long)]
    beacon_node: String,
    /// One JSON file per validator: `pubkey`, `privkey` and `vrf_seed`, each
    /// 0x-prefixed hex of 32 bytes. Files must be readable by their owner only.
    #[arg(long, group = "keys")]
    keys_dir: Option<PathBuf>,
    /// EIP-2335 BLS keystores, `*.json` or `<0xpubkey>/voting-keystore.json`.
    /// Each validator's XMSS and VRF seeds derive from its BLS secret key, as
    /// the devnet genesis derives them.
    #[arg(long, group = "keys", requires = "secrets_dir")]
    keystores_dir: Option<PathBuf>,
    /// The keystores' passwords, one file per `0x`-prefixed BLS pubkey.
    #[arg(long, requires = "keystores_dir")]
    secrets_dir: Option<PathBuf>,
    /// Holds each key's leaf record and expanded-key cache.
    #[arg(long)]
    data_dir: PathBuf,
    /// Creates the leaf record of a key that has none. Only for keys that
    /// never signed with another record: a lost record lets a leaf sign twice.
    #[arg(long)]
    init_leaf_records: bool,
    /// The devnet's precomputed expanded keys, one record per genesis
    /// validator. A key whose record is missing or refused is built instead.
    #[arg(long)]
    xmss_cache_url: Option<String>,
    /// Threads leanVM signs on; every core when absent.
    #[arg(long)]
    signer_threads: Option<NonZeroUsize>,
    /// Proposes only when set.
    #[arg(long, value_parser = parse_fee_recipient)]
    suggested_fee_recipient: Option<[u8; 20]>,
    /// At most 32 bytes of UTF-8, carried in every proposed block.
    #[arg(long, value_parser = parse_graffiti)]
    graffiti: Option<[u8; 32]>,
    /// Proposer preferences' target.
    #[arg(long, default_value_t = DEFAULT_GAS_LIMIT)]
    gas_limit: u64,
}

const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

impl Args {
    pub fn config(self) -> Result<Config, Error> {
        let proposals = self.suggested_fee_recipient.map(|fee_recipient| ProposalConfig {
            fee_recipient,
            graffiti: self.graffiti.unwrap_or_default(),
            gas_limit: self.gas_limit,
        });
        Ok(Config {
            spec: self.network.spec()?,
            genesis_validators_root: self.network.genesis_validators_root()?,
            beacon_node: self.beacon_node,
            keys_dir: self.keys_dir,
            keystores_dir: self.keystores_dir,
            secrets_dir: self.secrets_dir,
            data_dir: self.data_dir,
            init_leaf_records: self.init_leaf_records,
            genesis_state: match self.network.boot_source()? {
                BootSource::Genesis(path) => Some(path),
                _ => None,
            },
            xmss_cache_url: self.xmss_cache_url,
            signer_threads: self
                .signer_threads
                .or_else(|| thread::available_parallelism().ok())
                .map_or(1, NonZeroUsize::get),
            proposals,
        })
    }
}

fn parse_fee_recipient(text: &str) -> Result<[u8; 20], String> {
    let mut address = [0; 20];
    let hex = text.strip_prefix("0x").ok_or("not 0x-prefixed")?;
    hex::decode_to_slice(hex, &mut address).map_err(|_| "not a 20-byte hex address")?;
    Ok(address)
}

fn parse_graffiti(text: &str) -> Result<[u8; 32], String> {
    let mut graffiti = [0; 32];
    graffiti.get_mut(..text.len()).ok_or("longer than 32 bytes")?.copy_from_slice(text.as_bytes());
    Ok(graffiti)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: [&str; 4] =
        ["silver-vc", "--beacon-node=http://bn:5052", "--keys-dir=/keys", "--data-dir=/data"];

    fn config(extra: &[&str]) -> Config {
        Args::try_parse_from([&REQUIRED[..], extra].concat()).unwrap().config().unwrap()
    }

    #[test]
    fn proposes_only_with_a_fee_recipient() {
        let config = config(&[]);
        assert_eq!(config.spec.network_name(), "mainnet");
        assert_eq!(config.proposals, None);

        let proposals =
            self::config(&["--suggested-fee-recipient=0x1111111111111111111111111111111111111111"])
                .proposals;
        assert_eq!(
            proposals,
            Some(ProposalConfig {
                fee_recipient: [0x11; 20],
                graffiti: [0; 32],
                gas_limit: DEFAULT_GAS_LIMIT,
            })
        );
    }

    #[test]
    fn graffiti_pads_and_rejects_overflow() {
        let args = [
            "--suggested-fee-recipient=0x1111111111111111111111111111111111111111",
            "--graffiti=silver",
        ];
        assert_eq!(&config(&args).proposals.unwrap().graffiti[..7], b"silver\0");
        let long = format!("--graffiti={}", "x".repeat(33));
        assert!(Args::try_parse_from([&REQUIRED[..], &[&long]].concat()).is_err());
    }

    #[test]
    fn signer_threads_default_to_every_core() {
        assert!(config(&[]).signer_threads >= 1);
        assert_eq!(config(&["--signer-threads=3"]).signer_threads, 3);
        assert!(Args::try_parse_from([&REQUIRED[..], &["--signer-threads=0"]].concat()).is_err());
    }

    #[test]
    fn node_keys_and_data_dir_are_required() {
        assert!(Args::try_parse_from(&REQUIRED[..3]).is_err());
        assert!(Args::try_parse_from([REQUIRED[0], REQUIRED[2], REQUIRED[3]]).is_err());
        assert!(Args::try_parse_from([REQUIRED[0], REQUIRED[1], REQUIRED[3]]).is_err());
    }

    #[test]
    fn keystores_need_their_secrets() {
        let keystores = [REQUIRED[0], REQUIRED[1], REQUIRED[3], "--keystores-dir=/k"];
        assert!(Args::try_parse_from(keystores).is_err());
        let config = Args::try_parse_from([&keystores[..], &["--secrets-dir=/s"]].concat())
            .unwrap()
            .config()
            .unwrap();
        assert_eq!(config.keys_dir, None);
        assert_eq!(config.secrets_dir.as_deref(), Some(std::path::Path::new("/s")));
    }
}
