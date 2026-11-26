use serde::Deserialize;
use silver_chain_spec::SpecConfig;
use silver_common::json_fields::{bytes, uint64};

/// The genesis `--network` requires the beacon node to serve.
pub struct ExpectedGenesis {
    genesis_validators_root: [u8; 32],
    genesis_fork_version: [u8; 4],
}

impl ExpectedGenesis {
    pub fn new(spec: &SpecConfig, genesis_validators_root: &[u8; 32]) -> Self {
        Self {
            genesis_validators_root: *genesis_validators_root,
            genesis_fork_version: spec.genesis_fork_version,
        }
    }

    /// The genesis time from a `GET /eth/v1/beacon/genesis` answer.
    pub fn check(&self, body: &[u8]) -> Result<u64, String> {
        let Data { data: genesis } = serde_json::from_slice::<Data<Genesis>>(body)
            .map_err(|e| format!("unreadable genesis: {e}"))?;
        if genesis.genesis_fork_version != self.genesis_fork_version {
            return Err(format!(
                "genesis fork version 0x{}, expected 0x{}",
                hex::encode(genesis.genesis_fork_version),
                hex::encode(self.genesis_fork_version)
            ));
        }
        if genesis.genesis_validators_root != self.genesis_validators_root {
            return Err(format!(
                "genesis validators root 0x{}, expected 0x{}",
                hex::encode(genesis.genesis_validators_root),
                hex::encode(self.genesis_validators_root)
            ));
        }
        Ok(genesis.genesis_time)
    }
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
struct Genesis {
    #[serde(deserialize_with = "uint64")]
    genesis_time: u64,
    #[serde(deserialize_with = "bytes")]
    genesis_validators_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    genesis_fork_version: [u8; 4],
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const GENESIS: &str = r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95","genesis_fork_version":"0x00000000"}}"#;
    pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [
        0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd,
        0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b,
        0xfe, 0x95,
    ];

    fn mainnet() -> ExpectedGenesis {
        ExpectedGenesis::new(&SpecConfig::mainnet(), &GENESIS_VALIDATORS_ROOT)
    }

    #[test]
    fn mainnet_genesis_passes() {
        assert_eq!(mainnet().check(GENESIS.as_bytes()), Ok(1606824023));
    }

    #[test]
    fn other_network_genesis_is_rejected() {
        let hoodi = GENESIS.replace("0x00000000", "0x10000910");
        assert!(mainnet().check(hoodi.as_bytes()).unwrap_err().contains("genesis fork"));
        let other_root = GENESIS.replace("0x4b363db9", "0x00000000");
        assert!(mainnet().check(other_root.as_bytes()).unwrap_err().contains("root"));
    }
}
