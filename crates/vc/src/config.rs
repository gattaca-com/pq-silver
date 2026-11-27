use std::path::PathBuf;

use silver_chain_spec::SpecConfig;

#[derive(Debug)]
pub struct Config {
    pub spec: SpecConfig,
    pub genesis_validators_root: [u8; 32],
    pub beacon_node: String,
    pub signer: SignerConfig,
    pub signer_tiles: usize,
    pub proposals: Option<ProposalConfig>,
}

/// Where the signer tile reads its keys and keeps their records.
#[derive(Clone, Debug, Default)]
pub struct SignerConfig {
    pub keys_dir: Option<PathBuf>,
    pub keystores_dir: Option<PathBuf>,
    pub secrets_dir: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub init_leaf_records: bool,
    /// A devnet's `genesis.ssz`, whose registry authenticates remote keys.
    pub genesis_state: Option<PathBuf>,
    pub xmss_cache_url: Option<String>,
    pub vrf_state_url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalConfig {
    pub fee_recipient: [u8; 20],
    pub graffiti: [u8; 32],
    pub gas_limit: u64,
}
