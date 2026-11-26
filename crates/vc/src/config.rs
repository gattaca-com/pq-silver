use std::path::PathBuf;

use silver_chain_spec::SpecConfig;

#[derive(Debug)]
pub struct Config {
    pub spec: SpecConfig,
    pub genesis_validators_root: [u8; 32],
    pub beacon_node: String,
    pub keys_dir: PathBuf,
    pub signer_threads: usize,
    pub proposals: Option<ProposalConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalConfig {
    pub fee_recipient: [u8; 20],
    pub graffiti: [u8; 32],
    pub gas_limit: u64,
}
