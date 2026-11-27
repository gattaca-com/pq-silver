use std::error::Error;

use clap::Parser;
use flux::tile::{TileConfig, attach_tile};
use silver_common::{VcSpine, tracing::initialise_tracing_log_on_core};

use crate::{args::Args, keys::Shard, signer::SignerTile, tile::ValidatorTile};

mod args;
mod beacon_link;
mod block_contents;
mod clock;
mod config;
mod duties;
mod keys;
mod signer;
mod signing;
mod tile;

fn main() -> Result<(), Box<dyn Error>> {
    let config = Args::parse().config()?;
    let _tracing = initialise_tracing_log_on_core("silver-vc", 10, None, false, None, None);
    silver_log::info!(
        network = %config.spec.network_name(),
        beacon_node = %config.beacon_node,
        data_dir = %config.signer.data_dir.display(),
        proposals = ?config.proposals,
        "loaded config"
    );

    let validator = ValidatorTile::new(&config)?;
    let count = config.signer_tiles;
    let signers = (0..count)
        .map(|index| SignerTile::new(config.signer.clone(), Shard { index, count }))
        .collect::<Vec<_>>();
    VcSpine::new(None).start(None, None, |scoped_spine| {
        attach_tile(validator, scoped_spine, unpinned());
        for signer in signers {
            attach_tile(signer, scoped_spine, unpinned());
        }
    });

    Ok(())
}

/// The VC shares its host with a beacon node and leanVM, so the scheduler
/// places its tiles. An idle tile parks rather than spins.
fn unpinned() -> TileConfig {
    TileConfig::background_on_cores(Vec::new(), None).with_park()
}
