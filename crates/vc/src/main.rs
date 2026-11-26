use std::{error::Error, thread};

use clap::Parser;
use flux::{
    tile::{Tile, TileConfig, tile_runner},
    utils::ThreadNiceness,
};
use silver_common::{VcSpine, tracing::initialise_tracing_log_on_core};

use crate::{args::Args, tile::ValidatorTile};

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

const VALIDATOR_CORE: usize = 1;

fn main() -> Result<(), Box<dyn Error>> {
    let config = Args::parse().config()?;
    let _tracing = initialise_tracing_log_on_core("silver-vc", 10, None, false, None, None);
    silver_log::info!(
        network = %config.spec.network_name(),
        beacon_node = %config.beacon_node,
        keys_dir = %config.keys_dir.display(),
        signer_threads = config.signer_threads,
        proposals = ?config.proposals,
        "loaded config"
    );

    let tile = ValidatorTile::new(&config)?;
    let name = tile.name();
    let config = TileConfig::new(VALIDATOR_CORE, Some(ThreadNiceness::Highest));
    VcSpine::new(None).start(None, None, |scoped_spine| {
        thread::Builder::new()
            .name(name.as_str().to_owned())
            .spawn_scoped(scoped_spine.scope, tile_runner(tile, scoped_spine, config))
            .expect("spawn tile thread");
    });

    Ok(())
}
