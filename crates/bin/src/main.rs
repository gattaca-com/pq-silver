use std::{
    error::Error,
    io,
    net::IpAddr,
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use flux::{
    spine::ScopedSpine,
    tile::{Tile, TileConfig, TileName, tile_runner},
    utils::{ThreadNiceness, directories::shmem_dir_queues},
};
use mimalloc::MiMalloc;
use quinn_proto::{Endpoint, EndpointConfig};
use silver_application_boundary::ApplicationBoundaryTile;
use silver_beacon_state::{BeaconStateTile, SlotTicker};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_columns::tile::DataColumnsTile;
#[cfg(feature = "alloc-profile")]
use silver_common::metrics::CountingAllocator;
use silver_common::{
    APP_NAME, GossipTopic, Keypair, MAX_BLOBS_PER_BLOCK, MAX_CLUSTER_MESSAGE_BYTES, ProtoIdentify,
    SilverSpine, TCache, TCacheId, TCacheProducer, TCacheReader, TCacheTable,
    cell_store::{CellStoreConfig, GOSSIP_DELIVERY_RETENTION},
    column_util::data_column_sidecar_len,
    leanvm::MAX_RESPONSE_LEN,
    profiler::enable_profiler,
    set_attestation_subnets_pq,
    ssz_view::NUMBER_OF_COLUMNS,
    tracing::initialise_tracing_log_on_core,
};
use silver_config::Genesis;
use silver_control::{Controller, sync_engine::SyncEngine};
use silver_discovery::{DiscV5, Discovery};
use silver_gossip::GossipHandler;
use silver_httpcore::Bind;
use silver_leanvm::LeanVmTile;
use silver_network::{ClusterNodes, Context, InboundLimits, NetworkTile, P2p};
use silver_peer::PeerManager;
use silver_storage::tile::StorageTile;

use crate::{args::Args, checkpoint::BootCheckpoint, cluster::ClusterStartup};

mod args;
mod checkpoint;
mod cluster;
mod cluster_admin;

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(feature = "alloc-profile")]
#[global_allocator]
static GLOBAL: CountingAllocator<MiMalloc> = CountingAllocator(MiMalloc);

/// Normal Raft protocol messages only.
const CLUSTER_MESSAGE_TCACHE_SIZE: usize = 1 << 22;

/// By-root request payloads: one root list per request.
const CONTROL_RPC_TCACHE_SIZE: usize = 1 << 20;

/// Attester shufflings, one `u32` per active validator: three epochs of a
/// two-million-validator set, so the two the validator API serves never wait
/// on the one being written.
const BEACON_STATE_TCACHE_SIZE: usize = 1 << 25;
const LEANVM_TCACHE_SIZE: usize = 1 << 24;
const _: () = assert!(MAX_RESPONSE_LEN < LEANVM_TCACHE_SIZE);
/// Every column of a full block is about 6 MiB.
const PROPOSED_COLUMNS_TCACHE_SIZE: usize = 1 << 24;
const _: () = assert!(
    PROPOSED_COLUMNS_TCACHE_SIZE >=
        2 * NUMBER_OF_COLUMNS * data_column_sidecar_len(MAX_BLOBS_PER_BLOCK),
    "two held proposals must fit without wrapping"
);

/// The commit stays first: telemetry reads the first field as the commit.
const BUILD_INFO: &str = concat!(
    env!("SILVER_BUILD_COMMIT"),
    build_info::format!(" · v{} · {}", $.crate_info.version, $.timestamp)
);

fn publish_build_info() -> io::Result<()> {
    let dir = shmem_dir_queues(APP_NAME);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("build-info"), BUILD_INFO)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = Args::parse();
    if let Some(command) = args.command.take() {
        if let Err(error) = command.run() {
            eprintln!("silver: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Before tracing, which pins the logger to a configured core.
    let config = args.config()?;
    let cores = config.tile_cores;
    silver_log::set_log_core(cores.log);

    let build_info_log = format!("silver build info: {BUILD_INFO}");
    let _tracing = initialise_tracing_log_on_core(
        "silver",
        10,
        None,
        false,
        Some(cores.log),
        Some(&build_info_log),
    );
    if let Err(e) = silver_log::counts::enable(APP_NAME) {
        silver_log::error!(%e, "log counts disabled");
    }
    silver_log::debug!("start");

    // `#[timed]` is inert until a process opts in.
    enable_profiler(APP_NAME);

    silver_log::info!("loaded config: {config:#?}");
    #[cfg(not(feature = "metrics"))]
    if config.metrics.enabled {
        return Err("metrics.enabled requires building silver with --features metrics".into());
    }
    let chain_config = config.chain()?;
    chain_config.require_pq_from_genesis()?;
    chain_config.require_committee_count_in_range()?;
    chain_config.require_subnet_count_in_range()?;
    set_attestation_subnets_pq(chain_config.spec.attestation_subnet_count_pq as usize);
    chain_config.claim_data_dir_preset()?;
    if config.pbs().is_some() {
        return Err("PQ has no PBS: remove the [pbs] table and --pbs-endpoint".into());
    }

    let boot_checkpoint = BootCheckpoint::load(&chain_config)
        .inspect_err(|e| silver_log::error!(%e, "no boot checkpoint"))?;
    let booting_from_local_checkpoint = !boot_checkpoint.is_empty();
    silver_log::info!("boot state loaded: {booting_from_local_checkpoint}");

    let genesis = Genesis::from_state(boot_checkpoint.ssz())?;

    let wall_epoch = chain_config.wall_epoch(&genesis);
    let fork_digest = chain_config.fork_digest(&genesis)?;
    silver_log::info!("loaded config with fork digest: {}", hex::encode(fork_digest));

    publish_build_info()?;
    chain_config.node_chain(&genesis).publish()?;

    // TCaches
    let network_ingress_producer =
        TCache::producer(TCacheId::NetworkIngress, config.incoming_gossip_tcache_size());
    let control_processing_producer =
        TCache::producer(TCacheId::ControlProcessing, config.incoming_gossip_ssz_tcache_size());
    let control_gossip_producer =
        TCache::producer(TCacheId::ControlGossip, config.outgoing_gossip_tcache_size());
    let network_processing_producer =
        TCache::producer(TCacheId::NetworkProcessing, config.incoming_rpc_tcache_size());
    let boundary_processing_producer = TCache::producer(
        TCacheId::BoundaryProcessing,
        config.engine_config().incoming_engine_resp_tcache_size,
    );
    let cluster_cache_bytes = if config.cluster_config().is_some() {
        4 * MAX_CLUSTER_MESSAGE_BYTES
    } else {
        CLUSTER_MESSAGE_TCACHE_SIZE
    };
    let cluster_inbound_producer = TCache::producer(TCacheId::ClusterInbound, cluster_cache_bytes);
    let cluster_outbound_producer =
        TCache::producer(TCacheId::ClusterOutbound, cluster_cache_bytes);
    let control_rpc_producer = TCache::producer(TCacheId::ControlRpc, CONTROL_RPC_TCACHE_SIZE);
    let storage_delivery_producer =
        TCache::producer(TCacheId::StorageDelivery, config.outgoing_rpc_tcache_size());
    let beacon_state_handoff_producer =
        TCache::producer(TCacheId::BeaconStateHandoff, BEACON_STATE_TCACHE_SIZE);
    let proposed_columns_producer =
        TCache::producer(TCacheId::ProposedColumns, PROPOSED_COLUMNS_TCACHE_SIZE);
    let leanvm_producer = TCache::producer(TCacheId::LeanVmProcessing, LEANVM_TCACHE_SIZE);

    // Tiles.
    let keypair = Keypair::load_or_create(Path::new(&chain_config.data_dir))?;
    let enr_fork_id = chain_config.spec.enr_fork_id(wall_epoch, fork_digest);
    let mut local_enr = config.enr(&keypair, enr_fork_id)?;

    silver_log::info!(enr = local_enr.to_base64(), "local ENR on startup");

    let spec = Arc::new(chain_config.spec.clone());
    sleep_until_genesis(genesis.unix_secs);
    let ticker = SlotTicker::new(genesis.unix_secs, &spec, chain_config.playload_lookahead());

    // Long-lived subnets: advertised from boot (peer retention exempts us
    // from excess-peer pruning); the gossip subscriptions themselves
    // activate once Following — see `Controller::long_lived_pending`.
    let boot_wall_slot = ticker.current_slot();
    let boot_epoch = boot_wall_slot / SLOTS_PER_EPOCH;
    let attnet_count = config.attestation_subnet_count();
    let subnets =
        local_enr.node_id().attestation_subnets(spec.fork_at(boot_epoch), boot_epoch, attnet_count);
    let boot_format = spec.fork_at(boot_epoch);
    let mut gossip_topics = config.gossip_topics()?;
    let mut configured_attnets = 0u64;
    let mut long_lived_syncnets = config.sync_committee_subnets().long_lived();
    // Configured subnet topics subscribe at boot, so duties never leave them.
    for topic in &gossip_topics {
        match *topic {
            GossipTopic::BeaconAttestation(subnet) => configured_attnets |= 1 << subnet,
            GossipTopic::SyncCommittee(subnet) => long_lived_syncnets |= 1 << subnet,
            _ => {}
        }
    }
    let long_lived_attnets = u64::from_le_bytes(subnets) | configured_attnets;
    let advertised = long_lived_attnets & silver_common::attestation_subnet_mask(boot_format);
    local_enr.set_attnets(advertised.to_le_bytes(), keypair.secret_key())?;
    local_enr.set_syncnets(
        if boot_format == silver_common::ForkName::Pq { 0 } else { long_lived_syncnets },
        keypair.secret_key(),
    )?;

    // Cluster configuration
    let data_dir = Path::new(&chain_config.data_dir);
    let cluster_startup = match config.cluster_config() {
        Some(cluster) => Some(ClusterStartup::new(cluster, &local_enr, data_dir)?),
        None => {
            ClusterStartup::warn_unused_journal(data_dir);
            None
        }
    };

    let discv5_addr = config.discovery_bind_addr().expect("no discovery port");
    let p2p_addr = config.p2p_bind_addr().expect("no p2p port");
    let mut discv5 =
        DiscV5::new(config.discovery_config(), *keypair.secret_key(), local_enr, fork_digest);

    let trusted_peers = config.trusted_peers().to_vec();
    let trusted_ips = trusted_peers
        .iter()
        .filter_map(|enr| enr.ip4().map(IpAddr::from).or(enr.ip6().map(IpAddr::from)))
        .collect();

    let server_config = silver_network::create_server_config(&keypair)?;
    let p2p_endpoint = P2p::new(
        keypair,
        Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server_config)),
            false,
            None,
        ),
        config.max_connections(),
        trusted_ips,
        InboundLimits {
            gossip_bytes_per_second: config.gossip_max_bytes_per_second(),
            streams_per_second: config.max_inbound_streams_per_second(),
        },
    );
    let identify = config.identify(&keypair)?;

    let now = Instant::now();

    for enr in &chain_config.bootstrap_enrs {
        discv5.add_enr(enr, now);
    }

    // cgc is floored at SAMPLES_PER_SLOT when the ENR is built (see Config::enr).
    let das_custody_groups = local_enr
        .node_id()
        .custody_groups(local_enr.cgc().unwrap_or(silver_common::SAMPLES_PER_SLOT as u64) as u8);
    for i in 0..128 {
        if das_custody_groups & (1 << i) != 0 {
            gossip_topics.push(GossipTopic::DataColumnSidecar(i));
        }
    }

    let partial_columns = config.partial_columns();

    let cell_config =
        CellStoreConfig::new(spec.clone(), das_custody_groups, GOSSIP_DELIVERY_RETENTION)
            .map_err(|error| format!("cell store configuration: {error:?}"))?;
    let control_slot_producer =
        TCache::producer(TCacheId::ControlSlot, cell_config.cache_capacity());
    let (cell_slot, cell_slot_start) = ticker.current_slot_start();

    // Every tile opens the consumers it reads through in `try_init`.
    let tcaches = TCacheTable::from_iter([
        network_ingress_producer.cache_ref(),
        control_processing_producer.cache_ref(),
        control_gossip_producer.cache_ref(),
        network_processing_producer.cache_ref(),
        boundary_processing_producer.cache_ref(),
        cluster_inbound_producer.cache_ref(),
        cluster_outbound_producer.cache_ref(),
        control_rpc_producer.cache_ref(),
        storage_delivery_producer.cache_ref(),
        beacon_state_handoff_producer.cache_ref(),
        control_slot_producer.cache_ref(),
        proposed_columns_producer.cache_ref(),
        leanvm_producer.cache_ref(),
    ]);

    let p2p_context = Context {
        gossip_producer: network_ingress_producer,
        rpc_producer: network_processing_producer,
        identify: Some(ProtoIdentify::from((&identify, &keypair))),
        cluster_nodes: config.cluster_config().map(|_| ClusterNodes::default()),
        cluster_inbound_producer,
        partial_columns: partial_columns.supports_sending(),
        reader: TCacheReader::new(tcaches),
    };
    p2p_context.assert_ingress_capacity();
    let network_tile = NetworkTile::new(discv5_addr, discv5, p2p_addr, p2p_endpoint, p2p_context)?;

    let gossip_handler = GossipHandler::new(
        tcaches,
        control_processing_producer,
        control_gossip_producer,
        Some(silver_common::GossipDomain::new(fork_digest, spec.fork_at_slot(boot_wall_slot))),
    )?;

    let mut control_tile = Controller::new(
        PeerManager::new(
            keypair.peer_id(),
            trusted_peers,
            gossip_topics,
            config.peer_score_params(),
            config.syncing_config(),
            fork_digest,
            local_enr.into(),
            das_custody_groups,
        ),
        gossip_handler,
        control_rpc_producer,
        tcaches,
        cluster_outbound_producer,
        cluster_startup.as_ref().map(|cluster| cluster.config.clone()),
        SyncEngine::new(
            config.syncing_config(),
            booting_from_local_checkpoint,
            das_custody_groups,
            spec.clone(),
        ),
        spec.clone(),
        long_lived_attnets,
        long_lived_syncnets,
    )?;
    control_tile.set_attestation_subnet_assignment(
        local_enr.node_id(),
        attnet_count,
        configured_attnets,
    );
    control_tile = control_tile
        .with_data_columns_cache(
            cell_config.clone(),
            control_slot_producer,
            cell_slot,
            cell_slot_start,
            partial_columns,
        )
        .map_err(|error| format!("cell store construction: {error:?}"))?;

    let checkpoint = boot_checkpoint.decompose(&chain_config.spec);
    control_tile
        .set_gossip_clock(ticker.clone(), &checkpoint.state().immutable.genesis_validators_root);
    let beacon_state_tile = BeaconStateTile::new(
        ticker,
        spec.clone(),
        &config.syncing_config(),
        tcaches,
        beacon_state_handoff_producer,
        !config.disable_weak_subjectivity_check(),
        checkpoint,
        config.suggested_fee_recipient(),
        config.engine_config().get_payload_timeout(),
    );
    let state_reader = beacon_state_tile.reader();

    let storage_tile = StorageTile::new(
        tcaches,
        storage_delivery_producer,
        state_reader,
        das_custody_groups,
        spec.clone(),
        chain_config.data_dir.clone(),
        booting_from_local_checkpoint,
    );

    let state_reader = beacon_state_tile.reader();
    let data_columns_tile = DataColumnsTile::new(
        tcaches,
        state_reader,
        das_custody_groups,
        spec.clone(),
        SlotTicker::new(genesis.unix_secs, &spec, chain_config.playload_lookahead()),
        proposed_columns_producer,
    )
    .with_data_columns_cache(cell_config, cell_slot, cell_slot_start)
    .map_err(|error| format!("cell store construction: {error:?}"))?;

    let beacon_api_binds =
        config.beacon_api_bind().iter().map(String::as_str).map(Bind::parse).collect::<Vec<_>>();
    let application_boundary_tile = ApplicationBoundaryTile::new(
        &beacon_api_binds,
        config.beacon_api_allowed_hosts(),
        config.beacon_api_max_connections(),
        config.beacon_api_idle_timeout(),
        &keypair,
        local_enr,
        &identify,
        &spec,
        beacon_state_tile.reader(),
        config.engine_config(),
        config.pbs(),
        config.builder_bid_timeout(),
        tcaches,
        boundary_processing_producer,
    );

    #[cfg(feature = "metrics")]
    let application_boundary_tile = {
        let mut tile = application_boundary_tile;
        if config.metrics.enabled {
            let addr = tile.listen_metrics(config.metrics.bind, shmem_dir_queues(APP_NAME))?;
            silver_log::info!(%addr, "Prometheus metrics listening");
        }
        tile
    };

    let mut leanvm_cores = silver_leanvm::physical_cores(cores.highest() + 1);
    if let Some(count) = config.leanvm_cores() {
        if count > leanvm_cores.len() {
            let free = leanvm_cores.len();
            silver_log::warn!(count, free, "leanvm_cores asks for more cores than are free");
        }
        leanvm_cores.truncate(count);
    }
    if leanvm_cores.is_empty() {
        silver_log::warn!("no leanVM prover: no free cores, or leanvm_cores = 0");
    } else {
        silver_log::info!(?leanvm_cores, "leanVM prover cores");
    }
    // Without a prover the tile only answers each request `None`, unpinned.
    let leanvm_tile_config = match leanvm_cores.first() {
        Some(&core) => TileConfig::new(core, Some(ThreadNiceness::Highest)),
        None => TileConfig::background(None, Some(flux::timing::Duration::from_millis(1))),
    };
    let leanvm_tile = LeanVmTile::new(leanvm_cores, tcaches, leanvm_producer);

    // Spine
    let spine = SilverSpine::new(None);
    spine.start(None, None, |scoped_spine| {
        let tiles = [
            attached(control_tile, scoped_spine, cores.control),
            attached(network_tile, scoped_spine, cores.network),
            attached(beacon_state_tile, scoped_spine, cores.beacon_state),
            attached(storage_tile, scoped_spine, cores.storage),
            attached(application_boundary_tile, scoped_spine, cores.application_boundary),
            attached(data_columns_tile, scoped_spine, cores.data_columns),
            (
                leanvm_tile.name(),
                Box::new(tile_runner(leanvm_tile, scoped_spine, leanvm_tile_config)),
            ),
        ];
        for (name, run) in tiles {
            thread::Builder::new()
                .name(name.as_str().to_owned())
                .spawn_scoped(scoped_spine.scope, run)
                .expect("spawn tile thread");
        }
    });

    Ok(())
}

fn attached<'a, T: Tile<SilverSpine> + 'a>(
    tile: T,
    spine: &mut ScopedSpine<'a, '_, SilverSpine>,
    core: usize,
) -> (TileName, Box<dyn FnOnce() + Send + 'a>) {
    let name = tile.name();
    let config = TileConfig::new(core, Some(ThreadNiceness::Highest));
    (name, Box::new(tile_runner(tile, spine, config)))
}

fn sleep_until_genesis(genesis_unix_secs: u64) {
    let genesis = UNIX_EPOCH + Duration::from_secs(genesis_unix_secs);
    let Ok(remaining) = genesis.duration_since(SystemTime::now()) else {
        return;
    };

    silver_log::info!("waiting {}s for genesis at {genesis_unix_secs}", remaining.as_secs());
    std::thread::sleep(remaining);
}
