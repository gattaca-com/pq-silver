#![allow(improper_ctypes, improper_ctypes_definitions)]

use std::time::Duration;

pub use cluster_admin::*;
use flux::{
    communication::ShmemData,
    spine::{SpineAdapter, SpineQueue},
    spine_derive::from_spine,
    tile::TileInfo,
};
pub use leanvm::{LeanVmReq, LeanVmResp, RefusalCode};
pub use messages::*;
pub use stream_id::{LOCAL_GOSSIP_STREAM_ID, P2pStreamId};
pub use stream_protocol::{
    ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, RPC_PROTOCOLS, StreamProtocol,
};
pub use tcache::*;

use crate::cell_store::{CellStoreEvent, RetentionEvent};

mod cluster_admin;
pub mod leanvm;
mod messages;
mod stream_id;
mod stream_protocol;
mod tcache;

#[from_spine("silver", per_producer_consumer_timers)]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    /// New incoming network gossip messages
    #[queue(size(2usize.pow(19)))]
    pub gossip_in: SpineQueue<GossipMsgIn>,
    /// New incoming gossip messages
    #[queue(size(2usize.pow(18)))]
    pub new_gossip: SpineQueue<NewGossipMsg>,
    /// P2p send messages.
    #[queue(size(2usize.pow(19)))]
    pub p2p_send: SpineQueue<P2pSend>,
    /// RPC recv messages.
    #[queue(size(2usize.pow(14)))]
    pub rpc_inbound: SpineQueue<RpcInbound>,
    /// Raft messages received from other cluster nodes.
    #[queue(size(2usize.pow(14)))]
    pub cluster_inbound: SpineQueue<ClusterIn>,
    /// Raft messages to send to other cluster nodes.
    #[queue(size(2usize.pow(14)))]
    pub cluster_outbound: SpineQueue<ClusterMsgOut>,
    /// Requests submitted by the Beacon API.
    #[queue(size(2usize.pow(14)))]
    pub beacon_api_requests: SpineQueue<BeaconApiRequest>,
    /// Responses returned to the Beacon API.
    #[queue(size(2usize.pow(14)))]
    pub beacon_api_responses: SpineQueue<BeaconApiResponse>,
    #[queue(size(2usize.pow(4)))]
    pub locked_proposals: SpineQueue<LockedProposal>,
    #[queue(size(2usize.pow(16)))]
    pub peer_events: SpineQueue<PeerEvent>,
    #[queue(size(2usize.pow(16)))]
    pub peer_control: SpineQueue<PeerControl>,
    #[queue(size(2usize.pow(14)))]
    pub beacon_events: SpineQueue<BeaconStateEvent>,
    #[queue(size(2usize.pow(13)))]
    pub data_columns: SpineQueue<DataColumnsEvent>,
    #[queue(size(2usize.pow(10)))]
    pub retention: SpineQueue<RetentionEvent>,
    #[queue(size(2usize.pow(13)))]
    pub cells: SpineQueue<CellStoreEvent>,
    #[queue(size(2usize.pow(10)))]
    pub sync_target: SpineQueue<SyncUpdate>,
    #[queue(size(2usize.pow(14)))]
    pub sync_needs: SpineQueue<SyncNeed>,
    #[queue(size(2usize.pow(12)))]
    pub replay_blocks: SpineQueue<ReplayBlock>,
    #[queue(size(2usize.pow(1)))]
    pub syncing_strategy: SpineQueue<SyncingStrategy>,

    #[queue(size(2usize.pow(10)))]
    pub engine_reqs: SpineQueue<EngineReq>,
    #[queue(size(2usize.pow(10)))]
    pub engine_resps: SpineQueue<EngineResp>,
    #[queue(size(2usize.pow(8)))]
    pub engine_health: SpineQueue<EngineHealthEvent>,

    #[queue(size(2usize.pow(8)))]
    pub leanvm_reqs: SpineQueue<LeanVmReq>,
    #[queue(size(2usize.pow(8)))]
    pub leanvm_resps: SpineQueue<LeanVmResp>,
    #[queue(size(2usize.pow(8)))]
    pub leanvm_ready: SpineQueue<LeanVmReady>,

    #[queue(size(2usize.pow(6)))]
    pub sidecar_bid_requests: SpineQueue<SidecarBidRequest>,
    #[queue(size(2usize.pow(6)))]
    pub sidecar_bid_answers: SpineQueue<SidecarBidResponse>,
    #[queue(size(2usize.pow(6)))]
    pub builder_bid_requests: SpineQueue<BuilderBidsRequest>,
    #[queue(size(2usize.pow(6)))]
    pub builder_bid_answers: SpineQueue<BuilderBidsResponse>,

    #[queue(size(2usize.pow(12)))]
    pub peer_stats: SpineQueue<PeerStats>,
    #[queue(size(2usize.pow(12)))]
    pub cluster_commits: SpineQueue<ClusterCommit>,
    #[queue(size(2usize.pow(4)))]
    pub cluster_admin_requests: SpineQueue<ClusterAdminRequest>,
    #[queue(size(2usize.pow(4)))]
    pub cluster_admin_responses: SpineQueue<ClusterAdminResponse>,
}

/// Bounds the park that may follow this loop: the tile wakes within `timeout`
/// without a spine signal. Without it, timed work waits for the next signal.
pub fn wake_within(adapter: &mut SpineAdapter<SilverSpine>, timeout: Duration) {
    #[cfg(feature = "thread_park")]
    adapter.set_park_deadline(flux::timing::Instant::now() + flux::timing::Duration::from(timeout));
    #[cfg(not(feature = "thread_park"))]
    let _ = (adapter, timeout);
}
