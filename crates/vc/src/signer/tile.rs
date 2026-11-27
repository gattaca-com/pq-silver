use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::{Tile, TileName},
};
use silver_common::{
    Error, VcSpine,
    vc_spine::{SignAnswer, SignerEvent, SignerRequest},
};

use super::{RemoteCache, Signer, Submitted, VrfSource, vrf::genesis_registry};
use crate::{
    config::SignerConfig,
    keys::{Shard, load_keys},
};

/// Owns its shard of the keys: reads and expands them on its own thread, then
/// signs one of their requests per loop and answers on the spine. Every
/// signer tile sees every request and takes only its own keys'.
pub struct SignerTile {
    shard: Shard,
    /// Unique per shard: flux registers a tile by its name.
    name: TileName,
    state: State,
}

#[expect(clippy::large_enum_variant, reason = "one per signer tile")]
enum State {
    Loading(SignerConfig),
    Signing(Signer),
    Failed,
}

impl SignerTile {
    pub fn new(config: SignerConfig, shard: Shard) -> Self {
        let name = format!("SignerTile{}", shard.index);
        let name = TileName::try_from(name.as_str()).expect("a short tile name");
        Self { shard, name, state: State::Loading(config) }
    }
}

impl Tile<VcSpine> for SignerTile {
    /// Before any tile runs, so a request cannot precede the subscription.
    fn on_attach(&mut self, adapter: &mut SpineAdapter<VcSpine>) {
        adapter.subscribe_broadcast::<SignerRequest>();
    }

    /// A key that cannot load stops the process, as no duty can be done
    /// with it.
    fn try_init(&mut self, adapter: &mut SpineAdapter<VcSpine>) -> bool {
        let State::Loading(config) = &self.state else { return true };
        self.state = match load(config, self.shard) {
            Ok(signer) => {
                silver_log::info!(keys = signer.pubkeys().len(), "validator keys");
                for pubkey in signer.pubkeys() {
                    adapter.produce(SignerEvent::KeyLoaded(*pubkey));
                }
                adapter.produce(SignerEvent::Ready);
                State::Signing(signer)
            }
            Err(error) => {
                silver_log::error!(%error, "validator keys not loaded");
                adapter.request_stop_scope();
                State::Failed
            }
        };
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<VcSpine>) {
        let State::Signing(signer) = &mut self.state else { return };
        adapter.consume(|request: SignerRequest, producers| match request {
            SignerRequest::Sign(request) => {
                if signer.submit(&request) == Submitted::Refused {
                    let answer = SignAnswer::Refused;
                    producers.produce(SignerEvent::Signed { request, answer });
                }
            }
            SignerRequest::PrepareFor { slot } => signer.prepare_for(slot),
        });
        if signer.work(|request, answer| {
            adapter.produce(SignerEvent::Signed { request: *request, answer })
        }) {
            adapter.mark_work();
        }
    }

    fn name(&self) -> TileName {
        self.name
    }
}

fn load(config: &SignerConfig, shard: Shard) -> Result<Signer, Error> {
    let keys = load_keys(config, shard)?;
    // The network's own genesis authenticates both published artifacts.
    let registry = config.genesis_state.as_deref().and_then(|path| {
        genesis_registry(path)
            .inspect_err(|error| silver_log::warn!(error, "no genesis registry"))
            .ok()
    });
    let registry = registry.as_deref();
    let remote = with_registry("expanded keys", config.xmss_cache_url.as_deref(), registry)
        .and_then(|(url, registry)| {
            RemoteCache::with_registry(url, registry.iter().map(|(pubkey, _)| *pubkey))
                .inspect_err(|error| silver_log::warn!(url, error, "remote expanded keys"))
                .ok()
        });
    // A cached VRF tree needs only the genesis roots; the published state
    // is fetched only if a tree must be built.
    let vrf = registry.map(|registry| VrfSource::new(registry, config.vrf_state_url.clone()));
    if config.vrf_state_url.is_some() && vrf.is_none() {
        silver_log::warn!("VRF states unusable without the network's genesis.ssz");
    }
    Signer::load(&keys, &config.data_dir, remote.as_ref(), vrf, config.init_leaf_records)
}

/// A published artifact's URL, if given, with the registry that authenticates
/// it.
fn with_registry<'a, T>(
    artifact: &str,
    url: Option<&'a str>,
    registry: Option<&'a T>,
) -> Option<(&'a str, &'a T)>
where
    T: ?Sized,
{
    let url = url?;
    if registry.is_none() {
        silver_log::warn!(url, artifact, "unusable without the network's genesis.ssz");
    }
    Some((url, registry?))
}
