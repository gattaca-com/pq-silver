use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{Error, VcSpine};

use crate::{
    beacon_link::{BeaconLink, BeaconRequests},
    config::Config,
    duties::Duties,
    keys::load_keys,
    signer::{RemoteCache, Signer},
    signing::{SignAnswer, SignRequests},
};

pub struct ValidatorTile {
    beacon_link: BeaconLink,
    duties: Duties,
    signer: Signer,
    requests: BeaconRequests,
    signs: SignRequests,
}

impl ValidatorTile {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let keys = load_keys(config)?;
        silver_log::info!(keys = keys.len(), "validator keys");
        let beacon_link = BeaconLink::new(config)?;
        let remote = config.xmss_cache_url.as_deref().and_then(|url| {
            RemoteCache::open(url, config.genesis_state.as_deref())
                .inspect_err(|error| silver_log::warn!(url, error, "remote expanded keys unusable"))
                .ok()
        });
        let signer = Signer::new(
            &keys,
            &config.data_dir,
            remote.as_ref(),
            config.init_leaf_records,
            config.signer_threads,
            wake_the_loop,
        )?;
        let pubkeys = signer.pubkeys().to_vec();
        Ok(Self {
            beacon_link,
            duties: Duties::new(config, pubkeys),
            signer,
            requests: BeaconRequests::default(),
            signs: SignRequests::default(),
        })
    }
}

/// Under `thread_park` the loop sleeps in `epoll` until flux's waker, which it
/// registered, fires. Otherwise it never sleeps.
fn wake_the_loop() {
    #[cfg(feature = "thread_park")]
    flux::park::SIGNAL.signal();
}

impl Tile<VcSpine> for ValidatorTile {
    /// A tile with a registered waker is never parked by the runner; the loop
    /// sleeps in its own `epoll` instead.
    fn try_init(&mut self, adapter: &mut SpineAdapter<VcSpine>) -> bool {
        #[cfg(feature = "thread_park")]
        adapter.register_waker(self.beacon_link.waker().expect("waker on the VC's poll"));
        #[cfg(not(feature = "thread_park"))]
        let _ = adapter;
        true
    }

    fn loop_body(&mut self, _adapter: &mut SpineAdapter<VcSpine>) {
        let Self { beacon_link, duties, signer, requests, signs } = self;
        beacon_link.spin(requests, |event| duties.on_beacon_event(event, signs));
        // A request to an unhealthy node fails at once, and its duty retries
        // only from the next slot. The first tick once healthy starts the slot.
        if let Some(genesis_time) = beacon_link.genesis_time() &&
            beacon_link.is_healthy()
        {
            duties.on_tick(genesis_time, requests, signs);
        }
        if let Some(slot) = duties.current_slot() {
            signer.prepare_for(slot);
        }
        signs.drain(|request| {
            if !signer.submit(&request) {
                duties.on_signed(&request, SignAnswer::Refused, requests);
            }
        });
        signer.drain(|request, signature| {
            let answer = signature.map_or(SignAnswer::Refused, SignAnswer::Signature);
            duties.on_signed(request, answer, requests);
        });
    }
}
