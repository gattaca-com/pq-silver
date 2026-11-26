use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{Error, VcSpine};

use crate::{
    beacon_link::{BeaconLink, BeaconRequests},
    config::Config,
    duties::Duties,
};

pub struct ValidatorTile {
    beacon_link: BeaconLink,
    duties: Duties,
    requests: BeaconRequests,
}

impl ValidatorTile {
    pub fn new(config: &Config) -> Result<Self, Error> {
        Ok(Self {
            beacon_link: BeaconLink::new(config)?,
            duties: Duties::new(config),
            requests: BeaconRequests::default(),
        })
    }
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
        let Self { beacon_link, duties, requests } = self;
        beacon_link.spin(requests, |event| duties.on_beacon_event(event));
        if let Some(chain) = beacon_link.chain_info() {
            duties.on_tick(chain, requests);
        }
    }
}
