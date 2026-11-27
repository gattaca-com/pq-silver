use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    Error, VcSpine,
    ssz_view::XMSSPubkey,
    vc_spine::{SignerEvent, SignerRequest},
};

use crate::{
    beacon_link::{BeaconLink, BeaconRequests},
    config::Config,
    duties::Duties,
    signing::SignRequests,
};

pub struct ValidatorTile {
    beacon_link: BeaconLink,
    duties: Duties,
    requests: BeaconRequests,
    signs: SignRequests,
    prepared_slot: Option<u64>,
    loading: LoadingKeys,
}

/// The signer tiles' keys as they report them. Duties hold their keys
/// sorted and by position, so the keys join them all at once, sorted, when
/// the last signer tile is ready.
struct LoadingKeys {
    pubkeys: Vec<XMSSPubkey>,
    signers_loading: usize,
}

impl LoadingKeys {
    fn on_ready(&mut self, add: impl FnMut(XMSSPubkey)) {
        self.signers_loading -= 1;
        if self.signers_loading == 0 {
            self.pubkeys.sort_unstable();
            self.pubkeys.drain(..).for_each(add);
        }
    }
}

impl ValidatorTile {
    pub fn new(config: &Config) -> Result<Self, Error> {
        Ok(Self {
            beacon_link: BeaconLink::new(config)?,
            duties: Duties::new(config, Vec::new()),
            requests: BeaconRequests::default(),
            signs: SignRequests::default(),
            prepared_slot: None,
            loading: LoadingKeys { pubkeys: Vec::new(), signers_loading: config.signer_tiles },
        })
    }
}

impl Tile<VcSpine> for ValidatorTile {
    /// Before any tile runs, so the signer's first event is not missed.
    fn on_attach(&mut self, adapter: &mut SpineAdapter<VcSpine>) {
        adapter.subscribe_broadcast::<SignerEvent>();
    }

    /// A tile with a registered waker is never parked by the runner; the loop
    /// sleeps in its own `epoll`, which a signer event also wakes.
    fn try_init(&mut self, adapter: &mut SpineAdapter<VcSpine>) -> bool {
        #[cfg(feature = "thread_park")]
        adapter.register_waker(self.beacon_link.waker().expect("waker on the VC's poll"));
        #[cfg(not(feature = "thread_park"))]
        let _ = adapter;
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<VcSpine>) {
        let Self { beacon_link, duties, requests, signs, prepared_slot, loading } = self;
        beacon_link.spin(requests, |event| duties.on_beacon_event(event, signs));
        // A request to an unhealthy node fails at once, and its duty retries
        // only from the next slot. The first tick once healthy starts the slot.
        if let Some(genesis_time) = beacon_link.genesis_time() &&
            beacon_link.is_healthy()
        {
            duties.on_tick(genesis_time, requests, signs);
        }
        if let Some(slot) = duties.current_slot() &&
            *prepared_slot != Some(slot)
        {
            *prepared_slot = Some(slot);
            adapter.produce(SignerRequest::PrepareFor { slot });
        }
        signs.drain(|request| adapter.produce(SignerRequest::Sign(request)));
        adapter.consume(|event: SignerEvent, _| match event {
            SignerEvent::KeyLoaded(pubkey) => loading.pubkeys.push(pubkey),
            SignerEvent::Ready => loading.on_ready(|pubkey| duties.key_loaded(pubkey)),
            SignerEvent::Signed { request, answer } => {
                duties.on_signed(&request, &answer, requests)
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_join_sorted_once_every_signer_is_ready() {
        let mut loading = LoadingKeys { pubkeys: Vec::new(), signers_loading: 2 };
        let mut added = Vec::new();
        loading.pubkeys.extend([[3; 32], [1; 32]]);
        loading.on_ready(|pubkey| added.push(pubkey));
        assert!(added.is_empty(), "one signer tile still loading");
        loading.pubkeys.push([2; 32]);
        loading.on_ready(|pubkey| added.push(pubkey));
        assert_eq!(added, [[1; 32], [2; 32], [3; 32]]);
    }
}
