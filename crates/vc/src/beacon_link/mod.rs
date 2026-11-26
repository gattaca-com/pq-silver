mod beacon_node;
mod chain;
mod endpoint;
mod events;
mod head_stream;
mod health;
mod requests;
#[cfg(test)]
mod stub_server;

#[cfg(feature = "thread_park")]
use std::io;
use std::time::Duration;

use flux_network::{NetworkEvent, NetworkWithExternalPoll};
#[cfg(feature = "thread_park")]
use mio::Waker;
use mio::{Events, Poll, Token};
use silver_common::Error;

use self::{beacon_node::BeaconNode, chain::ExpectedGenesis};
pub use self::{
    events::{
        Aggregate, AttestationData, AttesterDuties, BeaconEvent, PayloadAttestationData,
        ProducedBlock, SlotDuties, ValidatorIndices,
    },
    head_stream::Head,
    requests::{BeaconRequest, BeaconRequests, CommitteeSubscription, RequestId},
};
use crate::config::Config;

const WAKER_TOKEN: Token = Token(0);
const EVENTS_CAPACITY: usize = 256;
/// Under `thread_park` the loop sleeps in `epoll` rather than spinning. Socket
/// readiness ends the wait at once; this bounds how late a slot phase or retry
/// fires.
#[cfg(feature = "thread_park")]
const POLL_TIMEOUT: Duration = Duration::from_millis(10);
#[cfg(not(feature = "thread_park"))]
const POLL_TIMEOUT: Duration = Duration::ZERO;

pub struct BeaconLink {
    poll: Poll,
    events: Events,
    net: NetworkWithExternalPoll,
    beacon_node: BeaconNode,
}

impl BeaconLink {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let expected = ExpectedGenesis::new(&config.spec, &config.genesis_validators_root);
        Ok(Self {
            poll,
            events: Events::with_capacity(EVENTS_CAPACITY),
            net: NetworkWithExternalPoll::new(registry, WAKER_TOKEN.0 + 1..usize::MAX),
            beacon_node: BeaconNode::new(
                &config.beacon_node,
                expected,
                config.spec.slot_duration_ms(),
            )?,
        })
    }

    #[cfg(feature = "thread_park")]
    pub fn waker(&self) -> io::Result<Waker> {
        Waker::new(self.poll.registry(), WAKER_TOKEN)
    }

    pub fn genesis_time(&self) -> Option<u64> {
        self.beacon_node.genesis_time()
    }

    /// Sends the queued requests before waiting on the sockets, so a request
    /// queued since the last spin does not wait out the poll timeout.
    pub fn spin(
        &mut self,
        requests: &mut BeaconRequests,
        mut on_event: impl FnMut(BeaconEvent<'_>),
    ) {
        let Self { poll, events, net, beacon_node } = self;
        requests.drain(|id, request, path, body| {
            beacon_node.send(net, id, request, path, body, &mut on_event)
        });

        let mut route = |event: NetworkEvent<'_>| beacon_node.on_event(&event);
        net.pre_poll(&mut route);
        if let Err(error) = poll.poll(events, Some(POLL_TIMEOUT.min(net.max_poll_interval()))) {
            silver_log::error!(%error, "poll");
        }
        for event in events.iter().filter(|event| event.token() != WAKER_TOKEN) {
            net.handle_event(event, &mut route);
        }
        net.post_poll(&mut route);
        beacon_node.drive(net, &mut on_event);
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Instant};

    use silver_chain_spec::SpecConfig;

    use super::*;
    use crate::beacon_link::{
        chain::tests as chain,
        head_stream::tests::{EVENTS_ROUTE, head_event},
        health::{SYNCING_PATH, tests::syncing_json},
        stub_server::stub_node,
    };

    fn beacon_link() -> BeaconLink {
        let node = stub_node(vec![
            ("/eth/v1/beacon/genesis", chain::GENESIS.into()),
            (SYNCING_PATH, syncing_json(false, false)),
            (EVENTS_ROUTE, head_event(65, 0xab)),
        ]);
        BeaconLink::new(&Config {
            spec: SpecConfig::mainnet(),
            genesis_validators_root: chain::GENESIS_VALIDATORS_ROOT,
            beacon_node: node,
            keys_dir: PathBuf::new(),
            signer_threads: 1,
            proposals: None,
        })
        .unwrap()
    }

    #[test]
    fn spin_reaches_the_node_over_its_own_poll() {
        let mut beacon_link = beacon_link();
        let mut requests = BeaconRequests::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        while beacon_link.genesis_time().is_none() {
            assert!(Instant::now() < deadline, "no genesis");
            beacon_link.spin(&mut requests, |_| {});
        }
        assert_eq!(beacon_link.genesis_time(), Some(1606824023));
    }

    #[test]
    fn heads_stream_once_the_node_is_healthy() {
        let mut beacon_link = beacon_link();
        let mut requests = BeaconRequests::default();
        let mut head = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while head.is_none() {
            assert!(Instant::now() < deadline, "no head");
            beacon_link.spin(&mut requests, |event| {
                if let BeaconEvent::Head(seen) = event {
                    head = Some(seen);
                }
            });
        }
        let head = head.unwrap();
        assert_eq!((head.slot, head.block), (65, [0xab; 32]));
        assert_eq!(head.current_duty_dependent_root, [0xd1; 32]);
    }

    #[test]
    fn idle_spin_returns_within_the_poll_timeout() {
        let mut beacon_link = beacon_link();
        let mut requests = BeaconRequests::default();
        for _ in 0..20 {
            beacon_link.spin(&mut requests, |_| {});
        }
        let started = Instant::now();
        beacon_link.spin(&mut requests, |_| {});
        assert!(started.elapsed() < POLL_TIMEOUT + Duration::from_millis(50));
    }
}
