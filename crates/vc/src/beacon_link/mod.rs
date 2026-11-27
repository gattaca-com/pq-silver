mod beacon_node;
mod chain;
mod endpoint;
mod event_stream;
mod events;
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
    event_stream::Head,
    events::{
        Aggregate, AttestationData, AttesterDuties, BeaconEvent, PayloadAttestationData,
        ProducedBlock, SlotDuties, ValidatorIndices,
    },
    requests::{BeaconRequest, BeaconRequests, CommitteeSubscription, RequestId},
};
use crate::config::Config;

/// flux's waker. mio allows one per `Poll`, so the signer wakes the loop
/// through flux too.
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

    /// Requests are refused until it is, so duties wait for it.
    pub fn is_healthy(&self) -> bool {
        self.beacon_node.is_healthy()
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
    use std::time::Instant;

    use silver_chain_spec::SpecConfig;

    use super::*;
    use crate::{
        beacon_link::{
            chain::tests as chain,
            event_stream::tests::{EVENTS_ROUTE, head_event, payload_available_event},
            health::{SYNCING_PATH, tests::syncing_json},
            stub_server::stub_node,
        },
        config::SignerConfig,
    };

    const DATA_PATH: &str = "/eth/v1/validator/attestation_data?slot=65&committee_index=0";

    fn beacon_link() -> BeaconLink {
        beacon_link_closing_after(None)
    }

    fn beacon_link_closing_after(idle: Option<Duration>) -> BeaconLink {
        let node = stub_node(
            vec![
                ("/eth/v1/beacon/genesis", chain::GENESIS.into()),
                (SYNCING_PATH, syncing_json(false, false)),
                (EVENTS_ROUTE, head_event(65, 0xab) + &payload_available_event(65)),
                (DATA_PATH, r#"{"data":{}}"#.into()),
            ],
            idle,
        );
        BeaconLink::new(&Config {
            spec: SpecConfig::mainnet(),
            genesis_validators_root: chain::GENESIS_VALIDATORS_ROOT,
            beacon_node: node,
            signer: SignerConfig::default(),
            signer_tiles: 1,
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

    /// Spins until the node is healthy: its heads count only then.
    fn healthy(beacon_link: &mut BeaconLink, requests: &mut BeaconRequests) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut head = false;
        while !head {
            assert!(Instant::now() < deadline, "never healthy");
            beacon_link.spin(requests, |event| head |= matches!(event, BeaconEvent::Head(_)));
        }
    }

    #[test]
    fn a_request_on_a_connection_the_node_closed_is_sent_again() {
        let mut beacon_link = beacon_link_closing_after(Some(Duration::from_millis(50)));
        let mut requests = BeaconRequests::default();
        healthy(&mut beacon_link, &mut requests);
        // The node closes every pooled connection, unseen until the next poll;
        // the request goes out on one before that poll.
        std::thread::sleep(Duration::from_millis(200));

        let id = requests.attestation_data(65);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answer = None;
        while answer.is_none() {
            assert!(Instant::now() < deadline, "no answer");
            beacon_link.spin(&mut requests, |event| match event {
                BeaconEvent::AttestationData { id: answered, .. } if answered == id => {
                    answer = Some(true)
                }
                BeaconEvent::Failed { id: failed, .. } if failed == id => answer = Some(false),
                _ => {}
            });
        }
        assert_eq!(answer, Some(true), "the request failed instead of being sent again");
    }

    #[test]
    fn payload_arrivals_stream_beside_heads() {
        let mut beacon_link = beacon_link();
        let mut requests = BeaconRequests::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut available = None;
        while available.is_none() {
            assert!(Instant::now() < deadline, "no payload event");
            beacon_link.spin(&mut requests, |event| {
                if let BeaconEvent::PayloadAvailable { slot } = event {
                    available = Some(slot);
                }
            });
        }
        assert_eq!(available, Some(65));
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
