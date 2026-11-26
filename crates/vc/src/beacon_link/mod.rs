mod beacon_node;
mod chain;
mod endpoint;
mod events;
mod head_stream;
mod health;
mod remote_signer;
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

#[cfg(test)]
pub use self::events::{AttestationData, PayloadAttestationData};
use self::{beacon_node::BeaconNode, chain::ExpectedGenesis, remote_signer::RemoteSigner};
pub use self::{
    chain::ChainInfo,
    events::{
        Aggregate, AttesterDuties, BeaconEvent, ProducedBlock, SignerKeys, SlotDuties,
        ValidatorIndices,
    },
    head_stream::Head,
    requests::{
        BeaconRequest, BeaconRequests, CommitteeSubscription, ForkInfo, IndexedSignature,
        RequestId, SignBody, SignPurpose, SignedAggregate, SignedAttestation, SignedPreferences,
    },
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
    remote_signer: RemoteSigner,
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
            remote_signer: RemoteSigner::new(&config.web3signer_url)?,
        })
    }

    #[cfg(feature = "thread_park")]
    pub fn waker(&self) -> io::Result<Waker> {
        Waker::new(self.poll.registry(), WAKER_TOKEN)
    }

    pub fn chain_info(&self) -> Option<&ChainInfo> {
        self.beacon_node.chain_info()
    }

    pub fn spin(
        &mut self,
        requests: &mut BeaconRequests,
        mut on_event: impl FnMut(BeaconEvent<'_>),
    ) {
        let Self { poll, events, net, beacon_node, remote_signer } = self;
        let mut route = |event: NetworkEvent<'_>| {
            if !remote_signer.on_event(&event) {
                beacon_node.on_event(&event);
            }
        };
        net.pre_poll(&mut route);
        if let Err(error) = poll.poll(events, Some(POLL_TIMEOUT.min(net.max_poll_interval()))) {
            silver_log::error!(%error, "poll");
        }
        for event in events.iter().filter(|event| event.token() != WAKER_TOKEN) {
            net.handle_event(event, &mut route);
        }
        net.post_poll(&mut route);
        beacon_node.drive(net, &mut on_event);
        remote_signer.drive(net, &mut on_event);
        requests.drain(|id, request, path, body| {
            if request.is_signing() {
                remote_signer.send(net, id, request, path, body, &mut on_event);
            } else {
                beacon_node.send(net, id, request, path, body, &mut on_event);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

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
        let signer = stub_node(vec![(
            "/api/v1/eth2/publicKeys",
            format!(r#"["0x{}"]"#, hex::encode([0xaa; 48])),
        )]);
        BeaconLink::new(&Config {
            spec: SpecConfig::mainnet(),
            genesis_validators_root: chain::GENESIS_VALIDATORS_ROOT,
            beacon_node: node,
            web3signer_url: signer,
            proposals: None,
        })
        .unwrap()
    }

    #[test]
    fn spin_reaches_node_and_signer_over_its_own_poll() {
        let mut beacon_link = beacon_link();
        let mut requests = BeaconRequests::default();
        let mut listed = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while beacon_link.chain_info().is_none() || !listed {
            assert!(Instant::now() < deadline, "no chain info or key listing");
            beacon_link.spin(&mut requests, |event| {
                listed |= matches!(event, BeaconEvent::SignerKeys(_));
            });
        }
        assert_eq!(beacon_link.chain_info().unwrap().genesis_time, 1606824023);
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
