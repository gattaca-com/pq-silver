use flux::timing::{Duration, Instant};
use flux_dns::Resolver;
use flux_network::{
    NetworkCore, NetworkEvent,
    http::{Failure, HttpEvent, HttpNetwork, HttpResponse, RequestId as HttpRequestId},
};
use silver_common::Error;

use crate::beacon_link::{
    chain::ExpectedGenesis,
    endpoint::{HttpEndpoint, JSON_HEADERS},
    event_stream::{ChainEvent, EventStream},
    events::BeaconEvent,
    health::{HealthCheck, SYNCING_PATH},
    requests::{BeaconRequest, RequestId},
};

const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
const REQUEST_TIMEOUT_SECS: u64 = 5;
const GENESIS_RETRY_SECS: u64 = 2;
/// Silver's BN answers at most 32768 ids per validators lookup, each in at
/// most 550 bytes.
const MAX_BODY_BYTES: usize = 32 * 1024 * 600;
/// HTTP/1.1 answers one request per connection at a time. A slow answer, such
/// as a block production, must not hold back a slot's publishes.
const CONNECTIONS: usize = 4;

enum Genesis {
    Due(Instant),
    InFlight(HttpRequestId),
    Known { genesis_time: u64 },
    Incompatible,
}

struct InFlight {
    http_id: HttpRequestId,
    id: RequestId,
    request: BeaconRequest,
}

pub struct BeaconNode {
    http: HttpNetwork,
    dns: Resolver,
    endpoint: HttpEndpoint,
    expected: ExpectedGenesis,
    genesis: Genesis,
    health: HealthCheck,
    event_stream: Option<EventStream>,
    in_flight: Vec<InFlight>,
}

impl BeaconNode {
    pub fn new(url: &str, expected: ExpectedGenesis, slot_duration_ms: u64) -> Result<Self, Error> {
        let now = Instant::now();
        Ok(Self {
            http: HttpNetwork::default()
                .with_request_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .with_max_body_bytes(MAX_BODY_BYTES),
            dns: Resolver::system()?,
            endpoint: HttpEndpoint::parse("beacon node", url)?,
            expected,
            genesis: Genesis::Due(now),
            health: HealthCheck::new(Duration::from_millis(slot_duration_ms), now),
            event_stream: None,
            in_flight: Vec::new(),
        })
    }

    pub fn genesis_time(&self) -> Option<u64> {
        match self.genesis {
            Genesis::Known { genesis_time } => Some(genesis_time),
            Genesis::Due(_) | Genesis::InFlight(_) | Genesis::Incompatible => None,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    pub fn on_event(&mut self, event: &NetworkEvent<'_>) {
        if !self.http.on_event(event) &&
            let Some(stream) = &mut self.event_stream
        {
            stream.on_event(event);
        }
    }

    pub fn send(
        &mut self,
        net: &mut NetworkCore,
        id: RequestId,
        request: BeaconRequest,
        path: &str,
        body: &[u8],
        mut on_event: impl FnMut(BeaconEvent<'_>),
    ) {
        if !self.health.is_healthy() {
            silver_log::warn!(path, "beacon node unhealthy; request not sent");
            return on_event(BeaconEvent::Failed { id, request });
        }
        let media = request.media_type();
        let mut headers = [("Accept", media), ("Content-Type", media), ("", ""), ("", "")];
        let optional = [
            request.consensus_version().map(|v| ("Eth-Consensus-Version", v)),
            request.extra_header(),
        ];
        let mut used = 2;
        for header in optional.into_iter().flatten() {
            headers[used] = header;
            used += 1;
        }
        let sent =
            self.endpoint.send(&mut self.http, net, request.method(), path, &headers[..used], body);
        match sent {
            Some(http_id) => self.in_flight.push(InFlight { http_id, id, request }),
            None => {
                silver_log::warn!(path, "beacon node request not sent");
                on_event(BeaconEvent::Failed { id, request });
            }
        }
    }

    pub fn drive(&mut self, net: &mut NetworkCore, mut on_event: impl FnMut(BeaconEvent<'_>)) {
        let now = Instant::now();
        let Self { http, dns, endpoint, expected, genesis, health, event_stream, in_flight } = self;

        if endpoint.wants_resolving(now) {
            if let Err(e) = dns.query(0, &endpoint.host) {
                silver_log::warn!(url = %endpoint.url, %e, "beacon node lookup not sent");
            }
        }
        dns.poll(|_, addrs| endpoint.resolved(http, net, addrs, CONNECTIONS));

        if let Genesis::Due(at) = *genesis &&
            at <= now &&
            endpoint.is_pooled()
        {
            *genesis = match endpoint.send(http, net, "GET", GENESIS_PATH, &JSON_HEADERS, &[]) {
                Some(http_id) => Genesis::InFlight(http_id),
                None => Genesis::Due(now + Duration::from_secs(GENESIS_RETRY_SECS)),
            };
        }

        if matches!(genesis, Genesis::Known { .. }) && health.is_due(now, &endpoint.url) {
            let sent = endpoint.send(http, net, "GET", SYNCING_PATH, &JSON_HEADERS, &[]);
            health.sent(sent, &endpoint.url);
        }

        http.drive(net, |event| {
            let (http_id, answer) = match event {
                HttpEvent::Response { id: Some(id), response, .. } => (id, Ok(response)),
                HttpEvent::Failed { id, reason } => (id, Err(reason)),
                _ => return,
            };

            if matches!(*genesis, Genesis::InFlight(sent) if sent == http_id) {
                *genesis = on_genesis(answer, expected, &endpoint.url, now);
                return;
            }
            if health.owns(http_id) {
                let answer = answer.ok().map(|response| (response.status, response.body));
                return health.on_answer(answer, &endpoint.url);
            }

            let Some(at) = in_flight.iter().position(|sent| sent.http_id == http_id) else {
                return;
            };
            let InFlight { id, request, .. } = in_flight.swap_remove(at);
            match answer {
                Ok(response) if response.status == 200 => on_event(request.answered(id, &response)),
                Ok(HttpResponse { status: 204, .. }) => {
                    on_event(BeaconEvent::NoContent { id, request })
                }
                Ok(HttpResponse { status, .. }) => {
                    silver_log::warn!(?request, status, "beacon node request refused");
                    on_event(BeaconEvent::Failed { id, request });
                }
                Err(reason) => {
                    silver_log::warn!(?request, ?reason, "beacon node request failed");
                    on_event(BeaconEvent::Failed { id, request });
                }
            }
        });

        drive_event_stream(event_stream, endpoint, health, net, on_event);
    }
}

/// Opens once the node is first healthy; its heads count only while it stays
/// healthy.
fn drive_event_stream(
    event_stream: &mut Option<EventStream>,
    endpoint: &HttpEndpoint,
    health: &HealthCheck,
    net: &mut NetworkCore,
    mut on_event: impl FnMut(BeaconEvent<'_>),
) {
    let healthy = health.is_healthy();
    if event_stream.is_none() {
        let (Some(addr), true) = (endpoint.addr(), healthy) else { return };
        let stream = EventStream::open(net, addr, endpoint.authority(), endpoint.tls_host());
        *event_stream = Some(stream);
    }
    let stream = event_stream.as_mut().expect("opened above");
    stream.drive(net, &endpoint.url, |event| {
        if healthy {
            on_event(match event {
                ChainEvent::Head(head) => BeaconEvent::Head(head),
                ChainEvent::PayloadAvailable { slot } => BeaconEvent::PayloadAvailable { slot },
            });
        }
    });
}

fn on_genesis(
    answer: Result<HttpResponse<'_>, Failure>,
    expected: &ExpectedGenesis,
    url: &str,
    now: Instant,
) -> Genesis {
    let retry = Genesis::Due(now + Duration::from_secs(GENESIS_RETRY_SECS));
    let body = match answer {
        Ok(HttpResponse { status: 200, body, .. }) => body,
        Ok(HttpResponse { status, .. }) => {
            silver_log::warn!(url, status, "beacon node genesis refused");
            return retry;
        }
        Err(reason) => {
            silver_log::warn!(url, ?reason, "beacon node genesis failed");
            return retry;
        }
    };
    match expected.check(body) {
        Ok(genesis_time) => {
            silver_log::info!(url, genesis_time, "beacon node compatible");
            Genesis::Known { genesis_time }
        }
        Err(reason) => {
            silver_log::error!(url, reason, "beacon node incompatible");
            Genesis::Incompatible
        }
    }
}
