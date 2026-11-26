use flux::timing::{Duration, Instant};
use flux_dns::Resolver;
use flux_network::{
    NetworkCore, NetworkEvent,
    http::{HttpEvent, HttpNetwork, HttpResponse, RequestId as HttpRequestId},
};
use silver_common::Error;

use crate::beacon_link::{
    chain::{ChainInfo, ExpectedGenesis},
    endpoint::{HttpEndpoint, JSON_HEADERS},
    events::BeaconEvent,
    head_stream::HeadStream,
    health::{HealthCheck, SYNCING_PATH},
    requests::{BeaconRequest, RequestId},
};

const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
const REQUEST_TIMEOUT_SECS: u64 = 5;
const GENESIS_RETRY_SECS: u64 = 2;
/// Silver's BN answers at most 32768 ids per validators lookup, each in at
/// most 550 bytes.
const MAX_BODY_BYTES: usize = 32 * 1024 * 600;

enum Genesis {
    Due(Instant),
    InFlight(HttpRequestId),
    Known(ChainInfo),
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
    head_stream: Option<HeadStream>,
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
            head_stream: None,
            in_flight: Vec::new(),
        })
    }

    pub fn chain_info(&self) -> Option<&ChainInfo> {
        match &self.genesis {
            Genesis::Known(chain) => Some(chain),
            Genesis::Due(_) | Genesis::InFlight(_) | Genesis::Incompatible => None,
        }
    }

    pub fn on_event(&mut self, event: &NetworkEvent<'_>) {
        if !self.http.on_event(event) &&
            let Some(stream) = &mut self.head_stream
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
        let Self { http, dns, endpoint, expected, genesis, health, head_stream, in_flight } = self;

        if endpoint.wants_resolving(now) {
            if let Err(e) = dns.query(0, &endpoint.host) {
                silver_log::warn!(url = %endpoint.url, %e, "beacon node lookup not sent");
            }
        }
        dns.poll(|_, addrs| endpoint.resolved(http, net, addrs, 1));

        if let Genesis::Due(at) = *genesis &&
            at <= now &&
            endpoint.is_pooled()
        {
            *genesis = match endpoint.send(http, net, "GET", GENESIS_PATH, &JSON_HEADERS, &[]) {
                Some(http_id) => Genesis::InFlight(http_id),
                None => Genesis::Due(now + Duration::from_secs(GENESIS_RETRY_SECS)),
            };
        }

        if matches!(genesis, Genesis::Known(_)) && health.is_due(now, &endpoint.url) {
            let sent = endpoint.send(http, net, "GET", SYNCING_PATH, &JSON_HEADERS, &[]);
            health.sent(sent, &endpoint.url);
        }

        http.drive(net, |event| {
            let (http_id, answer) = match event {
                HttpEvent::Response { id: Some(id), response, .. } => (id, Ok(response)),
                HttpEvent::Failed { id, reason } => (id, Err(format!("{reason:?}"))),
                _ => return,
            };

            if matches!(*genesis, Genesis::InFlight(sent) if sent == http_id) {
                *genesis = on_genesis(answer, expected, &endpoint.url, now);
                return;
            }
            if health.owns(http_id) {
                let answer = answer.map(|response| (response.status, response.body));
                return health.on_answer(answer, &endpoint.url);
            }

            let Some(at) = in_flight.iter().position(|sent| sent.http_id == http_id) else {
                return;
            };
            let InFlight { id, request, .. } = in_flight.swap_remove(at);
            match answer {
                Ok(response) if response.status == 200 => on_event(request.answered(id, &response)),
                Ok(HttpResponse { status, .. }) => {
                    silver_log::warn!(?request, status, "beacon node request refused");
                    on_event(BeaconEvent::Failed { id, request });
                }
                Err(error) => {
                    silver_log::warn!(?request, error, "beacon node request failed");
                    on_event(BeaconEvent::Failed { id, request });
                }
            }
        });

        drive_head_stream(head_stream, endpoint, health, net, on_event);
    }
}

/// Opens once the node is first healthy; its heads count only while it stays
/// healthy.
fn drive_head_stream(
    head_stream: &mut Option<HeadStream>,
    endpoint: &HttpEndpoint,
    health: &HealthCheck,
    net: &mut NetworkCore,
    mut on_event: impl FnMut(BeaconEvent<'_>),
) {
    let healthy = health.is_healthy();
    if head_stream.is_none() {
        let (Some(addr), true) = (endpoint.addr(), healthy) else { return };
        let stream = HeadStream::open(net, addr, endpoint.authority(), endpoint.tls_host());
        *head_stream = Some(stream);
    }
    let stream = head_stream.as_mut().expect("opened above");
    stream.drive(net, &endpoint.url, |head| {
        if healthy {
            on_event(BeaconEvent::Head(head));
        }
    });
}

fn on_genesis(
    answer: Result<HttpResponse<'_>, String>,
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
        Err(error) => {
            silver_log::warn!(url, error, "beacon node genesis failed");
            return retry;
        }
    };
    match expected.check(body) {
        Ok(chain) => {
            silver_log::info!(
                url,
                genesis_time = chain.genesis_time,
                genesis_validators_root = %hex::encode(chain.genesis_validators_root),
                "beacon node compatible"
            );
            Genesis::Known(chain)
        }
        Err(reason) => {
            silver_log::error!(url, reason, "beacon node incompatible");
            Genesis::Incompatible
        }
    }
}
