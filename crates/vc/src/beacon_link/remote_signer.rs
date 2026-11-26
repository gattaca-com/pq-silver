use flux::timing::{Duration, Instant};
use flux_dns::Resolver;
use flux_network::{
    NetworkCore, NetworkEvent,
    http::{HttpEvent, HttpNetwork, HttpResponse, RequestId as HttpRequestId},
};
use silver_common::Error;

use crate::beacon_link::{
    endpoint::{HttpEndpoint, JSON_HEADERS},
    events::{BeaconEvent, SignerKeys},
    requests::{BeaconRequest, RequestId},
};

const KEYS_PATH: &str = "/api/v1/eth2/publicKeys";
/// web3signer signs one key per request, so a duty's signatures go out in
/// parallel over this many connections.
const SIGNER_CONNECTIONS: usize = 8;
const REQUEST_TIMEOUT_SECS: u64 = 5;
const LISTING_RETRY_SECS: u64 = 2;
/// A request to an unreachable signer waits rather than failing, so silence
/// is reported at this pace instead.
const UNANSWERED_WARNING_SECS: u64 = 10;
/// web3signer's answer when its slashing protection refuses to sign.
const SLASHING_REFUSAL: u16 = 412;

enum Listing {
    Due(Instant),
    InFlight(HttpRequestId),
    Done,
}

struct InFlight {
    http_id: HttpRequestId,
    id: RequestId,
    request: BeaconRequest,
}

pub struct RemoteSigner {
    http: HttpNetwork,
    dns: Resolver,
    endpoint: HttpEndpoint,
    listing: Listing,
    unanswered_warning_at: Instant,
    in_flight: Vec<InFlight>,
}

impl RemoteSigner {
    pub fn new(url: &str) -> Result<Self, Error> {
        let now = Instant::now();
        Ok(Self {
            http: HttpNetwork::default()
                .with_request_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS)),
            dns: Resolver::system()?,
            endpoint: HttpEndpoint::parse("web3signer", url)?,
            listing: Listing::Due(now),
            unanswered_warning_at: now + Duration::from_secs(UNANSWERED_WARNING_SECS),
            in_flight: Vec::new(),
        })
    }

    pub fn on_event(&mut self, event: &NetworkEvent<'_>) -> bool {
        self.http.on_event(event)
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
        let endpoint = &self.endpoint;
        match endpoint.send(&mut self.http, net, request.method(), path, &JSON_HEADERS, body) {
            Some(http_id) => self.in_flight.push(InFlight { http_id, id, request }),
            None => {
                silver_log::warn!(path, "web3signer request not sent");
                on_event(BeaconEvent::Failed { id, request });
            }
        }
    }

    pub fn drive(&mut self, net: &mut NetworkCore, mut on_event: impl FnMut(BeaconEvent<'_>)) {
        let now = Instant::now();
        let Self { http, dns, endpoint, listing, unanswered_warning_at, in_flight } = self;

        if endpoint.wants_resolving(now) {
            if let Err(e) = dns.query(0, &endpoint.host) {
                silver_log::warn!(url = %endpoint.url, %e, "web3signer lookup not sent");
            }
        }
        dns.poll(|_, addrs| endpoint.resolved(http, net, addrs, SIGNER_CONNECTIONS));

        if let Listing::Due(at) = *listing &&
            at <= now &&
            endpoint.is_pooled()
        {
            *listing = match endpoint.send(http, net, "GET", KEYS_PATH, &JSON_HEADERS, &[]) {
                Some(http_id) => Listing::InFlight(http_id),
                None => Listing::Due(now + Duration::from_secs(LISTING_RETRY_SECS)),
            };
        }
        if !matches!(listing, Listing::Done) && *unanswered_warning_at <= now {
            *unanswered_warning_at = now + Duration::from_secs(UNANSWERED_WARNING_SECS);
            silver_log::warn!(url = %endpoint.url, "web3signer has not listed its keys");
        }

        http.drive(net, |event| {
            let (http_id, answer) = match event {
                HttpEvent::Response { id: Some(id), response, .. } => (id, Ok(response)),
                HttpEvent::Failed { id, reason } => (id, Err(format!("{reason:?}"))),
                _ => return,
            };

            if matches!(*listing, Listing::InFlight(sent) if sent == http_id) {
                *listing = match answer {
                    Ok(HttpResponse { status: 200, body, .. }) => {
                        on_event(BeaconEvent::SignerKeys(SignerKeys(body)));
                        Listing::Done
                    }
                    Ok(HttpResponse { status, .. }) => {
                        silver_log::warn!(url = %endpoint.url, status, "web3signer key listing refused");
                        Listing::Due(now + Duration::from_secs(LISTING_RETRY_SECS))
                    }
                    Err(error) => {
                        silver_log::warn!(url = %endpoint.url, error, "web3signer key listing failed");
                        Listing::Due(now + Duration::from_secs(LISTING_RETRY_SECS))
                    }
                };
                return;
            }

            let Some(at) = in_flight.iter().position(|sent| sent.http_id == http_id) else {
                return;
            };
            let InFlight { id, request, .. } = in_flight.swap_remove(at);
            on_event(match answer {
                Ok(response) if response.status == 200 => request.answered(id, &response),
                Ok(response) if response.status == SLASHING_REFUSAL => {
                    silver_log::warn!(?request, "web3signer refused: slashing protection");
                    BeaconEvent::Failed { id, request }
                }
                Ok(HttpResponse { status, .. }) => {
                    silver_log::warn!(?request, status, "web3signer request refused");
                    BeaconEvent::Failed { id, request }
                }
                Err(error) => {
                    silver_log::warn!(?request, error, "web3signer request failed");
                    BeaconEvent::Failed { id, request }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use flux_network::Network;
    use silver_common::ssz_view::AttestationDataView;

    use super::*;
    use crate::beacon_link::{
        requests::{BeaconRequests, ForkInfo, SignPurpose, tests::attestation_data_ssz},
        stub_server::stub_node,
    };

    const PUBKEY: [u8; 48] = [0xaa; 48];

    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Keys(Vec<[u8; 48]>),
        Signed(RequestId, [u8; 96]),
        Failed(RequestId),
    }

    /// Lists keys, then signs once for `PUBKEY`, collecting what comes back.
    fn run(routes: Vec<(&'static str, String)>) -> Vec<Seen> {
        let mut signer = RemoteSigner::new(&stub_node(routes)).unwrap();
        let mut net = Network::default();
        let mut requests = BeaconRequests::default();
        let data = attestation_data_ssz();
        let fork_info = ForkInfo {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: 0,
            genesis_validators_root: [0; 32],
        };
        let body = requests.attestation_sign_body(
            &fork_info,
            &[0x5a; 32],
            AttestationDataView::new(&data),
        );
        requests.sign(&PUBKEY, &body, SignPurpose::Attestation);

        let mut seen = Vec::new();
        let mut on_event = |event: BeaconEvent<'_>| {
            seen.push(match event {
                BeaconEvent::SignerKeys(keys) => {
                    let mut listed = Vec::new();
                    keys.for_each(4, |pubkey| listed.push(*pubkey)).unwrap();
                    Seen::Keys(listed)
                }
                BeaconEvent::Signed { id, signature, .. } => Seen::Signed(id, signature),
                BeaconEvent::Failed { id, .. } => Seen::Failed(id),
                _ => unreachable!("only signer events"),
            })
        };
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        while StdInstant::now() < deadline {
            net.poll_with(|event| {
                signer.on_event(&event);
            });
            signer.drive(&mut net, &mut on_event);
            if signer.endpoint.is_pooled() {
                requests.drain(|id, request, path, body| {
                    signer.send(&mut net, id, request, path, body, &mut on_event)
                });
            }
            if matches!(signer.listing, Listing::Done) && signer.in_flight.is_empty() {
                break;
            }
        }
        seen
    }

    fn sign_path() -> &'static str {
        format!("/api/v1/eth2/sign/0x{}", hex::encode(PUBKEY)).leak()
    }

    #[test]
    fn keys_are_listed_and_signatures_come_back() {
        let keys = format!(r#"["0x{}"]"#, hex::encode(PUBKEY));
        let signature = format!(r#"{{"signature":"0x{}"}}"#, "c1".repeat(96));
        let seen = run(vec![(KEYS_PATH, keys), (sign_path(), signature)]);
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&Seen::Keys(vec![PUBKEY])));
        assert!(
            seen.iter()
                .any(|seen| matches!(seen, Seen::Signed(_, signature) if *signature == [0xc1; 96]))
        );
    }

    #[test]
    fn refused_or_malformed_signatures_fail() {
        let keys = format!(r#"["0x{}"]"#, hex::encode(PUBKEY));
        let refused = run(vec![(KEYS_PATH, keys.clone())]);
        assert!(refused.iter().any(|seen| matches!(seen, Seen::Failed(_))));

        let malformed = run(vec![(KEYS_PATH, keys), (sign_path(), "0xc1".into())]);
        assert!(malformed.iter().any(|seen| matches!(seen, Seen::Failed(_))));
    }
}
