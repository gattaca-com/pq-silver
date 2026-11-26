use flux::timing::{Duration, Instant};
use flux_network::http::RequestId;
use serde::Deserialize;

pub const SYNCING_PATH: &str = "/eth/v1/node/syncing";

#[derive(Deserialize)]
struct SyncingBody {
    data: Syncing,
}

/// An optimistic node must not be attested or proposed on, so it counts as
/// syncing.
#[derive(Deserialize)]
struct Syncing {
    is_syncing: bool,
    #[serde(default)]
    is_optimistic: bool,
}

pub struct HealthCheck {
    interval: Duration,
    due: Instant,
    in_flight: Option<RequestId>,
    /// `None` until the first verdict.
    healthy: Option<bool>,
}

impl HealthCheck {
    pub fn new(interval: Duration, now: Instant) -> Self {
        Self { interval, due: now, in_flight: None, healthy: None }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy == Some(true)
    }

    /// A check still unanswered when the next falls due marks the node
    /// unhealthy: flux never times out a request to an unreachable node.
    pub fn is_due(&mut self, now: Instant, url: &str) -> bool {
        if now < self.due {
            return false;
        }
        self.due = now + self.interval;
        if self.in_flight.is_some() {
            self.judge(Err("no answer within a slot"), url);
            return false;
        }
        true
    }

    pub fn sent(&mut self, id: Option<RequestId>, url: &str) {
        self.in_flight = id;
        if id.is_none() {
            self.judge(Err("check not sent"), url);
        }
    }

    pub fn owns(&self, id: RequestId) -> bool {
        self.in_flight == Some(id)
    }

    /// `None` when the check got no answer.
    pub fn on_answer(&mut self, answer: Option<(u16, &[u8])>, url: &str) {
        self.in_flight = None;
        let verdict = match answer {
            Some((200, body)) => match serde_json::from_slice::<SyncingBody>(body) {
                Ok(SyncingBody { data: Syncing { is_syncing: true, .. } }) => Err("syncing"),
                Ok(SyncingBody { data: Syncing { is_optimistic: true, .. } }) => Err("optimistic"),
                Ok(_) => Ok(()),
                Err(_) => Err("malformed syncing answer"),
            },
            Some(_) => Err("syncing check refused"),
            None => Err("syncing check failed"),
        };
        self.judge(verdict, url);
    }

    fn judge(&mut self, verdict: Result<(), &str>, url: &str) {
        let healthy = verdict.is_ok();
        if self.healthy == Some(healthy) {
            return;
        }
        self.healthy = Some(healthy);
        match verdict {
            Ok(()) => silver_log::info!(url, "beacon node healthy"),
            Err(reason) => silver_log::warn!(url, reason, "beacon node unhealthy"),
        }
    }

    #[cfg(test)]
    pub fn is_judged(&self) -> bool {
        self.healthy.is_some()
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::SocketAddr;

    use flux_network::{Network, http::HttpNetwork};

    use super::*;

    pub fn syncing_json(is_syncing: bool, is_optimistic: bool) -> String {
        format!(
            r#"{{"data":{{"head_slot":"100","sync_distance":"0","is_syncing":{is_syncing},"is_optimistic":{is_optimistic},"el_offline":false}}}}"#
        )
    }

    const URL: &str = "http://bn:5052";
    const SLOT_SECS: u64 = 12;

    /// Ids of requests queued on a pool that never connects.
    fn request_ids() -> impl FnMut() -> RequestId {
        let mut net = Network::default();
        let mut http = HttpNetwork::default();
        let pool = http.pool(&mut net, SocketAddr::from(([127, 0, 0, 1], 1)), 1);
        move || http.send(&mut net, pool, "GET", SYNCING_PATH, &[], &[], 0).unwrap()
    }

    fn answered(check: &mut HealthCheck, answer: Option<(u16, &[u8])>) -> bool {
        check.on_answer(answer, URL);
        check.is_healthy()
    }

    #[test]
    fn synced_answer_is_healthy_and_anything_else_is_not() {
        let mut check = HealthCheck::new(Duration::from_secs(SLOT_SECS), Instant::now());
        assert!(!check.is_healthy());

        let synced = syncing_json(false, false);
        assert!(answered(&mut check, Some((200, synced.as_bytes()))));
        let syncing = syncing_json(true, false);
        assert!(!answered(&mut check, Some((200, syncing.as_bytes()))));
        assert!(answered(&mut check, Some((200, synced.as_bytes()))));
        let optimistic = syncing_json(false, true);
        assert!(!answered(&mut check, Some((200, optimistic.as_bytes()))));
        assert!(answered(&mut check, Some((200, br#"{"data":{"is_syncing":false}}"#))));
        assert!(!answered(&mut check, Some((503, synced.as_bytes()))));
        assert!(answered(&mut check, Some((200, synced.as_bytes()))));
        assert!(!answered(&mut check, Some((200, b"{}"))));
        assert!(answered(&mut check, Some((200, synced.as_bytes()))));
        assert!(!answered(&mut check, None));
    }

    #[test]
    fn checks_fall_due_once_per_interval() {
        let start = Instant::now();
        let mut next_id = request_ids();
        let mut check = HealthCheck::new(Duration::from_secs(SLOT_SECS), start);
        assert!(check.is_due(start, URL));
        let id = next_id();
        check.sent(Some(id), URL);
        assert!(check.owns(id) && !check.owns(next_id()));
        check.on_answer(Some((200, syncing_json(false, false).as_bytes())), URL);

        assert!(!check.is_due(start + Duration::from_secs(SLOT_SECS / 2), URL));
        assert!(check.is_due(start + Duration::from_secs(SLOT_SECS), URL));
    }

    #[test]
    fn node_going_silent_turns_unhealthy_at_the_next_check() {
        let start = Instant::now();
        let mut next_id = request_ids();
        let mut check = HealthCheck::new(Duration::from_secs(SLOT_SECS), start);
        assert!(check.is_due(start, URL));
        check.sent(Some(next_id()), URL);
        check.on_answer(Some((200, syncing_json(false, false).as_bytes())), URL);

        assert!(check.is_due(start + Duration::from_secs(SLOT_SECS), URL));
        check.sent(Some(next_id()), URL);
        assert!(check.is_healthy());
        assert!(!check.is_due(start + Duration::from_secs(2 * SLOT_SECS), URL));
        assert!(!check.is_healthy());

        check.on_answer(Some((200, syncing_json(false, false).as_bytes())), URL);
        assert!(check.is_healthy());
        assert!(check.is_due(start + Duration::from_secs(3 * SLOT_SECS), URL));
    }

    #[test]
    fn unsendable_check_is_unhealthy() {
        let mut check = HealthCheck::new(Duration::from_secs(SLOT_SECS), Instant::now());
        check.sent(None, URL);
        assert!(check.is_judged() && !check.is_healthy());
    }
}
