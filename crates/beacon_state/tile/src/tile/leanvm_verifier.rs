use flux::{Timer, spine::SpineProducers};
use silver_common::{LeanVmReq, LeanVmResp, Nanos, TCacheProducer, TCacheReader, TProducer};

use crate::tile::{
    Producers,
    pq_aggregation::{
        Claim,
        wire::{VerifyRequest, decode_verify_response},
    },
};

/// Set in every verify request's id, so its response is told apart from an
/// aggregation's, whose ids count up from 0.
const VERIFY_ID_BIT: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerdict {
    Valid,
    Invalid,
    /// The leanVM sidecar did not judge the proof: it was down, the request
    /// or its response did not fit or lapped in a tcache, or it refused the
    /// request.
    Unanswered,
}

/// Verify requests to the leanVM sidecar. Each is answered once, through
/// [`Self::verdict`], under the id [`Self::send`] returned; the caller keeps
/// what waits on it.
pub struct LeanVmVerifier {
    sent: u64,
    claims: Vec<Claim>,
    /// Each request awaiting its answer, and when it went out.
    in_flight: Vec<(u64, Nanos)>,
    round_trip: Timer,
}

impl Default for LeanVmVerifier {
    fn default() -> Self {
        Self {
            sent: 0,
            claims: Vec::new(),
            in_flight: Vec::new(),
            round_trip: Timer::new("silver", "leanvm_verify"),
        }
    }
}

impl LeanVmVerifier {
    /// Asks whether `proof` proves exactly the set of `claims`. `None` when
    /// the tcache has no room for the request.
    pub fn send(
        &mut self,
        claims: impl IntoIterator<Item = Claim>,
        proof: &[u8],
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) -> Option<u64> {
        self.claims.clear();
        self.claims.extend(claims);
        self.claims.sort_unstable();
        self.claims.dedup();
        debug_assert!(!self.claims.is_empty(), "leanVM has nothing to check against");
        let request = VerifyRequest { claims: &self.claims, proof };
        let Some(body) = tcache.write_with(request.len(), |out| request.write(out)) else {
            silver_log::error!(len = request.len(), "beacon_state tcache full; verify not sent");
            return None;
        };
        let request_id = self.next_request_id();
        self.sent += 1;
        self.in_flight.push((request_id, Nanos::now()));
        producers.produce(LeanVmReq { request_id, body });
        Some(request_id)
    }

    /// Ids go out in order, so the requests sent between two calls form a
    /// range.
    pub fn next_request_id(&self) -> u64 {
        VERIFY_ID_BIT | self.sent
    }

    /// The verdict `resp` carries, if it answers a verify request.
    pub fn verdict(
        &mut self,
        resp: &LeanVmResp,
        reader: &mut TCacheReader,
    ) -> Option<ProofVerdict> {
        if resp.request_id & VERIFY_ID_BIT == 0 {
            return None;
        }
        if let Some(at) = self.in_flight.iter().position(|&(id, _)| id == resp.request_id) {
            let (_, sent) = self.in_flight.swap_remove(at);
            if resp.body.is_some() {
                self.round_trip.emit_latency_from_nanos(sent, Nanos::now());
            }
        }
        let Some(body) = resp.body else { return Some(ProofVerdict::Unanswered) };
        let acquired = reader.acquire(body);
        let verdict = acquired.buffer().ok().map(|(body, _)| decode_verify_response(body));
        // A lapping writer could tear the bytes into a different verdict.
        let Some(verdict) = verdict.filter(|_| acquired.revalidate().is_ok()) else {
            silver_log::error!(request_id = resp.request_id, "leanvm verify response unreadable");
            return Some(ProofVerdict::Unanswered);
        };
        Some(verdict)
    }
}
