use flux::spine::SpineProducers;
use silver_common::{LeanVmReq, LeanVmResp, TCacheProducer, TCacheReader, TProducer};

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
#[derive(Default)]
pub struct LeanVmVerifier {
    sent: u64,
}

impl LeanVmVerifier {
    /// Asks whether `proof` proves exactly `claims`. `None` when the tcache
    /// has no room for the request.
    pub fn send(
        &mut self,
        claims: &[Claim],
        proof: &[u8],
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) -> Option<u64> {
        debug_assert!(claims.is_sorted_by(|a, b| a < b), "a proof's claims are strictly sorted");
        let request = VerifyRequest { claims, proof };
        let Some(body) = tcache.write_with(request.len(), |out| request.write(out)) else {
            silver_log::error!(len = request.len(), "beacon_state tcache full; verify not sent");
            return None;
        };
        let request_id = VERIFY_ID_BIT | self.sent;
        self.sent += 1;
        producers.produce(LeanVmReq { request_id, body });
        Some(request_id)
    }

    /// The verdict `resp` carries, if it answers a verify request.
    pub fn verdict(resp: &LeanVmResp, reader: &mut TCacheReader) -> Option<ProofVerdict> {
        if resp.request_id & VERIFY_ID_BIT == 0 {
            return None;
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
