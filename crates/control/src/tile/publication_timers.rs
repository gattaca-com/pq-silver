use flux::Timer;
use silver_common::{LOCAL_GOSSIP_STREAM_ID, Nanos, P2pStreamId, ticker::SlotTicker};

/// When attestations are handed to the mesh, as time into the wall slot: a
/// vote sent after its own slot ended wraps into the next one.
pub(super) struct PublicationTimers {
    relayed: Timer,
    local: Timer,
}

impl PublicationTimers {
    pub(super) fn new() -> Self {
        Self {
            relayed: Timer::new("silver", "attestation_publish_relayed"),
            local: Timer::new("silver", "attestation_publish_local"),
        }
    }

    pub(super) fn attestation(&mut self, originator: P2pStreamId, ticker: &SlotTicker) {
        let now = ticker.since_genesis();
        let slot = Nanos::from_millis(ticker.slot_duration().as_millis() as u64);
        let slot_start = Nanos(now.0 - now.0 % slot.0);
        let timer =
            if originator == LOCAL_GOSSIP_STREAM_ID { &mut self.local } else { &mut self.relayed };
        timer.emit_latency_from_nanos(slot_start, now);
    }
}
