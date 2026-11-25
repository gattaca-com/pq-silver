use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

use flux::{
    communication::{
        queue::{Consumer, Queue},
        timer::TimingMessage,
    },
    timing::Nanos,
};
use silver_observe::TimingFile;
use silver_stages::SlotClock;

pub const ARRIVAL_TIMER: &str = "pq_attestation_arrival";
pub const RELAYED_PUBLISH_TIMER: &str = "attestation_publish_relayed";
pub const LOCAL_PUBLISH_TIMER: &str = "attestation_publish_local";
pub const BIN_MS: u64 = 100;
const SLOT_HISTORY_LEN: usize = 64;

/// Arrival counts by time into the slot voted in.
#[derive(Clone)]
pub struct Arrivals {
    /// One per `BIN_MS` of the slot.
    pub bins: Vec<u32>,
    /// After the slot ended.
    pub late: u32,
}

impl Arrivals {
    fn new(bins: usize) -> Self {
        Self { bins: vec![0; bins], late: 0 }
    }

    fn record(&mut self, offset: Nanos) {
        let bin = (offset.0 / Nanos::from_millis(BIN_MS).0) as usize;
        match self.bins.get_mut(bin) {
            Some(count) => *count += 1,
            None => self.late += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.bins.iter().sum::<u32>() + self.late
    }
}

pub struct SlotArrivals {
    pub slot: u64,
    pub arrivals: Arrivals,
}

/// Votes by slot, from one time-into-slot latency queue. A sample carries only
/// its time into the slot, so the slot is the one that started that long
/// before the sample was read.
pub struct AttestationArrivals {
    timer: &'static str,
    clock: SlotClock,
    consumer: Option<Consumer<TimingMessage>>,
    /// Ascending by slot.
    slots: VecDeque<SlotArrivals>,
    /// Every arrival since surfer attached.
    pub all: Arrivals,
}

impl AttestationArrivals {
    pub fn new(clock: SlotClock, timer: &'static str) -> Self {
        let bins = (clock.slot_duration().0 / Nanos::from_millis(BIN_MS).0) as usize;
        Self { timer, clock, consumer: None, slots: VecDeque::new(), all: Arrivals::new(bins) }
    }

    /// Opens the queue once the node has created it.
    pub fn attach(&mut self, timings: &[TimingFile]) {
        if self.consumer.is_some() {
            return;
        }
        let Some(file) = timings.iter().find(|file| file.name == self.timer) else { return };
        if let Ok(queue) = Queue::<TimingMessage>::try_open_shared(&file.path) {
            self.consumer = Some(Consumer::new(queue, "surfer-attestation-arrivals").without_log());
        }
    }

    pub fn drain(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        self.drain_at(Nanos(now.as_nanos() as u64));
    }

    fn drain_at(&mut self, now: Nanos) {
        let Self { clock, consumer, slots, all, .. } = self;
        let Some(consumer) = consumer else { return };
        // Reading lags arrival by far less than half a slot.
        let half_slot = Nanos(clock.slot_duration().0 / 2);
        while consumer.consume(|msg| {
            if !msg.is_valid() {
                return;
            }
            let offset = Nanos::from(msg.elapsed());
            let slot = clock.slot_at(now.saturating_sub(offset) + half_slot);
            let at = slots.partition_point(|held| held.slot < slot);
            if slots.get(at).is_none_or(|held| held.slot != slot) {
                slots.insert(at, SlotArrivals { slot, arrivals: Arrivals::new(all.bins.len()) });
            }
            slots[at].arrivals.record(offset);
            all.record(offset);
            if slots.len() > SLOT_HISTORY_LEN {
                slots.pop_front();
            }
        }) {}
    }

    pub fn slots(&self) -> &VecDeque<SlotArrivals> {
        &self.slots
    }

    pub fn slot(&self, slot: u64) -> Option<&Arrivals> {
        self.slots.iter().find(|held| held.slot == slot).map(|held| &held.arrivals)
    }
}

#[cfg(test)]
mod tests {
    use flux::{
        communication::queue::{Producer, QueueType},
        timing::{Duration, Instant},
    };

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;

    fn sample(offset_ms: u64) -> TimingMessage {
        let ticks = Duration::from(Nanos::from_millis(offset_ms));
        TimingMessage { start_t: Instant(0), stop_t: Instant(ticks.0) }
    }

    #[test]
    fn a_sample_lands_in_the_slot_that_started_its_offset_before_the_read() {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let queue: Queue<TimingMessage> = Queue::new(8, QueueType::SPMC);
        let mut producer = Producer::from(queue);
        let mut arrivals = AttestationArrivals::new(clock, ARRIVAL_TIMER);
        arrivals.consumer = Some(Consumer::new(queue, "arrivals-test").without_log());
        let read_at = |slot, ms| clock.slot_start(slot) + Nanos::from_millis(ms);
        arrivals.drain_at(read_at(5, 0));

        producer.produce(&sample(3_250));
        arrivals.drain_at(read_at(5, 3_330));
        // A vote for slot 5 that arrives 1 s into slot 6.
        producer.produce(&sample(13_000));
        arrivals.drain_at(read_at(6, 1_050));

        let slot = arrivals.slot(5).expect("both samples are for slot 5");
        assert_eq!(slot.bins[32], 1);
        assert_eq!((slot.late, slot.total()), (1, 2));
        assert_eq!(arrivals.slots().len(), 1);
        assert_eq!(arrivals.all.total(), 2);
    }
}
