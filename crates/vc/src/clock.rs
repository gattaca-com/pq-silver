use std::time::{SystemTime, UNIX_EPOCH};

use silver_beacon_state_data::AGGREGATORS_PER_COMMITTEE;
use silver_common::ticker::{
    AGGREGATE_DUE_BPS_PQ, AGGREGATOR_DELAY_BPS, ATTESTATION_DUE_BPS_GLOAS, BASIS_POINTS,
    PAYLOAD_ATTESTATION_DUE_BPS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DutyPhase {
    SlotStart,
    AttestationDue,
    /// Spec `get_aggregate_due_ms(position)`.
    AggregateDue {
        position: u8,
    },
    PayloadAttestationDue,
}

impl DutyPhase {
    const ORDER: [Self; 3 + AGGREGATORS_PER_COMMITTEE] = [
        Self::SlotStart,
        Self::AttestationDue,
        Self::AggregateDue { position: 0 },
        Self::AggregateDue { position: 1 },
        Self::AggregateDue { position: 2 },
        Self::AggregateDue { position: 3 },
        Self::PayloadAttestationDue,
    ];

    fn offset_bps(self) -> u64 {
        match self {
            Self::SlotStart => 0,
            Self::AttestationDue => ATTESTATION_DUE_BPS_GLOAS,
            Self::AggregateDue { position } => {
                AGGREGATE_DUE_BPS_PQ + u64::from(position) * AGGREGATOR_DELAY_BPS
            }
            Self::PayloadAttestationDue => PAYLOAD_ATTESTATION_DUE_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick {
    pub slot: u64,
    pub phase: DutyPhase,
}

/// Emits each slot's phases once, in order, from the wall clock.
pub struct DutyClock {
    genesis_ms: u64,
    slot_ms: u64,
    /// The last emitted slot and its index into `DutyPhase::ORDER`.
    last: Option<(u64, usize)>,
}

impl DutyClock {
    /// None before genesis.
    pub fn start(genesis_time: u64, slot_ms: u64) -> Option<Self> {
        let clock = Self { genesis_ms: genesis_time * 1000, slot_ms, last: None };
        clock.millis_since_genesis().map(|_| clock)
    }

    pub fn current_slot(&self) -> u64 {
        self.millis_since_genesis().unwrap_or(0) / self.slot_ms
    }

    /// A missed phase is skipped, except the slot start, which a new slot
    /// always emits first.
    pub fn tick(&mut self) -> Option<Tick> {
        let ms = self.millis_since_genesis()?;
        let (slot, into) = (ms / self.slot_ms, ms % self.slot_ms);
        let passed = |phase: &DutyPhase| self.slot_ms * phase.offset_bps() / BASIS_POINTS <= into;

        match self.last {
            Some((last, _)) if last > slot => None,
            Some((last, index)) if last == slot => {
                let phase = *DutyPhase::ORDER.get(index + 1).filter(|phase| passed(phase))?;
                self.last = Some((slot, index + 1));
                Some(Tick { slot, phase })
            }
            _ => {
                let consumed = DutyPhase::ORDER[1..].iter().take_while(|phase| passed(phase));
                self.last = Some((slot, consumed.count()));
                Some(Tick { slot, phase: DutyPhase::SlotStart })
            }
        }
    }

    fn millis_since_genesis(&self) -> Option<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after unix epoch");
        (now.as_millis() as u64).checked_sub(self.genesis_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock_at(ms_into_chain: u64) -> DutyClock {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let genesis_secs = (now - ms_into_chain).div_ceil(1000);
        DutyClock::start(genesis_secs, 12_000).unwrap()
    }

    #[test]
    fn a_new_slot_starts_first_and_skips_passed_phases() {
        let mut clock = clock_at(100 * 12_000 + 10_500);
        let slot = clock.current_slot();
        assert_eq!(clock.tick(), Some(Tick { slot, phase: DutyPhase::SlotStart }));
        assert_eq!(clock.tick(), None, "every later phase already passed");
    }

    #[test]
    fn phases_are_in_slot_order() {
        let offsets = DutyPhase::ORDER.map(DutyPhase::offset_bps);
        assert!(offsets.is_sorted(), "{offsets:?}");
        assert_eq!(offsets[2..6], [6000, 6500, 7000, 7500], "spec's 7.2s to 9.0s of 12s");
    }

    #[test]
    fn not_started_before_genesis() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(DutyClock::start(now + 60, 12_000).is_none());
    }
}
