use std::time::{SystemTime, UNIX_EPOCH};

use silver_chain_spec::SpecConfig;
use silver_common::{
    SLOTS_PER_EPOCH,
    ticker::{
        AGGREGATE_DUE_BPS, AGGREGATE_DUE_BPS_GLOAS, BASIS_POINTS, PAYLOAD_ATTESTATION_DUE_BPS,
        attestation_due_bps,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DutyPhase {
    SlotStart,
    AttestationDue,
    AggregateDue,
    PayloadAttestationDue,
}

impl DutyPhase {
    const ORDER: [Self; 4] =
        [Self::SlotStart, Self::AttestationDue, Self::AggregateDue, Self::PayloadAttestationDue];

    fn offset_bps(self, gloas: bool) -> u64 {
        match self {
            Self::SlotStart => 0,
            Self::AttestationDue => attestation_due_bps(gloas),
            Self::AggregateDue if gloas => AGGREGATE_DUE_BPS_GLOAS,
            Self::AggregateDue => AGGREGATE_DUE_BPS,
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
    gloas_fork_slot: u64,
    /// The last emitted slot and its index into `DutyPhase::ORDER`.
    last: Option<(u64, usize)>,
}

impl DutyClock {
    /// None before genesis.
    pub fn start(genesis_time: u64, spec: &SpecConfig) -> Option<Self> {
        let clock = Self {
            genesis_ms: genesis_time * 1000,
            slot_ms: spec.slot_duration_ms(),
            gloas_fork_slot: spec.gloas_fork_epoch.saturating_mul(SLOTS_PER_EPOCH),
            last: None,
        };
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
        let passed = |phase: &DutyPhase| self.offset_ms(*phase, slot) <= into;

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

    fn offset_ms(&self, phase: DutyPhase, slot: u64) -> u64 {
        self.slot_ms * phase.offset_bps(slot >= self.gloas_fork_slot) / BASIS_POINTS
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
        DutyClock::start(genesis_secs, &SpecConfig::mainnet()).unwrap()
    }

    #[test]
    fn a_new_slot_starts_first_and_skips_passed_phases() {
        let mut clock = clock_at(100 * 12_000 + 10_500);
        let slot = clock.current_slot();
        assert_eq!(clock.tick(), Some(Tick { slot, phase: DutyPhase::SlotStart }));
        assert_eq!(clock.tick(), None, "every later phase already passed");
    }

    #[test]
    fn not_started_before_genesis() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(DutyClock::start(now + 60, &SpecConfig::mainnet()).is_none());
    }
}
