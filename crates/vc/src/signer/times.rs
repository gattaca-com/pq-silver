use std::time::Duration;

use silver_common::vc_spine::{SignPurpose, SignRequest};

/// A signature in a prepared tree takes ~18 ms on one core; one this slow
/// most likely built its bottom tree first.
const SLOW: Duration = Duration::from_millis(200);
const KINDS: [&str; 7] = [
    "attestation",
    "aggregate",
    "payload attestation",
    "proposer preferences",
    "RANDAO reveal",
    "block",
    "envelope",
];

#[derive(Clone, Copy, Default)]
struct Kind {
    count: u32,
    took: Duration,
    longest: Duration,
    longest_wait: Duration,
}

/// Each slot's signing work, by kind, logged once the slot ends: a starved
/// host shows as long waits for a free signer.
#[derive(Default)]
pub struct SigningTimes {
    slot: u64,
    kinds: [Kind; KINDS.len()],
}

impl SigningTimes {
    pub fn answered(&mut self, request: &SignRequest, waited: Duration, took: Duration) {
        let index = kind_index(&request.purpose);
        // A reveal's first proof builds its VRF tree, which logs on its own.
        let xmss = !matches!(request.purpose, SignPurpose::Randao { .. });
        if xmss && took > SLOW {
            let ms = took.as_millis() as u64;
            silver_log::warn!(slot = request.slot, kind = KINDS[index], ms, "slow signature");
        }
        let kind = &mut self.kinds[index];
        kind.count += 1;
        kind.took += took;
        kind.longest = kind.longest.max(took);
        kind.longest_wait = kind.longest_wait.max(waited);
    }

    /// Logs the slot that ended, once the wall clock reaches `slot`.
    pub fn slot_started(&mut self, slot: u64) {
        if slot == self.slot {
            return;
        }
        for (name, kind) in KINDS.iter().zip(&self.kinds).filter(|(_, kind)| kind.count > 0) {
            silver_log::info!(
                slot = self.slot,
                kind = *name,
                count = kind.count,
                avg_ms = (kind.took / kind.count).as_millis() as u64,
                max_ms = kind.longest.as_millis() as u64,
                max_wait_ms = kind.longest_wait.as_millis() as u64,
                "signed"
            );
        }
        *self = Self { slot, ..Self::default() };
    }

    #[cfg(test)]
    fn count(&self, kind: &str) -> u32 {
        self.kinds[KINDS.iter().position(|name| *name == kind).unwrap()].count
    }
}

fn kind_index(purpose: &SignPurpose) -> usize {
    match purpose {
        SignPurpose::Attestation { .. } => 0,
        SignPurpose::Aggregate { .. } => 1,
        SignPurpose::PayloadAttestation { .. } => 2,
        SignPurpose::ProposerPreferences { .. } => 3,
        SignPurpose::Randao { .. } => 4,
        SignPurpose::Block => 5,
        SignPurpose::Envelope => 6,
    }
}

#[cfg(test)]
mod tests {
    use silver_common::vc_spine::KeyWork;

    use super::*;

    #[test]
    fn a_slot_is_counted_by_kind_until_the_next_starts() {
        let request = |purpose| SignRequest {
            slot: 5,
            purpose,
            pubkey: [0; 32],
            work: KeyWork::Sign { leaf_index: 1, signing_root: [0; 32] },
        };
        let mut times = SigningTimes::default();
        times.slot_started(5);
        let attestation =
            request(SignPurpose::Attestation { validator_index: 1, committee_index: 0 });
        times.answered(&attestation, Duration::ZERO, Duration::from_millis(18));
        times.answered(&attestation, Duration::from_millis(3), Duration::from_millis(20));
        times.answered(&request(SignPurpose::Block), Duration::ZERO, Duration::from_millis(19));
        assert_eq!((times.count("attestation"), times.count("block")), (2, 1));
        times.slot_started(5);
        assert_eq!(times.count("attestation"), 2, "the same slot keeps counting");
        times.slot_started(6);
        assert_eq!((times.count("attestation"), times.slot), (0, 6));
    }
}
