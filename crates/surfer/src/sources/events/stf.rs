use silver_common::{Nanos, StfGate};

use super::trace::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StfSpan {
    /// Start of CL validation → fork-choice import or rejection.
    Root,
    Validate,
    /// Validated → post-state committed.
    Apply,
    /// Post-state committed → import, while the block is held on its data
    /// columns.
    DaWait,
    /// Post-state committed → leanVM's verdict on the block's attestation
    /// proof; an instant when the block had nothing to send.
    PqVerify,
}

#[derive(Default)]
pub struct StateTransition {
    validated: Option<Nanos>,
    done: Option<(Nanos, StfGate)>,
    attestable: Option<Nanos>,
    rejected: Option<Nanos>,
}

impl StateTransition {
    pub(super) fn validated(&mut self, ts: Nanos) {
        self.validated.get_or_insert(ts);
    }

    pub(super) fn done(&mut self, ts: Nanos, gate: StfGate) {
        self.done.get_or_insert((ts, gate));
    }

    pub(super) fn attestable(&mut self, ts: Nanos) {
        self.attestable.get_or_insert(ts);
    }

    pub(super) fn rejected(&mut self, ts: Nanos) {
        self.rejected.get_or_insert(ts);
    }

    pub fn validated_at(&self) -> Option<Nanos> {
        self.validated
    }

    pub fn attestable_at(&self) -> Option<Nanos> {
        self.attestable
    }

    pub fn gate(&self) -> Option<StfGate> {
        self.done.map(|(_, gate)| gate)
    }

    pub fn is_rejected(&self) -> bool {
        self.rejected.is_some()
    }

    pub fn end(&self) -> Option<Nanos> {
        self.attestable.or(self.rejected)
    }

    /// The wait row the gate opens, if any.
    pub fn wait_span(&self) -> Option<StfSpan> {
        match self.gate()? {
            StfGate::Now => None,
            StfGate::Data => Some(StfSpan::DaWait),
            StfGate::Verify | StfGate::NoAttestations | StfGate::OwnBlock => {
                Some(StfSpan::PqVerify)
            }
        }
    }

    /// A PQ block leanVM never saw: its verify row is the import instant.
    pub fn verify_skipped(&self) -> bool {
        matches!(self.gate(), Some(StfGate::NoAttestations | StfGate::OwnBlock))
    }

    /// `Validated` and `StfDone` come from one announcement, so a validated
    /// block always has its post-state.
    pub fn interval(&self, span: StfSpan, validate_from: Option<Nanos>) -> Option<Interval> {
        let done = self.done.map(|(ts, _)| ts);
        let (start, end) = match span {
            StfSpan::Root => (validate_from.or(self.validated)?, self.end().or(done)?),
            StfSpan::Validate => (validate_from?, self.validated?),
            StfSpan::Apply => (self.validated?, done?),
            StfSpan::DaWait | StfSpan::PqVerify => (done?, self.end()?),
        };
        Some(Interval { start, end: end.max(start) })
    }
}
