use super::*;

const OPENS: Nanos = Nanos::from_secs(100);
const SPEC: Nanos = Nanos::from_secs(107);

fn read_early(tracker: &mut DeadlineTracker, early: Nanos) {
    tracker.record_read(SPEC, SPEC - early, OPENS);
}

#[test]
fn the_deadline_uses_the_earliest_read_in_the_window() {
    let mut tracker = DeadlineTracker::default();
    for early in [1_000, 200, 2_000] {
        read_early(&mut tracker, Nanos::from_millis(early));
    }
    assert_eq!(tracker.deadline(SPEC), SPEC - Nanos::from_secs(2));
}

#[test]
fn a_late_read_leaves_the_deadline_at_its_due_time() {
    let mut tracker = DeadlineTracker::default();
    tracker.record_read(SPEC, SPEC + Nanos::from_millis(300), OPENS);
    tracker.record_read(SPEC, SPEC, OPENS);
    assert_eq!(tracker.deadline(SPEC), SPEC);
}

#[test]
fn an_early_read_leaves_the_window_after_it_is_full() {
    let mut tracker = DeadlineTracker::default();
    read_early(&mut tracker, Nanos::from_millis(3_000));
    for _ in 0..WINDOW - 1 {
        read_early(&mut tracker, Nanos::from_millis(100));
    }
    assert_eq!(tracker.deadline(SPEC), SPEC - Nanos::from_secs(3));
    read_early(&mut tracker, Nanos::from_millis(100));
    assert_eq!(tracker.deadline(SPEC), SPEC - Nanos::from_millis(100));
}

#[test]
fn a_read_before_the_slot_opens_is_ignored() {
    let mut tracker = DeadlineTracker::default();
    tracker.record_read(SPEC, OPENS - Nanos::from_millis(1), OPENS);
    assert_eq!(tracker.deadline(SPEC), SPEC - Nanos::from_millis(500));
    assert_eq!(tracker.deadline(Nanos::from_millis(100)), Nanos::ZERO);
    read_early(&mut tracker, Nanos::from_millis(200));
    tracker.record_read(SPEC, Nanos::ZERO, OPENS);
    assert_eq!(tracker.deadline(SPEC), SPEC - Nanos::from_millis(200));
}

#[test]
fn the_slot_start_bounds_the_deadline() {
    let mut tracker = DeadlineTracker::default();
    tracker.record_read(SPEC, OPENS, OPENS);
    assert_eq!(tracker.deadline(SPEC), OPENS);
    tracker.record_read(SPEC, OPENS - Nanos::from_millis(1), OPENS);
    assert_eq!(tracker.deadline(SPEC), OPENS, "an earlier read would move it before the slot");
    assert_eq!(tracker.deadline(Nanos::from_secs(1)), Nanos::ZERO);
}
