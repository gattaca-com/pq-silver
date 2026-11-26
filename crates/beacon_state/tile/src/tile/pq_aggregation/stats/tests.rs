use super::*;

#[test]
fn a_position_past_the_last_shares_the_last_deadline_tracker() {
    assert_eq!(deadline_index(0), 0);
    assert_eq!(deadline_index(3), 3);
    assert_eq!(deadline_index(4), 3);
    assert_eq!(deadline_index(u64::MAX), 3);
}
