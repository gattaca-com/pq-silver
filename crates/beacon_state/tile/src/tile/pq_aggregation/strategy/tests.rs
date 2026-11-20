use super::*;

#[test]
fn a_batch_is_ascending_and_never_empty() {
    assert_eq!(Batch::new(vec![3, 0, 2]).unwrap().indices(), [0, 2, 3]);
    assert!(Batch::new(Vec::new()).is_none());
}

#[test]
#[should_panic(expected = "repeated an index")]
fn a_batch_that_repeats_an_index_is_a_bug() {
    Batch::new(vec![0, 0]);
}
