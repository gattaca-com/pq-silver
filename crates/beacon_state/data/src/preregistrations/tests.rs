use super::{
    BuilderPreregistration, ListView, ListWriter, Preregistrations, PreregistrationsGroup,
    PreregistrationsId, Record,
};
use crate::{merkle::hash_list, progressive::ProgressiveHasher};

fn builder(seed: u8) -> BuilderPreregistration {
    BuilderPreregistration {
        pubkey: [seed; 32],
        withdrawal_credentials: [seed; 32],
        expiry_slot: u64::from(seed),
    }
}

fn base() -> Preregistrations {
    let mut ssz = Vec::new();
    builder(1).write_ssz(&mut ssz).unwrap();
    Preregistrations::from_ssz(&[], &ssz).unwrap()
}

fn builders(g: &PreregistrationsGroup, id: PreregistrationsId) -> Vec<BuilderPreregistration> {
    g.view(id).builders.iter().copied().collect()
}

/// The cached root against a full rehash of the effective list.
fn assert_root_is_fresh(list: ListView<'_, BuilderPreregistration>) {
    let rehashed = hash_list(ProgressiveHasher::new(), list.iter().map(|r| r.hash_tree_root()));
    assert_eq!(list.hash_root(), rehashed);
}

fn roll(
    g: &mut PreregistrationsGroup,
    parent: PreregistrationsId,
    edit: impl FnOnce(&mut ListWriter<'_, BuilderPreregistration>),
) -> PreregistrationsId {
    let mut wv = g.roll_from(parent);
    edit(&mut wv.builders());
    wv.commit()
}

#[test]
fn writes_do_not_leak_into_the_parent_or_the_base() {
    let mut g = PreregistrationsGroup::new(base());
    let parent = g.roll_fresh().commit();
    let appended = roll(&mut g, parent, |w| w.push(builder(2)));
    let rewritten = roll(&mut g, appended, |w| w.rewrite(|records| records[0] = builder(3)));

    assert_eq!(builders(&g, parent), [builder(1)]);
    assert_eq!(builders(&g, appended), [builder(1), builder(2)]);
    assert_eq!(builders(&g, rewritten), [builder(3), builder(2)]);
    assert_eq!(g.finalized().builders.as_slice(), [builder(1)]);
    for id in [parent, appended, rewritten] {
        assert_root_is_fresh(g.view(id).builders);
    }
}

#[test]
fn finalize_promotes_the_winner_and_rebases_survivors() {
    let mut g = PreregistrationsGroup::new(base());
    let root = g.roll_fresh().commit();
    let winner = roll(&mut g, root, |w| w.push(builder(2)));
    let appender = roll(&mut g, winner, |w| w.push(builder(4)));
    let remover =
        roll(&mut g, winner, |w| w.rewrite(|records| records.retain(|r| r.pubkey[0] != 1)));

    let fresh = g.finalize(winner, &[winner, appender, remover]);

    assert_eq!(g.finalized().builders.as_slice(), [builder(1), builder(2)]);
    assert_eq!(builders(&g, fresh[0]), [builder(1), builder(2)]);
    assert_eq!(builders(&g, fresh[1]), [builder(1), builder(2), builder(4)]);
    assert_eq!(builders(&g, fresh[2]), [builder(2)]);
    for id in fresh {
        assert_root_is_fresh(g.view(id).builders);
    }
}

#[test]
fn a_finalized_rewrite_lets_its_descendants_read_the_base_again() {
    let mut g = PreregistrationsGroup::new(base());
    let root = g.roll_fresh().commit();
    let winner = roll(&mut g, root, |w| w.rewrite(|records| records.clear()));
    let child = roll(&mut g, winner, |w| w.push(builder(5)));

    let fresh = g.finalize(winner, &[winner, child]);

    assert!(g.finalized().builders.as_slice().is_empty());
    assert_eq!(builders(&g, fresh[1]), [builder(5)]);
    assert_root_is_fresh(g.view(fresh[1]).builders);
    let grandchild = roll(&mut g, fresh[1], |w| w.push(builder(6)));
    assert_eq!(builders(&g, grandchild), [builder(5), builder(6)]);
    assert_root_is_fresh(g.view(grandchild).builders);
}

#[test]
fn decode_rejects_a_partial_record() {
    let mut ssz = Vec::new();
    builder(1).write_ssz(&mut ssz).unwrap();
    ssz.pop();
    assert!(Preregistrations::from_ssz(&[], &ssz).is_err());
}
