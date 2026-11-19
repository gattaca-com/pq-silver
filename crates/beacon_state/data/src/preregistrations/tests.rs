use super::{
    BuilderPreregistration, ListView, ListWriter, Preregistration, Preregistrations,
    PreregistrationsGroup, PreregistrationsId,
};
use crate::{merkle::hash_list, progressive::ProgressiveHasher};

fn builder(seed: u8) -> BuilderPreregistration {
    keyed(u32::from(seed), u64::from(seed))
}

fn keyed(key: u32, expiry_slot: u64) -> BuilderPreregistration {
    let mut pubkey = [0; 32];
    pubkey[..4].copy_from_slice(&key.to_le_bytes());
    pubkey[31] = 1;
    BuilderPreregistration { pubkey, withdrawal_credentials: pubkey, expiry_slot }
}

fn base_of(records: &[BuilderPreregistration]) -> Preregistrations {
    let mut ssz = Vec::new();
    records.iter().for_each(|record| record.write_ssz(&mut ssz).unwrap());
    Preregistrations::from_ssz(&[], &ssz).unwrap()
}

fn base() -> Preregistrations {
    base_of(&[builder(1)])
}

fn builders(g: &PreregistrationsGroup, id: PreregistrationsId) -> Vec<BuilderPreregistration> {
    g.view(id).builders.iter().collect()
}

/// The cached root against a full rehash of the effective list.
fn assert_root_is_fresh(list: ListView<'_, BuilderPreregistration>) {
    let rehashed = hash_list(ProgressiveHasher::new(), list.iter().map(|r| r.hash_tree_root()));
    assert_eq!(list.hash_root(), rehashed);
}

fn roll(
    g: &mut PreregistrationsGroup,
    parent: PreregistrationsId,
    edit: impl FnOnce(&mut ListWriter<'_, '_, BuilderPreregistration>),
) -> PreregistrationsId {
    let mut wv = g.roll_from(parent);
    edit(&mut wv.builders());
    wv.commit()
}

fn consume(w: &mut ListWriter<'_, '_, BuilderPreregistration>, record: BuilderPreregistration) {
    assert!(w.admit_deposit(&record.pubkey, 0, |binding| *binding == record));
}

#[test]
fn writes_do_not_leak_into_the_parent_or_the_base() {
    let mut g = PreregistrationsGroup::new(base());
    let parent = g.roll_fresh().commit();
    let appended = roll(&mut g, parent, |w| w.push(builder(2)));
    let renewed = BuilderPreregistration { expiry_slot: 9, ..builder(1) };
    let overwritten = roll(&mut g, appended, |w| w.admit(renewed, 1));
    let removed = roll(&mut g, overwritten, |w| consume(w, builder(2)));

    assert_eq!(builders(&g, parent), [builder(1)]);
    assert_eq!(builders(&g, appended), [builder(1), builder(2)]);
    assert_eq!(builders(&g, overwritten), [renewed, builder(2)]);
    assert_eq!(builders(&g, removed), [renewed]);
    assert_eq!(g.finalized().builders.as_slice(), [builder(1)]);
    for id in [parent, appended, overwritten, removed] {
        assert_root_is_fresh(g.view(id).builders);
    }
}

/// Survivors rebase whatever they did to the winner's records: kept,
/// overwritten, removed, or followed by their own.
#[test]
fn finalize_promotes_the_winner_and_rebases_survivors() {
    let mut g = PreregistrationsGroup::new(base_of(&[builder(1), builder(2), builder(3)]));
    let root = g.roll_fresh().commit();
    let winner = roll(&mut g, root, |w| {
        consume(w, builder(2));
        w.push(builder(4));
        w.push(builder(5));
    });
    let appender = roll(&mut g, winner, |w| w.push(builder(6)));
    let renewed = BuilderPreregistration { expiry_slot: 90, ..builder(5) };
    let editor = roll(&mut g, winner, |w| {
        consume(w, builder(4));
        w.admit(renewed, 5);
        consume(w, builder(1));
        w.push(builder(7));
    });

    let fresh = g.finalize(winner, &[winner, appender, editor]);

    let promoted = [builder(1), builder(3), builder(4), builder(5)];
    assert_eq!(g.finalized().builders.as_slice(), promoted);
    assert_eq!(builders(&g, fresh[0]), promoted);
    assert_eq!(builders(&g, fresh[1]), [&promoted[..], &[builder(6)]].concat());
    assert_eq!(builders(&g, fresh[2]), [builder(3), renewed, builder(7)]);
    for &id in &fresh {
        assert_root_is_fresh(g.view(id).builders);
    }

    // The index follows the compaction: a later key is found and removed.
    let child = roll(&mut g, fresh[2], |w| consume(w, builder(7)));
    assert_eq!(builders(&g, child), [builder(3), renewed]);
    assert_root_is_fresh(g.view(child).builders);
}

#[test]
fn decode_rejects_a_partial_record() {
    let mut ssz = Vec::new();
    builder(1).write_ssz(&mut ssz).unwrap();
    ssz.pop();
    assert!(Preregistrations::from_ssz(&[], &ssz).is_err());
}

/// A binding holds until the parent payload's slot reaches its expiry.
#[test]
fn bindings_expire_at_their_expiry_slot() {
    assert!(builder(5).is_active(4));
    assert!(!builder(5).is_active(5));
}

/// `builder(1)` expires at slot 1. At parent slot 0 it binds its key, so a new
/// request for the key is a no-op; at slot 1 the request replaces it in place.
#[test]
fn admission_replaces_only_an_expired_binding() {
    let mut g = PreregistrationsGroup::new(base());
    let parent = g.roll_fresh().commit();
    let renewed = BuilderPreregistration { expiry_slot: 9, ..builder(1) };

    let while_active = roll(&mut g, parent, |w| w.admit(renewed, 0));
    let after_expiry = roll(&mut g, while_active, |w| {
        w.admit(renewed, 1);
        w.admit(builder(2), 1);
    });

    assert_eq!(builders(&g, while_active), [builder(1)]);
    assert_eq!(builders(&g, after_expiry), [renewed, builder(2)]);
    assert_root_is_fresh(g.view(after_expiry).builders);
}

#[test]
fn matching_deposit_consumes_an_active_binding() {
    let mut g = PreregistrationsGroup::new(base());
    let parent = g.roll_fresh().commit();
    let with_two = roll(&mut g, parent, |w| w.push(builder(2)));
    let matches = |seed: u8| {
        move |binding: &BuilderPreregistration| binding.withdrawal_credentials[0] == seed
    };

    let mut outcomes = Vec::new();
    let consumed = roll(&mut g, with_two, |w| {
        outcomes.push(w.admit_deposit(&builder(1).pubkey, 0, matches(9)));
        outcomes.push(w.admit_deposit(&builder(1).pubkey, 0, matches(1)));
        outcomes.push(w.admit_deposit(&builder(2).pubkey, 2, matches(9)));
        outcomes.push(w.admit_deposit(&builder(7).pubkey, 0, matches(9)));
    });

    assert_eq!(outcomes, [false, true, true, true]);
    assert_eq!(builders(&g, consumed), [builder(2)]);
    assert_root_is_fresh(g.view(consumed).builders);
}

#[test]
fn retain_drops_records_wherever_they_live() {
    let mut g = PreregistrationsGroup::new(base_of(&[builder(1), builder(2), builder(3)]));
    let parent = g.roll_fresh().commit();
    let edited = roll(&mut g, parent, |w| {
        w.admit(keyed(2, 50), 2);
        w.push(builder(4));
        w.push(keyed(5, 60));
    });
    let swept = roll(&mut g, edited, |w| w.retain(|record| record.expiry_slot > 3));

    assert_eq!(builders(&g, swept), [keyed(2, 50), builder(4), keyed(5, 60)]);
    assert_root_is_fresh(g.view(swept).builders);
}

/// A xorshift stream, so the model test replays the same edits.
struct Draws(u64);

impl Draws {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

/// Every expiry is past slot 0, where `consume` checks bindings.
fn edit_both(
    w: &mut ListWriter<'_, '_, BuilderPreregistration>,
    model: &mut Vec<BuilderPreregistration>,
    draws: &mut Draws,
    next_key: &mut u32,
) {
    match draws.below(4) {
        0 => {
            let record = keyed(*next_key, 1 + draws.below(9) as u64);
            *next_key += 1;
            w.push(record);
            model.push(record);
        }
        1 if !model.is_empty() => {
            let i = draws.below(model.len());
            let renewed = BuilderPreregistration { expiry_slot: 99, ..model[i] };
            w.admit(renewed, model[i].expiry_slot);
            model[i] = renewed;
        }
        2 if !model.is_empty() => {
            let record = model.remove(draws.below(model.len()));
            consume(w, record);
        }
        _ => {
            let cutoff = draws.below(9) as u64;
            w.retain(|record| record.expiry_slot > cutoff);
            model.retain(|record| record.expiry_slot > cutoff);
        }
    }
}

/// Random edits on two sibling forks. Every few steps one fork's head is
/// finalized together with a descendant that edits further, so the rebase
/// meets the winner's records kept, overwritten, removed and appended to.
#[test]
fn matches_a_vec_model_across_forks_and_finalization() {
    let mut draws = Draws(0x9e37_79b9_7f4a_7c15);
    let mut next_key = 1000;
    let initial: Vec<_> = (0..40).map(|key| keyed(key, 1 + u64::from(key % 7))).collect();
    let mut g = PreregistrationsGroup::new(base_of(&initial));
    let root = g.roll_fresh().commit();
    let mut forks = [(root, initial.clone()), (root, initial)];

    for step in 0..300 {
        let side = draws.below(2);
        let (parent, mut model) = forks[side].clone();
        let id = roll(&mut g, parent, |w| edit_both(w, &mut model, &mut draws, &mut next_key));
        forks[side] = (id, model);

        if step % 5 == 4 {
            let (winner, winner_model) = forks[side].clone();
            let mut child_model = winner_model.clone();
            let child = roll(&mut g, winner, |w| {
                for _ in 0..3 {
                    edit_both(w, &mut child_model, &mut draws, &mut next_key);
                }
            });
            let fresh = g.finalize(winner, &[winner, child]);
            assert_eq!(g.finalized().builders.as_slice(), winner_model, "step {step}");
            forks = [(fresh[0], winner_model), (fresh[1], child_model)];
        }

        for (id, model) in &forks {
            assert_eq!(&builders(&g, *id), model, "step {step}");
            assert_root_is_fresh(g.view(*id).builders);
        }
    }
}
