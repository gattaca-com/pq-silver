use super::{BuilderPreregistration, Preregistrations, PreregistrationsGroup};

fn builder(seed: u8) -> BuilderPreregistration {
    BuilderPreregistration {
        pubkey: [seed; 32],
        withdrawal_credentials: [seed; 32],
        expiry_slot: u64::from(seed),
    }
}

fn base() -> Preregistrations {
    Preregistrations { validators: Vec::new(), builders: vec![builder(1)] }
}

#[test]
fn write_does_not_leak_into_parent_or_base() {
    let mut g = PreregistrationsGroup::new(base());
    let parent = g.roll_fresh().commit();
    let child = {
        let mut wv = g.roll_from(parent);
        wv.lists_mut().builders.push(builder(2));
        wv.commit()
    };

    assert_eq!(*g.view(parent), base());
    assert_eq!(g.view(child).builders, [builder(1), builder(2)]);
    g.with_finalized_locked(|f| assert_eq!(*f, base()));
}

#[test]
fn finalize_promotes_the_winner_and_keeps_survivors() {
    let mut g = PreregistrationsGroup::new(base());
    let winner = {
        let mut wv = g.roll_fresh();
        wv.lists_mut().builders.push(builder(2));
        wv.commit()
    };
    let sibling = {
        let mut wv = g.roll_from(winner);
        wv.lists_mut().builders.clear();
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, sibling]);

    g.with_finalized_locked(|f| assert_eq!(f.builders, [builder(1), builder(2)]));
    assert_eq!(g.view(fresh[0]).builders, [builder(1), builder(2)]);
    assert!(g.view(fresh[1]).builders.is_empty());
}
