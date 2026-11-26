use silver_beacon_state_data::Slot;
use silver_common::ssz_view::{MAX_STARK_PROOF_SIZE, bitvector_word};

use super::{
    super::{
        proof_sources::ProofSources,
        test_util::{Group, answer, group, group_of, running_of, visit_groups},
    },
    *,
};

const SLOT: Slot = 10;

/// A running proof of positions 1 and 2 of committee 0.
fn running() -> (RunningProof, ProofStore) {
    running_of(&[group(SLOT, 0, &[1, 2])], b"first")
}

fn bytes(aggregate: &ProvedAggregate) -> Vec<u8> {
    let mut out = vec![0; aggregate.ssz_len()];
    aggregate.write_ssz(&mut out);
    out
}

fn settle(
    running: &mut RunningProof,
    proofs: &mut ProofStore,
    response: Result<ProofBody<'_>, &'static str>,
    groups: &[Group],
) -> Result<(), &'static str> {
    running.settle(response, running.id, proofs, true, &mut ClaimCheck::default(), |_, visit| {
        visit_groups(groups, visit)
    })
}

fn coverage(running: &RunningProof) -> Vec<(Committee, Bits)> {
    running.groups().map(|group| (group.committee, group.positions)).collect()
}

#[test]
fn a_merge_is_accepted_when_its_answer_proves_exactly_the_union() {
    let (mut running, mut proofs) = running();
    let new_data = group_of(2, SLOT, 1, &[5]);
    let inputs = [group(SLOT, 0, &[2, 3]), group(SLOT, 1, &[4]), new_data.clone()];
    let expected = [group(SLOT, 0, &[1, 2, 3]), group(SLOT, 1, &[4]), new_data];
    settle(&mut running, &mut proofs, answer(&expected, b"second").parse(), &inputs).unwrap();
    let id = running.id.unwrap();
    let expected = expected.map(|group| {
        (group.committee, group.members.iter().map(|member| member.position).collect())
    });
    assert_eq!(coverage(&running), expected);
    assert_eq!(proofs.proof(id), b"second");
    assert_eq!(proofs.claims(id).len(), 5);
}

#[test]
fn an_answer_with_other_claims_is_refused_and_the_proof_stays() {
    let (mut running, mut proofs) = running();
    let before = coverage(&running);
    let inputs = [group(SLOT, 0, &[3])];
    for wrong in [&[1, 2, 3, 4][..], &[1, 2], &[1, 2, 4]] {
        let body = answer(&[group(SLOT, 0, wrong)], b"wrong");
        assert_eq!(
            settle(&mut running, &mut proofs, body.parse(), &inputs),
            Err("the proof covers other claims"),
            "{wrong:?}",
        );
        assert_eq!(coverage(&running), before);
        assert_eq!(proofs.proof(running.id.unwrap()), b"first");
    }
}

#[test]
fn a_refusal_or_an_unreadable_body_or_no_answer_keeps_the_proof() {
    let (mut running, mut proofs) = running();
    let before = coverage(&running);
    let inputs = [group(SLOT, 0, &[3])];
    let mut truncated = answer(&[group(SLOT, 0, &[1, 2, 3])], b"third");
    truncated.bytes.pop();
    let answers = [Err("rejected by the leanvm prover"), truncated.parse(), Err("no answer")];
    for answer in answers {
        assert!(settle(&mut running, &mut proofs, answer, &inputs).is_err());
        assert_eq!(coverage(&running), before);
        assert_eq!(proofs.proof(running.id.unwrap()), b"first");
    }
}

#[test]
fn a_stopped_target_stays_stopped_however_often_it_fails() {
    let mut running = RunningProof::default();
    let mut proofs = ProofStore::default();
    for _ in 0..=u8::MAX as usize {
        settle(&mut running, &mut proofs, Err("no answer"), &[]).unwrap_err();
    }
    assert!(running.is_stopped());
}

#[test]
fn an_answer_above_max_stark_proof_size_is_refused() {
    let mut running = RunningProof::default();
    let mut proofs = ProofStore::default();
    let inputs = [group(SLOT, 0, &[1])];
    let above = answer(&inputs, &vec![0; MAX_STARK_PROOF_SIZE + 1]);
    assert_eq!(
        settle(&mut running, &mut proofs, above.parse(), &inputs),
        Err("malformed response")
    );
    let at_cap = answer(&inputs, &vec![0; MAX_STARK_PROOF_SIZE]);
    settle(&mut running, &mut proofs, at_cap.parse(), &inputs).unwrap();
}

#[test]
fn on_chain_holds_validators_per_slot_from_its_floor() {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    let contains = |sources: &ProofSources, slot, validator| {
        sources.slot(slot).is_some_and(|entry| entry.on_chain.contains(validator))
    };
    sources.include_on_chain(SLOT + 1, &[3], &mut proofs);
    assert!(!contains(&sources, SLOT, 3), "on chain in another slot");
    sources.include_on_chain(SLOT, &[3], &mut proofs);
    assert!(contains(&sources, SLOT, 3));

    sources.prune_before(SLOT + 1, &mut proofs);
    assert!(!contains(&sources, SLOT, 3) && contains(&sources, SLOT + 1, 3));
    sources.include_on_chain(SLOT, &[4], &mut proofs);
    assert!(!contains(&sources, SLOT, 4), "below the floor");
}

#[test]
fn a_running_proof_of_one_committee_is_served_as_its_aggregate() {
    let voters = group_of(1, SLOT, 2, &[0, 3, 5]);
    let mut running = RunningProof::default();
    let mut proofs = ProofStore::default();
    let groups = std::slice::from_ref(&voters);
    settle(&mut running, &mut proofs, answer(groups, b"leaf").parse(), groups).unwrap();

    let ssz = bytes(&running.aggregate(&proofs).unwrap());
    assert_eq!(ssz[..4], (ProvedAttestationView::FIXED as u32).to_le_bytes());
    let attestation = ProvedAttestationView::attestation(&ssz);
    assert!(AttestationPqView::check_canonical(attestation));
    assert_eq!(AttestationPqView::data(attestation).as_bytes(), &voters.committee.data);
    assert_eq!(bitvector_word(AttestationPqView::committee_bits(attestation)), 1 << 2);
    assert_eq!(AttestationPqView::aggregation_bits(attestation), [0b0010_1001, 0b10]);
    assert_eq!(ProvedAttestationView::proof(&ssz), b"leaf");
    let other = group(SLOT, 3, &[1]);
    let body = answer(&[voters, other.clone()], b"two");
    settle(&mut running, &mut proofs, body.parse(), &[other]).unwrap();
    assert!(running.aggregate(&proofs).is_none(), "two committees are no aggregate");
}
