use std::ops::Range;

use silver_beacon_state_data::AGGREGATORS_PER_COMMITTEE;
use silver_common::{SLOTS_PER_EPOCH, ssz_view::VRFProof};

use crate::{
    beacon_link::{
        AttesterDuties, BeaconRequests, CommitteeSubscription, Head, RequestId, SlotDuties,
    },
    duties::validators::Validators,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttesterDuty {
    /// Position in `Validators`.
    pub key: usize,
    pub validator_index: u64,
    pub committee_index: u64,
    pub committees_at_slot: u64,
    pub slot: u64,
    /// Spec `get_aggregate_due_ms(position)` sets when it broadcasts.
    pub aggregator_position: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "inline in the reused duties Vec, so a proof costs no allocation"
)]
pub enum Reveal {
    Unasked,
    Asked,
    Proved(VRFProof),
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposerDuty {
    pub key: usize,
    pub validator_index: u64,
    pub slot: u64,
    pub randao: Reveal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtcDuty {
    pub key: usize,
    pub validator_index: u64,
    pub slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    Due { from_slot: u64 },
    InFlight(RequestId),
    Done,
}

struct Fetched<T> {
    dependent_root: Option<[u8; 32]>,
    duties: Vec<T>,
    fetch: Fetch,
}

impl<T> Fetched<T> {
    fn new() -> Self {
        Self { dependent_root: None, duties: Vec::new(), fetch: Fetch::Done }
    }

    fn reset(&mut self) {
        self.dependent_root = None;
        self.duties.clear();
        self.refetch();
    }

    fn refetch(&mut self) {
        self.fetch = Fetch::Due { from_slot: 0 };
    }

    fn refetch_unless_rooted_at(&mut self, root: &[u8; 32]) -> bool {
        let changed = self.dependent_root.is_some_and(|known| known != *root);
        if changed {
            self.refetch();
        }
        changed
    }

    fn is_due(&self, slot: u64) -> bool {
        matches!(self.fetch, Fetch::Due { from_slot } if from_slot <= slot)
    }

    /// A failed answer retries from the next slot.
    fn answered(
        &mut self,
        slot: u64,
        epoch: Option<u64>,
        kind: &'static str,
        fill: impl FnOnce(&mut Vec<T>) -> Result<[u8; 32], &'static str>,
    ) -> bool {
        self.duties.clear();
        match fill(&mut self.duties) {
            Ok(dependent_root) => {
                self.dependent_root = Some(dependent_root);
                self.fetch = Fetch::Done;
                silver_log::info!(epoch, kind, duties = self.duties.len(), "duties");
                true
            }
            Err(error) => {
                self.duties.clear();
                self.fetch = Fetch::Due { from_slot: slot + 1 };
                silver_log::warn!(epoch, kind, error, "duties");
                false
            }
        }
    }

    fn fetched(&self) -> &[T] {
        if self.fetch == Fetch::Done { &self.duties } else { &[] }
    }
}

struct EpochDuties {
    epoch: Option<u64>,
    attesters: Fetched<AttesterDuty>,
    proposers: Fetched<ProposerDuty>,
    ptc: Fetched<PtcDuty>,
    /// Tells the beacon node which subnets to join, and which of them to
    /// aggregate.
    subscription: Fetch,
}

impl EpochDuties {
    fn slot_range<T>(&self, duties: &[T], slot: u64, slot_of: impl Fn(&T) -> u64) -> Range<usize> {
        if self.epoch != Some(slot / SLOTS_PER_EPOCH) {
            return 0..0;
        }
        duties.partition_point(|duty| slot_of(duty) < slot)..
            duties.partition_point(|duty| slot_of(duty) <= slot)
    }
}

pub struct DutySchedule {
    proposes: bool,
    epochs: [EpochDuties; 2],
}

impl DutySchedule {
    pub fn new(proposes: bool) -> Self {
        let empty = || EpochDuties {
            epoch: None,
            attesters: Fetched::new(),
            proposers: Fetched::new(),
            ptc: Fetched::new(),
            subscription: Fetch::Done,
        };
        Self { proposes, epochs: [empty(), empty()] }
    }

    pub fn roll(&mut self, current_epoch: u64) {
        for epoch in [current_epoch, current_epoch + 1] {
            let entry = self.entry_mut(epoch);
            if entry.epoch != Some(epoch) {
                entry.epoch = Some(epoch);
                entry.attesters.reset();
                entry.proposers.reset();
                entry.ptc.reset();
                entry.subscription = Fetch::Due { from_slot: 0 };
            }
        }
    }

    pub fn refetch_all(&mut self) {
        for entry in self.epochs.iter_mut().filter(|entry| entry.epoch.is_some()) {
            entry.attesters.refetch();
            entry.proposers.refetch();
            entry.ptc.refetch();
        }
    }

    pub fn request_due(
        &mut self,
        slot: u64,
        validators: &Validators,
        requests: &mut BeaconRequests,
    ) {
        if !validators.any_index_known() {
            return;
        }
        for entry in &mut self.epochs {
            let Some(epoch) = entry.epoch else { continue };
            if entry.attesters.is_due(slot) {
                let id = requests.attester_duties(epoch, validators.known_indices());
                entry.attesters.fetch = Fetch::InFlight(id);
            }
            if self.proposes && entry.proposers.is_due(slot) {
                entry.proposers.fetch = Fetch::InFlight(requests.proposer_duties(epoch));
            }
            if entry.ptc.is_due(slot) {
                let id = requests.ptc_duties(epoch, validators.known_indices());
                entry.ptc.fetch = Fetch::InFlight(id);
            }
        }
    }

    pub fn on_duties(
        &mut self,
        id: RequestId,
        duties: &AttesterDuties<'_>,
        validators: &Validators,
        slot: u64,
    ) {
        let in_flight = Fetch::InFlight(id);
        let Some(entry) = self.epochs.iter_mut().find(|entry| entry.attesters.fetch == in_flight)
        else {
            return;
        };
        let fetched = entry.attesters.answered(slot, entry.epoch, "attester", |attesters| {
            let dependent_root = duties.for_each(validators.len(), |duty| {
                if let Some(key) = validators.key(&duty.pubkey) {
                    attesters.push(AttesterDuty {
                        key,
                        validator_index: duty.validator_index,
                        committee_index: duty.committee_index,
                        committees_at_slot: duty.committees_at_slot,
                        slot: duty.slot,
                        aggregator_position: duty.aggregator_position().map(|position| {
                            position.min(AGGREGATORS_PER_COMMITTEE as u64 - 1) as u8
                        }),
                    });
                }
            })?;
            attesters.sort_unstable_by_key(|duty| duty.slot);
            Ok(dependent_root)
        });
        if fetched {
            entry.subscription = Fetch::Due { from_slot: 0 };
        }
    }

    pub fn on_proposer_duties(
        &mut self,
        id: RequestId,
        duties: &SlotDuties<'_>,
        validators: &Validators,
        slot: u64,
    ) {
        let in_flight = Fetch::InFlight(id);
        let Some(entry) = self.epochs.iter_mut().find(|entry| entry.proposers.fetch == in_flight)
        else {
            return;
        };
        entry.proposers.answered(slot, entry.epoch, "proposer", |proposers| {
            let dependent_root = duties.for_each(SLOTS_PER_EPOCH as usize, |duty| {
                if let Some(key) = validators.key(&duty.pubkey) {
                    proposers.push(ProposerDuty {
                        key,
                        validator_index: duty.validator_index,
                        slot: duty.slot,
                        randao: Reveal::Unasked,
                    });
                }
            })?;
            proposers.sort_unstable_by_key(|duty| duty.slot);
            Ok(dependent_root)
        });
    }

    pub fn on_ptc_duties(
        &mut self,
        id: RequestId,
        duties: &SlotDuties<'_>,
        validators: &Validators,
        slot: u64,
    ) {
        let in_flight = Fetch::InFlight(id);
        let Some(entry) = self.epochs.iter_mut().find(|entry| entry.ptc.fetch == in_flight) else {
            return;
        };
        entry.ptc.answered(slot, entry.epoch, "PTC", |members| {
            let dependent_root = duties.for_each(validators.len(), |duty| {
                if let Some(key) = validators.key(&duty.pubkey) {
                    members.push(PtcDuty {
                        key,
                        validator_index: duty.validator_index,
                        slot: duty.slot,
                    });
                }
            })?;
            members.sort_unstable_by_key(|duty| duty.slot);
            Ok(dependent_root)
        });
    }

    pub fn on_failed(&mut self, id: RequestId, slot: u64) {
        let in_flight = Fetch::InFlight(id);
        for entry in &mut self.epochs {
            for fetch in
                [&mut entry.attesters.fetch, &mut entry.proposers.fetch, &mut entry.ptc.fetch]
            {
                if *fetch == in_flight {
                    *fetch = Fetch::Due { from_slot: slot + 1 };
                }
            }
        }
    }

    /// A head in epoch E names the dependent root of E's duties and of
    /// E + 1's.
    pub fn on_head(&mut self, head: &Head) {
        let head_epoch = head.slot / SLOTS_PER_EPOCH;
        let expected = [
            (head_epoch, head.previous_duty_dependent_root),
            (head_epoch + 1, head.current_duty_dependent_root),
        ];
        for (epoch, root) in expected {
            let entry = self.entry_mut(epoch);
            if entry.epoch != Some(epoch) {
                continue;
            }
            if entry.attesters.refetch_unless_rooted_at(&root) {
                silver_log::info!(epoch, "attester duties dependent root changed");
            }
            if entry.proposers.refetch_unless_rooted_at(&root) {
                silver_log::info!(epoch, "proposer duties dependent root changed");
            }
            if entry.ptc.refetch_unless_rooted_at(&root) {
                silver_log::info!(epoch, "PTC duties dependent root changed");
            }
        }
    }

    pub fn subscriptions_due(&mut self, slot: u64, requests: &mut BeaconRequests) {
        for entry in &mut self.epochs {
            let Fetch::Due { from_slot } = entry.subscription else { continue };
            let attesters = entry.attesters.fetched();
            if attesters.is_empty() || from_slot > slot {
                continue;
            }
            let subscriptions = attesters.iter().map(|duty| CommitteeSubscription {
                validator_index: duty.validator_index,
                committee_index: duty.committee_index,
                committees_at_slot: duty.committees_at_slot,
                slot: duty.slot,
                is_aggregator: duty.aggregator_position.is_some(),
            });
            entry.subscription = Fetch::InFlight(requests.committee_subscriptions(subscriptions));
        }
    }

    pub fn on_subscribed(&mut self, id: RequestId) {
        if let Some(entry) = self.subscription_mut(id) {
            entry.subscription = Fetch::Done;
            silver_log::info!(epoch = entry.epoch, "committee subscriptions sent");
        }
    }

    /// It retries at the next slot.
    pub fn on_subscription_failed(&mut self, id: RequestId, slot: u64) {
        if let Some(entry) = self.subscription_mut(id) {
            entry.subscription = Fetch::Due { from_slot: slot + 1 };
        }
    }

    fn subscription_mut(&mut self, id: RequestId) -> Option<&mut EpochDuties> {
        self.epochs.iter_mut().find(|entry| entry.subscription == Fetch::InFlight(id))
    }

    pub fn attesters_at(&self, slot: u64) -> &[AttesterDuty] {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        &entry.attesters.duties[entry.slot_range(&entry.attesters.duties, slot, |duty| duty.slot)]
    }

    pub fn aggregators_at(&self, slot: u64, position: u8) -> impl Iterator<Item = &AttesterDuty> {
        self.attesters_at(slot)
            .iter()
            .filter(move |duty| duty.aggregator_position == Some(position))
    }

    pub fn ptc_at(&self, slot: u64) -> &[PtcDuty] {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        &entry.ptc.duties[entry.slot_range(&entry.ptc.duties, slot, |duty| duty.slot)]
    }

    pub fn ask_randao(&mut self, mut ask: impl FnMut(&ProposerDuty)) {
        for entry in &mut self.epochs {
            if entry.proposers.fetch != Fetch::Done {
                continue;
            }
            for duty in &mut entry.proposers.duties {
                if duty.randao == Reveal::Unasked {
                    ask(duty);
                    duty.randao = Reveal::Asked;
                }
            }
        }
    }

    pub fn on_randao(&mut self, slot: u64, validator_index: u64, proof: Option<&VRFProof>) {
        let entry = self.entry_mut(slot / SLOTS_PER_EPOCH);
        let asked = entry.proposers.duties.iter_mut().find(|duty| {
            (duty.slot, duty.validator_index) == (slot, validator_index) &&
                duty.randao == Reveal::Asked
        });
        if let Some(duty) = asked {
            duty.randao = proof.map_or(Reveal::Refused, |proof| Reveal::Proved(*proof));
        }
    }

    /// Proposals in slot order, with the dependent root they were fetched at.
    /// An epoch not yet fetched ends them, so none is skipped.
    pub fn proposals(&self) -> impl Iterator<Item = (&ProposerDuty, &[u8; 32])> {
        let [first, second] = &self.epochs;
        let in_order = if first.epoch <= second.epoch { [first, second] } else { [second, first] };
        in_order
            .into_iter()
            .map_while(|entry| match (entry.proposers.fetch, &entry.proposers.dependent_root) {
                (Fetch::Done, Some(root)) => {
                    Some(entry.proposers.duties.iter().map(move |duty| (duty, root)))
                }
                _ => None,
            })
            .flatten()
    }

    pub fn proposer_at(&self, slot: u64) -> Option<&ProposerDuty> {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        let proposers = if entry.epoch == Some(slot / SLOTS_PER_EPOCH) {
            entry.proposers.fetched()
        } else {
            &[]
        };
        proposers.iter().find(|duty| duty.slot == slot)
    }

    fn entry_mut(&mut self, epoch: u64) -> &mut EpochDuties {
        &mut self.epochs[(epoch % 2) as usize]
    }
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::{VRF_PROOF_SIZE, XMSSPubkey};

    use super::*;
    use crate::beacon_link::{AttesterDuties, SlotDuties, ValidatorIndices};

    const A: XMSSPubkey = [0xaa; 32];
    const B: XMSSPubkey = [0xbb; 32];

    fn validators() -> Validators {
        let mut validators = Validators::new(vec![A, B]);
        let mut requests = BeaconRequests::default();
        validators.request_indices(0, &mut requests);
        let mut id = None;
        requests.drain(|sent, _, _, _| id = Some(sent));
        let json = format!(
            r#"{{"data":[{{"index":"7","validator":{{"pubkey":"0x{}"}}}},{{"index":"9","validator":{{"pubkey":"0x{}"}}}}]}}"#,
            hex::encode(A),
            hex::encode(B)
        );
        validators.on_indices(id.unwrap(), &ValidatorIndices(json.as_bytes()));
        validators
    }

    /// Index 7 is its committee's first aggregator.
    fn duties_json(root: u8, duties: &[(XMSSPubkey, u64, u64, u64)]) -> String {
        let data = duties
            .iter()
            .map(|(pubkey, index, committee, slot)| {
                let position =
                    if *index == 7 { r#","is_aggregator":true,"aggregator_position":"2""# } else { "" };
                format!(
                    r#"{{"pubkey":"0x{}","validator_index":"{index}","committee_index":"{committee}","committee_length":"1","committees_at_slot":"1","validator_committee_index":"0","slot":"{slot}"{position}}}"#,
                    hex::encode(pubkey)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"dependent_root":"0x{}","data":[{data}]}}"#, hex::encode([root; 32]))
    }

    fn sent(requests: &mut BeaconRequests) -> Vec<(RequestId, String)> {
        let mut sent = Vec::new();
        requests.drain(|id, _, path, _| sent.push((id, path.to_owned())));
        sent
    }

    #[test]
    fn duties_for_both_epochs_are_fetched_once_and_sorted_by_slot() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        schedule.request_due(64, &validators, &mut requests);
        let sent = sent(&mut requests);
        let paths = sent.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, [
            "/eth/v1/validator/duties/attester/2",
            "/eth/v1/validator/duties/ptc/2",
            "/eth/v1/validator/duties/attester/3",
            "/eth/v1/validator/duties/ptc/3"
        ]);

        let json = duties_json(1, &[(B, 9, 4, 70), (A, 7, 3, 65)]);
        schedule.on_duties(sent[0].0, &AttesterDuties(json.as_bytes()), &validators, 64);
        let duty =
            |key, validator_index, committee_index, slot, aggregator_position| AttesterDuty {
                key,
                validator_index,
                committee_index,
                committees_at_slot: 1,
                slot,
                aggregator_position,
            };
        assert_eq!(schedule.attesters_at(65), [duty(0, 7, 3, 65, Some(2))]);
        assert_eq!(schedule.attesters_at(70), [duty(1, 9, 4, 70, None)]);
        assert!(schedule.attesters_at(66).is_empty());
        assert!(schedule.attesters_at(97).is_empty());
    }

    #[test]
    fn failed_fetch_retries_from_the_next_slot() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let first = sent(&mut requests)[0].0;
        schedule.on_failed(first, 64);

        schedule.request_due(64, &validators, &mut requests);
        assert!(sent(&mut requests).is_empty());
        schedule.request_due(65, &validators, &mut requests);
        assert_eq!(sent(&mut requests).len(), 1);
    }

    fn head(slot: u64, previous: u8, current: u8) -> Head {
        Head {
            slot,
            previous_duty_dependent_root: [previous; 32],
            current_duty_dependent_root: [current; 32],
            ..Head::default()
        }
    }

    #[test]
    fn changed_dependent_root_refetches_only_its_epoch() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let sent_ids = sent(&mut requests);
        let current = duties_json(0xc0, &[(A, 7, 3, 65)]);
        let next = duties_json(0xc1, &[(A, 7, 3, 100)]);
        schedule.on_duties(sent_ids[0].0, &AttesterDuties(current.as_bytes()), &validators, 64);
        schedule.on_duties(sent_ids[2].0, &AttesterDuties(next.as_bytes()), &validators, 64);

        schedule.on_head(&head(66, 0xc0, 0xc1));
        schedule.request_due(66, &validators, &mut requests);
        assert!(sent(&mut requests).is_empty());

        schedule.on_head(&head(67, 0xc0, 0xee));
        schedule.request_due(67, &validators, &mut requests);
        let paths = sent(&mut requests).into_iter().map(|(_, path)| path).collect::<Vec<_>>();
        assert_eq!(paths, ["/eth/v1/validator/duties/attester/3"]);
    }

    #[test]
    fn rolling_an_epoch_drops_the_old_duties() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let id = sent(&mut requests)[0].0;
        let json = duties_json(1, &[(A, 7, 3, 65)]);
        schedule.on_duties(id, &AttesterDuties(json.as_bytes()), &validators, 64);

        schedule.roll(3);
        assert!(schedule.attesters_at(65).is_empty());
        schedule.request_due(96, &validators, &mut requests);
        let paths = sent(&mut requests).into_iter().map(|(_, path)| path).collect::<Vec<_>>();
        assert_eq!(paths, [
            "/eth/v1/validator/duties/attester/4",
            "/eth/v1/validator/duties/ptc/4"
        ]);
    }

    #[test]
    fn aggregators_are_marked_and_subscribe_once() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let fetched = sent(&mut requests)[0].0;
        sent(&mut requests);
        let json = duties_json(1, &[(A, 7, 3, 65), (B, 9, 4, 70)]);
        schedule.on_duties(fetched, &AttesterDuties(json.as_bytes()), &validators, 64);

        schedule.subscriptions_due(64, &mut requests);
        let mut bodies = Vec::new();
        requests.drain(|id, _, path, body| {
            bodies.push((id, path.to_owned(), String::from_utf8(body.to_vec()).unwrap()))
        });
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].1, "/eth/v1/validator/beacon_committee_subscriptions");
        let subscriptions = serde_json::from_str::<serde_json::Value>(&bodies[0].2).unwrap();
        let flags = subscriptions.as_array().unwrap().iter().map(|s| s["is_aggregator"].clone());
        assert!(flags.eq([serde_json::Value::Bool(true), serde_json::Value::Bool(false)]));

        let aggregators = schedule.aggregators_at(65, 2).map(|duty| duty.validator_index);
        assert!(aggregators.eq([7]));
        assert_eq!(schedule.aggregators_at(65, 0).count(), 0, "another position");
        assert_eq!(schedule.aggregators_at(70, 2).count(), 0);

        schedule.on_subscription_failed(bodies[0].0, 64);
        schedule.subscriptions_due(64, &mut requests);
        assert!(sent(&mut requests).is_empty());
        schedule.subscriptions_due(65, &mut requests);
        let retried = sent(&mut requests);
        assert_eq!(retried.len(), 1);
        schedule.on_subscribed(retried[0].0);
        schedule.subscriptions_due(66, &mut requests);
        assert!(sent(&mut requests).is_empty());
    }

    fn proposers_json(root: u8, duties: &[(XMSSPubkey, u64, u64)]) -> String {
        let data = duties
            .iter()
            .map(|(pubkey, index, slot)| {
                format!(
                    r#"{{"pubkey":"0x{}","validator_index":"{index}","slot":"{slot}"}}"#,
                    hex::encode(pubkey)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"dependent_root":"0x{}","data":[{data}]}}"#, hex::encode([root; 32]))
    }

    #[test]
    fn proposer_duties_are_fetched_only_when_proposing() {
        let validators = validators();
        let mut requests = BeaconRequests::default();
        let mut attest_only = DutySchedule::new(false);
        attest_only.roll(2);
        attest_only.request_due(64, &validators, &mut requests);
        assert!(sent(&mut requests).iter().all(|(_, path)| !path.contains("proposer")));

        let mut schedule = DutySchedule::new(true);
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let fetches = sent(&mut requests);
        let paths = fetches.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, [
            "/eth/v1/validator/duties/attester/2",
            "/eth/v2/validator/duties/proposer/2",
            "/eth/v1/validator/duties/ptc/2",
            "/eth/v1/validator/duties/attester/3",
            "/eth/v2/validator/duties/proposer/3",
            "/eth/v1/validator/duties/ptc/3"
        ]);
        let json = proposers_json(0xc0, &[(A, 7, 65), ([0xcc; 32], 100, 66)]);
        schedule.on_proposer_duties(fetches[1].0, &SlotDuties(json.as_bytes()), &validators, 64);
        let duty = ProposerDuty { key: 0, validator_index: 7, slot: 65, randao: Reveal::Unasked };
        assert_eq!(schedule.proposer_at(65), Some(&duty));
        assert_eq!(schedule.proposer_at(66), None);

        let mut asked = Vec::new();
        schedule.ask_randao(|duty| asked.push((duty.slot, duty.validator_index)));
        schedule.ask_randao(|_| unreachable!("asked once"));
        assert_eq!(asked, [(65, 7)]);
        schedule.on_randao(65, 8, Some(&[0x7b; VRF_PROOF_SIZE]));
        schedule.on_randao(65, 7, Some(&[0x7a; VRF_PROOF_SIZE]));
        assert_eq!(
            schedule.proposer_at(65).unwrap().randao,
            Reveal::Proved([0x7a; VRF_PROOF_SIZE])
        );
    }
}
