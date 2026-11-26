use std::ops::Range;

use silver_common::{SLOTS_PER_EPOCH, merkle::sha256, ssz_view::PROPOSER_PREFERENCES_SIZE};

use crate::{
    beacon_link::{
        AttesterDuties, BeaconRequests, CommitteeSubscription, Head, RequestId, SignedPreferences,
        SlotDuties,
    },
    duties::{aggregations::AggregatorDuty, validators::Validators},
};

/// Spec `is_aggregator`: a member aggregates when its selection proof hashes
/// into the one in `committee_len / 16`, at least one, it is chosen by.
pub(super) fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let hash = sha256(selection_proof);
    u64::from_le_bytes(hash[0..8].try_into().unwrap()).is_multiple_of(modulo)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttesterDuty {
    /// Position in `Validators`.
    pub key: usize,
    pub validator_index: u64,
    pub committee_index: u64,
    pub committee_length: u64,
    pub committees_at_slot: u64,
    pub slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signing {
    Unasked,
    Asked(RequestId),
    Signed([u8; 96]),
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerDuty {
    pub key: usize,
    pub validator_index: u64,
    pub slot: u64,
    pub randao: Signing,
    pub preferences: Signing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtcDuty {
    pub key: usize,
    pub validator_index: u64,
    pub slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Unknown,
    Aggregator([u8; 96]),
    Attester,
}

/// Each duty's aggregation role, decided by its selection proof, and the
/// subscription that tells beacon nodes which subnets to join.
struct Selections {
    /// The selection proof requests, in duty order, so ids ascend.
    requests: Vec<RequestId>,
    roles: Vec<Role>,
    subscription: Fetch,
}

impl Selections {
    fn clear(&mut self) {
        self.requests.clear();
        self.roles.clear();
        self.subscription = Fetch::Due { from_slot: 0 };
    }

    fn position(&self, id: RequestId) -> Option<usize> {
        self.requests.binary_search(&id).ok()
    }

    fn all_known(&self, duties: usize) -> bool {
        self.roles.len() == duties && !self.roles.contains(&Role::Unknown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    Due { from_slot: u64 },
    InFlight(RequestId),
    Done,
}

struct Fetched<T> {
    wanted: bool,
    dependent_root: Option<[u8; 32]>,
    duties: Vec<T>,
    fetch: Fetch,
}

impl<T> Fetched<T> {
    fn new() -> Self {
        Self { wanted: false, dependent_root: None, duties: Vec::new(), fetch: Fetch::Done }
    }

    fn reset(&mut self, wanted: bool) {
        self.wanted = wanted;
        self.dependent_root = None;
        self.duties.clear();
        self.refetch();
    }

    fn refetch(&mut self) {
        if self.wanted {
            self.fetch = Fetch::Due { from_slot: 0 };
        }
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

    fn answered(
        &mut self,
        slot: u64,
        answer: impl FnOnce(&mut Vec<T>) -> Result<[u8; 32], &'static str>,
    ) -> Result<(), &'static str> {
        self.duties.clear();
        match answer(&mut self.duties) {
            Ok(dependent_root) => {
                self.dependent_root = Some(dependent_root);
                self.fetch = Fetch::Done;
                Ok(())
            }
            Err(error) => {
                self.duties.clear();
                self.fetch = Fetch::Due { from_slot: slot + 1 };
                Err(error)
            }
        }
    }
}

struct EpochDuties {
    epoch: Option<u64>,
    attesters: Fetched<AttesterDuty>,
    proposers: Fetched<ProposerDuty>,
    ptc: Fetched<PtcDuty>,
    selections: Selections,
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
    gloas_fork_epoch: u64,
    epochs: [EpochDuties; 2],
}

impl DutySchedule {
    pub fn new(proposes: bool, gloas_fork_epoch: u64) -> Self {
        let empty = || EpochDuties {
            epoch: None,
            attesters: Fetched::new(),
            proposers: Fetched::new(),
            ptc: Fetched::new(),
            selections: Selections {
                requests: Vec::new(),
                roles: Vec::new(),
                subscription: Fetch::Done,
            },
        };
        Self { proposes, gloas_fork_epoch, epochs: [empty(), empty()] }
    }

    pub fn roll(&mut self, current_epoch: u64) {
        let (proposes, gloas_fork_epoch) = (self.proposes, self.gloas_fork_epoch);
        for epoch in [current_epoch, current_epoch + 1] {
            let entry = self.entry_mut(epoch);
            if entry.epoch != Some(epoch) {
                entry.epoch = Some(epoch);
                entry.attesters.reset(true);
                entry.proposers.reset(proposes);
                entry.ptc.reset(epoch >= gloas_fork_epoch);
                entry.selections.clear();
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
            if entry.proposers.is_due(slot) {
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
        let answered = entry.attesters.answered(slot, |attesters| {
            let dependent_root = duties.for_each(validators.len(), |duty| {
                if let Some(key) = validators.key(&duty.pubkey) {
                    attesters.push(AttesterDuty {
                        key,
                        validator_index: duty.validator_index,
                        committee_index: duty.committee_index,
                        committee_length: duty.committee_length,
                        committees_at_slot: duty.committees_at_slot,
                        slot: duty.slot,
                    });
                }
            })?;
            attesters.sort_unstable_by_key(|duty| duty.slot);
            Ok(dependent_root)
        });
        let duties = entry.attesters.duties.len();
        match answered {
            Ok(()) => {
                entry.selections.clear();
                silver_log::info!(epoch = entry.epoch, duties, "attester duties");
            }
            Err(error) => silver_log::warn!(epoch = entry.epoch, error, "attester duties"),
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
        let answered = entry.proposers.answered(slot, |proposers| {
            duties.for_each(SLOTS_PER_EPOCH as usize, |duty| {
                if let Some(key) = validators.key(&duty.pubkey) {
                    proposers.push(ProposerDuty {
                        key,
                        validator_index: duty.validator_index,
                        slot: duty.slot,
                        randao: Signing::Unasked,
                        preferences: Signing::Unasked,
                    });
                }
            })
        });
        let proposals = entry.proposers.duties.len();
        match answered {
            Ok(()) => silver_log::info!(epoch = entry.epoch, proposals, "proposer duties"),
            Err(error) => silver_log::warn!(epoch = entry.epoch, error, "proposer duties"),
        }
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
        let answered = entry.ptc.answered(slot, |members| {
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
        let duties = entry.ptc.duties.len();
        match answered {
            Ok(()) => silver_log::info!(epoch = entry.epoch, duties, "PTC duties"),
            Err(error) => silver_log::warn!(epoch = entry.epoch, error, "PTC duties"),
        }
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

    /// Asks once for every fetched duty's selection proof; `ask` returns the
    /// request it queued.
    pub fn ask_selections(&mut self, mut ask: impl FnMut(&AttesterDuty) -> RequestId) {
        for entry in &mut self.epochs {
            let selections = &mut entry.selections;
            if entry.attesters.fetch != Fetch::Done || !selections.requests.is_empty() {
                continue;
            }
            for duty in &entry.attesters.duties {
                selections.requests.push(ask(duty));
                selections.roles.push(Role::Unknown);
            }
        }
    }

    pub fn on_selection(&mut self, id: RequestId, selection_proof: [u8; 96]) {
        self.set_role(id, |duty| {
            if is_aggregator(duty.committee_length as usize, &selection_proof) {
                Role::Aggregator(selection_proof)
            } else {
                Role::Attester
            }
        })
    }

    /// A duty whose selection proof failed only attests.
    pub fn on_selection_failed(&mut self, id: RequestId) {
        self.set_role(id, |_| Role::Attester)
    }

    pub fn subscriptions_due(&mut self, slot: u64, requests: &mut BeaconRequests) {
        for entry in &mut self.epochs {
            let selections = &mut entry.selections;
            let Fetch::Due { from_slot } = selections.subscription else { continue };
            let attesters = &entry.attesters.duties;
            let fetched = entry.attesters.fetch == Fetch::Done && !attesters.is_empty();
            if !fetched || from_slot > slot || !selections.all_known(attesters.len()) {
                continue;
            }
            let subscriptions =
                attesters.iter().zip(&selections.roles).map(|(duty, role)| CommitteeSubscription {
                    validator_index: duty.validator_index,
                    committee_index: duty.committee_index,
                    committees_at_slot: duty.committees_at_slot,
                    slot: duty.slot,
                    is_aggregator: matches!(role, Role::Aggregator(_)),
                });
            selections.subscription =
                Fetch::InFlight(requests.committee_subscriptions(subscriptions));
        }
    }

    pub fn on_subscribed(&mut self, id: RequestId) {
        if let Some(entry) = self.subscription_mut(id) {
            entry.selections.subscription = Fetch::Done;
            silver_log::info!(epoch = entry.epoch, "committee subscriptions sent");
        }
    }

    /// It retries at the next slot.
    pub fn on_subscription_failed(&mut self, id: RequestId, slot: u64) {
        if let Some(entry) = self.subscription_mut(id) {
            entry.selections.subscription = Fetch::Due { from_slot: slot + 1 };
        }
    }

    pub fn aggregators_at(&self, slot: u64) -> impl Iterator<Item = (AggregatorDuty, [u8; 96])> {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        let range = entry.slot_range(&entry.attesters.duties, slot, |duty| duty.slot);
        entry.attesters.duties[range.clone()]
            .iter()
            .zip(entry.selections.roles.get(range).unwrap_or_default())
            .filter_map(|(duty, role)| match role {
                Role::Aggregator(proof) => {
                    let aggregator = AggregatorDuty {
                        key: duty.key,
                        validator_index: duty.validator_index,
                        committee: duty.committee_index,
                    };
                    Some((aggregator, *proof))
                }
                Role::Unknown | Role::Attester => None,
            })
    }

    fn set_role(&mut self, id: RequestId, role: impl FnOnce(&AttesterDuty) -> Role) {
        for entry in &mut self.epochs {
            if let Some(at) = entry.selections.position(id) {
                entry.selections.roles[at] = role(&entry.attesters.duties[at]);
                return;
            }
        }
    }

    fn subscription_mut(&mut self, id: RequestId) -> Option<&mut EpochDuties> {
        self.epochs.iter_mut().find(|entry| entry.selections.subscription == Fetch::InFlight(id))
    }

    pub fn attesters_at(&self, slot: u64) -> &[AttesterDuty] {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        &entry.attesters.duties[entry.slot_range(&entry.attesters.duties, slot, |duty| duty.slot)]
    }

    pub fn ptc_at(&self, slot: u64) -> &[PtcDuty] {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        &entry.ptc.duties[entry.slot_range(&entry.ptc.duties, slot, |duty| duty.slot)]
    }

    pub fn ask_randao(&mut self, mut ask: impl FnMut(&ProposerDuty) -> RequestId) {
        for entry in &mut self.epochs {
            if entry.proposers.fetch != Fetch::Done {
                continue;
            }
            for duty in &mut entry.proposers.duties {
                if duty.randao == Signing::Unasked {
                    duty.randao = Signing::Asked(ask(duty));
                }
            }
        }
    }

    pub fn on_randao(&mut self, id: RequestId, randao: Option<[u8; 96]>) {
        let asked = self.epochs.iter_mut().flat_map(|entry| &mut entry.proposers.duties);
        if let Some(duty) = asked.into_iter().find(|duty| duty.randao == Signing::Asked(id)) {
            duty.randao = randao.map_or(Signing::Done, Signing::Signed);
        }
    }

    pub fn ask_preferences(
        &mut self,
        mut ask: impl FnMut(&ProposerDuty, &[u8; 32]) -> Option<RequestId>,
    ) {
        for entry in &mut self.epochs {
            let (Fetch::Done, Some(dependent_root)) =
                (entry.proposers.fetch, entry.proposers.dependent_root)
            else {
                continue;
            };
            for duty in &mut entry.proposers.duties {
                if duty.preferences == Signing::Unasked {
                    duty.preferences =
                        ask(duty, &dependent_root).map_or(Signing::Done, Signing::Asked);
                }
            }
        }
    }

    pub fn on_preferences(&mut self, id: RequestId, signature: Option<[u8; 96]>) {
        let asked = self.epochs.iter_mut().flat_map(|entry| &mut entry.proposers.duties);
        if let Some(duty) = asked.into_iter().find(|duty| duty.preferences == Signing::Asked(id)) {
            duty.preferences = signature.map_or(Signing::Done, Signing::Signed);
        }
    }

    pub fn publish_preferences(
        &mut self,
        message: impl Fn(&ProposerDuty, &[u8; 32]) -> [u8; PROPOSER_PREFERENCES_SIZE],
        requests: &mut BeaconRequests,
    ) {
        for entry in &mut self.epochs {
            let Some(dependent_root) = entry.proposers.dependent_root else { continue };
            let duties = &mut entry.proposers.duties;
            let signed = |duty: &ProposerDuty| matches!(duty.preferences, Signing::Signed(_));
            if !duties.iter().any(signed) {
                continue;
            }
            requests.publish_proposer_preferences(duties.iter().filter_map(|duty| {
                match duty.preferences {
                    Signing::Signed(signature) => Some(SignedPreferences {
                        message: message(duty, &dependent_root),
                        signature,
                    }),
                    _ => None,
                }
            }));
            for duty in duties.iter_mut().filter(|duty| signed(duty)) {
                duty.preferences = Signing::Done;
            }
        }
    }

    pub fn proposer_at(&self, slot: u64) -> Option<&ProposerDuty> {
        let entry = &self.epochs[(slot / SLOTS_PER_EPOCH % 2) as usize];
        let fetched =
            entry.epoch == Some(slot / SLOTS_PER_EPOCH) && entry.proposers.fetch == Fetch::Done;
        let proposers = if fetched { &entry.proposers.duties[..] } else { &[] };
        proposers.iter().find(|duty| duty.slot == slot)
    }

    fn entry_mut(&mut self, epoch: u64) -> &mut EpochDuties {
        &mut self.epochs[(epoch % 2) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_link::{AttesterDuties, SlotDuties, ValidatorIndices};

    const A: [u8; 48] = [0xaa; 48];
    const B: [u8; 48] = [0xbb; 48];

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

    fn duties_json(root: u8, duties: &[([u8; 48], u64, u64, u64)]) -> String {
        let data = duties
            .iter()
            .map(|(pubkey, index, committee, slot)| {
                format!(
                    r#"{{"pubkey":"0x{}","validator_index":"{index}","committee_index":"{committee}","committee_length":"1","committees_at_slot":"1","validator_committee_index":"0","slot":"{slot}"}}"#,
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
        let mut schedule = DutySchedule::new(false, u64::MAX);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        schedule.request_due(64, &validators, &mut requests);
        let sent = sent(&mut requests);
        let paths = sent.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, [
            "/eth/v1/validator/duties/attester/2",
            "/eth/v1/validator/duties/attester/3"
        ]);

        let json = duties_json(1, &[(B, 9, 4, 70), (A, 7, 3, 65)]);
        schedule.on_duties(sent[0].0, &AttesterDuties(json.as_bytes()), &validators, 64);
        let duty = |key, validator_index, committee_index, slot| AttesterDuty {
            key,
            validator_index,
            committee_index,
            committee_length: 1,
            committees_at_slot: 1,
            slot,
        };
        assert_eq!(schedule.attesters_at(65), [duty(0, 7, 3, 65)]);
        assert_eq!(schedule.attesters_at(70), [duty(1, 9, 4, 70)]);
        assert!(schedule.attesters_at(66).is_empty());
        assert!(schedule.attesters_at(97).is_empty());
    }

    #[test]
    fn failed_fetch_retries_from_the_next_slot() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false, u64::MAX);
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
        let mut schedule = DutySchedule::new(false, u64::MAX);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let sent_ids = sent(&mut requests);
        let current = duties_json(0xc0, &[(A, 7, 3, 65)]);
        let next = duties_json(0xc1, &[(A, 7, 3, 100)]);
        schedule.on_duties(sent_ids[0].0, &AttesterDuties(current.as_bytes()), &validators, 64);
        schedule.on_duties(sent_ids[1].0, &AttesterDuties(next.as_bytes()), &validators, 64);

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
        let mut schedule = DutySchedule::new(false, u64::MAX);
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
        assert_eq!(paths, ["/eth/v1/validator/duties/attester/4"]);
    }

    #[test]
    fn selection_proofs_decide_roles_then_subscribe_once() {
        let validators = validators();
        let mut schedule = DutySchedule::new(false, u64::MAX);
        let mut requests = BeaconRequests::default();
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let fetched = sent(&mut requests)[0].0;
        let json = duties_json(1, &[(A, 7, 3, 65), (B, 9, 4, 70)]);
        schedule.on_duties(fetched, &AttesterDuties(json.as_bytes()), &validators, 64);

        let mut asked = Vec::new();
        schedule.ask_selections(|duty| {
            let id = requests.attestation_data(duty.slot);
            asked.push((id, duty.validator_index));
            id
        });
        schedule.ask_selections(|_| unreachable!("asked once"));
        assert_eq!(asked.iter().map(|(_, index)| *index).collect::<Vec<_>>(), [7, 9]);
        sent(&mut requests);

        schedule.subscriptions_due(64, &mut requests);
        assert!(sent(&mut requests).is_empty(), "roles still unknown");

        schedule.on_selection(asked[0].0, [0x77; 96]);
        schedule.on_selection_failed(asked[1].0);

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

        let aggregators = schedule.aggregators_at(65).collect::<Vec<_>>();
        assert_eq!(aggregators.len(), 1);
        assert_eq!((aggregators[0].0.validator_index, aggregators[0].1), (7, [0x77; 96]));
        assert_eq!(schedule.aggregators_at(70).count(), 0);

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

    fn proposers_json(root: u8, duties: &[([u8; 48], u64, u64)]) -> String {
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
        let mut attest_only = DutySchedule::new(false, u64::MAX);
        attest_only.roll(2);
        attest_only.request_due(64, &validators, &mut requests);
        assert!(sent(&mut requests).iter().all(|(_, path)| path.contains("attester")));

        let mut schedule = DutySchedule::new(true, u64::MAX);
        schedule.roll(2);
        schedule.request_due(64, &validators, &mut requests);
        let fetches = sent(&mut requests);
        let paths = fetches.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, [
            "/eth/v1/validator/duties/attester/2",
            "/eth/v2/validator/duties/proposer/2",
            "/eth/v1/validator/duties/attester/3",
            "/eth/v2/validator/duties/proposer/3"
        ]);
        let json = proposers_json(0xc0, &[(A, 7, 65), ([0xcc; 48], 100, 66)]);
        schedule.on_proposer_duties(fetches[1].0, &SlotDuties(json.as_bytes()), &validators, 64);
        let duty = ProposerDuty {
            key: 0,
            validator_index: 7,
            slot: 65,
            randao: Signing::Unasked,
            preferences: Signing::Unasked,
        };
        assert_eq!(schedule.proposer_at(65), Some(&duty));
        assert_eq!(schedule.proposer_at(66), None);

        let mut asked = Vec::new();
        schedule.ask_randao(|duty| {
            let id = requests.attestation_data(duty.slot);
            asked.push(id);
            id
        });
        schedule.ask_randao(|_| unreachable!("asked once"));
        schedule.on_randao(asked[0], Some([0x7a; 96]));
        assert_eq!(schedule.proposer_at(65).unwrap().randao, Signing::Signed([0x7a; 96]));
    }
}
