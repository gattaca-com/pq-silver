use serde::Deserialize;
use silver_common::{
    BeaconApiRequest, ForkName, SlotSubnets, SubnetsBySlot, compute_subnet_for_attestation,
    json_fields::uint64, ssz_view::MAX_COMMITTEES_PER_SLOT,
};

use crate::{
    ctx::ApiCtx,
    http::{ids::each_body_entry, response::Response, router::Request},
};

pub(crate) fn post_beacon_committee_subscriptions(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let window = SubnetsBySlot::window(ctx.node_status.wall_slot);
    let mut by_slot = SubnetsBySlot::default();
    let parsed = each_body_entry(req.body, |_, entry: CommitteeSubscription| {
        let format = ctx.spec.fork_at_slot(entry.slot);
        if let Some(mut slot_subnets) =
            entry.slot_subnets(format).filter(|held| window.contains(&held.slot))
        {
            if let Some(position) = (entry.is_aggregator && format == ForkName::Pq)
                .then(|| entry.aggregator_position(ctx))
                .flatten()
            {
                let subnet = u64::from(slot_subnets.aggregating.trailing_zeros());
                slot_subnets.aggregator_positions = SlotSubnets::position_bit(subnet, position);
            }
            by_slot.insert(slot_subnets);
        }
    });
    if let Err(message) = parsed {
        return resp.error(400, message);
    }
    let held = by_slot.held().count();
    if held == 0 {
        return resp.ok();
    }

    resp.submit(
        held * SlotSubnets::SIZE,
        |out| {
            for (record, slot) in out.chunks_exact_mut(SlotSubnets::SIZE).zip(by_slot.held()) {
                slot.encode(record);
            }
        },
        |subscriptions| BeaconApiRequest::BeaconCommitteeSubscriptions { subscriptions },
    );
}

#[derive(Deserialize)]
struct CommitteeSubscription {
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    #[serde(deserialize_with = "uint64")]
    committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    committees_at_slot: u64,
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    is_aggregator: bool,
}

impl CommitteeSubscription {
    /// Its place in the committee's aggregation committee. `None` when the
    /// head state does not show it.
    fn aggregator_position(&self, ctx: &ApiCtx) -> Option<u64> {
        ctx.read_state(|view| {
            let window = view.epoch.aggregation_committee_window();
            let index = usize::try_from(self.committee_index).ok()?;
            let mut aggregators = window.committee(view.slot.current_epoch(), self.slot, index)?;
            aggregators.position(|member| member == self.validator_index)
        })
        .map(|position| position as u64)
    }

    fn slot_subnets(&self, format: ForkName) -> Option<SlotSubnets> {
        let committees = self.committees_at_slot;
        if self.committee_index >= committees ||
            committees >
                (if format == ForkName::Pq {
                    silver_common::ssz_view::MAX_COMMITTEES_PER_SLOT_PQ
                } else {
                    MAX_COMMITTEES_PER_SLOT
                }) as u64
        {
            return None;
        }
        let subnet = 1 <<
            compute_subnet_for_attestation(format, committees, self.slot, self.committee_index);
        Some(SlotSubnets {
            slot: self.slot,
            attesting: subnet,
            aggregating: if self.is_aggregator { subnet } else { 0 },
            aggregator_positions: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        AggregationCommittee, BeaconState, BeaconStateOwner, EpochState, EpochStateFinalized,
        SpecConfig, ValSeed,
    };
    use silver_common::TCacheProducer;

    use super::*;
    use crate::{
        ctx::{anchor_ctx, test_ctx},
        http::router::Outcome,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/validator/beacon_committee_subscriptions";

    fn entry(
        committee_index: u64,
        committees_at_slot: u64,
        slot: u64,
        is_aggregator: bool,
    ) -> String {
        format!(
            "{{\"validator_index\":\"1\",\"committee_index\":\"{committee_index}\",\
             \"committees_at_slot\":\"{committees_at_slot}\",\"slot\":\"{slot}\",\
             \"is_aggregator\":{is_aggregator}}}"
        )
    }

    fn post(body: &str) -> (Outcome, Vec<u8>) {
        dispatch(&anchor_ctx(), &posting(PATH, body))
    }

    #[test]
    fn subscriptions_are_squashed_by_slot_into_the_cache() {
        let body = format!(
            "[{},{},{}]",
            entry(0, 4, 32, true),
            entry(3, 4, 32, false),
            entry(1, 4, 33, false)
        );
        let mut submissions = submissions();
        let (outcome, response) =
            dispatch_into(&anchor_ctx(), &posting(PATH, &body), &mut submissions);
        assert_eq!(status_code(&response), "200");
        let Outcome::Response(Some(BeaconApiRequest::BeaconCommitteeSubscriptions {
            subscriptions,
        })) = outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        assert!(SlotSubnets::decode_all(written).eq([
            SlotSubnets {
                slot: 32,
                attesting: 1 << 0 | 1 << 3,
                aggregating: 1 << 0,
                aggregator_positions: 0,
            },
            SlotSubnets { slot: 33, attesting: 1 << 5, ..SlotSubnets::default() },
        ]));
    }

    /// The aggregator position of validator 1, aggregating on `slot`'s
    /// committee 1. The head's window places it third there for slot 33.
    fn pq_aggregator_position(slot: u64) -> u64 {
        let seeds: Vec<_> = (0..10).map(|_| ValSeed::default()).collect();
        let state = BeaconState::for_test(
            EpochStateFinalized::from_state(EpochState::default()),
            &seeds,
            0,
        );
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        let mut fork = owner.apply_block_view(anchor);
        let mut epoch = fork.epoch.roll_fresh();
        epoch.rotate_aggregation_committee_window(2, |slot_in_epoch, index| {
            let mut committee = AggregationCommittee::default();
            if (slot_in_epoch, index) == (1, 1) {
                [5, 9, 1].into_iter().for_each(|member| committee.push(member));
            }
            committee
        });
        fork.epoch_idx = Some(epoch.commit());
        let head = fork.commit();
        owner.publish_state_id(head);
        let spec = SpecConfig { pq_fork_epoch: 0, ..SpecConfig::mainnet() };
        let ctx = test_ctx(&spec, owner.reader());

        let body = format!("[{}]", entry(1, 2, slot, true));
        let mut submissions = submissions();
        let (outcome, _) = dispatch_into(&ctx, &posting(PATH, &body), &mut submissions);
        let Outcome::Response(Some(BeaconApiRequest::BeaconCommitteeSubscriptions {
            subscriptions,
        })) = outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        let [held] = SlotSubnets::decode_all(written).collect::<Vec<_>>()[..] else {
            panic!("one slot")
        };
        let subnet = u64::from(held.aggregating.trailing_zeros());
        held.last_aggregator_position(subnet).unwrap()
    }

    #[test]
    fn a_pq_aggregator_takes_its_position_in_the_aggregation_committee() {
        assert_eq!(pq_aggregator_position(33), 2);
        assert_eq!(pq_aggregator_position(34), 3, "not placed in slot 34: the last position");
    }

    #[test]
    fn a_pq_aggregator_the_state_does_not_place_takes_the_last_position() {
        let spec = SpecConfig { pq_fork_epoch: 0, ..SpecConfig::mainnet() };
        let ctx = test_ctx(&spec, BeaconStateOwner::published_empty_test(0).reader());
        let body = format!("[{},{}]", entry(2, 4, 1, true), entry(3, 4, 1, false));
        let mut submissions = submissions();
        let (outcome, _) = dispatch_into(&ctx, &posting(PATH, &body), &mut submissions);
        let Outcome::Response(Some(BeaconApiRequest::BeaconCommitteeSubscriptions {
            subscriptions,
        })) = outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        let [held] = SlotSubnets::decode_all(written).collect::<Vec<_>>()[..] else {
            panic!("one slot")
        };
        let subnet = u64::from(held.aggregating.trailing_zeros());
        assert_eq!(held.aggregating.count_ones(), 1);
        assert_eq!(held.aggregator_positions, 0, "no place named");
        assert_eq!(held.last_aggregator_position(subnet), Some(3));
    }

    #[test]
    fn entries_naming_no_committee_of_their_slot_are_dropped() {
        for entry in [entry(4, 4, 32, true), entry(0, 65, 32, true), entry(0, 0, 32, true)] {
            let (outcome, response) = post(&format!("[{entry}]"));
            assert_eq!(outcome, Outcome::Response(None), "{entry}");
            assert_eq!(status_code(&response), "200", "{entry}");
        }
    }

    #[test]
    fn slots_outside_the_lookahead_from_the_wall_slot_are_dropped() {
        let mut ctx = anchor_ctx();
        ctx.node_status.wall_slot = 100;
        let last = 100 + SubnetsBySlot::LOOKAHEAD_SLOTS;
        for (slot, forwarded) in [(99, false), (100, true), (last, true), (last + 1, false)] {
            let body = format!("[{}]", entry(0, 1, slot, false));
            let (outcome, response) = dispatch(&ctx, &posting(PATH, &body));
            assert_eq!(status_code(&response), "200", "{slot}");
            assert_eq!(outcome != Outcome::Response(None), forwarded, "{slot}");
        }
    }

    #[test]
    fn malformed_bodies_are_a_400() {
        let entry = entry(0, 4, 32, false);
        for body in [
            String::new(),
            "{}".to_owned(),
            "[1]".to_owned(),
            format!("[{}]", entry.replace("\"4\"", "4")),
            format!("[{}]", entry.replace("false", "\"false\"")),
        ] {
            let (outcome, response) = post(&body);
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&response), "400", "{body}");
        }
    }
}
