use serde::Deserialize;
use silver_common::{
    BeaconApiRequest, ForkName, SlotSubnets, SubnetsBySlot, compute_subnet_for_attestation,
    json_fields::uint64,
    ssz_view::{MAX_COMMITTEES_PER_SLOT, MAX_COMMITTEES_PER_SLOT_PQ},
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
        if window.contains(&entry.slot) &&
            let Some(slot_subnets) = entry.slot_subnets(ctx)
        {
            by_slot.insert(slot_subnets);
        }
    });
    if let Err(message) = parsed {
        return resp.error(400, message);
    }
    resp.ok();
    submit_committee_subscriptions(&by_slot, resp);
}

pub(super) fn submit_committee_subscriptions(by_slot: &SubnetsBySlot, resp: &mut Response<'_>) {
    let held = by_slot.held().count();
    if held == 0 {
        return;
    }

    resp.submit(
        held * SlotSubnets::SIZE,
        |out| {
            let records = out.as_chunks_mut::<{ SlotSubnets::SIZE }>().0;
            for (record, slot) in records.iter_mut().zip(by_slot.held()) {
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
    /// Its place in the committee's aggregation committee. The last place
    /// when the head state does not show it, so its votes are cut off latest.
    fn aggregator_position(&self, ctx: &ApiCtx) -> u64 {
        let position = ctx.read_state(|view| {
            let window = view.epoch.aggregation_committee_window();
            let index = usize::try_from(self.committee_index).ok()?;
            let mut aggregators = window.committee(view.slot.current_epoch(), self.slot, index)?;
            aggregators.position(|member| member == self.validator_index)
        });
        position.map_or(SlotSubnets::POSITIONS_PER_SUBNET - 1, |position| position as u64)
    }

    fn slot_subnets(&self, ctx: &ApiCtx) -> Option<SlotSubnets> {
        let format = ctx.spec.fork_at_slot(self.slot);
        let committees = self.committees_at_slot;
        if self.committee_index >= committees ||
            committees >
                (if format == ForkName::Pq {
                    MAX_COMMITTEES_PER_SLOT_PQ
                } else {
                    MAX_COMMITTEES_PER_SLOT
                }) as u64
        {
            return None;
        }
        if self.is_aggregator && format == ForkName::Pq {
            return Some(SlotSubnets::pq_aggregator(
                self.slot,
                committees,
                self.committee_index,
                self.aggregator_position(ctx),
            ));
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
    use silver_beacon_state_data::{BeaconStateOwner, SpecConfig};
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
        assert_eq!(held.aggregator_positions, SlotSubnets::position_bit(subnet, 3));
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
