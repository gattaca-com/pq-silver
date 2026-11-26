use std::ops::Range;

use crate::{
    beacon_link::{Aggregate, RequestId, SignedAggregate},
    duties::round::SlotRound,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregatorDuty {
    /// Position in `Validators`.
    pub key: usize,
    pub validator_index: u64,
    pub committee: u64,
}

enum Served {
    Awaiting,
    Aggregate(Range<usize>),
    SentForSigning,
    Dropped,
}

struct Fetch {
    id: RequestId,
    duty: AggregatorDuty,
    selection_proof: [u8; 96],
    served: Served,
}

pub struct AggregateItem {
    duty: AggregatorDuty,
    selection_proof: [u8; 96],
    /// The aggregate's JSON object in `Aggregations::json`.
    json: Range<usize>,
}

/// One slot's aggregates: one fetch per aggregator duty, each signed once
/// served.
pub struct Aggregations {
    pub round: SlotRound<AggregateItem>,
    fetches: Vec<Fetch>,
    /// Served aggregates' JSON, reused across slots.
    json: String,
}

impl Aggregations {
    pub fn new(kind: &'static str) -> Self {
        Self { round: SlotRound::new(kind), fetches: Vec::new(), json: String::new() }
    }

    pub fn due(&mut self, slot: u64) {
        if self.round.due(slot) {
            self.fetches.clear();
            self.json.clear();
        }
    }

    /// `fetches` pairs each aggregator duty and its selection proof with its
    /// aggregate request.
    pub fn fetching(
        &mut self,
        fetches: impl IntoIterator<Item = (RequestId, AggregatorDuty, [u8; 96])>,
    ) {
        self.fetches.extend(fetches.into_iter().map(|(id, duty, selection_proof)| Fetch {
            id,
            duty,
            selection_proof,
            served: Served::Awaiting,
        }));
        if self.fetches.is_empty() { self.round.abandon() } else { self.round.working() }
    }

    pub fn on_aggregate(&mut self, id: RequestId, aggregate: &Aggregate<'_>) {
        let Some(fetch) = self.fetches.iter_mut().find(|fetch| fetch.id == id) else { return };
        fetch.served = match aggregate.json() {
            Ok(json) => {
                let start = self.json.len();
                self.json.push_str(json);
                Served::Aggregate(start..self.json.len())
            }
            Err(error) => {
                silver_log::warn!(slot = self.round.slot(), error, "aggregate dropped");
                Served::Dropped
            }
        };
    }

    pub fn on_fetch_failed(&mut self, id: RequestId) {
        if let Some(fetch) = self.fetches.iter_mut().find(|fetch| fetch.id == id) {
            fetch.served = Served::Dropped;
        }
    }

    /// Hands each newly served aggregate to `sign`, which returns its
    /// request.
    pub fn sign_served(
        &mut self,
        mut sign: impl FnMut(&AggregatorDuty, &[u8; 96], &str) -> RequestId,
    ) {
        let Self { round, fetches, json } = self;
        for fetch in fetches.iter_mut() {
            let Served::Aggregate(range) = &fetch.served else { continue };
            let range = range.clone();
            let id = sign(&fetch.duty, &fetch.selection_proof, &json[range.clone()]);
            let aggregate = AggregateItem {
                duty: fetch.duty,
                selection_proof: fetch.selection_proof,
                json: range,
            };
            round.sign(id, aggregate);
            fetch.served = Served::SentForSigning;
        }
    }

    pub fn all_answered(&self) -> bool {
        let fetched = self
            .fetches
            .iter()
            .all(|fetch| matches!(fetch.served, Served::SentForSigning | Served::Dropped));
        fetched && self.round.all_signatures_answered()
    }

    pub fn publish<'a>(
        &'a mut self,
        send: impl FnOnce(&mut dyn Iterator<Item = SignedAggregate<'a>>) -> RequestId,
    ) {
        let Self { round, json, .. } = self;
        round.publish(|round| {
            let mut signed = round.signed().map(|(aggregate, signature)| SignedAggregate {
                aggregator_index: aggregate.duty.validator_index,
                aggregate: &json[aggregate.json.clone()],
                selection_proof: aggregate.selection_proof,
                signature,
            });
            send(&mut signed)
        });
    }
}
