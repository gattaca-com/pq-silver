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
    /// Its place in the committee's aggregation committee.
    pub position: u64,
}

enum Served {
    Awaiting,
    Proved { json: Range<usize>, attestation: Vec<u8>, proof: Vec<u8> },
    SentForSigning,
    Dropped,
}

struct Fetch {
    id: RequestId,
    duty: AggregatorDuty,
    served: Served,
}

pub struct AggregateItem {
    duty: AggregatorDuty,
    /// The served `{"aggregate": …, "proof": …}` object in
    /// `Aggregations::json`.
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

    pub fn fetching(&mut self, fetches: impl IntoIterator<Item = (RequestId, AggregatorDuty)>) {
        self.fetches.extend(fetches.into_iter().map(|(id, duty)| Fetch {
            id,
            duty,
            served: Served::Awaiting,
        }));
        if self.fetches.is_empty() { self.round.abandon() } else { self.round.working() }
    }

    pub fn on_aggregate(&mut self, id: RequestId, aggregate: &Aggregate<'_>) {
        let Some(fetch) = self.fetches.iter_mut().find(|fetch| fetch.id == id) else { return };
        fetch.served = match aggregate.parse() {
            Ok(proved) => {
                let start = self.json.len();
                self.json.push_str(proved.json);
                let json = start..self.json.len();
                Served::Proved { json, attestation: proved.attestation, proof: proved.proof }
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

    /// Hands each newly served aggregate's attestation SSZ and proof to
    /// `sign`, which returns its request, or `None` to drop it.
    pub fn sign_served(
        &mut self,
        mut sign: impl FnMut(&AggregatorDuty, &[u8], &[u8]) -> Option<RequestId>,
    ) {
        let Self { round, fetches, .. } = self;
        for fetch in fetches.iter_mut() {
            let Served::Proved { json, attestation, proof } = &fetch.served else { continue };
            let json = json.clone();
            fetch.served = match sign(&fetch.duty, attestation, proof) {
                Some(id) => {
                    round.sign(id, AggregateItem { duty: fetch.duty, json });
                    Served::SentForSigning
                }
                None => Served::Dropped,
            };
        }
    }

    pub fn all_answered(&self) -> bool {
        let fetched = self
            .fetches
            .iter()
            .all(|fetch| matches!(fetch.served, Served::SentForSigning | Served::Dropped));
        fetched && self.round.all_signatures_answered()
    }

    pub fn publish(
        &mut self,
        send: impl FnOnce(&mut dyn Iterator<Item = SignedAggregate<'_>>) -> RequestId,
    ) {
        let Self { round, json, .. } = self;
        round.publish(|round| {
            let mut signed = round.signed().map(|(aggregate, signature)| SignedAggregate {
                aggregator_index: aggregate.duty.validator_index,
                proved: &json[aggregate.json.clone()],
                signature,
            });
            send(&mut signed)
        });
    }
}
