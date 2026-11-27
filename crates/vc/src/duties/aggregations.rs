use silver_common::{
    merkle::ZERO_HASH, ssz_hash_pq::hash_tree_root_aggregate_and_proof, vc_spine::ServedAggregate,
};

use crate::{
    beacon_link::{Aggregate, RequestId},
    duties::schedule::AttesterDuty,
};

struct Fetch {
    id: RequestId,
    aggregator: AttesterDuty,
}

/// One slot's aggregates: one fetch per aggregator, each hashed once served.
/// A slot's positions fetch in turn, so its fetches and served objects
/// accumulate until the next slot.
pub struct Aggregations {
    slot: u64,
    fetches: Vec<Fetch>,
    /// Served objects, published with their signatures.
    served: String,
    attestation_scratch: Vec<u8>,
    proof_scratch: Vec<u8>,
}

impl Aggregations {
    pub fn new() -> Self {
        Self {
            slot: u64::MAX,
            fetches: Vec::new(),
            served: String::new(),
            attestation_scratch: Vec::new(),
            proof_scratch: Vec::new(),
        }
    }

    pub fn fetching(
        &mut self,
        slot: u64,
        fetches: impl IntoIterator<Item = (RequestId, AttesterDuty)>,
    ) {
        if self.slot != slot {
            self.slot = slot;
            self.served.clear();
            self.fetches.clear();
        }
        self.fetches.extend(fetches.into_iter().map(|(id, aggregator)| Fetch { id, aggregator }));
    }

    /// The aggregator and its `AggregateAndProof` root, when `id` fetched a
    /// well-formed aggregate.
    pub fn on_aggregate(
        &mut self,
        id: RequestId,
        aggregate: &Aggregate<'_>,
    ) -> Option<(AttesterDuty, [u8; 32], ServedAggregate)> {
        let aggregator = self.fetches.iter().find(|fetch| fetch.id == id)?.aggregator;
        let (slot, committee) = (self.slot, aggregator.committee_index);
        let json = aggregate
            .parse(&mut self.attestation_scratch, &mut self.proof_scratch)
            .inspect_err(|error| silver_log::warn!(slot, committee, error, "aggregate dropped"))
            .ok()?;
        let root = hash_tree_root_aggregate_and_proof(
            aggregator.validator_index,
            &self.attestation_scratch,
            &self.proof_scratch,
        );
        if root == ZERO_HASH {
            silver_log::warn!(slot, committee, "aggregate malformed");
            return None;
        }
        let start = self.served.len() as u32;
        self.served.push_str(json);
        Some((aggregator, root, ServedAggregate { start, end: self.served.len() as u32 }))
    }

    pub fn served(&self, slot: u64, served: ServedAggregate) -> Option<&str> {
        (self.slot == slot).then(|| &self.served[served.start as usize..served.end as usize])
    }
}
