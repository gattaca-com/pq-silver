use silver_common::ssz_view::XMSSPubkey;

use crate::beacon_link::{BeaconRequests, RequestId, ValidatorIndices};

pub struct Validators {
    /// Sorted, so answers find their key by binary search.
    pubkeys: Vec<XMSSPubkey>,
    indices: Vec<Option<u64>>,
    known: usize,
    lookup: Option<RequestId>,
    looked_up_epoch: Option<u64>,
}

impl Validators {
    pub fn new(pubkeys: Vec<XMSSPubkey>) -> Self {
        debug_assert!(pubkeys.is_sorted());
        Self {
            indices: vec![None; pubkeys.len()],
            pubkeys,
            known: 0,
            lookup: None,
            looked_up_epoch: None,
        }
    }

    /// Keys arrive sorted. A new one is looked up from the next slot.
    pub fn add(&mut self, pubkey: XMSSPubkey) {
        debug_assert!(self.pubkeys.last().is_none_or(|last| *last < pubkey));
        self.pubkeys.push(pubkey);
        self.indices.push(None);
        self.looked_up_epoch = None;
    }

    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn pubkey(&self, key: usize) -> &XMSSPubkey {
        &self.pubkeys[key]
    }

    pub fn key(&self, pubkey: &XMSSPubkey) -> Option<usize> {
        self.pubkeys.binary_search(pubkey).ok()
    }

    pub fn any_index_known(&self) -> bool {
        self.known > 0
    }

    pub fn known_indices(&self) -> impl Iterator<Item = u64> + '_ {
        self.indices.iter().flatten().copied()
    }

    /// Once per epoch while any key is unknown; a failed lookup retries at the
    /// next call.
    pub fn request_indices(&mut self, epoch: u64, requests: &mut BeaconRequests) {
        if self.lookup.is_some() ||
            self.looked_up_epoch == Some(epoch) ||
            self.known == self.indices.len()
        {
            return;
        }
        let unknown = self.pubkeys.iter().zip(&self.indices).filter(|(_, index)| index.is_none());
        self.lookup = Some(requests.validator_indices(unknown.map(|(pubkey, _)| pubkey)));
        self.looked_up_epoch = Some(epoch);
    }

    /// Whether the answer taught any new index.
    pub fn on_indices(&mut self, id: RequestId, validators: &ValidatorIndices<'_>) -> bool {
        if self.lookup != Some(id) {
            return false;
        }
        self.lookup = None;

        let Self { pubkeys, indices, known, .. } = self;
        let known_before = *known;
        let answered = validators.for_each(pubkeys.len(), |pubkey, index| {
            if let Ok(at) = pubkeys.binary_search(pubkey) {
                *known += usize::from(indices[at].replace(index).is_none());
            }
        });
        if let Err(error) = answered {
            silver_log::warn!(error, "validator index lookup");
            self.looked_up_epoch = None;
        }

        let (known, unknown) = (self.known, self.indices.len() - self.known);
        silver_log::info!(known, unknown, "validator indices");
        known > known_before
    }

    pub fn on_failed(&mut self, id: RequestId) {
        if self.lookup == Some(id) {
            self.lookup = None;
            self.looked_up_epoch = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: XMSSPubkey = [0xaa; 32];
    const B: XMSSPubkey = [0xbb; 32];

    fn sent_bodies(requests: &mut BeaconRequests) -> Vec<(RequestId, String)> {
        let mut sent = Vec::new();
        requests.drain(|id, _, _, body| sent.push((id, String::from_utf8(body.to_vec()).unwrap())));
        sent
    }

    fn answer_a_is(validators: &mut Validators, id: RequestId, index: u64) {
        let json = format!(
            r#"{{"data":[{{"index":"{index}","validator":{{"pubkey":"0x{}"}}}}]}}"#,
            hex::encode(A)
        );
        validators.on_indices(id, &ValidatorIndices(json.as_bytes()));
    }

    #[test]
    fn unknown_keys_are_looked_up_once_per_epoch() {
        let mut validators = Validators::new(vec![A, B]);
        let mut requests = BeaconRequests::default();

        validators.request_indices(1, &mut requests);
        validators.request_indices(1, &mut requests);
        let sent = sent_bodies(&mut requests);
        assert_eq!(sent.len(), 1);
        answer_a_is(&mut validators, sent[0].0, 5);
        assert_eq!(validators.indices, [Some(5), None]);

        validators.request_indices(1, &mut requests);
        assert!(sent_bodies(&mut requests).is_empty());

        validators.request_indices(2, &mut requests);
        let sent = sent_bodies(&mut requests);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains(&hex::encode(B)) && !sent[0].1.contains(&hex::encode(A)));
    }

    #[test]
    fn failed_or_malformed_lookup_retries_within_the_epoch() {
        let mut validators = Validators::new(vec![A]);
        let mut requests = BeaconRequests::default();

        validators.request_indices(1, &mut requests);
        let failed = sent_bodies(&mut requests)[0].0;
        validators.on_failed(failed);

        validators.request_indices(1, &mut requests);
        let malformed = sent_bodies(&mut requests)[0].0;
        validators.on_indices(malformed, &ValidatorIndices(b"{}"));

        validators.request_indices(1, &mut requests);
        assert_eq!(sent_bodies(&mut requests).len(), 1);
    }

    #[test]
    fn stale_answers_are_ignored_and_known_keys_stop_lookups() {
        let mut validators = Validators::new(vec![A]);
        let mut requests = BeaconRequests::default();
        validators.request_indices(1, &mut requests);
        let stale = sent_bodies(&mut requests)[0].0;
        validators.on_failed(stale);
        answer_a_is(&mut validators, stale, 5);
        assert_eq!(validators.indices, [None]);

        validators.request_indices(1, &mut requests);
        let id = sent_bodies(&mut requests)[0].0;
        answer_a_is(&mut validators, id, 5);
        validators.request_indices(2, &mut requests);
        assert!(sent_bodies(&mut requests).is_empty());
    }
}
