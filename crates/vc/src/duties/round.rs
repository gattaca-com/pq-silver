use crate::beacon_link::RequestId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Due,
    Fetching(RequestId),
    /// Its duties went for signing over the data with this root.
    Signing([u8; 32]),
    Done,
}

/// One slot's duties of a kind, which all sign one value fetched once in the
/// slot they fall due.
pub struct DataRound {
    kind: &'static str,
    slot: u64,
    stage: Stage,
    /// The served data, published with each signature.
    json: String,
}

impl DataRound {
    pub fn new(kind: &'static str) -> Self {
        Self { kind, slot: u64::MAX, stage: Stage::Done, json: String::new() }
    }

    /// Only the first call in a slot makes it due.
    pub fn due(&mut self, slot: u64) {
        if self.slot != slot {
            self.slot = slot;
            self.stage = Stage::Due;
        }
    }

    pub fn is_due(&self, slot: u64) -> bool {
        self.slot == slot && self.stage == Stage::Due
    }

    pub fn fetching(&mut self, id: RequestId) {
        debug_assert_eq!(self.stage, Stage::Due);
        self.stage = Stage::Fetching(id);
    }

    /// When `id` is this round's fetch, keeps the served JSON and hands the
    /// data to `sign`, which returns the root it signed.
    pub fn on_data<V>(
        &mut self,
        id: RequestId,
        served: Result<(V, &str), &'static str>,
        sign: impl FnOnce(u64, &V) -> Result<[u8; 32], &'static str>,
    ) {
        if self.stage != Stage::Fetching(id) {
            return;
        }
        let signed = served.and_then(|(data, json)| {
            self.json.clear();
            self.json.push_str(json);
            sign(self.slot, &data)
        });
        self.stage = match signed {
            Ok(root) => Stage::Signing(root),
            Err(error) => {
                silver_log::warn!(slot = self.slot, kind = self.kind, error, "missed");
                Stage::Done
            }
        };
    }

    pub fn on_fetch_failed(&mut self, id: RequestId) {
        if self.stage == Stage::Fetching(id) {
            silver_log::warn!(slot = self.slot, kind = self.kind, "missed: no data");
            self.stage = Stage::Done;
        }
    }

    /// The node has no data for the slot, so there is nothing to sign.
    pub fn on_no_data(&mut self, id: RequestId) {
        if self.stage == Stage::Fetching(id) {
            silver_log::info!(slot = self.slot, kind = self.kind, "nothing to sign: no data");
            self.stage = Stage::Done;
        }
    }

    pub fn signed_root(&self, slot: u64) -> Option<&[u8; 32]> {
        match &self.stage {
            Stage::Signing(root) if self.slot == slot => Some(root),
            _ => None,
        }
    }

    pub fn signed_json(&self, slot: u64) -> Option<&str> {
        self.signed_root(slot).map(|_| self.json.as_str())
    }
}
