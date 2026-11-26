use silver_common::ssz_view::XMSSSignature;

use crate::beacon_link::RequestId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Waiting,
    Due,
    Working,
    Publishing { id: RequestId, count: usize },
    Done,
}

enum Signature {
    Awaiting,
    Signed(Box<XMSSSignature>),
    Refused,
}

struct Pending<T> {
    id: RequestId,
    item: T,
    signature: Signature,
}

/// One slot's duty of a kind: due on its trigger, one signature per item, then
/// a single publish, at most once per slot.
pub struct SlotRound<T> {
    kind: &'static str,
    slot: u64,
    stage: Stage,
    /// In request order, so ids ascend.
    pending: Vec<Pending<T>>,
}

impl<T> SlotRound<T> {
    pub fn new(kind: &'static str) -> Self {
        Self { kind, slot: 0, stage: Stage::Waiting, pending: Vec::new() }
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Whether `slot` starts a new round, so the owner resets its own state.
    pub fn due(&mut self, slot: u64) -> bool {
        let new = self.slot != slot;
        if new {
            self.slot = slot;
            self.stage = Stage::Waiting;
            self.pending.clear();
        }
        if self.stage == Stage::Waiting {
            self.stage = Stage::Due;
        }
        new
    }

    pub fn working(&mut self) {
        self.stage = Stage::Working;
    }

    pub fn abandon(&mut self) {
        self.stage = Stage::Done;
    }

    pub fn sign(&mut self, id: RequestId, item: T) {
        debug_assert!(self.pending.last().is_none_or(|last| last.id < id));
        self.pending.push(Pending { id, item, signature: Signature::Awaiting });
    }

    /// A refusal drops only that item's signature.
    pub fn on_answer(&mut self, id: RequestId, signature: Option<Box<XMSSSignature>>) {
        if let Some(pending) = self.pending_mut(id) {
            pending.signature = signature.map_or(Signature::Refused, Signature::Signed);
        }
    }

    pub fn all_signatures_answered(&self) -> bool {
        self.pending.iter().all(|pending| !matches!(pending.signature, Signature::Awaiting))
    }

    pub fn signed(&self) -> impl Iterator<Item = (&T, &XMSSSignature)> {
        self.pending.iter().filter_map(|pending| match &pending.signature {
            Signature::Signed(signature) => Some((&pending.item, &**signature)),
            Signature::Awaiting | Signature::Refused => None,
        })
    }

    /// Publishes what was signed, or ends the round when nothing was.
    pub fn publish(&mut self, send: impl FnOnce(&Self) -> RequestId) {
        let count = self.signed().count();
        if count == 0 {
            silver_log::warn!(slot = self.slot, kind = self.kind, "nothing signed to publish");
            self.stage = Stage::Done;
            return;
        }
        self.stage = Stage::Publishing { id: send(self), count };
    }

    pub fn on_accepted(&mut self, id: RequestId) {
        if let Stage::Publishing { id: sent, count } = self.stage &&
            sent == id
        {
            silver_log::info!(slot = self.slot, count, kind = self.kind, "published");
            self.stage = Stage::Done;
        }
    }

    pub fn on_publish_failed(&mut self, id: RequestId) {
        if let Stage::Publishing { id: sent, .. } = self.stage &&
            sent == id
        {
            silver_log::warn!(slot = self.slot, kind = self.kind, "not published");
            self.stage = Stage::Done;
        }
    }

    fn pending_mut(&mut self, id: RequestId) -> Option<&mut Pending<T>> {
        let at = self.pending.binary_search_by_key(&id, |pending| pending.id).ok()?;
        Some(&mut self.pending[at])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data<V> {
    Unasked,
    Awaiting(RequestId),
    Ready(V),
    /// Sent for signing; later duties of the slot reuse it.
    Signing(V),
}

/// A round whose items all sign one value fetched once per slot.
pub struct DataRound<V, T> {
    pub round: SlotRound<T>,
    pub data: Data<V>,
}

impl<V: Copy + PartialEq, T> DataRound<V, T> {
    pub fn new(kind: &'static str) -> Self {
        Self { round: SlotRound::new(kind), data: Data::Unasked }
    }

    pub fn due(&mut self, slot: u64) {
        if self.round.due(slot) {
            self.data = Data::Unasked;
        }
    }

    pub fn on_data(&mut self, id: RequestId, data: Result<V, &'static str>) {
        if self.data != Data::Awaiting(id) {
            return;
        }
        match data {
            Ok(data) => self.data = Data::Ready(data),
            Err(error) => {
                silver_log::warn!(
                    slot = self.round.slot(),
                    kind = self.round.kind,
                    error,
                    "missed"
                );
                self.round.abandon();
            }
        }
    }

    pub fn on_data_failed(&mut self, id: RequestId) {
        if self.data == Data::Awaiting(id) {
            silver_log::warn!(slot = self.round.slot(), kind = self.round.kind, "missed: no data");
            self.round.abandon();
        }
    }

    pub fn signed_data(&self, slot: u64) -> Option<&V> {
        match &self.data {
            Data::Signing(data) if self.round.slot() == slot => Some(data),
            _ => None,
        }
    }
}
