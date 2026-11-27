use silver_beacon_state_data::AGGREGATORS_PER_COMMITTEE;
use silver_common::{
    leanvm::{MAX_PROOFS, ProofBody, ProofLen},
    ssz_view::MAX_COMMITTEES_PER_SLOT_PQ,
};

use super::{claims::Claim, proof_sources::SOURCE_SLOTS};

pub(super) const MAX_AGGREGATE_PROOFS: usize = 256;
pub(super) const MAX_BLOCK_PROOFS: usize = 8;
// A block merge that picks aggregates has a running proof, leaving at most
// MAX_PROOFS - 1 orphaned picks and one new buffer during settlement.
const MAX_BUFFERS: usize = SOURCE_SLOTS * MAX_COMMITTEES_PER_SLOT_PQ * AGGREGATORS_PER_COMMITTEE +
    MAX_AGGREGATE_PROOFS +
    MAX_BLOCK_PROOFS +
    MAX_PROOFS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProofId(u16);

#[derive(Default)]
struct Buffer {
    bytes: Box<[u8]>,
    len: ProofLen,
    refs: u8,
}

pub(super) struct ProofStore {
    buffers: Box<[Buffer]>,
}

impl Default for ProofStore {
    fn default() -> Self {
        Self { buffers: std::iter::repeat_with(Buffer::default).take(MAX_BUFFERS).collect() }
    }
}

impl ProofStore {
    pub(super) fn take(&mut self, len: ProofLen, tail_len: usize) -> (ProofId, &mut [u8]) {
        let required = len.bytes() + tail_len;
        let index = self
            .buffers
            .iter()
            .enumerate()
            .filter(|(_, buffer)| buffer.refs == 0)
            .min_by_key(|(_, buffer)| (buffer.bytes.len() < required, buffer.bytes.len()))
            .map(|(index, _)| index)
            .expect("proof store has a free buffer");
        let buffer = &mut self.buffers[index];
        if buffer.bytes.len() < required {
            buffer.bytes = vec![0; required.next_power_of_two().max(64 * 1024)].into_boxed_slice();
        }
        buffer.len = len;
        buffer.refs = 1;
        (ProofId(index as u16), &mut buffer.bytes[..required])
    }

    pub(super) fn replace_response(
        &mut self,
        current: Option<ProofId>,
        running: Option<ProofId>,
        response: ProofBody<'_>,
    ) -> ProofId {
        let bytes = response.bytes();
        let len = response.lengths();
        if let Some(id) = current {
            let buffer = &mut self.buffers[usize::from(id.0)];
            // The request's reference is released when settlement returns.
            let owned = 1 + u8::from(running == current);
            if buffer.refs == owned && buffer.bytes.len() >= bytes.len() {
                buffer.bytes[..bytes.len()].copy_from_slice(bytes);
                buffer.len = len;
                return id;
            }
            self.release(id);
        }
        let (id, target) = self.take(len, 0);
        target.copy_from_slice(bytes);
        id
    }

    pub(super) fn release(&mut self, id: ProofId) {
        let buffer = &mut self.buffers[usize::from(id.0)];
        assert!(buffer.refs > 0);
        buffer.refs -= 1;
    }

    pub(super) fn share(&mut self, id: ProofId) {
        let buffer = &mut self.buffers[usize::from(id.0)];
        assert!(buffer.refs > 0);
        buffer.refs += 1;
    }

    fn buffer(&self, id: ProofId) -> &Buffer {
        let buffer = &self.buffers[usize::from(id.0)];
        assert!(buffer.refs > 0);
        buffer
    }

    pub(super) fn claims(&self, id: ProofId) -> &[Claim] {
        let buffer = self.buffer(id);
        buffer.bytes[..buffer.len.claims as usize * size_of::<Claim>()].as_chunks().0
    }

    pub(super) fn proof(&self, id: ProofId) -> &[u8] {
        let buffer = self.buffer(id);
        &buffer.bytes[buffer.len.claims as usize * size_of::<Claim>()..buffer.len.bytes()]
    }

    pub(super) fn bytes(&self, id: ProofId) -> &[u8] {
        let buffer = self.buffer(id);
        &buffer.bytes[..buffer.len.bytes()]
    }

    pub(super) fn len(&self, id: ProofId) -> ProofLen {
        self.buffer(id).len
    }

    pub(super) fn tail(&self, id: ProofId, len: usize) -> &[u8] {
        let buffer = self.buffer(id);
        let start = buffer.len.bytes();
        &buffer.bytes[start..start + len]
    }
}

#[cfg(test)]
mod tests;
