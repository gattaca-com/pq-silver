use silver_common::ssz_view::{
    MAX_STARK_PROOF_SIZE, MAX_VALIDATORS_PER_COMMITTEE, XMSS_SIGNATURE_SIZE,
};

use super::{claims::Claim, strategy::MAX_GROUPS};

const OP_AGGREGATE: u8 = 1;
const RECORD_SIZE: usize = 64 + XMSS_SIGNATURE_SIZE;

/// Most leanXMSS records in one request.
pub(super) const MAX_RECORDS: usize = 2048;
/// Most children in one request.
pub(super) const MAX_CHILDREN: usize = 16;
/// Most claims one proof covers: every position of every committee a merge
/// tells apart. A response with more is refused.
const MAX_PROOF_CLAIMS: usize = MAX_GROUPS * MAX_VALIDATORS_PER_COMMITTEE;

/// The longest `aggregate` request. The best proof, the longest child, comes
/// first. A leaf adds records; a merge adds children of one committee each.
pub(in crate::tile) const MAX_REQUEST_LEN: usize = {
    let best = child_len(MAX_PROOF_CLAIMS, MAX_STARK_PROOF_SIZE);
    let child = child_len(MAX_VALIDATORS_PER_COMMITTEE, MAX_STARK_PROOF_SIZE);
    let leaf = request_len(best, MAX_RECORDS);
    let merge = request_len(best + (MAX_CHILDREN - 1) * child, 0);
    if leaf > merge { leaf } else { merge }
};

/// One `aggregate` request, borrowed from its aggregation: children (claims,
/// proof) and leanXMSS records. No leanSPHINCS signatures, no blobs, every
/// covered claim as output.
pub(super) struct AggregateRequest<'a> {
    pub log_inv_rate: u8,
    pub children: Vec<(&'a [Claim], &'a [u8])>,
    pub records: Vec<(&'a Claim, &'a [u8; XMSS_SIGNATURE_SIZE])>,
}

impl AggregateRequest<'_> {
    pub(super) fn len(&self) -> usize {
        let children =
            self.children.iter().map(|(claims, proof)| child_len(claims.len(), proof.len()));
        request_len(children.sum(), self.records.len())
    }

    /// Fills `out`, which must be exactly `len()` bytes: a gap would send
    /// whatever `out` held before.
    pub(super) fn write(&self, mut out: &mut [u8]) {
        put(&mut out, &[OP_AGGREGATE, self.log_inv_rate]);
        put_u64(&mut out, self.children.len());
        for (claims, proof) in &self.children {
            put_claims(&mut out, claims);
            put_bytes(&mut out, proof);
        }
        put_u64(&mut out, self.records.len());
        for (claim, signature) in &self.records {
            put(&mut out, *claim);
            put(&mut out, *signature);
        }
        put_u64(&mut out, 0);
        put_u64(&mut out, 0);
        put(&mut out, &[0]);
        assert!(out.is_empty(), "aggregate request shorter than its slice");
    }

    #[cfg(test)]
    pub(super) fn body(&self) -> Vec<u8> {
        let mut body = vec![0; self.len()];
        self.write(&mut body);
        body
    }
}

/// Panics if `out` is shorter than `bytes`.
fn put(out: &mut &mut [u8], bytes: &[u8]) {
    let (head, tail) = std::mem::take(out).split_at_mut(bytes.len());
    head.copy_from_slice(bytes);
    *out = tail;
}

fn put_u64(out: &mut &mut [u8], value: usize) {
    put(out, &(value as u64).to_le_bytes());
}

fn put_bytes(out: &mut &mut [u8], bytes: &[u8]) {
    put_u64(out, bytes.len());
    put(out, bytes);
}

const fn request_len(children_len: usize, records: usize) -> usize {
    2 + 8 + children_len + 8 + records * RECORD_SIZE + 8 + 8 + 1
}

const fn child_len(claims: usize, proof: usize) -> usize {
    8 + claims_len(claims) + 8 + proof
}

const fn claims_len(claims: usize) -> usize {
    8 + claims * 64 + 8 + 1
}

fn put_claims(out: &mut &mut [u8], claims: &[Claim]) {
    put_u64(out, claims_len(claims.len()));
    put_u64(out, claims.len());
    claims.iter().for_each(|claim| put(out, claim));
    put_u64(out, 0);
    put(out, &[0]);
}

#[cfg(test)]
pub(in crate::tile) fn aggregate_response(claims: &[Claim], proof: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 1 + child_len(claims.len(), proof.len())];
    let mut out = body.as_mut_slice();
    put(&mut out, &[0]);
    put_claims(&mut out, claims);
    put_bytes(&mut out, proof);
    body
}

fn take<'a>(buf: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (head, tail) = buf.split_at_checked(len)?;
    *buf = tail;
    Some(head)
}

fn take_u64(buf: &mut &[u8]) -> Option<usize> {
    let bytes = take(buf, 8)?;
    usize::try_from(u64::from_le_bytes(bytes.try_into().ok()?)).ok()
}

fn take_bytes<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = take_u64(buf)?;
    take(buf, len)
}

fn parse_claims(mut bytes: &[u8]) -> Option<Vec<Claim>> {
    let count = take_u64(&mut bytes).filter(|&count| count <= MAX_PROOF_CLAIMS)?;
    let records = take(&mut bytes, count.checked_mul(64)?)?;
    let claims: Vec<Claim> = records.chunks_exact(64).map(|c| c.try_into().unwrap()).collect();
    let sorted = claims.windows(2).all(|pair| pair[0] < pair[1]);
    let no_sphincs_and_no_da = take_u64(&mut bytes)? == 0 && take(&mut bytes, 1)? == [0];
    (sorted && no_sphincs_and_no_da && bytes.is_empty()).then_some(claims)
}

fn parse_aggregate_body(mut body: &[u8]) -> Option<(Vec<Claim>, &[u8])> {
    let claims = parse_claims(take_bytes(&mut body)?)?;
    let proof = take_bytes(&mut body)?;
    (proof.len() <= MAX_STARK_PROOF_SIZE && body.is_empty()).then_some((claims, proof))
}

/// Decodes an `aggregate` response into its strictly sorted claims and proof.
/// A non-zero status logs the leanVM sidecar's message and fails.
pub(super) fn decode_aggregate_response(body: &[u8]) -> Result<(Vec<Claim>, &[u8]), &'static str> {
    let (&status, mut rest) = body.split_first().ok_or("empty response")?;
    if status != 0 {
        let message = take_bytes(&mut rest).unwrap_or_default();
        let message = String::from_utf8_lossy(message);
        silver_log::warn!(status, %message, "leanvm sidecar rejected the batch");
        return Err("rejected by the leanvm sidecar");
    }
    parse_aggregate_body(rest).ok_or("malformed response")
}

#[cfg(test)]
mod tests;
