use super::{
    ATTESTATION_DATA_SIZE, AttestationDataView, BEACON_BLOCK_FIXED, BEACON_BLOCK_HEADER_SIZE,
    BYTES_PER_KZG_COMMITMENT, DEPOSIT_SIZE, ETH1_DATA_SIZE, EXECUTION_PAYLOAD_BID_MAX,
    EXECUTION_PAYLOAD_BID_MIN, EXECUTION_PAYLOAD_ENVELOPE_MIN, ExecutionPayloadBidView,
    ExecutionPayloadEnvelopeView, ExecutionPayloadView, MAX_ATTESTER_SLASHINGS_ELECTRA,
    MAX_BLOB_COMMITMENTS_PER_BLOCK, MAX_PAYLOAD_SIZE, MAX_PROPOSER_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE, PAYLOAD_ATTESTATION_DATA_SIZE, PROPOSER_PREFERENCES_SIZE,
    bitlist_ok, fixed, fixed_list_ok, offsets_ok, u32_le, u64_le, variable_field,
    variable_list_len, variable_list_ok,
};
use crate::{
    body_offsets::{BlockBodyError, OperationKind},
    merkle::bitlist_len,
    ssz_hash_pq::ExecutionRequestsPqView,
};

pub const XMSS_SIGNATURE_SIZE: usize = 2404;
pub const XMSS_PUBKEY_SIZE: usize = 32;
pub const VRF_TREE_DEPTH: usize = 31;
pub const VRF_PROOF_SIZE: usize = (VRF_TREE_DEPTH + 1) * 32;
pub const MAX_STARK_PROOF_SIZE: usize = 1 << 20;

pub const MAX_COMMITTEES_PER_SLOT_PQ: usize = 16;
pub const MAX_ATTESTING_INDICES_PQ: usize =
    MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT_PQ;
const COMMITTEE_BYTES: usize = MAX_COMMITTEES_PER_SLOT_PQ / 8;
pub const MAX_ATTESTATIONS_PQ: usize = 16;
pub const MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD: usize = 64;
pub const MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD: usize = 4;
pub const MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD: usize = 16;

pub type XMSSSignature = [u8; XMSS_SIGNATURE_SIZE];
pub type XMSSPubkey = [u8; XMSS_PUBKEY_SIZE];
/// The leaf for a slot followed by its Merkle branch to the VRF root.
pub type VRFProof = [u8; VRF_PROOF_SIZE];

/// Fixed part of `{ message: <variable>, signature: XMSSSignature }`.
pub const SIGNED_PQ_FIXED: usize = 4 + XMSS_SIGNATURE_SIZE;

// -- SingleAttestation (beacon_attestation_{subnet_id}) ---------------
//
// All fixed, 2548B.
//   [0..8)      committee_index
//   [8..16)     attester_index
//   [16..144)   data (AttestationData 128B)
//   [144..2548) signature

pub const SINGLE_ATT_PQ_SIZE: usize = 16 + ATTESTATION_DATA_SIZE + XMSS_SIGNATURE_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SingleAttestationPqView;

impl SingleAttestationPqView {
    #[inline]
    pub fn committee_index(buf: &[u8; SINGLE_ATT_PQ_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn attester_index(buf: &[u8; SINGLE_ATT_PQ_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn data(buf: &[u8; SINGLE_ATT_PQ_SIZE]) -> AttestationDataView<'_> {
        AttestationDataView(fixed(buf, 16))
    }
    #[inline]
    pub fn signature(buf: &[u8; SINGLE_ATT_PQ_SIZE]) -> &XMSSSignature {
        fixed(buf, 16 + ATTESTATION_DATA_SIZE)
    }
}

// -- Attestation (block-body element, aggregate) -----------------------
//
// Variable, fixed part 134B. `signature` is gone.
//   [0..4)     offset: aggregation_bits (== 134)
//   [4..132)   data (AttestationData 128B)
//   [132..134) committee_bits (Bitvector[16])
//   [134..)    aggregation_bits (Bitlist)

pub const ATTESTATION_PQ_FIXED: usize = 4 + ATTESTATION_DATA_SIZE + COMMITTEE_BYTES;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct AttestationPqView;

impl AttestationPqView {
    #[inline]
    pub fn data(buf: &[u8]) -> AttestationDataView<'_> {
        AttestationDataView(fixed(buf, 4))
    }
    #[inline]
    pub fn committee_bits(buf: &[u8]) -> &[u8; COMMITTEE_BYTES] {
        fixed(buf, 132)
    }
    #[inline]
    pub fn aggregation_bits(buf: &[u8]) -> &[u8] {
        &buf[ATTESTATION_PQ_FIXED..]
    }

    pub fn check_canonical(buf: &[u8]) -> bool {
        buf.len() >= ATTESTATION_PQ_FIXED &&
            u32_le(buf, 0) as usize == ATTESTATION_PQ_FIXED &&
            bitlist_ok(&buf[ATTESTATION_PQ_FIXED..], MAX_ATTESTING_INDICES_PQ)
    }

    /// The committee index and set positions of an attestation of one
    /// committee. `None` unless `buf` is canonical, names exactly one
    /// committee and has at most `MAX_VALIDATORS_PER_COMMITTEE` positions.
    pub fn one_committee_positions(
        buf: &[u8],
    ) -> Option<(usize, impl Iterator<Item = usize> + '_)> {
        if !Self::check_canonical(buf) {
            return None;
        }
        let committees = u16::from_le_bytes(*Self::committee_bits(buf));
        let bits = Self::aggregation_bits(buf);
        let len = bitlist_len(bits);
        if committees.count_ones() != 1 || len > MAX_VALIDATORS_PER_COMMITTEE {
            return None;
        }
        let positions = (0..len).filter(move |&p| bits[p / 8] >> (p % 8) & 1 == 1);
        Some((committees.trailing_zeros() as usize, positions))
    }

    /// The size of an attestation of one committee. `None` if the committee
    /// or its size is out of range.
    pub fn one_committee_len(committee_index: usize, committee_len: usize) -> Option<usize> {
        (committee_index < MAX_COMMITTEES_PER_SLOT_PQ &&
            committee_len <= MAX_VALIDATORS_PER_COMMITTEE)
            .then_some(ATTESTATION_PQ_FIXED + committee_len / 8 + 1)
    }

    /// An attestation of one committee into `out`, of
    /// [`Self::one_committee_len`] bytes: `positions` are indices into the
    /// committee. False if a position is out of range.
    pub fn write_one_committee(
        out: &mut [u8],
        data: &[u8; ATTESTATION_DATA_SIZE],
        committee_index: usize,
        committee_len: usize,
        positions: impl IntoIterator<Item = usize>,
    ) -> bool {
        debug_assert_eq!(Some(out.len()), Self::one_committee_len(committee_index, committee_len));
        out.fill(0);
        out[..4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        out[4..4 + ATTESTATION_DATA_SIZE].copy_from_slice(data);
        out[4 + ATTESTATION_DATA_SIZE + committee_index / 8] |= 1 << (committee_index % 8);
        let bits = &mut out[ATTESTATION_PQ_FIXED..];
        for position in positions {
            if position >= committee_len {
                return false;
            }
            bits[position / 8] |= 1 << (position % 8);
        }
        bits[committee_len / 8] |= 1 << (committee_len % 8);
        true
    }

    /// [`Self::write_one_committee`] into a new buffer.
    pub fn encode_one_committee(
        data: &[u8; ATTESTATION_DATA_SIZE],
        committee_index: usize,
        committee_len: usize,
        positions: impl IntoIterator<Item = usize>,
    ) -> Option<Vec<u8>> {
        let mut out = vec![0; Self::one_committee_len(committee_index, committee_len)?];
        Self::write_one_committee(&mut out, data, committee_index, committee_len, positions)
            .then_some(out)
    }

    /// Appends an attestation of several committees to `out`: each is its
    /// index and its votes as a `Bitlist`. A repeated index unites its votes.
    /// `None`, with `out` partly written, unless the indices are in range and
    /// never descend, and repeats agree on length.
    pub fn write_committees<'a>(
        out: &mut Vec<u8>,
        data: &[u8; ATTESTATION_DATA_SIZE],
        committees: impl IntoIterator<Item = (usize, &'a [u8])>,
    ) -> Option<()> {
        let start = out.len();
        let bits_start = start + ATTESTATION_PQ_FIXED;
        out.resize(bits_start, 0);
        out[start..start + 4].copy_from_slice(&(ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        out[start + 4..start + 4 + ATTESTATION_DATA_SIZE].copy_from_slice(data);
        let (mut last, mut len) = (None, 0);
        for (index, votes) in committees {
            let committee_len = bitlist_len(votes);
            let at = match last {
                Some((last_index, last_len)) if index == last_index => {
                    if committee_len != last_len {
                        return None;
                    }
                    len - last_len
                }
                Some((last_index, _)) if index < last_index => return None,
                _ if index >= MAX_COMMITTEES_PER_SLOT_PQ => return None,
                _ => {
                    out[start + 4 + ATTESTATION_DATA_SIZE + index / 8] |= 1 << (index % 8);
                    len += committee_len;
                    out.resize(bits_start + len / 8 + 1, 0);
                    len - committee_len
                }
            };
            or_bits_at(&mut out[bits_start..], at, votes, committee_len);
            last = Some((index, committee_len));
        }
        last?;
        out[bits_start + len / 8] |= 1 << (len % 8);
        Some(())
    }
}

/// ORs the first `len` bits of `bits` into `out` from bit `at` on.
fn or_bits_at(out: &mut [u8], at: usize, bits: &[u8], len: usize) {
    let (base, shift) = (at / 8, at % 8);
    for (i, &byte) in bits[..len.div_ceil(8)].iter().enumerate() {
        let remaining = len - 8 * i;
        let byte = if remaining < 8 { byte & ((1u16 << remaining) - 1) as u8 } else { byte };
        out[base + i] |= byte << shift;
        if shift != 0 && byte >> (8 - shift) != 0 {
            out[base + i + 1] |= byte >> (8 - shift);
        }
    }
}

// -- ProvedAttestation: an aggregate with its proof -------------------
//
// Not a spec container; what an aggregator signs over, less its index.
//   [0..4)  offset: attestation (== 8)
//   [4..8)  offset: proof
//   [8..)   attestation | proof

pub struct ProvedAttestationView;

impl ProvedAttestationView {
    pub const FIXED: usize = 4 + 4;

    pub fn write_offsets(out: &mut [u8], attestation_len: usize) {
        out[..4].copy_from_slice(&(Self::FIXED as u32).to_le_bytes());
        out[4..8].copy_from_slice(&((Self::FIXED + attestation_len) as u32).to_le_bytes());
    }

    #[inline]
    pub fn attestation(buf: &[u8]) -> &[u8] {
        &buf[Self::FIXED..u32_le(buf, 4) as usize]
    }

    #[inline]
    pub fn proof(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 4) as usize..]
    }
}

// -- IndexedAttestation (inside AttesterSlashing) ---------------------
//
// Variable, fixed part 136B. `proof` takes `signature`'s place.
//   [0..4)     offset: attesting_indices (== 136)
//   [4..132)   data (AttestationData 128B)
//   [132..136) offset: proof
//   [136..)    attesting_indices (8B each) | proof

pub const INDEXED_ATTESTATION_PQ_FIXED: usize = 4 + ATTESTATION_DATA_SIZE + 4;
pub const INDEXED_ATTESTATION_PQ_MAX: usize =
    INDEXED_ATTESTATION_PQ_FIXED + MAX_ATTESTING_INDICES_PQ * 8 + MAX_STARK_PROOF_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct IndexedAttestationPqView;

impl IndexedAttestationPqView {
    const VARIABLE_OFFSETS: [usize; 2] = [0, 132];

    #[inline]
    pub fn data(buf: &[u8]) -> AttestationDataView<'_> {
        AttestationDataView(fixed(buf, 4))
    }
    #[inline]
    pub fn attesting_indices(buf: &[u8]) -> &[u8] {
        variable_field(buf, &Self::VARIABLE_OFFSETS, 0)
    }
    #[inline]
    pub fn proof(buf: &[u8]) -> &[u8] {
        variable_field(buf, &Self::VARIABLE_OFFSETS, 1)
    }

    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < INDEXED_ATTESTATION_PQ_FIXED ||
            buf.len() > INDEXED_ATTESTATION_PQ_MAX ||
            !offsets_ok(buf, &Self::VARIABLE_OFFSETS, INDEXED_ATTESTATION_PQ_FIXED)
        {
            return false;
        }
        fixed_list_ok(Self::attesting_indices(buf), 8, MAX_ATTESTING_INDICES_PQ) &&
            Self::proof(buf).len() <= MAX_STARK_PROOF_SIZE
    }
}

// -- AttesterSlashing (attester_slashing) -----------------------------
//
// Variable. Two PQ IndexedAttestations.
//   [0..4)  offset: attestation_1 (== 8)
//   [4..8)  offset: attestation_2

pub const ATTESTER_SLASHING_PQ_MIN: usize = 8 + 2 * INDEXED_ATTESTATION_PQ_FIXED;
pub const ATTESTER_SLASHING_PQ_MAX: usize = 8 + 2 * INDEXED_ATTESTATION_PQ_MAX;
const _: () = assert!(ATTESTER_SLASHING_PQ_MAX == 2_621_720, "MAX_ATTESTER_SLASHING_SIZE_PQ");

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct AttesterSlashingPqView;

impl AttesterSlashingPqView {
    const VARIABLE_OFFSETS: [usize; 2] = [0, 4];

    #[inline]
    pub fn attestation_1(buf: &[u8]) -> &[u8] {
        variable_field(buf, &Self::VARIABLE_OFFSETS, 0)
    }
    #[inline]
    pub fn attestation_2(buf: &[u8]) -> &[u8] {
        variable_field(buf, &Self::VARIABLE_OFFSETS, 1)
    }

    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= ATTESTER_SLASHING_PQ_MIN &&
            buf.len() <= ATTESTER_SLASHING_PQ_MAX &&
            offsets_ok(buf, &Self::VARIABLE_OFFSETS, 8) &&
            IndexedAttestationPqView::check_size(Self::attestation_1(buf)) &&
            IndexedAttestationPqView::check_size(Self::attestation_2(buf))
    }
}

// -- ProposerSlashing (proposer_slashing) -----------------------------
//
// All fixed, 5032B. Two SignedBeaconBlockHeaders of 2516B each.
//   [0..112)     signed_header_1.message
//   [112..2516)  signed_header_1.signature
//   [2516..2628) signed_header_2.message
//   [2628..5032) signed_header_2.signature

pub const SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE: usize =
    BEACON_BLOCK_HEADER_SIZE + XMSS_SIGNATURE_SIZE;
pub const PROPOSER_SLASHING_PQ_SIZE: usize = 2 * SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ProposerSlashingPqView;

impl ProposerSlashingPqView {
    #[inline]
    pub fn header_1(buf: &[u8; PROPOSER_SLASHING_PQ_SIZE]) -> &[u8; BEACON_BLOCK_HEADER_SIZE] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn signature_1(buf: &[u8; PROPOSER_SLASHING_PQ_SIZE]) -> &XMSSSignature {
        fixed(buf, BEACON_BLOCK_HEADER_SIZE)
    }
    #[inline]
    pub fn header_2(buf: &[u8; PROPOSER_SLASHING_PQ_SIZE]) -> &[u8; BEACON_BLOCK_HEADER_SIZE] {
        fixed(buf, SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE)
    }
    #[inline]
    pub fn signature_2(buf: &[u8; PROPOSER_SLASHING_PQ_SIZE]) -> &XMSSSignature {
        fixed(buf, SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE + BEACON_BLOCK_HEADER_SIZE)
    }
}

// -- SignedBeaconBlock (beacon_block) ---------------------------------
//
//   [0..4)       offset: message (== 2408)
//   [4..2408)    signature
//   [2408..2416) slot
//   [2416..2424) proposer_index
//   [2424..2456) parent_root
//   [2456..2488) state_root
//   [2488..2492) offset: body (relative to 2408, == 84)
//   [2492..)     body

pub const SIGNED_BEACON_BLOCK_PQ_MIN: usize = SIGNED_PQ_FIXED + BEACON_BLOCK_FIXED;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedBeaconBlockPqView;

impl SignedBeaconBlockPqView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &XMSSSignature {
        fixed(buf, 4)
    }
    /// Serialized `BeaconBlock`.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[SIGNED_PQ_FIXED..]
    }
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, SIGNED_PQ_FIXED)
    }
    #[inline]
    pub fn proposer_index(buf: &[u8]) -> u64 {
        u64_le(buf, SIGNED_PQ_FIXED + 8)
    }
    #[inline]
    pub fn parent_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, SIGNED_PQ_FIXED + 16)
    }
    #[inline]
    pub fn state_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, SIGNED_PQ_FIXED + 48)
    }
    #[inline]
    pub fn body(buf: &[u8]) -> &[u8] {
        &buf[SIGNED_BEACON_BLOCK_PQ_MIN..]
    }

    /// Pins the two offsets the accessors hardcode. The body is checked on
    /// its own by [`BeaconBlockBodyPqView::check_canonical`].
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_BEACON_BLOCK_PQ_MIN &&
            buf.len() <= MAX_PAYLOAD_SIZE &&
            u32_le(buf, 0) as usize == SIGNED_PQ_FIXED &&
            u32_le(buf, SIGNED_PQ_FIXED + 80) as usize == BEACON_BLOCK_FIXED
    }

    /// [`Self::check_size`], plus bounds for the bid accessors below.
    pub fn check_bid_size(buf: &[u8]) -> bool {
        if !Self::check_size(buf) {
            return false;
        }
        let body = Self::body(buf);
        if body.len() < BEACON_BLOCK_BODY_PQ_FIXED ||
            !offsets_ok(
                body,
                &BeaconBlockBodyPqView::VARIABLE_OFFSETS,
                BEACON_BLOCK_BODY_PQ_FIXED,
            )
        {
            return false;
        }
        let signed_bid = BeaconBlockBodyPqView::signed_execution_payload_bid(body);
        SignedExecutionPayloadBidPqView::check_size(signed_bid) &&
            ExecutionPayloadBidView::check_size(SignedExecutionPayloadBidPqView::message(
                signed_bid,
            ))
    }

    /// Serialized `ExecutionPayloadBid`.
    #[inline]
    pub fn bid(buf: &[u8]) -> &[u8] {
        let body = Self::body(buf);
        SignedExecutionPayloadBidPqView::message(
            BeaconBlockBodyPqView::signed_execution_payload_bid(body),
        )
    }
}

// -- BeaconBlockBody --------------------------------------------------
//
// ProgressiveContainer of width 14; the inactive `voluntary_exits`,
// `sync_aggregate`, `bls_to_execution_changes` and `payload_attestations`
// are not serialized. Fixed part 1156B.
//   [0..1024)    randao_reveal (VRFProof)
//   [1024..1096) eth1_data (72B)
//   [1096..1128) graffiti
//   [1128..1132) offset: proposer_slashings
//   [1132..1136) offset: attester_slashings
//   [1136..1140) offset: attestations
//   [1140..1144) offset: deposits
//   [1144..1148) offset: signed_execution_payload_bid
//   [1148..1152) offset: parent_execution_requests
//   [1152..1156) offset: proof
//   [1156..)     variable region

pub const BEACON_BLOCK_BODY_PQ_FIXED: usize = VRF_PROOF_SIZE + ETH1_DATA_SIZE + 32 + 7 * 4;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct BeaconBlockBodyPqView;

impl BeaconBlockBodyPqView {
    pub const VARIABLE_OFFSETS: [usize; 7] = [1128, 1132, 1136, 1140, 1144, 1148, 1152];

    #[inline]
    pub fn randao_reveal(buf: &[u8]) -> &VRFProof {
        fixed(buf, 0)
    }
    #[inline]
    pub fn eth1_data(buf: &[u8]) -> &[u8; ETH1_DATA_SIZE] {
        fixed(buf, VRF_PROOF_SIZE)
    }
    #[inline]
    pub fn graffiti(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, VRF_PROOF_SIZE + ETH1_DATA_SIZE)
    }
    #[inline]
    pub fn proposer_slashings(buf: &[u8]) -> &[u8] {
        Self::field(buf, 0)
    }
    #[inline]
    pub fn attester_slashings(buf: &[u8]) -> &[u8] {
        Self::field(buf, 1)
    }
    #[inline]
    pub fn attestations(buf: &[u8]) -> &[u8] {
        Self::field(buf, 2)
    }
    #[inline]
    pub fn deposits(buf: &[u8]) -> &[u8] {
        Self::field(buf, 3)
    }
    #[inline]
    pub fn signed_execution_payload_bid(buf: &[u8]) -> &[u8] {
        Self::field(buf, 4)
    }
    #[inline]
    pub fn parent_execution_requests(buf: &[u8]) -> &[u8] {
        Self::field(buf, 5)
    }
    #[inline]
    pub fn proof(buf: &[u8]) -> &[u8] {
        Self::field(buf, 6)
    }

    #[inline]
    fn field(buf: &[u8], i: usize) -> &[u8] {
        debug_assert!(offsets_ok(buf, &Self::VARIABLE_OFFSETS, BEACON_BLOCK_BODY_PQ_FIXED));
        variable_field(buf, &Self::VARIABLE_OFFSETS, i)
    }

    /// Progressive lists carry no type-level bound, so counts are left to
    /// [`Self::check_operation_limits`].
    pub fn check_canonical(body: &[u8]) -> bool {
        const UNCAPPED: usize = usize::MAX;
        body.len() >= BEACON_BLOCK_BODY_PQ_FIXED &&
            offsets_ok(body, &Self::VARIABLE_OFFSETS, BEACON_BLOCK_BODY_PQ_FIXED) &&
            fixed_list_ok(Self::proposer_slashings(body), PROPOSER_SLASHING_PQ_SIZE, UNCAPPED) &&
            variable_list_ok(
                Self::attester_slashings(body),
                UNCAPPED,
                AttesterSlashingPqView::check_size,
            ) &&
            variable_list_ok(
                Self::attestations(body),
                UNCAPPED,
                AttestationPqView::check_canonical,
            ) &&
            fixed_list_ok(Self::deposits(body), DEPOSIT_SIZE, UNCAPPED) &&
            SignedExecutionPayloadBidPqView::check_canonical(Self::signed_execution_payload_bid(
                body,
            )) &&
            ExecutionRequestsPqView::check_canonical(Self::parent_execution_requests(body)) &&
            Self::proof(body).len() <= MAX_STARK_PROOF_SIZE
    }

    /// Spec `verify_block_body_operation_limits`, plus
    /// `verify_execution_requests_limits` on the parent requests.
    pub fn check_operation_limits(body: &[u8]) -> Result<(), BlockBodyError> {
        debug_assert!(Self::check_canonical(body));
        OperationKind::ProposerSlashings.check_count(
            Self::proposer_slashings(body).len() / PROPOSER_SLASHING_PQ_SIZE,
            MAX_PROPOSER_SLASHINGS,
        )?;
        OperationKind::AttesterSlashings.check_count(
            variable_list_len(Self::attester_slashings(body)),
            MAX_ATTESTER_SLASHINGS_ELECTRA,
        )?;
        OperationKind::Attestations
            .check_count(variable_list_len(Self::attestations(body)), MAX_ATTESTATIONS_PQ)?;
        OperationKind::Deposits.check_count(Self::deposits(body).len() / DEPOSIT_SIZE, 0)?;
        ExecutionRequestsPqView::check_counts(Self::parent_execution_requests(body))?;
        Ok(())
    }
}

// -- SignedAggregateAndProof (beacon_aggregate_and_proof) -------------
//
// AggregateAndProof gains a trailing variable `proof`, so the aggregate's
// end is read from the proof offset.
//   [0..4)       offset: message (== 2408)
//   [4..2408)    signature
//   [2408..2416) aggregator_index
//   [2416..2420) offset: aggregate (relative to message, == 16)
//   [2420..2424) offset: proof (relative to message)
//   [2424..)     aggregate | proof

const AGGREGATE_AND_PROOF_PQ_FIXED: usize = 8 + 4 + 4;
const AGGREGATE_PQ_START: usize = SIGNED_PQ_FIXED + AGGREGATE_AND_PROOF_PQ_FIXED;

const AGGREGATION_BITS_START: usize = AGGREGATE_PQ_START + ATTESTATION_PQ_FIXED;
// Even an empty bitlist has a delimiter byte.
pub const SIGNED_AGG_PROOF_PQ_MIN: usize = AGGREGATION_BITS_START + 1;
pub const SIGNED_AGG_PROOF_PQ_MAX: usize =
    SIGNED_AGG_PROOF_PQ_MIN + MAX_ATTESTING_INDICES_PQ / 8 + MAX_STARK_PROOF_SIZE;
const _: () =
    assert!(SIGNED_AGG_PROOF_PQ_MAX == 1_055_231, "MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE_PQ");

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedAggregateAndProofPqView;

impl SignedAggregateAndProofPqView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &XMSSSignature {
        fixed(buf, 4)
    }
    /// Serialized `AggregateAndProof`.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[SIGNED_PQ_FIXED..]
    }
    #[inline]
    pub fn aggregator_index(buf: &[u8]) -> u64 {
        u64_le(buf, SIGNED_PQ_FIXED)
    }
    /// Serialized `Attestation`.
    #[inline]
    pub fn aggregate(buf: &[u8]) -> &[u8] {
        &buf[AGGREGATE_PQ_START..Self::proof_start(buf)]
    }
    #[inline]
    pub fn agg_data(buf: &[u8]) -> AttestationDataView<'_> {
        AttestationDataView(fixed(buf, AGGREGATE_PQ_START + 4))
    }
    #[inline]
    pub fn agg_committee_bits(buf: &[u8]) -> &[u8; COMMITTEE_BYTES] {
        fixed(buf, AGGREGATE_PQ_START + 132)
    }
    #[inline]
    pub fn agg_aggregation_bits(buf: &[u8]) -> &[u8] {
        &buf[AGGREGATION_BITS_START..Self::proof_start(buf)]
    }
    #[inline]
    pub fn proof(buf: &[u8]) -> &[u8] {
        &buf[Self::proof_start(buf)..]
    }

    #[inline]
    fn proof_start(buf: &[u8]) -> usize {
        SIGNED_PQ_FIXED + u32_le(buf, SIGNED_PQ_FIXED + 12) as usize
    }

    /// Pins every offset the accessors hardcode and checks the aggregate is
    /// canonical.
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < SIGNED_AGG_PROOF_PQ_MIN ||
            buf.len() > SIGNED_AGG_PROOF_PQ_MAX ||
            u32_le(buf, 0) as usize != SIGNED_PQ_FIXED ||
            u32_le(buf, SIGNED_PQ_FIXED + 8) as usize != AGGREGATE_AND_PROOF_PQ_FIXED
        {
            return false;
        }
        let proof_start = Self::proof_start(buf);
        proof_start >= AGGREGATE_PQ_START &&
            proof_start <= buf.len() &&
            buf.len() - proof_start <= MAX_STARK_PROOF_SIZE &&
            AttestationPqView::check_canonical(&buf[AGGREGATE_PQ_START..proof_start])
    }
}

// -- SignedExecutionPayloadBid (execution_payload_bid) ----------------
//
//   [0..4)    offset: message (== 2408)
//   [4..2408) signature
//   [2408..)  message (ExecutionPayloadBid)

pub const SIGNED_EXECUTION_PAYLOAD_BID_PQ_MIN: usize = SIGNED_PQ_FIXED + EXECUTION_PAYLOAD_BID_MIN;
pub const SIGNED_EXECUTION_PAYLOAD_BID_PQ_MAX: usize = SIGNED_PQ_FIXED + EXECUTION_PAYLOAD_BID_MAX;
const _: () = assert!(
    SIGNED_EXECUTION_PAYLOAD_BID_PQ_MAX == 199_240,
    "MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_PQ"
);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedExecutionPayloadBidPqView;

impl SignedExecutionPayloadBidPqView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &XMSSSignature {
        fixed(buf, 4)
    }
    /// Serialized `ExecutionPayloadBid`.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[SIGNED_PQ_FIXED..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_EXECUTION_PAYLOAD_BID_PQ_MIN &&
            buf.len() <= SIGNED_EXECUTION_PAYLOAD_BID_PQ_MAX &&
            u32_le(buf, 0) as usize == SIGNED_PQ_FIXED
    }

    pub fn check_canonical(buf: &[u8]) -> bool {
        Self::check_size(buf) &&
            ExecutionPayloadBidView::check_size(Self::message(buf)) &&
            fixed_list_ok(
                ExecutionPayloadBidView::blob_kzg_commitments(Self::message(buf)),
                BYTES_PER_KZG_COMMITMENT,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            )
    }
}

// -- SignedExecutionPayloadEnvelope (execution_payload) ---------------
//
//   [0..4)    offset: message (== 2408)
//   [4..2408) signature
//   [2408..)  message (ExecutionPayloadEnvelope, PQ ExecutionRequests)

pub const SIGNED_EXECUTION_PAYLOAD_ENVELOPE_PQ_MIN: usize =
    SIGNED_PQ_FIXED + EXECUTION_PAYLOAD_ENVELOPE_MIN;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedExecutionPayloadEnvelopePqView;

impl SignedExecutionPayloadEnvelopePqView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &XMSSSignature {
        fixed(buf, 4)
    }
    /// Serialized `ExecutionPayloadEnvelope`.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[SIGNED_PQ_FIXED..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_EXECUTION_PAYLOAD_ENVELOPE_PQ_MIN &&
            buf.len() <= MAX_PAYLOAD_SIZE &&
            u32_le(buf, 0) as usize == SIGNED_PQ_FIXED
    }

    pub fn check_canonical(buf: &[u8]) -> bool {
        if !Self::check_size(buf) {
            return false;
        }
        let message = Self::message(buf);
        ExecutionPayloadEnvelopeView::check_size(message) &&
            ExecutionPayloadView::check_canonical_gloas(ExecutionPayloadEnvelopeView::payload(
                message,
            )) &&
            ExecutionRequestsPqView::check_canonical(
                ExecutionPayloadEnvelopeView::execution_requests(message),
            )
    }
}

// -- PayloadAttestationMessage (payload_attestation_message) ----------
//
// All fixed, 2454B.
//   [0..8)     validator_index
//   [8..50)    data (PayloadAttestationData 42B)
//   [50..2454) signature

pub const PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE: usize =
    8 + PAYLOAD_ATTESTATION_DATA_SIZE + XMSS_SIGNATURE_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct PayloadAttestationMessagePqView;

impl PayloadAttestationMessagePqView {
    #[inline]
    pub fn validator_index(buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn data(
        buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE],
    ) -> &[u8; PAYLOAD_ATTESTATION_DATA_SIZE] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn signature(buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE]) -> &XMSSSignature {
        fixed(buf, 8 + PAYLOAD_ATTESTATION_DATA_SIZE)
    }
}

// -- SignedProposerPreferences (proposer_preferences) -----------------
//
// All fixed, 2480B: message(76) + signature(2404).

pub const SIGNED_PROPOSER_PREFERENCES_PQ_SIZE: usize =
    PROPOSER_PREFERENCES_SIZE + XMSS_SIGNATURE_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedProposerPreferencesPqView;

impl SignedProposerPreferencesPqView {
    #[inline]
    pub fn message(
        buf: &[u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE],
    ) -> &[u8; PROPOSER_PREFERENCES_SIZE] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn signature(buf: &[u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE]) -> &XMSSSignature {
        fixed(buf, PROPOSER_PREFERENCES_SIZE)
    }
}

// -- ValidatorPreregistrationRequest (ExecutionRequests element) ------
//   [0..32)  pubkey
//   [32..64) withdrawal_credentials
//   [64..96) vrf_root

pub const VALIDATOR_PREREGISTRATION_REQUEST_SIZE: usize = XMSS_PUBKEY_SIZE + 32 + 32;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ValidatorPreregistrationRequestView;

impl ValidatorPreregistrationRequestView {
    #[inline]
    pub fn pubkey(buf: &[u8; VALIDATOR_PREREGISTRATION_REQUEST_SIZE]) -> &XMSSPubkey {
        fixed(buf, 0)
    }
    #[inline]
    pub fn withdrawal_credentials(buf: &[u8; VALIDATOR_PREREGISTRATION_REQUEST_SIZE]) -> &[u8; 32] {
        fixed(buf, XMSS_PUBKEY_SIZE)
    }
    #[inline]
    pub fn vrf_root(buf: &[u8; VALIDATOR_PREREGISTRATION_REQUEST_SIZE]) -> &[u8; 32] {
        fixed(buf, XMSS_PUBKEY_SIZE + 32)
    }
}

// -- BuilderPreregistrationRequest (ExecutionRequests element) --------
//   [0..32)  pubkey
//   [32..64) withdrawal_credentials

pub const BUILDER_PREREGISTRATION_REQUEST_SIZE: usize = XMSS_PUBKEY_SIZE + 32;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct BuilderPreregistrationRequestView;

impl BuilderPreregistrationRequestView {
    #[inline]
    pub fn pubkey(buf: &[u8; BUILDER_PREREGISTRATION_REQUEST_SIZE]) -> &XMSSPubkey {
        fixed(buf, 0)
    }
    #[inline]
    pub fn withdrawal_credentials(buf: &[u8; BUILDER_PREREGISTRATION_REQUEST_SIZE]) -> &[u8; 32] {
        fixed(buf, XMSS_PUBKEY_SIZE)
    }
}

// -- VoluntaryExitRequest (ExecutionRequests element) -----------------
//   [0..32) pubkey

pub const VOLUNTARY_EXIT_REQUEST_SIZE: usize = XMSS_PUBKEY_SIZE;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct VoluntaryExitRequestView;

impl VoluntaryExitRequestView {
    #[inline]
    pub fn pubkey(buf: &[u8; VOLUNTARY_EXIT_REQUEST_SIZE]) -> &XMSSPubkey {
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn or_bits_at_matches_bit_by_bit_at_every_offset() {
        let bits = [0b1011_0110, 0xff, 0b1111_0101];
        for len in 0..=20 {
            for at in 0..16 {
                let mut out = vec![0; (at + len) / 8 + 1];
                or_bits_at(&mut out, at, &bits, len);
                let mut expected = vec![0; out.len()];
                for p in (0..len).filter(|p| bits[p / 8] >> (p % 8) & 1 == 1) {
                    expected[(at + p) / 8] |= 1 << ((at + p) % 8);
                }
                assert_eq!(out, expected, "len {len} at {at}");
            }
        }
    }

    #[test]
    fn write_committees_refuses_bad_committees() {
        let data = [7; ATTESTATION_DATA_SIZE];
        let nine = [0, 0b11];
        let ten = [0, 0b110];
        let write = |committees: &[(usize, &[u8])]| {
            AttestationPqView::write_committees(&mut Vec::new(), &data, committees.iter().copied())
        };
        assert!(write(&[(1, &nine), (1, &nine), (4, &ten)]).is_some());
        assert!(write(&[]).is_none(), "no committee");
        assert!(write(&[(4, &nine), (1, &nine)]).is_none(), "descending");
        assert!(write(&[(MAX_COMMITTEES_PER_SLOT_PQ, &nine)]).is_none(), "out of range");
        assert!(write(&[(1, &nine), (1, &ten)]).is_none(), "a repeat of another length");
    }
}
