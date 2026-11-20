//! Beacon-API bodies are written by hand: the spec quotes every integer as a
//! decimal string and every byte array as lowercase `0x`-hex, and the
//! SSZ-backed containers have no Rust struct to hang `Serialize` on.

use std::io::Write;

use silver_beacon_state_data::{
    B256, BeaconBlockHeader, Builder, Checkpoint, FAR_FUTURE_EPOCH, Fork, ForkName, SpecConfig,
    Version, pq::KeyScheme,
};
use silver_common::{
    AGENT_VERSION, PayloadFrame, PreparedPayloadAttributes,
    ssz_hash_pq::ExecutionRequestsPqView,
    ssz_view::{
        AttestationPqView, BEACON_BLOCK_FIXED, BEACON_BLOCK_HEADER_SIZE, BYTES_PER_BLOB,
        BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, BeaconBlockBodyPqView,
        BeaconBlockHeaderView, BuilderDepositRequestView, BuilderExitRequestView,
        BuilderPreregistrationRequestView, ConsolidationRequestView, DEPOSIT_SIZE, DepositDataView,
        DepositRequestView, DepositView, ETH1_DATA_SIZE, EXECUTION_PAYLOAD_ENVELOPE_MIN,
        Eth1DataView, ExecutionPayloadBidView, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        IndexedAttestationPqView, PAYLOAD_ATTESTATION_DATA_SIZE, PROPOSER_SLASHING_PQ_SIZE,
        PayloadAttestationDataView, ProposerPreferencesView, ProvedAttestationView,
        SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, SINGLE_ATT_PQ_SIZE, SignedExecutionPayloadBidPqView,
        SignedProposerPreferencesPqView, SingleAttestationPqView,
        ValidatorPreregistrationRequestView, VoluntaryExitRequestView, WITHDRAWAL_SIZE,
        WithdrawalRequestView, WithdrawalView, XMSSSignature, variable_list_items,
    },
};

use crate::{
    beacon::validators::ValidatorRecord,
    events::HeadEvent,
    node::peers::Peer,
    validator::{
        attestation_data::AttestationData, attester_duties::AttesterDuty,
        produce_block::ProducedBlockMetadata, proposer_duties::ProposerDuties, ptc_duties::PtcDuty,
    },
};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

const HEX_PAIRS: [[u8; 2]; 256] = {
    let mut pairs = [[0; 2]; 256];
    let mut byte = 0;
    while byte < 256 {
        pairs[byte] = [HEX_LOWER[byte >> 4], HEX_LOWER[byte & 0xf]];
        byte += 1;
    }
    pairs
};

/// A little-endian `uint256` in decimal, as the schemas spell Wei.
pub(crate) fn wei_decimal(little_endian: &[u8; 32]) -> String {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(little_endian.chunks_exact(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
    }
    let mut digits = Vec::new();
    loop {
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let current = (remainder << 64) | u128::from(*limb);
            *limb = (current / 10) as u64;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
        if limbs == [0; 4] {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

/// Appends JSON to a buffer the caller owns — fresh or reused is the caller's
/// affair. `start` is where this body begins, so bytes already in the buffer
/// are not siblings of the first value written.
pub(crate) struct Json<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> Json<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        let start = out.len();
        Self { out, start }
    }

    pub(crate) fn begin_object(&mut self) {
        self.separate();
        self.out.push(b'{');
    }

    pub(crate) fn end_object(&mut self) {
        self.out.push(b'}');
    }

    pub(crate) fn begin_array(&mut self) {
        self.separate();
        self.out.push(b'[');
    }

    pub(crate) fn end_array(&mut self) {
        self.out.push(b']');
    }

    pub(crate) fn restart(&mut self) {
        self.out.truncate(self.start);
    }

    pub(crate) fn key(&mut self, name: &str) {
        debug_assert!(json_safe(name), "field name goes into JSON unescaped");
        self.separate();
        self.out.push(b'"');
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(b"\":");
    }

    pub(crate) fn quoted_u64(&mut self, value: u64) {
        self.separate();
        self.unseparated_quoted_u64(value);
    }

    fn unseparated_quoted_u64(&mut self, value: u64) {
        // Most validators' epochs are unset, and `u64::MAX` is itoa's slowest
        // input.
        if value == FAR_FUTURE_EPOCH {
            self.out.extend_from_slice(b"\"18446744073709551615\"");
            return;
        }
        self.out.push(b'"');
        self.out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
        self.out.push(b'"');
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn null(&mut self) {
        self.separate();
        self.out.extend_from_slice(b"null");
    }

    pub(crate) fn hex(&mut self, bytes: &[u8]) {
        self.separate();
        self.unseparated_hex(bytes);
    }

    fn unseparated_hex(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(b"\"0x");
        let base = self.out.len();
        self.out.resize(base + bytes.len() * 2, 0);
        for (pair, byte) in self.out[base..].chunks_exact_mut(2).zip(bytes) {
            pair.copy_from_slice(&HEX_PAIRS[*byte as usize]);
        }
        self.out.push(b'"');
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.separate();
        self.out.extend_from_slice(if value { b"true".as_slice() } else { b"false".as_slice() });
    }

    pub(crate) fn string(&mut self, text: &str) {
        self.separate();
        self.out.push(b'"');
        for byte in text.bytes() {
            match byte {
                b'"' => self.out.extend_from_slice(b"\\\""),
                b'\\' => self.out.extend_from_slice(b"\\\\"),
                0x08 => self.out.extend_from_slice(b"\\b"),
                0x0c => self.out.extend_from_slice(b"\\f"),
                b'\n' => self.out.extend_from_slice(b"\\n"),
                b'\r' => self.out.extend_from_slice(b"\\r"),
                b'\t' => self.out.extend_from_slice(b"\\t"),
                // Everything else below 0x20 has no short escape; multi-byte
                // UTF-8 needs none, since JSON strings carry it verbatim.
                0x00..=0x1f => {
                    self.out.extend_from_slice(b"\\u00");
                    self.out.push(HEX_LOWER[(byte >> 4) as usize]);
                    self.out.push(HEX_LOWER[(byte & 0xf) as usize]);
                }
                _ => self.out.push(byte),
            }
        }
        self.out.push(b'"');
    }

    /// A comma belongs between two siblings and nowhere else, and the previous
    /// byte says which case this is: only `{`, `[` and `:` can be followed by
    /// a value that is not a sibling of one already written.
    fn separate(&mut self) {
        if self.out.len() > self.start && !matches!(self.out.last(), Some(b'{' | b'[' | b':')) {
            self.out.push(b',');
        }
    }
}

/// The three scalars `getGenesis` answers with (`apis/beacon/genesis.yaml`).
pub(crate) struct GenesisData {
    pub(crate) genesis_time: u64,
    pub(crate) genesis_validators_root: B256,
    pub(crate) genesis_fork_version: Version,
}

/// The three `EpochState` checkpoints `getStateFinalityCheckpoints` answers
/// with (`apis/beacon/states/finality_checkpoints.yaml`), split out so a read
/// copies these and not `EpochState`'s 512-byte `proposer_lookahead`.
pub(crate) struct FinalityCheckpoints {
    pub(crate) previous_justified: Checkpoint,
    pub(crate) current_justified: Checkpoint,
    pub(crate) finalized: Checkpoint,
}

/// The five flags and slots `getSyncingStatus` answers with
/// (`apis/node/syncing.yaml`).
pub(crate) struct SyncingData {
    pub(crate) head_slot: u64,
    pub(crate) sync_distance: u64,
    pub(crate) is_syncing: bool,
    pub(crate) is_optimistic: bool,
    pub(crate) el_offline: bool,
}

/// What a read reports about the data it answers with; both flags are
/// required beside `data` by the `states/{state_id}` schemas and by the block
/// reads.
#[derive(Clone, Copy)]
pub(crate) struct ReadFlags {
    pub(crate) execution_optimistic: bool,
    pub(crate) finalized: bool,
}

pub(crate) struct SignedHeader<'a> {
    pub(crate) root: B256,
    pub(crate) canonical: bool,
    pub(crate) header: BeaconBlockHeader,
    pub(crate) signature: &'a XMSSSignature,
}

/// Containers, in the field order the beacon-API schemas declare.
impl Json<'_> {
    pub(crate) fn peers<'p>(&mut self, peers: impl Iterator<Item = &'p Peer>) {
        self.begin_object();
        self.key("data");
        self.begin_array();
        let mut count = 0;
        for peer in peers {
            self.begin_object();
            self.key("peer_id");
            self.string(&peer.id_string());
            // xatu doesn't read enr so we skip it - updating it properly requires more work
            self.key("enr");
            self.null();
            self.key("last_seen_p2p_address");
            self.string(&peer.multiaddr());
            self.key("state");
            self.string("connected");
            self.key("direction");
            self.string(peer.direction());
            self.end_object();
            count += 1;
        }
        self.end_array();
        self.key("meta");
        self.begin_object();
        self.key("count");
        self.u64(count);
        self.end_object();
        self.end_object();
    }

    pub(crate) fn peer_count(&mut self, connected: u64) {
        self.begin_object();
        for (state, count) in
            [("disconnected", 0), ("connecting", 0), ("connected", connected), ("disconnecting", 0)]
        {
            self.key(state);
            self.quoted_u64(count);
        }
        self.end_object();
    }

    pub(crate) fn data_envelope(&mut self, data: impl FnOnce(&mut Self)) {
        self.begin_object();
        self.key("data");
        data(self);
        self.end_object();
    }

    pub(crate) fn versioned_envelope(&mut self, version: &str, data: impl FnOnce(&mut Self)) {
        self.begin_object();
        self.key("version");
        self.string(version);
        self.key("data");
        data(self);
        self.end_object();
    }

    pub(crate) fn flagged_envelope(&mut self, flags: ReadFlags, data: impl FnOnce(&mut Self)) {
        self.begin_flagged_envelope(flags);
        data(self);
        self.end_object();
    }

    /// The envelope up to its `data` value, for a body rendered in parts.
    pub(crate) fn begin_flagged_envelope(&mut self, flags: ReadFlags) {
        self.begin_object();
        self.key("execution_optimistic");
        self.bool(flags.execution_optimistic);
        self.key("finalized");
        self.bool(flags.finalized);
        self.key("data");
    }

    pub(crate) fn genesis(&mut self, genesis: &GenesisData) {
        self.begin_object();
        self.key("genesis_time");
        self.quoted_u64(genesis.genesis_time);
        self.key("genesis_validators_root");
        self.hex(&genesis.genesis_validators_root);
        self.key("genesis_fork_version");
        self.hex(&genesis.genesis_fork_version);
        self.end_object();
    }

    pub(crate) fn fork(&mut self, fork: &Fork) {
        self.begin_object();
        self.key("previous_version");
        self.hex(&fork.previous_version);
        self.key("current_version");
        self.hex(&fork.current_version);
        self.key("epoch");
        self.quoted_u64(fork.epoch);
        self.end_object();
    }

    pub(crate) fn block_root(&mut self, root: &B256) {
        self.begin_object();
        self.key("root");
        self.hex(root);
        self.end_object();
    }

    pub(crate) fn signed_headers(&mut self, headers: &[SignedHeader<'_>]) {
        self.begin_array();
        for signed in headers {
            self.signed_header(signed);
        }
        self.end_array();
    }

    pub(crate) fn signed_header(&mut self, signed: &SignedHeader<'_>) {
        self.begin_object();
        self.key("root");
        self.hex(&signed.root);
        self.key("canonical");
        self.bool(signed.canonical);
        self.key("header");
        self.begin_object();
        self.key("message");
        self.begin_object();
        self.key("slot");
        self.quoted_u64(signed.header.slot);
        self.key("proposer_index");
        self.quoted_u64(signed.header.proposer_index);
        self.key("parent_root");
        self.hex(&signed.header.parent_root);
        self.key("state_root");
        self.hex(&signed.header.state_root);
        self.key("body_root");
        self.hex(&signed.header.body_root);
        self.end_object();
        self.key("signature");
        self.hex(signed.signature);
        self.end_object();
        self.end_object();
    }

    pub(crate) fn checkpoint(&mut self, checkpoint: &Checkpoint) {
        self.begin_object();
        self.key("epoch");
        self.quoted_u64(checkpoint.epoch);
        self.key("root");
        self.hex(&checkpoint.root);
        self.end_object();
    }

    pub(crate) fn indexed_failures<'f>(
        &mut self,
        message: &str,
        failures: impl IntoIterator<Item = (usize, &'f str)>,
    ) {
        self.begin_object();
        self.key("code");
        self.u64(400);
        self.key("message");
        self.string(message);
        self.key("failures");
        self.begin_array();
        for (index, message) in failures {
            self.begin_object();
            self.key("index");
            self.u64(index as u64);
            self.key("message");
            self.string(message);
            self.end_object();
        }
        self.end_array();
        self.end_object();
    }

    pub(crate) fn attestation_data(&mut self, data: &AttestationData) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(data.slot);
        self.key("index");
        self.quoted_u64(data.index);
        self.key("beacon_block_root");
        self.hex(&data.beacon_block_root);
        self.key("source");
        self.checkpoint(&data.source);
        self.key("target");
        self.checkpoint(&data.target);
        self.end_object();
    }

    /// `ssz` is a `ProvedAttestationView`.
    pub(crate) fn proved_attestation(&mut self, ssz: &[u8]) {
        self.begin_object();
        self.key("aggregate");
        self.attestation_pq(ProvedAttestationView::attestation(ssz));
        self.key("proof");
        self.hex(ProvedAttestationView::proof(ssz));
        self.end_object();
    }

    pub(crate) fn syncing(&mut self, syncing: &SyncingData) {
        self.begin_object();
        self.key("head_slot");
        self.quoted_u64(syncing.head_slot);
        self.key("sync_distance");
        self.quoted_u64(syncing.sync_distance);
        self.key("is_syncing");
        self.bool(syncing.is_syncing);
        self.key("is_optimistic");
        self.bool(syncing.is_optimistic);
        self.key("el_offline");
        self.bool(syncing.el_offline);
        self.end_object();
    }

    pub(crate) fn block_event(
        &mut self,
        slot: u64,
        block_root: &[u8; 32],
        execution_optimistic: bool,
    ) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(slot);
        self.key("block");
        self.hex(block_root);
        self.key("execution_optimistic");
        self.bool(execution_optimistic);
        self.end_object();
    }

    pub(crate) fn head_event(&mut self, head: &HeadEvent) {
        let roots = ["previous_duty_dependent_root", "current_duty_dependent_root"];
        self.head(head, roots, None);
    }

    pub(crate) fn head_v2_event(&mut self, head: &HeadEvent, fork_name: &str) {
        self.begin_object();
        self.key("version");
        self.string(fork_name);
        self.key("data");
        let roots = ["current_epoch_dependent_root", "next_epoch_dependent_root"];
        self.head(head, roots, Some(head.payload.name()));
        self.end_object();
    }

    fn head(&mut self, head: &HeadEvent, [previous, current]: [&str; 2], payload: Option<&str>) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(head.slot);
        self.key("block");
        self.hex(&head.block_root);
        self.key("state");
        self.hex(&head.roots.state_root);
        if let Some(payload) = payload {
            self.key("payload_status");
            self.string(payload);
        }
        self.key("epoch_transition");
        self.bool(head.epoch_transition);
        self.key(previous);
        self.hex(&head.roots.previous_duty_dependent_root);
        self.key(current);
        self.hex(&head.roots.current_duty_dependent_root);
        self.key("execution_optimistic");
        self.bool(head.execution_optimistic);
        self.end_object();
    }

    pub(crate) fn payload_attributes_event(
        &mut self,
        attributes: &PreparedPayloadAttributes,
        withdrawals_ssz: &[u8],
        gloas: bool,
    ) {
        self.begin_object();
        self.key("proposer_index");
        self.quoted_u64(attributes.proposer_index);
        self.key("proposal_slot");
        self.quoted_u64(attributes.proposal_slot);
        if let Some(number) = attributes.parent_block_number {
            self.key("parent_block_number");
            self.quoted_u64(number);
        }
        self.key("parent_block_root");
        self.hex(&attributes.parent_block_root);
        self.key("parent_block_hash");
        self.hex(&attributes.parent_block_hash);
        self.key("payload_attributes");
        self.begin_object();
        self.key("timestamp");
        self.quoted_u64(attributes.timestamp);
        self.key("prev_randao");
        self.hex(&attributes.prev_randao);
        self.key("suggested_fee_recipient");
        self.hex(&attributes.fee_recipient);
        self.key("withdrawals");
        self.begin_array();
        for withdrawal in withdrawals_ssz.chunks_exact(WITHDRAWAL_SIZE) {
            self.withdrawal(withdrawal.try_into().unwrap());
        }
        self.end_array();
        self.key("parent_beacon_block_root");
        self.hex(&attributes.parent_block_root);
        if gloas {
            self.key("slot_number");
            self.quoted_u64(attributes.proposal_slot);
            self.key("target_gas_limit");
            self.quoted_u64(attributes.target_gas_limit);
        }
        self.end_object();
        self.end_object();
    }

    fn withdrawal(&mut self, ssz: &[u8; WITHDRAWAL_SIZE]) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(WithdrawalView::index(ssz));
        self.key("validator_index");
        self.quoted_u64(WithdrawalView::validator_index(ssz));
        self.key("address");
        self.hex(WithdrawalView::address(ssz));
        self.key("amount");
        self.quoted_u64(WithdrawalView::amount(ssz));
        self.end_object();
    }

    pub(crate) fn block_gossip_event(&mut self, slot: u64, block_root: &[u8; 32]) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(slot);
        self.key("block");
        self.hex(block_root);
        self.end_object();
    }

    pub(crate) fn execution_payload_available_event(&mut self, slot: u64, block_root: &[u8; 32]) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(slot);
        self.key("block_root");
        self.hex(block_root);
        self.end_object();
    }

    pub(crate) fn signed_proposer_preferences(
        &mut self,
        ssz: &[u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE],
    ) {
        let message = SignedProposerPreferencesPqView::message(ssz);
        self.begin_object();
        self.key("message");
        self.begin_object();
        self.key("dependent_root");
        self.hex(ProposerPreferencesView::dependent_root(message));
        self.key("proposal_slot");
        self.quoted_u64(ProposerPreferencesView::proposal_slot(message));
        self.key("validator_index");
        self.quoted_u64(ProposerPreferencesView::validator_index(message));
        self.key("fee_recipient");
        self.hex(ProposerPreferencesView::fee_recipient(message));
        self.key("target_gas_limit");
        self.quoted_u64(ProposerPreferencesView::target_gas_limit(message));
        self.end_object();
        self.key("signature");
        self.hex(SignedProposerPreferencesPqView::signature(ssz));
        self.end_object();
    }

    pub(crate) fn proposer_slashing(&mut self, ssz: &[u8; PROPOSER_SLASHING_PQ_SIZE]) {
        let (first, second) = ssz.split_at(PROPOSER_SLASHING_PQ_SIZE / 2);
        self.begin_object();
        self.key("signed_header_1");
        self.signed_block_header(first);
        self.key("signed_header_2");
        self.signed_block_header(second);
        self.end_object();
    }

    /// `ssz` is one `SignedBeaconBlockHeader`.
    fn signed_block_header(&mut self, ssz: &[u8]) {
        let (header, signature) = ssz.split_at(BEACON_BLOCK_HEADER_SIZE);
        let header = header.try_into().expect("BEACON_BLOCK_HEADER_SIZE bytes");
        self.begin_object();
        self.key("message");
        self.begin_object();
        self.key("slot");
        self.quoted_u64(BeaconBlockHeaderView::slot(header));
        self.key("proposer_index");
        self.quoted_u64(BeaconBlockHeaderView::proposer_index(header));
        self.key("parent_root");
        self.hex(BeaconBlockHeaderView::parent_root(header));
        self.key("state_root");
        self.hex(BeaconBlockHeaderView::state_root(header));
        self.key("body_root");
        self.hex(BeaconBlockHeaderView::body_root(header));
        self.end_object();
        self.key("signature");
        self.hex(signature);
        self.end_object();
    }

    /// `ssz` came out of the slashing pool, so its framing holds.
    pub(crate) fn attester_slashing(&mut self, ssz: &[u8]) {
        let second = u32::from_le_bytes(ssz[4..8].try_into().unwrap()) as usize;
        self.begin_object();
        self.key("attestation_1");
        self.indexed_attestation(&ssz[8..second]);
        self.key("attestation_2");
        self.indexed_attestation(&ssz[second..]);
        self.end_object();
    }

    fn attestation_pq(&mut self, ssz: &[u8]) {
        self.begin_object();
        self.key("aggregation_bits");
        self.hex(AttestationPqView::aggregation_bits(ssz));
        self.key("data");
        self.attestation_data(&AttestationPqView::data(ssz).into());
        self.key("committee_bits");
        self.hex(AttestationPqView::committee_bits(ssz));
        self.end_object();
    }

    /// A produced block's body: its version and values, and `data`.
    pub(crate) fn produced_block(
        &mut self,
        metadata: &ProducedBlockMetadata,
        data: impl FnOnce(&mut Self),
    ) {
        self.begin_object();
        self.key("version");
        self.string(metadata.version);
        self.key("consensus_block_value");
        self.string(&metadata.consensus_block_value);
        self.key("execution_payload_value");
        self.string(&metadata.execution_payload_value);
        self.key("execution_payload_included");
        self.bool(metadata.payload_included);
        self.key("data");
        data(self);
        self.end_object();
    }

    /// `ProduceBlockV4`'s `data` with the payload: the envelope is `envelope`'s
    /// fixed part followed by `payload`'s execution payload and requests.
    pub(crate) fn pq_block_and_envelope(
        &mut self,
        block: &[u8],
        envelope: &[u8; EXECUTION_PAYLOAD_ENVELOPE_MIN],
        payload: &PayloadFrame<'_>,
    ) {
        self.begin_object();
        self.key("block");
        self.beacon_block_pq(block);
        self.key("execution_payload_envelope");
        self.begin_object();
        self.key("payload");
        self.execution_payload_gloas(payload.execution_payload);
        self.key("execution_requests");
        self.execution_requests_pq(payload.execution_requests);
        self.key("builder_index");
        self.quoted_u64(ExecutionPayloadEnvelopeView::builder_index(envelope));
        self.key("beacon_block_root");
        self.hex(ExecutionPayloadEnvelopeView::beacon_block_root(envelope));
        self.key("parent_beacon_block_root");
        self.hex(ExecutionPayloadEnvelopeView::parent_beacon_block_root(envelope));
        self.end_object();
        self.key("kzg_proofs");
        self.hex_items::<BYTES_PER_KZG_PROOF>(payload.cell_proofs);
        self.key("blobs");
        self.hex_items::<BYTES_PER_BLOB>(payload.blobs);
        self.end_object();
    }

    /// A PQ `BeaconBlock`, whose fixed part opens like a header's.
    pub(crate) fn beacon_block_pq(&mut self, block: &[u8]) {
        let header: &[u8; BEACON_BLOCK_HEADER_SIZE] =
            block[..BEACON_BLOCK_HEADER_SIZE].try_into().expect("a block outgrows its header");
        self.begin_object();
        self.key("slot");
        self.quoted_u64(BeaconBlockHeaderView::slot(header));
        self.key("proposer_index");
        self.quoted_u64(BeaconBlockHeaderView::proposer_index(header));
        self.key("parent_root");
        self.hex(BeaconBlockHeaderView::parent_root(header));
        self.key("state_root");
        self.hex(BeaconBlockHeaderView::state_root(header));
        self.key("body");
        self.beacon_block_body_pq(&block[BEACON_BLOCK_FIXED..]);
        self.end_object();
    }

    fn beacon_block_body_pq(&mut self, body: &[u8]) {
        self.begin_object();
        self.key("randao_reveal");
        self.hex_items::<32>(BeaconBlockBodyPqView::randao_reveal(body));
        self.key("eth1_data");
        self.eth1_data(BeaconBlockBodyPqView::eth1_data(body));
        self.key("graffiti");
        self.hex(BeaconBlockBodyPqView::graffiti(body));
        self.key("proposer_slashings");
        self.begin_array();
        for slashing in BeaconBlockBodyPqView::proposer_slashings(body).as_chunks().0 {
            self.proposer_slashing(slashing);
        }
        self.end_array();
        self.key("attester_slashings");
        self.begin_array();
        for slashing in variable_list_items(BeaconBlockBodyPqView::attester_slashings(body)) {
            self.attester_slashing(slashing);
        }
        self.end_array();
        self.key("attestations");
        self.begin_array();
        for attestation in variable_list_items(BeaconBlockBodyPqView::attestations(body)) {
            self.attestation_pq(attestation);
        }
        self.end_array();
        self.key("deposits");
        self.begin_array();
        for deposit in BeaconBlockBodyPqView::deposits(body).as_chunks().0 {
            self.deposit(deposit);
        }
        self.end_array();
        self.key("signed_execution_payload_bid");
        self.signed_execution_payload_bid_pq(BeaconBlockBodyPqView::signed_execution_payload_bid(
            body,
        ));
        self.key("parent_execution_requests");
        self.execution_requests_pq(BeaconBlockBodyPqView::parent_execution_requests(body));
        self.key("proof");
        self.hex(BeaconBlockBodyPqView::proof(body));
        self.end_object();
    }

    fn eth1_data(&mut self, ssz: &[u8; ETH1_DATA_SIZE]) {
        self.begin_object();
        self.key("deposit_root");
        self.hex(Eth1DataView::deposit_root(ssz));
        self.key("deposit_count");
        self.quoted_u64(Eth1DataView::deposit_count(ssz));
        self.key("block_hash");
        self.hex(Eth1DataView::block_hash(ssz));
        self.end_object();
    }

    fn deposit(&mut self, ssz: &[u8; DEPOSIT_SIZE]) {
        let data = DepositView::data(ssz);
        self.begin_object();
        self.key("proof");
        self.hex_items::<32>(DepositView::proof(ssz));
        self.key("data");
        self.begin_object();
        self.key("pubkey");
        self.hex(DepositDataView::pubkey(data));
        self.key("withdrawal_credentials");
        self.hex(DepositDataView::withdrawal_credentials(data));
        self.key("amount");
        self.quoted_u64(DepositDataView::amount(data));
        self.key("signature");
        self.hex(DepositDataView::signature(data));
        self.end_object();
        self.end_object();
    }

    fn signed_execution_payload_bid_pq(&mut self, ssz: &[u8]) {
        let bid = SignedExecutionPayloadBidPqView::message(ssz);
        self.begin_object();
        self.key("message");
        self.begin_object();
        self.key("parent_block_hash");
        self.hex(ExecutionPayloadBidView::parent_block_hash(bid));
        self.key("parent_block_root");
        self.hex(ExecutionPayloadBidView::parent_block_root(bid));
        self.key("block_hash");
        self.hex(ExecutionPayloadBidView::block_hash(bid));
        self.key("prev_randao");
        self.hex(ExecutionPayloadBidView::prev_randao(bid));
        self.key("fee_recipient");
        self.hex(ExecutionPayloadBidView::fee_recipient(bid));
        self.key("gas_limit");
        self.quoted_u64(ExecutionPayloadBidView::gas_limit(bid));
        self.key("builder_index");
        self.quoted_u64(ExecutionPayloadBidView::builder_index(bid));
        self.key("slot");
        self.quoted_u64(ExecutionPayloadBidView::slot(bid));
        self.key("value");
        self.quoted_u64(ExecutionPayloadBidView::value(bid));
        self.key("execution_payment");
        self.quoted_u64(ExecutionPayloadBidView::execution_payment(bid));
        self.key("blob_kzg_commitments");
        self.hex_items::<BYTES_PER_KZG_COMMITMENT>(ExecutionPayloadBidView::blob_kzg_commitments(
            bid,
        ));
        self.key("execution_requests_root");
        self.hex(ExecutionPayloadBidView::execution_requests_root(bid));
        self.end_object();
        self.key("signature");
        self.hex(SignedExecutionPayloadBidPqView::signature(ssz));
        self.end_object();
    }

    fn execution_payload_gloas(&mut self, ssz: &[u8]) {
        self.begin_object();
        self.key("parent_hash");
        self.hex(ExecutionPayloadView::parent_hash(ssz));
        self.key("fee_recipient");
        self.hex(ExecutionPayloadView::fee_recipient(ssz));
        self.key("state_root");
        self.hex(ExecutionPayloadView::state_root(ssz));
        self.key("receipts_root");
        self.hex(ExecutionPayloadView::receipts_root(ssz));
        self.key("logs_bloom");
        self.hex(ExecutionPayloadView::logs_bloom(ssz));
        self.key("prev_randao");
        self.hex(ExecutionPayloadView::prev_randao(ssz));
        self.key("block_number");
        self.quoted_u64(ExecutionPayloadView::block_number(ssz));
        self.key("gas_limit");
        self.quoted_u64(ExecutionPayloadView::gas_limit(ssz));
        self.key("gas_used");
        self.quoted_u64(ExecutionPayloadView::gas_used(ssz));
        self.key("timestamp");
        self.quoted_u64(ExecutionPayloadView::timestamp(ssz));
        self.key("extra_data");
        self.hex(ExecutionPayloadView::extra_data(ssz));
        self.key("base_fee_per_gas");
        self.string(&wei_decimal(ExecutionPayloadView::base_fee_per_gas(ssz)));
        self.key("block_hash");
        self.hex(ExecutionPayloadView::block_hash(ssz));
        self.key("transactions");
        self.begin_array();
        for transaction in variable_list_items(ExecutionPayloadView::transactions(ssz)) {
            self.hex(transaction);
        }
        self.end_array();
        self.key("withdrawals");
        self.begin_array();
        for withdrawal in ExecutionPayloadView::withdrawals_gloas(ssz).as_chunks().0 {
            self.withdrawal(withdrawal);
        }
        self.end_array();
        self.key("blob_gas_used");
        self.quoted_u64(ExecutionPayloadView::blob_gas_used(ssz));
        self.key("excess_blob_gas");
        self.quoted_u64(ExecutionPayloadView::excess_blob_gas(ssz));
        self.key("block_access_list");
        self.hex(ExecutionPayloadView::block_access_list(ssz));
        self.key("slot_number");
        self.quoted_u64(ExecutionPayloadView::slot_number(ssz));
        self.end_object();
    }

    fn execution_requests_pq(&mut self, ssz: &[u8]) {
        let [
            deposits,
            withdrawals,
            consolidations,
            builder_deposits,
            builder_exits,
            validator_preregistrations,
            builder_preregistrations,
            voluntary_exits,
        ] = ExecutionRequestsPqView::sections(ssz);
        self.begin_object();
        self.key("deposits");
        self.objects(deposits, |json, request| {
            json.field_hex("pubkey", DepositRequestView::pubkey(request));
            json.field_hex(
                "withdrawal_credentials",
                DepositRequestView::withdrawal_credentials(request),
            );
            json.key("amount");
            json.quoted_u64(DepositRequestView::amount(request));
            json.field_hex("signature", DepositRequestView::signature(request));
            json.key("index");
            json.quoted_u64(DepositRequestView::index(request));
        });
        self.key("withdrawals");
        self.objects(withdrawals, |json, request| {
            json.field_hex("source_address", WithdrawalRequestView::source_address(request));
            json.field_hex("validator_pubkey", WithdrawalRequestView::validator_pubkey(request));
            json.key("amount");
            json.quoted_u64(WithdrawalRequestView::amount(request));
        });
        self.key("consolidations");
        self.objects(consolidations, |json, request| {
            json.field_hex("source_address", ConsolidationRequestView::source_address(request));
            json.field_hex("source_pubkey", ConsolidationRequestView::source_pubkey(request));
            json.field_hex("target_pubkey", ConsolidationRequestView::target_pubkey(request));
        });
        self.key("builder_deposits");
        self.objects(builder_deposits, |json, request| {
            json.field_hex("pubkey", BuilderDepositRequestView::pubkey(request));
            json.field_hex(
                "withdrawal_credentials",
                BuilderDepositRequestView::withdrawal_credentials(request),
            );
            json.key("amount");
            json.quoted_u64(BuilderDepositRequestView::amount(request));
            json.field_hex("signature", BuilderDepositRequestView::signature(request));
        });
        self.key("builder_exits");
        self.objects(builder_exits, |json, request| {
            json.field_hex("source_address", BuilderExitRequestView::source_address(request));
            json.field_hex("pubkey", BuilderExitRequestView::pubkey(request));
        });
        self.key("validator_preregistrations");
        self.objects(validator_preregistrations, |json, request| {
            json.field_hex("pubkey", ValidatorPreregistrationRequestView::pubkey(request));
            json.field_hex(
                "withdrawal_credentials",
                ValidatorPreregistrationRequestView::withdrawal_credentials(request),
            );
            json.field_hex("vrf_root", ValidatorPreregistrationRequestView::vrf_root(request));
        });
        self.key("builder_preregistrations");
        self.objects(builder_preregistrations, |json, request| {
            json.field_hex("pubkey", BuilderPreregistrationRequestView::pubkey(request));
            json.field_hex(
                "withdrawal_credentials",
                BuilderPreregistrationRequestView::withdrawal_credentials(request),
            );
        });
        self.key("voluntary_exits");
        self.objects(voluntary_exits, |json, request| {
            json.field_hex("pubkey", VoluntaryExitRequestView::pubkey(request));
        });
        self.end_object();
    }

    /// An array of one object per `N`-byte element of `ssz`.
    fn objects<const N: usize>(&mut self, ssz: &[u8], fields: impl Fn(&mut Self, &[u8; N])) {
        self.begin_array();
        for element in ssz.as_chunks().0 {
            self.begin_object();
            fields(self, element);
            self.end_object();
        }
        self.end_array();
    }

    fn field_hex(&mut self, name: &str, bytes: &[u8]) {
        self.key(name);
        self.hex(bytes);
    }

    /// An array of one hex string per `N`-byte element of `ssz`.
    fn hex_items<const N: usize>(&mut self, ssz: &[u8]) {
        self.begin_array();
        for element in ssz.as_chunks::<N>().0 {
            self.hex(element);
        }
        self.end_array();
    }

    fn indexed_attestation(&mut self, ssz: &[u8]) {
        self.begin_object();
        self.key("attesting_indices");
        self.begin_array();
        for index in IndexedAttestationPqView::attesting_indices(ssz).chunks_exact(8) {
            self.quoted_u64(u64::from_le_bytes(index.try_into().unwrap()));
        }
        self.end_array();
        self.key("data");
        self.attestation_data(&IndexedAttestationPqView::data(ssz).into());
        self.key("proof");
        self.hex(IndexedAttestationPqView::proof(ssz));
        self.end_object();
    }

    pub(crate) fn single_attestation_event(&mut self, ssz: &[u8; SINGLE_ATT_PQ_SIZE]) {
        self.begin_object();
        self.key("committee_index");
        self.quoted_u64(SingleAttestationPqView::committee_index(ssz));
        self.key("attester_index");
        self.quoted_u64(SingleAttestationPqView::attester_index(ssz));
        self.key("data");
        self.attestation_data(&SingleAttestationPqView::data(ssz).into());
        self.key("signature");
        self.hex(SingleAttestationPqView::signature(ssz));
        self.end_object();
    }

    pub(crate) fn data_column_sidecar_event(
        &mut self,
        block_root: &[u8; 32],
        column_index: u64,
        slot: u64,
        kzg_commitments: Option<&[u8]>,
    ) {
        self.begin_object();
        self.key("block_root");
        self.hex(block_root);
        self.key("index");
        self.quoted_u64(column_index);
        self.key("slot");
        self.quoted_u64(slot);
        if let Some(commitments) = kzg_commitments {
            debug_assert!(commitments.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT));
            self.key("kzg_commitments");
            self.begin_array();
            for commitment in commitments.chunks_exact(BYTES_PER_KZG_COMMITMENT) {
                self.hex(commitment);
            }
            self.end_array();
        }
        self.end_object();
    }

    /// `GetProposerDutiesResponse` (`apis/validator/duties/proposer.yaml`).
    pub(crate) fn proposer_duties(&mut self, duties: &ProposerDuties, execution_optimistic: bool) {
        self.duties_envelope(Some(duties.dependent_root), execution_optimistic, |json| {
            for duty in &duties.duties {
                let pubkey = duties.scheme.public_key(&duty.pubkey);
                json.duty(pubkey, duty.validator_index, |json| {
                    json.key("slot");
                    json.quoted_u64(duty.slot);
                });
            }
        });
    }

    /// `GetAttesterDutiesResponse` (`apis/validator/duties/attester.yaml`).
    pub(crate) fn attester_duties<'a>(
        &mut self,
        dependent_root: B256,
        execution_optimistic: bool,
        duties: impl Iterator<Item = AttesterDuty<'a>>,
    ) {
        self.duties_envelope(Some(dependent_root), execution_optimistic, |json| {
            for duty in duties {
                json.duty(duty.pubkey, duty.validator_index, |json| {
                    json.key("committee_index");
                    json.quoted_u64(duty.committee_index);
                    json.key("committee_length");
                    json.quoted_u64(duty.committee_length);
                    json.key("committees_at_slot");
                    json.quoted_u64(duty.committees_at_slot);
                    json.key("validator_committee_index");
                    json.quoted_u64(duty.validator_committee_index);
                    json.key("slot");
                    json.quoted_u64(duty.slot);
                    json.key("is_aggregator");
                    json.bool(duty.aggregator_position.is_some());
                    if let Some(position) = duty.aggregator_position {
                        json.key("aggregator_position");
                        json.quoted_u64(position);
                    }
                });
            }
        });
    }

    pub(crate) fn ptc_duties<'a>(
        &mut self,
        dependent_root: B256,
        execution_optimistic: bool,
        duties: impl Iterator<Item = PtcDuty<'a>>,
    ) {
        self.duties_envelope(Some(dependent_root), execution_optimistic, |json| {
            for duty in duties {
                json.duty(duty.pubkey, duty.validator_index, |json| {
                    json.key("slot");
                    json.quoted_u64(duty.slot);
                });
            }
        });
    }

    pub(crate) fn payload_attestation_data(&mut self, ssz: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) {
        self.begin_object();
        self.key("beacon_block_root");
        self.hex(PayloadAttestationDataView::beacon_block_root(ssz));
        self.key("slot");
        self.quoted_u64(PayloadAttestationDataView::slot(ssz));
        self.key("payload_present");
        self.bool(PayloadAttestationDataView::payload_present(ssz));
        self.key("blob_data_available");
        self.bool(PayloadAttestationDataView::blob_data_available(ssz));
        self.end_object();
    }

    pub(crate) fn liveness(&mut self, entries: impl Iterator<Item = (u64, bool)>) {
        self.data_envelope(|json| {
            json.begin_array();
            for (index, is_live) in entries {
                json.begin_object();
                json.key("index");
                json.quoted_u64(index);
                json.key("is_live");
                json.bool(is_live);
                json.end_object();
            }
            json.end_array();
        });
    }

    fn duty(&mut self, pubkey: &[u8], validator_index: u64, rest: impl FnOnce(&mut Self)) {
        self.begin_object();
        self.key("pubkey");
        self.hex(pubkey);
        self.key("validator_index");
        self.quoted_u64(validator_index);
        rest(self);
        self.end_object();
    }

    fn duties_envelope(
        &mut self,
        dependent_root: Option<B256>,
        execution_optimistic: bool,
        data: impl FnOnce(&mut Self),
    ) {
        self.begin_object();
        if let Some(root) = dependent_root {
            self.key("dependent_root");
            self.hex(&root);
        }
        self.key("execution_optimistic");
        self.bool(execution_optimistic);
        self.key("data");
        self.begin_array();
        data(self);
        self.end_array();
        self.end_object();
    }

    /// `ValidatorResponse` (`apis/beacon/states/validator.yaml`). Keys are
    /// literals, as a whole-registry read writes about a million of these.
    pub(crate) fn validator(&mut self, record: &ValidatorRecord) {
        let lifecycle = &record.lifecycle;
        self.separate();
        self.out.extend_from_slice(b"{\"index\":");
        self.unseparated_quoted_u64(record.index);
        self.out.extend_from_slice(b",\"balance\":");
        self.unseparated_quoted_u64(record.balance);
        self.out.extend_from_slice(b",\"status\":\"");
        self.out.extend_from_slice(record.status.name().as_bytes());
        self.out.extend_from_slice(b"\",\"validator\":{\"pubkey\":");
        self.unseparated_hex(record.scheme.public_key(&record.pubkey));
        if let Some(vrf_root) = &record.vrf_root {
            self.out.extend_from_slice(b",\"vrf_root\":");
            self.unseparated_hex(vrf_root);
        }
        self.out.extend_from_slice(b",\"withdrawal_credentials\":");
        self.unseparated_hex(&record.withdrawal_credentials.0);
        self.out.extend_from_slice(b",\"effective_balance\":");
        self.unseparated_quoted_u64(record.effective_balance);
        self.out.extend_from_slice(if lifecycle.slashed {
            b",\"slashed\":true,\"activation_eligibility_epoch\":".as_slice()
        } else {
            b",\"slashed\":false,\"activation_eligibility_epoch\":".as_slice()
        });
        self.unseparated_quoted_u64(lifecycle.activation_eligibility_epoch);
        self.out.extend_from_slice(b",\"activation_epoch\":");
        self.unseparated_quoted_u64(lifecycle.activation_epoch);
        self.out.extend_from_slice(b",\"exit_epoch\":");
        self.unseparated_quoted_u64(lifecycle.exit_epoch);
        self.out.extend_from_slice(b",\"withdrawable_epoch\":");
        self.unseparated_quoted_u64(lifecycle.withdrawable_epoch);
        self.out.extend_from_slice(b"}}");
    }

    pub(crate) fn builder(
        &mut self,
        index: u64,
        status: &str,
        builder: &Builder,
        scheme: KeyScheme,
    ) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(index);
        self.key("status");
        self.string(status);
        self.key("builder");
        self.begin_object();
        self.key("pubkey");
        self.hex(scheme.public_key(&builder.pubkey));
        self.key("version");
        self.quoted_u64(builder.version.into());
        self.key("execution_address");
        self.hex(&builder.execution_address);
        self.key("balance");
        self.quoted_u64(builder.balance);
        self.key("deposit_epoch");
        self.quoted_u64(builder.deposit_epoch);
        self.key("withdrawable_epoch");
        self.quoted_u64(builder.withdrawable_epoch);
        self.end_object();
        self.end_object();
    }

    pub(crate) fn validator_balance(&mut self, index: u64, balance: u64) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(index);
        self.key("balance");
        self.quoted_u64(balance);
        self.end_object();
    }

    pub(crate) fn committee(&mut self, index: u64, slot: u64, validators: &[u32]) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(index);
        self.key("slot");
        self.quoted_u64(slot);
        self.key("validators");
        self.begin_array();
        for &validator in validators {
            self.quoted_u64(validator as u64);
        }
        self.end_array();
        self.end_object();
    }

    pub(crate) fn finality_checkpoints(&mut self, checkpoints: &FinalityCheckpoints) {
        self.begin_object();
        self.key("previous_justified");
        self.checkpoint(&checkpoints.previous_justified);
        self.key("current_justified");
        self.checkpoint(&checkpoints.current_justified);
        self.key("finalized");
        self.checkpoint(&checkpoints.finalized);
        self.end_object();
    }
}

pub(crate) fn version_body() -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_object();
    json.key("version");
    json.string(AGENT_VERSION);
    json.end_object();
    json.end_object();
    out
}

/// `GET /eth/v1/config/fork_schedule`. Unscheduled forks are omitted: the
/// list is what this node is aware of *scheduling*, and a client that
/// derives a signing domain from the last entry must not land on a fork
/// that will never activate.
pub(crate) fn fork_schedule_body(spec: &SpecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_array();
    let mut previous_version = spec.fork_version(ForkName::Phase0);
    for fork in ForkName::ALL {
        let epoch = spec.fork_epoch(fork);
        if epoch == FAR_FUTURE_EPOCH {
            continue;
        }
        let current_version = spec.fork_version(fork);
        json.fork(&Fork { previous_version, current_version, epoch });
        previous_version = current_version;
    }
    json.end_array();
    json.end_object();
    out
}

/// `GET /eth/v1/config/deposit_contract`.
pub(crate) fn deposit_contract_body(spec: &SpecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_object();
    json.key("chain_id");
    json.quoted_u64(spec.deposit_chain_id);
    json.key("address");
    json.hex(&spec.deposit_contract_address);
    json.end_object();
    json.end_object();
    out
}

/// Whether `text` survives being spliced into JSON without escaping — the
/// guard for compile-time field names and messages, not for user input
/// ([`Json::string`] escapes).
pub(crate) fn json_safe(text: &str) -> bool {
    !text.contains(['"', '\\'])
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::FAR_FUTURE_EPOCH;

    use super::*;

    fn write(render: impl FnOnce(&mut Json<'_>)) -> String {
        let mut out = Vec::new();
        render(&mut Json::new(&mut out));
        String::from_utf8(out).unwrap()
    }

    /// Byte-exact body plus a parse: a golden that is not valid JSON is a
    /// golden that pinned a bug.
    fn assert_body(render: impl FnOnce(&mut Json<'_>), expected: &str) {
        let body = write(render);
        assert_eq!(body, expected);
        serde_json::from_str::<serde_json::Value>(&body).expect("valid JSON");
    }

    #[test]
    fn wei_decimal_renders_every_limb() {
        assert_eq!(wei_decimal(&[0; 32]), "0");
        let mut two_ether = [0; 32];
        two_ether[..8].copy_from_slice(&2_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(wei_decimal(&two_ether), "2000000000000000000");
        let mut two_to_64 = [0; 32];
        two_to_64[8] = 1;
        assert_eq!(wei_decimal(&two_to_64), "18446744073709551616");
    }

    #[test]
    fn integers_are_quoted_decimal_strings() {
        assert_eq!(write(|j| j.quoted_u64(0)), "\"0\"");
        assert_eq!(write(|j| j.quoted_u64(7)), "\"7\"");
        assert_eq!(write(|j| j.quoted_u64(10)), "\"10\"");
        assert_eq!(write(|j| j.quoted_u64(1_606_824_023)), "\"1606824023\"");
        assert_eq!(write(|j| j.quoted_u64(FAR_FUTURE_EPOCH)), "\"18446744073709551615\"");
        assert_eq!(write(|j| j.quoted_u64(u64::MAX)), "\"18446744073709551615\"");
    }

    #[test]
    fn hex_is_lowercase_and_full_width_at_every_spec_size() {
        assert_eq!(write(|j| j.hex(&[])), "\"0x\"");
        assert_eq!(write(|j| j.hex(&[0x00, 0x0a, 0xff, 0xAB])), "\"0x000affab\"");

        for width in [4usize, 20, 32, 48, 96] {
            let bytes = vec![0xdeu8; width];
            let rendered = write(|j| j.hex(&bytes));
            assert_eq!(rendered.len(), width * 2 + 4, "width {width}");
            assert!(rendered.starts_with("\"0x"), "width {width}: {rendered}");
            assert!(rendered.ends_with('"'), "width {width}: {rendered}");
            assert!(rendered[3..rendered.len() - 1].bytes().all(|b| b == b'd' || b == b'e'));
        }
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_control_bytes() {
        assert_eq!(write(|j| j.string("active_ongoing")), "\"active_ongoing\"");
        assert_eq!(write(|j| j.string("")), "\"\"");
        assert_eq!(write(|j| j.string("a\"b")), "\"a\\\"b\"");
        assert_eq!(write(|j| j.string("a\\b")), "\"a\\\\b\"");
        assert_eq!(write(|j| j.string("\n\r\t")), "\"\\n\\r\\t\"");
        assert_eq!(write(|j| j.string("\u{08}\u{0c}")), "\"\\b\\f\"");
        assert_eq!(write(|j| j.string("\u{00}\u{01}\u{1f}")), "\"\\u0000\\u0001\\u001f\"");
        assert_eq!(write(|j| j.string("\u{7f}")), "\"\u{7f}\"");
    }

    #[test]
    fn escaped_strings_round_trip_through_a_parser() {
        let awkward = "silver/v0.1 \"quoted\"\\slashed\ttabbed\nnewline\u{01}\u{7f}é☃";
        let body = write(|j| j.string(awkward));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed.as_str(), Some(awkward));
    }

    #[test]
    fn siblings_are_comma_separated_and_openers_are_not() {
        assert_body(
            |j| {
                j.begin_object();
                j.key("empty_object");
                j.begin_object();
                j.end_object();
                j.key("empty_array");
                j.begin_array();
                j.end_array();
                j.key("values");
                j.begin_array();
                j.quoted_u64(1);
                j.quoted_u64(2);
                j.bool(false);
                j.begin_object();
                j.key("nested");
                j.hex(&[0xab]);
                j.end_object();
                j.end_array();
                j.end_object();
            },
            "{\"empty_object\":{},\"empty_array\":[],\"values\":[\"1\",\"2\",false,{\"nested\":\"0xab\"}]}",
        );
    }

    #[test]
    fn body_appended_after_existing_bytes_gets_no_leading_comma() {
        let mut out = b"HTTP-ish prefix}".to_vec();
        let mut json = Json::new(&mut out);
        json.begin_object();
        json.key("epoch");
        json.quoted_u64(3);
        json.end_object();
        assert_eq!(String::from_utf8(out).unwrap(), "HTTP-ish prefix}{\"epoch\":\"3\"}");
    }

    #[test]
    fn data_column_sidecar_event_carries_the_root_index_slot_and_commitments() {
        let commitments =
            [[0x11; BYTES_PER_KZG_COMMITMENT], [0x22; BYTES_PER_KZG_COMMITMENT]].concat();
        let body = write(|json| {
            json.data_column_sidecar_event(&[0x9a; 32], 3, 10, Some(&commitments));
        });
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["block_root"], format!("0x{}", hex::encode([0x9a; 32])));
        assert_eq!(parsed["index"], "3");
        assert_eq!(parsed["slot"], "10");
        let expected = [format!("0x{}", "11".repeat(48)), format!("0x{}", "22".repeat(48))];
        assert_eq!(parsed["kzg_commitments"], serde_json::json!(expected));
    }

    #[test]
    fn column_event_without_commitments_omits_the_field() {
        let body = write(|json| json.data_column_sidecar_event(&[0x9a; 32], 3, 10, None));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["slot"], "10");
        assert!(parsed.get("kzg_commitments").is_none());
    }

    /// Lighthouse decodes the block body with `deny_unknown_fields`, so every
    /// container carries exactly its schema's fields. Values were checked
    /// against Lighthouse's own decoder on random blocks.
    #[test]
    fn pq_block_and_envelope_carry_exactly_the_schema_fields() {
        use silver_common::{
            ssz_view::SIGNED_PQ_FIXED,
            test_util::{SynthBid, SynthBlock, empty_signed_envelope_pq},
        };

        let signed = SynthBlock::pq(9, SynthBid::new(&[0x33; BYTES_PER_KZG_COMMITMENT]));
        let block = &signed.bytes()[SIGNED_PQ_FIXED..];
        let signed_envelope = empty_signed_envelope_pq(9, [3; 32]);
        let envelope = &signed_envelope[SIGNED_PQ_FIXED..];
        let payload = PayloadFrame {
            execution_payload: ExecutionPayloadEnvelopeView::payload(envelope),
            after_payload: &[],
            blob_count: 1,
            commitments: &[],
            execution_requests: ExecutionPayloadEnvelopeView::execution_requests(envelope),
            cell_proofs: &[0x44; 128 * BYTES_PER_KZG_PROOF],
            blobs: &[0x55; BYTES_PER_BLOB],
            should_override_builder: false,
            block_value: [0; 32],
        };
        let metadata = ProducedBlockMetadata {
            version: "pq",
            payload_included: true,
            execution_payload_value: "7".into(),
            consensus_block_value: "9".into(),
        };
        let body = write(|json| {
            json.produced_block(&metadata, |json| {
                json.pq_block_and_envelope(block, envelope[..80].try_into().unwrap(), &payload)
            })
        });
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let keys = |value: &serde_json::Value| -> Vec<String> {
            value.as_object().unwrap().keys().cloned().collect()
        };
        let sorted = |names: &[&str]| -> Vec<String> {
            let mut names: Vec<_> = names.iter().map(|name| name.to_string()).collect();
            names.sort();
            names
        };

        assert_eq!(
            keys(&parsed),
            sorted(&[
                "version",
                "consensus_block_value",
                "execution_payload_value",
                "execution_payload_included",
                "data",
            ])
        );
        let data = &parsed["data"];
        assert_eq!(
            keys(data),
            sorted(&["block", "execution_payload_envelope", "kzg_proofs", "blobs"])
        );
        assert_eq!(data["block"]["slot"], "9");
        assert_eq!(
            keys(&data["block"]["body"]),
            sorted(&[
                "randao_reveal",
                "eth1_data",
                "graffiti",
                "proposer_slashings",
                "attester_slashings",
                "attestations",
                "deposits",
                "signed_execution_payload_bid",
                "parent_execution_requests",
                "proof",
            ])
        );
        let bid = &data["block"]["body"]["signed_execution_payload_bid"]["message"];
        assert_eq!(bid["blob_kzg_commitments"][0], format!("0x{}", "33".repeat(48)));
        assert_eq!(data["block"]["body"]["randao_reveal"].as_array().unwrap().len(), 32);

        let envelope = &data["execution_payload_envelope"];
        let payload = &envelope["payload"];
        assert_eq!(payload["slot_number"], "9");
        assert_eq!(payload["base_fee_per_gas"], "0");
        assert_eq!(keys(payload).len(), 19);
        assert_eq!(keys(&envelope["execution_requests"]).len(), 8);
        assert_eq!(envelope["beacon_block_root"], format!("0x{}", "03".repeat(32)));
        assert_eq!(data["kzg_proofs"].as_array().unwrap().len(), 128);
        assert_eq!(data["blobs"][0], format!("0x{}", "55".repeat(BYTES_PER_BLOB)));
    }
}
