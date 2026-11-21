//! Envelope verification minus the EL call — the engine verdict arrives
//! asynchronously, not inline.

use flux_profiler::timed;
use silver_beacon_state_data::{
    BUILDER_INDEX_SELF_BUILD, SpecConfig, StateReadView, Version,
    bls::{self, DOMAIN_BEACON_BUILDER},
    pq::xmss_pubkey,
    xmss::SignatureCheck,
};
use silver_common::{
    SignedBlockLayout,
    ssz_view::{
        EXECUTION_PAYLOAD_FIXED_GLOAS, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        MAX_WITHDRAWALS_PER_PAYLOAD, SignedExecutionPayloadEnvelopePqView,
        SignedExecutionPayloadEnvelopeView, WITHDRAWAL_SIZE, WithdrawalView,
    },
};

use super::parent_payload::RequestsLayout;
use crate::error::EnvelopeError as E;

/// `layout` is the envelope's block's: it sets the signature scheme and the
/// execution requests type. `verify_xmss` is false only where XMSS is stubbed.
pub fn verify_execution_payload_envelope(
    rv: &StateReadView,
    cfg: &SpecConfig,
    layout: SignedBlockLayout,
    signed: &[u8],
    verify_xmss: bool,
) -> Result<(), E> {
    if envelope_layout(signed) != Some(layout) {
        return Err(E::Malformed);
    }
    let is_pq = layout == SignedBlockLayout::Pq;
    let envelope = layout.envelope_message(signed).ok_or(E::Malformed)?;
    let payload = ExecutionPayloadEnvelopeView::payload(envelope);
    let (wd_off, bal_off) = withdrawal_bounds(payload)?;

    let state = rv.slot.state();

    // beacon_block_root == the block this state belongs to: the caller found
    // `rv` by looking the root up in fork choice.
    if *ExecutionPayloadEnvelopeView::parent_beacon_block_root(envelope) !=
        state.latest_block_header.parent_root
    {
        return Err(E::PayloadMismatch { field: "parent_beacon_block_root" });
    }

    let bid = &state.latest_execution_payload_bid;
    let builder_index = ExecutionPayloadEnvelopeView::builder_index(envelope);
    if builder_index != bid.builder_index {
        return Err(E::BidMismatch { field: "builder_index" });
    }
    if *ExecutionPayloadView::prev_randao(payload) != bid.prev_randao {
        return Err(E::BidMismatch { field: "prev_randao" });
    }
    if ExecutionPayloadView::gas_limit(payload) != bid.gas_limit {
        return Err(E::BidMismatch { field: "gas_limit" });
    }
    if *ExecutionPayloadView::block_hash(payload) != bid.block_hash {
        return Err(E::BidMismatch { field: "block_hash" });
    }
    let requests = ExecutionPayloadEnvelopeView::execution_requests(envelope);
    let requests_layout = RequestsLayout::for_fork(is_pq);
    if requests_layout.hash_tree_root(requests) != bid.execution_requests_root {
        return Err(E::BidMismatch { field: "execution_requests_root" });
    }
    requests_layout.check_counts(requests)?;

    if ExecutionPayloadView::slot_number(payload) != state.slot {
        return Err(E::PayloadMismatch { field: "slot_number" });
    }
    if *ExecutionPayloadView::parent_hash(payload) != state.latest_block_hash {
        return Err(E::PayloadMismatch { field: "parent_hash" });
    }
    let expected_timestamp = rv.imm.genesis_time + state.slot * cfg.seconds_per_slot();
    if ExecutionPayloadView::timestamp(payload) != expected_timestamp {
        return Err(E::PayloadMismatch { field: "timestamp" });
    }

    let count = (bal_off - wd_off) / WITHDRAWAL_SIZE;
    if count > MAX_WITHDRAWALS_PER_PAYLOAD {
        return Err(E::TooManyWithdrawals { count, max: MAX_WITHDRAWALS_PER_PAYLOAD });
    }

    if is_pq && !verify_xmss {
        return Ok(());
    }
    let fork_version = rv.epoch.fork_version_at(rv.slot.current_epoch());
    let proposer_index = Some(state.latest_block_header.proposer_index);
    verify_envelope_signature(rv, layout, signed, fork_version, proposer_index)
}

/// The layout `signed` is a canonical envelope of. The first offset tells the
/// signature schemes apart.
pub fn envelope_layout(signed: &[u8]) -> Option<SignedBlockLayout> {
    if SignedExecutionPayloadEnvelopePqView::check_canonical(signed) {
        return Some(SignedBlockLayout::Pq);
    }
    SignedExecutionPayloadEnvelopeView::check_canonical(signed).then_some(SignedBlockLayout::Gloas)
}

/// The message of an envelope `verify_execution_payload_envelope` accepted.
/// The first offset tells the signature schemes apart.
fn verified_message(signed: &[u8]) -> &[u8] {
    if SignedExecutionPayloadEnvelopePqView::check_size(signed) {
        SignedExecutionPayloadEnvelopePqView::message(signed)
    } else {
        SignedExecutionPayloadEnvelopeView::message(signed)
    }
}

/// Only for an envelope `verify_execution_payload_envelope` accepted, which
/// bounds and roots its requests.
pub(crate) fn envelope_execution_requests(signed: &[u8]) -> (&[u8], RequestsLayout) {
    let is_pq = SignedExecutionPayloadEnvelopePqView::check_size(signed);
    let requests = ExecutionPayloadEnvelopeView::execution_requests(verified_message(signed));
    (requests, RequestsLayout::for_fork(is_pq))
}

/// `process_execution_payload`'s `payload.withdrawals ==
/// state.payload_expected_withdrawals`: a gossip-valid envelope that fails it
/// is relayed but never becomes this node's verified payload.
pub fn envelope_withdrawals_match_expected(rv: &StateReadView, signed: &[u8]) -> bool {
    let payload = ExecutionPayloadEnvelopeView::payload(verified_message(signed));
    payload_withdrawals_match_expected(rv, payload)
}

pub(crate) fn payload_withdrawals_match_expected(rv: &StateReadView, payload: &[u8]) -> bool {
    let Ok((wd_off, bal_off)) = withdrawal_bounds(payload) else { return false };
    let withdrawals = &payload[wd_off..bal_off];
    let expected = &rv.slot.state().payload_expected_withdrawals;
    withdrawals.len() == expected.len() * WITHDRAWAL_SIZE &&
        withdrawals.chunks_exact(WITHDRAWAL_SIZE).zip(expected.iter()).all(|(w, e)| {
            let w: &[u8; WITHDRAWAL_SIZE] = w.try_into().unwrap();
            WithdrawalView::index(w) == e.index &&
                WithdrawalView::validator_index(w) == e.validator_index &&
                *WithdrawalView::address(w) == e.address &&
                WithdrawalView::amount(w) == e.amount
        })
}

fn withdrawal_bounds(payload: &[u8]) -> Result<(usize, usize), E> {
    if payload.len() < EXECUTION_PAYLOAD_FIXED_GLOAS {
        return Err(E::Malformed);
    }
    let wd_off = ExecutionPayloadView::withdrawals_offset(payload) as usize;
    let bal_off = ExecutionPayloadView::block_access_list_offset(payload) as usize;
    if wd_off < EXECUTION_PAYLOAD_FIXED_GLOAS || bal_off < wd_off || payload.len() < bal_off {
        return Err(E::Malformed);
    }
    Ok((wd_off, bal_off))
}

/// An envelope checked before its block is known reads `rv` from the block's
/// parent, so the caller names the self-build proposer from its lookahead.
#[timed]
pub fn verify_envelope_signature(
    rv: &StateReadView,
    layout: SignedBlockLayout,
    signed: &[u8],
    fork_version: Version,
    proposer_index: Option<u64>,
) -> Result<(), E> {
    let envelope = layout.envelope_message(signed).ok_or(E::Malformed)?;
    let builder_index = ExecutionPayloadEnvelopeView::builder_index(envelope);
    let out_of_range = || E::BuilderOutOfRange { index: builder_index };
    let self_built = builder_index == BUILDER_INDEX_SELF_BUILD;
    let proposer = proposer_index
        .map(|index| index as usize)
        .filter(|&index| index < rv.validators.count())
        .ok_or_else(out_of_range);
    let builder = || rv.builders.get(builder_index as usize).ok_or_else(out_of_range);
    let domain =
        bls::compute_domain(DOMAIN_BEACON_BUILDER, fork_version, &rv.imm.genesis_validators_root);

    let valid = if layout == SignedBlockLayout::Pq {
        let pubkey = if self_built {
            *rv.validator_xmss_pubkey(proposer?).ok_or_else(out_of_range)?
        } else {
            *xmss_pubkey(&builder()?.pubkey)
        };
        let slot =
            ExecutionPayloadView::slot_number(ExecutionPayloadEnvelopeView::payload(envelope));
        SignatureCheck::execution_payload_envelope(signed, slot, &pubkey, &domain)
            .is_some_and(|check| check.verify())
    } else {
        let message_root = ExecutionPayloadEnvelopeView::hash_tree_root(envelope);
        let signing_root = bls::compute_signing_root(&message_root, &domain);
        let sig = SignedExecutionPayloadEnvelopeView::signature(signed);
        if self_built {
            bls::verify_one(rv.validators.pubkey_decompressed(proposer?), sig, &signing_root)
        } else {
            bls::verify_one_compressed(&builder()?.pubkey, sig, &signing_root)
        }
    };
    if !valid {
        return Err(E::BadSignature);
    }
    Ok(())
}
