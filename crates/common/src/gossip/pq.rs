//! Structural validation shared by the gossip, RPC and local submission paths.
//! A successful decode still requires state-dependent consensus verification.
use super::GossipTopic;
use crate::{
    ForkName,
    ssz_view::{
        AttesterSlashingPqView, BeaconBlockBodyPqView, PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE,
        PROPOSER_SLASHING_PQ_SIZE, PayloadAttestationMessagePqView,
        SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, SINGLE_ATT_PQ_SIZE, SignedAggregateAndProofPqView,
        SignedBeaconBlockPqView, SignedExecutionPayloadBidPqView,
        SignedExecutionPayloadEnvelopePqView,
    },
};

impl GossipTopic {
    /// Check the SSZ framing and the block-body and parent-request count limits
    /// that apply before a PQ message is eligible for relay.
    pub fn check_pq_signed_message(self, bytes: &[u8]) -> Result<(), &'static str> {
        if !self.supports_format(ForkName::Pq) {
            return Err("topic unavailable on PQ");
        }
        let canonical = match self {
            Self::BeaconBlock => {
                if !SignedBeaconBlockPqView::check_size(bytes) {
                    return Err("invalid PQ signed block offsets");
                }
                let body = SignedBeaconBlockPqView::body(bytes);
                if !BeaconBlockBodyPqView::check_canonical(body) {
                    return Err("invalid PQ block body");
                }
                return BeaconBlockBodyPqView::check_operation_limits(body)
                    .map_err(|_| "PQ block operation count exceeds limit");
            }
            Self::BeaconAttestation(_) => bytes.len() == SINGLE_ATT_PQ_SIZE,
            Self::BeaconAggregateAndProof => SignedAggregateAndProofPqView::check_size(bytes),
            Self::AttesterSlashing => AttesterSlashingPqView::check_size(bytes),
            Self::ProposerSlashing => bytes.len() == PROPOSER_SLASHING_PQ_SIZE,
            Self::ExecutionPayloadBid => SignedExecutionPayloadBidPqView::check_canonical(bytes),
            Self::ExecutionPayload => SignedExecutionPayloadEnvelopePqView::check_canonical(bytes),
            Self::ProposerPreferences => bytes.len() == SIGNED_PROPOSER_PREFERENCES_PQ_SIZE,
            Self::PayloadAttestationMessage => {
                let message: &[u8; PAYLOAD_ATTESTATION_MESSAGE_PQ_SIZE] =
                    bytes.try_into().map_err(|_| "invalid PQ payload attestation size")?;
                let data = PayloadAttestationMessagePqView::data(message);
                data[40] <= 1 && data[41] <= 1
            }
            _ => return Err("expected a signed PQ gossip topic"),
        };
        canonical.then_some(()).ok_or("invalid PQ signed message")
    }
}
