use crate::{
    beacon::{
        block_submission::{post_blinded_block_v2, post_block_v2},
        blocks::{block, block_header, block_root, head_headers},
        builders::post_state_builders,
        committees::get_epoch_committees,
        operations::{post_attestations, post_attester_slashing, post_proposer_slashing},
        payload_attestations::post_payload_attestation_messages,
        payload_submission::post_payload_envelope,
        pools::{get_attester_slashings, get_proposer_slashings},
        proposer_preferences::get_proposer_preferences,
        states::{genesis, state_finality_checkpoints, state_fork},
        validators::{
            get_state_validator_balances, get_state_validators, post_state_validator_balances,
            post_state_validators, state_validator,
        },
    },
    config::{deposit_contract, fork_schedule, spec},
    events::events,
    http::router::{Handler, Method},
    node::{
        identity::identity,
        peers::{peer_count, peers},
        status::{health, syncing, version},
    },
    validator::{
        aggregate_attestation::aggregate_attestation,
        aggregate_submission::post_aggregate_and_proofs,
        attestation_data::attestation_data,
        attester_duties::post_attester_duties,
        builder_preferences::post_builder_preferences,
        execution_payload_envelope::execution_payload_envelope,
        liveness::post_liveness,
        payload_attestation_data::payload_attestation_data,
        produce_block::produce_block_v4,
        proposer_duties::{proposer_duties, proposer_duties_v2},
        proposer_preferences::post_proposer_preferences,
        ptc_duties::post_ptc_duties,
        registration::{post_prepare_beacon_proposer, post_register_validator},
        subnet_subscriptions::post_beacon_committee_subscriptions,
    },
};

/// What a node answers before it follows the chain: its own status, the
/// chain's configuration, and event streams.
pub(crate) const SERVED_WHILE_SYNCING: &[&str] = &[
    "/eth/v1/beacon/genesis",
    "/eth/v1/config/deposit_contract",
    "/eth/v1/config/fork_schedule",
    "/eth/v1/config/spec",
    "/eth/v1/events",
    "/eth/v1/node/health",
    "/eth/v1/node/identity",
    "/eth/v1/node/peer_count",
    "/eth/v1/node/peers",
    "/eth/v1/node/syncing",
    "/eth/v1/node/version",
];

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Post, "/eth/v1/beacon/execution_payload_envelopes", post_payload_envelope),
    (Method::Get, "/eth/v1/beacon/blocks/{block_id}/root", block_root),
    (Method::Get, "/eth/v1/beacon/genesis", genesis),
    (Method::Get, "/eth/v1/beacon/headers", head_headers),
    (Method::Get, "/eth/v1/beacon/headers/{block_id}", block_header),
    (Method::Post, "/eth/v1/beacon/pool/payload_attestations", post_payload_attestation_messages),
    (Method::Get, "/eth/v1/beacon/pool/proposer_slashings", get_proposer_slashings),
    (Method::Post, "/eth/v1/beacon/pool/proposer_slashings", post_proposer_slashing),
    (Method::Get, "/eth/v1/beacon/proposer_preferences", get_proposer_preferences),
    (Method::Post, "/eth/v1/beacon/states/{state_id}/builders", post_state_builders),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/committees", get_epoch_committees),
    (
        Method::Get,
        "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
        state_finality_checkpoints,
    ),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/fork", state_fork),
    (
        Method::Get,
        "/eth/v1/beacon/states/{state_id}/validator_balances",
        get_state_validator_balances,
    ),
    (
        Method::Post,
        "/eth/v1/beacon/states/{state_id}/validator_balances",
        post_state_validator_balances,
    ),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators", get_state_validators),
    (Method::Post, "/eth/v1/beacon/states/{state_id}/validators", post_state_validators),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators/{validator_id}", state_validator),
    (Method::Get, "/eth/v1/config/deposit_contract", deposit_contract),
    (Method::Get, "/eth/v1/config/fork_schedule", fork_schedule),
    (Method::Get, "/eth/v1/config/spec", spec),
    (Method::Get, "/eth/v1/events", events),
    (Method::Get, "/eth/v1/node/health", health),
    (Method::Get, "/eth/v1/node/identity", identity),
    (Method::Get, "/eth/v1/node/peer_count", peer_count),
    (Method::Get, "/eth/v1/node/peers", peers),
    (Method::Get, "/eth/v1/node/syncing", syncing),
    (Method::Get, "/eth/v1/node/version", version),
    (Method::Get, "/eth/v1/validator/attestation_data", attestation_data),
    (
        Method::Post,
        "/eth/v1/validator/beacon_committee_subscriptions",
        post_beacon_committee_subscriptions,
    ),
    (Method::Post, "/eth/v1/validator/builder_preferences", post_builder_preferences),
    (Method::Post, "/eth/v1/validator/duties/attester/{epoch}", post_attester_duties),
    (Method::Get, "/eth/v1/validator/duties/proposer/{epoch}", proposer_duties),
    (Method::Post, "/eth/v1/validator/duties/ptc/{epoch}", post_ptc_duties),
    (Method::Post, "/eth/v1/validator/liveness/{epoch}", post_liveness),
    (Method::Get, "/eth/v1/validator/payload_attestation_data", payload_attestation_data),
    (Method::Post, "/eth/v1/validator/prepare_beacon_proposer", post_prepare_beacon_proposer),
    (Method::Post, "/eth/v1/validator/proposer_preferences", post_proposer_preferences),
    (Method::Post, "/eth/v1/validator/register_validator", post_register_validator),
    (Method::Get, "/eth/v2/beacon/blocks/{block_id}", block),
    (Method::Post, "/eth/v2/beacon/blinded_blocks", post_blinded_block_v2),
    (Method::Post, "/eth/v2/beacon/blocks", post_block_v2),
    (Method::Post, "/eth/v2/beacon/pool/attestations", post_attestations),
    (Method::Get, "/eth/v2/beacon/pool/attester_slashings", get_attester_slashings),
    (Method::Post, "/eth/v2/beacon/pool/attester_slashings", post_attester_slashing),
    (Method::Post, "/eth/v2/validator/aggregate_and_proofs", post_aggregate_and_proofs),
    (Method::Get, "/eth/v2/validator/aggregate_attestation", aggregate_attestation),
    (Method::Get, "/eth/v2/validator/duties/proposer/{epoch}", proposer_duties_v2),
    (Method::Post, "/eth/v4/validator/blocks/{slot}", produce_block_v4),
    (
        Method::Get,
        "/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}",
        execution_payload_envelope,
    ),
];

#[cfg(test)]
mod tests {
    use super::{ROUTES, SERVED_WHILE_SYNCING};
    use crate::{
        ctx::anchor_ctx,
        http::router::Method,
        testing::{answer, dispatch, posting, request},
    };

    fn concrete(pattern: &str) -> String {
        let root = format!("0x{}", "00".repeat(32));
        pattern
            .replace("{state_id}", "head")
            .replace("{block_id}", "head")
            .replace("{validator_id}", "0")
            .replace("{epoch}", "0")
            .replace("{slot}", "1")
            .replace("{beacon_block_root}", &root)
    }

    #[test]
    fn every_other_route_is_503_until_the_node_follows() {
        let mut ctx = anchor_ctx();
        ctx.node_status.target = None;
        let mut answered = Vec::new();
        for &(method, pattern, _) in ROUTES {
            if SERVED_WHILE_SYNCING.contains(&pattern) {
                continue;
            }
            let path = concrete(pattern);
            let req = match method {
                Method::Get => request("GET", &path),
                Method::Post => posting(&path, "[]"),
            };
            let (_, out) = dispatch(&ctx, &req);
            let status = std::str::from_utf8(&out).unwrap().lines().next().unwrap_or("").to_owned();
            if status != "HTTP/1.1 503 Service Unavailable" {
                answered.push(format!("{pattern}: {status}"));
            }
        }
        assert!(answered.is_empty(), "{answered:#?}");
    }

    #[test]
    fn metrics_is_on_a_separate_listener() {
        let resp = answer(&anchor_ctx(), &request("GET", "/metrics"));
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 404"));
    }
}
