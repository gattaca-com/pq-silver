"""
A PQ BeaconState from the consensus-specs pyspec, until consensus-spec-tests ship PQ.

Writes `state.ssz_snappy` (raw snappy) beside this file and prints the state root.
Every type comes from the `pq` pyspec build. Set up the venv as the docstring of
`crates/ssz/tests/fixtures/pq/gen_reference_vectors.py` describes, then from the repo root:

    PYTHONPATH=crates/ssz/tests/fixtures/pq venv/bin/python \
        crates/beacon_state/tile/tests/fixtures/pq/gen_reference_state.py
"""

import os

import cramjam
from eth_consensus_specs.pq import mainnet as spec
from gen_reference_vectors import b, execution_payload_bid, rng

N_VALIDATORS = 50
N_BUILDERS = 3


def small():
    return spec.Uint64(rng.randrange(1, 2**40))


def index(n):
    return spec.Uint64(rng.randrange(n))


def bits(length):
    return [bool(rng.getrandbits(1)) for _ in range(length)]


def sparse_roots(vector_type):
    """Mostly zero, so the fixture compresses; a few set entries pin positions."""
    length, root_type = vector_type.LENGTH, vector_type.ELEMENT_TYPE
    entries = [root_type() for _ in range(length)]
    for i in (0, 1, length // 2, length - 1):
        entries[i] = b(root_type)
    return vector_type(data=entries)


def eth1_data():
    return spec.Eth1Data(
        deposit_root=b(spec.Root), deposit_count=small(), block_hash=b(spec.Hash32)
    )


def builder_pending_withdrawal():
    return spec.BuilderPendingWithdrawal(
        fee_recipient=b(spec.ExecutionAddress), amount=small(), builder_index=index(N_BUILDERS)
    )


def validator():
    return spec.Validator(
        pubkey=b(spec.XMSSPubkey),
        vrf_root=b(spec.Root),
        withdrawal_credentials=b(spec.Bytes32),
        effective_balance=small(),
        slashed=spec.Boolean(rng.getrandbits(1)),
        activation_eligibility_epoch=small(),
        activation_epoch=small(),
        exit_epoch=small(),
        withdrawable_epoch=small(),
    )


def builder():
    return spec.Builder(
        pubkey=b(spec.XMSSPubkey),
        version=spec.Uint8(0),
        execution_address=b(spec.ExecutionAddress),
        balance=small(),
        deposit_epoch=small(),
        withdrawable_epoch=small(),
    )


def aggregation_committees():
    return spec.AggregationCommittees(
        data=[
            spec.AggregationCommittee(
                data=[index(N_VALIDATORS) for _ in range(rng.randrange(0, 4))]
            )
            for _ in range(rng.randrange(0, 3))
        ]
    )


def state():
    n = N_VALIDATORS
    slots_per_epoch = spec.SLOTS_PER_EPOCH
    return spec.BeaconState(
        genesis_time=small(),
        genesis_validators_root=b(spec.Root),
        slot=spec.Slot(10 * slots_per_epoch + 5),
        fork=spec.Fork(
            previous_version=spec.Version(bytes([0x07, 0, 0, 0])),
            current_version=spec.Version(bytes([0xE0, 0, 0, 0])),
            epoch=spec.Epoch(10),
        ),
        latest_block_header=spec.BeaconBlockHeader(
            slot=spec.Slot(10 * slots_per_epoch + 4),
            proposer_index=index(n),
            parent_root=b(spec.Root),
            state_root=b(spec.Root),
            body_root=b(spec.Root),
        ),
        block_roots=sparse_roots(spec.BlockRoots),
        state_roots=sparse_roots(spec.StateRoots),
        historical_roots=spec.HistoricalRoots(data=[b(spec.Root) for _ in range(2)]),
        eth1_data=eth1_data(),
        eth1_data_votes=spec.Eth1DataVotes(data=[eth1_data() for _ in range(3)]),
        eth1_deposit_index=small(),
        validators=spec.Validators(data=[validator() for _ in range(n)]),
        balances=spec.Balances(data=[small() for _ in range(n)]),
        randao_mixes=sparse_roots(spec.RandaoMixes),
        slashings=spec.Slashings(data=[spec.Gwei(0)] * (spec.Slashings.LENGTH - 1) + [small()]),
        previous_epoch_participation=spec.EpochParticipation(
            data=[spec.ParticipationFlags(rng.randrange(8)) for _ in range(n)]
        ),
        current_epoch_participation=spec.EpochParticipation(
            data=[spec.ParticipationFlags(rng.randrange(8)) for _ in range(n)]
        ),
        justification_bits=spec.JustificationBits(data=bits(spec.JustificationBits.LENGTH)),
        previous_justified_checkpoint=spec.Checkpoint(epoch=spec.Epoch(8), root=b(spec.Root)),
        current_justified_checkpoint=spec.Checkpoint(epoch=spec.Epoch(9), root=b(spec.Root)),
        finalized_checkpoint=spec.Checkpoint(epoch=spec.Epoch(7), root=b(spec.Root)),
        inactivity_scores=spec.InactivityScores(data=[small() for _ in range(n)]),
        latest_block_hash=b(spec.Hash32),
        next_withdrawal_index=small(),
        next_withdrawal_validator_index=index(n),
        historical_summaries=spec.HistoricalSummaries(
            data=[
                spec.HistoricalSummary(
                    block_summary_root=b(spec.Root), state_summary_root=b(spec.Root)
                )
                for _ in range(2)
            ]
        ),
        deposit_requests_start_index=small(),
        deposit_balance_to_consume=small(),
        exit_balance_to_consume=small(),
        earliest_exit_epoch=small(),
        consolidation_balance_to_consume=small(),
        earliest_consolidation_epoch=small(),
        pending_deposits=spec.PendingDeposits(
            data=[
                spec.PendingDeposit(
                    pubkey=spec.Bytes48(bytes(16) + b(spec.XMSSPubkey)),
                    withdrawal_credentials=b(spec.Bytes32),
                    amount=small(),
                    signature=spec.Bytes96(),
                    slot=small(),
                )
                for _ in range(2)
            ]
        ),
        pending_partial_withdrawals=spec.PendingPartialWithdrawals(
            data=[
                spec.PendingPartialWithdrawal(
                    validator_index=index(n), amount=small(), withdrawable_epoch=small()
                )
                for _ in range(2)
            ]
        ),
        pending_consolidations=spec.PendingConsolidations(
            data=[spec.PendingConsolidation(source_index=index(n), target_index=index(n))]
        ),
        proposer_lookahead=spec.ProposerLookahead(
            data=[index(n) for _ in range(spec.ProposerLookahead.LENGTH)]
        ),
        builders=spec.Builders(data=[builder() for _ in range(N_BUILDERS)]),
        next_withdrawal_builder_index=index(N_BUILDERS),
        execution_payload_availability=spec.ExecutionPayloadAvailability(
            data=bits(spec.ExecutionPayloadAvailability.LENGTH)
        ),
        builder_pending_payments=spec.BuilderPendingPayments(
            data=[
                spec.BuilderPendingPayment(
                    weight=small(), withdrawal=builder_pending_withdrawal(), proposer_index=index(n)
                )
                for _ in range(spec.BuilderPendingPayments.LENGTH)
            ]
        ),
        builder_pending_withdrawals=spec.BuilderPendingWithdrawals(
            data=[builder_pending_withdrawal()]
        ),
        latest_execution_payload_bid=execution_payload_bid(2, small, index(N_BUILDERS)),
        payload_expected_withdrawals=spec.Withdrawals(
            data=[
                spec.Withdrawal(
                    index=small(),
                    validator_index=index(n),
                    address=b(spec.ExecutionAddress),
                    amount=small(),
                )
                for _ in range(2)
            ]
        ),
        ptc_window=spec.PayloadTimelinessCommitteeWindow(
            data=[
                spec.PayloadTimelinessCommittee(
                    data=[index(n) for _ in range(spec.PayloadTimelinessCommittee.LENGTH)]
                )
                for _ in range(spec.PayloadTimelinessCommitteeWindow.LENGTH)
            ]
        ),
        validator_preregistrations=spec.ValidatorPreregistrations(
            data=[
                spec.ValidatorPreregistration(
                    pubkey=b(spec.XMSSPubkey),
                    withdrawal_credentials=b(spec.Bytes32),
                    vrf_root=b(spec.Root),
                    expiry_slot=small(),
                )
                for _ in range(3)
            ]
        ),
        builder_preregistrations=spec.BuilderPreregistrations(
            data=[
                spec.BuilderPreregistration(
                    pubkey=b(spec.XMSSPubkey),
                    withdrawal_credentials=b(spec.Bytes32),
                    expiry_slot=small(),
                )
                for _ in range(2)
            ]
        ),
        aggregation_committee_window=spec.AggregationCommitteeWindow(
            data=[aggregation_committees() for _ in range(spec.AggregationCommitteeWindow.LENGTH)]
        ),
    )


if __name__ == "__main__":
    value = state()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.ssz_snappy")
    with open(out, "wb") as f:
        f.write(bytes(cramjam.snappy.compress_raw(value.encode_bytes())))
    print(value.hash_tree_root().hex())
