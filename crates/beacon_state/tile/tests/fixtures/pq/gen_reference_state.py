"""
A PQ BeaconState from the spec's SSZ library, until consensus-spec-tests ship PQ.

Writes `state.ssz_snappy` (raw snappy) beside this file and prints the state root.
Needs `eth-ssz-specs==0.1.0` and `cramjam`, with the shared containers of
`crates/ssz/tests/fixtures/pq/gen_reference_vectors.py` importable.
"""

import os

import cramjam
from gen_reference_vectors import (
    BlobKzgCommitments,
    Bytes20,
    Bytes32,
    Bytes48,
    Bytes96,
    Checkpoint,
    Eth1Data,
    ExecutionPayloadBid,
    BeaconBlockHeader,
    b,
    rng,
    u64,
)
from ssz import (
    BitVector,
    Boolean,
    ByteVector,
    Container,
    List,
    ProgressiveContainer,
    ProgressiveList,
    Uint8,
    Uint64,
    Vector,
    active_fields,
    hash_tree_root,
)

SLOTS_PER_EPOCH = 32
N_VALIDATORS = 50
N_BUILDERS = 3
PTC_SIZE = 512


class Version(ByteVector):
    LENGTH = 4


class Fork(Container):
    previous_version: Version
    current_version: Version
    epoch: Uint64


class Roots8192(Vector[Bytes32]):
    LENGTH = 8192


class HistoricalRoots(List[Bytes32]):
    LIMIT = 2**24


class Eth1DataVotes(List[Eth1Data]):
    LIMIT = 64 * SLOTS_PER_EPOCH


class Validator(Container):
    pubkey: Bytes32
    vrf_root: Bytes32
    withdrawal_credentials: Bytes32
    effective_balance: Uint64
    slashed: Boolean
    activation_eligibility_epoch: Uint64
    activation_epoch: Uint64
    exit_epoch: Uint64
    withdrawable_epoch: Uint64


class Validators(ProgressiveList[Validator]):
    pass


class Balances(ProgressiveList[Uint64]):
    pass


class RandaoMixes(Vector[Bytes32]):
    LENGTH = 65536


class Slashings(Vector[Uint64]):
    LENGTH = 8192


class EpochParticipation(ProgressiveList[Uint8]):
    pass


class JustificationBits(BitVector):
    LENGTH = 4


class InactivityScores(ProgressiveList[Uint64]):
    pass


class HistoricalSummary(Container):
    block_summary_root: Bytes32
    state_summary_root: Bytes32


class HistoricalSummaries(List[HistoricalSummary]):
    LIMIT = 2**24


class PendingDeposit(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96
    slot: Uint64


class PendingDeposits(ProgressiveList[PendingDeposit]):
    pass


class PendingPartialWithdrawal(Container):
    validator_index: Uint64
    amount: Uint64
    withdrawable_epoch: Uint64


class PendingPartialWithdrawals(ProgressiveList[PendingPartialWithdrawal]):
    pass


class PendingConsolidation(Container):
    source_index: Uint64
    target_index: Uint64


class PendingConsolidations(ProgressiveList[PendingConsolidation]):
    pass


class ProposerLookahead(Vector[Uint64]):
    LENGTH = 2 * SLOTS_PER_EPOCH


class Builder(Container):
    pubkey: Bytes32
    version: Uint8
    execution_address: Bytes20
    balance: Uint64
    deposit_epoch: Uint64
    withdrawable_epoch: Uint64


class Builders(ProgressiveList[Builder]):
    pass


class ExecutionPayloadAvailability(BitVector):
    LENGTH = 8192


class BuilderPendingWithdrawal(Container):
    fee_recipient: Bytes20
    amount: Uint64
    builder_index: Uint64


class BuilderPendingPayment(Container):
    weight: Uint64
    withdrawal: BuilderPendingWithdrawal
    proposer_index: Uint64


class BuilderPendingPayments(Vector[BuilderPendingPayment]):
    LENGTH = 2 * SLOTS_PER_EPOCH


class BuilderPendingWithdrawals(ProgressiveList[BuilderPendingWithdrawal]):
    pass


class Withdrawal(Container):
    index: Uint64
    validator_index: Uint64
    address: Bytes20
    amount: Uint64


class Withdrawals(ProgressiveList[Withdrawal]):
    pass


class PayloadTimelinessCommittee(Vector[Uint64]):
    LENGTH = PTC_SIZE


class PayloadTimelinessCommitteeWindow(Vector[PayloadTimelinessCommittee]):
    LENGTH = 3 * SLOTS_PER_EPOCH


class ValidatorPreregistration(Container):
    pubkey: Bytes32
    withdrawal_credentials: Bytes32
    vrf_root: Bytes32
    expiry_slot: Uint64


class ValidatorPreregistrations(ProgressiveList[ValidatorPreregistration]):
    pass


class BuilderPreregistration(Container):
    pubkey: Bytes32
    withdrawal_credentials: Bytes32
    expiry_slot: Uint64


class BuilderPreregistrations(ProgressiveList[BuilderPreregistration]):
    pass


class BeaconState(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=50, gaps=(22, 23, 46, 47))

    genesis_time: Uint64
    genesis_validators_root: Bytes32
    slot: Uint64
    fork: Fork
    latest_block_header: BeaconBlockHeader
    block_roots: Roots8192
    state_roots: Roots8192
    historical_roots: HistoricalRoots
    eth1_data: Eth1Data
    eth1_data_votes: Eth1DataVotes
    eth1_deposit_index: Uint64
    validators: Validators
    balances: Balances
    randao_mixes: RandaoMixes
    slashings: Slashings
    previous_epoch_participation: EpochParticipation
    current_epoch_participation: EpochParticipation
    justification_bits: JustificationBits
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    inactivity_scores: InactivityScores
    latest_block_hash: Bytes32
    next_withdrawal_index: Uint64
    next_withdrawal_validator_index: Uint64
    historical_summaries: HistoricalSummaries
    deposit_requests_start_index: Uint64
    deposit_balance_to_consume: Uint64
    exit_balance_to_consume: Uint64
    earliest_exit_epoch: Uint64
    consolidation_balance_to_consume: Uint64
    earliest_consolidation_epoch: Uint64
    pending_deposits: PendingDeposits
    pending_partial_withdrawals: PendingPartialWithdrawals
    pending_consolidations: PendingConsolidations
    proposer_lookahead: ProposerLookahead
    builders: Builders
    next_withdrawal_builder_index: Uint64
    execution_payload_availability: ExecutionPayloadAvailability
    builder_pending_payments: BuilderPendingPayments
    builder_pending_withdrawals: BuilderPendingWithdrawals
    latest_execution_payload_bid: ExecutionPayloadBid
    payload_expected_withdrawals: Withdrawals
    ptc_window: PayloadTimelinessCommitteeWindow
    validator_preregistrations: ValidatorPreregistrations
    builder_preregistrations: BuilderPreregistrations


def small():
    return Uint64(rng.randrange(1, 2**40))


def sparse_roots(length, cls):
    """Mostly zero, so the fixture compresses; a few set entries pin positions."""
    roots = [Bytes32(bytes(32)) for _ in range(length)]
    for i in (0, 1, length // 2, length - 1):
        roots[i] = b(Bytes32)
    return cls(data=roots)


def index(n):
    return Uint64(rng.randrange(n))


def bits(length):
    return [bool(rng.getrandbits(1)) for _ in range(length)]


def state():
    n = N_VALIDATORS
    return BeaconState(
        genesis_time=small(),
        genesis_validators_root=b(Bytes32),
        slot=Uint64(10 * SLOTS_PER_EPOCH + 5),
        fork=Fork(
            previous_version=Version(bytes([0x07, 0, 0, 0])),
            current_version=Version(bytes([0xE0, 0, 0, 0])),
            epoch=Uint64(10),
        ),
        latest_block_header=BeaconBlockHeader(
            slot=Uint64(10 * SLOTS_PER_EPOCH + 4),
            proposer_index=index(n),
            parent_root=b(Bytes32),
            state_root=b(Bytes32),
            body_root=b(Bytes32),
        ),
        block_roots=sparse_roots(8192, Roots8192),
        state_roots=sparse_roots(8192, Roots8192),
        historical_roots=HistoricalRoots(data=[b(Bytes32) for _ in range(2)]),
        eth1_data=Eth1Data(deposit_root=b(Bytes32), deposit_count=small(), block_hash=b(Bytes32)),
        eth1_data_votes=Eth1DataVotes(
            data=[
                Eth1Data(deposit_root=b(Bytes32), deposit_count=small(), block_hash=b(Bytes32))
                for _ in range(3)
            ]
        ),
        eth1_deposit_index=small(),
        validators=Validators(
            data=[
                Validator(
                    pubkey=b(Bytes32),
                    vrf_root=b(Bytes32),
                    withdrawal_credentials=b(Bytes32),
                    effective_balance=small(),
                    slashed=Boolean(rng.getrandbits(1)),
                    activation_eligibility_epoch=small(),
                    activation_epoch=small(),
                    exit_epoch=small(),
                    withdrawable_epoch=small(),
                )
                for _ in range(n)
            ]
        ),
        balances=Balances(data=[small() for _ in range(n)]),
        randao_mixes=sparse_roots(65536, RandaoMixes),
        slashings=Slashings(data=[Uint64(0)] * 8191 + [small()]),
        previous_epoch_participation=EpochParticipation(
            data=[Uint8(rng.randrange(8)) for _ in range(n)]
        ),
        current_epoch_participation=EpochParticipation(
            data=[Uint8(rng.randrange(8)) for _ in range(n)]
        ),
        justification_bits=JustificationBits(data=bits(4)),
        previous_justified_checkpoint=Checkpoint(epoch=Uint64(8), root=b(Bytes32)),
        current_justified_checkpoint=Checkpoint(epoch=Uint64(9), root=b(Bytes32)),
        finalized_checkpoint=Checkpoint(epoch=Uint64(7), root=b(Bytes32)),
        inactivity_scores=InactivityScores(data=[small() for _ in range(n)]),
        latest_block_hash=b(Bytes32),
        next_withdrawal_index=small(),
        next_withdrawal_validator_index=index(n),
        historical_summaries=HistoricalSummaries(
            data=[
                HistoricalSummary(block_summary_root=b(Bytes32), state_summary_root=b(Bytes32))
                for _ in range(2)
            ]
        ),
        deposit_requests_start_index=small(),
        deposit_balance_to_consume=small(),
        exit_balance_to_consume=small(),
        earliest_exit_epoch=small(),
        consolidation_balance_to_consume=small(),
        earliest_consolidation_epoch=small(),
        pending_deposits=PendingDeposits(
            data=[
                PendingDeposit(
                    pubkey=Bytes48(bytes(16) + b(Bytes32)),
                    withdrawal_credentials=b(Bytes32),
                    amount=small(),
                    signature=Bytes96(bytes(96)),
                    slot=small(),
                )
                for _ in range(2)
            ]
        ),
        pending_partial_withdrawals=PendingPartialWithdrawals(
            data=[
                PendingPartialWithdrawal(
                    validator_index=index(n), amount=small(), withdrawable_epoch=small()
                )
                for _ in range(2)
            ]
        ),
        pending_consolidations=PendingConsolidations(
            data=[PendingConsolidation(source_index=index(n), target_index=index(n))]
        ),
        proposer_lookahead=ProposerLookahead(data=[index(n) for _ in range(2 * SLOTS_PER_EPOCH)]),
        builders=Builders(
            data=[
                Builder(
                    pubkey=b(Bytes32),
                    version=Uint8(0),
                    execution_address=b(Bytes20),
                    balance=small(),
                    deposit_epoch=small(),
                    withdrawable_epoch=small(),
                )
                for _ in range(N_BUILDERS)
            ]
        ),
        next_withdrawal_builder_index=index(N_BUILDERS),
        execution_payload_availability=ExecutionPayloadAvailability(data=bits(8192)),
        builder_pending_payments=BuilderPendingPayments(
            data=[
                BuilderPendingPayment(
                    weight=small(),
                    withdrawal=BuilderPendingWithdrawal(
                        fee_recipient=b(Bytes20), amount=small(), builder_index=index(N_BUILDERS)
                    ),
                    proposer_index=index(n),
                )
                for _ in range(2 * SLOTS_PER_EPOCH)
            ]
        ),
        builder_pending_withdrawals=BuilderPendingWithdrawals(
            data=[
                BuilderPendingWithdrawal(
                    fee_recipient=b(Bytes20), amount=small(), builder_index=index(N_BUILDERS)
                )
            ]
        ),
        latest_execution_payload_bid=ExecutionPayloadBid(
            parent_block_hash=b(Bytes32),
            parent_block_root=b(Bytes32),
            block_hash=b(Bytes32),
            prev_randao=b(Bytes32),
            fee_recipient=b(Bytes20),
            gas_limit=small(),
            builder_index=index(N_BUILDERS),
            slot=small(),
            value=small(),
            execution_payment=small(),
            blob_kzg_commitments=BlobKzgCommitments(data=[b(Bytes48) for _ in range(2)]),
            execution_requests_root=b(Bytes32),
        ),
        payload_expected_withdrawals=Withdrawals(
            data=[
                Withdrawal(
                    index=small(), validator_index=index(n), address=b(Bytes20), amount=small()
                )
                for _ in range(2)
            ]
        ),
        ptc_window=PayloadTimelinessCommitteeWindow(
            data=[
                PayloadTimelinessCommittee(data=[index(n) for _ in range(PTC_SIZE)])
                for _ in range(3 * SLOTS_PER_EPOCH)
            ]
        ),
        validator_preregistrations=ValidatorPreregistrations(
            data=[
                ValidatorPreregistration(
                    pubkey=b(Bytes32),
                    withdrawal_credentials=b(Bytes32),
                    vrf_root=b(Bytes32),
                    expiry_slot=small(),
                )
                for _ in range(3)
            ]
        ),
        builder_preregistrations=BuilderPreregistrations(
            data=[
                BuilderPreregistration(
                    pubkey=b(Bytes32), withdrawal_credentials=b(Bytes32), expiry_slot=small()
                )
                for _ in range(2)
            ]
        ),
    )


if __name__ == "__main__":
    value = state()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.ssz_snappy")
    with open(out, "wb") as f:
        f.write(bytes(cramjam.snappy.compress_raw(value.encode_bytes())))
    print(bytes(hash_tree_root(value)).hex())
