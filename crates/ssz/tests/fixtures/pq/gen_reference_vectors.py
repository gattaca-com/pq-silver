"""
PQ reference vectors from the spec's SSZ library, until consensus-spec-tests ship PQ.

One `<type> <serialized_hex> <root_hex>` line per case. Containers follow the `pq` branch of
consensus-specs. Regenerate with `eth-ssz-specs==0.1.0` installed:

    python3 gen_reference_vectors.py 1 > reference_vectors.txt
"""

import random
import sys

from ssz import (
    BitVector,
    ByteList,
    ByteVector,
    Container,
    List,
    ProgressiveBitList,
    ProgressiveContainer,
    ProgressiveList,
    Uint64,
    Vector,
    active_fields,
    hash_tree_root,
)


class Bytes20(ByteVector):
    LENGTH = 20


class Bytes32(ByteVector):
    LENGTH = 32


class Bytes48(ByteVector):
    LENGTH = 48


class Bytes96(ByteVector):
    LENGTH = 96


class XMSSSignature(ByteVector):
    LENGTH = 2404


class VRFProof(Vector[Bytes32]):
    LENGTH = 32


class AttestationProof(ByteList):
    LIMIT = 2**20


class Checkpoint(Container):
    epoch: Uint64
    root: Bytes32


class AttestationData(Container):
    slot: Uint64
    index: Uint64
    beacon_block_root: Bytes32
    source: Checkpoint
    target: Checkpoint


class AggregationBits(ProgressiveBitList):
    pass


class CommitteeBits(BitVector):
    LENGTH = 64


class Attestation(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=4, gaps=(2,))
    aggregation_bits: AggregationBits
    data: AttestationData
    committee_bits: CommitteeBits


class AttestingIndices(ProgressiveList[Uint64]):
    pass


class IndexedAttestation(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=3)
    attesting_indices: AttestingIndices
    data: AttestationData
    proof: AttestationProof


class AttesterSlashing(Container):
    attestation_1: IndexedAttestation
    attestation_2: IndexedAttestation


class AggregateAndProof(Container):
    aggregator_index: Uint64
    aggregate: Attestation
    selection_proof: VRFProof
    proof: AttestationProof


class BeaconBlockHeader(Container):
    slot: Uint64
    proposer_index: Uint64
    parent_root: Bytes32
    state_root: Bytes32
    body_root: Bytes32


class SignedBeaconBlockHeader(Container):
    message: BeaconBlockHeader
    signature: XMSSSignature


class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader


class Eth1Data(Container):
    deposit_root: Bytes32
    deposit_count: Uint64
    block_hash: Bytes32


class DepositProof(Vector[Bytes32]):
    LENGTH = 33


class DepositData(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96


class Deposit(Container):
    proof: DepositProof
    data: DepositData


class BlobKzgCommitments(ProgressiveList[Bytes48]):
    pass


class ExecutionPayloadBid(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=12)
    parent_block_hash: Bytes32
    parent_block_root: Bytes32
    block_hash: Bytes32
    prev_randao: Bytes32
    fee_recipient: Bytes20
    gas_limit: Uint64
    builder_index: Uint64
    slot: Uint64
    value: Uint64
    execution_payment: Uint64
    blob_kzg_commitments: BlobKzgCommitments
    execution_requests_root: Bytes32


class SignedExecutionPayloadBid(Container):
    message: ExecutionPayloadBid
    signature: XMSSSignature


class DepositRequest(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96
    index: Uint64


class WithdrawalRequest(Container):
    source_address: Bytes20
    validator_pubkey: Bytes48
    amount: Uint64


class ConsolidationRequest(Container):
    source_address: Bytes20
    source_pubkey: Bytes48
    target_pubkey: Bytes48


class BuilderDepositRequest(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96


class BuilderExitRequest(Container):
    source_address: Bytes20
    pubkey: Bytes48


class ValidatorPreregistrationRequest(Container):
    pubkey: Bytes32
    withdrawal_credentials: Bytes32
    vrf_root: Bytes32


class BuilderPreregistrationRequest(Container):
    pubkey: Bytes32
    withdrawal_credentials: Bytes32


class VoluntaryExitRequest(Container):
    pubkey: Bytes32


class DepositRequests(ProgressiveList[DepositRequest]):
    pass


class WithdrawalRequests(ProgressiveList[WithdrawalRequest]):
    pass


class ConsolidationRequests(ProgressiveList[ConsolidationRequest]):
    pass


class BuilderDepositRequests(ProgressiveList[BuilderDepositRequest]):
    pass


class BuilderExitRequests(ProgressiveList[BuilderExitRequest]):
    pass


class ValidatorPreregistrationRequests(ProgressiveList[ValidatorPreregistrationRequest]):
    pass


class BuilderPreregistrationRequests(ProgressiveList[BuilderPreregistrationRequest]):
    pass


class VoluntaryExitRequests(ProgressiveList[VoluntaryExitRequest]):
    pass


class ExecutionRequests(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=10, gaps=(5, 6))
    deposits: DepositRequests
    withdrawals: WithdrawalRequests
    consolidations: ConsolidationRequests
    builder_deposits: BuilderDepositRequests
    builder_exits: BuilderExitRequests
    validator_preregistrations: ValidatorPreregistrationRequests
    builder_preregistrations: BuilderPreregistrationRequests
    voluntary_exits: VoluntaryExitRequests


class ProposerSlashings(ProgressiveList[ProposerSlashing]):
    pass


class AttesterSlashings(ProgressiveList[AttesterSlashing]):
    pass


class Attestations(ProgressiveList[Attestation]):
    pass


class Deposits(ProgressiveList[Deposit]):
    pass


class BeaconBlockBody(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(width=14, gaps=(7, 8, 9, 11))
    randao_reveal: VRFProof
    eth1_data: Eth1Data
    graffiti: Bytes32
    proposer_slashings: ProposerSlashings
    attester_slashings: AttesterSlashings
    attestations: Attestations
    deposits: Deposits
    signed_execution_payload_bid: SignedExecutionPayloadBid
    parent_execution_requests: ExecutionRequests
    proof: AttestationProof


rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 0)


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def u64():
    return Uint64(rng.getrandbits(64))


def b(cls):
    return cls(rbytes(cls.LENGTH))


def checkpoint():
    return Checkpoint(epoch=u64(), root=b(Bytes32))


def attestation_data():
    return AttestationData(
        slot=u64(), index=u64(), beacon_block_root=b(Bytes32), source=checkpoint(), target=checkpoint()
    )


def proof(max_len):
    return AttestationProof(data=rbytes(rng.randrange(max_len + 1)))


def attestation():
    bits = [bool(rng.getrandbits(1)) for _ in range(rng.randrange(0, 300))]
    return Attestation(
        aggregation_bits=AggregationBits(data=bits),
        data=attestation_data(),
        committee_bits=CommitteeBits(data=[bool(rng.getrandbits(1)) for _ in range(64)]),
    )


def indexed_attestation():
    return IndexedAttestation(
        attesting_indices=AttestingIndices(data=[u64() for _ in range(rng.randrange(0, 40))]),
        data=attestation_data(),
        proof=proof(3000),
    )


def attester_slashing():
    return AttesterSlashing(attestation_1=indexed_attestation(), attestation_2=indexed_attestation())


def vrf_proof():
    return VRFProof(data=[b(Bytes32) for _ in range(32)])


def aggregate_and_proof():
    return AggregateAndProof(
        aggregator_index=u64(), aggregate=attestation(), selection_proof=vrf_proof(), proof=proof(5000)
    )


def signed_header():
    return SignedBeaconBlockHeader(
        message=BeaconBlockHeader(
            slot=u64(),
            proposer_index=u64(),
            parent_root=b(Bytes32),
            state_root=b(Bytes32),
            body_root=b(Bytes32),
        ),
        signature=b(XMSSSignature),
    )


def proposer_slashing():
    return ProposerSlashing(signed_header_1=signed_header(), signed_header_2=signed_header())


def signed_bid():
    return SignedExecutionPayloadBid(
        message=ExecutionPayloadBid(
            parent_block_hash=b(Bytes32),
            parent_block_root=b(Bytes32),
            block_hash=b(Bytes32),
            prev_randao=b(Bytes32),
            fee_recipient=b(Bytes20),
            gas_limit=u64(),
            builder_index=u64(),
            slot=u64(),
            value=u64(),
            execution_payment=u64(),
            blob_kzg_commitments=BlobKzgCommitments(data=[b(Bytes48) for _ in range(rng.randrange(0, 7))]),
            execution_requests_root=b(Bytes32),
        ),
        signature=b(XMSSSignature),
    )


def n(k):
    return rng.randrange(0, k + 1)


def execution_requests():
    return ExecutionRequests(
        deposits=DepositRequests(data=
            [
                DepositRequest(
                    pubkey=b(Bytes48),
                    withdrawal_credentials=b(Bytes32),
                    amount=u64(),
                    signature=b(Bytes96),
                    index=u64(),
                )
                for _ in range(n(5))
            ]
        ),
        withdrawals=WithdrawalRequests(data=
            [
                WithdrawalRequest(source_address=b(Bytes20), validator_pubkey=b(Bytes48), amount=u64())
                for _ in range(n(3))
            ]
        ),
        consolidations=ConsolidationRequests(data=
            [
                ConsolidationRequest(
                    source_address=b(Bytes20), source_pubkey=b(Bytes48), target_pubkey=b(Bytes48)
                )
                for _ in range(n(2))
            ]
        ),
        builder_deposits=BuilderDepositRequests(data=
            [
                BuilderDepositRequest(
                    pubkey=b(Bytes48), withdrawal_credentials=b(Bytes32), amount=u64(), signature=b(Bytes96)
                )
                for _ in range(n(3))
            ]
        ),
        builder_exits=BuilderExitRequests(data=
            [BuilderExitRequest(source_address=b(Bytes20), pubkey=b(Bytes48)) for _ in range(n(3))]
        ),
        validator_preregistrations=ValidatorPreregistrationRequests(data=
            [
                ValidatorPreregistrationRequest(
                    pubkey=b(Bytes32), withdrawal_credentials=b(Bytes32), vrf_root=b(Bytes32)
                )
                for _ in range(n(6))
            ]
        ),
        builder_preregistrations=BuilderPreregistrationRequests(data=
            [
                BuilderPreregistrationRequest(pubkey=b(Bytes32), withdrawal_credentials=b(Bytes32))
                for _ in range(n(4))
            ]
        ),
        voluntary_exits=VoluntaryExitRequests(data=
            [VoluntaryExitRequest(pubkey=b(Bytes32)) for _ in range(n(16))]
        ),
    )


def beacon_block_body():
    return BeaconBlockBody(
        randao_reveal=vrf_proof(),
        eth1_data=Eth1Data(deposit_root=b(Bytes32), deposit_count=u64(), block_hash=b(Bytes32)),
        graffiti=b(Bytes32),
        proposer_slashings=ProposerSlashings(data=[proposer_slashing() for _ in range(n(2))]),
        attester_slashings=AttesterSlashings(data=[attester_slashing() for _ in range(n(1))]),
        attestations=Attestations(data=[attestation() for _ in range(n(5))]),
        deposits=Deposits(data=[]),
        signed_execution_payload_bid=signed_bid(),
        parent_execution_requests=execution_requests(),
        proof=proof(4000),
    )


GENERATORS = {
    "Attestation": attestation,
    "IndexedAttestation": indexed_attestation,
    "AttesterSlashing": attester_slashing,
    "AggregateAndProof": aggregate_and_proof,
    "ProposerSlashing": proposer_slashing,
    "SignedExecutionPayloadBid": signed_bid,
    "ExecutionRequests": execution_requests,
    "BeaconBlockBody": beacon_block_body,
}

if __name__ == "__main__":
    for name, gen in GENERATORS.items():
        for _ in range(4):
            value = gen()
            print(name, value.encode_bytes().hex(), bytes(hash_tree_root(value)).hex())
