"""
PQ reference vectors from the consensus-specs pyspec, until consensus-spec-tests ship PQ.

One `<type> <serialized_hex> <root_hex>` line per case. Every type comes from the `pq`
pyspec build. Regenerate against a consensus-specs checkout of the `pq` branch at `$SPECS`:

    python3 -m venv venv
    venv/bin/pip install -e "$SPECS[test]" cramjam
    (venv=$PWD/venv; cd "$SPECS" && "$venv/bin/python" -m pysetup.generate_specs --all-forks)
    venv/bin/python gen_reference_vectors.py 1 > reference_vectors.txt

`generate_specs` writes the git-ignored `tests/core/pyspec/eth_consensus_specs/<fork>/`.
"""

import hashlib
import random
import sys

from eth_consensus_specs.pq import mainnet as spec

rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 0)


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def u64():
    return spec.Uint64(rng.getrandbits(64))


def b(cls):
    return cls(rbytes(cls.LENGTH))


def n(k):
    return rng.randrange(0, k + 1)


def bits(length):
    return [bool(rng.getrandbits(1)) for _ in range(length)]


def checkpoint():
    return spec.Checkpoint(epoch=u64(), root=b(spec.Root))


def attestation_data():
    return spec.AttestationData(
        slot=u64(),
        index=u64(),
        beacon_block_root=b(spec.Root),
        source=checkpoint(),
        target=checkpoint(),
    )


def proof(max_len):
    return spec.AttestationProof(data=rbytes(rng.randrange(max_len + 1)))


def attestation():
    return spec.Attestation(
        aggregation_bits=spec.AggregationBits(data=bits(rng.randrange(0, 300))),
        data=attestation_data(),
        committee_bits=spec.CommitteeBits(data=bits(spec.CommitteeBits.LENGTH)),
    )


def indexed_attestation():
    return spec.IndexedAttestation(
        attesting_indices=spec.AttestingIndices(data=[u64() for _ in range(rng.randrange(0, 40))]),
        data=attestation_data(),
        proof=proof(3000),
    )


def attester_slashing():
    return spec.AttesterSlashing(
        attestation_1=indexed_attestation(), attestation_2=indexed_attestation()
    )


def vrf_proof():
    return spec.VRFProof(data=[b(spec.Bytes32) for _ in range(spec.VRFProof.LENGTH)])


def aggregate_and_proof():
    return spec.AggregateAndProof(
        aggregator_index=u64(), aggregate=attestation(), proof=proof(5000)
    )


def signed_header():
    return spec.SignedBeaconBlockHeader(
        message=spec.BeaconBlockHeader(
            slot=u64(),
            proposer_index=u64(),
            parent_root=b(spec.Root),
            state_root=b(spec.Root),
            body_root=b(spec.Root),
        ),
        signature=b(spec.XMSSSignature),
    )


def proposer_slashing():
    return spec.ProposerSlashing(signed_header_1=signed_header(), signed_header_2=signed_header())


def execution_payload_bid(blob_count, uint, builder_index):
    return spec.ExecutionPayloadBid(
        parent_block_hash=b(spec.Hash32),
        parent_block_root=b(spec.Root),
        block_hash=b(spec.Hash32),
        prev_randao=b(spec.Bytes32),
        fee_recipient=b(spec.ExecutionAddress),
        gas_limit=uint(),
        builder_index=builder_index,
        slot=uint(),
        value=uint(),
        execution_payment=uint(),
        blob_kzg_commitments=spec.BlobKZGCommitments(
            data=[b(spec.KZGCommitment) for _ in range(blob_count)]
        ),
        execution_requests_root=b(spec.Root),
    )


def signed_bid():
    return spec.SignedExecutionPayloadBid(
        message=execution_payload_bid(rng.randrange(0, 7), u64, u64()),
        signature=b(spec.XMSSSignature),
    )


def up_to(k, list_type, make):
    return list_type(data=[make() for _ in range(n(k))])


def execution_requests():
    return spec.ExecutionRequests(
        deposits=up_to(
            5,
            spec.DepositRequests,
            lambda: spec.DepositRequest(
                pubkey=b(spec.Bytes48),
                withdrawal_credentials=b(spec.Bytes32),
                amount=u64(),
                signature=b(spec.Bytes96),
                index=u64(),
            ),
        ),
        withdrawals=up_to(
            3,
            spec.WithdrawalRequests,
            lambda: spec.WithdrawalRequest(
                source_address=b(spec.ExecutionAddress),
                validator_pubkey=b(spec.Bytes48),
                amount=u64(),
            ),
        ),
        consolidations=up_to(
            2,
            spec.ConsolidationRequests,
            lambda: spec.ConsolidationRequest(
                source_address=b(spec.ExecutionAddress),
                source_pubkey=b(spec.Bytes48),
                target_pubkey=b(spec.Bytes48),
            ),
        ),
        builder_deposits=up_to(
            3,
            spec.BuilderDepositRequests,
            lambda: spec.BuilderDepositRequest(
                pubkey=b(spec.Bytes48),
                withdrawal_credentials=b(spec.Bytes32),
                amount=u64(),
                signature=b(spec.Bytes96),
            ),
        ),
        builder_exits=up_to(
            3,
            spec.BuilderExitRequests,
            lambda: spec.BuilderExitRequest(
                source_address=b(spec.ExecutionAddress), pubkey=b(spec.Bytes48)
            ),
        ),
        validator_preregistrations=up_to(
            6,
            spec.ValidatorPreregistrationRequests,
            lambda: spec.ValidatorPreregistrationRequest(
                pubkey=b(spec.XMSSPubkey),
                withdrawal_credentials=b(spec.Bytes32),
                vrf_root=b(spec.Root),
            ),
        ),
        builder_preregistrations=up_to(
            4,
            spec.BuilderPreregistrationRequests,
            lambda: spec.BuilderPreregistrationRequest(
                pubkey=b(spec.XMSSPubkey), withdrawal_credentials=b(spec.Bytes32)
            ),
        ),
        voluntary_exits=up_to(
            16,
            spec.VoluntaryExitRequests,
            lambda: spec.VoluntaryExitRequest(pubkey=b(spec.XMSSPubkey)),
        ),
    )


def beacon_block_body():
    return spec.BeaconBlockBody(
        randao_reveal=vrf_proof(),
        eth1_data=spec.Eth1Data(
            deposit_root=b(spec.Root), deposit_count=u64(), block_hash=b(spec.Hash32)
        ),
        graffiti=b(spec.Bytes32),
        proposer_slashings=up_to(2, spec.ProposerSlashings, proposer_slashing),
        attester_slashings=up_to(1, spec.AttesterSlashings, attester_slashing),
        attestations=up_to(5, spec.Attestations, attestation),
        deposits=spec.Deposits(data=[]),
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
            print(name, value.encode_bytes().hex(), value.hash_tree_root().hex())
            if name == "AggregateAndProof":
                version = bytes.fromhex("e0000000")
                genesis_validators_root = bytes(range(32))
                fork_root = hashlib.sha256(
                    version.ljust(32, b"\x00") + genesis_validators_root
                ).digest()
                domain = bytes.fromhex("06000000") + fork_root[:28]
                signing_data = spec.SigningData(
                    object_root=value.hash_tree_root(), domain=spec.Domain(domain)
                )
                print(
                    "AggregateSigningRoot",
                    value.encode_bytes().hex(),
                    signing_data.hash_tree_root().hex(),
                )
