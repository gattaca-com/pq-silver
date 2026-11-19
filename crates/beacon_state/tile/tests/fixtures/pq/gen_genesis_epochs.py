"""
A 64-validator PQ genesis from the consensus-specs pyspec helpers, and its state
roots after each of three epoch transitions, until consensus-spec-tests ship PQ.

Writes `genesis.ssz_snappy` (raw snappy) beside this file and prints the roots
`pq_state.rs` pins. Set up the venv as the docstring of
`crates/ssz/tests/fixtures/pq/gen_reference_vectors.py` describes, then:

    venv/bin/python crates/beacon_state/tile/tests/fixtures/pq/gen_genesis_epochs.py
"""

import os

import cramjam
from eth_consensus_specs.pq import mainnet as spec
from eth_consensus_specs.test.helpers.genesis import create_genesis_state

state = create_genesis_state(spec, [spec.MAX_EFFECTIVE_BALANCE] * 64, spec.MAX_EFFECTIVE_BALANCE)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "genesis.ssz_snappy")
with open(out, "wb") as f:
    f.write(bytes(cramjam.snappy.compress_raw(state.encode_bytes())))

for epoch in (1, 2, 3):
    spec.process_slots(state, spec.Slot(epoch * spec.SLOTS_PER_EPOCH))
    print(int(state.slot), state.hash_tree_root().hex())
