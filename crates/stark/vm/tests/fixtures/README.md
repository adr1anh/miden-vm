`vm_eidos_v3.bin` is a canonical serialized `VmProof` for the descriptor-based VM protocol 5
statement. It executes `begin push.5 push.8 add drop end`, assembled with source name
`prover-integration`, and has zero stack inputs/outputs and the authenticated true deferred root.
The file is the low-level VM proof, not an `ExecutionProof` transport envelope.

`vm_eidos_v3.claim` is fixture-owner metadata: exactly 320 canonical bytes containing 40 Felts in
`K_entry[4] || R_E[4] || I[16] || O[16]` order, without a header. The expected descriptor is selected
from the named fixture environment before execution; it is not inferred from the proof or an
implementation digest. This fixture-only encoding does not add a general claim decoder.

Tests verify the proof natively, check claim/deferred mutations, and compare the complete
recursive-advice content/order against an independently decoded native transcript. They run
without the prover feature. The old `vm_eidos_v1_0.bin` and `.program` files remain legacy
program/kernel-statement rejection artifacts; `.program` cannot select current execution authority.

Regenerate into a separate directory after following the repository power guards whenever the
pinned VM relation or transcript profile changes:

```sh
MIDEN_VM_FIXTURE_OUTPUT_DIR=/tmp/miden-vm-advice-fixture RUST_MIN_STACK=16777216 \
  cargo test --profile test-dev --offline --locked -p miden-prover --test vm_advice_fixture \
  regenerate_vm_eidos_v3_advice_fixture -- --ignored --exact
```

Review both outputs before replacing the current fixture pair. The generator checks the owner's
expected claim against the execution witness and verifies the fresh proof before writing outputs.
It uses one Rayon worker for deterministic proof-of-work selection. Keep the legacy artifacts.
