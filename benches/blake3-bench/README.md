# Blake3 LibraryTree qualification

`FixtureEnvironment` collects complete fragments in caller order, followed by uncovered owner
selections in the existing `ProcedureKey` word order. It recursively splits that ordered collection
at `len / 2`, creating exactly `n - 1` Merkle branches without padding or duplicating items. These
edges preserve the inherited namespace. Canonical labels, procedure keys, selected implementation
roots and syscall authority remain unchanged; environment commitments and opening paths change.

A singleton mounts its existing root directly. The collection helper represents an empty collection
as `List([])`; fixture construction still rejects an entry without an explicitly selected
implementation. Each opening prepends its item's actual Merkle route to the unchanged local path.
Shared opening prefixes remain reusable by the existing occurrence ledger and resolution session.

Resource policies remain finite: at most 16,384 bindings/collection items, 262,144 submitted nodes
and physical visits, physical depth 256, and 32 MiB of submitted encoding. Collection branches count
toward these budgets, including occurrence-based traversal of mounted DAGs. Opening limits remain
257 nodes, depth 256, 16,384 immediate and aggregate List children, 2 MiB encoding and 4 MiB native
storage. Mounted Lists retain those limits. Construction, complete validation and opening preflight
reject excessive paths, including their collection prefixes. Existing VM/AIR Merkle support supplies
authentication and accounting; this change adds no host API or execution semantics.

The `librarytree-blake3` binary qualifies the historical 1, 8 and 32-hash chains. The seed is 32
`0xff` bytes. An independent native `blake3` oracle checks its standard empty-message vector, derives
the expected chain and supplies eight preserving MASM assertions. Native execution and proof claims
are also checked against those expected limbs. Before timing, the loader compares all 1,015
environment bindings against the canonical owner inventory, including every key, namespace, label
and selected implementation root. It retains the complete core library inventory.

The [2026-11-05 evidence](results/librarytree-merkle-2026-11-05/manifest.json) records implementation
commit `4eeb5d240`, based on PR19 commit `8a42f4bac2fec49fd127de507e0ee2a3526c0f59`. Raw diagnostic
and proof JSON, [sample medians](results/librarytree-merkle-2026-11-05/summary.json), compiler/binary
and source hashes, and per-run power checks are retained together. Timings used Rust 1.99.0,
the `optimized` profile, performance CPU 4 (capacity 1024), one Rayon worker, one discarded warmup
and five measured samples per workload. Processes ran sequentially with `RAYON_NUM_THREADS=1`,
`RUST_MIN_STACK=16777216`, `LC_ALL=C` and `RUST_LOG` unset. Every proof was fully verified. All 15
measured proofs reported **96 conjectured security bits** with the Eidos proof hash.

Diagnostics run in separate untimed processes. Every workload makes exactly **10 source callbacks**,
one for each first-use key, and caches those 10 bindings. Repeated EXECs reuse those authenticated
bindings. Guest clocks and EXEC counts match the historical checked workloads:

| Hashes | Guest cycles | EXECs | Padded heights: Core / Chiplets / Eidos / And8 |
| --- | ---: | ---: | --- |
| 1 | 6,853 | 32 | 8,192 / 2,048 / 8,192 / 65,536 |
| 8 | 53,949 | 249 | 65,536 / 8,192 / 8,192 / 65,536 |
| 32 | 215,421 | 993 | 262,144 / 32,768 / 8,192 / 65,536 |

The following work counts are constant across these three workloads. Library prefix rows include
two terminal rows and alignment to eight rows, `ceil((logical_rows + 2) / 8) * 8`. Opening compression
requests precede Controller/Eidos interning; distinct Eidos blocks cover the whole execution.

| Environment | Logical Library rows | Library prefix rows | Opening compression requests | Distinct Eidos blocks | Eidos rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| Historical root List | 1,128 | 1,136 | 620 | 670 | 21,440 |
| Balanced Merkle | 238 | 240 | 175 | 225 | 7,200 |

The historical List padded heights were `8,192 / 4,096 / 32,768 / 65,536`,
`65,536 / 16,384 / 32,768 / 65,536` and `262,144 / 32,768 / 32,768 / 65,536` respectively.
The earlier controlled Merkle diagnostic had 240 logical Library rows and 226 Eidos blocks because
it retained a singleton outer List; its Library prefix occupied 248 rows. It did not measure proofs.

`prove_ms` measures `prove_full` after witness generation. Combined time is the median of each
sample's `witness_ms + prove_ms`; setup, oracle work, diagnostics and verification are excluded.
Proof sizes are median serialized bytes.

| Hashes | Merkle prove ms | Merkle witness + prove ms | Historical List prove ms | Merkle proof bytes | Historical List proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1,207.372 | 1,211.282 | 2,037.377 | 160,573 | 159,037 |
| 8 | 3,406.083 | 3,418.879 | 4,392.601 | 163,229 | 163,357 |
| 32 | 12,477.071 | 12,517.322 | 13,169.720 | 180,901 | 180,709 |

The historical List timings come from commit `18d4a347d96b63118e9c93af760f077d76493d52`, using the
same timing methodology and checked workload bytes. They are archived measurements, rather than a
new paired timing run. The median prove reductions against those measurements are 40.74%, 22.46%
and 5.26%; proof sizes change by +1,536, -128 and +192 bytes. The
[historical reference](results/librarytree-merkle-2026-11-05/historical-reference.json) retains exact
archive members, SHA-256 hashes and a separate pre-LibraryTree comparison. That comparison's
historical `origin/next` means immutable `00b12150715891582864d256ef51c5ea46bfb282`.
The original evidence remains in the main clone's `.scratch/librarytree/archives/` unchanged.

To reproduce a case from the repository root, first run both power guards and proceed only if
each exits zero. Exit 75 from the heavy-work guard defers the run until the policy permits it.
Use a verified performance CPU on the local machine; CPU 4 was used for the recorded results.

```sh
(
set -e
systemd-ac-power
/usr/local/bin/headless-power-policy check-heavy
mkdir -p target
TMPDIR="$PWD/target" CARGO_BUILD_JOBS=1 cargo build --locked --offline --profile optimized \
    -p miden-vm-blake3-bench --bin librarytree-blake3

# Run the guards again before each diagnostic or proof process.
systemd-ac-power
/usr/local/bin/headless-power-policy check-heavy
env -u RUST_LOG RAYON_NUM_THREADS=1 RUST_MIN_STACK=16777216 LC_ALL=C \
    taskset -c 4 target/optimized/librarytree-blake3 --iterations 32 --mode diagnostics

systemd-ac-power
/usr/local/bin/headless-power-policy check-heavy
env -u RUST_LOG RAYON_NUM_THREADS=1 RUST_MIN_STACK=16777216 LC_ALL=C \
    taskset -c 4 target/optimized/librarytree-blake3 --iterations 32 --mode proof --samples 5
)
```

Validation passed: all 31 `miden-test-utils` library tests (including 15 LibraryTree tests), targeted
Clippy for `miden-test-utils`, `miden-vm-blake3-bench` and `miden-vm-synthetic-bench` with all targets,
all features and warnings denied, repository formatting, and `git diff --check`. Tests cover empty,
singleton and uneven collections, deterministic input handling, canonical binding preservation,
root-kernel/private-helper execution, correct and altered openings, shared-prefix reuse, ordered
fragment mounts, conflicts and duplicates, cache isolation and exact resource boundaries. Fuzz
targets were not run. An independent audit rechecked the saved medians, hashes, oracle outputs,
inventory, callback maps and timing metadata.
