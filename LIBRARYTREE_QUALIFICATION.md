# LibraryTree qualification measurements

Measured 4 November 2026 with Eidos proofs. All 28 release samples passed: seven scenarios, each in `shape`, `session`, `proof` and `recursive` modes. The [aggregate](.scratch/librarytree/pr16-measurements-final/aggregate.json) retains commands, raw JSON/stderr/RSS paths and guard outcomes. All 56 AC/heavy-policy checks passed. Source remained `ae045c1992f4dd5aa9d34ea19d6a586d775368fd`, with no tracked dirty paths before or after measurement. The plan ledger owns overall completion evidence; this report records measured results and their limits.

Toolchain: `rustc 1.99.0 (b940084d7 2026-09-28)`, commit `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`, host `aarch64-unknown-linux-gnu`, LLVM 23.1.1. The `release` build used manifest defaults, `processor/concurrent` and `vm/concurrent,internal`; its [log](.scratch/librarytree/pr16-release-bench-build.log) reports optimized completion in 1m18s. Executable SHA-256: `d3a293642faa6670daf7b603cf69c750a20e28ccc8ff051eba2b855dd65a2e5c`.

Recorded build and run:

```bash
task_repo=/home/adrian/.codex/worktrees/8e86/miden-vm
systemd-ac-power && /usr/local/bin/headless-power-policy check-heavy && \
TMPDIR="$task_repo/.scratch/librarytree/compiler-tmp" CARGO_TARGET_DIR="$task_repo/.scratch/librarytree/build-pr12" CARGO_NET_OFFLINE=true RUST_MIN_STACK=16777216 MIDEN_BUILD_LIB_DOCS=1 \
cargo build --offline --locked --release -p miden-vm-synthetic-bench --bench synthetic_bench
task_bench="$task_repo/.scratch/librarytree/build-pr12/release/deps/synthetic_bench-c95b8afb11e06475"
python3 .scratch/librarytree/measure-pr16.py "$task_bench" --profile release \
  --features 'cargo build --offline --locked --release -p miden-vm-synthetic-bench --bench synthetic_bench; manifest defaults; processor/concurrent and vm/concurrent,internal' \
  --output-dir .scratch/librarytree/pr16-measurements-final
```

The runner invokes each child as `/usr/bin/time -q -f '{"process_peak_rss_kib":%M,"exit_status":%x}' -o RSS_PATH EXECUTABLE --librarytree MODE SCENARIO`. Children receive a scratch `TMPDIR` and `RUST_MIN_STACK=16777216`. Configurations and caller-selected execution targets match across modes. Successful executions assert independently known sixteen-zero outputs; every native verification completes, every diagnostic session completes, and every recursive run authorizes its exact profile and executes one MASM child verifier without producing an outer proof.

Shape/session observations come from separate diagnostic executions. Logical opening rows and opening compression requests precede padding/shared Eidos interning. Prefix rows equal `round_up_8(logical + 2)`; the extra two rows are terminal PAD, and the table's alignment column excludes them. Eidos counts cover the complete execution's distinct compression blocks.

| Scenario | Logical opening rows | Prefix / alignment rows | Core raw rows / contexts | Chiplets padded rows | Opening compression requests | Eidos blocks |
|---|---:|---:|---:|---:|---:|---:|
| list-small | 20 | 24 / 2 | 17 / 1 | 64 | 18 | 19 |
| list-unused | 148 | 152 / 2 | 17 / 1 | 256 | 82 | 83 |
| merkle-small | 20 | 24 / 2 | 17 / 1 | 64 | 18 | 19 |
| merkle-unused | 32 | 40 / 6 | 17 / 1 | 64 | 24 | 25 |
| exec-repeat | 20 | 24 / 2 | 152 / 1 | 128 | 18 | 26 |
| call-repeat | 20 | 24 / 2 | 152 / 17 | 128 | 18 | 26 |
| equal-d | 30 | 32 / 0 | 152 / 1 | 128 | 27 | 33 |

The unused cases add 128 Data leaves. Repeating EXEC sixteen times preserves opening work while increasing Core rows from 17 to 152; sixteen CALLs observe 17 contexts. These are fixture-specific row comparisons. The byte-pair table stays at 65,536 rows in every case.

Times are milliseconds, rounded from recorded nanoseconds. Proof bytes and peak RSS are exact integers. RSS columns list **proof / recursive / shape / session**, in **KiB**.

| Scenario | Prove ms | Native verify ms | MASM verify ms | Proof bytes | Whole-process peak RSS KiB |
|---|---:|---:|---:|---:|---|
| list-small | 126.726 | 1.869 | 157.331 | 163101 | 236160 / 235088 / 17584 / 8784 |
| list-unused | 151.249 | 1.821 | 157.978 | 162109 | 261200 / 261232 / 19280 / 8784 |
| merkle-small | 128.267 | 1.735 | 160.588 | 161213 | 236672 / 234976 / 17040 / 8784 |
| merkle-unused | 129.856 | 1.845 | 159.883 | 161277 | 235456 / 237344 / 18624 / 8784 |
| exec-repeat | 130.527 | 1.767 | 159.147 | 162077 | 236400 / 237856 / 17616 / 8784 |
| call-repeat | 130.495 | 0.941 | 158.417 | 159773 | 237296 / 237968 / 17568 / 8832 |
| equal-d | 134.053 | 1.700 | 159.985 | 161885 | 243280 / 247472 / 18112 / 8832 |

Proving includes callback-counting overhead. Proof RSS includes fixture setup and native verification. Recursive RSS additionally includes child proving/native verification and recursive setup; its MASM timer covers only verifier execution. RSS is never prover-only. One sample per cell provides no variance estimate, cache speedup, or general performance ranking.

Host code is preloaded and processor caches start empty. Entry generates one opening callback and one code callback. EXEC/CALL repeats generate one further opening callback on first callee use, then fifteen runtime intervals with zero opening/code callbacks. Equal-D authenticates two distinct callee keys, each used eight times, then records fourteen such zero/zero intervals. Same-package exact code candidates can satisfy calls before the CodeRequest memo is consulted. These observations show within-execution reuse; they do not count dedicated cache hits or measure lazy code loading.

All fourteen native security records, including recursive children, agree: conjectured security 96 bits; 298 DEEP terms; 79 lookup fractions/row, maximum message width 16, three boundary terms; two OOD points; 799 composed constraints, maximum degree 9, eight quotient chunks, `max_combo=2`. Protocol parameters are log blowup 3, log folding arity 2, 27 queries, log final degree 7 and query/OOD/DEEP/folding/lookup PoW bits `17/0/12/4/0`. Instance parameters are log maximum height 16, field bits Q16 `8388606`, collision resistance 126 bits.

Resource/security boundaries and optional external Protocol scope remain governed by [PR16 and the plan's recorded invariants](LIBRARYTREE_PLAN.md#pr-16-adversarial-performance-and-final-qualification). No adopted Protocol adapter construction cost is claimed. Fuzz execution/campaigns are explicitly waived; none ran. Repository, no_std and adversarial validation evidence is recorded in the plan ledger, separately from these measurements.


## Blake3 revision comparison — 5 November 2026

A hash in this measurement is a VM program computing Blake3 over 32 bytes, repeatedly feeding the previous digest into the next call, starting with 32 bytes of `0xff`. This is distinct from choosing the proof transcript's hash. The transcript uses Eidos in both revisions. The same MASM source, inputs and runner source are byte-identical across the pinned revisions; VM invocation semantics and AIRs are allowed to differ.

Baseline is the local `origin/next` at `00b12150715891582864d256ef51c5ea46bfb282`; requested HEAD is `18d4a347d96b63118e9c93af760f077d76493d52`, before the subsequent retirement-only follow-up. Both isolated clean checkouts use `cargo +1.99.0 build --locked --offline --profile optimized -p miden-vm-blake3-bench --bin vm-performance -j2` (HEAD additionally requests JSON build messages). Rust 1.99.0, release-derived optimized profile, LTO, one codegen unit and empty Rust flags match. HEAD's source-required fixture dependencies add helper/testing/arbitrary features; this is a comparison of revisions built with the same command, not identical dependency feature closures. Independent source inspection found no added gate changing these execution/proving algorithms or layouts.

The final run pins the coordinator, children and Rayon workers to Linux CPU 4, a performance-class CPU (capacity 1024; efficiency class 561), with one worker. Twelve subprocesses run sequentially; revision order is counterbalanced across six workload pairs. Each subprocess verifies one warmup and five measured proofs: 60 measured proofs, all reporting 96-bit conjectured security and complete verification. Eight preserving output assertions check independently computed external-Blake3 digests. All power-policy checks pass. Earlier cached-build/unpinned runs are exploratory and excluded.

The primary time is the median of each sample's **execution-for-proving + proving**. Proving includes trace construction. Plain execution is a separate measurement; do not add it again. Assembly/input parsing are outside timers; fresh host construction, complete corelib loading and advice setup are inside execution/witness timers. Verification is measured separately.

| Blake3 calls | origin/next execute + prove s | HEAD execute + prove s | Change | origin/next plain execute ms | HEAD plain execute ms |
|---:|---:|---:|---:|---:|---:|
| 1 | 1.150 | 2.042 | +77.57% | 8.753 | 5.035 |
| 8 | 3.149 | 4.406 | +39.89% | 8.829 | 12.379 |
| 32 | 11.462 | 13.208 | +15.24% | 9.768 | 35.824 |

The measured proof-time increase is 15–78% for these three workloads. At 32 calls plain execution is 9.768→35.824ms, while execution plus proving is 11.462→13.208s. The larger relative plain-execution increase should not be confused with the total proof-time increase.

| Calls | Native verify ms, origin → HEAD | Proof bytes, origin → HEAD | Padded Core / Chiplets / Eidos / byte-pair rows, origin → HEAD |
|---:|---:|---:|---|
| 1 | 0.878 → 0.897 | 158301 → 159037 | 8192 / 1024 / 8192 / 65536 → 8192 / 4096 / 32768 / 65536 |
| 8 | 0.877 → 0.913 | 158461 → 163357 | 65536 / 8192 / 8192 / 65536 → 65536 / 16384 / 32768 / 65536 |
| 32 | 0.966 → 0.994 | 177157 → 180709 | 262144 / 32768 / 8192 / 65536 → 262144 / 32768 / 32768 / 65536 |

The control replaces only the hash call with `nop`, retaining the loop and eight output assertions:

| Loop iterations | origin/next control execute + prove s | HEAD control execute + prove s |
|---:|---:|---:|
| 1 | 0.653 | 1.718 |
| 8 | 0.655 | 1.723 |
| 32 | 0.657 | 1.736 |

This control shows a substantial fixed-cost difference even without Blake3 computation. HEAD's benchmark fixture places every selected implementation from the program/full corelib naming inventories beneath one root `List`, with no used-implementation filtering or Merkle layout (`benches/blake3-bench/src/lib.rs:66`, `crates/test-utils/src/librarytree.rs:160,206,330`). Opening the entry already carries and authenticates that List vector. This is a test-fixture choice, not a production profile default or an intrinsic lower bound for LibraryTree. Observed Eidos/Chiplets growth is consistent with more authentication work; these measurements do not isolate its exact time contribution. Hash-minus-control deltas remain diagnostic: padding changes discretely, so they are not an exact marginal cost per hash.

Five samples on one laptop CPU provide a bounded revision comparison, not a general throughput ranking or statistical confidence interval. CPU frequency is not fixed. The actual 32-byte hash work, caller environment layout, host loading and new runtime-call semantics all matter. No multicore speedup, alternative environment-layout result, or Blake3 precompile cost is claimed.

Authoritative raw [manifest](.scratch/librarytree/blake3-comparison/runs/20261105T075815.832527Z/manifest.json), [summary](.scratch/librarytree/blake3-comparison/runs/20261105T075815.832527Z/summary.json), per-case JSON/stderr and power-guards JSONL remain separate from this report. Independent review recomputes all 12 records/60 samples, hashes, timing arithmetic, security and nonoverlap with zero discrepancies. Build/feature manifests and the independent oracle are in `.scratch/librarytree/blake3-comparison/`. Binary SHA-256s: origin `14aaf06840b84a9109452773dae66f5f8671f93bd8de99687ea07ab400582b02`; HEAD `8630870624cad66bdc8531f23f5a14787a94ee3e18a837dce13002841d7a4118`.
