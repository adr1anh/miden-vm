# LibraryTree VM implementation plan

This plan is the current execution backlog for implementing the selected LibraryTree model in this repository. Once the plan is established, start implementation under the workflow below. This initial plan snapshot contains documentation only: no production implementation, compilation, tests, benchmarks or regeneration is claimed.

The repository baseline is `00b12150715891582864d256ef51c5ea46bfb282`, inspected on 2 November 2026. The design chapters use the earlier baseline `a3d9bc09ef8a956774eb4ec0e6e734428e194a8c`; source paths and interfaces below follow this checkout. The live design Pages remain unchanged.

## Sources and authority

Read the linked design chapters when implementing their contracts. This plan selects implementation boundaries; it does not silently decide remaining Protocol policy or compiler ABI questions.

- [LibraryTree design workspace](https://chatgpt.com/space/page_2e2830d3aca081919395850e2d6425c3), [design overview](https://chatgpt.com/space/page_78e4c04efdb48191a07eb544f8729784), and [decisions and next steps](https://chatgpt.com/space/page_a19f6685aeb88191a31a35296a82e48b).
- [Namespaced execution shared contracts](https://chatgpt.com/space/page_11597d3254d8819196b4f5b3d0d13718), [execution, MAST and processor design](https://chatgpt.com/space/page_6260aefe8dd481919833c1414f870d34), and [environment execution model](https://chatgpt.com/space/page_0cb8fddb96a88191809388bf83fe686a).
- [Library chiplet and authenticated resolution AIR](https://chatgpt.com/space/page_b955981e1f588191a1e3274f1bd6a3c3), [proof statements and protocol integration](https://chatgpt.com/space/page_077d46e54c908191a760066e259ad09c), and [implementation and verification design](https://chatgpt.com/space/page_28e54e1ae6a881918a137de353478cda).
- [Assembly, linking and package contracts](https://chatgpt.com/space/page_8f108eb2fcf88191922e49df0dff6e31), [EXEC and explicit inline opt-in](https://chatgpt.com/space/page_6d5de3bc86fc8191bf08070f21ab4eb6), and [compiler and toolchain handoff](https://chatgpt.com/space/page_9bfed3770b6881919c72ccbbed3e85af).
- [VM–Protocol execution and release contract](https://chatgpt.com/space/page_97a099703b9c81919476a98e51550cd4), [private account code and environment binding](https://chatgpt.com/space/page_8b7ff9039cb08191ad573b8333bf230d), and [VM contract and feasibility review](https://chatgpt.com/space/page_9183e46c5e648191939ffc4cb4bffb9d).

## Scope and invariants

Breaking changes are accepted subject to D2: existing MASM programs must remain usable after rebuilding, with digest-shaped invocation targets interpreted as keys. New serialized MAST formats are allowed. Implement one new callable/statement model and rebuild its consumers; do not create a permanent dual-target executor or runtime digest fallback to ease the transition.

1. **Environment authority:** execution is defined by immutable `(K_entry, R_E, N_kernel)`. Entry and every retained runtime invocation authenticate a binding in R_E. Code availability at implementation root D does not authorize execution. The environment root never switches on account/library calls.
2. **Uniform callable keys:** EXEC/CALL/SYSCALL and dynamic targets use ProcedureKey K; `procref` produces K. Separate newtypes distinguish K, D, R_E, N and label commitment L. Structural JOIN/SPLIT/LOOP/SPAN and `ExternalNode(D)` remain structural code commitments. Immediate keyed nodes have no callee child.
3. **Invocation modes:** EXEC/DYN preserve context and established principal; CALL/DYNCALL create a new user context and establish the requested K; SYSCALL enters root context while preserving principal. Entry initializes K_entry in the existing initial context. Matching returns restore frames/forests. Same-context execution shares RAM, overflow and FMP; namespaces do not isolate memory.
4. **Kernel authorization:** actual SYSCALL requires the authenticated immediate parent namespace to equal the authorized full accumulated N_kernel. Ordinary modes and entry may use the same exports. No privilege class, descendant wildcard, ordinary inequality test or kernel-string authority is introduced.
5. **Canonical authentication:** reuse standard Eidos FeltSequence framing and the agreed typed label codec/domains. Env extends N; Merkle/List preserve it; Mast(L,D) derives K under inherited N. DATA never emits an executable binding. Global executable-path uniqueness is a builder/admission obligation; selective membership is not its proof.
6. **Runtime exec:** every retained source exec, including local/bundled helpers, becomes real keyed EXEC (`0x5f`). Structural inline expansion requires explicit eligible fixed-body opt-in. Latest implementations are not silently frozen. Runtime recursion is distinct from forbidden structural inline cycles.
7. **Packed proof relation:** Library/Controller/AEAD/Memory/ACE/Bitwise/PAD share Chiplets24/4, the selected 22-cell Library overlay, nine fixed periodic columns and `[4,4,3,2]` lookup capacity. Four production AIRs remain. Degree bounds, lookup multiplicities and physical prefix relocation require actual capture/testing.
8. **Statement cutover:** claim44 v2, Core36 public Felts, Chiplets8 public Felts and deferred-only aux4 replace the present claim40/Core32/kernel-list authority. Expected public claims come from the verifier caller. Root END authenticates K_entry/D_root and closes the initial binding; all-HALT is invalid. Transport format 3 is separate from claim v2.
9. **Toolchain separation:** declarations/interface identity, release selection, canonical namespace home, code materialization and source aliases are separate. Latest can compile without D; pinned selection does not imply inlining. Retain all public/helper/address-taken callable roots. Final runnable artifacts contain no unresolved namespace relocations.
10. **Witness and resource trust:** host resolution/code loading supplies witnesses. AIR authenticates resolution; guest resource loaders must authenticate advice values before use. Code loading retains current requested-D/procedure-root checks and merge-advice-once behavior. Debug metadata never grants authority.

Included: core identities/MAST, processor and replay, packed AIR/proofs, assembler/project/package changes, supported runtime ABI/resource contracts, core library, public API/CLI, adversarial qualification and measured costs. Protocol registry/publisher authorization, inclusion freshness and concrete account policy remain external integrations with explicit required contracts and fixtures. Upstream Rust compiler lowering is a tracked handoff where its source is outside this repository. Do not implement a new registry or claim these external obligations are solved by the VM.

## Workflow and completion rules

The first goal commit contains this plan only. Subagents perform the main research, implementation and review work; the orchestrator owns integration, signed commits, branch transitions and acceptance. Prefer fresh bounded agents (`fork_turns: none`) with explicit task/file ownership, applicable user/repository instructions and selected references. Assign an independent reviewer who did not implement the change. Subagents must not commit or switch branches unless the orchestrator explicitly delegates that responsibility.

Use `LIBRARYTREE_CURRENT.md` for the current handoff, then read only the active PR and relevant invariant/spec sections it names. This plan remains the sole backlog/scope/dependency/acceptance authority, and its ledger/evidence owns durable completion. The brief is not a second status ledger. Routine source snapshots live in uncommitted `.scratch/librarytree/reference-cache/` with Page/date/SHA-256 provenance; superseded proposals/handoffs and raw artifacts are reference-only archives, not agent input. Preserve shared temporary sources for other readers.

Use one local branch per proposed PR in a **linear stack**: PR NN has PR NN−1 as its Git parent/base, even when its semantic dependency list is shorter. Research and design can proceed in parallel according to semantic dependencies; shared-worktree edits must have clear ownership. Branch names below are exact defaults using the required `adr1anh/` prefix. PR 00 starts from the baseline. Keep incomplete/noncompiling units as an unsubmitted local stack with deferred checks recorded. **Do not create any GitHub PR, including a draft, until the user explicitly says to do so.** No push or publication is required to execute the local stack.

Intermediate tips may fail to compile during the intentional breaking cutover. Record the exact known failure and the PR expected to resolve it. That permission does not waive soundness, malicious-input, native/recursive or final tests. Do not expose or release host-only keyed dispatch as a completed proof system. The final tip must build, lint, test and regenerate cleanly.

Choose many focused, reviewable commits as work proceeds; do not freeze commit counts now. Before each slice, identify the invariant/refactor it delivers, touched consumers and focused acceptance evidence. Prefer refactor/remove/reuse over duplicate resolvers, interpreters, codecs, builders or compatibility layers. If newly discovered coupling changes a boundary, update this plan in a **separate signed documentation commit**, never mixed with implementation.

Local uncommitted scratch files are allowed. Stage explicit file paths for each intended commit so scratch files and unrelated work are not swept into it. When a material shared design, product, ABI, security, policy or scope decision is needed, stop the affected work and ask the user a concise, concrete question to resolve together. Continue independent preparation only while waiting; do not silently choose a scope or weaken a selected contract to proceed. Routine implementation choices remain delegated within the agreed contracts.

Maintain root `PR_DESCRIPTION.md` for final branch review scope, never current-work discovery. Before switching branches, finalize and commit it separately from implementation and plan changes. Describe the problem/resulting behavior, stack base and semantic dependencies, checks passed/deferred with reasons, and material risks/open gates. Do not preserve abandoned approaches or use a passing happy path as completion evidence.

The status ledger below is authoritative for progress. Allowed states are `planned`, `in-progress`, `implemented-awaiting-validation`, `complete`, and `blocked`. Add actual implementation commit SHAs and concrete test/capture/regeneration evidence. `complete` means its acceptance criteria are met; a branch with unrun required tests is `implemented-awaiting-validation`. Record exact external/decision blockers without guessing a policy to clear them.

### Power and privilege rules

Before compiling or testing Rust, run `systemd-ac-power`. Exit 0 permits proceeding subject to the heavy-work guard; any other exit requires reporting battery power and waiting for user approval. Before CPU-intensive compilation, suites, benchmarks, generation or similar work, run `/usr/local/bin/headless-power-policy check-heavy`: exit 0 permits proceeding; exit 75 defers heavy work while lightweight work continues and the guard is retried later; any other exit defers until the guard works. Do not ask to bypass exit 75 unless the user explicitly requests an override. Recheck after a meaningful delay or changed power state, and avoid simultaneous local heavy suites.

For approved root commands use `sudo /usr/local/sbin/codex-duo-run /absolute/command [args...]` in a PTY and ask the user to approve Duo; otherwise use normal password-based sudo. Never ask for a password or configure NOPASSWD. Codex permissions are separate. Do not suspend or hibernate the remote machine.

## Stage 1 Shared contracts and foundations

### PR 00 Commit the implementation plan

**Branch:** `adr1anh/librarytree-00-plan`. **Git base:** baseline `00b121507`. **Semantic dependencies:** none.

**Files:** new root `LIBRARYTREE_PLAN.md` only in the first commit. Validate design/source links, baseline, sequencing, open gates and acceptance coverage. Later plan edits remain separate signed docs commits. **Checks:** independent review against the design chapters and current source; after staging the explicit plan path, `git diff --cached --check` (a bare `git diff --check` does not inspect an untracked plan). **Acceptance:** a durable standalone plan with no production code changes and no claimed build/test result.

### PR 01 Canonical identities and execution contracts

**Branch:** `adr1anh/librarytree-01-identities`. **Git base:** PR 00. **Semantic dependencies:** 00.

**Existing files:** `core/src/program/{mod,domain,claim,request}.rs`, `core/src/lib.rs`, existing Eidos helpers under `crates/crypto/src/hash/eidos/`. **New:** `core/src/program/environment.rs` or a small module directory if warranted.

Define distinct K/D/R_E/N/L types, typed label bytes, canonical environment objects, namespace/key derivation, bounded decode/build and duplicate executable-path validation. Establish the immutable execution descriptor and typed verifier identity/configuration contract. Coordinate actual claim activation with PR 12; keep one canonical codec rather than two authoritative statement models. AccountId parsing and registry policy stay outside core.

**Acceptance:** byte-exact Rust vectors cover every label tag, quoted/Unicode components, empty/multiblock collections, object domains and namespace/key distinctions. Unknown versions/tags, malformed fields, trailing data, duplicate executable paths and domain substitution reject. The vector set is consumable by MASM tests. **Checks:** `cargo test -p miden-core --lib program`; `cargo test -p miden-core --lib crypto_and_vm_registries_are_disjoint`.

### PR 02 Keyed MAST and wire format

**Branch:** `adr1anh/librarytree-02-keyed-mast`. **Git base:** PR 01. **Semantic dependencies:** 01.

**Existing files:** `core/src/operations/{mod,tests}.rs`, `core/src/mast/node/{mod,call_node,dyn_node,mast_forest_contributor}.rs`, `core/src/mast/{mod,dense_builder,dense_order,multi_forest_node_iterator,sparse,untrusted}.rs`, merger and serialization modules/tests. **New:** `core/src/mast/node/exec_node.rs`. Update affected `tools/miden-core-fuzz/fuzz_targets/` and seed/arbitrary generators.

Add EXEC control opcode 0x5f and target-only Exec/Call/SysCall nodes that hash K/mode without a structural callee. Replace dead callee-ID traversal assumptions directly. Preserve real structural External(D). Bump dense MAST 0.0.5 → 0.0.6 across safe/trusted/view/hashless/sparse readers/writers together.

**Acceptance:** canonical round trips and malformed count/offset/version rejection; changing environment D leaves caller MAST unchanged; equal-D/different-K remains distinct; runtime recursion is representable and structural cycles reject. Preserve existing MASM syntax through later lowering under D2; old serialized MAST compatibility is not required. **Checks:** `cargo test -p miden-core --lib mast`; `cargo test -p miden-core --lib operations`; run affected fuzz smoke checks at final qualification with explicit bounds.

### PR 03 Chiplet refactor and address ownership

**Branch:** `adr1anh/librarytree-03-chiplet-foundation`. **Git base:** PR 02. **Semantic dependencies:** 00 and selected layout/address contract; research can parallel PRs 01–02.

**Existing files:** `crates/air/source/src/vm/constraints/chiplets/{columns,selectors,memory,ace}.rs`, `crates/air/source/src/vm/constraints/chiplets/hasher_control/mod.rs`, lookup messages/chiplet AIR and buses, `processor/src/trace/chiplets/` and sequential/parallel trace/address state. **New if useful:** `processor/src/trace/chiplets/layout.rs` for one checked layout owner.

Extract logical Controller-address handling and checked relocation/sentinel rules; do not shift VM clocks, context IDs or memory/overflow addresses. Simplify Memory equations and reusable degree-reduced arithmetic with equivalence evidence. Preserve current relation behavior where possible and explicit lookup multiplicity ownership.

**Acceptance:** sequential/parallel traces agree; old/new Memory equations agree in context-change cases; writes preserve untouched slots/read-only/range rules; address conversion occurs once including valid logical zero and saved/replayed states; native/generated evaluator values/order/degrees agree. **Checks:** `cargo test -p miden-air-definitions --lib vm::constraints::chiplets`; `cargo test -p miden-processor --lib --features concurrent trace::parallel`; `cargo test -p miden-air --test constraint_capture --test generated_drift --test ace_codegen`.

### PR 04 Namespace plans and declaration-only interfaces

**Branch:** `adr1anh/librarytree-04-toolchain-contracts`. **Git base:** PR 03. **Semantic dependencies:** 01; interface/home codecs require the recorded Protocol contract.

**Existing files:** `crates/assembly-syntax/src/{module.rs,ast/invocation_target.rs,ast/instruction/mod.rs,ast/instruction/print.rs,parser/cst/instructions.rs}`, parser/sema tests, `crates/mast-package/src/{lib.rs,package/manifest.rs,package/mod.rs}`. **New:** `crates/mast-package/src/{interface.rs,namespace_plan.rs,interface/serialization.rs}` as needed. Touch CST lexer/parser only if selected explicit-key/inline syntax requires it.

Separate canonical declarations and optional body availability; add validated NamespacePlan/interface-only artifact and preserve existing key-literal/name/path forms. Explicit inline syntax remains optional. Preserve exact-byte optional ABI metadata separately from tooling FunctionType. Do not invent placeholder D/forest or activate a partially migrated package9 executable. Reuse existing parsed Path components and core hashes.

**Acceptance:** declaration-only Latest keys need no D; quoted `::`, exact Unicode bytes, typed labels and absent/present-empty ABI differ correctly; unknown versions/malformed homes reject; existing name/path/word invocation syntax remains accepted, with digest-shaped words interpreted as keys under D2. Explicit inline opt-in is an optional extension. **Checks:** `make test-assembly-syntax`; `cargo test -p miden-mast-package --lib interface`; CST tests only if changed.

## Stage 2 Authenticated execution and relation

### PR 05 Keyed runtime and atomic transitions

**Branch:** `adr1anh/librarytree-05-keyed-execution`. **Git base:** PR 04. **Semantic dependencies:** 01, 02; agree resolver/Resolve ledger schema with PRs 06–07.

**Existing files:** `processor/src/execution/{mod,call,dyn,external}.rs`, `processor/src/fast/{mod,operation,execution_api,step}.rs`, processor/executor/options/errors/continuation stack, host/default/forest store and public exports. **New:** small shared resolver/EXEC modules and bounded environment witness provider; focused `processor/src/fast/tests/environment.rs`. Extend the core arbitrary fixture with an authenticated environment and migrate `processor/src/fast/tests/arbitrary_forest.rs` so executable generation covers actual keyed invocations again.

Resolve `(R_E,K)->(N,D,opening)` before typed D-indexed code loading. Share prepare/commit transitions across pure/source-aware and sync/async execution; authenticate before state changes and make retries idempotent. Implement ENTRY/all runtime modes, requested-key caller/principals, context/FMP/overflow/return behavior and checked budgets. Remove kernel-ROM/digest dispatch authority. Cache bindings by `(R_E,K)`, code by D, and preserve code-root checks/advice merge-once.

**Acceptance:** complete mode/context/principal/local/host-loaded matrix; same-D aliases distinct; no fallback; wrong syscall namespace/descendant rejects; unknown key versus unavailable/bad D differ; cache/root/limit boundaries and failures/retries do not double-pop/save/charge. **Checks:** `cargo test -p miden-processor --lib environment`; `cargo test -p miden-processor --lib fast::tests`; focused existing source-debug/cache/aggregate-stack regressions. The environment-aware executable generator must exercise retained keyed invocations with valid bindings and bounded terminating call graphs, rather than leaving the temporary PR 02 structural-only restriction in place. Runtime success alone is not proof acceptance.

### PR 06 Packed Library witness and authenticated lookup

**Branch:** `adr1anh/librarytree-06-packed-library`. **Git base:** PR 05. **Semantic dependencies:** 01, 03 and PR 05 ledger contract; synthetic ledgers allow earlier research.

**New:** `crates/air/source/src/vm/constraints/chiplets/library/{mod,columns,tests}.rs`, `crates/air/source/src/vm/constraints/lookup/buses/library.rs`, `crates/air/source/src/vm/trace/chiplets/library.rs`, `processor/src/trace/chiplets/library/{mod,trace,tests}.rs`. **Existing:** chiplet selectors/columns/Memory/ACE/hasher control, lookup messages/buses, main trace schema, chiplet/parallel assembly and `processor/src/trace/tests/lookup.rs`.

Implement two-row Env/Merkle/Mast, complete reverse Lists, unit Open edges, normal/syscall Resolve frequencies, local four-coordinate syscall equations, compression interning and checked counts. Realize selected packed bands, 22 Library cells, ninth periodic column and `[4,4,3,2]` lookup groups without a fifth AIR or new Chiplets auxiliary column. Finalize prefix before physical address conversion.

**Acceptance:** forged full matrices reject list early-exit/midchain/CV/namespace/depth/padding changes, unrooted Open, false selectors/prefix exit, missing PAD/Controller initialization, cross-band/cyclic transitions and weighted namespace cancellation after dependent helpers are recomputed. Capture complete base/extension constraint and lookup degrees; degree ≤9 and capacity are measured gates. **Checks:** `cargo test -p miden-air-definitions --lib library`; `cargo test -p miden-processor --lib library`; generated capture/drift checks and `cargo test -p miden-processor --lib trace::tests::lookup`.

### PR 07 Core invocation binding and root completion

**Branch:** `adr1anh/librarytree-07-core-resolution`. **Git base:** PR 06. **Semantic dependencies:** 02, 05, 06. Production enablement also requires PR 12.

**Existing files:** `crates/air/source/src/vm/constraints/{columns.rs,decoder/,op_flags/,system/,lookup/}`, Core trace schema, processor block stack/tracer/state/parallel fragments and decoder/lookup tests. **New:** `crates/air/source/src/vm/constraints/lookup/buses/resolution.rs` for the dedicated Core Resolve column.

Add resolved-D columns and bind literal/memory K, mode, Resolve request and actually executed D on the same row. Demand one resolution per invocation including cache hits. Constrain requested principals/restoration and actual EXEC. Root END demands entry resolution using actual root hash/next principal; forbid initial HALT and require authenticated END into absorbing HALT. Remove old digest invocation equations.

**Acceptance:** trace-cell mutations reject wrong K/D/tag/child, omitted/doubled/cache-hit demand, principal/return mismatch, all-HALT/skipped completion and forged END frames. Recompute dependent hashes/helpers so tests exercise the intended equation. **Checks:** `cargo test -p miden-processor --lib trace::tests::decoder`; `cargo test -p miden-processor --lib trace::tests::lookup`; `cargo test -p miden-air-definitions --lib vm::constraints::system`; generated degree/drift capture.

### PR 08 Deterministic replay, prefix relocation and debugger

**Branch:** `adr1anh/librarytree-08-replay-debug`. **Git base:** PR 07. **Semantic dependencies:** 05–07.

**Existing files:** `processor/src/{tracer.rs,trace/mod.rs,trace/execution_tracer.rs,trace/trace_state.rs,trace/block_stack.rs}`, trace-state serde/tests, `processor/src/trace/parallel/`, chiplets integration, fast/host debug and continuation stack; coordinate `crates/mast-package/src/debug_info/`.

Extend the existing versioned execution witness with immutable descriptor, entry binding, requested K/resolved D/mode/principal, bounded opening ledger and resolution IDs. Replay without host I/O, retaining multiplicities across cache hits/fragments. Use one checked final P_L conversion of typed logical Controller addresses, preserving stopped/resumed state and sentinels. Distinguish real EXEC activations from inline source frames and display K/D separately.

**Acceptance:** sequential/parallel/buffered/streamed/no-source parity at each invocation/pending/return cut; malformed/missing ledger IDs reject; normal+syscall shared opening counts survive; zero/sentinel/eight-row prefix boundaries and omitted/doubled offsets reject. Old/inconsistent witness versions fail clearly. **Checks:** `cargo test -p miden-processor --lib --features concurrent trace::parallel`; `cargo test -p miden-processor --lib trace::trace_state`; focused existing source-debug/step regressions and trace lookup checks.

## Stage 3 Toolchain and runtime contracts

### PR 09 Keyed assembly and package9 cutover

**Branch:** `adr1anh/librarytree-09-keyed-packages`. **Git base:** PR 08. **Semantic dependencies:** 02, 04, 05; proof checks require PR 12.

**Existing files:** `crates/assembly/src/{assembler.rs,procedure.rs,mast_forest_builder.rs,fmp.rs,instruction/procedures.rs,linker/}`, `crates/assembly-syntax/src/sema/passes/verify_invoke.rs`, `crates/mast-package/src/package/{manifest.rs,mod.rs,serialization/}`, debug-info provenance. Extend assembly tests for procref/procedures/dynamic/kernels/root calls/link cycles/imports/packages/locals; add `crates/assembly/src/tests/namespaced_execution.rs`.

Split identity resolution from body supply, runtime reachability/SCCs from acyclic inline dependencies, and retain all public/helper/address-taken roots. Emit K for every retained invocation/procref; explicit inline alone composes a body. Activate validated namespaced package9 metadata and MAST0.0.6 together across trusted/safe readers, commitments and strip-debug. Replace root-centric Program/kernel reconstruction, root-call lowering and hardcoded `$kernel` authority rather than wrap them.

**Acceptance:** Latest-only declarations compile without D; caller hash stable across selected implementations; pinned-only self/helpers work; bundled/external supply preserves K; runtime recursion compiles/inline cycles reject; callback roots survive retention; malformed homes/relocations/old serialized callable formats reject and required metadata survives debug stripping. Existing MASM invocation/procref source rebuilds under D2, using K and real EXEC without digest fallback. **Checks:** `make test-assembly test=namespaced_execution`; `cargo test -p miden-mast-package --lib package::serialization`; then `make test-assembly` and package lib tests after focused failures resolve.

### PR 10 Revision-aware projects and code supply

**Branch:** `adr1anh/librarytree-10-project-imports`. **Git base:** PR 09. **Semantic dependencies:** 04, 09 and exact release identity codec; model research can parallel PR 09.

**Existing files:** `crates/project/src/{dependencies.rs,dependencies/graph.rs,linkage.rs,package.rs,ast/dependency.rs,ast/package.rs,ast/parsing.rs}`, project tests, `crates/mast-package/src/dependency/mod.rs`, manifest, `crates/assembly/src/project/{dependency_graph.rs,runtime_dependencies.rs,build_provenance.rs,post_process.rs,tests.rs}`, linker module ownership and packaging fixtures. **New if justified:** `crates/project/src/library_import.rs`.

Separate source aliases, interface/release instances and code/artifact identity. Replace PackageId-only graph/manifest/cache ownership; encode independent Latest/Pinned selection and External/Bundle supply. Latest initially requires external supply. Replace single embedded-kernel-package propagation with ordinary declaration/mount requirements and separately authorized N_kernel. Reuse existing source/package registry infrastructure without turning it into an on-chain resolver.

**Acceptance:** two pinned revisions coexist with equal module paths/D; same `(I,r,R)` deduplicates and conflicting R rejects; Latest aliases share canonical identity; bundling never inlines/changes K; semver/Git revisions never become Protocol revisions; canonical self/helper mount requirements propagate. **Checks:** `make test-project`; `make test-assembly test=project::tests`; `cargo test -p miden-assembly --test packaging`.

### PR 11 Runtime ABI profiles and immutable resources

**Branch:** `adr1anh/librarytree-11-runtime-contracts`. **Git base:** PR 10. **Semantic dependencies:** 01, 04, 09, 10; affected code waits for open ABI/resource gates below.

**Existing files:** assembly syntax advice-map/sema, assembly FMP/memory lowering, mast-package manifest/serialization/commitments, `core/src/mast/mod.rs`, core-lib memory/hash helpers. **New if useful:** `crates/mast-package/src/package/resources.rs`, `crates/lib/core/asm/sys/resources.masm` and focused adversarial integration tests.

Encode the agreed runtime-base/profile/init/resource contracts in required metadata. Reuse current advice-map bytes and build a canonical validated public content inventory; private/transaction advice remains supported. Runtime immutable loads check compiled/authenticated length/codec and hash/assert expected content before use. Track upstream compiler lowering separately. Preserve EXEC/DYN modes; no implicit per-library memory isolation or runtime namespace inferred from caller principal.

**Acceptance:** the agreed randomized private-instance profile preserves committed C/D without patching code; resource key with malicious value/length rejects before use; inventory survives retention/debug stripping/export; invalid content-addressed public entries reject. **Checks:** focused new resource/ABI tests; `cargo test -p miden-mast-package --lib resources`; `make test-core-lib test=sys`; changed assembly suites. Undefined ABI choices remain gates, not untested assumptions.

## Stage 4 Statements, library and public interfaces

### PR 12 Native statement and proof transport cutover

**Branch:** `adr1anh/librarytree-12-native-statement`. **Git base:** PR 11. **Semantic dependencies:** 01, 06, 07; namespaced end-to-end fixtures use 09.

**Existing files:** `core/src/program/{mod,claim,domain,kernel}.rs`, `core/src/proof.rs`, `crates/air/source/src/vm/{inputs,statement,tests}.rs`, AIRs/public inputs/lookup miden AIR, generated VM adapters/config/security, `crates/stark/vm/src/{prover,verifier,security,memory}.rs`, setup/preprocessed, processor trace, prover/verifier APIs. **New:** `crates/stark/vm/tests/librarytree_statement.rs` or equivalent existing unit module.

Activate claim44/domain v2 in canonical order `K_entry[4] || R_E[4] || N_kernel[4] || I[16] || O[16]` and proof format3. Explicitly derive Core36 as `I || O || K_entry` and Chiplets8 as `R_E || N_kernel` from the expected caller claim, retaining deferred-only aux4. Replace program/kernel external terms with singleton root Open and keep two deferred terms. Remove variable kernel-list/count/security authority. This is the production relation enablement point; earlier runtime slices remain incomplete until these bindings close.

**Acceptance:** exact field/order/tail vectors; every mutated R_E/N_kernel/K_entry/I/O fails, including ordinary-only execution; old claims/transport/public shapes/fifth AIR reject; three external terms and one combined Chiplets normalized sum close; deferred/empty/complete precompile obligations persist. **Checks:** `cargo test -p miden-core --lib program::claim`; `cargo test -p miden-air-definitions --lib vm`; `cargo test -p miden-vm-stark --lib`; `cargo test -p miden-verifier --lib`; focused native prove/verify cases.

### PR 13 Core-library packaging and runtime migration

**Branch:** `adr1anh/librarytree-13-core-library`. **Git base:** PR 12. **Semantic dependencies:** 09–12 and supported ABI profile; final recursive identity follows in 14.

**Existing files:** `crates/lib/core/{build.rs,src/lib.rs,src/bin/generate-package.rs,asm/miden-project.toml}`, MASM public/helpers/callback tables including `asm/sys/vm/{mod,ood_frames}.masm` and `asm/stark/utils.masm`, core-lib tests/helpers/sys/forest merge, assembly packaging fixtures and affected generated-assembly builders.

Build the library at an explicit canonical home with declaration/release/mount/resource metadata. Retain callback/helper callable roots and migrate ordinary package/build/host consumers to keys. Choose inline opt-ins deliberately rather than auto-inline existing exec. Prepare verifier bundle metadata contracts; PR 14 owns recursive mathematics, final verifier identities/configurations and related generated artifacts to avoid overlapping ownership.

**Acceptance:** external/bundled pinned library executes equivalently; private callbacks survive retention/export; pinned-only helpers and Latest callers work; package/resource inventory survives artifact export; source-root stability tests reflect intentional new semantics. **Checks:** `make test-core-lib` for ordinary/core-library scopes that are runnable at this stage; `make test-masm-root-stability`; record recursive checks precisely as deferred to 14 where necessary.

### PR 14 Recursive verification and generated identities

**Branch:** `adr1anh/librarytree-14-recursive-verifier`. **Git base:** PR 13. **Semantic dependencies:** 06, 07, 09, 12, 13; native relation must be settled.

**Existing files:** `crates/stark/vm/src/recursive/mod.rs`, core-lib `asm/sys/vm/{mod,claim,public_inputs,layout,parameters,aux_trace,ood_frames,constraints_eval,deep_queries}.masm`, regeneration binaries/helpers, `crates/air/generated/{build.rs,src/vm/}`, core proof compatibility, generated core-lib docs and proof-order/scatter/security tests. **New:** `crates/lib/core/tests/stark/librarytree_claim.rs`, registered in existing test module.

Read exactly44 advice Felts into safe48-cell staging/isolated tail; hash six blocks with zero tail and no overread. Stage Core36/Chiplets8/three external terms; remove kernel-list materialization while retaining security/deferred results and all24 proof permutations. Regenerate evaluators/ACE/layouts/constants/docs/setup/relation roots; bind verifier entry and helper/resource/mount configuration, including N_kernel, rather than D alone. Replace old `procref == verifier root` APIs/docs with typed identities/request v2.

**Acceptance:** native/MASM/recursive claims match; adjacent scratch cannot affect hash; old/missing/excess advice fails; malicious child/rebound entry/helper/root/N_kernel and omitted deferred obligation reject. Captured degrees/shape/security counts match generated assets and rebuilt identity. **Checks:** `make regenerate-constraints`; `make check-constraints`; generated capture/drift/ACE tests; `cargo test -p miden-core-lib --test core-lib stark`; `cargo test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library`; `make check-pvm-proof-fixture`. Regenerate generated MASM docs with `MIDEN_BUILD_LIB_DOCS=1 cargo build -p miden-core-lib` when changed, following repository CI. Regenerate PVM constants/root only if its emitted code/relation changed.

### PR 15 Public API, CLI and consumer closure

**Branch:** `adr1anh/librarytree-15-cli-integration`. **Git base:** PR 14. **Semantic dependencies:** 08–14.

**Existing files:** `miden-vm/src/{lib,internal}.rs`, `miden-vm/src/cli/{compile,bundle,run,prove,verify,data,utils}.rs`, processor public API, `crates/test-utils/`, integration exec/prove_verify/flow_control/CLI suites, examples, fixtures and user/developer documentation.

Replace root-only verification flags and implicit Program/kernel reconstruction with explicit versioned expected descriptor/claim inputs. Share run/prove/verify validation; separate environment preimages from code bundles and report K_entry/R_E/N_kernel/D distinctly. Migrate remaining root consumers; report Library authentication metrics instead of kernel-ROM counts. Preserve atomic output, security estimator and precompile preparation/resource guards introduced since the design baseline.

**Acceptance:** run/prove/verify round trips across supported transcript hashes, stopped witnesses and deferred/complete proof paths; changed expected descriptor fields/legacy flags/artifacts fail explicitly; allocation/budget checks precede execution; optional code hints cannot override bindings. **Checks:** `make test-vm test=cli::`; focused `prove_verify::`/`flow_control::` filters in the existing `miden-cli` integration test binary; compile supported public and no_std surfaces. Run the final commands in PR 16 before declaring release readiness.

## Stage 5 Qualification and release evidence

### PR 16 Adversarial, performance and final qualification

**Branch:** `adr1anh/librarytree-16-qualification`. **Git base:** PR 15. **Semantic dependencies:** all implementation PRs and resolved release gates.

**Existing files:** processor decoder/lookup/full-matrix harness and parallel tests, generated capture/drift/ACE tests, VM prove_verify integration, core-lib proof-order/security suites, Stark security/memory accounting and registered `miden-vm/benches/build_trace.rs`. **New:** `miden-vm/tests/integration/librarytree.rs`, registered in existing integration main; a real VM proof benchmark registered explicitly in `miden-vm/Cargo.toml` if no existing harness supplies the required measurements. Add a concise checked-in qualification report only once measured evidence exists.

Qualify the actual implementation across shallow Lists/selective Merkle, mostly-unused large environments, repeated/cache-hit calls, equal-D aliases, Latest changes with stable callers, pinned self/helpers, randomized private instances, nested N_kernel/private descendants, root modes, resumed/parallel traces and boundary/overflow attacks. Combine native and actual recursive malicious-child tests with forged trace/lookup matrices. Builder/Protocol fixtures cover global uniqueness, trusted namespace admission and freshness; AIR membership tests must not claim those properties.

Measure opening rows/compressions separately from invocation/context and Protocol construction costs; report prefix rounding, combined padded Chiplets height, proving time/peak memory/proof bytes, native/recursive verification and DEEP/lookup/security counts. Compare cold/warm code and opening caches. Avoid unsupported speed/minimality claims.

**Final acceptance:** all required focused/adversarial tests pass; generated/manual/native/MASM/recursive constraints and identities agree; no host-only resolution, implicit digest authority, fifth AIR or old required wire layout remains; resource/security bounds and unresolved external obligations are documented. No deferred required check remains. Artifact regeneration leaves no diff and the final tip builds/lints/tests cleanly.

**Checks after power guards:** repository `make exec`, `make exec-single`, `make format-check`, `make clippy`, `make test`, `make check-constraints`, `make check-pvm-proof-fixture`, `make test-masm-root-stability`; supported no_std surfaces including `cargo check -p miden-core -p miden-mast-package -p miden-assembly --no-default-features`; affected bounded fuzz/benchmark commands selected from the actual final changed graph. New test filters throughout this plan are provisional until registered test names exist; prefer the repository Make target where it supplies necessary features/stack settings. Resolve focused failures before broad suites, and repeat broad checks only for new changes/failures. Record exact commands/toolchains/features, commit SHAs and outcomes in the ledger/report. Verify deterministic regeneration with `git diff --exit-code` after intended generated changes are committed.

## Resolved implementation decisions

**D1 Environment-node preimage codec, agreed with the user on 2 November 2026:** own a VM v1
record `version:u8=1 || kind:u8 || payload`, with Env=0, Mast=1, Data=2, Merkle=3, List=4.
Fixed payload fields follow the selected hash-payload order and use existing canonical 32-byte
Word encoding; Data's type is little-endian u32. List is a little-endian u32 child count followed
by child words. Decoding requires exact input and a caller-supplied resource budget. This wire
header/count encoding does not change the selected node hashes. Implement and test this codec
separately from hash-only constructors. Protocol-specific codecs remain outside this decision.

**D2 Existing MASM compatibility, clarified with the user on 2 November 2026:** preserve existing
MASM syntax and stack/memory calling conventions. Recompilation and new serialized MAST formats
are allowed. Callable references and `caller` use ProcedureKeys; `exec` becomes a same-context
runtime invocation. Migration may update hardcoded digest identities and hash/cycle-count
expectations without requiring new syntax for existing programs. Existing digest-shaped target
words use the key interpretation. Optional inline syntax remains an extension. Do not retain
runtime digest dispatch or infer an authenticated binding from code availability. This does not
require preserving child-ID invocation nodes, old serialized layouts or digest-based implementation
lookup. Include existing source and stack/memory regressions in PRs 04/05/09 and final qualification.

**D3 Interface identity, closure and external profile, reviewed with the user on 2 November 2026:**
Protocol supplies immutable LibraryId I and authenticates its association with the canonical
publisher-qualified descriptor and declaration commitment. Do not derive I from declarations or
invent an identity hash. Closure metadata is the complete finite transitive LibraryId set excluding
self; all direct external requirements are included, with self references implicit. This introduces
no VM-level interface-cycle prohibition. Completeness needs authenticated contributing declarations.
Publisher-descriptor canonicalization, permitted complete homes and the Protocol-local numbered-v1
domain allocation remain **mandatory external profile inputs, with no permissive fallback**.

Implement the reviewed generic InterfaceArtifact/Home v1 framing under that required profile:
canonical Word/label encodings; little-endian u32 lengths; exact EOF; declarations with nonempty
semantic Text paths and absent/present UTF-8 ABI; strict envelope-byte path order and canonical-Word
byte order for unique direct/closure sets. Artifact fields are version 1, I, declaration commitment,
length-prefixed canonical descriptor Q0 and declaration bytes DB. Commit `B(Q0)||DB` using standard
Eidos FeltSequence over `[1, byte_length, packed_u32_bytes]` in the profile-supplied Protocol domain;
Q0 excludes I, commitment and association proofs. Home is version 1 plus an explicit complete typed
path, including explicit empty N0. Require caller budgets and expected I/context; structurally valid
bytes alone supply no authority. Reuse core label/hash helpers, add no default home/domain/profile,
and do not activate package9 or a ReleaseRecord codec. Sources: assembly §§3.2, 5–7
(cached lines 172–211, 347–405, 445–465, 554–562, 720–766), shared §2, vmprotocol §7.
Production descriptor/domain/home fixtures remain external acceptance gates.

## Open decisions and external gates

| Gate | Required decision/evidence | Blocks |
| --- | --- | --- |
| Canonical cross-team wire contract | VM node preimages are resolved in D1; generic interface/home v1 and required external profile are recorded in D3. Obtain owner descriptor/domain/home fixtures; confirm remaining release/resource/user/random codecs and provenance. The VM owns generic labels/objects, not AccountId/registry parsing. | 01, 04, 10–12 |
| Frontend syntax and eligibility | Preserve existing MASM name/path/word syntax under D2. Agree optional explicit key/inline extensions, fixed-body inline eligibility and diagnostics for genuinely invalid forms; source alias versus published alias versus wrapper semantics. | 04, 09 |
| Private reusable-instance ABI | Freeze runtime-base handle transport, typed relative suffix/procref lowering and validation. C/D must remain identical across randomized user mounts; no implicit relocation or caller-derived namespace. | 11, private-instance acceptance |
| Shared/fresh-context ABI | Specify supported value/pointer layouts, global/heap/function-table ownership, initialization and reentrancy for supported libraries. Namespace authentication supplies no RAM isolation. Do not guess a fresh-context-only/stateless-only scope. | 11, 13, final supported launch claim |
| Protocol authority and admission | Agree canonical homes, user U reconstruction, root binding on public input stack, uniqueness checks, exact N_kernel authorization, release/resource admission and inclusion freshness evidence. | Protocol integration fixtures and release adoption |
| AIR feasibility | Capture actual global degree ≤9, namespace degree and complete `[4,4,3,2]` lookup groups; prove unit rooted provenance/no-wrap under combined bounds and typed address relocation. | 06–08, 12, 14, 16 |
| Verifier closure | Canonical entry/config/helper/resource/mount identity including authorized N_kernel; no self-identity fixed point or entry-D-only trust. | 12–14, recursive acceptance |
| Measured costs and limits | Agree representative workload/limit matrix; report actual overhead and guard allocations/counts/replay. | 16, release readiness |

If a gate requires a material shared decision, stop its dependent work, ask the user the concrete questions and record the exact unresolved choice. Continue independent preparation while waiting. Do not silently weaken the selected execution modes, security contract or supported scope to bypass it.

## Status ledger

All implementation rows begin planned. The first plan commit SHA and later exact evidence are filled by the orchestrator after commits/checks occur. No test was run to prepare this initial snapshot; later evidence must be recorded as implementation proceeds.

| PR | Status | Implementation/plan commit SHA | Passed evidence | Deferred checks or blocker |
| --- | --- | --- | --- | --- |
| 00 Plan | complete | `1411d8581` initial plan-only commit | Two independent source/design reviews; PR/branch structure and whitespace checks; staged `git diff --cached --check`; SSH signature verified | No Rust build/test needed for documentation-only scope |
| 01 Identities | complete | Latest `8152f9a34`; prior slice SHAs in evidence below | Independent reviews; 86 program tests including registry disjointness; final verifier fixture tests 12/12; public API fixtures; no-default-features, scoped rustfmt/Clippy; 36 shared vectors | None for PR 01; Protocol-specific codecs/authority remain outside this unit. |
| 02 MAST | implemented-awaiting-validation | Latest `364fbb35c`; generator `91d52f92c`; base `4f6cda599` | Independent reviews; 398 arbitrary-feature core tests, 198 default MAST tests, four explicit cycle/recursion cases, core seed generation, public API and full-feature Clippy pass | Processor witness checks await 05/09; fuzz smoke at 16. Restore environment-aware executable generator at 05. D2 preserves existing MASM source. |
| 03 Chiplet foundation | implemented-awaiting-validation | Latest `a8e0daec9`; state `997c5edae`; Memory `411b22f8b`; base `7602d32ed` | Memory unit/generated/Clippy checks pass; independent logical/physical/state/acceptance reviews and formatting | Twenty-five address/state tests authored, unrun; processor has ten known callable-cutover errors. Execute processor/parallel/serde suites after 05/09; actual Library prefix/alignment at 06. |
| 04 Toolchain contracts | in-progress | Encoding `a70fdc8b1`; Home `a4ceb8260`; syntax `8a02bc43c`; semantic `77ba2607a`; base `45be30b96` | Independent reviews; 38 interface-filter tests, full 327-test syntax suite, debug regression, scoped/combined test-inclusive Clippy, no-default-features and pinned formatting pass | Next strict artifact decoding. Production Protocol profile fixtures remain external gates; executable lowering at 09. |
| 05 Runtime | planned | — | — | Depends on 01–02, shared ledger contract |
| 06 Library | planned | — | — | Depends on 01,03, ledger; degree/soundness gates |
| 07 Core resolution | planned | — | — | Depends on 02,05,06; production needs12 |
| 08 Replay/debug | planned | — | — | Depends on 05–07 |
| 09 Assembly/packages | planned | — | — | Depends on 02,04,05 |
| 10 Projects/imports | planned | — | — | Depends on 04,09; release identity codec |
| 11 ABI/resources | planned | — | — | Explicit unresolved ABI/resource gates |
| 12 Native statement | planned | — | — | Depends on 01,06,07; fixtures09 |
| 13 Core library | planned | — | — | Depends on 09–12 and supported ABI |
| 14 Recursive verifier | planned | — | — | Depends on settled06–07,09,12–13 |
| 15 API/CLI closure | planned | — | — | Depends on 08–14 |
| 16 Qualification | planned | — | — | Entire stack and release gates |

## Implementation evidence

The domain audit found the selected environment/verifier allocations free in the current registry.
Verifier configuration mounts require explicit forward-coordinate lexicographic ordering; existing
`Word::Ord` compares coordinates in reverse and must not supply that canonical order. Add a vector
that distinguishes those orders when implementing the configuration codec.

### PR 01 Typed execution identities

Commit `bf840bc6d` adds the five opaque Word roles and `ExecutionDescriptor`, reusing canonical
Word serialization. An independent reviewer found no actionable issue. Existing Program and claim
activation remain assigned to the later cutover.

Passed on Rust 1.99.0 after successful AC/heavy-work guards:

- `cargo test --locked -p miden-core --lib program::environment`: one test, including all truncated
  lengths and a noncanonical value in each coordinate across all five roles.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --test public_api`: all three fixtures,
  including rejection of an implementation root in the descriptor's procedure-key slot. The new
  stderr was generated, inspected for the intended type mismatch, then verified without overwrite.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib -- -D warnings`.
- `cargo +nightly-2026-10-09 fmt -p miden-core -- --check` and staged whitespace checks.

### PR 01 Environment and verifier domains

Commit `ee4e7f937` registers the eleven selected domains without activating the later claim or
proof-request cutover. Independent review found no actionable issue. Frozen cryptographic vectors
were produced with an independent portable reference checked against existing generic vectors;
tests also compare literal IV/block framing to the production FeltSequence helper.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::domain`: five tests.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and whitespace checks.

### PR 01 Built-in canonical labels

Commit `6b27da605` adds retained Text/LibraryId/nonzero Revision preimages and ENV_LABEL hashing,
reusing the existing LE32 packer. Independent review found no actionable issue. This slice does not
complete label decoding, TypedId, environment objects or PR 01.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::label`:
  five tests, including nine independent frozen vectors and allocation-boundary checks without
  giant allocations.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- `cargo +nightly-2026-10-09 fmt -p miden-core -- --check` and staged whitespace checks.

### PR 01 Exact labels and external TypedId validation

Commit `3d389cf58` adds exact built-in decoding and explicit caller validation for opaque TypedIds,
including a synthetic-codec frozen vector. No AccountId codec or unknown-codec recognition is
assumed. Independent review found no actionable issue.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::label`:
  all eleven tests, including malformed framing/payloads, EOF and callback validation boundaries.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Namespace and procedure-key derivation

Commit `ed50330fc` adds allocation-free typed initial/child namespace and procedure-key helpers.
Independent review found no actionable issue; frozen vectors cover direct and accumulated parents.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::tests`:
  four tests, including three new derivation tests and the existing identity encoding test.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Owned environment object commitments

Commit `eda3053b4` adds one owned EnvNode representation for all five commitments, reused by the
following D1 codec slice. Independent review found no actionable issue. List flattening checks
framing/layout bounds before fallible allocation; commitments confer no completeness or authority.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::object`:
  five tests, including eleven frozen object cases and arithmetic-only allocation boundaries.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Exact budgeted D1 node codec

Commit `27e100e10` implements the user-approved D1 record format on the same owned EnvNode.
Independent review found no actionable issue. Whole-input budget checks prevent a valid prefix
from hiding suffixes when BudgetedReader exhausts its budget; hashes remain unchanged.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::object::encoding`:
  seven tests, including eleven frozen byte cases and malformed/budget/allocation boundaries.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Shared encoded-size preflight

Commit `295809479` extracts allocation-free EnvNode::encoded_len and makes encoding delegate,
preserving all size/layout/error semantics. Independent review found no actionable issue. The
existing frozen-vector test checks all eleven expected lengths without another encoding path.

Passed after successful AC/heavy-work guards: the seven focused codec tests, core Clippy
(`--lib --tests -- -D warnings`), no-default-features check, pinned-nightly formatting and staged
whitespace checks, using the exact commands in the preceding D1 evidence section.

### PR 01 Bounded preimage storage

Commit `8d0036dd7` adds explicit caller limits, internally committed owned-node storage and
transactional insert preflight. Independent review found no actionable issue. Duplicate accepted
work/bytes and retained List capacity/scratch are charged; this store does not certify completeness.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::builder`:
  thirteen tests for exact/one-short limits, capacity, duplicate work, arithmetic and failure atomicity.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Complete bounded occurrence validation

Commit `c67f3a963` adds consuming finish(root), immutable internally derived bindings and
iterative per-occurrence traversal. Missing reachable preimages and duplicate keys reject;
shared subtrees retain inherited namespaces at every occurrence. Independent review found no
actionable issue. This optional local utility confers no authority or executable availability.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::environment::builder`:
  thirty tests, including seventeen new completeness/uniqueness/occurrence/depth/work/storage cases.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Native verifier configuration

Commit `d79a6c34c` adds immutable typed mounts/configuration and the v2 commitment with mandatory
full N_kernel. Forward canonical-u64 sorting deliberately differs from Word::Ord; duplicate pairs
reject while same-namespace distinct fragments remain subject to external disjointness checks.
Independent review found no actionable issue. No claim/request/recursive activation is included.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::verifier`: nine tests,
  including independently frozen complete 14/22/30-Felt preimages and ordering/mutation/boundaries.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

### PR 01 Identity derivation and shared-vector closure

Commit `f02a64403` adds allocation-free typed verifier identity derivation with the exact
12-Felt preimage and registered v1 domain. Commits `649bb327e` and `8152f9a34` move frozen
expectations into `core/tests/fixtures/librarytree-vectors.txt`: 36 unique rows, with a small
test-only parser and no production codec/dependency. Future MASM host tests can consume the
same bytes/Felts/digests. All 32 previous environment/domain tests and production prefixes
were preserved. Independent identity, acceptance and fixture reviews found no actionable issue.
No MASM execution, recursive trust, claim/request cutover or root authority is claimed here.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program`: 86 tests, including
  registry disjointness, all environment slices and twelve verifier tests.
- After the final test-only verifier fixture migration:
  `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib program::verifier`: twelve tests.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --test public_api`: all three
  compile fixtures passed, including the D-versus-K compile failure.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`:
  passed again after the final fixture migration.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly core formatting and staged whitespace checks.

PR 01 acceptance is complete. D2 governs the following MAST/toolchain work; its source-compatibility
regressions remain PRs 04/09/final gates rather than an unimplemented PR 01 runtime claim.

### PR 02 EXEC opcode reservation

Commit `66c94030b` reserves control opcode 0x5f without adding a basic Operation or activating
runtime/AIR behavior. Independent review found no issue. After successful AC/heavy-work guards,
`CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib operations` passed thirteen tests,
including the deterministic pin/rejection, control strategy and exhaustive wire sweep. Core Clippy
(`--lib --tests -- -D warnings`), pinned-nightly formatting and staged whitespace checks passed.

The following node/API refactor intentionally precedes codec/test migration. Any observed
intermediate failure must be recorded before deferring its closure to the next PR 02 slice;
processor/assembler semantic migration remains PRs 05/09. No old digest authority is retained.

### PR 02 Childless keyed invocation nodes

Commit `7be0e06c0` directly replaces Call/SysCall child IDs with ProcedureKey targets, adds Exec,
and shares opcode-domain K||0 hashing. Traversal/remapping/fingerprints, forest recomputation and
sparse structural validation no longer treat invocations as structural edges. External(D) remains
structural. Independent review found no actionable issue; three calibrated frozen mode vectors
join the shared fixture (39 rows total). Five focused node tests are present but not yet runnable.

Pinned-nightly core formatting and staged whitespace checks passed. After successful AC/heavy-work
guards, `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --lib` failed with eight errors
in `serialization/info.rs` (old callee accessor/constructor types) and `serialization/sparse.rs`
(old callee accessor/constructor/build_linked). Raw log is uncommitted at
`.scratch/librarytree/logs/pr02-keyed-node-check.log`; short findings are separate.

This is intentional intermediate breakage allowed by the workflow, not passed acceptance. Complete
these codecs next in PR 02; then migrate old core tests/arbitrary constructors and run the pending
node/MAST/serialization checks and Clippy. Processor/assembler semantic consumers remain PRs 05/09.

### PR 02 Dense and sparse keyed codec closure

Commit `85171ecad` writes canonical key payloads for sparse Call/SysCall/Exec, adds sparse tag9,
and requires ExecutionWitness v3 before reading replay payloads. Direct sparse encoding remains
trusted/version-local; independent containment review found no other persisted sparse envelope.
Commit `9d80e8eaf` implements dense v0.0.6 with one shared layout scanner, canonical per-invocation
slots, separate target/external sections, hashless key retention and key-aware metadata/views.
The writer, materialization and bulk metadata are linear; wire target access is O(1). In-memory
single-entry metadata retains its documented existing prefix-scan tradeoff. Independent reviews
found no actionable issue. Seven sparse and thirteen dense tests are authored but not yet runnable.

Passed on the integrated codec working tree after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --lib`.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-core --no-default-features`.
- Pinned-nightly formatting and staged whitespace checks.

`CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib --no-run` fails with 42 errors
in legacy constructor/callee-ID fixtures: basic_block_node/arbitrary.rs (7), serialization/tests.rs
(7), merger/tests.rs (23), multi_forest_node_iterator.rs (4), mast/tests.rs (1). Full compiler log
is uncommitted at `.scratch/librarytree/logs/pr02-core-test-compilation.log`. Migrate those next,
then run the pending focused tests and test-inclusive Clippy. The earlier eight production codec
errors are resolved. Processor witness tests remain deferred until PRs 05/09 close downstream
invocation consumers; no processor test pass is claimed.

### Executable arbitrary-fixture integration obligation

The PR 02 generator migration preserves GenerationMode::Executable's runtime guarantee by
excluding unresolved immediate keyed invocations from that mode during the staged cutover.
StructureOnly continues to generate all keyed invocation modes with independent keys and explicit
retained code roots; it makes no executable-environment promise. The existing D-only KernelDescriptor
is metadata, not key authority. Do not weaken the executable guarantee to caller-supplied bindings.
PR 05 must supply an environment-aware executable fixture and update its sole processor consumer,
`processor/src/fast/tests/arbitrary_forest.rs`, restoring meaningful executable invocation coverage.
This is not a final testing or runtime scope reduction.

### PR 02 Fixture and generator migration validated

Commit `91d52f92c` migrates merger/traversal fixtures to independent symbolic keys and explicit
body roots, preserves structural replacement/error-code/ordering coverage, and adds all keyed
modes to structural generation. The executable-mode restriction and PR 05 restoration obligation
remain as documented above. Commit `90ef69d6d` migrates canonical v0.0.6 serialization expectations,
including malformed overflow/lazy-digest regressions, sparse keys and old-version rejection.
Independent review found no concrete issue. The previous 42 test-compilation errors are resolved.

After successful AC/heavy-work guards,
`CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib mast` passed 198 tests; one manual
fuzz-seed generator is intentionally ignored. This runs the five keyed-node, thirteen dense and
seven sparse tests for the first time, alongside existing MAST regressions. Test-inclusive Clippy
(`CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests -- -D warnings`),
pinned-nightly core formatting and staged whitespace checks passed. Full test log stays separate
at uncommitted `.scratch/librarytree/logs/pr02-mast-tests.log`.

### PR 02 Fuzz source and full-core qualification

Commit `9ebac7cc1` adds pre-serialization expected-key/mode oracles and full/hashless keyed seeds,
preserving the existing root-order and large-ID checks. Independent bounded review found no issue.
After successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib --features arbitrary`: 398 passed,
  one manual seed test ignored.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib --features arbitrary generate_fuzz_seeds -- --ignored --nocapture`: one passed. Generated MAST corpus stays local; two tracked Program seeds rewritten by the helper were restored, and final cross-stack corpus regeneration remains PR 16.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-core --lib --tests --features arbitrary -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --test public_api`: all three fixtures passed.
- Pinned formatting and staged whitespace checks.

Full test/seed logs stay separate under uncommitted `.scratch/librarytree/logs/`. Fuzz target
compilation/execution and processor witness tests are not claimed: their dependency graph still
contains downstream processor/assembler consumers owned by PRs 05/09, with bounded fuzz smoke at 16.
The final bounded acceptance audit found two evidence gaps to close now: explicit structural
self/two-node cycle rejection, and a self/mutually-recursive key binding fixture. Existing childless
tests support these by inference; add dedicated cases rather than claim those gates passed.

### PR 02 Explicit cycles and deferred integration disposition

Commit `364fbb35c` closes both final audit gaps with four test-only cases. Valid-ID corrupted
structural self/two-node loops reject with the exact cycle error, without claiming a real
cryptographic hash cycle. Self Call/Exec and mutual keyed recursion derive N/L/K before D,
construct complete bounded K→D environments and round-trip both wire modes without execution.
Independent review found no actionable issue.

After successful AC/heavy-work guards, both focused commands passed two tests each:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib --features arbitrary canonicalization_rejects_structural`.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-core --lib --features arbitrary keyed_recursion_tests`.

Full-feature test-inclusive Clippy and pinned formatting/staged whitespace checks passed again.
The earlier 398-test full-core pass predates these four added cases; no rerun is claimed.
PR 02 core acceptance is closed, but its row remains implemented-awaiting-validation until the
required cross-graph checks run. After PRs 05/09 close old invocation consumers, run the authored
`CARGO_NET_OFFLINE=true cargo test --locked -p miden-processor --lib trace::tests::witness_wire_rejects_unsupported_version`
and related witness round trips. `tools/miden-core-fuzz/Cargo.toml` directly depends on that
processor and assembly graph, so its build/smoke remains PR 16, not a claimed current pass.
The local stack may continue under the workflow's intentional intermediate-build allowance.

### PR 03 Memory inverse and delta simplification

Commit `411b22f8b` constrains the existing same-context/address flag directly and reuses it for
delta selection. Independent algebra review establishes the same accepted assignments in both
context cases; the old/new delta difference vanishes under the unchanged flag definition.
All six inverse/flag/delta emission positions and all other Memory equations remain unchanged.
The finite 7,560-assignment regression matrix complements that proof; it is not exhaustive field
enumeration. It retains non-Boolean address ratios on context changes and arbitrary same-key
read/read clock inverses. No helper columns or trace/writer layout changed.

Passed after successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-air-definitions --lib vm::constraints::chiplets`:
  eighteen tests.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-air --test constraint_capture --test generated_drift --test ace_codegen`:
  eighteen tests; one manual timing benchmark ignored. Generated/native values, degrees, capture
  structure and ACE lowering agree for the current relation.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-air-definitions --lib --tests -- -D warnings`.
- Pinned-nightly formatting and staged whitespace checks.

Logs stay separate under uncommitted `.scratch/librarytree/logs/pr03-*.log`. These checks do not
establish future packed Library dimensions/degrees/lookup bounds; those remain later measured gates.

### PR 03 Checked logical Controller-address owner

Commit `48896072b` distinguishes nullable one-based logical addresses from zero-based row cursors
and operation-log indices. Existing trace caps/errors bound checked span arithmetic before
append/replay/cache mutations. Hasher errors propagate; infallible hook failures reach the existing
clock-finalization error boundary. Exact-cap end cursors and absent zero remain representable.
Private row-count invariants and aligned MAX_TRACE_LEN justify infallible padding rounding.
No physical relocation, saved-state codec or global-clock conversion is activated in this slice.

Independent review found no concrete issue in the eight-file change and fourteen authored
boundary/atomicity tests. Pinned formatting and staged whitespace checks pass. After successful
AC/heavy-work guards, `CARGO_NET_OFFLINE=true cargo check --locked -p miden-processor --lib`
failed with ten known callable-cutover errors: six old callee() uses and four missing Exec arms
in execution/call.rs, execution/mod.rs, execution_tracer.rs and parallel/tracer/{mod,trace_row}.rs.
No address-type diagnostic was emitted. This is not a successful processor build or test pass.
The compiler log stays uncommitted at `.scratch/librarytree/logs/pr03-controller-owner-check.log`.

Address tests/processor Clippy remain deferred until PRs 05/09 close that graph. Final
materialization conversion is the next PR 03 slice; saved/replayed state must remain logical.

### PR 03 Final materialization boundary and validation disposition

Commit `997c5edae` makes saved decoder/block-stack/node-end/Hasher replay addresses nominally
logical with the existing canonical Felt wire encoding. Compact wire-size bounds remain explicit
for budgeted readers. Commit `a8e0daec9` shares one checked immutable ChipletsLayout after
buffered/prebuilt convergence, applying physical conversion only at final Core/helper/chiplet
row emission. Only Controller address roles change; VM clocks, context/RAM/overflow values and
unrelated inverses remain untouched. Current decoder has no Controller-address inverse helper.
The final host into_traces writer is crate-private/fallible, with its sole repo caller updated;
no infallible compatibility wrapper bypasses layout errors.

Independent saved-state, final-sink and acceptance reviews found no concrete remaining gap.
Pinned formatting and staged whitespace checks passed. Eleven additional physical/state cases
join the fourteen logical-owner cases, all authored but unrun. Production prefix is zero; synthetic
17/11 prefixes test coordinate ownership, not valid Library AIR. PR 06 must implement actual
P_L=8*ceil((R+2)/8), terminal PAD pair, phase-seven exit and nonzero-prefix proof checks.

After successful AC/heavy-work guards, the integrated
`CARGO_NET_OFFLINE=true cargo check --locked -p miden-processor --lib` again reports exactly the
same six callee() and four missing-Exec cutover errors, with no address diagnostic. No standalone
build is claimed for the intermediate nominal-state commit. Full log is uncommitted at
`.scratch/librarytree/logs/pr03-physical-layout-check.log`.

PR 03 remains implemented-awaiting-validation. After PRs 05/09 close consumers, run processor
lib filters trace::chiplets::layout::tests, trace::chiplets::hasher, trace::chiplets::memory,
trace::execution_tracer::controller_address_tests, tracer::physical_helper_tests and trace::trace_state;
run `cargo test -p miden-processor --lib --features concurrent trace::parallel` and processor Clippy.
Apply the standard AC/heavy-work guards to every command. Final packed shape/degree/lookup/four-AIR,
D2 source/stack/memory regressions and clean regeneration remain PRs 06/later/16 gates.

### PR 04 Declaration model and reviewed profile boundary

Commit `5435a9cab` adds declaration-only paths/ABI/tooling signatures and explicit typed NamespacePlan
homes, deriving keys with existing core helpers without body/D/forest. Independent review closed a
forward/reverse quote-parsing discrepancy: validate the exact retained forward local spelling rather
than a reverse suffix. Commit `ba9f981d5` independently repairs the existing debug-remapping fixture
with a structural Loop parent, preserving non-root remapping coverage without casting D to K.

After successful AC/heavy-work guards, these current-tree commands passed:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib interface`: 13 tests.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib test_package_source_debug_merge_remaps_non_root_execution_nodes`: one test.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-mast-package --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-mast-package --no-default-features`.
- Pinned-nightly package formatting and whitespace checks.

D3 records the user's shared-contract decisions. Protocol namespace 0x02 is reserved to its owner;
no local Protocol registry is present here, and narrow connected-source searches do not prove an ID
free. Generic codecs require an explicit validating profile and externally allocated domain, not a
VM allocation or permissive policy. The uncommitted working draft and research are reference notes;
this plan owns decisions/acceptance, code owns exact implemented wire behavior, and the current brief
owns handoff. Actual production descriptor/domain/home fixtures remain external gates.

### PR 04 Semantic paths, source compatibility and Home v1 validated

Commit `77ba2607a` shares procedure semantic-character validation and adds bounded decoded public
paths without escaping/reparsing. Source construction retains exact forward-spelling validation.
Independent review passed; 17 package interface-filter tests and scoped package Clippy passed.
Commit `26342ece3` mechanically moves unchanged tests after the feature-gated Arbitrary implementation,
closing the subsequent syntax test-inclusive Clippy ordering lint.

Commit `8a02bc43c` repairs word-form procref printing, retains existing invocation grammar/legacy AST
shape, and documents key literals without authority. Seven new tests cover all invocation forms,
canonical/63-digit word spelling, malformed words and accepted quoted names. Independent review
closed a test helper that reinterpreted a Symbol as a Path. Initial source fixtures assumed quoted
Unicode/backslash tokens were names; the existing CST lexer classifies them as strings. Accepted
source fixtures were corrected, while semantic declarations retain exact Unicode/backslash tests.
Reconcile this source-token/decoded-path distinction during PR 09 frontend lowering; no restriction
was added or made a new acceptance requirement. Actual keyed assembly lowering remains PR 09.

Commit `a4ceb8260` adds explicit finite logical codec limits and required external TypedId/Home
profiles, then exact Home v1 encoding/decoding. Explicit empty N0 still requires permission; final
home validation follows EOF. Twelve new budget/malformed/profile/frozen-vector tests pass. Independent
review found no issue. Bounds do not promise RSS limits or fallible allocation inside reused core
label copies. No AccountId parser, production policy/domain/default, or package9 activation is added.

After successful AC/heavy-work guards, current combined-tree checks passed:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib interface`: 29 tests.
- `CARGO_NET_OFFLINE=true make test-assembly-syntax`: all 327 tests, including the seven new invocation tests and two semantic-validator tests, checked-in MASM corpus and printed-corelib parser regressions.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-mast-package -p miden-assembly-syntax --lib --tests --features miden-assembly-syntax/testing,miden-assembly-syntax/serde -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-mast-package --no-default-features`.
- Pinned-nightly targeted formatting and staged whitespace checks.

The first Make attempt lacked cached metadata dependencies; the sandbox retry could not write Cargo's
external registry cache. An approved cache-filling rerun enabled the normal offline checks. These were
environment failures, followed by the addressed test/lint issues above; no failed check is counted as
passing. Logs remain separate under uncommitted `.scratch/librarytree/logs/`. Nine canonical reference
snapshots match their recorded provenance hashes; the superseded wire draft is archived outside routine
input. Continue with D3 verified artifact encoding and then exact decoding, retaining external production
profile fixtures and all later processor/AIR/proof gates.

### PR 04 Verified interface construction and encoding validated

Commit `a70fdc8b1` adds opaque LibraryId/DeclarationCommitment roles and immutable InterfaceArtifactV1
construction/encoding with required external descriptor, immutable-association and closure validation.
The typed profile supplies its allocated Protocol numbered-v1 FeltSequence domain; generic namespace/
version checks do not establish allocation ownership. Encoding recomputes stored C before contextual
authority callbacks. Exact optional ABI, canonical envelope-vector path ordering and Word-byte ID
ordering are committed; tooling signatures remain outside wire/hash/authority. No decoder or production
Protocol profile is claimed. Native ID input order canonicalizes; duplicate IDs reject.

Two independent wire/resource and authority/domain reviews found no correctness issue. Nine new tests
include literal DB/hash preimages, 255/256-byte envelope ordering and authority short-circuit sequences.
An independent Python reconstruction agrees with the literal DB/DCL and fourteen-Felt payload; the
test domain is explicitly synthetic, not a production allocation. Artifact dependency wiring changes
only one existing Cargo.lock edge. A test-only hex-helper Clippy lint was fixed without a suppression.
After successful AC/heavy-work guards, final current-tree checks passed:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib interface`: 38 tests.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-mast-package --lib --tests -- -D warnings`.
- `CARGO_NET_OFFLINE=true cargo check --locked -p miden-mast-package --no-default-features`.
- Pinned-nightly targeted formatting and whitespace checks.

Strict decoding follows as its own commit: exact outer/nested EOF, expected I and stored-C checks,
canonical wire ordering without silently sorting input, bounded parsing and authority callback suppression
on malformed data. Reuse core labels and shared envelope extraction without invoking TypedId validators
for disallowed declaration-path tags. Retain production profile fixtures and all later security gates.
