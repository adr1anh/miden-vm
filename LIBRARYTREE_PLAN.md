# LibraryTree VM implementation plan

This plan is the current execution backlog for implementing the selected LibraryTree model in this repository. Once the plan is established, start implementation under the workflow below. This initial plan snapshot contains documentation only: no production implementation, compilation, tests, benchmarks or regeneration is claimed.

The repository baseline is `00b12150715891582864d256ef51c5ea46bfb282`, inspected on 2 November 2026. The design chapters use the earlier baseline `a3d9bc09ef8a956774eb4ec0e6e734428e194a8c`; source paths and interfaces below follow this checkout. The live design Pages remain unchanged.

## Sources and authority

Read the linked design chapters when implementing their contracts. This plan selects implementation boundaries; it does not silently decide remaining Protocol policy or compiler ABI questions.

**Scope and identity clarification, 3 November 2026:** implement VM/toolchain support without implementing a Protocol registry. Generic APIs may consume opaque typed LibraryIds, declarations and explicit homes. D3 retains the Pages' selected identity/interface formulas and permanent registration binding: any Protocol profile must derive/verify that identity and satisfy its required external validation gates. The earlier opaque-assignment decision and wording treating the Page formulas as historical are superseded. Do not invent an identity codec/domain or make Protocol metadata mandatory for generic compilation. Preserve every existing security and acceptance gate; continue independent VM work while external inputs remain pending.

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
9. **Toolchain separation:** an opaque typed ID at the generic API boundary, declarations, explicit namespace home, code materialization and source aliases are separate. Derive K from the supplied home/export labels without requiring D or an interface commitment. Protocol-profile identity and registered-release validation must satisfy D3; generic consumers need not implement a registry. Bundling does not imply inlining. Retain all public/helper/address-taken callable roots. Final runnable artifacts contain no unresolved namespace relocations.
10. **Witness and resource trust:** host resolution/code loading supplies witnesses. AIR authenticates resolution; guest resource loaders must authenticate advice values before use. Code loading retains current requested-D/procedure-root checks and merge-advice-once behavior. Debug metadata never grants authority.

Included: core identities/MAST, processor and replay, packed AIR/proofs, assembler/project/package changes needed for opaque typed IDs/declarations/explicit homes, existing calling conventions, core library, public API/CLI, adversarial qualification and measured costs. Protocol registry/account implementation remains external; its selected identity/interface semantics are D3, not undecided policy. Exact owner-supplied codecs/domains, publisher/home/profile validation, registration and authenticated closure remain required before claiming Protocol-profile acceptance. Existing prototypes do not establish it. Upstream Rust compiler lowering is a tracked handoff where its source is outside this repository. Do not claim these external obligations are solved by the VM or weaken their validation to unblock generic consumers.

## Workflow and completion rules

The first goal commit contains this plan only. Subagents perform the main research, implementation and review work; the orchestrator owns integration, signed commits, branch transitions and acceptance. Prefer fresh bounded agents (`fork_turns: none`) with explicit task/file ownership, applicable user/repository instructions and selected references. Assign an independent reviewer who did not implement the change. Subagents must not commit or switch branches unless the orchestrator explicitly delegates that responsibility.

Use `LIBRARYTREE_CURRENT.md` for the current handoff, then read only the active PR and relevant invariant/spec sections it names. This plan remains the sole backlog/scope/dependency/acceptance authority, and its ledger/evidence owns durable completion. The brief is not a second status ledger. Routine source snapshots live in uncommitted `.scratch/librarytree/reference-cache/` with Page/date/SHA-256 provenance; superseded proposals/handoffs and raw artifacts are reference-only archives, not agent input. Preserve shared temporary sources for other readers.

Use one local branch per proposed PR in a **linear stack**: PR NN has PR NN−1 as its Git parent/base, even when its semantic dependency list is shorter. Research and design can proceed in parallel according to semantic dependencies; shared-worktree edits must have clear ownership. Branch names below are exact defaults using the required `adr1anh/` prefix. PR 00 starts from the baseline. Keep incomplete/noncompiling units as an unsubmitted local stack with deferred checks recorded. **Do not create any GitHub PR, including a draft, until the user explicitly says to do so.** No push or publication is required to execute the local stack.

The deferred AIR/Chiplets cleanup inserts PR 15a between PR 15 and PR 16; existing numbers and
completed branch history stay unchanged. PR 16 qualifies the final post-cleanup relation.

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

PR 15a revisits Controller counter/address ownership and removes relocation machinery if the
validated cleanup makes it unnecessary. This follow-up does not waive PR 03's outstanding checks.

**Acceptance:** sequential/parallel traces agree; old/new Memory equations agree in context-change cases; writes preserve untouched slots/read-only/range rules; address conversion occurs once including valid logical zero and saved/replayed states; native/generated evaluator values/order/degrees agree. **Checks:** `cargo test -p miden-air-definitions --lib vm::constraints::chiplets`; `cargo test -p miden-processor --lib --features concurrent trace::parallel`; `cargo test -p miden-air --test constraint_capture --test generated_drift --test ace_codegen`.

### PR 04 Namespace plans and declaration-only interfaces

**Branch:** `adr1anh/librarytree-04-toolchain-contracts`. **Git base:** PR 03. **Semantic dependencies:** 01. Protocol-owned interface codecs remain required external inputs for Protocol-profile acceptance, independently of generic declaration/home support.

**Existing files:** `crates/assembly-syntax/src/{module.rs,ast/invocation_target.rs,ast/instruction/mod.rs,ast/instruction/print.rs,parser/cst/instructions.rs}`, parser/sema tests, `crates/mast-package/src/{lib.rs,package/manifest.rs,package/mod.rs}`. **New:** `crates/mast-package/src/{interface.rs,namespace_plan.rs,interface/serialization.rs}` as needed. Touch CST lexer/parser only if selected explicit-key/inline syntax requires it.

Separate canonical declarations and optional body availability; add validated NamespacePlan/interface-only artifact and preserve existing key-literal/name/path forms. Explicit inline syntax remains optional. Preserve exact-byte optional ABI metadata separately from tooling FunctionType. Do not invent placeholder D/forest or activate a partially migrated package9 executable. Reuse existing parsed Path components and core hashes.

Under D3, generic compilation may consume an opaque typed ID, declarations and explicit home without publisher metadata or registered association/closure proofs. The Protocol profile must derive/verify the Page-defined I and validate its interface association and closure. Existing InterfaceArtifact/Profile code is a prototype, not production acceptance; separate mandatory generic-consumer coupling at a focused implementation checkpoint while preserving validation and tests.

**Acceptance:** declaration-only Latest keys need no D; quoted `::`, exact Unicode bytes, typed labels and absent/present-empty ABI differ correctly; unknown versions/malformed homes reject; existing name/path/word invocation syntax remains accepted, with digest-shaped words interpreted as keys under D2. Explicit inline opt-in is an optional extension. **Checks:** `make test-assembly-syntax`; `cargo test -p miden-mast-package --lib interface`; CST tests only if changed.

## Stage 2 Authenticated execution and relation

### PR 05 Keyed runtime and atomic transitions

**Branch:** `adr1anh/librarytree-05-keyed-execution`. **Git base:** PR 04. **Semantic dependencies:** 01, 02; agree resolver/Resolve ledger schema with PRs 06–07.

**Existing files:** `processor/src/execution/{mod,call,dyn,external}.rs`, `processor/src/fast/{mod,operation,execution_api,step}.rs`, processor/executor/options/errors/continuation stack, host/default/forest store and public exports. **New:** small shared resolver/EXEC modules and bounded environment witness provider; focused public `processor/tests/keyed_execution.rs` and `processor/tests/keyed_witness.rs` with a shared single-Mast fixture. Extend the core arbitrary fixture with an authenticated environment and migrate `processor/src/fast/tests/arbitrary_forest.rs` so executable generation covers actual keyed invocations again.

Resolve `(R_E,K)->(N,D,opening)` before typed D-indexed code loading. Share prepare/commit transitions across pure/source-aware and sync/async execution; authenticate before state changes and make retries idempotent. Implement ENTRY/all runtime modes, requested-key caller/principals, context/FMP/overflow/return behavior and checked budgets. Remove kernel-ROM/digest dispatch authority. Cache bindings by `(R_E,K)`, code by D, and preserve code-root checks/advice merge-once.

**Acceptance:** complete mode/context/principal/local/host-loaded matrix; same-D aliases distinct; no fallback; wrong syscall namespace/descendant rejects; unknown key versus unavailable/bad D differ; cache/root/limit boundaries and failures/retries do not double-pop/save/charge. **Checks:** `cargo test -p miden-processor --lib environment`; `cargo test -p miden-processor --lib fast::tests`; focused existing source-debug/cache/aggregate-stack regressions. The environment-aware executable generator must exercise retained keyed invocations with valid bindings and bounded terminating call graphs, rather than leaving the temporary PR 02 structural-only restriction in place. Runtime success alone is not proof acceptance.

### PR 06 Packed Library witness and authenticated lookup

**Branch:** `adr1anh/librarytree-06-packed-library`. **Git base:** PR 05. **Semantic dependencies:** 01, 03 and PR 05 ledger contract; synthetic ledgers allow earlier research.

**New:** `crates/air/source/src/vm/constraints/chiplets/library/{mod,columns,tests}.rs`, `crates/air/source/src/vm/constraints/lookup/buses/library.rs`, `crates/air/source/src/vm/trace/chiplets/library.rs`, `processor/src/trace/chiplets/library/{mod,trace,tests}.rs`. **Existing:** chiplet selectors/columns/Memory/ACE/hasher control, lookup messages/buses, main trace schema, chiplet/parallel assembly and `processor/src/trace/tests/lookup.rs`.

Implement two-row Env/Merkle/Mast, complete reverse Lists, unit Open edges, normal/syscall Resolve frequencies, local four-coordinate syscall equations, compression interning and checked counts. Realize selected packed bands, 22 Library cells, ninth periodic column and `[4,4,3,2]` lookup groups without a fifth AIR or new Chiplets auxiliary column. Finalize prefix before physical address conversion.

Keep this implementation as the integration baseline. After functional integration through PR 15,
PR 15a revisits physical region order, clock ownership and trace packing; no redesign is required in
the current in-flight work, and every existing security/acceptance gate still applies.

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

Generic package metadata covers the opaque typed library ID and naming/callable/code information needed by VM/toolchain consumers, independently of Protocol artifacts. This separation grants no Protocol admission: its profile must derive/verify D3's I and validate publisher/home, immutable interface association, release and closure inputs before acceptance. Missing required naming/code metadata still rejects. Preserve independent callable-root retention and the in-flight builder/frontend/graph work.

**Acceptance:** Latest-only declarations compile without D; caller hash stable across selected implementations; pinned-only self/helpers work; bundled/external supply preserves K; runtime recursion compiles/inline cycles reject; callback roots survive retention; malformed homes/relocations/old serialized callable formats reject and required metadata survives debug stripping. Existing MASM invocation/procref source rebuilds under D2, using K and real EXEC without digest fallback. **Checks:** `make test-assembly test=namespaced_execution`; `cargo test -p miden-mast-package --lib package::serialization`; then `make test-assembly` and package lib tests after focused failures resolve.

### PR 10 Revision-aware projects and code supply

**Branch:** `adr1anh/librarytree-10-project-imports`. **Git base:** PR 09. **Semantic dependencies:** 04, 09. Exact Protocol release codecs remain external inputs; generic dependency-instance support can proceed independently.

**Existing files:** `crates/project/src/{dependencies.rs,dependencies/graph.rs,linkage.rs,package.rs,ast/dependency.rs,ast/package.rs,ast/parsing.rs}`, project tests, `crates/mast-package/src/dependency/mod.rs`, manifest, `crates/assembly/src/project/{dependency_graph.rs,runtime_dependencies.rs,build_provenance.rs,post_process.rs,tests.rs}`, linker module ownership and packaging fixtures. **New if justified:** `crates/project/src/library_import.rs`.

Separate source aliases, opaque typed library IDs, dependency instances, explicit namespace bindings and optional code/artifact supply. Replace PackageId-only graph/manifest/cache ownership where it prevents distinct bound artifacts from coexisting. Bundling supplies code without changing K or implying inlining. Propagate required callable/helper mounts and separately authorized N_kernel. Generic consumers need not implement registry storage or release codecs. Protocol adapters must retain D3: revisions may change bodies/helpers/pinned choices, while retained Latest dependencies remain dynamic; validate required release/closure inputs before claiming that behavior.

**Acceptance:** distinct explicitly bound dependency instances coexist with equal module paths or D; ambiguous/conflicting callable bindings reject rather than selecting a body from an alias or ID alone; bundled/external code preserves K and runtime invocation semantics; source semver/Git provenance remains separate from runtime naming; required self/helper mounts propagate. Do not freeze a new generic artifact-ID or release-history algorithm merely to support this. **Checks:** `make test-project`; `make test-assembly test=project::tests`; `cargo test -p miden-assembly --test packaging`.

### PR 11 Runtime ABI profiles and immutable resources

**Branch:** `adr1anh/librarytree-11-runtime-contracts`. **Git base:** PR 10. **Semantic dependencies:** 01, 04, 09, 10; affected code waits for open ABI/resource gates below.

**Existing files:** assembly syntax advice-map/sema, assembly FMP/memory lowering, mast-package manifest/serialization/commitments, `core/src/mast/mod.rs`, core-lib memory/hash helpers. **New if useful:** `crates/mast-package/src/package/resources.rs`, `crates/lib/core/asm/sys/resources.masm` and focused adversarial integration tests.

Preserve existing advice-map bytes, private/transaction advice and supported calling conventions. Runtime immutable loads check compiled/authenticated length/codec and hash/assert expected content before use. If an additional runtime-base/init/resource profile is explicitly adopted, specify its metadata and validated inventory then. Track upstream compiler lowering separately. Preserve EXEC/DYN modes; no implicit per-library memory isolation or runtime namespace inferred from caller principal.

Under superseding D3, Protocol-specific private-instance, initialization and resource-inventory schemas are deferred. Preserve D2 and existing supported calling conventions and advice integrity. Additional ABI metadata or randomized-instance support becomes a requirement only for an explicitly selected supported feature; do not make that optional integration a prerequisite for the minimum VM.

**Acceptance:** existing supported calling/advice conventions remain valid; resource key with malicious value/length rejects before semantic use; any supported content-addressed entries are validated and retained through export. Randomized-instance C/D stability and profile-specific inventory/init checks apply only if that extension is adopted; do not claim unsupported behavior. **Checks:** focused resource/calling-convention tests, changed assembly suites and `make test-core-lib test=sys`; new profile test targets are conditional on adoption. Undefined optional ABI choices do not block the minimum VM or become untested guarantees.

## Stage 4 Statements, library and public interfaces

### PR 12 Native statement and proof transport cutover

**Branch:** `adr1anh/librarytree-12-native-statement`. **Git base:** PR 11. **Semantic dependencies:** 01, 06, 07; namespaced end-to-end fixtures use 09.

**Existing files:** `core/src/program/{mod,claim,domain,kernel}.rs`, `core/src/proof.rs`, `crates/air/source/src/vm/{inputs,statement,tests}.rs`, AIRs/public inputs/lookup miden AIR, generated VM adapters/config/security, `crates/stark/vm/src/{prover,verifier,security,memory}.rs`, setup/preprocessed, processor trace, prover/verifier APIs. **New:** `crates/stark/vm/tests/librarytree_statement.rs` or equivalent existing unit module.

Activate claim44/domain v2 in canonical order `K_entry[4] || R_E[4] || N_kernel[4] || I[16] || O[16]` and proof format3. Explicitly derive Core36 as `I || O || K_entry` and Chiplets8 as `R_E || N_kernel` from the expected caller claim, retaining deferred-only aux4. Replace program/kernel external terms with singleton root Open and keep two deferred terms. Remove variable kernel-list/count/security authority. This is the production relation enablement point; earlier runtime slices remain incomplete until these bindings close.

**Acceptance:** exact field/order/tail vectors; every mutated R_E/N_kernel/K_entry/I/O fails, including ordinary-only execution; old claims/transport/public shapes/fifth AIR reject; three external terms and one combined Chiplets normalized sum close; deferred/empty/complete precompile obligations persist. **Checks:** `cargo test -p miden-core --lib program::claim`; `cargo test -p miden-air-definitions --lib vm`; `cargo test -p miden-vm-stark --lib`; `cargo test -p miden-verifier --lib`; focused native prove/verify cases.

### PR 13 Core-library packaging and runtime migration

**Branch:** `adr1anh/librarytree-13-core-library`. **Git base:** PR 12. **Semantic dependencies:** 09–12 and preserved supported calling conventions; final recursive identity follows in 14.

**Existing files:** `crates/lib/core/{build.rs,src/lib.rs,src/bin/generate-package.rs,asm/miden-project.toml}`, MASM public/helpers/callback tables including `asm/sys/vm/{mod,ood_frames}.masm` and `asm/stark/utils.masm`, core-lib tests/helpers/sys/forest merge, assembly packaging fixtures and affected generated-assembly builders.

Build the library with its supplied opaque ID, explicit home, declarations and required callable/mount/code metadata. Retain existing advice/resources and callback/helper callable roots; migrate ordinary package/build/host consumers to keys. Protocol release records or new inventory/profile schemas are conditional on a future adapter, not generic packaging requirements. Choose inline opt-ins deliberately rather than auto-inline existing exec. Prepare verifier bundle metadata contracts; PR 14 owns recursive mathematics, final verifier identities/configurations and related generated artifacts to avoid overlapping ownership.

**Acceptance:** external/bundled supply under the same explicit bindings executes equivalently; private callbacks and required helpers survive retention/export; declaration-only callers can use a changed authenticated implementation without changing their keys; required package/code/advice data survives artifact export; source-root stability tests reflect intentional new semantics. Registered Latest/Pinned and profile-specific inventory tests apply only to an adopted adapter. **Checks:** `make test-core-lib` for ordinary/core-library scopes that are runnable at this stage; `make test-masm-root-stability`; record recursive checks precisely as deferred to 14 where necessary.

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

## Stage 5 AIR cleanup, qualification and release evidence

### PR 15a Revisit AIR and Chiplets trace cleanup

**Branch:** `adr1anh/librarytree-15a-air-cleanup`. **Git base:** PR 15. **Semantic dependencies:**
03, 06–08 and functional/native/recursive/public integration through 12–15. Planned follow-up;
do not create this branch or interrupt current implementation now.

Revisit the AIR/trace choices from PRs 03/06–08 against the integrated system. The preferred
direction is a Controller-owned one-based address counter: anchor it at Controller entry, increment
only within Controller, preserve absent-zero semantics and evaluate reusing its cell outside that
region. It need not equal the global Chiplets row number. Review Controller-first/Library-second
against Library-first with a local counter; choose and record the validated simpler design rather
than assuming physical order follows selector priority. Simplify selectors, overlays, writers,
initialization and replay/address adapters; remove physical-prefix retagging if no longer needed.

**Acceptance:** preserve 24 main/four auxiliary columns, four AIRs, nine periodics, `[4,4,3,2]`
lookup capacity and measured degree≤9. Preserve rooted unit Open, every Resolve demand, complete
Lists, full syscall namespace checks, statement/deferred obligations, resource bounds and D2.
Keep Core/Memory/ACE operation clocks separate from Controller addresses. Test counter forgery,
entry/exit/reentry, A/B and eight-row alignment, padding, sentinels and stopped/parallel replay.
Capture actual MAIN/extension/lookup degrees and compare padded height and trace behavior.

Own regeneration and rebinding of every affected native/generated/MASM/recursive evaluator,
layout, constant, relation root and verifier identity after PR 14's initial migration; update PVM
artifacts only if its emitted code/relation changes. Require focused adversarial checks, native/
recursive parity and clean regeneration before PR 16. Record the chosen layout and evidence in
this ledger. Existing deferred checks remain required; cleanup is not a substitute for them.

### PR 16 Adversarial, performance and final qualification

**Branch:** `adr1anh/librarytree-16-qualification`. **Git base:** PR 15a. **Semantic dependencies:** all implementation PRs, completed PR 15a cleanup and resolved release gates. Qualify the final post-cleanup relation and regenerated identities.

**Existing files:** processor decoder/lookup/full-matrix harness and parallel tests, generated capture/drift/ACE tests, VM prove_verify integration, core-lib proof-order/security suites, Stark security/memory accounting and registered `miden-vm/benches/build_trace.rs`. **New:** `miden-vm/tests/integration/librarytree.rs`, registered in existing integration main; a real VM proof benchmark registered explicitly in `miden-vm/Cargo.toml` if no existing harness supplies the required measurements. Add a concise checked-in qualification report only once measured evidence exists.

Qualify the actual implementation across shallow Lists/selective Merkle, mostly-unused large environments, repeated/cache-hit calls, equal-D aliases, changed authenticated implementations with stable callers, explicit self/helper bindings, nested N_kernel/private descendants, root modes, resumed/parallel traces and boundary/overflow attacks. Combine native and actual recursive malicious-child tests with forged trace/lookup matrices. Builder tests establish global executable-path uniqueness; caller-selected descriptor authority is explicit. Registered Latest/Pinned, randomized private-instance and Protocol admission/freshness fixtures apply only to future adopted adapters, not minimum VM completion. AIR membership must not claim those external properties.

Measure opening rows/compressions separately from invocation/context costs; report prefix rounding, combined padded Chiplets height, proving time/peak memory/proof bytes, native/recursive verification and DEEP/lookup/security counts. Compare cold/warm code and opening caches. Report Protocol construction costs only for an adopted adapter. Avoid unsupported speed/minimality claims.

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

**D3 Page-defined identity and required Protocol profile, reaffirmed by the user on 3 November
2026:** this supersedes the earlier Protocol-assigned opaque-I decision and the later wording
treating the Page formulas as historical. Retain the LibraryTree Space's actual formulas:

```text
LibraryId = H_LIBRARY(publisher_id, name, interface_version)
interface_comm = CommitLibInterface(publisher_id, name, interface_version,
    List(proc_exports), List(dynamic_deps), List(dynamic_deps_closure))
```

Registration permanently associates LibraryId with that interface commitment. I is independent of
implementation bodies, private helpers, release revision and pinned dependency choices. Changes
to public API or declared dynamic dependencies require a new interface version. Release revisions
may change implementations, private helpers and pinned dependencies; retained Latest dependencies
remain dynamic. Do not adopt `merge(user_supplied, assembler_derived_interface_or_code_hash)`.

Generic VM APIs may receive opaque typed I, declarations and explicit homes without publisher
metadata or D. This is an API boundary, not permission for arbitrary Protocol identity assignment:
the Protocol profile must derive/verify the Page-defined I and authenticate its permanent interface
association. Exact canonical identity encoding and H_LIBRARY domain remain required external
Protocol-owner inputs. Do not invent a VM hash, default generator or permissive fallback.

The Page's full closure **L(I) includes I itself**; `external(I) = L(I) \ {I}`. The generic codec's
stored closure represents external(I), with full logical closure `{I} ∪ stored_external`.
Authenticate that projection and complete contributing declarations, including direct external
requirements. Do not claim the Page's full closure excludes self or add a VM-level cycle prohibition.

Existing InterfaceArtifact/Home v1 codecs retain canonical encodings, exact input, caller budgets
and expected-I/context checks. Their generic transport commitment is not evidence of equivalence
to CommitLibInterface: owner-approved encoding/domain and closure-projection fixtures must establish
that mapping. Publisher-descriptor canonicalization, permitted homes/TypedIds, allocated domains,
profile validation, immutable registration and authenticated closure remain mandatory external
inputs with no fallback. Package9/ReleaseRecord and production-profile acceptance remain separate,
unclaimed gates. Keep generic declaration/home consumers independent without weakening existing
artifact validation; continue independent VM work while these inputs are pending.

Preserve all existing authentication, root-END, invocation/principal, full N_kernel, code/root,
malformed-input, replay, resource, degree/lookup, generated/native/MASM/recursive and security gates.
This correction changes documentation only and does not implement Protocol registry/account policy.

Sources: [LibraryTree proposal](https://chatgpt.com/space/page_d5d09034b1e881919a4c425fe6429d0a)
(identity/interface/registration blocks f83b18f1, 6d71b671, c1b6063f; closure 88b6753b/b8c4a9c4) and
[compiler/assembler contract](https://chatgpt.com/space/page_ad138e12f6cc8191a0e7af15a751dbf1)
(block 996d90e2 retains the formula). Bounded excerpts have Page/date/block/hash cache provenance.

**D4 Explicit inline opt-in, approved by the user on 3 November 2026:** add optional
`inline.<target>` syntax. Existing `exec.<target>` remains a runtime invocation. Inline requires a
local fixed body or an explicitly pinned import, rejects Latest imports and structural cycles,
and preserves inner runtime keys. Approval selects syntax/eligibility, not completed implementation.

## Open decisions and external gates

| Gate | Required decision/evidence | Blocks |
| --- | --- | --- |
| Generic VM/toolchain interchange | D1 fixes VM node preimages. D3 permits opaque typed I/declarations/explicit homes at generic boundaries, while retaining selected Protocol identity/interface semantics and required external validation. Audit mandatory InterfaceArtifact/Profile consumer coupling without weakening canonical/budget/malformed-input/code-root checks. | 04, 09–10, public API closure |
| Frontend syntax and eligibility | D2 preserves existing MASM name/path/word syntax; D4 approves optional inline.<target> for local fixed bodies or explicitly pinned imports, rejecting Latest and structural cycles. Implement source-alias versus published-alias/wrapper behavior and diagnostics without changing inner runtime keys. | 04, 09 |
| Private reusable-instance ABI (deferred extension) | If later adopted, specify authenticated runtime-base transport and relative-key/procref lowering before claiming immutable randomized-instance support. Current explicit absolute homes still require final linking; no implicit relocation or caller-derived namespace. | Future optional ABI adoption only |
| Existing shared/fresh-context behavior | Preserve D2's stack/memory/FMP/overflow and all invocation-mode conventions with regressions. Namespace authentication supplies no RAM isolation. Additional high-level layouts, heap/function-table ownership and initialization/reentrancy profiles are deferred unless an explicitly selected feature needs them; do not invent a fresh-context-only/stateless-only restriction. | 05, 09, 13, 15–16 calling-convention acceptance |
| Protocol profile and production fixtures | D3 fixes Page-derived I and permanent interface association. Exact identity/interface/release codecs/domains, publisher/home/TypedId policy and authenticated registration/closure fixtures remain required external owner inputs, with no fallback. Generic VM work may continue; production-profile acceptance is unclaimed. Expected descriptor authority, executable-path uniqueness and full N_kernel checks remain required. | Protocol-profile acceptance; dependent codec/admission work |
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
| 02 MAST | implemented-awaiting-validation | Latest `364fbb35c`; generator `91d52f92c`; base `4f6cda599` | Independent reviews; 398 arbitrary-feature core tests, 198 default MAST tests, four explicit cycle/recursion cases, core seed generation, public API and full-feature Clippy pass | Processor witness checks await 05/09; fuzz smoke at 16. Environment-aware executable generator restored at 05 (`4bfa6fc94`, `15a9a07c0`). D2 preserves existing MASM source. |
| 03 Chiplet foundation | implemented-awaiting-validation | Latest `a8e0daec9`; state `997c5edae`; Memory `411b22f8b`; base `7602d32ed` | Memory unit/generated/Clippy checks pass; independent logical/physical/state/acceptance reviews and formatting | Twenty-five address/state tests authored, unrun; callable library compilation is restored at 05. Execute processor/parallel/serde suites after 05/09; actual Library prefix/alignment at 06. |
| 04 Toolchain contracts | implemented-awaiting-validation | Fixture `2a3f608e3`; decoder `5c9c78799`; encoding `a70fdc8b1`; Home `a4ceb8260`; syntax `8a02bc43c`; base `45be30b96` | Independent reviews; full package 208 passed/one manual seed test ignored, 52 interface-filter tests, syntax327, scoped/combined test-inclusive Clippy, no-default-features and formatting | D3 Page-derived identity/interface/registration/closure production fixtures remain required, unresolved and unclaimed. Audit generic declaration/home consumer coupling while preserving profile validation. Executable lowering at09; fuzz at16. |
| 05 Runtime | implemented-awaiting-validation | Matrix `2f9394e19`; terminal callback `4ebcb72ee`; earlier implementation/fixture refs below; base `722392682` | Independent reviews; actual processor lib/default/no_std/strict Clippy; 16 public execution (40-case matrix) and five witness tests; core406; exact-source host/fixture10 and overflow4; strict harness Clippy; 52 earlier native tests | Migrate old processor context/serde/environment fixtures; inherited normal processor/parallel/address/state and fuzz gates remain. The earlier three assembly errors are resolved by PR09; normal processor checks still require a fresh run. Proof/AIR/statement activation is later. |
| 06 Library | implemented-awaiting-validation | MAIN `b9db78846`; lookup `d5245be2e`; public boundary `4bbba1e34`; native `668f581c4`; test `8ddf89e49`; reporting `c53ea3cc7`; earlier refs below; base `53acb4837` | Independent reviews; AIR360 with actual packed degree≤9/shape24/4/periodic9/public8/exact [4,4,3,2], raw moved-fraction multisets; witness9 default/testing; execution16/40cases; strict scoped Clippy/no_std | Full production forged matrices/Range+And8 closure and normal/parallel/lookup/streamed fixtures await inherited assembly/fixture migration and Core07/claim12 closure; generated/MASM/recursive/security/qualification and measured snapshot recapture remain |
| 07 Core resolution | implemented-awaiting-validation | MAIN `c668075ff`; lookup `299452ea6`; native `cf934ab3f`; public tests `606d36364`; base `cc6a74742` | Independent reviews; actual Core52/decoder27/aux5/Core36 and degree9; AIR383 pass with one explicit legacy-claim failure; execution18/witness9 default+testing; strict scoped Clippy/no_std | Legacy claim fixture/public projection remains12; normal processor/parallel/decoder/lookup gates await assembly/fixture migration; full forged-matrix/generated/MASM/recursive/security and inherited acceptance remain |
| 08 Replay/debug | implemented-awaiting-validation | Fixture `11465c4f2`; snapshot fix `96adee6a6`; replay tests `63dde7907`; runtime debug `7afd90af7`; tests `fbac6f48b`; base `12e78f953` | Independent source/test/projection reviews; execution22/witness9 default, testing and testing+concurrent; strict processor/source/public Clippy, no_std | Earlier normal private attempt stopped at three assembly errors, now resolved by PR09; fresh normal private/relocation/sidecar checks remain unrun, as do complete forged relocation/global lookup/native/generated/MASM/recursive/security and inherited gates |
| 09 Assembly/packages | in-progress | Inline syntax `ff5784032`; implementation `72218ae6e`; tests `319d291ae`; earlier refs below; base `82935d673` | Independent reviews; inline13/identity12/builder63/linker35/cycles7/nested1 pass within configured-stack full run; syntax319 and strict syntax/assembly library/test Clippy pass; assembly no_std pass; prior package223/one ignored and package Clippy/no_std pass | Full assembly252 pass/230 fail/6 ignored:228 missing explicit namespace metadata, one obsolete diagnostic, one masked panic fixture. Package9/admission, project inputs, fresh normal processor and all inherited/external gates remain |
| 10 Projects/imports | planned | — | — | Depends on 04,09; generic dependency-instance/home/code-supply model under superseding D3 |
| 11 ABI/resources | planned | — | — | Explicit unresolved ABI/resource gates |
| 12 Native statement | planned | — | — | Depends on 01,06,07; fixtures09 |
| 13 Core library | planned | — | — | Depends on 09–12 and supported ABI |
| 14 Recursive verifier | planned | — | — | Depends on settled06–07,09,12–13 |
| 15 API/CLI closure | planned | — | — | Depends on 08–14 |
| 15a AIR/Chiplets cleanup | planned | — | — | After functional integration through15; revisit Controller-local counter, region order and address/trace simplification; recapture/regenerate all affected relation assets before16 |
| 16 Qualification | planned | — | — | Entire stack including15a final relation/identities and release gates |

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

### PR 04 Strict decoding validated; package fixture migration pending

Commit `5c9c78799` adds exact profile-bound decoding, canonical raw envelope/Word ordering, expected-I
and stored-C checks before authority, and shared borrowed label extraction preserving Home behavior.
Fourteen independently authored adversarial tests recompute malformed raw-DB commitments so unrelated
hash failures cannot mask missing canonicality checks. Independent production and test reviews found
no issue. After successful AC/heavy-work guards, the interface filter passed all 52 tests, package
Clippy with tests and `-D warnings` passed, and package no-default-features passed. Pinned formatting
and whitespace checks passed. Production descriptor/domain/home/association/closure fixtures remain
required external acceptance evidence; generic profiles and synthetic vectors do not discharge them.

A broader `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib` check passed 202,
failed five and ignored one. All five fail in the shared test-only `locate_first_node_hash` helper:
its old MAST offsets misread v0.0.6's added target count/table, causing an out-of-bounds vint64 peek
before spoofed-digest assertions. Repair this test helper separately, retaining trusted/untrusted
hash-validation coverage; do not change executable package serialization to accommodate the fixture.
The failing full check is not counted as passing. Log: uncommitted
`.scratch/librarytree/logs/pr04-package-regression.log`. Root will rerun affected/full package checks
following the repair, then finalize this branch's description and unresolved-gate disposition.

### PR 04 Generic implementation closed; production profile evidence remains open

Commit `2a3f608e3` repairs the package spoof-fixture locator using shared ByteReader/
BudgetedReader<SliceReader> rather than a custom vint64 parser. It checks v6 framing, skips the
fixed target count/table, and verifies the original node hash before patching. A keyed Exec fixture
proves the target table is untouched while trusted decoding retains and untrusted decoding rejects
the spoofed hash. Independent static review and pinned formatting passed; production package bytes
and trust boundaries were not changed.

After successful AC/heavy-work guards:

- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib spoofed`: all six passed.
- `CARGO_NET_OFFLINE=true cargo test --locked -p miden-mast-package --lib`: 208 passed, zero failed; only the manual `package::seed_gen::generate_fuzz_seeds` is ignored. This includes all 52 interface/Home tests and closes the five previous offset failures.
- `CARGO_NET_OFFLINE=true cargo clippy --locked -p miden-mast-package --lib --tests -- -D warnings` passed on the repaired tree.
- Pinned-nightly formatting and whitespace checks passed. The decoder no-default-features check and 327-test syntax evidence above remain applicable; the subsequent repair changes only tests.

PR 04 is **implemented-awaiting-validation**, not complete. Its generic implementation/local checks
are done; Protocol must still provide authoritative descriptor bytes, allocated domain, permitted
complete homes and immutable association/authenticated closure fixtures. The pending source question
does not authorize defaults or waive evidence. Validate accepted/rejected owner fixtures through both
artifact and Home codecs and record provenance before clearing this gate. Continue the local stack
with this unresolved validation owner explicit; no GitHub PR or push is authorized.

### PR 05 Opening foundation starting boundary

The branch `adr1anh/librarytree-05-keyed-execution` starts at PR 04 tip `722392682`; PR 04's
production-profile evidence remains open. First implement bounded environment-opening candidate and
private verified-result types in processor `src/environment/{mod,witness,tests}.rs`, with module/export
wiring only. Reuse core EnvNode commitments, Namespace/ProcedureKey derivation and ExecutionDescriptor;
verify selected Merkle paths and complete List material before exposing a binding. No deployment
limits/defaults, full-enumeration requirement or root-admission authority are inferred.

Implement occurrence opening/Resolve ledger and immutable-descriptor resolution session in the next
focused slice, followed by host adapters and shared prepare/commit invocation transitions. Unit rooted
Open edges, complete reverse Lists, per-invocation normal/syscall demand including root-END reserve,
source occurrence and idempotent retries must remain compatible with PRs 06–08. Source/API findings
are uncommitted references, not a second plan. The existing ten callable-cutover processor errors and
PRs 02/03 deferred checks remain until real transitions/consumers are migrated; do not add digest or
old child-ID adapters to create an intermediate passing build. Only actual validation clears gates.

### PR 05 Opening checkpoint and superseding identity clarification

Commit `d8972f02c` adds native bounded selective opening verification, immutable private verified
results and exact retained preimages/slots. Entire-candidate limits cover nodes/depth, per-List and
aggregate children, encoded lengths, native Vec capacities and maximum sequential hash scratch.
Core commitments and N/K derivations are reused; membership grants no root/global-uniqueness/code/
invocation authority. Independent source and test reviews found no issue; pinned formatting passed.

After successful AC/heavy-work guards, the actual processor lib check still fails with the same six
callee() uses and four missing Exec matches, with no new opening-module diagnostic. The uncommitted
`.scratch/librarytree/opening-harness/` imports the exact production module/tests, supplying only
normal alloc/std declarations and reexports, with no resolver implementation or compatibility stubs.
Its 17 tests, test-inclusive Clippy with `-D warnings`, and no-default-features check passed; these are
isolated unit evidence, not passing processor integration. The first harness attempt omitted the
processor's alloc macro import; fixing the harness setup enabled the passing run. Logs remain separate.

At this verified safe checkpoint, the user explicitly superseded the earlier opaque Protocol-assigned
LibraryId choice with the two cited Pages' deterministic identity/interface formulas, permanent binding
and full L(I)/external(I) distinction; D3 above is authoritative. Both Pages were read on 2 November
2026, sequence 0; bounded relevant cache excerpts retain original block hashes and provenance. No
implementation changes accompany this documentation correction, and PR 05 opening work is preserved.
The user also directed continuation of the VM stack while production Protocol inputs remain pending;
this does not authorize arbitrary identity assignment, merge/code-hash alternatives, defaults or gate
waivers. Continue with occurrence ledger/session and staged invocation work; align profile Rustdoc and
production codec/fixture equivalence separately before PR 04's external gate is cleared.

### PR 05 Occurrence-ledger boundary and shared trace limit

The next focused slice adds processor `src/environment/ledger.rs` and independent nested tests:
merge authenticated prefixes by parent occurrence/slot, retain exact preimages/N/C/depth and selected
unit edges, and stage all fallible work before allocation-free publication. A short-lived exclusive
borrow guard prevents stale/cross-ledger publication; session/source/use-frequency/host transitions
remain a later slice. The only opening-verifier change authorized here is a private consuming path
accessor, preserving authentication and immutable public results.

Reuse the existing MAX_TRACE_LEN safety ceiling through a small separate refactor: move its unchanged
2^29 value into `processor/src/trace/limits.rs`, expose that module and preserve the parallel module's
existing crate-private path by reexport. Ledger logical rows must respect this necessary ceiling even
if caller policy is looser. Logical Library rows and conservative compression-request counts follow
selected pair formulas; they are neither padded prefix size nor distinct interned Controller work.
Actual prefix rounding/terminal PAD/combined T/no-wrap/degree/lookup gates remain PRs 06–07/16. Limits
are explicit, not deployment defaults. Account retained native capacities and conservative prepare
peak (old/input/staged/replacement overlap), and recheck returned capacities before publication; no
allocator-excess/RSS guarantee or whole-ledger clone is implied. Commit the shared-owner refactor
separately from ledger implementation and document actual checks without waiving inherited failures.

### PR 05 Occurrence ledger validated in isolation

Commit `99bfbe6d9` mechanically gives the unchanged MAX_TRACE_LEN constant a shared owner while
preserving existing crate-private paths. Commit `739acedb7` adds bounded occurrence merging and
atomic preparation/publication, plus only a private consuming accessor to the verified opening.
Parent/slot provenance distinguishes equal commitments/N/depth at different positions; complete
Lists and full inherited namespaces are retained. A borrowed guard owns staged/reserved buffers,
so error/drop leaves published storage unchanged and commit allocates nothing. Logical row/request
costs and native capacity/peak accounting are explicit; the shared necessary row ceiling does not
clear final packed/global proof gates. No session, use frequency, host or invocation behavior is added.

Independent production and 18-test reviews found no actionable issue. After successful AC/heavy-work
guards, the exact-source uncommitted harness passed 35 tests (17 opening plus 18 ledger), test-inclusive
Clippy with `-D warnings`, and no-default-features. It imports the real shared trace-limit source,
not a substitute definition. Actual `cargo check --locked -p miden-processor --lib` still fails on
exactly six callee() uses and four missing Exec matches, with no environment-module diagnostic.
The capacity-excess test verifies sizing/rejection math directly; actual post-reservation calls are
supported by source review rather than allocator-driven fault injection. Pinned formatting and
whitespace checks pass. These are isolated unit results, not processor/proof integration acceptance.

Continue with immutable ExecutionDescriptor-scoped resolution session, checked normal/syscall uses,
entry reservation discharged at actual root END, and staged source/use records. Existing host loaders
and all fallible VM transition preflights must precede final publication when integrated; do not infer
runtime atomicity from native bookkeeping alone. Preserve the superseding D3 identity/closure contract
and its external profile gates throughout subsequent work.

The next session slice includes prepared entry, ordinary/syscall miss/cache-hit preparation, reserved
normal entry demand, root-END-only discharge and strict finalization together; no permissive partial
finish API is selected. Preserve OpeningLimits/LedgerLimits and add only explicit session cache/use/
storage limits. Reuse immutable ExecutionDescriptor and existing RowIndex as an adapter-supplied source
marker; actual-row binding and package-owned debug context remain transition/Core/replay obligations.
The selected exclusive Core groups emit at most one request per row (execution lines 443–450), so
committed invocations plus the reserved root demand must obey the necessary shared MAX_TRACE_LEN
ceiling. This is native checked-integer accounting, not a new AIR frequency range or proof gate waiver.
Rustdoc-only commit `71bf65973` separately aligned opaque VM I/profile requirements with superseding D3;
non-Rustdoc lines were unchanged, and owner production projection/registration fixtures remain pending.

Session peak composition additionally needs one private ledger hook: prepare_with_peak_limit applies
min(stored policy, outer available peak), with no change to stored limits/counters or public prepare's
accepted behavior. It shares existing sizing/preparation and checks the tighter ceiling before first
reservation and after returned capacities. Session passes available outer bytes after old session
buffers, then preflights its staged/replacement/root-reserved buffers against the actual ledger guard
peak. Reserving the whole configured ledger cap is unnecessary and can falsely reject modest work.
Commit this independently reviewed hook separately from the coherent native session lifecycle.
The scratch harness reexports the actual miden-air-definitions RowIndex; no source type is substituted.

### PR 05 Native descriptor session validated; execution integration next

Commit `768a79319` independently adds the private composable ledger peak ceiling. Commit `f4b511056`
adds immutable-descriptor native session phases, authenticated binding cache, normal/syscall use
records and native counts, separately reserved entry demand/capacity, root-END-only discharge and
strict read-only finalization. Ordinary/entry may target kernel exports; actual syscall checks exact
full immediate N against N_kernel on misses and hits. Consuming borrowed guards publish only after
all reservations/admission checks; drop/failure changes no published state. This is native bookkeeping,
not an actual-VM completion certificate or integration of context/principal/stack transitions.

Independent production and 17-test reviews found no remaining actionable issue. Review found an omitted
phase helper, which was added; a nested-if Clippy lint was fixed without suppression. After successful
AC/heavy-work guards the exact-source harness passed all 52 tests (35 prior plus 17 session), strict
test-inclusive Clippy and no-default-features. It reexports the real miden-air-definitions RowIndex;
actual row binding remains a transition/Core/replay gate. Allocator-excess tests exercise sizing/recheck
inputs, not a real allocator over-return/OOM. Pinned formatting/whitespace pass. Actual processor lib
check still fails exactly six callee() and four missing Exec matches, with no environment diagnostic.

Next bind this infrastructure to real execution through a shared prepared-target path: ENTRY, keyed
same-context EXEC and actual root END, followed by all CALL/SYSCALL/dynamic modes. Establish exact
sans-IO pending request, explicit descriptor/limit input and bounded sync/async witness-provider seams
before assigning disjoint host/execution/tracer owners. Authentication precedes D loading; retain code
root/procedure-root and advice-once checks. Current loaders publish cache/advice before debug validation,
and current tracer finalization can fail after VM mutation; those fallible seams require real preflight,
not a session-commit call added after the old flow. Preserve all D2 semantics and later proof gates.

### PR 05 Required execution/provider and retry boundary

First integrate an explicit immutable ExecutionEnvironment containing descriptor and opening/ledger/
session limits (no Default or digest-authority path), plus bounded sync/async environment-witness
requests. DefaultHost may have no configured witness source: that is unavailable evidence and must
fail closed, never authorize code by D. None from a provider does not prove cryptographic nonmembership.
Keep provider failure, invalid opening, missing code and malformed requested-D root distinct.

ResumeContext owns session and an owned pending key/binding across waits; step APIs borrow it rather
than consuming it, so cancellation/prepublication retry cannot lose or replay a pop. Peek a retained
keyed StartNode until one shared final transition consumes it. Authenticate fixed R_E/K and actual
syscall N first, then prepare D-indexed local/host code, actual source/debug owner, advice-once work,
VM stack/context/FMP/return/continuation and projected stopper/tracer checks. No whole-state clone or
rollback claim. Known fallible checks precede publication. Unexpected arbitrary late tracer/stopper
callback errors terminally invalidate that execution: no subsequent transition, successful output or
proof/witness export; retry must not publish twice. Actual driver/transition tests must establish this.

Assign host/config/source files before disjoint execution and tracer owners; shared API references
are short findings, not another plan. First vertical slice is real ENTRY/EXEC/root END, then all modes.
Distinguish invocation-node hash H(mode,K) from loaded body D and its END; outer invocation END keeps
its own node digest. Root discharge uses actual entry activation/completed D, not empty continuations.
When mandatory keyed records are added to replay persistence, bump **ExecutionWitness replay envelope
to version 4** and reject previous/unknown layouts before payload parsing. Existing replay v3 has no
resolution records; do not silently reuse it. This routine breaking-version migration is separate
from the planned proof transport format 3 and execution claim v2, whose contracts are unchanged.


### PR 05 Provider seam validated; code-supply preparation next

Commit `1fdca8496` adds immutable explicit ExecutionEnvironment policies, bounded native witness
requests, sync/async host forwarding, an explicitly configured DefaultHost source, and distinct
unavailable/provider/invalid-opening errors. None is unavailable evidence, never nonmembership.
Runtime entry/execute APIs do not yet consume this seam. Independent source and eight-test reviews
found no remaining issue. AC/heavy guards passed; actual processor lib check still has exactly six
old callee() and four missing Exec errors, with no new provider/config diagnostic. An optional
reference-host blanket introduced one ambiguity and was removed before commit. Eight new host tests
are authored but unrun behind the processor cutover; do not count them as passing. Pinned nightly
formatting and whitespace checks pass.

Before ENTRY/EXEC integration, refactor existing advice-map extension into an exclusive borrowed
prepare/commit guard, preserving checked conflicts/budgets and the public extension behavior. Then
share postfetch requested-D/root/debug validation between sync/async loaders, prepare advice before
publishing cache/merge-once changes, and keep prepared code supply separate from environment authority.
Commit these focused refactors independently. Existing BTree allocation behavior does not guarantee
survival of allocator abort. No whole-state clone, digest-authority fallback or proof acceptance is
introduced. Root/entry/trace preflights, all invocation modes and replay remain required integration.


### PR 05 Advice/code publication refactors validated; live/replay integration next

Commit `94d690f2e` shares ordered advice conflict/budget checks through an exclusive two-lifetime
prepare/commit guard; drop does not publish, and commit returns no execution error. Commit `b3445530a`
shares requested-D/local-root/debug preparation between sync/async loaders and preflights advice
before cache/merge-marker publication. A host answer containing only External(D) now rejects as
malformed code supply; an earlier external marker cannot hide a later exact local body. Structural
external references remain supported. Independent production and four/five-test source reviews
passed. After AC/heavy guards, actual processor lib check still reports exactly six callee() and four
missing-Exec errors, with no new refactor diagnostic. The nine new tests are authored/unrun, as are
the eight provider tests. Pinned nightly formatting and whitespace checks pass; no suite pass is
claimed for this noncompiling intermediate branch.

Next connect real ENTRY/EXEC/root END in shared live/replay transitions. Keep concrete native session
in live outer drivers, owned pending resolution through waits, and generic transition functions for
Sparse replay. ENTRY is zero-cycle authentication/reservation, not a fabricated row use. Peek finish
continuations before pop/tracer start; a real FinishBasicBlock and RootBoundary may expose actual root
END through only zero-cycle forest restorations. Separate fallible tracer/environment preparation
from infallible publication; built-in stopper and return/controller errors must preflight, while
unexpected late custom failures invalidate execution and prohibit success/export/reentry. Reconstruct
private authenticated records from bounded untrusted replay evidence, not unchecked constructors.
Commit shared contracts and actual consumers in focused reviewable slices; conditional replay v4,
all invocation/context modes, later AIR/statement/resource gates and D3 remain required.


### PR 05 Shared preparation contracts committed; consumer edits in flight

Commit `967887de5` adds public keyed event/actual-target/global-cycle projection types, owned tracer
reservations, separate entry preparation/publication, per-cycle preflight and stopper preflight.
Independent source review passed; a stale trait overview was corrected, and pinned formatting plus
whitespace checks pass. Required tracer implementations are deliberately migrated next; no compile
or integration pass is claimed for this contract-only intermediate commit. The last processor check
preceded this change and retained ten inherited callee/missing-Exec errors.

Execution and tracer owners now implement disjoint real consumers; root owns error wiring and commits.
Prefer focused control-hash/return/address preflight refactors before committing serialization-coupled
queues. Do not add transient serializer panics, no-op execution arms or silent replay-v3 field loss.
Compact occurrence snapshots, lazy path reconstruction and explicit caller wire/peak/work policies
are the selected replay implementation direction; the exact bounded reader/validation API still
requires source review. No unchecked authenticated-record constructors or serialized policy override.
All D3, runtime-mode, replay-v4, actual root-END and later packed/proof acceptance gates remain open.


### PR 05 ENTRY/EXEC/replay source integration committed; remaining modes next

Commit `816742996` adds exact root-ID/digest checks for dense/sparse/Arc forests. Its external-first
shared-digest regression passes, as does core test-inclusive Clippy with `-D warnings`. Commit
`354880d7a` adds real EXEC/control-hash and checked source/Core trace preflights; `2757c6232` adds
shared retained EXEC/actual root-END transitions, source restoration and END-frame reservation.
Reviewed fixes address inherited inline context, pure-path restoration, exact root selection and
prepublication capacity/type checks. No transition runtime test pass is claimed.

Commit `fe5e06d45` adds explicit trace policies with no default; live peak is trace-owned, native
limits remain independent. Commit `4cb37ebe9` binds every runnable/resume API to immutable authority,
authenticates entry before code/advice selection, retains keyed evidence through waits and invalidates
late failures. Legacy non-keyed async Emit/External cancellation is terminal rather than resumably
losing a consumed continuation. Actual authenticated entry D supplies legacy ProgramInfo metadata;
this neither activates the new claim nor grants authority to ProgramInfo/kernel-list metadata.

Commit `b3323e3ad` adds bounded compact replay evidence and native revalidation; `8be2703c1` composes
staged tracing, strict witness replay v4, explicit-budget readers/writers and validated build/export.
Independent resource/composition reviews closed fragment placement, stale/cross-queue reservations,
preallocation storage, repeat-validation revocation, work accounting and post-root replay findings.
RootBoundary must be bottommost, actual root END must be the final executed row, and only zero-cycle
forest restorations may remain. This is source-review evidence, not proof/AIR qualification.

After AC/heavy guards, actual default and no-default-features processor lib checks fail only on four
remaining `callee()` uses in `execution/call.rs`, with no warnings. The first integration check also
found a streamed Result callsite and three warnings; these were corrected. Pinned formatting and
whitespace pass. Seventeen provider/advice/loader tests remain authored/unrun; new driver/wire tests
and old explicit-environment/serde/constructor fixture migrations remain required. In particular,
old witness/TraceReplay and trace-state serialization tests still call removed unbudgeted APIs.
Do not restore implicit policy or unchecked fixtures to pass those tests.

Next implement CALL/SYSCALL/DYN/DYNCALL via the same retained bridge and prepared component tokens,
including exact dynamic peek/consume, fresh/root/shared-context semantics and projected return
principal. Immediate invocation hashes use K; **dynamic wrapper hashes stay static zero/zero**, while
dynamic memory reads authenticate K and Resolve selects D (execution spec sections 3.2/5.2). Earlier
agent shorthand H(mode,K) applied too broadly and is superseded by this distinction. No DynNode
commitment redesign is selected. All pending PR 05 tests, source ABI, D3 and later packed/proof gates
remain; PR 05 is still in progress.


### PR 05 All invocation modes build; public execution regressions pass

Commit `78adc658f` adds prepared stack/system/memory effects; `7fa01c810` routes all modes through the
retained authenticated bridge, with full-N syscall authorization before any D lookup (cached too).
`c22c423ef` composes replay, targeted trace queue reservations and terminal failure handling. Owned
word-read/pop/context/write/return tokens avoid known fallible rechecks after publication; only
affected overflow or a required replacement buffer is staged. Native and independent component/bridge
reviews covered projected root return principal/depth, dynamic pop-before-save conventions and
once-only read/FMP hooks. Static DYN/DYNCALL commitments remain unchanged.

Dead runtime KernelDescriptor threading was removed after an independent caller audit; legacy
ProgramInfo/chiplet transport remains pending its planned cutover and grants no native authority.
ReplayProcessor consumes the existing ExecutionReplay bundle, forwarding its two tracer queues
without replacement defaults. OpeningError is boxed inside contextual ExecutionError to keep ordinary
Result size bounded. One targeted large-enum Clippy allowance preserves owned inline fixed-stack
reservations rather than introducing an unbudgeted heap allocation. Other lints were fixed directly.

After successful AC/heavy guards, actual `cargo check --locked -p miden-processor --lib`, the same
no-default-features check, and lib Clippy with `-D warnings` pass without warnings. First mode compile
found four FastProcessor/trait getter-shadowing errors; these were corrected through the shared
Processor API. The first Clippy run exposed one oversized error variant and mechanical lints; the
passing run follows their fixes. No failed attempt is counted as passing.

Commits `051cc3274`/`157ff858e` add twelve public-API regressions. They run against the actual processor
dependency through an uncommitted standalone harness pointing directly at the repository test file;
there is no substitute VM. The harness uses the normal core arbitrary feature for public test builders
and a lock derived from this repository; its first missing-feature setup failure was corrected. All
twelve tests and strict test-target Clippy pass. Coverage includes entry authority/hint override,
same-D aliases, exact deep kernel namespace and ordinary kernel exports, all context modes/RAM/FMP,
retry/cancellation ownership, explicit budgets, replay-v4 roundtrip, and bounded keyed self-recursion
whose entry reserve closes only at actual root END. A direct DynCall-only public entry fixture cannot
seed RAM: coverage is terminal DYNCALL inside authenticated setup, not a claimed standalone case.

This restores library compilation and supplies native runtime evidence, not proof acceptance or full
PR 05 completion. The original seventeen host/advice/loader tests and address/state/parallel suites
still need their normal dev graph, and older context/serde/constructor fixtures need explicit API
migration. Restore the temporarily restricted environment-aware executable generator and its bounded
invocation fixture; run required witness/fuzz checks at the recorded dependent stages. External D3
profile fixtures, private ABI decisions and all later packed/AIR/statement/recursive gates remain.


### PR 05 Executable-fixture ownership boundary

The normal `cargo test --locked -p miden-processor --lib environment` attempt, after AC/heavy
guards, stops in miden-assembly with three remaining keyed-MAST migration errors; it does not run
processor tests. Record this concrete dev-graph blocker without restoring digest/child-ID adapters.

Restore runtime generation through an `ExecutableForestFixture` that owns the forest, validated
environment, stable label/key-to-body metadata and root openings. Core keeps processor policies out;
its environment builder takes explicit caller limits. Synthetic nested namespace and full kernel
namespace are fixture data, not Protocol defaults. Reuse existing EnvironmentBuilder validation and
ID remapping; procedure labels/keys remain independent of implementation D. Generate bounded
acyclic runtime targets with all retained modes and balanced dynamic setup.

A bare MastForest cannot retain that environment. Make bare arbitrary defaults structure-only and
reject explicit Executable requests with a clear fixture-API migration diagnostic; only the new
owned fixture strategy carries the complete executable guarantee. Migrate the sole processor
consumer to serve its openings and execute every root under an explicit descriptor/resource policy.
This is a breaking testing API change, not a runtime or MASM scope reduction. Coverage must prove
all modes remain retained and executable, same-D aliases, key stability, remapping and termination.
Commit fixture implementation, consumer/tests and this boundary separately; do not close PR 05 on
source generation alone. Existing normal test/assembly and later proof gates remain open.


### PR 05 Executable fixture restored; overflow tests migrated

`4bfa6fc94` adds the owned executable core fixture; `15a9a07c0` migrates its processor consumer.
Every materialized root and invocation alias has a validated binding and actual opening under a
full nested namespace; IDs are remapped before body commitments are selected. All five modes and
structural externals execute in bounded acyclic graphs. Bare arbitrary forests now explicitly use
StructureOnly; they cannot silently discard executable authority. Independent source reviews found
no actionable issues.

After AC/heavy guards, `cargo test --locked -p miden-core --lib --features arbitrary` passed
406 tests (one manual seed test ignored); test-inclusive strict core Clippy and the arbitrary-feature
no-default-features library check passed. The uncommitted runtime harness imports actual processor
APIs and exact repository test sources: eight host-provider tests and both executable-fixture tests
passed, including arbitrary canonical 0–16-element stacks and retained-mode coverage. Strict harness
Clippy passed. These are isolated test results, not a passing normal processor suite.

`d880ef50a` separately migrates overflow restoration tests to prepared tokens. Four exact-source
tests passed, including stale caller-address rejection at matching frame/element counts without
mutation; independent review and strict harness Clippy passed. Logs are under
`.scratch/librarytree/logs/pr05-{executable-fixture-*,overflow-restore-token-*}`. The normal dev-graph
assembly blocker, remaining advice/loader and legacy witness/context/environment test migrations,
address/state/parallel/fuzz checks and all D3/packed/proof gates remain open. PR 05 stays in progress.


### PR 05 Source-aware retries and explicit witness test migration

`0906c91fe` migrates three fast restoration unit tests to checked component preparations before
either commit; independent review and formatting passed, normal-graph execution remains deferred.
`a4ae9b224` adds a shared native single-Mast fixture and five public witness tests; `9d083316a`
separately migrates nine private continuation/AEAD/precompile mutation cases to bounded replay v4.
The five public tests passed through actual processor APIs, including identical native AEAD trace
matrices after byte-stable roundtrip; strict test-target Clippy passed. The nine private cases
remain unrun behind the known three-error assembly dev-graph blocker.

`2d8a3adf1` adds retained source-aware DYNCALL cancellation and unavailable/malformed-code retries.
`542b8f9de` separately covers post-entry request exhaustion: requested 2 with limit 1 preserves
full caller stack/RAM, source ownership and native demand state, then rejects further stepping.
Independent review's full-memory snapshot finding was addressed. The fixture's explicit advice
budget was corrected from 8 KiB to 64 KiB after observing the empty provider's 24,480-byte retained
allocation; no production policy changed. All 14 public execution regressions and strict Clippy
passed after AC/heavy guards. Logs: `pr05-{keyed-witness-*,source-dyncall-*}` under the scratch log
directory. Next finish the native five-mode/local-host/source-aware/sync-async matrix and terminal
late-callback regression; normal test, D3, packed/proof and subsequent stage gates remain open.


### PR 05 Native mode/API matrix checkpoint

`2f9394e19` adds the full 40-case native matrix: five invocation modes, local/host-supplied D,
pure/source-aware execution and sync/async stepping. A local user-call wrapper makes SYSCALL's
root-context transition observable. Exact operand/overflow restoration, RAM/FMP/principals, source
owner/graph restoration, one witness per K and ordered native uses/tags are checked. `4ebcb72ee`
separately verifies a host event error after target publication is terminal without repeated
callbacks, host requests, state advancement or use publication. Independent review found no
actionable issue; a missing test trait import was fixed before execution.

After AC/heavy guards all 16 public execution tests passed, including every matrix case, and strict
all-target harness Clippy passed. Logs: `pr05-native-mode-matrix-*`. PR 05 is
implemented-awaiting-validation, not complete: normal processor/legacy/parallel/address/state and
private mutation checks remain deferred through the recorded assembly/trace migrations; fuzz smoke
is at 16. Keep every PR 05 acceptance gate. Continue the linear stack to PR06; native resolution
and trace reconstruction do not establish the packed AIR or statement relation.


### PR 06 Opening boundary

PR05 final review-description commit `53acb4837` is the exact linear base of
`adr1anh/librarytree-06-packed-library`; no PR or push was created. Start with the one shared
Library22 view, canonical kind encoding and pure local predicates, reusing existing borrow/field
conventions. Two independent source reviews agree that the active selector switch must instead
coordinate both selector implementations, views/writers, Controller mode/boundaries and periodic
consumers. This first slice does not activate a partial AIR or add another committed matrix.
All PR06 acceptance gates above remain required; PR05 inherited checks remain open.


### PR 06 Shared schema/local expressions checkpoint

`441bacb95` defines the shared 22-cell Library overlay, canonical kind bits and zero-copy accessor.
`487a2a51a` separately adds cubic kind flags, explicit Library/phase scope and compact sigma
selection/validity expressions. No live section selector, writer, periodic layout, lookup or AIR
evaluation is activated by these commits. Independent implementation review found no actionable
issue.

After AC/heavy guards, `cargo test --locked -p miden-air-definitions --lib library` passed all seven
layout/mutation/truth-table tests. Strict library/test Clippy and no-default-features library check
passed. Production-only `expect(dead_code)` is limited to the new Library module while its
expressions await consumers; remove it during constraint integration. Logs: `pr06-library-schema-*`.
These local checks do not establish integrated degree, group capacity or soundness. Next simplify
Controller mode/scoping, then coordinate packed selectors/views/writers/boundaries and Library
witness/buses. Every PR06 acceptance gate and inherited validation remains open.


### PR 06 Controller mode/scoping refactor checkpoint

`5c7c9ce26` derives Controller mode from hs1/hs2, removes the physical getter and off-Controller
zero shortcut, scopes all generic Merkle equations/lookups, and simplifies the three init gates.
Unused cubic Controller flag compositions are removed. `59b36d0ec` removes the mode write and
reduces Controller width from22 to21 without changing rows/alignment/addresses. Independent review
found a stale mutation-test row locator using sharedc22; it now selects MP/MU by their kind bits.
`4e2158717` adds actual Chiplets shape/base-extension-degree capture and refactors the existing
lookup validator to derive its layout from production APIs. Duplicate validation was consolidated.
`87267f9a3` separately updates the processor trace overview.

After AC/heavy guards the full handwritten AIR suite passed308 tests; exact lookup group/column
annotations validate and current captured degrees are≤9 at24main/fouraux/fourAIR. Five public
witness/native trace reconstruction tests passed. Strict AIR library/test and processor library
Clippy and no-default-features processor checks passed. Logs: `pr06-controller-*`. Processor-only
materialization/Merkle mutation tests remain authored but unrun behind the existing assembly
dev-graph blocker; no normal processor-suite or generated-proof pass is claimed.

Next coordinate Memory/ACE helpers and packed views/writers/selectors/prefix/boundaries. Existing
Controller global-first initialization and physical next-selector dependencies remain legacy until
that migration. Current degree checks do not clear the full packed, public-input, lookup-capacity,
forged-matrix or generated/native/recursive gates. All PR06 and inherited acceptance remain open.


### PR 06 Memory/ACE helpers and family-band witness completion

`67390876a` exposes scoped helper views. `3b07ee656` binds Memory e0/e1 and ACE z, reducing
not-written/arithmetic degrees while retaining all conditional-inverse, value, read-only and
ternary-validity rules. Review found an actual integration conflict: the legacy stream-mode zero
gate and Memory classifier still treated c22 as mode outside Bitwise. Both now respect Memory e1,
with full production-selector sequence regressions including forged entry reads.

`57c6f9426` completes only materialized Memory/ACE bands after scatter, with no new allocations,
compact-buffer holes, offsets, messages or selector-order changes. Private fixtures test absent/
present bands and preserved payload/clocks/AEAD cells; normal processor execution of those fixtures
remains deferred behind assembly. `43b2824f8` supplies public native materialization evidence for
ten scalar/word accesses, exact helper/payload/clock semantics and replay-matrix equality.

After AC/heavy guards AIR321 and all six public witness tests passed, including measured current
degree≤9/exact lookup validation. Strict AIR/test, processor/lib and public-test Clippy and
no-default-features processor checks passed. Clippy's fixed-size chunk suggestion was adopted
without new allowances. Logs: `pr06-memory-ace-*`. These checks do not activate Library or clear
packed/public/lookup-capacity/generated/recursive gates. Next implement complete scoped Library
constraints and existing-group lookup entry points; public8/periodic9/validated boundary inputs
and packed production dispatch remain coordinated integration.


### PR 06 Scoped Library relation and genuine compression providers

`40887c022` extracts canonical symbolic Eidos framing without changing the transcript formula.
`7a184a8ca` adds explicitly scoped Library MAIN constraints: proper prefix/pairs/PAD, complete reverse
Lists, routing and four per-supplier SYS namespace equations. `ab18cccc4` adds unit rooted Open,
normal/syscall Resolve and compression emissions into an existing group, plus an explicit public
R_E seed with canonical initial namespace; no production dispatch or additional column is activated.
`800f6d75d` tests the same entry points with genuine Eidos MAIN/lookup providers, fresh auxiliaries,
fixed Resolve demands and both challenge encodings. Negatives rehash incomplete Lists/padding and
exercise unit provenance and weighted SYS cancellation. Acceptance uses the actual rational lookup
correction; exact multiset equality is diagnostic. Independent reviews found and resolved a test
oracle issue, and a previously unused MAIN reexport was removed after strict Clippy caught it.

After AC/heavy guards the full AIR suite passed347; the strengthened combined subset passed all
seven tests again. Strict AIR library/test Clippy, no-default-features processor and all six public
witness reconstruction tests passed. Logs: `pr06-library-relation-*`. Isolated exact lookup metadata
and MAIN/auxiliary degree≤9 do not establish integrated packed acceptance. Full Range/And8 closure,
public8/periodic9/validated boundary propagation, both selectors, native writers/prefix relocation,
Controller entry, `[4,4,3,2]` redistribution and generated/native/recursive/security gates remain open.

Next reuse the authenticated occurrence ledger and existing compression interner for native Library
prefix planning/writing. D3's Page-defined identity/full-closure correction is committed separately
as `a477732bc`, with profile Rustdoc in `71bf65973`; it supersedes opaque-assignment history without
waiving any external Protocol input or acceptance gate. No GitHub PR or push was created.


### PR 06 Native writer and checked shared compression admission

`0c619b145` exposes the existing shared LibraryCols view to native consumers. `414647cca` routes
Controller, AEAD and direct packed requests through one checked interner. Entry/summed multiplicities
and unique-state cycle growth are checked before registration; direct requests append no Controller
rows. Review caught an admitted duplicate AEAD state/clock that the materializer requires to have
unit multiplicity; admission now rejects duplicate/nonunit AEAD without mutation. New single-row
Controller requests preflight both row capacity and registration before append. Memoized replay can
already have copied its full row span when registration fails; that materialization failure is
explicitly terminal and requires discarding the hasher. The raw public external helper remains an
unchecked separate admission gate, not the native Library path.

`11114a250` adds a borrowed completed-session writer with no allocated row matrix/request vector.
It reuses ledger counters, validates occurrence/binding associations, writes the caller's exact
aligned prefix, streams canonical requests, preserves separate normal/SYS frequencies, and computes
List CVs forward directly into reverse pair destinations. The caller must admit combined height/PCS/
proving memory before allocation; callback failure leaves disposable partial buffers, never changed
native authority. Independent reviews found no remaining issue. Library production dispatch remains
inactive.

After AC/heavy guards all five exact-source writer tests and six public witness tests passed.
Strict processor library and exact-source/public-test Clippy, plus no-default-features processor,
passed. Initial import errors and fixed-chunk/parity Clippy suggestions were corrected without new
dependencies or allowances. The fresh normal private-test attempt stops in miden-assembly at exactly
three existing keyed-constructor/Exec migration errors; six private interner tests are authored but
unrun. Logs: `pr06-native-library-*`. No normal processor-suite or proof pass is claimed.

Next relay the existing owned completed session through execution-witness capture and replay
revalidation, account its actual retained storage, and share one pair/request walker for registration
before exact admission and final writing afterward. Production packed/public/boundary/Controller/
lookup/security/generated/recursive gates and all inherited checks remain open; PR06 stays in progress.


### PR 06 Completed native owner relay and shared pre-admission walk

`de1e70117` factors one fixed-stack pair/request traversal. Pre-admission visits stream compression
requests without prefix storage; final writing uses the same canonical implementation without
registering requests again. `a1691533b` preserves typed keyed-trace/resource errors without formatting
or allocating on failure. Review caught threshold probes accepting every error as an expected
retained-limit rejection; all probes now reject unrelated failures, including entry metadata's
previously erased budget errors. `f34e805d4` separately factors the actual shared test fixture.

`cf08681dc` moves the original completed ResolutionSession through every full proving/source/async/
streamed path into required native TraceReplay storage. Public execute APIs discard the returned
owner; stopped/resumable contexts keep theirs. Bounded reads retain the completed session already
built by native revalidation. No cloned ledger, optional/default authority, new encoded field or
wire-version change is introduced. Capture/root-END queue preparation, read and export account exact
native retained capacities, including the final keyed-record delta. Trace preparation peak remains
explicitly separate from native preparation; read allowances are clamped before native allocation,
and final retained checks precede use/validation publication. Fixture budgets remain unchanged.

`c35c3c5e2` adds private original-owner/entry-frequency/retention/drop/trust tests and migrates six
stale replay serialization fixtures. These are reviewed but unrun behind the existing three assembly
migration errors; inherited Controller address fixtures still need constructor migration. `d39735bbe`
adds public mode/wire/claim/descriptor/full-matrix parity and independently measured exact capture,
read, live-export and restored-export retained boundaries. Capacity differences do not imply equal
thresholds. Neither private source review nor public replay parity establishes a proof relation.

After AC/heavy guards: seven exact-source walker tests, eight public witness tests with both default
and testing/source-async configurations, and sixteen public execution tests including all40 native
mode/API cases passed. Strict processor library and source/public-test Clippy in both configurations,
plus no-default-features processor, passed. Logs: `pr06-session-relay-*`. The isolated harness lock was
refreshed offline for its real testing feature; no repository dependency/default changed.

Next coordinate packed selectors, physical views/bands/writers, Controller entry/address relocation,
periodic9 and `[4,4,3,2]` lookup redistribution with required public8/boundary inputs. The current
materializer still discards the retained owner and uses a zero prefix. Production Library dispatch,
Core Resolve/root-END/statement activation, full Range/And8 closure and all measured/generated/
recursive/security gates remain open. PR06 stays in progress; no GitHub PR or push was created.


### PR 06 Coordinated packed cutover ownership

Proceed jointly with MAIN/schema/periodic migration, matching lookup dispatch/redistribution, and
native band/buffer/materialization migration. Introduce mandatory Chiplets8 public inputs and pass
them explicitly to MAIN and the Open boundary; unconverted producers must reject missing inputs,
without zero defaults or legacy-aux inference. Root owns public-count/boundary propagation and
statement shape validation. Core Resolve/root-END and canonical claim/transport/recursive activation
remain PR07/12 obligations. Intermediate consumers may break during this selected cutover; that is
not permission to accept a partial proof relation or clear any inherited/final gate. Exact degree,
lookup multiset/capacity, prefix/boundary, public-binding and generated/security checks remain required.


### PR 06 Packed relation/materialization checkpoint

`b9db78846` selects the shared packed overlays, matching prefix-gated MAIN selectors, periodic9,
complete Library exit into Controller and relocated Controller initialization. `d5245be2e` migrates
lookup activity, keeps Library inside the existing hash-kernel group and redistributes AND8 2+2 and
Memory ranges4+1 without changing raw tuple/frequency multisets. Retired KernelRom messages are
removed; bus slots0/3 remain reserved, preserving COUNT41 and message width16. `4bbba1e34` requires
explicit Chiplets8 in MAIN/boundary propagation, validates every AIR public slice before indexing,
rejects missing/malformed shapes and removes absent-input defaults. Core's old fixed prefix and
canonical legacy claim carrier remain explicit until PR07/12; they no longer seed kernel authority.

`668f581c4` consumes the retained completed session, registers Library requests into the same checked
Hasher before Eidos/range/height/memory admission, then writes into the final allocated prefix only.
It uses six checked bands, separate typed AEAD/Bitwise buffers, Controller c1, checked cell layouts
and one typed Controller-address relocation. Obsolete native KernelRom files/band/builder are removed.
`013573703` migrates private band fixtures without claiming their execution. `8ddf89e49` checks real
Mast/entry frequency1, prefix8, physical Controller address9, three unit compression footers, exact
budget rejection and live/read/source/async matrix equality.

`c53ea3cc7` migrates CLI/benchmark reports and required measured-breakdown fields to six bands while
retaining the five calibration dimensions and checked sum+1. Benchmark documentation `a1f94df23`
identifies pre-cutover metrics as historical. Measured JSON/provenance remain untouched; enabled
`committed_snapshots_load` still requires genuine producer recapture and updated height pins. Small
synthetic schema fixtures do not claim new measured results. Reporting/bench checks remain unrun.

After AC/heavy guards all360 AIR tests passed, capturing actual whole MAIN/extension degree≤9,
public8, periodic9, four AIRs, exact [4,4,3,2] metadata and moved lookup fractions. Nine public witness
tests passed in default/testing configurations and all16 public execution tests (40-case matrix)
passed. Strict AIR library/test, processor library and source/public-test Clippy in both configurations
and no-default-features processor passed. Logs: `pr06-packed-*`. Review/compile/lint found and fixed
stale imports/width names, a test mutating the newly reserved Controller selector, explicit-public
fixtures, and fixed-chunk iterator lints. No gate or degree bound was relaxed.

PR06 is implemented-awaiting-validation, not complete. Normal processor/parallel/lookup/streamed and
old fixture migrations remain behind three assembly errors and deferred toolchain work. Full active
production forged matrices, complete Range/And8/global Resolve closure, source/generated drift,
native/MASM/recursive/security and qualification gates remain. Old prove/verify/recursive producers
omit Chiplets8 and reject at statement construction; their legacy carrier cannot enable the selected
proof. Proceed to PR07 Core binding, then PR12 canonical claim/public/transport activation without
defaults or old-authority adapters. No GitHub PR or push was created.


### PR 07 Opening boundary

`adr1anh/librarytree-07-core-resolution` starts exactly at PR06 final review-description commit
`cc6a74742722ff9860d34cae20323faf90ee04ee`. PR06 remains implemented-awaiting-validation with every
recorded gate. Bounded source research confirms the selected four explicit decoder resolved-D lanes
produce decoder27/Core52, separately from public Core36, and add one dedicated capacity1 Core Resolve
column. It identifies existing keyed K/D/mode/row evidence for native production, missing EXEC
classifications, first-row/padding principal gaps and END/root completion changes. Proceed under PR07's
existing scope/acceptance; no shared semantic ambiguity or new policy/default was selected. No PR07
code/check pass is claimed at this opening, and no GitHub PR or push was created.


### PR 07 Initial Core validation checkpoint

At branch `adr1anh/librarytree-07-core-resolution`, verified HEAD
`66c8dd135e4356607e0087e8c8bd18977610be64`, the reviewed Core MAIN/Resolve/native sources
remain uncommitted. After AC/heavy guards the actual AIR and processor libraries compile.
AIR tests pass382/fail2: actual Core52/decoder27/aux5/Core36, degree9 and new Core binding tests
pass; the expected column-map snapshot is now updated but not rerun. The legacy claim fixture's
32-public assumption remains an explicit PR12 integration gate, with no dropped principal or
compatibility fallback. Public execution passes17/fails1: the new all-mode native fixture reaches
OutputStackOverflow(12); the strengthened mutation-rejection test passes. Logs `pr07-core-*`.
These scoped results do not establish full proof acceptance or clear inherited gates.

The user's repeated identity clarification reaffirms authoritative D3 and separate correction
`a477732bc`; profile Rustdoc alignment is `71bf65973`. Both exact Page formulas, permanent binding,
full L(I)/external(I) projection and required external Protocol inputs remain unchanged. This
checkpoint updates documentation only, preserving all in-flight implementation. No GitHub PR or push.


### PR 07 Reviewed Core binding and native checkpoint

`c668075ff` appends four resolved-D lanes, enables EXEC, constrains canonical invocation helpers,
real root-END/absorbing HALT and first/final K_entry principal. `299452ea6` adds the dedicated unit
Resolve column with literal normal/SYS tags, executed-child D versus static K/zero preimages and
root completion from actual completed hash/next principal. Signed END multiplicity r−1 preserves
degree9; Core boundary now accepts exactly deferred4 and emits only two transcript terms.
`cf934ab3f` writes validated retained K/D/mode/row events, preserves initial/terminal principals
and marks the actual RootEnd. Public tests `606d36364` cover all five modes, K≠D, alias/cache-hit
frequencies, source/debug/replay/streamed/fragment parity and exact mutation rejection. Review
strengthened the negative oracle; final dynamic fixture cleanup restores stack depth without
removing saved-overflow coverage. No new witness authority, encoded field or wire version.

After AC/heavy guards AIR383 tests pass; the sole failure is the explicit legacy-claim fixture
32-versus36 public mismatch, reserved for PR12 rather than hidden by a K-dropping fallback.
The column snapshot passes. Public execution18 and witness9 pass in default/testing configurations.
Strict AIR library/tests, processor library and exact-source/public-test Clippy in both configurations
plus no-default-features processor pass. Logs `pr07-core-*`. Initial test/lint failures are retained
separately. Source and integration reviews are clean; formatting/whitespace checks pass.

PR07 remains implemented-awaiting-validation. Full production forged matrices/global lookup closure,
normal decoder/lookup/parallel suites behind assembly migration, generated/MASM/recursive/security
and inherited gates remain open. Canonical claim44/transport3/proof activation remains PR12.
Finalize PR07 review scope, then continue PR08 without replacing the retained session, duplicating
its ledger or assuming replay parity establishes proof acceptance. D3 and external profiles unchanged.


### PR 08 Opening boundary

Branch `adr1anh/librarytree-08-replay-debug` starts at final PR07 review-description commit
`12e78f95374f2bc5c690ca814e44601e48104b8b`. PR07 retains its explicit legacy-claim and inherited
acceptance gates. Reuse existing bounded v4/session reconstruction and one typed relocation.
Bounded research identifies cut/mixed-tag/malformed-ID coverage and separate runtime-versus-inline
debug diagnostics as remaining slices; no new ledger or serialized authority is selected.


### PR 08 First cut-coverage checkpoint

`11465c4f2` factors the same authenticated single-Mast fixture for arbitrary root programs and
migrates the private relocation test to explicit environment/trace limits, actual Controller length,
prefixes0/8/16 and serialized contexts across executable first cuts. Independently reviewed; unrun
behind the recorded assembly migration. No synthetic-prefix proof acceptance is claimed.

After AC/heavy guards the first public replay run passes18/fails1. New mixed normal/SYS counts
and nine precise malformed-ID cases pass. Fragment1 exposes DYN native build failure before export
(`invalid keyed replay record`); a focused diagnostic run confirms mode/cut. Keep the stronger
assertion and diagnose capture/replay. The separate source-independent runtime-frame API compiles
and has clean source/lifetime review, with public behavior checks pending. Temporary logging is
local diagnosis only and must be removed before implementation commits. Logs `pr08-*`.


### PR 08 Reviewed replay and runtime-debug checkpoint

`96adee6a6` fixes ordinary block snapshots at fragment boundaries: only an actual prepared keyed
transition retains its executing continuation. One-row DYN cleanup-SPAN replay exposed the old
outer-root shortcut; diagnostic evidence confirmed the wrong FinishJoin snapshot. Temporary
logging was removed. `63dde7907` tests all invocation/return cuts, source matrices at sizes1/3,
mixed normal/SYS cache frequencies and nine exact malformed opening/forest/root ID rejections.

`7afd90af7` exposes source-independent runtime Entry/Invoke frames with distinct K/D/opening/use
observations. Bounded transient markers reserve before publication and reference existing native
uses; no parallel authority ledger or wire change. Clone retains diagnostics, while trace projection
and serde omit them; ordinary capture avoids cloning discarded sidecars. `fbac6f48b` checks all
five modes/source/sync/async cuts, inline exclusion, pending/cancel publication, recursion/cache-hit
identity, cross-execution inequality and actual root-END entry retention/removal. Reviews are clean.

After AC/heavy guards execution22/witness9 pass in default, testing and testing+concurrent
configurations. Strict processor library and exact-source/public-test Clippy (default and combined
features), no-default-features processor and formatting/whitespace checks pass. The isolated
harness lock was refreshed offline for its real concurrent feature; repository dependencies/lock
were unchanged. Fresh normal `--lib trace::trace_state` stops at exactly three assembly errors:
finalizer.rs464/466 still pass child IDs, pending_record.rs77 lacks Exec. Private relocation and
sidecar unit tests remain unrun. Logs `pr08-*`; prior failed diagnostic/lint runs remain separate.

PR08 is implemented-awaiting-validation. Full relation rejection for omitted/doubled relocation,
normal private/parallel/lookup fixtures, production forged matrices, generated/MASM/recursive/security
and inherited gates remain. No proof acceptance or measured diagnostic-overhead claim. Proceed to
PR09 keyed assembly/package cutover, preserving D2/D3, required external production inputs and all gates.


### PR 09 Opening boundary

Branch `adr1anh/librarytree-09-keyed-packages` starts at final PR08 review-scope commit
`82935d6733278d871ab1f3f5a7e94f88b6e468d9`. Bounded source research confirms three assembly
errors reflect child-based pending/finalized calls, while exec still inlines and procref emits D.
Reuse PR04 NamespacePlan for declaration/key prebinding independent of optional bodies; then
thread typed K through real Exec/Call/SYS builders and retain independently callable roots.
Private/entry callable representation is distinct from the public-interface path restriction.
Package9 requires coordinated required metadata and explicit profile-aware admission; no version-only
bump, default home/profile, digest key, arbitrary I or old-format reinterpretation is selected.
PR08 and all inherited/external acceptance gates remain. No PR09 code/check pass is claimed.


### PR 09 First coordinated builder/path ownership

Proceed with zero-child typed-key pending Exec/Call/SYS records and canonical core builders in
MAST builder/finalizer/import code. In parallel, general semantic callable paths support entry and
helpers under explicit NamespacePlan; PublicProcedurePath restrictions and all existing codecs
remain unchanged. Frontend declaration prebinding must supply actual K independently of body
availability before these pieces are validated together. No dummy keys, default home/profile,
source-alias identity or kernel-string authorization is introduced. Source ownership is exclusive;
no PR09 test/build result is claimed yet.


### PR 09 Callable paths and semantic checkpoint

`b3440301e` adds general semantic callable paths and NamespacePlan K/parent derivation for entry
and helpers by reusing unchanged public-path validation rules. Public reserved-path restrictions
remain; no codecs or profile authority change. Independent review is clean. After AC/heavy guards
all215 package tests pass (one manual seed test ignored), strict library/test Clippy and no_std pass.
Uncommitted semantic cleanup passes317 syntax tests: runtime procedure recursion/ProcRef metadata
and qualified syscall name resolution, preserving constant/type/import checks. Independent sema
review is clean; its lint remains pending. Logs `pr09-callable-*` and `pr09-invoke-syntax-*`.

Builder and explicit frontend binding slices are frozen for integration/compiler review. Runtime
reachability must replace the old invocation DAG separately from real source-alias/constant cycles.
The user has been asked to select explicit-inline source syntax versus API-only opt-in; dependent
expansion remains unimplemented while independent work continues. No final package9/profile or
proof acceptance is claimed.


### PR 09 Frontend library and retention review checkpoint

`450ff638f` separately commits the reviewed semantic cleanup after317 syntax tests and strict
library/test Clippy pass. The actual assembly library now compiles: old child-ID/Exec errors are
resolved, with unused former implicit-inline machinery still warning while explicit-inline choice
is pending. Frontend binding/resolver reviews find no identity fallback but identify a concrete P1:
static subtree import loses independent helper/callback bodies after keyed nodes have zero children.
Builder ownership now fixes selected static callable-inventory retention with regressions. Runtime
scheduling and actual closed source-alias cycle checks proceed under separate graph ownership.
Frontend tests moved to a child module; review corrected an iterator-method error and strengthened
CALL/SYS source-operation pairing. Integration checks wait for coherent owner checkpoints.


### PR 09 Earlier scope checkpoint — identity wording superseded by D3

At verified branch `adr1anh/librarytree-09-keyed-packages`, HEAD `b6807f1b700b92849ceeede66d511f1b7bc29705`,
the user clarified that LibraryId is an opaque Word contained in the library, and publisher/name/
version derivation and interface commitments should not be specified now. D3 and scope above
now supersede that identity wording with the Page formulas and required Protocol validation.
Generic assembly/package consumers
need supplied IDs, declarations, explicit homes and callable/code metadata; separating any required
InterfaceArtifact/Profile coupling is follow-up implementation, not a claimed result of this edit.
Builder/frontend/graph changes are in flight and preserved. This checkpoint changes only the plan
and current brief, with no source, codec, format, test or implementation change. Existing VM
security/acceptance gates and no-PR/no-push restriction remain.

### PR 09 Reaffirmed Page identity and documentation checkpoint

Verified branch `adr1anh/librarytree-09-keyed-packages`, source HEAD
`ee32f09562da67002f4b315caf8c28a65705b026`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`.
The latest user clarification retains the actual Page formulas, permanent registration association
and full L(I)/external(I) distinction. D3 replaces arbitrary opaque Protocol assignment and the
later historical-formula wording, while generic APIs may still receive typed I independently.
Exact production inputs remain external, without weakening any acceptance gate. D4 separately
records the user's inline syntax approval; expansion is not yet implemented.

This checkpoint changes only the plan/current brief. Four private-code package files remain
uncommitted and untouched. Existing PR05–08 implementation and committed PR09 builder/frontend/
graph/fixture work are preserved. All11 cached source hashes match provenance; shared /tmp copies
remain retained. No Protocol production acceptance, code/format change, push or GitHub PR is claimed.


### PR 09 Keyed compilation and private-code validation evidence

Builder `235287733` with regressions `332e826dd` retains independent helper/callback roots across
static inventories and finalizes source occurrences child-first without using code supply as
binding authority. Callable declarations `0410592b0`, frontend `95761edcd`, runtime graph
`f36982d5a` and tests `6ce937f6e`/`8ac8c7e9b` separate K resolution, optional body supply,
recursive runtime reachability and actual source-alias cycles. Fixture `ee32f0956` preserves the
original nested MASM source with explicit complete program/kernel homes. Independent reviews
passed after retention, source-ordering and kernel-alias precedence findings were corrected.

Focused checks pass: builder63, callable frontend12, linker35 and nested fixture1. Syntax317 and
strict syntax Clippy passed earlier. The actual assembly library and no-default-features check
pass; strict assembly lint still stops on unused former implicit-inline helpers. It is not a pass.

`80a1933d8` separates an empty public API from actual callable code inventory. Constructors and
both readers require procedure roots independently of public exports; private bodies and explicit
External(D) references do not manufacture exports, entrypoints, code availability or authority.
Complete-forest commitments retain private-body identity. Independent four-file review is clean;
package223 pass/one manual seed ignored, strict package library/test Clippy and no_std pass.
All7 runtime-cycle tests now pass, including the previously failing private-only package fixture.
AC/heavy guards passed before each Rust command. Logs are `pr09-keyed-builder-tests-final-shared-policy`,
`pr09-frontend-identity-tests-final`, `pr09-linker-tests-final`, `pr09-nested-blocks-test-final`,
`pr09-private-code-package-*`, `pr09-runtime-cycles-tests-private-code` and
`pr09-assembly-no-std-private-code` under `.scratch/librarytree/logs/`.

PR09 remains in progress. D4 expansion is next; package9 activation, complete assembly and fresh
normal processor/relocation/sidecar checks, Protocol production inputs and all inherited acceptance
remain. The original three assembly compiler errors are resolved, not a current blocker. No
whole-stack/proof acceptance or GitHub publication is claimed. Documentation correction `2cb3757fc`
retains D3 and was committed separately from implementation.


### PR 09 Explicit inline validation and legacy fixture boundary

`ff5784032` adds distinct Inline AST/sema metadata without changing runtime EXEC. All319 syntax
unit tests and strict library/test Clippy pass. Implementation `72218ae6e` requires current-artifact
source ownership or an explicit expected-ImplementationRoot pin attached to the concrete defining
callable. Separate structural ordering rejects inline cycles while retaining mixed runtime recursion.
It reuses compiled callee bodies, local-frame wrappers and source occurrence machinery; inner K values
remain bound in callee context. Generic pin selection grants no Protocol admission.

Independent ownership/graph and source/expansion reviews are clean after correcting a P2 provenance
finding: complete static inventory import could replace the selected root's latest source occurrence
with a sibling wrapper's decorated occurrence. Materialization now returns the selected MastNodeUse
explicitly across inventory retention. Tests `319d291ae` cover eligibility, aliases, wrong/missing pins,
cycles/rollback, mixed recursion, local frames, definition/source separation, no-debug/missing callsite
and the exact static provenance regression. All13 pass; strict assembly library/test Clippy and
no-default-features pass without the former implicit-inline warnings.

The first bare full libtest run aborted on its default thread stack; Makefile155–165 explicitly sets
16MiB. The configured-stack rerun finishes252 pass/230 fail/6 ignored. It includes passing builder63,
identity12, linker35, runtime-cycle7 and nested fixture1. Read-only failure audit identifies228 missing
explicit caller NamespacePlan failures, one outdated MAST-root-versus-procedure-key diagnostic and
one expected-panic fixture stopped earlier by missing metadata. These setup failures mask later
assertions: no broad MASM or nesting-boundary acceptance is claimed. Standard test-dev/nextest coverage
remains pending. Logs: `pr09-inline-syntax-*`, `pr09-inline-frontend-tests-fourth`,
`pr09-inline-assembly-*` and `pr09-full-assembly-lib-configured-stack` under the separate log directory;
all Rust commands passed AC/heavy guards.

Next work supplies explicit test-fixture naming independently from production inputs and investigates
per-target project metadata. Do not add production default homes, infer authority from source aliases,
replace runtime exec with inline, or suppress failed gates. Package9, D3 production fixtures and all
inherited processor/proof/recursive/security/qualification gates remain; PR09 stays in progress.
