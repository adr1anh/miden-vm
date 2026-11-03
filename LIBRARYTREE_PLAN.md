# LibraryTree VM implementation plan

This plan is the current execution backlog for implementing the selected LibraryTree model in this repository. Once the plan is established, start implementation under the workflow below. This initial plan snapshot contains documentation only: no production implementation, compilation, tests, benchmarks or regeneration is claimed.

The repository baseline is `00b12150715891582864d256ef51c5ea46bfb282`, inspected on 2 November 2026. The design chapters use the earlier baseline `a3d9bc09ef8a956774eb4ec0e6e734428e194a8c`; source paths and interfaces below follow this checkout. The live design Pages remain unchanged.

## Sources and authority

Read the linked design chapters when implementing their contracts. This plan selects implementation boundaries; it does not silently decide remaining Protocol policy or compiler ABI questions. Current D3/D7 supersede earlier identity-formula selection and own-interface assumptions; D6/D8 supersede configurable N_kernel and claim44. Keep source snapshots/provenance unchanged; historical implementation evidence does not establish the revised contracts.

**Scope and identity clarification, revised 3 November 2026:** implement VM/toolchain support without implementing a Protocol registry. The user selects model C: generic code packages plus a separate publication/release wrapper. Library identity is an externally supplied opaque Word, optionally wrapped as LibraryId; identity derivation, including the Page formula, remains open outside the VM. Human-readable names are optional tooling mappings resolved before assembly. Do not invent an identity algorithm/domain or make publication metadata mandatory for generic compilation. Selected publication profiles must still enforce all their required validation. Preserve every existing security and acceptance gate; continue independent VM work while external inputs remain pending.

- [LibraryTree design workspace](https://chatgpt.com/space/page_2e2830d3aca081919395850e2d6425c3), [design overview](https://chatgpt.com/space/page_78e4c04efdb48191a07eb544f8729784), and [decisions and next steps](https://chatgpt.com/space/page_a19f6685aeb88191a31a35296a82e48b).
- [Namespaced execution shared contracts](https://chatgpt.com/space/page_11597d3254d8819196b4f5b3d0d13718), [execution, MAST and processor design](https://chatgpt.com/space/page_6260aefe8dd481919833c1414f870d34), and [environment execution model](https://chatgpt.com/space/page_0cb8fddb96a88191809388bf83fe686a).
- [Library chiplet and authenticated resolution AIR](https://chatgpt.com/space/page_b955981e1f588191a1e3274f1bd6a3c3), [proof statements and protocol integration](https://chatgpt.com/space/page_077d46e54c908191a760066e259ad09c), and [implementation and verification design](https://chatgpt.com/space/page_28e54e1ae6a881918a137de353478cda).
- [Assembly, linking and package contracts](https://chatgpt.com/space/page_8f108eb2fcf88191922e49df0dff6e31), [EXEC and explicit inline opt-in](https://chatgpt.com/space/page_6d5de3bc86fc8191bf08070f21ab4eb6), and [compiler and toolchain handoff](https://chatgpt.com/space/page_9bfed3770b6881919c72ccbbed3e85af).
- [VM–Protocol execution and release contract](https://chatgpt.com/space/page_97a099703b9c81919476a98e51550cd4), [private account code and environment binding](https://chatgpt.com/space/page_8b7ff9039cb08191ad573b8333bf230d), and [VM contract and feasibility review](https://chatgpt.com/space/page_9183e46c5e648191939ffc4cb4bffb9d).

## Scope and invariants

Breaking changes are accepted subject to D2: existing MASM programs must remain usable after rebuilding, with digest-shaped invocation targets interpreted as keys. New serialized MAST formats are allowed. Implement one new callable/statement model and rebuild its consumers; do not create a permanent dual-target executor or runtime digest fallback to ease the transition.

1. **Environment authority:** execution is defined by immutable `(K_entry, R_E)` under D6; syscall namespace N0 is a VM constant, not a descriptor field. Entry and every retained runtime invocation authenticate a binding in R_E. Code availability at implementation root D does not authorize execution. The environment root never switches on account/library calls.
2. **Uniform callable keys:** EXEC/CALL/SYSCALL and dynamic targets use ProcedureKey K; `procref` produces K. Separate newtypes distinguish K, D, R_E, N and label commitment L. Structural JOIN/SPLIT/LOOP/SPAN and `ExternalNode(D)` remain structural code commitments. Immediate keyed nodes have no callee child.
3. **Invocation modes:** EXEC/DYN preserve context and established principal; CALL/DYNCALL create a new user context and establish the requested K; SYSCALL enters root context while preserving principal. Entry initializes K_entry in the existing initial context. Matching returns restore frames/forests. Same-context execution shares RAM, overflow and FMP; namespaces do not isolate memory.
4. **Kernel authorization:** actual SYSCALL requires authenticated immediate parent `N = N0 = Namespace::initial()`. Environment construction reserves root exports for kernel-safe entry points and places application exports/entries and unsafe helpers beneath Env namespaces. List/Merkle grouping preserves N0 at any physical depth. Ordinary modes and kernel entry may still use root exports; add no ordinary-mode inequality, source privilege class, descendant wildcard or kernel-string authority. Namespace placement does not add RAM isolation or change context/principal conventions.
5. **Canonical authentication:** reuse standard Eidos FeltSequence framing and the agreed typed label codec/domains. Env extends N; Merkle/List preserve it; Mast(L,D) derives K under inherited N. DATA never emits an executable binding. Global executable-path uniqueness is a builder/admission obligation; selective membership is not its proof.
6. **Runtime exec:** every retained source exec, including local/bundled helpers, becomes real keyed EXEC (`0x5f`). Structural inline expansion requires explicit eligible fixed-body opt-in. Latest implementations are not silently frozen. Runtime recursion is distinct from forbidden structural inline cycles.
7. **Packed proof relation:** Library/Controller/AEAD/Memory/ACE/Bitwise/PAD share Chiplets24/4, the selected 22-cell Library overlay, nine fixed periodic columns and `[4,4,3,2]` lookup capacity. Four production AIRs remain. Degree bounds, lookup multiplicities and physical prefix relocation require actual capture/testing.
8. **Statement cutover:** D6 selects a new claim40 v2 (`K_entry[4] || R_E[4] || I[16] || O[16]`), Core36 public Felts, Chiplets4 public Felts and deferred-only aux4. The legacy claim40 has different semantics/domain and is not compatible; remove kernel-list and configurable-kernel authority. Expected public claims come from the verifier caller. Root END authenticates K_entry/D_root and closes the initial binding; all-HALT is invalid. Transport format 3 is separate from claim v2.
9. **Toolchain separation:** an opaque typed ID at the generic API boundary, declarations, explicit namespace home, code materialization and source aliases are separate. Derive K from the supplied home/export labels without requiring D or an interface commitment. Protocol-profile identity and registered-release validation must satisfy D3; generic consumers need not implement a registry. Bundling does not imply inlining. Retain all public/helper/address-taken callable roots. Final runnable artifacts contain no unresolved namespace relocations.
10. **Witness and resource trust:** host resolution/code loading supplies witnesses. AIR authenticates resolution; guest resource loaders must authenticate advice values before use. Code loading retains current requested-D/procedure-root checks and merge-advice-once behavior. Debug metadata never grants authority.

Included: core identities/MAST, processor and replay, packed AIR/proofs, assembler/project/package changes needed for opaque typed IDs/declarations/explicit homes, existing calling conventions, core library, public API/CLI, adversarial qualification and measured costs. Protocol registry/account implementation and identity derivation remain external under D3. An explicitly selected publication profile needs owner-approved identity/interface/release semantics, codecs/domains and its required publisher/home, registration and authenticated-closure evidence before acceptance is claimed. Existing prototypes do not establish it. Upstream Rust compiler lowering is a tracked handoff where its source is outside this repository. Do not claim these external obligations are solved by the VM or weaken their validation to unblock generic consumers.

## Workflow and completion rules

**Overall goal and milestones:** complete the full approved implementation and qualification in this
plan, incorporating subsequent user-approved revisions across every affected consumer and artifact.
Milestones organize work within that goal; they do not replace its scope or establish completion.
The user has requested continuation under this general goal after the design discussion.

**Initial milestone M1 — D6–D8 alignment under revised D3/D7 model C:** implement fixed-root syscall
semantics and public-kernel/private-helper placement, remove configurable kernel inputs, and carry
the generic code-package/publication separation through required consumers and formats. Validate
affected runtime/replay/assembler/AIR/public-input/native/recursive/generated contracts. This may
span several existing PRs: source-only correction is a substep, not proof that the milestone is done.
The current slice is the fixed-root correction before Package9 and project routing. Record partial
progress and downstream gates honestly; close M1 only with actual acceptance evidence. Then select
the next milestone from the remaining plan without closing, shrinking or recreating the overall goal.
Final completion still requires every required integration, regeneration and qualification gate;
external-profile obligations stay scoped to an explicitly selected integration.

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

Define distinct K/D/R_E/N/L types, typed label bytes, canonical environment objects, namespace/key derivation, bounded decode/build and duplicate executable-path validation. Establish the immutable execution descriptor and typed verifier identity/configuration contract. D6 reopens the implemented descriptor/configuration boundary for fixed N0 and `(K_entry,R_E)`; prior identity/hash vectors remain evidence for their unchanged primitives. Coordinate actual claim activation with PR 12; keep one canonical codec rather than two authoritative statement models. AccountId parsing and registry policy stay outside core.

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

Under D3/D7, generic compilation may consume an externally supplied opaque Word ID, declarations and explicit home without publisher metadata or registered association/closure proofs. Optional readable-name resolution belongs to tooling. Identity derivation and publication/interface associations are external profile policy, not a selected Page formula in the VM. Existing InterfaceArtifact/Profile code is a prototype, not production acceptance; separate mandatory generic-consumer coupling at a focused implementation checkpoint while preserving its validation and tests.

**Acceptance:** declaration-only Latest keys need no D; quoted `::`, exact Unicode bytes, typed labels and absent/present-empty ABI differ correctly; unknown versions/malformed homes reject; existing name/path/word invocation syntax remains accepted, with digest-shaped words interpreted as keys under D2. Explicit inline opt-in is an optional extension. **Checks:** `make test-assembly-syntax`; `cargo test -p miden-mast-package --lib interface`; CST tests only if changed.

## Stage 2 Authenticated execution and relation

### PR 05 Keyed runtime and atomic transitions

**Branch:** `adr1anh/librarytree-05-keyed-execution`. **Git base:** PR 04. **Semantic dependencies:** 01, 02; agree resolver/Resolve ledger schema with PRs 06–07.

**Existing files:** `processor/src/execution/{mod,call,dyn,external}.rs`, `processor/src/fast/{mod,operation,execution_api,step}.rs`, processor/executor/options/errors/continuation stack, host/default/forest store and public exports. **New:** small shared resolver/EXEC modules and bounded environment witness provider; focused public `processor/tests/keyed_execution.rs` and `processor/tests/keyed_witness.rs` with a shared single-Mast fixture. Extend the core arbitrary fixture with an authenticated environment and migrate `processor/src/fast/tests/arbitrary_forest.rs` so executable generation covers actual keyed invocations again.

Resolve `(R_E,K)->(N,D,opening)` before typed D-indexed code loading. Share prepare/commit transitions across pure/source-aware and sync/async execution; authenticate before state changes and make retries idempotent. Implement ENTRY/all runtime modes, requested-key caller/principals, context/FMP/overflow/return behavior and checked budgets. D6 removes configurable kernel input and checks authenticated immediate parent against fixed N0 on actual SYSCALL, including cache hits. Remove kernel-ROM/digest dispatch authority. Cache bindings by `(R_E,K)`, code by D, and preserve code-root checks/advice merge-once.

**Acceptance:** complete mode/context/principal/local/host-loaded matrix; same-D aliases distinct; no fallback; non-root syscall parents/Env descendants reject while namespace-preserving root List/Merkle paths pass; unknown key versus unavailable/bad D differ; cache/root/limit boundaries and failures/retries do not double-pop/save/charge. **Checks:** `cargo test -p miden-processor --lib environment`; `cargo test -p miden-processor --lib fast::tests`; focused existing source-debug/cache/aggregate-stack regressions. The environment-aware executable generator must exercise retained keyed invocations with valid bindings and bounded terminating call graphs, rather than leaving the temporary PR 02 structural-only restriction in place. Runtime success alone is not proof acceptance.

### PR 06 Packed Library witness and authenticated lookup

**Branch:** `adr1anh/librarytree-06-packed-library`. **Git base:** PR 05. **Semantic dependencies:** 01, 03 and PR 05 ledger contract; synthetic ledgers allow earlier research.

**New:** `crates/air/source/src/vm/constraints/chiplets/library/{mod,columns,tests}.rs`, `crates/air/source/src/vm/constraints/lookup/buses/library.rs`, `crates/air/source/src/vm/trace/chiplets/library.rs`, `processor/src/trace/chiplets/library/{mod,trace,tests}.rs`. **Existing:** chiplet selectors/columns/Memory/ACE/hasher control, lookup messages/buses, main trace schema, chiplet/parallel assembly and `processor/src/trace/tests/lookup.rs`.

Implement two-row Env/Merkle/Mast, complete reverse Lists, unit Open edges, normal/syscall Resolve frequencies, local four-coordinate syscall equality to fixed N0, compression interning and checked counts. Realize selected packed bands, 22 Library cells, ninth periodic column and `[4,4,3,2]` lookup groups without a fifth AIR or new Chiplets auxiliary column. Finalize prefix before physical address conversion.

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

Extend the existing versioned execution witness with immutable descriptor, entry binding, requested K/resolved D/mode/principal, bounded opening ledger and resolution IDs. D6 removes the kernel parameter from descriptor/replay contracts; version changed wire layouts and reject obsolete records instead of silently defaulting their field. Replay without host I/O, retaining multiplicities across cache hits/fragments. Use one checked final P_L conversion of typed logical Controller addresses, preserving stopped/resumed state and sentinels. Distinguish real EXEC activations from inline source frames and display K/D separately.

**Acceptance:** sequential/parallel/buffered/streamed/no-source parity at each invocation/pending/return cut; malformed/missing ledger IDs reject; normal+syscall shared opening counts survive; zero/sentinel/eight-row prefix boundaries and omitted/doubled offsets reject. Old/inconsistent witness versions fail clearly. **Checks:** `cargo test -p miden-processor --lib --features concurrent trace::parallel`; `cargo test -p miden-processor --lib trace::trace_state`; focused existing source-debug/step regressions and trace lookup checks.

## Stage 3 Toolchain and runtime contracts

### PR 09 Keyed assembly and package9 cutover

**Branch:** `adr1anh/librarytree-09-keyed-packages`. **Git base:** PR 08. **Semantic dependencies:** 02, 04, 05; proof checks require PR 12.

**Existing files:** `crates/assembly/src/{assembler.rs,procedure.rs,mast_forest_builder.rs,fmp.rs,instruction/procedures.rs,linker/}`, `crates/assembly-syntax/src/sema/passes/verify_invoke.rs`, `crates/mast-package/src/package/{manifest.rs,mod.rs,serialization/}`, debug-info provenance. Extend assembly tests for procref/procedures/dynamic/kernels/root calls/link cycles/imports/packages/locals; add `crates/assembly/src/tests/namespaced_execution.rs`.

Before freezing Package9, deliver the focused D6/D8 correction in small commits on the current integration branch: core descriptor/verifier configuration, processor session/replay/witness, Library AIR/public-value interfaces and assembler syscall lowering/placement. Kernel tooling places public executable exports at root and private helpers beneath Env, without an extra syscall-export list. Revalidate affected contracts without rewriting historical stack commits or undertaking PR15a cleanup. Then split identity resolution from body supply, runtime reachability/SCCs from acyclic inline dependencies, and retain all public/helper/address-taken roots. Emit K for every retained invocation/procref; explicit inline alone composes a body. Activate validated namespaced package9 metadata and MAST0.0.6 together across trusted/safe readers, commitments and strip-debug. Replace root-centric Program/kernel reconstruction, root-call lowering and hardcoded `$kernel` authority rather than wrap them.

Kernel item reexports preserve the defining canonical K and receive the same construction checks
as direct exports. Remove old parser/linker bans based solely on kernel source roles while retaining
ordinary visibility, module/item validity, conflicts and import-cycle checks. Public submodule
exports are part of the public kernel surface; their canonical bindings belong at N0 even when
their source paths have several components. Source aliases never manufacture a second binding.

D7 selects model C: generic Package9 carries complete naming/callable/code information without own_library_id or own_interface_commitment fields; a separate publication/release wrapper owns the library/revision and profile-specific associations. Wrapper and package may be distributed together. IDs are supplied opaque Words, not inferred from homes, D, package names or readable aliases. This grants no publication admission: any selected profile must enforce its required identity/interface, publisher/home, release and closure evidence under D3. Implement the generic package and publication boundary without inventing external ReleaseRecord bytes. Missing required naming/code metadata still rejects. Preserve independent callable-root retention and the in-flight builder/frontend/graph work. Exact required naming must affect artifact commitments and deduplication/cache matching: equal D or source provenance with changed home/canonical binding cannot reuse old symbols or artifacts.

D5 selects a standard assembler/project Latest/Pinned naming convention over these generic bindings, with an explicit custom-home/binding escape hatch. Preserve selected homes and callable identities without making the VM recognize path names. D6/D7 resolve the former kernel-input and code-only-package applicability questions. Standard home helpers and explicit source default-home configuration now exist; complete artifact callable expectations, automatic target naming and distinct instances remain PR10. A source default home is not a package ownership/public-surface claim.

Package9 retains required naming as opaque transport in the generic code container. Decoding code
and transport does not approve a home or unknown TypedId; canonical naming admission uses explicit
current profile/context/limits. Locally retained canonical compiler metadata can be paired with its
exact transport without claiming publication admission. Imports must preserve that exact naming,
project bindings onto linker symbols and retain private callable metadata independently of source
aliases/debug paths. Code candidates may omit an entry across usage tags; actual runnable entry
selection requires explicit K and its own selected procedure root. An existing manifest entry must
agree with that K. A target tag does not manufacture an entry or public API.

**Acceptance:** Latest-only declarations compile without D; caller hash stable across selected implementations; pinned-only self/helpers work; bundled/external supply preserves K; runtime recursion compiles/inline cycles reject; callback roots survive retention; malformed homes/relocations/old serialized callable formats reject and required metadata survives debug stripping. Existing MASM invocation/procref source rebuilds under D2, using K and real EXEC without digest fallback. **Checks:** scoped `assembler::callable_identity_tests`, `assembler::inline::tests` and `tests::link_cycles` within `RUST_MIN_STACK=16777216 cargo test --locked -p miden-assembly --lib`; full package `cargo test --locked -p miden-mast-package --lib`; then full unit run and standard `make test-assembly EXTRA=--locked NEXTEST_PROFILE=ci` after focused failures resolve. The Makefile forwards `test=` to its filter; the previous `namespaced_execution` filter names no current assembly test. Use existing modules and verify nonzero execution counts.

### PR 10 Revision-aware projects and code supply

**Branch:** `adr1anh/librarytree-10-project-imports`. **Git base:** PR 09. **Semantic dependencies:** 04, 09. Exact Protocol release codecs remain external inputs; generic dependency-instance support can proceed independently.

**Existing files:** `crates/project/src/{dependencies.rs,dependencies/graph.rs,linkage.rs,package.rs,ast/dependency.rs,ast/package.rs,ast/parsing.rs}`, project tests, `crates/mast-package/src/dependency/mod.rs`, manifest, `crates/assembly/src/project/{dependency_graph.rs,runtime_dependencies.rs,build_provenance.rs,post_process.rs,tests.rs}`, linker module ownership and packaging fixtures. **New if justified:** `crates/project/src/library_import.rs`.

Separate source aliases, supplied opaque Word library IDs, optional readable-name catalogs, dependency instances, explicit namespace bindings and optional code/artifact supply. Resolve configured readable names before assembly; missing or ambiguous names reject. Replace PackageId-only graph/manifest/cache ownership where it prevents distinct bound artifacts from coexisting. Bundling supplies code without changing K or implying inlining. Propagate required callable/helper mounts and the D6 reserved-root convention; no configurable kernel namespace is supplied. Generic consumers need not implement registry storage or release codecs. Retained Latest dependencies remain dynamic across authorized environments, including inside pinned releases; selected publication adapters must validate their required release/closure inputs before claiming profile behavior. D3 leaves identity derivation and interface policy external.

Complete D5's standard Latest/Pinned project/import routing over the implemented LibraryImport helpers and explicit source-default manifest choices; retain custom homes and complete Bound declarations. Artifact imports need explicit expected visible-path/callable mappings, preserving defining keys for reexports and mixed helper/dependency homes. Do not infer public ownership from PackageNaming.namespace_plan or require every retained binding to share a home. Route caller-supplied full ancestor bases and opaque IDs through configuration/API metadata, not special MASM import spelling. Use the existing miden-project.toml project layer when adding file configuration; exact fields and ergonomic builder names remain implementation design, not already supported syntax. Keep code supply (bundled/external) independent from namespace selection and expected implementation bindings. Test standard and custom homes, stable Latest K across selected bodies, distinct revision-qualified K, unchanged source aliases, naming-aware caches and equivalent bundled/external invocation behavior. This adds no registry, ID generator or interface-commitment requirement to generic assembly.

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

Activate D6 claim40/domain v2 in canonical order `K_entry[4] || R_E[4] || I[16] || O[16]` and proof format3. Explicitly derive Core36 as `I || O || K_entry` and Chiplets4 as `R_E` from the expected caller claim, retaining deferred-only aux4. Keep domain/version rejection of legacy40 and obsolete44 layouts despite matching legacy field counts. Replace program/kernel external terms with singleton root Open and keep two deferred terms. Remove variable kernel-list/count/security authority. This is the production relation enablement point; earlier runtime slices remain incomplete until these bindings close.

**Acceptance:** exact field/order/tail vectors; every mutated R_E/K_entry/I/O fails, including ordinary-only execution; non-root syscall suppliers fail the fixed-N0 local checks; old claims/transport/public shapes/fifth AIR reject; three external terms and one combined Chiplets normalized sum close; deferred/empty/complete precompile obligations persist. **Checks:** `cargo test -p miden-core --lib program::claim`; `cargo test -p miden-air-definitions --lib vm`; `cargo test -p miden-vm-stark --lib`; `cargo test -p miden-verifier --lib`; focused native prove/verify cases.

### PR 13 Core-library packaging and runtime migration

**Branch:** `adr1anh/librarytree-13-core-library`. **Git base:** PR 12. **Semantic dependencies:** 09–12 and preserved supported calling conventions; final recursive identity follows in 14.

**Existing files:** `crates/lib/core/{build.rs,src/lib.rs,src/bin/generate-package.rs,asm/miden-project.toml}`, MASM public/helpers/callback tables including `asm/sys/vm/{mod,ood_frames}.masm` and `asm/stark/utils.masm`, core-lib tests/helpers/sys/forest merge, assembly packaging fixtures and affected generated-assembly builders.

Build the library with its supplied opaque ID, explicit home, declarations and required callable/mount/code metadata. Retain existing advice/resources and callback/helper callable roots; migrate ordinary package/build/host consumers to keys. Protocol release records or new inventory/profile schemas are conditional on a future adapter, not generic packaging requirements. Choose inline opt-ins deliberately rather than auto-inline existing exec. Prepare verifier bundle metadata contracts; PR 14 owns recursive mathematics, final verifier identities/configurations and related generated artifacts to avoid overlapping ownership.

**Acceptance:** external/bundled supply under the same explicit bindings executes equivalently; private callbacks and required helpers survive retention/export; declaration-only callers can use a changed authenticated implementation without changing their keys; required package/code/advice data survives artifact export; source-root stability tests reflect intentional new semantics. Registered Latest/Pinned and profile-specific inventory tests apply only to an adopted adapter. **Checks:** `make test-core-lib` for ordinary/core-library scopes that are runnable at this stage; `make test-masm-root-stability`; record recursive checks precisely as deferred to 14 where necessary.

### PR 14 Recursive verification and generated identities

**Branch:** `adr1anh/librarytree-14-recursive-verifier`. **Git base:** PR 13. **Semantic dependencies:** 06, 07, 09, 12, 13; native relation must be settled.

**Existing files:** `crates/stark/vm/src/recursive/mod.rs`, core-lib `asm/sys/vm/{mod,claim,public_inputs,layout,parameters,aux_trace,ood_frames,constraints_eval,deep_queries}.masm`, regeneration binaries/helpers, `crates/air/generated/{build.rs,src/vm/}`, core proof compatibility, generated core-lib docs and proof-order/scatter/security tests. **New:** `crates/lib/core/tests/stark/librarytree_claim.rs`, registered in existing test module.

Read exactly40 advice Felts with bounded staging/no overread; hash five complete eight-Felt blocks under the new claim frame/domain. Stage Core36/Chiplets4/three external terms; remove kernel-list materialization while retaining security/deferred results and all24 proof permutations. Regenerate evaluators/ACE/layouts/constants/docs/setup/relation roots; bind verifier entry and helper/resource/mount configuration under the fixed-N0 relation, rather than D alone; remove the independent N_kernel configuration field. Replace old `procref == verifier root` APIs/docs with typed identities/request v2.

**Acceptance:** native/MASM/recursive claims match; adjacent scratch cannot affect hash; old/missing/excess advice fails; malicious child/rebound entry/helper/root, non-root syscall suppliers and omitted deferred obligation reject. Captured degrees/shape/security counts match generated assets and rebuilt identity. **Checks:** `make regenerate-constraints`; `make check-constraints`; generated capture/drift/ACE tests; `cargo test -p miden-core-lib --test core-lib stark`; `cargo test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library`; `make check-pvm-proof-fixture`. Regenerate generated MASM docs with `MIDEN_BUILD_LIB_DOCS=1 cargo build -p miden-core-lib` when changed, following repository CI. Regenerate PVM constants/root only if its emitted code/relation changed.

### PR 15 Public API, CLI and consumer closure

**Branch:** `adr1anh/librarytree-15-cli-integration`. **Git base:** PR 14. **Semantic dependencies:** 08–14.

**Existing files:** `miden-vm/src/{lib,internal}.rs`, `miden-vm/src/cli/{compile,bundle,run,prove,verify,data,utils}.rs`, processor public API, `crates/test-utils/`, integration exec/prove_verify/flow_control/CLI suites, examples, fixtures and user/developer documentation.

Replace root-only verification flags and implicit Program/kernel reconstruction with explicit versioned expected descriptor/claim inputs. Share run/prove/verify validation; separate environment preimages from code bundles and report K_entry/R_E/D distinctly and explain fixed-N0 syscall eligibility. Migrate remaining root consumers; report Library authentication metrics instead of kernel-ROM counts. Preserve atomic output, security estimator and precompile preparation/resource guards introduced since the design baseline.

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
Lists, local fixed-N0 syscall checks, statement/deferred obligations, resource bounds and D2.
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

Qualify the actual implementation across shallow Lists/selective Merkle, mostly-unused large environments, repeated/cache-hit calls, equal-D aliases, changed authenticated implementations with stable callers, explicit self/helper bindings, root syscalls through nested List/Merkle grouping, ineligible Env descendants/private helpers, root modes, resumed/parallel traces and boundary/overflow attacks. Combine native and actual recursive malicious-child tests with forged trace/lookup matrices. Builder tests establish global executable-path uniqueness; caller-selected descriptor authority is explicit. Registered Latest/Pinned, randomized private-instance and Protocol admission/freshness fixtures apply only to future adopted adapters, not minimum VM completion. AIR membership must not claim those external properties.

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

**D3 Externally supplied library identity, revised with the user on 3 November 2026:** the VM and
generic toolchain receive an opaque identity commitment as a Word, optionally typed as LibraryId.
Identity derivation, including the Page's publisher/name/interface-version formula, remains open
outside the VM. This supersedes the earlier decision that the Page formula and permanent interface
association were selected requirements. Do not derive I from names, D or interface/code hashes, merge
it with assembler-derived hashes, or introduce a generic identity generator or registry.

Human-readable names are optional tooling/catalog mappings to the supplied I, resolved before
assembly. Direct Word input needs no catalog. Unknown or ambiguous configured names reject; source
aliases and display names do not enter K derivation or establish ownership, binding authority or
permission to publish. A map or a tooling trait may provide resolution and optional reverse display;
exact API names are implementation design, not a VM trait or runtime name-lookup requirement.

D7 selects a separate publication/release wrapper. Its identity/revision/interface associations,
publisher authorization, identity formula, codecs/domains and registry/freshness rules belong to
an explicitly selected external profile. An opaque ID alone authenticates none of them. Such a
profile must enforce every required home/TypedId, publisher, registration, interface, release and
closure check; missing policy/evidence grants no fallback or production-acceptance claim. Generic
VM work may proceed while those owner inputs remain pending.

Preserve existing InterfaceArtifact/Home v1 canonical encoding, exact input, caller budgets,
expected-I/context checks and validation/tests while decoupling generic consumers. Their transport
commitment is not automatically a Protocol interface commitment. For the existing Page/prototype
closure contract, L(I) includes self and stored_external represents L(I) minus self; preserve that
projection without claiming it defines a future profile or adding a VM-level cycle prohibition.
Retained Latest dependencies stay dynamic across authorized executions even inside pinned releases.

Preserve all authentication, root-END, invocation/principal, D6 syscall-parent, code/root,
malformed-input, replay, resource, degree/lookup, generated/native/MASM/recursive and security gates.
The [LibraryTree proposal](https://chatgpt.com/space/page_d5d09034b1e881919a4c425fe6429d0a) and
[compiler/assembler contract](https://chatgpt.com/space/page_ad138e12f6cc8191a0e7af15a751dbf1)
remain reference proposals with cached Page/date/block/hash provenance; their identity formula is
not a frozen VM requirement. This decision changes documentation, not registry/account policy.

**D4 Explicit inline opt-in, approved by the user on 3 November 2026:** add optional
`inline.<target>` syntax. Existing `exec.<target>` remains a runtime invocation. Inline requires a
local fixed body or an explicitly pinned import, rejects Latest imports and structural cycles,
and preserves inner runtime keys. Approval selects syntax/eligibility, not completed implementation.

**D5 Standard assembler namespace convention with explicit custom bindings, approved by the user
on 3 November 2026:** provide first-class assembler/project support for Latest/Pinned dependency
naming over the generic VM namespace primitives. Under the caller-supplied complete ancestor base,
the standard convention is:

```text
Latest(I):    base / Text("latest") / LibraryId(I) / module... / export
Pinned(I,r):  base / Text("pinned") / LibraryId(I) / Revision(r) / module... / export
```

These are typed labels, not source path strings or VM namespace classes. Preserve an explicit
custom-home/callable-binding path; the standard convention does not restrict the generic API to
these layouts. Existing MASM `use`, `exec`, `call` and `procref` spelling remains; import/project
configuration selects bindings. **User clarification, 3 November 2026:** project dependencies
must explicitly select Latest or Pinned; an omitted selection is an error, not implicit Latest.
Explicit custom-home/callable bindings remain supported. Exact manifest fields and helper API
names remain implementation design. Raw NamespaceInputs still has no implicit N0 home.

LibraryId is supplied as an opaque Word to generic assembly; this convention supplies no identity
hash or mandatory publisher/interface/registration metadata. Selected implementation D and code
supply do not enter K derivation. Namespace spelling alone does not authenticate a pinned body;
the caller's authorized environment/expected bindings establish it. Changing a complete home
requires relinking or an explicitly supported runtime-base mechanism, not silent relocation.
Keep D4's inner runtime keys and every VM/security acceptance gate. D6/D7 below resolve kernel-input timing
and code-only package identity/interface applicability; exact configuration fields remain implementation design,
while the explicit-selection requirement above is settled.

This records an approved implementation direction for PR09/10; approval alone is not implementation
evidence. Consult the ledger for completed helpers/configuration and remaining artifact/profile gates.

**D6 Fixed-root kernel, agreed with the user on 3 November 2026:** replace configurable/public
N_kernel with the fixed `N0 = Namespace::initial() = H_ENV_INITIAL_NAMESPACE([])`, independent of
R_E and not the zero Word. Actual SYSCALL requires its authenticated immediate parent to equal
N0, checked locally on every relevant supplier/use, including cached resolution. Every root
export is eligible; source visibility, package kind and textual names grant no separate privilege.
Environment construction reserves root for kernel-safe exports and places application entries,
ordinary application exports and unsafe helpers beneath Env. List/Merkle grouping preserves N0;
this is not a physical-tree-depth restriction. Root executable labels remain globally unique.

Execution fixes `(K_entry,R_E)`; the caller/verifier must still authorize R_E and its selected
bindings. Remove independent kernel-namespace inputs from descriptors, assembly, replay/witness,
verifier configuration and public statements. Planned claim40 v2 is `K_entry[4] || R_E[4] ||
I[16] || O[16]`; Core36 remains `I || O || K_entry`, Chiplets4 becomes R_E, deferred-only aux4
and three external terms remain. Recompute framing/transcript/generated/native/MASM/recursive
contracts consistently; legacy40 and obsolete44 formats are not silently interchangeable.

Preserve existing ordinary invocation/entry eligibility, context/RAM/FMP/overflow/principal rules,
root-END, authenticated K-to-D/code separation, complete openings, resource/lookup/degree/security
gates and global path uniqueness. Packed24/4, four AIRs and PR15a's later cleanup are unchanged by
this decision. Existing code/evidence uses the prior kernel parameter until migrated and tested.
This closes the old build-time-versus-execution-time kernel-path question.

**D7 Model C package/publication separation, revised with the user on 3 November 2026:** generic
code packages have no own_library_id or own_interface_commitment fields. They retain complete
callable names/homes, code/helper roots and any required entry/binding metadata, independently of
executable/kernel/library-like usage tags. A home containing I does not establish package ownership.
The inventory records retained callables and required compiled homes; additional environment mounts
can derive alias keys without relocating embedded keys or replacing required canonical mounts.

A separate publication/release wrapper contains or references the code package and owns the supplied
library identity, revision and selected-profile metadata/evidence. Both may be distributed together;
separation does not require two files. D3 leaves identity derivation and interface association policy
external. A selected profile still validates all its required evidence without fallback; no production
ReleaseRecord schema is invented here. Existing code-dependent Package::interface_commitment is not
the immutable declaration commitment and must remain distinguished during migration. Concrete type,
constructor, section and catalog-trait details remain implementation design. Unbound relocatable
objects are a separate optional toolchain extension, not required for this choice.

**D8 Kernel-package placement, agreed with the user on 3 November 2026:** assembler/package
tooling places public executable kernel exports directly in fixed N0 and retained private helpers
beneath a child Env namespace. Reuse existing public/private declarations and namespace bindings;
no additional syscall-export list is required. This is a construction convention: the VM ignores
source visibility and authorizes actual SYSCALL solely by the authenticated immediate parent.
Any executable binding actually placed at root is eligible, even if its source was private.

Keep public root labels globally unique across composed kernel fragments; reject conflicts rather
than silently renaming or selecting a body. Source aliases do not invent new canonical keys, and
ordinary EXEC into a child helper preserves its existing context/principal conventions. Child
helper homes may be package/revision-qualified using D5/custom bindings; this decision does not
freeze the exact prefix spelling or configuration/API representation, require an own LibraryId
for code-only packages, or derive names from implementation D. Existing source imports remain.

The user has requested continuation under the general implementation goal and M1 above. Revised
D3/D7 and D6/D8 are approved design, not claims that source, public-input layouts, readers or
acceptance checks have been migrated.

## Open decisions and external gates

| Gate | Required decision/evidence | Blocks |
| --- | --- | --- |
| Generic VM/toolchain interchange | D1 fixes VM node preimages. D3 takes externally supplied opaque Word IDs; derivation/interface policy remains external and open. Optional readable-name maps/catalogs resolve before assembly. Audit mandatory InterfaceArtifact/Profile consumer coupling without weakening canonical/budget/malformed-input/code-root checks. | 04, 09–10, public API closure |
| Frontend syntax and eligibility | D2 preserves existing MASM name/path/word syntax; D4 approves optional inline.<target> for local fixed bodies or explicitly pinned imports, rejecting Latest and structural cycles. Implement source-alias versus published-alias/wrapper behavior and diagnostics without changing inner runtime keys. | 04, 09 |
| Standard namespace convention implementation | D5 approves standard assembler/project Latest/Pinned naming plus explicit custom bindings. Implement configuration/routing, metadata persistence and cache matching; exact fields remain implementation design; omitted Latest/Pinned selection rejects. No new MASM import syntax, VM path interpretation, implicit N0 or generic ID/registry/interface-commitment requirement. | 09–10, public API closure |
| Fixed-root kernel migration | D6 resolves kernel input: fixed N0, descriptor `(K_entry,R_E)` and revised claim40/Core36/Chiplets4. D8 fixes kernel tooling placement: public executable exports at root, private helpers beneath Env, no extra export list. Migrate descriptors/runtime/replay/assembler/AIR/public/verifier contracts and revalidate; retain trusted R_E, local parent checks and all acceptance gates. | 01, 05–09, 12–15 source/format/validation follow-up |
| Package9/publication boundary implementation | D7 selects C: generic code package without own I/interface fields, separate publication/release wrapper. Retain complete callable/code/entry metadata and mandatory selected-profile validation; do not invent external wrapper bytes. | Package9 constructors/readers/admission; 09–10 |
| Private reusable-instance ABI (deferred extension) | If later adopted, specify authenticated runtime-base transport and relative-key/procref lowering before claiming immutable randomized-instance support. Current explicit absolute homes still require final linking; no implicit relocation or caller-derived namespace. | Future optional ABI adoption only |
| Existing shared/fresh-context behavior | Preserve D2's stack/memory/FMP/overflow and all invocation-mode conventions with regressions. Namespace authentication supplies no RAM isolation. Additional high-level layouts, heap/function-table ownership and initialization/reentrancy profiles are deferred unless an explicitly selected feature needs them; do not invent a fresh-context-only/stateless-only restriction. | 05, 09, 13, 15–16 calling-convention acceptance |
| Protocol profile and production fixtures | D3 leaves identity derivation, including the Page formula, and interface policy external/open. A selected production profile requires owner-approved semantics/codecs/domains and all applicable publisher/home/TypedId, registration and closure evidence, with no fallback. These inputs do not block generic VM work; production-profile acceptance is unclaimed. Expected descriptor authority, executable-path uniqueness and D6 fixed-N0 syscall checks remain required. | Selected Protocol-profile acceptance; dependent codec/admission work |
| AIR feasibility | Capture actual global degree ≤9, namespace degree and complete `[4,4,3,2]` lookup groups; prove unit rooted provenance/no-wrap under combined bounds and typed address relocation. | 06–08, 12, 14, 16 |
| Verifier closure | Canonical entry/config/helper/resource/mount identity under the fixed-N0 relation; no self-identity fixed point or entry-D-only trust. | 12–14, recursive acceptance |
| Measured costs and limits | Agree representative workload/limit matrix; report actual overhead and guard allocations/counts/replay. | 16, release readiness |

If a gate requires a material shared decision, stop its dependent work, ask the user the concrete questions and record the exact unresolved choice. Continue independent preparation while waiting. Do not silently weaken the selected execution modes, security contract or supported scope to bypass it.


## Status ledger

All implementation rows begin planned. The first plan commit SHA and later exact evidence are filled by the orchestrator after commits/checks occur. No test was run to prepare this initial snapshot; later evidence must be recorded as implementation proceeds. Evidence and decision checkpoints below record the contract selected at their time. Current D3/D7 supersede earlier identity-formula finality and optional-own-field wording; pre-D6 evidence records the original configurable-kernel relation. Preserve history and rerun affected gates after migration.

| PR | Status | Implementation/plan commit SHA | Passed evidence | Deferred checks or blocker |
| --- | --- | --- | --- | --- |
| 00 Plan | complete | `1411d8581` initial plan-only commit | Two independent source/design reviews; PR/branch structure and whitespace checks; staged `git diff --cached --check`; SSH signature verified | No Rust build/test needed for documentation-only scope |
| 01 Identities | implemented-awaiting-validation | Latest `8152f9a34`; prior slice SHAs in evidence below | Independent reviews; 86 program tests including registry disjointness; final verifier fixture tests 12/12; public API fixtures; no-default-features, scoped rustfmt/Clippy; 36 shared vectors | Prior PR01 contract was complete; D6 now requires descriptor/verifier-configuration migration and fresh affected checks. Protocol-specific codecs/authority remain outside this unit. |
| 02 MAST | implemented-awaiting-validation | Latest `364fbb35c`; generator `91d52f92c`; base `4f6cda599` | Independent reviews; 398 arbitrary-feature core tests, 198 default MAST tests, four explicit cycle/recursion cases, core seed generation, public API and full-feature Clippy pass | Processor witness checks await 05/09; fuzz smoke at 16. Environment-aware executable generator restored at 05 (`4bfa6fc94`, `15a9a07c0`). D2 preserves existing MASM source. |
| 03 Chiplet foundation | implemented-awaiting-validation | Latest `a8e0daec9`; state `997c5edae`; Memory `411b22f8b`; base `7602d32ed` | Memory unit/generated/Clippy checks pass; independent logical/physical/state/acceptance reviews and formatting | Fresh processor address/state, parallel and serde execution is recorded at the PR09 checkpoint. Full relation, adversarial and qualification gates remain; actual Library prefix/alignment is at 06. |
| 04 Toolchain contracts | implemented-awaiting-validation | Fixture `2a3f608e3`; decoder `5c9c78799`; encoding `a70fdc8b1`; Home `a4ceb8260`; syntax `8a02bc43c`; base `45be30b96` | Independent reviews; full package 208 passed/one manual seed test ignored, 52 interface-filter tests, syntax327, scoped/combined test-inclusive Clippy, no-default-features and formatting | D3 now leaves identity derivation/interface policy external/open; selected-profile production fixtures remain unresolved and unclaimed. Audit generic declaration/home consumer coupling while preserving profile validation. Executable lowering at09; fuzz at16. |
| 05 Runtime | implemented-awaiting-validation | Matrix `2f9394e19`; terminal callback `4ebcb72ee`; earlier implementation/fixture refs below; base `722392682` | Independent reviews; actual processor lib/default/no_std/strict Clippy; 16 public execution (40-case matrix) and five witness tests; core406; exact-source host/fixture10 and overflow4; strict harness Clippy; 52 earlier native tests | Processor unit/integration fixture migration now runs normally: 1,866 unit passes/24 legacy-public-statement failures/one existing ignore, 49 integrations and 69 concurrent replay tests pass. Remaining statement/proof/fuzz gates stay open. Proof/AIR/statement activation is later. |
| 06 Library | implemented-awaiting-validation | MAIN `b9db78846`; lookup `d5245be2e`; public boundary `4bbba1e34`; native `668f581c4`; test `8ddf89e49`; reporting `c53ea3cc7`; earlier refs below; base `53acb4837` | Independent reviews; AIR360 with actual packed degree≤9/shape24/4/periodic9/public8/exact [4,4,3,2], raw moved-fraction multisets; witness9 default/testing; execution16/40cases; strict scoped Clippy/no_std | Fresh normal/parallel/streamed fixture evidence and 32 reviewed snapshots are at PR09; 24 unit checks stop at the legacy public-statement adapter. Full production forged matrices/Range+And8 closure, claim12, generated/MASM/recursive/security/qualification remain |
| 07 Core resolution | implemented-awaiting-validation | MAIN `c668075ff`; lookup `299452ea6`; native `cf934ab3f`; public tests `606d36364`; base `cc6a74742` | Independent reviews; actual Core52/decoder27/aux5/Core36 and degree9; AIR383 pass with one explicit legacy-claim failure; execution18/witness9 default+testing; strict scoped Clippy/no_std | Legacy claim fixture/public projection remains12; fresh processor/parallel/decoder/lookup migration evidence is at PR09, including 24 public-statement failures. Full forged-matrix/generated/MASM/recursive/security and inherited acceptance remain |
| 08 Replay/debug | implemented-awaiting-validation | Fixture `11465c4f2`; snapshot fix `96adee6a6`; replay tests `63dde7907`; runtime debug `7afd90af7`; tests `fbac6f48b`; base `12e78f953` | Independent source/test/projection reviews; execution22/witness9 default, testing and testing+concurrent; strict processor/source/public Clippy, no_std | PR09 normal package-entry API4 now passes; full unit crate now compiles and runs: 1,866 pass/24 legacy-public-statement failures/one existing ignore; 49 integrations and 69 concurrent replay tests pass. Normal private/relocation/sidecar, complete forged relocation/global lookup/native/generated/MASM/recursive/security and inherited gates remain |
| 09 Assembly/packages | implemented-awaiting-validation | Final review `0ec317994`; CLI `fb4d1c7be`; VM benches `7bd9765b1`; native estimator `953eed44b`; fixture homes `c9b9c7b44`; prior SHAs below; base `82935d673` | Independent reviews; package 289 pass/one existing ignore; standard assembly 544 pass/six existing skips; estimator two/native file admission one pass; VM benches compile; integration source including precompile fixtures passes strict Clippy; prior evidence below | Full CLI runtime and constraints/proofs await PR12 statement cutover; guest/project E2E/full fuzz campaigns; PR10 artifact expectations/target naming/distinct instances; renewed valid-principal counterfactual evidence. All inherited native/generated/MASM/recursive/security/fuzz gates remain open |
| 10 Projects/imports | in-progress | Branch `adr1anh/librarytree-10-project-imports`, base `0ec317994` | Bounded source analysis identified independent artifact expectations, declaration naming, alias/instance graph and cache/routing seams; no PR10 checks yet | Implement explicit expected visible-callable mappings and source declaration helper first; then complete configured target naming, aliases/distinct instances, routing/cache/runtime multiplicity and required project/static/dynamic gates. Preserve all inherited qualification/security gates |
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


### PR 09 Explicit fixture namespaces and package naming prerequisites

`e4cb2fbaa` adds test-only FixtureNamespace with an explicitly selected typed home and bindings for
concrete declarations, including private helpers and entrypoints. TestContext source helpers use
it; foreign fixture packages require explicit binding sidecars. Configuration rejects conflicting
preconfigured homes through a read-only Assembler namespace_plan accessor. No production default
home/LibraryId algorithm, reverse-D dispatch, alias-derived authority or Protocol acceptance is added.
Independent review is clean after removing a silent home overwrite. Tests `9fd347f4f` all7 pass,
including raw missing-plan and missing-sidecar rejection; strict assembly library/test Clippy with
feature testing and no-default-features/testing check pass. Error conversion uses existing
IntoDiagnostic rather than requiring core errors to implement Diagnostic.

Configured16MiB full assembly now332 pass/157 fail/6 ignored, versus252/230/6 before these seven new
regressions. It clears73 existing setup failures. Remaining failures include149 missing explicit
caller homes and reviewed invocation snapshots/diagnostics; later assertions remain masked. Logs:
`pr09-fixture-helper-tests-second`, `pr09-fixture-helper-clippy-testing-first`,
`pr09-fixture-helper-no-std-testing`, `pr09-full-assembly-lib-fixture-helper`. Results precede current
raw-fixture and pure type-ownership edits; their checks remain pending. Generated .snap.new files
are review artifacts, never blanket-accepted or staged as source.

Bounded research identifies package9 prerequisites: format8 currently loses K/home/helper metadata
when reconstructing imported symbols; move existing CallableBinding to mast-package rather than
creating another model or a syntax dependency cycle. Keep source providers separate from explicit
per-target naming. Both exported-D library deduplication and source/profile project cache reuse
must compare requested naming before reuse; no new identity hash is selected. HomeV1's explicit
profile/context/budget boundary and D3 external inputs remain required. Short source indices are
`findings-pr09-project.md` and `findings-pr09-package.md` in uncommitted scratch. No target-input API,
wire9/commitment/admission activation, final Program/kernel conversion or production cache fix is
claimed. PR09 and all inherited/external acceptance gates remain open.


### PR 09 Shared binding ownership and callable fixture closure

`caac542d3` moves CallableBinding byte-identically into mast-package and preserves the assembly
root re-export. It changes ownership only: no manifest field, codec, wire version, descriptor,
commitment or profile activation. This avoids a future syntax/package dependency cycle and a
competing callable-binding model. Independent review is clean; all223 package tests pass with
one manual seed ignored.

`355a8ef12` configures five emission/serde/debug-budget fixtures with exact parsed-module metadata;
all sources, cost tables/differencing, operations, roundtrip and decoder-budget assertions remain.
`61a54fc10` configures callable fixtures, derives four literal CALL targets as K, preserves procref's
reversed key pushes and re-export identity, and verifies independent callable roots. Three inspected
procedure snapshots now show real keyed EXEC; direct body assertions preserve nested procedure
operations and all27 original non-padding locals/FMP operations omitted by that display. The masked
constructor-panic and locals-limit expectations pass unchanged after configuration. No retained
exec was replaced by inline. Independent fixture/snapshot review is clean.

Configured16MiB full assembly now347 pass/142 fail/6 ignored. Every newly migrated group passes:
cycle costs, serialization, product debug-budget, procedures, procref, main-call, key-literal calls
and locals. Remaining failures are139 missing caller homes and three reviewed-but-unaccepted
invocation snapshots; setup failures still mask later assertions. Combined strict package/assembly
library/test Clippy with assembly/testing and no-default-features/testing checks pass. Logs:
`pr09-callable-binding-move-package-tests`, `pr09-full-assembly-lib-callable-fixtures-third`,
`pr09-move-callable-fixtures-clippy-first`, `pr09-move-callable-fixtures-no-std-testing`. All Rust
commands passed AC/heavy guards; compile-only assertion constructor/inference fixes changed no
expected values or policy.

Only scratch and three .snap.new review artifacts remain untracked at this source checkpoint.
Next work continues required callable inventory/package9 and remaining fixture migration;
production homes/ID codecs, admission, project naming/cache matching, final Program/kernel
conversion and all inherited gates remain open. PR09 is not complete.


### PR 09 Detached callable inventory and kernel namespace fixture checkpoint

`15d543940` introduces detached PackageCallables using the existing full CallableBinding: bindings,
visible semantic paths to existing K, and independently optional selected D. Duplicate rows and
dangling alias/selection keys reject; private/helper/address-taken declarations survive without
visibility or code. Empty inventories are model candidates, not empty runnable code packages.
Tests `a206ab680` all9 pass; full package232 pass/one manual seed ignored, strict library/test Clippy
and no-default-features pass. No live Package8 field, codec, commitment or admission is activated.

`6fa2541f8` supplies explicit constant/library fixture homes and imported sidecars without changing
MASM bodies or constant/type/visibility negatives. Its sole accepted snapshot replaces External(D)
with keyed EXEC; added assertions retain exact producer D, constant-folded [PAD, INCR] and target K.
`eb84810b9` tests full accumulated kernel parents, literal-K semantics, ordinary kernel-key access,
source alias precedence, equal-D/different-K and kernel-owned library retention. `b8ab72a92` isolates
the generic candidate/runnable distinction: real private submodule code may form a candidate with
no public root exports, while both descriptor and with_kernel conversions still reject. Wholly
empty code still rejects. Existing unimported-name rejection remains; an explicitly imported
variant tests wrong-parent rejection and exact-parent acceptance with unchanged target spelling.
No production authority rule changed. Independent source/snapshot reviews and delta rereviews are clean.

Configured16MiB full assembly379 pass/110 fail/6 ignored; constants60, cross-module constants9,
libraries3 (one ignored), compiled libraries2, forest merge2 and kernels14 pass. Remaining failures
are107 missing caller homes and three invocation snapshots. Strict combined package/assembly
library/test Clippy with assembly/testing passes after replacing a Vec<Box<Module>> helper parameter
with an iterator; focused kernel14 passes after that change. Logs: `pr09-callable-inventory-*`,
`pr09-full-assembly-lib-constant-kernel-fixtures-third`, `pr09-inventory-constant-kernel-clippy-second`,
`pr09-kernel-fixtures-final`. All Rust commands passed AC/heavy guards. These are default libtest
results, not a pass of the still-pending standard test-dev/nextest suite.

Next aggregate validation must use explicit HomeProfile/context and one cumulative budget across
all owned inventory relations, retain existing HomeV1 bytes/checks, and store no admitted flag.
Current implementation and import/link fixtures are uncommitted and untested at this checkpoint.
Actual wire9 admission, artifact-kind identity/entry/full-kernel requirements, source/cache naming
matching and all D3/native/proof/recursive/security gates remain required; PR09 stays in progress.


### PR 09 Aggregate home validation and import/link fixture checkpoint

`d7f19ec91` adds stateless validate_homes with explicit HomeProfile/context and logical bounds over
all three owned inventory relations. It charges cumulative logical bytes in the same Budget,
checks records/components/path and home payload totals before any policy callback, and revalidates
every home, including repeated/private/unaliased/N0 homes. Shared HomeV1 contents validation charges
home payloads once; its encoder/decoder bytes, exact input, layout and wire-limit behavior remain
unchanged. Success stores no checked/admitted bit and grants no identity, registration, binding,
kernel or code-availability authority. Logical owned-data accounting defines no inventory wire format.

Tests `68a2f8839` all8 pass, including exact and one-less limits, prior/shared budget consumption,
UTF-8/final path components, changed contexts, unknown TypedIds and N0/empty distinctions. Full
package240 pass/one manual seed ignored, including unchanged HomeV1 tests; strict package Clippy
and no-default-features pass. A four-byte Unicode-letter fixture replaced an invalid emoji without
relaxing character rules or changing golden resource counts. Independent source review is clean.

`a79c7f83d` supplies exact import/link cohorts and explicit producer/re-export sidecars, retaining
source text, visibility/type/cycle negatives, concrete definition identity, body D/root, K/mode and
equal-D/different-K assertions. `3387d4226` updates only five inspected snapshots: eight External(D)
to EXEC(K) substitutions and one CALL(D) to CALL(K); operations/joins are unchanged. Independent
source and generated-snapshot delta reviews are clean. All owned groups now pass, including
previously masked post-snapshot export-leak and invalid-quoted-alias negatives.

Configured16MiB full assembly407 pass/82 fail/6 ignored. Remaining failures are79 missing explicit
caller homes (project43, debug20 and other raw fixtures16) and three invocation snapshots; their
later assertions remain unknown. Strict combined package/assembly library/test Clippy with
assembly/testing and no-default-features/testing checks pass. Logs: `pr09-callable-home-validation-*`,
`pr09-full-assembly-lib-home-import-fixtures-second`, `pr09-home-import-fixtures-clippy-first`,
`pr09-home-import-fixtures-no-std-testing`. All Rust commands passed AC/heavy guards.

All implementation/test slices are committed separately from this documentation checkpoint. Only
scratch and the three unaccepted .snap.new artifacts remain untracked. Required package9 metadata
transport/commitments/readers/admission, source/project cache comparison, final Program/kernel
conversion and all D3/native/proof/recursive/security/qualification gates remain; PR09 stays in progress.

### PR 09 Runtime debug and raw artifact fixture checkpoint

`3ab60c69c` supplies explicit forest/module/symbol fixture inputs. `e72fc3572` retains each named
private callee's error operations and the ordered local-frame/locaddr/EXEC/teardown regression;
`921dcb06e` preserves vendored bodies while checking childless keyed EXEC and its one-cycle row.
Only three semantically reviewed existing snapshots change. `82d70c303` separates runtime debug
control annotations from retained definition provenance, including aliases, equal-D/different-K,
literal-key interpretation and two additional runtime annotation regressions. Independent reviews
are clean after restoring per-name body association, ordered operation coverage and explicit
canonical linkage assertions. The six structural-inline cases remain unchanged in these commits.

Configured16MiB full assembly442 pass/49 fail/6 ignored: all migrated cases pass; failures are43
project-input cases and six structural-inline fixtures. Fresh strict assembly library/test Clippy
with testing passes. Logs: `pr09-full-assembly-lib-runtime-debug-artifact-fixtures-third` and
`pr09-runtime-debug-artifact-clippy-first`; both Rust commands passed AC/heavy guards. No fresh
no_std or standard test-dev/nextest result is claimed. Package9 and all inherited gates remain open.
The current brief owns subsequent assignments; this ledger owns these durable results.

### PR 09 Explicit inline debug and source-owned emission checkpoint

`3889b5734` migrates only the six structural debug fixtures to explicit inline, retaining runtime
tests and nesting/range/stale-frame/201-or-256-operation padding coverage. Imported bodies require
concrete typed-D pins; canonical definitions retain only their original compiler frames. Debug22
and inline13 pass; independent review is clean. Full assembly then448 pass/43 fail/6 ignored.

Producer `82e5a30b8` and tests `b1e8ee052` retain existing PackageCallables plus direct defining-path
node/source selections, explicit caller/kernel inputs and entry K in public raw AssemblyProduct.
Aliases retain defining K; distinct concrete AST definitions, including prelinked ones, reject
duplicate K. Imported/declaration aliases may coalesce only identical bindings and consistent D,
while preserving exact per-path sources. Public cohort methods reject mismatched target/root kinds.
Package8 extraction still discards raw naming; package9 transport/admission remains unimplemented.

Full assembly454 pass/43 project failures/6 ignored; final producer6, strict assembly library/test
Clippy with testing and no_std/testing pass. Logs: `pr09-full-assembly-lib-emitted-callables`,
`pr09-emitted-callables-final`, `pr09-emitted-callables-clippy-second` and
`pr09-emitted-callables-no-std-testing-second`. After the full run, only reviewed boxing and removal
of an obsolete unused-lint expectation changed; final focused checks cover that state. All Rust
commands passed AC/heavy guards. Independent review resolved alias/concrete-definition coverage.
Standard test-dev/nextest, package9, project/cache and every inherited/external gate remain open.

### PR 09 Canonical callable payload and fresh processor integration boundary

Codec `73d0d32a4` and tests `38dbfa982` add generic PackageCallables v1 bytes with explicit current
HomeProfile/context/limits. Shared Text ordering, count-tail and label helpers preserve existing
HomeV1/interface behavior. Complete wire/layout/aggregate preflight precedes callbacks; staged
embedding uses the ongoing caller Budget without recharging. Decode checks declared references,
strict canonical Word-byte/Text-envelope ordering, exact input and recomputed K. No permissive
TypedId validator, identity/domain change or live package9 activation is introduced.

Independent review is clean. Codec11 and full package251 pass/one manual seed ignored, including
unchanged HomeV1/interface and owned-data limit tests. Fixed fixture412 bytes/10 records/11
components/51 blob bytes checks accounting independently; malformed, order, budget, shared embedding
and current-policy cases pass. Strict combined package/assembly library/test Clippy with testing
and no_std/testing pass. Logs: `pr09-callables-codec-{first,full-package,clippy-first,no-std-testing}`.

Fresh normal `miden-processor --lib environment` gets past the earlier assembly compilation errors,
then fails at `prover/src/prover.rs:261,276`: both calls omit required ExecutionEnvironment. No
processor tests ran. Log: `pr09-normal-processor-environment-first`. Migrate that explicit consumer
under the proof/public-API cutover; do not fabricate authority from Program/root D to unblock it.
All Rust commands passed AC/heavy guards. Live package9, pending kernel input, project/cache,
standard test-dev/nextest and inherited/external acceptance remain open.

### PR 09 Coherent pending namespace inputs

Refactor `a16c005aa` replaces four pending Assembler fields with NamespaceInputs and one private
LocalPath/Bound declaration map. Existing incremental builders delegate to it; whole replacement
clears pending caller/kernel/maps, including an explicitly absent kernel. Prebinding derives local
paths under the final supplied home and retains immutable linked-binding conflicts and separate
inline-pin checks. Default inputs lack a caller home; they do not mean N0 or admit any authority.
No project cache, artifact wire format or kernel presence policy changes.

Tests `2a9b8db73` exercise actual public library/executable products: prelinked clone isolation,
replacement of both metadata forms, foreign homes, incremental order, missing/absent declarations,
duplicates, existing linked identities and independent pin validation. All11 pass. Full assembly465
pass/43 project failures/6 ignored; fresh strict assembly library/test Clippy with testing and
no_std/testing pass. Logs: `pr09-namespace-inputs-{first,clippy,no-std-testing}` and
`pr09-full-assembly-lib-namespace-inputs`. Independent review is clean; all Rust commands passed
AC/heavy guards. Implementation/tests are separate from this documentation.

Bounded container research found an additional applicability gap: Page assembly §§7.1–7.2 describe
interface/release roles, while TargetType describes usage. Neither maps an own LibraryId/interface
obligation onto every code-only candidate. The user question is recorded above; do not silently
require a Protocol interface everywhere or make identity optional for selected release profiles.
Live package9, project/cache, standard test-dev/nextest and all inherited/external gates remain open.

### PR 09 Callable codec fuzz integration

`108dc3607` adds the bounded callable_inventory_codec target to the existing fuzz workspace,
CI matrix and fuzz-all runner. Strict synthetic home/TypedId allowlists confer no Protocol
admission. Every input also generates1–4 valid declarations, optional repeated aliases and shared
D selections; raw/mutated bytes exercise canonical round trips, revoked-context rejection, trailing
bytes and the4096-byte limit. Generation stays within20 records/24 components/192 blob bytes/913
wire bytes. Independent source/runner review is clean.

`54f7db5af` corrects exactly one stale nested-lock dependency edge for existing mast-package
miden-crypto; no package/version/checksum changes. Locked target check and strict target Clippy
pass. Scratch-local cargo-fuzz0.13.2 and nightly2026-10-09 build the AddressSanitizer dev binary.
The first run executes6045 cases then fails its LeakSanitizer exit check under host ptrace. A
rerun with only `ASAN_OPTIONS=detect_leaks=0` passes5916 executions/31s, with AddressSanitizer
still enabled and seeds covering all homes/repeated aliases/shared D, canonical empty inventory
and4097-byte rejection. This is bounded smoke evidence, not leak or full fuzz qualification.

Logs: `pr09-cargo-fuzz-install`, `pr09-callables-fuzz-check-{first,refresh-lock,locked}`,
`pr09-callables-fuzz-clippy`, `pr09-callables-fuzz-asan-{build,smoke,smoke-no-lsan}`. Build, check,
install and fuzz commands passed AC/heavy guards; no concurrent heavy suites ran. Corpus, build,
tool and host-failure artifacts remain uncommitted scratch outside routine agent input. Live
package9 and both required container decisions remain unresolved; no inherited gate is waived.


### PR 09/10 Standard namespace convention decision checkpoint

At verified HEAD `c0c6ef28c48326cd0219d5b886d2ea53800431e8` on
`adr1anh/librarytree-09-keyed-packages`, the user approved the standard assembler/project
Latest/Pinned naming convention with an explicit custom-binding path. D5 records the boundary;
PR09/10 now route implementation without changing generic VM/AIR semantics, source import spelling
or opaque-ID ownership. Exact configuration UX is not selected, and the two existing kernel-input
and code-only-package applicability questions remain open. This checkpoint changes only the plan
and brief, preserves the committed implementation and adds no code/test/format acceptance claim.

### Reconciled D6/D7 discussion checkpoint

At verified HEAD `6a075a069023f978c5ebfce53c8dbfb4a002a1a4` (source `108dc3607`), D5 was
already committed but the two handoff questions had since been answered in this conversation.
D6 records fixed-root syscall semantics and its descriptor/claim consequences; D7 records
code-only optional own identity/interface. Current invariants/future PR contracts and gate entries
now follow those decisions; earlier evidence is historical, and PR01's changed contract requires
follow-up validation. No existing code/test result is represented as proving D6/D7. This is a
documentation-only reconciliation: preserve all implementation, remain paused for discussion,
then correct the root policy before Package9 and project-routing work. API/default-selection and
kernel publication ergonomics remain unfrozen; no additional answer blocks this checkpoint.

### D8 kernel placement discussion checkpoint

At verified HEAD `3536ebd7109533900d16cc2dedecd63df3b37ee1` (source `108dc3607`), the user
selected public kernel exports at root and private helpers beneath a child namespace. D8 records
this as tooling placement, not a second VM authorization list or source privilege flag. Default
dependency selection remains unfrozen; it does not block the fixed-root correction. This changes
only plan/handoff documentation, preserves the paused implementation and claims no new code/test
result. Exact helper-prefix/configuration details remain delegated implementation design.

### Model C and external identity discussion checkpoint

At verified HEAD `5590babbeacb194911f1f7298822b3438df249f0` (source `108dc3607`), the user
selected C: generic code packages plus a separate publication/release wrapper, with library identity
supplied as a Word and optional human-readable tooling names. Revised D3/D7 supersede earlier
Page-formula finality and optional own-field wording. Identity derivation/interface policy remain
external/open; selected-profile validation and all VM/security/acceptance gates remain intact.
This checkpoint changes only plan/handoff documentation, preserves the committed implementation
and leaves implementation paused. No new architecture question blocks the fixed-N0 correction;
dependency default-selection UX remains unfrozen. No source/test/format migration is claimed.

### General goal and milestone handoff

At verified HEAD `bbce64812` (source `108dc3607`), the user requested a general continuing goal
covering the full approved plan, with an intermediary D6–D8 milestone. The goal tool reported no
attached goal; retain all existing implementation/evidence and establish a replacement broad goal,
not a narrowed D6–D8 objective. Workflow/M1 and the current brief now express the completion
boundary and next slice. This checkpoint changes documentation only; no new source/test evidence
or milestone completion is claimed. Existing branch/commit, power, review and no-PR/push rules apply.

### Fixed-root core and AIR correction

Core `45bf6ccd4` removes configurable kernel authority from `ExecutionDescriptor` and
`VerifierConfiguration`. Descriptor identities are `(K_entry, R_E)`; configuration uses v3 domain
`0x01010a03` and checked `10 + 8*n` Felt framing. Historical v2 vectors remain explicit legacy
anchors. Executable arbitrary fixtures use authenticated N0 bindings. Independent bounded review
found no actionable issue. Fresh guarded checks passed: program88, full arbitrary-feature core408
with one ignored, public API/trybuild, strict test-inclusive core/AIR Clippy and no-default-features
library checks. Scoped pinned-nightly formatting and whitespace checks passed.

AIR `91c8cc96b` independently constrains each syscall supplier's four namespace coordinates to
fixed N0 and requires Chiplets public4 = R_E. Root List/Merkle positives, child/zero/coordinate
forgeries and rooted signed-frequency cancellation regressions pass. Independent bounded review
found no actionable issue. Full handwritten AIR: 387 passed, one failure at
`statement.rs:71` copying Core36 into legacy claim32; this known statement-cutover gate remains
required at PR12. Actual packed layout/lookup/periodic/degree tests pass; no generated/native/MASM/
recursive relation closure or milestone completion is claimed. Logs stay in scratch, separate from
this durable evidence. Reviewed processor/assembler changes remain uncommitted at this checkpoint.
Guarded exact-source opening/session harness52 and actual-processor public-source harness checks
native/source22, execution22 and witness10 pass, including full arbitrary-stack generation and
exact replay-v5 budgets. These avoid the existing prover dev-dependency compile break and do not
establish a passing normal processor suite or proof-system qualification.

### Fixed-root runtime and assembler correction

Runtime `87ed5d1b4` consistently checks N0 in session miss/cache, fast resolution and native Library
trace validation. Replay removes the kernel Word, reduces the environment header176→144 bytes and
uses witness version5, rejecting4. Caller `(K_entry, R_E)` authority, exact wire budgets and
reauthentication remain. Independent review found no actionable issue. The preceding harness
checks pass; public execution22/witness10 also pass with `testing,concurrent`. Strict production
processor Clippy, test-inclusive runtime harness Clippy and no-default-features library check pass.

Assembler `1615fc816` removes configurable kernel inputs/product plumbing and checks known SYS
parents against N0; literal K remains runtime-authenticated without a kernel configuration input.
Independent review and scoped assembler47 pass. Full assembly466 pass/43 existing missing-caller-
home project failures/6 ignored; routing remains required. Signatures on these source commits,
core/AIR commits above and documentation `2d00843a8` verify against the configured signing public
key using a scratch allowed-signers file, without changing Git configuration.

The D8 placement slice is reviewed but uncommitted: resolved public export keys at N0, nonexported
retained concrete helpers beneath Env, foreign root dependencies allowed, no extra persisted list.
Focused construction tests4 pass/one fails at the legacy parser ban on kernel reexports. Remove
that source-role ban and migrate the same source regressions to canonical-key assertions before
claiming acceptance. This expands the frontend portion of the existing PR09 correction; it does
not authorize SYS through an alias or weaken visibility/cycle/parent checks.

Optional interface transport Rust documentation now reflects revised D3/D7: opaque supplied I and
external identity policy, with unchanged mandatory selected-profile callbacks. Generic Package9
must not acquire publication requirements. Its future reader/admission boundary must keep current
profile validation explicit rather than preserving context-free readers with a permissive profile.
No Package9/native/recursive/generated closure or M1 completion is claimed.

### Kernel construction placement and alias validation

Source `dfdbc42b3` validates kernel construction against resolved public export keys and canonical
parents: public executable exports must occupy N0; nonexported retained concrete helpers must be
beneath a child Env. Foreign compiled/declaration-only dependencies are not misclassified as local
private helpers. No extra serialized syscall list or key rebasing is introduced. Public submodule
exports use root bindings; aliases preserve defining keys; distinct concrete root-label collisions
still reject. Ordinary nonkernel construction and actual VM authorization remain visibility-agnostic.

Removed obsolete kernel item-reexport bans in AST/sema/linker. Executable export restrictions,
module/item validity, source visibility, conflicts and import cycles remain. Both original reexport
regression sources now assert defining K and absence of alias definitions; child/textual-kernel SYS
rejection remains. The existing module-capacity/rollback test retains its two-module source and
failure/retry assertions, with explicit public export bindings corrected to N0.

Independent bounded reviews found no actionable issue across production, frontend and fixtures.
Fresh guarded syntax319 and construction5 pass; the compiled dependency matrix includes child
reexport rejection, root reexport identity and unexported foreign root/child acceptance. Full
assembly471 passed/43 existing project missing-home failures/6 ignored. Strict test-inclusive
syntax/assembly Clippy, no-default-features checks, scoped pinned-nightly rustfmt and whitespace
checks pass. The earlier four/five construction result is superseded by these final checks.

Scratch assembler/project/inline findings now contain short current source indices; superseded
research is preserved under `.scratch/librarytree/archive/`, outside routine input. The reference
cache and shared /tmp sources remain intact. Documentation `bfe2b1aec` is separately committed and
its SSH signature verified. Next is Package9 required metadata and explicit raw/admitted boundaries,
using existing enclosing-Budget seams, before project routing/cache matching. No production profile,
native/recursive/generated closure, normal processor suite or M1 completion is claimed.

### Package9 required naming and import-propagation checkpoint

At verified HEAD `3ea23e3d4`, uncommitted source introduces PackageNaming and bounded NamingV1
transport, required opaque naming in Package9, exact slice readers, v2 naming-sensitive dependency/
artifact/full commitments, explicit current-context naming admission and producer persistence across
debug stripping. Generic code construction has no own I/interface or publication-profile default.
Private code candidates retain their prior applicability across usage tags; explicit entries must
select their own real procedure root, even when another K selects equal D. Existing manifest/code
validation precedes naming validation. Fixtures retain code/source/negative assertions.

Independent bounded component/container/producer reviews found no actionable issue. Guarded full
package278 pass/one manual seed test ignored; strict package test/bench Clippy and no-default-features
library check pass. Earlier focused naming19 and full package270 preceded container activation;
these are groundwork evidence, not final qualification. Producer checks52 pass/one failure:
`pinned_static_inline_keeps_selected_export_source_after_inventory_retention` exposes a retained
private callback root whose canonical metadata is lost by current imports. Preserve the complete-
root gate and fix full import metadata, not source/body coverage or derived placeholder keys.

Current authors are implementing exact PackageNaming/transport integrity at import, named symbol
projection, name-aware dedup/provenance and private metadata retention without invented source paths.
Raw read/admission checks remain distinct; selected production profiles still need their external
owner evidence. Public import APIs and remaining consumers are intentionally in flight. No completed
Package9 cutover, Program/kernel conversion, project routing, proof closure or M1 acceptance is claimed.

### Package9 persistence, named imports and canonical inventory retention

Source `6233ae58c` persists required NamingV1 in Package9 (rejecting8), with explicit own home,
callable inventory and optional entry K. Generic containers retain opaque, bounded naming bytes;
`admit_naming` uses current explicit HomeProfile/context/CodecLimits and checks current container
relations. No own I/interface, publication profile or TypedId fallback is introduced. Code candidates
remain valid without entry/public exports across usage tags; explicit private entries require their
own selected root, and manifest entries require matching explicit K. Exact naming affects v2
dependency/artifact/full commitments while exported-code/interface meanings remain unchanged.
Safe/trusted byte readers reject trailing input; debug stripping preserves required naming.

The aggregate codec reuses one fully charged Budget. Prepared callable reference checks and entry
declaration checks precede every profile callback, including own-home validation; no counter is
reset/recharged. Raw transport can preserve unknown codecs or invalid references only as opaque
unadmitted bytes. Current-context admission rejects them. Fixed fixtures195/7/6/25 and the earlier
callable412-byte vector remain intact. These limits describe logical work, not measured RSS.

Source `359d5840d` borrows one canonical inventory into producer artifacts and requires exact
package/naming pairs at import. It projects defining bindings onto source aliases, rejects rebasing
and conflicting module surfaces atomically, and indexes imports by naming-sensitive dependency
identity. Full private inventories survive separately from source paths; selected D survives only
where an actual final procedure root exists. No private defining path is invented. Independent
review found a static debug lookup comparing a forest digest with the new package identity; the
fix uses the stored source-ID index plus exact debug equality, with canonical frame-source reuse
asserted. The old package-backed interface-D provenance alias is removed.

Source `9d6f8caa2` retains canonical data from local project products, checks it after hooks and
propagates package/kernel naming Arc pairs together. Raw/cached/registry/preassembled/embedded
loads need an explicit naming-provider callback; absence rejects. This does **not** implement
per-target namespace routing, D5 selectors/file configuration, distinct dependency instances or
exact naming-aware project cache selection. Existing PackageId caches/base-assembler cloning and
legacy Program/kernel reconstruction remain required follow-up. Source `ea4fa6a57` supplies explicit
metadata to manual registry/processor fixtures; no source operations or negative coverage is removed.

Fresh guarded evidence: full package280 pass/one manual seed test ignored; producer/import54 pass;
full assembly478 pass/43 existing project-input failures/6 ignored; registry resolver25 pass. Strict
package/assembly library/test/bench Clippy, no-default-features library checks, scoped pinned-nightly
rustfmt and whitespace checks pass. The two temporary fixture failures were resolved by retaining
the duplicate-module diagnostic category and rejecting an unconfigured foreign home before module
registration; the original negative invocation remains tested. Fresh normal processor attempt
stops at `prover.rs:261,276` missing ExecutionEnvironment; no processor tests ran. Further import
API consumers, fuzz seeds, generated/native/MASM/recursive and inherited qualification remain.

All four source commits and documentation `99c4d8967` have verified SSH signatures against the
configured public key using the scratch allowed-signers file. No Git configuration, pushes or
GitHub PRs changed. This is implementation progress within PR09/M1, not completed cutover or proof
qualification. The current brief routes the next slice; this ledger owns the durable evidence.

### PR09 target namespace routing and exact source reuse (3 November 2026)

Source `fb4d5c141` extends existing source/Git, dependency-closure and profile provenance with an
optional resolved compilation commitment. New section tags6/7 retain that value; tags0–5 remain
readable without it and cannot establish equality with current committed inputs. Section decoding
rejects trailing bytes. Tests cover independently encoded historical records, new variants,
truncation and exact package-section consumption.

Source `fc1eb143e` fingerprints complete typed caller homes, exact defining-source declarations
and resolved semantic callable paths without D-derived names or publication authority. Local-path
and equivalent bound inputs normalize together; source declaration bytes retain their exact
spelling. Project matching additionally covers inline pins, effective profile/warnings, actual full
imported artifacts/linkage and the separate kernel. Inherited AST/advice and declaration-only state
without a complete snapshot remain compilable but cannot justify reuse; source printing/equality
is deliberately not treated as an exact snapshot.

Source `959a1bded` adds explicit per-target namespace providers after source loading and resolved
import/kernel linking, before memory or registered source reuse. Callbacks receive the actual
prebound assembler graph. Missing providers reject, including warm-cache paths. Graph identities
and executable-target suffixes select consistent cache slots; provenance mismatch is a memory
miss, while an immutable registered same-version collision retains its existing diagnostic. Both
reuse paths enforce the same dependency-section eligibility. Manual ASTs preserve their origin,
skip provider/post-processing hooks and never justify reuse, even with supplied file provenance;
their declared source file/extension need not exist or have a source provider.

Project fixtures explicitly select homes and bindings. Kernel reexports retain defining keys;
the packaging fixture publishes its imported utility at N0 before reexporting it, with an explicit
test profile. No production admission fallback is added. Existing debug coverage now verifies two
real runtime EXEC edges and separate callee provenance; byte-tampering tests follow MAST0.0.6's
invocation target table and still reject corrupted non-root hashes. Source-change diagnostics now
identify the changed transitive leaf before parent reuse.

Fresh AC/heavy-guarded standard `make test-assembly EXTRA=--locked NEXTEST_PROFILE=ci` passes539
(537 unit and2 packaging tests), with6 existing skips. Strict package/assembly library/test/bench
Clippy with `-D warnings`, no-default-features library checks, scoped pinned-nightly rustfmt and
whitespace checks pass. Independent review's memory-section, manual-context and callback kernel
visibility findings are fixed and covered. All three source commits have verified SSH signatures.
Logs remain local scratch; no pushes or GitHub PRs were created.

This closes the former project-input failures, not PR09/M1 or final qualification. Program/kernel
reconstruction, remaining consumer migrations, D5 selector/file configuration, PR10 distinct bound
instances and all inherited native/MASM/recursive/generated/security gates remain required. The
normal processor's earlier prover ExecutionEnvironment compile failure is not claimed resolved.

### PR09 canonical entry code and kernel-presence checkpoint (3 November 2026)

Source `282445d4c` requires exact borrowed PackageNaming for package-to-Program code conversion.
After owned transport/manifest/code checks, only explicit entry K and its selected D determine
entry code. A validated matching manifest node preserves source occurrence only. Private entries
without aliases work; absent metadata rejects. The main-path fallback and embedded-kernel
reconstruction are removed. `check_kernel_code` checks exact naming, kernel kind and nonempty
public executable surface without source-path filters, duplicate-D prohibition or255-export cap.
Nine new tests cover these cases, naming mismatch and independent embedded-code distribution.

Source `0a1b5d888` removes the linker's KernelDescriptor storage and assembler D-list accessor.
Kernel presence uses existing source/package state; attached exports keep their canonical keys
and N0 validation. Arbitrary source namespaces attach without requiring `$kernel`. The optional
unqualified source adapter can use only the attached package's own `$kernel` descriptor, never
an unrelated preexisting module. Rollback/duplicate checks and an explicit unrelated-alias
regression preserve atomic linking. AssemblyProduct converts with retained naming; fixture homes
remain explicit. Distribution tests still check embedded kernel name/version/commitment, exact
naming and retained root K-to-D code. Missing or mismatched embedded code cannot manufacture
authority: code conversion is independent, while explicit embedded-package association validation
retains its mismatch rejection and source dependency resolution still rejects missing dependencies.

Source `bee88c1af` requires exact naming at processor package preparation, uses fallible conversion,
and rejects a descriptor requesting another entry K before creating execution state. Four public
API tests cover private entry preparation, typed mismatch/recovery, stale same-code naming and
missing entry. Preparation alone does not authenticate any opening or execute code.

Fresh AC/heavy-guarded evidence: full package289 pass/one existing manual seed test ignored;
standard `make test-assembly EXTRA=--locked NEXTEST_PROFILE=ci`540 pass/6 existing skips. Strict
package/assembly library/test/bench Clippy, processor-library Clippy, all three no_std library
checks, scoped pinned-nightly rustfmt and whitespace checks pass. Normal processor integration
attempt still stops in prover.rs:261,276 at missing ExecutionEnvironment arguments; no normal
processor tests ran. The existing isolated runtime harness runs the exact new integration source
against the actual public processor crate:4 pass, supplemental to the unresolved normal gates.
Independent source review reports no remaining findings in this slice. All three source commits
have verified SSH signatures. No pushes, PRs or Git configuration changes.

PR09/M1 remain open. Remaining processor/CLI/test/fuzz callers must migrate these breaking APIs;
prover environment plumbing and legacy Program/ProgramInfo claim transport remain incomplete.
D5 selector/file configuration, PR10 distinct instances, complete inherited AST reuse snapshots
and inherited native/MASM/recursive/generated/security/fuzz qualification remain required.

### PR09 prover environment and shared execution fixtures (3 November 2026)

Documentation `5010a7b72` separately records the user's D5 clarification: standard project
Latest/Pinned selection must be explicit; omission rejects. Custom bindings remain supported,
configuration fields remain implementation design, and no selector implementation is claimed.

Source `97013a482` adds caller ExecutionEnvironment to synchronous proving and passes it unchanged
through buffered and overlapped execution. Its regression exercises both scheduling choices and
requires the exact caller root/key when evidence is unavailable. No root, key, native policy or
opening authority is inferred from code or proving settings.

Source `132f27548` shares the existing kernel source-fixture placement algorithm as
FixtureNamespace::add_kernel_modules, including visibility, imported canonical aliases and global
root-label conflict checks. It also rejects an empty cohort without panicking. Source `a2dea935c`
retains exact compiler/admitted names and selected code in shared test preparation while keeping
the public compile tuple. Cache identity includes complete library artifacts; the cache retains
its source-manager owner so an allocator cannot recycle the address used as source identity.
Fixed finite fixture admission still refuses unknown homes/TypedIds. The locally selected test
root contains typed home Env paths and semantic Text procedure paths, with unique K bindings;
equal D under distinct K remains valid, while conflicting selections reject. Sources enforce
requested root/key and construction limits, verify candidates and retain finite request budgets.
Full/debug/step/proving helpers pass explicit environments and finite trace policies; existing
memory, full-versus-step, proof and constraint assertions remain intact. Nested helper/procref and
root-SYS/private-helper tests execute through actual authenticated openings and preserve stack rules.

Source `8a2fb1cc3` gives processor test hosts optional native environment sources and adapts executor
and host fixtures without changing event/trace/snapshot/source-manager behavior. A cfg(test)-only
bridge copies every native policy field and witness node/slot between the dependency processor
and its separately compiled unit-test crate; it creates no names, tree or authority. These unit
cases remain unexecuted until the rest of the unit test crate compiles.

Fresh AC/heavy-guarded checks: prover environment regression1 pass (both scheduling modes), all
shared test-utils12 pass, standard assembly Nextest540 pass/6 existing skips. Crucially, normal
`cargo test --locked -p miden-processor --test package_entry_metadata` now runs4 passing tests;
the former prover compile stop is resolved. Strict scoped prover integration/library, test-utils
library/tests and processor testing-library Clippy pass, as do no_std and scoped formatting checks.
A full normal processor unit compile now reaches226 remaining older API/fixture errors, with the
largest groups in fast/tests/mod.rs, tests/mod.rs, masm_consistency and parallel trace fixtures;
no unit tests ran. New executor/host type-identity errors were fixed, not waived. Logs/source index
stay local scratch. Independent source reviews report no remaining findings in this slice.
All five decision/source commits have verified SSH signatures; no pushes, PRs or Git settings changed.

PR09/M1 remain in progress. Complete normal processor/parallel/debug/trace fixture migration,
remaining CLI/fuzz/tooling consumers, D5 file/API configuration, PR10 distinct instances, PR12 claim
transport and all inherited adversarial/native/generated/MASM/recursive/security gates remain.


### PR09 processor fixture and diagnostic checkpoint, 3 November 2026

Source `ff5a05c2d` adds explicit named processor source/code fixtures and native trace/replay policy
bridges. Default source cohorts opt into the bounded fixture convention; partial caller namespace
inputs are never repaired with an inferred home. Synthetic code receives independently supplied
bindings and selected implementations. The trace-only pure-forest helper rejects retained
invocations rather than synthesizing their identities.

`128cad6ba` migrates fast processor, memory/advice/MASM and u32 fixtures to explicit environments,
opening sources, keyed targets and real EXEC. Completion booleans, unentered ENTRY, cache publication
and exact continuation boundaries retain their assertions. Debug recovery recognizes the paired
keyed finish/restoration as one caller activation, preserving recursive and repeated activations.
`a817c2af5` preserves source context on unavailable selected implementations in both sync/async
resolution and on context-return errors. Diagnostic tests now point to actual EXEC source locations;
non-root SYSCALL rejects by authenticated parent even with its body available, paired with root success.

`0377a45ee` migrates trace, parallel, decoder, chiplet and saved-fragment fixtures. Complete replay
roundtrips undergo native revalidation; decoded keyed queues never inherit native validation.
Tampering targets the live keyed queue; root END closes the singleton entry interaction rather than
an ordinary child dequeue. Packed Controller selectors use typed payload fields; address oracles
use aligned Library/Controller bands without changing VM values. `1df0163c4` updates 32 reviewed
snapshots: unchanged stack data/output and core execution row counts, intentional key-valued
procrefs/caller words, runtime EXEC clock/context offsets and LibraryTree matrix/layout changes.
CALL/SYSCALL body commitments change with their K targets; obsolete kernel descriptors disappear.

`7d15864e0` migrates the four remaining processor integration consumers. Async-only hosts yield
while supplying bounded authenticated openings. ACE overflow/resource limits, static linking and
buffered/overlapped trace equality retain their checks. No environment authority is inferred from
body hashes or code supply. All six source commits have verified SSH signatures.

**Fresh guarded validation:** full unfiltered `cargo test --locked -p miden-processor --lib`
compiles and executes 1,891 tests: 1,866 pass, 24 fail, one existing ignore. Every failure is
`PublicValuesLengthMismatch { expected:36, actual:32 }` in the planned PR12 statement adapter:
decoder 8, lookup 13, range 3. This is unresolved production-relation qualification, not a green gate;
no new skip/ignore, fake K/R_E, padding or weakened constraint assertion was introduced.
`cargo test --locked -p miden-processor --test '*'` passes all 49 tests across eight targets.
Strict `cargo clippy --locked -p miden-processor --lib --tests -- -D warnings` passes.
`cargo test --locked -p miden-processor --lib --features concurrent trace::parallel` passes 69 tests;
`cargo check --locked -p miden-processor --lib --no-default-features` and scoped formatting pass.
Logs stay separate in local scratch; source findings route to exact helpers, not another status/specification copy.

PR09/M1 remain in progress. Remaining CLI/tooling/test/fuzz consumers, D5 explicit-selection file/API
configuration, PR10 distinct instances, PR12 canonical claim/statement/proof cutover and all inherited
native/generated/MASM/recursive/security/qualification gates remain. No pushes or GitHub PRs.


### PR09 explicit project source homes and prover consumers, 3 November 2026

`db3b3b668` adds LibraryImport/LibrarySelection over generic NamespacePlan/CallableBinding. The
caller supplies the complete ancestor base, opaque Word ID and explicit Latest/Pinned selection;
Pinned requires nonzero revision. Names remain independent of D/code, source aliases and artifact
provenance. Existing custom bindings and externally validated TypedId ancestors remain supported
in memory. Compiler checks cover declaration-only/selected-code parity and revision-qualified keys.

`dbebdfd51` requires explicit binding configuration on file and programmatic source-project
dependencies, preserving inheritance/override, source version/linkage independence, serialization
and graph-edge metadata. No implicit Latest or invented I is supplied. Preassembled-manifest-derived
edges retain missing project metadata without inventing a namespace. Built-in label/Word decoding
remains canonical; unknown TypedIds have no permissive decoder. Generic manifest writing rejects
externally validated TypedId homes without an owner-aware writer rather than emitting files the
reader cannot reload. Existing graph/examples/tests now supply explicit custom fixture inputs.

`520574869` routes a source default-home request to TargetAssemblyContext::dependency_binding and
checks returned NamespaceInputs before memory/registered cache reuse. Complete Bound declarations,
reexports and retained foreign/helper homes stay independent. Standard selection on preassembled
artifacts explicitly rejects pending consumer expected-callable mappings. A package's primary home
cannot establish its public surface or ownership of I; neither an all-bindings check nor a single
matching binding would be sound. Custom artifact requests check only their requested default
metadata; the independent naming provider still admits the full inventory/profile. Automatic
target/public/helper naming and distinct bound source instances remain PR10, not completed here.

`b33d07fab` migrates ten prover security modules and async/advice-fixture integrations to retained
naming and bounded environment/trace policies. Dynamic targets use retained canonical foo keys,
not body digests or forest order. Raw forests use independent test-owned names and code-only D.
All mutation/precondition/oracle/proof assertions and the existing regeneration ignore remain.
Independent review found no new source regressions; compilation does not qualify attack attribution.

**Newly identified inherited security gates:** ctx_continuation_end_soundness_repro:129 requires
zero root fn_hash; dyncall_end_relabel_repro:91 relies on zero saved-root principal and a degenerate
caller-frame payload. Actual ENTRY/root-END use authenticated K_entry. Those prerequisites cannot
be made true by substituting zero keys or removing assertions. Renew the valid-principal attack
construction and counterfactual rejection attribution after PR12; also recheck block-stack entry-kind
tag-isolation claims against the new principal constraints. Keep honest-proof/generated/native/MASM/
recursive/security qualification open until actual evidence proves them.

**Fresh guarded checks:** project full 48 pass; assembly project 54 and callable-identity13 pass;
strict project/prover library+test Clippy and assembly-library Clippy pass; project no-default-features
and scoped formatting pass. The 17 earlier prover unit API errors now compile through normal Clippy.
Three bounded source/review agents ran no builds/tests. Root batched essential checks; no broad
processor/proof run or regeneration was launched. All four source commits have verified signatures.
Separate README/SPEC updates describe actual configuration and current limits; scratch findings
index exact source locations, while logs remain separate. No pushes or GitHub PRs. Overall goal,
PR09/M1 and the remaining CLI/wasm/fuzz/PR10/PR12/inherited acceptance gates remain active.


### PR09 Wasm/fuzz consumers and VM facade checkpoint, 3 November 2026

`b98d4bf31` migrates Wasm handler source/project fixtures and the calibration bench to exact naming,
independent bounded environment inputs and matching opening sources. Local compiler naming is
retained through artifact extraction. Both local and project wire-roundtrip execution uses the
pre-wire expected PackageNaming, detecting changed labels/entry even within an admitted home;
handler sections are compared exactly. Project fixtures explicitly select their namespace/naming
providers. Existing ABI/fuel/resource/capability/panic/mutation/embedded-kernel assertions remain.
The two test-utils dependency edges are recorded in the main lockfile.

`9ebd0652e` migrates five fuzz targets and shares an explicit finite synthetic naming policy.
Detached callable-codec synthetic TypedId recognition remains exact; package policy recognizes
only independently enumerated built-in homes and rejects every TypedId. Generated valid named
packages execute semantic checks before hostile-input rejection, including different K sharing D,
private retained roots, explicit private entry and entryless candidates. Safe/trusted admission,
canonical byte equality, revocation, selected-root/key/program-code, debug, embedded-kernel and
workspace-inheritance oracles remain. Controlled source/project fixtures require successful assembly
with explicit source inputs; they no longer silently discard fixed valid cases. Body-changing
metamorphic checks cover 32 selectors and require exactly the two public selected bodies to change,
while names/entry remain stable. No corpus or generated artifact was rewritten.

`5d4e4b550` exposes the existing execution descriptor/key/root/environment, finite policy, witness
source/request/error and program-building primitives through miden-vm's public facade. This is a
source-level reexport update; no whole-VM compilation/runtime/proof claim is made. CoreLibrary
build.rs still needs explicit producer target naming before that build is ready.

**Fresh guarded validation:** miden-wasm-event-handlers library 7, WAT/package E2E 3 and handler 78
pass; four Rust-guest cases were command-filtered to avoid nested guest compilation, with their
assertions intact. miden-wasm-event-handlers-project library 5/config 23 pass; its two cargo-building
project E2E cases remain unrun. Strict all-target Clippy for both crates passes, including bench/test
compilation. The standalone fuzz library and callable_inventory_codec/package_deserialize/
package_semantic_deserialize/project_assemble/project_load compile with locked/offline dependencies
and shared target cache. Its two library tests pass, including the 32-selector semantic matrix;
this is not fuzz-campaign/sanitizer/throughput qualification. Scoped formatting/whitespace pass.
All three source commits have verified signatures. Two source implementers, two independent
reviewers and one CLI source auditor ran no builds. Root centralized the focused checks; no broad
processor, whole-VM/core, proof or guest generation was launched. No pushes or GitHub PRs.

**Next concrete CLI slice:** add a shared execution-input admission layer independent of packages
and private advice: exact caller K_entry/R_E, finite opening/ledger/session/trace policies and a
bounded local opening source using existing exact EnvNode decoding/child slots. Do not infer a
production home/profile, ID or descriptor from package/body/source data. CLI argument names and
bounded local input layout are implementation design. Source/package loaders then need explicit
NamespaceInputs and retained/admitted PackageNaming pairs; core artifacts must be injected with
owned naming. Embedded kernel remains code/handler supply, not authority. Verify must obtain the
independently authorized expected statement; PR12 owns actual claim/proof activation. Existing
CLI methods still call superseded APIs and old program-hash/kernel authority, so remain unqualified.
Scratch source index records exact sites. PR09/M1/overall goal and all remaining acceptance stay open.

### PR09 bounded CLI execution evidence checkpoint, 3 November 2026

`625580803` adds EnvNode v1 framing preflight without List allocation, shared by exact decoding, so callers
can check List child/storage limits before allocation. Preflight does not validate canonical Words
or authenticate membership; exact decoding and native verification remain required. The regular-file
opener extracts the existing metadata/nonblocking/recheck path; callers still bound reads/growth.

`694e2b5ce` adds `miden-vm/src/internal/execution_inputs.rs`. Its caller supplies ExecutionEnvironment,
trace policy and explicit finite file/source limits. Strict versioned JSON echoes K_entry/R_E and
supplies existing EnvNode v1 bytes plus exact child selections; it carries no authority, private
advice, code or policy defaults. Admission verifies every supplied path under caller opening limits,
requires entry evidence and rejects duplicate keys. The source retains immutable encoded evidence,
checks tighter request limits before decoding, and returns candidates for independent consumer
verification. Each factory-produced host source has its own atomic request quota; Arc clones share
that quota, including failed/missing/wrong-root requests. Ledger/session/trace policies are preserved,
including zero limits, rather than silently expanded during evidence admission.

Input size, schema depth/unescaped ASCII, streaming borrowed parsing, aggregate paths/encoded bytes,
retained payload and preparation budgets are checked before associated allocation requests and
returned capacities before publication. Accounting scope/exclusions are documented on
ExecutionInputLimits; it does not claim an allocator/RSS bound. File loading uses the shared
nonblocking regular-file opener, bounded chunks and an overflow probe. All hashes, canonical Words
and membership checks reuse existing core/native implementations; no parallel commitment scheme.

**Fresh guarded validation:** the focused prover integration target includes the actual production
module by path, avoiding the unrelated CoreLibrary producer build. Its 21 tests pass: real named
program execution, complete List/Merkle/Env paths and slots, independent descriptors/policies,
canonical/malformed encodings, strict/escaped/deep JSON, file/allocation bounds, each native opening
axis, missing/duplicate/foreign evidence and concurrent quotas. Core codec 8 and file-helper 6 tests
pass, including isolated replacement-FIFO safety. Strict Clippy passes for both support libraries
and the focused integration target; support-library no_std and scoped formatting/whitespace pass.
No new ignores, altered security oracles, broad workspace build or whole-VM/proof qualification.
Both source commits have verified signatures. Bounded source/test/review agents ran no builds;
root centralized these AC/heavy-guarded checks. No pushes or GitHub PRs.

**Remaining:** this is admission, not runnable CLI closure. Next shared CLI arguments must supply
the expected descriptor/policies independently of evidence. CoreLibrary's producer still needs
explicit namespace/declaration inputs. Locally compiled source must retain AssemblyProduct naming;
raw package conversion requires separately admitted naming through a caller-selected profile/context,
not a permissive production fallback. `cli/{run,prove,data,utils}.rs` still use superseded APIs;
verify retains legacy statement handling until PR12. PR10 artifact expectations, PR12 claim transport,
core generation, whole-VM/CLI and final security/qualification gates remain open. Scratch audit
findings retain exact source sites. Overall scope, PR09 and M1 are unchanged.

### PR09 retained core naming and explicit CLI policy checkpoint, 3 November 2026

`ad3a47cd3` adds ProjectAssembler naming-retaining normal/interruptible entrypoints returning the
existing ResolvedPackage. Legacy package-only APIs delegate to the same assembly path; interruption,
caching, providers and postprocessors retain their behavior. The regression checks exact package
correspondence, executable entry, private declarations, reexport defining keys and stable naming
across implementation changes. All 55 project tests and strict project-library Clippy pass.

`88b75005d` supplies the core producer's explicit empty custom compilation home and complete
defining semantic paths, including root/support/private/generated procedures. Core's ordinary sys
modules keep child namespace paths; this is not kernel publication. A deterministic Rust sidecar
retains the compiler-owned homes, bindings, aliases, selected D values and optional entry. CoreLibrary
reconstructs that inventory, checks exact Package9 correspondence and exposes retained naming;
it does not admit arbitrary artifact-controlled names through a fabricated profile. The compilation
benchmark uses the same explicit source convention. Legacy recursive-helper D versus procref K
documentation is clarified without changing runtime behavior or proof assertions.

**Core gate:** the producer and library build. The full library unit run is **14 pass, 1 fail**,
with all three new private-address-taken/reexport/home-mismatch tests passing. The unchanged
`proof_compatibility_roots_match_the_embedded_core_library` assertion fails because the rebuilt core
verifier's implementation root differs from the old Verifier compatibility constant. This is a
remaining PR14 identity/recursive qualification gate, not a passing core/proof suite. Do not bypass
the assertion or update the whitelist merely to green this producer change. Strict library plus
compilation-bench Clippy and core-library no_std pass.

`965c4f7cb` adds shared required run/prove arguments for independently authorized K_entry/R_E,
opening-evidence path, caller resource-policy path and explicit policy-file byte cap. Versioned
resource JSON requires all native opening/ledger/session/trace/source limits, preserves zero values,
and rejects unknown/authority fields and duplicates; it supplies no descriptor. Commands admit once,
attach the bounded source, install trace limits and pass caller ExecutionEnvironment in every native
execution/debug branch. The focused harness includes the actual adapter and actual evidence loader;
its four tests and strict Clippy pass, including file-to-admission, exact policy-file cap, mismatch
rejection and retained policies. Whole CLI commands and their existing tests remain uncompiled:
source/raw-package loaders still discard or omit required naming, and verify remains pre-PR12.

All three source commits have verified signatures; scoped formatting/whitespace pass. Parallel
bounded implementers/reviewers ran no builds; root centralized focused AC/heavy-guarded checks.
No new skips, weakened security oracles, broad workspace build, regeneration of proof identities,
pushes or GitHub PRs. Next migrate CLI source/package loaders and CoreLibrary linking callers with
retained or independently admitted naming. Raw inputs need caller-selected profile/context and
expected mappings; PR10/PR12/PR14 and all previous security/final gates remain open. PR09/M1/overall
completion is not claimed. Short scratch findings retain exact remaining caller sites.

### PR09 explicit CLI naming and owned consumer imports, 3 November 2026

`48e8e9a37` adds Test::with_library_and_naming and revalidates exact owned pairs plus current raw
fixture admission before cache lookup. Four regressions cover foreign-home K/D execution, mismatched
equal-code metadata, raw-after-owned cache reuse and dangling naming. Core tests/benchmark imports
retain the same CoreLibrary naming; hostile handlers and security/proof assertions are unchanged.
The helper's full 16-test suite passes, and a real core u64 procedure executes natively through
the retained import. Manual core/benchmark source, environment and proof adapters remain unmigrated.

`d86140278` adds naming-retaining root library/kernel assembly entrypoints; legacy wrappers share
the parser/assembly path and preserve debug behavior. Full assembly units: 542 pass, six existing
ignores, no new skips. `b3c850d40` adds the explicit CLI builtin-exact-v1 naming-input backend and
source/package loader integration. Caller-selected complete home permissions, codec limits, source
declaration bindings and independent existing NamingV1 expectations replace discarded/inferred
naming. Every raw target, embedded kernel and library requires its own expectation; actual admission
must equal it in full. TypedId always rejects; this generic custom-home profile claims no Protocol,
publisher or publication validation. JSON byte caps and per-operation codec bounds have separate
documented accounting scopes, without an allocator/RSS guarantee.

Local source retains AssemblyProduct naming, checks caller entry equality and preserves core/foreign
metadata through linking; code and private advice remain separate from execution authority. Compile
now emits Package9 .masp, and producers can export checked NamingV1. Runtime branches share source/raw
loading and handler registration; handler-section deduplication is published only after successful
registration. No legacy kernel authority or permissive profile was restored.

**Validation:** VM library/internal tests: 42 pass, including all nine new naming tests; one existing
socket-file test failed at sandbox-denied UnixListener::bind (EPERM), then passed unchanged in a
focused sandbox-exempt retry. Strict library Clippy for VM/internal, assembly and test-utils passes;
assembly/test-utils no_std, scoped formatting and whitespace pass. Source reviews found no remaining
actionable issue. All three source commits have verified signatures. Root centralized guarded checks;
bounded agents ran no builds. No pushes or GitHub PRs.

**Open gates:** executable checking finds the removed to_kernel_descriptor call in cli/verify.rs:228;
the verifier's legacy program-hash/kernel claim path needs PR12 expected-statement migration. No full
executable/CLI-test/proof success is claimed. Remaining manual core/benchmark source bindings,
program extraction, native environment/trace setup and legacy claims stay in the scratch source
index. Existing PR14 compatibility-root, security-counterfactual and guest/project gates remain;
PR09/M1/final acceptance and PR10/PR12/PR14 work are still open. No proof constant regeneration.

### PR09 manual core execution and external test builders, 3 November 2026

`661a52d88` routes exported test-builder macros through Test::from_source_parts, preserving the
caller's loaded source/manager, stack/advice and tracing settings while keeping naming private.
Two external integration tests cover every input arity and source identity. Explicit raw/owned
append also discards naming for removed tail slots, preventing clear-and-reselection from inheriting
old owned metadata or a warmed cache. New same-object regressions cover raw rejection and valid
owned replacement. Helper units 18 plus external builders 2 pass; no fixture admission was broadened.

`3cce2348e` exposes the existing std source-manager accessor and reexports Parse, allowing callers
to parse in the assembler's exact source context without a second manager or extra dependency.
`1acd73374` migrates manual core debug/memory/crypto/precompile/recursive fixtures. The shared nested
test support module configures local fixture declarations, retains AssemblyProduct naming, and
builds finite environments from exact local/core/kernel inventories. Kernel public/private placement,
full batch cohorts, actual host sources, async forwarding, mutable stepping contexts and explicit
proving trace policies are preserved through extraction/execution. Imported core is never renamed
under the fixture convention. Existing forged handlers, memory overlap, security/proof/root assertions
and zero precompile ceilings remain intact; no new ignores/skips, refreshed proof-root constants
or deployment defaults.

**Qualification:** the 656-case core-lib integration target compiles. The separate auto-discovered
debug target runs 27 tests successfully; it is not selected by filtering the core-lib target.
Memory copy 4, manual precompile roots 10 (including forged advice), deferred wrapper 1 and defensive
signature-load/overlapping-local-write 1 pass. Strict Clippy for the core-lib/debug targets and
helper library/external builders passes; assembly/helper no_std, scoped formatting and whitespace
pass. Independent reviews found no remaining actionable issue. Three source signatures verified;
root centralized guarded checks, bounded agents ran no builds. No pushes or GitHub PRs.

Full 656-case execution, recursive/proof paths and compatibility identities are not qualified by
these focused native tests. Legacy claim construction and every existing PR12/PR14 security oracle
remain, without padding old public values or refreshing root constants. Next migrate benchmark/VM
integration source naming and environment/trace consumers; the CLI verification compile error and
previous claim/security/guest/final gates remain open. PR09, M1 and the overall goal are not complete.

### PR09 benchmark and VM integration consumers, 3 November 2026

`22f5089f4` shares NamedProgram assembly/product conversion through test-utils; core support becomes
a reexport. Exact artifact/naming, same parsing context and finite environment stay together. The
fallible conversion preserves calibration's Result contract when valid products exceed fixture
resource limits; a small valid deep-home product regression verifies error propagation, not panic.
Helper units 20/external builders 2 and strict library/test Clippy/no_std pass.

`ef12fb33b` migrates Blake3/precompile/synthetic source, calibration and recursive benchmark paths.
Each actual host gets a fresh matching witness source; execution/proving gets selected environment
and finite trace policy. Debug entry/source metadata, workload/configuration/measurement axes,
precompile limits and verification checks stay intact. Local transaction cache v6 additionally binds
independently selected K_entry/R_E; compatibility, relation, PCS, ProgramInfo and input checks remain.
Cache tests 2 and snippet tests 5 pass; all targets of all three packages compile/pass strict Clippy.
This is not a benchmark campaign, baseline refresh, calibration/proof-runtime or performance claim.

`ed5d3006d` migrates VM native/proving/event/advice and bounded witness round-trip fixtures. Reads
retain the original NamedProgram/environment and preselected capture trace policy, with explicit
4 MiB wire/16 MiB validation bounds. Structural external forests, byte/metadata/deferred round trips,
malformed traces, mutations and security assertions remain. Native dynamic/procref/caller oracles
now derive independent declaration K, retain Core reexport K, and distinguish equal-D module/local
identities; syscall D is rebuilt from an independently declared root callee K. These are PR09/D2
native oracles, not deferred proof-compatibility identity changes. Constraint checks are preserved.
CLI test package construction retains kernel/source naming; CLI command inputs remain unmigrated.

The VM integration target compiles; arbitrary-feature strict Clippy passes. Native events 6 and
advice-budget 6 pass. Full VM runtime, constraints/witness/proof/recursive paths remain unqualified
where legacy claims reach PR12. No new skips, weakened attack oracle, padded public values or proof
root refresh. Scoped formatting/whitespace and three source signatures verified. Root centralized
AC/heavy-guarded checks; bounded agents ran no builds. No pushes or GitHub PRs.

Next close VM-owned benchmark/CLI fixture consumers and fresh PR09 package/assembly checks. Existing
CLI verification compile error, PR12 statement transport, PR14 proof-request/compatibility roots,
security-counterfactual/guest/project/performance and final gates remain. PR09/M1/overall completion
is not claimed; PR10 and all later planned scope remain intact.


### PR09 parallel consumer and acceptance checkpoint, 3 November 2026

`7bd9765b1` retains owned naming/environments and fresh host witness sources in the three VM
benchmarks; their scoped `cargo check --locked -p miden-vm --features internal --bench build_trace
--bench program_execution_fast --bench program_execution_for_trace` passes. No performance claim.
`953eed44b` independently derives estimator K, preserves separate D/getter assertions and passes
both native `security_estimator_key_matches_procref` tests. `c9b9c7b44` supplies explicit fixture
custom dependency homes: full package units pass 289/one existing ignore, and standard
`make test-assembly EXTRA=--locked NEXTEST_PROFILE=ci` passes 544/six existing skips.

`fb4d1c7be` migrates CLI run/prove/bundle fixture inputs and adds Package9/optional-sidecar compile
coverage. Full naming expectations remain independent owned products; selected local bindings
supply K_entry/R_E, with at most128 native opening paths/4 MiB evidence and explicit finite policies.
Security, error ordering, atomic writes, handler deduplication and complete/deferred oracles remain.
The actual internal naming/opening file-admission plus native execution regression passes.
Strict `cargo clippy --locked -p miden-vm --features internal --test miden-cli -- --cfg
'feature="executable"' -D warnings` passes, compiling its precompile fixture module without claiming
production CLI qualification.

An existing VM binary runs flow-control nine pass/11 fail and caller one fail: native K output
assertions precede the preserved failing constraints, all at expected36/actual32 public values.
Production CLI legacy verification, PR12 statements, PR14 proof identities and previous final gates
remain open. Independent reviews and source signatures verified; documentation follows separately.
Root centralized guarded checks; agents ran no builds. No skips added, proof constants refreshed,
pushes or GitHub PRs. PR09/M1/overall completion is not claimed.


PR09 branch audit at `a97397cf1` found no additional PR09-owned source blocker; final review scope is committed separately as `0ec317994`. PR09 remains implemented-awaiting-validation for its preserved downstream gates. PR10 starts at that exact local stack base; the first owned slice is independent artifact callable expectations and opt-in source declaration naming. No branch/publication or validation claim changes the overall goal or M1.
