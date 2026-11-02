# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code SHA `66c94030bc50437ba48e82f64d8986138ef0147f` (EXEC opcode reservation). PR 02 starts from PR 01 tip `4f6cda59906ffbbbbe3c794232bb5395be0cf344`. Documentation commits follow the code checkpoint; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is in progress. The current small slice replaces Call/SysCall callee child IDs with typed ProcedureKey targets and adds childless Exec nodes. Hash K||0 in the existing opcode-domain construction; no environment FeltSequence substitution. Child enumeration/remapping/fingerprints must separate structural edges from keyed invocation. Keep one call model and preserve External(D).

The fresh `keyed_nodes` agent owns mast/node/{call_node,exec_node,mod,mast_forest_contributor}.rs and mast/{mod,node_builder_utils,sparse}.rs. Codecs and existing test migrations follow separately; their intermediate compile failures are expected but must be captured precisely. No processor/assembly/AIR files are owned by this slice.

Start with this brief and plan **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-keyed-node-refactor.md`; consult cached execution.md **lines 151–219** only. Cache provenance.json owns Page/date/hash identity. Archives, whole chapters and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger/evidence. Node/hash/childlessness tests and codec closure remain pending. No joint decision blocks this slice. D2 preserves existing MASM source after rebuilding and interprets digest-shaped targets as keys; a new serialized MAST format is allowed.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
