# Declaration-only interfaces and explicit namespace homes

LibraryTree tooling needs procedure keys before executable bodies or releases are selected. This branch adds validated semantic declaration paths, exact optional UTF-8 ABI metadata, separate tooling signatures, and explicit typed NamespacePlan homes that derive keys with the core label/hash helpers.

InterfaceArtifact v1 and Home v1 codecs require explicit finite budgets and external Protocol profiles/context. Artifacts commit canonical publisher-qualified descriptor/declaration bytes, retain externally assigned immutable LibraryId, and validate association and transitive dependency closure. Decoding rejects malformed framing, noncanonical Words/order/paths, wrong expected identity and commitment before authority callbacks. Encoding revalidates context; tooling signatures are outside wire/hash/authority. Profiles must supply descriptor canonicalization, permitted homes and an allocated Protocol numbered-v1 domain; none has a default.

Existing MASM invocation grammar is preserved. Word-form procref now prints canonically; the legacy MastRoot AST spelling documents opaque ProcedureKey semantics. Executable assembler lowering and package9 activation remain PR 09. Test fixtures now follow childless keyed MAST and the v6 target table without weakening trusted/untrusted hash checks.

Stack base: PR 03, `45be30b96`. Semantic foundation: PR 01 identities and reviewed D3 contract. Implementation is awaiting production Protocol profile evidence; synthetic domains/codecs are test fixtures and claim no allocation or publication authority.

Validation after AC/heavy-work guards:

- Package lib tests: 208 passed; one manual fuzz-seed generator ignored. Focused interface/Home tests: 52 passed.
- Full Make assembly-syntax suite: 327 passed, including checked-in MASM and printed-corelib parser regressions.
- Scoped and combined test-inclusive Clippy with `-D warnings`, package no-default-features, pinned formatting and whitespace checks passed.

Required external descriptor/domain/home/immutable-association/authenticated-closure fixtures remain open. Processor/fuzz validation inherited from earlier stack branches and runtime/AIR/statement/recursive integration belong to later PRs; this branch does not activate those execution/proof paths. The existing source-token versus decoded Unicode/backslash distinction is tracked for PR 09. No GitHub PR or push has been created.
