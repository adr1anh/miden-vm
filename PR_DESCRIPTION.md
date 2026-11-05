# PR11: exact immutable advice resource lengths

Fixed-format resource loaders consumed a compiled prefix without checking the complete advice-map
value length. They now reject short or appended values before copying or semantic use: both ACE
streams, eight VM/PVM query rows and the FRI row. The shared ACE renderer and checked-in wrappers
carry the same length assertion; existing hash, Merkle, codec and domain checks remain intact.
Arbitrary/private/transaction advice keys and calling conventions remain supported. No optional ABI,
initialization or resource-inventory schema is introduced.

**Stack base:** PR10 `eefae17e7be44b130044bb5e53b6d1eec3dc2b9b`.

Central guarded validation:

- Eight actual-loader tests run: seven pass, one VM valid control remains failing. All 33 malformed
  length/hash cases pass independently; PVM, query-row and FRI valid controls pass.
- Renderer alignment and mixed advice-key transport tests pass. The latter removes real debug data
  and checks values/stable dependency commitments through trusted and normal readers.
- Core-library test target and ACE/package all-target strict Clippy pass; independent reviews pass.

**Open qualification:** the VM embeds 7,920 circuit felts while its wrapper expects 6,992. The valid
control stays unignored. Full generation check fails; the generator refuses to write because its
pinned ACE digest is stale. No identity, proof constant or compatibility whitelist was refreshed.
PR12/PR14 must complete coherent relation/statement/recursive qualification; all inherited security
and final gates remain open. No GitHub PRs or pushes.
