# PR06: Packed Library witness and authenticated lookup

Base: `adr1anh/librarytree-05-keyed-execution` at `53acb4837e8dc9f0ad046533600d2224afa8eea7`.
Semantic dependencies: canonical identities, chiplet/address foundation and authenticated runtime ledger.

Authenticated environment openings previously had no packed witness or Chiplets authentication
relation. This branch adds the Library side of resolution: unit rooted Open edges, complete reverse
Lists, normal/syscall Resolve suppliers and per-supplier full-namespace syscall equations. It keeps
four AIRs and Chiplets24/4 with nine periodic columns and lookup capacity `[4,4,3,2]`.

The shared layout and both selector paths now use Library → Controller → AEAD → Memory → ACE →
Bitwise → PAD. Controller initialization moves to the aligned Library exit. Memory/ACE helper
refactors keep the captured degree within nine. Kernel ROM bands, builder and messages are removed;
retired bus slots stay reserved.

Native replay retains the completed session. One stack-only traversal registers its compression
requests into the existing checked Hasher before exact allocation admission; final writing uses the
same traversal without registering again. Checked bands finalize the prefix before the existing
logical Controller-address conversion. Separate AEAD/Bitwise buffers preserve family order, clocks,
calling conventions and replay parity. Resource errors remain typed and retained native storage is
accounted at capture, read and export. Chiplets public `R_E || N_kernel` is mandatory and cannot be
inferred from legacy auxiliary data.

CLI/benchmark reports count six bands. Existing measured snapshots remain unchanged and require
recapture; their metrics are documented as historical.

## Validation

- Actual authored AIR library: 360 tests pass, including full degree capture, exact lookup metadata,
  moved-fraction multisets, boundary/public-shape rejection and Library mutation cases.
- Exact-source public harness using the real processor: nine witness tests pass in default/testing
  configurations, and sixteen execution tests cover the 40-case native mode/API matrix. Tests inspect
  the real prefix, entry frequency, relocated address, compression multiplicities and budget boundary.
- Strict AIR/test, processor/lib and source/public-test Clippy pass; processor no-default-features passes.
- Independent MAIN, lookup, native, integration and reporting source reviews completed.

## Remaining acceptance

PR06 is implemented-awaiting-validation. Normal processor/parallel/lookup/streamed fixtures remain
behind the three assembly migration errors and legacy fixture work. Complete production forged
matrices/Range/And8/global Resolve closure, generated/MASM/native/recursive/security checks, fuzz and
measured benchmark recapture remain required. Reporting/benchmark checks have not run.

Core Resolve/root-END binding is PR07; canonical Core36/claim44/transport and recursive activation
remain PR12/14. Legacy prove/verify producers omit mandatory Chiplets publics and reject statement
construction. This branch does not establish end-to-end proof acceptance. All external Protocol
identity/profile/registration/closure fixtures remain required under plan D3.
