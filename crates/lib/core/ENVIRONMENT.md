# Environment construction, inspection, and upgrades

`miden::core::sys::environment` implements the same domain-separated commitments as
`miden_core::program::{EnvNode, Namespace}`. A procedure leaf commits its **local label** and
**implementation root**. Its callable key is derived separately from the accumulated namespace
and local label. A list of callable keys and implementation roots therefore also needs label
commitments to construct a VM environment.

All stack diagrams below put the top of the stack on the left. Words use ordinary memory
element order. Label inputs are commitments produced by `CanonicalLabel::commitment`, not
unframed strings or procedure keys.

## Commitment and inspection helpers

| Procedure | Input | Output |
| --- | --- | --- |
| `initial_namespace` | `[]` | `[NAMESPACE]` |
| `child_namespace` | `[PARENT, LABEL]` | `[NAMESPACE]` |
| `procedure_key` | `[NAMESPACE, LABEL]` | `[KEY]` |
| `hash_env` | `[LABEL, CHILD]` | `[ROOT]` |
| `hash_mast` | `[LABEL, IMPLEMENTATION]` | `[ROOT]` |
| `hash_merkle` | `[LEFT, RIGHT]` | `[ROOT]` |
| `hash_list` | `[children_ptr, count]` | `[ROOT]` |
| `hash_data` | `[kind, LABEL, VALUE]` | `[ROOT]` |
| `open_env` | `[ROOT]` | `[LABEL, CHILD]` |
| `open_mast` | `[ROOT]` | `[LABEL, IMPLEMENTATION]` |
| `open_merkle` | `[ROOT]` | `[LEFT, RIGHT]` |

Each `hash_*` helper records the exact hash payload in the advice map under its resulting root.
The fixed-size openings check both advice length and the typed commitment before returning
fields. Opening a Mast commitment as an Env or Merkle object fails, even when the underlying
payload has the same shape. These helpers preserve the operand-stack tail.

Lists hash `count` consecutive child words, including an empty list. A partial final compression
block is zero-padded without reading beyond the list. Data kinds must fit in a u32. List pointers
must be word-aligned u32s; `4*count` and the exclusive end address must fit in u32. This
stack-only helper has no working locals, so it also accepts arrays in caller locals or at
higher memory addresses.

Advice entries are **raw Felt hash payloads**, not serialized `EnvNode::to_bytes()` records or
native `ResolutionWitness` objects. Their type is supplied by the caller and authenticated by
the corresponding domain. Native environment sources remain a separate host interface.
Binary collection nodes use the native Merkle-node chaining word, shared by `mtree_verify`,
`mtree_get`, `mtree_set`, and `mtree_merge`. It has the reserved all-zero frame, rather than
Felt-sequence domain/length framing. The former `ENV_MERKLE` allocation remains retired and
reserved. This changes commitments of binary collections and every enclosing environment;
the other node types, callable keys, and canonical node encoding are unchanged.

For a tree available only in the native Merkle store, inspect its children with `mtree_get`.
The `open_merkle` helper additionally requires the parent's raw advice-map preimage.

## Constructing and checking a complete library

`environment::library::create` takes:

```text
[NAMESPACE, entries_ptr, count, scratch_ptr, ...] -> [ROOT, ...]
```

Each twelve-Felt entry is `[LABEL, KEY, IMPLEMENTATION]`. Entries must be strictly sorted by
KEY using `miden::core::word` ordering (most significant word coordinate first). The procedure
checks `KEY == procedure_key(NAMESPACE, LABEL)` for every entry and rejects equal keys.
The input entries are preserved; scratch contains `count` words and is overwritten. These
helpers support at most 65,536 entries, bounding host witness preparation before allocation.

For a nonempty library, each entry becomes a Mast leaf. Successive rounds hash adjacent pairs
as native Merkle nodes and promote an unpaired last child unchanged. There are no padding leaves.
A singleton is its Mast root; an empty library is the empty List root. This deterministic shape
has logarithmic maximum depth. It need not match another application's choice of tree shape.

For example, after initializing two sorted entries in memory at address 1024:

```masm
use miden::core::sys::environment
use miden::core::sys::environment::library

begin
    push.4096.2.1024
    exec.environment::initial_namespace
    exec.library::create
    # => [ROOT, ...]
end
```

To mount the library beneath an Env label, derive its namespace with `child_namespace` before
construction and wrap its returned root with `hash_env` using that same label. Repeat this for
each enclosing namespace. Collection edges do not extend the namespace.

`library::verify` takes the expected root as an additional first argument:

```text
[ROOT, NAMESPACE, entries_ptr, count, scratch_ptr, ...] -> [...]
```

It constructs the complete library and asserts equality with ROOT, which can be a public input.
The root binds the supplied order, labels, implementations, and tree shape. Missing or extra
entries change the root. Both memory ranges must be word-aligned, have u32 exclusive end
addresses, and be disjoint unless empty. Construction and its inlined helpers use no working
locals, so caller-local storage and higher memory addresses are both supported.

MASM checks every callable key, enforces strict ordering, and hashes every typed Mast leaf
into scratch. Trees with two through seven entries are constructed directly with `mtree_merge`.
This avoids host tree preparation and per-leaf membership checks for small trees, while recording
both the native Merkle-store nodes and the exact raw parent preimages. The reducer specializes
three- and four-node rounds and merges the final pair without another reduction round.

Larger trees use the registered tree-building event to construct a candidate native tree,
populate the advice provider's Merkle store, and record each parent's raw advice-map
preimage. `CoreLibrary::handlers()` supplies the default handler.

The candidate root remains untrusted until MASM verifies every scratch leaf with
`mtree_verify`. Depths and indices are computed in MASM from the entry count and the canonical
pair-and-promote shape. Those positions cover a complete prefix-free leaf frontier: a handler
cannot satisfy verification by repeating one position, omitting a binding, or hiding extra
leaves. Empty and singleton libraries need no event or native opening: their roots are computed
directly from the validated inputs, and `verify` compares those roots with its expected ROOT.
Native membership checks are used only for the larger-tree branch. The verification loop retains
the root, depth, and index in the opcode's operand slots between leaves to avoid repeated copies.

The event is witness preparation; it does not authorize a root or authenticate its returned
nodes. VM work includes `n` callable-key hashes, `n` Mast hashes, and either direct native merges
or native membership checks. Each membership opcode is one main-VM operation, but its path adds
chiplet controller rows and runtime hashing work. Identical compression inputs are deduplicated
in the compression trace. VM-cycle savings therefore do not by themselves imply proportional
proving-cost savings.

## Indexed native-library upgrades

`library::update_at` replaces one procedure at a native Merkle position:

```text
[descriptor_ptr, ROOT, KEY, NAMESPACE, ...] -> [NEW_ROOT, ...]
```

Its aligned sixteen-Felt descriptor contains:

```text
[LABEL: word, OLD_IMPLEMENTATION: word, NEW_IMPLEMENTATION: word, depth, index, 0, 0]
```

MASM derives KEY from NAMESPACE and LABEL, computes the replacement Mast digest, and calls
`mtree_set`. It checks the opcode's authenticated old leaf against the descriptor's label and
old implementation before returning the new root. This uses one path update and preserves
every unrelated sibling. No separate membership verification is needed. The advice provider
must have the required native Merkle path, supplied by construction or by the caller's host.
The new Mast preimage is recorded in the advice map; updated native parents are retained in
the Merkle store.

Depth zero is the singleton case: index must be zero, ROOT must equal the old Mast digest,
and the result is the new Mast digest. Nonzero depths follow the native opcode's depth/index
rules. Both reserved fields must be zero. The descriptor must fit in u32 memory, be
word-aligned, and precede working locals, checked with `locaddr` before any local writes.

NAMESPACE is the caller's intended namespace for this library fragment. Authentication of its
mount into a larger environment remains the caller's responsibility. Use the mixed-path
helpers below when the namespace path itself must be authenticated.

## Selective binding verification and upgrades

`environment::paths::verify_binding` authenticates one binding under a supplied root and key:

```text
[descriptor_ptr, ROOT, KEY, ...] -> [IMPLEMENTATION, NAMESPACE, ...]
```

The aligned twelve-Felt descriptor contains:

```text
[leaf_label: word, old_implementation: word, path_ptr, path_len, 0, 0]
```

Its path contains `path_len` eight-Felt records, ordered from the leaf's parent toward the root:

```text
[kind, selector, 0, 0, payload: word]
```

| Kind | Payload | Selector |
| --- | --- | --- |
| `0`: Env | Local label commitment | Must be `0` |
| `1`: Merkle | Sibling root | `0` for selected left child, `1` for selected right child |

An empty path opens a Mast directly at ROOT. Namespace derivation starts at the fixed initial
namespace and visits Env labels in reverse path order, from root toward leaf. The helper checks
the derived callable key and recomputed root. Pointers, lengths, reserved fields, kinds, and
selectors are checked before traversal. Descriptor and path ranges must precede the verifier's
working locals, checked through the supported `locaddr` instruction; descriptors stored in caller
locals remain valid. This compact path
format supports Env and Merkle ancestors. List ancestors require a separate full-list check
with `hash_list`.

Verification reads the descriptor directly and computes the old root without advice-map writes.
Constructors and updates register node preimages; fixed-size openings read existing map entries.

`paths::update_binding` takes a replacement implementation before the same arguments:

```text
[NEW_IMPLEMENTATION, descriptor_ptr, ROOT, KEY, ...] -> [NEW_ROOT, ...]
```

It authenticates the old binding, then rehashes the Mast and its ancestors with the replacement.
All labels, sibling roots, selected slots, and topology are preserved. New node preimages are
recorded in the advice map. Work is linear in path length, hence logarithmic in a library built
by `create`. An unchanged implementation returns the original root.

For multiple replacements, call the update helper against successive returned roots. Each later
descriptor must contain the old implementation and sibling commitments for that current root.
The procedures do not define a shared multiproof format or assume that stale paths remain valid.

## Root authority and executable code

An opening proves selective membership, not global absence of duplicate keys or availability of
the executable MAST. `library::create` establishes key uniqueness within its complete flat
library; mounting multiple libraries requires the enclosing environment's own uniqueness policy.
Implementation-only updates preserve the callable keys of an already admitted environment.

Applications must authorize the environment root independently, for example by supplying an
expected root as a public input and checking it against their protocol's upgrade policy. The
returned implementation can be compared with an expected code commitment or version. Namespace
derivation alone does not authenticate a path. These helpers do not change the VM's fixed
execution target during a running execution, resolve executable code, or grant syscall authority.

See the [instruction reference](../../../docs/src/user_docs/assembly/instruction_reference.md)
for instruction stack effects and assembler operation counts.
