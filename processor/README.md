# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor provides multiple APIs depending on your use case:

### High-level API
The `ProgramExecutor` trait provides a pluggable ordinary-execution interface returning
`ExecutionOutput`, with `FastProcessor` as its default implementation:

Pass the caller-authorized `ExecutionTarget` by value, public inputs as `StackInputs`, and private
inputs as `AdviceInputs`. The target contains the expected entry procedure key `K_entry` and
environment root `R_E`. The `Host` owns loaded package code, supplies untrusted environment
lookup evidence and non-deterministic inputs, and receives messages from the VM.

Keep code, checked symbols, advice, and exact source metadata together in the `CodePackage`
produced by assembly or project compilation. Load it with `DefaultHost::load_library(code)` or
`DefaultHost::with_library(code)`, and configure the opening-evidence source with
`DefaultHost::with_environment_source`. Execution uses `execute_sync(target, &mut host)` or its
async analogue, `execute(target, &mut host).await`.

`ExecutionOptions` sets limits such as the maximum allowed number of cycles. Construct
`ResolutionLimits::new(opening, ledger, session)` with caller-selected `OpeningLimits`,
`LedgerLimits`, and `SessionLimits`, and install it with `with_resolution_limits`. These policies
have no default. Missing policies reject before entry authentication or host calls; explicit zero
limits remain zero. Tracing additionally requires caller-selected `EnvironmentTraceLimits` through
`with_environment_trace_limits`, also without a default.

Resolution policies bound candidate openings, retained opening occurrences, and session accounting
separately. Trace policies bound event count, accounted retained bytes, trace preparation peak,
and validation work. They do not bound allocator metadata, fixed stack storage, process RSS, or
prior host allocations. Native session preparation has its own resolution limit; a combined
native/trace ceiling requires checked addition of the two policies.

The caller authorizes the target independently of the host's packages and evidence. Every retained
runtime invocation authenticates a binding under the same `R_E` before the host supplies code for
the selected implementation root `D`. Generic host loading by `D` remains available subject to
requested-root and procedure-root checks; code availability alone does not authorize a call.
Syscalls require an authenticated immediate parent namespace equal to the fixed, nonzero
`N0 = Namespace::initial()`. Package and source metadata confer no syscall privilege.

The async trait method returns `Result<ExecutionOutput, ExecutionError>`, containing the final stack
state, advice provider, memory, and deferred state on success.

### Low-level API
For more control over execution and trace generation, you can use `FastProcessor` directly:

`FastProcessor::execute(target, &mut host)` runs without trace generation overhead and returns an
`ExecutionOutput` with the final stack state and other execution results.

`FastProcessor::execute_for_proving()` and `FastProcessor::execute_for_proving_sync()` run a
target while collecting the complete post-execution `ExecutionWitness`. Both take the target and
host separately from processor options. Pass the `VmWitness`
from `ExecutionWitness::into_parts()` and a caller-supplied proving budget to `build_trace()` to
construct the full `VmTrace`. Trace
building is parallel when the `concurrent` feature is enabled.

With the `std` feature, `FastProcessor::execute_and_build_trace_sync()` preserves the optimized
synchronous path that overlaps execution with hasher trace construction. It returns
`(VmTrace, Option<PrecompileWitness>)`. Execution stays on the calling thread while Rayon may run
the hasher builder on a worker. A caller with no separate Rayon worker uses compact buffered replay
and builds the trace after execution.

The target and selected resolution policies remain immutable through step/resume execution.
Host-owned packages retain exact source occurrences, including private entry metadata. Debug
metadata supplies diagnostics rather than authority. A built `VmTrace::entry_implementation()`
reports the authenticated selected `D`, separately from the expected target and public claim.

### Witness transport

Replay format v6 is read with
`ExecutionWitness::read_from_bytes_with_limits(bytes, target, resolution_limits, trace_limits, read_limits)`.
The reader requires the caller's expected `ExecutionTarget`, explicit `ResolutionLimits` and
`EnvironmentTraceLimits`, and bounded `ReplayReadLimits`. It revalidates the replay under those
policies and clamps resource use to the supplied limits, preserving explicit zeros. Host package
ownership metadata does not become replay authority. Rust API changes do not change the selected
canonical label codecs, claim40 v2 semantics, or replay v6 wire format.

## Processor components
The processor is separated into two main components: **execution** and **trace generation**.

### Execution with `FastProcessor`
The `FastProcessor` is designed for fast program execution with minimal overhead. It can operate in two modes:

* **Pure execution** via `FastProcessor::execute()`: Executes a program without generating any trace-related metadata. This mode is optimized for maximum performance when proof generation is not required.
* **Witness-producing execution** via `FastProcessor::execute_for_proving()` /
  `FastProcessor::execute_for_proving_sync()`: Executes a program while collecting the complete
  post-execution `ExecutionWitness`.

### Trace generation with `build_trace()`
After execution with `FastProcessor::execute_for_proving*()`, split the returned
`ExecutionWitness` and call `build_trace(vm_witness, &budget)`. The VM backend provides
`miden_vm_stark::memory::default_budget()` and `canonical_budget(limit_bytes)` using the canonical
proof configuration. Processor enforces the supplied model before final allocations and retains
independent row-index and raw-buffer limits. When the `concurrent` feature is enabled, trace
generation is parallelized for improved performance.


Trace generation produces the four matrices in the Miden proof statement:

* the core trace for the system, decoder, and operand stack;
* the stacked chiplets trace for the hash controller, bitwise, memory, ACE, and kernel ROM;
* the standalone 32-row Eidos compression trace; and
* the fixed And8 lookup trace, whose multiplicities also serve 16-bit range checks.

Typed LogUp relations connect requests and responses across these matrices. The processor collects
range-check and byte-lookup multiplicities while replaying execution and writes them into the fixed
And8 table; there is no separate range-checker execution-trace segment.

A much more in-depth description of Miden VM design is available [here](https://docs.miden.xyz/miden-vm/design).

## Crate features
Miden processor can be compiled with the following features:

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature enables concurrency across parts of execution. The `testing` feature enables APIs used in
tests.

To compile with `no_std`, disable default features via `--no-default-features` flag, in which case only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
