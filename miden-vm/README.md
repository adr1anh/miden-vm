# Miden VM

This crate aggregates all components of the Miden VM in a single place. Specifically, it re-exports
functionality from [processor](../processor/), [prover](../prover/), and [verifier](../verifier/)
crates. Additionally, when compiled as an executable, this crate can be used via a
[CLI interface](#cli-interface) to execute Miden VM programs and to verify correctness of their
execution.

## Basic concepts

An in-depth description of Miden VM is available in the full Miden VM [documentation](https://docs.miden.xyz/miden-vm/). In this section we cover only the basics to make the included examples easier to understand.

### Writing programs

Our goal is to make Miden VM an easy compilation target for high-level languages such as Rust,
Move, Sway, and others. We believe it is important to let people write programs in the languages of
their choice. However, compilers to help with this have not been developed yet. Thus, for now, the
primary way to write programs for Miden VM is to use
[Miden assembly](../crates/assembly/).

Miden assembler compiles assembly source code into a [program MAST](https://docs.miden.xyz/miden-vm/design/programs). Assembly and project products provide a `CodePackage` that keeps code, checked symbols, advice, and exact source metadata together. Load this package through the host before execution. Assembly requires an explicit namespace configuration; compiling or loading a package does not authorize its entry point.

Dependencies are linked with the same owner: `assembler.link_package(code, Linkage::Dynamic)`
or `with_package(code, linkage)`. Built-in libraries expose it through
`core_lib.code_package().clone()`. Kernel attachment also receives a `CodePackage`; callers do
not separately pair a package with its symbols.

#### Execution identity

The caller independently selects and authorizes an `ExecutionTarget` containing the expected entry procedure key `K_entry` and environment root `R_E`. The authenticated environment binds callable keys to implementation roots `D`. Host-loaded packages and environment lookup evidence supply witnesses for this target; they never supply execution authority. After binding authentication, the host may supply code for the requested `D`, subject to implementation-root and procedure-root checks.

The authenticated `entry_implementation` is useful for diagnostics about the selected code. It is separate from the target and the public `ExecutionClaim`, which also commits to public stack inputs and outputs. The environment root remains fixed throughout execution. Syscalls require an authenticated immediate parent namespace equal to the fixed, nonzero `N0 = Namespace::initial()`; code availability and source metadata confer no syscall privilege.

### Inputs / outputs

Currently, there are 3 ways to get values onto the stack:

1. You can use `push` instruction to push values onto the stack. These values become a part of the program itself, and, therefore, cannot be changed between program executions. You can think of them as constants.
2. The stack can be initialized to some set of values at the beginning of the program. These inputs are public and must be shared with the verifier for them to verify a proof of the correct execution of a Miden program. At most 16 values could be provided for the stack initialization, attempts to provide more than 16 values will cause an error.
3. The program may request nondeterministic advice inputs from the prover. These inputs are secret inputs. This means that the prover does not need to share them with the verifier. Advice can come from a stack, a map of element lists, or a Merkle store used by instructions that work with Merkle trees. Advice is subject to the configured advice-size and execution limits.

The stack is provided to Miden VM via `StackInputs` struct. These are public inputs of the execution, and should also be provided to the verifier. Initial private inputs are supplied as `AdviceInputs` when constructing the processor, which maintains an in-memory `AdviceProvider`. The host supplies code, environment evidence, and responses to runtime interactions. Package advice is merged once when its code is loaded for execution; guest resource loaders must authenticate advice values before using them.

Values remaining on the stack after a program is executed can be returned as stack outputs. You can specify exactly how many values (from the top of the stack) should be returned. Notice, that, similar to stack inputs, at most 16 values can be returned via the stack. Attempts to return more than 16 values will cause an error.

Having a small number elements to describe public inputs and outputs of a program may seem limiting, however, just 4 elements are sufficient to represent a root of a Merkle tree or a sequential hash of elements. Both of these can be expanded into an arbitrary number of values by supplying the actual values non-deterministically via the host interface.

## Usage

Miden crate exposes types and functions for executing programs, generating proofs of their correct execution, and verifying the generated proofs. How to do this is explained below, but you can also take a look at working examples [here](masm-examples/) and find instructions for running them via CLI [here](#fibonacci-example).

### Executing programs

For ordinary execution, construct `FastProcessor` and call `execute()` or `execute_sync()`.
Generic code can use the `ProgramExecutor` trait, whose default implementation is
`FastProcessor`. These interfaces take the following inputs:

- `target: ExecutionTarget` contains the caller-authorized entry key and environment root.
- `stack_inputs: StackInputs` contains the public inputs.
- `advice_inputs: AdviceInputs` contains the private inputs used to build the advice provider. Use `AdviceInputs::default()` when no private inputs are needed.
- `host` is a `Host` for `execute()` or a `SyncHost` for `execute_sync()`. It owns loaded package code, supplies untrusted environment evidence and nondeterministic inputs, and receives messages from the VM.
- `options: ExecutionOptions` controls execution settings such as the maximum cycle count. Execution requires explicit `ResolutionLimits::new(opening, ledger, session)` installed with `with_resolution_limits`. These policies have no default.

Ordinary execution returns a `Result<ExecutionOutput, ExecutionError>` containing the final stack
state and other execution outputs, or an error if execution failed. `ProgramExecutor` represents
this ordinary execution path; it does not capture a proving witness.

An `ExecutionOutput` cannot be converted into an `ExecutionWitness` after execution. The ordinary
path selects `NoopTracer` before the program runs, so it does not retain the replay data needed to
materialize the VM trace. If the execution will be proved, select tracing up front with
`FastProcessor::execute_for_proving()` / `FastProcessor::execute_for_proving_sync()`, then pass the
returned `ExecutionWitness` to `Prover::prove()`. To materialize only the VM trace, split the
witness with `ExecutionWitness::into_parts()` and pass the resulting `VmWitness` to
`trace::build_trace()` with a caller-selected proving budget. Tracing also requires explicit
`EnvironmentTraceLimits` installed with `with_environment_trace_limits`; these limits have no
default.

For example, the application supplies the package for `begin push.3 push.5 add swap drop end`,
an independently authorized target, and its execution policies. Its host must already have an
environment witness source, configured with `DefaultHost::with_environment_source`, and any
other packages the application needs:

```rust,no_run
use miden_vm::{
    advice::AdviceInputs,
    CodePackage, DefaultHost, ExecutionOptions, ExecutionOutput, ExecutionTarget, FastProcessor,
    LedgerLimits, OpeningLimits, ResolutionLimits, SessionLimits, StackInputs,
};

fn execute_addition(
    code: CodePackage,
    target: ExecutionTarget,
    mut host: DefaultHost,
    options: ExecutionOptions,
    opening: OpeningLimits,
    ledger: LedgerLimits,
    session: SessionLimits,
) -> ExecutionOutput {
    host.load_library(code).expect("package loading failed");
    let options = options.with_resolution_limits(ResolutionLimits::new(opening, ledger, session));
    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("invalid advice inputs")
        .execute_sync(target, &mut host)
        .expect("execution failed")
}
```

`DefaultHost::with_library(code)` is the builder form of `load_library(code)`. The async path uses
the same target and policies with `execute(target, &mut host).await`. Missing required policies
reject before entry authentication or host calls; explicit zero limits remain zero.

### Proving program execution

Execute with `FastProcessor` to produce an `ExecutionWitness`, and read its public claim before
proving consumes it. `Prover::prove` proves the VM portion. The returned `ExecutionProof` has an
empty precompile status when no deferred work exists, or a deferred status carrying one portable
`PrecompileWitness`. Use `Prover::prove_full` to complete all proof work in the local process.

For delegated precompile proving, transport the proof with `ExecutionProof::to_bytes`, then decode
it with `ExecutionProof::read_from_bytes`. Pass the carried witnesses to
`Prover::prove_precompiles(Vec<PrecompileWitness>)`. One batch produces one proof, preserving input
root order and repeated roots. After precompile proving, call `complete` and then `Verifier::verify`.
Completion preserves the compatibility declaration.

`ExecutionOptions::with_execution_precompile_limits` bounds guest-induced deferred work, while
`ExecutionOptions::with_verification_precompile_limits` bounds the final root-reachable witness
exported after execution. `Verifier::with_verification_precompile_limits` and
`Prover::with_verification_precompile_limits` configure the same per-singleton verification policy
for transported witnesses. Preparation applies verification limits before commitment hashing;
native semantic evaluation and Session import do not reapply admission. These logical limits are
distinct from the prover's batch-wide peak-memory budget.

`ExecutionOptions` configure execution, while `Prover::with_hash_fn` selects the proof hash
function. The FastProcessor-backed
`prove_sync(&Prover, target, stack_inputs, advice_inputs, &mut host, execution_options)` function
executes and fully proves in one synchronous call while preserving optimized overlapped execution
and trace construction.

`prove_sync()` overlaps execution with hasher-chiplet trace construction when a Rayon worker is
available. A caller with no separate Rayon worker uses compact buffered replay, including on
targets such as `wasm32-unknown-unknown`.

#### Proof generation example

Here is a simple example of executing a program which pushes two numbers onto the stack and computes their sum:

```rust,no_run
use miden_vm::{
    advice::AdviceInputs,
    field::PrimeField64,
    CodePackage, DefaultHost, EnvironmentTraceLimits, ExecutionOptions, ExecutionProof,
    ExecutionTarget, FastProcessor, Prover, ResolutionLimits, StackInputs,
};

fn prove_addition(
    code: CodePackage,
    target: ExecutionTarget,
    mut host: DefaultHost,
    options: ExecutionOptions,
    resolution: ResolutionLimits,
    tracing: EnvironmentTraceLimits,
) -> ExecutionProof {
    host.load_library(code).expect("package loading failed");
    let options = options
        .with_resolution_limits(resolution)
        .with_environment_trace_limits(tracing);
    let witness = FastProcessor::new_with_options(
        StackInputs::default(), AdviceInputs::default(), options,
    )
    .expect("invalid advice inputs")
    .execute_for_proving_sync(target, &mut host)
    .expect("execution failed");
    let outputs = *witness.claim().stack_outputs();
    let proof = Prover::new().prove(witness).expect("proof generation failed");
    assert_eq!(8, outputs.first().unwrap().as_canonical_u64());
    proof
}
```

### Verifying program execution

To verify program execution, use `Verifier::new().verify(&claim, &proof)`. The verifier borrows:

- `claim: &ExecutionClaim`. The expected execution target (`K_entry`, `R_E`) and public stack inputs and outputs.
- `proof: &ExecutionProof`. The deferred or complete execution proof artifacts.

The caller must independently choose and authorize the expected entry key and environment root, and supply the expected public inputs and outputs. Host-loaded code and environment lookup evidence provide witnesses for this claim.

The claim stores both stack inputs and outputs top-of-stack first, in their canonical zero-padded 16-element form. The first element of each stored stack is its top value.

The verifier returns `Result<VerificationOutcome, VerificationError>`. A successful deferred outcome
evaluates the carried witness and authenticates its outstanding VM root; a successful
complete outcome verifies every applicable STARK. Canonical proof decoding checks portable graph
encoding and allocation bounds without a registry. Preparation later validates and commits each
graph under the configured per-witness limits. Precompile proving imports the prepared witnesses
directly into a shared Session. See the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md) for transport and limit details.

> A complete verified proof attests that execution from the expected entry key under the fixed expected environment root, with the supplied public inputs and some private advice, produced the expected outputs.

The verifier takes the expected target and public stack inputs and outputs through the claim. It does not need the program code or environment lookup witnesses.

#### Proof verification example

Here is a simple example using the proof from the previous example and a target independently authorized by the verifying application:

```rust,no_run
use miden_vm::{
    ExecutionClaim, ExecutionProof, ExecutionTarget, StackInputs, StackOutputs,
    VerificationError, VerificationOutcome, Verifier,
};

fn verify_addition(
    proof: &ExecutionProof,
    expected_target: ExecutionTarget,
) -> Result<VerificationOutcome, VerificationError> {
    // The application authorizes expected_target independently of the supplied proof.
    let inputs = StackInputs::default();
    let outputs = StackOutputs::new(&[8_u32.into()]).unwrap();
    let claim = ExecutionClaim::new(expected_target, inputs, outputs);
    Verifier::new().verify(&claim, proof)
}
```

## Fibonacci calculator

Let's write a simple program for Miden VM (using
[Miden assembly](../crates/assembly/)). Our program will compute the 5-th
[Fibonacci number](https://en.wikipedia.org/wiki/Fibonacci_number):

```masm
push.0      // stack state: 0
push.1      // stack state: 1 0
swap        // stack state: 0 1
dup.1       // stack state: 1 0 1
add         // stack state: 1 1
swap        // stack state: 1 1
dup.1       // stack state: 1 1 1
add         // stack state: 2 1
swap        // stack state: 1 2
dup.1       // stack state: 2 1 2
add         // stack state: 3 2
```

Notice that except for the first 2 operations which initialize the stack, the sequence of `swap dup.1 add` operations repeats over and over. We can repeat these operations to compute another Fibonacci number. To compute the 50th term with public starting values, compile this source using an assembler configured with explicit namespaces:

```masm
begin
    repeat.49
        swap dup.1 add
    end
end
```

The application supplies the resulting `CodePackage`, its independently authorized target, and a
host configured with environment evidence. The synchronous helper executes and fully proves the
result:

```rust,no_run
use miden_vm::{
    advice::AdviceInputs,
    field::PrimeField64,
    prove_sync, CodePackage, DefaultHost, EnvironmentTraceLimits, ExecutionOptions,
    ExecutionProof, ExecutionTarget, Prover, ResolutionLimits, StackInputs,
};

fn prove_fibonacci(
    code: CodePackage,
    target: ExecutionTarget,
    mut host: DefaultHost,
    options: ExecutionOptions,
    resolution: ResolutionLimits,
    tracing: EnvironmentTraceLimits,
) -> ExecutionProof {
    host.load_library(code).expect("package loading failed");
    let options = options
        .with_resolution_limits(resolution)
        .with_environment_trace_limits(tracing);
    let inputs = StackInputs::new(&[1_u32.into(), 0_u32.into()]).unwrap();
    let (outputs, proof) = prove_sync(
        &Prover::new(), target, inputs, AdviceInputs::default(), &mut host, options,
    )
    .expect("execution or proving failed");
    assert_eq!(12586269025, outputs.get_num_elements(1)[0].as_canonical_u64());
    proof
}
```

Public inputs initialize the stack, so the same compiled code can run from different starting
values. The verifier supplies those expected inputs, the expected outputs, and its authorized
target through `ExecutionClaim`.

## CLI interface

If you want to execute, prove, and verify programs on Miden VM, but don't want to write Rust code, you can use Miden CLI. It also contains a number of useful tools to help analyze and debug programs.

The CLI limits package (`.masp`) files to 512 MiB, input (`.inputs`) JSON files to
64 MiB, and output (`.outputs`) JSON files to 64 KiB. Verification also limits the whole
proof transport to 512 MiB by default; `--max-proof-size` selects another byte cap
(for example, `64Mi`). The proof cap is checked before reading and decoding, and an explicit
zero stays zero. Files at the limit are accepted;
larger files are rejected before decoding. These readers accept regular files and
symlinks to regular files. Pipes, devices, and directories are rejected.

The CLI writes each proof and output JSON artifact to a temporary file in the
destination directory. It replaces the destination after writing and syncing the
complete artifact, so a write failure leaves the previous file intact. Replacing
a destination symlink replaces the link itself.

New artifacts and replacements belong to the current user and use normal file
creation permissions, including inherited ACLs. The CLI does not copy the previous
file's ownership or access controls.

On Unix, the CLI syncs the destination directory after replacement to persist the
rename. A failure at this final step reports that the new artifact has already
replaced the previous file.

### Compiling Miden VM

First, make sure you have Rust [installed](https://www.rust-lang.org/tools/install). The current version of Miden VM requires Rust version **1.96** or later.

Then, to compile Miden VM into a binary, run the following `make` command:

```shell
make exec
```

This will place `miden-vm` executable in the `./target/optimized` directory.

By default, the executable will be compiled in the multi-threaded mode. If you would like to enable single-threaded proof generation, you can compile Miden VM using the following command:

```shell
make exec-single
```

We also provide a number of `make` commands to simplify building Miden VM for various targets:

```shell
# build an executable for a generic target (concurrent)
make exec

# build an executable for targets with AVX2 instructions (concurrent)
make exec-avx2

# build an executable for targets with SVE instructions (concurrent)
make exec-sve

# build an executable with log tree enabled
make exec-info
```

### Running Miden VM

Once the executable has been compiled, you can run Miden VM like so:

```shell
./target/optimized/miden-vm [subcommand] [parameters]
```

Currently, Miden VM can be executed with the following subcommands:

- `run` executes a Miden assembly program and outputs the result without generating a proof.
- `prove` executes a Miden assembly program and generates a STARK proof.
- `verify` verifies a previously generated proof for a given program.
- `compile` compiles a Miden assembly program and reports compilation statistics.
- `debug` starts a CLI debugger for the specified Miden assembly program and inputs.
- `analyze` runs a Miden assembly program against specific inputs and reports execution statistics.

All of the above subcommands require various parameters to be provided. To get more detailed help on what is needed for a given subcommand, you can run the following:

```shell
./target/optimized/miden-vm [subcommand] --help
```

For example:

```shell
./target/optimized/miden-vm prove --help
```

### Fibonacci example

In the `miden-vm/masm-examples/fib` directory, we provide a very simple Fibonacci calculator example. This example computes the 1000th term of the Fibonacci sequence. You can execute this example on Miden VM like so:

```shell
./target/optimized/miden-vm run miden-vm/masm-examples/fib/fib.masm -n 1
```

This will run the example code to completion and will output the top element remaining on the stack.

## Crate features

Miden VM can be compiled with the following features:

- `std` is enabled by default and relies on the Rust standard library.
- `concurrent` implies `std` and enables multithreaded proof generation.
- `executable` is required for building the Miden VM binary as described above. It implies `std`.
- `metal` enables [Metal](<https://en.wikipedia.org/wiki/Metal_(API)>)-based acceleration of proof generation for recursive proofs on supported platforms such as Apple silicon.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
  - Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation

When compiled with `concurrent` feature enabled, the VM will generate STARK proofs using multiple threads. For benefits of concurrent proof generation check out these [benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. To control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
