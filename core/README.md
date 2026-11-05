# Miden core
This crate contains core components used by Miden VM. These components include:

* Miden VM instruction set, defined in the [Operation](./src/operations/mod.rs) struct.
* Miden VM code structure, defined by the [MAST](./src/mast/mod.rs) types and described [here](https://docs.miden.xyz/miden-vm/design/programs).
* Typed callable identities and commitments, including `ProcedureKey`, `ImplementationRoot`, `EnvironmentRoot`, and `Namespace`, defined in [program](./src/program/mod.rs).
* Miden VM execution target, defined in [ExecutionTarget](./src/program/environment.rs), which contains the caller's expected entry procedure key and environment root.
* Miden VM public execution claim, defined in [ExecutionClaim](./src/program/claim.rs), which combines the expected execution target with public stack inputs and outputs.
* Input and output containers for Miden VM programs, defined in [StackInputs](./src/program/stack/inputs.rs) and [StackOutputs](./src/program/stack/outputs.rs) structs.
* Constants describing the shape of the VM's execution trace.
* Various minor utility functions used by other VM crates.

The caller independently authorizes the `ExecutionTarget` (`K_entry`, `R_E`). Loaded code,
checked package symbols, source metadata, and environment lookup evidence supply witnesses; they
do not authorize that target. The authenticated environment binds each invoked key to an
implementation root, and its root stays fixed throughout execution. Actual syscalls require an
authenticated immediate parent namespace equal to the fixed, nonzero
`N0 = Namespace::initial()`.

`ExecutionClaim` contains the target and canonical public stack inputs and outputs. A selected
implementation root `D`, including the authenticated `entry_implementation` exposed by trace
diagnostics, is separate from this claim. Package ownership and native execution policies belong
to the host and processor APIs respectively.

## Acknowledgements
The `racy_lock` module found under `core/src/utils/sync` is based on the [once_cell](https://crates.io/crates/once_cell) crate's implementation of `race::OnceBox`.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
