#![cfg(feature = "std")]

// Compile the actual CLI adapter and evidence loader together without the unrelated built-in
// core producer/legacy CLI commands. The alias provides only their real source module path.
extern crate self as miden_vm;

#[path = "../../miden-vm/src/internal/execution_inputs.rs"]
pub mod execution_inputs;

pub mod internal {
    pub use crate::execution_inputs;
}

#[path = "../../miden-vm/src/cli/execution_inputs.rs"]
pub mod cli_execution_inputs;
