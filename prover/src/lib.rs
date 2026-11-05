#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod prover;

// EXPORTS
// ================================================================================================
pub use miden_core::{
    Word,
    advice::AdviceInputs,
    deferred::{PrecompileLimits, PrecompileWitness},
    program::{ExecutionClaim, ExecutionTarget, InputError, StackInputs, StackOutputs},
    proof::{ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof},
    serde::DeserializationError,
};
pub use miden_precompiles_stark::prover::PrecompileProvingError;
pub use miden_processor::{
    ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness, FutureMaybeSend, Host,
    ResolutionLimits, SyncHost, VmWitness,
};
pub use prover::{Prover, ProverError, prove_sync};

#[cfg(all(test, feature = "std"))]
mod block_stack_entry_kind_repro;
#[cfg(all(test, feature = "std"))]
mod ctx_continuation_end_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod dyncall_bottom_slot_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod dyncall_end_relabel_repro;
#[cfg(all(test, feature = "std"))]
mod dyncall_saved_frame_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod first_row_repeat_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod mrupdate_sibling_level_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod overflow_pointer_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod repeat_loop_schema_soundness_repro;
#[cfg(all(test, feature = "std"))]
mod repro_harness;
#[cfg(all(test, feature = "std"))]
mod span_entry_soundness_repro;

#[cfg(test)]
#[path = "test_utils/named_fixture.rs"]
mod named_fixture;
