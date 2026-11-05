//! Fuzz target for bounded `ExecutionWitness` deserialization.
//!
//! Fuzz inputs are a caller-owned `K_entry[32] || R_E[32]` prefix followed by replay-v6
//! bytes. The prefix is a harness envelope, never part of the production witness format.
//!
//! Run with: cargo +nightly fuzz run execution_witness_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core_fuzz::witness::exercise;

fuzz_target!(|data: &[u8]| {
    let _ = exercise(data);
});
