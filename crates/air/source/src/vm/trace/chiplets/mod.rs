use miden_core::{Felt, ONE, ZERO};

pub mod ace;
pub mod bitwise;
pub mod hasher;
pub mod library;
pub mod memory;

// CONSTANTS
// ================================================================================================

/// Number of selector cells preceding each packed row family's payload.
pub const NUM_CONTROLLER_SELECTORS: usize = 2;
pub const NUM_AEAD_SELECTORS: usize = 3;
pub const NUM_MEMORY_SELECTORS: usize = 4;
pub const NUM_ACE_SELECTORS: usize = 5;
pub const NUM_BITWISE_SELECTORS: usize = 6;
