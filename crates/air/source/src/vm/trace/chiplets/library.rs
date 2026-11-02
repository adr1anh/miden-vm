//! Trace constants for the packed Library overlay in the shared Chiplets AIR.

use core::{mem::size_of, ops::Range};

use miden_core::{Felt, ONE, ZERO};

use crate::vm::constraints::chiplets::library::columns::LibraryCols;

/// Number of local Library cells, derived from the one shared schema.
pub const TRACE_WIDTH: usize = size_of::<LibraryCols<u8>>();

/// Library's shared cells, excluding the direct selector and global clock.
pub const LIBRARY_COL_RANGE: Range<usize> = 1..1 + TRACE_WIDTH;

// Kind bits are little-endian: k0 is the least significant bit.

/// Kind 0: Library padding.
pub const PAD: [Felt; 3] = [ZERO, ZERO, ZERO];
/// Kind 1: Merkle pair.
pub const MERKLE: [Felt; 3] = [ONE, ZERO, ZERO];
/// Kind 2: Env pair.
pub const ENV: [Felt; 3] = [ZERO, ONE, ZERO];
/// Kind 3: Mast pair.
pub const MAST: [Felt; 3] = [ONE, ONE, ZERO];
/// Kind 4: Nonempty List start pair.
pub const LIST_START: [Felt; 3] = [ZERO, ZERO, ONE];
/// Kind 5: List continuation pair.
pub const LIST_CONTINUE: [Felt; 3] = [ONE, ZERO, ONE];
/// Kind 6: Empty List pair.
pub const EMPTY_LIST: [Felt; 3] = [ZERO, ONE, ONE];
/// Kind 7: Invalid pattern, rejected by Library MAIN.
pub const INVALID: [Felt; 3] = [ONE, ONE, ONE];

const _: () = assert!(TRACE_WIDTH == 22);
