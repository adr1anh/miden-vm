//! Trace constants for the packed Library overlay in the shared Chiplets AIR.

use core::{mem::size_of, ops::Range};

use miden_core::{
    Felt, ONE, ZERO,
    field::{Algebra, BinomiallyExtendable},
    program::Namespace,
};

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
/// Kind 3: Mast pair outside the initial namespace.
pub const MAST: [Felt; 3] = [ONE, ONE, ZERO];
/// Kind 4: Nonempty List start pair.
pub const LIST_START: [Felt; 3] = [ZERO, ZERO, ONE];
/// Kind 5: List continuation pair.
pub const LIST_CONTINUE: [Felt; 3] = [ONE, ZERO, ONE];
/// Kind 6: Empty List pair.
pub const EMPTY_LIST: [Felt; 3] = [ZERO, ONE, ONE];
/// Kind 7: Mast pair in the initial namespace, with the label as its key.
pub const ROOT_MAST: [Felt; 3] = [ONE, ONE, ONE];

const _: () = assert!(TRACE_WIDTH == 22);

/// Quadratic norms of the two halves of the namespace's difference from the initial namespace.
///
/// The quadratic extension's nonresidue makes each norm zero exactly when both of its
/// coordinates are zero. Non-root Mast A rows use their scalars to witness that at least one
/// norm is nonzero.
pub fn namespace_difference_norms<E: Algebra<Felt>>(namespace: [E; 4]) -> [E; 2] {
    let [x0, x1, x2, x3] = namespace;
    let [n0, n1, n2, n3] = Namespace::initial().into_word().into_elements();
    let norm = |x: E, y: E| x.square() - y.square() * <Felt as BinomiallyExtendable<2>>::W;
    [norm(x0 - n0, x1 - n1), norm(x2 - n2, x3 - n3)]
}
