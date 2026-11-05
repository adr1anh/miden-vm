//! Shared column schema for the packed Library region.

use miden_core::WORD_SIZE;

/// Library's 22 local cells, viewed from shared Chiplets `c[1..23]`.
///
/// The direct Library selector at `c[0]` and Controller-local address `chip_clk` at `c[23]`
/// are outside this overlay. The words and scalars have row-kind-dependent meanings; the scalar `b`
/// holds sigma on Merkle and nonempty List B rows.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct LibraryCols<T> {
    pub x: [T; WORD_SIZE],
    pub y: [T; WORD_SIZE],
    pub z: [T; WORD_SIZE],
    pub w: [T; WORD_SIZE],
    /// Authentication depth.
    pub d: T,
    /// Row-kind-dependent frequency or List length.
    pub a: T,
    /// Row-kind-dependent frequency, odd flag, or selection scalar.
    pub b: T,
    /// Kind bits in little-endian order: `k[0] + 2*k[1] + 4*k[2]`.
    pub k: [T; 3],
}
