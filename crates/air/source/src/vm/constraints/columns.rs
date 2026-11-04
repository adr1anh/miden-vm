//! Column layout types for the main and auxiliary execution traces.
//!
//! These `#[repr(C)]` structs provide typed, named access to trace columns.
//! They are borrowed zero-copy from raw `[T; WIDTH]` slices and are used
//! exclusively by constraint code. They are independent of trace storage
//! (`MainTrace`, `TraceStorage`, etc.).

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use super::{
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
        AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseCols,
        ControllerCols, LibraryCols, MemoryCols,
    },
    decoder::columns::DecoderCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
use crate::vm::trace::{CHIPLETS_DATA_WIDTH, TRACE_WIDTH, chiplets::library::LIBRARY_COL_RANGE};

// CORE TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the core execution trace.
///
/// `CoreCols` covers the system, decoder, and stack segments — the columns owned by `CoreAir`.
/// It is also the layout of the leading `NUM_CORE_COLS` columns of the unified `TRACE_WIDTH`-wide
/// main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CORE_COLS]` slice or the prefix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<CoreCols<T>>`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CoreCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
}

/// Number of columns in the core trace (52), derived from the struct layout.
pub const NUM_CORE_COLS: usize = size_of::<CoreCols<u8>>();

impl<T> Borrow<CoreCols<T>> for [T] {
    fn borrow(&self) -> &CoreCols<T> {
        debug_assert_eq!(self.len(), NUM_CORE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<CoreCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<CoreCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut CoreCols<T> {
        debug_assert_eq!(self.len(), NUM_CORE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<CoreCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

impl<T> CoreCols<T> {
    /// Returns the column layout as a flat slice of length NUM_CORE_COLS, in column-index
    /// order. Useful for column-index → field lookups (e.g. a `CoreCols<&str>` name table).
    pub fn as_slice(&self) -> &[T] {
        let ptr = self as *const Self as *const T;
        unsafe { core::slice::from_raw_parts(ptr, NUM_CORE_COLS) }
    }
}

// CHIPLETS TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the chiplets execution trace.
///
/// `ChipletCols` covers the shared chiplet data columns and `chip_clk`.
/// Shared chiplet cells are row overlays; prefer semantic accessors over raw indices.
/// These are the columns owned by `ChipletsAir`. It is also the layout of the trailing
/// `NUM_CHIPLETS_COLS`
/// columns of the unified main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CHIPLETS_COLS]` slice or the suffix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<ChipletCols<T>>`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct ChipletCols<T> {
    pub(crate) chiplets: [T; CHIPLETS_DATA_WIDTH],
    /// Controller-local address: starts at 1 on section entry and increments through padding.
    /// Unused outside Controller; native traces write zero there.
    pub chip_clk: T,
}

/// Number of columns in the chiplets trace, derived from the struct layout.
pub const NUM_CHIPLETS_COLS: usize = size_of::<ChipletCols<u8>>();

impl<T> ChipletCols<T> {
    /// Returns the Library overlay of shared cells `c[1..23]`.
    pub fn library(&self) -> &LibraryCols<T> {
        self.chiplets[LIBRARY_COL_RANGE].borrow()
    }

    /// Returns the packed section selectors `[S_lib, C, A, m, a, b]`.
    ///
    /// Later selector cells are payload when an earlier section owns the row.
    pub fn chiplet_selectors(&self) -> [T; 6]
    where
        T: Copy,
    {
        core::array::from_fn(|i| self.chiplets[i])
    }

    /// Returns a typed borrow of the bitwise chiplet columns (chiplets\[6..19\]).
    pub fn bitwise(&self) -> &BitwiseCols<T> {
        self.chiplets[6..19].borrow()
    }

    /// Returns a typed borrow of the AEAD stream columns (chiplets\[3..23\]).
    pub fn aead_stream(&self) -> &AeadStreamCols<T> {
        self.chiplets[3..23].borrow()
    }

    /// Returns a typed borrow of the memory chiplet columns (chiplets\[4..19\]).
    pub fn memory(&self) -> &MemoryCols<T> {
        self.chiplets[4..19].borrow()
    }

    /// Returns the lower 16-bit limb of the memory word address (chiplets\[19\]).
    ///
    /// Range-check auxiliary column populated by the trace builder for the lookup-bus
    /// emitter; not part of [`MemoryCols`] because the memory AIR's own transition
    /// constraints don't act on it.
    pub fn memory_word_addr_lo(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[19]
    }

    /// Returns the upper 16-bit limb of the memory word address (chiplets\[20\]).
    ///
    /// See [`Self::memory_word_addr_lo`] for the same caveat about the range-check
    /// auxiliary columns living outside [`MemoryCols`].
    pub fn memory_word_addr_hi(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[20]
    }

    /// Returns the Memory write helpers `e0` and `e1` (shared cells `c[21]` and `c[22]`).
    ///
    /// Meaningful only on Memory rows. Other row families own these cells through their
    /// respective overlays.
    pub fn memory_write_helpers(&self) -> [T; 2]
    where
        T: Copy,
    {
        [self.chiplets[21], self.chiplets[22]]
    }

    /// Returns mutable Memory write-helper cells `c[21]` and `c[22]`.
    ///
    /// Callers must restrict writes through this view to materialized Memory rows.
    pub fn memory_write_helpers_mut(&mut self) -> &mut [T; 2] {
        (&mut self.chiplets[21..23]).try_into().expect("fixed Memory helper width")
    }

    /// Returns a typed borrow of the ACE chiplet columns (chiplets\[5..21\]).
    pub fn ace(&self) -> &AceCols<T> {
        self.chiplets[5..21].borrow()
    }

    /// Returns the ACE operation-square helper `z` (shared cell `c[21]`).
    ///
    /// Meaningful only on ACE EVAL rows. Other row families own this cell through their
    /// respective overlays.
    pub fn ace_op_squared(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[21]
    }

    /// Returns the mutable ACE operation-square helper cell `c[21]`.
    ///
    /// Callers must restrict writes through this view to materialized ACE rows.
    pub fn ace_op_squared_mut(&mut self) -> &mut T {
        &mut self.chiplets[21]
    }

    /// Returns a typed borrow of the controller sub-chiplet columns (chiplets\[2..21\]).
    pub fn controller(&self) -> &ControllerCols<T> {
        self.chiplets[2..21].borrow()
    }

    /// Returns the controller-local final-row marker (`chiplets[21]`).
    ///
    /// Meaningful only on Controller rows; other chiplets use this physical cell according to
    /// their own overlays.
    pub fn controller_op_final(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[21]
    }

    /// Returns the controller-local MRUPDATE id (`chiplets[22]`).
    ///
    /// Meaningful only on Controller rows; other chiplets use this physical cell according to
    /// their own overlays.
    pub fn controller_mrupdate_id(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[22]
    }
}

impl<T> Borrow<ChipletCols<T>> for [T] {
    fn borrow(&self) -> &ChipletCols<T> {
        debug_assert_eq!(self.len(), NUM_CHIPLETS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ChipletCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ChipletCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ChipletCols<T> {
        debug_assert_eq!(self.len(), NUM_CHIPLETS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ChipletCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

// Compile-time invariant: the two halves cover the full main trace exactly.
const _: () = assert!(NUM_CORE_COLS + NUM_CHIPLETS_COLS == TRACE_WIDTH);

// CONST HELPERS
// ================================================================================================

/// Generates an array `[0, 1, 2, ..., N-1]` at compile time.
pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut arr = [0; N];
    let mut i = 0;
    while i < N {
        arr[i] = i;
        i += 1;
    }
    arr
}

// COLUMN COUNTS
// ================================================================================================
//
// The auxiliary trace is the LogUp lookup-argument segment built per-AIR by `CoreAir`'s
// and `ChipletsAir`'s `AuxBuilder` impls (see `crates/air/source/src/vm/constraints/lookup/`): 5
// Core columns + 4 Chiplets columns.

pub const NUM_SYSTEM_COLS: usize = size_of::<SystemCols<u8>>();
pub const NUM_DECODER_COLS: usize = size_of::<DecoderCols<u8>>();
pub const NUM_STACK_COLS: usize = size_of::<StackCols<u8>>();
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();
pub const NUM_AEAD_STREAM_COLS: usize = size_of::<AeadStreamCols<u8>>();
pub const NUM_AEAD_STREAM_READ_COLS: usize = size_of::<AeadStreamReadCols<u8>>();
pub const NUM_AEAD_STREAM_HIGH_FIRST_COLS: usize = size_of::<AeadStreamHighFirstCols<u8>>();
pub const NUM_AEAD_STREAM_LOW_SECOND_COLS: usize = size_of::<AeadStreamLowSecondCols<u8>>();
pub const NUM_AEAD_STREAM_HIGH_SECOND_COLS: usize = size_of::<AeadStreamHighSecondCols<u8>>();
pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();
pub const NUM_ACE_COLS: usize = size_of::<AceCols<u8>>();
pub const NUM_ACE_READ_COLS: usize = size_of::<AceReadCols<u8>>();
pub const NUM_ACE_EVAL_COLS: usize = size_of::<AceEvalCols<u8>>();

const _: () = assert!(NUM_CORE_COLS == 52);
const _: () = assert!(TRACE_WIDTH == 76);
const _: () = assert!(NUM_SYSTEM_COLS == 6);
const _: () = assert!(NUM_DECODER_COLS == 27);
const _: () = assert!(NUM_STACK_COLS == 19);
const _: () = assert!(NUM_BITWISE_COLS == 13);
const _: () = assert!(NUM_AEAD_STREAM_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_READ_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_HIGH_FIRST_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_LOW_SECOND_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_HIGH_SECOND_COLS == 20);
const _: () = assert!(NUM_MEMORY_COLS == 15);
const _: () = assert!(NUM_ACE_COLS == 16);
const _: () = assert!(NUM_ACE_READ_COLS == 4);
const _: () = assert!(NUM_ACE_EVAL_COLS == 4);

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::trace::{
        CHIPLETS_CLK_COL, CHIPLETS_WIDTH, DECODER_TRACE_OFFSET, RESOLVED_DIGEST_RANGE,
        STACK_TRACE_OFFSET,
    };

    /// Per-AIR index maps used only by the column-layout tests below. Each field holds its
    /// column index inside its own AIR. `CORE_COL_MAP` lines up with unified-trace offsets
    /// since `CoreCols` sits at offset 0; `CHIPLET_COL_MAP` is 0-based within `ChipletCols`.
    const CORE_COL_MAP: CoreCols<usize> = unsafe {
        core::mem::transmute::<[usize; NUM_CORE_COLS], CoreCols<usize>>(
            indices_arr::<NUM_CORE_COLS>(),
        )
    };

    const CHIPLET_COL_MAP: ChipletCols<usize> = unsafe {
        core::mem::transmute::<[usize; NUM_CHIPLETS_COLS], ChipletCols<usize>>(indices_arr::<
            NUM_CHIPLETS_COLS,
        >())
    };

    // --- Core trace column map vs offset constants -------------------------------------------
    //
    // `CoreCols` starts at offset 0 of the unified main trace, so its per-AIR indices match
    // the unified trace offsets one-for-one.

    #[test]
    fn col_map_system() {
        assert_eq!(CORE_COL_MAP.system.clk, 0);
        assert_eq!(CORE_COL_MAP.system.ctx, 1);
        assert_eq!(CORE_COL_MAP.system.fn_hash[0], 2);
        assert_eq!(CORE_COL_MAP.system.fn_hash[3], 5);
    }

    #[test]
    fn col_map_decoder() {
        assert_eq!(CORE_COL_MAP.decoder.addr, DECODER_TRACE_OFFSET);
        assert_eq!(CORE_COL_MAP.decoder.op_bits[0], DECODER_TRACE_OFFSET + 1);
        assert_eq!(CORE_COL_MAP.decoder.op_bits[6], DECODER_TRACE_OFFSET + 7);
        assert_eq!(CORE_COL_MAP.decoder.hasher_state[0], DECODER_TRACE_OFFSET + 8);
        assert_eq!(CORE_COL_MAP.decoder.in_span, DECODER_TRACE_OFFSET + 16);
        assert_eq!(CORE_COL_MAP.decoder.group_count, DECODER_TRACE_OFFSET + 17);
        assert_eq!(CORE_COL_MAP.decoder.op_index, DECODER_TRACE_OFFSET + 18);
        assert_eq!(CORE_COL_MAP.decoder.full_batch, DECODER_TRACE_OFFSET + 19);
        assert_eq!(CORE_COL_MAP.decoder.batch_size_code, DECODER_TRACE_OFFSET + 20);
        assert_eq!(CORE_COL_MAP.decoder.extra[0], DECODER_TRACE_OFFSET + 21);
        assert_eq!(CORE_COL_MAP.decoder.extra[1], DECODER_TRACE_OFFSET + 22);
        assert_eq!(
            CORE_COL_MAP.decoder.resolved_digest,
            core::array::from_fn(|i| RESOLVED_DIGEST_RANGE.start + i)
        );
        assert_eq!(RESOLVED_DIGEST_RANGE.end, STACK_TRACE_OFFSET);
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(CORE_COL_MAP.stack.top[0], STACK_TRACE_OFFSET);
        assert_eq!(CORE_COL_MAP.stack.top[15], STACK_TRACE_OFFSET + 15);
        assert_eq!(CORE_COL_MAP.stack.b0, STACK_TRACE_OFFSET + 16);
        assert_eq!(CORE_COL_MAP.stack.b1, STACK_TRACE_OFFSET + 17);
        assert_eq!(CORE_COL_MAP.stack.h0, STACK_TRACE_OFFSET + 18);
    }

    // --- Chiplet trace column map -------------------------------------------------------------
    //
    // `CHIPLET_COL_MAP` is 0-based within `ChipletCols`.

    #[test]
    fn col_map_chiplets() {
        assert_eq!(CHIPLET_COL_MAP.chiplets[0], 0);
        assert_eq!(CHIPLET_COL_MAP.chip_clk, CHIPLETS_CLK_COL);
        assert_eq!(CHIPLET_COL_MAP.memory_write_helpers(), [21, 22]);
        assert_eq!(CHIPLET_COL_MAP.ace_op_squared(), 21);
        assert_eq!(CHIPLET_COL_MAP.chiplet_selectors(), [0, 1, 2, 3, 4, 5]);
        assert_eq!(CHIPLET_COL_MAP.controller().s0, 2);
        assert_eq!(CHIPLET_COL_MAP.controller_op_final(), 21);
        assert_eq!(CHIPLET_COL_MAP.controller_mrupdate_id(), 22);
        assert_eq!(CHIPLET_COL_MAP.bitwise().op_flag, 6);
        assert_eq!(CHIPLET_COL_MAP.memory().is_read, 4);
        assert_eq!(CHIPLET_COL_MAP.memory_word_addr_lo(), 19);
        assert_eq!(CHIPLET_COL_MAP.memory_word_addr_hi(), 20);
        assert_eq!(CHIPLET_COL_MAP.ace().s_start, 5);
    }

    #[test]
    fn chiplet_helper_writes_preserve_other_cells() {
        let mut row = indices_arr::<NUM_CHIPLETS_COLS>();
        let mut expected = row;
        {
            let cols: &mut ChipletCols<usize> = row.as_mut_slice().borrow_mut();
            *cols.memory_write_helpers_mut() = [101, 102];
            assert_eq!(cols.memory_write_helpers(), [101, 102]);
        }
        expected[21..23].copy_from_slice(&[101, 102]);
        assert_eq!(row, expected);

        {
            let cols: &mut ChipletCols<usize> = row.as_mut_slice().borrow_mut();
            *cols.ace_op_squared_mut() = 103;
            assert_eq!(cols.ace_op_squared(), 103);
            assert_eq!(cols.memory_write_helpers(), [103, 102]);
        }
        expected[21] = 103;
        assert_eq!(row, expected);
    }

    // --- Per-AIR width invariants -------------------------------------------------------------

    /// `NUM_CORE_COLS` matches the sum of the segment widths it covers.
    #[test]
    fn core_cols_width() {
        assert_eq!(NUM_CORE_COLS, NUM_SYSTEM_COLS + NUM_DECODER_COLS + NUM_STACK_COLS,);
    }

    /// `NUM_CHIPLETS_COLS` matches the chiplets segment width.
    #[test]
    fn chiplet_cols_width() {
        assert_eq!(NUM_CHIPLETS_COLS, CHIPLETS_WIDTH);
    }

    // --- Layout snapshots ---------------------------------------------------------------------
    //
    // These pin the resolved column-index maps of each `Cols<T>` view to `.snap` files,
    // so layout changes surface as snapshot diffs.
    // Regenerate with `cargo insta review` (or `INSTA_UPDATE=auto cargo test -p
    // miden-air-definitions`).

    /// Builds a `$cols<usize>` index map by reinterpreting `[0, 1, …, N-1]` through the
    /// struct's `#[repr(C)]` layout, where `N = size_of::<$cols<u8>>()`.
    macro_rules! col_map {
        ($cols:ident) => {{
            const N: usize = core::mem::size_of::<$cols<u8>>();
            const M: $cols<usize> =
                unsafe { core::mem::transmute::<[usize; N], $cols<usize>>(indices_arr::<N>()) };
            M
        }};
    }

    #[test]
    fn core_col_map_layout() {
        insta::assert_debug_snapshot!(CORE_COL_MAP);
    }

    #[test]
    fn chiplet_col_map_layout() {
        insta::assert_debug_snapshot!(CHIPLET_COL_MAP);
    }

    #[test]
    fn bitwise_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(BitwiseCols));
    }

    #[test]
    fn aead_stream_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamCols));
    }

    #[test]
    fn aead_stream_read_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamReadCols));
    }

    #[test]
    fn aead_stream_high_first_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamHighFirstCols));
    }

    #[test]
    fn aead_stream_low_second_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamLowSecondCols));
    }

    #[test]
    fn aead_stream_high_second_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamHighSecondCols));
    }

    #[test]
    fn memory_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(MemoryCols));
    }

    #[test]
    fn ace_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceCols));
    }

    #[test]
    fn ace_read_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceReadCols));
    }

    #[test]
    fn ace_eval_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceEvalCols));
    }

    #[test]
    fn hasher_controller_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(ControllerCols));
    }
}
