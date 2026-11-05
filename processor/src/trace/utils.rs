#[cfg(test)]
use alloc::vec::Vec;

use crate::{ExecutionError, Felt, ONE, trace::chiplets::layout::ChipletBand};
#[cfg(test)]
use crate::{operation::Operation, utils::ToElements};

// ROW-MAJOR TRACE WRITER
// ================================================================================================

/// Row-major flat buffer writer (`write_row` is a single `copy_from_slice`).
///
/// `payload` is the number of leading columns written per row; `stride` is the physical row
/// width of the backing buffer. When `stride > payload`, the trailing `stride - payload`
/// columns of each row are left untouched (callers rely on them staying zero-initialized).
#[derive(Debug)]
pub struct RowMajorTraceWriter<'a, E> {
    data: &'a mut [E],
    payload: usize,
    stride: usize,
}

impl<'a, E: Copy> RowMajorTraceWriter<'a, E> {
    /// Creates a writer whose physical row width equals the per-row payload.
    #[cfg(test)]
    pub(super) fn new(data: &'a mut [E], width: usize) -> Self {
        Self::with_stride(data, width, width)
    }

    /// Creates a writer that writes `payload` columns per row into a buffer with physical row
    /// width `stride` (`stride >= payload`).
    pub fn with_stride(data: &'a mut [E], payload: usize, stride: usize) -> Self {
        debug_assert!(stride >= payload, "stride must be >= payload");
        debug_assert_eq!(data.len() % stride, 0, "buffer length must be a multiple of stride");
        Self { data, payload, stride }
    }

    /// Checks the complete destination span before a clock-cycle transition is published.
    pub(crate) fn preflight_write_row(&self, row: usize) -> Result<(), ExecutionError> {
        let end = row
            .checked_mul(self.stride)
            .and_then(|start| start.checked_add(self.payload))
            .ok_or(ExecutionError::Internal("core trace writer row overflow"))?;
        if self.stride == 0 || self.payload > self.stride || end > self.data.len() {
            return Err(ExecutionError::Internal("core trace writer row is out of bounds"));
        }
        Ok(())
    }

    /// Writes one row's payload; `values.len()` must equal `payload`.
    #[inline(always)]
    pub fn write_row(&mut self, row: usize, values: &[E]) {
        debug_assert_eq!(values.len(), self.payload);
        let start = row * self.stride;
        self.data[start..start + self.payload].copy_from_slice(values);
    }
}

// TRACE FRAGMENT
// ================================================================================================

/// A writable, row-major view over one chiplet's region of the chiplets trace.
///
/// A chiplet occupies a contiguous band of rows and a contiguous band of columns
/// `[col_start, col_start + num_cols)`. [`Self::copy_rows_from`] also writes the per-row
/// `prefix_one_cols` selectors. Controller fragments additionally write their local one-based
/// address counter in the trailing `chip_clk` column.
pub struct ChipletTraceFragment<'a> {
    /// Contiguous `num_rows * stride` row-major slice (this chiplet's rows).
    band: &'a mut [Felt],
    stride: usize,
    col_start: usize,
    num_rows: usize,
    num_cols: usize,
    /// Only Controller owns the trailing address counter; other fragments leave it untouched.
    write_controller_counter: bool,
    /// Columns `< col_start` to set to ONE on every row in this band.
    prefix_one_cols: &'static [usize],
}

impl<'a> ChipletTraceFragment<'a> {
    /// Bare fragment with no prefix selectors or `chip_clk`. For chiplet-level unit tests.
    pub fn row_major(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
    ) -> Self {
        Self::new(band, stride, col_start, num_cols, false, &[])
    }

    /// Adds per-row ONEs at `prefix_one_cols`, using the layout's checked physical band.
    pub(crate) fn with_overheads(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
        physical_band: ChipletBand,
        prefix_one_cols: &'static [usize],
    ) -> Self {
        debug_assert_eq!(band.len() / stride, physical_band.len());
        Self::new(band, stride, col_start, num_cols, false, prefix_one_cols)
    }

    /// Writes Controller's local one-based address counter at column `stride - 1`. Its extent
    /// has been admitted by the layout; the physical prefix does not affect the counter.
    pub(crate) fn with_controller_counter(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
        controller_band: ChipletBand,
    ) -> Self {
        debug_assert_eq!(band.len() / stride, controller_band.len());
        debug_assert!(stride > col_start + num_cols, "Controller counter overlaps payload");
        Self::new(band, stride, col_start, num_cols, true, &[])
    }

    fn new(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
        write_controller_counter: bool,
        prefix_one_cols: &'static [usize],
    ) -> Self {
        debug_assert_eq!(band.len() % stride, 0, "band length must be a multiple of stride");
        debug_assert!(col_start + num_cols <= stride, "column band overruns the row stride");
        debug_assert!(
            prefix_one_cols.iter().all(|&c| c < col_start),
            "prefix_one_cols must lie before col_start",
        );
        let num_rows = band.len() / stride;
        Self {
            band,
            stride,
            col_start,
            num_rows,
            num_cols,
            write_controller_counter,
            prefix_one_cols,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this execution trace fragment.
    pub fn width(&self) -> usize {
        self.num_cols
    }

    /// Returns the number of rows in this execution trace fragment.
    pub fn len(&self) -> usize {
        self.num_rows
    }

    /// Mutable access to columns `[0..col_start)` of `row`, for chiplets whose prefix
    /// selectors vary per row (e.g. the hasher's `s_ctrl`).
    pub fn prefix_mut(&mut self, row: usize) -> &mut [Felt] {
        let row_start = row * self.stride;
        &mut self.band[row_start..row_start + self.col_start]
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Copies a chiplet's row-major buffer (`num_cols` cells per row) into this fragment's
    /// band, fusing the per-row prefix-selector ONEs and Controller counter when configured.
    pub fn copy_rows_from(&mut self, src: &[Felt]) {
        debug_assert_eq!(src.len(), self.num_rows * self.num_cols, "source buffer size mismatch");
        self.copy_rows_into(0, src);
    }

    /// Copies `src.len() / num_cols` rows starting at `row_offset` into this fragment's band,
    /// fusing the per-row prefix-selector ONEs and Controller counter when configured.
    pub fn copy_rows_into(&mut self, row_offset: usize, src: &[Felt]) {
        debug_assert_eq!(src.len() % self.num_cols, 0, "source buffer size not row-aligned");
        let chunk_rows = src.len() / self.num_cols;
        debug_assert!(
            row_offset + chunk_rows <= self.num_rows,
            "chunk overruns fragment row range",
        );
        let clk_col = self.stride - 1;
        for r in 0..chunk_rows {
            let dst_row = row_offset + r;
            let row_start = dst_row * self.stride;
            let row = &mut self.band[row_start..row_start + self.stride];
            for &col in self.prefix_one_cols {
                row[col] = ONE;
            }
            row[self.col_start..self.col_start + self.num_cols]
                .copy_from_slice(&src[r * self.num_cols..(r + 1) * self.num_cols]);
            if self.write_controller_counter {
                row[clk_col] = Felt::from_u32(dst_row as u32 + 1);
            }
        }
    }
}

// U32 HELPERS
// ================================================================================================

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_canonical_u64());
    (Felt::new_unchecked(hi as u64), Felt::new_unchecked(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}

// TEST HELPERS
// ================================================================================================

/// Builds a 17-op basic block payload that straddles a RESPAN batch boundary, plus the initial
/// values its `Push` ops emit. Consumed by decoder / hasher tests that exercise multi-batch
/// SPAN execution.
#[cfg(test)]
pub(super) fn build_span_with_respan_ops() -> (Vec<Operation>, Vec<Felt>) {
    let iv = [1, 3, 5, 7, 9, 11, 13, 15, 17].to_elements();
    let ops = alloc::vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Push(iv[5]),
        Operation::Push(iv[6]),
        // next batch
        Operation::Push(iv[7]),
        Operation::Push(iv[8]),
        Operation::Add,
        // drops to make sure stack overflow is empty on exit
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ];
    (ops, iv)
}

#[cfg(test)]
mod chiplet_fragment_tests {
    use miden_air_definitions::vm::trace::{CHIPLETS_CLK_COL, CHIPLETS_WIDTH};

    use super::*;
    use crate::{ZERO, trace::chiplets::layout::ChipletsLayout};

    #[test]
    fn only_controller_fragments_write_local_counters_across_chunks() {
        const W: usize = CHIPLETS_WIDTH;
        let layout = ChipletsLayout::new(16, 8, 8, 0, 0, 0).unwrap();
        let payload = [ONE; 4];
        let mut controller_rows = [ZERO; 8 * W];
        let mut fragment = ChipletTraceFragment::with_controller_counter(
            &mut controller_rows,
            W,
            3,
            1,
            layout.controller(),
        );
        fragment.copy_rows_into(4, &payload);
        fragment.copy_rows_into(0, &payload);
        for (index, row) in controller_rows.as_chunks::<W>().0.iter().enumerate() {
            assert_eq!(row[CHIPLETS_CLK_COL], Felt::from_u32(index as u32 + 1));
            assert_eq!(row[3], ONE);
        }

        let mut aead_rows = [ZERO; 8 * W];
        let mut fragment =
            ChipletTraceFragment::with_overheads(&mut aead_rows, W, 3, 1, layout.aead(), &[2]);
        fragment.copy_rows_into(0, &payload);
        fragment.copy_rows_into(4, &payload);
        for row in aead_rows.as_chunks::<W>().0 {
            assert_eq!(row[CHIPLETS_CLK_COL], ZERO);
            assert_eq!(row[2], ONE);
            assert_eq!(row[3], ONE);
        }
    }
}
