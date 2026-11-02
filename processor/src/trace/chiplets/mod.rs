use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air_definitions::vm::trace::{
    CHIPLETS_CLK_COL, CHIPLETS_WIDTH,
    chiplets::{
        NUM_ACE_SELECTORS, NUM_AEAD_SELECTORS, NUM_BITWISE_SELECTORS, NUM_CONTROLLER_SELECTORS,
        NUM_MEMORY_SELECTORS,
        ace::ACE_CHIPLET_NUM_COLS,
        bitwise::TRACE_WIDTH as BITWISE_WIDTH,
        hasher::{HasherState, TRACE_WIDTH as HASHER_WIDTH},
        memory::TRACE_WIDTH as MEMORY_WIDTH,
    },
    eidos_compression::NUM_EIDOS_COMPRESSION_COLS,
};
use miden_core::{field::PrimeCharacteristicRing, mast::OpBatch};

use crate::{
    ExecutionError, Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{ChipletTraceFragment, range::RangeChecker},
};

mod bitwise;
use bitwise::AEAD_STREAM_FRAGMENT_WIDTH;
pub(crate) use bitwise::{AEAD_STREAM_CYCLE_LEN, Bitwise};

const CONTROLLER_COL_START: usize = NUM_CONTROLLER_SELECTORS;
const AEAD_COL_START: usize = NUM_AEAD_SELECTORS;
const MEMORY_COL_START: usize = NUM_MEMORY_SELECTORS;
const ACE_COL_START: usize = NUM_ACE_SELECTORS;
const BITWISE_COL_START: usize = NUM_BITWISE_SELECTORS;
const _: () = assert!(CONTROLLER_COL_START + HASHER_WIDTH == CHIPLETS_CLK_COL);
const _: () = assert!(AEAD_COL_START + AEAD_STREAM_FRAGMENT_WIDTH == CHIPLETS_CLK_COL);
const _: () = assert!(MEMORY_COL_START + MEMORY_WIDTH == 21);
const _: () = assert!(ACE_COL_START + ACE_CHIPLET_NUM_COLS == 21);
const _: () = assert!(BITWISE_COL_START + BITWISE_WIDTH == 19);

mod hasher;
pub(crate) use hasher::Hasher;
pub use hasher::{
    build_external_eidos_compression_traces, build_ordered_external_eidos_compression_traces,
};

pub(crate) mod layout;
use layout::{ChipletBand, ChipletsLayout};

mod library;
pub(crate) use library::LibraryTrace;

pub(crate) fn build_and8_lookup_trace(and8_counts: &[u64]) -> Vec<Felt> {
    hasher::build_and8_lookup_trace(and8_counts)
}

mod memory;
pub(crate) use memory::Memory;

mod ace;
pub use ace::{
    Ace, CircuitEvaluation, MAX_EVAL_CIRCUIT_INVOCATIONS, MAX_EVAL_CIRCUIT_WIRES,
    MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD,
};

#[cfg(test)]
mod tests;

// TRACE
// ================================================================================================

pub struct ChipletsTrace {
    pub(crate) trace: Vec<Felt>,
}

pub struct EidosCompressionTrace {
    pub(crate) trace: Vec<Felt>,
}

// PACKED CHIPLETS
// ================================================================================================

/// Records row-family payloads before their final checked placement. Library rows are borrowed
/// from the immutable completed resolution session when this trace is materialized.
///
/// Physical order is Library, Controller, AEAD, Memory, ACE, normal Bitwise, then global PAD.
/// Each family owns only its packed selector prefix and payload; c[23] is the shared row clock.
#[derive(Debug, Default)]
pub struct Chiplets {
    pub hasher: Hasher,
    pub bitwise: Bitwise,
    pub memory: Memory,
    pub ace: Ace,
}

impl Chiplets {
    /// Returns the non-Library row count, including the mandatory global padding row.
    pub fn trace_len(&self) -> usize {
        self.hasher.trace_len()
            + self.bitwise.trace_len()
            + self.memory.trace_len()
            + self.ace.trace_len()
            + 1
    }

    /// Returns the unpadded trace length of the standalone Eidos compression AIR.
    pub fn eidos_compression_trace_len(&self) -> usize {
        self.hasher.eidos_compression_trace_len()
    }

    // EXECUTION TRACE
    // --------------------------------------------------------------------------------------------

    /// Checks final physical placement once all buffered or streamed chiplets have converged.
    pub(crate) fn layout(&self, prefix_len: usize) -> Result<ChipletsLayout, ExecutionError> {
        ChipletsLayout::new(
            prefix_len,
            self.hasher.trace_len(),
            self.bitwise.aead_trace_len(),
            self.memory.trace_len(),
            self.ace.trace_len(),
            self.bitwise.normal_trace_len(),
        )
    }

    /// Adds all range checks required by the memory chiplet to the provided `RangeChecker`
    /// instance.
    pub fn append_range_checks(&self, range_checker: &mut RangeChecker) {
        self.memory.append_range_checks(range_checker);
    }

    /// Adds range checks emitted by the standalone Eidos compression AIR.
    pub fn append_eidos_compression_range_checks(
        &self,
        eidos_compression_height: usize,
        range_checker: &mut RangeChecker,
    ) {
        self.hasher
            .append_eidos_compression_range_checks(eidos_compression_height, range_checker);
    }

    /// Returns execution traces for `ChipletsAir` and `EidosCompressionAir`.
    pub(crate) fn into_traces(
        self,
        library: &LibraryTrace<'_>,
        layout: ChipletsLayout,
        trace_len: usize,
        eidos_compression_trace_len: usize,
    ) -> Result<(ChipletsTrace, EidosCompressionTrace, Vec<u64>), ExecutionError> {
        let padding = layout.padding(trace_len)?;
        if library.prefix_len() != layout.library().len()
            || self.hasher.trace_len() != layout.controller().len()
            || self.bitwise.aead_trace_len() != layout.aead().len()
            || self.bitwise.normal_trace_len() != layout.bitwise().len()
            || self.memory.trace_len() != layout.memory().len()
            || self.ace.trace_len() != layout.ace().len()
        {
            return Err(ExecutionError::Internal("Chiplets layout does not match its trace bands"));
        }
        if self.eidos_compression_trace_len() > eidos_compression_trace_len {
            return Err(ExecutionError::Internal(
                "target Eidos compression trace length too small",
            ));
        }

        let chiplet_cells = checked_trace_cells(CHIPLETS_WIDTH, trace_len)?;
        let eidos_cells =
            checked_trace_cells(NUM_EIDOS_COMPRESSION_COLS, eidos_compression_trace_len)?;
        let mut trace = Felt::zero_vec(chiplet_cells);
        library.write(&mut trace[..library.prefix_cells()])?;
        let mut eidos_compression_trace = Felt::zero_vec(eidos_cells);
        let and8_counts =
            self.fill_trace(&mut trace, layout, padding, &mut eidos_compression_trace);

        Ok((
            ChipletsTrace { trace },
            EidosCompressionTrace { trace: eidos_compression_trace },
            and8_counts,
        ))
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Writes only the already admitted non-Library bands. The Library writer owns its exact
    /// final prefix, and compression requests have already been registered before admission.
    fn fill_trace(
        self,
        trace: &mut [Felt],
        layout: ChipletsLayout,
        padding: ChipletBand,
        eidos_compression_trace: &mut [Felt],
    ) -> Vec<u64> {
        const W: usize = CHIPLETS_WIDTH;
        debug_assert_eq!(trace.len(), W * (padding.start() + padding.len()));
        let Chiplets { hasher, bitwise, memory, ace } = self;
        debug_assert_eq!(hasher.trace_len(), layout.controller().len());
        debug_assert_eq!(bitwise.aead_trace_len(), layout.aead().len());
        debug_assert_eq!(bitwise.normal_trace_len(), layout.bitwise().len());
        debug_assert_eq!(memory.trace_len(), layout.memory().len());
        debug_assert_eq!(ace.trace_len(), layout.ace().len());

        let (_, rest) = trace.split_at_mut(layout.controller().start() * W);
        let (hasher_band, rest) = rest.split_at_mut(layout.controller().len() * W);
        let (aead_band, rest) = rest.split_at_mut(layout.aead().len() * W);
        let (memory_band, rest) = rest.split_at_mut(layout.memory().len() * W);
        let (ace_band, rest) = rest.split_at_mut(layout.ace().len() * W);
        let (bitwise_band, padding_band) = rest.split_at_mut(layout.bitwise().len() * W);

        let mut hasher_fragment = ChipletTraceFragment::with_overheads(
            hasher_band,
            W,
            CONTROLLER_COL_START,
            HASHER_WIDTH,
            layout.controller(),
            &[],
        );
        let mut aead_fragment = ChipletTraceFragment::with_overheads(
            aead_band,
            W,
            AEAD_COL_START,
            AEAD_STREAM_FRAGMENT_WIDTH,
            layout.aead(),
            &[2],
        );
        let mut bitwise_fragment = ChipletTraceFragment::with_overheads(
            bitwise_band,
            W,
            BITWISE_COL_START,
            BITWISE_WIDTH,
            layout.bitwise(),
            &[3, 4],
        );
        let mut and8_counts = Vec::new();
        let mut bitwise_and8_counts = Vec::new();
        rayon::scope(|s| {
            let and8_counts = &mut and8_counts;
            s.spawn(move |_| {
                *and8_counts = hasher.fill_trace(&mut hasher_fragment, eidos_compression_trace);
            });
            let bitwise_and8_counts = &mut bitwise_and8_counts;
            s.spawn(move |_| {
                *bitwise_and8_counts =
                    bitwise.fill_trace(&mut aead_fragment, &mut bitwise_fragment);
            });
            s.spawn(move |_| {
                {
                    let mut memory_fragment = ChipletTraceFragment::with_overheads(
                        memory_band,
                        W,
                        MEMORY_COL_START,
                        MEMORY_WIDTH,
                        layout.memory(),
                        &[],
                    );
                    memory.fill_trace(&mut memory_fragment);
                }
                for row in memory_band.as_chunks_mut::<W>().0 {
                    Memory::fill_row_helpers(row.as_mut_slice().borrow_mut());
                }
            });
            s.spawn(move |_| {
                {
                    let mut ace_fragment = ChipletTraceFragment::with_overheads(
                        ace_band,
                        W,
                        ACE_COL_START,
                        ACE_CHIPLET_NUM_COLS,
                        layout.ace(),
                        &[3],
                    );
                    ace.fill_trace(&mut ace_fragment);
                }
                for row in ace_band.as_chunks_mut::<W>().0 {
                    Ace::fill_row_helpers(row.as_mut_slice().borrow_mut());
                }
            });
            s.spawn(move |_| fill_padding_rows(padding_band, padding));
        });
        debug_assert_eq!(and8_counts.len(), bitwise_and8_counts.len());
        for (count, bitwise_count) in and8_counts.iter_mut().zip(bitwise_and8_counts) {
            *count += bitwise_count;
        }
        and8_counts
    }
}

/// Checks both height and backing-storage representation before either final matrix is allocated.
fn checked_trace_cells(width: usize, height: usize) -> Result<usize, ExecutionError> {
    let overflow = || ExecutionError::TraceLenExceeded(crate::trace::limits::MAX_TRACE_LEN);
    if height > crate::trace::limits::MAX_TRACE_LEN {
        return Err(overflow());
    }
    let cells = width.checked_mul(height).ok_or_else(overflow)?;
    core::alloc::Layout::array::<Felt>(cells).map_err(|_| overflow())?;
    Ok(cells)
}

/// Global PAD owns c[3..6] = ONE and the shared physical clock.
fn fill_padding_rows(band: &mut [Felt], physical_band: ChipletBand) {
    const W: usize = CHIPLETS_WIDTH;
    for (i, row) in band.as_chunks_mut::<W>().0.iter_mut().enumerate() {
        row[3..6].fill(ONE);
        row[CHIPLETS_CLK_COL] = physical_band.clock_at(i);
    }
}

#[cfg(test)]
mod helper_integration_tests {
    use core::borrow::Borrow;

    use miden_ace::instruction::{Op, encode_instruction};
    use miden_air_definitions::vm::ChipletCols;

    use super::*;
    use crate::ContextId;

    #[test]
    fn final_matrix_storage_rejects_oversized_heights_and_cell_counts_before_allocation() {
        let cap = crate::trace::limits::MAX_TRACE_LEN;
        for result in [
            checked_trace_cells(CHIPLETS_WIDTH, cap + 1),
            checked_trace_cells(NUM_EIDOS_COMPRESSION_COLS, cap + 1),
            checked_trace_cells(usize::MAX, 2),
            checked_trace_cells(usize::MAX, 1),
        ] {
            assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(limit)) if limit == cap));
        }
        assert_eq!(checked_trace_cells(CHIPLETS_WIDTH, 8).unwrap(), CHIPLETS_WIDTH * 8);
    }

    #[test]
    fn completes_helpers_only_in_materialized_memory_and_ace_bands() {
        const PREFIX_ROWS: usize = 16;
        const W: usize = CHIPLETS_WIDTH;
        let sentinel = Felt::from_u32(99);

        for (include_memory, include_ace) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let mut chiplets = Chiplets::default();
            chiplets
                .bitwise
                .aead_stream(
                    ZERO,
                    ONE,
                    ZERO,
                    Felt::from_u32(4),
                    ZERO,
                    [ZERO; 4],
                    [ONE; 8],
                    [ONE; 8],
                )
                .unwrap();
            chiplets.bitwise.u32xor(Felt::from_u32(5), Felt::from_u32(6)).unwrap();

            if include_memory {
                for index in 0..4_u32 {
                    chiplets
                        .memory
                        .write(
                            ContextId::root(),
                            Felt::from_u32(index),
                            (index + 1).into(),
                            Felt::from_u32(index + 11),
                        )
                        .unwrap();
                }
                chiplets.memory.read_word(ContextId::root(), ZERO, 5.into()).unwrap();
                chiplets
                    .memory
                    .write_word(
                        ContextId::root(),
                        ZERO,
                        6.into(),
                        [21, 22, 23, 24].map(Felt::from_u32).into(),
                    )
                    .unwrap();
                chiplets.memory.read(ContextId::root(), Felt::from_u32(2), 7.into()).unwrap();
            }

            let mut ace_payload = Vec::new();
            if include_ace {
                let clk = 11.into();
                let mut evaluation = CircuitEvaluation::new(ContextId::root(), clk, 1, 3);
                evaluation.do_read(Felt::from_u32(100), [2, 1, 3, 1].map(Felt::from_u32).into());
                for (ptr, left, right, op) in
                    [(104, 4, 3, Op::Add), (105, 2, 4, Op::Mul), (106, 1, 1, Op::Sub)]
                {
                    evaluation
                        .do_eval(Felt::from_u32(ptr), encode_instruction(left, right, op).unwrap())
                        .unwrap();
                }
                ace_payload = Felt::zero_vec(evaluation.num_rows() * ACE_CHIPLET_NUM_COLS);
                evaluation.fill(0, &mut ace_payload);
                chiplets.ace.add_circuit_evaluation(clk, evaluation);
            }

            let layout = chiplets.layout(PREFIX_ROWS).unwrap();
            let trace_len = PREFIX_ROWS + chiplets.trace_len() + 1;
            let padding = layout.padding(trace_len).unwrap();
            let mut trace = Felt::zero_vec(trace_len * W);
            trace[..PREFIX_ROWS * W].fill(sentinel);
            let mut compression_trace =
                Felt::zero_vec(chiplets.eidos_compression_trace_len() * NUM_EIDOS_COMPRESSION_COLS);
            let _ = chiplets.fill_trace(&mut trace, layout, padding, &mut compression_trace);

            assert!(trace[..PREFIX_ROWS * W].iter().all(|&cell| cell == sentinel));
            for (index, row) in trace.as_chunks::<W>().0.iter().enumerate().skip(PREFIX_ROWS) {
                assert_eq!(row[CHIPLETS_CLK_COL], Felt::from_u32(index as u32 + 1));
            }
            for index in 0..AEAD_STREAM_CYCLE_LEN {
                let start = (layout.aead().start() + index) * W;
                assert_eq!(&trace[start..start + 3], &[ZERO, ZERO, ONE]);
            }
            let normal_bitwise = layout.bitwise().start() * W;
            assert_eq!(
                &trace[normal_bitwise..normal_bitwise + 6],
                &[ZERO, ZERO, ZERO, ONE, ONE, ZERO]
            );

            let memory = layout.memory();
            let memory_rows = trace[memory.start() * W..(memory.start() + memory.len()) * W]
                .as_chunks::<W>()
                .0;
            let expected_helpers = [
                [ONE, ZERO],
                [ZERO, ONE],
                [ONE, ZERO],
                [ZERO, ONE],
                [ZERO, ZERO],
                [ZERO, ZERO],
                [ZERO, ZERO],
            ];
            let expected_values = [
                [11, 0, 0, 0],
                [11, 12, 0, 0],
                [11, 12, 13, 0],
                [11, 12, 13, 14],
                [11, 12, 13, 14],
                [21, 22, 23, 24],
                [21, 22, 23, 24],
            ];
            assert_eq!(memory_rows.len(), if include_memory { 7 } else { 0 });
            for (index, row) in memory_rows.iter().enumerate() {
                let cols: &ChipletCols<Felt> = row.as_slice().borrow();
                assert_eq!(&row[..4], &[ZERO, ZERO, ZERO, ZERO]);
                assert_eq!(cols.memory_write_helpers(), expected_helpers[index]);
                assert_eq!(cols.memory().values, expected_values[index].map(Felt::from_u32));
                assert_eq!(cols.memory().clk, Felt::from_u32(index as u32 + 1));
                assert_eq!(cols.memory_word_addr_lo(), ZERO);
                assert_eq!(cols.memory_word_addr_hi(), ZERO);
            }

            let ace = layout.ace();
            let ace_rows = trace[ace.start() * W..(ace.start() + ace.len()) * W].as_chunks::<W>().0;
            assert_eq!(ace_rows.len(), if include_ace { 4 } else { 0 });
            for ((index, row), payload) in ace_rows
                .iter()
                .enumerate()
                .zip(ace_payload.as_chunks::<ACE_CHIPLET_NUM_COLS>().0)
            {
                let cols: &ChipletCols<Felt> = row.as_slice().borrow();
                assert_eq!(&row[..5], &[ZERO, ZERO, ZERO, ONE, ZERO]);
                assert_eq!(&row[5..21], payload.as_slice());
                assert_eq!(row[22], ZERO);
                assert_eq!(cols.ace_op_squared(), [ZERO, ONE, ZERO, ONE][index]);
            }
        }
    }
}

// HELPER STRUCTS
// ================================================================================================

/// Result of a Merkle tree node update.
///
/// Contains the old root, the new root, and the trace row where the computation started.
#[derive(Debug, Copy, Clone)]
pub struct MerkleRootUpdate {
    address: Felt,
    old_root: Word,
    new_root: Word,
}

impl MerkleRootUpdate {
    pub fn get_address(&self) -> Felt {
        self.address
    }
    pub fn get_old_root(&self) -> Word {
        self.old_root
    }
    pub fn get_new_root(&self) -> Word {
        self.new_root
    }
}
