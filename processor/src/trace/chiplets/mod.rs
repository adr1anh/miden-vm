use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air_definitions::vm::trace::{
    CHIPLETS_CLK_COL, CHIPLETS_WIDTH,
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH,
        ace::ACE_CHIPLET_NUM_COLS,
        bitwise::TRACE_WIDTH as BITWISE_WIDTH,
        hasher::{HasherState, TRACE_WIDTH as HASHER_WIDTH},
        memory::TRACE_WIDTH as MEMORY_WIDTH,
    },
    eidos_compression::NUM_EIDOS_COMPRESSION_COLS,
};
use miden_core::{field::PrimeCharacteristicRing, mast::OpBatch, program::KernelDescriptor};

use crate::{
    ExecutionError, Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{ChipletTraceFragment, RowIndex, range::RangeChecker},
};

mod bitwise;
use bitwise::AEAD_STREAM_FRAGMENT_WIDTH;
pub(crate) use bitwise::{AEAD_STREAM_CYCLE_LEN, Bitwise};

const BITWISE_COL_START: usize = 2;
const BITWISE_FRAGMENT_WIDTH: usize = if BITWISE_WIDTH > AEAD_STREAM_FRAGMENT_WIDTH {
    BITWISE_WIDTH
} else {
    AEAD_STREAM_FRAGMENT_WIDTH
};
const _: () = assert!(BITWISE_COL_START + BITWISE_FRAGMENT_WIDTH == CHIPLETS_CLK_COL);

mod hasher;
pub(crate) use hasher::Hasher;
pub use hasher::{
    build_external_eidos_compression_traces, build_ordered_external_eidos_compression_traces,
};

pub(crate) mod layout;
use layout::{ChipletBand, ChipletsLayout};

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Library writing remains dormant until the coordinated packed cutover"
    )
)]
mod library;

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

mod kernel_rom;
pub(crate) use kernel_rom::KernelRom;

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

// CHIPLETS MODULE OF HASHER, BITWISE, MEMORY, ACE, AND KERNEL ROM CHIPLETS
// ================================================================================================

/// This module manages the VM's hasher, bitwise, memory, arithmetic circuit evaluation (ACE)
/// and kernel ROM chiplets and is responsible for building a final execution trace from their
/// stacked execution traces and chiplet selectors.
///
/// The module's trace can be thought of as 5 stacked segments in the following form.
///
/// The chiplet system uses `s_ctrl = column 0` to select the hasher controller.
/// Columns 1-4 (`s1..s4`) subdivide the remaining region. The final shared data column is
/// row-local: bitwise rows use it as normal/AEAD stream mode. Controller rows derive Merkle/
/// padding mode from their row-kind bits.
///
/// * Hasher segment: fills the first rows of the trace up to the hasher `trace_len`.
///   - column 0 (s_ctrl): ONE
///   - columns 1-19: hasher-controller overlay
///   - columns 20-21: operation-final marker and MRUPDATE id
///   - column 22: unused, padded with ZERO
///
/// * Bitwise segment: begins at the end of the hasher segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ZERO
///   - columns 2-14: execution trace of bitwise chiplet
///   - columns 15-21: unused columns padded with ZERO
///   - column 22: ZERO for normal bitwise rows
///
/// * Memory segment: begins at the end of the bitwise segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ONE
///   - column 2 (s2): ZERO
///   - columns 3-19: execution trace of memory chiplet
///   - column 20: unused, padded with ZERO
///   - columns 21-22: write helpers e0/e1
///
/// * ACE segment: begins at the end of the memory segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1-2 (s1, s2): ONE
///   - column 3 (s3): ZERO
///   - columns 4-19: execution trace of ACE chiplet
///   - column 20: unused, padded with ZERO
///   - column 21: operation-square helper z
///   - column 22: ZERO
///
/// * Kernel ROM segment: begins at the end of the ACE segment.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-3 (s1, s2, s3): ONE
///   - column 4 (s4): ZERO
///   - columns 5-9: execution trace of kernel ROM chiplet
///   - columns 10-21: unused columns padded with ZERO
///   - column 22: ZERO
///
/// * Padding segment: fills the rest of the trace.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-4 (s1..s4): ONE
///   - columns 5-22: ZERO
///
/// Column ranges are stable for existing chiplets: controller uses columns 1..20,
/// normal bitwise uses 2..15, memory uses 3..18, ACE uses 4..20, and kernel ROM
/// uses 5..10. AEAD stream rows reuse the bitwise region and use columns 2..21 as
/// payload, with column 22 as the AEAD stream selector.
#[derive(Debug)]
pub struct Chiplets {
    pub hasher: Hasher,
    pub bitwise: Bitwise,
    pub memory: Memory,
    pub ace: Ace,
    pub kernel_rom: KernelRom,
}

impl Chiplets {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new chiplet set instantiated with the provided kernel descriptor.
    pub fn new(kernel: KernelDescriptor) -> Self {
        Self {
            hasher: Hasher::default(),
            bitwise: Bitwise::default(),
            memory: Memory::default(),
            ace: Ace::default(),
            kernel_rom: KernelRom::new(kernel),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the chiplets trace length, including the mandatory padding row used by auxiliary
    /// connector columns that read the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hasher.trace_len()
            + self.bitwise.trace_len()
            + self.memory.trace_len()
            + self.ace.trace_len()
            + self.kernel_rom.trace_len()
            + 1
    }

    /// Returns the unpadded trace length of the standalone Eidos compression AIR.
    pub fn eidos_compression_trace_len(&self) -> usize {
        self.hasher.eidos_compression_trace_len()
    }

    /// Returns the index of the first row of `Bitwise` execution trace.
    pub fn bitwise_start(&self) -> RowIndex {
        self.hasher.trace_len().into()
    }

    /// Returns the index of the first row of the `Memory` execution trace.
    pub fn memory_start(&self) -> RowIndex {
        self.bitwise_start() + self.bitwise.trace_len()
    }

    /// Returns the index of the first row of `ACE` execution trace.
    pub fn ace_start(&self) -> RowIndex {
        self.memory_start() + self.memory.trace_len()
    }

    /// Returns the index of the first row of `KernelRom` execution trace.
    pub fn kernel_rom_start(&self) -> RowIndex {
        self.ace_start() + self.ace.trace_len()
    }

    /// Returns the index of the first row of the padding section of the execution trace.
    pub fn padding_start(&self) -> RowIndex {
        self.kernel_rom_start() + self.kernel_rom.trace_len()
    }

    // EXECUTION TRACE
    // --------------------------------------------------------------------------------------------

    /// Checks final physical placement once all buffered or streamed chiplets have converged.
    pub(crate) fn layout(&self, prefix_len: usize) -> Result<ChipletsLayout, ExecutionError> {
        ChipletsLayout::new(
            prefix_len,
            self.hasher.trace_len(),
            self.bitwise.trace_len(),
            self.memory.trace_len(),
            self.ace.trace_len(),
            self.kernel_rom.trace_len(),
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
        layout: ChipletsLayout,
        trace_len: usize,
        eidos_compression_trace_len: usize,
    ) -> Result<(ChipletsTrace, EidosCompressionTrace, Vec<u64>), ExecutionError> {
        let padding = layout.padding(trace_len)?;
        if self.hasher.trace_len() != layout.controller().len()
            || self.bitwise.trace_len() != layout.bitwise().len()
            || self.memory.trace_len() != layout.memory().len()
            || self.ace.trace_len() != layout.ace().len()
            || self.kernel_rom.trace_len() != layout.kernel_rom().len()
        {
            return Err(ExecutionError::Internal("Chiplets layout does not match its trace bands"));
        }
        if self.eidos_compression_trace_len() > eidos_compression_trace_len {
            return Err(ExecutionError::Internal(
                "target Eidos compression trace length too small",
            ));
        }

        let mut trace = Felt::zero_vec(CHIPLETS_WIDTH * trace_len);
        let mut eidos_compression_trace =
            Felt::zero_vec(NUM_EIDOS_COMPRESSION_COLS * eidos_compression_trace_len);
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

    /// Fills the provided trace for the chiplets module with the stacked execution traces of the
    /// Hasher, Bitwise, Memory, ACE, and kernel ROM chiplets along with selector columns
    /// to identify each individual chiplet trace in addition to padding to fill the rest of
    /// the trace.
    fn fill_trace(
        self,
        trace: &mut [Felt],
        layout: ChipletsLayout,
        padding: ChipletBand,
        eidos_compression_trace: &mut [Felt],
    ) -> Vec<u64> {
        const W: usize = CHIPLETS_WIDTH;
        debug_assert_eq!(trace.len(), W * (padding.start() + padding.len()));

        let Chiplets { hasher, bitwise, memory, ace, kernel_rom } = self;

        // Per-chiplet row counts. Chiplets are stacked vertically, so each one's region is a
        // contiguous band of rows: hasher [0, h), bitwise [h, h+b), and so on.
        debug_assert_eq!(hasher.trace_len(), layout.controller().len());
        debug_assert_eq!(bitwise.trace_len(), layout.bitwise().len());
        debug_assert_eq!(memory.trace_len(), layout.memory().len());
        debug_assert_eq!(ace.trace_len(), layout.ace().len());
        debug_assert_eq!(kernel_rom.trace_len(), layout.kernel_rom().len());

        // Chiplets are nested as hasher > bitwise > memory > ace > kernel_rom and begin at columns
        // 1, 2, 3, 4, 5. Each chiplet's `copy_rows_from` writes its prefix selector ONEs and
        // `chip_clk` along with its data; `s_ctrl` (col 0) is hasher-set per row, and
        // padding rows are filled directly below.

        // Carve `trace` into the per-chiplet contiguous row bands.
        let (_, rest) = trace.split_at_mut(layout.controller().start() * W);
        let (hasher_band, rest) = rest.split_at_mut(layout.controller().len() * W);
        let (bitwise_band, rest) = rest.split_at_mut(layout.bitwise().len() * W);
        let (memory_band, rest) = rest.split_at_mut(layout.memory().len() * W);
        let (ace_band, rest) = rest.split_at_mut(layout.ace().len() * W);
        let (kernel_band, padding_band) = rest.split_at_mut(layout.kernel_rom().len() * W);

        let mut hasher_fragment = ChipletTraceFragment::with_overheads(
            hasher_band,
            W,
            1,
            HASHER_WIDTH,
            layout.controller(),
            &[],
        );
        let mut bitwise_fragment = ChipletTraceFragment::with_overheads(
            bitwise_band,
            W,
            BITWISE_COL_START,
            BITWISE_FRAGMENT_WIDTH,
            layout.bitwise(),
            &[],
        );
        let mut kernel_rom_fragment = ChipletTraceFragment::with_overheads(
            kernel_band,
            W,
            5,
            KERNEL_ROM_TRACE_WIDTH,
            layout.kernel_rom(),
            &[1, 2, 3],
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
                *bitwise_and8_counts = bitwise.fill_trace(&mut bitwise_fragment);
            });
            s.spawn(move |_| {
                {
                    let mut memory_fragment = ChipletTraceFragment::with_overheads(
                        memory_band,
                        W,
                        3,
                        MEMORY_WIDTH,
                        layout.memory(),
                        &[1],
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
                        4,
                        ACE_CHIPLET_NUM_COLS,
                        layout.ace(),
                        &[1, 2],
                    );
                    ace.fill_trace(&mut ace_fragment);
                }
                for row in ace_band.as_chunks_mut::<W>().0 {
                    Ace::fill_row_helpers(row.as_mut_slice().borrow_mut());
                }
            });
            s.spawn(move |_| {
                kernel_rom.fill_trace(&mut kernel_rom_fragment);
            });
            s.spawn(move |_| {
                fill_padding_rows(padding_band, padding);
            });
        });

        for (count, bitwise_count) in and8_counts.iter_mut().zip(bitwise_and8_counts) {
            *count += bitwise_count;
        }

        and8_counts
    }
}

/// Fills padding rows after the kernel ROM region: cols 1..=4 = ONE, chip_clk = row + 1.
fn fill_padding_rows(band: &mut [Felt], physical_band: ChipletBand) {
    const W: usize = CHIPLETS_WIDTH;
    let (rows, _) = band.as_chunks_mut::<W>();
    for (i, row) in rows.iter_mut().enumerate() {
        row[1] = ONE;
        row[2] = ONE;
        row[3] = ONE;
        row[4] = ONE;
        row[W - 1] = physical_band.clock_at(i);
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
    fn completes_helpers_only_in_materialized_memory_and_ace_bands() {
        const PREFIX_ROWS: usize = 3;
        const W: usize = CHIPLETS_WIDTH;
        let sentinel = Felt::from_u32(99);

        for (include_memory, include_ace) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let mut chiplets = Chiplets::new(KernelDescriptor::default());
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
            for band in [layout.memory(), layout.ace()] {
                for row in
                    trace[band.start() * W..(band.start() + band.len()) * W].as_chunks_mut::<W>().0
                {
                    row[20] = sentinel;
                }
            }
            let mut compression_trace =
                Felt::zero_vec(chiplets.eidos_compression_trace_len() * NUM_EIDOS_COMPRESSION_COLS);
            let _ = chiplets.fill_trace(&mut trace, layout, padding, &mut compression_trace);

            assert!(trace[..PREFIX_ROWS * W].iter().all(|&cell| cell == sentinel));
            for (index, row) in trace.as_chunks::<W>().0.iter().enumerate().skip(PREFIX_ROWS) {
                assert_eq!(row[CHIPLETS_CLK_COL], Felt::from_u32(index as u32 + 1));
            }
            for index in 0..AEAD_STREAM_CYCLE_LEN {
                let start = (layout.bitwise().start() + index) * W;
                assert_eq!(trace[start + 22], ONE, "AEAD mode must retain its shared cell");
            }
            let normal_bitwise = (layout.bitwise().start() + AEAD_STREAM_CYCLE_LEN) * W;
            assert_eq!(trace[normal_bitwise + 22], ZERO);

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
                assert_eq!(&row[..3], &[ZERO, ONE, ZERO]);
                assert_eq!(row[20], sentinel);
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
                assert_eq!(&row[..4], &[ZERO, ONE, ONE, ZERO]);
                assert_eq!(&row[4..20], payload.as_slice());
                assert_eq!(row[20], sentinel);
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
