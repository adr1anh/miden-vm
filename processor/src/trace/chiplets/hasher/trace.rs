use alloc::vec::Vec;
use core::{borrow::BorrowMut, ops::Range};

use miden_air_definitions::vm::{
    ControllerCols,
    trace::chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, PADDING, TRACE_WIDTH},
};
use miden_core::chiplets::eidos_compression;

use super::{
    ChipletTraceFragment, Felt, HasherState, MP_VERIFY, MR_UPDATE_NEW, MR_UPDATE_OLD, ONE,
    STATE_WIDTH, Selectors, ZERO,
};
use crate::{ExecutionError, trace::chiplets::layout::ControllerRow};

const _: () =
    assert!(crate::trace::parallel::MAX_TRACE_LEN.is_multiple_of(CONTROLLER_TRACE_ALIGNMENT));

// HASHER OPERATION
// ================================================================================================

/// A logical operation appended to the hasher trace.
#[derive(Debug, Clone)]
enum HasherOp {
    /// A single controller row.
    Controller {
        selectors: Selectors,
        state: HasherState,
        row_data: [Felt; 4],
        op_final: Felt,
        mrupdate_id: Felt,
    },
    /// Padding rows filling the controller region to the chiplet alignment boundary.
    Padding { count: usize, mrupdate_id: Felt },
}

impl HasherOp {
    /// Number of controller rows this op contributes when materialized.
    fn row_count(&self) -> usize {
        match self {
            Self::Controller { .. } => 1,
            Self::Padding { count, .. } => *count,
        }
    }
}

// HASHER TRACE
// ================================================================================================

/// Execution trace for hasher controller rows.
///
/// Each controller row writes 21 fragment cells:
/// - 3 row-kind selectors.
/// - 12 state cells.
/// - 4 row-kind data cells.
/// - 1 final-row marker.
/// - 1 carried MRUPDATE id.
#[derive(Debug, Default)]
pub(super) struct HasherTrace {
    ops: Vec<HasherOp>,
    /// Always at most MAX_TRACE_LEN: appends/replay check the entire span, and alignment
    /// rounding stays within the cap because the cap is itself aligned.
    row_count: usize,
}

impl HasherTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current controller trace length.
    pub(super) fn trace_len(&self) -> usize {
        self.row_count
    }

    /// Returns the next row address. Row addresses start at ONE.
    pub fn next_row_addr(&self) -> Result<Felt, ExecutionError> {
        Ok(ControllerRow::new(self.row_count)?.logical_address().to_felt())
    }

    /// Checks a whole request before any rows or compression requests are appended.
    pub(super) fn check_rows(&self, count: usize) -> Result<(), ExecutionError> {
        ControllerRow::new(self.row_count)?.checked_advance(count)?;
        Ok(())
    }

    /// Returns the index that the next op pushed will occupy.
    pub fn next_op_index(&self) -> usize {
        self.ops.len()
    }

    // CONTROLLER ROW METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a single controller row to the logical op log.
    pub(super) fn append_controller_row(
        &mut self,
        selectors: Selectors,
        state: &HasherState,
        row_data: [Felt; 4],
        op_final: Felt,
        mrupdate_id: Felt,
    ) -> Result<(), ExecutionError> {
        let end = ControllerRow::new(self.row_count)?.checked_advance(1)?;
        self.ops.push(HasherOp::Controller {
            selectors,
            state: *state,
            row_data,
            op_final,
            mrupdate_id,
        });
        self.row_count = end.position();
        Ok(())
    }

    // CONTROLLER PADDING
    // --------------------------------------------------------------------------------------------

    /// Appends padding rows to fill the controller region to `CONTROLLER_TRACE_ALIGNMENT`.
    pub fn pad_to_controller_boundary(&mut self, mrupdate_id: Felt) {
        let remainder = self.row_count % CONTROLLER_TRACE_ALIGNMENT;
        if remainder != 0 {
            let count = CONTROLLER_TRACE_ALIGNMENT - remainder;
            self.ops.push(HasherOp::Padding { count, mrupdate_id });
            // MAX_TRACE_LEN is a multiple of the controller alignment, so rounding an
            // already checked row count cannot exceed the cap or overflow usize.
            self.row_count = self.row_count.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT);
        }
    }

    // MEMOIZATION SUPPORT
    // --------------------------------------------------------------------------------------------

    /// Re-pushes the ops in `range` with `new_mrupdate_id` substituted.
    ///
    /// Returns the post-compression state and every copied compression input state.
    pub fn replay_ops_range(
        &mut self,
        range: Range<usize>,
        new_mrupdate_id: Felt,
    ) -> Result<(HasherState, Vec<HasherState>), ExecutionError> {
        let mut end = ControllerRow::new(self.row_count)?;
        for op in &self.ops[range.clone()] {
            end = end.checked_advance(op.row_count())?;
        }
        let mut last_state = [ZERO; STATE_WIDTH];
        let mut input_states = Vec::with_capacity(range.len() / 2);
        for idx in range {
            let mut op = self.ops[idx].clone();
            match &mut op {
                HasherOp::Controller {
                    mrupdate_id, selectors, state, row_data, ..
                } => {
                    *mrupdate_id = new_mrupdate_id;
                    if *selectors != PADDING {
                        input_states.push(input_state_from_row(*selectors, state));
                        last_state = output_state_from_row(*selectors, state, row_data);
                    }
                },
                HasherOp::Padding { mrupdate_id, .. } => {
                    *mrupdate_id = new_mrupdate_id;
                },
            }
            self.ops.push(op);
        }
        self.row_count = end.position();
        Ok((last_state, input_states))
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment by materializing the op log row by row.
    pub(super) fn fill_trace(self, trace: &mut ChipletTraceFragment) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert!(trace.width() >= TRACE_WIDTH, "inconsistent trace widths");

        let row_width = trace.width();
        let mut chunk = vec![ZERO; row_width * CONTROLLER_TRACE_ALIGNMENT];

        let mut row_idx = 0usize;
        for op in &self.ops {
            let n = op.row_count();
            debug_assert!(n <= CONTROLLER_TRACE_ALIGNMENT);
            match op {
                HasherOp::Controller {
                    selectors,
                    state,
                    row_data,
                    op_final,
                    mrupdate_id,
                } => {
                    write_controller_row(
                        &mut chunk[..row_width],
                        *selectors,
                        state,
                        *row_data,
                        *op_final,
                        *mrupdate_id,
                    );
                },
                HasherOp::Padding { count, mrupdate_id } => {
                    for row in chunk.chunks_mut(row_width).take(*count) {
                        write_controller_row(
                            row,
                            PADDING,
                            &[ZERO; STATE_WIDTH],
                            [ZERO; 4],
                            ZERO,
                            *mrupdate_id,
                        );
                    }
                },
            }

            trace.copy_rows_into(row_idx, &chunk[..n * row_width]);

            // Write packed `C = ONE` at c[1], leaving the Library selector c[0] zero.
            for i in 0..n {
                let prefix = trace.prefix_mut(row_idx + i);
                if let Some(s_ctrl) = prefix.get_mut(1) {
                    *s_ctrl = ONE;
                }
            }

            row_idx += n;
        }
        debug_assert_eq!(row_idx, self.row_count);
    }
}

// CONTROLLER ROW WRITERS
// ================================================================================================

fn write_controller_row(
    row: &mut [Felt],
    selectors: Selectors,
    state: &HasherState,
    row_data: [Felt; 4],
    op_final: Felt,
    mrupdate_id: Felt,
) {
    row.fill(ZERO);

    let cols: &mut ControllerCols<Felt> = row[..CONTROLLER_OVERLAY_WIDTH].borrow_mut();
    cols.s0 = selectors[0];
    cols.s1 = selectors[1];
    cols.s2 = selectors[2];
    cols.state = *state;
    cols.row_data = row_data;
    row[OP_FINAL_OFFSET] = op_final;
    row[MRUPDATE_ID_OFFSET] = mrupdate_id;
}

const CONTROLLER_OVERLAY_WIDTH: usize = 19;
const OP_FINAL_OFFSET: usize = 19;
const MRUPDATE_ID_OFFSET: usize = 20;

fn is_merkle_selector(selectors: Selectors) -> bool {
    selectors == MP_VERIFY || selectors == MR_UPDATE_OLD || selectors == MR_UPDATE_NEW
}

fn input_state_from_row(selectors: Selectors, state: &HasherState) -> HasherState {
    let mut input = *state;
    if is_merkle_selector(selectors) {
        let cv = eidos_compression::merkle_node_chaining_word();
        input[8..12].copy_from_slice(cv.as_elements());
    }
    input
}

fn output_state_from_row(
    selectors: Selectors,
    state: &HasherState,
    row_data: &[Felt; 4],
) -> HasherState {
    let mut output = [ZERO; STATE_WIDTH];
    if is_merkle_selector(selectors) {
        let cv = eidos_compression::merkle_node_chaining_word();
        output[..4].copy_from_slice(cv.as_elements());
        output[8..12].copy_from_slice(&state[8..12]);
    } else {
        output[..4].copy_from_slice(&state[8..12]);
        output[8..12].copy_from_slice(row_data);
    }
    output
}

#[cfg(test)]
mod tests {
    use miden_core::{mast::BasicBlockNodeBuilder, operations::Operation};

    use super::{super::Hasher, *};
    use crate::trace::parallel::MAX_TRACE_LEN;

    fn controller_op() -> HasherOp {
        HasherOp::Controller {
            selectors: super::super::LINEAR_HASH,
            state: [ZERO; STATE_WIDTH],
            row_data: [ZERO; 4],
            op_final: ONE,
            mrupdate_id: ZERO,
        }
    }

    fn assert_limit<T>(result: Result<T, ExecutionError>) {
        assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))));
    }

    #[test]
    fn controller_rows_fit_reduced_width_and_clear_unused_fragment_cells() {
        let selectors = [
            super::super::LINEAR_HASH,
            super::super::HASH_ABSORB,
            MP_VERIFY,
            MR_UPDATE_OLD,
            MR_UPDATE_NEW,
        ];
        for width in [TRACE_WIDTH, TRACE_WIDTH + 2] {
            let mut trace = HasherTrace::default();
            for selector in selectors {
                trace
                    .append_controller_row(selector, &[ONE; STATE_WIDTH], [ONE; 4], ONE, ONE)
                    .unwrap();
            }
            trace.pad_to_controller_boundary(ONE);
            assert_eq!(trace.trace_len(), CONTROLLER_TRACE_ALIGNMENT);

            let mut rows = vec![ONE; width * trace.trace_len()];
            let mut fragment = ChipletTraceFragment::row_major(&mut rows, width, 0, width);
            trace.fill_trace(&mut fragment);

            for (index, row) in rows.chunks(width).enumerate() {
                let expected_selector = selectors.get(index).copied().unwrap_or(PADDING);
                assert_eq!(&row[..3], &expected_selector);
                let expected_payload = if index < selectors.len() { ONE } else { ZERO };
                assert!(row[3..OP_FINAL_OFFSET].iter().all(|&value| value == expected_payload));
                assert_eq!(row[OP_FINAL_OFFSET], expected_payload);
                assert_eq!(row[MRUPDATE_ID_OFFSET], ONE);
                assert!(row[TRACE_WIDTH..].iter().all(|&value| value == ZERO));
            }
        }
    }

    #[test]
    fn append_accepts_exact_cap_then_rejects_atomically() {
        // A synthetic count exercises the cap without allocating a cap-sized trace.
        let mut trace = HasherTrace {
            row_count: MAX_TRACE_LEN - 1,
            ..Default::default()
        };
        trace
            .append_controller_row(
                super::super::LINEAR_HASH,
                &[ZERO; STATE_WIDTH],
                [ZERO; 4],
                ONE,
                ZERO,
            )
            .unwrap();
        assert_eq!(trace.trace_len(), MAX_TRACE_LEN);
        assert_eq!(trace.next_row_addr().unwrap(), Felt::from_u32(MAX_TRACE_LEN as u32 + 1));
        assert_limit(trace.append_controller_row(
            super::super::LINEAR_HASH,
            &[ZERO; STATE_WIDTH],
            [ZERO; 4],
            ONE,
            ZERO,
        ));
        assert_eq!(trace.next_op_index(), 1);
        assert_eq!(trace.trace_len(), MAX_TRACE_LEN);
        trace.pad_to_controller_boundary(ZERO);
        assert_eq!(trace.next_op_index(), 1);
    }

    #[test]
    fn replay_counts_rows_instead_of_operation_indices() {
        let mut trace = HasherTrace {
            ops: vec![controller_op(), HasherOp::Padding { count: 7, mrupdate_id: ZERO }],
            row_count: MAX_TRACE_LEN - 8,
        };
        let (_, inputs) = trace.replay_ops_range(0..2, ONE).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(trace.trace_len(), MAX_TRACE_LEN);
        assert_eq!(trace.next_op_index(), 4);
        match (&trace.ops[1], &trace.ops[3]) {
            (
                HasherOp::Padding { mrupdate_id: original, .. },
                HasherOp::Padding { mrupdate_id: copied, .. },
            ) => {
                assert_eq!(*original, ZERO);
                assert_eq!(*copied, ONE);
            },
            _ => panic!("replay must preserve padding ops"),
        }
        assert_limit(trace.replay_ops_range(0..1, ONE));
        assert_eq!(trace.trace_len(), MAX_TRACE_LEN);
        assert_eq!(trace.next_op_index(), 4);
    }

    #[test]
    fn replay_rejects_the_entire_span_before_copying() {
        let mut trace = HasherTrace {
            ops: vec![controller_op(), controller_op()],
            row_count: MAX_TRACE_LEN - 1,
        };
        assert_limit(trace.replay_ops_range(0..2, ONE));
        assert_eq!(trace.trace_len(), MAX_TRACE_LEN - 1);
        assert_eq!(trace.next_op_index(), 2);
    }

    #[test]
    fn hasher_preflights_basic_block_and_both_merkle_legs() {
        let mut hasher = Hasher {
            trace: HasherTrace {
                row_count: MAX_TRACE_LEN - 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let block = BasicBlockNodeBuilder::new(vec![Operation::Noop; 73]).build().unwrap();
        assert_eq!(block.num_op_batches(), 2);
        assert_limit(hasher.hash_basic_block(block.op_batches(), [ZERO; 4].into()));

        let path = super::super::MerklePath::new(vec![[ZERO; 4].into()]);
        assert_limit(hasher.update_merkle_root([ZERO; 4].into(), [ONE; 4].into(), &path, ZERO));
        assert_eq!(hasher.mrupdate_id, ZERO);
        assert_eq!(hasher.trace.trace_len(), MAX_TRACE_LEN - 1);
        assert_eq!(hasher.trace.next_op_index(), 0);
        assert!(hasher.compression_request_map.is_empty());
        assert!(hasher.memoized_trace_map.is_empty());
    }

    #[test]
    fn memoized_replay_overflow_leaves_caches_and_rows_unchanged() {
        let mut hasher = Hasher::default();
        let digest = [ONE; 4].into();
        hasher.hash_control_block(digest, digest, ZERO, digest).unwrap();
        let requests = hasher.compression_request_map.clone();
        let memoized = hasher.memoized_trace_map.clone();
        hasher.trace.row_count = MAX_TRACE_LEN;

        assert_limit(hasher.hash_control_block(digest, digest, ZERO, digest));
        assert_eq!(hasher.trace.trace_len(), MAX_TRACE_LEN);
        assert_eq!(hasher.trace.next_op_index(), 1);
        assert_eq!(hasher.compression_request_map, requests);
        assert_eq!(hasher.memoized_trace_map, memoized);
    }
}
