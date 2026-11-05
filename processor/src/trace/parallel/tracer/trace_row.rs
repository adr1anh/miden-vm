//! Module which concerns itself with all the trace row building logic.

use alloc::sync::Arc;

use miden_air_definitions::vm::{
    CoreCols, DecoderCols, StackCols, SystemCols,
    trace::{
        chiplets::hasher::CONTROLLER_ROWS_PER_HASHER_OP,
        decoder::{NUM_OP_BATCH_ENCODING_COLS, NUM_OP_BITS, NUM_USER_OP_HELPERS},
    },
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{
        BasicBlockNode, CallNode, ExecNode, JoinNode, LoopNode, MastNodeExt, OpBatch,
        SparseMastForest, SplitNode,
    },
    operations::{Operation, opcodes},
    program::MIN_STACK_DEPTH,
};

use super::{ExecutionContextInfo, StackState, SystemState, get_digest_in_forest};
use crate::{
    ExecutionError, InvocationTag, KeyedEventKind, KeyedMode,
    continuation_stack::Continuation,
    errors::MapExecErrNoCtx,
    mast::{ExecutableMastForest, MastNode},
    trace::{
        chiplets::layout::{ChipletsLayout, LogicalControllerAddress},
        parallel::{
            core_trace_fragment::BasicBlockContext, processor::ReplayProcessor,
            tracer::CoreTraceGenerationTracer,
        },
    },
};

// DECODER ROW
// ================================================================================================

/// The data necessary to build the decoder part of a trace row.
#[derive(Debug)]
struct DecoderRow {
    /// The address field to write into trace
    pub addr: LogicalControllerAddress,
    /// The operation code for start operations
    pub opcode: u8,
    /// The two child hashes for start operations (first hash, second hash)
    pub hasher_state: (Word, Word),
    /// Authenticated implementation root, present only on a keyed invocation row.
    pub resolved_digest: Word,
    /// Whether this row is an operation within a basic block
    pub in_basic_block: bool,
    /// Remaining operation groups for basic-block decoding. LOOP multiplicity is filled after
    /// trace rows are assembled.
    pub group_count: Felt,
    /// The index of the operation within its operation group, or 0 if this is not a row containing
    /// an operation in a basic block.
    pub op_index: Felt,
    /// The two-column encoding of the number of groups in the current operation batch.
    pub op_batch_encoding: [Felt; NUM_OP_BATCH_ENCODING_COLS],
}

impl DecoderRow {
    /// Creates a new `DecoderRow` for control flow operations (JOIN/SPLIT start or end).
    ///
    /// Control flow operations do not occur within basic blocks, so the relevant fields are set
    /// to their default values.
    pub fn new_control_flow(
        opcode: u8,
        hasher_state: (Word, Word),
        addr: LogicalControllerAddress,
    ) -> Self {
        Self {
            opcode,
            hasher_state,
            resolved_digest: Word::default(),
            addr,
            in_basic_block: false,
            group_count: ZERO,
            op_index: ZERO,
            op_batch_encoding: [ZERO; NUM_OP_BATCH_ENCODING_COLS],
        }
    }

    /// Creates a new `DecoderRow` for the start of a new batch in a basic block.
    ///
    /// This corresponds either to the SPAN or RESPAN operations.
    pub fn new_basic_block_batch(
        start_op: BasicBlockStartOperation,
        op_batch: &OpBatch,
        addr: LogicalControllerAddress,
        group_count: Felt,
    ) -> Result<Self, ExecutionError> {
        let opcode = match start_op {
            BasicBlockStartOperation::Span => opcodes::SPAN,
            BasicBlockStartOperation::Respan => opcodes::RESPAN,
        };

        let hasher_state = (
            op_batch.groups()[0..4].try_into().expect("slice with incorrect length"),
            op_batch.groups()[4..8].try_into().expect("slice with incorrect length"),
        );

        Ok(Self {
            opcode,
            hasher_state,
            resolved_digest: Word::default(),
            addr,
            in_basic_block: false,
            group_count,
            op_index: ZERO,
            op_batch_encoding: get_op_batch_encoding(group_count)?,
        })
    }

    /// Creates a new `DecoderRow` for an operation within a basic block.
    pub fn new_operation(
        operation: Operation,
        current_addr: LogicalControllerAddress,
        parent_addr: LogicalControllerAddress,
        op_idx_in_group: usize,
        basic_block_ctx: &BasicBlockContext,
        user_op_helpers: [Felt; NUM_USER_OP_HELPERS],
        layout: ChipletsLayout,
    ) -> Result<Self, ExecutionError> {
        let hasher_state: (Word, Word) = {
            let word1 = [
                basic_block_ctx.current_op_group,
                layout.controller_address(parent_addr)?.to_felt(),
                user_op_helpers[0],
                user_op_helpers[1],
            ];
            let word2 =
                [user_op_helpers[2], user_op_helpers[3], user_op_helpers[4], user_op_helpers[5]];

            (word1.into(), word2.into())
        };

        Ok(Self {
            opcode: operation.op_code(),
            hasher_state,
            resolved_digest: Word::default(),
            addr: current_addr,
            in_basic_block: true,
            group_count: basic_block_ctx.group_count_in_block,
            op_index: Felt::from_u32(op_idx_in_group as u32),
            op_batch_encoding: [ZERO; NUM_OP_BATCH_ENCODING_COLS],
        })
    }
}

/// Enum representing the type of operation that starts a basic block.
#[derive(Debug)]
enum BasicBlockStartOperation {
    Span,
    Respan,
}

// BASIC BLOCK TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    /// Checks the exact address and decoder work without consuming replay queues.
    pub(super) fn preflight_trace_row(
        &self,
        continuation: &Continuation<Arc<SparseMastForest>>,
        processor: &ReplayProcessor,
        forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        use Continuation::*;

        match continuation {
            StartNode(node_id) => {
                let node = super::get_node_in_forest(forest, *node_id)?;
                let address = self.block_address_replay.peek_block_address()?;
                let parent = self.block_stack_replay.peek_node_start_parent_addr()?;
                self.layout.controller_address(address)?;
                self.layout.controller_address(parent)?;
                let mut missing_child = false;
                node.for_each_child(|child| {
                    missing_child |= forest.get_digest_by_id(child).is_none();
                });
                if missing_child {
                    return Err(ExecutionError::Internal("core replay control child is missing"));
                }
                if let MastNode::Block(block) = node {
                    let context =
                        BasicBlockContext::new_at_batch_start(block, 0).map_exec_err_no_ctx()?;
                    get_op_batch_encoding(context.group_count_in_block)?;
                } else if matches!(node, MastNode::External(_)) {
                    return Err(ExecutionError::Internal("external replay node was not resolved"));
                }
            },
            ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let MastNode::Block(block) = super::get_node_in_forest(forest, *node_id)? else {
                    return Err(ExecutionError::Internal("core replay basic block is missing"));
                };
                BasicBlockContext::new_at_op(block, *batch_index, *op_idx_in_batch)
                    .map_exec_err_no_ctx()?;
                self.layout.controller_address(self.decoder_state.current_addr)?;
                self.layout.controller_address(self.decoder_state.parent_addr)?;
            },
            Respan { node_id, batch_index } => {
                let MastNode::Block(block) = super::get_node_in_forest(forest, *node_id)? else {
                    return Err(ExecutionError::Internal("core replay basic block is missing"));
                };
                let context = BasicBlockContext::new_at_batch_start(block, *batch_index)
                    .map_exec_err_no_ctx()?;
                get_op_batch_encoding(context.group_count_in_block)?;
                self.layout.controller_address(self.decoder_state.current_addr)?;
                self.decoder_state.current_addr.checked_advance(CONTROLLER_ROWS_PER_HASHER_OP)?;
            },
            FinishLoop(node_id) if processor.stack.get(0) == ONE => {
                let MastNode::Loop(node) = super::get_node_in_forest(forest, *node_id)? else {
                    return Err(ExecutionError::Internal("core replay loop node is missing"));
                };
                get_digest_in_forest(forest, node.body())?;
                self.layout.controller_address(self.decoder_state.current_addr)?;
            },
            FinishJoin(node_id)
            | FinishSplit(node_id)
            | FinishLoop(node_id)
            | FinishCall(node_id)
            | FinishDyn(node_id)
            | FinishExec(node_id)
            | FinishBasicBlock(node_id) => {
                let node = super::get_node_in_forest(forest, *node_id)?;
                match continuation {
                    FinishExec(_) if !matches!(node, MastNode::Exec(_)) => {
                        return Err(ExecutionError::Internal(
                            "expected exec node in FinishExec continuation",
                        ));
                    },
                    FinishBasicBlock(_) if !matches!(node, MastNode::Block(_)) => {
                        return Err(ExecutionError::Internal(
                            "expected basic block node in FinishBasicBlock continuation",
                        ));
                    },
                    _ => {},
                }
                self.compute_end_block_flags(continuation, forest)?;
                let end = self.block_stack_replay.peek_node_end()?;
                self.layout.controller_address(end.ended_node_addr)?;
                self.layout.controller_address(end.prev_addr)?;
                self.layout.controller_address(end.prev_parent_addr)?;
            },
            EnterForest { .. } | RootBoundary { .. } => {
                return Err(ExecutionError::Internal("zero-cycle continuation cannot be traced"));
            },
        }
        Ok(())
    }

    /// Writes the literal key committed by a same-context EXEC wrapper.
    pub fn fill_exec_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        exec_node: &ExecNode,
    ) -> Result<(), ExecutionError> {
        let decoder_row = DecoderRow::new_control_flow(
            opcodes::EXEC,
            (exec_node.target().into_word(), Word::default()),
            self.decoder_state.parent_addr,
        );
        self.fill_trace_row(system, stack, decoder_row)
    }

    /// Fills a trace row for SPAN start operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the SPAN operation that starts
    /// a basic block execution.
    pub fn fill_basic_block_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        basic_block_node: &BasicBlockNode,
    ) -> Result<(), ExecutionError> {
        let group_count_for_block = Felt::from_u32(basic_block_node.num_op_groups() as u32);
        let first_op_batch = basic_block_node
            .op_batches()
            .first()
            .ok_or(ExecutionError::Internal("basic block should have at least one op batch"))?;

        let decoder_row = DecoderRow::new_basic_block_batch(
            BasicBlockStartOperation::Span,
            first_op_batch,
            self.decoder_state.parent_addr,
            group_count_for_block,
        )?;
        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    /// Fills a trace row for SPAN end operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the END operation that completes
    /// a basic block execution.
    pub fn fill_basic_block_end_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        basic_block_node: &BasicBlockNode,
        hasher_state_second_word: Word,
    ) -> Result<(), ExecutionError> {
        let ended_node_addr = self.decoder_state.replay_node_end(&mut self.block_stack_replay)?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::END,
            (basic_block_node.digest(), hasher_state_second_word),
            ended_node_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    // RESPAN
    // -------------------------------------------------------------------------------------------

    /// Processes a RESPAN operation that starts processing of a new operation batch within
    /// the same basic block.
    ///
    /// This method updates the processor state and adds a corresponding trace row
    /// to the main trace fragment.
    pub fn fill_respan_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        op_batch: &OpBatch,
        basic_block_context: &mut BasicBlockContext,
    ) -> Result<(), ExecutionError> {
        let next_address =
            self.decoder_state.current_addr.checked_advance(CONTROLLER_ROWS_PER_HASHER_OP)?;
        // Add RESPAN trace row
        {
            let decoder_row = DecoderRow::new_basic_block_batch(
                BasicBlockStartOperation::Respan,
                op_batch,
                self.decoder_state.current_addr,
                basic_block_context.group_count_in_block,
            )?;
            self.fill_trace_row(system, stack, decoder_row)?;
        }

        // Update block address for the upcoming block
        self.decoder_state.current_addr = next_address;

        // Update basic block context
        basic_block_context.group_count_in_block -= ONE;
        basic_block_context.current_op_group = op_batch.groups()[0];

        Ok(())
    }

    /// Writes a trace row for an operation within a basic block.
    ///
    /// This must be called *after* the operation has been executed and the
    /// stack has been updated.
    pub fn fill_operation_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        operation: Operation,
        op_idx_in_group: usize,
        user_op_helpers: [Felt; NUM_USER_OP_HELPERS],
        basic_block_context: &mut BasicBlockContext,
    ) -> Result<(), ExecutionError> {
        // update operations left to be executed in the group
        basic_block_context.remove_operation_from_current_op_group();

        // Add trace row
        let decoder_row = DecoderRow::new_operation(
            operation,
            self.decoder_state.current_addr,
            self.decoder_state.parent_addr,
            op_idx_in_group,
            basic_block_context,
            user_op_helpers,
            self.layout,
        )?;
        self.fill_trace_row(system, stack, decoder_row)
    }
}

// CONTROL FLOW TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    // CALL operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a CALL/SYSCALL operation.
    pub fn fill_call_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        call_node: &CallNode,
        _current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        // Immediate invocation hashing commits K || ZERO, independently of the resolved D.
        let callee_hash = call_node.target().into_word();
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            if call_node.is_syscall() {
                opcodes::SYSCALL
            } else {
                opcodes::CALL
            },
            (callee_hash, zero_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    // DYN operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a DYN operation.
    pub fn fill_dyn_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        callee_hash: Word,
    ) -> Result<(), ExecutionError> {
        let decoder_row = DecoderRow::new_control_flow(
            opcodes::DYN,
            (callee_hash, Word::default()),
            self.decoder_state.parent_addr,
        );
        self.fill_trace_row(system, stack, decoder_row)
    }

    /// Fills a trace row for the start of a DYNCALL operation.
    ///
    /// The decoder hasher trace columns are populated with the callee hash, as well as the stack
    /// helper registers (specifically their state after shifting the stack left). We need to store
    /// those in the decoder trace so that the block stack table can access them (since in the next
    /// row, we start a new context, and hence the stack registers are reset to their default
    /// values).
    pub fn fill_dyncall_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        callee_hash: Word,
        ctx_info: ExecutionContextInfo,
    ) -> Result<(), ExecutionError> {
        let second_hasher_state: Word = [
            Felt::from_u32(ctx_info.parent_stack_depth),
            ctx_info.parent_next_overflow_addr,
            ZERO,
            ZERO,
        ]
        .into();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::DYNCALL,
            (callee_hash, second_hasher_state),
            self.decoder_state.parent_addr,
        );
        self.fill_trace_row(system, stack, decoder_row)
    }

    // JOIN operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for starting a JOIN operation to the main trace fragment.
    pub fn fill_join_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        join_node: &JoinNode,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        // Get the child hashes for the hasher state
        let child1_hash: Word = get_digest_in_forest(current_forest, join_node.first())?;
        let child2_hash: Word = get_digest_in_forest(current_forest, join_node.second())?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::JOIN,
            (child1_hash, child2_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    // LOOP operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a LOOP operation.
    pub fn fill_loop_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        loop_node: &LoopNode,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        // For LOOP operations, the hasher state in start operations contains the loop body hash in
        // the first half.
        let body_hash: Word = get_digest_in_forest(current_forest, loop_node.body())?;
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::LOOP,
            (body_hash, zero_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    /// Fills a trace row for the start of a REPEAT operation.
    pub fn fill_loop_repeat_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        loop_node: &LoopNode,
        current_forest: &Arc<SparseMastForest>,
        current_addr: LogicalControllerAddress,
    ) -> Result<(), ExecutionError> {
        // For REPEAT operations, the hasher state in start operations contains the loop body hash
        // in the first half.
        let body_hash: Word = get_digest_in_forest(current_forest, loop_node.body())?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::REPEAT,
            // We set hasher[4] (is_loop_body) to 1
            (body_hash, [ONE, ZERO, ZERO, ZERO].into()),
            current_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    // SPLIT operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a SPLIT operation.
    pub fn fill_split_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        split_node: &SplitNode,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        // Get the child hashes for the hasher state
        let on_true_hash: Word = get_digest_in_forest(current_forest, split_node.on_true())?;
        let on_false_hash: Word = get_digest_in_forest(current_forest, split_node.on_false())?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::SPLIT,
            (on_true_hash, on_false_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }

    /// Fills a trace row for the end of a control block.
    ///
    /// This method also updates the decoder state by popping the block from the stack.
    pub fn fill_end_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        node_digest: Word,
        hasher_state_second_word: Word,
    ) -> Result<(), ExecutionError> {
        // Pop the block from stack and use its info for END operations
        let ended_node_addr = self.decoder_state.replay_node_end(&mut self.block_stack_replay)?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::END,
            (node_digest, hasher_state_second_word),
            ended_node_addr,
        );

        self.fill_trace_row(system, stack, decoder_row)?;
        Ok(())
    }
}

// HELPER METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    /// Fills a trace row for a control flow operation (JOIN/SPLIT start or end) to the main trace
    /// fragment.
    ///
    /// This is a shared implementation that handles the common trace row generation logic
    /// for both JOIN and SPLIT operations. The operation-specific details are provided
    /// through the `config` parameter.
    fn fill_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        mut decoder_row: DecoderRow,
    ) -> Result<(), ExecutionError> {
        let mode = match decoder_row.opcode {
            opcodes::EXEC => Some(KeyedMode::Exec),
            opcodes::CALL => Some(KeyedMode::Call),
            opcodes::SYSCALL => Some(KeyedMode::Syscall),
            opcodes::DYN => Some(KeyedMode::Dyn),
            opcodes::DYNCALL => Some(KeyedMode::DynCall),
            _ => None,
        };
        if let Some(mode) = mode {
            let event = self.keyed_event.ok_or(ExecutionError::Internal(
                "invocation trace row has no authenticated keyed event",
            ))?;
            let tag = if mode == KeyedMode::Syscall {
                InvocationTag::Syscall
            } else {
                InvocationTag::Normal
            };
            if event.kind != KeyedEventKind::Invoke(mode)
                || event.use_record.tag() != tag
                || event.use_record.row() != system.clk
                || event.use_record.procedure_key().into_word() != decoder_row.hasher_state.0
            {
                return Err(ExecutionError::Internal(
                    "invocation trace row differs from authenticated keyed event",
                ));
            }
            decoder_row.resolved_digest = event.use_record.implementation_root().into_word();
        } else if let Some(event) = self.keyed_event {
            if decoder_row.opcode != opcodes::END
                || event.kind != KeyedEventKind::RootEnd
                || event.use_record.tag() != InvocationTag::Normal
                || event.use_record.row() != system.clk
                || event.use_record.implementation_root().into_word() != decoder_row.hasher_state.0
                || event.use_record.procedure_key() != event.principal_after
                || decoder_row.hasher_state.1[0] != ZERO
                || decoder_row.hasher_state.1[3] != ONE
            {
                return Err(ExecutionError::Internal(
                    "root END trace row differs from authenticated keyed event",
                ));
            }
        } else if decoder_row.opcode == opcodes::END && decoder_row.hasher_state.1[3] != ZERO {
            return Err(ExecutionError::Internal("root END trace row has no authenticated event"));
        }

        let mut row = CoreCols::<Felt>::default();
        if let Some(system) = &self.system_cols {
            row.system = system.clone();
        }
        if let Some(stack) = &self.stack_cols {
            row.stack = stack.clone();
        }
        Self::write_decoder(&mut row.decoder, &decoder_row, self.layout)?;

        self.writer.write_row(self.row_write_index, row.as_slice());

        // Store the buffer for the next call
        self.system_cols = Some(Self::build_system_cols(system));
        self.stack_cols = Some(Self::build_stack_cols(stack));

        // Increment the row write index
        self.row_write_index += 1;
        Ok(())
    }

    fn write_decoder(
        decoder: &mut DecoderCols<Felt>,
        decoder_row: &DecoderRow,
        layout: ChipletsLayout,
    ) -> Result<(), ExecutionError> {
        // Block address
        decoder.addr = layout.controller_address(decoder_row.addr)?.to_felt();

        // Decompose operation into bits
        let opcode = decoder_row.opcode;
        for i in 0..NUM_OP_BITS {
            decoder.op_bits[i] = Felt::from_u8((opcode >> i) & 1);
        }

        // Hasher state
        let (first_hash, second_hash) = decoder_row.hasher_state;
        decoder.hasher_state[0] = first_hash[0];
        decoder.hasher_state[1] = first_hash[1];
        decoder.hasher_state[2] = first_hash[2];
        decoder.hasher_state[3] = first_hash[3];
        decoder.hasher_state[4] = second_hash[0];
        decoder.hasher_state[5] = second_hash[1];
        decoder.hasher_state[6] = second_hash[2];
        decoder.hasher_state[7] = second_hash[3];
        decoder.resolved_digest = decoder_row.resolved_digest.into_elements();

        // Remaining decoder trace columns (identical for all control flow operations)
        decoder.op_index = decoder_row.op_index;
        decoder.group_count = decoder_row.group_count;
        decoder.in_span = if decoder_row.in_basic_block { ONE } else { ZERO };

        let [full_batch, batch_size_code] = decoder_row.op_batch_encoding;
        decoder.full_batch = full_batch;
        decoder.batch_size_code = batch_size_code;

        // Extra bit columns
        let bit6 = Felt::from_u8((opcode >> 6) & 1);
        let bit5 = Felt::from_u8((opcode >> 5) & 1);
        let bit4 = Felt::from_u8((opcode >> 4) & 1);
        decoder.extra[0] = bit6 * (ONE - bit5) * bit4;
        decoder.extra[1] = bit6 * bit5;
        Ok(())
    }

    fn build_system_cols(system: &SystemState) -> SystemCols<Felt> {
        SystemCols {
            clk: (system.clk + 1).into(),
            ctx: system.ctx.into(),
            fn_hash: *system.fn_hash,
        }
    }

    fn build_stack_cols(stack: &StackState) -> StackCols<Felt> {
        let mut top = [ZERO; MIN_STACK_DEPTH];
        for (i, slot) in top.iter_mut().enumerate() {
            *slot = stack.get(i);
        }

        // H0 will be inverted using batch inversion later.
        StackCols {
            top,
            b0: Felt::new_unchecked(stack.stack_depth() as u64),
            b1: stack.overflow_addr(),
            h0: stack.overflow_helper(),
        }
    }
}

// HELPERS
// ===============================================================================================

/// Returns the operation-batch encoding for the specified group count.
fn get_op_batch_encoding(
    num_groups_left: Felt,
) -> Result<[Felt; NUM_OP_BATCH_ENCODING_COLS], ExecutionError> {
    use miden_air_definitions::vm::trace::decoder::{
        OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
    };
    use miden_core::mast::OP_BATCH_SIZE;

    let num_groups = core::cmp::min(num_groups_left.as_canonical_u64() as usize, OP_BATCH_SIZE);
    match num_groups {
        8 => Ok(OP_BATCH_8_GROUPS),
        4 => Ok(OP_BATCH_4_GROUPS),
        2 => Ok(OP_BATCH_2_GROUPS),
        1 => Ok(OP_BATCH_1_GROUPS),
        _ => Err(ExecutionError::Internal(
            "invalid number of groups in a batch, must be 1, 2, 4, or 8",
        )),
    }
}

#[cfg(test)]
mod tests {
    use core::borrow::Borrow;

    use miden_core::mast::BasicBlockNodeBuilder;

    use super::*;
    use crate::{
        ContextId,
        trace::{
            parallel::{CORE_TRACE_WIDTH, MAX_TRACE_LEN},
            trace_state::{BlockAddressReplay, BlockStackReplay, DecoderState},
            utils::RowMajorTraceWriter,
        },
    };

    fn respan_batch() -> OpBatch {
        BasicBlockNodeBuilder::new(alloc::vec![Operation::Pad])
            .build()
            .unwrap()
            .op_batches()[0]
            .clone()
    }

    fn tracer(
        buffer: &mut [Felt],
        current_addr: LogicalControllerAddress,
    ) -> CoreTraceGenerationTracer<'_> {
        CoreTraceGenerationTracer::new(
            RowMajorTraceWriter::new(buffer, CORE_TRACE_WIDTH),
            DecoderState {
                current_addr,
                parent_addr: LogicalControllerAddress::from_felt(Felt::from_u8(7)).unwrap(),
            },
            BlockAddressReplay::default(),
            BlockStackReplay::default(),
            ChipletsLayout::new(0, MAX_TRACE_LEN - 1, 0, 0, 0, 0).unwrap(),
        )
    }

    fn system() -> SystemState {
        SystemState {
            clk: 0u32.into(),
            ctx: ContextId::root(),
            fn_hash: Word::default(),
            deferred_root: Word::default(),
        }
    }

    #[test]
    fn respan_advances_materializable_rows_while_preserving_absence() {
        let batch = respan_batch();
        let stack = StackState::new([ZERO; MIN_STACK_DEPTH], MIN_STACK_DEPTH, ZERO);
        for (address, next_address) in [
            (ONE, Felt::from_u32(1 + CONTROLLER_ROWS_PER_HASHER_OP as u32)),
            (ZERO, ZERO),
            (
                Felt::from_u32((MAX_TRACE_LEN - CONTROLLER_ROWS_PER_HASHER_OP) as u32),
                Felt::from_u32(MAX_TRACE_LEN as u32),
            ),
        ] {
            let mut buffer = [ZERO; CORE_TRACE_WIDTH];
            {
                let mut tracer =
                    tracer(&mut buffer, LogicalControllerAddress::from_felt(address).unwrap());
                let mut context = BasicBlockContext {
                    current_op_group: Felt::from_u8(99),
                    group_count_in_block: ONE,
                };
                tracer.fill_respan_trace_row(&system(), &stack, &batch, &mut context).unwrap();

                assert_eq!(tracer.row_write_index, 1);
                assert_eq!(tracer.decoder_state.current_addr.to_felt(), next_address);
                assert_eq!(tracer.decoder_state.parent_addr.to_felt(), Felt::from_u8(7));
                assert_eq!(context.current_op_group, batch.groups()[0]);
                assert_eq!(context.group_count_in_block, ZERO);
            }
            let row: &CoreCols<Felt> = buffer.as_slice().borrow();
            assert_eq!(row.decoder.addr, address);
            assert_eq!(row.decoder.group_count, ONE);
        }
    }

    #[test]
    fn respan_overflow_preserves_trace_decoder_and_block_context() {
        let batch = respan_batch();
        let stack = StackState::new([ZERO; MIN_STACK_DEPTH], MIN_STACK_DEPTH, ZERO);
        for address in [Felt::from_u32(MAX_TRACE_LEN as u32 + 1)] {
            let untouched = [Felt::from_u8(99); CORE_TRACE_WIDTH];
            let mut buffer = untouched;
            {
                let mut tracer =
                    tracer(&mut buffer, LogicalControllerAddress::from_felt(address).unwrap());
                let mut context = BasicBlockContext {
                    current_op_group: Felt::from_u8(11),
                    group_count_in_block: ONE,
                };

                let result = tracer.fill_respan_trace_row(&system(), &stack, &batch, &mut context);
                assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))));
                assert_eq!(tracer.row_write_index, 0);
                assert_eq!(
                    tracer.decoder_state,
                    DecoderState {
                        current_addr: LogicalControllerAddress::from_felt(address).unwrap(),
                        parent_addr: LogicalControllerAddress::from_felt(Felt::from_u8(7)).unwrap()
                    },
                );
                assert!(tracer.system_cols.is_none());
                assert!(tracer.stack_cols.is_none());
                assert_eq!(context.current_op_group, Felt::from_u8(11));
                assert_eq!(context.group_count_in_block, ONE);
            }
            assert_eq!(buffer, untouched);
        }
    }

    #[test]
    fn physical_row_writer_maps_parent_and_typed_helpers_without_changing_vm_values() {
        use crate::tracer::OperationHelperRegisters;

        let row_zero = LogicalControllerAddress::from_felt(ONE).unwrap();
        let state_prev = [ONE, Felt::from_u8(2), ZERO, Felt::from_u8(4)].into();
        for parent in [LogicalControllerAddress::ABSENT, row_zero] {
            for (operation, helper) in [
                (Operation::Compress, OperationHelperRegisters::Compress { addr: ONE }),
                (
                    Operation::MpVerify(ZERO),
                    OperationHelperRegisters::MerklePath { addr: ONE, index: ONE },
                ),
                (
                    Operation::LogDeferred,
                    OperationHelperRegisters::LogDeferred { addr: ONE, state_prev },
                ),
            ] {
                let layout = ChipletsLayout::new(7, 2, 0, 0, 0, 0).unwrap();
                let mut system = system();
                system.clk = 23u32.into();
                system.ctx = ContextId::from(3);
                system.fn_hash = state_prev;
                let stack = StackState::new([ONE; MIN_STACK_DEPTH], MIN_STACK_DEPTH + 2, ONE);
                let expected_system = CoreTraceGenerationTracer::build_system_cols(&system);
                let expected_stack = CoreTraceGenerationTracer::build_stack_cols(&stack);
                let mut buffer = [ZERO; CORE_TRACE_WIDTH];
                {
                    let mut tracer = CoreTraceGenerationTracer::new(
                        RowMajorTraceWriter::new(&mut buffer, CORE_TRACE_WIDTH),
                        DecoderState {
                            current_addr: row_zero,
                            parent_addr: parent,
                        },
                        BlockAddressReplay::default(),
                        BlockStackReplay::default(),
                        layout,
                    );
                    tracer.system_cols = Some(expected_system.clone());
                    tracer.stack_cols = Some(expected_stack.clone());
                    let mut context = BasicBlockContext {
                        current_op_group: Felt::from_u8(operation.op_code()),
                        group_count_in_block: ONE,
                    };
                    tracer
                        .fill_operation_trace_row(
                            &system,
                            &stack,
                            operation,
                            0,
                            helper.to_physical_user_op_helpers(layout).unwrap(),
                            &mut context,
                        )
                        .unwrap();
                    assert_eq!(tracer.decoder_state.current_addr, row_zero);
                    assert_eq!(tracer.decoder_state.parent_addr, parent);
                }
                let row: &CoreCols<Felt> = buffer.as_slice().borrow();
                assert_eq!(row.decoder.addr, Felt::from_u8(8));
                assert_eq!(
                    row.decoder.hasher_state[1],
                    if parent == LogicalControllerAddress::ABSENT {
                        ZERO
                    } else {
                        Felt::from_u8(8)
                    }
                );
                let mut expected_helpers = helper.to_user_op_helpers();
                expected_helpers[0] = Felt::from_u8(8);
                assert_eq!(row.decoder.user_op_helpers(), expected_helpers);
                assert_eq!(row.system.clk, expected_system.clk);
                assert_eq!(row.system.ctx, expected_system.ctx);
                assert_eq!(row.system.fn_hash, expected_system.fn_hash);
                assert_eq!(row.stack.top, expected_stack.top);
                assert_eq!(row.stack.b0, expected_stack.b0);
                assert_eq!(row.stack.b1, ONE);
                assert_eq!(row.stack.h0, Felt::from_u8(2));
            }
        }
    }
}
