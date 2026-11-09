use alloc::sync::Arc;

use miden_air_definitions::vm::{StackCols, SystemCols};
use miden_core::program::{MIN_STACK_DEPTH, ProcedureKey};

use super::{
    super::{
        block_stack::ExecutionContextInfo,
        trace_state::{
            BlockAddressReplay, BlockStackReplay, DecoderState, StackState, SystemState,
        },
        utils::RowMajorTraceWriter,
    },
    core_trace_fragment::BasicBlockContext,
    processor::ReplayProcessor,
};
use crate::{
    ExecutionError, Felt, ONE, Word, ZERO,
    continuation_stack::{Continuation, ContinuationStack},
    errors::MapExecErrNoCtx,
    mast::{ExecutableMastForest, MastNode, MastNodeExt, MastNodeId, SparseMastForest},
    trace::{
        chiplets::layout::ChipletsLayout,
        trace_state::{EndBlockFlags, EndBlockStackEntryKind},
    },
    tracer::{
        CycleProjection, KeyedEvent, KeyedEventKind, KeyedMode, KeyedTarget,
        OperationHelperRegisters, Tracer,
    },
};

mod trace_row;

// TRACER FINAL STATE
// ================================================================================================

/// The final state of a [`CoreTraceGenerationTracer`] after trace generation completes.
///
/// Contains the last stack and system trace cols (or zeros if none were written), which are needed
/// to initialize the first row of the next fragment, as well as the number of trace rows that were
/// built.
pub(crate) struct TracerFinalState {
    pub last_stack_cols: StackCols<Felt>,
    pub last_system_cols: SystemCols<Felt>,
    pub num_rows_written: usize,
}

// CORE TRACE GENERATION TRACER
// ================================================================================================

/// A tracer implementation for generating a core trace fragment of a predetermined number of rows.
///
/// This tracer is used in conjunction with the [`ReplayProcessor`] to fill in trace rows for a
/// fragment of the execution. Trace rows are written in [`Tracer::finalize_clock_cycle`] after
/// collecting the necessary state in [`Tracer::start_clock_cycle`].
///
/// The tracer handles errors internally; if an error is encountered during execution, it is stored
/// and all subsequent calls to these methods become no-ops. The error is returned by
/// `into_final_state()`, which should be called after trace generation completes to retrieve the
/// final state of the tracer (or the error, if one was encountered).
#[derive(Debug)]
pub(crate) struct CoreTraceGenerationTracer<'a> {
    /// The writer for the core trace fragment.
    writer: RowMajorTraceWriter<'a, Felt>,
    /// The index of the next row to write in the trace fragment.
    row_write_index: usize,
    /// Shared immutable Chiplets layout, used to check final Controller address bounds.
    layout: ChipletsLayout,

    /// The decoder state being replayed, tracking the current and parent block addresses.
    decoder_state: DecoderState,
    /// Replays the sequence of block addresses that were assigned during the initial execution.
    block_address_replay: BlockAddressReplay,
    /// Replays block stack push/pop operations (parent address and block context) from the
    /// initial execution.
    block_stack_replay: BlockStackReplay,

    /// Buffered stack trace column data from the current clock cycle. Written to the fragment on
    /// the *next* clock cycle (since stack columns are one row behind), and returned via
    /// [`into_parts`](Self::into_parts) so the next fragment can continue from this state.
    stack_cols: Option<StackCols<Felt>>,
    /// Buffered system trace column data from the current clock cycle. Written to the fragment on
    /// the *next* clock cycle (since system columns are one row behind), and returned via
    /// [`into_parts`](Self::into_parts) so the next fragment can continue from this state.
    system_cols: Option<SystemCols<Felt>>,

    /// Execution context info captured at the beginning of a DYNCALL clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)) to be used when finalizing it.
    ctx_info: Option<ExecutionContextInfo>,
    /// Loop condition captured at the beginning of a `FinishLoop` clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)). `true` means the loop body will be
    /// re-executed (REPEAT); `false` means the loop is finished (END).
    finish_loop_condition: Option<bool>,
    /// Hash of the called procedure for `Dyn` nodes, captured at the beginning of a DYN clock
    /// cycle (in [`start_clock_cycle`](Tracer::start_clock_cycle)) to be used when finalizing
    /// it.
    dyn_callee_hash: Option<Word>,

    /// The continuation captured at the beginning of the clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)), describing what is being executed at
    /// this cycle.
    continuation: Option<Continuation<Arc<SparseMastForest>>>,

    /// Whether the node ending in this clock cycle is a body of a LOOP node. This is determined
    /// by peeking at the continuation stack in [`start_clock_cycle`](Tracer::start_clock_cycle)
    /// to check if the next clock-incrementing continuation is a `FinishLoop`.
    ///
    /// This is only relevant for END operations (Finish* continuations).
    is_loop_body: bool,

    /// If an error is encountered during trace generation, it is stored here. Once set, all
    /// subsequent `start_clock_cycle` and `finalize_clock_cycle` calls become no-ops, and the
    /// error is returned by [`into_parts`](Self::into_parts).
    error_encountered: Option<ExecutionError>,
    keyed_event: Option<KeyedEvent>,
    prepared_keyed_cycle: Option<(KeyedEventKind, ProcedureKey)>,
}

impl<'a> CoreTraceGenerationTracer<'a> {
    pub fn new(
        writer: RowMajorTraceWriter<'a, Felt>,
        decoder_state: DecoderState,
        block_address_replay: BlockAddressReplay,
        block_stack_replay: BlockStackReplay,
        layout: ChipletsLayout,
    ) -> Self {
        Self {
            writer,
            row_write_index: 0,
            layout,
            decoder_state,
            block_address_replay,
            block_stack_replay,
            stack_cols: None,
            system_cols: None,
            ctx_info: None,
            finish_loop_condition: None,
            dyn_callee_hash: None,
            continuation: None,
            is_loop_body: false,
            error_encountered: None,
            keyed_event: None,
            prepared_keyed_cycle: None,
        }
    }

    /// Consumes this tracer and returns its final state, or an error if one was encountered
    /// during trace generation.
    pub fn into_final_state(self) -> Result<TracerFinalState, ExecutionError> {
        if let Some(err) = self.error_encountered {
            return Err(err);
        }
        if self.keyed_event.is_some() || self.prepared_keyed_cycle.is_some() {
            return Err(ExecutionError::InvalidExecutionState);
        }

        Ok(TracerFinalState {
            last_stack_cols: self.stack_cols.unwrap_or(StackCols {
                top: [ZERO; MIN_STACK_DEPTH],
                b0: ZERO,
                b1: ZERO,
                h0: ZERO,
            }),
            last_system_cols: self.system_cols.unwrap_or(SystemCols {
                clk: ZERO,
                ctx: ZERO,
                fn_hash: [ZERO; miden_core::WORD_SIZE],
            }),
            num_rows_written: self.row_write_index,
        })
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills a trace row for a `StartNode` continuation based on the type of node being started.
    fn fill_start_row(
        &mut self,
        node_id: MastNodeId,
        processor: &ReplayProcessor,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        let node = get_node_in_forest(current_forest, node_id)?;

        match node {
            MastNode::Block(basic_block_node) => {
                self.fill_basic_block_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    basic_block_node,
                )?;
            },
            MastNode::Join(join_node) => {
                self.fill_join_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    join_node,
                    current_forest,
                )?;
            },
            MastNode::Split(split_node) => {
                self.fill_split_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    split_node,
                    current_forest,
                )?;
            },
            MastNode::Loop(loop_node) => {
                self.fill_loop_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    loop_node,
                    current_forest,
                )?;
            },
            MastNode::Call(call_node) => {
                self.fill_call_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    call_node,
                    current_forest,
                )?;
            },
            MastNode::Exec(exec_node) => {
                self.fill_exec_start_trace_row(&processor.system, &processor.stack, exec_node)?;
            },
            MastNode::Dyn(dyn_node) => {
                let callee_hash = self.dyn_callee_hash.take().ok_or(ExecutionError::Internal(
                    "dyn callee hash not stored at start of clock cycle",
                ))?;

                if dyn_node.is_dyncall() {
                    let ctx_info = self.ctx_info.take().ok_or(ExecutionError::Internal(
                        "execution context info not stored at start of clock cycle for DYNCALL node",
                    ))?;

                    self.fill_dyncall_start_trace_row(
                        &processor.system,
                        &processor.stack,
                        callee_hash,
                        ctx_info,
                        dyn_node.is_digest(),
                    )?;
                } else {
                    self.fill_dyn_start_trace_row(
                        &processor.system,
                        &processor.stack,
                        callee_hash,
                        dyn_node.is_digest(),
                    )?;
                }
            },
            MastNode::External(_) => {
                unreachable!("The Tracer contract guarantees that external nodes do not occur here")
            },
        }

        Ok(())
    }

    /// Returns the execution context info for a DYNCALL node, or `None` if the continuation does
    /// not represent a `StartNode` for a DYNCALL. The state of the processor is expected to be at
    /// the beginning of the DYNCALL execution (i.e., during `start_clock_cycle()`).
    ///
    /// Recall that DYNCALL drops the top stack element, which represents the memory address where
    /// the callee hash is stored. The execution context info is captured *after* the top stack
    /// element has been dropped, as per the semantics of DYNCALL.
    fn get_execution_context_for_dyncall(
        &self,
        current_forest: &Arc<SparseMastForest>,
        continuation: &Continuation<Arc<SparseMastForest>>,
        processor: &ReplayProcessor,
    ) -> Result<Option<ExecutionContextInfo>, ExecutionError> {
        let Continuation::StartNode(node_id) = &continuation else {
            return Ok(None);
        };

        let Some(node) = current_forest.get_node_by_id(*node_id) else {
            return Err(ExecutionError::Internal("invalid node ID stored in continuation"));
        };

        let MastNode::Dyn(dyn_node) = node else {
            return Ok(None);
        };

        if !dyn_node.is_dyncall() {
            return Ok(None);
        }

        let overflow_addr_after_drop = if processor.stack.stack_depth() > MIN_STACK_DEPTH {
            // Stack is above minimum depth, so peek at the overflow replay for the post-pop
            // overflow address.
            let (_, overflow_addr_after_drop) = processor
                .stack_overflow_replay
                .peek_replay_pop_overflow()
                .ok_or(ExecutionError::Internal(
                    "stack depth is above minimum, but no corresponding overflow pop in the replay",
                ))?;
            *overflow_addr_after_drop
        } else {
            // At minimum depth there is no overflow row to consume.
            ZERO
        };

        Ok(Some(ExecutionContextInfo::new(
            processor.system.ctx,
            processor.system.fn_hash,
            overflow_addr_after_drop,
        )))
    }

    /// Returns the loop condition sitting on top of the stack for a `FinishLoop` continuation, or
    /// `None` if the continuation is not a `FinishLoop`.
    ///
    /// The loop condition is `true` if the top of the stack equals ONE (meaning the loop body
    /// should be re-executed), and `false` otherwise (meaning the loop is finished).
    fn get_finish_loop_condition(
        &self,
        continuation: &Continuation<Arc<SparseMastForest>>,
        processor: &ReplayProcessor,
    ) -> Option<bool> {
        if let Continuation::FinishLoop(_) = &continuation {
            let condition = processor.stack.get(0);
            return Some(condition == ONE);
        }

        None
    }

    /// Returns the `EndBlockFlags` for an END operation based on the continuation type and state
    /// captured in `start_clock_cycle`.
    fn compute_end_block_flags(
        &self,
        continuation: &Continuation<Arc<SparseMastForest>>,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<EndBlockFlags, ExecutionError> {
        let is_loop_body = self.is_loop_body;

        let flags = match continuation {
            Continuation::FinishLoop(_) => {
                // The Loop node itself is ending. With do-while semantics every loop is entered, so
                // the `is_loop` flag is unconditionally true here.
                Ok(EndBlockFlags::new(is_loop_body, EndBlockStackEntryKind::LoopContinuation))
            },
            Continuation::FinishCall(node_id) => {
                let node = get_node_in_forest(current_forest, *node_id)?;
                let MastNode::Call(_) = node else {
                    return Err(ExecutionError::Internal(
                        "expected call node in FinishCall continuation",
                    ));
                };
                Ok(EndBlockFlags::new(is_loop_body, EndBlockStackEntryKind::CallerFrame))
            },
            Continuation::FinishDyn(node_id) => {
                let node = get_node_in_forest(current_forest, *node_id)?;
                let MastNode::Dyn(dyn_node) = node else {
                    return Err(ExecutionError::Internal(
                        "expected dyn node in FinishDyn continuation",
                    ));
                };
                let entry_kind = if dyn_node.is_dyncall() {
                    EndBlockStackEntryKind::CallerFrame
                } else {
                    EndBlockStackEntryKind::Continuation
                };
                Ok(EndBlockFlags::new(is_loop_body, entry_kind))
            },
            Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishExec(_)
            | Continuation::FinishBasicBlock(_) => {
                Ok(EndBlockFlags::new(is_loop_body, EndBlockStackEntryKind::Continuation))
            },
            _ => Err(ExecutionError::Internal(
                "compute_end_block_flags called for non-END continuation",
            )),
        }?;
        let is_root_end = matches!(self.keyed_event, Some(event)
            if event.kind == KeyedEventKind::RootEnd);
        if is_root_end && is_loop_body {
            return Err(ExecutionError::Internal("root END cannot end a loop body"));
        }
        Ok(flags.with_root_end(is_root_end))
    }

    /// Returns the callee hash for a `Dyn` node, or `None` if the continuation is not a
    /// `StartNode` for a `Dyn` node.
    ///
    /// The callee hash is read from the memory reads replay, as `Dyn` nodes read the procedure
    /// hash (as a word) from memory.
    fn get_dyn_callee_hash(
        &self,
        continuation: &Continuation<Arc<SparseMastForest>>,
        processor: &ReplayProcessor,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<Option<Word>, ExecutionError> {
        if let Continuation::StartNode(node_id) = continuation {
            let Some(node) = current_forest.get_node_by_id(*node_id) else {
                return Err(ExecutionError::Internal("invalid node ID stored in continuation"));
            };

            if let MastNode::Dyn(_) = node {
                let word_read = processor
                    .memory_reads_replay
                    .peek_read_word(
                        processor.system.ctx,
                        processor.stack.get(0),
                        processor.system.clk,
                    )
                    .map_err(ExecutionError::MemoryErrorNoCtx)?;
                return Ok(Some(word_read));
            }
        }

        Ok(None)
    }

    fn keyed_cycle(
        &self,
        continuation: &Continuation<Arc<SparseMastForest>>,
        continuation_stack: &ContinuationStack<Arc<SparseMastForest>>,
        processor: &ReplayProcessor,
        forest: &Arc<SparseMastForest>,
    ) -> Result<Option<(KeyedEventKind, ProcedureKey)>, ExecutionError> {
        if let Continuation::StartNode(id) = continuation {
            let mode_and_key = match get_node_in_forest(forest, *id)? {
                MastNode::Exec(node) => Some((KeyedMode::Exec, node.target())),
                MastNode::Call(node) if node.digest_callee().is_none() => Some((
                    if node.is_syscall() {
                        KeyedMode::Syscall
                    } else {
                        KeyedMode::Call
                    },
                    node.target(),
                )),
                MastNode::Dyn(node) if !node.is_digest() => Some((
                    if node.is_dyncall() {
                        KeyedMode::DynCall
                    } else {
                        KeyedMode::Dyn
                    },
                    ProcedureKey::new(
                        self.get_dyn_callee_hash(continuation, processor, forest)?
                            .expect("actual dynamic node has its checked memory word"),
                    ),
                )),
                _ => None,
            };
            return Ok(mode_and_key.map(|(mode, key)| (KeyedEventKind::Invoke(mode), key)));
        }
        if matches!(
            continuation,
            Continuation::FinishBasicBlock(_)
                | Continuation::FinishJoin(_)
                | Continuation::FinishSplit(_)
                | Continuation::FinishExec(_)
                | Continuation::FinishLoop(_)
                | Continuation::FinishCall(_)
                | Continuation::FinishDyn(_)
        ) && !matches!(continuation, Continuation::FinishLoop(_)
            if processor.stack.get(0) == ONE)
        {
            return Ok(continuation_stack
                .root_boundary_after_next()
                .map(|(_, principal)| (KeyedEventKind::RootEnd, principal)));
        }
        Ok(None)
    }
}

// TRACER IMPLEMENTATION
// ================================================================================================

impl Tracer for CoreTraceGenerationTracer<'_> {
    type Processor = ReplayProcessor;
    type Forest = Arc<SparseMastForest>;
    type KeyedReservation = KeyedEvent;

    fn prepare_environment(
        &mut self,
        _descriptor: &crate::ExecutionTarget,
        _entry: crate::SessionBinding,
    ) -> Result<KeyedEvent, ExecutionError> {
        Err(ExecutionError::Internal("fragment replay cannot initialize native environment"))
    }

    fn commit_environment(&mut self, _reservation: KeyedEvent) {
        unreachable!("replay environment is validated before fragment generation")
    }

    fn prepare_environment_completion(
        &mut self,
        _target: crate::ExecutionTarget,
        _session: &crate::ResolutionSession,
    ) -> Result<KeyedEvent, ExecutionError> {
        Err(ExecutionError::Internal("fragment replay cannot capture native environment"))
    }

    fn commit_environment_completion(&mut self, _reservation: KeyedEvent) {
        unreachable!("replay environment is validated before fragment generation")
    }

    fn prepare_keyed_transition(
        &mut self,
        processor: &ReplayProcessor,
        event: &KeyedEvent,
        target: KeyedTarget<'_, Arc<SparseMastForest>>,
        projection: CycleProjection,
    ) -> Result<KeyedEvent, ExecutionError> {
        let record = processor
            .keyed
            .peek()
            .map_err(|_| ExecutionError::Internal("missing validated keyed replay event"))?;
        let forest_id = processor
            .mast_forest_store
            .iter()
            .position(|forest| Arc::ptr_eq(forest, target.forest))
            .and_then(|index| u32::try_from(index).ok())
            .map(crate::mast::MastForestId::from)
            .ok_or(ExecutionError::Internal("keyed target forest is absent from replay store"))?;
        record.matches(*event, forest_id, target.root).map_err(|_| {
            ExecutionError::Internal("keyed replay event differs from actual transition")
        })?;
        if self.keyed_event.is_some()
            || event.use_record.row() != projection.row
            || processor.system.clk != projection.row
            || event.use_record.implementation_root() != target.implementation
            || processor.system.fn_hash != event.principal_before
        {
            return Err(ExecutionError::Internal(
                "keyed event does not match replay row or principal",
            ));
        }
        if self.prepared_keyed_cycle != Some((event.kind, event.use_record.procedure_key()))
            || match event.kind {
                KeyedEventKind::Invoke(KeyedMode::Call | KeyedMode::DynCall) => {
                    event.principal_after != event.use_record.implementation_root().into_word()
                },
                KeyedEventKind::Invoke(_) => event.principal_before != event.principal_after,
                KeyedEventKind::RootEnd => event.principal_after != Word::default(),
            }
        {
            return Err(ExecutionError::Internal("keyed replay event differs from actual mode"));
        }
        Ok(*event)
    }

    fn commit_keyed_transition(&mut self, reservation: KeyedEvent, event: KeyedEvent) {
        debug_assert_eq!(reservation, event);
        self.keyed_event = Some(reservation);
    }

    fn prepare_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        continuation: &Continuation<Arc<SparseMastForest>>,
        continuation_stack: &ContinuationStack<Arc<SparseMastForest>>,
        current_forest: &Arc<SparseMastForest>,
        projection: CycleProjection,
    ) -> Result<(), ExecutionError> {
        if self.error_encountered.is_some() {
            return Err(ExecutionError::Internal("core replay tracer has been invalidated"));
        }
        if projection.row != processor.system.clk
            || projection.row.as_usize().checked_add(1) != Some(projection.next_clock.as_usize())
        {
            return Err(ExecutionError::Internal("core replay projection does not match clock"));
        }
        self.writer.preflight_write_row(self.row_write_index)?;
        let ctx_info =
            self.get_execution_context_for_dyncall(current_forest, continuation, processor)?;
        let dyn_callee_hash = self.get_dyn_callee_hash(continuation, processor, current_forest)?;
        self.preflight_trace_row(continuation, processor, current_forest)?;
        self.prepared_keyed_cycle =
            self.keyed_cycle(continuation, continuation_stack, processor, current_forest)?;
        self.ctx_info = ctx_info;
        self.dyn_callee_hash = dyn_callee_hash;
        Ok(())
    }

    fn start_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        continuation: Continuation<Arc<SparseMastForest>>,
        continuation_stack: &ContinuationStack<Arc<SparseMastForest>>,
        _current_forest: &Arc<SparseMastForest>,
    ) {
        if self.error_encountered.is_some() {
            return;
        }

        let result = (|| -> Result<(), ExecutionError> {
            let event = self.keyed_event;
            if self.prepared_keyed_cycle.take()
                != event.map(|event| (event.kind, event.use_record.procedure_key()))
            {
                return Err(ExecutionError::Internal("row has no matching authenticated event"));
            }
            if let Some(event) = event
                && (event.use_record.row() != processor.system.clk
                    || event.principal_before != processor.system.fn_hash)
            {
                return Err(ExecutionError::Internal("authenticated event belongs to another row"));
            }
            self.finish_loop_condition = self.get_finish_loop_condition(&continuation, processor);

            // For END operations, determine if the ending node is a body of a LOOP by checking
            // whether the next clock-incrementing continuation is a FinishLoop.
            self.is_loop_body = matches!(
                continuation_stack.iter_continuations_for_next_clock().last(),
                Some(Continuation::FinishLoop(_))
            );

            // Store state for finalizing the clock cycle later.
            self.continuation = Some(continuation);

            Ok(())
        })();

        if let Err(e) = result {
            self.error_encountered = Some(e);
        }
    }

    fn finalize_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        op_helper_registers: OperationHelperRegisters,
        current_forest: &Arc<SparseMastForest>,
    ) -> Result<(), ExecutionError> {
        if self.error_encountered.is_some() {
            return Err(ExecutionError::InvalidExecutionState);
        }

        use Continuation::*;

        let result = (|| -> Result<(), ExecutionError> {
            if let Some(event) = self.keyed_event
                && event.principal_after != processor.system.fn_hash
            {
                return Err(ExecutionError::Internal(
                    "keyed replay principal after transition differs from actual mode",
                ));
            }
            let continuation = self.continuation.as_ref().ok_or(ExecutionError::Internal(
                "continuation not stored at start of clock cycle",
            ))?;

            match continuation {
                StartNode(node_id) => {
                    self.decoder_state.replay_node_start(
                        &mut self.block_address_replay,
                        &mut self.block_stack_replay,
                    )?;

                    self.fill_start_row(*node_id, processor, current_forest)?;
                },
                FinishJoin(node_id) => {
                    let node = get_node_in_forest(current_forest, *node_id)?;
                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        node.digest(),
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                FinishSplit(node_id) => {
                    let node = get_node_in_forest(current_forest, *node_id)?;
                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        node.digest(),
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                FinishLoop(node_id) => {
                    let loop_condition = self.finish_loop_condition.take().ok_or(
                        ExecutionError::Internal(
                            "loop condition not stored at start of clock cycle for FinishLoop continuation",
                        ),
                    )?;

                    if loop_condition {
                        // Loop body is about to be re-executed, so fill in a REPEAT row.
                        let MastNode::Loop(loop_node) =
                            get_node_in_forest(current_forest, *node_id)?
                        else {
                            return Err(ExecutionError::Internal(
                                "expected loop node in FinishLoop continuation",
                            ));
                        };
                        let current_addr = self.decoder_state.current_addr;

                        self.fill_loop_repeat_trace_row(
                            &processor.system,
                            &processor.stack,
                            loop_node,
                            current_forest,
                            current_addr,
                        )?;
                    } else {
                        // Loop is finished, so fill in an END row.
                        let node = get_node_in_forest(current_forest, *node_id)?;
                        let flags = self.compute_end_block_flags(continuation, current_forest)?;
                        self.fill_end_trace_row(
                            &processor.system,
                            &processor.stack,
                            node.digest(),
                            flags.to_hasher_state_second_word(),
                        )?;
                    }
                },
                FinishCall(node_id) => {
                    let node = get_node_in_forest(current_forest, *node_id)?;
                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        node.digest(),
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                FinishExec(node_id) => {
                    let node = get_node_in_forest(current_forest, *node_id)?;
                    if !matches!(node, MastNode::Exec(_)) {
                        return Err(ExecutionError::Internal(
                            "expected exec node in FinishExec continuation",
                        ));
                    }
                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        node.digest(),
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                FinishDyn(node_id) => {
                    let node = get_node_in_forest(current_forest, *node_id)?;
                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        node.digest(),
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                    let MastNode::Block(basic_block_node) =
                        get_node_in_forest(current_forest, *node_id)?
                    else {
                        return Err(ExecutionError::Internal(
                            "expected basic block node in ResumeBasicBlock continuation",
                        ));
                    };

                    let mut basic_block_context = BasicBlockContext::new_at_op(
                        basic_block_node,
                        *batch_index,
                        *op_idx_in_batch,
                    )
                    .map_exec_err_no_ctx()?;
                    let current_batch = basic_block_node
                        .op_batches()
                        .get(*batch_index)
                        .ok_or(ExecutionError::Internal("batch index out of bounds"))?;
                    let operation = *current_batch
                        .ops()
                        .get(*op_idx_in_batch)
                        .ok_or(ExecutionError::Internal("op index in batch out of bounds"))?;
                    let (_, op_idx_in_group) = current_batch
                        .op_idx_in_batch_to_group(*op_idx_in_batch)
                        .ok_or(ExecutionError::Internal("invalid op index in batch"))?;

                    self.fill_operation_trace_row(
                        &processor.system,
                        &processor.stack,
                        operation,
                        op_idx_in_group,
                        op_helper_registers.checked_user_op_helpers(self.layout)?,
                        &mut basic_block_context,
                    )?;
                },
                Respan { node_id, batch_index } => {
                    let MastNode::Block(basic_block_node) =
                        get_node_in_forest(current_forest, *node_id)?
                    else {
                        return Err(ExecutionError::Internal(
                            "expected basic block node in Respan continuation",
                        ));
                    };

                    let mut basic_block_context =
                        BasicBlockContext::new_at_batch_start(basic_block_node, *batch_index)
                            .map_exec_err_no_ctx()?;
                    let current_batch = basic_block_node
                        .op_batches()
                        .get(*batch_index)
                        .ok_or(ExecutionError::Internal("batch index out of bounds"))?;

                    self.fill_respan_trace_row(
                        &processor.system,
                        &processor.stack,
                        current_batch,
                        &mut basic_block_context,
                    )?;
                },
                FinishBasicBlock(node_id) => {
                    let MastNode::Block(basic_block_node) =
                        get_node_in_forest(current_forest, *node_id)?
                    else {
                        return Err(ExecutionError::Internal(
                            "expected basic block node in FinishBasicBlock continuation",
                        ));
                    };

                    let flags = self.compute_end_block_flags(continuation, current_forest)?;
                    self.fill_basic_block_end_trace_row(
                        &processor.system,
                        &processor.stack,
                        basic_block_node,
                        flags.to_hasher_state_second_word(),
                    )?;
                },
                EnterForest { .. } | RootBoundary { .. } => {
                    unreachable!(
                        "Tracer contract guarantees that EnterForest continuations do not occur here"
                    )
                },
            }

            self.keyed_event = None;
            Ok(())
        })();

        if let Err(e) = result {
            self.error_encountered = Some(e);
            return Err(ExecutionError::InvalidExecutionState);
        }

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a reference to the node with the given ID from the forest, or an error if not found.
fn get_node_in_forest<F>(forest: &F, node_id: MastNodeId) -> Result<&MastNode, ExecutionError>
where
    F: ExecutableMastForest + ?Sized,
{
    forest
        .get_node_by_id(node_id)
        .ok_or(ExecutionError::Internal("invalid node ID stored in continuation"))
}

/// Returns the digest of the node with the given ID from the forest, or an error if not found.
///
/// Prefer this over [`get_node_in_forest`] when only the digest is needed: on a
/// [`miden_core::mast::SparseMastForest`], digest-only entries are reachable through this path
/// but not through [`get_node_in_forest`].
fn get_digest_in_forest<F>(forest: &F, node_id: MastNodeId) -> Result<Word, ExecutionError>
where
    F: ExecutableMastForest + ?Sized,
{
    forest
        .get_digest_by_id(node_id)
        .ok_or(ExecutionError::Internal("invalid node ID stored in continuation"))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::mast::DynNodeBuilder;

    use super::*;
    use crate::{
        ContextId,
        trace::{
            parallel::CORE_TRACE_WIDTH,
            trace_state::{ExecutionReplay, StackOverflowReplay, StackState, SystemState},
            utils::RowMajorTraceWriter,
        },
    };

    /// Ensures that `get_execution_context_for_dyncall()` correctly populates the
    /// `parent_next_overflow_addr` field of the execution context info when the stack is at
    /// MIN_STACK_DEPTH with a non-empty overflow table replay.
    ///
    /// Scenario: the stack is at MIN_STACK_DEPTH (16), but the `StackOverflowReplay` contains a
    /// pending overflow pop (representing a future pop that will occur as the stack grows beyond
    /// the minimum depth) with a non-zero overflow address. This simulates a state where the
    /// overflow table replay is non-empty, even though the stack is currently at minimum depth. In
    /// this case, `get_execution_context_for_dyncall()` should return execution context info with
    /// `parent_next_overflow_addr` equal to the stack's `last_overflow_addr` (which is ZERO),
    /// rather than peeking at the replay queue and returning the post-pop overflow address from the
    /// future/unrelated overflow pop (which is non-zero).
    #[test]
    fn get_execution_context_for_dyncall_at_min_stack_depth_with_overflow_entries() {
        // Build a MastForest with a single DYNCALL node.
        let mut forest = miden_core::mast::MastForest::new();
        let dyncall_node_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        // Build a sparse forest containing only the visited dyncall node (matching what the
        // execution tracer would produce for this fragment).
        let mut sparse_builder = miden_core::mast::SparseMastForestBuilder::new(Arc::new(forest));
        sparse_builder.record_visit(dyncall_node_id, miden_core::mast::VisitKind::FullVisit);
        let forest = Arc::new(sparse_builder.finalize());

        let continuation = Continuation::StartNode(dyncall_node_id);

        // Create a stack of depth 16 (and hence `last_overflow_addr == ZERO`).
        let stack = StackState::new([ZERO; MIN_STACK_DEPTH], MIN_STACK_DEPTH, ZERO);

        // Place an entry in the overflow replay queue that corresponds to a future pop (once the
        // stack will have grown beyond the minimum depth).
        let overflow_addr_of_future_pop = Felt::new_unchecked(42);
        let mut stack_overflow_replay = StackOverflowReplay::new();
        stack_overflow_replay
            .record_pop_overflow(Felt::new_unchecked(99), overflow_addr_of_future_pop);

        let system = SystemState {
            clk: 0u32.into(),
            ctx: ContextId::root(),
            fn_hash: Word::default(),
            deferred_root: Word::default(),
        };

        let (processor, block_stack_replay, block_address_replay) = ReplayProcessor::from_replay(
            system,
            stack,
            ExecutionReplay {
                stack_overflow: stack_overflow_replay,
                ..ExecutionReplay::default()
            },
            vec![forest.clone()],
            crate::ExecutionOptions::DEFAULT_MAX_STACK_DEPTH,
            1u32.into(),
        );

        let mut buffer = vec![ZERO; CORE_TRACE_WIDTH];
        let writer = RowMajorTraceWriter::new(&mut buffer, CORE_TRACE_WIDTH);

        let tracer = CoreTraceGenerationTracer::new(
            writer,
            DecoderState {
                current_addr: crate::trace::chiplets::layout::LogicalControllerAddress::ABSENT,
                parent_addr: crate::trace::chiplets::layout::LogicalControllerAddress::ABSENT,
            },
            block_address_replay,
            block_stack_replay,
            ChipletsLayout::new(0, 0, 0, 0, 0, 0).unwrap(),
        );

        // Call the method under test.
        let ctx_info = tracer
            .get_execution_context_for_dyncall(&forest, &continuation, &processor)
            .expect("replay should not fail")
            .expect("should return Some for a DYNCALL StartNode continuation");

        // check for bug: When the stack is at MIN_STACK_DEPTH with a non-empty overflow table
        // replay queue, parent_next_overflow_addr should reflect the current overflow state of
        // ZERO; NOT the non-zero overflow address from the future pop in the replay queue (which
        // would indicate an incorrect peek at the replay queue).
        assert_eq!(
            ctx_info.parent_next_overflow_addr, ZERO,
            "parent_next_overflow_addr should be ZERO, reflecting the current overflow state of the stack, \
            and should not reflect the non-zero overflow address from the future pop in the replay queue"
        );
    }
}
