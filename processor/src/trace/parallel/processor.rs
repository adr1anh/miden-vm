use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{
    Felt, WORD_SIZE, Word, ZERO, deferred::Digest, field::PrimeField64, mast::SparseMastForest,
    program::MIN_STACK_DEPTH, utils::range,
};
use miden_mast_package::debug_info::DebugSourceNodeId;

use super::super::trace_state::{
    AdviceReplay, BlockAddressReplay, BlockStackReplay, ExecutionContextReplay, ExecutionReplay,
    HasherResponseReplay, MastForestResolutionReplay, MemoryReadsReplay, StackOverflowReplay,
    StackState, SystemState,
};
use crate::{
    BreakReason, ContextId, CycleProjection, ExecutionError, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{MapExecErrNoCtx, OperationError},
    execution::{
        InternalBreakReason, execute_impl_noop_host, finish_emit_op_execution,
        finish_load_mast_forest_from_external,
    },
    host::default::NoopHost,
    processor::{Processor, StackInterface, SystemInterface},
    tracer::Tracer,
};

// REPLAY PROCESSOR
// ================================================================================================

fn replay_keyed_error(_: crate::trace::keyed::KeyedReplayError) -> ExecutionError {
    ExecutionError::Internal("invalid keyed replay record")
}

/// A processor implementation used in conjunction with the [`CoreTraceGenerationTracer`] in
/// [`super::build_trace`] to replay the execution of a fragment of execution for a predetermined
/// number of clock cycles.
///
/// This processor uses various "replay" structures to provide the necessary state during execution,
/// such as stack overflows, memory reads, advice provider values, hasher responses, execution
/// contexts, and MAST forest resolutions. The processor executes until it reaches the specified
/// maximum clock cycle, at which point it stops execution (due to the [`ReplayStopper`]).
///
/// The replay structures and initial system and stack state are built by the
/// [`crate::trace::execution_tracer::ExecutionTracer`] in conjunction with
/// [`crate::FastProcessor::execute_for_proving`].
#[derive(Debug)]
pub(crate) struct ReplayProcessor {
    pub system: SystemState,
    pub stack: StackState,
    pub stack_overflow_replay: StackOverflowReplay,
    pub execution_context_replay: ExecutionContextReplay,
    pub advice_replay: AdviceReplay,
    pub memory_reads_replay: MemoryReadsReplay,
    pub hasher_response_replay: HasherResponseReplay,
    pub mast_forest_resolution_replay: MastForestResolutionReplay,
    pub keyed: crate::trace::keyed::KeyedReplay,

    /// Per-fragment view of the trace replay's `mast_forest_store`. Used to resolve `usize`
    /// indices recorded in the replays back to [`Arc<SparseMastForest>`] handles
    /// during execution.
    pub mast_forest_store: Vec<Arc<SparseMastForest>>,

    /// The maximum number of field elements allowed on the operand stack in an active execution
    /// context.
    pub max_stack_depth: usize,

    /// The maximum clock cycle at which this processor should stop execution.
    pub maximum_clock: RowIndex,

    /// Failed fragments cannot resume after consuming their authenticated observations.
    invalidated: bool,
}

/// Only the projected caller overflow metadata is needed to prepare a replay context switch.
#[derive(Debug)]
pub(crate) struct ReplayContextStart {
    stack_depth: usize,
    last_overflow_addr: Felt,
}

/// The checked next return record, retained until the shared transition commits.
#[derive(Debug)]
pub(crate) struct ReplayContextRestore {
    stack_depth: usize,
    last_overflow_addr: Felt,
}

/// One checked operand pop and its resulting overflow metadata.
#[derive(Debug)]
pub(crate) struct ReplayStackPop {
    stack_depth: usize,
    overflow: Option<(Felt, Felt)>,
}

/// Saved system registers checked together with the matching stack return token.
#[derive(Debug)]
pub(crate) struct ReplayCallRestore {
    context: ContextId,
    principal: Word,
}

impl ReplayProcessor {
    /// Creates a new instance of the [`ReplayProcessor`].
    ///
    /// The parameters are expected to be built by the
    /// [`crate::trace::execution_tracer::ExecutionTracer`] when used in conjunction with
    /// [`crate::FastProcessor::execute_for_proving`].
    ///
    /// Returns the block-stack and block-address replay queues for the fragment's tracer.
    pub fn from_replay(
        initial_system: SystemState,
        initial_stack: StackState,
        replay: ExecutionReplay,
        mast_forest_store: Vec<Arc<SparseMastForest>>,
        max_stack_depth: usize,
        num_clocks_to_execute: RowIndex,
    ) -> (Self, BlockStackReplay, BlockAddressReplay) {
        let ExecutionReplay {
            keyed,
            block_stack,
            execution_context: execution_context_replay,
            stack_overflow: stack_overflow_replay,
            memory_reads: memory_reads_replay,
            advice: advice_replay,
            hasher: hasher_response_replay,
            block_address,
            mast_forest_resolution: mast_forest_resolution_replay,
        } = replay;
        let maximum_clock = initial_system.clk + num_clocks_to_execute.as_usize();

        (
            Self {
                system: initial_system,
                stack: initial_stack,
                stack_overflow_replay,
                execution_context_replay,
                advice_replay,
                memory_reads_replay,
                hasher_response_replay,
                mast_forest_resolution_replay,
                keyed,
                mast_forest_store,
                max_stack_depth,
                maximum_clock,
                invalidated: false,
            },
            block_stack,
            block_address,
        )
    }

    /// Executes the processor until it reaches the end of the fragment, or until an error occurs.
    pub fn execute<T>(
        &mut self,
        continuation_stack: &mut ContinuationStack<Arc<SparseMastForest>>,
        current_forest: &mut Arc<SparseMastForest>,
        tracer: &mut T,
    ) -> Result<(), ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<SparseMastForest>>,
    {
        if self.invalidated {
            return Err(ExecutionError::InvalidExecutionState);
        }
        let result = match self.execute_impl(continuation_stack, current_forest, tracer) {
            ControlFlow::Continue(_) => {
                // End of program reached - i.e. the execution loop exited without the end of
                // fragment being reached (and thus the stopper breaking).
                Ok(())
            },
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(_continuation) => {
                    // Our ReplayStopper stopped us because we reached the end of the fragment.
                    // Hence, this is expected, and we can just return Ok.
                    Ok(())
                },
            },
        };
        if let Err(error) = result {
            self.invalidated = true;
            return Err(error);
        }
        if !self.keyed.is_empty() {
            self.invalidated = true;
            return Err(ExecutionError::Internal("unused keyed replay events in fragment"));
        }
        Ok(())
    }

    /// Core execution loop implementation for the replay processor.
    ///
    /// This method uses the [`crate::execution::execute_impl`] function to perform the core
    /// execution loop. See its documentation for more details.
    fn execute_impl<T>(
        &mut self,
        continuation_stack: &mut ContinuationStack<Arc<SparseMastForest>>,
        current_forest: &mut Arc<SparseMastForest>,
        tracer: &mut T,
    ) -> ControlFlow<BreakReason<Arc<SparseMastForest>>>
    where
        T: Tracer<Processor = Self, Forest = Arc<SparseMastForest>>,
    {
        let host = &mut NoopHost;
        let stopper = &ReplayStopper;
        let mut package_debug_info = None;
        // Loaded package owners are native state and never enter replay projections.
        let mut loaded_owner = None;
        let mut inline_call_contexts = Vec::new();

        while let ControlFlow::Break(internal_break_reason) = execute_impl_noop_host(
            self,
            continuation_stack,
            current_forest,
            host,
            tracer,
            stopper,
            &mut package_debug_info,
            &mut loaded_owner,
            &mut inline_call_contexts,
        ) {
            match internal_break_reason {
                InternalBreakReason::ResolveKey(request) => {
                    let result = (|| -> Result<_, ExecutionError> {
                        let record = self.keyed.peek().map_err(replay_keyed_error)?;
                        let event = record.event().map_err(replay_keyed_error)?;
                        if event.kind != crate::KeyedEventKind::Invoke(request.mode)
                            || event.use_record.procedure_key() != request.key()
                            || event.use_record.row() != request.row
                            || event.principal_before != self.system.fn_hash
                            || match request.mode {
                                crate::KeyedMode::Call | crate::KeyedMode::DynCall => {
                                    event.principal_after
                                        != event.use_record.implementation_root().into_word()
                                },
                                _ => event.principal_before != event.principal_after,
                            }
                        {
                            return Err(ExecutionError::Internal(
                                "invocation differs from keyed replay event",
                            ));
                        }
                        let target = crate::execution::LoadedTarget {
                            implementation: event.use_record.implementation_root(),
                            root: record.target_root(),
                            forest: super::lookup_mast_forest(
                                &self.mast_forest_store,
                                record.target_forest(),
                            )?
                            .clone(),
                            package_debug_info: None,
                            loaded_owner: None,
                            source_node_id: None,
                        };
                        let mut state = crate::execution::ExecutionState {
                            processor: self,
                            continuation_stack: &mut *continuation_stack,
                            host: &mut *host,
                            tracer: &mut *tracer,
                            stopper,
                            source_debug_info: None,
                            loaded_owner: &mut loaded_owner,
                            current_source_node_id: request.source_node_id,
                            inline_call_contexts: &mut inline_call_contexts,
                        };
                        let prepared = crate::execution::preflight_invocation(
                            &mut state,
                            current_forest,
                            request,
                            &target,
                        )?;
                        let reservation = state.tracer.prepare_keyed_transition(
                            state.processor,
                            &event,
                            crate::KeyedTarget {
                                forest: &target.forest,
                                root: target.root,
                                implementation: target.implementation,
                            },
                            prepared.projection,
                        )?;
                        state.processor.keyed.pop_front().map_err(replay_keyed_error)?;
                        Ok(crate::execution::finish_invocation(
                            &mut state,
                            current_forest,
                            request,
                            target,
                            prepared,
                            Some((event, reservation)),
                        ))
                    })();
                    match result {
                        Ok(flow) => flow?,
                        Err(error) => return ControlFlow::Break(BreakReason::Err(error)),
                    }
                },
                InternalBreakReason::ResolveDigest(request) => {
                    let result = (|| -> Result<_, ExecutionError> {
                        let crate::execution::InvocationTarget::Digest { implementation, callee } =
                            request.target
                        else {
                            unreachable!("digest replay requires a digest target");
                        };
                        let (root, forest) = if let Some(callee) = callee {
                            (callee, current_forest.clone())
                        } else {
                            let (root, id) =
                                self.mast_forest_resolution_replay.replay_resolution()?;
                            (root, super::lookup_mast_forest(&self.mast_forest_store, id)?.clone())
                        };
                        let target = crate::execution::LoadedTarget {
                            implementation,
                            root,
                            forest,
                            package_debug_info: None,
                            loaded_owner: None,
                            source_node_id: None,
                        };
                        let mut state = crate::execution::ExecutionState {
                            processor: self,
                            continuation_stack: &mut *continuation_stack,
                            host: &mut *host,
                            tracer: &mut *tracer,
                            stopper,
                            source_debug_info: None,
                            loaded_owner: &mut loaded_owner,
                            current_source_node_id: request.source_node_id,
                            inline_call_contexts: &mut inline_call_contexts,
                        };
                        let prepared = crate::execution::preflight_invocation(
                            &mut state,
                            current_forest,
                            request,
                            &target,
                        )?;
                        Ok(crate::execution::finish_invocation(
                            &mut state,
                            current_forest,
                            request,
                            target,
                            prepared,
                            None,
                        ))
                    })();
                    match result {
                        Ok(flow) => flow?,
                        Err(error) => return ControlFlow::Break(BreakReason::Err(error)),
                    }
                },
                InternalBreakReason::RootEnd(request) => {
                    let result = (|| -> Result<_, ExecutionError> {
                        let record = self.keyed.peek().map_err(replay_keyed_error)?;
                        let event = record.event().map_err(replay_keyed_error)?;
                        let root = request
                            .continuation
                            .exec_node()
                            .ok_or(ExecutionError::Internal("root END has no node"))?;
                        if event.kind != crate::KeyedEventKind::RootEnd
                            || event.use_record.row() != request.row
                            || event.use_record.implementation_root() != request.implementation
                            || event.use_record.procedure_key() != request.entry_key
                            || event.principal_before != self.system.fn_hash
                            || event.principal_after != Word::default()
                            || record.target_root() != root
                            || !Arc::ptr_eq(
                                current_forest,
                                super::lookup_mast_forest(
                                    &self.mast_forest_store,
                                    record.target_forest(),
                                )?,
                            )
                        {
                            return Err(ExecutionError::Internal(
                                "root END differs from keyed replay event",
                            ));
                        }
                        let mut state = crate::execution::ExecutionState {
                            processor: self,
                            continuation_stack: &mut *continuation_stack,
                            host: &mut *host,
                            tracer: &mut *tracer,
                            stopper,
                            source_debug_info: None,
                            loaded_owner: &mut loaded_owner,
                            current_source_node_id: request.source_node_id,
                            inline_call_contexts: &mut inline_call_contexts,
                        };
                        let prepared = crate::execution::preflight_root_end(
                            &mut state,
                            current_forest,
                            &request,
                        )?;
                        let reservation = state.tracer.prepare_keyed_transition(
                            state.processor,
                            &event,
                            crate::KeyedTarget {
                                forest: current_forest,
                                root,
                                implementation: request.implementation,
                            },
                            prepared.projection,
                        )?;
                        state.processor.keyed.pop_front().map_err(replay_keyed_error)?;
                        let flow = crate::execution::finish_root_end(
                            &mut state,
                            current_forest,
                            request,
                            prepared,
                            event,
                            reservation,
                        );
                        if let ControlFlow::Break(BreakReason::Err(error)) = flow {
                            return Err(error);
                        }
                        let completed_clock = event
                            .use_record
                            .row()
                            .as_u32()
                            .checked_add(1)
                            .map(RowIndex::from)
                            .ok_or(ExecutionError::InvalidExecutionState)?;
                        if state.processor.system.clk != completed_clock
                            || !state.continuation_stack.iter_with_source_node_ids().all(
                                |(continuation, _)| {
                                    matches!(continuation, Continuation::EnterForest { .. })
                                },
                            )
                        {
                            return Err(ExecutionError::Internal(
                                "root END did not terminate the replay activation",
                            ));
                        }
                        // Only transparent forest restorations may follow the authenticated END.
                        // Apply them without starting another clock cycle, then finish replay.
                        while let Some(continuation) = state.continuation_stack.pop_continuation() {
                            let Continuation::EnterForest {
                                forest,
                                loaded_owner: owner,
                                inline_context_depth,
                                ..
                            } = continuation
                            else {
                                unreachable!(
                                    "root completion checked every remaining continuation"
                                );
                            };
                            *current_forest = forest;
                            *state.loaded_owner = owner;
                            state.inline_call_contexts.truncate(inline_context_depth);
                        }
                        Ok(ControlFlow::Continue(()))
                    })();
                    match result {
                        Ok(flow) => return flow,
                        Err(error) => return ControlFlow::Break(BreakReason::Err(error)),
                    }
                },
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit { op_idx: _, continuation, source_node_id } => {
                    // do nothing - in replay processor we don't need to emit anything

                    // Call `finish_emit_op_execution()`, as per the sans-IO contract.
                    finish_emit_op_execution(
                        continuation,
                        source_node_id,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                    source_node_id: _,
                } => {
                    // load mast forest from replay
                    let (root_id, new_forest_id) =
                        match self.mast_forest_resolution_replay.replay_resolution() {
                            Ok(v) => v,
                            Err(err) => {
                                return ControlFlow::Break(BreakReason::Err(err));
                            },
                        };
                    let new_forest =
                        match super::lookup_mast_forest(&self.mast_forest_store, new_forest_id) {
                            Ok(f) => f.clone(),
                            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                        };

                    // Finish loading the MAST forest from the External node, as per the sans-IO
                    // contract.
                    finish_load_mast_forest_from_external(
                        crate::execution::LoadedTarget {
                            implementation: miden_core::program::ImplementationRoot::new(
                                procedure_hash,
                            ),
                            root: root_id,
                            forest: new_forest,
                            package_debug_info: None,
                            loaded_owner: None,
                            source_node_id: None,
                        },
                        None,
                        (external_node_id, None),
                        current_forest,
                        &mut package_debug_info,
                        &mut loaded_owner,
                        &mut inline_call_contexts,
                        continuation_stack,
                        tracer,
                    )?;
                },
            }
        }

        // End of program reached (since loop exited without the stopper breaking)
        ControlFlow::Continue(())
    }
}

impl SystemInterface for ReplayProcessor {
    type CallRestore = ReplayCallRestore;

    fn caller_hash(&self) -> Word {
        self.system.fn_hash
    }

    fn clock(&self) -> RowIndex {
        self.system.clk
    }

    fn ctx(&self) -> ContextId {
        self.system.ctx
    }

    fn deferred_root(&self) -> Word {
        self.system.deferred_root
    }

    fn set_caller_hash(&mut self, caller_hash: Word) {
        self.system.fn_hash = caller_hash;
    }

    fn set_ctx(&mut self, ctx: ContextId) {
        self.system.ctx = ctx;
    }

    fn increment_clock(&mut self) {
        self.system.clk += 1_u32;
    }

    fn log_deferred_statement(
        &mut self,
        _statement_digest: Digest,
        expected_new_root: Word,
    ) -> Result<(), OperationError> {
        self.system.deferred_root = expected_new_root;
        Ok(())
    }

    fn save_call_state(&mut self) {
        // no-op for the replay processor: the system call state was already recorded by the
        // tracer into `execution_context_replay` during the original execution.
    }

    fn prepare_save_call_state(&mut self) -> Result<(), ExecutionError> {
        // Replay reads saved frames at END. Invocation and row checks happen before this point.
        Ok(())
    }

    fn prepare_restore_call_state(&self) -> Result<Self::CallRestore, OperationError> {
        let saved = self.execution_context_replay.peek_execution_context()?;
        Ok(ReplayCallRestore {
            context: saved.parent_ctx,
            principal: saved.parent_fn_hash,
        })
    }

    fn restored_caller_hash(prepared: &Self::CallRestore) -> Word {
        prepared.principal
    }

    fn commit_restore_call_state(&mut self, prepared: Self::CallRestore) {
        self.execution_context_replay.commit_execution_context();
        self.system.ctx = prepared.context;
        self.system.fn_hash = prepared.principal;
    }
}

#[inline(always)]
fn stack_word_start_idx(stack_len: usize, start_idx: usize) -> usize {
    stack_len - start_idx - WORD_SIZE
}

impl StackInterface for ReplayProcessor {
    type ContextStart = ReplayContextStart;
    type ContextRestore = ReplayContextRestore;
    type StackPop = ReplayStackPop;

    fn top(&self) -> &[Felt] {
        &self.stack.stack_top
    }

    fn get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx + WORD_SIZE <= MIN_STACK_DEPTH);

        let word_start_idx = stack_word_start_idx(MIN_STACK_DEPTH, start_idx);
        let mut result: [Felt; WORD_SIZE] =
            self.top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap();
        // Reverse so top of stack (idx 0) goes to word[0]
        result.reverse();
        result.into()
    }

    fn depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.stack.num_overflow_elements_in_current_ctx()) as u32
    }

    fn set(&mut self, idx: usize, element: Felt) {
        *self.get_mut(idx) = element;
    }

    fn set_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx + WORD_SIZE <= MIN_STACK_DEPTH);
        let word_start_idx = stack_word_start_idx(MIN_STACK_DEPTH, start_idx);

        // Reverse so word[0] ends up at the top of stack (highest internal index)
        let mut source: [Felt; WORD_SIZE] = (*word).into();
        source.reverse();

        let word_on_stack = &mut self.stack.stack_top[range(word_start_idx, WORD_SIZE)];
        word_on_stack.copy_from_slice(&source);
    }

    fn swap(&mut self, idx1: usize, idx2: usize) {
        let a = self.get(idx1);
        let b = self.get(idx2);
        self.set(idx1, b);
        self.set(idx2, a);
    }

    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) =
            self.stack.stack_top.split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.stack.stack_top[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack.stack_top[rotation_bot_index + i] =
                self.stack.stack_top[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.set(0, new_stack_top_element);
    }

    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.stack.stack_top[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack.stack_top[MIN_STACK_DEPTH - i] =
                self.stack.stack_top[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack.stack_top[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_size(&mut self) -> Result<(), ExecutionError> {
        const SENTINEL_VALUE: Felt = Felt::new_unchecked(Felt::ORDER_U64 - 1);

        let depth = self.depth() as usize + 1;
        let max = self.max_stack_depth;
        if depth > max {
            return Err(ExecutionError::StackDepthLimitExceeded { depth, max });
        }

        // push the last element on the overflow table
        {
            let last_element = self.get(MIN_STACK_DEPTH - 1);
            self.stack.push_overflow(last_element, self.clock());
        }

        // Shift all other elements down
        for write_idx in (1..MIN_STACK_DEPTH).rev() {
            let read_idx = write_idx - 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Set the top element to SENTINEL_VALUE to help in debugging. Per the method docs, this
        // value will be overwritten
        self.set(0, SENTINEL_VALUE);

        Ok(())
    }

    fn preflight_decrement_size(&self) -> Result<(), OperationError> {
        self.prepare_decrement_size().map(|_| ())
    }

    fn decrement_size(&mut self) -> Result<(), OperationError> {
        let prepared = self.prepare_decrement_size()?;
        self.commit_decrement_size(prepared);
        Ok(())
    }

    fn prepare_decrement_size(&self) -> Result<Self::StackPop, OperationError> {
        let depth = self.stack.stack_depth();
        if depth > MIN_STACK_DEPTH {
            let overflow = self
                .stack_overflow_replay
                .peek_replay_pop_overflow()
                .copied()
                .ok_or(OperationError::Internal("no stack overflow pop recorded"))?;
            Ok(ReplayStackPop {
                stack_depth: depth - 1,
                overflow: Some(overflow),
            })
        } else {
            Ok(ReplayStackPop {
                stack_depth: MIN_STACK_DEPTH,
                overflow: None,
            })
        }
    }

    fn commit_decrement_size(&mut self, prepared: Self::StackPop) {
        // Shift all other elements up
        for write_idx in 0..(MIN_STACK_DEPTH - 1) {
            let read_idx = write_idx + 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Pop the last element from the overflow table
        let overflow_addr = if let Some((last_element, overflow_addr)) = prepared.overflow {
            self.stack_overflow_replay.commit_pop_overflow();
            self.set(MIN_STACK_DEPTH - 1, last_element);
            overflow_addr
        } else {
            self.set(MIN_STACK_DEPTH - 1, ZERO);
            ZERO
        };
        self.stack.set_prepared_overflow_state(prepared.stack_depth, overflow_addr);
    }

    fn prepare_start_context(
        &mut self,
        drop_top: bool,
    ) -> Result<Self::ContextStart, ExecutionError> {
        let mut stack_depth = self.stack.stack_depth();
        let mut last_overflow_addr = self.stack.overflow_addr();
        if drop_top {
            let pop = self.prepare_decrement_size().map_exec_err_no_ctx()?;
            stack_depth = pop.stack_depth;
            last_overflow_addr = pop.overflow.map_or(ZERO, |(_, address)| address);
        }
        Ok(ReplayContextStart { stack_depth, last_overflow_addr })
    }

    fn commit_start_context(&mut self, prepared: Self::ContextStart) {
        assert_eq!(self.stack.stack_depth(), prepared.stack_depth);
        assert_eq!(self.stack.overflow_addr(), prepared.last_overflow_addr);
        self.stack.start_context();
    }

    fn prepare_restore_context(&self) -> Result<Self::ContextRestore, ExecutionError> {
        if self.stack.stack_depth() != MIN_STACK_DEPTH {
            return Err(OperationError::InvalidStackDepthOnReturn {
                depth: self.stack.stack_depth(),
            })
            .map_exec_err_no_ctx();
        }
        let (stack_depth, last_overflow_addr) =
            self.stack_overflow_replay.peek_restore_context().map_exec_err_no_ctx()?;
        if stack_depth < MIN_STACK_DEPTH || stack_depth > self.max_stack_depth {
            return Err(ExecutionError::Internal("invalid saved replay stack depth"));
        }
        if stack_depth == MIN_STACK_DEPTH && last_overflow_addr != ZERO {
            return Err(ExecutionError::Internal("empty saved replay stack has overflow address"));
        }
        Ok(ReplayContextRestore { stack_depth, last_overflow_addr })
    }

    fn commit_restore_context(&mut self, prepared: Self::ContextRestore) {
        self.stack_overflow_replay.commit_restore_context();
        self.stack
            .set_prepared_overflow_state(prepared.stack_depth, prepared.last_overflow_addr);
    }

    fn restored_context_depth(prepared: &Self::ContextRestore) -> usize {
        prepared.stack_depth
    }
}

impl Processor for ReplayProcessor {
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceReplay;
    type Memory = MemoryReadsReplay;
    type Hasher = HasherResponseReplay;

    fn stack(&self) -> &Self::Stack {
        self
    }

    fn stack_mut(&mut self) -> &mut Self::Stack {
        self
    }

    fn system(&self) -> &Self::System {
        self
    }

    fn system_mut(&mut self) -> &mut Self::System {
        self
    }

    fn advice_provider(&self) -> &Self::AdviceProvider {
        &self.advice_replay
    }

    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        &mut self.advice_replay
    }

    fn memory_mut(&mut self) -> &mut Self::Memory {
        &mut self.memory_reads_replay
    }

    fn hasher(&mut self) -> &mut Self::Hasher {
        &mut self.hasher_response_replay
    }
}

// REPLAY STOPPER
// ================================================================================================

/// A stopper implementation used with the [`ReplayProcessor`] to stop execution when the end of the
/// fragment is reached.
#[derive(Debug)]
pub(crate) struct ReplayStopper;

impl Stopper for ReplayStopper {
    type Processor = ReplayProcessor;
    type Forest = Arc<SparseMastForest>;

    fn preflight_cycle(
        &self,
        processor: &ReplayProcessor,
        projection: CycleProjection,
    ) -> Result<(), ExecutionError> {
        if projection.row != processor.system.clk || projection.next_clock > processor.maximum_clock
        {
            return Err(ExecutionError::Internal("replay cycle exceeds fragment clock boundary"));
        }
        Ok(())
    }

    fn should_stop(
        &self,
        processor: &ReplayProcessor,
        _continuation_stack: &ContinuationStack<Arc<SparseMastForest>>,
        continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Arc<SparseMastForest>>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Arc<SparseMastForest>>> {
        if processor.system().clock() >= processor.maximum_clock {
            ControlFlow::Break(BreakReason::Stopped(continuation_after_stop()))
        } else {
            ControlFlow::Continue(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::trace_state::{ExecutionReplay, StackState, SystemState};

    fn build_replay_processor() -> ReplayProcessor {
        let system = SystemState {
            clk: 0_u32.into(),
            ctx: ContextId::root(),
            fn_hash: Word::default(),
            deferred_root: Word::default(),
        };
        let stack = StackState::new([ZERO; MIN_STACK_DEPTH], MIN_STACK_DEPTH, ZERO);

        let (processor, ..) = ReplayProcessor::from_replay(
            system,
            stack,
            ExecutionReplay::default(),
            Vec::new(),
            MIN_STACK_DEPTH,
            1_u32.into(),
        );
        processor
    }

    #[test]
    fn stack_set_word_allows_max_start_idx() {
        let mut processor = build_replay_processor();
        let start_idx = MIN_STACK_DEPTH - WORD_SIZE;
        let word = Word::from([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);

        processor.set_word(start_idx, &word);

        assert_eq!(processor.get_word(start_idx), word);
    }
}
