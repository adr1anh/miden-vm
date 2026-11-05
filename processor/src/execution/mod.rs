use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::program::{ImplementationRoot, ProcedureKey};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, BreakReason, ContextId, ExecutionError, Felt, MapExecErr, Stopper, Word,
    continuation_stack::{Continuation, ContinuationStack, SourceInlineCallContext},
    errors::PackageSourceDebugContext,
    host::{LoadedMastForest, default::NoopHost},
    mast::{ExecutableMastForest, MastNode, MastNodeExt, MastNodeId},
    operation::OperationError,
    option_map_break_reason,
    processor::{MemoryInterface, Processor, StackInterface, SystemInterface},
    tracer::{
        CycleProjection, KeyedEvent, KeyedEventKind, KeyedMode, OperationHelperRegisters, Tracer,
    },
};

mod basic_block;
mod call;
mod r#dyn;
mod exec;
mod external;
mod join;
mod r#loop;
mod operations;
mod split;

// RE-EXPORTS
// ================================================================================================
pub(crate) use basic_block::finish_emit_op_execution;
pub(crate) use exec::{finish_keyed_invocation, preflight_keyed_invocation};
pub(crate) use external::finish_load_mast_forest_from_external;
#[cfg(test)]
pub(crate) use operations::eval_circuit_impl;
use operations::execute_op;

/// A retained keyed invocation selected before any continuation or tracer mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyedRequest {
    pub key: ProcedureKey,
    pub mode: KeyedMode,
    pub node_id: MastNodeId,
    pub source_node_id: Option<DebugSourceNodeId>,
    pub row: RowIndex,
    pub dynamic: Option<DynamicKey>,
}

/// The exact memory observation selecting a dynamic ProcedureKey, retained across host waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DynamicKey {
    pub context: ContextId,
    pub address: Felt,
    pub value: Word,
}

#[derive(Debug, Clone)]
pub(crate) struct RootEndRequest<F> {
    pub continuation: Continuation<F>,
    pub implementation: ImplementationRoot,
    pub principal: ProcedureKey,
    pub row: RowIndex,
    pub source_node_id: Option<DebugSourceNodeId>,
}

/// Root completion retains every component needed for the actual final END row.
pub(crate) struct PreparedRootEnd<P: Processor> {
    pub projection: CycleProjection,
    return_context: Option<call::PreparedReturn<P>>,
    loop_pop: Option<<P::Stack as StackInterface>::StackPop>,
}

/// Code supply validated against an expected implementation root.
///
/// Keyed invocation authenticates this root; structural External materialization checks requested
/// D.
#[derive(Debug)]
pub(crate) struct LoadedTarget<F> {
    pub implementation: ImplementationRoot,
    pub root: MastNodeId,
    pub forest: F,
    pub package_debug_info: Option<Arc<PackageDebugInfo>>,
    pub loaded_owner: Option<LoadedMastForest>,
    pub source_node_id: Option<DebugSourceNodeId>,
}

// EXECUTION STATE
// ================================================================================================

/// Bundles the common state threaded through all execution functions.
///
/// Note: `current_forest` is intentionally excluded from this struct. Including it would prevent
/// passing node references (obtained from the forest) alongside `&mut ExecutionState` to
/// functions, since both would borrow the same struct.
pub(crate) struct ExecutionState<'a, P, H, S, T, F> {
    pub processor: &'a mut P,
    pub continuation_stack: &'a mut ContinuationStack<F>,
    pub host: &'a mut H,
    pub tracer: &'a mut T,
    pub stopper: &'a S,
    pub source_debug_info: Option<Arc<PackageDebugInfo>>,
    pub loaded_owner: &'a mut Option<LoadedMastForest>,
    pub current_source_node_id: Option<DebugSourceNodeId>,
    pub inline_call_contexts: &'a mut Vec<Option<SourceInlineCallContext>>,
}

impl<'a, P, H: BaseHost, S, T, F> ExecutionState<'a, P, H, S, T, F> {
    pub fn current_source_node_id(&self) -> Option<DebugSourceNodeId> {
        self.current_source_node_id
    }

    pub fn current_inline_call_context(&self) -> Option<SourceInlineCallContext> {
        SourceInlineCallContext::for_source_boundary(
            self.source_debug_info.clone()?,
            self.current_source_node_id,
        )
    }

    pub fn child_source_node_id(
        &self,
        child_index: usize,
    ) -> Result<Option<DebugSourceNodeId>, ExecutionError> {
        let Some(source_debug_info) = &self.source_debug_info else {
            return Ok(None);
        };
        let Some(current_source_node_id) = self.current_source_node_id else {
            return Ok(None);
        };

        Ok(source_debug_info
            .child_source_node(current_source_node_id, child_index)
            .map_err(|_| {
                ExecutionError::Internal(
                    "package debug source graph has malformed child references",
                )
            })?
            .map(|(source_node_id, _)| source_node_id))
    }

    pub fn package_source_context(&self) -> Option<PackageSourceDebugContext<'_>> {
        Some(PackageSourceDebugContext::new_optional(
            self.source_debug_info.as_deref()?,
            self.current_source_node_id,
        ))
    }

    pub fn operation_error_with_current_context(&self, err: OperationError) -> ExecutionError {
        match self.package_source_context() {
            Some(context) => err.with_package_source_context(context, self.host, None),
            None => err.with_context(),
        }
    }
}

// MAIN EXECUTION FUNCTION
// ================================================================================================

/// Executes the main execution loop given an abstract processor until a break condition is met.
///
/// By "main execution loop", we mean the loop that fetches the top continuation from the provided
/// continuation stack, executes it (possibly pushing new continuations onto the stack), and checks
/// the stopper after each clock cycle to see whether execution should stop. Execution is complete
/// when `ControlFlow::Continue` is returned, at which point the implementing processor can inspect
/// the final state of the processor and/or tracer.
///
/// # Tracing
///
/// Different processor implementations will need to record different pieces of information as the
/// the program is executed. For example, the [`crate::FastProcessor::execute_for_proving`]
/// execution mode needs to build a private trace replay which records information necessary to
/// build the trace at each clock cycle, while the
/// [`crate::parallel::core_trace_fragment::CoreTraceFragmentFiller`] needs to build the trace
/// essentially by recording the processor state at each clock cycle. For this purpose, the
/// [`Self::execute_impl`] method takes in [`Tracer`] argument that abstracts away the "information
/// recording" logic (or "tracing") for each processor implementation. Note that the same processor
/// implementation is also free to use different tracers for different execution modes.
///
/// # Stopping
///
/// Execution can be stopped at any clock cycle based on user-defined conditions. For this purpose,
/// the [`Self::execute_impl`] method takes in a [`Stopper`] argument that is queried after each
/// clock cycle to determine whether execution should stop. This is useful for implementing stepping
/// modes (e.g., step-by-step execution), or executing a predetermined number of clock cycles (e.g.,
/// in trace generation, where separate trace fragments are generated concurrently).
///
/// # Sans-IO
///
/// In addition to the stopper, execution can also be interrupted by operations that may require
/// asynchronous execution outside of the main loop. We refer to this general pattern as "sans-IO".
/// Each such operation has their own [`InternalBreakReason`] enum variant, and a corresponding
/// "finish" function (e.g., [`finish_emit_op_execution`] for the `Emit` break reason) that must be
/// called to complete the execution of the operation after the main loop has been interrupted, and
/// before calling [`Self::execute_impl`] again.
///
/// In pseudo-code, the general pattern when implementing program execution in a processor is as
/// follows:
///
/// ```ignore
/// let mut continuation_stack = ...;
/// let mut current_forest = ...;
/// let mut host = ...;
/// let mut tracer = ...;
/// let stopper = ...;
///
/// while let ControlFlow::Break(internal_break_reason) = self.execute_impl() {
///     match internal_break_reason {
///         InternalBreakReason::User(reason) => {
///             // Handle user-initiated break (e.g., propagate break reason)
///         },
///         InternalBreakReason::Emit { op_idx, continuation, source_node_id } => {
///             // Handle Emit operation (e.g., call `SyncHost::on_event`)
///             self.op_emit(...);
///
///             // As per `InternalBreakReason::Emit` documentation, we call `finish_emit_op_execution`
///             // to complete the execution of the Emit operation.
///             finish_emit_op_execution(...);
///         },
///         InternalBreakReason::ResolveKey(request) => {
///             // Authenticate (R_E, K), authorize actual SYSCALL, then prepare D-indexed code.
///             let (target, event, reservation) = self.resolve_and_prepare(request);
///             let prepared = preflight_keyed_invocation(...);
///             finish_keyed_invocation(..., prepared, event, reservation);
///         },
///         InternalBreakReason::RootEnd(request) => {
///             // Prepare the retained actual END and its reserved entry demand before commit.
///             let prepared = preflight_root_end(...);
///             finish_root_end(..., prepared, event, reservation);
///         },
///         InternalBreakReason::LoadMastForestFromExternal { external_node_id, procedure_hash } => {
///             // load MAST forest containing the callee procedure
///             let (procedure_id, new_forest) = self.load_mast_forest(...);
///
///             // As per `InternalBreakReason::LoadMastForestFromExternal` documentation, we call
///             // `finish_load_mast_forest_from_external_start` to complete the execution of the operation.
///             finish_load_mast_forest_from_external_start(...);
///         },
///     }
/// }
/// ```
pub(crate) fn execute_impl<P, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    mut host: &mut dyn BaseHost,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    loaded_owner: &mut Option<LoadedMastForest>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    execute_impl_inner(
        processor,
        continuation_stack,
        current_forest,
        &mut host,
        tracer,
        stopper,
        source_debug_info,
        loaded_owner,
        inline_call_contexts,
    )
}

pub(crate) fn execute_impl_noop_host<P, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    host: &mut NoopHost,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    loaded_owner: &mut Option<LoadedMastForest>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    execute_impl_inner(
        processor,
        continuation_stack,
        current_forest,
        host,
        tracer,
        stopper,
        source_debug_info,
        loaded_owner,
        inline_call_contexts,
    )
}

fn execute_impl_inner<P, H, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    loaded_owner: &mut Option<LoadedMastForest>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    if source_debug_info.is_none() && !continuation_stack.tracks_source_nodes() {
        execute_impl_pure(
            processor,
            continuation_stack,
            current_forest,
            host,
            tracer,
            stopper,
            loaded_owner,
            inline_call_contexts,
        )
    } else {
        execute_impl_with_source(
            processor,
            continuation_stack,
            current_forest,
            host,
            tracer,
            stopper,
            source_debug_info,
            loaded_owner,
            inline_call_contexts,
        )
    }
}

#[inline(never)]
fn execute_impl_with_source<P, H, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    loaded_owner: &mut Option<LoadedMastForest>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    let mut state = ExecutionState {
        processor,
        continuation_stack,
        host,
        tracer,
        stopper,
        source_debug_info: source_debug_info.clone(),
        loaded_owner,
        current_source_node_id: None,
        inline_call_contexts,
    };

    while state.continuation_stack.peek_continuation().is_some() {
        if let Some(request) = next_keyed_transition(&mut state, current_forest)
            .map_err(|err| InternalBreakReason::User(BreakReason::Err(err)))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)?
        {
            return ControlFlow::Break(request);
        }
        let mut prepared_return = match preflight_next_end(&mut state, current_forest) {
            Ok(prepared) => prepared,
            Err(err) => {
                return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(err)));
            },
        };
        let (continuation, source_node_id) = state
            .continuation_stack
            .pop_continuation_with_source_node_id()
            .expect("peeked continuation exists");
        state.current_source_node_id = source_node_id;
        match continuation {
            Continuation::StartNode(node_id) => {
                let node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id),
                    "node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                match node {
                    MastNode::Block(basic_block_node) => {
                        basic_block::execute_basic_block_node_from_start(
                            &mut state,
                            basic_block_node,
                            node_id,
                            current_forest,
                        )?
                    },
                    MastNode::Join(join_node) => {
                        join::start_join_node(&mut state, join_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Split(split_node) => {
                        split::start_split_node(&mut state, split_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Loop(loop_node) => {
                        r#loop::start_loop_node(&mut state, loop_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Exec(_) | MastNode::Call(_) | MastNode::Dyn(_) => {
                        unreachable!("keyed invocation dispatch retains its StartNode")
                    },
                    MastNode::External(_) => external::execute_external_node(
                        node_id,
                        state.current_source_node_id(),
                        current_forest,
                        state.tracer,
                    )?,
                }
            },
            Continuation::FinishJoin(node_id) => {
                join::finish_join_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishSplit(node_id) => {
                split::finish_split_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishLoop(node_id) => {
                r#loop::finish_loop_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishExec(node_id) => {
                exec::finish_exec_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::RootBoundary { .. } => {
                return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(
                    ExecutionError::Internal("entry boundary reached without its actual root END"),
                )));
            },
            Continuation::FinishCall(node_id) => call::finish_call_node(
                &mut state,
                node_id,
                current_forest,
                prepared_return.take().expect("prepared CALL return retains both saved frames"),
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishDyn(node_id) => {
                r#dyn::finish_dyn_node(&mut state, node_id, current_forest, prepared_return.take())
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id).and_then(MastNode::get_basic_block),
                    "basic block node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                basic_block::execute_basic_block_node_from_op_idx(
                    &mut state,
                    basic_block_node,
                    node_id,
                    batch_index,
                    op_idx_in_batch,
                    current_forest,
                )?
            },
            Continuation::Respan { node_id, batch_index } => {
                let basic_block_node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id).and_then(MastNode::get_basic_block),
                    "basic block node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                basic_block::execute_basic_block_node_from_batch(
                    &mut state,
                    basic_block_node,
                    node_id,
                    batch_index,
                    current_forest,
                )?
            },
            Continuation::FinishBasicBlock(node_id) => {
                basic_block::finish_basic_block(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::EnterForest {
                forest,
                package_debug_info,
                loaded_owner: restored_loaded_owner,
                inline_context_depth,
            } => {
                // Restore the previous forest
                *current_forest = forest;
                state.source_debug_info = package_debug_info.clone();
                *source_debug_info = package_debug_info;
                *state.loaded_owner = restored_loaded_owner;
                state.inline_call_contexts.truncate(inline_context_depth);
            },
        }
    }

    ControlFlow::Continue(())
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn execute_impl_pure<P, H, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
    loaded_owner: &mut Option<LoadedMastForest>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    let mut state = ExecutionState {
        processor,
        continuation_stack,
        host,
        tracer,
        stopper,
        source_debug_info: None,
        loaded_owner,
        current_source_node_id: None,
        inline_call_contexts,
    };

    while state.continuation_stack.peek_continuation().is_some() {
        if let Some(request) = next_keyed_transition(&mut state, current_forest)
            .map_err(|err| InternalBreakReason::User(BreakReason::Err(err)))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)?
        {
            return ControlFlow::Break(request);
        }
        let mut prepared_return = match preflight_next_end(&mut state, current_forest) {
            Ok(prepared) => prepared,
            Err(err) => {
                return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(err)));
            },
        };
        let continuation =
            state.continuation_stack.pop_continuation().expect("peeked continuation exists");
        match continuation {
            Continuation::StartNode(node_id) => {
                let node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id),
                    "node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                match node {
                    MastNode::Block(basic_block_node) => {
                        basic_block::execute_basic_block_node_from_start(
                            &mut state,
                            basic_block_node,
                            node_id,
                            current_forest,
                        )?
                    },
                    MastNode::Join(join_node) => {
                        join::start_join_node_pure(&mut state, join_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Split(split_node) => split::start_split_node_pure(
                        &mut state,
                        split_node,
                        node_id,
                        current_forest,
                    )
                    .map_break(InternalBreakReason::from)?,
                    MastNode::Loop(loop_node) => {
                        r#loop::start_loop_node_pure(&mut state, loop_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Exec(_) | MastNode::Call(_) | MastNode::Dyn(_) => {
                        unreachable!("keyed invocation dispatch retains its StartNode")
                    },
                    MastNode::External(_) => external::execute_external_node(
                        node_id,
                        None,
                        current_forest,
                        state.tracer,
                    )?,
                }
            },
            Continuation::FinishJoin(node_id) => {
                join::finish_join_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishSplit(node_id) => {
                split::finish_split_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishLoop(node_id) => {
                r#loop::finish_loop_node_pure(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishExec(node_id) => {
                exec::finish_exec_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::RootBoundary { .. } => {
                return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(
                    ExecutionError::Internal("entry boundary reached without its actual root END"),
                )));
            },
            Continuation::FinishCall(node_id) => call::finish_call_node(
                &mut state,
                node_id,
                current_forest,
                prepared_return.take().expect("prepared CALL return retains both saved frames"),
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishDyn(node_id) => {
                r#dyn::finish_dyn_node(&mut state, node_id, current_forest, prepared_return.take())
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id).and_then(MastNode::get_basic_block),
                    "basic block node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                basic_block::execute_basic_block_node_from_op_idx(
                    &mut state,
                    basic_block_node,
                    node_id,
                    batch_index,
                    op_idx_in_batch,
                    current_forest,
                )?
            },
            Continuation::Respan { node_id, batch_index } => {
                let basic_block_node = option_map_break_reason(
                    current_forest.get_node_by_id(node_id).and_then(MastNode::get_basic_block),
                    "basic block node not found in current forest",
                )
                .map_break(InternalBreakReason::from)?;

                basic_block::execute_basic_block_node_from_batch(
                    &mut state,
                    basic_block_node,
                    node_id,
                    batch_index,
                    current_forest,
                )?
            },
            Continuation::FinishBasicBlock(node_id) => {
                basic_block::finish_basic_block(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::EnterForest {
                forest,
                loaded_owner: restored_loaded_owner,
                inline_context_depth,
                ..
            } => {
                *current_forest = forest;
                *state.loaded_owner = restored_loaded_owner;
                state.inline_call_contexts.truncate(inline_context_depth);
            },
        }
    }

    ControlFlow::Continue(())
}

// INTERNAL BREAK REASON
// ================================================================================================

/// Represents either a user-initiated break or a break due to an operation that (potentially)
/// requires asynchronous handling outside of the main execution loop.
///
/// Each variant (except for `User`) has an associated continuation that can be used to resume
/// execution after the operation has been handled.
///
/// # Emit
///
/// - *Function to call after handling*: [`finish_emit_op_execution`]
///
/// The `Emit` variant is used to break execution when an `Emit` operation is encountered. The
/// associated data includes the operation index, the source node, and the continuation that should
/// be passed to [`finish_emit_op_execution`] to resume execution after the host has processed the
/// emitted event.
///
/// Handling an `Emit` operation typically involves invoking the host environment to process the
/// emitted event. After the host has processed the event, the processor *must* call
/// [`finish_emit_op_execution`] to complete the execution of the `Emit` operation and resume
/// execution immediately after the `Emit` operation.
///
/// # ResolveKey and RootEnd
///
/// Keyed requests retain their original StartNode, row, source occurrence and dynamic memory
/// observation. The outer driver authenticates fixed-environment evidence before D-indexed supply,
/// then calls the shared prepared invocation transition. RootEnd retains the actual entry END;
/// its paired return frames or loop pop are prepared before native completion publishes.
///
/// # LoadMastForestFromExternal
///
/// - *Function to call after handling*: [`finish_load_mast_forest_from_external`]
///
/// The `LoadMastForestFromExternal` variant is used to break execution when an `ExternalNode` is
/// encountered that requires loading a MAST forest containing a given procedure. The associated
/// data includes the ID of the external node and the hash of the procedure to be loaded.
///
/// Handling this operation typically involves loading the MAST forest from the host environment.
/// After the MAST forest has been loaded, the processor *must* call
/// [`finish_load_mast_forest_from_external`] to complete the execution of the operation and resume
/// execution with the first operation of the called procedure.
pub enum InternalBreakReason<F> {
    ResolveKey(KeyedRequest),
    RootEnd(RootEndRequest<F>),
    User(BreakReason<F>),
    Emit {
        op_idx: usize,
        continuation: Continuation<F>,
        source_node_id: Option<DebugSourceNodeId>,
    },
    LoadMastForestFromExternal {
        external_node_id: MastNodeId,
        procedure_hash: Word,
        source_node_id: Option<DebugSourceNodeId>,
    },
}

impl<F> From<BreakReason<F>> for InternalBreakReason<F> {
    fn from(reason: BreakReason<F>) -> Self {
        Self::User(reason)
    }
}

// HELPERS
// ================================================================================================

/// This function marks the end of a clock cycle.
///
/// Delegates to [`finalize_clock_cycle_with_continuation`] with a continuation closure that returns
/// no continuation.
#[inline(always)]
fn finalize_clock_cycle<P, S, T, F>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    continuation_stack: &ContinuationStack<F>,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    finalize_clock_cycle_with_continuation(
        processor,
        tracer,
        stopper,
        continuation_stack,
        || None,
        current_forest,
    )
}

/// This function marks the end of a clock cycle.
///
/// Delegates to [`finalize_clock_cycle_with_continuation_and_op_helpers`] with the `Empty` variant
/// of [`OperationHelperRegisters`].
#[inline(always)]
fn finalize_clock_cycle_with_continuation<P, S, T, F>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    continuation_stack: &ContinuationStack<F>,
    continuation_after_stop: impl FnOnce() -> Option<(Continuation<F>, Option<DebugSourceNodeId>)>,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    finalize_clock_cycle_with_continuation_and_op_helpers(
        processor,
        tracer,
        stopper,
        continuation_stack,
        continuation_after_stop,
        OperationHelperRegisters::Empty,
        current_forest,
    )
}

/// This function marks the end of a clock cycle.
///
/// Specifically, it
/// 1. Calls `tracer.finish_clock_cycle()` to signal the end of the clock cycle to the tracer.
/// 2. Increments the processor's clock by 1.
/// 3. Checks if execution should stop using the provided `stopper`, providing the computed
///    continuation (from `continuation_after_stop()`) to the `BreakReason::Stopped` variant.
///
/// The `op_helper_registers` argument encodes the helper registers returned by [`execute_sync_op`]
/// when executing synchronous operations; pass in the `Empty` variant otherwise. These registers
/// are passed to the tracer when finalizing the clock cycle.
///
/// A continuation is computed using `continuation_after_stop()` in cases where simply resuming
/// execution from the top of the continuation stack is not sufficient to continue execution
/// correctly. For example, when stopping execution in the middle of a basic block, we need to
/// provide a `ResumeBasicBlock` continuation to ensure that execution resumes at the correct
/// operation within the basic block (i.e. the operation right after the one that was last executed
/// before being stopped). No continuation is provided in case of error, since it is expected that
/// execution will not be resumed.
#[inline(always)]
fn finalize_clock_cycle_with_continuation_and_op_helpers<P, S, T, F>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    continuation_stack: &ContinuationStack<F>,
    continuation_after_stop: impl FnOnce() -> Option<(Continuation<F>, Option<DebugSourceNodeId>)>,
    op_helper_registers: OperationHelperRegisters,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    // Signal the end of clock cycle to tracer (before incrementing processor clock).
    if let Err(e) = tracer.finalize_clock_cycle(processor, op_helper_registers, current_forest) {
        return ControlFlow::Break(BreakReason::Err(e));
    }

    // Increment the processor clock.
    processor.system_mut().increment_clock();

    stopper.should_stop(processor, continuation_stack, continuation_after_stop)
}

/// Selects retained keyed work before the generic execution loop pops or starts tracing a row.
fn next_keyed_transition<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
) -> Result<Option<InternalBreakReason<F>>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    F: ExecutableMastForest + Clone,
{
    let Some((continuation, source_node_id)) =
        state.continuation_stack.peek_continuation_with_source_node_id()
    else {
        return Ok(None);
    };
    let row = state.processor.system().clock();
    if let Continuation::StartNode(node_id) = continuation {
        let node_id = *node_id;
        let selected = match current_forest.get_node_by_id(node_id) {
            Some(MastNode::Exec(node)) => Some((node.target(), KeyedMode::Exec, None)),
            Some(MastNode::Call(node)) => Some((
                node.target(),
                if node.is_syscall() {
                    KeyedMode::Syscall
                } else {
                    KeyedMode::Call
                },
                None,
            )),
            Some(MastNode::Dyn(node)) => {
                let context = state.processor.system().ctx();
                let address = state.processor.stack().get(0);
                let value =
                    state.processor.memory_mut().peek_word(context, address, row).map_exec_err()?;
                Some((
                    ProcedureKey::new(value),
                    if node.is_dyncall() {
                        KeyedMode::DynCall
                    } else {
                        KeyedMode::Dyn
                    },
                    Some(DynamicKey { context, address, value }),
                ))
            },
            _ => None,
        };
        if let Some((key, mode, dynamic)) = selected {
            return Ok(Some(InternalBreakReason::ResolveKey(KeyedRequest {
                key,
                mode,
                node_id,
                source_node_id,
                row,
                dynamic,
            })));
        }
    }
    let is_end = match continuation {
        Continuation::FinishBasicBlock(_)
        | Continuation::FinishJoin(_)
        | Continuation::FinishSplit(_)
        | Continuation::FinishExec(_)
        | Continuation::FinishCall(_)
        | Continuation::FinishDyn(_) => true,
        Continuation::FinishLoop(_) => state.processor.stack().get(0) == crate::ZERO,
        _ => false,
    };
    if is_end && let Some((_, principal)) = state.continuation_stack.root_boundary_after_next() {
        let node_id = continuation
            .exec_node()
            .ok_or(ExecutionError::Internal("root END has no executable node"))?;
        let node = current_forest
            .get_node_by_id(node_id)
            .ok_or(ExecutionError::Internal("root END node is missing"))?;
        return Ok(Some(InternalBreakReason::RootEnd(RootEndRequest {
            continuation: continuation.clone(),
            implementation: ImplementationRoot::new(node.digest()),
            principal,
            row,
            source_node_id,
        })));
    }
    Ok(None)
}

/// Shared read-only tracer/stopper preflight. The selected continuation is still retained.
pub(crate) fn prepare_transition_cycle<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    continuation: &Continuation<F>,
    continuation_len: usize,
) -> Result<CycleProjection, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    let row = state.processor.system().clock();
    let next_clock = row
        .as_u32()
        .checked_add(1)
        .ok_or(ExecutionError::Internal("execution clock overflow"))?
        .into();
    let projection = CycleProjection { row, next_clock, continuation_len };
    state.stopper.preflight_cycle(state.processor, projection)?;
    state.tracer.prepare_clock_cycle(
        state.processor,
        continuation,
        state.continuation_stack,
        current_forest,
        projection,
    )?;
    Ok(projection)
}

/// Prepares both saved frames for context-return continuations before either frame is consumed.
fn prepare_end_return<P, H, S, T, F>(
    state: &ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    continuation: &Continuation<F>,
) -> Result<Option<call::PreparedReturn<P>>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    F: ExecutableMastForest + Clone,
{
    let returns_context = match continuation {
        Continuation::FinishCall(id) => match current_forest.get_node_by_id(*id) {
            Some(MastNode::Call(_)) => true,
            _ => return Err(ExecutionError::Internal("CALL return node is missing")),
        },
        Continuation::FinishDyn(id) => match current_forest.get_node_by_id(*id) {
            Some(MastNode::Dyn(node)) => node.is_dyncall(),
            _ => return Err(ExecutionError::Internal("dynamic return node is missing")),
        },
        _ => false,
    };
    if returns_context {
        call::preflight_return(state).map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn preflight_root_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: &RootEndRequest<F>,
) -> Result<PreparedRootEnd<P>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    if !matches!(
        request.continuation,
        Continuation::FinishBasicBlock(_)
            | Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishExec(_)
            | Continuation::FinishCall(_)
            | Continuation::FinishDyn(_)
            | Continuation::FinishLoop(_)
    ) {
        return Err(ExecutionError::Internal(
            "root completion requires an actual END continuation",
        ));
    }
    let (expected, principal) = state
        .continuation_stack
        .root_boundary_after_next()
        .ok_or(ExecutionError::Internal("root END is not immediately above the entry boundary"))?;
    if expected != request.implementation
        || principal != request.principal
        || state.processor.system().clock() != request.row
    {
        return Err(ExecutionError::Internal(
            "actual root END does not match the entry activation",
        ));
    }
    let (retained, source) = state
        .continuation_stack
        .peek_continuation_with_source_node_id()
        .ok_or(ExecutionError::Internal("root END continuation is missing"))?;
    if retained.exec_node() != request.continuation.exec_node()
        || core::mem::discriminant(retained) != core::mem::discriminant(&request.continuation)
        || source != request.source_node_id
    {
        return Err(ExecutionError::Internal("root END continuation changed before publication"));
    }
    let node_id = retained
        .exec_node()
        .ok_or(ExecutionError::Internal("root END node is missing"))?;
    let node = current_forest
        .get_node_by_id(node_id)
        .ok_or(ExecutionError::Internal("root END body is missing"))?;
    if node.digest() != *expected.as_word() {
        return Err(ExecutionError::Internal("root END body changed before publication"));
    }
    let return_context = prepare_end_return(state, current_forest, retained)?;
    let principal_after = return_context.as_ref().map_or_else(
        || state.processor.system().caller_hash(),
        |prepared| <P::System as SystemInterface>::restored_caller_hash(&prepared.system),
    );
    if principal_after != *principal.as_word() {
        return Err(ExecutionError::Internal("root END does not restore the entry principal"));
    }
    let loop_pop = if matches!(retained, Continuation::FinishLoop(_)) {
        if state.processor.stack().get(0) != crate::ZERO {
            return Err(ExecutionError::Internal("root loop END condition changed"));
        }
        Some(
            state
                .processor
                .stack()
                .prepare_decrement_size()
                .map_err(|error| state.operation_error_with_current_context(error))?,
        )
    } else {
        None
    };
    let output_depth = if let Some(prepared) = &return_context {
        <P::Stack as StackInterface>::restored_context_depth(&prepared.stack)
    } else {
        let depth = state.processor.stack().depth() as usize;
        if loop_pop.is_some() {
            depth.saturating_sub(1).max(miden_core::program::MIN_STACK_DEPTH)
        } else {
            depth
        }
    };
    if output_depth != miden_core::program::MIN_STACK_DEPTH {
        return Err(ExecutionError::OutputStackOverflow(
            output_depth.saturating_sub(miden_core::program::MIN_STACK_DEPTH),
        ));
    }
    let continuation_len = state
        .continuation_stack
        .len()
        .checked_sub(2)
        .ok_or(ExecutionError::Internal("root END continuation count underflow"))?;
    let projection =
        prepare_transition_cycle(state, current_forest, &request.continuation, continuation_len)?;
    Ok(PreparedRootEnd { projection, return_context, loop_pop })
}

/// Executes the actual retained END after its native, VM and tracing work has been prepared.
pub(crate) fn finish_root_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: RootEndRequest<F>,
    prepared: PreparedRootEnd<P>,
    event: KeyedEvent,
    reservation: T::KeyedReservation,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    debug_assert_eq!(event.kind, KeyedEventKind::RootEnd);
    state
        .continuation_stack
        .pop_continuation()
        .expect("prepared root END is retained");
    state.continuation_stack.discharge_root_boundary();
    state.current_source_node_id = request.source_node_id;
    state.tracer.commit_keyed_transition(reservation, event);
    match request.continuation {
        Continuation::FinishBasicBlock(id) => {
            basic_block::finish_basic_block(state, id, current_forest)
        },
        Continuation::FinishJoin(id) => join::finish_join_node(state, id, current_forest),
        Continuation::FinishSplit(id) => split::finish_split_node(state, id, current_forest),
        Continuation::FinishExec(id) => exec::finish_exec_node(state, id, current_forest),
        Continuation::FinishCall(id) => call::finish_call_node(
            state,
            id,
            current_forest,
            prepared.return_context.expect("prepared root CALL retains both saved frames"),
        ),
        Continuation::FinishDyn(id) => {
            r#dyn::finish_dyn_node(state, id, current_forest, prepared.return_context)
        },
        Continuation::FinishLoop(id) => {
            // The retained zero condition and its exact overflow pop were checked before native
            // root completion. Do not repeat a fallible pop inside the ordinary loop helper.
            state.tracer.start_clock_cycle(
                state.processor,
                Continuation::FinishLoop(id),
                state.continuation_stack,
                current_forest,
            );
            state.processor.stack_mut().commit_decrement_size(
                prepared.loop_pop.expect("prepared root loop END retains its condition pop"),
            );
            finalize_clock_cycle(
                state.processor,
                state.tracer,
                state.stopper,
                state.continuation_stack,
                current_forest,
            )
        },
        _ => unreachable!("preflight selected an actual root END continuation"),
    }
}

/// Ordinary END rows use the same pre-publication checks as authenticated root END.
fn preflight_next_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
) -> Result<Option<call::PreparedReturn<P>>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    let Some((continuation, source)) =
        state.continuation_stack.peek_continuation_with_source_node_id()
    else {
        return Ok(None);
    };
    let continuation = continuation.clone();
    // Return preflight can fail before the continuation is popped. Use its exact source occurrence
    // even when this execution state was just recreated after a stop.
    state.current_source_node_id = source;
    let mut length = state.continuation_stack.len() - 1;
    let prepared_return = prepare_end_return(state, current_forest, &continuation)?;
    match &continuation {
        Continuation::FinishBasicBlock(_)
        | Continuation::FinishJoin(_)
        | Continuation::FinishSplit(_)
        | Continuation::FinishExec(_)
        | Continuation::FinishCall(_)
        | Continuation::FinishDyn(_) => {},
        Continuation::FinishLoop(_) => {
            state.processor.stack().preflight_decrement_size().map_err(|_| {
                ExecutionError::Internal("loop transition cannot consume its stack condition")
            })?;
            if state.processor.stack().get(0) == crate::ONE {
                state.child_source_node_id(0)?;
                state.continuation_stack.prepare_push(2)?;
                length = length
                    .checked_add(2)
                    .ok_or(ExecutionError::Internal("continuation count overflow"))?;
            }
        },
        _ => return Ok(None),
    }
    prepare_transition_cycle(state, current_forest, &continuation, length)?;
    Ok(prepared_return)
}
