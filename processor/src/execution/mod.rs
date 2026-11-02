use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::program::{ImplementationRoot, ProcedureKey};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, BreakReason, ContextId, ExecutionError, KernelDescriptor, Stopper, Word,
    continuation_stack::{Continuation, ContinuationStack, SourceInlineCallContext},
    errors::PackageSourceDebugContext,
    host::default::NoopHost,
    mast::{ExecutableMastForest, MastNode, MastNodeExt, MastNodeId},
    operation::OperationError,
    option_map_break_reason,
    processor::{Processor, StackInterface, SystemInterface},
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
pub(crate) use r#dyn::finish_load_mast_forest_from_dyn_start;
pub(crate) use exec::{finish_keyed_exec, preflight_keyed_exec};
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
}

#[derive(Debug, Clone)]
pub(crate) struct RootEndRequest<F> {
    pub continuation: Continuation<F>,
    pub implementation: ImplementationRoot,
    pub principal: ProcedureKey,
    pub row: RowIndex,
    pub source_node_id: Option<DebugSourceNodeId>,
}

/// Code supply validated against an authenticated implementation root.
pub(crate) struct LoadedTarget<F> {
    pub implementation: ImplementationRoot,
    pub root: MastNodeId,
    pub forest: F,
    pub package_debug_info: Option<Arc<PackageDebugInfo>>,
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
    pub kernel: &'a KernelDescriptor,
    pub host: &'a mut H,
    pub tracer: &'a mut T,
    pub stopper: &'a S,
    pub source_debug_info: Option<Arc<PackageDebugInfo>>,
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
/// let kernel = ...;
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
///         InternalBreakReason::LoadMastForestFromDyn { callee_hash } => {
///             // load MAST forest containing the callee procedure
///             let (procedure_id, new_forest) = self.load_mast_forest(...);
///
///             // As per `InternalBreakReason::LoadMastForestFromDyn` documentation, we call
///             // `finish_load_mast_forest_from_dyn_start` to complete the execution of the operation.
///             finish_load_mast_forest_from_dyn_start(...);
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
    kernel: &KernelDescriptor,
    mut host: &mut dyn BaseHost,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
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
        kernel,
        &mut host,
        tracer,
        stopper,
        source_debug_info,
        inline_call_contexts,
    )
}

pub(crate) fn execute_impl_noop_host<P, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    kernel: &KernelDescriptor,
    host: &mut NoopHost,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
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
        kernel,
        host,
        tracer,
        stopper,
        source_debug_info,
        inline_call_contexts,
    )
}

fn execute_impl_inner<P, H, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    kernel: &KernelDescriptor,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
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
            kernel,
            host,
            tracer,
            stopper,
            inline_call_contexts,
        )
    } else {
        execute_impl_with_source(
            processor,
            continuation_stack,
            current_forest,
            kernel,
            host,
            tracer,
            stopper,
            source_debug_info,
            inline_call_contexts,
        )
    }
}

#[inline(never)]
fn execute_impl_with_source<P, H, S, T, F>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack<F>,
    current_forest: &mut F,
    kernel: &KernelDescriptor,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
    source_debug_info: &mut Option<Arc<PackageDebugInfo>>,
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
        kernel,
        host,
        tracer,
        stopper,
        source_debug_info: source_debug_info.clone(),
        current_source_node_id: None,
        inline_call_contexts,
    };

    while state.continuation_stack.peek_continuation().is_some() {
        if let Some(request) = next_keyed_transition(&state, current_forest)
            .map_err(|err| InternalBreakReason::User(BreakReason::Err(err)))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)?
        {
            return ControlFlow::Break(request);
        }
        if let Err(err) = preflight_next_end(&mut state, current_forest) {
            return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(err)));
        }
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
                    MastNode::Exec(_) => unreachable!("EXEC dispatch retains its StartNode"),
                    MastNode::Call(call_node) => {
                        call::start_call_node(&mut state, call_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Dyn(_) => r#dyn::start_dyn_node(&mut state, node_id, current_forest)?,
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
            Continuation::FinishCall(node_id) => {
                call::finish_call_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishDyn(node_id) => {
                r#dyn::finish_dyn_node(&mut state, node_id, current_forest)
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
                inline_context_depth,
            } => {
                // Restore the previous forest
                *current_forest = forest;
                state.source_debug_info = package_debug_info.clone();
                *source_debug_info = package_debug_info;
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
    kernel: &KernelDescriptor,
    host: &mut H,
    tracer: &mut T,
    stopper: &S,
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
        kernel,
        host,
        tracer,
        stopper,
        source_debug_info: None,
        current_source_node_id: None,
        inline_call_contexts,
    };

    while state.continuation_stack.peek_continuation().is_some() {
        if let Some(request) = next_keyed_transition(&state, current_forest)
            .map_err(|err| InternalBreakReason::User(BreakReason::Err(err)))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)?
        {
            return ControlFlow::Break(request);
        }
        if let Err(err) = preflight_next_end(&mut state, current_forest) {
            return ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(err)));
        }
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
                    MastNode::Exec(_) => unreachable!("EXEC dispatch retains its StartNode"),
                    MastNode::Call(call_node) => {
                        call::start_call_node_pure(&mut state, call_node, node_id, current_forest)
                            .map_break(InternalBreakReason::from)?
                    },
                    MastNode::Dyn(_) => {
                        r#dyn::start_dyn_node_pure(&mut state, node_id, current_forest)?
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
            Continuation::FinishCall(node_id) => {
                call::finish_call_node(&mut state, node_id, current_forest)
                    .map_break(InternalBreakReason::from)?
            },
            Continuation::FinishDyn(node_id) => {
                r#dyn::finish_dyn_node(&mut state, node_id, current_forest)
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
            Continuation::EnterForest { forest, inline_context_depth, .. } => {
                *current_forest = forest;
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
/// # LoadMastForestFromDyn
///
/// - *Function to call after handling*: [`finish_load_mast_forest_from_dyn_start`]
///
/// The `LoadMastForestFromDyn` variant is used to break execution when `DynNode` is encountered
/// that requires loading a MAST forest containing a given procedure. The associated data includes
/// the hash of the callee procedure to be loaded.
///
/// Handling this operation typically involves loading the MAST forest from the host environment.
/// After the MAST forest has been loaded, the processor *must* call
/// [`finish_load_mast_forest_from_dyn_start`] to complete the execution of the operation and resume
/// execution with the first operation of the called procedure.
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
    LoadMastForestFromDyn {
        callee_hash: Word,
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

/// Returns the next context ID that would be created given the current state.
///
/// Note: This only applies to the context created upon a `CALL` or `DYNCALL` operation;
/// specifically the `SYSCALL` operation doesn't apply as it always goes back to the root
/// context.
fn get_next_ctx_id(processor: &impl Processor) -> ContextId {
    (processor.system().clock() + 1).into()
}

/// Selects retained keyed work before the generic execution loop pops or starts tracing a row.
fn next_keyed_transition<P, H, S, T, F>(
    state: &ExecutionState<'_, P, H, S, T, F>,
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
    if let Continuation::StartNode(node_id) = continuation
        && let Some(MastNode::Exec(node)) = current_forest.get_node_by_id(*node_id)
    {
        return Ok(Some(InternalBreakReason::ResolveKey(KeyedRequest {
            key: node.target(),
            mode: KeyedMode::Exec,
            node_id: *node_id,
            source_node_id,
            row,
        })));
    }
    let is_end = match continuation {
        Continuation::FinishBasicBlock(_)
        | Continuation::FinishJoin(_)
        | Continuation::FinishSplit(_)
        | Continuation::FinishExec(_) => true,
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

pub(crate) fn preflight_root_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: &RootEndRequest<F>,
) -> Result<CycleProjection, ExecutionError>
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
        || state.processor.system().caller_hash() != *principal.as_word()
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
    if matches!(retained, Continuation::FinishLoop(_)) {
        if state.processor.stack().get(0) != crate::ZERO {
            return Err(ExecutionError::Internal("root loop END condition changed"));
        }
        state.processor.stack().preflight_decrement_size().map_err(|_| {
            ExecutionError::Internal("root loop END cannot consume its stack condition")
        })?;
    }
    let continuation_len = state
        .continuation_stack
        .len()
        .checked_sub(2)
        .ok_or(ExecutionError::Internal("root END continuation count underflow"))?;
    prepare_transition_cycle(state, current_forest, &request.continuation, continuation_len)
}

/// Executes the actual retained END after its native, VM and tracing work has been prepared.
pub(crate) fn finish_root_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: RootEndRequest<F>,
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
        Continuation::FinishLoop(id) => {
            if state.source_debug_info.is_some() || state.continuation_stack.tracks_source_nodes() {
                r#loop::finish_loop_node(state, id, current_forest)
            } else {
                r#loop::finish_loop_node_pure(state, id, current_forest)
            }
        },
        _ => unreachable!("preflight selected an actual root END continuation"),
    }
}

/// Ordinary END rows use the same pre-publication checks as authenticated root END.
fn preflight_next_end<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
) -> Result<(), ExecutionError>
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
        return Ok(());
    };
    let continuation = continuation.clone();
    let mut length = state.continuation_stack.len() - 1;
    match &continuation {
        Continuation::FinishBasicBlock(_)
        | Continuation::FinishJoin(_)
        | Continuation::FinishSplit(_)
        | Continuation::FinishExec(_) => {},
        Continuation::FinishLoop(_) => {
            state.processor.stack().preflight_decrement_size().map_err(|_| {
                ExecutionError::Internal("loop transition cannot consume its stack condition")
            })?;
            if state.processor.stack().get(0) == crate::ONE {
                state.current_source_node_id = source;
                state.child_source_node_id(0)?;
                state.continuation_stack.prepare_push(2)?;
                length = length
                    .checked_add(2)
                    .ok_or(ExecutionError::Internal("continuation count overflow"))?;
            }
        },
        _ => return Ok(()),
    }
    prepare_transition_cycle(state, current_forest, &continuation, length)?;
    Ok(())
}
