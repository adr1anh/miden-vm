//! Prepared keyed invocation transitions, shared by live execution and deterministic replay.

use core::ops::ControlFlow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE};

use super::{
    ExecutionState, KeyedRequest, LoadedTarget, finalize_clock_cycle, prepare_transition_cycle,
};
use crate::{
    BaseHost, BreakReason, ContextId, ExecutionError, MapExecErr, Stopper,
    continuation_stack::Continuation,
    mast::{ExecutableMastForest, MastNode, MastNodeExt, MastNodeId},
    processor::{MemoryInterface, Processor, StackInterface, SystemInterface},
    tracer::{CycleProjection, KeyedEvent, KeyedEventKind, KeyedMode, Tracer},
};

/// Owned preparations for exactly the components changed by this invocation row.
pub(crate) struct PreparedInvocation<P: Processor> {
    pub projection: CycleProjection,
    context: Option<<P::Stack as StackInterface>::ContextStart>,
    dynamic_read: Option<<P::Memory as MemoryInterface>::WordRead>,
    dynamic_pop: Option<<P::Stack as StackInterface>::StackPop>,
    fmp_write: Option<<P::Memory as MemoryInterface>::ElementWrite>,
    next_context: Option<ContextId>,
}

/// Checks the retained invocation and reserves exactly its continuation/source buffers.
pub(crate) fn preflight_keyed_invocation<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: KeyedRequest,
    target: &LoadedTarget<F>,
) -> Result<PreparedInvocation<P>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    if state.processor.system().clock() != request.row {
        return Err(ExecutionError::Internal("retained invocation row changed before publication"));
    }
    let Some((Continuation::StartNode(node_id), source)) =
        state.continuation_stack.peek_continuation_with_source_node_id()
    else {
        return Err(ExecutionError::Internal("retained invocation StartNode is missing"));
    };
    if *node_id != request.node_id || source != request.source_node_id {
        return Err(ExecutionError::Internal("retained invocation continuation changed"));
    }
    match current_forest.get_node_by_id(request.node_id) {
        Some(MastNode::Exec(node))
            if request.mode == KeyedMode::Exec
                && request.dynamic.is_none()
                && node.target() == request.key => {},
        Some(MastNode::Call(node))
            if request.dynamic.is_none()
                && node.target() == request.key
                && request.mode
                    == if node.is_syscall() {
                        KeyedMode::Syscall
                    } else {
                        KeyedMode::Call
                    } => {},
        Some(MastNode::Dyn(node))
            if request.dynamic.is_some()
                && request.mode
                    == if node.is_dyncall() {
                        KeyedMode::DynCall
                    } else {
                        KeyedMode::Dyn
                    } => {},
        _ => return Err(ExecutionError::Internal("retained invocation key or mode changed")),
    }
    let body = target
        .forest
        .get_node_by_id(target.root)
        .ok_or(ExecutionError::Internal("resolved invocation root is missing"))?;
    if body.is_external()
        || body.digest() != *target.implementation.as_word()
        || !target
            .forest
            .is_procedure_root_with_exact_digest(target.root, *target.implementation.as_word())
    {
        return Err(ExecutionError::Internal(
            "resolved invocation body does not match its implementation",
        ));
    }
    let continuation_len = state
        .continuation_stack
        .len()
        .checked_add(2)
        .ok_or(ExecutionError::Internal("continuation count overflow"))?;
    state.continuation_stack.prepare_push(3)?;
    state
        .inline_call_contexts
        .try_reserve(1)
        .map_err(|_| ExecutionError::Internal("inline source context allocation failed"))?;
    let projection = prepare_transition_cycle(
        state,
        current_forest,
        &Continuation::StartNode(request.node_id),
        continuation_len,
    )?;
    let (dynamic_read, dynamic_pop) = if let Some(captured) = request.dynamic {
        if state.processor.system().ctx() != captured.context
            || state.processor.stack().get(0) != captured.address
            || captured.value != *request.key.as_word()
        {
            return Err(ExecutionError::Internal("retained dynamic address or key changed"));
        }
        let read = state
            .processor
            .memory_mut()
            .prepare_word_read(captured.context, captured.address, request.row)
            .map_exec_err()?;
        if <P::Memory as MemoryInterface>::word_read_value(&read) != captured.value {
            return Err(ExecutionError::Internal("retained dynamic memory word changed"));
        }
        let pop = state
            .processor
            .stack()
            .prepare_decrement_size()
            .map_err(|error| state.operation_error_with_current_context(error))?;
        (Some(read), Some(pop))
    } else {
        (None, None)
    };
    let changes_context =
        matches!(request.mode, KeyedMode::Call | KeyedMode::Syscall | KeyedMode::DynCall);
    let (context, next_context, fmp_write) = if changes_context {
        let context =
            state.processor.stack_mut().prepare_start_context(request.dynamic.is_some())?;
        state.processor.system_mut().prepare_save_call_state()?;
        let next_context = if request.mode == KeyedMode::Syscall {
            ContextId::root()
        } else {
            projection.next_clock.into()
        };
        let fmp_write = if request.mode == KeyedMode::Syscall {
            None
        } else {
            Some(
                state
                    .processor
                    .memory_mut()
                    .prepare_write_element(next_context, FMP_ADDR, FMP_INIT_VALUE)
                    .map_exec_err()?,
            )
        };
        (Some(context), Some(next_context), fmp_write)
    } else {
        (None, None, None)
    };
    Ok(PreparedInvocation {
        projection,
        context,
        dynamic_read,
        dynamic_pop,
        fmp_write,
        next_context,
    })
}

/// Publishes a fully prepared activation. Both trace hooks observe the caller forest.
///
/// Every component token is consumed here; no fallible VM preparation is repeated.
pub(crate) fn finish_keyed_invocation<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &mut F,
    request: KeyedRequest,
    target: LoadedTarget<F>,
    prepared: PreparedInvocation<P>,
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
    debug_assert_eq!(event.kind, KeyedEventKind::Invoke(request.mode));
    let inline_call_context = state.current_inline_call_context();
    let inline_context_depth = state.inline_call_contexts.len();
    let continuation = state
        .continuation_stack
        .pop_continuation()
        .expect("prepared invocation retains its continuation");
    state.tracer.commit_keyed_transition(reservation, event);
    state.tracer.start_clock_cycle(
        state.processor,
        continuation,
        state.continuation_stack,
        current_forest,
    );
    if let Some(read) = prepared.dynamic_read {
        let word = state.processor.memory_mut().commit_word_read(read);
        debug_assert_eq!(Some(word), request.dynamic.map(|captured| captured.value));
    }
    if let Some(pop) = prepared.dynamic_pop {
        state.processor.stack_mut().commit_decrement_size(pop);
    }
    if let Some(context) = prepared.context {
        state.processor.stack_mut().commit_start_context(context);
        state.processor.system_mut().save_call_state();
        let next_context = prepared.next_context.expect("prepared context switch has its target");
        state.processor.system_mut().set_ctx(next_context);
        if request.mode != KeyedMode::Syscall {
            state.processor.system_mut().set_caller_hash(*request.key.as_word());
        }
    }
    if let Some(write) = prepared.fmp_write {
        state.processor.memory_mut().commit_write_element(write);
        if request.mode == KeyedMode::Call {
            state.tracer.record_memory_write_element(
                FMP_INIT_VALUE,
                FMP_ADDR,
                prepared.next_context.expect("prepared FMP write has its context"),
                request.row,
            );
        }
    }
    if let Some(captured) = request.dynamic {
        if request.mode == KeyedMode::DynCall {
            state.tracer.record_dyncall_memory(
                captured.value,
                captured.address,
                captured.context,
                prepared.next_context.expect("prepared DYNCALL has its context"),
                request.row,
            );
        } else {
            state.tracer.record_memory_read_word(
                captured.value,
                captured.address,
                captured.context,
                request.row,
            );
        }
    }
    let finish = match request.mode {
        KeyedMode::Exec => Continuation::FinishExec(request.node_id),
        KeyedMode::Call | KeyedMode::Syscall => Continuation::FinishCall(request.node_id),
        KeyedMode::Dyn | KeyedMode::DynCall => Continuation::FinishDyn(request.node_id),
    };
    state
        .continuation_stack
        .push_with_source_node_id(finish, request.source_node_id);
    state.continuation_stack.push_runtime_activation(request.row, request.mode);
    state.continuation_stack.push_enter_forest_with_package_debug_info(
        current_forest.clone(),
        state.source_debug_info.clone(),
        inline_context_depth,
        request.source_node_id,
    );
    state.inline_call_contexts.push(inline_call_context);
    state
        .continuation_stack
        .push_with_source_node_id(Continuation::StartNode(target.root), target.source_node_id);

    let flow = finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    );
    // The next cycle belongs to the loaded body even when stepping stops on this invocation row.
    *current_forest = target.forest;
    state.source_debug_info = target.package_debug_info;
    flow
}

pub(super) fn finish_exec_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    node_id: MastNodeId,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::FinishExec(node_id),
        state.continuation_stack,
        current_forest,
    );
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}
