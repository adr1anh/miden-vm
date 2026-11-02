//! Same-context keyed EXEC transitions, shared by live execution and deterministic replay.

use core::ops::ControlFlow;

use super::{
    ExecutionState, KeyedRequest, LoadedTarget, finalize_clock_cycle, prepare_transition_cycle,
};
use crate::{
    BaseHost, BreakReason, ExecutionError, Stopper,
    continuation_stack::Continuation,
    mast::{ExecutableMastForest, MastNode, MastNodeExt, MastNodeId},
    processor::{Processor, SystemInterface},
    tracer::{CycleProjection, KeyedEvent, KeyedEventKind, KeyedMode, Tracer},
};

/// Checks the retained invocation and reserves exactly its continuation/source buffers.
pub(crate) fn preflight_keyed_exec<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &F,
    request: KeyedRequest,
    target: &LoadedTarget<F>,
) -> Result<CycleProjection, ExecutionError>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    if request.mode != KeyedMode::Exec || state.processor.system().clock() != request.row {
        return Err(ExecutionError::Internal("retained EXEC request changed before publication"));
    }
    let Some((Continuation::StartNode(node_id), source)) =
        state.continuation_stack.peek_continuation_with_source_node_id()
    else {
        return Err(ExecutionError::Internal("retained EXEC StartNode is missing"));
    };
    if *node_id != request.node_id || source != request.source_node_id {
        return Err(ExecutionError::Internal("retained EXEC continuation changed"));
    }
    match current_forest.get_node_by_id(request.node_id) {
        Some(MastNode::Exec(node)) if node.target() == request.key => {},
        _ => return Err(ExecutionError::Internal("retained EXEC key changed")),
    }
    let body = target
        .forest
        .get_node_by_id(target.root)
        .ok_or(ExecutionError::Internal("resolved EXEC root is missing"))?;
    if body.is_external()
        || body.digest() != *target.implementation.as_word()
        || !target
            .forest
            .is_procedure_root_with_exact_digest(target.root, *target.implementation.as_word())
    {
        return Err(ExecutionError::Internal(
            "resolved EXEC body does not match its implementation",
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
    prepare_transition_cycle(
        state,
        current_forest,
        &Continuation::StartNode(request.node_id),
        continuation_len,
    )
}

/// Publishes a fully prepared activation. Both trace hooks observe the caller forest.
///
/// No context, stack, RAM, FMP or principal register changes occur in this transition.
pub(crate) fn finish_keyed_exec<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    current_forest: &mut F,
    request: KeyedRequest,
    target: LoadedTarget<F>,
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
    debug_assert_eq!(event.kind, KeyedEventKind::Invoke(KeyedMode::Exec));
    let inline_call_context = state.current_inline_call_context();
    let inline_context_depth = state.inline_call_contexts.len();
    let continuation = state
        .continuation_stack
        .pop_continuation()
        .expect("prepared EXEC retains its continuation");
    state.tracer.commit_keyed_transition(reservation, event);
    state.tracer.start_clock_cycle(
        state.processor,
        continuation,
        state.continuation_stack,
        current_forest,
    );
    state.continuation_stack.push_with_source_node_id(
        Continuation::FinishExec(request.node_id),
        request.source_node_id,
    );
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
    // The next cycle belongs to the loaded body even when stepping stops on the EXEC row.
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
