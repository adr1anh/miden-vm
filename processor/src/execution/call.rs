//! Paired stack/system returns for keyed CALL, SYSCALL and DYNCALL activations.

use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, ExecutionError, Stopper,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle},
    mast::{ExecutableMastForest, MastNodeId},
    processor::{Processor, StackInterface, SystemInterface},
    tracer::Tracer,
};

/// Both saved frames are checked and retained before either can be popped.
pub(crate) struct PreparedReturn<P: Processor> {
    pub(super) stack: <P::Stack as StackInterface>::ContextRestore,
    pub(super) system: <P::System as SystemInterface>::CallRestore,
}

pub(super) fn preflight_return<P, H, S, T, F>(
    state: &ExecutionState<'_, P, H, S, T, F>,
) -> Result<PreparedReturn<P>, ExecutionError>
where
    P: Processor,
    H: BaseHost,
{
    let stack = state.processor.stack().prepare_restore_context()?;
    let system = state
        .processor
        .system()
        .prepare_restore_call_state()
        .map_err(|error| state.operation_error_with_current_context(error))?;
    Ok(PreparedReturn { stack, system })
}

pub(super) fn commit_return<P: Processor>(processor: &mut P, prepared: PreparedReturn<P>) {
    processor.stack_mut().commit_restore_context(prepared.stack);
    processor.system_mut().commit_restore_call_state(prepared.system);
}

pub(super) fn finish_call_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    node_id: MastNodeId,
    current_forest: &F,
    prepared: PreparedReturn<P>,
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
        Continuation::FinishCall(node_id),
        state.continuation_stack,
        current_forest,
    );
    commit_return(state.processor, prepared);
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}
