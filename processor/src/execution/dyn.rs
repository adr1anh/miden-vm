//! END for a keyed dynamic activation. Runtime selection is shared with immediate invocations.

use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, Stopper,
    continuation_stack::Continuation,
    execution::{
        ExecutionState,
        call::{PreparedReturn, commit_return},
        finalize_clock_cycle,
    },
    mast::{ExecutableMastForest, MastNodeId},
    processor::Processor,
    tracer::Tracer,
};

pub(super) fn finish_dyn_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    node_id: MastNodeId,
    current_forest: &F,
    prepared: Option<PreparedReturn<P>>,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    // The preceding zero-cycle EnterForest already restored the caller's inline contexts.
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::FinishDyn(node_id),
        state.continuation_stack,
        current_forest,
    );
    if let Some(prepared) = prepared {
        commit_return(state.processor, prepared);
    }
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}
