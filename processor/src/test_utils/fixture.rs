//! Bridges the dependency processor's fixture types into this separately compiled unit-test crate.

use alloc::sync::Arc;

use miden_utils_testing::{librarytree::FixtureEnvironment, processor as dependency_processor};

use crate::{
    EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionTarget, LedgerLimits, OpeningLimits, OpeningStep,
    ResolutionLimits, ResolutionWitness, SessionLimits,
};

/// Preserves the fixture's core descriptor, native policies and bounded witness source.
pub(crate) fn native_fixture_environment(
    fixture: &FixtureEnvironment,
) -> (ExecutionTarget, ResolutionLimits, Arc<dyn EnvironmentWitnessSource>) {
    let limits = fixture.resolution_limits();
    let opening = limits.opening_limits();
    let ledger = limits.ledger_limits();
    let session = limits.session_limits();
    let limits = ResolutionLimits::new(
        OpeningLimits {
            max_nodes: opening.max_nodes,
            max_depth: opening.max_depth,
            max_list_children: opening.max_list_children,
            max_total_list_children: opening.max_total_list_children,
            max_encoded_bytes: opening.max_encoded_bytes,
            max_storage_bytes: opening.max_storage_bytes,
        },
        LedgerLimits {
            max_occurrences: ledger.max_occurrences,
            max_total_list_children: ledger.max_total_list_children,
            max_encoded_bytes: ledger.max_encoded_bytes,
            max_library_rows: ledger.max_library_rows,
            max_compression_requests: ledger.max_compression_requests,
            max_retained_bytes: ledger.max_retained_bytes,
            max_peak_bytes: ledger.max_peak_bytes,
        },
        SessionLimits {
            max_cached_keys: session.max_cached_keys,
            max_requests: session.max_requests,
            max_retained_bytes: session.max_retained_bytes,
            max_prepare_peak_bytes: session.max_prepare_peak_bytes,
        },
    );
    (fixture.target(), limits, Arc::new(FixtureSource(fixture.source())))
}

struct FixtureSource(Arc<dyn dependency_processor::EnvironmentWitnessSource>);

pub(crate) fn native_trace_limits() -> EnvironmentTraceLimits {
    let limits = miden_utils_testing::librarytree::trace_limits();
    EnvironmentTraceLimits {
        max_events: limits.max_events,
        max_retained_bytes: limits.max_retained_bytes,
        max_prepare_peak_bytes: limits.max_prepare_peak_bytes,
        max_validation_work: limits.max_validation_work,
    }
}

impl EnvironmentWitnessSource for FixtureSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        let limits = request.limits;
        let request = dependency_processor::EnvironmentWitnessRequest {
            root: request.root,
            key: request.key,
            limits: dependency_processor::OpeningLimits {
                max_nodes: limits.max_nodes,
                max_depth: limits.max_depth,
                max_list_children: limits.max_list_children,
                max_total_list_children: limits.max_total_list_children,
                max_encoded_bytes: limits.max_encoded_bytes,
                max_storage_bytes: limits.max_storage_bytes,
            },
        };
        self.0.get(request).map(|witness| {
            witness.map(|witness| ResolutionWitness {
                path: witness
                    .path
                    .into_iter()
                    .map(|step| OpeningStep {
                        node: step.node,
                        selected_child: step.selected_child,
                    })
                    .collect(),
            })
        })
    }
}

/// One finite aggregate budget for fixture replay sections belonging to the same witness.
pub(crate) fn native_replay_budget() -> crate::trace::keyed::ReplayReadBudget {
    crate::trace::keyed::ReplayReadBudget::new(
        native_trace_limits(),
        crate::trace::ReplayReadLimits {
            max_wire_bytes: 16 * 1024 * 1024,
            max_validation_peak_bytes: 1536 * 1024 * 1024,
        },
    )
}
