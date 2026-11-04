use alloc::{sync::Arc, vec::Vec};

use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};

use crate::{
    BaseHost, EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource,
    LoadedMastForest, MastForestStore, MemMastForestStore, ProcessorState, ResolutionWitness,
    SyncHost, advice::AdviceMutation, event::EventError,
};

/// A minimal testing host that records regular events.
///
/// It does *not* implement `on_trace`, to represent hosts in the wild which might not implement
/// it either. Still they must be able to handle traces without error, by way of the no-op default
/// implementation of `on_trace`.
///
/// Intended for checked fixture packages supplied explicitly by tests. It produces no advice
/// mutations and gains no execution authority from loaded code.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct NonTracingTestHost {
    /// Regular host event IDs received via [`SyncHost::on_event`], in emission order.
    pub events: Vec<u64>,
    source_manager: Arc<DefaultSourceManager>,
    environment_source: Option<super::EnvironmentSource>,
    store: MemMastForestStore,
}

#[cfg(test)]
impl NonTracingTestHost {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            environment_source: None,
            store: MemMastForestStore::default(),
        }
    }

    /// Attaches a source of untrusted environment witnesses for explicit execution requests.
    pub fn with_environment_source(mut self, source: Arc<dyn EnvironmentWitnessSource>) -> Self {
        self.environment_source = Some(super::EnvironmentSource(source));
        self
    }

    /// Retains checked fixture code separately from the test's target and witness source.
    pub fn with_code(mut self, code: miden_mast_package::CodePackage) -> Self {
        self.store.insert_loaded(LoadedMastForest::from_code_package(code));
        self
    }
}

#[cfg(test)]
impl Default for NonTracingTestHost {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl BaseHost for NonTracingTestHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

#[cfg(test)]
impl SyncHost for NonTracingTestHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        match &self.environment_source {
            Some(source) => source.0.get(request),
            None => Ok(None),
        }
    }

    fn get_mast_forest(&self, request: crate::CodeRequest) -> Option<LoadedMastForest> {
        self.store.get(request)
    }

    fn on_event(&mut self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = process.get_stack_item(0).as_canonical_u64();
        self.events.push(event_id);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use miden_utils_testing::Test;

    use super::NonTracingTestHost;
    use crate::{
        AdviceInputs, ExecutionOptions, FastProcessor, StackInputs,
        test_utils::native_fixture_environment,
    };

    /// A host which does not implement `on_trace` should still execute trace events gracefully via
    /// the default no-op implementation, and trace events must not be routed to `on_event`.
    #[test]
    fn non_tracing_host_ignores_trace_events() {
        const REGULAR_EVENT_ID_1: u64 = 3000;
        const REGULAR_EVENT_ID_2: u64 = 4000;
        const TRACE_ID: u32 = 1000;

        let source = format!(
            "\
    begin
        push.{REGULAR_EVENT_ID_1}
        emit
        drop
        push.{TRACE_ID}
        trace
        drop
        push.{REGULAR_EVENT_ID_2}
        emit
        drop
    end"
        );
        let test = Test::new("non_tracing_host_ignores_trace_events", &source, false);
        let (code, _) = test.compile().unwrap();
        let (target, limits, source) =
            native_fixture_environment(&test.fixture_environment().unwrap());
        let mut host =
            NonTracingTestHost::default().with_environment_source(source).with_code(code);
        host.source_manager = test.source_manager;
        FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_resolution_limits(limits),
        )
        .expect("failed to construct FastProcessor")
        .execute_sync(target, &mut host)
        .unwrap();

        assert_eq!(host.events, vec![REGULAR_EVENT_ID_1, REGULAR_EVENT_ID_2]);
    }
}
