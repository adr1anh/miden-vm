use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::Felt;
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};

use crate::{
    BaseHost, EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource,
    LoadedMastForest, MastForestStore, MemMastForestStore, ProcessorState, ResolutionWitness,
    SyncHost, Word,
    advice::AdviceMutation,
    event::{EventError, TraceError},
    mast::MastForest,
};

/// A snapshot of the processor state for consistency checking between processors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorStateSnapshot {
    clk: u32,
    ctx: u32,
    stack_state: Vec<Felt>,
    stack_words: [Word; 4],
    mem_state: Vec<(crate::MemoryAddress, Felt)>,
}

impl From<&ProcessorState<'_>> for ProcessorStateSnapshot {
    fn from(state: &ProcessorState) -> Self {
        ProcessorStateSnapshot {
            clk: state.clock().into(),
            ctx: state.ctx().into(),
            stack_state: state.get_stack_state(),
            stack_words: [
                state.get_stack_word(0),
                state.get_stack_word(4),
                state.get_stack_word(8),
                state.get_stack_word(12),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

impl ProcessorStateSnapshot {
    /// Captures the user-visible state at an `emit` checkpoint.
    ///
    /// The checkpoint pattern used by tests is `push.<event> emit drop`, so the host observes the
    /// event ID at the top of the stack. The checkpoint snapshot skips that synthetic stack item to
    /// match the state after the trailing `drop`, and to preserve the old trace-decorator test
    /// shape.
    fn from_emit_checkpoint(state: &ProcessorState) -> Self {
        let mut stack_state = state.get_stack_state();
        if !stack_state.is_empty() {
            stack_state.remove(0);
        }

        ProcessorStateSnapshot {
            clk: state.clock().into(),
            ctx: state.ctx().into(),
            stack_state,
            stack_words: [
                state.get_stack_word(1),
                state.get_stack_word(5),
                state.get_stack_word(9),
                state.get_stack_word(13),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }

    /// Captures the user-visible state at a trace checkpoint.
    ///
    /// The checkpoint pattern used by tests is `push.<trace_id> push.<sys::trace_event> emit drop
    /// drop`, so the host observes the `SystemEvent::TraceEvent` id at the top of the stack  and
    /// the trace id below it (position 1). The checkpoint snapshot skips both synthetic stack items
    /// to match the state after the trailing `drop drop`.
    fn from_trace_checkpoint(state: &ProcessorState) -> Self {
        let mut stack_state = state.get_stack_state();
        if stack_state.len() >= 2 {
            stack_state.drain(0..2);
        }

        ProcessorStateSnapshot {
            clk: state.clock().into(),
            ctx: state.ctx().into(),
            stack_state,
            stack_words: [
                state.get_stack_word(2),
                state.get_stack_word(6),
                state.get_stack_word(10),
                state.get_stack_word(14),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

/// A unified testing host that combines event handling, debug handling, and external node
/// resolution.
#[derive(Debug, Clone)]
pub struct TestHost<S: SourceManager = DefaultSourceManager> {
    /// List of event IDs that have been received
    pub event_handler: Vec<u64>,

    /// List of trace IDs that have been received
    pub trace_handler: Vec<u64>,

    /// Process state snapshots captured at emitted test checkpoints.
    snapshots: BTreeMap<u64, Vec<ProcessorStateSnapshot>>,

    /// Process state snapshots captured at trace checkpoints.
    trace_snapshots: BTreeMap<u64, Vec<ProcessorStateSnapshot>>,

    /// MAST forest store for external node resolution
    store: MemMastForestStore,

    /// Source manager for debugging information
    pub source_manager: Arc<S>,

    environment_source: Option<super::EnvironmentSource>,
}

impl TestHost {
    /// Creates a new TestHost with minimal functionality for basic testing.
    pub fn new() -> Self {
        Self {
            event_handler: Vec::new(),
            trace_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            trace_snapshots: BTreeMap::new(),
            store: MemMastForestStore::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            environment_source: None,
        }
    }

    /// Creates a new TestHost with a kernel forest for full consistency testing.
    pub fn with_kernel_forest(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest);
        Self {
            event_handler: Vec::new(),
            trace_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            trace_snapshots: BTreeMap::new(),
            store,
            source_manager: Arc::new(DefaultSourceManager::default()),
            environment_source: None,
        }
    }

    /// Gets the processor state snapshots captured by emitted test checkpoints.
    pub fn snapshots(&self) -> &BTreeMap<u64, Vec<ProcessorStateSnapshot>> {
        &self.snapshots
    }

    /// Gets the processor state snapshots captured at trace checkpoints.
    pub fn trace_snapshots(&self) -> &BTreeMap<u64, Vec<ProcessorStateSnapshot>> {
        &self.trace_snapshots
    }
}

impl<S: SourceManager> TestHost<S> {
    /// Retains checked fixture code without supplying target or environment authority.
    pub fn with_code(mut self, code: miden_mast_package::CodePackage) -> Self {
        self.store.insert_loaded(LoadedMastForest::from_code_package(code));
        self
    }

    /// Attaches a source of untrusted environment witnesses for explicit execution requests.
    pub fn with_environment_source(mut self, source: Arc<dyn EnvironmentWitnessSource>) -> Self {
        self.environment_source = Some(super::EnvironmentSource(source));
        self
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> BaseHost for TestHost<S>
where
    S: SourceManagerSync,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl<S> SyncHost for TestHost<S>
where
    S: SourceManagerSync,
{
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
        self.event_handler.push(event_id);
        self.snapshots
            .entry(event_id)
            .or_default()
            .push(ProcessorStateSnapshot::from_emit_checkpoint(process));
        Ok(Vec::new())
    }

    fn on_trace(&mut self, process: &ProcessorState) -> Result<(), TraceError> {
        let trace_id = process.get_stack_item(1).as_canonical_u64();
        self.trace_handler.push(trace_id);
        self.trace_snapshots
            .entry(trace_id)
            .or_default()
            .push(ProcessorStateSnapshot::from_trace_checkpoint(process));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_utils_testing::Test;

    use super::TestHost;
    use crate::{
        AdviceInputs, ExecutionOptions, FastProcessor, StackInputs,
        test_utils::native_fixture_environment,
    };

    #[test]
    fn test_host_records_trace_and_snapshot() {
        const TRACE_ID_1: u64 = 100;
        const TRACE_ID_2: u64 = 200;

        let source = format!(
            "\
    begin
        push.{TRACE_ID_1}
        trace
        drop
        push.{TRACE_ID_2}
        trace
        drop
    end"
        );
        let test = Test::new("test_host_records_trace_and_snapshot", &source, false);
        let (code, _) = test.compile().unwrap();
        let (target, limits, source) =
            native_fixture_environment(&test.fixture_environment().unwrap());
        let mut host = TestHost::default().with_environment_source(source).with_code(code);
        host.source_manager = test.source_manager;
        FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_resolution_limits(limits),
        )
        .expect("failed to construct FastProcessor")
        .execute_sync(target, &mut host)
        .unwrap();

        // Each trace id is recorded, in emission order.
        assert_eq!(host.trace_handler, vec![TRACE_ID_1, TRACE_ID_2]);
        // A snapshot is captured at each trace checkpoint, keyed by trace id.
        assert_eq!(host.trace_snapshots().get(&TRACE_ID_1).map(Vec::len), Some(1));
        assert_eq!(host.trace_snapshots().get(&TRACE_ID_2).map(Vec::len), Some(1));

        // Traces do not trigger non-trace handlers.
        assert!(host.event_handler.is_empty());
        assert!(host.snapshots().is_empty());
    }
}
