use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use miden_core::{
    Word,
    events::{EventId, EventName},
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_mast_package::CodePackage;

use super::handlers::{
    EventError, EventHandler, EventHandlerRegistry, TraceError, TraceHandler, TraceHandlerRegistry,
};
use crate::{
    BaseHost, EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource,
    ExecutionError, LoadedMastForest, MastForestStore, MemMastForestStore, ProcessorState,
    ResolutionWitness, SyncHost, advice::AdviceMutation,
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default SyncHost implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<S: SourceManager = DefaultSourceManager> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    trace_handlers: TraceHandlerRegistry,
    source_manager: Arc<S>,
    environment_source: Option<EnvironmentSource>,
}

struct EnvironmentSource(Arc<dyn EnvironmentWitnessSource>);

impl fmt::Debug for EnvironmentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EnvironmentWitnessSource").finish_non_exhaustive()
    }
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            trace_handlers: TraceHandlerRegistry::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            environment_source: None,
        }
    }
}

impl<S> DefaultHost<S>
where
    S: SourceManager,
{
    /// Use the given source manager implementation instead of the default one
    /// [`DefaultSourceManager`].
    pub fn with_source_manager<O>(self, source_manager: Arc<O>) -> DefaultHost<O>
    where
        O: SourceManager,
    {
        DefaultHost::<O> {
            store: self.store,
            event_handlers: self.event_handlers,
            trace_handlers: self.trace_handlers,
            source_manager,
            environment_source: self.environment_source,
        }
    }

    /// Uses an explicit source of untrusted environment witnesses.
    ///
    /// The host forwards each bounded request; its caller must authenticate returned candidates.
    /// An absent source or `None` response means evidence is unavailable, not nonmembership or
    /// authority to execute code by implementation digest.
    pub fn with_environment_source(mut self, source: Arc<dyn EnvironmentWitnessSource>) -> Self {
        self.environment_source = Some(EnvironmentSource(source));
        self
    }

    /// Returns mutable access to the low-level store of untrusted code witnesses.
    ///
    /// Raw forest insertion assigns no procedure names or keys and supplies no authority for an
    /// entry key or environment root. Execution still authenticates requested bindings and checks
    /// returned code against the requested implementation digest and procedure roots.
    pub fn mast_forest_store_mut(&mut self) -> &mut MemMastForestStore {
        &mut self.store
    }

    /// Loads a [`HostLibrary`] containing owned package code and its event handlers.
    ///
    /// The load is atomic: if one handler fails to register, the host keeps the state it had
    /// before the call. It holds no handler of the library and it does not hold the MAST forest.
    ///
    /// # Errors
    /// Returns an error when a handler of the library has an empty or reserved event name, or
    /// when its event already has a handler in this host.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();

        // Each successful registration adds a handler that the registry did not have, so
        // un-registering the added IDs gives back the state before the call.
        let mut registered = Vec::with_capacity(library.handlers.len());
        for (event, handler) in library.handlers {
            let id = event.to_event_id();
            if let Err(err) = self.event_handlers.register(event, handler) {
                for id in registered {
                    self.event_handlers.unregister(id);
                }
                return Err(err);
            }
            registered.push(id);
        }

        self.store.insert_loaded(LoadedMastForest::from_code_package(library.code));
        Ok(())
    }

    /// Adds a [`HostLibrary`] containing owned package code and its event handlers to the host.
    pub fn with_library(mut self, library: impl Into<HostLibrary>) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
    }

    /// Registers a single [`EventHandler`] into this host.
    ///
    /// The handler can be either a closure or a free function with signature
    /// `fn(&mut ProcessorState) -> Result<(), EventHandler>`
    pub fn register_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        self.event_handlers.register(event, handler)
    }

    /// Un-registers a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    pub fn unregister_handler(&mut self, id: EventId) -> bool {
        self.event_handlers.unregister(id)
    }

    /// Replaces a handler with the given event, returning a flag indicating whether a handler
    /// was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    pub fn replace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<bool, ExecutionError> {
        self.event_handlers.replace(event, handler)
    }

    /// Registers a single [`TraceHandler`] into this host.
    ///
    /// Trace handlers observe VM state for optional, read-only trace events; they cannot mutate the
    /// advice provider. Unhandled trace event IDs are ignored. The handler can be either a closure
    /// or a free function.
    pub fn register_trace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn TraceHandler>,
    ) -> Result<(), ExecutionError> {
        self.trace_handlers.register(event, handler)
    }

    /// Un-registers a trace handler with the given id, returning a flag indicating whether a
    /// handler was previously registered with this id.
    pub fn unregister_trace_handler(&mut self, id: EventId) -> bool {
        self.trace_handlers.unregister(id)
    }

    /// Replaces a trace handler with the given event, returning a flag indicating whether a
    /// handler was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    pub fn replace_trace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn TraceHandler>,
    ) -> Result<bool, ExecutionError> {
        self.trace_handlers.replace(event, handler)
    }
}

impl<S> BaseHost for DefaultHost<S>
where
    S: SourceManager,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.event_handlers.resolve_event(event_id)
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        self.trace_handlers.resolve_trace(trace_id)
    }
}

impl<S> SyncHost for DefaultHost<S>
where
    S: SourceManager,
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

    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest> {
        self.store.get(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        match self.event_handlers.handle_event(event_id, process) {
            Ok(Some(mutations)) => Ok(mutations),
            Ok(None) => {
                #[derive(Debug, thiserror::Error)]
                #[error("no event handler registered")]
                struct UnhandledEvent;

                Err(UnhandledEvent.into())
            },
            Err(e) => Err(e),
        }
    }

    fn on_trace(&mut self, process: &ProcessorState<'_>) -> Result<(), TraceError> {
        // The trace id sits one below the `SystemEvent::TraceEvent` id.
        let trace_id = EventId::from_felt(process.get_stack_item(1));
        match self.trace_handlers.handle_trace(trace_id, process) {
            Ok(Some(())) => Ok(()),
            // Traces are optional/readonly, so an unhandled trace is not an error.
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// NOOPHOST
// ================================================================================================

/// A SyncHost which does nothing.
pub struct NoopHost;

impl BaseHost for NoopHost {
    #[inline(always)]
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for NoopHost {
    #[inline(always)]
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        None
    }

    #[inline(always)]
    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

// HOST LIBRARY
// ================================================================================================

/// Package code and the event handlers for events it may call.
///
/// The code retains its exact checked symbols, advice and source metadata. Loading it makes code
/// available; the execution caller still supplies the expected target and environment root.
pub struct HostLibrary {
    code: CodePackage,
    handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
}

impl HostLibrary {
    /// Creates a host library retaining the complete code package.
    ///
    /// Packaged Wasm event handlers are not loaded: this crate cannot depend on the Wasm runner.
    /// Use `miden_wasm_event_handlers::host_library_from_package` to load those handlers.
    pub fn new(code: CodePackage) -> Self {
        Self { code, handlers: Vec::new() }
    }

    /// Returns the complete package code and its exact checked symbols.
    pub fn code(&self) -> &CodePackage {
        &self.code
    }

    /// Returns the event handlers registered when this library is loaded.
    pub fn handlers(&self) -> &[(EventName, Arc<dyn EventHandler>)] {
        &self.handlers
    }

    /// Replaces the event handlers of this library.
    ///
    /// Use this to supply handlers that the source of the library does not provide, for example
    /// the Wasm event handlers of a package.
    pub fn set_handlers(mut self, handlers: Vec<(EventName, Arc<dyn EventHandler>)>) -> Self {
        self.handlers = handlers;
        self
    }
}

impl From<CodePackage> for HostLibrary {
    fn from(code: CodePackage) -> Self {
        Self::new(code)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{
        mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
        operations::Operation,
        program::{CanonicalLabel, ImplementationRoot},
    };
    use miden_mast_package::{
        CallableProcedurePath, NamespacePath, Package, PackageCallables, PackageDebugInfoError,
        PackageId, PackageProcedureOccurrence, PackageSymbols, ProcedureName, Section, SectionId,
        TargetType, Version,
    };

    use super::{super::handlers::NoopEventHandler, *};
    use crate::errors::HostError;

    /// Builds a library with one procedure and one handler per event name.
    fn library(events: &[&'static str]) -> HostLibrary {
        let mut mast_forest = MastForest::new();
        let block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(block);

        let home = NamespacePath::new(vec![CanonicalLabel::text("host-test").unwrap()]);
        let path =
            CallableProcedurePath::from_semantic_components(vec!["procedure".into()]).unwrap();
        let binding = ProcedureName::new(home.clone(), path).unwrap();
        let key = binding.key();
        let selected = [(key, ImplementationRoot::new(mast_forest[block].digest()))];
        let symbols = Arc::new(
            PackageSymbols::new(
                home,
                PackageCallables::new([binding], [], selected).unwrap(),
                None,
            )
            .unwrap(),
        );
        let package = Package::create(
            PackageId::from("host-test"),
            Version::new(1, 0, 0),
            TargetType::Library,
            Arc::new(mast_forest),
            [],
            [],
            &symbols,
        )
        .unwrap()
        .with_procedure_occurrences([PackageProcedureOccurrence::new(key, block, None)], &symbols)
        .unwrap();
        let code = CodePackage::new(Arc::new(package), symbols).unwrap();

        let handlers = events
            .iter()
            .map(|event| {
                (EventName::new(event), Arc::new(NoopEventHandler) as Arc<dyn EventHandler>)
            })
            .collect();
        HostLibrary::new(code).set_handlers(handlers)
    }

    /// Returns `true` when the host resolves a handler for the named event.
    fn is_registered(host: &DefaultHost, event: &'static str) -> bool {
        host.resolve_event(EventName::new(event).to_event_id()).is_some()
    }

    #[test]
    fn load_library_registers_the_handlers_and_the_forest() {
        let library = library(&["test::a", "test::b"]);
        let procedure =
            library.code().package().mast_forest().local_procedure_digests().next().unwrap();

        let code = library.code().clone();
        let occurrence = code.package().procedure_occurrences()[0];
        let mut host = DefaultHost::default();
        host.load_library(library).unwrap();

        assert!(is_registered(&host, "test::a"));
        assert!(is_registered(&host, "test::b"));
        let loaded = host.get_mast_forest(&procedure).expect("the forest is loaded");
        let retained = loaded.code_package().expect("the whole code package is retained");
        assert!(Arc::ptr_eq(retained.package(), code.package()));
        assert!(Arc::ptr_eq(loaded.symbols().unwrap(), code.symbols()));
        assert_eq!(loaded.procedure_occurrence(occurrence.key()), Some(&occurrence));
    }

    #[test]
    fn rich_load_retains_deferred_package_debug_failure() {
        let code = library(&[]).code().clone();
        let mut package = code.package().as_ref().clone();
        package.sections.push(Section::new(SectionId::DEBUG_INFO, vec![0xff]));
        let code = CodePackage::new(Arc::new(package), code.symbols().clone()).unwrap();
        let procedure = code.package().mast_forest().local_procedure_digests().next().unwrap();
        let mut host = DefaultHost::default();
        host.load_library(code.clone()).unwrap();

        let loaded = host.get_mast_forest(&procedure).unwrap();
        assert!(Arc::ptr_eq(loaded.code_package().unwrap().package(), code.package()));
        let error = loaded.package_debug_info().expect_err("malformed debug info stays an error");
        assert!(matches!(&*error, PackageDebugInfoError::DecodeSection { .. }));
    }

    #[test]
    fn failed_load_library_leaves_no_partial_state() {
        let mut host = DefaultHost::default();
        host.register_handler(EventName::new("test::b"), Arc::new(NoopEventHandler))
            .unwrap();

        // The second handler of the library collides with the handler of the host.
        let library = library(&["test::a", "test::b"]);
        let procedure =
            library.code().package().mast_forest().local_procedure_digests().next().unwrap();
        let err = host.load_library(library).unwrap_err();

        assert!(
            matches!(err, ExecutionError::HostError(HostError::DuplicateEventHandler { .. })),
            "unexpected error: {err}"
        );
        assert!(!is_registered(&host, "test::a"), "the first handler must be rolled back");
        assert!(host.get_mast_forest(&procedure).is_none(), "the forest must not be loaded");
    }
}
