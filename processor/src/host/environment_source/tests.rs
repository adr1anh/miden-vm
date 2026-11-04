use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    error::Error,
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
};

use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ExecutionTarget, ImplementationRoot, Namespace,
        ProcedureKey,
    },
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceSpan};

use super::{EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource};
use crate::{
    BaseHost, DefaultHost, ExecutionEnvironment, FutureMaybeSend, Host, LedgerLimits,
    LoadedMastForest, OpeningError, OpeningLimits, OpeningStep, ProcessorState, ResolutionWitness,
    SessionLimits, SyncHost, advice::AdviceMutation, event::EventError,
};

#[test]
fn configuration_preserves_explicit_authority_and_limits() {
    let descriptor =
        ExecutionTarget::new(ProcedureKey::new(word(10)), EnvironmentRoot::new(word(20)));
    let opening = OpeningLimits { max_depth: 0, ..opening_limits() };
    let ledger = LedgerLimits {
        max_occurrences: 0,
        max_total_list_children: 17,
        max_encoded_bytes: 19,
        max_library_rows: 23,
        max_compression_requests: 29,
        max_retained_bytes: 31,
        max_peak_bytes: 37,
    };
    let session = SessionLimits {
        max_cached_keys: usize::MAX,
        max_requests: 0,
        max_retained_bytes: 41,
        max_prepare_peak_bytes: 43,
    };

    // Const evaluation remains available to callers, including for deliberately restrictive policy.
    const fn configured_values(
        descriptor: ExecutionTarget,
        opening: OpeningLimits,
        ledger: LedgerLimits,
        session: SessionLimits,
    ) -> (ExecutionTarget, OpeningLimits, LedgerLimits, SessionLimits) {
        let environment = ExecutionEnvironment::new(descriptor, opening, ledger, session);
        (
            environment.descriptor(),
            environment.opening_limits(),
            environment.ledger_limits(),
            environment.session_limits(),
        )
    }

    assert_eq!(
        configured_values(descriptor, opening, ledger, session),
        (descriptor, opening, ledger, session)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn available_code_does_not_supply_missing_environment_evidence() {
    let mut forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(body);
    let implementation = forest.local_procedure_digests().next().unwrap();
    let mut host = DefaultHost::default();
    host.mast_forest_store_mut().insert(Arc::new(forest));
    let request = EnvironmentWitnessRequest {
        root: EnvironmentRoot::new(word(50)),
        // Even a key whose bytes match available code does not authorize that implementation.
        key: ProcedureKey::new(implementation),
        limits: opening_limits(),
    };

    assert!(
        SyncHost::get_mast_forest(
            &host,
            crate::CodeRequest::External {
                implementation: ImplementationRoot::new(implementation)
            }
        )
        .is_some()
    );
    assert!(SyncHost::get_environment_witness(&mut host, request).unwrap().is_none());
    assert!(Host::get_environment_witness(&mut host, request).await.unwrap().is_none());

    let source = recording_source(request, || Ok(None));
    let mut host = host.with_environment_source(source.clone());
    assert!(SyncHost::get_environment_witness(&mut host, request).unwrap().is_none());
    assert!(Host::get_environment_witness(&mut host, request).await.unwrap().is_none());
    assert_eq!(source.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn configured_source_receives_the_exact_bounded_request() {
    let request = request();
    let source = recording_source(request, || Ok(Some(witness(None))));
    let mut host = DefaultHost::default().with_environment_source(source.clone());

    let candidate = SyncHost::get_environment_witness(&mut host, request).unwrap().unwrap();
    assert_eq!(candidate, witness(None));
    let binding = candidate.verify(request.root, request.key, request.limits).unwrap();
    assert_eq!(binding.implementation_root(), ImplementationRoot::new(word(60)));
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn provider_errors_are_preserved_by_sync_and_async_hosts() {
    let request = request();
    let source = recording_source(request, || Err(Box::new(SourceFailure(19))));
    let mut host = DefaultHost::default().with_environment_source(source.clone());

    let error = SyncHost::get_environment_witness(&mut host, request).unwrap_err();
    assert_eq!(error.downcast_ref::<SourceFailure>(), Some(&SourceFailure(19)));
    let error = Host::get_environment_witness(&mut host, request).await.unwrap_err();
    assert_eq!(error.downcast_ref::<SourceFailure>(), Some(&SourceFailure(19)));
    assert_eq!(source.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn source_candidates_require_independent_verification() {
    let request = request();
    for malformed in [false, true] {
        let source = recording_source(request, move || {
            Ok(Some(if malformed {
                witness(Some(0))
            } else {
                ResolutionWitness { path: vec![] }
            }))
        });
        let mut host = DefaultHost::default().with_environment_source(source.clone());

        // Retrieval must preserve even an invalid candidate as evidence, rather than grant a
        // binding.
        let candidate = SyncHost::get_environment_witness(&mut host, request).unwrap().unwrap();
        let expected = if malformed {
            assert_eq!(candidate, witness(Some(0)));
            OpeningError::UnexpectedChildSelection { depth: 0 }
        } else {
            assert!(candidate.path.is_empty());
            OpeningError::EmptyPath
        };
        assert_eq!(candidate.verify(request.root, request.key, request.limits), Err(expected));
        assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn source_survives_replacing_the_source_manager() {
    let request = request();
    let source = recording_source(request, || Ok(Some(witness(None))));
    let mut host = DefaultHost::default()
        .with_environment_source(source.clone())
        .with_source_manager(Arc::new(DefaultSourceManager::default()));

    let candidate = Host::get_environment_witness(&mut host, request).await.unwrap().unwrap();
    assert_eq!(candidate, witness(None));
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn custom_sync_and_async_hosts_default_to_unavailable_evidence() {
    let request = request();
    let mut sync_host = LegacySyncHost;
    let mut async_host = AsyncOnlyHost;

    assert!(SyncHost::get_environment_witness(&mut sync_host, request).unwrap().is_none());
    assert!(Host::get_environment_witness(&mut sync_host, request).await.unwrap().is_none());
    assert!(Host::get_environment_witness(&mut async_host, request).await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn sync_overrides_forward_through_the_async_host() {
    let request = request();
    let mut host = OverrideHost { expected: request, calls: 0 };

    assert!(SyncHost::get_environment_witness(&mut host, request).unwrap().is_some());
    assert!(Host::get_environment_witness(&mut host, request).await.unwrap().is_some());
    assert_eq!(host.calls, 2);
}

struct RecordingSource<F> {
    expected: EnvironmentWitnessRequest,
    calls: AtomicUsize,
    reply: F,
}

impl<F> EnvironmentWitnessSource for RecordingSource<F>
where
    F: Fn() -> Result<Option<ResolutionWitness>, EnvironmentSourceError> + Send + Sync,
{
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        assert_eq!(request, self.expected);
        self.calls.fetch_add(1, Ordering::Relaxed);
        (self.reply)()
    }
}

fn recording_source<F>(expected: EnvironmentWitnessRequest, reply: F) -> Arc<RecordingSource<F>>
where
    F: Fn() -> Result<Option<ResolutionWitness>, EnvironmentSourceError> + Send + Sync,
{
    Arc::new(RecordingSource {
        expected,
        calls: AtomicUsize::new(0),
        reply,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct SourceFailure(u32);

impl fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "environment source failure {}", self.0)
    }
}

impl Error for SourceFailure {}

struct LegacySyncHost;

impl BaseHost for LegacySyncHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::default(), None)
    }
}

impl SyncHost for LegacySyncHost {
    fn get_mast_forest(&self, _request: crate::CodeRequest) -> Option<LoadedMastForest> {
        panic!("environment lookup must not fall back to code lookup")
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![])
    }
}

struct AsyncOnlyHost;

impl BaseHost for AsyncOnlyHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::default(), None)
    }
}

impl Host for AsyncOnlyHost {
    fn get_mast_forest(
        &self,
        _request: crate::CodeRequest,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        async { panic!("environment lookup must not fall back to code lookup") }
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async { Ok(vec![]) }
    }
}

struct OverrideHost {
    expected: EnvironmentWitnessRequest,
    calls: usize,
}

impl BaseHost for OverrideHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::default(), None)
    }
}

impl SyncHost for OverrideHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        assert_eq!(request, self.expected);
        self.calls += 1;
        Ok(Some(ResolutionWitness { path: vec![] }))
    }

    fn get_mast_forest(&self, _request: crate::CodeRequest) -> Option<LoadedMastForest> {
        panic!("environment lookup must not fall back to code lookup")
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![])
    }
}

fn request() -> EnvironmentWitnessRequest {
    let candidate = witness(None);
    let EnvNode::Mast { label, .. } = &candidate.path[0].node else {
        unreachable!()
    };
    EnvironmentWitnessRequest {
        root: candidate.path[0].node.commitment().unwrap(),
        key: Namespace::initial().procedure_key(*label),
        limits: opening_limits(),
    }
}

fn witness(selected_child: Option<usize>) -> ResolutionWitness {
    ResolutionWitness {
        path: vec![OpeningStep {
            node: EnvNode::Mast {
                label: CanonicalLabel::text("entry").unwrap().commitment(),
                implementation: ImplementationRoot::new(word(60)),
            },
            selected_child,
        }],
    }
}

const fn opening_limits() -> OpeningLimits {
    OpeningLimits {
        max_nodes: 3,
        max_depth: 2,
        max_list_children: 7,
        max_total_list_children: 11,
        max_encoded_bytes: 1289,
        max_storage_bytes: 4099,
    }
}

fn word(seed: u32) -> Word {
    Word::new([seed, seed + 1, seed + 2, seed + 3].map(Felt::from_u32))
}
