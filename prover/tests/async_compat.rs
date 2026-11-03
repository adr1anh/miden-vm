use std::sync::Arc;

#[path = "common/named_source.rs"]
mod named_source;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, EnvironmentSourceError, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionOptions, FastProcessor, Felt, FutureMaybeSend, Host,
    LoadedMastForest, ProcessorState, ResolutionWitness, Word,
    advice::AdviceMutation,
    event::{EventError, EventName},
};
use miden_prover::{AdviceInputs, ExecutionClaim, ExecutionProof, Prover, StackInputs};
use miden_utils_testing::librarytree::{FixtureEnvironment, trace_limits};
use miden_verifier::Verifier;
use named_source::named_source;

struct YieldingAsyncHost {
    event_calls: usize,
    environment: Arc<dyn EnvironmentWitnessSource>,
}

impl YieldingAsyncHost {
    fn new(environment: &FixtureEnvironment) -> Self {
        Self {
            event_calls: 0,
            environment: environment.source(),
        }
    }
}

impl BaseHost for YieldingAsyncHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for YieldingAsyncHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> impl FutureMaybeSend<Result<Option<ResolutionWitness>, EnvironmentSourceError>> {
        async move {
            tokio::task::yield_now().await;
            self.environment.get(request)
        }
    }

    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        async { None }
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        self.event_calls += 1;
        async {
            tokio::task::yield_now().await;
            Ok(Vec::new())
        }
    }
}

fn verify_generated_proof(claim: &ExecutionClaim, proof: &ExecutionProof) {
    let outcome = Verifier::new()
        .verify(claim, proof)
        .expect("generated proof should verify against its execution claim");
    assert!(outcome.is_complete());
}

fn simple_program() -> (miden_processor::Program, FixtureEnvironment) {
    named_source(
        r#"
            begin
                repeat.64
                    swap dup.1 add
                end
            end
            "#,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn async_and_sync_execution_witnesses_prove_equivalently() {
    let (program, environment) = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(0), Felt::new_unchecked(1)]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let execution_options =
        ExecutionOptions::default().with_environment_trace_limits(trace_limits());

    let mut sync_host = DefaultHost::default().with_environment_source(environment.source());
    let sync_witness = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs.clone(),
        execution_options.clone(),
    )
    .unwrap()
    .execute_for_proving_sync(&program, environment.execution(), &mut sync_host)
    .unwrap();
    let sync_claim = sync_witness.claim();
    let sync_outputs = *sync_claim.stack_outputs();
    let sync_proof = Prover::new().prove_full(sync_witness).unwrap();

    let mut async_host = DefaultHost::default().with_environment_source(environment.source());
    let async_witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
            .unwrap()
            .execute_for_proving(&program, environment.execution(), &mut async_host)
            .await
            .unwrap();
    let async_claim = async_witness.claim();
    let async_outputs = *async_claim.stack_outputs();
    let async_proof = Prover::new().prove_full(async_witness).unwrap();

    assert_eq!(sync_outputs, async_outputs);
    verify_generated_proof(&sync_claim, &sync_proof);
    verify_generated_proof(&async_claim, &async_proof);
}

#[tokio::test(flavor = "current_thread")]
async fn proving_supports_witnesses_from_async_only_host_events() {
    let event_name = EventName::new("test::async::prove");
    let event_id = event_name.to_event_id().as_u64();
    let (program, environment) = named_source(&format!("begin push.{event_id} emit drop end"));

    let mut host = YieldingAsyncHost::new(&environment);
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_environment_trace_limits(trace_limits()),
    )
    .unwrap()
    .execute_for_proving(&program, environment.execution(), &mut host)
    .await
    .expect("async execution should succeed");
    let claim = witness.claim();
    let proof = Prover::new().prove_full(witness).expect("proving should succeed");

    assert_eq!(host.event_calls, 1);
    verify_generated_proof(&claim, &proof);
}
