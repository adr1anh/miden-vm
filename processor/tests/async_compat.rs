use std::sync::Arc;

#[path = "common/named_source.rs"]
mod named_source;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, EnvironmentSourceError, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionOptions, FastProcessor, Felt, FutureMaybeSend, Host,
    LoadedMastForest, ProcessorState, ResolutionWitness, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventName, TraceError},
};
use miden_utils_testing::librarytree::{FixtureEnvironment, trace_limits};
use named_source::named_source;

struct YieldingAsyncHost {
    event_calls: usize,
    trace_calls: usize,
    environment: Arc<dyn EnvironmentWitnessSource>,
}

impl YieldingAsyncHost {
    fn new(environment: &FixtureEnvironment) -> Self {
        Self {
            event_calls: 0,
            trace_calls: 0,
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
        _request: miden_processor::CodeRequest,
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

    fn on_trace(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        async move {
            tokio::task::yield_now().await;
            self.trace_calls += 1;
            Ok(())
        }
    }
}

fn simple_program() -> (miden_processor::Program, FixtureEnvironment) {
    named_source("begin push.2 add end")
}

fn emit_trace_program() -> (miden_processor::Program, FixtureEnvironment) {
    named_source("begin trace.event(\"test::async::trace_emit\") end")
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_matches_execute() {
    let (program, environment) = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(3)]).unwrap();
    let advice_inputs = AdviceInputs::default();

    let mut sync_host = DefaultHost::default().with_environment_source(environment.source());
    let sync_output = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs.clone(),
        ExecutionOptions::default(),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(&program, environment.execution(), &mut sync_host)
    .unwrap();

    let mut async_host = DefaultHost::default().with_environment_source(environment.source());
    let async_output =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("failed to construct FastProcessor")
            .execute(&program, environment.execution(), &mut async_host)
            .await
            .unwrap();

    assert_eq!(sync_output.stack, async_output.stack);
}

#[tokio::test(flavor = "current_thread")]
async fn fast_processor_execute_for_proving_async_matches_sync() {
    let (program, environment) = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(3)]).unwrap();

    let mut sync_host = DefaultHost::default().with_environment_source(environment.source());
    let sync_witness = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default().with_environment_trace_limits(trace_limits()),
    )
    .unwrap()
    .execute_for_proving_sync(&program, environment.execution(), &mut sync_host)
    .unwrap();

    let mut async_host = DefaultHost::default().with_environment_source(environment.source());
    let async_witness = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default().with_environment_trace_limits(trace_limits()),
    )
    .unwrap()
    .execute_for_proving(&program, environment.execution(), &mut async_host)
    .await
    .unwrap();

    assert_eq!(sync_witness.claim().stack_outputs(), async_witness.claim().stack_outputs());
    let (sync_vm_witness, _) = sync_witness.into_parts();
    let (async_vm_witness, _) = async_witness.into_parts();
    let sync_trace = miden_processor::trace::build_trace(
        sync_vm_witness,
        &miden_vm_stark::memory::default_budget(),
    )
    .unwrap();
    let async_trace = miden_processor::trace::build_trace(
        async_vm_witness,
        &miden_vm_stark::memory::default_budget(),
    )
    .unwrap();

    assert_eq!(sync_trace.public_inputs(), async_trace.public_inputs());
    assert_eq!(sync_trace.trace_len_summary(), async_trace.trace_len_summary());
    for (sync_column, async_column) in
        sync_trace.main_trace().columns().zip(async_trace.main_trace().columns())
    {
        assert_eq!(sync_column, async_column);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_events() {
    let event_name = EventName::new("test::async::emit");
    let event_id = event_name.to_event_id().as_u64();
    let (program, environment) = named_source(&format!("begin push.{event_id} emit drop end"));

    let mut host = YieldingAsyncHost::new(&environment);
    let output = FastProcessor::new(StackInputs::default())
        .execute(&program, environment.execution(), &mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.event_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_traces() {
    let (program, environment) = emit_trace_program();

    let mut host = YieldingAsyncHost::new(&environment);
    let output = FastProcessor::new(StackInputs::default())
        .execute(&program, environment.execution(), &mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.trace_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}
