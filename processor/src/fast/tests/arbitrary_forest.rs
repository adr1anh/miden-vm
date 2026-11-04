use alloc::{
    string::{String, ToString},
    sync::Arc,
};

use miden_core::{
    Felt,
    mast::{
        MastNode,
        arbitrary::{
            ExecutableForestFixture, GenerationMode, MastForestParams, executable_forest_strategy,
        },
    },
    program::{EnvironmentBuildLimits, ExecutionTarget, StackInputs},
};
use proptest::{prelude::*, strategy::ValueTree, test_runner::TestRunner};

use crate::{
    DefaultHost, EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource,
    ExecutionOptions, FastProcessor, LedgerLimits, OpeningLimits, OpeningStep, ResolutionLimits,
    ResolutionWitness, SessionLimits, test_utils::fixture_code,
};

fn params() -> MastForestParams {
    MastForestParams {
        blocks: 1..=4,
        max_joins: 2,
        max_splits: 2,
        max_loops: 2,
        max_calls: 2,
        max_execs: 2,
        max_syscalls: 2,
        max_externals: 2,
        max_dyns: 4,
        mode: GenerationMode::Executable,
        ..Default::default()
    }
}

// These finite policies belong to this bounded synthetic fixture, not to a Protocol profile.
// There are at most 22 roots and 10 target aliases. Runtime-use limits allow repeated executions
// through shared joins and external wrappers; they are deliberately larger than the key count.
fn build_limits() -> EnvironmentBuildLimits {
    EnvironmentBuildLimits {
        max_submitted_nodes: 64,
        max_visits: 64,
        max_depth: 3,
        max_list_children: 61,
        max_encoded_bytes: 16_384,
        max_bindings: 61,
        max_storage_bytes: 262_144,
    }
}

fn opening_limits() -> OpeningLimits {
    OpeningLimits {
        max_nodes: 4,
        max_depth: 3,
        max_list_children: 64,
        max_total_list_children: 64,
        max_encoded_bytes: 8192,
        max_storage_bytes: 32_768,
    }
}

fn ledger_limits() -> LedgerLimits {
    LedgerLimits {
        max_occurrences: 128,
        max_total_list_children: 256,
        max_encoded_bytes: 65_536,
        max_library_rows: 1024,
        max_compression_requests: 1024,
        max_retained_bytes: 1_048_576,
        max_peak_bytes: 2_097_152,
    }
}

fn session_limits() -> SessionLimits {
    SessionLimits {
        max_cached_keys: 64,
        max_requests: 1024,
        max_retained_bytes: 2_097_152,
        max_prepare_peak_bytes: 4_194_304,
    }
}

fn execution_options() -> ExecutionOptions {
    ExecutionOptions::new(Some(65_536), 256, 256)
        .expect("bounded fixture cycle policy")
        .with_max_num_continuations(128)
        .with_max_stack_depth(128)
        .expect("bounded fixture stack policy")
        .with_max_memory_elements(4096)
        .with_resolution_limits(ResolutionLimits::new(
            opening_limits(),
            ledger_limits(),
            session_limits(),
        ))
}

fn fixture_strategy() -> BoxedStrategy<ExecutableForestFixture> {
    executable_forest_strategy(params(), build_limits())
        .prop_map(|sample| sample.expect("explicit executable fixture build limits are sufficient"))
        .boxed()
}

struct FixtureSource(Arc<ExecutableForestFixture>);

impl EnvironmentWitnessSource for FixtureSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        if request.root != self.0.environment().root() {
            return Ok(None);
        }
        Ok(self.0.opening(request.key).map(|path| ResolutionWitness {
            path: path
                .into_iter()
                .map(|(node, selected_child)| OpeningStep { node, selected_child })
                .collect(),
        }))
    }
}

/// Runs every generated binding, including same-D aliases, using the fixture's fixed environment.
/// Every forest root has its own binding and uses its remapped materialized root as the supply
/// hint.
fn run_every_binding(fixture: ExecutableForestFixture, stack: &[Felt]) -> Result<(), String> {
    let fixture = Arc::new(fixture);
    let mut host =
        DefaultHost::default().with_environment_source(Arc::new(FixtureSource(fixture.clone())));
    let supplied_root = fixture.procedures().first().expect("generated fixtures have roots").root;
    // This complete owner supplies code by implementation root. Generated callable keys and
    // their authorization still come exclusively from the separately fixed fixture environment.
    host.load_library(fixture_code(fixture.forest().clone(), supplied_root))
        .map_err(|err| err.to_string())?;
    for procedure in fixture.procedures() {
        let target = ExecutionTarget::new(procedure.key, fixture.environment().root());
        let inputs = StackInputs::new(stack).map_err(|err| err.to_string())?;
        FastProcessor::new(inputs)
            .with_options(execution_options())
            .map_err(|err| err.to_string())?
            .execute_sync(target, &mut host)
            .map_err(|err| {
                format!("binding {:?}, root {} failed: {err}", procedure.key, procedure.root)
            })?;
    }
    Ok(())
}

proptest! {
    /// Every root and invocation alias authenticates and terminates for any valid input values.
    #[test]
    fn executable_fixtures_run_on_any_stack(
        fixture in fixture_strategy(),
        stack in prop::collection::vec(any::<Felt>(), 0..=16),
    ) {
        prop_assert_eq!(run_every_binding(fixture, &stack), Ok(()));
    }
}

#[test]
fn executable_fixtures_execute_all_retained_invocation_modes() {
    let strategy = fixture_strategy();
    let mut runner = TestRunner::default();
    // CALL, EXEC, SYSCALL, DYN, DYNCALL and structural external resolution.
    let mut seen = [false; 6];
    for _ in 0..256 {
        let fixture = strategy.new_tree(&mut runner).expect("fixture strategy samples").current();
        for node in fixture.forest().nodes() {
            match node {
                MastNode::Call(call) if call.is_syscall() => seen[2] = true,
                MastNode::Call(_) => seen[0] = true,
                MastNode::Exec(_) => seen[1] = true,
                MastNode::Dyn(dynamic) => seen[3 + usize::from(dynamic.is_dyncall())] = true,
                MastNode::External(_) => seen[5] = true,
                _ => {},
            }
        }
        assert_eq!(run_every_binding(fixture, &[Felt::from_u32(7); 16]), Ok(()));
        if seen.into_iter().all(|covered| covered) {
            return;
        }
    }
    panic!("missing executable node kinds: {seen:?}");
}
