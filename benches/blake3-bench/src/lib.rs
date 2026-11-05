use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use miden_core_lib::CoreLibrary;
use miden_utils_testing::librarytree::{self, FixtureEnvironment, assemble_fixture_program};
use miden_vm::{
    Assembler, CanonicalLabel, CodePackage, DefaultHost, ExecutionOptions, ExecutionOutput,
    ExecutionProof, ExecutionWitness, FastProcessor, HashFunction, Prover, StackInputs,
    StackOutputs, Verifier, VmTrace,
    advice::{AdviceInputs, AdviceStack},
    assembly::{
        DefaultSourceManager, Path as LibraryPath,
        ast::{Module, ModuleKind},
    },
    internal::InputFile,
    trace,
};
use serde::{Deserialize, Serialize};
use tracing::{Subscriber, span};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
};

pub const BENCH_GROUP: &str = "blake3_1to1";
pub const PRIMARY_METRIC: &str = "e2e_prove";
pub const EXECUTE_FOR_PROVING_METRIC: &str = "execute_for_proving_sync";

/// Returns the canonical name for a user-facing or historical benchmark axis.
pub fn normalize_axis_name(axis: &str) -> &str {
    match axis {
        "execute_trace_inputs_sync" => EXECUTE_FOR_PROVING_METRIC,
        "prove" | "prove_program_sync" => PRIMARY_METRIC,
        _ => axis,
    }
}

const PROGRAM_RELATIVE_PATH: &str = "miden-vm/masm-examples/hashing/blake3_1to1/blake3_1to1.masm";

#[derive(Clone)]
pub struct Blake3Fixture {
    pub code: CodePackage,
    pub environment: FixtureEnvironment,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
}

impl Blake3Fixture {
    /// Loads the historical qualification workload with eight preserving output assertions.
    ///
    /// Expected outputs come from the independent native `blake3` crate, after checking its
    /// standard empty-message vector. Fixture construction and oracle work happen before timing.
    /// The assertions and seed match the archived 2026-11-05 comparison at 1, 8 and 32 hashes.
    pub fn load_checked_chain(repo_root: &Path, iterations: u32) -> (Self, [u64; 8]) {
        assert!(matches!(iterations, 1 | 8 | 32), "qualification supports 1, 8 or 32 hashes");
        assert_eq!(
            blake3::hash(b"").to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        let mut state = [0xff; 32];
        for _ in 0..iterations {
            state = *blake3::hash(&state).as_bytes();
        }
        let expected = core::array::from_fn(|index| {
            u64::from(u32::from_le_bytes(state[index * 4..index * 4 + 4].try_into().unwrap()))
        });

        let program_path = repo_root.join(PROGRAM_RELATIVE_PATH);
        let input_file = InputFile::read(&None, &program_path).expect("read Blake3 fixture inputs");
        assert_eq!(input_file.operand_stack, vec!["4294967295"; 8], "oracle seed changed");
        let source = std::fs::read_to_string(&program_path).expect("read Blake3 fixture source");
        assert_eq!(source.matches("exec.blake3::hash").count(), 1, "hash-call site changed");
        let marker = "    exec.sys::truncate_stack";
        assert_eq!(source.matches(marker).count(), 1, "output-assertion insertion point changed");
        let mut assertions =
            "    # Independently checked output; identical assertion count in every case.\n"
                .to_owned();
        for (index, value) in expected.iter().enumerate() {
            writeln!(assertions, "    dup.{index} push.{value} assert_eq").unwrap();
        }
        let source = source.replace(marker, &(assertions + marker));

        let core_lib = CoreLibrary::default();
        let mut assembler = Assembler::default();
        assembler
            .link_package(core_lib.code_package().clone(), miden_vm::assembly::Linkage::Dynamic)
            .expect("load core library");
        let (code, environment) =
            assemble_fixture_program(assembler, "program", source.as_str(), &[core_lib.naming()]);
        // Check the complete owner-supplied inventory before any measured execution. This is
        // independent of the environment's shape, traversal order and authenticated openings.
        let mut expected_bindings = BTreeMap::new();
        for symbols in [code.symbols(), core_lib.naming()] {
            for (&key, &implementation) in symbols.callables().selected_implementations() {
                let binding = symbols.callables().binding(key).expect("selected canonical binding");
                assert_eq!(binding.key(), key, "canonical ProcedureKey changed");
                let leaf = binding.path().components().last().expect("canonical procedure label");
                let label = CanonicalLabel::text(leaf).expect("canonical label").commitment();
                let expected = (binding.parent_namespace(), label, implementation);
                if let Some(previous) = expected_bindings.insert(key, expected) {
                    assert_eq!(previous, expected, "conflicting owner-selected binding");
                }
            }
        }
        assert_eq!(
            expected_bindings.len(),
            1_015,
            "review a changed Blake3 qualification inventory"
        );
        let bindings = environment.validated_environment().bindings();
        assert_eq!(bindings.len(), expected_bindings.len(), "complete binding inventory changed");
        for binding in bindings {
            let expected = expected_bindings.get(&binding.key()).expect("unexpected ProcedureKey");
            assert_eq!(binding.namespace(), expected.0, "binding namespace changed");
            assert_eq!(binding.label(), expected.1, "canonical procedure label changed");
            assert_eq!(
                binding.implementation(),
                expected.2,
                "selected implementation root changed"
            );
        }
        let fixture = Self {
            code,
            environment,
            stack_inputs: input_file.parse_stack_inputs().expect("parse Blake3 fixture inputs"),
            advice_inputs: AdviceInputs::default().with_stack(
                AdviceStack::try_from_values([u64::from(iterations)])
                    .expect("bounded Blake3 iteration count"),
            ),
        };
        (fixture, expected)
    }

    pub fn load_from_repo(repo_root: &Path) -> Self {
        let program_path = repo_root.join(PROGRAM_RELATIVE_PATH);
        let input_file = InputFile::read(&None, &program_path)
            .unwrap_or_else(|err| panic!("failed to read Blake3 inputs: {err}"));

        let source_manager = Arc::new(DefaultSourceManager::default());
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let ast = parser
            .parse_file(Some(LibraryPath::exec_path()), &program_path, source_manager.clone())
            .unwrap_or_else(|err| {
                panic!("failed to parse Blake3 program at {}: {err}", program_path.display())
            });

        let core_lib = CoreLibrary::default();
        let mut assembler = Assembler::new(source_manager);
        assembler
            .link_package(core_lib.code_package().clone(), miden_vm::assembly::Linkage::Dynamic)
            .expect("failed to load core library");
        let (code, environment) =
            assemble_fixture_program(assembler, "program", ast, &[core_lib.naming()]);

        Self {
            code,
            environment,
            stack_inputs: input_file.parse_stack_inputs().expect("failed to parse stack inputs"),
            advice_inputs: input_file.parse_advice_inputs().expect("failed to parse advice inputs"),
        }
    }
}

pub fn repo_root_from_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn execution_options() -> ExecutionOptions {
    ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .expect("CLI-compatible Blake3 execution options should be valid")
    .with_environment_trace_limits(librarytree::trace_limits())
}

pub fn default_host() -> DefaultHost {
    DefaultHost::default()
        .with_library(&CoreLibrary::default())
        .expect("failed to load core library into host")
}

fn host_for_fixture(fixture: &Blake3Fixture) -> DefaultHost<DefaultSourceManager> {
    let mut host = default_host().with_environment_source(fixture.environment.source());
    host.load_library(fixture.code.clone())
        .expect("failed to load Blake3 benchmark package");
    host
}

pub fn execute_for_proving(fixture: &Blake3Fixture) -> ExecutionWitness {
    let mut host = host_for_fixture(fixture);
    let processor = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options().with_resolution_limits(fixture.environment.resolution_limits()),
    )
    .expect("processor advice inputs should fit advice map limits");
    processor
        .execute_for_proving_sync(fixture.environment.target(), &mut host)
        .expect("failed to execute Blake3 benchmark")
}

pub fn execute_program(fixture: &Blake3Fixture) -> ExecutionOutput {
    let mut host = host_for_fixture(fixture);
    let processor = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options().with_resolution_limits(fixture.environment.resolution_limits()),
    )
    .expect("processor advice inputs should fit advice map limits");
    processor
        .execute_sync(fixture.environment.target(), &mut host)
        .expect("failed to execute Blake3 benchmark")
}

pub fn prove_program(fixture: &Blake3Fixture) {
    let _span = tracing::info_span!("prove_program_sync").entered();
    prove_trace(execute_for_proving(fixture));
}

pub fn prove_trace(witness: ExecutionWitness) -> (StackOutputs, ExecutionProof) {
    prove_trace_outputs(witness)
}

pub fn prove_and_verify_once(fixture: &Blake3Fixture) {
    let witness = execute_for_proving(fixture);
    let claim = witness.claim();
    let (_, proof) = prove_trace_outputs(witness);
    let outcome = Verifier::new()
        .verify(&claim, &proof)
        .expect("failed to verify Blake3 benchmark proof");
    assert!(outcome.is_complete(), "prove_full must settle all precompile work");
}

fn prove_trace_outputs(witness: ExecutionWitness) -> (StackOutputs, ExecutionProof) {
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Blake3_256)
        .prove_full(witness)
        .expect("failed to prove Blake3 benchmark witness");
    (stack_outputs, proof)
}

pub fn build_trace(witness: ExecutionWitness) -> VmTrace {
    let (vm_witness, _) = witness.into_parts();
    trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget())
        .expect("failed to build Blake3 execution trace")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpanRecord {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub name: String,
    pub target: String,
    pub path: String,
    pub duration_ms: f64,
}

#[derive(Clone, Debug)]
struct SpanTiming {
    started_at: Instant,
    parent_id: Option<u64>,
    name: String,
    target: String,
    path: String,
}

#[derive(Clone, Default)]
struct SpanRecorder {
    records: Arc<Mutex<Vec<SpanRecord>>>,
}

impl SpanRecorder {
    fn records(&self) -> Vec<SpanRecord> {
        let mut records = self.records.lock().expect("span recorder lock poisoned").clone();
        records.sort_by_key(|record| record.id);
        records
    }
}

impl<S> Layer<S> for SpanRecorder
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        let parent = attrs
            .parent()
            .and_then(|parent_id| ctx.span(parent_id))
            .or_else(|| ctx.lookup_current());
        let parent_id = parent.as_ref().map(|span| span.id().into_u64());
        let parent_path = parent.and_then(|span| {
            span.extensions().get::<SpanTiming>().map(|timing| timing.path.clone())
        });
        let name = metadata.name().to_string();
        let path = parent_path.map_or_else(|| name.clone(), |parent| format!("{parent} > {name}"));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanTiming {
                started_at: Instant::now(),
                parent_id,
                name,
                target: metadata.target().to_string(),
                path,
            });
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(timing) = span.extensions().get::<SpanTiming>().cloned() else {
            return;
        };
        self.records.lock().expect("span recorder lock poisoned").push(SpanRecord {
            id: id.into_u64(),
            parent_id: timing.parent_id,
            name: timing.name,
            target: timing.target,
            path: timing.path,
            duration_ms: duration_ms(timing.started_at.elapsed()),
        });
    }
}

pub fn collect_trace_spans(fixture: &Blake3Fixture) -> Vec<SpanRecord> {
    let recorder = SpanRecorder::default();
    let subscriber = Registry::default().with(recorder.clone());
    tracing::subscriber::with_default(subscriber, || prove_program(fixture));
    recorder.records()
}

pub fn prove_span_duration(fixture: &Blake3Fixture) -> Duration {
    let spans = collect_trace_spans(fixture);
    let prove_span = spans
        .iter()
        .find(|span| span.name == "prove")
        .expect("failed to collect `prove` span from Blake3 proof run");
    Duration::from_secs_f64(prove_span.duration_ms / 1000.0)
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
