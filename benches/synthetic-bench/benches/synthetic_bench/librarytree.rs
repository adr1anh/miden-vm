//! Opt-in, single-sample LibraryTree qualification measurements.
//!
//! Run the registered executable with `--librarytree MODE SCENARIO`. Modes are `proof`,
//! `shape`, `session`, and `recursive`; scenarios are `list-small`, `list-unused`,
//! `merkle-small`, `merkle-unused`, `exec-repeat`, `call-repeat`, and `equal-d`.
//! Each invocation emits one JSON object. Run proof cases in separate processes under
//! `/usr/bin/time` to measure whole-process peak RSS (including setup and verification).
//! Shape and session modes are separate diagnostic executions, not observations of the
//! private session inside a timed proof. No configured resource budget is a memory measurement.
//! List/Merkle scenarios describe explicitly selected fragments. Each case mounts exactly one
//! complete fragment, so the fixture's singleton collection preserves that fragment's root.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Instant,
};

use miden_assembly::{
    Linkage,
    debuginfo::{Location, SourceFile, SourceSpan},
};
use miden_core::{
    Felt, Word,
    events::{EventId, EventName},
    program::{
        CanonicalLabel, EnvNode, EnvironmentBuildLimits, EnvironmentBuilder, EnvironmentRoot,
        ExecutionClaim, ValidatedEnvironment,
    },
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    BaseHost, CodeRequest, DefaultHost, EnvironmentSource, EnvironmentSourceError,
    EnvironmentWitnessRequest, FastProcessor, LoadedMastForest, ProcessorState, ResolutionWitness,
    SessionPhase, SyncHost,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, TraceError},
    trace::RowIndex,
};
use miden_utils_testing::librarytree::{FixtureEnvironment, assemble_fixture_program};
use miden_vm::{
    Assembler, CodePackage, ExecutionProof, HashFunction, Prover, StackInputs, StackOutputs,
    Verifier, prove_sync, trace::build_trace,
};
use miden_vm_stark::recursive::RecursiveVerifierInputs;
use serde_json::{Value, json};

use super::execution_options;

const USAGE: &str = "--librarytree <proof|shape|session|recursive> <list-small|list-unused|merkle-small|merkle-unused|exec-repeat|call-repeat|equal-d>";

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    merkle: bool,
    unused: usize,
    calls: usize,
    call: bool,
    aliases: bool,
}

impl Scenario {
    fn parse(name: &str) -> Self {
        let (name, merkle, unused, calls, call, aliases) = match name {
            "list-small" => ("list-small", false, 0, 1, false, false),
            "list-unused" => ("list-unused", false, 128, 1, false, false),
            "merkle-small" => ("merkle-small", true, 0, 1, false, false),
            "merkle-unused" => ("merkle-unused", true, 128, 1, false, false),
            "exec-repeat" => ("exec-repeat", false, 0, 16, false, false),
            "call-repeat" => ("call-repeat", false, 0, 16, true, false),
            "equal-d" => ("equal-d", false, 0, 16, false, true),
            _ => panic!("unknown LibraryTree scenario {name:?}; usage: {USAGE}"),
        };
        Self {
            name,
            merkle,
            unused,
            calls,
            call,
            aliases,
        }
    }

    fn configuration(self) -> Value {
        json!({
            "scenario": self.name,
            "grouping": if self.merkle { "selective-merkle" } else { "shallow-list" },
            "grouping_scope": "explicit_fragment",
            "fixture_collection": "singleton_fragment_root",
            "unused_data_leaves": self.unused,
            "runtime_invocations": self.calls,
            "invocation": if self.call { "CALL" } else { "EXEC" },
            "callee_keys": if self.aliases { 2 } else { 1 },
            "callee_body": "push.1 drop",
        })
    }
}

/// This wrapper counts real source callbacks. DefaultHost itself has no opening cache.
struct CountedSource {
    inner: Arc<dyn EnvironmentSource>,
    queries: Mutex<BTreeMap<String, usize>>,
}

impl CountedSource {
    fn snapshot(&self) -> BTreeMap<String, usize> {
        self.queries.lock().expect("opening counter lock").clone()
    }

    fn total(&self) -> usize {
        self.queries.lock().expect("opening counter lock").values().sum()
    }
}

impl EnvironmentSource for CountedSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        *self
            .queries
            .lock()
            .expect("opening counter lock")
            .entry(format!("{:?}", request.key))
            .or_default() += 1;
        self.inner.get(request)
    }
}

/// Delegates every host operation while counting actual loaded-code requests.
struct CountedHost {
    inner: DefaultHost,
    code_queries: Mutex<BTreeMap<String, usize>>,
}

impl CountedHost {
    fn code_snapshot(&self) -> BTreeMap<String, usize> {
        self.code_queries.lock().expect("code counter lock").clone()
    }

    fn code_total(&self) -> usize {
        self.code_queries.lock().expect("code counter lock").values().sum()
    }
}

impl BaseHost for CountedHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.inner.resolve_event(event_id)
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        self.inner.resolve_trace(trace_id)
    }
}

impl SyncHost for CountedHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        SyncHost::get_environment_witness(&mut self.inner, request)
    }

    fn get_mast_forest(&self, request: CodeRequest) -> Option<LoadedMastForest> {
        *self
            .code_queries
            .lock()
            .expect("code counter lock")
            .entry(format!("{request:?}"))
            .or_default() += 1;
        SyncHost::get_mast_forest(&self.inner, request)
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        SyncHost::on_event(&mut self.inner, process)
    }

    fn on_trace(&mut self, process: &ProcessorState<'_>) -> Result<(), TraceError> {
        SyncHost::on_trace(&mut self.inner, process)
    }
}

struct Case {
    code: CodePackage,
    environment: FixtureEnvironment,
}

impl Case {
    fn host(&self) -> (CountedHost, Arc<CountedSource>) {
        let source = Arc::new(CountedSource {
            inner: self.environment.source(),
            queries: Mutex::new(BTreeMap::new()),
        });
        let mut host = DefaultHost::default().with_environment_source(source.clone());
        host.load_library(self.code.clone())
            .expect("preload LibraryTree benchmark code");
        (
            CountedHost {
                inner: host,
                code_queries: Mutex::new(BTreeMap::new()),
            },
            source,
        )
    }
}

fn fixture(scenario: Scenario) -> Case {
    let mut source = String::from("proc callee push.1 drop end\n");
    if scenario.aliases {
        source.push_str("proc alias push.1 drop end\n");
    }
    source.push_str("begin\n");
    for index in 0..scenario.calls {
        let callee = if scenario.aliases && index % 2 == 1 {
            "alias"
        } else {
            "callee"
        };
        writeln!(source, "{}.{}", if scenario.call { "call" } else { "exec" }, callee)
            .expect("write fixed-body invocation");
    }
    source.push_str("end\n");
    let (code, _) = assemble_fixture_program(Assembler::default(), "librarytree", source, &[]);
    let naming = code.symbols();
    let selected = naming.callables().selected_implementations().collect::<Vec<_>>();
    if scenario.aliases {
        let mut helper_implementations = selected
            .iter()
            .filter(|(key, _)| Some(**key) != naming.entry_key())
            .map(|(_, implementation)| *implementation);
        let first = helper_implementations.next().expect("first alias implementation");
        assert_eq!(helper_implementations.next(), Some(first), "aliases must select equal D");
        assert!(helper_implementations.next().is_none(), "exactly two helper keys");
    }
    let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
        max_submitted_nodes: 4096,
        max_visits: 4096,
        max_depth: 64,
        max_list_children: 1024,
        max_encoded_bytes: 1024 * 1024,
        max_bindings: 16,
        max_storage_bytes: 8 * 1024 * 1024,
    });
    let mut children = Vec::new();
    for (key, implementation) in selected {
        let binding = naming.callables().binding(*key).expect("exact selected binding");
        let (leaf, parents) = binding.path().components().split_last().expect("callable label");
        let mut root = builder
            .insert(EnvNode::Mast {
                label: CanonicalLabel::text(leaf).expect("compiled label").commitment(),
                implementation: *implementation,
            })
            .expect("insert executable leaf");
        let labels = binding
            .namespace_plan()
            .home()
            .iter()
            .cloned()
            .chain(
                parents
                    .iter()
                    .map(|label| CanonicalLabel::text(label).expect("compiled parent")),
            )
            .collect::<Vec<_>>();
        for label in labels.into_iter().rev() {
            root = builder
                .insert(EnvNode::Env { label: label.commitment(), child: root })
                .expect("preserve exact compiled namespace");
        }
        children.push(root);
    }
    for index in 0..scenario.unused {
        children.push(
            builder
                .insert(EnvNode::Data {
                    kind: 0,
                    label: CanonicalLabel::text(&format!("unused_{index}"))
                        .expect("fixed unused label")
                        .commitment(),
                    value: Word::new([Felt::from_u32(index as u32); 4]),
                })
                .expect("insert unused data leaf"),
        );
    }
    let root = if scenario.merkle {
        merkle_root(&mut builder, &children)
    } else {
        builder.insert(EnvNode::List(children)).expect("insert shallow List")
    };
    let fragment: Arc<ValidatedEnvironment> =
        Arc::new(builder.finish(root).expect("validate fragment"));
    let environment = FixtureEnvironment::new_with_fragments(
        naming.entry_key().expect("caller-selected compiled entry"),
        [naming.as_ref()],
        core::slice::from_ref(&fragment),
    )
    .expect("mount exact benchmark fragment");
    assert_eq!(
        environment.validated_environment().root(),
        fragment.root(),
        "a singleton fragment must retain its selected collection shape without an outer edge",
    );
    Case { code, environment }
}

fn merkle_root(builder: &mut EnvironmentBuilder, children: &[EnvironmentRoot]) -> EnvironmentRoot {
    match children {
        [] => return builder.insert(EnvNode::List(Vec::new())).expect("insert empty collection"),
        [root] => return *root,
        _ => {},
    }
    let midpoint = children.len() / 2;
    let left = merkle_root(builder, &children[..midpoint]);
    let right = merkle_root(builder, &children[midpoint..]);
    builder
        .insert(EnvNode::Merkle { left, right })
        .expect("insert balanced Merkle node")
}

/// Every selected source starts with the default stack and uses only stack-neutral bodies.
/// This expectation belongs to the benchmark caller, independently of producer outputs.
fn expected_outputs() -> StackOutputs {
    StackOutputs::default()
}

fn native_proof(case: &Case) -> (ExecutionProof, ExecutionClaim, Value) {
    let (mut host, source) = case.host();
    let prover = Prover::new().with_hash_fn(HashFunction::Eidos);
    let start = Instant::now();
    let (outputs, proof) = prove_sync(
        &prover,
        case.environment.target(),
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        execution_options(&case.environment),
    )
    .expect("prove exactly one LibraryTree execution");
    let prove_ns = start.elapsed().as_nanos();
    let expected = expected_outputs();
    assert_eq!(outputs, expected, "fixed-body fixture must preserve the known zero stack");
    let claim = ExecutionClaim::new(case.environment.target(), StackInputs::default(), expected);
    let start = Instant::now();
    let outcome = Verifier::new().verify(&claim, &proof).expect("verify caller-built claim");
    assert!(outcome.is_complete(), "native verification must discharge every obligation");
    let verify_ns = start.elapsed().as_nanos();
    let security = outcome.vm_security_parameters();
    let protocol = security.protocol_params;
    let instance = security.instance_shape;
    let air = security.air_shape;
    let result = json!({
        "run_scope": "one_actual_prove_sync_then_native_verification",
        "hash": "Eidos",
        "timing_instrumentation": "source_and_host_callback_counting_included",
        "prove_ns": prove_ns,
        "native_verify_ns": verify_ns,
        "proof_bytes": proof.to_bytes().len(),
        "verification_complete": outcome.is_complete(),
        "opening_source_queries": source.snapshot(),
        "code_host_queries": host.code_snapshot(),
        "security": {
            "conjectured_bits": security.conjectured_security_level(),
            "num_deep_terms": air.num_deep_terms,
            "lookup_fractions_per_row": air.lookup.map(|lookup| lookup.fractions_per_row),
            "lookup_max_message_width": air.lookup.map(|lookup| lookup.max_message_width),
            "num_lookup_boundary_terms": security.num_lookup_boundary_terms,
            "num_ood_points": security.num_ood_points,
            "log_final_degree": security.log_final_degree,
            "air_shape": {
                "num_composed_constraints": air.num_composed_constraints,
                "max_constraint_degree": air.max_constraint_degree,
                "num_quotient_chunks": air.num_quotient_chunks,
                "max_combo": air.max_combo,
            },
            "protocol": {
                "log_blowup": protocol.log_blowup,
                "log_folding_arity": protocol.log_folding_arity,
                "num_queries": protocol.num_queries,
                "query_pow_bits": protocol.query_pow_bits,
                "ood_pow_bits": protocol.ood_pow_bits,
                "deep_pow_bits": protocol.deep_pow_bits,
                "folding_pow_bits": protocol.folding_pow_bits,
                "lookup_pow_bits": protocol.lookup_pow_bits,
            },
            "instance": {
                "log_max_height": instance.log_max_height,
                "field_bits_q16": instance.field_bits,
                "collision_resistance_bits": instance.collision_resistance,
            },
        },
    });
    (proof, claim, result)
}

fn shape(case: &Case) -> Value {
    let (mut host, source) = case.host();
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        execution_options(&case.environment),
    )
    .expect("bounded shape processor")
    .execute_for_proving_sync(case.environment.target(), &mut host)
    .expect("separate shape execution");
    let (vm_witness, _) = witness.into_parts();
    let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget())
        .expect("materialize actual trace");
    assert_eq!(
        *trace.stack_outputs(),
        expected_outputs(),
        "separate shape execution must preserve the known zero stack",
    );
    let summary = trace.trace_len_summary();
    let chiplets = summary.chiplets();
    let contexts = (0..summary.core_rows())
        .map(|row| trace.main_trace().ctx(RowIndex::from(row as u32)).as_canonical_u64())
        .collect::<BTreeSet<_>>();
    json!({
        "run_scope": "separate_untimed_execute_for_proving_and_build_trace",
        "library_rows": chiplets.library_len(),
        "controller_rows": chiplets.hash_chiplet_len(),
        "aead_rows": chiplets.aead_len(),
        "memory_rows": chiplets.memory_chiplet_len(),
        "ace_rows": chiplets.ace_chiplet_len(),
        "bitwise_rows": chiplets.bitwise_chiplet_len(),
        "chiplets_rows": summary.chiplets_rows(),
        "core_rows": summary.core_rows(),
        "eidos_compression_rows": summary.eidos_compression_rows(),
        "eidos_compression_count": summary.eidos_compression_count(),
        "byte_pair_lookup_rows": summary.byte_pair_lookup_rows(),
        "padded_heights_core_chiplets_eidos_bytepair": summary.padded_heights(),
        "distinct_core_contexts_unpadded": contexts.len(),
        "opening_source_queries": source.snapshot(),
        "code_host_queries": host.code_snapshot(),
    })
}

fn session(case: &Case) -> Value {
    let (mut host, source) = case.host();
    let mut processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        execution_options(&case.environment),
    )
    .expect("bounded diagnostic processor");
    let mut resume = processor
        .get_initial_resume_context(case.environment.target())
        .expect("caller-selected diagnostic target");
    let mut session_intervals = Vec::new();
    let mut previous = resume.resolution_session().counters();
    let mut previous_phase = resume.resolution_session().phase();
    let mut queries = 0;
    let mut code_queries = 0;
    let mut steps = 0;
    while !resume.is_complete() {
        processor.step_sync(&mut host, &mut resume).expect("step diagnostic execution");
        steps += 1;
        assert!(steps <= 100_000, "bounded scenario must finish within diagnostic step limit");
        let counters = resume.resolution_session().counters();
        let phase = resume.resolution_session().phase();
        if counters.committed_requests != previous.committed_requests
            || counters.reserved_requests != previous.reserved_requests
            || phase != previous_phase
        {
            // Entry authentication initially reserves its eventual root-END use. If an
            // execution step also commits an invocation, keep both operations in one
            // explicitly labeled interval instead of attributing every callback to it.
            let stage = if previous_phase == SessionPhase::Unentered {
                if counters.committed_requests != previous.committed_requests {
                    "entry_authentication_and_runtime_commit"
                } else {
                    "entry_authentication"
                }
            } else if phase == SessionPhase::Completed {
                "terminal_root_end_entry_commit"
            } else {
                "runtime_invocation_commit"
            };
            let current_queries = source.total();
            let current_code_queries = host.code_total();
            session_intervals.push(json!({
                "stage": stage,
                "phase_before": format!("{previous_phase:?}"),
                "phase_after": format!("{phase:?}"),
                "committed_requests_before": previous.committed_requests,
                "committed_requests_after": counters.committed_requests,
                "reserved_requests_before": previous.reserved_requests,
                "reserved_requests_after": counters.reserved_requests,
                "cached_keys_before": previous.cached_keys,
                "cached_keys_after": counters.cached_keys,
                "opening_queries_total": current_queries,
                "opening_queries_in_interval": current_queries - queries,
                "code_queries_total": current_code_queries,
                "code_queries_in_interval": current_code_queries - code_queries,
            }));
            previous = counters;
            previous_phase = phase;
            queries = current_queries;
            code_queries = current_code_queries;
        }
    }
    let outputs = StackOutputs::new(&processor.stack().iter().rev().copied().collect::<Vec<_>>())
        .expect("completed fixed-body diagnostic stack must fit public outputs");
    assert_eq!(
        outputs,
        expected_outputs(),
        "session execution must preserve the known zero stack"
    );
    let session = resume.resolution_session();
    let counters = session.finalize().expect("native session completed");
    let ledger = session.ledger().counters();
    let bindings = session
        .bindings()
        .iter()
        .map(|binding| {
            json!({
                "key": format!("{:?}", binding.procedure_key()),
                "implementation": format!("{:?}", binding.implementation_root()),
                "normal_uses": binding.counts().normal,
                "syscall_uses": binding.counts().syscall,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "run_scope": "separate_untimed_completed_public_stepping_session",
        "session_complete": resume.is_complete(),
        "cached_keys": counters.cached_keys,
        "committed_requests": counters.committed_requests,
        "reserved_requests": counters.reserved_requests,
        "binding_uses": bindings,
        "invocation_use_records_including_root_end": session.uses().count(),
        "ledger": {
            "occurrences": ledger.occurrences,
            "total_list_children": ledger.total_list_children,
            "encoded_bytes": ledger.encoded_bytes,
            "logical_library_rows_before_prefix_padding": ledger.library_rows,
            "opening_compression_requests_before_shared_eidos_interning": ledger.compression_requests,
        },
        "opening_source_queries": source.snapshot(),
        "code_host_queries": host.code_snapshot(),
        "interval_semantics": "actual_callbacks_between_observed_session_state_changes_not_hit_or_miss_counts",
        "session_intervals": session_intervals,
    })
}

/// Executes exactly one child-proof verifier in MASM, with its selected profile's exact
/// shared fragment and full advice/resource authorization. Child proving/setup is excluded
/// from the recursive execution timer and reported in the native proof measurement.
fn recursive(case: &Case) -> Value {
    let (proof, claim, native) = native_proof(case);
    let core_lib = CoreLibrary::default();
    let profile = core_lib.vm_recursive_verifier_profile().expect("embedded VM verifier profile");
    let (advice_inputs, claim_commitment) =
        RecursiveVerifierInputs::for_request(profile.identity(), &proof, &claim)
            .expect("one child recursive request")
            .into_parts();
    let mut source = String::from("use miden::core::sys\nuse miden::core::sys::vm\nbegin\n");
    push_word(&mut source, claim_commitment);
    source.push_str("dupw\n");
    push_word(&mut source, profile.identity().into_word());
    source.push_str(
        "exec.sys::build_proof_request_key\nadv.push_mapval dropw\nexec.vm::verify_proof\ndropw dropw dropw dropw\nend\n",
    );
    let assembler = Assembler::default()
        .with_package(core_lib.code_package().clone(), Linkage::Dynamic)
        .expect("link exact core library");
    let (code, _) =
        assemble_fixture_program(assembler, "librarytree_one_child", source, &[core_lib.naming()]);
    let environment = FixtureEnvironment::new_with_fragments(
        code.symbols().entry_key().expect("recursive entry"),
        [code.symbols().as_ref(), core_lib.naming().as_ref()],
        &[profile.shared_fragment()],
    )
    .expect("mount exact recursive profile fragment");
    let mut effective_advice = core_lib.mast_forest().advice_map().clone();
    effective_advice
        .merge(advice_inputs.map())
        .expect("child advice must not conflict");
    effective_advice
        .merge(code.package().mast_forest().advice_map())
        .expect("caller advice must not conflict");
    profile
        .authorize(
            environment.target().environment_root(),
            environment.validated_environment(),
            &effective_advice,
            environment.validated_environment().visits(),
        )
        .expect("authorize exact recursive environment and resources");
    let mut host = DefaultHost::default().with_environment_source(environment.source());
    host.load_library(&core_lib).expect("preload recursive verifier code");
    host.load_library(code).expect("preload recursive caller code");
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        advice_inputs,
        execution_options(&environment),
    )
    .expect("bounded recursive processor");
    let start = Instant::now();
    let output = processor
        .execute_sync(environment.target(), &mut host)
        .expect("verify one child in MASM");
    let recursive_execute_ns = start.elapsed().as_nanos();
    assert_eq!(
        output.stack,
        expected_outputs(),
        "recursive verifier caller must restore its known zero stack",
    );
    json!({
        "run_scope": "one_child_native_proof_then_one_actual_masm_verifier_execution",
        "native_child": native,
        "child_proofs": 1,
        "masm_verify_execute_ns": recursive_execute_ns,
        "profile_authorized": true,
        "outer_proof_generated": false,
    })
}

fn push_word(source: &mut String, word: Word) {
    for value in word.into_elements().into_iter().rev() {
        writeln!(source, "push.{}", value.as_canonical_u64()).expect("write recursive word");
    }
}

pub(super) fn dispatch() -> bool {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().is_none_or(|argument| argument != "--librarytree") {
        return false;
    }
    assert_eq!(arguments.len(), 3, "usage: {USAGE}");
    let mode = arguments[1].as_str();
    assert!(matches!(mode, "proof" | "shape" | "session" | "recursive"), "usage: {USAGE}");
    let scenario = Scenario::parse(&arguments[2]);
    let case = fixture(scenario);
    let measurement = match mode {
        "proof" => native_proof(&case).2,
        "shape" => shape(&case),
        "session" => session(&case),
        "recursive" => recursive(&case),
        _ => unreachable!("validated mode"),
    };
    println!(
        "{}",
        json!({
            "schema": "miden-librarytree-qualification-v1",
            "mode": mode,
            "configuration": scenario.configuration(),
            "execution_target": format!("{:?}", case.environment.target()),
            "environment_visits": case.environment.validated_environment().visits(),
            "expected_outputs": "sixteen_zero_felts_from_stack_neutral_source",
            "cache_policy": {
                "host_code": "preloaded_via_load_library_before_timing",
                "processor_code_request_cache": "initially_empty_per_execution",
                "processor_binding_cache": "initially_empty_resolution_session_per_execution",
                "host_opening_cache": "none",
                "repeated_calls": "binding_and_loaded_CodeRequest_caches_warm_only_within_execution",
                "opening_queries": "observed_actual_EnvironmentSource_callbacks",
                "code_queries": "observed_actual_SyncHost_get_mast_forest_callbacks",
                "cold_lazy_code_loading_measured": false,
            },
            "measurement": measurement,
        })
    );
    true
}
