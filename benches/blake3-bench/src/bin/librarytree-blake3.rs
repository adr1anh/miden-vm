//! Independently checked Blake3 LibraryTree qualification.
//!
//! Run diagnostics and proof timings in separate processes, pinned to one performance CPU.
//! For example: `taskset -c 4 librarytree-blake3 --iterations 32 --mode diagnostics` and
//! `taskset -c 4 librarytree-blake3 --iterations 32 --mode proof --samples 5`.
//! Diagnostics use fresh executions for the trace and the public resolution session. Their
//! counters describe those executions; callback instrumentation is absent from timed runs.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use clap::Parser;
use miden_core::operations::opcodes;
use miden_vm::{
    DefaultHost, EnvironmentSource, EnvironmentSourceError, EnvironmentWitnessRequest,
    FastProcessor, HashFunction, Prover, ResolutionWitness, StackOutputs, Verifier,
    trace::RowIndex,
};
use miden_vm_blake3_bench::{
    Blake3Fixture, build_trace, default_host, execute_for_proving, execute_program,
    execution_options, repo_root_from_manifest,
};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    about = "Qualify balanced LibraryTree fixtures with independently checked Blake3 chains."
)]
struct Args {
    #[arg(long)]
    repo_root: Option<PathBuf>,
    #[arg(long, value_parser = ["1", "8", "32"])]
    iterations: String,
    #[arg(long, value_parser = ["diagnostics", "proof"])]
    mode: String,
    /// Measured proofs after one unmeasured warmup proof.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..))]
    samples: u32,
}

struct CountedSource {
    inner: Arc<dyn EnvironmentSource>,
    callbacks: Mutex<BTreeMap<String, usize>>,
}

impl CountedSource {
    fn snapshot(&self) -> Value {
        let callbacks = self.callbacks.lock().expect("opening callback counter");
        json!({
            "total_callbacks": callbacks.values().sum::<usize>(),
            "unique_requested_keys": callbacks.len(),
            "callbacks_per_key": *callbacks,
        })
    }
}

impl EnvironmentSource for CountedSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        *self
            .callbacks
            .lock()
            .expect("opening callback counter")
            .entry(format!("{:?}", request.key))
            .or_default() += 1;
        self.inner.get(request)
    }
}

fn diagnostic_host(fixture: &Blake3Fixture) -> (DefaultHost, Arc<CountedSource>) {
    let source = Arc::new(CountedSource {
        inner: fixture.environment.source(),
        callbacks: Mutex::new(BTreeMap::new()),
    });
    let mut host = default_host().with_environment_source(source.clone());
    host.load_library(fixture.code.clone()).expect("load Blake3 fixture code");
    (host, source)
}

fn diagnostic_processor(fixture: &Blake3Fixture) -> FastProcessor {
    FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options().with_resolution_limits(fixture.environment.resolution_limits()),
    )
    .expect("bounded diagnostic processor")
}

fn assert_output(outputs: &StackOutputs, expected: &[u64; 8]) {
    let actual = outputs.iter().map(|felt| felt.as_canonical_u64()).collect::<Vec<_>>();
    assert_eq!(&actual[..8], expected, "independent native Blake3 chain oracle");
    assert!(
        actual[8..].iter().all(|&value| value == 0),
        "remaining output limbs must be zero"
    );
}

fn trace_diagnostics(fixture: &Blake3Fixture, expected: &[u64; 8]) -> Value {
    let (mut host, source) = diagnostic_host(fixture);
    let witness = diagnostic_processor(fixture)
        .execute_for_proving_sync(fixture.environment.target(), &mut host)
        .expect("execute diagnostic trace witness");
    assert_output(witness.claim().stack_outputs(), expected);
    let trace = build_trace(witness);
    assert_output(trace.stack_outputs(), expected);
    let shape = trace.trace_len_summary();
    let execs = (0..shape.core_rows())
        .filter(|&row| {
            let row = RowIndex::from(u32::try_from(row).expect("bounded core trace"));
            trace.main_trace().get_op_code(row).as_canonical_u64() == u64::from(opcodes::EXEC)
        })
        .count();
    let last = trace.main_trace().last_program_row();
    json!({
        "scope": "separate_fresh_execute_for_proving_and_trace_no_proof",
        "guest_cycles": trace.main_trace().clk(last).as_canonical_u64(),
        "execs": execs,
        "core_rows": shape.core_rows(),
        "library_prefix_rows": shape.chiplets().library_len(),
        "chiplets_rows": shape.chiplets_rows(),
        "distinct_eidos_blocks": shape.eidos_compression_count(),
        "eidos_compression_rows": shape.eidos_compression_rows(),
        "and8_rows": shape.byte_pair_lookup_rows(),
        "padded_heights_core_chiplets_eidos_and8": shape.padded_heights(),
        "opening_source": source.snapshot(),
    })
}

fn session_diagnostics(fixture: &Blake3Fixture, expected: &[u64; 8]) -> Value {
    let (mut host, source) = diagnostic_host(fixture);
    let mut processor = diagnostic_processor(fixture);
    let mut resume = processor
        .get_initial_resume_context(fixture.environment.target())
        .expect("initialize diagnostic session");
    let mut steps = 0usize;
    while !resume.is_complete() {
        processor
            .step_sync(&mut host, &mut resume)
            .expect("complete diagnostic session step");
        steps += 1;
        assert!(steps < 1_000_000, "bounded qualification stepping budget");
    }
    let outputs = StackOutputs::new(&processor.stack().iter().rev().copied().collect::<Vec<_>>())
        .expect("completed public stack");
    assert_output(&outputs, expected);
    let session = resume.resolution_session();
    let counters = session.finalize().expect("completed resolution session");
    let ledger = session.ledger().counters();
    json!({
        "scope": "separate_fresh_completed_public_step_session_no_trace_or_proof",
        "guest_cycles": processor.state().clock().as_usize(),
        "cached_keys": counters.cached_keys,
        "committed_requests_including_root_end": counters.committed_requests,
        "ledger": {
            "occurrences": ledger.occurrences,
            "total_list_children": ledger.total_list_children,
            "encoded_bytes": ledger.encoded_bytes,
            "logical_library_rows_before_prefix_padding": ledger.library_rows,
            "compression_requests_before_eidos_interning": ledger.compression_requests,
            "selected_edges": ledger.selected_edge_count(),
        },
        "opening_source": source.snapshot(),
    })
}

fn proof_samples(
    fixture: &Blake3Fixture,
    expected: &[u64; 8],
    measured: u32,
) -> Result<Value, Box<dyn std::error::Error>> {
    let prover = Prover::new().with_hash_fn(HashFunction::Eidos);
    let verifier = Verifier::new();
    let mut samples = Vec::new();
    for sample_index in 0..=measured {
        let start = Instant::now();
        let output = execute_program(fixture);
        let execute_ms = start.elapsed().as_secs_f64() * 1_000.0;
        assert_output(&output.stack, expected);

        let start = Instant::now();
        let witness = execute_for_proving(fixture);
        let witness_ms = start.elapsed().as_secs_f64() * 1_000.0;
        let claim = witness.claim();
        assert_eq!(claim.execution_descriptor(), fixture.environment.target());
        assert_eq!(claim.stack_inputs(), &fixture.stack_inputs);
        assert_eq!(claim.stack_outputs(), &output.stack);
        assert_output(claim.stack_outputs(), expected);

        let start = Instant::now();
        let proof = prover.prove_full(witness)?;
        let prove_ms = start.elapsed().as_secs_f64() * 1_000.0;
        let start = Instant::now();
        let outcome = verifier.verify(&claim, &proof)?;
        let verify_ms = start.elapsed().as_secs_f64() * 1_000.0;
        assert!(outcome.is_complete(), "proof must settle all precompile work");
        if sample_index > 0 {
            samples.push(json!({
                "execute_ms": execute_ms,
                "witness_ms": witness_ms,
                "prove_ms": prove_ms,
                "witness_plus_prove_ms": witness_ms + prove_ms,
                "verify_ms": verify_ms,
                "proof_bytes": proof.to_bytes().len(),
                "conjectured_security_bits": outcome.vm_security_parameters()
                    .conjectured_security_level(),
            }));
        }
    }
    Ok(json!({
        "scope": "uninstrumented_fresh_execution_witness_prove_full_and_verify_per_sample",
        "proof_hash": "eidos",
        "warmup_proofs": 1,
        "samples": samples,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    rayon::ThreadPoolBuilder::new().num_threads(1).build_global()?;
    let iterations = args.iterations.parse::<u32>()?;
    let root = args.repo_root.unwrap_or_else(repo_root_from_manifest);
    let (fixture, expected) = Blake3Fixture::load_checked_chain(&root, iterations);
    let measurements = match args.mode.as_str() {
        "diagnostics" => json!({
            "trace": trace_diagnostics(&fixture, &expected),
            "session": session_diagnostics(&fixture, &expected),
        }),
        "proof" => proof_samples(&fixture, &expected, args.samples)?,
        _ => unreachable!("clap validates qualification mode"),
    };
    let result = json!({
        "schema": "librarytree_blake3_qualification_v1",
        "workload": "blake3_1to1",
        "iterations": iterations,
        "mode": args.mode,
        "rayon_threads": rayon::current_num_threads(),
        "independent_oracle": "native blake3 crate with checked standard empty-message vector",
        "expected_top_eight_limbs": expected,
        "preserving_output_assertions": 8,
        "entry_key": format!("{:?}", fixture.environment.target().entry_key()),
        "environment_root": format!("{:?}", fixture.environment.target().environment_root()),
        "complete_environment_bindings": fixture.environment.validated_environment().bindings().len(),
        "measurements": measurements,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
