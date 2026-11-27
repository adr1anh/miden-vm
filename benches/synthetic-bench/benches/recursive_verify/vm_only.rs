//! Matched execution and proving measurements for VM-only recursive verification.

use std::{collections::HashSet, hint::black_box, path::PathBuf, time::Instant};

use miden_core::{
    deferred::TRUE_DIGEST,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
};
use miden_core_lib::CoreLibrary;
use miden_processor::{ExecutionOptions, FastProcessor};
use miden_utils_testing::librarytree::trace_limits;
use miden_vm::{Prover, StackInputs, StackOutputs};

use super::{
    RecursionCase, build_recursive_verifier_case,
    config::{BenchConfig, env_usize, env_usize_allow_zero},
    fixtures::load_tx_fixtures,
    measurements::{print_case_shape, prove_recursive_once},
};

pub(super) enum Mode {
    Smoke,
    Execute,
    Prove,
}

impl Mode {
    pub(super) fn from_env() -> Option<Self> {
        match std::env::var("RECURSION_VM_ONLY") {
            Ok(mode) => Some(match mode.as_str() {
                "smoke" => Self::Smoke,
                "execute" => Self::Execute,
                "prove" => Self::Prove,
                _ => panic!("RECURSION_VM_ONLY must be smoke, execute, or prove"),
            }),
            Err(std::env::VarError::NotPresent) => None,
            Err(err) => panic!("invalid RECURSION_VM_ONLY: {err}"),
        }
    }

    pub(super) fn run(
        &self,
        config: &BenchConfig,
        prover: &Prover,
        max_proofs: usize,
        core_lib: &CoreLibrary,
    ) {
        let fixture_dir = PathBuf::from(
            std::env::var_os("RECURSION_VM_FIXTURE_DIR").expect("set RECURSION_VM_FIXTURE_DIR"),
        );
        let smoke = matches!(self, Self::Smoke);
        let repeats = if smoke { 1 } else { env_usize("RECURSION_VM_REPEATS", 5) };
        let warmups = if smoke {
            0
        } else {
            env_usize_allow_zero("RECURSION_VM_WARMUPS", 2)
        };
        let mut cases = Vec::new();
        for scenario in ["bitwise-memory", "compression-arithmetic"] {
            let path = fixture_dir.join(format!("{scenario}.masm"));
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            let fixtures = load_tx_fixtures(core_lib, config, max_proofs, &source, scenario);
            for &composition in config.compositions() {
                cases.push(build_recursive_verifier_case(
                    core_lib,
                    &fixtures,
                    composition,
                    None,
                    scenario,
                    config.write_recursive_masm(),
                    smoke,
                ));
            }
        }

        if smoke {
            check_calls(&cases[0]);
            for case in &cases {
                execute_once(case);
                prove_recursive_once(prover, case);
                println!(
                    "BENCH_VM_SMOKE scenario={} {} accepted=true empty_deferred=true outer_verified=true",
                    case.scenario,
                    case.composition.machine_fields(),
                );
            }
            return;
        }
        if matches!(self, Self::Prove) {
            for case in &cases {
                print_case_shape(case);
            }
        }
        for round in 0..warmups + repeats {
            for offset in 0..cases.len() {
                let case = &cases[(round + offset) % cases.len()];
                let (phase, elapsed_ms, proof_bytes) = match self {
                    Self::Execute => ("execute", execute_once(case), 0),
                    Self::Prove => {
                        let (elapsed_ms, proof_bytes) = prove_recursive_once(prover, case);
                        ("prove", elapsed_ms, proof_bytes)
                    },
                    Self::Smoke => unreachable!("smoke checks run separately"),
                };
                if round >= warmups {
                    println!(
                        "BENCH_VM_SAMPLE phase={phase} scenario={} {} run={} ms={elapsed_ms:.6} proof_bytes={proof_bytes}",
                        case.scenario,
                        case.composition.machine_fields(),
                        round - warmups + 1,
                    );
                }
            }
        }
    }
}

fn execute_once(case: &RecursionCase) -> f64 {
    let mut host = case.host();
    let options = ExecutionOptions::default()
        .with_environment_trace_limits(trace_limits())
        .with_resolution_limits(case.environment.resolution_limits());
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        case.advice_inputs.clone(),
        options,
    )
    .expect("recursive verifier advice should fit provider limits");
    let target = case.environment.target();
    let start = Instant::now();
    let output = processor.execute_sync(target, &mut host).expect("execute recursive verifier");
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(output.stack, StackOutputs::default());
    assert_eq!(output.precompile_root(), TRUE_DIGEST);
    black_box(output);
    elapsed_ms
}

fn check_calls(case: &RecursionCase) {
    let library = case.core_lib.mast_forest();
    let profile = case.core_lib.vm_recursive_verifier_profile().expect("VM verifier profile");
    let wrapper_forest = case.code.package().mast_forest();
    assert!(wrapper_forest.nodes().iter().any(|node| {
        matches!(node, MastNode::Exec(exec) if exec.target() == profile.entry_key())
    }));
    let verifier = library
        .find_procedure_root(case.core_lib.vm_recursive_verifier_root())
        .expect("verifier implementation");
    let inner = descendants(library, verifier)
        .into_iter()
        .find_map(|node| match node {
            MastNode::Call(call) => Some(call.target()),
            _ => None,
        })
        .expect("verifier's isolated call");
    let implementation = case
        .core_lib
        .naming()
        .callables()
        .selected_implementation(inner)
        .expect("selected inner verifier implementation");
    let inner = library
        .find_procedure_root(*implementation.as_word())
        .expect("inner verifier body");
    let keyed_exec_nodes = descendants(library, inner)
        .iter()
        .filter(|node| matches!(node, MastNode::Exec(_)))
        .count();
    assert!(keyed_exec_nodes > 0, "expected keyed execs inside the verifier");
    println!(
        "BENCH_VM_CALLS wrapper=keyed_exec verifier_inner_keyed_exec_nodes={keyed_exec_nodes}"
    );
}

fn descendants(forest: &MastForest, root: MastNodeId) -> Vec<&MastNode> {
    let mut nodes = Vec::new();
    let mut pending = vec![root];
    let mut seen = HashSet::new();
    while let Some(id) = pending.pop() {
        if seen.insert(id) {
            let node = &forest[id];
            node.for_each_child(|child| pending.push(child));
            nodes.push(node);
        }
    }
    nodes
}
