use std::{array, fmt::Write as _, sync::Arc};

use miden_air::vm::{MIDEN_AIR_COUNT, MidenAir, MidenMultiAir, config};
use miden_assembly::{
    Assembler,
    testing::{FixtureNamespace, source_file},
};
use miden_core::{
    Felt, WORD_SIZE, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    program::{ExecutionClaim, KernelDescriptor, NUM_CLAIM_ELEMENTS, Namespace},
    proof::HashFunction,
};
use miden_mast_package::{Package, TargetType};
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor};
use miden_stark::{Preprocessed, StarkConfig, air::Statement};
use miden_utils_testing::{
    AdviceInputs, Prover,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use miden_vm_stark::setup::config::eidos_config;
use p3_challenger::{CanObserve, FieldChallenger};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;
mod isolation;
mod proof_order_maps;
mod pvm_aux_trace;
mod pvm_deep_queries;
mod pvm_public_inputs;
mod pvm_scatter_bench;
mod pvm_settlement;
mod pvm_sigma_scatter;
mod pvm_verifier;
mod pvm_wrapper;
mod random_coin;
mod resource_lengths;
mod security;
mod security_math;
mod security_proven;
mod verifier_stack;
mod vm_scatter_bench;
mod vm_sigma_scatter;

use verifier_stack::{CALLER_WORD, VERIFIER_RETURN, VerifierStack};

use crate::naming::assemble;

pub(crate) fn pvm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/pvm/layout.masm");
    let prefix = format!("const {name} = ");
    let region_prefix = format!("### {name}: ");
    let value = source
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix(&prefix).or_else(|| {
                let (_, range) = line.strip_prefix(&region_prefix)?.split_once(" felts at ")?;
                range.split_once("..").map(|(start, _)| start)
            })?;
            value.parse::<u64>().ok()
        })
        .unwrap_or_else(|| panic!("missing generated PVM layout constant {name}"));
    u32::try_from(value).expect("PVM layout pointer must fit in u32")
}

pub(crate) fn vm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/vm/layout.masm");
    let prefix = format!("const {name} = ");
    let value = source
        .lines()
        .chain(include_str!("../../asm/sys/vm/parameters.masm").lines())
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("pub ")
                .unwrap_or(line)
                .strip_prefix(&prefix)?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or_else(|| panic!("missing generated VM layout constant {name}"));
    u32::try_from(value).expect("VM layout pointer must fit in u32")
}

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_large() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_even() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_EVEN_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_odd() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_ODD_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_single() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_max_kernel() {
    let kernel = max_kernel_source();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(&kernel),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_deferred_root() {
    let data =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_flipped_order() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_LARGE,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    let order = run_recursive_verifier(&data);
    let expected = expected_order_from_shape(&data);

    assert_eq!(order, expected);
    assert_ne!(order, (0..MIDEN_AIR_COUNT).collect::<Vec<_>>());
}

#[test]
fn stark_verifier_e2f4_derives_the_shape_proof_order_for_small_proofs() {
    let equal_height = generate_recursive_verifier_data(EXAMPLE_EQUAL_HEIGHTS, vec![], None);
    let core_heavy = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);

    let equal_height_order = run_recursive_verifier(&equal_height);
    let core_heavy_order = run_recursive_verifier(&core_heavy);

    assert_eq!(equal_height_order, expected_order_from_shape(&equal_height));
    assert_eq!(core_heavy_order, expected_order_from_shape(&core_heavy));
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let circuit_key = recursive_circuit_key();
    data.advice_map.retain(|(key, _)| *key != circuit_key);

    assert_recursive_verifier_rejects(data, "missing ACE circuit stream should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_corrupted_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let circuit_key = recursive_circuit_key();
    let stream = advice_map_value_mut(&mut data, circuit_key);
    stream[0] += Felt::ONE;

    assert_recursive_verifier_rejects(data, "corrupted ACE circuit stream should fail");
}

/// A forged per-AIR log height must be rejected.
///
/// The transcript-bound per-AIR heights are the verifier's authoritative proof-order input.
/// `stage_proof_order_maps` derives both position maps from them once; scatter staging, boundary
/// placement, and fold-coefficient staging read those maps. No standalone order tag is stored.
/// The heights arrive on the advice stack, so
/// `sys/vm/public_inputs.masm` observes them into the Fiat-Shamir transcript: a forged height
/// diverges the transcript, and the proof cannot survive that divergence.
///
/// The non-vacuity guard at the end is what makes this cover *order* binding rather than height
/// binding alone: at least one forgery must land the verifier on a different proof order, which is
/// exactly the case a verifier that took the heights on trust would scatter wrongly for.
#[test]
fn each_air_log_height_is_transcript_bound() {
    /// Proof-stream index of the first advice-supplied log height: 4 security parameters and the
    /// 4-felt deferred root precede it.
    const FIRST_LOG_HEIGHT: usize = 8;
    /// The And8Lookup height is verifier-fixed setup, so only the others come from the proof.
    const ADVICE_SUPPLIED_HEIGHTS: usize = MIDEN_AIR_COUNT - 1;

    let base = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    let honest_order = expected_order_from_shape(&base);
    let mut reordering_forgeries = 0usize;

    for air in 0..ADVICE_SUPPLIED_HEIGHTS {
        let mut data = base.clone();
        // Raise the height rather than lower it: `assert_shape_log`'s bounds stay satisfied either
        // way, so rejection cannot be explained by the structural check firing first.
        data.proof_stream[FIRST_LOG_HEIGHT + air] += 1;
        if expected_order_from_shape(&data) != honest_order {
            reordering_forgeries += 1;
        }

        assert_recursive_verifier_rejects(
            data,
            &format!("verifier accepted a forged log height for AIR {air}"),
        );
    }

    assert!(
        reordering_forgeries > 0,
        "no forged height moved the proof order, so this fixture cannot cover order binding"
    );
}

/// The negative direction of order binding cannot be explained by transcript divergence alone:
/// `each_air_log_height_is_transcript_bound` above would pass identically against a verifier
/// whose scatter, sigma placement and fold staging were hard-wired to the identity order, since a
/// forged height already diverges the transcript regardless of routing. This builds a mutant
/// `vm::verify_proof` from a fully staged scatter table, exchanging only the equal-width Core and
/// Chiplets auxiliary destinations. A paired control from the same source template accepts the
/// proof with correct routing; the mutant rejects it with only those destinations exchanged,
/// showing that the routing is load-bearing.
#[test]
fn verifier_rejects_a_non_identity_order_when_scatter_destinations_are_swapped() {
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    let proof_order = expected_order_from_shape(&data);
    assert_ne!(
        proof_order,
        (0..MIDEN_AIR_COUNT).collect::<Vec<_>>(),
        "fixture must have a non-identity proof order to exercise scatter routing"
    );

    let proof_position = |target| {
        proof_order
            .iter()
            .position(|&air| air == target)
            .expect("each Miden AIR occurs once in the proof order")
    };
    // Auxiliary destinations begin at table offset 12 and occupy two felts per proof position.
    // Core and Chiplets both use `pipe_2`, so exchanging only these cells keeps every procedure
    // digest and segment length valid while corrupting the routing permutation.
    let core_aux_destination = 12 + 2 * proof_position(MidenAir::CORE.instance_index());
    let chiplets_aux_destination = 12 + 2 * proof_position(MidenAir::CHIPLETS.instance_index());

    let source = |swap_destinations: bool| {
        let routing_mutation = if swap_destinations {
            format!(
                "exec.layout::ood_scatter_table_ptr add.{core_aux_destination} mem_load\n            \
                 exec.layout::ood_scatter_table_ptr add.{chiplets_aux_destination} mem_load\n            \
                 exec.layout::ood_scatter_table_ptr add.{core_aux_destination} mem_store\n            \
                 exec.layout::ood_scatter_table_ptr add.{chiplets_aux_destination} mem_store"
            )
        } else {
            String::new()
        };
        format!(
            "
        use miden::core::sys
        use miden::core::stark::utils
        use miden::core::stark::verifier

        use miden::core::sys::vm
        use miden::core::sys::vm::claim
        use miden::core::sys::vm::constraints_eval
        use miden::core::sys::vm::deep_queries
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::ood_frames
        use miden::core::sys::vm::public_inputs
        use miden::core::sys::vm::aux_trace

        begin
            exec.layout::claim_commitment_ptr mem_storew_le
            exec.layout::claim_ptr exec.claim::materialize_claim

            exec.utils::load_security_params
            exec.public_inputs::stage_boundary_inputs
            exec.vm::load_air_context
            {routing_mutation}

            procref.deep_queries::compute_deep_composition_polynomial_queries
            procref.constraints_eval::execute_constraint_evaluation_check
            procref.ood_frames::process_row_ood_evaluations
            procref.public_inputs::process_public_inputs
            procref.aux_trace::observe_aux_trace

            exec.verifier::verify
            exec.sys::truncate_stack
        end
    "
        )
    };

    let control_data = data.clone();
    let control_source = source(false);
    let control = build_test!(
        control_source.as_str(),
        &control_data.initial_stack(),
        control_data.advice_stack(),
        control_data.store,
        control_data.advice_map
    );
    control
        .execute_for_output()
        .expect("the paired control with correct scatter destinations must accept the proof");

    let mutated_source = source(true);
    let test = build_test!(
        mutated_source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store,
        data.advice_map
    );
    test.execute().expect_err(
        "verifier must reject a non-identity proof order when two scatter destinations are swapped",
    );
}

fn assert_recursive_verifier_rejects(data: VerifierData, message: &str) {
    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map
    );

    assert!(test.execute_for_output().is_err(), "{message}");
}

#[test]
fn folding_reseed_helper_matches_reference_sampler() {
    fn source(use_combined_helper: bool, pow_bits: usize) -> String {
        let sample = if use_combined_helper {
            "
            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            "
        } else {
            "
            push.41.31.29.23 push.0
            exec.random_coin::reseed_with_felt
            exec.random_coin::sample_folding_pow_and_ext
            "
        };

        format!(
            "
            use miden::core::sys
            use {{
                FOLDING_POW_BITS_PTR, RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_CV_PTR,
                RANDOM_COIN_INPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR,
                RANDOM_COIN_OUTPUT_WORD_PTR
            }} from miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.{pow_bits} mem_store.FOLDING_POW_BITS_PTR
                push.109.113.127.131 mem_storew_le.RANDOM_COIN_CV_PTR dropw
                exec.random_coin::eidos_clear_buffer
                push.0 mem_store.RANDOM_COIN_COUNTER_PTR
                push.0 mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR

                {sample}

                mem_load.RANDOM_COIN_OUTPUT_LENGTH_PTR
                mem_load.RANDOM_COIN_COUNTER_PTR
                mem_load.RANDOM_COIN_INPUT_LENGTH_PTR
                padw mem_loadw_le.RANDOM_COIN_OUTPUT_WORD_PTR
                padw mem_loadw_le.RANDOM_COIN_CV_PTR
                exec.sys::truncate_stack
            end
            "
        )
    }

    for pow_bits in [0, 1] {
        let (reference, _) = build_test!(&source(false, pow_bits), &[])
            .execute_for_output()
            .unwrap_or_else(|err| {
                panic!("reference sampler should execute with pow_bits={pow_bits}: {err:?}")
            });
        let (combined, _) = build_test!(&source(true, pow_bits), &[])
            .execute_for_output()
            .unwrap_or_else(|err| {
                panic!("combined sampler should execute with pow_bits={pow_bits}: {err:?}")
            });

        assert_eq!(
            combined.stack.get_num_elements(15),
            reference.stack.get_num_elements(15),
            "combined FRI reseed helper diverged from reference sampler with pow_bits={pow_bits}"
        );
    }
}

#[test]
fn folding_reseed_rejects_nonempty_buffer() {
    let source = "
        use {FOLDING_POW_BITS_PTR, RANDOM_COIN_CV_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.1 mem_store.FOLDING_POW_BITS_PTR
            push.109.113.127.131 mem_storew_le.RANDOM_COIN_CV_PTR dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(
        test,
        "reseed_with_folding_pow_and_ext: buffer must be empty"
    );
}

#[test]
fn zero_pow_folding_reseed_accepts_nonempty_buffer() {
    let source = "
        use {FOLDING_POW_BITS_PTR, RANDOM_COIN_CV_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.0 mem_store.FOLDING_POW_BITS_PTR
            push.109.113.127.131 mem_storew_le.RANDOM_COIN_CV_PTR dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            drop drop
        end
        ";

    build_test!(source, &[])
        .execute()
        .expect("zero-PoW reseed should flush a partial buffer");
}

#[test]
fn word_observe_helper_matches_scalar_observe() {
    fn source(use_word_helpers: bool) -> String {
        let observe = if use_word_helpers {
            "
            push.11.7.5.3
            exec.random_coin::observe_word
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        } else {
            "
            push.3 exec.random_coin::observe_felt
            push.5 exec.random_coin::observe_felt
            push.7 exec.random_coin::observe_felt
            push.11 exec.random_coin::observe_felt
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        };

        format!(
            "
            use miden::core::sys
            use {{
                RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_CV_PTR, RANDOM_COIN_INPUT_LENGTH_PTR,
                RANDOM_COIN_OUTPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_WORD_PTR
            }} from miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 mem_storew_le.RANDOM_COIN_CV_PTR dropw
                exec.random_coin::eidos_clear_buffer
                push.0 mem_store.RANDOM_COIN_COUNTER_PTR
                push.0 mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR

                {observe}
                exec.random_coin::sample_felt

                mem_load.RANDOM_COIN_OUTPUT_LENGTH_PTR
                mem_load.RANDOM_COIN_COUNTER_PTR
                mem_load.RANDOM_COIN_INPUT_LENGTH_PTR
                padw mem_loadw_le.RANDOM_COIN_OUTPUT_WORD_PTR
                padw mem_loadw_le.RANDOM_COIN_CV_PTR
                exec.sys::truncate_stack
            end
            "
        )
    }

    let (reference, _) = build_test!(&source(false), &[])
        .execute_for_output()
        .expect("scalar observe path should execute");
    let (optimized, _) = build_test!(&source(true), &[])
        .execute_for_output()
        .expect("word observe path should execute");

    assert_eq!(
        optimized.stack.get_num_elements(13),
        reference.stack.get_num_elements(13),
        "batched observe helpers changed random coin state"
    );
}

#[test]
fn observe_word_and_flush_buffer_matches_scalar_observe() {
    fn source(prefix_len: usize, use_word_helper: bool) -> String {
        let prefix = (0..prefix_len)
            .map(|idx| format!("push.{} exec.random_coin::observe_felt", idx + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let observe = if use_word_helper {
            "
            push.23.19.17.13
            exec.random_coin::observe_word_and_flush_buffer
            "
        } else {
            "
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            push.19 exec.random_coin::observe_felt
            push.23 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        };

        format!(
            "
            use miden::core::sys
            use {{
                RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_CV_PTR, RANDOM_COIN_INPUT_LENGTH_PTR,
                RANDOM_COIN_OUTPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_WORD_PTR
            }} from miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 mem_storew_le.RANDOM_COIN_CV_PTR dropw
                exec.random_coin::eidos_clear_buffer
                push.0 mem_store.RANDOM_COIN_COUNTER_PTR
                push.0 mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR

                {prefix}
                {observe}
                exec.random_coin::sample_felt

                mem_load.RANDOM_COIN_OUTPUT_LENGTH_PTR
                mem_load.RANDOM_COIN_COUNTER_PTR
                mem_load.RANDOM_COIN_INPUT_LENGTH_PTR
                padw mem_loadw_le.RANDOM_COIN_OUTPUT_WORD_PTR
                padw mem_loadw_le.RANDOM_COIN_CV_PTR
                exec.sys::truncate_stack
            end
            "
        )
    }

    for prefix_len in [0, 3, 4, 6] {
        let (reference, _) = build_test!(&source(prefix_len, false), &[])
            .execute_for_output()
            .expect("scalar observe path should execute");
        let (optimized, _) = build_test!(&source(prefix_len, true), &[])
            .execute_for_output()
            .expect("word observe path should execute");

        assert_eq!(
            optimized.stack.get_num_elements(13),
            reference.stack.get_num_elements(13),
            "word observe-and-flush helper changed random coin state with prefix_len={prefix_len}"
        );
    }
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> VerifierData {
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel = context.parse_kernel(source_file!(&context, kernel)).unwrap();
                let assembler = Assembler::new(context.source_manager());
                let mut fixture = FixtureNamespace::assembly_tests();
                fixture.add_kernel_modules(&assembler, &[&kernel]).unwrap();
                let product = fixture
                    .configure(assembler, [&*kernel])
                    .unwrap()
                    .assemble_library_modules("kernel".into(), kernel, [], TargetType::Kernel)
                    .unwrap();
                let kernel_naming = product.naming().clone();
                let kernel_lib = product.into_artifact(false).map(Arc::<Package>::from).unwrap();
                let assembler = Assembler::with_kernel(
                    context.source_manager(),
                    kernel_lib.clone(),
                    kernel_naming.clone(),
                )
                .unwrap();
                let program = assemble(assembler, "program", source, &[&kernel_naming]);
                (program, Some(kernel_lib))
            },
            None => {
                let program = assemble(Assembler::default(), "program", source, &[]);
                (program, None)
            },
        }
    };
    let stack_inputs = stack_inputs_from_ints(stack_inputs);
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default().with_environment_source(program.environment.source());
    if let Some(ref kernel_lib) = kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    let processor = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        ExecutionOptions::default()
            .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
    )
    .unwrap();
    let witness = processor
        .execute_for_proving_sync(&program.program, program.environment.execution(), &mut host)
        .unwrap();
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new().with_hash_fn(HashFunction::Eidos).prove(witness).unwrap();

    let claim = ExecutionClaim::new(
        program.environment.execution().descriptor(),
        stack_inputs,
        stack_outputs,
    );

    generate_advice_inputs(vm_verify_proof_root(), &proof, &claim).unwrap()
}

/// Returns the MAST root used to identify `sys::vm::verify_proof` in proof-request keys.
///
/// Operators obtain it through `CoreLibrary::vm_recursive_verifier_root`. Consumers obtain the
/// same value in MASM with `procref.vm::verify_proof`; the root belongs to the procedure itself and
/// does not depend on the program that calls it.
fn vm_verify_proof_root() -> Word {
    miden_core_lib::CoreLibrary::default().vm_recursive_verifier_root()
}

/// Test helper that copies `count` felts (a multiple of 4) from advice into memory at `dst`.
pub(crate) const COPY_ADVICE_TO_MEM: &str = "
        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                padw adv_loadw
                dup.4 mem_storew_le dropw
                add.4
                swap sub.4 swap
                dup.1 push.0 neq
            end
            drop drop
        end
";

/// Builds the consumer program: stage the claim from the consumer's own inputs, derive its
/// commitment, fetch the proof package registered under
/// `proof_request_key(verifier_root, claim_commitment)`, verify it, compute its security level, and
/// enforce the consumer's threshold. `vm::verify_proof` contains neither the estimator nor the
/// policy.
fn request_consumer_source(bound: &str, target: u32) -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        begin
            # 1) Fill the canonical claim encoding into VM memory from the consumer's own inputs
            #    (the advice tape) and derive the commitment that names it.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR}
            exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment
            # => [CLAIM_COMMITMENT]

            # 2) Fetch the registered proof package by content: request keys name
            #    vm::verify_proof's root, derived in-VM via procref.
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw
            # => [CLAIM_COMMITMENT]

            # 3) Verify the claim; vm::verify_proof returns the common security descriptor followed
            #    by the deferred obligation.
            exec.vm::verify_proof
            # => [security_descriptor(12), D]

            # 4) Compute the security level and enforce the consumer's threshold.
            exec.security::compute_{bound}_security_level
            # => [level, D]
            u32lt.{target} assertz.err=\"proof security level is below the accepted target\"
            # => [D]
            exec.sys::truncate_stack
        end
        "
    )
}

/// The end-to-end guarantee of fetching by content: a proof fetched via `proof_request_key` and
/// `adv.push_mapval` verifies when it matches the consumer's claim, and is rejected when it
/// does not. No separate binding check is needed for the fetched proof package.
#[test]
fn request_flow_binds_proof_to_claim() {
    use miden_core::program::proof_request_key;

    let intended = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);

    let source = request_consumer_source("conjectured", 96);
    let entry = |proof_stream: &[u64]| -> (Word, Vec<Felt>) {
        let felts: Vec<Felt> = proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        (proof_request_key(vm_verify_proof_root(), intended.claim_commitment), felts)
    };

    // Control: the intended proof, registered under its key, verifies.
    let (k, v) = entry(&intended.proof_stream);
    let mut advice_map = intended.advice_map.clone();
    advice_map.push((k, v));
    // Both estimators consume the same authenticated descriptor without disturbing the
    // deferred obligation. The proven threshold reflects the weaker proven query bound.
    for consumer in [&source, &request_consumer_source("proven", 56)] {
        let ok = build_test!(
            consumer.as_str(),
            &[],
            &intended.claim_advice,
            intended.store.clone(),
            advice_map.clone()
        );
        ok.execute_for_output()
            .expect("the matching proof must satisfy either security policy");
    }

    // Substitution: a different claim's proof under the same key fails against the consumer's
    // claim — the advice provider cannot pass off another proof. The intended claim's own
    // content-addressed entries stay available so rejection happens in verification,
    // rather than because an authenticated claim preimage is missing.
    let other =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    let (k, v) = entry(&other.proof_stream);
    let mut advice_map = other.advice_map.clone();
    advice_map.extend(intended.advice_map.iter().cloned());
    advice_map.push((k, v));
    let bad = build_test!(source.as_str(), &[], &intended.claim_advice, other.store, advice_map);
    assert!(
        bad.execute_for_output().is_err(),
        "a proof for a different claim must be rejected by verification"
    );
}

/// Two independently proven executions of one program (distinct stack i/o) verified inside a
/// single consumer program — each proof is registered
/// under `proof_request_key(verifier_root, claim_commitment)` and fetched by content, independent
/// of its position in the advice. The consumer stages each claim from its own inputs and derives
/// the commitment that names the claim and addresses its proof entry, so passing requires the
/// in-VM claim-commitment and request-key derivations to match their native
/// mirrors (a mismatch is a missing advice-map key).
#[test]
fn stark_verifier_e2f4_request_multi_proof() {
    use miden_core::program::proof_request_key;
    use miden_utils_testing::crypto::MerkleStore;

    let mut inputs = fib_stack_inputs();
    let tx0 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs.clone(), None);
    inputs[13] = 7; // distinct claim: same program, different stack inputs
    let tx1 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);

    // One advice provider for both proofs: the tape carries the claims from which the consumer
    // derives the commitments. Claim preimages, proof streams, and query rows are
    // content-addressed in the advice map.
    let verifier_root = vm_verify_proof_root();
    let mut tape = Vec::new();
    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();
    for tx in [&tx0, &tx1] {
        tape.extend(tx.claim_advice.iter().copied());
        store.extend(tx.store.inner_nodes());
        advice_map.extend(tx.advice_map.iter().cloned());
        let stream: Vec<Felt> = tx.proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        advice_map.push((proof_request_key(verifier_root, tx.claim_commitment), stream));
    }

    let source = format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        proc verify_one_claim
            # Per claim: stage the fields from the consumer's own inputs, derive the
            # commitment that names the claim, fetch and verify the proof package it
            # addresses, then compute the security level and enforce the acceptance threshold.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR} exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment # => [CLAIM_COMMITMENT]
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw                        # => [CLAIM_COMMITMENT]
            exec.vm::verify_proof                        # => [security_descriptor(12), D]
            exec.security::compute_conjectured_security_level # => [level, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            # => [D]
        end

        begin
            exec.verify_one_claim dropw
            exec.verify_one_claim dropw
            exec.sys::truncate_stack
        end
        "
    );

    let test = build_test!(source.as_str(), &[], &tape, store, advice_map);
    test.execute_for_output().expect("both content-addressed proofs must verify");
}

fn vm_verify_proof_program() -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::sys::vm

        const VERIFIER_RETURN = event(\"{VERIFIER_RETURN}\")

        begin
            exec.vm::verify_proof
            # => [security_descriptor(12), D, ...]
            trace.VERIFIER_RETURN
            exec.sys::truncate_stack
        end
        "
    )
}

fn run_recursive_verifier(data: &VerifierData) -> Vec<usize> {
    use miden_air::vm::security;

    let source = vm_verify_proof_program();
    let mut initial_stack = data.initial_stack().to_vec();
    initial_stack.extend(CALLER_WORD);
    let verifier_stack = VerifierStack::default();
    let test = build_test!(
        source.as_str(),
        &initial_stack,
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    )
    .with_trace_handler(VERIFIER_RETURN, verifier_stack.clone());
    let order = ace_read_check::execute_and_check(&test, &data.proof_stream, &data.claim_advice);

    // Pin the full common descriptor and deferred root so any value or ordering drift is caught
    // across every end-to-end configuration.
    let params = config::pcs_params();
    let height_start = 4 + WORD_SIZE;
    let log_max_height = data.proof_stream[height_start..height_start + MIDEN_AIR_COUNT - 1]
        .iter()
        .copied()
        .chain([u64::from(AND8_LOOKUP_LOG_HEIGHT)])
        .max()
        .expect("the MVM relation has AIR instances");
    assert_eq!(security::CORE_BOUNDARY_LOOKUP_TERMS, 3);

    let mut expected = vec![
        u64::from(security::LOOKUP_POW_BITS),
        u64::from(security::AIR_SHAPE.num_composed_constraints),
        u64::from(security::AIR_SHAPE.max_constraint_degree),
        u64::from(security::AIR_SHAPE.num_deep_terms.unwrap()),
        u64::from(security::LOOKUP_SHAPE.max_message_width),
        u64::from(security::CORE_BOUNDARY_LOOKUP_TERMS),
        u64::from(security::LOOKUP_SHAPE.fractions_per_row),
        log_max_height,
        params.num_queries() as u64,
        params.query_pow_bits() as u64,
        params.deep_pow_bits() as u64,
        params.folding_pow_bits() as u64,
    ];
    expected.extend_from_slice(&data.proof_stream[4..4 + WORD_SIZE]);
    verifier_stack.assert_outputs_and_caller(&expected);
    order
}

/// Derives the expected proof order from the log heights carried in the proof stream.
///
/// Proof-stream layout: 4 security parameters, the 4-felt deferred root, then the three
/// execution-dependent log heights (the And8Lookup height is verifier-fixed).
fn expected_order_from_shape(data: &VerifierData) -> Vec<usize> {
    vm_scatter_bench::proof_order(&[
        data.proof_stream[8],
        data.proof_stream[9],
        data.proof_stream[10],
        u64::from(AND8_LOOKUP_LOG_HEIGHT),
    ])
}

/// Each of the four security parameters (num_queries, query_pow_bits, deep_pow_bits,
/// folding_pow_bits) is absorbed into the Fiat-Shamir transcript, so forging any one of them in
/// the proof stream diverges the transcript and fails verification. They are the first four
/// advice values `vm::verify_proof` reads, i.e. `proof_stream[0..4]`.
#[test]
fn each_security_parameter_is_transcript_bound() {
    let source = vm_verify_proof_program();
    let base = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    for param in 0usize..4 {
        let mut data = base.clone();
        // Forge the parameter downward. In particular, the proof's original PoW nonces satisfy
        // the weaker targets, so rejection cannot be explained solely by demanding more work;
        // the changed transcript/verification schedule must invalidate the proof.
        data.proof_stream[param] -= 1;
        let test = build_test!(
            source.as_str(),
            &data.initial_stack(),
            data.advice_stack(),
            data.store.clone(),
            data.advice_map.clone()
        );
        expect_assert_error_message!(test);
    }
}

/// Claim v2 has no legacy kernel-sidecar fetch. Missing or forged advice under R_E is
/// unrelated to the proof, including lengths that the old protocol rejected.
#[test]
fn legacy_kernel_sidecars_have_no_authority() {
    let base = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let environment_root = claim_environment_root(&base);
    assert!(
        base.advice_map.iter().all(|(key, _)| *key != environment_root),
        "the canonical fixture must supply no legacy kernel sidecar"
    );
    let source = vm_verify_proof_program();
    for (case, sidecar) in [
        ("missing", None),
        ("forged", Some(vec![Felt::ONE; WORD_SIZE])),
        ("misaligned", Some(vec![Felt::ONE; WORD_SIZE + 1])),
        (
            "oversized",
            Some(vec![Felt::ZERO; (KernelDescriptor::MAX_NUM_PROCEDURES + 1) * WORD_SIZE]),
        ),
    ] {
        let mut data = base.clone();
        if let Some(sidecar) = sidecar {
            data.advice_map.push((environment_root, sidecar));
        }
        let test = build_test!(
            source.as_str(),
            &data.initial_stack(),
            data.advice_stack(),
            data.store.clone(),
            data.advice_map.clone()
        );
        test.execute_for_output().unwrap_or_else(|error| {
            panic!("{case} legacy kernel sidecar must be ignored as unrelated advice: {error}")
        });
    }
}

/// R_E remains authenticated by claim40 and by the proof statement even though unrelated
/// advice under its value has no authority. Recommit a changed expected R_E so materializing
/// the forged claim succeeds, and require the original proof to fail verification.
#[test]
fn mutated_expected_environment_root_is_rejected() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let old_commitment = data.claim_commitment;
    data.claim_advice[4] ^= 1;
    let forged_claim: [Felt; NUM_CLAIM_ELEMENTS] =
        array::from_fn(|i| Felt::new_unchecked(data.claim_advice[i]));
    let forged_commitment = miden_core::program::claim_commitment(&forged_claim);
    *advice_map_value_mut(&mut data, old_commitment) = forged_claim.to_vec();
    let claim_entry = data
        .advice_map
        .iter_mut()
        .find(|(key, _)| *key == old_commitment)
        .expect("claim preimage entry remains present");
    claim_entry.0 = forged_commitment;
    data.claim_commitment = forged_commitment;

    // Neither the original root nor an arbitrary value under the forged root can override
    // the expected descriptor committed by the caller.
    let forged_root = claim_environment_root(&data);
    data.advice_map.push((forged_root, vec![Felt::ONE; WORD_SIZE]));
    let materialize_source = "
        use miden::core::sys::vm::claim
        use miden::core::sys::vm::layout
        begin
            exec.layout::claim_ptr exec.claim::materialize_claim
        end
    ";
    let (materialized, _) = build_test!(
        materialize_source,
        &data.initial_stack(),
        &[],
        data.store.clone(),
        data.advice_map.clone()
    )
    .execute_for_output()
    .expect("the recommitted expected claim must authenticate before proof verification");
    assert_eq!(
        read_word(&materialized, vm_layout_const("CLAIM_PTR") + WORD_SIZE as u32),
        forged_root.into_elements(),
        "the forged root must be staged from the caller's authenticated expected claim"
    );
    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    test.execute_for_output()
        .expect_err("the original proof must reject a changed caller-authorized environment root");
}

/// The claim preimage is untrusted advice and must match the caller-provided commitment.
#[rstest]
#[case(0)]
#[case(4)]
fn tampered_claim_preimage_is_rejected(#[case] offset: usize) {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage[offset] = Felt::new_unchecked(preimage[offset].as_canonical_u64() ^ 1);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(test, "claim preimage commitment does not match");
}

/// The advice-map value under the claim commitment must use the canonical 40-felt encoding.
#[rstest]
#[case(NUM_CLAIM_ELEMENTS - 1)]
#[case(NUM_CLAIM_ELEMENTS + 1)]
fn malformed_claim_preimage_length_is_rejected(#[case] len: usize) {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage.resize(len, Felt::ZERO);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(test, "claim preimage has a non-canonical length");
}

/// R_E occupies claim40 offsets 4..8. Its value is public data, never a legacy sidecar key.
fn claim_environment_root(data: &VerifierData) -> Word {
    Word::new(array::from_fn(|i| Felt::new_unchecked(data.claim_advice[WORD_SIZE + i])))
}

/// Mutable reference to the advice-map value stored under `key`.
fn advice_map_value_mut(data: &mut VerifierData, key: Word) -> &mut Vec<Felt> {
    let entry = data
        .advice_map
        .iter_mut()
        .find(|(k, _)| *k == key)
        .expect("advice map has an entry under the requested key");
    &mut entry.1
}

/// Advice-map key the recursive verifier fetches the ACE circuit stream under.
///
/// One circuit serves every proof order, so this is the canonical circuit's own digest — the
/// same value `build_merkle_data` keys the advice entry with and the loader pins the stream to.
fn recursive_circuit_key() -> Word {
    miden_vm_stark::setup::ace::shared_recursive_circuit().commitment
}

// EXAMPLE PROGRAMS
// ================================================================================================

/// repeat.320 -> log_trace_height=10 -> FRI remainder degree < 64 -> verify_64 path
const EXAMPLE_FIB_SMALL: &str = "begin
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// repeat.400 -> log_trace_height=11 -> FRI remainder degree < 128 -> verify_128 path
const EXAMPLE_FIB_LARGE: &str = "begin
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

/// Tiny program where every AIR lands at its minimum height.
const EXAMPLE_EQUAL_HEIGHTS: &str = "begin push.1 drop end";

/// Like EXAMPLE_FIB_SMALL but with a syscall, for kernel-aware tests.
const EXAMPLE_FIB_KERNEL_SMALL: &str = "begin
        syscall.foo
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// Like EXAMPLE_FIB_LARGE but with a syscall, for kernel-aware flipped-order tests.
const EXAMPLE_FIB_KERNEL_LARGE: &str = "begin
        syscall.foo
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

const EXAMPLE_LOG_DEFERRED: &str = "begin
        log_deferred
        dropw
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

fn log_deferred_stack_inputs() -> Vec<u64> {
    // TRUE_DIGEST is the zero word and must occupy the top four positions. A nonzero first tail
    // element makes the post-`dropw` output visibly distinct from an empty stack.
    let mut inputs = vec![0_u64; 16];
    inputs[4] = 7;
    inputs
}

// EIDOS CHALLENGER PARITY TESTS
// ================================================================================================

/// The trusted AND8 preprocessed-trace commitment for the canonical Miden statement shape, as
/// bound by `load_air_context` (must match `AND8_PREPROCESSED_TRACE_COM_*` in `sys/vm/mod.masm`).
fn and8_preprocessed_commitment() -> [Felt; WORD_SIZE] {
    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![
            (0, vec![Felt::ZERO; miden_air::vm::NUM_PUBLIC_VALUES]),
            (1, vec![Felt::ZERO; WORD_SIZE]),
            (2, vec![]),
            (3, vec![]),
        ],
        vec![Felt::ZERO; WORD_SIZE],
    )
    .expect("zero public inputs satisfy the Miden statement shape");
    let commitment: [u64; WORD_SIZE] = Preprocessed::build(&statement, &config)
        .expect("the Miden relation declares the AND8 preprocessed table")
        .commitment()
        .into();
    commitment.map(Felt::new_unchecked)
}

fn read_word(output: &miden_processor::ExecutionOutput, addr: u32) -> [Felt; WORD_SIZE] {
    let ctx = miden_processor::ContextId::root();
    array::from_fn(|i| {
        output
            .memory
            .read_element(ctx, Felt::from_u32(addr + i as u32))
            .expect("memory read")
    })
}

/// Step-I transcript parity: the MASM Fiat-Shamir schedule (relation digest + PCS params via
/// `init_seed`, preprocessed commitment, `[CLAIM_HASH | D]`, AIR shape as five single felts,
/// main-trace commitment) squeezes the same word as the Rust Eidos challenger fed the identical
/// observation stream.
#[test]
fn public_input_transcript_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;
    const RANDOM_COIN_BUFFER_LEN_PTR: u32 = 3223322767;
    const RANDOM_COIN_OUTPUT_LENGTH_PTR: u32 = 3223322768;

    let log_heights = [10_u64, 11, 12];
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // The transcript binds the claim only through its commitment; the preimage merely has to be
    // staged for `stage_boundary_inputs`/`load_public_inputs` to read.
    let claim: [u64; NUM_CLAIM_ELEMENTS] = array::from_fn(|_| rng.next_u32() as u64);
    let claim_hash: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let deferred_root: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let main_trace_commitment: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);

    let mut advice_stack = log_heights.to_vec();
    advice_stack.extend_from_slice(&claim);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&main_trace_commitment);

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, MAIN_TRACE_COM_PTR, NUM_QUERIES_PTR,
            QUERY_POW_BITS_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            exec.vm::load_air_context

            # Stage the claim region and commitment the way `vm::verify_proof` leaves them.
            push.{NUM_CLAIM_ELEMENTS} exec.layout::claim_ptr exec.copy_advice_to_mem
            push.{ch3}.{ch2}.{ch1}.{ch0}
            exec.layout::claim_commitment_ptr mem_storew_le dropw
            exec.public_inputs::stage_boundary_inputs

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            # Main-trace commitment, then squeeze (the squeeze flushes the buffered stream).
            padw adv_loadw
            mem_storew_le.MAIN_TRACE_COM_PTR
            exec.random_coin::observe_word
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
        ch0 = claim_hash[0],
        ch1 = claim_hash[1],
        ch2 = claim_hash[2],
        ch3 = claim_hash[3],
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    // Rust mirror over the identical observation stream.
    let config = eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    miden_stark::config::observe_protocol_params(config.pcs(), &mut challenger);
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    for &element in claim_hash.iter().chain(deferred_root.iter()) {
        challenger.observe(Felt::new_unchecked(element));
    }
    challenger.observe(Felt::new_unchecked(MIDEN_AIR_COUNT as u64));
    for log_height in
        [log_heights[0], log_heights[1], log_heights[2], AND8_LOOKUP_LOG_HEIGHT as u64]
    {
        challenger.observe(Felt::new_unchecked(log_height));
    }
    for &element in &main_trace_commitment {
        challenger.observe(Felt::new_unchecked(element));
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);

    // The squeeze left neither buffered input nor cached output behind.
    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    assert_eq!(read(RANDOM_COIN_BUFFER_LEN_PTR), Felt::ZERO);
    assert_eq!(read(RANDOM_COIN_OUTPUT_LENGTH_PTR), Felt::ZERO);
}

#[test]
fn eidos_init_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, NUM_QUERIES_PTR, QUERY_POW_BITS_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            exec.vm::load_air_context
            exec.random_coin::init_seed
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
    );

    let shape = [10_u64, 11, 12];
    let test = build_test!(source.as_str(), &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    miden_stark::config::observe_protocol_params(config.pcs(), &mut challenger);
    // `init_seed` also stages the trusted preprocessed-trace commitment onto the buffered stream.
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
}

#[test]
fn eidos_relation_digest_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    // The pushed word is `Eidos::transcript_init_cv(STARK_TRANSCRIPT)`, matching the
    // `EIDOS_TRANSCRIPT_INIT_CV_*` constants in `stark/random_coin.masm`.
    let source = "
        use miden::core::sys::vm
        use {RELATION_DIGEST_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            exec.vm::load_air_context
            push.6620516959492505600.11170449401267093504.11912009168875159552.13503953893964383489
            padw mem_loadw_le.RELATION_DIGEST_PTR
            exec.random_coin::eidos_init_challenger
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let shape = [10_u64, 11, 12];
    let test = build_test!(source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
}

#[test]
fn eidos_absorb_block_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let source = "
        use miden::core::stark::random_coin
        use {RANDOM_COIN_CV_PTR} from miden::core::stark::constants

        begin
            push.13.12.11.10 mem_storew_le.RANDOM_COIN_CV_PTR
            dropw
            exec.random_coin::eidos_clear_buffer
            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let test = build_test!(source, &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let init_cv = Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
    ]);
    let mut challenger = miden_crypto::hash::eidos::EidosChallenger::new(init_cv);
    challenger.observe([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ]);
    let expected_word = challenger.squeeze_word();

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
}

#[test]
fn eidos_absorb_block_rejects_nonempty_buffer() {
    let source = "
        use {RANDOM_COIN_CV_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.13.12.11.10 mem_storew_le.RANDOM_COIN_CV_PTR dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "eidos_absorb_block: buffer must be empty");
}

#[test]
fn eidos_hash_elements_single_block_matches_masm_compress_loop() {
    const HASH_WORD_PTR: u32 = 1000;

    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(
        miden_crypto::hash::eidos::domains::GENERIC_FELT_SEQUENCE,
        8,
    );
    let source = format!(
        "
        begin
            push.{cv3}.{cv2}.{cv1}.{cv0}
            push.8.7.6.5
            push.4.3.2.1
            compress
            dropw dropw
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let elements = (1..=8).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    assert_eq!(Word::new(read_word(&output, HASH_WORD_PTR)), expected_word);
}

#[test]
fn eidos_hash_elements_adv_pipe_loop_matches_masm_compress_loop() {
    const HASH_WORD_PTR: u32 = 1000;
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(
        miden_crypto::hash::eidos::domains::GENERIC_FELT_SEQUENCE,
        elements.len() as u32,
    );
    let advice_stack: Vec<u64> = elements.iter().map(Felt::as_canonical_u64).collect();

    let source = format!(
        "
        begin
            push.{STREAM_PTR}
            push.{cv3}.{cv2}.{cv1}.{cv0}
            padw padw
            repeat.2
                adv_pipe
                compress
            end
            dropw dropw
            movup.4 drop
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    assert_eq!(Word::new(read_word(&output, HASH_WORD_PTR)), expected_word);
}

#[test]
fn eidos_hash_elements_advice_map_loop_matches_masm_compress_loop() {
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);
    let map_values = elements
        .iter()
        .map(Felt::as_canonical_u64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(
        miden_crypto::hash::eidos::domains::GENERIC_FELT_SEQUENCE,
        elements.len() as u32,
    );

    let source = format!(
        "
        adv_map HASH_OUTPUT([{key0}, {key1}, {key2}, {key3}]) = [
            {map_values}
        ]

        begin
            push.HASH_OUTPUT
            adv.push_mapval
            push.{STREAM_PTR}
            push.{cv3}.{cv2}.{cv1}.{cv0}
            padw padw
            repeat.2
                adv_pipe
                compress
            end
            dropw dropw
            movup.4 drop
            assert_eqw
        end
        ",
        key0 = expected_word[0].as_canonical_u64(),
        key1 = expected_word[1].as_canonical_u64(),
        key2 = expected_word[2].as_canonical_u64(),
        key3 = expected_word[3].as_canonical_u64(),
        map_values = map_values,
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[]);
    test.execute().expect("execution failed");
}

// REDUCED INPUTS TESTS
// ================================================================================================

#[rstest]
#[case(0, [10, 11, 12, 16])]
#[case(1, [12, 10, 11, 16])]
#[case(2, [10, 10, 10, 16])]
#[case(3, [18, 17, 19, 16])]
fn boundary_inputs_and_outer_logup_boundary(
    #[case] seed: u8,
    #[case] log_heights: [u8; MIDEN_AIR_COUNT],
) {
    use crate::helpers::read_memory_felt;

    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let fixture_source = format!("begin push.{seed} drop end");
    let fixture = assemble(Assembler::default(), "boundary_claim", &fixture_source, &[]);
    let descriptor = fixture.environment.execution().descriptor();
    let stack_inputs: [Felt; 16] = array::from_fn(|_| Felt::from_u32(rng.next_u32()));
    let stack_outputs: [Felt; 16] = array::from_fn(|_| Felt::from_u32(rng.next_u32()));
    let deferred_root = Word::new(array::from_fn(|_| Felt::from_u32(rng.next_u32())));
    let main_commitment: [u64; WORD_SIZE] = array::from_fn(|_| u64::from(rng.next_u32()));
    let claim = ExecutionClaim::new(descriptor, stack_inputs.into(), stack_outputs.into());
    let claim_elements = claim.to_elements();
    let claim_commitment = claim.commitment();
    let [claim_c0, claim_c1, claim_c2, claim_c3] =
        claim_commitment.into_elements().map(|felt| felt.as_canonical_u64());
    let environment_root = claim.environment_root().into_word().into_elements();
    let entry_key = claim.entry_key().into_word().into_elements();
    let namespace = Namespace::initial().into_word().into_elements();
    assert_ne!(namespace, [Felt::ZERO; WORD_SIZE], "the fixed initial namespace is nonzero");

    let mut base_advice: Vec<u64> =
        log_heights[..3].iter().map(|&height| u64::from(height)).collect();
    base_advice.extend(deferred_root.as_elements().iter().map(Felt::as_canonical_u64));
    base_advice.extend_from_slice(&main_commitment);
    let advice_map = [(claim_commitment, claim_elements.to_vec())];
    let params = config::pcs_params();
    let source = |hook: bool| {
        let operation = if hook {
            "exec.aux_trace::observe_aux_trace"
        } else {
            "exec.random_coin::generate_aux_randomness
             exec.public_inputs::compute_outer_logup_correction"
        };
        format!(
            "
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, MAIN_TRACE_COM_PTR, NUM_QUERIES_PTR,
            QUERY_POW_BITS_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm
        use miden::core::sys::vm::aux_trace
        use miden::core::sys::vm::claim
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            exec.vm::load_air_context

            # Authenticate claim40 K_entry | R_E | I | O, then stage the internal R_E | D block.
            push.{claim_c3}.{claim_c2}.{claim_c1}.{claim_c0}
            exec.layout::claim_commitment_ptr mem_storew_le
            exec.layout::claim_ptr exec.claim::materialize_claim
            exec.public_inputs::stage_boundary_inputs

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
            padw adv_loadw
            mem_storew_le.MAIN_TRACE_COM_PTR
            exec.random_coin::observe_word
            {operation}
        end
        ",
            num_queries = params.num_queries(),
            query_pow_bits = params.query_pow_bits(),
            deep_pow_bits = params.deep_pow_bits(),
            folding_pow_bits = params.folding_pow_bits(),
        )
    };
    let sampler_source = source(false);
    let (output, _) = build_test!(
        sampler_source.as_str(),
        &[],
        &base_advice,
        miden_utils_testing::crypto::MerkleStore::new(),
        advice_map.clone()
    )
    .execute_for_output()
    .expect("the authenticated statement and auxiliary challenge sampler must execute");
    let read = |addr| read_memory_felt(&output, addr);

    let boundary_ptr = vm_layout_const("BOUNDARY_INPUTS_PTR");
    for (i, &value) in environment_root.iter().chain(deferred_root.as_elements()).enumerate() {
        assert_eq!(read(boundary_ptr + i as u32), value, "internal boundary felt {i}");
    }
    const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322638;
    let public_ptr = read(PUBLIC_INPUTS_ADDRESS_PTR).as_canonical_u64() as u32;
    let expected_public: Vec<Felt> = stack_inputs
        .into_iter()
        .chain(stack_outputs)
        .chain(entry_key.iter().copied())
        .chain(environment_root.iter().copied())
        .collect();
    assert_eq!(expected_public.len(), 40, "Core36 and Chiplets4 occupy exactly 40 ACE slots");
    for (i, &value) in expected_public.iter().enumerate() {
        assert_eq!(read(public_ptr + 2 * i as u32), value, "ACE public slot {i}");
        assert_eq!(
            read(public_ptr + 2 * i as u32 + 1),
            Felt::ZERO,
            "ACE public slot {i} high coord"
        );
    }

    let rand_ptr = vm_layout_const("AUX_RAND_ELEM_PTR");
    let beta = QuadFelt::new([read(rand_ptr), read(rand_ptr + 1)]);
    let alpha = QuadFelt::new([read(rand_ptr + 2), read(rand_ptr + 3)]);
    // Independent native polynomial oracle: Open has depth zero at beta^0, R_E at beta^1..4,
    // and the fixed nonzero N0 at beta^5..8. LibraryOpen is bus 39, hence prefix alpha+40*gamma.
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let denominator = |scale: u8, payload: &[Felt]| {
        let message = payload
            .iter()
            .rev()
            .fold(QuadFelt::ZERO, |acc, &value| acc * beta + QuadFelt::from(value));
        alpha + gamma * QuadFelt::from_u8(scale) + message
    };
    let open_payload: Vec<Felt> = [Felt::ZERO]
        .into_iter()
        .chain(environment_root.iter().copied())
        .chain(namespace)
        .collect();
    let expected_correction = denominator(40, &open_payload)
        .try_inverse()
        .expect("nonzero initial Open denominator")
        + denominator(3, &[Felt::ZERO; WORD_SIZE])
            .try_inverse()
            .expect("nonzero deferred init denominator")
        - denominator(3, deferred_root.as_elements())
            .try_inverse()
            .expect("nonzero deferred final denominator");
    let correction_ptr = vm_layout_const("C_TOTAL_PTR");
    let correction = QuadFelt::new([read(correction_ptr), read(correction_ptr + 1)]);
    assert_eq!(
        correction, expected_correction,
        "MASM must match the fixed three-term native oracle"
    );

    let (air_inputs, aux_inputs) =
        miden_air::vm::PublicInputs::from_claim(&claim, deferred_root).to_air_inputs();
    assert_eq!(air_inputs.iter().map(Vec::len).collect::<Vec<_>>(), vec![36, 4, 0, 0]);
    assert_eq!(aux_inputs.len(), WORD_SIZE, "the only statement aux inputs are deferred4");
    let zero = [QuadFelt::ZERO];
    let zero_sums = [zero.as_slice(); MIDEN_AIR_COUNT];
    let native_external = |values: &[QuadFelt; MIDEN_AIR_COUNT]| {
        let per_air = values.map(|value| [value]);
        let views = per_air.each_ref().map(<[QuadFelt; 1]>::as_slice);
        miden_air_definitions::vm::statement::eval_external(
            &[alpha, beta],
            &air_inputs,
            &aux_inputs,
            &views,
            &log_heights,
        )
        .expect("the exact public40/deferred4 native statement must reduce")
    };
    assert_eq!(
        miden_air_definitions::vm::statement::eval_external(
            &[alpha, beta],
            &air_inputs,
            &aux_inputs,
            &zero_sums,
            &log_heights,
        )
        .unwrap(),
        vec![expected_correction],
        "native external reduction must agree with the independent boundary polynomial"
    );

    // Use three distinguishable nonzero normalized sums, then balance the fourth. All four AIRs
    // contribute, and unequal heights make a missing scale or a misplaced sum observable.
    let mut sums = [
        QuadFelt::new([Felt::from_u32(13), Felt::from_u32(17)]),
        QuadFelt::new([Felt::from_u32(19), Felt::from_u32(23)]),
        QuadFelt::new([Felt::from_u32(29), Felt::from_u32(31)]),
        QuadFelt::ZERO,
    ];
    let partial = sums.iter().zip(log_heights).fold(QuadFelt::ZERO, |sum, (&value, height)| {
        sum + value * Felt::new_unchecked(1_u64 << height)
    });
    sums[3] =
        (-expected_correction - partial) * Felt::new_unchecked(1_u64 << log_heights[3]).inverse();
    assert!(sums.iter().all(|&value| value != QuadFelt::ZERO));
    assert_eq!(native_external(&sums), vec![QuadFelt::ZERO]);

    let mut order: [usize; MIDEN_AIR_COUNT] = array::from_fn(|air| air);
    order.sort_by_key(|&air| (log_heights[air], air));
    let hook_advice = |values: &[QuadFelt; MIDEN_AIR_COUNT]| {
        let mut advice = base_advice.clone();
        advice.extend([71, 72, 73, 74]); // Auxiliary-trace commitment.
        for air in order {
            advice.extend(
                values[air].as_basis_coefficients_slice().iter().map(Felt::as_canonical_u64),
            );
        }
        advice
    };
    let hook_source = source(true);
    let (hook_output, _) = build_test!(
        hook_source.as_str(),
        &[],
        &hook_advice(&sums),
        miden_utils_testing::crypto::MerkleStore::new(),
        advice_map.clone()
    )
    .execute_for_output()
    .expect("the production source hook must accept the same four balanced normalized sums");
    assert_eq!(
        QuadFelt::new([
            read_memory_felt(&hook_output, correction_ptr),
            read_memory_felt(&hook_output, correction_ptr + 1),
        ]),
        expected_correction,
        "the production hook must use the native boundary correction"
    );
    let sums_ptr = vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    for (air, value) in sums.iter().enumerate() {
        assert_eq!(
            QuadFelt::new([
                read_memory_felt(&hook_output, sums_ptr + 2 * air as u32),
                read_memory_felt(&hook_output, sums_ptr + 2 * air as u32 + 1),
            ]),
            *value,
            "source hook must retain normalized sum for canonical AIR {air}"
        );
        let mut forged = sums;
        forged[air] += QuadFelt::ONE;
        let expected_residual = QuadFelt::from(Felt::new_unchecked(1_u64 << log_heights[air]));
        assert_eq!(native_external(&forged), vec![expected_residual]);
        let test = build_test!(
            hook_source.as_str(),
            &[],
            &hook_advice(&forged),
            miden_utils_testing::crypto::MerkleStore::new(),
            advice_map.clone()
        );
        expect_assert_error_code_from_msg!(
            test,
            "outer-LogUp boundary mismatch: weighted sums coord 0"
        );
    }
}

#[test]
fn quotient_recomposition_constants_match_derivation() {
    // The generated evaluator serializes values derived from two independent protocol inputs:
    // quotient arity from the AIRs, and the canonical LDE shift from the PCS configuration. The VM
    // has arity = blowup = 8, so deriving all three from the blowup would produce the
    // same numbers and conceal the conflation that breaks relations where they differ.
    let masm = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/asm/sys/vm/constraints_eval.masm"
    ))
    .expect("read generated VM constraints evaluator");
    let masm_const = |name: &str| -> u64 {
        masm.lines()
            .find_map(|line| {
                let (lhs, rhs) = line.trim().strip_prefix("const ")?.split_once('=')?;
                if lhs.trim() != name {
                    return None;
                }
                Some(rhs.split_whitespace().next()?.parse().expect("parse const value"))
            })
            .unwrap_or_else(|| panic!("const {name} not found in VM constraints evaluator"))
    };

    let shift_ratio = Felt::new(masm_const("QUOTIENT_SHIFT_RATIO")).unwrap();
    let first_shift = Felt::new(masm_const("QUOTIENT_FIRST_SHIFT")).unwrap();
    let first_weight = Felt::new(masm_const("QUOTIENT_FIRST_WEIGHT")).unwrap();

    let log_quotient_degree = miden_air::vm::AIRS
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    let expected = miden_stark::quotient_recomposition_inputs::<Felt>(
        log_quotient_degree,
        config::pcs_params().log_blowup(),
    )
    .expect("the Miden quotient degree fits its PCS blowup");

    assert_eq!(shift_ratio, expected.shift_ratio, "QUOTIENT_SHIFT_RATIO is stale");
    assert_eq!(first_shift, expected.first_shift, "QUOTIENT_FIRST_SHIFT is stale");
    assert_eq!(first_weight, expected.first_weight, "QUOTIENT_FIRST_WEIGHT is stale");
}

/// A relation may stage per-AIR fold coefficients only once its ACE input region holds them.
///
/// Each generated evaluator's `stage_air_fold_coefficients` writes one extension-field
/// coefficient per AIR immediately after the selector block, at base offsets
/// `FIRST_SELECTOR_OFFSET + SELECTOR_STRIDE * num_airs + 2k` from the relation's stark-vars base.
/// Only the felts below `ACE_CIRCUIT_STREAM_PTR` belong to that region; a coefficient past its
/// end lands in the circuit-stream region, where the loader's next `adv_pipe` silently overwrites
/// it. The memory-map test cannot see this — it compares *declared* extents, and both regions
/// stay dense and disjoint whether or not the writes stay inside them — so the bound is asserted
/// here instead, against the offset the evaluator actually addresses.
#[test]
fn staged_fold_coefficients_fit_the_declared_ace_input_region() {
    const STAGING_PROC: &str = "stage_air_fold_coefficients";
    const OFFSET_SITE: &str = "exec.layout::auxiliary_ace_inputs_ptr add.";
    /// Base felts per staged coefficient (one quadratic-extension element).
    const COEFFICIENT_STRIDE: u32 = 2;

    let shared = include_str!("../../asm/stark/constraints_eval_inputs.masm");
    let masm_const = |source: &str, name: &str, what: &str| -> u32 {
        let prefix = format!("const {name} = ");
        source
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix)?.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing {what} constant {name}"))
    };

    let first_selector_offset = masm_const(shared, "FIRST_SELECTOR_OFFSET", "shared");
    let selector_stride = masm_const(shared, "SELECTOR_STRIDE", "shared");
    assert!(
        !shared.contains(&format!("proc {STAGING_PROC}")),
        "the shared module must not carry a second fold-coefficient algorithm"
    );

    for (relation, layout_const, evaluator) in [
        (
            "vm",
            vm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/vm/constraints_eval.masm"),
        ),
        (
            "pvm",
            pvm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/pvm/constraints_eval.masm"),
        ),
    ] {
        let num_airs = masm_const(evaluator, "NUM_AIRS", relation);
        let region_felts =
            layout_const("ACE_CIRCUIT_STREAM_PTR") - layout_const("AUXILIARY_ACE_INPUTS_PTR");

        // Walk the procedure declarations rather than the raw text so a rename fails here instead
        // of turning this guard into a silent no-op.
        let mut declares_staging = false;
        let mut in_staging = false;
        let mut staged_offset = None;
        for line in evaluator.lines() {
            let trimmed = line.trim();
            if let Some(rest) =
                trimmed.strip_prefix("pub proc ").or_else(|| trimmed.strip_prefix("proc "))
            {
                let name = rest.split(['(', ' ']).next().unwrap_or(rest);
                if name == STAGING_PROC {
                    assert!(
                        !trimmed.starts_with("pub "),
                        "{relation}: {STAGING_PROC} must stay private to the evaluator"
                    );
                }
                declares_staging |= name == STAGING_PROC;
                in_staging = name == STAGING_PROC;
            }
            if in_staging && let Some(offset) = trimmed.strip_prefix(OFFSET_SITE) {
                staged_offset = offset.parse::<u32>().ok();
            }
        }
        assert!(declares_staging, "{relation}: {STAGING_PROC} is no longer declared");
        let staged_offset =
            staged_offset.unwrap_or_else(|| panic!("{relation}: {STAGING_PROC} has no offset"));

        let selectors_end = first_selector_offset + selector_stride * num_airs;
        assert_eq!(
            staged_offset, selectors_end,
            "{relation}: the evaluator stages fold coefficients off the slot right after the \
             selector block"
        );
        let coefficients_end = selectors_end + COEFFICIENT_STRIDE * num_airs;
        assert!(
            coefficients_end <= region_felts,
            "{relation}: {num_airs} fold coefficients end at felt {coefficients_end}, past the \
             {region_felts}-felt AUXILIARY_ACE_INPUTS_PTR region; enlarge the region before \
             staging them"
        );
    }
}

// HELPERS
// ===============================================================================================

fn max_kernel_source() -> String {
    let mut source = KERNEL_SINGLE_PROC.to_owned();
    for i in 1..KernelDescriptor::MAX_NUM_PROCEDURES {
        write!(source, "\npub proc unused_{i}\n    push.{i} drop\nend").unwrap();
    }
    source
}

// CONSTANTS
// ===============================================================================================

/// The verifier-fixed And8Lookup log trace height (the full byte-pair table).
const AND8_LOOKUP_LOG_HEIGHT: u8 = 16;

/// Memory used by test consumers while deriving a claim commitment.
const CONSUMER_CLAIM_PTR: u64 = 4096;

const KERNEL_SINGLE_PROC: &str = r#"
        pub proc foo
            add
        end"#;

const KERNEL_EVEN_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end"#;

const KERNEL_ODD_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end
        pub proc baz
            mul
        end"#;
