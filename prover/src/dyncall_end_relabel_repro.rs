//! Regression test: a DYNCALL's caller-frame END must not be relabelled as a continuation END.
//!
//! DYNCALL records its saved caller frame into decoder cells rather than the real columns:
//! `block_stack_and_range_logcap.rs` builds a caller-frame addition with
//! `caller_stack_depth = h4` and `caller_overflow_addr = h5` (CALL/SYSCALL use the real `b0`/`b1`).
//! At the root, `caller_ctx = 0` and `caller_overflow_addr = 0`, while `caller_fn_hash` is the
//! independently selected K_entry. Clearing saved depth no longer creates the historical
//! zero-principal payload collision. These compound rejection controls preserve the current
//! nonzero-principal baseline; they do not attribute rejection to a single protection. Carrying
//! a callee principal through the final row also violates the independent K_entry boundary.

use alloc::vec;

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{Felt, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::repro_harness::{ReproTrace, core_row_mut};

const ADDR: u64 = 40;

struct Fixture {
    trace: ReproTrace,
    height: usize,
    dyncall_row: usize,
    dyncall_end: usize,
    /// The callee's context and digest, honestly restored to root at `dyncall_end + 1`.
    callee_ctx: Felt,
    callee_fn_hash: [Felt; 4],
}

fn build_fixture() -> Fixture {
    // A DYNCALL at root depth 16 with an empty overflow table and the actual entry principal.
    // `call.foo` keeps `foo` in the forest; its canonical key is retained separately.
    let source = "
        proc foo
            nop
        end
        begin
            call.foo
            mem_storew_le.40
            movup.4
            dyncall
        end
    ";
    let fixture = crate::named_fixture::named_source(source);
    let foo_key = fixture.key("foo").into_word();
    let program = fixture.program;
    let environment = fixture.environment;

    let mut stack_values = vec![Felt::ZERO; 16];
    for (i, limb) in foo_key.as_elements().iter().enumerate() {
        stack_values[i] = *limb;
    }
    stack_values[4] = Felt::new_unchecked(ADDR);
    let stack_inputs = StackInputs::new(&stack_values).unwrap();

    let mut host = DefaultHost::default().with_environment_source(environment.source());
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
        .with_options(
            miden_processor::ExecutionOptions::default()
                .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
        )
        .unwrap()
        .execute_and_build_trace_sync(
            &program,
            environment.execution(),
            &mut host,
            &miden_vm_stark::memory::default_budget(),
        )
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op = |r: usize| main.get_op_code(RowIndex::from(r)).as_canonical_u64() as u8;

    let dyncall_row = (0..height).find(|&r| op(r) == opcodes::DYNCALL).expect("has DYNCALL");
    let dyncall_end = (dyncall_row..height)
        .find(|&r| {
            op(r) == opcodes::END && main.restores_caller_frame_flag(RowIndex::from(r)) == Felt::ONE
        })
        .expect("DYNCALL block has a caller-frame END");

    // Current baseline: root context does not imply a zero principal.
    assert_eq!(main.stack_depth(RowIndex::from(dyncall_row)), Felt::new_unchecked(16));
    assert_eq!(main.ctx(RowIndex::from(dyncall_row)), Felt::ZERO);
    let entry = trace.execution_descriptor().entry_key().into_word().into_elements();
    assert_ne!(entry, [Felt::ZERO; 4]);
    assert_eq!(main.fn_hash(RowIndex::from(dyncall_row)), entry);
    assert_eq!(
        main.decoder_hasher_state_element(4, RowIndex::from(dyncall_row)),
        Felt::new_unchecked(16),
        "h4 must honestly hold the caller depth 16"
    );

    // Callee context and digest, honestly restored to root right after the caller-frame END.
    let callee_ctx = main.ctx(RowIndex::from(dyncall_end));
    let callee_fn_hash = main.fn_hash(RowIndex::from(dyncall_end));
    assert_ne!(callee_ctx, Felt::ZERO, "the callee runs in a non-root context");
    assert_ne!(callee_fn_hash, [Felt::ZERO; 4]);
    assert_eq!(main.ctx(RowIndex::from(dyncall_end + 1)), Felt::ZERO, "honestly restored");
    assert_eq!(main.decoder_hasher_state_element(6, RowIndex::from(dyncall_end)), Felt::ONE);

    Fixture {
        trace: ReproTrace::new(&trace),
        height,
        dyncall_row,
        dyncall_end,
        callee_ctx,
        callee_fn_hash,
    }
}

/// Carries the callee's `ctx`/`fn_hash` forward from `dyncall_end` through the tail of the
/// trace, instead of the honest root values -- i.e. the caller's context is never restored.
fn carry_callee_context_forward(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    for row in (f.dyncall_end + 1)..f.height {
        let r = core_row_mut(core, row);
        r.system.ctx = f.callee_ctx;
        r.system.fn_hash = f.callee_fn_hash;
    }
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// Zero the DYNCALL's saved depth, relabel its caller-frame END as a continuation END, and carry
/// the callee context forward. This compound mutation checks the complete repaired path; it does
/// not attribute rejection to either protection in isolation.
#[test]
fn relabelled_dyncall_end_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[4] = Felt::ZERO;
    core_row_mut(&mut core, f.dyncall_end).decoder.hasher_state[6] = Felt::ZERO;
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a relabelled DYNCALL END: {result:?}"
    );
    // The mutation violates the direct `h4 = b0 - overflow()` binding and saved-frame rules.
    // This combined rejection does not isolate either rule or the independent entry boundary.
}

/// Control: relabel the END and carry the context forward, but leave `h4 = 16`. The DYNCALL
/// addition remains a caller-frame entry, so the continuation removal matches no addition.
/// Carrying the callee context forward satisfies continuation preservation but also changes the
/// final principal. Block-stack rejection and the K_entry boundary are independent here.
#[test]
fn relabel_without_degenerating_the_addition_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    // h4 left at its honest 16.
    core_row_mut(&mut core, f.dyncall_end).decoder.hasher_state[6] = Felt::ZERO;
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "with h4 = 16, relabelling the caller-frame END and carrying the callee context forward \
         must be rejected by the block-stack relation: {result:?}"
    );
}

/// Control: degenerate the addition and carry the context forward, but leave the caller-frame flag
/// set on the END. This is rejected independently by the direct `h4` binding and by the
/// caller-frame relation, whose removal no longer matches the state DYNCALL recorded. It is a
/// combined regression control, not an attribution test for either mechanism alone.
#[test]
fn degenerate_addition_without_relabelling_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[4] = Felt::ZERO;
    // The CALL/DYNCALL caller-frame flag is left at one on the END.
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "degenerating h4 while leaving the caller-frame END honest must be rejected by the direct \
         h4 binding and the mismatched caller-frame payload: {result:?}"
    );
}
