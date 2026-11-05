//! Regression tests for the block-stack entry-kind tag.
//!
//! A continuation and a caller frame with zero saved state differ by the entry-kind tag.
//! The combined mutation forges caller restoration at a continuation END and supplies a zeroed
//! callee row; the real CALL END then restores the following authenticated root state. First and
//! final principals and the independently expected claim remain unchanged.
//!
//! A private comparison changes only the tag term in the first LogUp recurrence and recenters
//! its auxiliary accumulator. The constructed artifact verifies under that comparison, while
//! current native and MASM verifiers reject the same artifact. Structural, polynomial-coefficient
//! and degree guards identify the narrow change. Honest artifacts verify in both consumers; an
//! unrelated final-clock defect still rejects under the comparison.
//!
//! The two single-half mutations remain rejection-pipeline controls and may stop at lookup
//! construction. Their rejection alone does not establish isolated-rule necessity.

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{
    Felt,
    field::Field,
    operations::opcodes,
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::repro_harness::{CoreMode, ReproTrace, core_row_mut};

struct Fixture {
    trace: ReproTrace,
    /// END of the callee's basic block: a continuation END strictly inside the CALL.
    continuation_end_row: usize,
    /// END of the CALL block itself, the row after `continuation_end_row`.
    call_end_row: usize,
    /// Honest values at `call_end_row`, for the assertions below.
    honest_ctx: Felt,
    honest_fn_hash: [Felt; 4],
    honest_b0: Felt,
}

fn build_fixture() -> Fixture {
    let fixture = crate::named_fixture::named_source("proc inner nop nop end begin call.inner end");
    let program = fixture.code;
    let environment = fixture.environment;

    let mut host = DefaultHost::default().with_environment_source(environment.source());
    host.load_library(program).unwrap();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::default())
        .with_options(
            miden_processor::ExecutionOptions::default()
                .with_resolution_limits(environment.resolution_limits())
                .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
        )
        .unwrap()
        .execute_and_build_trace_sync(
            environment.target(),
            &mut host,
            &miden_vm_stark::memory::default_budget(),
        )
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op_at = |row: usize| main.get_op_code(RowIndex::from(row));

    let call_end_row = (0..height)
        .find(|&row| {
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
        })
        .expect("program must have a caller-frame END row");

    // The callee's basic block closes with a continuation END immediately before the CALL END.
    let continuation_end_row = call_end_row - 1;
    assert_eq!(op_at(continuation_end_row), Felt::from_u8(opcodes::END));
    assert_eq!(
        main.restores_caller_frame_flag(RowIndex::from(continuation_end_row)),
        Felt::ZERO
    );

    // Honest state at the call's END row: the callee's context, non-root.
    let honest_ctx = main.ctx(RowIndex::from(call_end_row));
    let honest_fn_hash = main.fn_hash(RowIndex::from(call_end_row));
    let honest_b0 = main.stack_depth(RowIndex::from(call_end_row));
    assert_ne!(honest_ctx, Felt::ZERO, "the callee must run in a non-root context");
    assert_ne!(honest_fn_hash, [Felt::ZERO; 4], "the callee must have a non-zero fn_hash");

    // The CALL's END restores from what the CALL row recorded, so the excursion is erased.
    assert_eq!(main.ctx(RowIndex::from(call_end_row + 1)), Felt::ZERO);
    assert_eq!(main.stack_depth(RowIndex::from(call_end_row + 1)), Felt::new_unchecked(16));

    Fixture {
        trace: ReproTrace::new(&trace),
        continuation_end_row,
        call_end_row,
        honest_ctx,
        honest_fn_hash,
        honest_b0,
    }
}

/// Zeroes the caller-frame payload columns at the CALL's END row. In the old untagged relation,
/// that gives the forged caller-frame removal emitted by the previous row the same encoding as a
/// continuation removal.
fn zero_caller_frame_payload(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    let row = core_row_mut(core, f.call_end_row);
    row.system.ctx = Felt::ZERO;
    row.system.fn_hash = [Felt::ZERO; 4];
    row.stack.b0 = Felt::ZERO;
    row.stack.b1 = Felt::ZERO;
    // `overflow() = (b0 - 16) * h0` feeds `(1 - overflow) * (depth - 16) = 0`. With b0 forced
    // to 0, h0 must be the true inverse or that constraint demands depth == 16.
    row.stack.h0 = (Felt::ZERO - Felt::new_unchecked(16)).inverse();
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// Mark the callee's continuation END as restoring a CALL/DYNCALL frame and zero the saved-state
/// payload on the next row. Preservation of ctx / fn_hash / b0 / b1 is switched off, but the
/// authenticated entry kind prevents the removal from matching the SPAN's continuation addition.
#[test]
fn forged_caller_frame_flag_on_continuation_end_is_rejected() {
    let mut f = build_fixture();
    let honest = f
        .trace
        .prove_comparison(CoreMode::Standard)
        .expect("honest caller-frame proof construction must complete");
    assert!(honest.verification.is_ok());
    f.trace.assert_native_and_recursive_accept(honest.proof);
    let claim = f.trace.claim();
    let mut core = f.trace.core.clone();
    let first = core_row_mut(&mut core, 0).system.fn_hash;
    let last = core.height() - 1;
    let final_principal = core_row_mut(&mut core, last).system.fn_hash;
    assert_ne!(first, [Felt::ZERO; 4], "the expected entry principal must be nonzero");
    assert_eq!(final_principal, first);
    core_row_mut(&mut core, f.continuation_end_row).decoder.hasher_state[6] = Felt::ONE;
    zero_caller_frame_payload(&f, &mut core);
    assert_eq!(core_row_mut(&mut core, 0).system.fn_hash, first);
    assert_eq!(core_row_mut(&mut core, last).system.fn_hash, final_principal);
    f.trace.core = core;
    assert_eq!(f.trace.claim(), claim);
    let comparison = f
        .trace
        .prove_comparison(CoreMode::TaglessFrames)
        .expect("the tag comparison must complete proof construction");
    assert!(
        comparison.verification.is_ok(),
        "only the entry-kind tag may reject the witness: {:?}",
        comparison.verification
    );
    f.trace.assert_native_and_recursive_air_rejection(comparison.proof);

    // An unrelated final-HALT clock defect must remain visible after the tag-only comparison.
    core_row_mut(&mut f.trace.core, last).system.clk += Felt::ONE;
    let control = f
        .trace
        .prove_comparison(CoreMode::TaglessFrames)
        .expect("the unrelated control must also complete proof construction");
    assert!(control.verification.is_err());
}

/// Control: the identical payload zeroing without forging a caller-frame
/// flag must be rejected, because then the preservation constraints are still live.
#[test]
fn zeroed_payload_without_forged_caller_frame_flag_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    // Same value changes, but leave the continuation END correctly classified.
    zero_caller_frame_payload(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "without the forged caller-frame flag the proof pipeline must reject this: \
         {result:?}"
    );
}

/// Control: forging the caller-frame flag while leaving the payload at its
/// honest non-zero values must be rejected, because the caller-frame removal matches no addition.
#[test]
fn forged_caller_frame_flag_without_zeroed_payload_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.continuation_end_row).decoder.hasher_state[6] = Felt::ONE;
    // Payload left honest: ctx != 0, fn_hash != 0, b0 == 16.
    assert_ne!(f.honest_ctx, Felt::ZERO);
    assert_ne!(f.honest_fn_hash, [Felt::ZERO; 4]);
    assert_eq!(f.honest_b0, Felt::new_unchecked(16));

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "a caller-frame removal with a non-zero payload matches no addition and must unbalance \
         the block-stack bus: {result:?}"
    );
}
