//! Production regressions for preserving context and principal across continuation ENDs.
//!
//! Caller-frame ENDs restore saved state; continuation ENDs must preserve it. These fixtures
//! mutate context or principal while retaining the captured expected claim. Equal-D alias tails
//! preserve resolution demand counts, and nested CALL mutations restore the honest entry boundary.
//! Honest proofs must verify in native and MASM consumers; balanced mutations must construct a
//! production proof and reach exact AIR rejection in both consumers.

use alloc::{vec, vec::Vec};

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::{Operation, opcodes},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};
use miden_utils_testing::librarytree::fixture_code;

use crate::repro_harness::{ReproTrace, core_row_mut};

// HARNESS
// ================================================================================================

fn set_ctx(trace: &mut ReproTrace, rows: impl Iterator<Item = usize>, ctx: Felt) {
    for row in rows {
        core_row_mut(&mut trace.core, row).system.ctx = ctx;
    }
}

fn set_fn_hash(trace: &mut ReproTrace, rows: impl Iterator<Item = usize>, fn_hash: [Felt; 4]) {
    for row in rows {
        core_row_mut(&mut trace.core, row).system.fn_hash = fn_hash;
    }
}

const FORGED_CTX: Felt = Felt::new_unchecked(7);
// SINGLE BASIC BLOCK: THE MINIMAL GAP
// ================================================================================================

/// Row indices of interest in the single-basic-block program.
struct BasicRows {
    /// Continuation END of the basic block: both caller-frame flags are zero.
    continuation_end: usize,
    /// An ordinary transition, where `default_flag = 1` pins both columns.
    noop: usize,
    height: usize,
}

fn build_basic_harness() -> (ReproTrace, BasicRows) {
    let operations = vec![
        Operation::Push(Felt::new_unchecked(101)),
        Operation::Noop,
        Operation::Drop,
        Operation::Noop,
    ];
    let mut mast_forest = MastForest::new();
    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);
    let program = fixture_code(mast_forest.into(), basic_block_id);
    let environment = crate::named_fixture::raw_environment(&program, "continuation-end");

    let stack_values = (1..17).rev().map(Felt::new_unchecked).collect::<Vec<_>>();
    let stack_inputs = StackInputs::new(&stack_values).unwrap();
    let mut host = DefaultHost::default().with_environment_source(environment.source());
    host.load_library(program).unwrap();
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
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

    let continuation_end = (0..height)
        .find(|&row| {
            let idx = RowIndex::from(row);
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(idx) == Felt::ZERO
        })
        .expect("the basic block must end with a continuation END");
    let noop = (0..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::NOOP))
        .expect("the program must contain a NOOP");
    assert!(noop < continuation_end);

    // Root context and principal are separate: the principal is the independently selected key.
    assert_eq!(main.ctx(RowIndex::from(continuation_end)), Felt::ZERO);
    let entry = trace.execution_descriptor().entry_key().into_word().into_elements();
    assert_ne!(entry, [Felt::ZERO; 4]);
    assert_eq!(main.fn_hash(RowIndex::from(continuation_end)), entry);

    let repro = ReproTrace::new(&trace);
    (repro, BasicRows { continuation_end, noop, height })
}

/// Control: the unmodified trace verifies, so rejections below are attributable to the
/// mutation rather than to the harness.
#[test]
fn honest_basic_block_trace_verifies() {
    let (repro, _) = build_basic_harness();
    let proof = repro.prove_current().expect("honest proof construction must complete");
    repro.assert_native_and_recursive_accept(proof);
}

/// `ctx` jumps from 0 to 7 across the continuation END and is preserved (as the default-flag
/// constraint requires) through the remaining HALT rows.
#[test]
fn forged_context_at_continuation_end_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    let expected_claim = repro.claim();
    set_ctx(&mut repro, (rows.continuation_end + 1)..rows.height, FORGED_CTX);
    assert_eq!(repro.claim(), expected_claim);

    let proof = repro
        .prove_current()
        .expect("the context mutation must construct a production proof");
    repro.assert_native_and_recursive_air_rejection(proof);
}

/// Control for the above: the identical mutation across an ordinary NOOP transition, where
/// `default_flag = 1`, must be rejected. This proves the mutation reaches the proven trace
/// and that the verifier does police `ctx`.
#[test]
fn forged_context_at_ordinary_row_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    let expected_claim = repro.claim();
    set_ctx(&mut repro, (rows.noop + 1)..rows.height, FORGED_CTX);
    assert_eq!(repro.claim(), expected_claim);

    let proof = repro
        .prove_current()
        .expect("the context mutation must construct a production proof");
    repro.assert_native_and_recursive_air_rejection(proof);
}

/// Exchange equal-D callee aliases after nested continuation ENDs, preserving the entry boundary
/// and balanced resolution demand counts.
#[test]
fn forged_fn_hash_at_continuation_end_is_rejected() {
    check_alias_principal_exchange(true);
}

/// Control: exchange the same aliases across ordinary callee transitions.
#[test]
fn forged_fn_hash_at_ordinary_row_is_rejected() {
    check_alias_principal_exchange(false);
}

// PRESERVATION INSIDE A CALL
// ================================================================================================

/// Row indices of interest in the program containing a `call`.
struct CallRows {
    /// An ordinary transition inside the callee body.
    ordinary_in_callee: usize,
    /// The if/else arm's END, strictly inside the callee body.
    nested_continuation_end: usize,
    /// The END of the CALL block itself: it restores a CALL/DYNCALL caller frame.
    call_end: usize,
}

fn check_alias_principal_exchange(after_continuation: bool) {
    let body = "push.1 if.true push.7 drop else push.8 drop end push.9 drop";
    let source =
        alloc::format!("proc left {body} end proc right {body} end begin call.left call.right end");
    let fixture = crate::named_fixture::named_source(&source);
    let keys = [fixture.key("left"), fixture.key("right")];
    assert_ne!(keys[0], keys[1]);
    let implementations = keys.map(|key| {
        fixture.naming.callables().selected_implementation(key).expect("selected alias")
    });
    assert_eq!(implementations[0], implementations[1], "the aliases must select equal D");
    let mut host = DefaultHost::default().with_environment_source(fixture.environment.source());
    host.load_library(fixture.code.clone()).unwrap();
    let (trace, precompile) = FastProcessor::new(StackInputs::default())
        .with_options(
            miden_processor::ExecutionOptions::default()
                .with_resolution_limits(fixture.environment.resolution_limits())
                .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
        )
        .unwrap()
        .execute_and_build_trace_sync(
            fixture.environment.target(),
            &mut host,
            &miden_vm_stark::memory::default_budget(),
        )
        .unwrap();
    assert!(precompile.is_none());
    let main = trace.main_trace();
    let height = main.core_height();
    let opcode = |row| main.get_op_code(RowIndex::from(row));
    let calls = (0..height)
        .filter(|&row| opcode(row) == Felt::from_u8(opcodes::CALL))
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    let principals = keys.map(|key| key.into_word().into_elements());
    let entry = trace.execution_descriptor().entry_key().into_word().into_elements();
    let rows: [CallRows; 2] = core::array::from_fn(|index| {
        let call = calls[index];
        let call_end = ((call + 1)..height)
            .find(|&row| {
                opcode(row) == Felt::from_u8(opcodes::END)
                    && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
            })
            .expect("caller-frame END");
        let nested_continuation_end = ((call + 1)..call_end)
            .find(|&row| {
                opcode(row) == Felt::from_u8(opcodes::END)
                    && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ZERO
            })
            .expect("nested continuation END");
        let ordinary_in_callee = ((call + 1)..nested_continuation_end)
            .find(|&row| opcode(row) != Felt::from_u8(opcodes::END))
            .expect("ordinary callee transition");
        assert_eq!(main.fn_hash(RowIndex::from(call + 1)), principals[index]);
        assert_eq!(main.fn_hash(RowIndex::from(call_end)), principals[index]);
        assert_eq!(main.fn_hash(RowIndex::from(call_end + 1)), entry);
        assert!(nested_continuation_end + 1 < call_end);
        CallRows {
            ordinary_in_callee,
            nested_continuation_end,
            call_end,
        }
    });
    let mut repro = ReproTrace::new(&trace);
    let expected_claim = repro.claim();
    let honest = repro.prove_current().expect("honest alias proof construction must complete");
    repro.assert_native_and_recursive_accept(honest);

    // Both aliases already have authenticated openings. Invocation and root-completion demands
    // remain unchanged; only the callee principal tails change in the Core matrix.
    for index in 0..2 {
        let start = if after_continuation {
            rows[index].nested_continuation_end
        } else {
            rows[index].ordinary_in_callee
        };
        set_fn_hash(&mut repro, (start + 1)..=rows[index].call_end, principals[1 - index]);
    }
    assert_eq!(core_row_mut(&mut repro.core, 0).system.fn_hash, entry);
    assert_eq!(core_row_mut(&mut repro.core, height - 1).system.fn_hash, entry);
    assert_eq!(repro.claim(), expected_claim);
    let proof = repro
        .prove_current()
        .expect("balanced alias demands must reach production proof construction");
    repro.assert_native_and_recursive_air_rejection(proof);
}

/// Builds a trace for `begin call.inner end`, where `inner` contains a nested block -- so the
/// callee body has a continuation END with further callee rows after it.
fn build_call_harness() -> (ReproTrace, CallRows) {
    let source = "
        proc inner
            push.1
            if.true
                push.7 drop
            else
                push.8 drop
            end
            push.9 drop
        end
        begin
            call.inner
        end
    ";
    let fixture = crate::named_fixture::named_source(source);
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

    let call_row = (0..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::CALL))
        .expect("program must contain a CALL");
    let call_end = (call_row..height)
        .find(|&row| {
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
        })
        .expect("the CALL block must have a caller-frame END row");

    // The callee's own context, established by `ctx' = clk + 1` on the CALL row, and the
    // caller's context restored by the block-stack bus on the caller-frame END row.
    let callee_ctx = main.ctx(RowIndex::from(call_row + 1));
    assert_ne!(callee_ctx, Felt::ZERO, "the callee must run in a non-root context");
    assert_eq!(main.ctx(RowIndex::from(call_end + 1)), Felt::ZERO);

    let nested_continuation_end = ((call_row + 1)..call_end)
        .find(|&row| {
            let idx = RowIndex::from(row);
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(idx) == Felt::ZERO
        })
        .expect("the callee body must contain a nested continuation END");
    assert!(
        nested_continuation_end + 1 < call_end,
        "there must be callee rows after the nested continuation END for the forgery to matter"
    );

    // An ordinary (non-END) callee row strictly before the nested continuation END, used as the
    // control. Every row in the callee body runs at `callee_ctx`.
    let ordinary_in_callee = ((call_row + 1)..nested_continuation_end)
        .find(|&row| op_at(row) != Felt::from_u8(opcodes::END))
        .expect("the callee body must contain an ordinary row");
    assert_eq!(main.ctx(RowIndex::from(ordinary_in_callee)), callee_ctx);

    let repro = ReproTrace::new(&trace);
    (
        repro,
        CallRows {
            ordinary_in_callee,
            nested_continuation_end,
            call_end,
        },
    )
}

/// Control: the unmodified call-program trace verifies.
#[test]
fn honest_call_program_trace_verifies() {
    let (repro, _) = build_call_harness();
    let proof = repro.prove_current().expect("honest call proof construction must complete");
    repro.assert_native_and_recursive_accept(proof);
}

/// A context mutation after a nested continuation END runs the callee tail in the caller's
/// context until the honest caller-frame END restores it. Only the context column changes;
/// the principal and independently captured expected claim remain fixed.
#[test]
fn callee_reentering_caller_context_at_nested_continuation_end_is_rejected() {
    check_call_context_preservation(true);
}

/// Control: the same context mutation across an ordinary callee transition must also reject.
#[test]
fn callee_reentering_caller_context_at_ordinary_row_is_rejected() {
    check_call_context_preservation(false);
}

fn check_call_context_preservation(after_continuation: bool) {
    let (mut repro, rows) = build_call_harness();
    let expected_claim = repro.claim();
    let honest = repro
        .prove_current()
        .expect("honest call context proof construction must complete");
    repro.assert_native_and_recursive_accept(honest);

    let start = if after_continuation {
        rows.nested_continuation_end
    } else {
        rows.ordinary_in_callee
    };
    // Only Core ctx changes: the caller-frame END restores the original root context. All
    // principal columns, other AIR matrices and the independently expected claim remain fixed.
    set_ctx(&mut repro, (start + 1)..=rows.call_end, Felt::ZERO);
    assert_eq!(repro.claim(), expected_claim);
    let proof = repro
        .prove_current()
        .expect("the changed context witness must finish production proof construction");
    repro.assert_native_and_recursive_air_rejection(proof);
}
