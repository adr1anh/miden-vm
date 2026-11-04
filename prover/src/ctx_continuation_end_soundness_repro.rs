//! Regression tests: `ctx` and `fn_hash` are preserved across a continuation END.
//!
//! `crates/air/source/src/vm/constraints/system/mod.rs` used to gate the preservation of both
//! columns on the *coarse* END flag:
//!
//! ```ignore
//! let change_ctx_flag = f_call + f_syscall + f_dyncall + f_end;
//! let default_flag = change_ctx_flag.not();
//! builder.when_transition().when(default_flag).assert_eq(ctx_next, ctx);
//! ...
//! let f_preserve = (f_call + f_dyncall + f_end).not();
//! builder.when_transition().when(f_preserve).assert_eq_arrays(next.fn_hash, local.fn_hash);
//! ```
//!
//! On *any* END row that made `default_flag = f_preserve = 0`, leaving both columns pinned by
//! nothing. Restoration through the block-stack relation covers only caller-frame ENDs:
//! `end_caller_frame` removes a `BlockStackMsg::CallerFrame` carrying `ctx_next` /
//! `fn_hash_next`, while `end_continuation` removes a `BlockStackMsg::Continuation` carrying only
//! `(block_id, parent_id, is_loop)`. A prover could therefore jump `ctx` at any continuation END --
//! including one nested inside a call, re-entering the caller's memory context -- or forge
//! `fn_hash`, which CALLER copies onto the stack as a public output.
//!
//! The fix gates both on the same precise caller-frame restoration selector already used for
//! stack depth `b0` and the overflow pointer `b1` in stack/overflow.rs.
//!
//! The ordinary-transition controls and honest baselines check the regression harness. These
//! rejection tests alone do not establish necessity of an individual END rule: in particular,
//! changes carried through the final principal also violate the independent K_entry boundary.
//! The alias-principal and nested-call context cases preserve that boundary. Their separate
//! private evaluator comparisons change only the targeted preservation rule. Each historical
//! coarse-END selector accepts its continuation witness while current native and MASM verifiers
//! reject that same artifact; ordinary-transition controls still reject under each comparison.
//! The context comparison keeps principal preservation, and the principal comparison keeps context
//! preservation. Neither attributes the separate compound DYNCALL controls.

use alloc::{vec, vec::Vec};

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    proof::{ExecutionProof, PrecompileStatus},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};
use miden_utils_testing::librarytree::fixture_code;
use miden_verifier::Verifier;

use crate::repro_harness::{CoreMode, ReproTrace, core_row_mut};

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
    let claim = repro.claim();
    let proof = repro.prove_current().expect("honest proof construction must complete");
    let proof = ExecutionProof::new(proof, PrecompileStatus::Empty);
    assert!(Verifier::new().verify(&claim, &proof).is_ok(), "the honest trace must verify");
}

/// `ctx` jumps from 0 to 7 across the continuation END and is preserved (as the default-flag
/// constraint requires) through the remaining HALT rows.
#[test]
fn forged_context_at_continuation_end_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_ctx(&mut repro, (rows.continuation_end + 1)..rows.height, FORGED_CTX);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a context change across a continuation END: {result:?}"
    );
}

/// Control for the above: the identical mutation across an ordinary NOOP transition, where
/// `default_flag = 1`, must be rejected. This proves the mutation reaches the proven trace
/// and that the verifier does police `ctx`.
#[test]
fn forged_context_at_ordinary_row_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_ctx(&mut repro, (rows.noop + 1)..rows.height, FORGED_CTX);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a context change on an ordinary (non-END) transition; \
         if this passes, the harness is not exercising what these tests claim: {result:?}"
    );
}

/// Exchange equal-D callee aliases after nested continuation ENDs. The unchanged entry boundary
/// and balanced resolution demand counts cannot substitute for preserving the callee principal.
/// The same witness is accepted only by the isolated historical coarse-END principal evaluator.
#[test]
fn forged_fn_hash_at_continuation_end_is_rejected() {
    check_alias_principal_exchange(true);
}

/// Control: exchange the same aliases across ordinary callee transitions.
#[test]
fn forged_fn_hash_at_ordinary_row_is_rejected() {
    check_alias_principal_exchange(false);
}

// INSIDE A CALL: THE ISOLATION-RELEVANT CASE
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
    let honest = repro
        .prove_comparison(CoreMode::Standard)
        .expect("the unchanged wrapper must construct the honest alias proof");
    assert!(
        honest.verification.is_ok(),
        "the unchanged evaluator must accept: {:?}",
        honest.verification
    );
    repro.assert_native_and_recursive_accept(honest.proof);

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
    let comparison = repro
        .prove_comparison(CoreMode::Alternate)
        .expect("balanced alias demands must reach actual comparison proof construction");
    assert_eq!(
        comparison.verification.is_ok(),
        after_continuation,
        "the historical selector must accept only the continuation witness: {:?}",
        comparison.verification
    );
    // Verify this very artifact with the current native and MASM evaluators. The captured
    // descriptor, claim, configuration/pins and every witness matrix are identical.
    repro.assert_native_and_recursive_air_rejection(comparison.proof);
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
    assert!(repro.prove_and_verify_current().is_ok(), "the honest trace must verify");
}

/// The isolation-relevant case: a nested continuation END lets the callee drop back into the
/// *caller's* execution context for the remainder of the call.
///
/// `call` resets `ctx` to `clk + 1` on entry, and the block-stack bus pins `ctx` back to the
/// caller's value only on the END *of the call*. Between those two points the only thing
/// holding `ctx` at the callee value is the default-flag preservation constraint. The historical
/// coarse-END selector made it vacuous at nested continuation ENDs. This fixture isolates that
/// context column; memory requests read `ctx` straight from it
/// (`chiplet_requests.rs`), so a callee tail running at `ctx = 0` addresses caller memory.
#[test]
fn callee_reentering_caller_context_at_nested_continuation_end_is_rejected() {
    check_call_context_comparison(true);
}

/// Control for the above: dropping into the caller's context one transition earlier -- across
/// an ordinary callee row rather than the nested continuation END -- must be rejected. This pins
/// the acceptance to the END transition specifically, not to `ctx` being loose inside calls.
#[test]
fn callee_reentering_caller_context_at_ordinary_row_is_rejected() {
    check_call_context_comparison(false);
}

fn check_call_context_comparison(after_continuation: bool) {
    let (mut repro, rows) = build_call_harness();
    let expected_claim = repro.claim();
    let honest = repro
        .prove_comparison(CoreMode::Standard)
        .expect("honest call context proof construction must complete");
    assert!(
        honest.verification.is_ok(),
        "the unchanged evaluator must accept: {:?}",
        honest.verification
    );
    repro.assert_native_and_recursive_accept(honest.proof);

    let start = if after_continuation {
        rows.nested_continuation_end
    } else {
        rows.ordinary_in_callee
    };
    // Only Core ctx changes: the caller-frame END restores the original root context. All
    // principal columns, other AIR matrices and the independently expected claim remain fixed.
    set_ctx(&mut repro, (start + 1)..=rows.call_end, Felt::ZERO);
    assert_eq!(repro.claim(), expected_claim);
    let comparison = repro
        .prove_comparison(CoreMode::CoarseContext)
        .expect("the changed context witness must finish comparison proof construction");
    assert_eq!(
        comparison.verification.is_ok(),
        after_continuation,
        "only the continuation context witness may pass the historical selector: {:?}",
        comparison.verification
    );
    repro.assert_native_and_recursive_air_rejection(comparison.proof);
}
