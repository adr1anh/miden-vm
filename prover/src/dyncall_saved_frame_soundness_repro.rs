//! Regression tests: DYNCALL's saved caller-frame depth and overflow pointer must match reality.
//!
//! Historically a free decoder helper let the caller resume at a prover-selected depth through
//! an otherwise honest caller-frame restoration. The compact layout derives the saved depth as
//! `b0 - overflow()` and saves only the post-pop overflow pointer in `group_count`. Its second
//! hasher word holds the authenticated implementation and stays unchanged in every attack here.
//!
//! These mutations retain the caller-frame kind at both ends. Forging a restored depth must
//! mismatch the independently derived saved frame; forging its pointer must fail either the
//! empty-overflow constraint or the nonempty overflow-record authentication.
//!
//! To keep the rest of the trace valid, the forged restored depth `D` is contained inside an
//! enclosing `call`: the dyncall runs inside a called procedure, the dyncall's END restores the
//! caller (the enclosing procedure) to depth `D`, and the enclosing call's own END restores the
//! root to 16 -- erasing the excursion before the last-row `b0 = 16` boundary.

use alloc::{format, vec, vec::Vec};

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{Felt, field::Field, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::repro_harness::{ReproTrace, core_row_mut};

const ADDR: u64 = 40;
/// The forged caller depth. Any value != 16 exercises the gap.
const FORGED_DEPTH: u64 = 99;

struct Fixture {
    trace: ReproTrace,
    dyncall_row: usize,
    invocation_state: [Felt; 8],
    dyncall_end: usize,
    /// The enclosing procedure's caller-frame END, after which the root is restored.
    outer_end: usize,
}

fn build_fixture() -> Fixture {
    build_fixture_with_setup("mem_storew_le.40 movup.4 dyncall", 16)
}

fn build_fixture_with_setup(dyncall_setup: &str, pre_dyncall_depth: u64) -> Fixture {
    // The dyncall runs inside a called procedure `bar`, so the excursion it opens is erased by
    // bar's own END. `foo` (the dyncall target, a no-op) is kept in the forest by `call.foo`.
    let source = format!(
        "
        proc foo
            nop
        end
        proc bar
            {dyncall_setup}
        end
        begin
            call.foo
            call.bar
        end
    "
    );
    let fixture = crate::named_fixture::named_source(source.as_str());
    let foo_key = fixture.key("foo").into_word();
    let program = fixture.code;
    let environment = fixture.environment;

    let mut stack_values = vec![Felt::ZERO; 16];
    for (i, limb) in foo_key.as_elements().iter().enumerate() {
        stack_values[i] = *limb;
    }
    stack_values[4] = Felt::new_unchecked(ADDR);
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
    let op = |r: usize| main.get_op_code(RowIndex::from(r)).as_canonical_u64() as u8;

    let dyncalls: Vec<usize> = (0..height).filter(|&r| op(r) == opcodes::DYNCALL).collect();
    assert_eq!(dyncalls.len(), 1, "the dyncall must resolve to `foo`, not recurse into `bar`");
    let dyncall_row = dyncalls[0];

    let restores_caller_frame = |r: usize| {
        op(r) == opcodes::END && main.restores_caller_frame_flag(RowIndex::from(r)) == Felt::ONE
    };
    let dyncall_end =
        (dyncall_row..height).find(|&r| restores_caller_frame(r)).expect("dyncall END");
    let outer_end = ((dyncall_end + 1)..height)
        .find(|&r| restores_caller_frame(r))
        .expect("bar END");

    // Preconditions.
    assert_eq!(
        main.stack_depth(RowIndex::from(dyncall_row)),
        Felt::new_unchecked(pre_dyncall_depth),
    );
    assert_eq!(
        main.dyncall_caller_stack_depth(RowIndex::from(dyncall_row)),
        Felt::new_unchecked(16),
        "the derived post-pop caller depth is 16"
    );
    assert_eq!(
        main.dyncall_caller_overflow_addr(RowIndex::from(dyncall_row)),
        Felt::ZERO,
        "the group-count overlay holds the post-pop overflow pointer"
    );
    // The dyncall's END honestly restores the caller (bar) to depth 16 ...
    assert_eq!(main.stack_depth(RowIndex::from(dyncall_end + 1)), Felt::new_unchecked(16));
    // ... and bar's END restores the root to depth 16.
    assert_eq!(main.stack_depth(RowIndex::from(outer_end + 1)), Felt::new_unchecked(16));

    Fixture {
        trace: ReproTrace::new(&trace),
        dyncall_row,
        invocation_state: main.decoder_hasher_state(RowIndex::from(dyncall_row)),
        dyncall_end,
        outer_end,
    }
}

fn assert_invocation_unchanged(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    assert_eq!(core_row_mut(core, f.dyncall_row).decoder.hasher_state, f.invocation_state);
}

/// Holds `b0` at the forged depth `D` across the excursion window `[dyncall_end+1 ..= outer_end]`,
/// with the overflow helper `h0 = 1/(D-16)` so the flag constraint `(1-overflow)(b0-16)=0` holds.
fn apply_depth_excursion(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    let d = Felt::new_unchecked(FORGED_DEPTH);
    let h0 = (d - Felt::new_unchecked(16)).inverse();
    // The invocation's authenticated implementation and derived saved depth stay honest.
    // Carry a forged restored depth through the window, then erase it at the outer return.
    for row in (f.dyncall_end + 1)..=f.outer_end {
        let r = core_row_mut(core, row);
        r.stack.b0 = d;
        r.stack.h0 = h0;
    }
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// The former gap: restore an arbitrary caller depth while keeping the caller-frame entry kind
/// honest. The contained `b0` excursion must disagree with the depth derived at DYNCALL.
#[test]
fn forged_caller_depth_via_caller_frame_path_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    apply_depth_excursion(&f, &mut core);

    assert_invocation_unchanged(&f, &mut core);
    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a restored caller depth that disagrees with the \
         saved b0 - overflow() value: {result:?}"
    );
}

/// Control: corrupt only the first restored depth, leaving the remaining caller trace honest.
/// The frame removal must still disagree with the DYNCALL's independently derived addition.
#[test]
fn forged_restored_depth_without_matching_excursion_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    let restored = core_row_mut(&mut core, f.dyncall_end + 1);
    restored.stack.b0 = Felt::new_unchecked(FORGED_DEPTH);
    restored.stack.h0 = (restored.stack.b0 - Felt::new_unchecked(16)).inverse();

    assert_invocation_unchanged(&f, &mut core);
    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a forged restored depth: {result:?}"
    );
}

/// The sibling gap: DYNCALL's saved caller overflow pointer is recorded from a
/// decoder cell. The stack-overflow relation pins it only when the overflow table is non-empty
/// (that branch is gated on `dyncall * overflow`), so the empty case — the common one — was open.
///
/// Forge the group-count overlay on the DYNCALL row and carry the matching `b1` across
/// the excursion window, which bar's enclosing END erases before the last-row `b1 = 0` boundary.
#[test]
fn forged_caller_overflow_pointer_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    let forged = Felt::new_unchecked(1234);

    core_row_mut(&mut core, f.dyncall_row).decoder.group_count = forged;
    for row in (f.dyncall_end + 1)..=f.outer_end {
        core_row_mut(&mut core, row).stack.b1 = forged;
    }

    assert_invocation_unchanged(&f, &mut core);
    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a forged saved caller overflow pointer: it is pinned to \
         zero on a DYNCALL taken from an empty overflow table: {result:?}"
    );
}

/// Control for the above: forging the saved pointer with `b1` left honest must be rejected by the
/// block-stack relation regardless, since the addition then records a pointer the matching
/// removal does not restore.
#[test]
fn forged_saved_pointer_without_matching_restoration_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    core_row_mut(&mut core, f.dyncall_row).decoder.group_count = Felt::new_unchecked(1234);

    assert_invocation_unchanged(&f, &mut core);
    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "forging the saved pointer with b1 left honest must be rejected by the empty-overflow \
         constraint and the mismatched caller frame: {result:?}"
    );
}

/// With one overflow row, DYNCALL must authenticate that row's predecessor as the saved caller
/// pointer. The forged pointer is carried to the matching END, so the caller-frame relation still
/// balances; only the overflow relation can reject it.
#[test]
fn forged_caller_overflow_pointer_with_nonempty_table_is_rejected() {
    let f = build_fixture_with_setup("mem_storew_le.40 push.111 movup.5 dyncall", 17);
    let mut core = f.trace.core.clone();
    let forged = Felt::new_unchecked(1234);

    core_row_mut(&mut core, f.dyncall_row).decoder.group_count = forged;
    for row in (f.dyncall_end + 1)..=f.outer_end {
        core_row_mut(&mut core, row).stack.b1 = forged;
    }

    assert_invocation_unchanged(&f, &mut core);
    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a saved pointer that is not the predecessor of the overflow row \
         consumed by DYNCALL: {result:?}"
    );
}
