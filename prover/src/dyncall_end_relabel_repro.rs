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
//!
//! The separate continuation-preservation tests below keep the DYNCALL saved frame and its END
//! honest. They change only principal or only context after a real inner continuation END,
//! through the callee's caller-frame END, then restore the honest entry boundary. Equal-D aliases
//! balance principal-dependent completion demands. Each witness must be accepted by the private
//! evaluator changing only its targeted coarse-END preservation selector, while the identical
//! change across an ordinary transition rejects. Current native and MASM consumers reject the
//! retained artifacts in AIR evaluation. These cases isolate preservation inside a DYNCALL;
//! they do not attribute the compound caller-frame relabelling controls above to a single rule.

use alloc::{format, vec, vec::Vec};

use miden_air_definitions::vm::trace::RowIndex;
use miden_core::{Felt, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::repro_harness::{CoreMode, ReproTrace, core_row_mut};

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

// ISOLATED PRESERVATION INSIDE AN HONEST DYNCALL
// ================================================================================================

struct DyncallContinuationRows {
    ordinary_in_callee: usize,
    inner_end: usize,
    caller_frame_end: usize,
}

struct ContinuationFixture {
    trace: ReproTrace,
    rows: [DyncallContinuationRows; 2],
    principals: [[Felt; 4]; 2],
    entry: [Felt; 4],
    height: usize,
}

fn build_continuation_fixture() -> ContinuationFixture {
    // The two authenticated aliases select the same implementation. Exchanging only their
    // principal tails preserves the multiset of root-completion resolution demands. Each body
    // has an internal branch END followed by an overflow-free NOOP suffix, with no memory
    // operations or further invocations in either callee tail.
    let body = "push.1 if.true push.7 drop else push.8 drop end nop nop";
    let source = format!(
        "proc left {body} end proc right {body} end begin
            procref.left mem_storew_le.40 dropw push.40 dyncall
            procref.right mem_storew_le.44 dropw push.44 dyncall
        end"
    );
    let fixture = crate::named_fixture::named_source(&source);
    let keys = [fixture.key("left"), fixture.key("right")];
    assert_ne!(keys[0], keys[1]);
    let implementations = keys.map(|key| {
        fixture.naming.callables().selected_implementation(key).expect("selected alias")
    });
    assert_eq!(implementations[0], implementations[1], "the aliases must select equal D");
    let principals = keys.map(|key| key.into_word().into_elements());
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
    let dyncalls = (0..height)
        .filter(|&row| opcode(row) == Felt::from_u8(opcodes::DYNCALL))
        .collect::<Vec<_>>();
    assert_eq!(dyncalls.len(), 2);
    let entry = trace.execution_descriptor().entry_key().into_word().into_elements();
    assert_ne!(entry, [Felt::ZERO; 4]);
    let rows = core::array::from_fn(|index| {
        let dyncall = dyncalls[index];
        let caller_frame_end = ((dyncall + 1)..height)
            .find(|&row| {
                opcode(row) == Felt::from_u8(opcodes::END)
                    && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
            })
            .expect("the DYNCALL must have an honest caller-frame END");
        // The condition SPAN also ends before the split consumes its condition. Select the
        // last continuation END that still precedes a suffix NOOP, after all branch work.
        let inner_end = ((dyncall + 1)..caller_frame_end)
            .rfind(|&row| {
                opcode(row) == Felt::from_u8(opcodes::END)
                    && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ZERO
                    && ((row + 1)..caller_frame_end)
                        .any(|suffix| opcode(suffix) == Felt::from_u8(opcodes::NOOP))
            })
            .expect(
                "the DYNCALL callee must have an inner continuation END before its NOOP suffix",
            );
        let ordinary_in_callee = ((inner_end + 1)..caller_frame_end)
            .find(|&row| opcode(row) == Felt::from_u8(opcodes::NOOP))
            .expect("the callee suffix must have an ordinary NOOP transition");
        assert!(ordinary_in_callee + 1 < caller_frame_end, "the NOOP must have a callee tail");
        for row in inner_end..=caller_frame_end {
            let idx = RowIndex::from(row);
            assert_eq!(main.stack_depth(idx), Felt::new_unchecked(16));
            assert_eq!(main.parent_overflow_address(idx), Felt::ZERO);
            assert!(!main.is_non_empty_overflow(idx));
            assert!(
                matches!(
                    opcode(row).as_canonical_u64() as u8,
                    opcodes::SPAN | opcodes::NOOP | opcodes::END
                ),
                "the selected callee tail must contain no RAM or overflow-changing operations"
            );
        }

        // The address operand is popped from depth 17, saving a real depth-16 caller frame
        // with no overflow. The mutation below leaves every decoder and stack cell untouched.
        assert_eq!(main.stack_depth(RowIndex::from(dyncall)), Felt::new_unchecked(17));
        assert_eq!(
            main.decoder_hasher_state_element(4, RowIndex::from(dyncall)),
            Felt::new_unchecked(16),
            "h4 must keep the honest post-pop depth"
        );
        assert_eq!(
            main.decoder_hasher_state_element(5, RowIndex::from(dyncall)),
            Felt::ZERO,
            "h5 must keep the honest post-pop overflow pointer"
        );
        assert_eq!(
            main.decoder_hasher_state_element(6, RowIndex::from(caller_frame_end)),
            Felt::ONE,
            "h6 must keep the caller-frame restoration flag"
        );
        assert_eq!(main.ctx(RowIndex::from(dyncall)), Felt::ZERO);
        assert_eq!(main.fn_hash(RowIndex::from(dyncall)), entry);
        let callee_ctx = main.ctx(RowIndex::from(dyncall + 1));
        assert_ne!(callee_ctx, Felt::ZERO);
        for row in (dyncall + 1)..=caller_frame_end {
            assert_eq!(main.ctx(RowIndex::from(row)), callee_ctx);
            assert_eq!(main.fn_hash(RowIndex::from(row)), principals[index]);
        }
        assert_eq!(main.ctx(RowIndex::from(caller_frame_end + 1)), Felt::ZERO);
        assert_eq!(main.fn_hash(RowIndex::from(caller_frame_end + 1)), entry);
        assert_eq!(main.stack_depth(RowIndex::from(caller_frame_end + 1)), Felt::new_unchecked(16));
        DyncallContinuationRows {
            ordinary_in_callee,
            inner_end,
            caller_frame_end,
        }
    });
    assert!(rows[0].caller_frame_end < dyncalls[1]);
    ContinuationFixture {
        trace: ReproTrace::new(&trace),
        rows,
        principals,
        entry,
        height,
    }
}

#[derive(Clone, Copy)]
enum PreservedColumn {
    Principal,
    Context,
}

fn check_dyncall_continuation_preservation(column: PreservedColumn, after_continuation: bool) {
    let ContinuationFixture {
        mut trace,
        rows,
        principals,
        entry,
        height,
    } = build_continuation_fixture();
    let expected_claim = trace.claim();
    let honest = trace
        .prove_comparison(CoreMode::Standard)
        .expect("the honest DYNCALL fixture must finish comparison proof construction");
    assert!(
        honest.verification.is_ok(),
        "the unchanged evaluator must accept the honest DYNCALL fixture: {:?}",
        honest.verification
    );
    trace.assert_native_and_recursive_accept(honest.proof);

    for index in 0..2 {
        let start = if after_continuation {
            rows[index].inner_end
        } else {
            rows[index].ordinary_in_callee
        };
        // Change exactly one system column from the chosen transition's next row through
        // the honest caller-frame END. Its next row and the outer entry/final boundary stay
        // honest; all saved-frame cells, stack state and other witness matrices stay fixed.
        for row in (start + 1)..=rows[index].caller_frame_end {
            let system = &mut core_row_mut(&mut trace.core, row).system;
            match column {
                PreservedColumn::Principal => system.fn_hash = principals[1 - index],
                PreservedColumn::Context => system.ctx = Felt::ZERO,
            }
        }
        let restored = &core_row_mut(&mut trace.core, rows[index].caller_frame_end + 1).system;
        assert_eq!(restored.ctx, Felt::ZERO);
        assert_eq!(restored.fn_hash, entry);
    }
    assert_eq!(core_row_mut(&mut trace.core, 0).system.ctx, Felt::ZERO);
    assert_eq!(core_row_mut(&mut trace.core, 0).system.fn_hash, entry);
    assert_eq!(core_row_mut(&mut trace.core, height - 1).system.ctx, Felt::ZERO);
    assert_eq!(core_row_mut(&mut trace.core, height - 1).system.fn_hash, entry);
    assert_eq!(trace.claim(), expected_claim);

    let mode = match column {
        PreservedColumn::Principal => CoreMode::Alternate,
        PreservedColumn::Context => CoreMode::CoarseContext,
    };
    let comparison = trace
        .prove_comparison(mode)
        .expect("the isolated DYNCALL witness must finish actual comparison proof construction");
    assert_eq!(
        comparison.verification.is_ok(),
        after_continuation,
        "the isolated historical selector must accept only the inner-END witness: {:?}",
        comparison.verification
    );
    trace.assert_native_and_recursive_air_rejection(comparison.proof);
}

/// Equal-D principal tails can be exchanged after inner ENDs only under the coarse principal
/// comparison; the same artifact must fail current native and MASM AIR evaluation.
#[test]
fn dyncall_principal_change_at_inner_continuation_end_is_rejected() {
    check_dyncall_continuation_preservation(PreservedColumn::Principal, true);
}

/// The identical principal exchange across ordinary callee transitions also fails the comparison.
#[test]
fn dyncall_principal_change_at_ordinary_transition_is_rejected() {
    check_dyncall_continuation_preservation(PreservedColumn::Principal, false);
}

/// Only context changes: the suffix runs in the caller's root context until the honest DYNCALL
/// caller-frame END restores it. The coarse context comparison alone accepts that witness.
#[test]
fn dyncall_context_change_at_inner_continuation_end_is_rejected() {
    check_dyncall_continuation_preservation(PreservedColumn::Context, true);
}

/// Moving the same context change to an ordinary transition must still fail the comparison.
#[test]
fn dyncall_context_change_at_ordinary_transition_is_rejected() {
    check_dyncall_continuation_preservation(PreservedColumn::Context, false);
}
