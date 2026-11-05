//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM,
//! which manages execution context and principal-key system column transitions.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory context isolation)
//! - `fn_hash` (four elements): Current principal key (legacy column name)
//!
//! ## Context Transitions
//!
//! | Operation             | ctx'              | Description               |
//! |-----------------------|-------------------|---------------------------|
//! | CALL or DYNCALL       | clk + 1           | Create new context        |
//! | SYSCALL               | 0                 | Return to kernel context  |
//! | Caller-frame END      | (from block stack)| Restore caller context    |
//! | Continuation END      | ctx               | Unchanged                 |
//! | Other ops             | ctx               | Unchanged                 |
//!
//! ## Function Hash Transitions
//!
//! | Operation                       | fn_hash'           | Description                 |
//! |---------------------------------|--------------------|-----------------------------|
//! | CALL or DYNCALL                 | decoder h0..h3     | Load requested principal key     |
//! | Caller-frame END                | (from block stack) | Restore previous hash       |
//! | Continuation END                | fn_hash            | Unchanged                   |
//! | Other ops (incl. EXEC, DYN, SYSCALL)  | fn_hash            | Unchanged                   |
//!
//! Note: restoration is handled by the block-stack relation only for an END that consumes a
//! caller-frame entry, whose removal carries `ctx` and `fn_hash`. A continuation entry carries
//! neither, so these constraints must preserve both columns across a continuation END -- see
//! `f_restore_caller_frame` below.

pub mod columns;

use miden_stark::air::AirBuilder;
use p3_field::Dup;

use crate::vm::{
    CoreCols, MidenAirBuilder,
    constraints::{constants::F_1, op_flags::OpFlags, utils::BoolNot},
};

// ENTRY POINTS
// ================================================================================================

/// Enforces system constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Clock and context start at 0. The public boundary binds the initial principal to K_entry.
    // Clock increments by 1 on each transition.
    {
        let builder = &mut builder.when_first_row();
        builder.assert_zero(local.system.clk);
        builder.assert_zero(local.system.ctx);
    }
    {
        builder.when_transition().assert_eq(next.system.clk, local.system.clk + F_1);
    }
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();

    // Only a caller-frame END may restore `ctx` and `fn_hash`; a continuation END preserves them.
    // The decoder constrains this selector, and the block-stack relation authenticates the entry
    // kind and restored payload.
    let end_flags = local.decoder.end_block_flags();
    let f_restore_caller_frame = op_flags.end() * end_flags.restores_caller_frame;

    // Execution context transition constraints (see module doc for transition table)
    {
        let ctx = local.system.ctx;
        let ctx_next = next.system.ctx;
        let clk = local.system.clk;

        let call_dyncall_flag = f_call.dup() + f_dyncall.dup();
        let change_ctx_flag =
            f_call.dup() + f_syscall.dup() + f_dyncall.dup() + f_restore_caller_frame.dup();
        let default_flag = change_ctx_flag.not();

        builder.when(call_dyncall_flag).assert_eq(ctx_next, clk + F_1);
        builder.when(f_syscall).assert_zero(ctx_next);
        builder.when_transition().when(default_flag).assert_eq(ctx_next, ctx);
    }

    // Function hash transition constraints (see module doc for transition table)
    {
        let f_load = f_call + f_dyncall;
        let f_preserve = (f_load.dup() + f_restore_caller_frame).not();

        {
            let builder = &mut builder.when(f_load);
            for i in 0..4 {
                builder.assert_eq(next.system.fn_hash[i], local.decoder.hasher_state[i]);
            }
        }

        builder
            .when_transition()
            .when(f_preserve)
            .assert_eq_arrays(next.system.fn_hash, local.system.fn_hash);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };
    use miden_stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
    use p3_matrix::dense::RowMajorMatrix;

    use super::enforce_main;
    use crate::vm::{
        CoreCols,
        constraints::{
            op_flags::{OpFlags, generate_test_row},
            system::columns::SystemCols,
        },
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
    };

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        preprocessed: RowWindow<'static, Felt>,
        evaluations: Vec<QuadFelt>,
        public_values: Vec<Felt>,
        first_row: Felt,
        last_row: Felt,
    }

    impl ConstraintEvalBuilder {
        fn new() -> Self {
            Self {
                main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
                aux: RowMajorMatrix::new(
                    vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2],
                    AUX_TRACE_WIDTH,
                ),
                randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
                permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
                periodic_values: Vec::new(),
                preprocessed: RowWindow::from_two_rows(&[], &[]),
                evaluations: Vec::new(),
                public_values: vec![Felt::ZERO; 36],
                first_row: Felt::ONE,
                last_row: Felt::ZERO,
            }
        }
    }

    impl AirBuilder for ConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;
        type PeriodicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed
        }

        fn is_first_row(&self) -> Self::Expr {
            self.first_row
        }

        fn is_last_row(&self) -> Self::Expr {
            self.last_row
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "system tests use two-row transition windows");
            self.is_transition()
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(QuadFelt::from(x.into()));
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &self.public_values
        }

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    impl ExtensionBuilder for ConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I>(&mut self, x: I)
        where
            I: Into<Self::ExprEF>,
        {
            self.evaluations.push(x.into());
        }
    }

    impl PermutationAirBuilder for ConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
    }

    fn forged_system_state() -> SystemCols<Felt> {
        SystemCols {
            clk: Felt::ZERO,
            ctx: Felt::new_unchecked(7),
            fn_hash: [
                Felt::new_unchecked(11),
                Felt::new_unchecked(22),
                Felt::new_unchecked(33),
                Felt::new_unchecked(44),
            ],
        }
    }

    #[test]
    fn system_constraints_reject_nonzero_initial_context() {
        let mut local = generate_test_row(0);
        local.system = forged_system_state();

        let mut next = generate_test_row(0);
        next.system = forged_system_state();
        next.system.clk = Felt::ONE;

        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = ConstraintEvalBuilder::new();
        enforce_main(&mut builder, &local, &next, &op_flags);

        assert!(
            builder.evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "system constraints should reject a forged initial context"
        );
    }

    #[test]
    fn system_initial_principal_is_supplied_by_the_public_boundary() {
        let mut local = generate_test_row(0);
        local.system.fn_hash = [Felt::from_u8(19); 4];
        let mut next = local.clone();
        next.system.clk = Felt::ONE;
        let flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = ConstraintEvalBuilder::new();
        enforce_main(&mut builder, &local, &next, &flags);
        assert!(builder.evaluations.iter().all(|v| *v == QuadFelt::ZERO));

        local.system.clk = Felt::ONE;
        next.system.clk += Felt::ONE;
        let flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = ConstraintEvalBuilder::new();
        enforce_main(&mut builder, &local, &next, &flags);
        assert!(builder.evaluations.iter().any(|v| *v != QuadFelt::ZERO));
    }

    fn eval_public_boundary(
        local: &CoreCols<Felt>,
        entry: [Felt; 4],
        first: bool,
        last: bool,
    ) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        builder.first_row = Felt::from_bool(first);
        builder.last_row = Felt::from_bool(last);
        builder.public_values[32..36].copy_from_slice(&entry);
        super::super::public_inputs::enforce_main(&mut builder, local);
        builder.evaluations
    }

    #[test]
    fn public_boundary_binds_initial_and_final_principals_to_the_entry_key() {
        let entry = core::array::from_fn(|i| Felt::from_u8(17 + i as u8));
        let mut row = generate_test_row(opcodes::HALT.into());
        row.system.fn_hash = entry;
        for (first, last) in [(true, false), (false, true)] {
            assert!(
                eval_public_boundary(&row, entry, first, last)
                    .iter()
                    .all(|v| *v == QuadFelt::ZERO)
            );
            for lane in 0..4 {
                let mut forged = row.clone();
                forged.system.fn_hash[lane] += Felt::ONE;
                assert!(
                    eval_public_boundary(&forged, entry, first, last)
                        .iter()
                        .any(|v| *v != QuadFelt::ZERO)
                );
            }
            let mut zero_principal = row.clone();
            zero_principal.system.fn_hash.fill(Felt::ZERO);
            assert!(
                eval_public_boundary(&zero_principal, entry, first, last)
                    .iter()
                    .any(|v| *v != QuadFelt::ZERO)
            );
        }

        // The public boundary does not overwrite a nested call's interior principal.
        row.system.fn_hash = [Felt::from_u8(99); 4];
        assert!(
            eval_public_boundary(&row, entry, false, false)
                .iter()
                .all(|v| *v == QuadFelt::ZERO)
        );
    }

    #[test]
    #[should_panic(expected = "Core requires exactly 36 public values")]
    fn public_boundary_rejects_missing_entry_key() {
        let mut builder = ConstraintEvalBuilder::new();
        builder.public_values.truncate(32);
        super::super::public_inputs::enforce_main(&mut builder, &generate_test_row(0));
    }

    #[test]
    #[should_panic(expected = "Core requires exactly 36 public values")]
    fn public_boundary_rejects_trailing_public_values() {
        let mut builder = ConstraintEvalBuilder::new();
        builder.public_values.push(Felt::ZERO);
        super::super::public_inputs::enforce_main(&mut builder, &generate_test_row(0));
    }

    /// Evaluates the system constraints on an interior transition, excluding first-row boundary
    /// constraints from these caller-frame restoration tests.
    fn eval_system(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> Vec<QuadFelt> {
        use crate::vm::constraints::stack::test_utils::ConstraintEvalBuilder as SharedBuilder;
        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = SharedBuilder::new().with_row_flags(false, false, true);
        enforce_main(&mut builder, local, next, &op_flags);
        builder.evaluations
    }

    /// Builds an END row carrying the given caller-frame restoration flag, with a non-root context
    /// and digest, plus the following row.
    fn end_rows(restores_caller_frame: Felt) -> (CoreCols<Felt>, CoreCols<Felt>) {
        let mut local = generate_test_row(opcodes::END.into());
        local.decoder.hasher_state[6] = restores_caller_frame;
        local.system.ctx = Felt::new_unchecked(7);
        local.system.fn_hash = [Felt::new_unchecked(11); 4];

        let mut next = generate_test_row(0);
        next.system.clk = local.system.clk + Felt::ONE;
        next.system.ctx = local.system.ctx;
        next.system.fn_hash = local.system.fn_hash;
        (local, next)
    }

    #[test]
    fn continuation_end_preserves_context_and_fn_hash() {
        let (local, next) = end_rows(Felt::ZERO);
        assert!(
            eval_system(&local, &next).iter().all(|v| *v == QuadFelt::ZERO),
            "an ordinary END that preserves ctx/fn_hash must be accepted"
        );

        // Changing either column across an ordinary END must be caught.
        let mut changed_ctx = next.clone();
        changed_ctx.system.ctx += Felt::ONE;
        assert!(
            eval_system(&local, &changed_ctx).iter().any(|v| *v != QuadFelt::ZERO),
            "an ordinary END must not be able to change ctx"
        );

        let mut changed_hash = next;
        changed_hash.system.fn_hash[0] += Felt::ONE;
        assert!(
            eval_system(&local, &changed_hash).iter().any(|v| *v != QuadFelt::ZERO),
            "an ordinary END must not be able to change fn_hash"
        );
    }

    #[test]
    fn invocation_modes_load_only_requested_call_principals() {
        let principal = [Felt::from_u8(11); 4];
        let key = [Felt::from_u8(22); 4];
        let implementation = [Felt::from_u8(33); 4];
        for opcode in
            [opcodes::EXEC, opcodes::DYN, opcodes::SYSCALL, opcodes::CALL, opcodes::DYNCALL]
        {
            let mut local = generate_test_row(opcode.into());
            local.system.ctx = Felt::from_u8(7);
            local.system.fn_hash = principal;
            local.decoder.hasher_state[..4].copy_from_slice(&key);
            local.decoder.hasher_state[4..8].copy_from_slice(&implementation);
            let mut next = generate_test_row(opcodes::JOIN.into());
            next.system.clk = Felt::ONE;
            let establishes_principal = matches!(opcode, opcodes::CALL | opcodes::DYNCALL);
            next.system.ctx = if establishes_principal {
                Felt::ONE
            } else if opcode == opcodes::SYSCALL {
                Felt::ZERO
            } else {
                local.system.ctx
            };
            next.system.fn_hash = if establishes_principal { key } else { principal };
            assert!(eval_system(&local, &next).iter().all(|v| *v == QuadFelt::ZERO));

            let mut wrong_principal = next.clone();
            wrong_principal.system.fn_hash = implementation;
            assert!(eval_system(&local, &wrong_principal).iter().any(|v| *v != QuadFelt::ZERO));
            let mut wrong_ctx = next;
            wrong_ctx.system.ctx += Felt::ONE;
            assert!(eval_system(&local, &wrong_ctx).iter().any(|v| *v != QuadFelt::ZERO));
        }
    }

    #[test]
    fn halt_preserves_the_entry_principal() {
        let mut local = generate_test_row(opcodes::HALT.into());
        local.system.fn_hash = [Felt::from_u8(17); 4];
        let mut next = local.clone();
        next.system.clk = Felt::ONE;
        assert!(eval_system(&local, &next).iter().all(|v| *v == QuadFelt::ZERO));
        next.system.fn_hash[0] += Felt::ONE;
        assert!(eval_system(&local, &next).iter().any(|v| *v != QuadFelt::ZERO));
    }

    #[test]
    fn caller_frame_end_permits_restoration() {
        let (local, next) = end_rows(Felt::ONE);

        let mut restored = next;
        restored.system.ctx = Felt::ZERO;
        restored.system.fn_hash = [Felt::ZERO; 4];

        assert!(
            eval_system(&local, &restored).iter().all(|v| *v == QuadFelt::ZERO),
            "a caller-frame END must permit ctx/fn_hash to be restored to the caller's values"
        );
    }
}
