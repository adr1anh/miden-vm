//! ACE (Arithmetic Circuit Evaluation) chiplet constraints.
//!
//! The ACE chiplet reduces the number of cycles required when recursively verifying
//! a STARK proof by evaluating arithmetic circuits and ensuring they evaluate to zero.
//!
//! ## Operation Phases
//!
//! 1. **READ blocks**: Load extension field elements from memory and assign node IDs
//! 2. **EVAL blocks**: Execute arithmetic operations on previously loaded nodes
//!
//! ## Column Layout (within chiplet, offset by selectors)
//!
//! | Column    | Purpose                                        |
//! |-----------|------------------------------------------------|
//! | sstart    | Section start flag (1 = first row of section)  |
//! | sblock    | Block selector (0=READ, 1=EVAL)                |
//! | ctx       | Memory access context                          |
//! | ptr       | Memory pointer (+4 in READ, +1 in EVAL)        |
//! | clk       | Memory access clock cycle                      |
//! | op        | Operation type (-1=SUB, 0=MUL, 1=ADD)          |
//! | id0       | Result node ID                                 |
//! | v0_0/v0_1 | Result node value (extension field)            |
//! | id1       | First operand node ID                          |
//! | v1_0/v1_1 | First operand value                            |
//! | id2/n_eval| Second operand ID (EVAL) / num evals (READ)    |
//! | v2_0      | Second operand value (coefficient 0)           |
//! | v2_1/m1   | Second operand (EVAL) / multiplicity (READ)    |
//! | m0        | Wire bus multiplicity for node 0               |

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::vm::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_4},
        ext_field::{QuadFeltAirBuilder, QuadFeltExpr},
        utils::BoolNot,
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce ACE chiplet constraints that apply to all rows.
pub fn enforce_ace_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let op_squared: AB::Expr = local.ace_op_squared().into();
    let local = local.ace();
    let next = next.ace();

    let ace_flag = flags.is_active.clone();
    let ace_transition = flags.is_transition.clone();
    let ace_last = flags.is_last.clone();

    // Derived section flags
    let s_start = local.s_start;
    let s_start_next = next.s_start;
    let s_transition = s_start_next.into().not();

    // ==========================================================================
    // FIRST ROW CONSTRAINTS
    // ==========================================================================

    // First row of ACE must have sstart' = 1
    builder.when(flags.next_is_first.clone()).assert_one(s_start_next);

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    // When ACE is active, section flags must be boolean.
    {
        let builder = &mut builder.when(ace_flag.clone());
        builder.assert_bool(local.s_start);
        builder.assert_bool(local.s_block);
    }

    let f_eval = local.s_block;
    let f_eval_next = next.s_block;
    let f_read = f_eval.into().not();
    let f_read_next = f_eval_next.into().not();

    // ==========================================================================
    // SECTION/BLOCK FLAGS CONSTRAINTS
    // ==========================================================================
    {
        // Last row of ACE chiplet cannot be section start
        builder.when(ace_last).assert_zero(s_start);

        // Prevent consecutive section starts within ACE chiplet
        builder.when(ace_transition.clone()).when(s_start).assert_zero(s_start_next);

        // Sections must start with READ blocks (not EVAL)
        builder.when(ace_flag.clone()).when(s_start).assert_zero(f_eval);

        // EVAL blocks cannot be followed by READ blocks within same section
        builder
            .when(ace_transition.clone())
            .when(s_transition.clone())
            .when(f_eval)
            .assert_zero(f_read_next.clone());
    }

    // ==========================================================================
    // SECTION CONSTRAINTS (within section)
    // ==========================================================================

    // Within-section transitions: context, clock, pointer, and node ID consistency.
    {
        let builder = &mut builder.when(ace_transition.clone() * s_transition);

        // clk and ctx are stable
        builder.assert_eq(next.ctx, local.ctx);
        builder.assert_eq(next.clk, local.clk);

        // Memory pointer increments: +4 in READ, +1 in EVAL
        // ptr' = ptr + 4 * f_read + f_eval
        let expected_ptr: AB::Expr = local.ptr + f_read.clone() * F_4 + f_eval;
        builder.assert_eq(next.ptr, expected_ptr);

        // Node ID decrements: -2 in READ, -1 in EVAL
        // id0 = id0' + 2 * f_read + f_eval
        let expected_id0: AB::Expr = next.id_0 + f_read.double() + f_eval;
        builder.assert_eq(local.id_0, expected_id0);
    }

    // ==========================================================================
    // READ BLOCK CONSTRAINTS
    // ==========================================================================

    // In READ block, the two node IDs should be consecutive (id1 = id0 - 1)
    builder
        .when(ace_flag.clone())
        .when(f_read.clone())
        .assert_eq(local.id_1, local.id_0 - F_1);

    // READ→EVAL transition occurs when n_eval matches the first EVAL id0.
    // n_eval is constant across READ rows and encodes (num_eval_rows - 1).
    // Enforce: f_read * (f_read' * n_eval' + f_eval' * id0' - n_eval) = 0
    let selected: AB::Expr = f_read_next * next.read().num_eval + f_eval_next * next.id_0;
    builder
        .when(ace_transition)
        .when(f_read.clone())
        .assert_eq(selected, local.read().num_eval);

    // ==========================================================================
    // EVAL BLOCK CONSTRAINTS
    // ==========================================================================

    // EVAL block: op ternary validity and arithmetic operation result.
    {
        let builder = &mut builder.when(ace_flag * f_eval);
        let op: AB::Expr = local.eval_op.into();

        let op_square = op.square();
        // op must be -1, 0, or 1: ternary validity
        // op * (op² - 1) = op ( op - 1) ( op + 1 )
        builder.assert_zero(op.clone() * (op_square.clone() - F_1));
        builder.assert_eq(op_squared.clone(), op_square);

        // Compute expected EVAL block output (v0) from op and operands.
        //
        // Operations in extension field 𝔽ₚ[x]/(x² - 7):
        // - op = -1: Subtraction (v0 = v1 - v2)
        // - op =  0: Multiplication (v0 = v1 × v2)
        // - op =  1: Addition (v0 = v1 + v2)
        let v0: QuadFeltExpr<AB::Expr> = local.v_0.into_expr();
        let v1: QuadFeltExpr<AB::Expr> = local.v_1.into_expr();
        let v2: QuadFeltExpr<AB::Expr> = local.eval().v_2.into_expr();

        // With z = op², z*v1 + op*v2 selects the linear gates and
        // (1-z)*(v1*v2) selects multiplication. Each coordinate has degree three.
        let expected = v1.clone() * op_squared.clone()
            + v2.clone() * op
            + (v1 * v2) * (AB::Expr::ONE - op_squared);
        builder.assert_eq_quad(v0, expected);
    }

    // ==========================================================================
    // FINALIZATION CONSTRAINTS
    // ==========================================================================

    // At section end: result value and node ID must be zero.
    {
        // f_end fires on the last ACE row or on section boundaries.
        let f_end = flags.is_last.clone() + flags.is_transition.clone() * s_start_next;
        let builder = &mut builder.when(f_end);

        // Sections must end with EVAL blocks (not READ).
        builder.assert_zero(f_read);

        let v0: QuadFeltExpr<AB::Expr> = local.v_0.into_expr();

        builder.assert_eq_quad(v0, QuadFeltExpr::new(AB::Expr::ZERO, AB::Expr::ZERO));

        builder.assert_zero(local.id_0);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::borrow::BorrowMut;

    use miden_core::{
        Felt,
        field::{BasedVectorSpace, PrimeCharacteristicRing, QuadFelt},
    };

    use super::enforce_ace_constraints_all_rows;
    use crate::vm::{
        AceCols, ChipletCols, QuadFeltExpr,
        constraints::{
            chiplets::selectors::build_chiplet_selectors, stack::test_utils::ConstraintEvalBuilder,
        },
        trace::CHIPLETS_DATA_WIDTH,
    };

    fn ace_cols(row: &mut ChipletCols<Felt>) -> &mut AceCols<Felt> {
        row.chiplets[5..21].borrow_mut()
    }

    fn quad_expr(value: QuadFelt) -> QuadFeltExpr<Felt> {
        let coefficients = value.as_basis_coefficients_slice();
        QuadFeltExpr(coefficients[0], coefficients[1])
    }

    fn eval_row(op: Felt, inputs: [[u8; 2]; 2]) -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        };
        // Packed ACE prefix follows Library, Controller, AEAD, and Memory.
        row.chiplets[3] = Felt::ONE;
        let v1 = QuadFelt::new(inputs[0].map(Felt::from_u8));
        let v2 = QuadFelt::new(inputs[1].map(Felt::from_u8));
        let result = if op == -Felt::ONE {
            v1 - v2
        } else if op == Felt::ZERO {
            v1 * v2
        } else {
            v1 + v2
        };
        let cols = ace_cols(&mut row);
        cols.s_block = Felt::ONE;
        cols.eval_op = op;
        cols.v_0 = quad_expr(result);
        cols.v_1 = quad_expr(v1);
        cols.eval_mut().v_2 = quad_expr(v2);
        *row.ace_op_squared_mut() = op.square();
        row
    }

    fn evaluations(row: &ChipletCols<Felt>) -> Vec<QuadFelt> {
        // Evaluate row-local constraints with the production selectors on full shared rows.
        let mut builder = ConstraintEvalBuilder::new().with_row_flags(false, false, false);
        let selectors = build_chiplet_selectors(&mut builder, row, row);
        enforce_ace_constraints_all_rows(&mut builder, row, row, &selectors.ace);
        builder.evaluations
    }

    fn assert_accepts(row: &ChipletCols<Felt>) {
        let evaluations = evaluations(row);
        assert!(
            evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "expected ACE constraints to accept: {evaluations:?}",
        );
    }

    fn assert_rejects(row: &ChipletCols<Felt>) {
        assert!(evaluations(row).iter().any(|value| *value != QuadFelt::ZERO));
    }

    fn recompute_arithmetic(row: &mut ChipletCols<Felt>) {
        let z = row.ace_op_squared();
        let cols = ace_cols(row);
        let v1 = cols.v_1;
        let v2 = cols.eval().v_2;
        cols.v_0 = v1 * z + v2 * cols.eval_op + (v1 * v2) * (Felt::ONE - z);
    }

    #[test]
    fn ace_eval_binds_square_and_checks_all_three_operations() {
        for inputs in [[[2, 0], [5, 0]], [[2, 3], [5, 7]]] {
            for op in [-Felt::ONE, Felt::ZERO, Felt::ONE] {
                let row = eval_row(op, inputs);
                assert_accepts(&row);

                // A forged helper cannot choose another operation, even if the result is rebuilt.
                let mut forged = row.clone();
                *forged.ace_op_squared_mut() = Felt::ONE - op.square();
                recompute_arithmetic(&mut forged);
                assert_rejects(&forged);

                // Rebuilding the helper does not authorize a wrong result in either coordinate.
                for coordinate in 0..2 {
                    let mut forged = row.clone();
                    *forged.ace_op_squared_mut() = forged.ace().eval_op.square();
                    let result = &mut ace_cols(&mut forged).v_0;
                    if coordinate == 0 {
                        result.0 += Felt::ONE;
                    } else {
                        result.1 += Felt::ONE;
                    }
                    assert_rejects(&forged);
                }
            }
        }
    }

    #[test]
    fn ace_eval_rejects_nonternary_op_with_recomputed_helper_and_result() {
        let mut row = eval_row(Felt::ONE, [[2, 3], [5, 7]]);
        ace_cols(&mut row).eval_op = Felt::from_u8(2);
        *row.ace_op_squared_mut() = row.ace().eval_op.square();
        recompute_arithmetic(&mut row);
        assert_rejects(&row);
    }

    #[test]
    fn ace_square_constraint_leaves_read_and_other_family_payload_free() {
        let mut row = eval_row(Felt::from_u8(9), [[2, 3], [5, 7]]);
        {
            let cols = ace_cols(&mut row);
            cols.s_block = Felt::ZERO;
            cols.id_0 = Felt::ONE;
            cols.id_1 = Felt::ZERO;
        }
        *row.ace_op_squared_mut() = Felt::from_u8(13);
        assert_accepts(&row);

        // The same physical cells belong to unrelated payloads outside the ACE band.
        row.chiplets[0] = Felt::ONE;
        ace_cols(&mut row).s_block = Felt::from_u8(17);
        assert_accepts(&row);
    }
}
