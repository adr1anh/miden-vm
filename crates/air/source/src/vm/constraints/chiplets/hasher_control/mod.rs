//! Controller sub-chiplet constraints.
//!
//! The controller records one Eidos compression request per row. Hash rows carry
//! `block[8] || cv_in[4]` in `state` and `cv_out[4]` in `row_data`. Merkle rows carry
//! `block[8] || cv_out[4]` in `state` and `[node_index, node_index_next, is_start, level]`
//! in `row_data`.

pub mod flags;

use flags::ControllerFlags;
use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;

use crate::vm::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletFlags},
        utils::BoolNot,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforces controller row validity, operation sequencing, and hash/Merkle routing.
///
/// Merkle level increments are enforced by [`enforce_merkle_level_constraints`].
pub fn enforce_controller_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    chiplet: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols: &ControllerCols<AB::Var> = local.controller();
    let cols_next: &ControllerCols<AB::Var> = next.controller();
    let rows = ControllerFlags::<AB::Expr>::new(cols);

    let merkle_start: AB::Expr = cols.merkle_is_start().into();
    let merkle_start_next: AB::Expr = cols_next.merkle_is_start().into();
    let op_final: AB::Expr = local.controller_op_final().into();
    let controller_next: AB::Expr = (AB::Expr::ONE - next.chiplets[0].into()) * next.chiplets[1];
    let merkle_or_padding = cols.merkle_or_padding::<AB::Expr>();
    let controller_s0: AB::Expr = cols.s0.into();

    let controller_padding =
        chiplet.is_active.clone() * merkle_or_padding.clone() * controller_s0.not();
    let controller_merkle = chiplet.is_active.clone() * merkle_or_padding.clone() * controller_s0;

    // The first Controller follows the terminal Library PAD B row. Its complete operation
    // initialization belongs to that boundary, rather than to global trace row zero.
    {
        let builder = &mut builder.when(chiplet.next_is_first.clone());
        builder.assert_one(controller_next.clone());
        builder.assert_one(cols_next.s0);
        builder.assert_zero(cols_next.merkle_or_padding::<AB::Expr>() * merkle_start_next.not());
        let first_mv_row =
            Into::<AB::Expr>::into(cols_next.s1) * Into::<AB::Expr>::into(cols_next.s2).not();
        builder.assert_eq(next.controller_mrupdate_id(), first_mv_row);
        builder
            .when(cols_next.merkle_or_padding::<AB::Expr>())
            .assert_zero(cols_next.merkle_level());
    }

    builder
        .when(chiplet.is_active.clone())
        .assert_bools([cols.s0, cols.s1, cols.s2]);
    builder.when(chiplet.is_active.clone()).assert_bool(op_final.clone());
    builder.when(chiplet.is_active.clone()).assert_zero(rows.is_invalid.clone());

    // Padding rows stay padding until the controller section ends.
    {
        let gate = controller_padding.clone() * controller_next.clone();
        let builder = &mut builder.when(gate);
        builder.assert_zero(cols_next.s0);
        builder.assert_one(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }

    // Padding rows carry only the MRUPDATE id.
    {
        let builder = &mut builder.when(controller_padding);
        builder.assert_zeros(cols.state);
        builder.assert_zeros(cols.row_data);
        builder.assert_zero(local.controller_op_final());
    }

    // The controller-local MRUPDATE id increments exactly when the next row starts an MV leg.
    {
        let mrupdate_id: AB::Expr = local.controller_mrupdate_id().into();
        let s1_next: AB::Expr = cols_next.s1.into();
        let s2_next: AB::Expr = cols_next.s2.into();
        let mv_start_next = s1_next * s2_next.not() * merkle_start_next.clone();
        let ctrl_pair = chiplet.is_active.clone() * controller_next.clone();
        builder
            .when(ctrl_pair)
            .assert_eq(next.controller_mrupdate_id(), mrupdate_id + mv_start_next);
    }

    // Operation sequencing.
    {
        let gate = chiplet.is_active.clone() * rows.is_hash.clone() * op_final.not();
        let builder = &mut builder.when(gate);
        builder.assert_one(controller_next.clone());
        builder.assert_zero(cols_next.s0);
        builder.assert_zero(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }
    {
        let gate = controller_merkle.clone() * op_final.not();
        let builder = &mut builder.when(gate);
        builder.assert_one(controller_next.clone());
        builder.assert_one(cols_next.s0);
        builder.assert_eq(cols_next.s1, cols.s1);
        builder.assert_eq(cols_next.s2, cols.s2);
        builder.assert_zero(merkle_start_next.clone());
    }

    // Conversely, any continuation row must follow a non-final matching row.
    {
        let hash_absorb_next = Into::<AB::Expr>::into(cols_next.s0).not()
            * Into::<AB::Expr>::into(cols_next.s1).not()
            * Into::<AB::Expr>::into(cols_next.s2).not();
        let gate = controller_next.clone() * hash_absorb_next;
        let builder = &mut builder.when(gate);
        builder.assert_zero(op_final.clone());
        builder.assert_zero(cols.s1);
        builder.assert_zero(cols.s2);
    }
    {
        let merkle_cont_next = chiplet.is_active.clone()
            * controller_next
            * cols_next.merkle_or_padding::<AB::Expr>()
            * Into::<AB::Expr>::into(cols_next.s0)
            * merkle_start_next.not();
        let builder = &mut builder.when(merkle_cont_next);
        builder.assert_zero(op_final.clone());
        builder.assert_one(cols.s0);
        builder.assert_eq(cols.s1, cols_next.s1);
        builder.assert_eq(cols.s2, cols_next.s2);
    }

    // Hash continuation: the next hash row's input CV equals this row's output CV.
    {
        let gate = chiplet.is_active.clone() * rows.is_hash * op_final.not();
        let cv_next = cols_next.state_tail();
        let cv_out = cols.hash_cv();
        let builder = &mut builder.when(gate);
        for i in 0..4 {
            builder.assert_eq(cv_next[i], cv_out[i]);
        }
    }

    // Merkle rows.
    {
        let builder = &mut builder.when(controller_merkle.clone());

        builder.assert_bool(merkle_start.clone());
        builder.when(merkle_start).assert_zero(cols.merkle_level());

        let node_index: AB::Expr = cols.merkle_node_index().into();
        let node_index_next: AB::Expr = cols.merkle_node_index_next().into();
        let bit = node_index - node_index_next.double();
        builder.assert_bool(bit);
    }

    // Merkle continuation: carry the shifted index and route the digest into the selected block
    // word of the next row, using that row's virtual direction bit.
    {
        let merkle_cont = controller_merkle.clone() * op_final.not();
        let builder = &mut builder.when(merkle_cont);
        builder.assert_eq(cols_next.merkle_node_index(), cols.merkle_node_index_next());

        let node_index_next: AB::Expr = cols_next.merkle_node_index().into();
        let node_index_after_next: AB::Expr = cols_next.merkle_node_index_next().into();
        let bit_next = node_index_next - node_index_after_next.double();
        let digest = cols.merkle_digest();
        let block_lo_next = cols_next.block_lo();
        let block_hi_next = cols_next.block_hi();
        for j in 0..4 {
            builder.assert_eq(
                digest[j],
                block_lo_next[j] + bit_next.clone() * (block_hi_next[j] - block_lo_next[j]),
            );
        }
    }

    // Final Merkle row reaches the root, so its shifted index is zero.
    builder
        .when(controller_merkle)
        .when(op_final)
        .assert_zero(cols.merkle_node_index_next());
}

/// Enforces the Merkle path level increment between consecutive rows of a path.
///
/// [`enforce_controller_constraints`] requires level zero on the start row.
pub fn enforce_merkle_level_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    chiplet: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols: &ControllerCols<AB::Var> = local.controller();
    let cols_next: &ControllerCols<AB::Var> = next.controller();
    let op_final: AB::Expr = local.controller_op_final().into();
    let controller_merkle = chiplet.is_active.clone()
        * cols.merkle_or_padding::<AB::Expr>()
        * Into::<AB::Expr>::into(cols.s0);
    let level: AB::Expr = cols.merkle_level().into();

    builder
        .when(controller_merkle * op_final.not())
        .assert_eq(cols_next.merkle_level(), level + AB::Expr::ONE);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::mem::size_of;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
    use p3_matrix::dense::RowMajorMatrix;

    use crate::vm::{
        ChipletCols,
        constraints::chiplets::selectors::{ChipletFlags, build_chiplet_selectors},
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, CHIPLETS_DATA_WIDTH, CHIPLETS_WIDTH},
    };

    const S_CTRL_COL: usize = 1;
    const CTRL_BASE: usize = 2;
    const CTRL_SELECTOR_COUNT: usize = 3;
    const CTRL_STATE_WIDTH: usize = 12;
    const CTRL_STATE_BASE: usize = CTRL_BASE + CTRL_SELECTOR_COUNT;
    const CTRL_ROW_DATA_BASE: usize = CTRL_STATE_BASE + CTRL_STATE_WIDTH;
    const CTRL_OVERLAY_WIDTH: usize = size_of::<crate::vm::ControllerCols<u8>>();
    const OP_FINAL_COL: usize = CTRL_BASE + CTRL_OVERLAY_WIDTH;
    const MP_VERIFY_SELECTORS: [u64; 3] = [1, 0, 1];

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        preprocessed: RowWindow<'static, Felt>,
        evaluations: Vec<QuadFelt>,
    }

    impl ConstraintEvalBuilder {
        fn new() -> Self {
            Self {
                main: RowMajorMatrix::new(vec![Felt::ZERO; CHIPLETS_WIDTH * 2], CHIPLETS_WIDTH),
                aux: RowMajorMatrix::new(
                    vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2],
                    AUX_TRACE_WIDTH,
                ),
                randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
                permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
                periodic_values: Vec::new(),
                preprocessed: RowWindow::from_two_rows(&[], &[]),
                evaluations: Vec::new(),
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
            Felt::ZERO
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "controller tests use two-row transition windows");
            self.is_transition()
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(QuadFelt::from(x.into()));
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
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

    fn merkle_controller_row(
        selectors: [u64; 3],
        node_index: u64,
        is_start: bool,
        is_final: bool,
    ) -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        };
        row.chiplets[S_CTRL_COL] = Felt::ONE;
        row.chiplets[CTRL_BASE] = Felt::new_unchecked(selectors[0]);
        row.chiplets[CTRL_BASE + 1] = Felt::new_unchecked(selectors[1]);
        row.chiplets[CTRL_BASE + 2] = Felt::new_unchecked(selectors[2]);
        for i in 0..4 {
            row.chiplets[CTRL_STATE_BASE + 8 + i] = Felt::new_unchecked(10 + i as u64);
        }
        row.chiplets[CTRL_ROW_DATA_BASE] = Felt::new_unchecked(node_index);
        row.chiplets[CTRL_ROW_DATA_BASE + 1] = Felt::new_unchecked(node_index >> 1);
        row.chiplets[CTRL_ROW_DATA_BASE + 2] = if is_start { Felt::ONE } else { Felt::ZERO };
        row.chiplets[OP_FINAL_COL] = if is_final { Felt::ONE } else { Felt::ZERO };
        row
    }

    fn non_controller_row() -> ChipletCols<Felt> {
        ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        }
    }

    fn set_block_lo(row: &mut ChipletCols<Felt>, word: [Felt; 4]) {
        for (i, value) in word.into_iter().enumerate() {
            row.chiplets[CTRL_STATE_BASE + i] = value;
        }
    }

    fn merkle_digest(row: &ChipletCols<Felt>) -> [Felt; 4] {
        [
            row.chiplets[CTRL_STATE_BASE + 8],
            row.chiplets[CTRL_STATE_BASE + 9],
            row.chiplets[CTRL_STATE_BASE + 10],
            row.chiplets[CTRL_STATE_BASE + 11],
        ]
    }

    fn eval_controller_pair(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        let selectors = build_chiplet_selectors(&mut builder, local, next);
        super::enforce_controller_constraints(&mut builder, local, next, &selectors.controller);
        super::enforce_merkle_level_constraints(&mut builder, local, next, &selectors.controller);
        builder.evaluations
    }

    fn assert_accepts(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO), "{message}");
    }

    fn assert_rejects(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next);
        assert!(evaluations.iter().any(|value| *value != QuadFelt::ZERO), "{message}");
    }

    fn valid_merkle_continuation_pair() -> (ChipletCols<Felt>, ChipletCols<Felt>) {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 5, true, false);
        let mut next = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::ONE;
        set_block_lo(&mut next, merkle_digest(&local));
        (local, next)
    }

    #[test]
    fn controller_initialization_belongs_to_library_exit() {
        let mut library_pad = non_controller_row();
        library_pad.chiplets[0] = Felt::ONE;
        for selectors in [[1, 0, 0], [1, 0, 1], [1, 1, 0], [1, 1, 1]] {
            let is_merkle = selectors[1] != 0 || selectors[2] != 0;
            let mut first = merkle_controller_row(selectors, 0, is_merkle, true);
            first.chiplets[22] = Felt::from_bool(selectors == [1, 1, 0]);
            assert_accepts(&library_pad, &first, "valid first operation after Library");

            let mut forged = first.clone();
            forged.chiplets[CTRL_BASE] = Felt::ZERO;
            assert_rejects(&library_pad, &forged, "first Controller must start an operation");
            let mut forged = first.clone();
            forged.chiplets[22] += Felt::ONE;
            assert_rejects(&library_pad, &forged, "first MRUPDATE id must be initialized");
            if is_merkle {
                let mut forged = first.clone();
                forged.chiplets[CTRL_ROW_DATA_BASE + 2] = Felt::ZERO;
                assert_rejects(&library_pad, &forged, "first Merkle row must start its path");
                let mut forged = first.clone();
                forged.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::ONE;
                assert_rejects(&library_pad, &forged, "first Merkle level must be zero");
            }
        }
    }

    #[test]
    fn merkle_controller_accepts_valid_index_route() {
        let (local, next) = valid_merkle_continuation_pair();
        assert_accepts(&local, &next, "valid Merkle continuation should satisfy constraints");
    }

    #[test]
    fn controller_constraints_ignore_other_chiplets_payload() {
        // Other chiplets can use every Controller overlay cell as arbitrary payload. Evaluate
        // only the Controller constraints, since each row family's selectors have their own AIR.
        let controller = ChipletFlags {
            is_active: Felt::ZERO,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        };
        for selectors in [[1, 0, 1], [1, 1, 0], [1, 1, 1], [2, 3, 4]] {
            let mut local = non_controller_row();
            let mut next = non_controller_row();
            for (i, cell) in local.chiplets.iter_mut().enumerate().skip(CTRL_BASE) {
                *cell = Felt::from_usize(7 + i);
            }
            for (i, cell) in next.chiplets.iter_mut().enumerate().skip(CTRL_BASE) {
                *cell = Felt::from_usize(37 + i);
            }
            for (i, selector) in selectors.into_iter().enumerate() {
                local.chiplets[CTRL_BASE + i] = Felt::new_unchecked(selector);
            }

            let mut builder = ConstraintEvalBuilder::new();
            super::enforce_controller_constraints(&mut builder, &local, &next, &controller);
            super::enforce_merkle_level_constraints(&mut builder, &local, &next, &controller);
            assert!(
                builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                "off-Controller payload must not activate Controller routing: {selectors:?}",
            );
        }
    }

    #[test]
    fn merkle_controller_scope_uses_semantic_active_flag() {
        // Isolate the Controller scope from the current physical selector encoding: an
        // overlaid row may have the same cells as a Merkle continuation while owned elsewhere.
        let controller = ChipletFlags {
            is_active: Felt::ZERO,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        };
        let mut local = merkle_controller_row(MP_VERIFY_SELECTORS, 17, false, false);
        let mut next = merkle_controller_row(MP_VERIFY_SELECTORS, 3, false, true);
        local.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::from_u8(23);
        local.chiplets[OP_FINAL_COL] = Felt::from_u8(7);
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::from_u8(41);

        let mut builder = ConstraintEvalBuilder::new();
        super::enforce_controller_constraints(&mut builder, &local, &next, &controller);
        super::enforce_merkle_level_constraints(&mut builder, &local, &next, &controller);
        assert!(
            builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "inactive Controller rows must not activate generic Merkle equations",
        );
    }

    #[test]
    fn controller_rejects_invalid_row_kinds() {
        for selectors in [[0, 0, 1], [0, 1, 1]] {
            // Zero payload also satisfies the padding equations, so the invalid-kind equation
            // is required to reject these otherwise inactive row kinds.
            let mut local = non_controller_row();
            local.chiplets[S_CTRL_COL] = Felt::ONE;
            for (i, selector) in selectors.into_iter().enumerate() {
                local.chiplets[CTRL_BASE + i] = Felt::new_unchecked(selector);
            }
            assert_rejects(&local, &non_controller_row(), "invalid Controller row kind");
        }
    }

    #[test]
    fn controller_rejects_nonboolean_row_kind_selectors() {
        for selector_col in CTRL_BASE..CTRL_BASE + CTRL_SELECTOR_COUNT {
            let mut local = merkle_controller_row([1, 0, 0], 0, false, true);
            local.chiplets[selector_col] = Felt::from_u8(2);
            assert_rejects(&local, &non_controller_row(), "Controller selectors must be Boolean");
        }
    }

    #[test]
    fn controller_padding_uses_derived_mode() {
        let mut local = non_controller_row();
        local.chiplets[S_CTRL_COL] = Felt::ONE;
        local.chiplets[CTRL_BASE + 1] = Felt::ONE;
        // The MRUPDATE id is independent of the derived row-kind mode.
        local.chiplets[22] = Felt::from_u8(17);
        assert_accepts(&local, &non_controller_row(), "derived padding mode should be accepted");

        local.chiplets[CTRL_STATE_BASE] = Felt::ONE;
        assert_rejects(&local, &non_controller_row(), "padding must still carry zero payload");
    }

    #[test]
    fn hash_controller_preserves_continuation_cv() {
        let mut local = merkle_controller_row([1, 0, 0], 0, false, false);
        let mut next = merkle_controller_row([0, 0, 0], 0, false, true);
        for i in 0..4 {
            let value = Felt::from_usize(21 + i);
            local.chiplets[CTRL_ROW_DATA_BASE + i] = value;
            next.chiplets[CTRL_STATE_BASE + 8 + i] = value;
        }
        assert_accepts(&local, &next, "hash continuation must accept the previous output CV");

        next.chiplets[CTRL_STATE_BASE + 8] += Felt::ONE;
        assert_rejects(&local, &next, "hash continuation must reject a forged input CV");
    }

    #[test]
    fn merkle_controller_rejects_nonboolean_start_and_final_flags() {
        for flag_col in [CTRL_ROW_DATA_BASE + 2, OP_FINAL_COL] {
            let local = merkle_controller_row(MP_VERIFY_SELECTORS, 1, true, true);
            assert_accepts(&local, &non_controller_row(), "single-row Merkle path is valid");
            let mut forged = local;
            forged.chiplets[flag_col] = Felt::from_u8(2);
            assert_rejects(&forged, &non_controller_row(), "Controller flags must be Boolean");
        }
    }

    #[test]
    fn merkle_controller_rejects_section_exit_before_final_row() {
        let (local, _) = valid_merkle_continuation_pair();
        assert_rejects(&local, &non_controller_row(), "non-final Merkle rows must continue");
    }

    #[test]
    fn merkle_controller_rejects_continuation_after_final_row() {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 1, true, true);
        let mut next = merkle_controller_row(MP_VERIFY_SELECTORS, 0, false, true);
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::ONE;
        set_block_lo(&mut next, merkle_digest(&local));
        assert_rejects(&local, &next, "a Merkle continuation must follow a non-final row");
    }

    #[test]
    fn merkle_controller_rejects_nonzero_level_on_start_row() {
        let (mut local, mut next) = valid_merkle_continuation_pair();
        // Keep the increment valid so only the start-level constraint can reject these rows.
        local.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::ONE;
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::new_unchecked(2);

        assert_rejects(&local, &next, "a Merkle start row must carry level zero");
    }

    #[test]
    fn merkle_controller_rejects_unincremented_level_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::ZERO;

        assert_rejects(
            &local,
            &next,
            "a Merkle continuation must carry the previous level plus one",
        );
    }

    #[test]
    fn merkle_controller_rejects_skipped_level_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_ROW_DATA_BASE + 3] = Felt::new_unchecked(2);

        assert_rejects(&local, &next, "a Merkle continuation must not skip a level");
    }

    #[test]
    fn merkle_controller_rejects_wrong_shifted_index_on_current_row() {
        let (mut local, next) = valid_merkle_continuation_pair();
        local.chiplets[CTRL_ROW_DATA_BASE + 1] += Felt::ONE;

        assert_rejects(&local, &next, "Merkle row must carry node_index_next = node_index >> 1");
    }

    #[test]
    fn merkle_controller_rejects_wrong_node_index_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_ROW_DATA_BASE] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must carry current node_index into the next row",
        );
    }

    #[test]
    fn merkle_controller_rejects_wrong_digest_route_to_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_STATE_BASE] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must route digest into the next selected block half",
        );
    }

    #[test]
    fn merkle_controller_rejects_nonzero_final_shifted_index() {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        let next = non_controller_row();

        assert_rejects(&local, &next, "final Merkle row must have shifted index zero");
    }
}
