//! Memory chiplet constraints.
//!
//! The memory chiplet provides linear read-write random access memory.
//! Memory is element-addressable with addresses in range [0, 2^32).
//!
//! ## Column Layout (within chiplet, offset by selectors)
//!
//! | Column      | Purpose                                          |
//! |-------------|--------------------------------------------------|
//! | is_read     | Read/write selector: 1=read, 0=write             |
//! | is_word     | Element/word access: 0=element, 1=word           |
//! | ctx         | Context ID                                       |
//! | word_addr   | Word address                                     |
//! | idx0, idx1  | Element index bits (0-3)                         |
//! | clk         | Clock cycle of operation                         |
//! | v0-v3       | Memory word values                               |
//! | d0, d1      | Lower/upper 16 bits of the active delta          |
//! | d_inv       | Inverse of the active delta (docs: column `t`)   |
//! | f_sca       | Same context/addr flag (`is_same_ctx_and_addr`)  |
//! | w0          | Lower 16 bits of word index (word_addr / 4)      |
//! | w1          | Upper 16 bits of word index (word_addr / 4)      |
//!
//! ## Address range checks
//!
//! The constraint `word_addr = 4 * (w0 + 2^16 * w1)` decomposes the word address
//! into 16-bit limbs. Combined with range checks on `w0`, `w1`, and `4 * w1` via
//! the wiring bus, this proves all memory addresses are valid 32-bit values.
//! The `4 * w1` check prevents Goldilocks field wraparound (P > 2^18).

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::vm::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        constants::{F_4, TWO_POW_16},
        utils::BoolNot,
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
///
/// The memory trace is ordered by (ctx, addr, clk). Consecutive rows are compared
/// via deltas to enforce monotonicity of this ordering. A select mechanism
/// using `ctx_changed` and the same-context/address flag determines which delta
/// is active: context change takes precedence over address change, which takes
/// precedence over clock change.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols = local.memory();
    let cols_next = next.memory();

    // ==========================================================================
    // ROW CONSTRAINTS (all rows)
    // ==========================================================================
    // Selectors and indices must be binary.
    {
        let builder = &mut builder.when(flags.is_active.clone());
        builder.assert_bool(cols.is_read);
        builder.assert_bool(cols.is_word);
        builder.assert_bool(cols.idx0);
        builder.assert_bool(cols.idx1);

        // Element-write helpers are shared-row witnesses, outside the compact memory payload.
        // They let initialization and value consistency select the write target at degree two.
        let [e0, e1] = local.memory_write_helpers();
        let is_element_write = (AB::Expr::ONE - cols.is_read) * (AB::Expr::ONE - cols.is_word);
        builder.assert_eq(e0, is_element_write.clone() * (AB::Expr::ONE - cols.idx0));
        builder.assert_eq(e1, is_element_write * cols.idx0);

        let word_addr_lo = local.memory_word_addr_lo();
        let word_addr_hi = local.memory_word_addr_hi();
        let word_addr = (word_addr_hi * TWO_POW_16 + word_addr_lo) * F_4;
        builder.assert_eq(cols.word_addr, word_addr);

        // For word access, idx bits must be zero (only element accesses use idx0/idx1).
        {
            let builder = &mut builder.when(cols.is_word);
            builder.assert_zero(cols.idx0);
            builder.assert_zero(cols.idx1);
        }
    }

    // not_written[i] = 1 when v'[i] is NOT being written and must be constrained.
    // Computed once, shared between first-row initialization and value consistency.
    let not_written = compute_not_written_flags::<AB>(next);

    // ==========================================================================
    // FIRST-ROW INITIALIZATION
    // ==========================================================================
    // On the first row of the memory section, every value that is not being written must be zero,
    // so that a read of a never-written cell returns zero. `next_is_first` marks the row before the
    // first memory row and is derived from the section boundary directly, so this holds whether the
    // memory section follows AEAD or, when AEAD is empty, follows the controller directly.
    // (See `next_is_memory_first` in `selectors.rs`.)
    {
        let builder = &mut builder.when(flags.next_is_first.clone());
        for (i, nw) in not_written.iter().enumerate() {
            builder.when(nw.clone()).assert_zero(cols_next.values[i]);
        }
    }

    // ==========================================================================
    // TRANSITION CONSTRAINTS (all rows except last)
    // ==========================================================================
    // Enforces: delta inverse, monotonicity, same-context/addr flag, read-only,
    // and value consistency.
    let builder = &mut builder.when(flags.is_transition.clone());

    // --- delta inverse ---
    // d_inv (docs: column `t`) is shared across all three delta levels (ctx, addr, clk).
    // The Booleanity and closure constraints below force d_inv to the correct value
    // when the context or address changes.
    let d_inv_next = cols_next.d_inv;

    // Context: prover sets d_inv = 1/ctx_delta → ctx_changed = 1.
    let ctx_delta = cols_next.ctx - cols.ctx;
    let ctx_changed = ctx_delta.clone() * d_inv_next;
    let same_ctx = ctx_changed.not();
    // ctx_changed must be boolean. When ctx_delta ≠ 0, this forces ctx_changed ∈ {0, 1}.
    // If ctx_changed were 0 (same_ctx = 1), the assert_zero(ctx_delta) below would
    // require ctx_delta = 0 — contradiction. So ctx_changed = 1, forcing d_inv = 1/ctx_delta.
    builder.assert_bool(ctx_changed.clone());

    // Address: prover sets d_inv = 1/addr_delta → addr_changed = 1.
    // Only meaningful when same_ctx = 1; when context changes, addr_changed =
    // addr_delta/ctx_delta which is unconstrained, but always gated by same_ctx.
    let addr_delta = cols_next.word_addr - cols.word_addr;
    let addr_changed = addr_delta.clone() * d_inv_next;
    let same_addr = addr_changed.not();

    // Completes the ctx_changed enforcement: unchanged context requires ctx_delta = 0.
    builder.when(same_ctx.clone()).assert_zero(ctx_delta.clone());

    // --- same context/addr flag ---
    // f_sca' = 1 when both context and word address are unchanged between rows.
    // Stored in a dedicated column for degree reduction (same_ctx * same_addr is
    // degree 4; the column lets downstream constraints use it at degree 1).
    // Not constrained in the first row (intentional — first-row constraints use
    // not_written flags directly, not f_sca).
    let same_ctx_and_addr = cols_next.is_same_ctx_and_addr;
    // When same_ctx = 1, f_sca' = 1 - addr_changed, so Booleanity and closure of
    // f_sca' are equivalent to the conditional address inverse constraints.
    // When same_ctx = 0, f_sca' = 0 and addr_changed may be non-Boolean.
    builder.assert_bool(same_ctx_and_addr);
    builder.when(same_ctx_and_addr).assert_zero(addr_delta.clone());
    builder.assert_eq(same_ctx_and_addr, same_ctx.clone() * same_addr.clone());

    // --- monotonicity ---
    // The priority-selected delta must equal the range-checked decomposition.
    // d0, d1 are range-checked 16-bit limbs, so delta_next >= 0. For ctx and addr,
    // delta = 0 would contradict the flag being 1, so those deltas are strictly
    // positive. For clk, delta = 0 is allowed (duplicate reads; see read-only).
    //   ctx changed  → ctx_delta
    //   addr changed → addr_delta  (reachable only when same context)
    //   neither      → clk_delta
    let clk_delta = cols_next.clk - cols.clk;
    let computed_delta = {
        let ctx_term = ctx_changed * ctx_delta;
        // The flag definition gives same_ctx - f_sca' = same_ctx * addr_changed.
        let addr_term = (same_ctx - same_ctx_and_addr) * addr_delta;
        let clk_term = same_ctx_and_addr * clk_delta.clone();
        ctx_term + addr_term + clk_term
    };
    let delta_next = cols_next.d1 * TWO_POW_16 + cols_next.d0;
    builder.assert_eq(computed_delta, delta_next);

    // --- read-only constraint ---
    // When context/addr are unchanged (f_sca'=1) and the clock doesn't advance,
    // both operations must be reads.
    //
    // clk_no_change = 1 - clk_delta * d_inv is used as a when() gate. Unlike the ctx
    // and addr levels, no constraint forces d_inv = 1/clk_delta. This is intentional:
    //   clk advances → prover must set d_inv = 1/clk_delta to get clk_no_change = 0,
    //     otherwise the gate stays active and blocks writes the prover needs.
    //   clk unchanged → clk_delta = 0, so clk_no_change = 1 regardless of d_inv.
    // One-sided safe: a wrong d_inv can only block writes, never enable them.
    {
        let clk_no_change = AB::Expr::ONE - clk_delta * d_inv_next;
        let is_write = cols.is_read.into().not();
        let is_write_next = cols_next.is_read.into().not();
        let any_write = is_write + is_write_next;

        builder.when(same_ctx_and_addr).when(clk_no_change).assert_zero(any_write);
    }

    // --- value consistency ---
    // Values not being written must follow the consistency rule:
    //   same context/addr (f_sca'=1): v'[i] = v[i]  (copy from previous row)
    //   new context/addr  (f_sca'=0): v'[i] = 0      (initialize to zero)
    // Combined: v'[i] = f_sca' * v[i]
    let values = cols.values;
    let values_next = cols_next.values;
    for (i, nw) in not_written.into_iter().enumerate() {
        builder.when(nw).assert_eq(values_next[i], same_ctx_and_addr * values[i]);
    }
}

// INTERNAL HELPERS
// ================================================================================================

/// Compute "not written" flags for each of the 4 word elements.
///
/// Returns `not_written[i]`: 1 when `v[i]` is NOT the write target (must be constrained),
/// 0 when `v[i]` IS being written (unconstrained).
///
/// The three operation modes:
/// - **Read** (`is_read=1`): all flags = 1 (reads don't change any value)
/// - **Word write** (`is_word=1`): all flags = 0 (all 4 elements are written)
/// - **Element write** (`is_word=0, is_read=0`): flag = 0 for the selected element, 1 for the other
///   three
///
/// The row's bound helpers select the low index bit of an element write; multiplying by the
/// selected high index bit completes the one-hot selection. Each returned expression has degree
/// two: `not_written[i] = 1 - (1-is_read)*is_word - e_low*h_high`.
fn compute_not_written_flags<AB>(row: &ChipletCols<AB::Var>) -> [AB::Expr; 4]
where
    AB: MidenAirBuilder,
{
    let cols = row.memory();
    let is_word_write = (AB::Expr::ONE - cols.is_read) * cols.is_word;
    let [e0, e1] = row.memory_write_helpers();
    let idx1 = cols.idx1;
    let not_idx1 = AB::Expr::ONE - idx1;
    let element_writes = [e0 * not_idx1.clone(), e1 * not_idx1, e0 * idx1, e1 * idx1];

    element_writes.map(|element_write| AB::Expr::ONE - is_word_write.clone() - element_write)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::borrow::BorrowMut;

    use miden_core::{
        Felt,
        field::{Field, PrimeCharacteristicRing, QuadFelt},
    };
    use miden_stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
    use p3_matrix::dense::RowMajorMatrix;

    use super::{compute_not_written_flags, enforce_memory_constraints};
    use crate::vm::{
        ChipletCols, MemoryCols,
        constraints::chiplets::selectors::{ChipletFlags, build_chiplet_selectors},
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, CHIPLETS_DATA_WIDTH, TRACE_WIDTH},
    };

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
            assert_eq!(size, 2, "memory tests use two-row transition windows");
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

    fn memory_flags() -> ChipletFlags<Felt> {
        ChipletFlags {
            is_active: Felt::ONE,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        }
    }

    fn memory_row() -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chip_clk: Felt::ONE,
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
        };
        recompute_write_helpers(&mut row);
        row
    }

    fn memory_cols(row: &mut ChipletCols<Felt>) -> &mut MemoryCols<Felt> {
        row.chiplets[4..19].borrow_mut()
    }

    fn set_word_addr_limbs(row: &mut ChipletCols<Felt>, lo: u64, hi: u64) {
        row.chiplets[19] = Felt::new_unchecked(lo);
        row.chiplets[20] = Felt::new_unchecked(hi);
    }

    fn recompute_write_helpers(row: &mut ChipletCols<Felt>) {
        let cols = row.memory();
        let is_element_write = (Felt::ONE - cols.is_read) * (Felt::ONE - cols.is_word);
        let helpers = [is_element_write * (Felt::ONE - cols.idx0), is_element_write * cols.idx0];
        *row.memory_write_helpers_mut() = helpers;
    }

    fn eval_memory_window(
        local: &ChipletCols<Felt>,
        next: &ChipletCols<Felt>,
        flags: &ChipletFlags<Felt>,
    ) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        enforce_memory_constraints(&mut builder, local, next, flags);
        builder.evaluations
    }

    fn eval_memory_constraints(row: &ChipletCols<Felt>) -> Vec<QuadFelt> {
        let next = memory_row();
        eval_memory_window(row, &next, &memory_flags())
    }

    fn assert_constraints_accept(row: &ChipletCols<Felt>) {
        let evaluations = eval_memory_constraints(row);
        assert!(
            evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "expected all memory constraints to evaluate to zero; got {evaluations:?}",
        );
    }

    fn assert_constraints_reject(row: &ChipletCols<Felt>) {
        let evaluations = eval_memory_constraints(row);
        assert!(
            evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "expected at least one nonzero memory constraint evaluation",
        );
    }

    #[test]
    fn memory_constraints_bind_word_addr_to_range_checked_limbs() {
        let mut valid = memory_row();
        {
            let cols = memory_cols(&mut valid);
            cols.is_read = Felt::ONE;
            cols.is_word = Felt::ONE;
            cols.word_addr = Felt::new_unchecked(4 * (7 + (3 << 16)));
        }
        set_word_addr_limbs(&mut valid, 7, 3);
        recompute_write_helpers(&mut valid);
        assert_constraints_accept(&valid);

        let mut invalid = valid.clone();
        set_word_addr_limbs(&mut invalid, 0, 0);
        assert_constraints_reject(&invalid);
    }

    // SAME-CLOCK ACCESS TESTS
    // ============================================================================================

    #[derive(Clone, Copy, Debug)]
    enum AccessType {
        Read,
        Write,
    }

    impl AccessType {
        fn is_read(self) -> Felt {
            match self {
                Self::Read => Felt::ONE,
                Self::Write => Felt::ZERO,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum AccessSize {
        Element(u8),
        Word,
    }

    fn set_access_size(row: &mut ChipletCols<Felt>, size: AccessSize) {
        let cols = memory_cols(row);
        match size {
            AccessSize::Element(index) => {
                assert!(index < 4, "element index must be in the range 0..4");
                cols.is_word = Felt::ZERO;
                cols.idx0 = Felt::new_unchecked(u64::from(index & 1));
                cols.idx1 = Felt::new_unchecked(u64::from(index >> 1));
            },
            AccessSize::Word => {
                cols.is_word = Felt::ONE;
                cols.idx0 = Felt::ZERO;
                cols.idx1 = Felt::ZERO;
            },
        }
        recompute_write_helpers(row);
    }

    fn same_key_memory_rows(
        local_access: AccessType,
        next_access: AccessType,
    ) -> (ChipletCols<Felt>, ChipletCols<Felt>) {
        let mut local = memory_row();
        let mut next = memory_row();
        let values = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ];

        for (row, access) in [(&mut local, local_access), (&mut next, next_access)] {
            let cols = memory_cols(row);
            cols.is_read = access.is_read();
            cols.is_word = Felt::ONE;
            cols.word_addr = Felt::new_unchecked(4);
            cols.clk = Felt::new_unchecked(7);
            cols.values = values;
        }
        memory_cols(&mut next).is_same_ctx_and_addr = Felt::ONE;

        // word_addr = 4 * (w0 + 2^16 * w1), with (w0, w1) = (1, 0).
        set_word_addr_limbs(&mut local, 1, 0);
        set_word_addr_limbs(&mut next, 1, 0);
        recompute_write_helpers(&mut local);
        recompute_write_helpers(&mut next);

        (local, next)
    }

    fn eval_memory_transition(
        local: &ChipletCols<Felt>,
        next: &ChipletCols<Felt>,
    ) -> Vec<QuadFelt> {
        let flags = ChipletFlags {
            is_active: Felt::ONE,
            is_transition: Felt::ONE,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        };
        eval_memory_window(local, next, &flags)
    }

    fn all_access_sizes() -> [AccessSize; 5] {
        [
            AccessSize::Word,
            AccessSize::Element(0),
            AccessSize::Element(1),
            AccessSize::Element(2),
            AccessSize::Element(3),
        ]
    }

    fn is_written(access: AccessType, size: AccessSize, slot: usize) -> bool {
        matches!(access, AccessType::Write)
            && match size {
                AccessSize::Word => true,
                AccessSize::Element(index) => usize::from(index) == slot,
            }
    }

    /// Collects both the shared selector equations and Memory equations for every window. Each
    /// memory row must appear as a local row so its helpers are bound, including helpers first
    /// consumed by the preceding window's initialization or value-consistency constraints.
    fn eval_shared_memory_sequence(rows: &[&ChipletCols<Felt>]) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        for window in rows.windows(2) {
            let flags = build_chiplet_selectors(&mut builder, window[0], window[1]).memory;
            enforce_memory_constraints(&mut builder, window[0], window[1], &flags);
        }
        builder.evaluations
    }

    #[test]
    fn memory_write_helpers_coexist_with_shared_selector_constraints() {
        let controller = row_with_selectors([0, 1, 0, 0, 0, 0]);
        let pad = row_with_selectors([0, 0, 0, 1, 1, 1]);

        for access in [AccessType::Read, AccessType::Write] {
            for size in all_access_sizes() {
                let (mut first, mut next) = same_key_memory_rows(access, AccessType::Read);
                set_access_size(&mut first, size);
                memory_cols(&mut first).values = core::array::from_fn(|slot| {
                    if is_written(access, size, slot) {
                        Felt::new_unchecked(9)
                    } else {
                        Felt::ZERO
                    }
                });
                let values = first.memory().values;
                {
                    let cols = memory_cols(&mut next);
                    cols.values = values;
                    cols.clk += Felt::ONE;
                    cols.d0 = Felt::ONE;
                    cols.d_inv = Felt::ONE;
                }

                let expected_helpers = match (access, size) {
                    (AccessType::Write, AccessSize::Element(index)) => {
                        if index & 1 == 0 {
                            [Felt::ONE, Felt::ZERO]
                        } else {
                            [Felt::ZERO, Felt::ONE]
                        }
                    },
                    _ => [Felt::ZERO; 2],
                };
                assert_eq!(first.memory_write_helpers(), expected_helpers, "{access:?}/{size:?}");
                assert_eq!(first.chiplets[22], expected_helpers[1]);

                let evals = eval_shared_memory_sequence(&[&controller, &first, &next, &pad, &pad]);
                assert!(
                    evals.iter().all(|value| *value == QuadFelt::ZERO),
                    "shared selectors and Memory must accept {access:?}/{size:?}; got {evals:?}",
                );

                for helper in 0..2 {
                    let mut forged = first.clone();
                    let value = forged.memory_write_helpers()[helper];
                    forged.memory_write_helpers_mut()[helper] = Felt::ONE - value;
                    let evals =
                        eval_shared_memory_sequence(&[&controller, &forged, &next, &pad, &pad]);
                    assert!(
                        evals.iter().any(|value| *value != QuadFelt::ZERO),
                        "forged helper {helper} must reject {access:?}/{size:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn shared_selector_sequence_binds_helpers_consumed_by_memory_entry() {
        let controller = row_with_selectors([0, 1, 0, 0, 0, 0]);
        let pad = row_with_selectors([0, 0, 0, 1, 1, 1]);

        for helper in 0..2 {
            let mut forged = row_with_selectors([0, 0, 0, 0, 0, 0]);
            memory_cols(&mut forged).is_read = Felt::ONE;
            recompute_write_helpers(&mut forged);
            memory_cols(&mut forged).values[helper] = Felt::new_unchecked(42);
            forged.memory_write_helpers_mut()[helper] = Felt::ONE;

            // The forged Boolean helper masks the fresh read at entry. The production flags and
            // active equations on the next window must still reject its false helper binding.
            let entry_evals = eval_shared_memory_sequence(&[&controller, &forged]);
            assert!(entry_evals.iter().all(|value| *value == QuadFelt::ZERO));
            let evals = eval_shared_memory_sequence(&[&controller, &forged, &pad, &pad]);
            assert!(evals.iter().any(|value| *value != QuadFelt::ZERO));
        }
    }

    #[test]
    fn shared_memory_helpers_leave_earlier_section_payload_free() {
        for prefix in [&[1][..], &[0, 1][..], &[0, 0, 1][..]] {
            let mut row = row_with_selectors([0; 6]);
            row.chiplets.fill(Felt::from_u8(17));
            for (slot, value) in row.chiplets.iter_mut().zip(prefix) {
                *slot = Felt::new_unchecked(*value);
            }
            let mut builder = ConstraintEvalBuilder::new();
            let flags = build_chiplet_selectors(&mut builder, &row, &row);
            assert!(builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO));
            assert_eq!(flags.memory.is_active, Felt::ZERO);
        }
        for selectors in [[0, 0, 0, 1, 0, 0], [0, 0, 0, 1, 1, 0], [0, 0, 0, 1, 1, 1]] {
            let row = row_with_selectors(selectors);
            let evals = eval_shared_memory_sequence(&[&row, &row]);
            assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));
            let mut forged = row;
            forged.chiplets[22] = Felt::ONE;
            let evals = eval_shared_memory_sequence(&[&forged, &forged]);
            assert!(evals.iter().any(|value| *value != QuadFelt::ZERO));
        }
    }

    #[test]
    fn memory_write_helpers_bind_all_access_modes_and_element_slots() {
        for access in [AccessType::Read, AccessType::Write] {
            for size in all_access_sizes() {
                let mut row = memory_row();
                memory_cols(&mut row).is_read = access.is_read();
                set_access_size(&mut row, size);
                assert_constraints_accept(&row);

                let not_written = compute_not_written_flags::<ConstraintEvalBuilder>(&row);
                for (slot, flag) in not_written.into_iter().enumerate() {
                    let expected = if is_written(access, size, slot) {
                        Felt::ZERO
                    } else {
                        Felt::ONE
                    };
                    assert_eq!(flag, expected, "{access:?}/{size:?}, slot {slot}");
                }

                // Each helper is independently bound on the row that supplies the memory payload.
                for helper in 0..2 {
                    let mut forged = row.clone();
                    forged.memory_write_helpers_mut()[helper] += Felt::ONE;
                    assert_constraints_reject(&forged);
                    recompute_write_helpers(&mut forged);
                    assert_constraints_accept(&forged);
                }
            }
        }
    }

    #[test]
    fn memory_first_entry_preserves_zero_initialization_with_recomputed_helpers() {
        let previous = memory_row();
        let flags = ChipletFlags {
            is_active: Felt::ZERO,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ONE,
        };

        for access in [AccessType::Read, AccessType::Write] {
            for size in all_access_sizes() {
                let mut first = memory_row();
                memory_cols(&mut first).is_read = access.is_read();
                set_access_size(&mut first, size);
                for slot in 0..4 {
                    if is_written(access, size, slot) {
                        memory_cols(&mut first).values[slot] = Felt::new_unchecked(9);
                    }
                }
                assert_constraints_accept(&first);
                let evals = eval_memory_window(&previous, &first, &flags);
                assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));

                // Helper forgery is rejected by the first row's own active equations, even when
                // the predecessor's initialization equations accept a resulting zero mask.
                for helper in 0..2 {
                    let mut forged = first.clone();
                    forged.memory_write_helpers_mut()[helper] += Felt::ONE;
                    assert_constraints_reject(&forged);
                }

                for slot in 0..4 {
                    let mut forged = first.clone();
                    memory_cols(&mut forged).values[slot] += Felt::ONE;
                    recompute_write_helpers(&mut forged);
                    assert_constraints_accept(&forged);
                    let evals = eval_memory_window(&previous, &forged, &flags);
                    let accepts = evals.iter().all(|value| *value == QuadFelt::ZERO);
                    assert_eq!(
                        accepts,
                        is_written(access, size, slot),
                        "{access:?}/{size:?}, slot {slot}",
                    );
                }
            }
        }
    }

    #[test]
    fn memory_first_entry_cannot_use_forged_helpers_to_hide_fresh_read() {
        let previous = memory_row();
        let flags = ChipletFlags {
            is_active: Felt::ZERO,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ONE,
        };
        for helper in 0..2 {
            let mut first = memory_row();
            memory_cols(&mut first).is_read = Felt::ONE;
            recompute_write_helpers(&mut first);
            memory_cols(&mut first).values[helper] = Felt::new_unchecked(42);
            first.memory_write_helpers_mut()[helper] = Felt::ONE;

            // The forged helper hides the fresh read from the predecessor's initialization.
            let evals = eval_memory_window(&previous, &first, &flags);
            assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));
            // Its binding on the first memory row still rejects the complete row sequence.
            assert_constraints_reject(&first);
            recompute_write_helpers(&mut first);
            assert_constraints_accept(&first);
            let evals = eval_memory_window(&previous, &first, &flags);
            assert!(evals.iter().any(|value| *value != QuadFelt::ZERO));
        }
    }

    #[test]
    fn memory_transitions_preserve_untouched_slots_with_recomputed_helpers() {
        for access in [AccessType::Read, AccessType::Write] {
            for size in all_access_sizes() {
                let (local, mut next) = same_key_memory_rows(AccessType::Read, access);
                set_access_size(&mut next, size);
                {
                    let cols = memory_cols(&mut next);
                    cols.clk += Felt::ONE;
                    cols.d0 = Felt::ONE;
                    cols.d_inv = Felt::ONE;
                    for slot in 0..4 {
                        if is_written(access, size, slot) {
                            cols.values[slot] += Felt::new_unchecked(9);
                        }
                    }
                }
                assert_constraints_accept(&local);
                assert_constraints_accept(&next);
                let evals = eval_memory_transition(&local, &next);
                assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));

                for slot in 0..4 {
                    let mut forged = next.clone();
                    memory_cols(&mut forged).values[slot] += Felt::ONE;
                    recompute_write_helpers(&mut forged);
                    assert_constraints_accept(&forged);
                    let evals = eval_memory_transition(&local, &forged);
                    let accepts = evals.iter().all(|value| *value == QuadFelt::ZERO);
                    assert_eq!(
                        accepts,
                        is_written(access, size, slot),
                        "{access:?}/{size:?}, slot {slot}",
                    );
                }
            }
        }
    }

    #[test]
    fn memory_helpers_leave_unrelated_family_rows_unconstrained() {
        let mut local = memory_row();
        let mut next = memory_row();
        local.chiplets.fill(Felt::new_unchecked(2));
        next.chiplets.fill(Felt::new_unchecked(3));
        let flags = ChipletFlags {
            is_active: Felt::ZERO,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        };
        let evals = eval_memory_window(&local, &next, &flags);
        assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));
    }

    /// Reference polynomials from before the inverse/selected-delta refactor. The remaining
    /// constraints are unchanged; the equivalence fixtures below make all of them zero by using
    /// valid addresses and read-only zero-valued rows.
    fn legacy_inverse_and_delta_constraints(
        local: &ChipletCols<Felt>,
        next: &ChipletCols<Felt>,
    ) -> [Felt; 6] {
        let local = local.memory();
        let next = next.memory();
        let ctx_delta = next.ctx - local.ctx;
        let addr_delta = next.word_addr - local.word_addr;
        let clk_delta = next.clk - local.clk;
        let ctx_changed = ctx_delta * next.d_inv;
        let same_ctx = Felt::ONE - ctx_changed;
        let addr_changed = addr_delta * next.d_inv;
        let same_addr = Felt::ONE - addr_changed;
        let selected_delta = ctx_changed * ctx_delta
            + same_ctx * (addr_changed * addr_delta + same_addr * clk_delta);
        let decomposed_delta = next.d1 * Felt::new_unchecked(1 << 16) + next.d0;

        [
            ctx_changed * (ctx_changed - Felt::ONE),
            same_ctx * ctx_delta,
            same_ctx * addr_changed * (addr_changed - Felt::ONE),
            same_ctx * same_addr * addr_delta,
            next.is_same_ctx_and_addr - same_ctx * same_addr,
            selected_delta - decomposed_delta,
        ]
    }

    fn inverse_test_memory_rows(
        ctx_step: u64,
        next_word_addr: u64,
        clk_step: u64,
    ) -> (ChipletCols<Felt>, ChipletCols<Felt>) {
        assert_eq!(next_word_addr % 4, 0);
        let (mut local, mut next) = same_key_memory_rows(AccessType::Read, AccessType::Read);
        for row in [&mut local, &mut next] {
            let cols = memory_cols(row);
            cols.ctx = Felt::new_unchecked(3);
            cols.values = [Felt::ZERO; 4];
        }
        {
            let cols = memory_cols(&mut next);
            cols.ctx += Felt::new_unchecked(ctx_step);
            cols.word_addr = Felt::new_unchecked(next_word_addr);
            cols.clk += Felt::new_unchecked(clk_step);
        }
        set_word_addr_limbs(&mut next, next_word_addr / 4, 0);
        (local, next)
    }

    #[test]
    fn memory_inverse_refactor_preserves_old_zero_set_for_adversarial_assignments() {
        let two = Felt::new_unchecked(2);
        let four = Felt::new_unchecked(4);
        let eight = Felt::new_unchecked(8);
        let inverses = [
            Felt::ZERO,
            Felt::ONE,
            two,
            -Felt::ONE,
            two.inverse(),
            four.inverse(),
            eight.inverse(),
        ];

        for ctx_step in [0, 1, 2] {
            for next_word_addr in [0, 4, 8, 12] {
                for clk_step in [0, 1, 3] {
                    let (local, mut next) =
                        inverse_test_memory_rows(ctx_step, next_word_addr, clk_step);
                    let ctx_delta = next.memory().ctx - local.memory().ctx;
                    let addr_delta = next.memory().word_addr - local.memory().word_addr;
                    let clk_delta = next.memory().clk - local.memory().clk;

                    for d_inv in inverses {
                        let ctx_changed = ctx_delta * d_inv;
                        let same_ctx = Felt::ONE - ctx_changed;
                        let addr_changed = addr_delta * d_inv;
                        let same_addr = Felt::ONE - addr_changed;
                        let legacy_delta = ctx_changed * ctx_delta
                            + same_ctx * (addr_changed * addr_delta + same_addr * clk_delta);

                        // Include forged Boolean flags, non-Boolean flags, and the legacy flag
                        // expression even when a malicious inverse makes that expression invalid.
                        for flag in [Felt::ZERO, Felt::ONE, two, -Felt::ONE, same_ctx * same_addr] {
                            // An inverse/flag error must still reject when the claimed delta is
                            // chosen to satisfy the old monotonicity equation exactly.
                            for delta in [
                                Felt::ZERO,
                                ctx_delta,
                                addr_delta,
                                clk_delta,
                                legacy_delta,
                                legacy_delta + Felt::ONE,
                            ] {
                                let cols = memory_cols(&mut next);
                                cols.d_inv = d_inv;
                                cols.is_same_ctx_and_addr = flag;
                                cols.d0 = delta;

                                let legacy = legacy_inverse_and_delta_constraints(&local, &next);
                                let legacy_accepts =
                                    legacy.iter().all(|value| *value == Felt::ZERO);
                                let evaluations = eval_memory_transition(&local, &next);
                                let refactored_accepts =
                                    evaluations.iter().all(|value| *value == QuadFelt::ZERO);

                                // Independently describe the accepted relation by the first
                                // changed key. Clock-only reads deliberately allow any d_inv.
                                let should_accept = if ctx_delta != Felt::ZERO {
                                    ctx_delta * d_inv == Felt::ONE
                                        && flag == Felt::ZERO
                                        && delta == ctx_delta
                                } else if addr_delta != Felt::ZERO {
                                    addr_delta * d_inv == Felt::ONE
                                        && flag == Felt::ZERO
                                        && delta == addr_delta
                                } else {
                                    flag == Felt::ONE && delta == clk_delta
                                };
                                assert_eq!(
                                    legacy_accepts, should_accept,
                                    "legacy relation: ctx_delta={ctx_delta:?}, \
                                     addr_delta={addr_delta:?}, clk_delta={clk_delta:?}, \
                                     d_inv={d_inv:?}, flag={flag:?}, delta={delta:?}; \
                                     constraints={legacy:?}",
                                );
                                assert_eq!(
                                    refactored_accepts, legacy_accepts,
                                    "old/new zero sets differ: ctx_delta={ctx_delta:?}, \
                                     addr_delta={addr_delta:?}, clk_delta={clk_delta:?}, \
                                     d_inv={d_inv:?}, flag={flag:?}, delta={delta:?}; \
                                     constraints={evaluations:?}",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn changed_context_allows_non_boolean_address_change_ratio() {
        let (local, mut next) = inverse_test_memory_rows(2, 8, 3);
        let two = Felt::new_unchecked(2);
        {
            let cols = memory_cols(&mut next);
            cols.d_inv = two.inverse();
            cols.d0 = two;
            cols.is_same_ctx_and_addr = Felt::ZERO;
        }
        let addr_changed =
            (next.memory().word_addr - local.memory().word_addr) * next.memory().d_inv;
        assert_eq!(addr_changed, two);
        assert!(
            legacy_inverse_and_delta_constraints(&local, &next)
                .iter()
                .all(|value| *value == Felt::ZERO),
        );
        let evaluations = eval_memory_transition(&local, &next);
        assert!(
            evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "a context change must allow a non-Boolean address-change ratio; got {evaluations:?}",
        );
    }

    /// Ensures that repeating `(ctx, word_addr, clk)` is valid only when both accesses are reads.
    /// In particular, this prevents overlapping multi-memory operations such as `crypto_stream`
    /// from reading and writing the same word in one clock cycle.
    #[test]
    fn same_key_memory_rows_allow_only_reads() {
        for (local_access, next_access) in [
            (AccessType::Read, AccessType::Read),
            (AccessType::Read, AccessType::Write),
            (AccessType::Write, AccessType::Read),
            (AccessType::Write, AccessType::Write),
        ] {
            let (local, next) = same_key_memory_rows(local_access, next_access);
            let evaluations = eval_memory_transition(&local, &next);
            let accepted = evaluations.iter().all(|value| *value == QuadFelt::ZERO);
            let should_accept =
                matches!((local_access, next_access), (AccessType::Read, AccessType::Read));
            assert_eq!(
                accepted, should_accept,
                "unexpected result for {local_access:?}/{next_access:?}",
            );
        }
    }

    /// Repeating `(ctx, word_addr, clk)` is safe for any combination of read access sizes. This is
    /// required when operations such as ACE read multiple elements from the same word in one clock
    /// cycle.
    #[test]
    fn same_key_memory_rows_allow_all_read_access_sizes() {
        for (local_size, next_size) in [
            (AccessSize::Word, AccessSize::Word),
            (AccessSize::Word, AccessSize::Element(2)),
            (AccessSize::Element(1), AccessSize::Word),
            (AccessSize::Element(0), AccessSize::Element(1)),
        ] {
            let (mut local, mut next) = same_key_memory_rows(AccessType::Read, AccessType::Read);
            set_access_size(&mut local, local_size);
            set_access_size(&mut next, next_size);

            let evaluations = eval_memory_transition(&local, &next);
            assert!(
                evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                "same-clock {local_size:?}/{next_size:?} reads should be accepted; got \
                 {evaluations:?}",
            );
        }
    }

    /// Same-clock accesses at different word addresses may contain reads or writes. This covers the
    /// two distinct word accesses emitted by operations such as `mem_stream` and `adv_pipe`.
    #[test]
    fn same_clock_memory_rows_at_different_addresses_allow_reads_and_writes() {
        for (local_access, next_access) in [
            (AccessType::Read, AccessType::Read),
            (AccessType::Read, AccessType::Write),
            (AccessType::Write, AccessType::Read),
            (AccessType::Write, AccessType::Write),
        ] {
            let (local, mut next) = same_key_memory_rows(local_access, next_access);
            {
                let next = memory_cols(&mut next);
                next.word_addr = Felt::new_unchecked(8);
                next.values = [Felt::ZERO; 4];
                next.d0 = Felt::new_unchecked(4);
                next.d_inv = Felt::new_unchecked(4).inverse();
                next.is_same_ctx_and_addr = Felt::ZERO;
            }
            set_word_addr_limbs(&mut next, 2, 0);

            let evaluations = eval_memory_transition(&local, &next);
            assert!(
                evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                "same-clock accesses to different words should be accepted for \
                 {local_access:?}/{next_access:?}; got {evaluations:?}",
            );
        }
    }

    // EMPTY-SECTION BOUNDARY REGRESSION TESTS
    // ============================================================================================
    // Memory may directly follow Controller when AEAD is empty. Its first-row initialization
    // must fire on either preceding section, independent of Memory payload cells.

    fn row_with_selectors(selectors: [u64; 6]) -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chip_clk: Felt::ONE,
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
        };
        for (slot, value) in row.chiplets[..6].iter_mut().zip(selectors) {
            *slot = Felt::new_unchecked(value);
        }
        if selectors[..4] == [0, 0, 0, 0] {
            recompute_write_helpers(&mut row);
        }
        row
    }

    fn memory_flags_for_window(
        local: &ChipletCols<Felt>,
        next: &ChipletCols<Felt>,
    ) -> ChipletFlags<Felt> {
        let mut builder = ConstraintEvalBuilder::new();
        build_chiplet_selectors(&mut builder, local, next).memory
    }

    #[test]
    fn memory_first_row_init_enforced_with_or_without_aead() {
        for predecessor in [[0, 1, 0, 0, 0, 0], [0, 0, 1, 0, 0, 0]] {
            let previous = row_with_selectors(predecessor);
            let mut first_memory = row_with_selectors([0, 0, 0, 0, 0, 0]);
            memory_cols(&mut first_memory).is_read = Felt::ONE;
            recompute_write_helpers(&mut first_memory);
            let flags = memory_flags_for_window(&previous, &first_memory);
            assert_eq!(flags.next_is_first, Felt::ONE);

            let mut forged = first_memory.clone();
            memory_cols(&mut forged).values[0] = Felt::new_unchecked(42);
            let evals = eval_memory_window(&previous, &forged, &flags);
            assert!(evals.iter().any(|value| *value != QuadFelt::ZERO));
            let evals = eval_memory_window(&previous, &first_memory, &flags);
            assert!(evals.iter().all(|value| *value == QuadFelt::ZERO));
        }
    }

    #[test]
    fn memory_next_is_first_marks_only_the_entry_row() {
        let aead = row_with_selectors([0, 0, 1, 0, 0, 0]);
        let memory = row_with_selectors([0, 0, 0, 0, 0, 0]);
        assert_eq!(memory_flags_for_window(&aead, &memory).next_is_first, Felt::ONE);
        assert_eq!(memory_flags_for_window(&memory, &memory).next_is_first, Felt::ZERO);
        let ace = row_with_selectors([0, 0, 0, 1, 0, 0]);
        assert_eq!(memory_flags_for_window(&memory, &ace).next_is_first, Felt::ZERO);
    }
}
