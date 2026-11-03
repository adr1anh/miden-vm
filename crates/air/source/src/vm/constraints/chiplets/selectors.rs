//! Packed section selectors for Library, Controller, AEAD, Memory, ACE, Bitwise, and PAD.
//!
//! Only a section's preceding prefix constrains its selector: later selector cells are payload
//! on earlier rows. Physical transitions are noncyclic; the lookup edge from PAD to Library is
//! excluded by the transition filter.

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;

use crate::vm::{ChipletCols, MidenAirBuilder, constraints::utils::BoolNot};

/// Precomputed flags for a single chiplet.
#[derive(Clone)]
pub struct ChipletFlags<E> {
    pub is_active: E,
    pub is_transition: E,
    pub is_last: E,
    /// Current row immediately precedes this section's first row.
    pub next_is_first: E,
}

/// MAIN scopes. AEAD and normal Bitwise have independent sections.
#[derive(Clone)]
pub struct ChipletSelectors<E> {
    pub library: E,
    pub controller: ChipletFlags<E>,
    pub aead_stream: ChipletFlags<E>,
    pub memory: ChipletFlags<E>,
    pub ace: ChipletFlags<E>,
    pub bitwise: ChipletFlags<E>,
}

/// Enforces the selected prefix-gated Boolean and one-way section rules.
pub fn build_chiplet_selectors<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
) -> ChipletSelectors<AB::Expr>
where
    AB: MidenAirBuilder,
{
    let [library, controller, aead, memory, ace, bitwise]: [AB::Expr; 6] =
        local.chiplet_selectors().map(Into::into);
    let [library_next, controller_next, aead_next, memory_next, ace_next, bitwise_next]: [AB::Expr;
        6] = next.chiplet_selectors().map(Into::into);
    let transition = builder.is_transition();

    let after_library = library.not();
    let after_controller = after_library.clone() * controller.not();
    let remaining = after_controller.clone() * aead.not();
    let after_memory = remaining.clone() * memory.clone();
    let after_ace = after_memory.clone() * ace.clone();
    let pad = after_ace.clone() * bitwise.clone();

    builder.assert_bool(library.clone());
    builder.when(after_library.clone()).assert_bool(controller.clone());
    builder.when(after_controller.clone()).assert_bool(aead.clone());
    builder.when(remaining.clone()).assert_bool(memory.clone());
    builder.when(after_memory.clone()).assert_bool(ace.clone());
    builder.when(after_ace.clone()).assert_bool(bitwise.clone());

    {
        let builder = &mut builder.when_transition();
        // Library/C/A move from one to zero; m/a/b move from zero to one.
        builder.when(after_library.clone()).assert_zero(library_next.clone());
        builder.when(after_controller.clone()).assert_zero(controller_next.clone());
        builder.when(remaining.clone()).assert_zero(aead_next.clone());
        builder.when(after_memory.clone()).assert_one(memory_next.clone());
        builder.when(after_ace.clone()).assert_one(ace_next.clone());
        builder.when(pad.clone()).assert_one(bitwise_next.clone());
    }
    {
        let builder = &mut builder.when_last_row();
        builder.assert_zero(library.clone());
        builder.assert_zero(controller.clone());
        builder.assert_zero(aead.clone());
        builder.assert_one(memory.clone());
        builder.assert_one(ace.clone());
        builder.assert_one(bitwise.clone());
    }

    let q_controller = after_library * controller;
    let q_aead = after_controller * aead;
    let q_memory = remaining.clone() * memory.not();
    let q_ace = after_memory.clone() * ace.not();
    let q_bitwise = after_ace.clone() * bitwise.not();
    let library_exit = transition.clone() * library.clone() * library_next.not();
    // Library is nonempty and can exit only into Controller. Library MAIN separately requires
    // PAD B at this boundary and enforces its eight-row alignment.
    builder.when(library_exit.clone()).assert_one(controller_next.clone());

    let controller_last = transition.clone() * q_controller.clone() * controller_next.not();
    let aead_last = transition.clone() * q_aead.clone() * aead_next.not();
    let controller_leave = q_controller.clone() * controller_next.not() * aead_next.not();
    let earlier_leave = controller_leave + q_aead.clone() * aead_next.not();
    let not_library_next = library_next.not();
    let first_memory =
        transition.clone() * not_library_next.clone() * earlier_leave.clone() * memory_next.not();
    let first_ace = transition.clone()
        * not_library_next.clone()
        * (earlier_leave + q_memory.clone())
        * memory_next.clone()
        * ace_next.not();

    // Canonical unused cells. Section overlays own every other shared payload cell.
    builder.when(q_ace.clone()).assert_zero(local.chiplets[22]);
    {
        let builder = &mut builder.when(q_bitwise.clone());
        for &cell in &local.chiplets[19..23] {
            builder.assert_zero(cell);
        }
    }
    {
        let builder = &mut builder.when(pad);
        for &cell in &local.chiplets[6..23] {
            builder.assert_zero(cell);
        }
    }

    ChipletSelectors {
        library,
        controller: ChipletFlags {
            is_active: q_controller.clone(),
            is_transition: transition.clone() * q_controller * controller_next,
            is_last: controller_last.clone(),
            next_is_first: library_exit,
        },
        aead_stream: ChipletFlags {
            is_active: q_aead.clone(),
            is_transition: transition.clone() * q_aead * aead_next.clone(),
            is_last: aead_last,
            next_is_first: controller_last * aead_next,
        },
        memory: ChipletFlags {
            is_active: q_memory.clone(),
            // Do not replace these reduced prefix gates with current*next active products.
            is_transition: transition.clone()
                * remaining
                * not_library_next.clone()
                * memory_next.not(),
            is_last: transition.clone() * q_memory * memory_next,
            next_is_first: first_memory,
        },
        ace: ChipletFlags {
            is_active: q_ace.clone(),
            is_transition: transition.clone()
                * after_memory
                * not_library_next.clone()
                * ace_next.not(),
            is_last: transition.clone() * q_ace * ace_next,
            next_is_first: first_ace,
        },
        bitwise: ChipletFlags {
            is_active: q_bitwise.clone(),
            is_transition: transition.clone() * after_ace * not_library_next * bitwise_next.not(),
            is_last: transition * q_bitwise * bitwise_next,
            // Normal Bitwise rows have no section-entry initialization.
            next_is_first: AB::Expr::ZERO,
        },
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };

    use super::*;
    use crate::vm::{
        constraints::stack::test_utils::ConstraintEvalBuilder, trace::CHIPLETS_DATA_WIDTH,
    };

    fn row(prefix: &[u64]) -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        };
        for (cell, value) in row.chiplets.iter_mut().zip(prefix) {
            *cell = Felt::from_u64(*value);
        }
        row
    }

    fn accepts(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>) -> bool {
        let mut builder = ConstraintEvalBuilder::new();
        build_chiplet_selectors(&mut builder, local, next);
        builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO)
    }

    #[test]
    fn packed_selectors_reject_each_physical_section_reentry() {
        let sections = [
            row(&[1]),
            row(&[0, 1]),
            row(&[0, 0, 1]),
            row(&[0, 0, 0, 0]),
            row(&[0, 0, 0, 1, 0]),
            row(&[0, 0, 0, 1, 1, 0]),
            row(&[0, 0, 0, 1, 1, 1]),
        ];
        for pair in sections.windows(2) {
            assert!(accepts(&pair[0], &pair[1]));
            assert!(!accepts(&pair[1], &pair[0]));
        }
        assert!(!accepts(&sections[0], &sections[2]), "Library must exit into Controller");
        for (index, prefix) in [
            &[2][..],
            &[0, 2][..],
            &[0, 0, 2][..],
            &[0, 0, 0, 2][..],
            &[0, 0, 0, 1, 2][..],
            &[0, 0, 0, 1, 1, 2][..],
        ]
        .into_iter()
        .enumerate()
        {
            let malformed = row(prefix);
            assert!(!accepts(&malformed, &malformed), "selector {index} must be Boolean");
        }
    }

    #[test]
    fn final_pad_filters_the_cyclic_library_edge() {
        let pad = row(&[0, 0, 0, 1, 1, 1]);
        let library = row(&[1]);
        let mut builder = ConstraintEvalBuilder::new().with_row_flags(false, true, false);
        build_chiplet_selectors(&mut builder, &pad, &library);
        assert!(builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO));
        for invalid_final in [row(&[1]), row(&[0, 1]), row(&[0, 0, 0, 1, 1, 0])] {
            let mut builder = ConstraintEvalBuilder::new().with_row_flags(false, true, false);
            build_chiplet_selectors(&mut builder, &invalid_final, &library);
            assert!(builder.evaluations.iter().any(|value| *value != QuadFelt::ZERO));
        }
    }

    #[test]
    fn first_memory_and_ace_cover_empty_intermediate_sections() {
        let controller = row(&[0, 1]);
        let aead = row(&[0, 0, 1]);
        let memory = row(&[0, 0, 0, 0]);
        let ace = row(&[0, 0, 0, 1, 0]);
        for predecessor in [&controller, &aead] {
            let mut builder = ConstraintEvalBuilder::new();
            let flags = build_chiplet_selectors(&mut builder, predecessor, &memory);
            assert_eq!(flags.memory.next_is_first, Felt::ONE);
        }
        for predecessor in [&controller, &aead, &memory] {
            let mut builder = ConstraintEvalBuilder::new();
            let flags = build_chiplet_selectors(&mut builder, predecessor, &ace);
            assert_eq!(flags.ace.next_is_first, Felt::ONE);
        }
        let mut builder = ConstraintEvalBuilder::new();
        let flags = build_chiplet_selectors(&mut builder, &ace, &ace);
        assert_eq!(flags.ace.next_is_first, Felt::ZERO);
        assert_eq!(flags.memory.next_is_first, Felt::ZERO);
    }
}
