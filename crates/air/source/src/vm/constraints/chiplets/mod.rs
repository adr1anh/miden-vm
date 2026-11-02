//! Chiplets trace constraints.
//!
//! This module enforces:
//! - chiplet selector constraints (including hasher internal selectors)
//! - Library authentication routing and public kernel-namespace constraints
//! - controller sub-chiplet main-trace constraints
//! - AEAD stream and normal bitwise main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//!
//! Eidos compression constraints are enforced by the separate
//! [`crate::vm::EidosCompressionAir`], with byte-table relations supplied by
//! [`crate::vm::And8LookupAir`].
//!
//! Chiplet LogUp lookup-argument constraints are emitted by
//! [`crate::vm::constraints::lookup::chiplet_air::emit_chiplet_lookup_columns`] and wired
//! through [`crate::vm::ChipletsAir`]'s `LookupAir` impl from `ChipletsAir::eval`.

pub mod ace;
pub mod aead_stream;
pub mod bitwise;
pub mod columns;
pub mod hasher_control;
pub mod library;
pub mod memory;
pub mod selectors;

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;
use selectors::ChipletSelectors;

use crate::vm::{ChipletCols, MidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
    kernel: &[AB::Expr; 4],
) where
    AB: MidenAirBuilder,
{
    // Selector constraints (including hasher internal selectors) are enforced in
    // build_chiplet_selectors (called by ChipletsAir).

    // Chiplet-trace row counter `chip_clk`: starts at 1 and increments by 1 each row.
    builder.when_first_row().assert_eq(local.chip_clk, AB::Expr::ONE);
    builder
        .when_transition()
        .assert_eq(next.chip_clk.into(), local.chip_clk.into() + AB::Expr::ONE);

    let periodic: &columns::PeriodicCols<_> = builder.periodic_values().borrow();
    let library_context = library::LibraryRowContext {
        is_active: selectors.library.clone(),
        next_is_active: next.chiplets[0].into(),
        phase: periodic.library_phase.into(),
        exit_aligned: periodic.aead_stream.phases[7].into(),
    };
    library::constraints::enforce_library_constraints(
        builder,
        local.library(),
        next.library(),
        &library_context,
        kernel,
    );

    // Hasher controller.
    hasher_control::enforce_controller_constraints(builder, local, next, &selectors.controller);

    aead_stream::enforce_aead_stream_constraints(builder, local, next, selectors);
    bitwise::enforce_bitwise_constraints(builder, local, next, selectors.bitwise.is_active.clone());
    memory::enforce_memory_constraints(builder, local, next, &selectors.memory);
    ace::enforce_ace_constraints_all_rows(builder, local, next, &selectors.ace);
    hasher_control::enforce_merkle_level_constraints(builder, local, next, &selectors.controller);
}
