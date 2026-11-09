//! Library MAIN equations for the packed Chiplets prefix.

use miden_core::{
    field::PrimeCharacteristicRing,
    program::{Namespace, domain},
};
use miden_stark::air::AirBuilder;

use super::{
    LibraryKindFlags, LibraryPhaseFlags, LibraryRowContext, columns::LibraryCols, sigma_hi,
    sigma_validity,
};
use crate::{
    shared::eidos::framing::initial_cv_from_frame,
    vm::{MidenAirBuilder, trace::chiplets::library::namespace_difference_norms},
};

/// Enforces the complete local Library relation with explicit section and periodic inputs.
///
/// Hashing and rooted authorization are supplied by the paired Library lookup entry point. This
/// function constrains routing, complete reverse Lists, prefix boundaries, and whether each Mast
/// supplier belongs to the initial namespace.
pub fn enforce_library_constraints<AB: MidenAirBuilder>(
    builder: &mut AB,
    local: &LibraryCols<AB::Var>,
    next: &LibraryCols<AB::Var>,
    context: &LibraryRowContext<AB::Expr>,
) {
    let kinds = LibraryKindFlags::<AB::Expr>::new(local);
    let next_kinds = LibraryKindFlags::<AB::Expr>::new(next);
    let phases = LibraryPhaseFlags::new(context.is_active.clone(), context.phase.clone());
    let list = kinds.is_list_start.clone() + kinds.is_list_continue.clone();
    let mast = kinds.is_mast.clone() + kinds.is_root_mast.clone();
    let transition = builder.is_transition();

    // Library occupies a nonempty proper prefix and complete A/B pairs. Scope is Boolean even
    // outside the prefix; no cyclic last-to-first transition can reactivate it.
    builder.assert_bool(context.is_active.clone());
    builder.when_first_row().assert_one(context.is_active.clone());
    builder.when_first_row().assert_zero(context.phase.clone());
    builder.when_last_row().assert_zero(context.is_active.clone());
    builder
        .when_transition()
        .assert_zero(context.next_is_active.clone() * (AB::Expr::ONE - context.is_active.clone()));
    builder
        .when_transition()
        .when(phases.phase_a.clone())
        .assert_one(context.next_is_active.clone());
    {
        let builder = &mut builder.when(context.is_active.clone());
        for bit in local.k {
            builder.assert_bool(bit);
        }
    }
    builder.when_first_row().assert_zero(kinds.is_list_continue.clone());
    {
        let builder = &mut builder.when(transition.clone() * phases.phase_a.clone());
        for (current, following) in local.k.into_iter().zip(next.k) {
            builder.assert_eq(current, following);
        }
        builder.assert_eq(local.d, next.d);
    }
    {
        // Exit is scoped once. Multiplying this gate by phase-seven again would raise the
        // degree of unrelated high-degree List equations without strengthening their scope.
        let exit = context.is_active.clone() - context.next_is_active.clone();
        let builder = &mut builder.when(transition.clone() * exit);
        builder.assert_one(context.phase.clone());
        builder.assert_one(kinds.is_pad.clone());
        builder.assert_one(context.exit_aligned.clone());
    }
    {
        // At the exit the next row belongs to Controller and is not a Library payload.
        let pad_step = phases.kind_b(kinds.is_pad.clone()) * context.next_is_active.clone();
        builder.when_transition().when(pad_step).assert_one(next_kinds.is_pad.clone());
        let builder = &mut builder.when(context.is_active.clone() * kinds.is_pad.clone());
        for word in [local.x, local.y, local.z, local.w] {
            for value in word {
                builder.assert_zero(value);
            }
        }
        builder.assert_zero(local.d);
        builder.assert_zero(local.a);
        builder.assert_zero(local.b);
    }

    let zero_scalars = kinds.is_merkle.clone() + kinds.is_env.clone() + kinds.is_root_mast.clone();
    {
        let builder = &mut builder.when(phases.kind_a(zero_scalars));
        builder.assert_zero(local.a);
        builder.assert_zero(local.b);
    }
    {
        // An ordinary Mast must have a nonzero namespace difference. The two degree-two norms
        // and their witness coefficients give degree eight under the Mast A selector.
        let [low, high] = namespace_difference_norms::<AB::Expr>(local.w.map(Into::into));
        builder
            .when(phases.kind_a(kinds.is_mast.clone()))
            .assert_one(low * local.a + high * local.b);
    }
    {
        let builder =
            &mut builder.when(transition.clone() * phases.kind_a(kinds.is_merkle.clone()));
        for i in 0..4 {
            builder.assert_eq(local.x[i], next.x[i]);
            builder.assert_eq(local.y[i], next.y[i]);
            builder.assert_eq(local.w[i], next.w[i]);
        }
    }
    {
        let builder = &mut builder.when(phases.kind_b(kinds.is_merkle.clone()));
        for value in local.z {
            builder.assert_zero(value);
        }
        builder.assert_zero(local.a);
        builder.assert_zero(sigma_validity::<AB::Expr>(local.b.into()));
    }
    {
        let builder =
            &mut builder.when(transition.clone() * phases.kind_a(kinds.is_env.clone() + mast));
        for i in 0..4 {
            builder.assert_eq(next.x[i], local.w[i]);
            builder.assert_eq(next.y[i], local.x[i]);
            builder.assert_eq(next.w[i], local.y[i]);
        }
    }
    {
        let builder = &mut builder.when(phases.kind_b(kinds.is_env.clone()));
        builder.assert_zero(local.a);
        builder.assert_zero(local.b);
    }
    builder.when(phases.kind_b(kinds.is_mast.clone())).assert_zero(local.b);
    {
        let builder = &mut builder.when(phases.kind_b(kinds.is_root_mast.clone()));
        let initial = Namespace::initial().into_word().into_elements();
        for (coordinate, authorized) in local.x.into_iter().zip(initial) {
            builder.assert_eq(coordinate, AB::Expr::from(authorized));
        }
    }

    // Every List pair copies its logical block and inherited namespace from A to B.
    {
        let list_or_empty = list.clone() + kinds.is_empty_list.clone();
        let builder = &mut builder.when(transition.clone() * phases.kind_a(list_or_empty));
        for i in 0..4 {
            builder.assert_eq(local.x[i], next.x[i]);
            builder.assert_eq(local.y[i], next.y[i]);
            builder.assert_eq(local.w[i], next.w[i]);
        }
        builder.assert_eq(local.a, next.a);
    }
    {
        let builder = &mut builder.when(phases.kind_a(kinds.is_list_start.clone()));
        builder.assert_bool(local.b);
        builder.assert_eq(local.a, AB::Expr::from_u8(8) - local.b * AB::Expr::from_u8(4));
        for value in local.y {
            builder.assert_zero(local.b * value);
        }
        builder
            .when_transition()
            .assert_zero(local.b * sigma_hi::<AB::Expr>(next.b.into()));
    }
    builder.when(phases.kind_a(kinds.is_list_continue.clone())).assert_zero(local.b);
    builder
        .when(phases.kind_b(list.clone()))
        .assert_zero(sigma_validity::<AB::Expr>(local.b.into()));

    // A continuation may only follow a nonempty List B. The next scope avoids reading Controller
    // kind bits at the PAD exit. Monotone scope already implies current Library on this transition.
    builder.when_transition().assert_zero(
        context.next_is_active.clone()
            * context.phase.clone()
            * next_kinds.is_list_continue.clone()
            * (AB::Expr::ONE - list.clone()),
    );
    {
        // Only current scope is needed here: an active List pair cannot cross the PAD-only exit.
        // This keeps the two cubic kind selectors plus routing equation at degree nine.
        let continuing = phases.kind_b(list.clone()) * next_kinds.is_list_continue.clone();
        let builder = &mut builder.when(transition.clone() * continuing);
        for i in 0..4 {
            builder.assert_eq(next.z[i], local.z[i]);
            builder.assert_eq(next.w[i], local.w[i]);
        }
        builder.assert_eq(next.d, local.d);
        builder.assert_eq(next.a, local.a.into() + AB::Expr::from_u8(8));
        builder.assert_zero(next.b);
    }
    {
        let terminal = phases.kind_b(list) * (AB::Expr::ONE - next_kinds.is_list_continue);
        let initial = initial_cv_from_frame([
            AB::Expr::from(domain::domain_tag(domain::ENV_LIST)),
            local.a.into(),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ]);
        let builder = &mut builder.when(transition * terminal);
        for (actual, expected) in local.z.into_iter().zip(initial) {
            builder.assert_eq(actual, expected);
        }
    }
    {
        let builder = &mut builder.when(context.is_active.clone() * kinds.is_empty_list.clone());
        for value in local.x.into_iter().chain(local.y) {
            builder.assert_zero(value);
        }
        builder.assert_zero(local.a);
        builder.assert_zero(local.b);
    }
    {
        let initial = initial_cv_from_frame([
            AB::Expr::from(domain::domain_tag(domain::ENV_LIST)),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ]);
        let builder = &mut builder.when(phases.kind_b(kinds.is_empty_list));
        for (actual, expected) in local.z.into_iter().zip(initial) {
            builder.assert_eq(actual, expected);
        }
    }
}
