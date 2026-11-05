//! Private comparison of the caller-frame tag in Core's first LogUp column.
//!
//! Only the cyclic recurrence changes; its auxiliary accumulator is centered under the same
//! corrected column-zero fractions. All other message coefficients, columns and constraints stay
//! production values. The guards identify the tag term independently in the captured polynomial.

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::{
    CoreCols,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};
use miden_core::{
    Felt,
    field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing},
    utils::{Matrix, RowMajorMatrix},
};
use miden_stark::{
    air::{LiftedAirBuilder, WindowAccess},
    lookup::{Challenges, LookupFractions, build_lookup_fractions},
};

use super::emission_adapter::eval_with_adjustments;

// After 264 base assertions, the first extension assertion anchors the accumulator. The next
// assertion is the cyclic recurrence for column zero. Guards pin both the class and equation.
const RECURRENCE: usize = 265;
const CORE_AUX_WIDTH: usize = 5;

fn caller_frame_flag<V: Copy, E: PrimeCharacteristicRing + Algebra<V>>(local: &CoreCols<V>) -> E {
    let bits = local.decoder.op_bits.map(Into::<E>::into);
    let call_sys = (E::ONE - bits[4].clone()) * bits[3].clone() * local.decoder.extra[1];
    let dyncall = ((bits[3].clone() * bits[2].clone())
        * (E::ONE - bits[1].clone())
        * (E::ONE - bits[0].clone()))
        * local.decoder.extra[0];
    let end = bits[4].clone()
        * ((E::ONE - bits[3].clone()) * (E::ONE - bits[2].clone()))
        * local.decoder.extra[1];
    call_sys + dyncall + end * local.decoder.end_block_flags().restores_caller_frame
}

fn correction<AB: LiftedAirBuilder<F = Felt>>(builder: &AB) -> AB::ExprEF {
    let main = builder.main();
    let local: &CoreCols<AB::Var> = (*main.current_slice()).borrow();
    let flag: AB::Expr = caller_frame_flag(local);
    let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
    let auxiliary = builder.permutation();
    assert_eq!(auxiliary.current_slice().len(), CORE_AUX_WIDTH);
    assert_eq!(builder.permutation_values().len(), 1);
    let sum = auxiliary
        .current_slice()
        .iter()
        .fold(AB::ExprEF::ZERO, |sum, &value| sum + Into::<AB::ExprEF>::into(value));
    let z = Into::<AB::ExprEF>::into(auxiliary.next_slice()[0]) - sum
        + Into::<AB::ExprEF>::into(builder.permutation_values()[0].clone());
    (beta.exp_u64(10) * flag) * z
}

pub(super) fn eval<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let delta = -correction(builder);
    eval_with_adjustments(MidenAir::CORE, builder, &[], &[(RECURRENCE, delta)]);
}

fn column_zero_totals<EF: ExtensionField<Felt>>(fractions: &LookupFractions<Felt, EF>) -> Vec<EF> {
    let mut cursor = 0;
    let mut totals = Vec::with_capacity(fractions.num_rows());
    for counts in fractions.counts().chunks_exact(fractions.num_columns()) {
        let sum = fractions.fractions()[cursor..cursor + counts[0]].iter().fold(
            EF::ZERO,
            |sum, &(multiplicity, denominator)| {
                sum + EF::from(multiplicity) * denominator.inverse()
            },
        );
        totals.push(sum);
        cursor += counts.iter().sum::<usize>();
    }
    assert_eq!(cursor, fractions.fractions().len());
    totals
}

/// Recenter only the first accumulator and its committed sum. Other four auxiliary columns are
/// copied unchanged. Masking coefficient ten is used solely to read this column's fractions:
/// its other messages have at most four payload coordinates, and only caller frames use slot10.
pub(super) fn adjust_aux<EF: ExtensionField<Felt>>(
    main: &RowMajorMatrix<Felt>,
    challenges: &[EF],
    mut aux: RowMajorMatrix<EF>,
    mut values: Vec<EF>,
) -> (RowMajorMatrix<EF>, Vec<EF>) {
    assert_eq!(aux.width(), CORE_AUX_WIDTH);
    assert_eq!(aux.height(), main.height());
    assert_eq!(values.len(), 1);
    let normal =
        Challenges::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let mut without_tag =
        Challenges::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    without_tag.beta_powers[10] = EF::ZERO;
    let original = build_lookup_fractions(&MidenAir::CORE, main, None, &[], &normal);
    let alternate = build_lookup_fractions(&MidenAir::CORE, main, None, &[], &without_tag);
    assert_eq!(original.counts(), alternate.counts());
    assert_eq!(original.shape(), alternate.shape());
    assert_eq!(original.num_columns(), CORE_AUX_WIDTH);
    // Check exactly which live row terms the coefficient mask changes before computing deltas.
    let mut cursor = 0;
    for (row, counts) in original.counts().as_chunks::<CORE_AUX_WIDTH>().0.iter().enumerate() {
        let local: &CoreCols<Felt> =
            main.values[row * main.width()..(row + 1) * main.width()].borrow();
        let flag: Felt = caller_frame_flag(local);
        assert!(flag == Felt::ZERO || flag == Felt::ONE);
        let before = &original.fractions()[cursor..cursor + counts[0]];
        let after = &alternate.fractions()[cursor..cursor + counts[0]];
        if flag == Felt::ZERO {
            assert_eq!(before, after, "non-frame column-zero terms must be unchanged");
        } else {
            assert_eq!(before.len(), 1);
            assert_eq!(before[0].0, after[0].0);
            assert_eq!(before[0].1 - after[0].1, normal.beta_powers[10]);
        }
        cursor += counts.iter().sum::<usize>();
    }
    let deltas: Vec<_> = column_zero_totals(&alternate)
        .into_iter()
        .zip(column_zero_totals(&original))
        .map(|(after, before)| after - before)
        .collect();
    let mean = deltas.iter().copied().sum::<EF>() * EF::from_usize(main.height()).inverse();
    let mut prefix = EF::ZERO;
    for (row, delta) in deltas.into_iter().enumerate() {
        aux.values[row * CORE_AUX_WIDTH] += prefix - EF::from_usize(row) * mean;
        prefix += delta;
    }
    values[0] += mean;
    (aux, values)
}

#[cfg(test)]
pub(super) fn assert_tag_policy_is_isolated(alternate: super::comparison_air::ComparisonAir) {
    use miden_constraint_compiler::{
        ir::{GraphBuilder, capture_into},
        testing::{EvaluationInputs, constraint_degrees, eval_graph},
    };
    use miden_core::field::QuadFelt;
    use miden_stark::air::LiftedAir;

    let mut graph = GraphBuilder::new();
    let production = capture_into(&MidenAir::CORE, &mut graph);
    let changed = capture_into(&alternate, &mut graph);
    let graph = graph.freeze();
    assert_eq!(production.base_roots, changed.base_roots);
    assert_eq!(production.base_global_indices, changed.base_global_indices);
    assert_eq!(production.ext_global_indices, changed.ext_global_indices);
    assert_eq!(production.ext_roots.len(), 6);
    assert_eq!(production.ext_global_indices[1], RECURRENCE);
    let changed_indices: Vec<_> = production
        .ext_roots
        .iter()
        .zip(&changed.ext_roots)
        .zip(&production.ext_global_indices)
        .filter_map(|((a, b), &index)| (a != b).then_some(index))
        .collect();
    assert_eq!(changed_indices, vec![RECURRENCE]);

    // Independently project beta^10 from the full production polynomial. Other column-zero
    // payloads have width<=4 and batch size<=4: their beta degrees are <=64. Only the entry-kind
    // tag occupies coefficient10. The power-of-two projection has no alias at those degrees.
    let degrees = beta_degrees(&graph);
    let root = production.ext_roots[1];
    let alt_root = changed.ext_roots[1];
    let samples =
        (MIDEN_MAX_MESSAGE_WIDTH * MidenAir::CORE.column_shape()[0] + 1).next_power_of_two();
    assert!(degrees[root.index()] < samples && degrees[alt_root.index()] < samples);
    assert_eq!((Felt::ORDER - 1) % samples as u64, 0);
    let omega = Felt::from_u64(7).exp_u64((Felt::ORDER - 1) / samples as u64);
    assert_eq!(omega.exp_u64(samples as u64), Felt::ONE);
    assert_ne!(omega.exp_u64((samples / 2) as u64), Felt::ONE);
    let weight_step = omega.exp_u64(10).inverse();
    for seed in [0, 1, 17, 31, 256, 65537, u32::MAX as u64, u64::MAX] {
        let defaults = eval_graph(&graph, seed);
        let beta = graph
            .iter()
            .find_map(|(id, node)| {
                matches!(
                    node,
                    miden_constraint_compiler::ir::Node::Leaf(
                        miden_constraint_compiler::ir::Leaf::Challenge(1)
                    )
                )
                .then_some(defaults[id.index()])
            })
            .unwrap();
        let inputs = EvaluationInputs::<Felt, QuadFelt>::new(
            <MidenAir as LiftedAir<Felt, QuadFelt>>::air_layout(&MidenAir::CORE),
            seed,
        );
        let expected = correction(&inputs.builder());
        let (mut projected, mut projected_alt) = (QuadFelt::ZERO, QuadFelt::ZERO);
        let (mut scale, mut weight) = (Felt::ONE, Felt::ONE);
        for _ in 0..samples {
            let evaluated = eval_with_beta(&graph, &defaults, beta * scale);
            projected += evaluated[root.index()] * weight;
            projected_alt += evaluated[alt_root.index()] * weight;
            scale *= omega;
            weight *= weight_step;
        }
        let inverse_n = QuadFelt::from_usize(samples).inverse();
        assert_eq!(projected * inverse_n, expected, "production tag coefficient: seed={seed}");
        assert_eq!(
            projected_alt * inverse_n,
            QuadFelt::ZERO,
            "only tag coefficient removed: seed={seed}"
        );
    }
    let before = constraint_degrees(&MidenAir::CORE);
    let after = constraint_degrees(&alternate);
    for (actual, bound) in after.iter().flatten().zip(before.iter().flatten()) {
        assert!(actual <= bound);
    }
}

#[cfg(test)]
fn beta_degrees(graph: &miden_constraint_compiler::ir::Graph) -> Vec<usize> {
    use miden_constraint_compiler::ir::{Leaf, Node, OpKind};
    let mut degrees = vec![0; graph.len()];
    for (id, node) in graph.iter() {
        degrees[id.index()] = match node {
            Node::Leaf(Leaf::Challenge(1)) => 1,
            Node::Leaf(Leaf::ExtBase(inner)) => degrees[inner.index()],
            Node::Leaf(_) => 0,
            Node::Op { op, x, y, .. } => match (op, y) {
                (OpKind::Add | OpKind::Sub, Some(y)) => degrees[x.index()].max(degrees[y.index()]),
                (OpKind::Mul, Some(y)) => degrees[x.index()] + degrees[y.index()],
                (OpKind::Neg, None) => degrees[x.index()],
                _ => unreachable!("IR operation arity"),
            },
        };
    }
    degrees
}

#[cfg(test)]
fn eval_with_beta(
    graph: &miden_constraint_compiler::ir::Graph,
    defaults: &[miden_core::field::QuadFelt],
    beta: miden_core::field::QuadFelt,
) -> Vec<miden_core::field::QuadFelt> {
    use miden_constraint_compiler::ir::{Leaf, Node, OpKind};
    let mut values = Vec::with_capacity(graph.len());
    for (id, node) in graph.iter() {
        let value = match node {
            Node::Leaf(Leaf::Challenge(1)) => beta,
            Node::Leaf(Leaf::ExtBase(inner)) => values[inner.index()],
            Node::Leaf(_) => defaults[id.index()],
            Node::Op { op, x, y, .. } => match (op, y) {
                (OpKind::Add, Some(y)) => values[x.index()] + values[y.index()],
                (OpKind::Sub, Some(y)) => values[x.index()] - values[y.index()],
                (OpKind::Mul, Some(y)) => values[x.index()] * values[y.index()],
                (OpKind::Neg, None) => -values[x.index()],
                _ => unreachable!("IR operation arity"),
            },
        };
        values.push(value);
    }
    values
}
