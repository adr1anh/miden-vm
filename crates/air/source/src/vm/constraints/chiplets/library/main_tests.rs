//! Tests exercise Library MAIN over the shared 24-cell row schema.
//! Hash and Open/Resolve lookup soundness is tested by the combined lookup adapter separately.

use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};

use miden_core::{
    Word,
    field::QuadFelt,
    program::{Namespace, domain},
};
use miden_crypto::hash::eidos::{Eidos, EidosFrame};
use miden_stark::air::{
    AirBuilder, WindowAccess,
    symbolic::{AirLayout, SymbolicAirBuilder},
};

use super::{constraints::enforce_library_constraints, *};
use crate::vm::{
    constraints::{
        columns::{ChipletCols, NUM_CHIPLETS_COLS},
        stack::test_utils::ConstraintEvalBuilder,
    },
    trace::chiplets::library::{
        EMPTY_LIST, ENV, INVALID, LIBRARY_COL_RANGE, LIST_CONTINUE, LIST_START, MAST, MERKLE, PAD,
    },
};

type SharedRow = [Felt; NUM_CHIPLETS_COLS];

fn initial_namespace() -> [Felt; 4] {
    Namespace::initial().into_word().into_elements()
}

fn word(base: u32) -> [Felt; 4] {
    core::array::from_fn(|i| Felt::from_u32(base + i as u32))
}

fn cols(row: &SharedRow) -> &LibraryCols<Felt> {
    row[LIBRARY_COL_RANGE].borrow()
}

fn cols_mut(row: &mut SharedRow) -> &mut LibraryCols<Felt> {
    row[LIBRARY_COL_RANGE].borrow_mut()
}

fn row(kind: [Felt; 3]) -> SharedRow {
    let mut row = [Felt::ZERO; NUM_CHIPLETS_COLS];
    row[0] = Felt::ONE;
    cols_mut(&mut row).k = kind;
    row
}

fn compress(cv: [Felt; 4], x: [Felt; 4], y: [Felt; 4]) -> [Felt; 4] {
    Eidos::compress(Word::new(cv), core::array::from_fn(|i| if i < 4 { x[i] } else { y[i - 4] }))
        .into_elements()
}

fn object_pair(kind: [Felt; 3]) -> [SharedRow; 2] {
    let mut pair = [row(kind), row(kind)];
    let a = cols_mut(&mut pair[0]);
    a.x = word(1);
    a.y = word(11);
    a.w = initial_namespace();
    a.d = Felt::from_u8(3);
    let init = if kind == MERKLE {
        Eidos::init_chaining_word(domain::ENV_MERKLE, 8)
    } else if kind == ENV {
        Eidos::init_chaining_word(domain::ENV_ENVIRONMENT, 8)
    } else {
        assert_eq!(kind, MAST);
        Eidos::init_chaining_word(domain::ENV_MAST, 8)
    };
    a.z = compress(init.into_elements(), a.x, a.y);
    let a = cols(&pair[0]).clone();
    let b = cols_mut(&mut pair[1]);
    b.d = a.d;
    if kind == MERKLE {
        b.x = a.x;
        b.y = a.y;
        b.w = a.w;
        b.b = Felt::from_u8(3);
    } else {
        b.x = a.w;
        b.y = a.x;
        b.w = a.y;
        let init = if kind == ENV {
            Eidos::init_chaining_word(domain::ENV_NAMESPACE, 8)
        } else {
            Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8)
        };
        b.z = compress(init.into_elements(), b.x, b.y);
        if kind == MAST {
            b.a = Felt::from_u8(5);
            b.b = Felt::from_u8(7);
        }
    }
    pair
}

fn list_pairs(num_children: usize) -> Vec<SharedRow> {
    let num_pairs = num_children.div_ceil(2).max(1);
    let mut cv = EidosFrame::for_domain(domain::ENV_LIST, [4 * num_children as u32, 0, 0])
        .initial_chaining_word()
        .into_elements();
    let mut pairs = Vec::new();
    for block in 0..num_pairs {
        let x = if 2 * block < num_children {
            word(100 + block as u32 * 10)
        } else {
            [Felt::ZERO; 4]
        };
        let y = if 2 * block + 1 < num_children {
            word(200 + block as u32 * 10)
        } else {
            [Felt::ZERO; 4]
        };
        let out = compress(cv, x, y);
        pairs.push((x, y, cv, out));
        cv = out;
    }

    let mut rows = Vec::new();
    for (reverse_index, (x, y, input, output)) in pairs.into_iter().rev().enumerate() {
        let kind = if num_children == 0 {
            EMPTY_LIST
        } else if reverse_index == 0 {
            LIST_START
        } else {
            LIST_CONTINUE
        };
        let odd = num_children % 2 == 1 && reverse_index == 0;
        let length = if num_children == 0 {
            0
        } else {
            8 * (reverse_index + 1) - 4 * usize::from(num_children % 2 == 1)
        };
        let mut pair = [row(kind), row(kind)];
        for (phase, row) in pair.iter_mut().enumerate() {
            let cols = cols_mut(row);
            cols.x = x;
            cols.y = y;
            cols.z = if phase == 0 { output } else { input };
            cols.w = initial_namespace();
            cols.d = Felt::from_u8(3);
            cols.a = Felt::from_usize(length);
            cols.b = if phase == 0 {
                Felt::from_bool(odd)
            } else if num_children == 0 {
                Felt::ZERO
            } else {
                Felt::from_u8(if odd { 1 } else { 3 })
            };
        }
        rows.extend(pair);
    }
    rows
}

fn finish(mut rows: Vec<SharedRow>) -> Vec<SharedRow> {
    assert_eq!(rows.len() % 2, 0);
    // At least one PAD pair; the Controller entry remains aligned to the fixed eight-row cycle.
    let prefix_len = (rows.len() + 2).next_multiple_of(8);
    rows.resize(prefix_len, row(PAD));
    let height = (prefix_len + 1).next_power_of_two();
    // Arbitrary non-Library payload must remain uninterpreted after the prefix.
    let mut inactive = [Felt::from_u8(19); NUM_CHIPLETS_COLS];
    inactive[0] = Felt::ZERO;
    rows.resize(height, inactive);
    for (index, row) in rows.iter_mut().enumerate() {
        row[23] = Felt::from_usize(index + 1);
    }
    rows
}

fn evaluations(rows: &[SharedRow]) -> Vec<(usize, Vec<QuadFelt>)> {
    rows.iter()
        .enumerate()
        .map(|(index, local)| {
            let next = &rows[(index + 1) % rows.len()];
            let mut builder = ConstraintEvalBuilder::new().with_row_flags(
                index == 0,
                index + 1 == rows.len(),
                index + 1 != rows.len(),
            );
            let context = LibraryRowContext {
                is_active: local[0],
                next_is_active: next[0],
                phase: Felt::from_usize(index % 2),
                exit_aligned: Felt::from_bool(index % 8 == 7),
            };
            enforce_library_constraints(&mut builder, cols(local), cols(next), &context);
            (index, builder.evaluations)
        })
        .collect()
}

fn assert_accept(rows: &[SharedRow]) {
    for (index, values) in evaluations(rows) {
        assert!(values.iter().all(|value| *value == QuadFelt::ZERO), "row {index}: {values:?}");
    }
}

fn assert_reject(rows: &[SharedRow]) {
    assert!(
        evaluations(rows)
            .iter()
            .any(|(_, values)| values.iter().any(|value| *value != QuadFelt::ZERO)),
        "forged shared Library matrix was accepted",
    );
}

/// Recompute every compression and CV link in a reverse List after changing its terminal input.
/// This does not repair a false frame, length, namespace, or depth constraint.
fn recompute_list_hashes(rows: &mut [SharedRow]) {
    for a_index in (0..rows.len()).step_by(2).rev() {
        let input = cols(&rows[a_index + 1]).z;
        let a = cols_mut(&mut rows[a_index]);
        a.z = compress(input, a.x, a.y);
        if a_index != 0 {
            cols_mut(&mut rows[a_index - 1]).z = cols(&rows[a_index]).z;
        }
    }
}

#[test]
fn library_main_accepts_all_kinds_and_list_lengths_in_shared_rows() {
    let mut rows = Vec::new();
    for kind in [MERKLE, ENV, MAST] {
        rows.extend(object_pair(kind));
    }
    for num_children in 0..8 {
        rows.extend(list_pairs(num_children));
    }
    assert_accept(&finish(rows));
    assert_accept(&finish(Vec::new()));
}

#[test]
fn library_main_rejects_invalid_kinds_and_pair_copies() {
    let valid = finish(object_pair(MERKLE).into());
    assert_accept(&valid);
    for kind in [INVALID, [Felt::from_u8(2), Felt::ZERO, Felt::ZERO]] {
        let mut forged = valid.clone();
        cols_mut(&mut forged[0]).k = kind;
        cols_mut(&mut forged[1]).k = kind;
        assert_reject(&forged);
    }
    for cell in [17, 20, 21, 22] {
        let mut forged = valid.clone();
        forged[1][cell] += Felt::ONE;
        assert_reject(&forged);
    }
}

#[test]
fn library_main_rejects_routing_and_unused_object_cells() {
    for kind in [MERKLE, ENV, MAST] {
        let valid = finish(object_pair(kind).into());
        assert_accept(&valid);
        // All three kinds route X/Y/W into their prescribed B overlay banks.
        for cell in (1..9).chain(13..17) {
            let mut forged = valid.clone();
            forged[1][cell] += Felt::ONE;
            assert_reject(&forged);
        }
        for cell in [18, 19] {
            let mut forged = valid.clone();
            forged[0][cell] = Felt::ONE;
            assert_reject(&forged);
        }
        if kind == MERKLE {
            for cell in 9..13 {
                let mut forged = valid.clone();
                forged[1][cell] = Felt::ONE;
                assert_reject(&forged);
            }
            let mut forged = valid.clone();
            cols_mut(&mut forged[1]).a = Felt::ONE;
            assert_reject(&forged);
            cols_mut(&mut forged[1]).a = Felt::ZERO;
            cols_mut(&mut forged[1]).b = Felt::from_u8(4);
            assert_reject(&forged);
        } else if kind == ENV {
            for cell in [18, 19] {
                let mut forged = valid.clone();
                forged[1][cell] = Felt::ONE;
                assert_reject(&forged);
            }
        }
    }
}

#[test]
fn library_main_requires_a_complete_absorbing_aligned_pad_prefix() {
    let valid = finish(object_pair(MAST).into());
    assert_accept(&valid);
    for prefix_len in [1, 2, 4, 6, 7] {
        let mut forged = finish(Vec::new());
        for (index, row) in forged.iter_mut().enumerate() {
            row[0] = Felt::from_bool(index < prefix_len);
        }
        assert_reject(&forged);
    }
    for cell in 1..23 {
        let mut forged = valid.clone();
        forged[6][cell] += Felt::ONE;
        assert_reject(&forged);
    }
    let mut forged = valid.clone();
    forged[0][0] = Felt::ZERO;
    assert_reject(&forged);
    let mut forged = finish(Vec::new());
    forged[8] = row(PAD);
    assert_reject(&forged);
    let mut forged = finish(Vec::new());
    forged[5][0] = Felt::ZERO;
    assert_reject(&forged);
    let mut forged = valid.clone();
    forged[6..8].copy_from_slice(&object_pair(MAST));
    assert_reject(&forged); // Active objects cannot follow PAD or exit without a PAD pair.
    let mut forged = finish(Vec::new());
    let last = forged.len() - 1;
    forged[last] = row(PAD);
    assert_reject(&forged); // The cyclic next row is never a Library re-entry.
    let mut forged = valid;
    forged[0][0] = Felt::from_u8(2);
    assert_reject(&forged);
}

#[test]
fn library_main_rejects_reverse_list_splices_and_incomplete_chains() {
    let valid = finish(list_pairs(6));
    assert_accept(&valid);
    let mut forged = valid.clone();
    cols_mut(&mut forged[0]).k = LIST_CONTINUE;
    cols_mut(&mut forged[1]).k = LIST_CONTINUE;
    assert_reject(&forged); // Locally valid pair cannot enter at LIST_CONTINUE.
    for index in [2, 4] {
        let mut forged = valid.clone();
        cols_mut(&mut forged[index]).k = LIST_START;
        cols_mut(&mut forged[index + 1]).k = LIST_START;
        assert_reject(&forged);
    }
    for index in [2, 4] {
        let mut forged = valid.clone();
        forged[index] = row(PAD);
        forged[index + 1] = row(PAD);
        assert_reject(&forged);
    }
    for cell in [13, 14, 15, 16, 17, 18] {
        let mut forged = valid.clone();
        forged[2][cell] += Felt::ONE;
        forged[3][cell] += Felt::ONE;
        recompute_list_hashes(&mut forged[..6]);
        assert_reject(&forged);
    }
    for coordinate in 0..4 {
        let mut forged = valid.clone();
        cols_mut(&mut forged[1]).z[coordinate] += Felt::ONE;
        let input = cols(&forged[1]).z;
        let a = cols_mut(&mut forged[0]);
        a.z = compress(input, a.x, a.y);
        assert_reject(&forged); // A recomputed output cannot hide a broken inter-block CV link.
    }
    let mut forged = valid.clone();
    cols_mut(&mut forged[2]).b = Felt::ONE;
    assert_reject(&forged);
    let mut forged = valid.clone();
    cols_mut(&mut forged[3]).b = Felt::from_u8(4);
    assert_reject(&forged);
    for coordinate in 0..4 {
        let mut forged = valid.clone();
        cols_mut(&mut forged[5]).z[coordinate] += Felt::ONE;
        recompute_list_hashes(&mut forged[..6]);
        assert_reject(&forged); // Recomputed compression helpers cannot hide a false initial CV.
    }

    let mut forged = object_pair(MERKLE).to_vec();
    let mut continuation = list_pairs(2);
    for row in &mut continuation {
        cols_mut(row).k = LIST_CONTINUE;
    }
    forged.extend(continuation);
    assert_reject(&finish(forged));
    let mut forged = list_pairs(0);
    forged.extend(list_pairs(2).into_iter().map(|mut row| {
        cols_mut(&mut row).k = LIST_CONTINUE;
        row
    }));
    assert_reject(&finish(forged));
}

#[test]
fn library_main_rejects_false_list_lengths_and_odd_padding_after_rehashing() {
    for num_children in [1, 2, 3, 4, 5] {
        let valid = finish(list_pairs(num_children));
        assert_accept(&valid);
        let list_rows = num_children.div_ceil(2) * 2;
        let mut forged = valid.clone();
        for row in &mut forged[..list_rows] {
            cols_mut(row).a += Felt::from_u8(4);
        }
        let false_length = cols(&forged[list_rows - 1]).a.as_canonical_u64() as u32;
        cols_mut(&mut forged[list_rows - 1]).z =
            EidosFrame::for_domain(domain::ENV_LIST, [false_length, 0, 0])
                .initial_chaining_word()
                .into_elements();
        recompute_list_hashes(&mut forged[..list_rows]);
        assert_reject(&forged);
        if num_children % 2 == 1 {
            for coordinate in 0..4 {
                let mut forged = valid.clone();
                cols_mut(&mut forged[0]).y[coordinate] = Felt::ONE;
                cols_mut(&mut forged[1]).y[coordinate] = Felt::ONE;
                recompute_list_hashes(&mut forged[..list_rows]);
                assert_reject(&forged);
            }
            for selection in [2, 3] {
                let mut forged = valid.clone();
                cols_mut(&mut forged[1]).b = Felt::from_u8(selection);
                assert_reject(&forged);
            }
        }
    }
    let mut forged = finish(list_pairs(2));
    cols_mut(&mut forged[0]).b = Felt::from_u8(2);
    assert_reject(&forged);
}

#[test]
fn library_main_rejects_empty_list_payload_and_frame_changes() {
    let valid = finish(list_pairs(0));
    assert_accept(&valid);
    for index in 0..2 {
        for cell in (1..9).chain(18..20) {
            let mut forged = valid.clone();
            forged[index][cell] = Felt::ONE;
            assert_reject(&forged);
        }
    }
    for coordinate in 0..4 {
        let mut forged = valid.clone();
        cols_mut(&mut forged[1]).z[coordinate] += Felt::ONE;
        recompute_list_hashes(&mut forged[..2]);
        assert_reject(&forged);
    }
}

#[test]
fn library_main_checks_each_syscall_supplier_namespace_without_frequency_ranges() {
    let valid = finish(object_pair(MAST).into());
    assert_accept(&valid);
    for coordinate in 0..4 {
        let mut forged = valid.clone();
        cols_mut(&mut forged[0]).w[coordinate] += Felt::ONE;
        cols_mut(&mut forged[1]).x[coordinate] += Felt::ONE;
        // Recompute the procedure key after changing the authenticated inherited namespace.
        let b = cols_mut(&mut forged[1]);
        b.z =
            compress(Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8).into_elements(), b.x, b.y);
        assert_reject(&forged);
        cols_mut(&mut forged[1]).b = Felt::ZERO;
        cols_mut(&mut forged[1]).a = -Felt::ONE;
        assert_accept(&forged); // Ordinary use may authenticate under any namespace.
    }
    let mut unrestricted = valid.clone();
    cols_mut(&mut unrestricted[1]).a = -Felt::from_u8(2);
    cols_mut(&mut unrestricted[1]).b = -Felt::from_u8(3);
    assert_accept(&unrestricted); // Matching demands, rather than local ranges, bind frequencies.

    let mut cancellation = Vec::new();
    for sign in [Felt::ONE, -Felt::ONE] {
        let mut pair = object_pair(MAST);
        for coordinate in 0..4 {
            cols_mut(&mut pair[0]).w[coordinate] += sign * Felt::from_usize(coordinate + 1);
            cols_mut(&mut pair[1]).x[coordinate] += sign * Felt::from_usize(coordinate + 1);
        }
        let b = cols_mut(&mut pair[1]);
        b.b = Felt::ONE;
        b.z =
            compress(Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8).into_elements(), b.x, b.y);
        cancellation.extend(pair);
    }
    for (coordinate, authorized) in initial_namespace().iter().enumerate() {
        let aggregate = cols(&cancellation[1]).b
            * (cols(&cancellation[1]).x[coordinate] - *authorized)
            + cols(&cancellation[3]).b * (cols(&cancellation[3]).x[coordinate] - *authorized);
        assert_eq!(aggregate, Felt::ZERO);
    }
    assert_reject(&finish(cancellation));
}

#[test]
fn library_main_rejects_zero_word_as_syscall_namespace() {
    assert_ne!(initial_namespace(), [Felt::ZERO; 4]);
    let mut pair = object_pair(MAST);
    cols_mut(&mut pair[0]).w = [Felt::ZERO; 4];
    let b = cols_mut(&mut pair[1]);
    b.x = [Felt::ZERO; 4];
    b.z = compress(Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8).into_elements(), b.x, b.y);
    assert_ne!(b.b, Felt::ZERO);
    assert_reject(&finish(pair.into()));
}

#[test]
fn library_main_symbolic_degree_is_nine_with_explicit_shared_inputs() {
    // A test adapter calls the same entry point with actual shared-row variables and the fixed
    // periodic order; the initial namespace is a VM constant, not a public input.
    let mut builder = SymbolicAirBuilder::<Felt>::new(AirLayout {
        preprocessed_width: 0,
        main_width: NUM_CHIPLETS_COLS,
        num_public_values: 0,
        permutation_width: 0,
        num_permutation_challenges: 0,
        num_permutation_values: 0,
        num_periodic_columns: 9,
    });
    let main = builder.main();
    let local: &ChipletCols<_> = main.current_slice().borrow();
    let next: &ChipletCols<_> = main.next_slice().borrow();
    let context = LibraryRowContext {
        is_active: local.chiplets[0].into(),
        next_is_active: next.chiplets[0].into(),
        phase: builder.periodic_values()[8].into(),
        exit_aligned: builder.periodic_values()[7].into(),
    };
    enforce_library_constraints(&mut builder, local.library(), next.library(), &context);
    assert_eq!(
        builder
            .base_constraints()
            .iter()
            .map(|constraint| constraint.degree_multiple())
            .max(),
        Some(9),
    );
    assert!(builder.extension_constraints().is_empty());
}
