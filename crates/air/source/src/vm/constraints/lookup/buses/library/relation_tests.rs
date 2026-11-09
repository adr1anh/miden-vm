//! External Range/And8 provider closure remains a production-integration gate; generated
//! Eidos cycles here validate production equations and fresh lookup auxiliaries.
//!
//! Combined tests of Library MAIN and the existing-group lookup entry points.
//!
//! These fixtures use the actual 24-cell shared rows and fixed nine-column periodic order.

use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

use miden_core::{
    Word,
    field::{Field, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::{Eidos, EidosFrame};
use miden_stark::{
    air::{LiftedAir, WindowAccess},
    lookup::{
        Challenges, ConstraintLookupBuilder, LookupAir, LookupBuilder, LookupColumn,
        LookupFractions, LookupMessage, accumulate_slow, build_lookup_fractions,
    },
};

use super::*;
use crate::vm::{
    MidenAir,
    constraints::{
        chiplets::library::constraints::enforce_library_constraints,
        columns::{ChipletCols, NUM_CHIPLETS_COLS},
        eidos_compression::{
            self, TraceMode, generate_felt_trace_block, lookup::FOOTER_INPUT_COLUMN,
        },
        lookup::messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
        stack::test_utils::ConstraintEvalBuilder,
    },
    trace::chiplets::library::{
        EMPTY_LIST, ENV, LIBRARY_COL_RANGE, LIST_CONTINUE, LIST_START, MAST, MERKLE, PAD,
        ROOT_MAST, namespace_difference_norms,
    },
};

type SharedRow = [Felt; NUM_CHIPLETS_COLS];
type Fraction = (Felt, QuadFelt);
const SHAPE: [usize; 4] = [4, 4, 3, 2];

/// Only an adapter around production entry points, with Library in existing column one.
struct RelationLookup;

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for RelationLookup {
    fn column_shape(&self) -> &[usize] {
        &SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();
        let context = LibraryRowContext {
            is_active: local.chiplets[0].into(),
            next_is_active: next.chiplets[0].into(),
            phase: builder.periodic_values()[8].into(),
            exit_aligned: builder.periodic_values()[7].into(),
        };
        for column in 0..SHAPE.len() {
            let degree = if column == 1 {
                Deg { v: 9, u: 7 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |col| {
                    col.group(
                        "combined_library_relation",
                        |group| {
                            if column == 1 {
                                emit_library(group, local.library(), next.library(), &context);
                            }
                        },
                        degree,
                    );
                },
                degree,
            );
        }
    }
}

#[derive(Clone)]
struct Demand {
    multiplicity: Felt,
    syscall: Felt,
    key: [Felt; 4],
    implementation: [Felt; 4],
}

#[derive(Clone)]
struct Fixture {
    rows: Vec<SharedRow>,
    public_root: [Felt; 4],
    demands: Vec<Demand>,
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

fn compress(input: [Felt; 4], x: [Felt; 4], y: [Felt; 4]) -> [Felt; 4] {
    Eidos::compress(Word::new(input), core::array::from_fn(|i| if i < 4 { x[i] } else { y[i - 4] }))
        .into_elements()
}

fn fixed_input(tag: Felt) -> [Felt; 4] {
    initial_cv_from_frame([tag, Felt::from_u8(8), Felt::ZERO, Felt::ZERO])
}

fn ordinary_pair(
    kind: [Felt; 3],
    x: [Felt; 4],
    y: [Felt; 4],
    namespace: [Felt; 4],
    depth: usize,
) -> [SharedRow; 2] {
    let mut pair = [row(kind), row(kind)];
    let input = if kind == ENV {
        fixed_input(domain::domain_tag(domain::ENV_ENVIRONMENT))
    } else if kind == MAST || kind == ROOT_MAST {
        fixed_input(domain::domain_tag(domain::ENV_MAST))
    } else {
        assert_eq!(kind, MERKLE);
        Eidos::merkle_node_init_chaining_word().into_elements()
    };
    let a = cols_mut(&mut pair[0]);
    a.x = x;
    a.y = y;
    a.z = compress(input, x, y);
    a.w = namespace;
    a.d = Felt::from_usize(depth);
    if kind == MAST {
        let [low, high] = namespace_difference_norms(namespace);
        if low != Felt::ZERO {
            a.a = low.inverse();
        } else {
            a.b = high.inverse();
        }
    }
    let b = cols_mut(&mut pair[1]);
    b.d = Felt::from_usize(depth);
    if kind == MERKLE {
        b.x = x;
        b.y = y;
        b.w = namespace;
        b.b = Felt::from_u8(3);
    } else {
        b.x = namespace;
        b.y = x;
        b.w = y;
        if kind != ROOT_MAST {
            let tag = if kind == ENV {
                domain::domain_tag(domain::ENV_NAMESPACE)
            } else {
                domain::domain_tag(domain::ENV_PROCEDURE)
            };
            b.z = compress(fixed_input(tag), b.x, b.y);
        }
    }
    pair
}

fn mast(namespace: [Felt; 4], depth: usize, index: usize) -> [SharedRow; 2] {
    let kind = if namespace == Namespace::initial().into_word().into_elements() {
        ROOT_MAST
    } else {
        MAST
    };
    ordinary_pair(
        kind,
        word(100 + 10 * index as u32),
        word(500 + 10 * index as u32),
        namespace,
        depth,
    )
}

fn demand(pair: &[SharedRow; 2], syscall: bool, multiplicity: usize) -> Demand {
    let b = cols(&pair[1]);
    Demand {
        multiplicity: Felt::from_usize(multiplicity),
        syscall: Felt::from_bool(syscall),
        key: if b.k == ROOT_MAST { b.y } else { b.z },
        implementation: b.w,
    }
}

fn finish(mut rows: Vec<SharedRow>) -> Vec<SharedRow> {
    assert_eq!(rows.len() % 2, 0);
    let prefix_len = (rows.len() + 2).next_multiple_of(8);
    rows.resize(prefix_len, row(PAD));
    let height = (prefix_len + 1).next_power_of_two();
    let mut inactive = [Felt::from_u8(19); NUM_CHIPLETS_COLS];
    inactive[0] = Felt::ZERO;
    rows.resize(height, inactive);
    for (index, row) in rows.iter_mut().enumerate() {
        row[23] = Felt::from_usize(index + 1);
    }
    rows
}

fn mast_fixture() -> Fixture {
    let namespace = Namespace::initial().into_word().into_elements();
    let mut pair = mast(namespace, 0, 0);
    cols_mut(&mut pair[1]).a = Felt::from_u8(2);
    cols_mut(&mut pair[1]).b = Felt::from_u8(3);
    Fixture {
        public_root: cols(&pair[0]).z,
        demands: vec![demand(&pair, false, 2), demand(&pair, true, 3)],
        rows: finish(pair.into()),
    }
}

fn merkle_fixture() -> Fixture {
    let namespace = Namespace::initial().into_word().into_elements();
    let mut left = mast(namespace, 1, 0);
    let mut right = mast(namespace, 1, 1);
    cols_mut(&mut left[1]).a = Felt::ONE;
    cols_mut(&mut right[1]).b = Felt::ONE;
    let root = ordinary_pair(MERKLE, cols(&left[0]).z, cols(&right[0]).z, namespace, 0);
    let public_root = cols(&root[0]).z;
    let demands = vec![demand(&left, false, 1), demand(&right, true, 1)];
    let rows = root.into_iter().chain(left).chain(right).collect();
    Fixture { rows: finish(rows), public_root, demands }
}

/// Build Env -> complete List -> selected Mast openings. Unselected commitments remain hashed.
fn list_fixture(num_children: usize, open_all: bool) -> Fixture {
    list_fixture_at_home(num_children, open_all, false)
}

fn list_fixture_at_home(num_children: usize, open_all: bool, at_root: bool) -> Fixture {
    let initial = Namespace::initial().into_word().into_elements();
    let label = word(10);
    let namespace = if at_root {
        initial
    } else {
        compress(fixed_input(domain::domain_tag(domain::ENV_NAMESPACE)), initial, label)
    };
    let depth = usize::from(!at_root);
    let mut children: Vec<_> = (0..num_children).map(|i| mast(namespace, depth + 1, i)).collect();
    let mut demands = Vec::new();
    for (index, pair) in children.iter_mut().enumerate() {
        if open_all || index == 0 {
            cols_mut(&mut pair[1]).a = Felt::from_u8(2);
            demands.push(demand(pair, false, 2));
            if at_root {
                cols_mut(&mut pair[1]).b = Felt::from_u8(3);
                demands.push(demand(pair, true, 3));
            }
        }
    }
    let mut cv = EidosFrame::for_domain(domain::ENV_LIST, [4 * num_children as u32, 0, 0])
        .initial_chaining_word()
        .into_elements();
    let mut pairs = Vec::new();
    let count = num_children.div_ceil(2).max(1);
    for block in 0..count {
        let x = children.get(2 * block).map_or([Felt::ZERO; 4], |pair| cols(&pair[0]).z);
        let y = children.get(2 * block + 1).map_or([Felt::ZERO; 4], |pair| cols(&pair[0]).z);
        let output = compress(cv, x, y);
        let mut pair = [row(LIST_CONTINUE), row(LIST_CONTINUE)];
        for (phase, row) in pair.iter_mut().enumerate() {
            let c = cols_mut(row);
            c.x = x;
            c.y = y;
            c.z = if phase == 0 { output } else { cv };
            c.w = namespace;
            c.d = Felt::from_usize(depth);
            if phase == 1 && num_children != 0 {
                let low = open_all || block == 0;
                let high = open_all && 2 * block + 1 < num_children;
                c.b = Felt::from_u8(u8::from(low) + 2 * u8::from(high));
            }
        }
        pairs.push(pair);
        cv = output;
    }
    let env = ordinary_pair(ENV, label, cv, initial, 0);
    let public_root = if at_root { cv } else { cols(&env[0]).z };
    let mut rows = if at_root { Vec::new() } else { env.to_vec() };
    for (index, mut pair) in pairs.into_iter().rev().enumerate() {
        for (phase, row) in pair.iter_mut().enumerate() {
            let c = cols_mut(row);
            c.k = if num_children == 0 {
                EMPTY_LIST
            } else if index == 0 {
                LIST_START
            } else {
                LIST_CONTINUE
            };
            c.a = Felt::from_usize(if num_children == 0 {
                0
            } else {
                8 * (index + 1) - 4 * (num_children % 2)
            });
            if phase == 0 {
                c.b = Felt::from_bool(index == 0 && num_children % 2 == 1);
            }
        }
        rows.extend(pair);
    }
    for (index, pair) in children.into_iter().enumerate() {
        if open_all || index == 0 {
            rows.extend(pair);
        }
    }
    Fixture { rows: finish(rows), public_root, demands }
}

/// Add a selected Merkle grouping level without changing inherited namespaces or Resolve keys.
fn group_root_in_merkle(mut fixture: Fixture) -> Fixture {
    let namespace = Namespace::initial().into_word().into_elements();
    let mut root = ordinary_pair(MERKLE, fixture.public_root, word(900), namespace, 0);
    cols_mut(&mut root[1]).b = Felt::ONE;
    let mut rows = root.to_vec();
    for mut child in fixture.rows.into_iter().take_while(|row| row[0] == Felt::ONE) {
        if cols(&child).k == PAD {
            continue;
        }
        cols_mut(&mut child).d += Felt::ONE;
        rows.push(child);
    }
    fixture.public_root = cols(&root[0]).z;
    fixture.rows = finish(rows);
    fixture
}

fn periodic_columns() -> Vec<Vec<Felt>> {
    let mut periodic: Vec<_> = (0..8)
        .map(|phase| (0..8).map(|i| Felt::from_bool(i == phase)).collect())
        .collect();
    periodic.push(vec![Felt::ZERO, Felt::ONE]);
    periodic
}

fn challenges(variant: u32) -> Challenges<QuadFelt> {
    Challenges::new(
        QuadFelt::new([Felt::from_u32(7 + variant), Felt::ONE]),
        QuadFelt::from_u32(11 + variant),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    )
}

fn fractions_at(
    fractions: &LookupFractions<Felt, QuadFelt>,
    row: usize,
    column: usize,
) -> &[Fraction] {
    let index = row * fractions.num_columns() + column;
    let start = fractions.counts()[..index].iter().sum::<usize>();
    &fractions.fractions()[start..start + fractions.counts()[index]]
}

/// Obtain the actual negative compression response from an honestly generated production Eidos
/// cycle. The claimed output is deliberately absent from the arguments to this function.
fn compression_response(
    block: [Felt; 8],
    input: [Felt; 4],
    challenges: &Challenges<QuadFelt>,
) -> Fraction {
    let unpack = |value: Felt, half: usize| (value.as_canonical_u64() >> (32 * half)) as u32;
    let block = core::array::from_fn(|i| unpack(block[i / 2], i % 2));
    let cv = core::array::from_fn(|i| unpack(input[i / 2], i % 2));
    let trace = generate_felt_trace_block(block, cv, TraceMode::Compression);
    let matrix =
        RowMajorMatrix::new(trace.rows.as_flattened().to_vec(), eidos_compression::NUM_COLS);
    let fractions = build_lookup_fractions(
        &MidenAir::EIDOS_COMPRESSION,
        &matrix,
        None,
        &eidos_compression::periodic::get_periodic_column_values(),
        challenges,
    );
    let (auxiliary, sigma_prime) = accumulate_slow(&fractions);
    let periodic = eidos_compression::periodic::get_periodic_column_values();
    for index in 0..trace.rows.len() {
        let mut builder =
            window_builder(&trace.rows, &auxiliary, &periodic, challenges, sigma_prime, index);
        <MidenAir as LiftedAir<Felt, QuadFelt>>::eval(&MidenAir::EIDOS_COMPRESSION, &mut builder);
        assert!(
            builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "generated Eidos MAIN/lookup auxiliary rejected at row {index}"
        );
    }
    let footer = fractions_at(&fractions, 31, FOOTER_INPUT_COLUMN);
    assert_eq!(footer.len(), 2);
    assert_eq!(footer[1].0, -Felt::ONE);
    footer[1]
}

fn compression_responses(rows: &[SharedRow], challenges: &Challenges<QuadFelt>) -> Vec<Fraction> {
    let mut responses = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row[0] != Felt::ONE {
            continue;
        }
        let c = cols(row);
        let tag = if c.k == ENV {
            Some(if index % 2 == 0 {
                domain::domain_tag(domain::ENV_ENVIRONMENT)
            } else {
                domain::domain_tag(domain::ENV_NAMESPACE)
            })
        } else if c.k == ROOT_MAST && index % 2 == 0 {
            Some(domain::domain_tag(domain::ENV_MAST))
        } else if c.k == MAST {
            Some(if index % 2 == 0 {
                domain::domain_tag(domain::ENV_MAST)
            } else {
                domain::domain_tag(domain::ENV_PROCEDURE)
            })
        } else {
            None
        };
        let input = if index % 2 == 0 && c.k == MERKLE {
            Eidos::merkle_node_init_chaining_word().into_elements()
        } else if let Some(tag) = tag {
            fixed_input(tag)
        } else if index % 2 == 0 && [LIST_START, LIST_CONTINUE, EMPTY_LIST].contains(&c.k) {
            cols(&rows[index + 1]).z
        } else {
            continue;
        };
        responses.push(compression_response(
            core::array::from_fn(|i| if i < 4 { c.x[i] } else { c.y[i - 4] }),
            input,
            challenges,
        ));
    }
    responses
}

struct SeedCollector<'a> {
    challenges: &'a Challenges<QuadFelt>,
    fractions: Vec<Fraction>,
}

impl BoundaryBuilder for SeedCollector<'_> {
    type F = Felt;
    type EF = QuadFelt;

    fn var_len_public_inputs(&self) -> &[&[Felt]] {
        panic!("the root seed must come from the fixture's fixed public statement");
    }

    fn insert<M: LookupMessage<Felt, QuadFelt>>(
        &mut self,
        _name: &'static str,
        multiplicity: Felt,
        message: M,
    ) {
        self.fractions.push((multiplicity, message.encode(self.challenges)));
    }
}

fn main_accepts(fixture: &Fixture) -> bool {
    fixture.rows.iter().enumerate().all(|(index, local)| {
        let next = &fixture.rows[(index + 1) % fixture.rows.len()];
        let mut builder = ConstraintEvalBuilder::new().with_row_flags(
            index == 0,
            index + 1 == fixture.rows.len(),
            index + 1 != fixture.rows.len(),
        );
        let context = LibraryRowContext {
            is_active: local[0],
            next_is_active: next[0],
            phase: Felt::from_usize(index % 2),
            exit_aligned: Felt::from_bool(index % 8 == 7),
        };
        enforce_library_constraints(&mut builder, cols(local), cols(next), &context);
        builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO)
    })
}

fn window_builder<const WIDTH: usize>(
    rows: &[[Felt; WIDTH]],
    auxiliary: &[Vec<QuadFelt>],
    periodic: &[Vec<Felt>],
    challenges: &Challenges<QuadFelt>,
    sigma_prime: QuadFelt,
    index: usize,
) -> ConstraintEvalBuilder {
    let next = (index + 1) % rows.len();
    let main = RowMajorMatrix::new(rows[index].iter().chain(&rows[next]).copied().collect(), WIDTH);
    let aux = RowMajorMatrix::new(
        [index, next]
            .into_iter()
            .flat_map(|row| auxiliary.iter().map(move |column| column[row]))
            .collect(),
        auxiliary.len(),
    );
    let periodic = periodic.iter().map(|column| column[index % column.len()]).collect();
    ConstraintEvalBuilder::new()
        .with_row_flags(index == 0, index + 1 == rows.len(), index + 1 != rows.len())
        .with_lookup_windows(
            main,
            aux,
            vec![challenges.alpha, challenges.beta_powers[1]],
            vec![sigma_prime],
            periodic,
        )
}

fn lookup_accepts(fixture: &Fixture, seed: bool) -> bool {
    // Acceptance follows the production rational correction. Exact multiplicity matching is
    // an independent diagnostic; eagerly evaluate both encodings even for a rejected fixture.
    [0, 6].map(|variant| {
        let challenges = challenges(variant);
        let matrix = RowMajorMatrix::new(fixture.rows.as_flattened().to_vec(), NUM_CHIPLETS_COLS);
        let fractions = build_lookup_fractions(
            &RelationLookup,
            &matrix,
            None,
            &periodic_columns(),
            &challenges,
        );
        // Every forgery rebuilds both fractions and all four auxiliary columns from its matrix.
        let (auxiliary, sigma_prime) = accumulate_slow(&fractions);
        assert_eq!(auxiliary.len(), SHAPE.len());
        assert!(auxiliary.iter().all(|column| column.len() == fixture.rows.len()));
        for index in 0..fixture.rows.len() {
            let mut builder = window_builder(
                &fixture.rows,
                &auxiliary,
                &periodic_columns(),
                &challenges,
                sigma_prime,
                index,
            );
            let mut lookup = ConstraintLookupBuilder::new(&mut builder, &RelationLookup);
            RelationLookup.eval(&mut lookup);
            lookup.finish();
            assert!(
                builder.evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                "fresh lookup auxiliary rejected at row {index}"
            );
        }
        let mut events = fractions.fractions().to_vec();
        events.extend(compression_responses(&fixture.rows, &challenges));
        if seed {
            let mut boundary = SeedCollector {
                challenges: &challenges,
                fractions: Vec::new(),
            };
            emit_open_seed(&mut boundary, fixture.public_root);
            events.extend(boundary.fractions);
        }
        for demand in &fixture.demands {
            events.push((
                -demand.multiplicity,
                LibraryResolveMsg {
                    requires_syscall: demand.syscall,
                    key: demand.key,
                    implementation: demand.implementation,
                }
                .encode(&challenges),
            ));
        }
        let external_sum: QuadFelt = events[fractions.fractions().len()..]
            .iter()
            .map(|(weight, denominator)| QuadFelt::from(*weight) / *denominator)
            .sum();
        let rational_match =
            sigma_prime * Felt::from_usize(fixture.rows.len()) + external_sum == QuadFelt::ZERO;
        let mut totals: Vec<Fraction> = Vec::new();
        for (weight, denominator) in events {
            assert_ne!(denominator, QuadFelt::ZERO);
            if let Some((total, _)) = totals.iter_mut().find(|(_, value)| *value == denominator) {
                *total += weight;
            } else {
                totals.push((weight, denominator));
            }
        }
        let exact_match = totals.iter().all(|(weight, _)| *weight == Felt::ZERO);
        assert_eq!(
            exact_match, rational_match,
            "production rational correction must agree with the diagnostic at selected challenges",
        );
        rational_match
    })
    .into_iter()
    .all(core::convert::identity)
}

fn assert_accept(fixture: &Fixture) {
    assert!(main_accepts(fixture), "honest combined MAIN fixture rejected");
    assert!(lookup_accepts(fixture, true), "honest combined lookup fixture rejected");
}

fn assert_lookup_reject(fixture: &Fixture) {
    assert!(main_accepts(fixture), "attack should preserve the local MAIN relation");
    assert!(!lookup_accepts(fixture, true), "forged combined lookup fixture accepted");
}

/// Rehash a reverse List from its possibly forged terminal input, repairing every CV link.
fn rehash_list(rows: &mut [SharedRow]) {
    for index in (0..rows.len()).step_by(2).rev() {
        let input = cols(&rows[index + 1]).z;
        let c = cols_mut(&mut rows[index]);
        c.z = compress(input, c.x, c.y);
        if index != 0 {
            cols_mut(&mut rows[index - 1]).z = cols(&rows[index]).z;
        }
    }
}

fn rehash_env_header(fixture: &mut Fixture) {
    let child = cols(&fixture.rows[2]).z;
    cols_mut(&mut fixture.rows[0]).y = child;
    cols_mut(&mut fixture.rows[1]).w = child;
    let c = cols_mut(&mut fixture.rows[0]);
    c.z = compress(fixed_input(domain::domain_tag(domain::ENV_ENVIRONMENT)), c.x, c.y);
}

#[test]
fn library_combined_accepts_rooted_env_mast_merkle_and_complete_lists() {
    assert_accept(&mast_fixture());
    assert_accept(&merkle_fixture());
    assert_accept(&group_root_in_merkle(list_fixture_at_home(3, true, true)));
    assert_accept(&group_root_in_merkle(list_fixture_at_home(3, false, true)));
    for count in 0..8 {
        assert_accept(&list_fixture(count, true));
        assert_accept(&list_fixture(count, false));
        assert_accept(&list_fixture_at_home(count, true, true));
        assert_accept(&list_fixture_at_home(count, false, true));
    }
}

#[test]
fn library_combined_rejects_a_nonroot_leaf_using_the_raw_key() {
    let ordinary = list_fixture(3, false);
    assert_accept(&ordinary);
    let mut forged = ordinary;
    let mast_a = 2 + 2 * 3_usize.div_ceil(2);
    let a = cols_mut(&mut forged.rows[mast_a]);
    a.k = ROOT_MAST;
    a.a = Felt::ZERO;
    a.b = Felt::ZERO;
    let b = cols_mut(&mut forged.rows[mast_a + 1]);
    b.k = ROOT_MAST;
    b.z = [Felt::ZERO; 4];
    forged.demands[0].key = b.y;
    assert!(!main_accepts(&forged));
    assert!(lookup_accepts(&forged, true)); // Env/List openings authenticate the true nonroot N.

    cols_mut(&mut forged.rows[mast_a + 1]).b = Felt::from_u8(3);
    let pair = [forged.rows[mast_a], forged.rows[mast_a + 1]];
    forged.demands.push(demand(&pair, true, 3));
    assert!(!main_accepts(&forged));
    assert!(lookup_accepts(&forged, true));
}

#[test]
fn library_combined_rejects_each_forged_root_namespace_coordinate() {
    let fixture = mast_fixture();
    let initial = Namespace::initial().into_word().into_elements();
    assert_ne!(initial, [Felt::ZERO; 4]);
    for coordinate in 0..4 {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[0]).w[coordinate] += Felt::ONE;
        cols_mut(&mut forged.rows[1]).x[coordinate] += Felt::ONE;
        // The raw key remains valid while both the fixed root seed and MAIN reject the namespace.
        assert!(!main_accepts(&forged));
        assert!(!lookup_accepts(&forged, true));
    }
}

#[test]
fn library_combined_rejects_the_hashed_key_for_a_root_mast() {
    let fixture = mast_fixture();
    let b = cols(&fixture.rows[1]);
    let hashed = compress(fixed_input(domain::domain_tag(domain::ENV_PROCEDURE)), b.x, b.y);
    assert_ne!(hashed, b.y);
    for index in 0..2 {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[1]).z = hashed;
        forged.demands[index].key = hashed;
        assert_lookup_reject(&forged);
    }

    let mut forged = fixture;
    cols_mut(&mut forged.rows[0]).k = MAST;
    let b = cols_mut(&mut forged.rows[1]);
    b.k = MAST;
    b.b = Felt::ZERO;
    b.z = hashed;
    forged.demands.pop();
    forged.demands[0].key = hashed;
    assert!(lookup_accepts(&forged, true));
    assert!(!main_accepts(&forged));
}

#[test]
fn library_combined_requires_the_public_seed_and_unit_rooted_edges() {
    let fixture = merkle_fixture();
    assert_accept(&fixture);
    assert!(!lookup_accepts(&fixture, false));
    for coordinate in 0..4 {
        let mut forged = fixture.clone();
        forged.public_root[coordinate] += Felt::ONE;
        assert_lookup_reject(&forged);
    }
    for sigma in [0, 1, 2] {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[1]).b = Felt::from_u8(sigma);
        assert_lookup_reject(&forged); // One or both opened children lack their unit edge.
    }
    let mut duplicate = fixture.clone();
    let mut active = duplicate.rows[..6].to_vec();
    let mut extra = [duplicate.rows[2], duplicate.rows[3]];
    cols_mut(&mut extra[1]).a = Felt::ZERO;
    active.extend(extra);
    duplicate.rows = finish(active);
    assert_lookup_reject(&duplicate); // Frequencies cannot multiply an incoming Open token.
    let mut missing = fixture.clone();
    // Keep the selected edge but omit its opened child and the corresponding attempted use.
    missing.rows = finish(missing.rows[..4].to_vec());
    missing.demands.pop();
    assert_lookup_reject(&missing);
    let mut detached = mast_fixture();
    let extra = mast(word(900), 7, 4);
    detached.rows = finish(detached.rows[..2].iter().copied().chain(extra).collect());
    assert_lookup_reject(&detached);
    for sigma in [-Felt::ONE, Felt::from_u8(4), Felt::from_u8(2).inverse()] {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[1]).b = sigma;
        assert!(!main_accepts(&forged));
        assert!(!lookup_accepts(&forged, true));
    }
}

#[test]
fn library_combined_binds_each_commitment_namespace_depth_key_implementation_and_tag() {
    let fixture = mast_fixture();
    for coordinate in 0..4 {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[0]).z[coordinate] += Felt::ONE;
        assert_lookup_reject(&forged); // Eidos provider recomputes its output from input only.
        forged.public_root[coordinate] += Felt::ONE;
        assert_lookup_reject(&forged); // Even balancing Open cannot authenticate the false hash.
        let mut forged = fixture.clone();
        forged.demands[0].key[coordinate] += Felt::ONE;
        assert_lookup_reject(&forged);
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[0]).y[coordinate] += Felt::ONE;
        cols_mut(&mut forged.rows[1]).w[coordinate] += Felt::ONE;
        let a = cols_mut(&mut forged.rows[0]);
        a.z = compress(fixed_input(domain::domain_tag(domain::ENV_MAST)), a.x, a.y);
        assert_lookup_reject(&forged); // Public R_E and expected Resolve D remain fixed.
    }
    let mut forged = fixture.clone();
    for row in &mut forged.rows[..2] {
        cols_mut(row).d = -Felt::ONE;
    }
    assert_lookup_reject(&forged);
    let mut forged = fixture;
    cols_mut(&mut forged.rows[1]).a = Felt::from_u8(3);
    cols_mut(&mut forged.rows[1]).b = Felt::from_u8(2);
    assert_lookup_reject(&forged); // Identical K/D cannot exchange normal and syscall demand.
}

#[test]
fn library_combined_rejects_incomplete_midchain_and_merged_lists_after_rehashing() {
    let fixture = list_fixture(5, false);
    assert_accept(&fixture);
    for coordinate in 0..4 {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[7]).z[coordinate] += Felt::ONE;
        rehash_list(&mut forged.rows[2..8]);
        rehash_env_header(&mut forged);
        assert!(!main_accepts(&forged)); // Every hash is genuine; the terminal frame is false.
        assert!(!lookup_accepts(&forged, true));
    }
    let mut midchain = fixture.clone();
    cols_mut(&mut midchain.rows[2]).k = LIST_CONTINUE;
    cols_mut(&mut midchain.rows[3]).k = LIST_CONTINUE;
    cols_mut(&mut midchain.rows[2]).b = Felt::ZERO;
    assert!(!main_accepts(&midchain));
    assert!(!lookup_accepts(&midchain, true));

    // A complete shorter chain has a valid shorter frame and recomputed List and Env headers.
    // Its sole selected leaf and fixed ordinary Resolve consumer are identical to the original.
    for count in [1, 2, 3, 4] {
        let mut shorter = list_fixture(count, false);
        assert_accept(&shorter);
        shorter.public_root = fixture.public_root;
        assert_lookup_reject(&shorter);
    }

    let mut merged = fixture;
    // Replace the final reverse block by a different List's fully recomputed block/CV. All
    // preceding outputs and the outer Env commitment are repaired, but the length frame stays 20.
    let other = list_fixture(2, false);
    let replacement = cols(&other.rows[3]).z;
    cols_mut(&mut merged.rows[7]).z = replacement;
    rehash_list(&mut merged.rows[2..8]);
    rehash_env_header(&mut merged);
    assert!(!main_accepts(&merged));
    assert!(!lookup_accepts(&merged, true));
}

#[test]
fn library_combined_rejects_odd_padding_with_all_hashes_recomputed() {
    let fixture = list_fixture(3, false);
    for coordinate in 0..4 {
        let mut forged = fixture.clone();
        cols_mut(&mut forged.rows[2]).y[coordinate] = Felt::ONE;
        cols_mut(&mut forged.rows[3]).y[coordinate] = Felt::ONE;
        rehash_list(&mut forged.rows[2..6]);
        rehash_env_header(&mut forged);
        assert!(!main_accepts(&forged));
        assert!(!lookup_accepts(&forged, true));
    }
}

#[test]
fn library_combined_rejects_weighted_syscall_namespace_cancellation_locally() {
    let initial = Namespace::initial().into_word().into_elements();
    let label = word(700);
    let namespace =
        compress(fixed_input(domain::domain_tag(domain::ENV_NAMESPACE)), initial, label);
    assert_ne!(namespace, initial);
    let mut leaves = [mast(namespace, 2, 0), mast(namespace, 2, 1)];
    for (pair, frequency) in leaves.iter_mut().zip([Felt::ONE, -Felt::ONE]) {
        let a = cols_mut(&mut pair[0]);
        a.k = ROOT_MAST;
        a.a = Felt::ZERO;
        a.b = Felt::ZERO;
        let b = cols_mut(&mut pair[1]);
        b.k = ROOT_MAST;
        b.b = frequency;
        b.z = [Felt::ZERO; 4];
    }
    let merkle = ordinary_pair(MERKLE, cols(&leaves[0][0]).z, cols(&leaves[1][0]).z, namespace, 1);
    let root = ordinary_pair(ENV, label, cols(&merkle[0]).z, initial, 0);
    let fixture = Fixture {
        public_root: cols(&root[0]).z,
        demands: leaves
            .iter()
            .map(|pair| Demand {
                multiplicity: cols(&pair[1]).b,
                syscall: Felt::ONE,
                key: cols(&pair[1]).y,
                implementation: cols(&pair[1]).w,
            })
            .collect(),
        rows: finish(root.into_iter().chain(merkle).chain(leaves.into_iter().flatten()).collect()),
    };
    // Nonzero field frequencies can cancel in every aggregate coordinate. Each supplier must
    // still satisfy the fixed-N0 equations independently, even with genuine rooted openings.
    for (coordinate, authorized) in initial.into_iter().enumerate() {
        assert_eq!(
            cols(&fixture.rows[5]).b * (cols(&fixture.rows[5]).x[coordinate] - authorized)
                + cols(&fixture.rows[7]).b * (cols(&fixture.rows[7]).x[coordinate] - authorized),
            Felt::ZERO,
        );
    }
    assert!(!main_accepts(&fixture));
    assert!(
        lookup_accepts(&fixture, true),
        "fully rooted genuine providers isolate the local syscall equations"
    );
}

#[cfg(feature = "std")]
#[test]
fn library_combined_captures_exact_lookup_metadata_and_degree_nine_including_scope() {
    use miden_stark::{
        air::{
            AirBuilder,
            symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpr},
        },
        lookup::debug::{ValidateLayout, ValidateLookupAir},
    };

    RelationLookup
        .validate(ValidateLayout {
            preprocessed_width: 0,
            trace_width: NUM_CHIPLETS_COLS,
            num_public_values: 4,
            num_periodic_columns: 9,
            permutation_width: SHAPE.len(),
            num_permutation_challenges: 2,
            num_permutation_values: 1,
        })
        .unwrap_or_else(|error| panic!("combined Library lookup metadata: {error}"));
    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(AirLayout {
        preprocessed_width: 0,
        main_width: NUM_CHIPLETS_COLS,
        num_public_values: 4,
        num_periodic_columns: 9,
        permutation_width: SHAPE.len(),
        num_permutation_challenges: 2,
        num_permutation_values: 1,
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
    let mut lookup = ConstraintLookupBuilder::new(&mut builder, &RelationLookup);
    RelationLookup.eval(&mut lookup);
    lookup.finish();
    assert_eq!(
        builder.base_constraints().iter().map(SymbolicExpr::degree_multiple).max(),
        Some(9)
    );
    assert_eq!(
        builder.extension_constraints().iter().map(SymbolicExpr::degree_multiple).max(),
        Some(9)
    );
    assert_eq!(SHAPE, [4, 4, 3, 2]);
}
