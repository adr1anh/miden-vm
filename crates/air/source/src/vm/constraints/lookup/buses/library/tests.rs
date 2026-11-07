use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::{
    air::WindowAccess,
    lookup::{
        Challenges, LookupAir, LookupBuilder, LookupColumn, LookupFractions, LookupMessage,
        build_lookup_fractions,
    },
};

use super::*;
use crate::vm::{
    constraints::{
        columns::{ChipletCols, NUM_CHIPLETS_COLS},
        lookup::messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    },
    trace::chiplets::library::{EMPTY_LIST, ENV, LIST_CONTINUE, LIST_START, MAST, MERKLE, PAD},
};

const SHAPE: [usize; 4] = [4, 4, 3, 2];

/// Exercises the real emitter in column 1 of the selected packed shape. Other row families are
/// absent in this fixture; production group integration remains a coordinated cutover obligation.
struct LibraryLookupAir;

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for LibraryLookupAir {
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
        let ctx = LibraryRowContext {
            is_active: local.chiplets[0].into(),
            next_is_active: next.chiplets[0].into(),
            phase: builder.periodic_values()[0].into(),
            exit_aligned: LB::Expr::ONE,
        };
        for column in 0..SHAPE.len() {
            let deg = if column == 1 {
                Deg { v: 9, u: 8 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |col| {
                    col.group(
                        "packed_library_fixture",
                        |group| {
                            if column == 1 {
                                emit_library(group, local.library(), next.library(), &ctx);
                            }
                        },
                        deg,
                    );
                },
                deg,
            );
        }
    }
}

fn challenges() -> Challenges<QuadFelt> {
    Challenges::new(QuadFelt::from_u32(7), QuadFelt::from_u32(11), 16, BusId::COUNT)
}

fn row(kind: [Felt; 3]) -> [Felt; NUM_CHIPLETS_COLS] {
    let mut row = core::array::from_fn(|i| Felt::from_usize(100 + i));
    row[0] = Felt::ONE;
    cols_mut(&mut row).k = kind;
    row
}

fn cols(row: &[Felt; NUM_CHIPLETS_COLS]) -> &LibraryCols<Felt> {
    let chiplets: &ChipletCols<_> = row.as_slice().borrow();
    chiplets.library()
}

fn cols_mut(row: &mut [Felt; NUM_CHIPLETS_COLS]) -> &mut LibraryCols<Felt> {
    row[1..23].borrow_mut()
}

fn fractions(rows: &[[Felt; NUM_CHIPLETS_COLS]; 2]) -> LookupFractions<Felt, QuadFelt> {
    let trace = RowMajorMatrix::new(rows.as_flattened().to_vec(), NUM_CHIPLETS_COLS);
    build_lookup_fractions(
        &LibraryLookupAir,
        &trace,
        None,
        &[vec![Felt::ZERO, Felt::ONE]],
        &challenges(),
    )
}

fn at(fractions: &LookupFractions<Felt, QuadFelt>, row: usize) -> &[(Felt, QuadFelt)] {
    let index = row * SHAPE.len() + 1;
    let offset = fractions.counts()[..index].iter().sum::<usize>();
    &fractions.fractions()[offset..offset + fractions.counts()[index]]
}

fn compression_denominator(local: &LibraryCols<Felt>, input: [Felt; 4]) -> QuadFelt {
    let mut payload = [Felt::ZERO; 16];
    payload[..4].copy_from_slice(&local.x);
    payload[4..8].copy_from_slice(&local.y);
    payload[8..12].copy_from_slice(&input);
    payload[12..].copy_from_slice(&local.z);
    challenges().encode(BusId::HasherCompressionLink as usize, payload)
}

fn fixed_input(tag: Felt) -> [Felt; 4] {
    initial_cv_from_frame([tag, Felt::from_u8(8), Felt::ZERO, Felt::ZERO])
}

fn open_denominator(depth: Felt, commitment: [Felt; 4], namespace: [Felt; 4]) -> QuadFelt {
    challenges().encode(
        BusId::LibraryOpen as usize,
        [
            depth,
            commitment[0],
            commitment[1],
            commitment[2],
            commitment[3],
            namespace[0],
            namespace[1],
            namespace[2],
            namespace[3],
        ],
    )
}

#[test]
fn library_headers_consume_unit_open_and_request_all_compressions() {
    for (kind, frame) in [
        (MERKLE, [Felt::ZERO; 4]),
        (ENV, felt_pair_frame(domain::domain_tag(domain::ENV_ENVIRONMENT))),
        (MAST, felt_pair_frame(domain::domain_tag(domain::ENV_MAST))),
    ] {
        let mut rows = [row(kind), row(PAD)];
        // These cells are not Open frequencies, even on a malformed row.
        cols_mut(&mut rows[0]).a = Felt::from_u8(23);
        cols_mut(&mut rows[0]).b = -Felt::ONE;
        let local = cols(&rows[0]);
        let actual = fractions(&rows);
        assert_eq!(
            at(&actual, 0),
            &[
                (-Felt::ONE, open_denominator(local.d, local.z, local.w)),
                (Felt::ONE, compression_denominator(local, initial_cv_from_frame(frame))),
            ]
        );
    }

    for kind in [LIST_START, LIST_CONTINUE, EMPTY_LIST] {
        let mut rows = [row(kind), row(kind)];
        cols_mut(&mut rows[1]).z = core::array::from_fn(|i| Felt::from_usize(500 + i));
        let local = cols(&rows[0]);
        let next = cols(&rows[1]);
        let actual = fractions(&rows);
        let mut expected = Vec::new();
        if kind != LIST_CONTINUE {
            expected.push((-Felt::ONE, open_denominator(local.d, local.z, local.w)));
        }
        expected.push((Felt::ONE, compression_denominator(local, next.z)));
        assert_eq!(at(&actual, 0), expected, "kind {kind:?}");
    }
}

#[test]
fn library_merkle_and_list_child_selections_are_positive_unit_events() {
    for kind in [MERKLE, LIST_START, LIST_CONTINUE] {
        for sigma in 0_u8..4 {
            let mut rows = [row(PAD), row(kind)];
            cols_mut(&mut rows[1]).a = Felt::from_u8(29);
            cols_mut(&mut rows[1]).b = Felt::from_u8(sigma);
            let local = cols(&rows[1]);
            let actual = fractions(&rows);
            let mut expected = Vec::new();
            if sigma & 1 != 0 {
                expected.push((Felt::ONE, open_denominator(local.d + Felt::ONE, local.x, local.w)));
            }
            if sigma & 2 != 0 {
                expected.push((Felt::ONE, open_denominator(local.d + Felt::ONE, local.y, local.w)));
            }
            assert_eq!(at(&actual, 1), expected, "kind {kind:?}, sigma {sigma}");
        }
    }
}

#[test]
fn library_env_b_requests_namespace_compression_and_supplies_one_child() {
    let rows = [row(PAD), row(ENV)];
    let local = cols(&rows[1]);
    let actual = fractions(&rows);
    assert_eq!(
        at(&actual, 1),
        &[
            (
                Felt::ONE,
                compression_denominator(
                    local,
                    fixed_input(domain::domain_tag(domain::ENV_NAMESPACE))
                )
            ),
            (Felt::ONE, open_denominator(local.d + Felt::ONE, local.w, local.z)),
        ]
    );
}

#[test]
fn library_mast_b_emits_three_simultaneous_fractions_with_independent_frequencies() {
    let mut rows = [row(PAD), row(MAST)];
    cols_mut(&mut rows[1]).a = Felt::from_u8(5);
    cols_mut(&mut rows[1]).b = Felt::from_u8(7);
    let local = cols(&rows[1]);
    let normal = LibraryResolveMsg {
        requires_syscall: Felt::ZERO,
        key: local.z,
        implementation: local.w,
    }
    .encode(&challenges());
    let syscall = LibraryResolveMsg {
        requires_syscall: Felt::ONE,
        key: local.z,
        implementation: local.w,
    }
    .encode(&challenges());
    let actual = fractions(&rows);
    assert_eq!(MAX_INTERACTIONS_PER_ROW, 3);
    assert_eq!(
        at(&actual, 1),
        &[
            (
                Felt::ONE,
                compression_denominator(
                    local,
                    fixed_input(domain::domain_tag(domain::ENV_PROCEDURE))
                )
            ),
            (Felt::from_u8(5), normal),
            (Felt::from_u8(7), syscall),
        ]
    );
    assert_ne!(normal, syscall);

    // Resolve permits arbitrary field frequencies; Open provenance does not use these cells.
    cols_mut(&mut rows[1]).a = -Felt::from_u8(3);
    let actual = fractions(&rows);
    assert_eq!(at(&actual, 1)[1], (-Felt::from_u8(3), normal));

    cols_mut(&mut rows[1]).a = Felt::ZERO;
    cols_mut(&mut rows[1]).b = Felt::ZERO;
    let actual = fractions(&rows);
    assert_eq!(at(&actual, 1).len(), 1, "zero-use Mast still requests its key compression");
}

#[test]
fn library_scope_pad_and_empty_b_emit_no_interactions() {
    for kind in [MERKLE, ENV, MAST, LIST_START, LIST_CONTINUE, EMPTY_LIST] {
        let mut rows = [row(kind), row(kind)];
        rows[0][0] = Felt::ZERO;
        rows[1][0] = Felt::ZERO;
        assert!(fractions(&rows).fractions().is_empty(), "kind {kind:?}");
    }
    let rows = [row(PAD), row(EMPTY_LIST)];
    assert!(fractions(&rows).fractions().is_empty());
}

#[test]
fn library_messages_preserve_nine_slot_payloads_and_global_width() {
    let values = row(MAST);
    let local = cols(&values);
    let open = LibraryOpenMsg {
        depth: local.d,
        commitment: local.z,
        namespace: local.w,
    };
    assert_eq!(open.encode(&challenges()), open_denominator(local.d, local.z, local.w));
    for requires_syscall in [Felt::ZERO, Felt::ONE] {
        let resolve = LibraryResolveMsg {
            requires_syscall,
            key: local.z,
            implementation: local.w,
        };
        assert_eq!(
            resolve.encode(&challenges()),
            challenges().encode(
                BusId::LibraryResolve as usize,
                [
                    requires_syscall,
                    local.z[0],
                    local.z[1],
                    local.z[2],
                    local.z[3],
                    local.w[0],
                    local.w[1],
                    local.w[2],
                    local.w[3],
                ]
            )
        );
        assert_ne!(open.encode(&challenges()), resolve.encode(&challenges()));
    }
    assert_eq!(MIDEN_MAX_MESSAGE_WIDTH, 16);
    assert_eq!(BusId::LibraryOpen as usize, 39);
    assert_eq!(BusId::LibraryResolve as usize, 40);
    assert_eq!(BusId::COUNT, 41);
}

struct SeedCollector(Vec<(Felt, QuadFelt)>);

impl BoundaryBuilder for SeedCollector {
    type F = Felt;
    type EF = QuadFelt;

    fn var_len_public_inputs(&self) -> &[&[Felt]] {
        panic!("Library Open seed must use its explicitly supplied public root");
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, msg: M)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.0.push((multiplicity, msg.encode(&challenges())));
    }
}

#[test]
fn library_open_seed_uses_explicit_root_and_canonical_initial_namespace() {
    let root = core::array::from_fn(|i| Felt::from_usize(700 + i));
    let namespace = Namespace::initial().into_word();
    let mut boundary = SeedCollector(Vec::new());
    emit_open_seed(&mut boundary, root);
    assert_eq!(
        boundary.0,
        vec![(
            Felt::ONE,
            open_denominator(Felt::ZERO, root, core::array::from_fn(|i| namespace[i]))
        )]
    );
    let mut different = SeedCollector(Vec::new());
    let mut changed_root = root;
    changed_root[3] += Felt::ONE;
    emit_open_seed(&mut different, changed_root);
    assert_ne!(boundary.0, different.0);
}

#[cfg(feature = "std")]
#[test]
fn library_actual_emitter_metadata_and_lookup_constraints_have_degree_at_most_nine() {
    use miden_stark::{
        air::symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpr},
        lookup::{
            ConstraintLookupBuilder,
            debug::{ValidateLayout, ValidateLookupAir},
        },
    };

    LibraryLookupAir
        .validate(ValidateLayout {
            preprocessed_width: 0,
            trace_width: NUM_CHIPLETS_COLS,
            num_public_values: 0,
            num_periodic_columns: 1,
            permutation_width: SHAPE.len(),
            num_permutation_challenges: 2,
            num_permutation_values: 1,
        })
        .unwrap_or_else(|err| panic!("Library lookup metadata validation failed: {err}"));

    let mut symbolic = SymbolicAirBuilder::<Felt, QuadFelt>::new(AirLayout {
        preprocessed_width: 0,
        main_width: NUM_CHIPLETS_COLS,
        num_public_values: 0,
        num_periodic_columns: 1,
        permutation_width: SHAPE.len(),
        num_permutation_challenges: 2,
        num_permutation_values: 1,
    });
    let mut builder = ConstraintLookupBuilder::new(&mut symbolic, &LibraryLookupAir);
    LibraryLookupAir.eval(&mut builder);
    builder.finish();
    let degrees: Vec<_> = symbolic
        .extension_constraints()
        .iter()
        .map(SymbolicExpr::degree_multiple)
        .collect();
    assert_eq!(degrees.iter().copied().max(), Some(9));
    assert!(degrees.iter().all(|degree| *degree <= 9), "{degrees:?}");
}
