use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_air_definitions::vm::trace::chiplets::library::PAD;
use miden_core::program::{CanonicalLabel, ExecutionTarget, ImplementationRoot, LabelCommitment};

use super::*;
use crate::{
    environment::{
        InvocationTag, LedgerLimits, OpeningLimits, OpeningStep, ResolutionWitness,
        ResolvedBinding, SessionError, SessionLimits, SessionPhase,
    },
    trace::RowIndex,
};

#[test]
fn root_export_remains_syscall_eligible_beneath_list_and_merkle_grouping() {
    let leaf = mast("kernel_service", 40);
    let merkle = EnvNode::Merkle {
        left: commitment(&leaf),
        right: EnvironmentRoot::new(Word::default()),
    };
    let list = EnvNode::List(vec![commitment(&merkle)]);
    let resolved = binding(vec![step(&list, Some(0)), step(&merkle, Some(0)), step(&leaf, None)]);
    assert_eq!(resolved.namespace(), Namespace::initial());
    assert_ne!(resolved.namespace().into_word(), Word::default());
    let key = resolved.procedure_key();
    let implementation = resolved.implementation_root();
    let mut session = new_session(&resolved);
    session.prepare_entry(resolved).unwrap().commit();
    session.prepare_cached(key, InvocationTag::Syscall, row(1)).unwrap().commit();
    session.prepare_root_end(implementation, row(2)).unwrap().commit();
    let trace = LibraryTrace::new(&session).unwrap();
    let (cells, _) = materialize(&trace);
    assert_eq!(cols(&cells, 4).k, MAST);
    assert_eq!(cols(&cells, 4).w, Namespace::initial().into_word().into_elements());
    assert_eq!((cols(&cells, 5).a, cols(&cells, 5).b), (ONE, ONE));
}

#[test]
fn completed_nested_session_maps_occurrences_and_frequencies_to_exact_packed_rows() {
    let entry = mast("entry", 40);
    let alias = mast("alias", 40);
    let other = mast("other", 80);
    let merkle = EnvNode::Merkle {
        left: commitment(&entry),
        right: commitment(&alias),
    };
    let nested_list =
        EnvNode::List(vec![commitment(&other), EnvironmentRoot::new(Word::default())]);
    let nested = env("nested", &nested_list);
    let list = EnvNode::List(vec![
        commitment(&merkle),
        commitment(&nested),
        EnvironmentRoot::new(Word::default()),
    ]);
    let root = env("runtime", &list);
    let entry_path = vec![
        step(&root, Some(0)),
        step(&list, Some(0)),
        step(&merkle, Some(0)),
        step(&entry, None),
    ];
    let alias_path = vec![
        step(&root, Some(0)),
        step(&list, Some(0)),
        step(&merkle, Some(1)),
        step(&alias, None),
    ];
    let other_path = vec![
        step(&root, Some(0)),
        step(&list, Some(1)),
        step(&nested, Some(0)),
        step(&nested_list, Some(0)),
        step(&other, None),
    ];
    let namespace = Namespace::initial().child(label("runtime"));
    let entry_binding = binding(entry_path);
    let entry_key = entry_binding.procedure_key();
    let implementation = entry_binding.implementation_root();
    let mut session = new_session(&entry_binding);
    session.prepare_entry(entry_binding).unwrap().commit();
    session
        .prepare_cached(entry_key, InvocationTag::Normal, row(2))
        .unwrap()
        .commit();
    session
        .prepare_cached(entry_key, InvocationTag::Normal, row(3))
        .unwrap()
        .commit();
    session
        .prepare(
            entry_key,
            binding(vec![
                step(&root, Some(0)),
                step(&list, Some(0)),
                step(&merkle, Some(0)),
                step(&entry, None),
            ]),
            InvocationTag::Normal,
            row(4),
        )
        .unwrap()
        .commit();
    let alias_binding = binding(alias_path);
    let alias_key = alias_binding.procedure_key();
    assert_ne!(entry_key, alias_key);
    assert_eq!(alias_binding.implementation_root(), implementation);
    session
        .prepare(alias_key, alias_binding, InvocationTag::Normal, row(5))
        .unwrap()
        .commit();
    session
        .prepare_cached(alias_key, InvocationTag::Normal, row(6))
        .unwrap()
        .commit();
    let other_binding = binding(other_path);
    let other_key = other_binding.procedure_key();
    session
        .prepare(other_key, other_binding, InvocationTag::Normal, row(7))
        .unwrap()
        .commit();
    session.prepare_root_end(implementation, row(9)).unwrap().commit();

    let trace = LibraryTrace::new(&session).unwrap();
    assert_eq!(trace.prefix_len(), 24);
    assert_eq!(session.ledger().counters().library_rows, 18);
    assert_eq!(session.counters().committed_requests, 7);
    let (cells, requests) = materialize(&trace);
    assert_prefix(&cells, 18);
    assert_eq!(requests.len(), 14);
    assert_eq!(requests.len(), session.ledger().counters().compression_requests);
    let kinds = [ENV, LIST_START, LIST_CONTINUE, MERKLE, MAST, MAST, ENV, LIST_START, MAST];
    for (pair, kind) in kinds.into_iter().enumerate() {
        assert_eq!(cols(&cells, pair * 2).k, kind);
        assert_eq!(cols(&cells, pair * 2 + 1).k, kind);
    }
    // The root Env extends the namespace once; collection nodes preserve all four coordinates.
    assert_eq!(cols(&cells, 0).w, Namespace::initial().into_word().into_elements());
    assert_eq!(cols(&cells, 1).z, namespace.into_word().into_elements());
    assert_eq!(cols(&cells, 1).w, commitment(&list).into_word().into_elements());
    assert_eq!(cols(&cells, 2).w, namespace.into_word().into_elements());
    assert_eq!(cols(&cells, 2).d, Felt::from_u8(1));
    assert_eq!(cols(&cells, 2).a, Felt::from_u8(4));
    assert_eq!(cols(&cells, 2).b, ONE);
    assert_eq!(cols(&cells, 3).b, ZERO);
    assert_eq!(cols(&cells, 5).b, Felt::from_u8(3));
    assert_eq!(cols(&cells, 7).b, Felt::from_u8(3));
    assert_eq!(cols(&cells, 7).z, [ZERO; 4]);
    assert_eq!(cols(&cells, 9).z, entry_key.into_word().into_elements());
    assert_eq!(cols(&cells, 9).w, implementation.into_word().into_elements());
    assert_eq!((cols(&cells, 9).a, cols(&cells, 9).b), (Felt::from_u8(4), ZERO));
    assert_eq!(cols(&cells, 11).z, alias_key.into_word().into_elements());
    assert_eq!((cols(&cells, 11).a, cols(&cells, 11).b), (Felt::from_u8(2), ZERO));
    assert_eq!(cols(&cells, 15).y, [ZERO; 4]); // A real, unselected high child.
    assert_eq!(cols(&cells, 15).b, ONE);
    assert_eq!(cols(&cells, 17).z, other_key.into_word().into_elements());
    assert_eq!((cols(&cells, 17).a, cols(&cells, 17).b), (ONE, ZERO));

    let mut expected = Vec::new();
    for (index, occurrence) in session.ledger().occurrences().iter().enumerate() {
        let physical = [0, 2, 6, 8, 10, 12, 14, 16][index];
        assert_object_requests(&mut expected, occurrence, &cells, physical);
    }
    assert_eq!(requests, expected);
    assert_walk_matches_materialization(
        &trace,
        &cells,
        &requests,
        &[0, 4, 2, 6, 8, 10, 12, 14, 16],
    );
    assert_eq!(session.phase(), SessionPhase::Completed);
    assert_eq!(session.counters().committed_requests, 7);
}

#[test]
fn odd_even_and_multiblock_lists_include_every_child_and_reverse_complete_cvs() {
    for n in 1..=6 {
        let leaf = mast("entry", 40);
        let selected = if n == 1 { 0 } else { n - 2 };
        let mut children = vec![EnvironmentRoot::new(Word::default()); n];
        // Nonzero opaque siblings and real zero children both remain in the complete payload.
        for (slot, child) in children.iter_mut().enumerate() {
            if slot % 2 == 0 && slot + 1 != n {
                *child = EnvironmentRoot::new(word(100 + slot as u32));
            }
        }
        children[selected] = commitment(&leaf);
        let list = EnvNode::List(children.clone());
        let resolved = binding(vec![step(&list, Some(selected)), step(&leaf, None)]);
        let implementation = resolved.implementation_root();
        let mut session = new_session(&resolved);
        session.prepare_entry(resolved).unwrap().commit();
        session.prepare_root_end(implementation, row(1)).unwrap().commit();
        let trace = LibraryTrace::new(&session).unwrap();
        let (cells, requests) = materialize(&trace);
        let pairs = n.div_ceil(2);
        assert_eq!(session.ledger().counters().library_rows, 2 * pairs + 2);
        assert_eq!(requests.len(), pairs + 2);
        assert_prefix(&cells, 2 * pairs + 2);
        let offsets: Vec<_> = (0..pairs).rev().map(|pair| 2 * pair).chain([2 * pairs]).collect();
        assert_walk_matches_materialization(&trace, &cells, &requests, &offsets);
        let mut cv = Eidos::init_chaining_word(domain::ENV_LIST, (4 * n) as u32);
        for block in 0..pairs {
            let reverse = pairs - block - 1;
            let a = cols(&cells, 2 * reverse);
            let b = cols(&cells, 2 * reverse + 1);
            let x = children[2 * block].into_word();
            let y = children.get(2 * block + 1).map_or(Word::default(), |child| child.into_word());
            assert_eq!(requests[block], state(x, y, cv));
            let output =
                Eidos::compress(cv, core::array::from_fn(|i| if i < 4 { x[i] } else { y[i - 4] }));
            assert_eq!(a.x, x.into_elements());
            assert_eq!(a.y, y.into_elements());
            assert_eq!(a.z, output.into_elements());
            assert_eq!(b.z, cv.into_elements());
            assert_eq!(a.k, if reverse == 0 { LIST_START } else { LIST_CONTINUE });
            assert_eq!(b.k, a.k);
            assert_eq!(a.a, Felt::from_u32((8 * (reverse + 1) - 4 * (n % 2)) as u32));
            assert_eq!(b.a, a.a);
            assert_eq!(
                a.b,
                if reverse == 0 {
                    Felt::from_u8((n % 2) as u8)
                } else {
                    ZERO
                }
            );
            assert_eq!(
                b.b,
                Felt::from_u8(
                    u8::from(selected == 2 * block) + 2 * u8::from(selected == 2 * block + 1)
                )
            );
            cv = output;
        }
        assert_eq!(cols(&cells, 0).z, commitment(&list).into_word().into_elements());
        assert_eq!(cv, commitment(&list).into_word());
        assert_eq!(
            cols(&cells, 2 * pairs - 1).z,
            Eidos::init_chaining_word(domain::ENV_LIST, (4 * n) as u32).into_elements()
        );
        if n > 1 {
            let last_child = if n % 2 == 1 {
                cols(&cells, 0).x
            } else {
                cols(&cells, 0).y
            };
            assert_eq!(last_child, [ZERO; 4]);
        }
    }
}

#[test]
fn empty_list_helper_preserves_the_distinct_empty_frame_without_a_second_ledger_path() {
    let mut rows = [ZERO; 2 * CHIPLETS_WIDTH];
    let mut captured = Vec::new();
    let mut callback = |request: &[Felt; STATE_WIDTH]| {
        captured.push(*request);
        Ok(())
    };
    let mut requests = Requests {
        callback: &mut callback,
        count: 0,
        limit: 1,
    };
    let namespace = Namespace::initial();
    let mut emitted = 0;
    visit_list(
        &[],
        &[],
        namespace,
        3,
        commitment(&EnvNode::List(vec![])),
        &mut requests,
        &mut |offset, pair| {
            assert_eq!(offset, 0);
            rows.copy_from_slice(pair);
            emitted += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(requests.count, 1);
    assert_eq!(emitted, 1);
    assert_eq!(cols(&rows, 0).k, EMPTY_LIST);
    assert_eq!(cols(&rows, 1).k, EMPTY_LIST);
    for index in 0..2 {
        let row = cols(&rows, index);
        assert_eq!((row.x, row.y), ([ZERO; 4], [ZERO; 4]));
        assert_eq!((row.a, row.b), (ZERO, ZERO));
        assert_eq!(row.w, namespace.into_word().into_elements());
        assert_eq!(row.d, Felt::from_u8(3));
    }
    assert_eq!(cols(&rows, 1).z, Eidos::init_chaining_word(domain::ENV_LIST, 0).into_elements());
    assert_eq!(
        captured,
        vec![state(
            Word::default(),
            Word::default(),
            Eidos::init_chaining_word(domain::ENV_LIST, 0)
        )]
    );
}

#[test]
fn phase_size_and_callback_failures_do_not_mutate_the_native_authority() {
    let leaf = mast("entry", 40);
    let resolved = binding(vec![step(&leaf, None)]);
    let implementation = resolved.implementation_root();
    let mut session = new_session(&resolved);
    assert!(matches!(
        LibraryTrace::new(&session),
        Err(ExecutionError::EnvironmentSession(SessionError::InvalidPhase {
            actual: SessionPhase::Unentered,
            ..
        }))
    ));
    session.prepare_entry(resolved).unwrap().commit();
    assert!(matches!(
        LibraryTrace::new(&session),
        Err(ExecutionError::EnvironmentSession(SessionError::InvalidPhase {
            actual: SessionPhase::PendingEntry,
            ..
        }))
    ));
    session.prepare_root_end(implementation, row(2)).unwrap().commit();
    let trace = LibraryTrace::new(&session).unwrap();
    let counters = session.counters();
    for size in [0, trace.prefix_cells() - 1, trace.prefix_cells() + 1] {
        let mut destination = vec![ONE; size];
        let result = trace.write(&mut destination);
        assert!(matches!(result, Err(ExecutionError::Internal(_))));
        assert_eq!(destination, vec![ONE; size]);
    }
    for stop in 1..=2 {
        let mut calls = 0;
        let result = trace.visit_compression_requests(|_| {
            calls += 1;
            if calls == stop {
                Err(ExecutionError::Internal("callback stopped"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(ExecutionError::Internal("callback stopped"))));
        assert_eq!(calls, stop);
        assert_eq!(session.counters(), counters);
    }
    let mut requests = 0;
    let mut pairs = 0;
    let result = trace.walk(
        |offset, _| {
            assert_eq!(offset, 0);
            pairs += 1;
            Err(ExecutionError::Internal("pair stopped"))
        },
        |_| {
            requests += 1;
            Ok(())
        },
    );
    assert!(matches!(result, Err(ExecutionError::Internal("pair stopped"))));
    assert_eq!((pairs, requests), (1, 2));
    assert_eq!(session.counters(), counters);
    let (retry, requests) = materialize(&trace);
    assert_prefix(&retry, 2);
    assert_eq!(requests.len(), 2);
}

#[test]
fn pre_admission_needs_only_a_fixed_request_sink_and_write_does_not_register_again() {
    let leaf = mast("entry", 40);
    let resolved = binding(vec![step(&leaf, None)]);
    let implementation = resolved.implementation_root();
    let key = resolved.procedure_key();
    let mut session = new_session(&resolved);
    session.prepare_entry(resolved).unwrap().commit();
    session.prepare_root_end(implementation, row(1)).unwrap().commit();
    let counters = session.counters();
    let trace = LibraryTrace::new(&session).unwrap();
    // No prefix or growable request storage exists during pre-admission.
    let mut requests = [[ZERO; STATE_WIDTH]; 2];
    let mut registered = 0;
    trace
        .visit_compression_requests(|state| {
            requests[registered] = *state;
            registered += 1;
            Ok(())
        })
        .unwrap();
    let EnvNode::Mast { label, .. } = leaf else {
        unreachable!()
    };
    assert_eq!(registered, 2);
    assert_eq!(
        requests,
        [
            state(
                label.into_word(),
                implementation.into_word(),
                Eidos::init_chaining_word(domain::ENV_MAST, 8),
            ),
            state(
                Namespace::initial().into_word(),
                label.into_word(),
                Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8),
            ),
        ]
    );
    let mut destination = vec![ONE; trace.prefix_cells()];
    trace.write(&mut destination).unwrap();
    assert_eq!(registered, session.ledger().counters().compression_requests);
    assert_eq!(cols(&destination, 1).z, key.into_word().into_elements());
    assert_prefix(&destination, 2);
    assert_eq!(session.counters(), counters);
}

#[test]
fn compression_request_limit_stops_before_the_callback_and_uses_checked_counts() {
    let mut calls = 0;
    let mut callback = |_: &[Felt; STATE_WIDTH]| {
        calls += 1;
        Ok(())
    };
    let mut requests = Requests {
        callback: &mut callback,
        count: 0,
        limit: 1,
    };
    requests.compress(Word::default(), Word::default(), Word::default()).unwrap();
    assert!(matches!(
        requests.compress(Word::default(), Word::default(), Word::default()),
        Err(ExecutionError::Internal(_))
    ));
    assert_eq!(requests.count, 1);
    requests.count = usize::MAX;
    assert!(matches!(
        requests.compress(Word::default(), Word::default(), Word::default()),
        Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))
    ));
    assert_eq!(calls, 1);
}

#[test]
fn padding_and_integer_ceilings_are_checked_without_large_allocations() {
    for (active, prefix) in [
        (0, 8),
        (2, 8),
        (6, 8),
        (8, 16),
        (14, 16),
        (16, 24),
        (MAX_TRACE_LEN - 2, MAX_TRACE_LEN),
    ] {
        assert_eq!(checked_prefix_len(active).unwrap(), prefix);
    }
    for active in [MAX_TRACE_LEN, MAX_TRACE_LEN + 2, usize::MAX - 1, usize::MAX] {
        assert!(checked_prefix_len(active).is_err());
    }
    assert!(checked_prefix_len(1).is_err());
    assert_eq!(bounded_felt(MAX_TRACE_LEN).unwrap().as_canonical_u64(), MAX_TRACE_LEN as u64);
    assert!(bounded_felt(MAX_TRACE_LEN + 1).is_err());
}

fn assert_object_requests(
    expected: &mut Vec<[Felt; STATE_WIDTH]>,
    occurrence: &OpeningOccurrence,
    cells: &[Felt],
    physical: usize,
) {
    let a = cols(cells, physical);
    let b = cols(cells, physical + 1);
    let x = Word::new(a.x);
    let y = Word::new(a.y);
    match occurrence.node() {
        EnvNode::Env { .. } => {
            expected.push(state(x, y, Eidos::init_chaining_word(domain::ENV_ENVIRONMENT, 8)));
            expected.push(state(
                Word::new(b.x),
                Word::new(b.y),
                Eidos::init_chaining_word(domain::ENV_NAMESPACE, 8),
            ));
        },
        EnvNode::Mast { .. } => {
            expected.push(state(x, y, Eidos::init_chaining_word(domain::ENV_MAST, 8)));
            expected.push(state(
                Word::new(b.x),
                Word::new(b.y),
                Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8),
            ));
        },
        EnvNode::Merkle { .. } => {
            expected.push(state(x, y, Eidos::init_chaining_word(domain::ENV_MERKLE, 8)))
        },
        EnvNode::List(children) => {
            let pairs = children.len().div_ceil(2);
            for block in (0..pairs).rev() {
                let a = cols(cells, physical + 2 * block);
                let b = cols(cells, physical + 2 * block + 1);
                expected.push(state(Word::new(a.x), Word::new(a.y), Word::new(b.z)));
            }
        },
        EnvNode::Data { .. } => panic!("Data cannot be retained"),
    }
}

fn assert_prefix(cells: &[Felt], active: usize) {
    assert_eq!(cells.len() % (8 * CHIPLETS_WIDTH), 0);
    assert!(cells.len() / CHIPLETS_WIDTH >= active + 2);
    for (index, row) in cells.as_chunks::<CHIPLETS_WIDTH>().0.iter().enumerate() {
        assert_eq!(row[0], ONE);
        assert_eq!(row[CHIPLETS_CLK_COL], Felt::from_u32(index as u32 + 1));
        if index >= active {
            assert_eq!(cols(cells, index).k, PAD);
            assert!(row[LIBRARY_COL_RANGE].iter().all(|value| *value == ZERO));
        }
    }
    assert_eq!((cells.len() / CHIPLETS_WIDTH - 1) % 8, 7);
}

fn materialize(trace: &LibraryTrace<'_>) -> (Vec<Felt>, Vec<[Felt; STATE_WIDTH]>) {
    let mut requests = Vec::new();
    trace
        .visit_compression_requests(|state| {
            requests.push(*state);
            Ok(())
        })
        .unwrap();
    let mut cells = vec![ONE; trace.prefix_cells()];
    trace.write(&mut cells).unwrap();
    (cells, requests)
}

fn assert_walk_matches_materialization(
    trace: &LibraryTrace<'_>,
    cells: &[Felt],
    expected_requests: &[[Felt; STATE_WIDTH]],
    expected_offsets: &[usize],
) {
    let mut requests = Vec::new();
    let mut emitted = vec![false; trace.session.ledger().counters().library_rows / 2];
    let mut pairs = 0;
    trace
        .walk(
            |offset, pair| {
                assert_eq!(offset, expected_offsets[pairs]);
                assert_eq!(offset % 2, 0);
                assert!(!emitted[offset / 2]);
                emitted[offset / 2] = true;
                for phase in 0..2 {
                    let source = &pair[phase * CHIPLETS_WIDTH..(phase + 1) * CHIPLETS_WIDTH];
                    let destination = &cells
                        [(offset + phase) * CHIPLETS_WIDTH..(offset + phase + 1) * CHIPLETS_WIDTH];
                    assert_eq!(source[LIBRARY_COL_RANGE], destination[LIBRARY_COL_RANGE]);
                    assert_eq!((source[0], source[CHIPLETS_CLK_COL]), (ZERO, ZERO));
                }
                pairs += 1;
                Ok(())
            },
            |state| {
                requests.push(*state);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(pairs, expected_offsets.len());
    assert!(emitted.into_iter().all(|emitted| emitted));
    assert_eq!(requests, expected_requests);
}

fn cols(cells: &[Felt], row: usize) -> &LibraryCols<Felt> {
    cells[row * CHIPLETS_WIDTH..(row + 1) * CHIPLETS_WIDTH][LIBRARY_COL_RANGE].borrow()
}

fn state(x: Word, y: Word, cv: Word) -> [Felt; STATE_WIDTH] {
    let mut result = [ZERO; STATE_WIDTH];
    result[BLOCK_LO_RANGE].copy_from_slice(x.as_slice());
    result[BLOCK_HI_RANGE].copy_from_slice(y.as_slice());
    result[CV_RANGE].copy_from_slice(cv.as_slice());
    result
}

fn binding(path: Vec<OpeningStep>) -> ResolvedBinding {
    let root = commitment(&path[0].node);
    let mut namespace = Namespace::initial();
    for opening in &path {
        if let EnvNode::Env { label, .. } = &opening.node {
            namespace = namespace.child(*label);
        }
    }
    let EnvNode::Mast { label, .. } = &path.last().unwrap().node else {
        panic!("Mast terminal required")
    };
    let key = namespace.procedure_key(*label);
    ResolutionWitness { path }
        .verify(
            root,
            key,
            OpeningLimits {
                max_nodes: 32,
                max_depth: 31,
                max_list_children: 32,
                max_total_list_children: 128,
                max_encoded_bytes: 32_000,
                max_storage_bytes: 128_000,
            },
        )
        .unwrap()
}

fn new_session(binding: &ResolvedBinding) -> ResolutionSession {
    ResolutionSession::new(
        ExecutionTarget::new(binding.procedure_key(), binding.environment_root()),
        LedgerLimits {
            max_occurrences: 128,
            max_total_list_children: 256,
            max_encoded_bytes: 128_000,
            max_library_rows: 512,
            max_compression_requests: 512,
            max_retained_bytes: 256_000,
            max_peak_bytes: 512_000,
        },
        SessionLimits {
            max_cached_keys: 32,
            max_requests: 128,
            max_retained_bytes: 512_000,
            max_prepare_peak_bytes: 1_000_000,
        },
    )
}

fn step(node: &EnvNode, selected_child: Option<usize>) -> OpeningStep {
    OpeningStep { node: node.clone(), selected_child }
}

fn commitment(node: &EnvNode) -> EnvironmentRoot {
    node.commitment().unwrap()
}

fn mast(name: &str, seed: u32) -> EnvNode {
    EnvNode::Mast {
        label: label(name),
        implementation: ImplementationRoot::new(word(seed)),
    }
}

fn env(name: &str, child: &EnvNode) -> EnvNode {
    EnvNode::Env {
        label: label(name),
        child: commitment(child),
    }
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn word(seed: u32) -> Word {
    Word::new(core::array::from_fn(|i| Felt::from_u32(seed + i as u32)))
}

fn row(index: usize) -> RowIndex {
    index.into()
}
