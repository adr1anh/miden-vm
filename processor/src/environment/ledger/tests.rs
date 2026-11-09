use alloc::vec::Vec;

use miden_core::{
    Felt, Word,
    program::{CanonicalLabel, ImplementationRoot, LabelCommitment, ProcedureKey},
};

use super::*;
use crate::environment::{OpeningLimits, ResolutionWitness};

#[test]
fn empty_ledger_has_no_root_seed_or_selected_edges() {
    let expected_root = root(100);
    let limits = generous_limits();
    let ledger = OpeningLedger::new(expected_root, limits);
    assert_eq!(ledger.expected_root(), expected_root);
    assert_eq!(ledger.limits(), limits);
    assert_eq!(ledger.root(), None);
    assert!(ledger.occurrences().is_empty());
    assert_eq!(ledger.counters(), empty_counters());
    assert_eq!(ledger.counters().root_seed_count(), 0);
    assert_eq!(ledger.counters().selected_edge_count(), 0);
}

#[test]
fn root_mast_has_exact_preimage_and_one_seed_without_an_incoming_edge() {
    let fixture = direct("entry", 40);
    let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
    let prepared = ledger.prepare(fixture.binding()).unwrap();
    assert_eq!(prepared.opening_id().index(), 0);
    assert_eq!(prepared.counters().occurrences, 1);
    assert_eq!(prepared.counters().library_rows, 2);
    assert_eq!(prepared.counters().compression_requests, 1);
    assert_eq!(prepared.commit().index(), 0);
    assert_eq!(ledger.root().unwrap().index(), 0);
    assert_eq!(assert_path(&ledger, &fixture).index(), 0);
    assert_eq!(ledger.occurrences()[0].parent(), None);
    assert!(ledger.occurrences()[0].selected_children().is_empty());
    assert_topology(&ledger);
}

#[test]
fn mixed_path_retains_canonical_preimages_and_full_inherited_namespaces() {
    let fixture = nested();
    let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
    ledger.prepare(fixture.binding()).unwrap().commit();
    let terminal = assert_path(&ledger, &fixture);
    assert_eq!(terminal.index(), 4);
    assert_eq!(
        ledger.occurrence(terminal).unwrap().namespace(),
        Namespace::initial().child(label("runtime")).child(label("kernel")),
    );
    let counters = ledger.counters();
    // Env + Merkle + three-child List + Env + Mast: 2+2+4+2+2 rows.
    assert_eq!(counters.library_rows, 12);
    assert_eq!(counters.compression_requests, 2 + 1 + 2 + 2 + 2);
    assert_eq!(counters.total_list_children, 3);
    assert_eq!(counters.encoded_bytes, fixture.encoded_bytes());
    assert_eq!(counters.retained_bytes, retained_storage(&ledger));
    assert_topology(&ledger);
}

#[test]
fn shared_prefix_extends_only_the_missing_slot_and_suffix() {
    let (first, second) = siblings();
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    let first_id = ledger.prepare(first.binding()).unwrap().commit();
    let old = ledger.counters();
    let prepared = ledger.prepare(second.binding()).unwrap();
    assert_eq!(prepared.counters().occurrences, old.occurrences + 1);
    assert_eq!(prepared.counters().library_rows, old.library_rows + 2);
    assert_eq!(prepared.counters().compression_requests, old.compression_requests + 2);
    assert_eq!(prepared.counters().total_list_children, old.total_list_children);
    let second_id = prepared.commit();
    assert_ne!(first_id, second_id);
    assert_eq!(assert_path(&ledger, &first), first_id);
    assert_eq!(assert_path(&ledger, &second), second_id);
    let list = &ledger.occurrences()[1];
    assert_eq!(list.selected_children(), &[Some(first_id), Some(second_id), None]);
    assert_topology(&ledger);
}

#[test]
fn exact_path_retry_reuses_identity_costs_edges_and_published_storage() {
    let fixture = nested();
    let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
    let id = ledger.prepare(fixture.binding()).unwrap().commit();
    let before = snapshot(&ledger);
    for _ in 0..3 {
        let prepared = ledger.prepare(fixture.binding()).unwrap();
        assert_eq!(prepared.opening_id(), id);
        assert_eq!(prepared.counters(), before.counters);
        assert_eq!(prepared.commit(), id);
        assert_eq!(snapshot(&ledger), before);
    }
    assert_topology(&ledger);
}

#[test]
fn equal_commitments_in_distinct_slots_keep_distinct_occurrences() {
    let leaf = mast("entry", 40);
    let list = EnvNode::List(vec![leaf.commitment().unwrap(); 2]);
    let first = Fixture::new(vec![step(list.clone(), Some(0)), step(leaf.clone(), None)]);
    let second = Fixture::new(vec![step(list, Some(1)), step(leaf, None)]);
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    let left = ledger.prepare(first.binding()).unwrap().commit();
    let right = ledger.prepare(second.binding()).unwrap().commit();
    assert_ne!(left, right);
    let left_node = ledger.occurrence(left).unwrap();
    let right_node = ledger.occurrence(right).unwrap();
    assert_eq!(left_node.node(), right_node.node());
    assert_eq!(left_node.commitment(), right_node.commitment());
    assert_eq!(left_node.namespace(), right_node.namespace());
    assert_eq!(left_node.depth(), right_node.depth());
    assert_eq!(left_node.parent().unwrap().child_slot(), 0);
    assert_eq!(right_node.parent().unwrap().child_slot(), 1);
    assert_eq!(ledger.counters().occurrences, 3);
    assert_eq!(ledger.counters().compression_requests, 1 + 1 + 1);
    assert_topology(&ledger);
}

#[test]
fn equal_leaf_commitments_under_distinct_parents_are_not_interned() {
    let leaf = mast("entry", 40);
    let left = EnvNode::Merkle {
        left: leaf.commitment().unwrap(),
        right: root(100),
    };
    let right = EnvNode::Merkle {
        left: leaf.commitment().unwrap(),
        right: root(200),
    };
    let list = EnvNode::List(vec![left.commitment().unwrap(), right.commitment().unwrap()]);
    let first = Fixture::new(vec![
        step(list.clone(), Some(0)),
        step(left, Some(0)),
        step(leaf.clone(), None),
    ]);
    let second = Fixture::new(vec![step(list, Some(1)), step(right, Some(0)), step(leaf, None)]);
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    let first_id = ledger.prepare(first.binding()).unwrap().commit();
    let second_id = ledger.prepare(second.binding()).unwrap().commit();
    let a = ledger.occurrence(first_id).unwrap();
    let b = ledger.occurrence(second_id).unwrap();
    assert_eq!(
        (a.commitment(), a.namespace(), a.depth()),
        (b.commitment(), b.namespace(), b.depth())
    );
    assert_ne!(a.parent().unwrap().opening(), b.parent().unwrap().opening());
    assert_ne!(first_id, second_id);
    assert_eq!(ledger.counters().occurrences, 5);
    assert_path(&ledger, &first);
    assert_path(&ledger, &second);
    assert_topology(&ledger);
}

#[test]
fn same_leaf_under_distinct_accumulated_namespaces_keeps_both_bindings() {
    let leaf = mast("entry", 40);
    let left = EnvNode::Env {
        label: label("left"),
        child: leaf.commitment().unwrap(),
    };
    let right = EnvNode::Env {
        label: label("right"),
        child: leaf.commitment().unwrap(),
    };
    let list = EnvNode::List(vec![left.commitment().unwrap(), right.commitment().unwrap()]);
    let first = Fixture::new(vec![
        step(list.clone(), Some(0)),
        step(left, Some(0)),
        step(leaf.clone(), None),
    ]);
    let second = Fixture::new(vec![step(list, Some(1)), step(right, Some(0)), step(leaf, None)]);
    assert_ne!(first.key, second.key);
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    let a = ledger.prepare(first.binding()).unwrap().commit();
    let b = ledger.prepare(second.binding()).unwrap().commit();
    assert_ne!(a, b);
    let a = ledger.occurrence(a).unwrap();
    let b = ledger.occurrence(b).unwrap();
    assert_eq!(a.commitment(), b.commitment());
    assert_ne!(a.namespace(), b.namespace());
    assert_eq!(a.namespace(), Namespace::initial().child(label("left")));
    assert_eq!(b.namespace(), Namespace::initial().child(label("right")));
    assert_path(&ledger, &first);
    assert_path(&ledger, &second);
    assert_topology(&ledger);
}

#[test]
fn complete_odd_and_even_lists_preserve_real_zero_and_unselected_slots() {
    for count in 1..=6 {
        let fixture = list_fixture(count, count - 1);
        let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
        let id = ledger.prepare(fixture.binding()).unwrap().commit();
        let list = &ledger.occurrences()[0];
        assert_eq!(list.node(), &fixture.path[0].node);
        assert_eq!(list.selected_children().len(), count);
        for (slot, selected) in list.selected_children().iter().enumerate() {
            assert_eq!(*selected, if slot == count - 1 { Some(id) } else { None });
        }
        let EnvNode::List(children) = list.node() else {
            unreachable!()
        };
        if count > 1 {
            assert_eq!(children[0], EnvironmentRoot::new(Word::default()));
            assert_eq!(list.selected_children()[0], None);
        }
        let pairs = (count / 2) + (count % 2);
        assert_eq!(ledger.counters().library_rows, 2 * pairs + 2);
        assert_eq!(ledger.counters().compression_requests, pairs + 1);
        assert_eq!(ledger.counters().total_list_children, count);
        assert_eq!(ledger.counters().encoded_bytes, fixture.encoded_bytes());
        assert_path(&ledger, &fixture);
        assert_topology(&ledger);
    }
}

#[test]
fn dropping_preparation_preserves_empty_and_existing_ledger_values_and_pointers() {
    let (first, second) = siblings();
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    let empty = snapshot(&ledger);
    {
        let prepared = ledger.prepare(first.binding()).unwrap();
        assert_eq!(prepared.counters().occurrences, 3);
    }
    assert_eq!(snapshot(&ledger), empty);
    ledger.prepare(first.binding()).unwrap().commit();
    let before = snapshot(&ledger);
    {
        let prepared = ledger.prepare(second.binding()).unwrap();
        assert_eq!(prepared.counters().occurrences, 4);
    }
    assert_eq!(snapshot(&ledger), before);
    ledger.prepare(second.binding()).unwrap().commit();
    assert_eq!(ledger.counters().occurrences, 4);
    assert_topology(&ledger);
}

#[test]
fn wrong_root_and_failed_suffix_admission_leave_every_published_allocation_unchanged() {
    let (first, second) = siblings();
    let mut limits = generous_limits();
    limits.max_occurrences = 3;
    let mut ledger = OpeningLedger::new(first.root, limits);
    ledger.prepare(first.binding()).unwrap().commit();
    let before = snapshot(&ledger);
    let other = direct("unrelated", 100);
    assert_eq!(
        ledger.prepare(other.binding()).unwrap_err(),
        LedgerError::WrongRoot { expected: first.root, actual: other.root },
    );
    assert_eq!(snapshot(&ledger), before);
    for _ in 0..2 {
        assert_eq!(
            ledger.prepare(second.binding()).unwrap_err(),
            LedgerError::LimitExceeded {
                resource: LedgerResource::Occurrences,
                limit: 3,
                requested: 4,
            },
        );
        assert_eq!(snapshot(&ledger), before);
    }
    let original_id = assert_path(&ledger, &first);
    assert_eq!(ledger.prepare(first.binding()).unwrap().commit(), original_id);
    assert_eq!(snapshot(&ledger), before);
}

#[test]
fn every_explicit_limit_accepts_exact_and_rejects_one_below_without_publication() {
    let fixture = nested();
    let mut probe = OpeningLedger::new(fixture.root, generous_limits());
    let prepared = probe.prepare(fixture.binding()).unwrap();
    let counters = prepared.counters();
    let peak = prepared.requested_peak_bytes();
    drop(prepared);
    let exact = LedgerLimits {
        max_occurrences: counters.occurrences,
        max_total_list_children: counters.total_list_children,
        max_encoded_bytes: counters.encoded_bytes,
        max_library_rows: counters.library_rows,
        max_compression_requests: counters.compression_requests,
        max_retained_bytes: counters.retained_bytes,
        max_peak_bytes: peak,
    };
    let mut accepted = OpeningLedger::new(fixture.root, exact);
    assert_eq!(accepted.prepare(fixture.binding()).unwrap().counters(), counters);
    assert_eq!(accepted.counters(), empty_counters());

    for (resource, requested) in [
        (LedgerResource::Occurrences, counters.occurrences),
        (LedgerResource::TotalListChildren, counters.total_list_children),
        (LedgerResource::EncodedBytes, counters.encoded_bytes),
        (LedgerResource::LibraryRows, counters.library_rows),
        (LedgerResource::CompressionRequests, counters.compression_requests),
        (LedgerResource::RetainedBytes, counters.retained_bytes),
        (LedgerResource::PeakBytes, peak),
    ] {
        let mut limits = exact;
        set_limit(&mut limits, resource, requested - 1);
        let mut ledger = OpeningLedger::new(fixture.root, limits);
        let before = snapshot(&ledger);
        assert_eq!(
            ledger.prepare(fixture.binding()).unwrap_err(),
            LedgerError::LimitExceeded {
                resource,
                limit: requested - 1,
                requested
            },
        );
        assert_eq!(snapshot(&ledger), before);
    }
}

#[test]
fn each_resource_failure_preserves_an_existing_root_and_its_unselected_slot() {
    let first_leaf = mast("first", 40);
    let second_leaf = mast("second", 80);
    let list = EnvNode::List(vec![root(100), root(200), second_leaf.commitment().unwrap()]);
    let merkle = EnvNode::Merkle {
        left: first_leaf.commitment().unwrap(),
        right: list.commitment().unwrap(),
    };
    let first = Fixture::new(vec![step(merkle.clone(), Some(0)), step(first_leaf, None)]);
    let second =
        Fixture::new(vec![step(merkle, Some(1)), step(list, Some(2)), step(second_leaf, None)]);
    let mut probe = OpeningLedger::new(first.root, generous_limits());
    probe.prepare(first.binding()).unwrap().commit();
    let prepared = probe.prepare(second.binding()).unwrap();
    let counters = prepared.counters();
    let peak = prepared.requested_peak_bytes();
    drop(prepared);

    for (resource, requested) in [
        (LedgerResource::Occurrences, counters.occurrences),
        (LedgerResource::TotalListChildren, counters.total_list_children),
        (LedgerResource::EncodedBytes, counters.encoded_bytes),
        (LedgerResource::LibraryRows, counters.library_rows),
        (LedgerResource::CompressionRequests, counters.compression_requests),
        (LedgerResource::RetainedBytes, counters.retained_bytes),
        (LedgerResource::PeakBytes, peak),
    ] {
        let mut limits = generous_limits();
        set_limit(&mut limits, resource, requested - 1);
        let mut ledger = OpeningLedger::new(first.root, limits);
        ledger.prepare(first.binding()).unwrap().commit();
        let before = snapshot(&ledger);
        assert_eq!(
            ledger.prepare(second.binding()).unwrap_err(),
            LedgerError::LimitExceeded {
                resource,
                limit: requested - 1,
                requested
            },
        );
        assert_eq!(snapshot(&ledger), before);
        assert_eq!(ledger.occurrences()[0].selected_children()[1], None);
    }
}

#[test]
fn retained_storage_uses_actual_list_and_slot_capacities_while_peak_covers_overlap() {
    let mut fixture = list_fixture(5, 4);
    fixture.path.reserve_exact(17);
    let EnvNode::List(children) = &mut fixture.path[0].node else {
        unreachable!()
    };
    children.reserve_exact(29);
    let list_capacity = children.capacity();
    let list_pointer = children.as_ptr();
    let binding = fixture.binding();
    let EnvNode::List(input_children) = &binding.opening().path()[0].node else {
        unreachable!()
    };
    let moved_pointer = input_children.as_ptr();
    assert_ne!(moved_pointer, list_pointer);
    let input_bytes = fixture.path.capacity() * size_of::<OpeningStep>()
        + list_capacity * size_of::<EnvironmentRoot>();
    let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
    let prepared = ledger.prepare(binding).unwrap();
    let staged_slot_bytes = prepared
        .staged
        .iter()
        .map(|occurrence| occurrence.selected_children.capacity() * size_of::<Option<OpeningId>>())
        .sum::<usize>();
    let replacement_bytes =
        prepared.replacement.as_ref().unwrap().capacity() * size_of::<OpeningOccurrence>();
    let staged_bytes = prepared.staged.capacity() * size_of::<OpeningOccurrence>();
    assert_eq!(
        prepared.requested_peak_bytes(),
        input_bytes + staged_bytes + replacement_bytes + staged_slot_bytes,
    );
    assert!(
        prepared.counters().retained_bytes
            >= list_capacity * size_of::<EnvironmentRoot>()
                + 5 * size_of::<Option<OpeningId>>()
                + 2 * size_of::<OpeningOccurrence>()
    );
    prepared.commit();
    assert_eq!(ledger.counters().retained_bytes, retained_storage(&ledger));
    let EnvNode::List(retained) = ledger.occurrences()[0].node() else {
        unreachable!()
    };
    assert_eq!(retained.capacity(), list_capacity);
    assert_eq!(retained.as_ptr(), moved_pointer);
}

#[test]
fn peak_for_extension_includes_old_ledger_input_staging_and_replacement() {
    let (first, mut second) = siblings();
    let mut ledger = OpeningLedger::new(first.root, generous_limits());
    ledger.prepare(first.binding()).unwrap().commit();
    let old = snapshot(&ledger);
    second.path.reserve_exact(19);
    let path_capacity = second.path.capacity();
    let EnvNode::List(children) = &mut second.path[1].node else {
        unreachable!()
    };
    children.reserve_exact(11);
    let input_bytes = path_capacity * size_of::<OpeningStep>()
        + children.capacity() * size_of::<EnvironmentRoot>();
    let prepared = ledger.prepare(second.binding()).unwrap();
    let staged_bytes = prepared.staged.capacity() * size_of::<OpeningOccurrence>();
    let replacement_bytes =
        prepared.replacement.as_ref().unwrap().capacity() * size_of::<OpeningOccurrence>();
    // Only the terminal Mast is new; the full excess input List remains in the peak charge.
    assert!(prepared.staged[0].selected_children.is_empty());
    assert_eq!(
        prepared.requested_peak_bytes(),
        old.counters.retained_bytes + input_bytes + staged_bytes + replacement_bytes,
    );
    drop(prepared);
    assert_eq!(snapshot(&ledger), old);
}

#[test]
fn post_reservation_capacity_excess_is_readmitted_before_publication() {
    let fixture = nested();
    let binding = fixture.binding();
    let terminal_namespace = binding.namespace();
    let path = binding.into_path();
    let mut ledger = OpeningLedger::new(fixture.root, generous_limits());
    let prefix = ledger.shared_prefix(&path).unwrap();
    let plan = ledger.plan(&path, path.capacity(), &prefix, terminal_namespace).unwrap();
    let (retained, peak) = ledger
        .check_storage(&plan, plan.new_occurrences, plan.replacement_capacity, plan.slot_bytes)
        .unwrap();
    let before = snapshot(&ledger);
    ledger.limits.max_retained_bytes = retained;
    assert_eq!(
        ledger.check_storage(
            &plan,
            plan.new_occurrences,
            plan.replacement_capacity.map(|capacity| capacity + 1),
            plan.slot_bytes,
        ),
        Err(LedgerError::LimitExceeded {
            resource: LedgerResource::RetainedBytes,
            limit: retained,
            requested: retained + size_of::<OpeningOccurrence>(),
        }),
    );
    assert_eq!(
        ledger.check_storage(
            &plan,
            plan.new_occurrences,
            plan.replacement_capacity,
            plan.slot_bytes + size_of::<Option<OpeningId>>(),
        ),
        Err(LedgerError::LimitExceeded {
            resource: LedgerResource::RetainedBytes,
            limit: retained,
            requested: retained + size_of::<Option<OpeningId>>(),
        }),
    );
    ledger.limits.max_retained_bytes = usize::MAX;
    ledger.limits.max_peak_bytes = peak;
    assert_eq!(
        ledger.check_storage(
            &plan,
            plan.new_occurrences + 1,
            plan.replacement_capacity,
            plan.slot_bytes,
        ),
        Err(LedgerError::LimitExceeded {
            resource: LedgerResource::PeakBytes,
            limit: peak,
            requested: peak + size_of::<OpeningOccurrence>(),
        }),
    );
    assert_eq!(snapshot(&ledger), before);
}

#[test]
fn logical_costs_include_empty_list_pair_and_count_requests_before_interning() {
    let initial = Namespace::initial();
    assert_eq!(logical_cost(&mast("entry", 40), 0, initial), Ok((2, 1)));
    assert_eq!(logical_cost(&mast("entry", 40), 1, initial.child(label("env"))), Ok((2, 2)));
    assert_eq!(
        logical_cost(&EnvNode::Env { label: label("env"), child: root(40) }, 0, initial),
        Ok((2, 2))
    );
    assert_eq!(
        logical_cost(&EnvNode::Merkle { left: root(40), right: root(80) }, 0, initial),
        Ok((2, 1))
    );
    for (count, expected) in
        [(0, (2, 1)), (1, (2, 1)), (2, (2, 1)), (3, (4, 2)), (4, (4, 2)), (5, (6, 3))]
    {
        assert_eq!(logical_cost(&EnvNode::List(vec![root(40); count]), 0, initial), Ok(expected));
    }
}

#[test]
fn intrinsic_trace_rows_and_arithmetic_layout_limits_need_no_large_allocation() {
    assert_eq!(check_trace_rows(MAX_TRACE_LEN), Ok(()));
    let unsupported = MAX_TRACE_LEN.checked_add(1).unwrap();
    assert_eq!(check_limit(LedgerResource::LibraryRows, unsupported, usize::MAX), Ok(()));
    assert_eq!(
        check_trace_rows(unsupported),
        Err(LedgerError::TraceRowLimitExceeded { requested: unsupported }),
    );
    assert_eq!(checked_add(usize::MAX - 1, 1), Ok(usize::MAX));
    assert_eq!(checked_add(usize::MAX, 1), Err(LedgerError::LengthOverflow));
    assert_eq!(array_bytes::<OpeningOccurrence>(0), Ok(0));
    assert_eq!(array_bytes::<OpeningOccurrence>(usize::MAX), Err(LedgerError::LengthOverflow));
    let beyond_layout = (isize::MAX as usize / size_of::<OpeningOccurrence>()) + 1;
    assert_eq!(
        array_bytes::<OpeningOccurrence>(beyond_layout),
        Err(LedgerError::LengthOverflow)
    );
    assert_eq!(array_bytes::<Option<OpeningId>>(usize::MAX), Err(LedgerError::LengthOverflow));
}

struct Fixture {
    path: Vec<OpeningStep>,
    root: EnvironmentRoot,
    key: ProcedureKey,
}

impl Fixture {
    fn new(path: Vec<OpeningStep>) -> Self {
        let root = path[0].node.commitment().unwrap();
        let mut namespace = Namespace::initial();
        for step in &path {
            if let EnvNode::Env { label, .. } = &step.node {
                namespace = namespace.child(*label);
            }
        }
        let EnvNode::Mast { label, .. } = &path.last().unwrap().node else {
            panic!("fixture must terminate at a Mast");
        };
        let key = namespace.procedure_key(*label);
        Self { path, root, key }
    }

    fn binding(&self) -> ResolvedBinding {
        let mut path = Vec::with_capacity(self.path.capacity());
        for step in &self.path {
            let node = match &step.node {
                EnvNode::List(children) => {
                    let mut copied = Vec::with_capacity(children.capacity());
                    copied.extend_from_slice(children);
                    EnvNode::List(copied)
                },
                node => node.clone(),
            };
            path.push(OpeningStep {
                node,
                selected_child: step.selected_child,
            });
        }
        ResolutionWitness { path }
            .verify(self.root, self.key, opening_limits())
            .unwrap()
    }

    fn encoded_bytes(&self) -> usize {
        self.path.iter().map(|step| step.node.to_bytes().unwrap().len()).sum()
    }
}

fn direct(export: &str, seed: u64) -> Fixture {
    Fixture::new(vec![step(mast(export, seed), None)])
}

fn nested() -> Fixture {
    let leaf = mast("entry", 40);
    let kernel = EnvNode::Env {
        label: label("kernel"),
        child: leaf.commitment().unwrap(),
    };
    let list = EnvNode::List(vec![
        EnvironmentRoot::new(Word::default()),
        root(100),
        kernel.commitment().unwrap(),
    ]);
    let merkle = EnvNode::Merkle {
        left: root(200),
        right: list.commitment().unwrap(),
    };
    let env = EnvNode::Env {
        label: label("runtime"),
        child: merkle.commitment().unwrap(),
    };
    Fixture::new(vec![
        step(env, Some(0)),
        step(merkle, Some(1)),
        step(list, Some(2)),
        step(kernel, Some(0)),
        step(leaf, None),
    ])
}

fn siblings() -> (Fixture, Fixture) {
    let first = mast("first", 40);
    let second = mast("second", 80);
    let list =
        EnvNode::List(vec![first.commitment().unwrap(), second.commitment().unwrap(), root(100)]);
    let env = EnvNode::Env {
        label: label("runtime"),
        child: list.commitment().unwrap(),
    };
    (
        Fixture::new(vec![
            step(env.clone(), Some(0)),
            step(list.clone(), Some(0)),
            step(first, None),
        ]),
        Fixture::new(vec![step(env, Some(0)), step(list, Some(1)), step(second, None)]),
    )
}

fn list_fixture(count: usize, selected: usize) -> Fixture {
    let leaf = mast("entry", 40);
    let mut children: Vec<_> = (0..count).map(|index| root(100 + index as u64 * 4)).collect();
    children[0] = EnvironmentRoot::new(Word::default());
    children[selected] = leaf.commitment().unwrap();
    Fixture::new(vec![step(EnvNode::List(children), Some(selected)), step(leaf, None)])
}

fn assert_path(ledger: &OpeningLedger, fixture: &Fixture) -> OpeningId {
    let mut id = ledger.root().unwrap();
    let mut namespace = Namespace::initial();
    for (depth, step) in fixture.path.iter().enumerate() {
        let occurrence = ledger.occurrence(id).unwrap();
        assert_eq!(occurrence.node(), &step.node);
        assert_eq!(occurrence.commitment(), step.node.commitment().unwrap());
        assert_eq!(occurrence.depth(), depth);
        assert_eq!(occurrence.namespace(), namespace);
        if let Some(slot) = step.selected_child {
            if let EnvNode::Env { label, .. } = &step.node {
                namespace = namespace.child(*label);
            }
            id = occurrence.selected_children()[slot].unwrap();
        }
    }
    id
}

fn assert_topology(ledger: &OpeningLedger) {
    let counters = ledger.counters();
    assert_eq!(counters.occurrences, ledger.occurrences().len());
    assert_eq!(counters.root_seed_count(), 1);
    let mut incoming = vec![0; counters.occurrences];
    let mut edges = 0;
    for (index, occurrence) in ledger.occurrences().iter().enumerate() {
        for (slot, child) in occurrence.selected_children().iter().enumerate() {
            let Some(child) = *child else { continue };
            let child_node = ledger.occurrence(child).unwrap();
            let parent = child_node.parent().unwrap();
            assert_eq!(parent.opening().index(), index);
            assert_eq!(parent.child_slot(), slot);
            assert_eq!(child_node.depth(), occurrence.depth() + 1);
            incoming[child.index()] += 1;
            edges += 1;
        }
    }
    assert_eq!(incoming[0], 0);
    assert!(incoming[1..].iter().all(|count| *count == 1));
    assert_eq!(edges, counters.selected_edge_count());
    assert_eq!(edges, counters.occurrences - 1);
    assert_eq!(counters.retained_bytes, retained_storage(ledger));
}

fn retained_storage(ledger: &OpeningLedger) -> usize {
    ledger.occurrences.capacity() * size_of::<OpeningOccurrence>()
        + ledger
            .occurrences()
            .iter()
            .map(|occurrence| {
                let lists = match occurrence.node() {
                    EnvNode::List(children) => children.capacity() * size_of::<EnvironmentRoot>(),
                    _ => 0,
                };
                lists + occurrence.selected_children.capacity() * size_of::<Option<OpeningId>>()
            })
            .sum::<usize>()
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    counters: LedgerCounters,
    root: Option<OpeningId>,
    pointer: usize,
    capacity: usize,
    occurrences: Vec<OccurrenceSnapshot>,
}

#[derive(Debug, PartialEq, Eq)]
struct OccurrenceSnapshot {
    parent: Option<OpeningParent>,
    depth: usize,
    namespace: Namespace,
    commitment: EnvironmentRoot,
    node: EnvNode,
    list_allocation: Option<(usize, usize)>,
    selections: Vec<Option<OpeningId>>,
    selection_allocation: (usize, usize),
}

fn snapshot(ledger: &OpeningLedger) -> Snapshot {
    Snapshot {
        counters: ledger.counters(),
        root: ledger.root(),
        pointer: ledger.occurrences().as_ptr() as usize,
        capacity: ledger.occurrences.capacity(),
        occurrences: ledger
            .occurrences()
            .iter()
            .map(|occurrence| OccurrenceSnapshot {
                parent: occurrence.parent(),
                depth: occurrence.depth(),
                namespace: occurrence.namespace(),
                commitment: occurrence.commitment(),
                node: occurrence.node().clone(),
                list_allocation: match occurrence.node() {
                    EnvNode::List(children) => {
                        Some((children.as_ptr() as usize, children.capacity()))
                    },
                    _ => None,
                },
                selections: occurrence.selected_children().to_vec(),
                selection_allocation: (
                    occurrence.selected_children().as_ptr() as usize,
                    occurrence.selected_children.capacity(),
                ),
            })
            .collect(),
    }
}

fn generous_limits() -> LedgerLimits {
    LedgerLimits {
        max_occurrences: usize::MAX,
        max_total_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_library_rows: usize::MAX,
        max_compression_requests: usize::MAX,
        max_retained_bytes: usize::MAX,
        max_peak_bytes: usize::MAX,
    }
}

fn opening_limits() -> OpeningLimits {
    OpeningLimits {
        max_nodes: usize::MAX,
        max_depth: usize::MAX,
        max_list_children: usize::MAX,
        max_total_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_storage_bytes: usize::MAX,
    }
}

fn empty_counters() -> LedgerCounters {
    LedgerCounters {
        occurrences: 0,
        total_list_children: 0,
        encoded_bytes: 0,
        library_rows: 0,
        compression_requests: 0,
        retained_bytes: 0,
    }
}

fn set_limit(limits: &mut LedgerLimits, resource: LedgerResource, value: usize) {
    match resource {
        LedgerResource::Occurrences => limits.max_occurrences = value,
        LedgerResource::TotalListChildren => limits.max_total_list_children = value,
        LedgerResource::EncodedBytes => limits.max_encoded_bytes = value,
        LedgerResource::LibraryRows => limits.max_library_rows = value,
        LedgerResource::CompressionRequests => limits.max_compression_requests = value,
        LedgerResource::RetainedBytes => limits.max_retained_bytes = value,
        LedgerResource::PeakBytes => limits.max_peak_bytes = value,
    }
}

fn step(node: EnvNode, selected_child: Option<usize>) -> OpeningStep {
    OpeningStep { node, selected_child }
}

fn mast(export: &str, seed: u64) -> EnvNode {
    EnvNode::Mast {
        label: label(export),
        implementation: ImplementationRoot::new(word(seed)),
    }
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn root(seed: u64) -> EnvironmentRoot {
    EnvironmentRoot::new(word(seed))
}

fn word(seed: u64) -> Word {
    Word::new([seed, seed + 1, seed + 2, seed + 3].map(Felt::new_unchecked))
}
