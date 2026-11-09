use alloc::vec;

use crate::{
    Felt, WORD_SIZE, Word,
    program::{
        EnvNode, EnvironmentBuildError, EnvironmentBuildLimits, EnvironmentBuildResource,
        EnvironmentBuilder, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace,
        ProcedureKey, ValidatedEnvironment,
    },
};

#[test]
fn duplicate_bindings_cannot_hide_in_distinct_collection_shapes() {
    let mut builder = EnvironmentBuilder::new(limits());
    let export = builder.insert(mast(1, 10)).unwrap();
    let data = builder.insert(data(2)).unwrap();
    let first = builder.insert(EnvNode::List(vec![export])).unwrap();
    let second = builder.insert(EnvNode::Merkle { left: data, right: export }).unwrap();
    let root = builder.insert(EnvNode::List(vec![first, second])).unwrap();

    assert_eq!(
        builder.finish(root).unwrap_err(),
        EnvironmentBuildError::DuplicateProcedureKey(Namespace::initial().procedure_key(label(1))),
    );
}

#[test]
fn shared_subtree_is_visited_at_every_physical_occurrence() {
    let mut builder = EnvironmentBuilder::new(limits());
    let export = builder.insert(mast(1, 10)).unwrap();
    let shared = builder.insert(EnvNode::Env { label: label(20), child: export }).unwrap();
    let root = builder.insert(EnvNode::Merkle { left: shared, right: shared }).unwrap();

    assert_eq!(
        builder.finish(root).unwrap_err(),
        EnvironmentBuildError::DuplicateProcedureKey(
            Namespace::initial().child(label(20)).procedure_key(label(1)),
        ),
    );
}

#[test]
fn same_path_with_different_implementations_is_also_a_duplicate() {
    let mut builder = EnvironmentBuilder::new(limits());
    let first = builder.insert(mast(1, 10)).unwrap();
    let second = builder.insert(mast(1, 11)).unwrap();
    let root = builder.insert(EnvNode::List(vec![first, second])).unwrap();

    assert_eq!(
        builder.finish(root).unwrap_err(),
        EnvironmentBuildError::DuplicateProcedureKey(Namespace::initial().procedure_key(label(1))),
    );
}

#[test]
fn a_root_label_cannot_duplicate_a_child_procedure_key() {
    let mut builder = EnvironmentBuilder::new(limits());
    let child_label = label(20);
    let child_key = Namespace::initial().child(child_label).procedure_key(label(1));
    let child_export = builder.insert(mast(1, 10)).unwrap();
    let child = builder
        .insert(EnvNode::Env { label: child_label, child: child_export })
        .unwrap();
    let root_export = builder
        .insert(EnvNode::Mast {
            label: LabelCommitment::new(child_key.into_word()),
            implementation: implementation(11),
        })
        .unwrap();
    let root = builder.insert(EnvNode::Merkle { left: root_export, right: child }).unwrap();

    assert_eq!(
        builder.finish(root).unwrap_err(),
        EnvironmentBuildError::DuplicateProcedureKey(child_key)
    );
}

#[test]
fn shared_implementation_and_subtree_can_have_distinct_parent_namespaces() {
    let mut builder = EnvironmentBuilder::new(limits());
    let export_node = mast(1, 10);
    let export = builder.insert(export_node.clone()).unwrap();
    let first = builder.insert(EnvNode::Env { label: label(20), child: export }).unwrap();
    let second = builder.insert(EnvNode::Env { label: label(21), child: export }).unwrap();
    let root = builder.insert(EnvNode::List(vec![first, second])).unwrap();
    let environment = builder.finish(root).unwrap();

    assert_eq!(environment.root(), root);
    assert_eq!(environment.get(export), Some(&export_node));
    assert_eq!(environment.visits(), 5);
    assert_eq!(environment.max_depth(), 2);
    assert_eq!(environment.bindings().len(), 2);
    assert!(environment.bindings().windows(2).all(|pair| pair[0].key() < pair[1].key()));
    for parent in [20, 21] {
        let namespace = Namespace::initial().child(label(parent));
        let key = namespace.procedure_key(label(1));
        let binding = environment.binding(key).unwrap();
        assert_eq!(binding.key(), key);
        assert_eq!(binding.namespace(), namespace);
        assert_eq!(binding.label(), label(1));
        assert_eq!(binding.implementation(), implementation(10));
    }
    assert!(environment.binding(ProcedureKey::new(word(999))).is_none());
}

#[test]
fn repeated_prefixes_union_disjoint_exports_across_mixed_collections() {
    let mut builder = EnvironmentBuilder::new(limits());
    let first_export = builder.insert(mast(1, 10)).unwrap();
    let second_export = builder.insert(mast(2, 11)).unwrap();
    let opaque_data = builder.insert(data(3)).unwrap();
    let first_fragment = builder.insert(EnvNode::List(vec![first_export])).unwrap();
    let second_fragment = builder
        .insert(EnvNode::Merkle { left: opaque_data, right: second_export })
        .unwrap();
    let first = builder
        .insert(EnvNode::Env { label: label(20), child: first_fragment })
        .unwrap();
    let second = builder
        .insert(EnvNode::Env { label: label(20), child: second_fragment })
        .unwrap();
    let root = builder.insert(EnvNode::List(vec![first, second])).unwrap();
    let environment = builder.finish(root).unwrap();
    let namespace = Namespace::initial().child(label(20));

    assert_eq!(environment.bindings().len(), 2);
    assert_eq!(environment.visits(), 8);
    assert_eq!(environment.max_depth(), 3);
    for (export_label, implementation_value) in [(1, 10), (2, 11)] {
        let binding = environment.binding(namespace.procedure_key(label(export_label))).unwrap();
        assert_eq!(binding.namespace(), namespace);
        assert_eq!(binding.implementation(), implementation(implementation_value));
    }
}

#[test]
fn data_and_empty_list_are_complete_roots_without_bindings_or_child_edges() {
    for node in [data(1), EnvNode::List(vec![])] {
        let mut exact = limits();
        exact.max_visits = 1;
        exact.max_depth = 0;
        exact.max_bindings = 0;
        let mut builder = EnvironmentBuilder::new(exact);
        let root = builder.insert(node.clone()).unwrap();
        let environment = builder.finish(root).unwrap();

        assert_eq!(environment.root(), root);
        assert_eq!(environment.get(root), Some(&node));
        assert!(environment.bindings().is_empty());
        assert_eq!(environment.visits(), 1);
        assert_eq!(environment.max_depth(), 0);
    }
}

#[test]
fn mast_implementation_is_opaque_and_does_not_require_an_environment_preimage() {
    let mut builder = EnvironmentBuilder::new(limits());
    let root = builder.insert(mast(1, 10)).unwrap();
    let environment = builder.finish(root).unwrap();

    assert!(environment.get(EnvironmentRoot::new(word(10))).is_none());
    assert_eq!(environment.visits(), 1);
    assert_eq!(environment.max_depth(), 0);
    assert_eq!(environment.bindings().len(), 1);
    assert_eq!(
        environment
            .binding(Namespace::initial().procedure_key(label(1)))
            .unwrap()
            .implementation(),
        implementation(10),
    );
}

#[test]
fn missing_or_tampered_selected_root_has_no_validated_result() {
    let missing = root(999);
    assert_eq!(
        EnvironmentBuilder::new(limits()).finish(missing).unwrap_err(),
        EnvironmentBuildError::MissingPreimage(missing),
    );

    let mut builder = EnvironmentBuilder::new(limits());
    let stored = builder.insert(mast(1, 10)).unwrap();
    // This is an unrelated caller-selected root, not a modified private commitment record.
    assert_ne!(stored, missing);
    assert_eq!(
        builder.finish(missing).unwrap_err(),
        EnvironmentBuildError::MissingPreimage(missing),
    );
}

#[test]
fn every_structural_edge_requires_its_preimage_in_deterministic_child_order() {
    let missing = root(999);
    let other_missing = root(1000);
    for node in [
        EnvNode::Env { label: label(20), child: missing },
        EnvNode::Merkle { left: missing, right: other_missing },
        EnvNode::List(vec![missing, other_missing]),
    ] {
        let mut builder = EnvironmentBuilder::new(limits());
        let root = builder.insert(node).unwrap();
        assert_eq!(
            builder.finish(root).unwrap_err(),
            EnvironmentBuildError::MissingPreimage(missing),
        );
    }

    for use_list in [false, true] {
        let mut builder = EnvironmentBuilder::new(limits());
        let present = builder.insert(data(1)).unwrap();
        let node = if use_list {
            EnvNode::List(vec![present, missing])
        } else {
            EnvNode::Merkle { left: present, right: missing }
        };
        let root = builder.insert(node).unwrap();
        assert_eq!(
            builder.finish(root).unwrap_err(),
            EnvironmentBuildError::MissingPreimage(missing),
        );
    }
}

#[test]
fn physical_depth_and_visits_have_exact_and_one_short_limits() {
    let mut exact = limits();
    exact.max_visits = 4;
    exact.max_depth = 2;
    exact.max_bindings = 1;
    let (builder, root) = depth_fixture(exact);
    let environment = builder.finish(root).unwrap();
    assert_eq!(environment.visits(), 4);
    assert_eq!(environment.max_depth(), 2);
    assert_eq!(environment.bindings().len(), 1);

    let mut one_short = exact;
    one_short.max_visits = 3;
    let (builder, root) = depth_fixture(one_short);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Visits, 3, 4);

    let mut one_short = exact;
    one_short.max_depth = 1;
    let (builder, root) = depth_fixture(one_short);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Depth, 1, 2);

    let mut zero_visits = exact;
    zero_visits.max_visits = 0;
    let (builder, root) = depth_fixture(zero_visits);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Visits, 0, 1);
}

#[test]
fn binding_count_has_exact_and_one_short_limits() {
    let mut exact = limits();
    exact.max_bindings = 2;
    let (builder, root) = two_binding_fixture(exact);
    assert_eq!(builder.finish(root).unwrap().bindings().len(), 2);

    exact.max_bindings = 1;
    let (builder, root) = two_binding_fixture(exact);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Bindings, 1, 2);
}

#[test]
fn deep_namespace_chain_is_walked_iteratively_with_accumulated_namespace() {
    const DEPTH: usize = 2048;
    let mut exact = limits();
    exact.max_depth = DEPTH;
    exact.max_visits = DEPTH + 1;
    exact.max_bindings = 1;
    let mut builder = EnvironmentBuilder::new(exact);
    let mut root = builder.insert(mast(1, 10)).unwrap();
    for _ in 0..DEPTH {
        root = builder.insert(EnvNode::Env { label: label(20), child: root }).unwrap();
    }
    let environment = builder.finish(root).unwrap();
    let mut namespace = Namespace::initial();
    for _ in 0..DEPTH {
        namespace = namespace.child(label(20));
    }

    assert_eq!(environment.visits(), DEPTH + 1);
    assert_eq!(environment.max_depth(), DEPTH);
    assert_eq!(environment.bindings().len(), 1);
    assert_eq!(
        environment.binding(namespace.procedure_key(label(1))).unwrap().implementation(),
        implementation(10),
    );
}

#[test]
fn exponential_dag_expansion_is_bounded_by_occurrence_visits() {
    let mut bounded = limits();
    bounded.max_visits = 31;
    bounded.max_depth = 20;
    let (builder, root) = dag_fixture(bounded, 20);
    assert_eq!(builder.len(), 21);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Visits, 31, 32);

    let mut exact = limits();
    exact.max_visits = 15;
    exact.max_depth = 3;
    exact.max_bindings = 0;
    let (builder, root) = dag_fixture(exact, 3);
    let environment = builder.finish(root).unwrap();
    assert_eq!(environment.visits(), 15);
    assert_eq!(environment.max_depth(), 3);
    assert!(environment.bindings().is_empty());

    exact.max_visits = 14;
    let (builder, root) = dag_fixture(exact, 3);
    assert_limit(builder.finish(root), EnvironmentBuildResource::Visits, 14, 15);
}

#[test]
fn private_cycle_shaped_corruption_is_rejected_even_when_namespace_would_change() {
    let mut bounded = limits();
    bounded.max_visits = 8;
    bounded.max_depth = 8;
    let mut builder = EnvironmentBuilder::new(bounded);
    let root = builder.insert(data(1)).unwrap();
    // Defense check only: public insert cannot produce this root/preimage relation. Mutating a
    // private stored preimage does not construct a real commitment cycle or hash collision.
    builder.records.get_mut(0).unwrap().node = EnvNode::Env { label: label(20), child: root };

    assert_eq!(builder.finish(root).unwrap_err(), EnvironmentBuildError::Cycle(root));
}

fn limits() -> EnvironmentBuildLimits {
    EnvironmentBuildLimits {
        max_submitted_nodes: usize::MAX,
        max_visits: usize::MAX,
        max_depth: usize::MAX,
        max_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_bindings: usize::MAX,
        max_storage_bytes: usize::MAX,
    }
}

fn depth_fixture(limits: EnvironmentBuildLimits) -> (EnvironmentBuilder, EnvironmentRoot) {
    let mut builder = EnvironmentBuilder::new(limits);
    let export = builder.insert(mast(1, 10)).unwrap();
    let wrapped = builder.insert(EnvNode::Env { label: label(20), child: export }).unwrap();
    let opaque_data = builder.insert(data(2)).unwrap();
    let root = builder.insert(EnvNode::List(vec![wrapped, opaque_data])).unwrap();
    (builder, root)
}

fn two_binding_fixture(limits: EnvironmentBuildLimits) -> (EnvironmentBuilder, EnvironmentRoot) {
    let mut builder = EnvironmentBuilder::new(limits);
    let first = builder.insert(mast(1, 10)).unwrap();
    let second = builder.insert(mast(2, 11)).unwrap();
    let root = builder.insert(EnvNode::List(vec![first, second])).unwrap();
    (builder, root)
}

fn dag_fixture(
    limits: EnvironmentBuildLimits,
    depth: usize,
) -> (EnvironmentBuilder, EnvironmentRoot) {
    let mut builder = EnvironmentBuilder::new(limits);
    let mut root = builder.insert(data(1)).unwrap();
    for _ in 0..depth {
        root = builder.insert(EnvNode::Merkle { left: root, right: root }).unwrap();
    }
    (builder, root)
}

fn assert_limit(
    result: Result<ValidatedEnvironment, EnvironmentBuildError>,
    resource: EnvironmentBuildResource,
    limit: usize,
    requested: usize,
) {
    assert_eq!(
        result.unwrap_err(),
        EnvironmentBuildError::LimitExceeded { resource, limit, requested },
    );
}

fn mast(export_label: u32, implementation_value: u32) -> EnvNode {
    EnvNode::Mast {
        label: label(export_label),
        implementation: implementation(implementation_value),
    }
}

fn data(value: u32) -> EnvNode {
    EnvNode::Data {
        kind: value,
        label: label(value),
        value: word(value + 1),
    }
}

fn implementation(value: u32) -> ImplementationRoot {
    ImplementationRoot::new(word(value))
}

fn label(value: u32) -> LabelCommitment {
    LabelCommitment::new(word(value))
}

fn root(value: u32) -> EnvironmentRoot {
    EnvironmentRoot::new(word(value))
}

fn word(value: u32) -> Word {
    Word::new([Felt::from_u32(value); WORD_SIZE])
}
