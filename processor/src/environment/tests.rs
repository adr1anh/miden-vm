use alloc::vec::Vec;

use miden_core::{
    Felt, WORD_SIZE, Word,
    chiplets::hasher,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace,
        ProcedureKey, domain,
    },
};

use super::{
    OpeningError, OpeningLimits, OpeningResource, OpeningStep, ResolutionWitness, ResolvedBinding,
};

#[test]
fn root_mast_authenticates_key_namespace_and_implementation() {
    let label = label("entry");
    let fixture = direct(label, implementation(40));
    assert_eq!(fixture.key.into_word(), label.into_word());
    assert_ne!(fixture.key.into_word(), fixture.implementation.into_word());
    let limits = exact_limits(&fixture.path);
    assert_eq!(limits.max_depth, 0);
    let legacy_payload = [Namespace::initial().into_word(), label.into_word()];
    let legacy_key = ProcedureKey::new(hasher::hash_elements_in_domain(
        Word::words_as_elements(&legacy_payload),
        domain::ENV_PROCEDURE,
    ));
    assert_eq!(
        ResolutionWitness { path: copy_path(&fixture.path) }
            .verify(fixture.root, legacy_key, limits)
            .unwrap_err(),
        OpeningError::KeyMismatch {
            expected: legacy_key,
            actual: fixture.key
        },
    );
    assert_binding(fixture, limits);
}

#[test]
fn nested_collections_preserve_the_full_accumulated_namespace() {
    let fixture = nested();
    let expected_namespace = Namespace::initial()
        .child(label("runtime"))
        .child(label("kernel"))
        .child(label("v2"));
    assert_eq!(fixture.namespace, expected_namespace);
    assert_ne!(fixture.namespace, Namespace::initial().child(label("kernel")));
    assert_ne!(fixture.namespace, Namespace::initial().child(label("v2")));
    assert_binding(fixture, unbounded());
}

#[test]
fn implementation_substitution_changes_the_root_but_preserves_the_key() {
    let original = direct(label("entry"), implementation(40));
    let replacement = direct(label("entry"), implementation(80));
    assert_eq!(original.key, replacement.key);
    assert_ne!(original.root, replacement.root);
    assert!(matches!(
        ResolutionWitness { path: replacement.path }.verify(
            original.root,
            original.key,
            unbounded(),
        ),
        Err(OpeningError::CommitmentMismatch { depth: 0, .. })
    ));
    assert_binding(direct(label("entry"), implementation(80)), unbounded());
}

#[test]
fn export_and_ancestor_labels_change_the_derived_key() {
    let original = direct(label("entry"), implementation(40));
    let renamed = direct(label("Entry"), implementation(40));
    assert_ne!(original.key, renamed.key);
    assert_ne!(original.root, renamed.root);
    assert!(matches!(
        ResolutionWitness { path: renamed.path }.verify(renamed.root, original.key, unbounded()),
        Err(OpeningError::KeyMismatch { .. })
    ));

    let leaf = mast(label("entry"), implementation(40));
    let leaf_root = leaf.commitment().unwrap();
    let mut keys = Vec::new();
    let mut roots = Vec::new();
    for ancestor in [label("kernel"), label("Kernel")] {
        let fixture = Fixture::new(
            vec![
                step(EnvNode::Env { label: ancestor, child: leaf_root }, Some(0)),
                step(leaf.clone(), None),
            ],
            Namespace::initial().child(ancestor),
            label("entry"),
            implementation(40),
        );
        keys.push(fixture.key);
        roots.push(fixture.root);
        assert_binding(fixture, unbounded());
    }
    assert_ne!(keys[0], keys[1]);
    assert_ne!(roots[0], roots[1]);
}

#[test]
fn wrong_root_and_implementation_shaped_key_do_not_resolve() {
    let fixture = direct(label("entry"), implementation(40));
    assert!(matches!(
        ResolutionWitness { path: fixture.path }.verify(root(900), fixture.key, unbounded()),
        Err(OpeningError::CommitmentMismatch { depth: 0, .. })
    ));
    let fixture = direct(label("entry"), implementation(40));
    let digest_shaped_key = ProcedureKey::new(fixture.implementation.into_word());
    assert!(matches!(
        ResolutionWitness { path: fixture.path }.verify(
            fixture.root,
            digest_shaped_key,
            unbounded(),
        ),
        Err(OpeningError::KeyMismatch { .. })
    ));
}

#[test]
fn both_merkle_slots_authenticate_the_unselected_sibling() {
    for selected in [0, 1] {
        let leaf = mast(label("entry"), implementation(40));
        let child = leaf.commitment().unwrap();
        let collection = if selected == 0 {
            EnvNode::Merkle { left: child, right: root(100) }
        } else {
            EnvNode::Merkle { left: root(100), right: child }
        };
        let expected_root = collection.commitment().unwrap();
        let mut fixture = Fixture::new(
            vec![step(collection, Some(selected)), step(leaf, None)],
            Namespace::initial(),
            label("entry"),
            implementation(40),
        );
        assert_eq!(fixture.root, expected_root);
        if let EnvNode::Merkle { left, right } = &mut fixture.path[0].node {
            if selected == 0 {
                *right = root(200);
            } else {
                *left = root(200);
            }
        }
        assert!(matches!(
            ResolutionWitness { path: copy_path(&fixture.path) }.verify(
                expected_root,
                fixture.key,
                unbounded(),
            ),
            Err(OpeningError::CommitmentMismatch { depth: 0, .. })
        ));
        fixture.root = fixture.path[0].node.commitment().unwrap();
        assert_ne!(fixture.root, expected_root);
        assert_binding(fixture, unbounded());
    }
}

#[test]
fn lists_authenticate_every_child_for_odd_and_even_lengths() {
    for count in 1..=4 {
        for selected in 0..count {
            let fixture = list_fixture(count, selected);
            assert_binding(fixture, unbounded());
        }
    }

    let mut fixture = list_fixture(3, 1);
    let original_root = fixture.root;
    if let EnvNode::List(children) = &mut fixture.path[0].node {
        // This is a real committed zero child, not padding to omit from the hash.
        assert_eq!(children[0], EnvironmentRoot::new(Word::default()));
        children[0] = root(300);
    }
    assert!(matches!(
        ResolutionWitness { path: copy_path(&fixture.path) }.verify(
            original_root,
            fixture.key,
            unbounded(),
        ),
        Err(OpeningError::CommitmentMismatch { depth: 0, .. })
    ));
    fixture.root = fixture.path[0].node.commitment().unwrap();
    assert_ne!(fixture.root, original_root);
    assert_binding(fixture, unbounded());
}

#[test]
fn empty_lists_invalid_slots_and_zero_children_are_not_executable_padding() {
    let key = Namespace::initial().procedure_key(label("entry"));
    for selected in [None, Some(0), Some(usize::MAX)] {
        let node = EnvNode::List(vec![]);
        let expected_root = node.commitment().unwrap();
        assert!(
            ResolutionWitness { path: vec![step(node, selected)] }
                .verify(expected_root, key, unbounded())
                .is_err()
        );
    }
    for selected in [2, usize::MAX] {
        let mut fixture = list_fixture(2, 1);
        fixture.path[0].selected_child = Some(selected);
        assert_eq!(
            ResolutionWitness { path: fixture.path }
                .verify(fixture.root, fixture.key, unbounded())
                .unwrap_err(),
            OpeningError::InvalidChildSelection { depth: 0, selected_child: selected },
        );
    }
    let mut fixture = list_fixture(3, 1);
    fixture.path[0].selected_child = Some(0);
    assert!(matches!(
        ResolutionWitness { path: fixture.path }.verify(fixture.root, fixture.key, unbounded()),
        Err(OpeningError::CommitmentMismatch { depth: 1, .. })
    ));
}

#[test]
fn repeated_commitments_retain_the_selected_structural_slot() {
    let leaf = mast(label("entry"), implementation(40));
    let child = leaf.commitment().unwrap();
    for collection in
        [EnvNode::List(vec![child, child]), EnvNode::Merkle { left: child, right: child }]
    {
        for selected in [0, 1] {
            // Selective membership makes no global executable-key uniqueness claim.
            let binding = assert_binding(
                Fixture::new(
                    vec![step(collection.clone(), Some(selected)), step(leaf.clone(), None)],
                    Namespace::initial(),
                    label("entry"),
                    implementation(40),
                ),
                unbounded(),
            );
            assert_eq!(binding.opening().path()[0].selected_child, Some(selected));
        }
    }
}

#[test]
fn data_is_opaque_even_when_its_value_is_an_executable_commitment() {
    let leaf = mast(label("entry"), implementation(40));
    let data = EnvNode::Data {
        kind: 0,
        label: label("entry"),
        value: leaf.commitment().unwrap().into_word(),
    };
    let expected_root = data.commitment().unwrap();
    let key = Namespace::initial().procedure_key(label("entry"));
    for selected in [None, Some(0)] {
        let mut path = vec![step(data.clone(), selected)];
        if selected.is_some() {
            path.push(step(leaf.clone(), None));
        }
        assert_eq!(
            ResolutionWitness { path }.verify(expected_root, key, unbounded()).unwrap_err(),
            OpeningError::DataNode { depth: 0 },
        );
    }
}

#[test]
fn empty_truncated_mismatched_and_trailing_preimages_reject() {
    let fixture = nested();
    assert_eq!(
        ResolutionWitness { path: vec![] }
            .verify(fixture.root, fixture.key, unbounded())
            .unwrap_err(),
        OpeningError::EmptyPath,
    );
    for len in 1..fixture.path.len() {
        assert_eq!(
            ResolutionWitness { path: copy_path(&fixture.path[..len]) }
                .verify(fixture.root, fixture.key, unbounded())
                .unwrap_err(),
            OpeningError::MissingChild { depth: len - 1 },
        );
    }
    let mut wrong_child = copy_path(&fixture.path);
    wrong_child[1].node = EnvNode::List(vec![]);
    assert!(matches!(
        ResolutionWitness { path: wrong_child }.verify(fixture.root, fixture.key, unbounded()),
        Err(OpeningError::CommitmentMismatch { depth: 1, .. })
    ));
    let mut trailing = fixture.path;
    let terminal_depth = trailing.len() - 1;
    trailing.push(step(mast(label("unreachable"), implementation(500)), None));
    assert_eq!(
        ResolutionWitness { path: trailing }
            .verify(fixture.root, fixture.key, unbounded())
            .unwrap_err(),
        OpeningError::TrailingPath { depth: terminal_depth },
    );
}

#[test]
fn selectors_are_required_only_for_real_collection_edges() {
    let fixture = nested();
    for depth in 0..fixture.path.len() - 1 {
        let mut path = copy_path(&fixture.path);
        path[depth].selected_child = None;
        assert_eq!(
            ResolutionWitness { path }
                .verify(fixture.root, fixture.key, unbounded())
                .unwrap_err(),
            OpeningError::MissingChildSelection { depth },
        );
    }
    for (depth, invalid_slot) in [(0, 1), (1, 2), (2, 3), (3, usize::MAX), (4, 2), (5, 1)] {
        let mut path = copy_path(&fixture.path);
        path[depth].selected_child = Some(invalid_slot);
        assert_eq!(
            ResolutionWitness { path }
                .verify(fixture.root, fixture.key, unbounded())
                .unwrap_err(),
            OpeningError::InvalidChildSelection { depth, selected_child: invalid_slot },
        );
    }
    let mut path = fixture.path;
    let depth = path.len() - 1;
    path[depth].selected_child = Some(0);
    assert_eq!(
        ResolutionWitness { path }
            .verify(fixture.root, fixture.key, unbounded())
            .unwrap_err(),
        OpeningError::UnexpectedChildSelection { depth },
    );
}

#[test]
fn every_resource_accepts_its_exact_bound_and_rejects_one_less() {
    let fixture = nested();
    let limits = exact_limits(&fixture.path);
    assert_eq!(limits.max_nodes, 7);
    assert_eq!(limits.max_depth, 6);
    assert_eq!(limits.max_list_children, 3);
    assert_eq!(limits.max_total_list_children, 5);
    assert_binding(fixture, limits);

    for resource in [
        OpeningResource::Nodes,
        OpeningResource::Depth,
        OpeningResource::ListChildren,
        OpeningResource::TotalListChildren,
        OpeningResource::EncodedBytes,
        OpeningResource::StorageBytes,
    ] {
        let fixture = nested();
        let mut limits = exact_limits(&fixture.path);
        let bound = match resource {
            OpeningResource::Nodes => &mut limits.max_nodes,
            OpeningResource::Depth => &mut limits.max_depth,
            OpeningResource::ListChildren => &mut limits.max_list_children,
            OpeningResource::TotalListChildren => &mut limits.max_total_list_children,
            OpeningResource::EncodedBytes => &mut limits.max_encoded_bytes,
            OpeningResource::StorageBytes => &mut limits.max_storage_bytes,
        };
        let requested = *bound;
        *bound -= 1;
        assert_eq!(
            ResolutionWitness { path: fixture.path }
                .verify(fixture.root, fixture.key, limits)
                .unwrap_err(),
            OpeningError::LimitExceeded {
                resource,
                limit: requested - 1,
                requested
            },
        );
    }
}

#[test]
fn unused_path_and_list_capacities_are_charged_and_retained() {
    for spare_path_capacity in [false, true] {
        let mut fixture = list_fixture(3, 1);
        if spare_path_capacity {
            fixture.path.reserve_exact(19);
        } else if let EnvNode::List(children) = &mut fixture.path[0].node {
            children.reserve_exact(19);
        }
        let limits = exact_limits(&fixture.path);
        let compact_storage = fixture.path.len() * size_of::<OpeningStep>()
            + 3 * size_of::<EnvironmentRoot>()
            + 3 * WORD_SIZE * size_of::<Felt>();
        assert!(limits.max_storage_bytes > compact_storage);
        let mut too_small = limits;
        too_small.max_storage_bytes = compact_storage;
        assert!(matches!(
            ResolutionWitness { path: fixture.path }.verify(fixture.root, fixture.key, too_small),
            Err(OpeningError::LimitExceeded {
                resource: OpeningResource::StorageBytes,
                ..
            })
        ));
    }

    let mut fixture = list_fixture(3, 1);
    fixture.path.reserve_exact(19);
    if let EnvNode::List(children) = &mut fixture.path[0].node {
        children.reserve_exact(19);
    }
    let limits = exact_limits(&fixture.path);
    assert_binding(fixture, limits);
}

#[test]
fn whole_candidate_is_preflighted_before_an_invalid_root_or_terminal() {
    for invalid_root in [false, true] {
        let mut fixture = direct(label("entry"), implementation(40));
        fixture.path.push(step(EnvNode::List(vec![root(1), root(2), root(3)]), Some(0)));
        let mut limits = unbounded();
        limits.max_list_children = 2;
        assert_eq!(
            ResolutionWitness { path: fixture.path }
                .verify(if invalid_root { root(900) } else { fixture.root }, fixture.key, limits,)
                .unwrap_err(),
            OpeningError::LimitExceeded {
                resource: OpeningResource::ListChildren,
                limit: 2,
                requested: 3,
            },
        );
    }
}

struct Fixture {
    path: Vec<OpeningStep>,
    root: EnvironmentRoot,
    key: ProcedureKey,
    namespace: Namespace,
    implementation: ImplementationRoot,
}

impl Fixture {
    fn new(
        path: Vec<OpeningStep>,
        namespace: Namespace,
        export_label: LabelCommitment,
        implementation: ImplementationRoot,
    ) -> Self {
        Self {
            root: path[0].node.commitment().unwrap(),
            key: namespace.procedure_key(export_label),
            path,
            namespace,
            implementation,
        }
    }
}

fn direct(export_label: LabelCommitment, implementation: ImplementationRoot) -> Fixture {
    Fixture::new(
        vec![step(mast(export_label, implementation), None)],
        Namespace::initial(),
        export_label,
        implementation,
    )
}

fn nested() -> Fixture {
    let implementation = implementation(40);
    let leaf = mast(label("entry"), implementation);
    let revision = EnvNode::Env {
        label: label("v2"),
        child: leaf.commitment().unwrap(),
    };
    let inner = EnvNode::List(vec![revision.commitment().unwrap(), root(100)]);
    let kernel = EnvNode::Env {
        label: label("kernel"),
        child: inner.commitment().unwrap(),
    };
    let outer = EnvNode::List(vec![
        EnvironmentRoot::new(Word::default()),
        root(200),
        kernel.commitment().unwrap(),
    ]);
    let merkle = EnvNode::Merkle {
        left: root(300),
        right: outer.commitment().unwrap(),
    };
    let runtime = EnvNode::Env {
        label: label("runtime"),
        child: merkle.commitment().unwrap(),
    };
    Fixture::new(
        vec![
            step(runtime, Some(0)),
            step(merkle, Some(1)),
            step(outer, Some(2)),
            step(kernel, Some(0)),
            step(inner, Some(0)),
            step(revision, Some(0)),
            step(leaf, None),
        ],
        Namespace::initial()
            .child(label("runtime"))
            .child(label("kernel"))
            .child(label("v2")),
        label("entry"),
        implementation,
    )
}

fn list_fixture(count: usize, selected: usize) -> Fixture {
    let leaf = mast(label("entry"), implementation(40));
    let mut children: Vec<_> = (0..count).map(|index| root(100 + index as u64)).collect();
    if selected != 0 {
        children[0] = EnvironmentRoot::new(Word::default());
    }
    children[selected] = leaf.commitment().unwrap();
    Fixture::new(
        vec![step(EnvNode::List(children), Some(selected)), step(leaf, None)],
        Namespace::initial(),
        label("entry"),
        implementation(40),
    )
}

fn assert_binding(fixture: Fixture, limits: OpeningLimits) -> ResolvedBinding {
    let expected_path = copy_path(&fixture.path);
    let path_pointer = fixture.path.as_ptr();
    let list_allocations: Vec<_> = fixture
        .path
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match &step.node {
            EnvNode::List(children) => Some((index, children.as_ptr(), children.capacity())),
            _ => None,
        })
        .collect();
    let binding = ResolutionWitness { path: fixture.path }
        .verify(fixture.root, fixture.key, limits)
        .unwrap();
    assert_eq!(binding.environment_root(), fixture.root);
    assert_eq!(binding.procedure_key(), fixture.key);
    assert_eq!(binding.namespace(), fixture.namespace);
    assert_eq!(binding.implementation_root(), fixture.implementation);
    assert_eq!(binding.opening().environment_root(), fixture.root);
    assert_eq!(binding.opening().procedure_key(), fixture.key);
    assert_eq!(binding.opening().path(), expected_path);
    assert_eq!(binding.opening().path().as_ptr(), path_pointer);
    for (index, pointer, capacity) in list_allocations {
        let EnvNode::List(children) = &binding.opening().path()[index].node else {
            panic!("verified opening changed a List preimage");
        };
        assert_eq!(children.as_ptr(), pointer);
        assert_eq!(children.capacity(), capacity);
    }
    binding
}

fn exact_limits(path: &Vec<OpeningStep>) -> OpeningLimits {
    let lists: Vec<_> = path
        .iter()
        .filter_map(|step| match &step.node {
            EnvNode::List(children) => Some(children),
            _ => None,
        })
        .collect();
    OpeningLimits {
        max_nodes: path.len(),
        max_depth: path.len() - 1,
        max_list_children: lists.iter().map(|children| children.len()).max().unwrap_or(0),
        max_total_list_children: lists.iter().map(|children| children.len()).sum(),
        max_encoded_bytes: path.iter().map(|step| step.node.to_bytes().unwrap().len()).sum(),
        max_storage_bytes: path.capacity() * size_of::<OpeningStep>()
            + lists
                .iter()
                .map(|children| children.capacity() * size_of::<EnvironmentRoot>())
                .sum::<usize>()
            + lists
                .iter()
                .map(|children| children.len() * WORD_SIZE * size_of::<Felt>())
                .max()
                .unwrap_or(0),
    }
}

fn unbounded() -> OpeningLimits {
    OpeningLimits {
        max_nodes: usize::MAX,
        max_depth: usize::MAX,
        max_list_children: usize::MAX,
        max_total_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_storage_bytes: usize::MAX,
    }
}

fn copy_path(path: &[OpeningStep]) -> Vec<OpeningStep> {
    path.iter()
        .map(|step| OpeningStep {
            node: step.node.clone(),
            selected_child: step.selected_child,
        })
        .collect()
}

fn step(node: EnvNode, selected_child: Option<usize>) -> OpeningStep {
    OpeningStep { node, selected_child }
}

fn mast(label: LabelCommitment, implementation: ImplementationRoot) -> EnvNode {
    EnvNode::Mast { label, implementation }
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn implementation(seed: u64) -> ImplementationRoot {
    ImplementationRoot::new(word(seed))
}

fn root(seed: u64) -> EnvironmentRoot {
    EnvironmentRoot::new(word(seed))
}

fn word(seed: u64) -> Word {
    Word::new([seed, seed + 1, seed + 2, seed + 3].map(Felt::new_unchecked))
}
