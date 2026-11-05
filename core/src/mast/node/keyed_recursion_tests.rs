use alloc::vec::Vec;

use super::{CallNodeBuilder, ExecNodeBuilder, MastNode, MastNodeBuilder, MastNodeExt};
use crate::{
    mast::{DenseMastForestBuilder, MastForest, MastNodeId, UntrustedMastForest},
    program::{
        CanonicalLabel, EnvNode, EnvironmentBuildLimits, EnvironmentBuilder, ImplementationRoot,
        LabelCommitment, Namespace, ProcedureKey, ValidatedEnvironment,
    },
    serde::Serializable,
};

#[test]
fn self_recursive_keys_bind_to_implementations_without_structural_cycles() {
    let namespace_label = label("self-recursive");
    let namespace = Namespace::initial().child(namespace_label);
    let export_label = label("recur");
    let key = namespace.procedure_key(export_label);

    // Both retained invocation modes can refer to their own export before its code is hashed.
    // These fixtures establish representation only; executing either body would not terminate.
    let bodies: [MastNodeBuilder; 2] =
        [CallNodeBuilder::new(key).into(), ExecNodeBuilder::new(key).into()];
    for body in bodies {
        let mut builder = DenseMastForestBuilder::new();
        let root = builder.push_node(body).unwrap();
        builder.mark_root(root);
        let forest = builder.build().unwrap();
        let implementation = ImplementationRoot::new(forest[root].digest());
        assert_ne!(key.into_word(), implementation.into_word());

        let environment = bind_implementations(namespace_label, &[(export_label, implementation)]);
        let binding = environment.binding(key).unwrap();
        assert_eq!(binding.namespace(), namespace);
        assert_eq!(binding.label(), export_label);
        assert_eq!(binding.implementation(), implementation);
        let bound_root = bound_root(&forest, &environment, key);
        assert_eq!(bound_root, root);
        assert_eq!(target(&forest[bound_root]), key);

        assert_childless_roundtrips(&forest);
    }
}

#[test]
fn mutually_recursive_keys_bind_to_implementations_without_structural_cycles() {
    let namespace_label = label("mutually-recursive");
    let namespace = Namespace::initial().child(namespace_label);
    let first_label = label("first");
    let second_label = label("second");
    let first_key = namespace.procedure_key(first_label);
    let second_key = namespace.procedure_key(second_label);
    assert_ne!(first_key, second_key);

    // Both keys exist before either implementation digest: no digest fixed point is needed.
    let mut builder = DenseMastForestBuilder::new();
    let first_root = builder.push_node(CallNodeBuilder::new(second_key)).unwrap();
    let second_root = builder.push_node(ExecNodeBuilder::new(first_key)).unwrap();
    builder.mark_root(first_root);
    builder.mark_root(second_root);
    let forest = builder.build().unwrap();
    let first_implementation = ImplementationRoot::new(forest[first_root].digest());
    let second_implementation = ImplementationRoot::new(forest[second_root].digest());
    for key in [first_key, second_key] {
        for implementation in [first_implementation, second_implementation] {
            assert_ne!(key.into_word(), implementation.into_word());
        }
    }

    let environment = bind_implementations(
        namespace_label,
        &[(first_label, first_implementation), (second_label, second_implementation)],
    );
    for (key, export_label, implementation) in [
        (first_key, first_label, first_implementation),
        (second_key, second_label, second_implementation),
    ] {
        let binding = environment.binding(key).unwrap();
        assert_eq!(binding.namespace(), namespace);
        assert_eq!(binding.label(), export_label);
        assert_eq!(binding.implementation(), implementation);
    }

    // Following bindings and keyed targets closes a cycle; following structural children does not.
    let first_bound_root = bound_root(&forest, &environment, first_key);
    let second_bound_root = bound_root(&forest, &environment, second_key);
    assert_eq!(first_bound_root, first_root);
    assert_eq!(second_bound_root, second_root);
    assert!(matches!(&forest[first_bound_root], MastNode::Call(node) if !node.is_syscall()));
    assert!(matches!(&forest[second_bound_root], MastNode::Exec(_)));
    assert_eq!(target(&forest[first_bound_root]), second_key);
    assert_eq!(target(&forest[second_bound_root]), first_key);
    assert_eq!(
        bound_root(&forest, &environment, target(&forest[first_bound_root])),
        second_bound_root,
    );
    assert_eq!(
        bound_root(&forest, &environment, target(&forest[second_bound_root])),
        first_bound_root,
    );

    assert_childless_roundtrips(&forest);
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn bind_implementations(
    namespace_label: LabelCommitment,
    exports: &[(LabelCommitment, ImplementationRoot)],
) -> ValidatedEnvironment {
    let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
        max_submitted_nodes: 4,
        max_visits: 4,
        max_depth: 2,
        max_list_children: 2,
        max_encoded_bytes: 512,
        max_bindings: 2,
        max_storage_bytes: 4096,
    });
    let children = exports
        .iter()
        .map(|&(label, implementation)| {
            builder.insert(EnvNode::Mast { label, implementation }).unwrap()
        })
        .collect();
    let list = builder.insert(EnvNode::List(children)).unwrap();
    let root = builder.insert(EnvNode::Env { label: namespace_label, child: list }).unwrap();
    let environment = builder.finish(root).unwrap();
    assert_eq!(environment.bindings().len(), exports.len());
    assert_eq!(environment.visits(), exports.len() + 2);
    environment
}

fn bound_root(
    forest: &MastForest,
    environment: &ValidatedEnvironment,
    key: ProcedureKey,
) -> MastNodeId {
    let implementation = environment.binding(key).unwrap().implementation();
    forest.find_procedure_root(implementation.into_word()).unwrap()
}

fn target(node: &MastNode) -> ProcedureKey {
    match node {
        MastNode::Call(node) => node.target(),
        MastNode::Exec(node) => node.target(),
        _ => panic!("expected a retained keyed invocation"),
    }
}

fn assert_childless_roundtrips(forest: &MastForest) {
    forest.validate().unwrap();
    for node in forest.nodes() {
        assert!(!node.has_children());
        node.for_each_child(|_| panic!("a recursive procedure key is not a structural child"));
    }

    for hashless in [false, true] {
        let bytes = if hashless {
            let mut bytes = Vec::new();
            forest.write_hashless(&mut bytes);
            bytes
        } else {
            forest.to_bytes()
        };
        let rebuilt = UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate().unwrap();
        assert_eq!(&rebuilt, forest);
    }
}
