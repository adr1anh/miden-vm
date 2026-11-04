use alloc::vec;

use miden_core::{
    advice::AdviceMap,
    mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastNode, MastNodeId},
    operations::Operation,
    program::CanonicalLabel,
    utils::IndexVec,
};
use miden_mast_package::{
    CallableProcedurePath, NamespacePath, Package, PackageCallables, PackageId, ProcedureName,
    Section, SectionId, TargetType, Version,
    debug_info::{DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder},
};

use super::*;

fn equal_digest_forest() -> (Arc<MastForest>, [MastNodeId; 2], ImplementationRoot) {
    let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
    let mut roots = Vec::new();
    for _ in 0..2 {
        let node = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
        roots.push(nodes.push(node.into()).unwrap());
    }
    let root_ids = [roots[0], roots[1]];
    let forest = Arc::new(MastForest::from_raw_parts(nodes, roots, AdviceMap::default()).unwrap());
    let implementation = ImplementationRoot::new(forest[root_ids[0]].digest());
    assert_ne!(root_ids[0], root_ids[1]);
    assert_eq!(forest[root_ids[0]].digest(), forest[root_ids[1]].digest());
    (forest, root_ids, implementation)
}

fn package_owner(
    forest: Arc<MastForest>,
    root: MastNodeId,
    name: &'static str,
    with_source: bool,
) -> (LoadedMastForest, ProcedureKey, PackageProcedureOccurrence) {
    let home = NamespacePath::new(vec![CanonicalLabel::text("host-store-test").unwrap()]);
    let path = CallableProcedurePath::from_semantic_components(vec![name.into()]).unwrap();
    let procedure = ProcedureName::new(home.clone(), path).unwrap();
    let key = procedure.key();
    let implementation = ImplementationRoot::new(forest[root].digest());
    let symbols = Arc::new(
        PackageSymbols::new(
            home,
            PackageCallables::new([procedure], [], [(key, implementation)]).unwrap(),
            None,
        )
        .unwrap(),
    );
    let mut package = Package::create(
        PackageId::from(name),
        Version::new(1, 0, 0),
        TargetType::Library,
        forest.clone(),
        [],
        [],
        &symbols,
    )
    .unwrap();
    let mut source = None;
    if with_source {
        let mut debug = PackageDebugInfoBuilder::default();
        let context = debug.add_string(name);
        let operation = debug.add_string("add");
        for &exec_node in forest.procedure_roots() {
            let source_node = debug
                .add_node(DebugSourceNode {
                    exec_node,
                    children: Vec::new(),
                    op_start: 0,
                    op_end: 1,
                    asm_ops: vec![DebugSourceAsmOp::new(0, None, context, operation, 1)],
                    debug_vars: Vec::new(),
                    inline_calls: Vec::new(),
                })
                .unwrap();
            debug.add_root(source_node);
            if exec_node == root {
                source = Some(source_node);
            }
        }
        package.sections.push(Section::new(
            SectionId::DEBUG_INFO,
            debug.build().to_bytes_with_standard_limits().unwrap(),
        ));
    }
    let occurrence = PackageProcedureOccurrence::new(key, root, source);
    let package = package.with_procedure_occurrences([occurrence], &symbols).unwrap();
    let loaded =
        LoadedMastForest::from_code_package(CodePackage::new(Arc::new(package), symbols).unwrap());
    (loaded, key, occurrence)
}

#[test]
fn equal_digest_private_owners_survive_either_load_order() {
    let (forest, roots, implementation) = equal_digest_forest();
    let (first, first_key, first_row) = package_owner(forest.clone(), roots[0], "first", true);
    let (second, second_key, second_row) = package_owner(forest, roots[1], "second", true);
    assert_ne!(first_key, second_key);
    assert_ne!(first_row.source_node(), second_row.source_node());
    for owner in [&first, &second] {
        assert_eq!(owner.symbols().unwrap().callables().visible_paths().count(), 0);
    }

    for owners in [[&first, &second], [&second, &first]] {
        let mut store = MemMastForestStore::default();
        for owner in owners {
            store.insert_loaded(owner.clone());
        }
        for (expected, key, row) in
            [(&first, first_key, first_row), (&second, second_key, second_row)]
        {
            let loaded = store.get(CodeRequest::Procedure { key, implementation }).unwrap();
            assert_eq!(&loaded, expected);
            assert_eq!(loaded.procedure_occurrence(key), Some(&row));
            let debug = loaded.package_debug_info().unwrap().unwrap();
            assert_eq!(
                debug.source_node(row.source_node().unwrap()).unwrap().exec_node,
                row.exec_node()
            );
        }
        assert_eq!(store.mast_forests[implementation.as_word()].len(), 2);
        assert_eq!(
            store.get(CodeRequest::External { implementation }).as_ref(),
            owners.last().copied()
        );
    }
}

#[test]
fn exact_metadata_survives_later_raw_code_and_preserves_absent_source() {
    let (forest, roots, implementation) = equal_digest_forest();
    let (exact, key, row) = package_owner(forest.clone(), roots[1], "private", false);
    let raw = LoadedMastForest::new(forest);
    let mut store = MemMastForestStore::default();
    store.insert_loaded(exact.clone());
    store.insert_loaded(raw.clone());

    let loaded = store.get(CodeRequest::Procedure { key, implementation }).unwrap();
    assert_eq!(loaded, exact);
    assert_eq!(loaded.procedure_occurrence(key), Some(&row));
    assert_eq!(row.exec_node(), roots[1]);
    assert_eq!(row.source_node(), None);
    assert!(loaded.package_debug_info().unwrap().is_none());
    assert_eq!(store.get(CodeRequest::External { implementation }), Some(raw.clone()));
    assert_eq!(
        store.get(CodeRequest::Procedure {
            key: ProcedureKey::new(Word::default()),
            implementation
        }),
        Some(raw),
    );
}

#[test]
fn load_identity_deduplicates_clones_and_preserves_latest_insertion() {
    let (forest, roots, implementation) = equal_digest_forest();
    let (first, key, _) = package_owner(forest, roots[0], "shared", true);
    let second = LoadedMastForest::from_code_package(first.code_package().unwrap().clone());
    let first_clone = first.clone();
    assert_eq!(first, first_clone);
    assert_ne!(first, second);
    assert!(Arc::ptr_eq(first.mast_forest(), second.mast_forest()));
    assert_eq!(size_of::<LoadedMastForest>(), size_of::<Arc<()>>());
    let first_debug = first.package_debug_info().unwrap().unwrap();
    assert!(Arc::ptr_eq(&first_debug, &first_clone.package_debug_info().unwrap().unwrap()));

    let mut store = MemMastForestStore::default();
    store.insert_loaded(first_clone);
    store.insert_loaded(first.clone());
    assert_eq!(store.mast_forests[implementation.as_word()].len(), 1);
    store.insert_loaded(second.clone());
    assert_eq!(store.mast_forests[implementation.as_word()].len(), 2);
    assert_eq!(store.get(CodeRequest::Procedure { key, implementation }), Some(second));
    store.insert_loaded(first.clone());
    assert_eq!(store.mast_forests[implementation.as_word()].len(), 2);
    assert_eq!(store.get(CodeRequest::Procedure { key, implementation }), Some(first.clone()));
    assert_eq!(store.get(CodeRequest::External { implementation }), Some(first));
}

#[test]
fn duplicate_key_and_digest_prefer_the_latest_exact_package_occurrence() {
    let (forest, roots, implementation) = equal_digest_forest();
    let (first, key, first_row) = package_owner(forest.clone(), roots[0], "duplicate", true);
    let (second, same_key, second_row) = package_owner(forest, roots[1], "duplicate", false);
    assert_eq!(key, same_key);
    assert_ne!(first_row.exec_node(), second_row.exec_node());
    for (owners, expected_row) in [([&first, &second], second_row), ([&second, &first], first_row)]
    {
        let mut store = MemMastForestStore::default();
        for owner in owners {
            store.insert_loaded(owner.clone());
        }
        let loaded = store.get(CodeRequest::Procedure { key, implementation }).unwrap();
        assert_eq!(loaded.procedure_occurrence(key), Some(&expected_row));
        assert_eq!(store.mast_forests[implementation.as_word()].len(), 2);
        assert!(
            loaded
                .materialized_procedure_occurrence(key, ImplementationRoot::new(Word::default()))
                .is_none()
        );
    }
}

#[test]
fn external_occurrence_does_not_displace_an_exact_materialized_owner() {
    let mut forest = MastForest::new();
    let local = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(local);
    let implementation = ImplementationRoot::new(forest[local].digest());
    let external = ExternalNodeBuilder::new(*implementation.as_word())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(external);
    let forest = Arc::new(forest);
    let (materialized, key, _) = package_owner(forest.clone(), local, "external", false);
    let (external_hint, same_key, _) = package_owner(forest, external, "external", false);
    assert_eq!(key, same_key);
    assert!(external_hint.materialized_procedure_occurrence(key, implementation).is_none());
    let mut store = MemMastForestStore::default();
    store.insert_loaded(materialized.clone());
    store.insert_loaded(external_hint.clone());
    assert_eq!(store.get(CodeRequest::Procedure { key, implementation }), Some(materialized));
    assert_eq!(store.get(CodeRequest::External { implementation }), Some(external_hint));
}

#[test]
fn raw_only_code_is_available_without_synthesizing_key_metadata() {
    let (forest, _, implementation) = equal_digest_forest();
    let mut store = MemMastForestStore::default();
    store.insert(forest);
    let key = ProcedureKey::new(Word::default());
    let request = CodeRequest::Procedure { key, implementation };
    assert_eq!(request.key(), Some(key));
    assert_eq!(request.implementation(), implementation);
    assert_eq!(CodeRequest::External { implementation }.key(), None);
    let loaded = store.get(request).unwrap();
    assert!(loaded.code_package().is_none());
    assert!(loaded.procedure_occurrence(key).is_none());
    assert!(loaded.materialized_procedure_occurrence(key, implementation).is_none());
    assert_eq!(store.mast_forests[implementation.as_word()].len(), 1);
    let unavailable = ImplementationRoot::new(Word::default());
    assert!(store.get(CodeRequest::External { implementation: unavailable }).is_none());
}
