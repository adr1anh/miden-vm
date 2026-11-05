use alloc::boxed::Box;

use miden_core::mast::{ExternalNodeBuilder, MastForestContributor};

use super::*;
use crate::mast_forest_builder::finalizer::MastForestBuilderError;

#[derive(Clone, Copy)]
enum InvocationMode {
    Exec,
    Call,
    Syscall,
}

const MODES: [InvocationMode; 3] =
    [InvocationMode::Exec, InvocationMode::Call, InvocationMode::Syscall];

impl InvocationMode {
    fn ensure(self, builder: &mut MastForestBuilder, target: ProcedureKey) -> MastNodeUse {
        let asm_op = test_asm_op("keyed::caller", "invoke");
        match self {
            Self::Exec => builder.ensure_exec_node_use(target, asm_op, vec![]),
            Self::Call => builder.ensure_call_node_use(target, false, asm_op, vec![]),
            Self::Syscall => builder.ensure_call_node_use(target, true, asm_op, vec![]),
        }
        .unwrap()
    }

    fn core_node(self, target: ProcedureKey) -> MastNode {
        match self {
            Self::Exec => ExecNodeBuilder::new(target).build().into(),
            Self::Call => CallNodeBuilder::new(target).build().into(),
            Self::Syscall => CallNodeBuilder::new_syscall(target).build().into(),
        }
    }
}

#[test]
fn declaration_key_invocations_are_independent_of_body_supply() {
    let target = test_procedure_key("declared_callee");
    for mode in MODES {
        let expected = mode.core_node(target);
        let mut body_digests = Vec::new();
        for body in [None, Some(Operation::Add), Some(Operation::Mul)] {
            let mut builder = MastForestBuilder::new(&[]).unwrap();
            let body_ref = body.map(|op| {
                let body_ref =
                    builder.ensure_block_ref(vec![op], vec![], vec![], vec![], vec![]).unwrap();
                // Independently callable roots survive without a structural edge from the caller.
                record_test_root(&mut builder, body_ref);
                body_ref
            });
            let caller = mode.ensure(&mut builder, target);
            assert_eq!(builder.pending_node_mast_root(caller.node_ref()), expected.digest());
            assert!(builder.nodes[caller.node_ref()].child_refs.is_empty());
            assert!(builder.debug_info[caller.source_ref()].children.is_empty());
            builder.record_procedure_root_use(caller);

            let (forest, remapping, debug, source_remapping) =
                builder.build().unwrap().into_parts_with_debug_info();
            assert_eq!(forest[remapping[&caller.node_ref()]], expected);
            assert!(debug[source_remapping[&caller.source_ref()]].children.is_empty());
            if let Some(body_ref) = body_ref {
                let body_id = remapping[&body_ref];
                assert!(forest.procedure_roots().contains(&body_id));
                body_digests.push(forest[body_id].digest());
            }
        }
        assert_ne!(body_digests[0], body_digests[1]);
    }
}

#[test]
fn invocation_keys_and_modes_remain_distinct() {
    let mut builder = MastForestBuilder::new(&[]).unwrap();
    let mut refs = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for name in ["first_declaration", "second_declaration"] {
        let target = test_procedure_key(name);
        for mode in MODES {
            let node = mode.ensure(&mut builder, target);
            assert!(refs.insert(node.node_ref()));
            assert!(digests.insert(builder.pending_node_mast_root(node.node_ref())));
            builder.record_procedure_root_use(node);
        }
    }
    let (forest, _) = builder.build().unwrap().into_parts();
    assert_eq!(forest.num_nodes(), 6);
    assert_eq!(forest.procedure_roots().len(), 6);
}

#[test]
fn static_imports_preserve_keys_modes_and_structural_externals() {
    let mut builder = MastForestBuilder::new(&[]).unwrap();
    let mut expected_nodes = Vec::new();
    for name in ["first_import", "second_import"] {
        let target = test_procedure_key(name);
        for mode in MODES {
            let expected = mode.core_node(target);
            let imported = builder
                .ensure_node_from_statically_linked_source_ref(expected.clone(), vec![], None)
                .unwrap();
            let local = mode.ensure(&mut builder, target);
            assert_eq!(imported, local.node_ref());
            assert!(builder.nodes[imported].child_refs.is_empty());
            builder.record_procedure_root_use(local);
            expected_nodes.push((imported, expected));
        }
    }

    let external = MastNode::External(ExternalNodeBuilder::new(test_word(55)).build());
    let external_ref = builder
        .ensure_node_from_statically_linked_source_ref(external.clone(), vec![], None)
        .unwrap();
    record_test_root(&mut builder, external_ref);
    expected_nodes.push((external_ref, external));

    let (forest, remapping, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
    for (node_ref, expected) in expected_nodes {
        let node_id = remapping[&node_ref];
        assert_eq!(forest[node_id], expected);
        assert!(!forest[node_id].has_children());
        for source in source_nodes_for_exec(&debug, node_id) {
            assert!(source.children.is_empty());
        }
    }
}

#[test]
fn keyed_invocations_reject_structural_and_source_children() {
    let target = test_procedure_key("childless_declaration");
    for mode in MODES {
        for source_child in [false, true] {
            let mut builder = MastForestBuilder::new(&[]).unwrap();
            let body = builder
                .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
                .unwrap();
            builder.record_procedure_root_use(body);
            let invocation = mode.ensure(&mut builder, target);
            builder.record_procedure_root_use(invocation);
            if source_child {
                builder.debug_info[invocation.source_ref()].children.push(body.source_ref());
            } else {
                builder.nodes[invocation.node_ref()].child_refs.push(body.node_ref());
            }
            let error = builder.build().err().expect("keyed nodes cannot have callee children");
            let error = error.downcast_ref::<MastForestBuilderError>().unwrap();
            if source_child {
                assert!(matches!(
                    error,
                    MastForestBuilderError::InvalidInvocationSourceChildCount { actual: 1, .. }
                ));
            } else {
                assert!(matches!(
                    error,
                    MastForestBuilderError::InvalidChildCount { expected: 0, actual: 1, .. }
                ));
            }
        }
    }
}

#[test]
fn static_imports_reject_callee_children_and_noncanonical_keyed_digests() {
    let target = test_procedure_key("imported_declaration");
    let mut builder = MastForestBuilder::new(&[]).unwrap();
    let body = builder
        .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
        .unwrap();
    for mode in MODES {
        assert!(
            builder
                .ensure_node_from_statically_linked_source_ref(
                    mode.core_node(target),
                    vec![body],
                    None,
                )
                .is_err()
        );
        let forged_digest = test_word(77);
        let forged_node = match mode {
            InvocationMode::Exec => {
                ExecNodeBuilder::new(target).with_digest(forged_digest).build().into()
            },
            InvocationMode::Call => {
                CallNodeBuilder::new(target).with_digest(forged_digest).build().into()
            },
            InvocationMode::Syscall => {
                CallNodeBuilder::new_syscall(target).with_digest(forged_digest).build().into()
            },
        };
        assert!(
            builder
                .ensure_node_from_statically_linked_source_ref(forged_node, vec![], None)
                .is_err()
        );
    }
}

#[test]
fn invocation_inline_annotations_do_not_retain_callee_children() {
    let mut builder = MastForestBuilder::new(&[]).unwrap();
    let body = builder
        .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
        .unwrap();
    let body_digest = builder.pending_node_mast_root(body.node_ref());
    let (callee_idx, loc_idx) = {
        let debug = builder.debug_info_mut();
        let location = debug.add_location(Location::new(
            Uri::from("file:///keyed-invocation.masm"),
            ByteIndex::from(0_u32),
            ByteIndex::from(1_u32),
        ));
        let file = debug.debug_info().locations()[location].file_idx;
        let name = debug.add_string("diagnostic_callee");
        let callee = debug.add_function(FunctionInfo::new(
            None,
            name,
            file,
            LineNumber::new(1).unwrap(),
            ColumnNumber::new(1).unwrap(),
            body_digest,
        ));
        debug.set_function_source_node(callee, body.source_ref());
        (callee, location)
    };
    let caller = builder
        .ensure_exec_node_use(
            test_procedure_key("diagnostic_callee"),
            test_asm_op("caller", "exec.diagnostic_callee"),
            vec![DebugSourceInlineCall {
                op_idx: 0,
                op_end: 1,
                callee_idx,
                loc_idx,
            }],
        )
        .unwrap();
    builder.record_procedure_root_use(caller);
    let (forest, remapping, debug, source_remapping) =
        builder.build().unwrap().into_parts_with_debug_info();
    assert_eq!(forest.num_nodes(), 1);
    assert!(!remapping.contains_key(&body.node_ref()));
    let source = &debug[source_remapping[&caller.source_ref()]];
    assert!(source.children.is_empty());
    assert_eq!(source.inline_calls.len(), 1);
    assert!(debug[source.inline_calls[0].callee_idx].source_node.into_option().is_none());
}

struct StaticInventoryFixture {
    forest: MastForest,
    debug: PackageDebugInfo,
    export: MastNodeId,
    helper: MastNodeId,
    callback: MastNodeId,
}

fn static_inventory_fixture() -> StaticInventoryFixture {
    static_inventory_fixture_with_join(false)
}

fn static_inventory_fixture_with_join(join: bool) -> StaticInventoryFixture {
    let mut builder = MastForestBuilder::new(&[]).unwrap();
    let asm_op = add_test_asm_op(&mut builder, test_asm_op("private_helper", "add"));
    let helper = builder
        .ensure_block_ref(vec![Operation::Add], vec![asm_op], vec![], vec![], vec![])
        .unwrap();
    record_test_root(&mut builder, helper);
    let helper_key = test_procedure_key("private_helper");
    let callback = builder
        .ensure_call_node_use(
            helper_key,
            false,
            test_asm_op("private_callback", "call.private_helper"),
            vec![],
        )
        .unwrap();
    builder.record_procedure_root_use(callback);
    let invocation = builder
        .ensure_exec_node_use(
            helper_key,
            test_asm_op("exported_entry", "exec.private_helper"),
            vec![],
        )
        .unwrap();
    let export = if join {
        let dynamic = builder
            .ensure_dyn_node_use(false, test_asm_op("exported_entry", "dynexec"), vec![])
            .unwrap();
        builder
            .join_node_uses(vec![invocation, dynamic], Some(test_asm_op("exported_entry", "begin")))
            .unwrap()
    } else {
        invocation
    };
    builder.record_procedure_root_use(export);
    let (forest, node_ids, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
    StaticInventoryFixture {
        forest,
        debug: *debug,
        export: node_ids[&export.node_ref()],
        helper: node_ids[&helper],
        callback: node_ids[&callback.node_ref()],
    }
}

#[test]
fn static_package_import_retains_private_helper_and_callback_roots() {
    let fixture = static_inventory_fixture();
    let mut unrelated = MastForestBuilder::new(&[]).unwrap();
    let unrelated_root = unrelated
        .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
        .unwrap();
    record_test_root(&mut unrelated, unrelated_root);
    let (unrelated_forest, _) = unrelated.build().unwrap().into_parts();

    for include_debug in [false, true] {
        let path = PathBuf::new("keyed_inventory::entry").unwrap();
        let path = path.as_path().to_absolute().unwrap().into_owned();
        let exports = [PackageExport::Procedure(ProcedureExport::new(
            Arc::from(path.into_boxed_path()),
            Some(fixture.export),
            fixture.forest[fixture.export].digest(),
            None,
        ))];
        let naming = fixture_naming(
            FixtureNamespace::assembly_tests().namespace_plan().clone(),
            TargetType::Library,
            &fixture.forest,
            &exports,
        );
        let mut package = Package::create(
            PackageId::from("keyed-inventory"),
            Version::new(0, 0, 0),
            TargetType::Library,
            Arc::new(fixture.forest.clone()),
            exports,
            [],
            &naming,
        )
        .unwrap();
        if include_debug {
            package
                .sections
                .push(Section::new(SectionId::DEBUG_INFO, fixture.debug.to_bytes()));
        }
        let library = crate::linker::LinkLibrary::from_package(Arc::new(package), naming).unwrap();
        for exact_source in [false, true] {
            let mut builder = MastForestBuilder::new_with_static_libraries([
                StaticLibrary::from_link_library(&library, library.package.debug_info().unwrap())
                    .unwrap(),
                StaticLibrary::from_mast_forest(&unrelated_forest, None),
            ])
            .unwrap();
            let import = |builder: &mut MastForestBuilder| {
                builder
                    .ensure_external_link_with_source_ref(
                        fixture.forest[fixture.export].digest(),
                        exact_source.then_some(library.commitment()),
                        exact_source.then_some(fixture.export),
                        None,
                    )
                    .unwrap()
            };
            let imported_export = import(&mut builder);
            assert_eq!(imported_export, import(&mut builder));
            record_test_root(&mut builder, imported_export);

            let (forest, node_ids, debug, _) =
                builder.build().unwrap().into_parts_with_debug_info();
            assert_eq!(forest.num_nodes(), 4);
            assert_eq!(forest.procedure_roots().len(), 4);
            assert_eq!(forest[node_ids[&imported_export]], fixture.forest[fixture.export]);
            for (source_root, context) in
                [(fixture.helper, "private_helper"), (fixture.callback, "private_callback")]
            {
                let retained = forest
                    .find_procedure_root(fixture.forest[source_root].digest())
                    .expect("private callable roots must survive outside the export subtree");
                assert_eq!(forest[retained], fixture.forest[source_root]);
                assert_eq!(source_nodes_for_exec(&debug, retained).len(), 1);
                let contexts = source_asm_contexts(&debug, retained);
                if exact_source && include_debug {
                    assert_eq!(contexts, vec![context.to_string()]);
                } else {
                    assert!(
                        contexts.is_empty(),
                        "code-only imports must not choose source metadata"
                    );
                }
            }
            let unrelated_root = forest
                .find_procedure_root(
                    unrelated_forest[unrelated_forest.procedure_roots()[0]].digest(),
                )
                .unwrap();
            assert!(source_asm_contexts(&debug, unrelated_root).is_empty());
        }
    }
}

#[test]
fn failed_static_inventory_import_is_not_cached_as_complete() {
    use crate::mast_forest_builder::static_import::StaticInventoryKind;

    let fixture = static_inventory_fixture();
    let helper_source =
        fixture.debug.unique_source_root_for_exec_node(fixture.helper).unwrap().unwrap();
    let mut builder =
        MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
            &fixture.forest,
            Some(fixture.debug.clone()),
        )])
        .unwrap();
    // Inject a bad helper source after construction to fail partway through inventory copying.
    let mut bad_debug = PackageDebugInfoBuilder::from(Box::new(
        builder.statically_linked_package_debug_info[0].take().unwrap(),
    ));
    bad_debug[helper_source].children.push(helper_source);
    builder.statically_linked_package_debug_info[0] = Some(*bad_debug.build());
    let import = |builder: &mut MastForestBuilder| {
        builder.ensure_external_link_with_source_ref(
            fixture.forest[fixture.export].digest(),
            Some(fixture.forest.commitment()),
            Some(fixture.export),
            None,
        )
    };
    assert!(import(&mut builder).is_err());
    assert!(builder.retained_static_inventories.is_empty());
    builder.statically_linked_package_debug_info[0] = Some(fixture.debug.clone());

    let export = import(&mut builder).unwrap();
    assert!(
        builder
            .retained_static_inventories
            .contains(&(0, StaticInventoryKind::ExactSource))
    );
    record_test_root(&mut builder, export);
    let (forest, _) = builder.build().unwrap().into_parts();
    assert_eq!(forest.procedure_roots().len(), 3);
    assert!(forest.find_procedure_root(fixture.forest[fixture.helper].digest()).is_some());
    assert!(forest.find_procedure_root(fixture.forest[fixture.callback].digest()).is_some());
}

#[test]
fn digest_only_import_retains_contributing_inventories_without_choosing_metadata() {
    let fixture = static_inventory_fixture();
    let mut alternate = MastForestBuilder::new(&[]).unwrap();
    let asm_op = add_test_asm_op(&mut alternate, test_asm_op("alternate_helper", "mul"));
    let helper = alternate
        .ensure_block_ref(vec![Operation::Mul], vec![asm_op], vec![], vec![], vec![])
        .unwrap();
    record_test_root(&mut alternate, helper);
    let export = alternate
        .ensure_exec_node_use(
            test_procedure_key("private_helper"),
            test_asm_op("alternate_entry", "exec.private_helper"),
            vec![],
        )
        .unwrap();
    alternate.record_procedure_root_use(export);
    let (alternate_forest, alternate_ids, alternate_debug, _) =
        alternate.build().unwrap().into_parts_with_debug_info();
    let alternate_helper_digest = alternate_forest[alternate_ids[&helper]].digest();
    assert_eq!(
        fixture.forest[fixture.export].digest(),
        alternate_forest[alternate_ids[&export.node_ref()]].digest()
    );

    let mut builder = MastForestBuilder::new_with_static_libraries([
        StaticLibrary::from_mast_forest(&fixture.forest, Some(fixture.debug.clone())),
        StaticLibrary::from_mast_forest(&alternate_forest, Some(*alternate_debug)),
    ])
    .unwrap();
    let imported = builder
        .ensure_external_link_with_source_ref(
            fixture.forest[fixture.export].digest(),
            None,
            None,
            None,
        )
        .unwrap();
    record_test_root(&mut builder, imported);
    let (forest, _, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
    assert_eq!(forest.procedure_roots().len(), 4);
    assert!(forest.find_procedure_root(alternate_helper_digest).is_some());
    for source_root in [fixture.helper, fixture.callback, fixture.export] {
        assert!(forest.find_procedure_root(fixture.forest[source_root].digest()).is_some());
    }
    for &root in forest.procedure_roots() {
        assert!(source_asm_contexts(&debug, root).is_empty());
    }
}

#[test]
fn structural_external_provider_keeps_its_independent_callable_roots() {
    let provider = static_inventory_fixture();
    let provider_digest = provider.forest[provider.export].digest();
    let mut source = MastForestBuilder::new(&[]).unwrap();
    let external = source
        .ensure_external_link_with_source_ref(provider_digest, None, None, None)
        .unwrap();
    let parent = source
        .ensure_loop_node_ref(external, test_asm_op("source_entry", "while.true"), vec![])
        .unwrap();
    record_test_root(&mut source, parent);
    let (source_forest, source_ids, source_debug, _) =
        source.build().unwrap().into_parts_with_debug_info();
    let source_root = source_ids[&parent];

    for include_debug in [false, true] {
        for exact_source in [false, true] {
            let mut builder = MastForestBuilder::new_with_static_libraries([
                StaticLibrary::from_mast_forest(
                    &source_forest,
                    include_debug.then(|| source_debug.as_ref().clone()),
                ),
                StaticLibrary::from_mast_forest(
                    &provider.forest,
                    include_debug.then(|| provider.debug.clone()),
                ),
            ])
            .unwrap();
            let imported = builder
                .ensure_external_link_with_source_ref(
                    source_forest[source_root].digest(),
                    exact_source.then_some(source_forest.commitment()),
                    exact_source.then_some(source_root),
                    None,
                )
                .unwrap();
            record_test_root(&mut builder, imported);
            let (forest, ids, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
            assert_eq!(forest.procedure_roots().len(), 4);
            assert_eq!(forest[ids[&imported]].digest(), source_forest[source_root].digest());
            let MastNode::Loop(parent) = &forest[ids[&imported]] else {
                panic!("the source structural root must remain a loop")
            };
            assert_eq!(forest[parent.body()], provider.forest[provider.export]);
            assert!(matches!(&forest[parent.body()], MastNode::Exec(_)));
            for source_root in [provider.helper, provider.callback, provider.export] {
                let root =
                    forest.find_procedure_root(provider.forest[source_root].digest()).expect(
                        "a merged structural provider must retain its complete callable inventory",
                    );
                assert_eq!(forest[root], provider.forest[source_root]);
                assert!(
                    source_asm_contexts(&debug, root).is_empty(),
                    "resolving structural code must not choose provider source metadata",
                );
            }
        }
    }
}

#[test]
fn direct_external_root_uses_its_concrete_provider_and_rebinds_source_occurrences() {
    for join in [false, true] {
        let provider = static_inventory_fixture_with_join(join);
        let digest = provider.forest[provider.export].digest();
        let mut source = MastForestBuilder::new(&[]).unwrap();
        let external =
            source.ensure_external_link_with_source_ref(digest, None, None, None).unwrap();
        let external_source = source.latest_node_use(external).unwrap().source_ref();
        record_test_root(&mut source, external);
        let debug = source.debug_info_mut();
        let location = debug.add_location(Location::new(
            Uri::from("file:///external-alias.masm"),
            ByteIndex::from(0_u32),
            ByteIndex::from(1_u32),
        ));
        let file = debug.debug_info().locations()[location].file_idx;
        let name = debug.add_string("external_alias");
        debug.add_function(FunctionInfo::new(
            Some(external_source),
            name,
            file,
            LineNumber::new(1).unwrap(),
            ColumnNumber::new(1).unwrap(),
            digest,
        ));
        let (source_forest, source_ids, source_debug, _) =
            source.build().unwrap().into_parts_with_debug_info();
        let source_root = source_ids[&external];

        for include_debug in [false, true] {
            for exact_source in [false, true] {
                let mut builder = MastForestBuilder::new_with_static_libraries([
                    StaticLibrary::from_mast_forest(
                        &source_forest,
                        include_debug.then(|| source_debug.as_ref().clone()),
                    ),
                    StaticLibrary::from_mast_forest(
                        &provider.forest,
                        include_debug.then(|| provider.debug.clone()),
                    ),
                ])
                .unwrap();
                let imported = builder
                    .ensure_external_link_with_source_ref(
                        digest,
                        exact_source.then_some(source_forest.commitment()),
                        exact_source.then_some(source_root),
                        None,
                    )
                    .unwrap();
                assert!(!builder.nodes[imported].kind.is_external());
                assert!(builder.external_boundary_source_refs.is_empty());
                let original_source = builder.debug_info.roots()[0];
                let (forest, ids, debug, source_ids) =
                    builder.build().unwrap().into_parts_with_debug_info();
                let root = ids[&imported];
                assert_eq!(forest[root].digest(), digest);
                assert_eq!(forest.procedure_roots().len(), 3);
                let child_count = if join { 2 } else { 0 };
                assert_eq!(debug[source_ids[&original_source]].exec_node, root);
                assert_eq!(debug[source_ids[&original_source]].children.len(), child_count);
                if join {
                    let MastNode::Join(node) = &forest[root] else {
                        panic!("the direct external must become its structural Join provider")
                    };
                    assert!(matches!(&forest[node.first()], MastNode::Exec(_)));
                    assert!(matches!(&forest[node.second()], MastNode::Dyn(_)));
                } else {
                    let MastNode::Exec(node) = &forest[root] else {
                        panic!("the direct external must become its keyed Exec provider")
                    };
                    assert_eq!(node.target(), test_procedure_key("private_helper"));
                }
                for source_node in debug.nodes() {
                    let mut children = Vec::new();
                    forest[source_node.exec_node].for_each_child(|child| children.push(child));
                    assert_eq!(
                        children,
                        source_node
                            .children
                            .iter()
                            .map(|child| debug[*child].exec_node)
                            .collect::<Vec<_>>()
                    );
                    assert!(source_node.asm_ops.is_empty());
                }
                let alias = debug
                    .functions()
                    .iter()
                    .find(|function| debug[function.name_idx].as_ref() == "external_alias");
                if exact_source && include_debug {
                    let alias_source = alias.unwrap().source_node.into_option().unwrap();
                    assert_eq!(debug[alias_source].exec_node, root);
                    assert_eq!(debug[alias_source].children.len(), child_count);
                } else {
                    assert!(alias.is_none());
                }
                for source_root in [provider.helper, provider.callback] {
                    assert!(
                        forest.find_procedure_root(provider.forest[source_root].digest()).is_some()
                    );
                }
            }
        }
    }
}

fn assert_source_children_match_execution(forest: &MastForest, debug: &PackageDebugInfo) {
    for source in debug.nodes() {
        let mut children = Vec::new();
        forest[source.exec_node].for_each_child(|child| children.push(child));
        assert_eq!(
            children,
            source.children.iter().map(|child| debug[*child].exec_node).collect::<Vec<_>>()
        );
    }
}

#[test]
fn external_replacement_preserves_full_keys_before_and_after_provider_import() {
    let variants = [
        (
            vec![Operation::Assert(Felt::from_u32(3))],
            vec![Operation::Assert(Felt::from_u32(11))],
        ),
        (vec![Operation::Add, Operation::Noop], vec![Operation::Add]),
    ];
    for (selected_ops, alternate_ops) in variants {
        for structural_provider in [false, true] {
            let mut provider = MastForestBuilder::new(&[]).unwrap();
            let body = provider
                .ensure_block_ref(selected_ops.clone(), vec![], vec![], vec![], vec![])
                .unwrap();
            record_test_root(&mut provider, body);
            let provider_root = if structural_provider {
                provider
                    .ensure_loop_node_ref(body, test_asm_op("provider", "while.true"), vec![])
                    .unwrap()
            } else {
                body
            };
            record_test_root(&mut provider, provider_root);
            let (provider_forest, provider_ids) = provider.build().unwrap().into_parts();
            let provider_root_id = provider_ids[&provider_root];
            let digest = provider_forest[provider_root_id].digest();

            let mut builder = MastForestBuilder::new([&provider_forest]).unwrap();
            // Reserve a structural placeholder and parent before code materialization. Their
            // stable refs must acquire the provider's full identity, including through ancestors.
            let external = builder
                .intern_pending_node(PendingMastNodeDraft::new(
                    PendingMastNodeKind::External,
                    digest,
                    vec![],
                ))
                .unwrap();
            let parent = builder
                .ensure_loop_node_ref(external, test_asm_op("caller", "while.true"), vec![])
                .unwrap();
            let old_parent_key = builder.nodes[parent].key;
            record_test_root(&mut builder, parent);
            let selected = builder
                .ensure_external_link_with_source_ref(
                    digest,
                    Some(provider_forest.commitment()),
                    Some(provider_root_id),
                    None,
                )
                .unwrap();
            assert_eq!(selected, external);
            assert!(!builder.nodes[selected].kind.is_external());
            assert_ne!(builder.nodes[selected].key, builder.nodes[selected].digest);
            assert_ne!(builder.nodes[parent].key, old_parent_key);

            let selected_body = if structural_provider {
                builder.nodes[selected].child_refs[0]
            } else {
                selected
            };
            let alternate_body = builder
                .ensure_block_ref(alternate_ops.clone(), vec![], vec![], vec![], vec![])
                .unwrap();
            let alternate = if structural_provider {
                builder
                    .ensure_loop_node_ref(
                        alternate_body,
                        test_asm_op("provider", "while.true"),
                        vec![],
                    )
                    .unwrap()
            } else {
                alternate_body
            };
            let alternate_parent = builder
                .ensure_loop_node_ref(alternate, test_asm_op("caller", "while.true"), vec![])
                .unwrap();
            record_test_root(&mut builder, alternate_parent);
            assert_ne!(selected_body, alternate_body);
            assert_ne!(selected, alternate);
            assert_ne!(parent, alternate_parent);
            assert_eq!(builder.nodes[selected].digest, builder.nodes[alternate].digest);
            assert_eq!(builder.nodes[parent].digest, builder.nodes[alternate_parent].digest);
            let imported_boundary = builder
                .ensure_node_from_statically_linked_source_ref(
                    MastNode::External(ExternalNodeBuilder::new(digest).build()),
                    vec![],
                    None,
                )
                .unwrap();
            assert_eq!(imported_boundary, selected);
            assert_eq!(
                builder
                    .ensure_loop_node_ref(
                        imported_boundary,
                        test_asm_op("caller", "while.true"),
                        vec![]
                    )
                    .unwrap(),
                parent,
                "a refreshed existing parent must deduplicate with the same selected layout",
            );
            for exact_source in [false, true] {
                let repeated = builder
                    .ensure_external_link_with_source_ref(
                        digest,
                        exact_source.then_some(provider_forest.commitment()),
                        exact_source.then_some(provider_root_id),
                        None,
                    )
                    .unwrap();
                assert_eq!(repeated, selected, "later externals must select the static provider");
            }
            assert_eq!(
                builder
                    .ensure_block_ref(selected_ops.clone(), vec![], vec![], vec![], vec![])
                    .unwrap(),
                selected_body,
            );
            let (forest, ids, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
            for (body_ref, expected_ops) in
                [(selected_body, &selected_ops), (alternate_body, &alternate_ops)]
            {
                let MastNode::Block(block) = &forest[ids[&body_ref]] else {
                    panic!("each same-digest body must retain its own raw operations")
                };
                assert_eq!(block.raw_operations().copied().collect::<Vec<_>>(), *expected_ops);
            }
            assert_source_children_match_execution(&forest, &debug);
        }
    }
}

#[test]
fn source_finalization_rejects_cycles_and_missing_children() {
    for missing_child in [false, true] {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let body = builder
            .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let parent = builder
            .ensure_loop_node_use(body, test_asm_op("caller", "while.true"), vec![])
            .unwrap();
        builder.record_procedure_root_use(parent);
        let child = if missing_child {
            SourceNodeRef::from(u32::MAX)
        } else {
            parent.source_ref()
        };
        builder.debug_info[parent.source_ref()].children = vec![child];
        let error = builder.build().err().expect("invalid source DAGs must return diagnostics");
        let error = error.downcast_ref::<MastForestBuilderError>().unwrap();
        if missing_child {
            assert!(matches!(error, MastForestBuilderError::MissingFinalSourceChild { .. }));
        } else {
            assert!(matches!(error, MastForestBuilderError::CyclicSourceGraph { .. }));
        }
    }
}

#[test]
fn local_external_code_availability_preserves_same_digest_variants_and_their_sources() {
    let variants = [
        (
            vec![Operation::Assert(Felt::from_u32(3))],
            vec![Operation::Assert(Felt::from_u32(11))],
        ),
        (vec![Operation::Add, Operation::Noop], vec![Operation::Add]),
    ];
    for (first_variant, second_variant) in variants {
        for reverse in [false, true] {
            let (first_ops, second_ops) = if reverse {
                (&second_variant, &first_variant)
            } else {
                (&first_variant, &second_variant)
            };
            let digest = BasicBlockNodeBuilder::new(first_ops.clone()).build().unwrap().digest();
            assert_eq!(
                digest,
                BasicBlockNodeBuilder::new(second_ops.clone()).build().unwrap().digest(),
            );
            for external_first in [false, true] {
                let mut builder = MastForestBuilder::new(&[]).unwrap();
                let placeholder = external_first.then(|| {
                    builder.ensure_external_link_with_source_ref(digest, None, None, None).unwrap()
                });
                let original_source = placeholder
                    .map(|node_ref| builder.latest_node_use(node_ref).unwrap().source_ref());
                let first_asm =
                    add_test_asm_op(&mut builder, test_asm_op("first_definition", "body"));
                let first = builder
                    .ensure_block_use(first_ops.clone(), vec![first_asm], vec![], vec![], vec![])
                    .unwrap();
                if let Some(placeholder) = placeholder {
                    assert_eq!(placeholder, first.node_ref());
                }
                let external =
                    builder.ensure_external_link_with_source_ref(digest, None, None, None).unwrap();
                assert_eq!(external, first.node_ref());
                assert_eq!(
                    builder.latest_node_use(external).unwrap().source_ref(),
                    first.source_ref()
                );

                let second_asm =
                    add_test_asm_op(&mut builder, test_asm_op("second_definition", "body"));
                let second = builder
                    .ensure_block_use(second_ops.clone(), vec![second_asm], vec![], vec![], vec![])
                    .unwrap();
                assert_ne!(first.node_ref(), second.node_ref());
                assert_ne!(
                    builder.nodes[first.node_ref()].key,
                    builder.nodes[second.node_ref()].key
                );
                assert_eq!(
                    builder.nodes[first.node_ref()].digest,
                    builder.nodes[second.node_ref()].digest
                );
                let repeated =
                    builder.ensure_external_link_with_source_ref(digest, None, None, None).unwrap();
                assert_eq!(repeated, first.node_ref(), "local D availability must remain stable");
                assert_eq!(
                    builder.latest_node_use(repeated).unwrap().source_ref(),
                    first.source_ref()
                );
                builder.record_procedure_root_use(first);
                builder.record_procedure_root_use(second);
                let (forest, ids, debug, source_ids) =
                    builder.build().unwrap().into_parts_with_debug_info();
                let first_id = ids[&first.node_ref()];
                let second_id = ids[&second.node_ref()];
                assert_ne!(first_id, second_id);
                for (node_id, expected_ops, source_ref, expected_context) in [
                    (first_id, first_ops, first.source_ref(), "first_definition"),
                    (second_id, second_ops, second.source_ref(), "second_definition"),
                ] {
                    let MastNode::Block(block) = &forest[node_id] else {
                        panic!("local code variants must remain concrete blocks")
                    };
                    assert_eq!(block.raw_operations().copied().collect::<Vec<_>>(), *expected_ops);
                    let source = &debug[source_ids[&source_ref]];
                    assert_eq!(source.exec_node, node_id);
                    assert_eq!(
                        debug[source.asm_ops[0].context_name_idx].as_ref(),
                        expected_context
                    );
                    assert!(
                        source_asm_contexts(&debug, node_id)
                            .iter()
                            .all(|context| context == expected_context)
                    );
                }
                if let Some(original_source) = original_source {
                    let source = &debug[source_ids[&original_source]];
                    assert_eq!(source.exec_node, first_id);
                    assert_eq!(
                        debug[source.asm_ops[0].context_name_idx].as_ref(),
                        "first_definition"
                    );
                }
                assert_source_children_match_execution(&forest, &debug);
            }
        }
    }
}

#[test]
fn static_external_child_reuses_local_full_key_code_and_preserves_source_provenance() {
    let variants = [
        (
            vec![Operation::Assert(Felt::from_u32(3))],
            vec![Operation::Assert(Felt::from_u32(11))],
        ),
        (vec![Operation::Add, Operation::Noop], vec![Operation::Add]),
    ];
    for (first_variant, second_variant) in variants {
        let digest = BasicBlockNodeBuilder::new(first_variant.clone()).build().unwrap().digest();
        let mut source = MastForestBuilder::new(&[]).unwrap();
        let external =
            source.ensure_external_link_with_source_ref(digest, None, None, None).unwrap();
        let external_source = source.latest_node_use(external).unwrap().source_ref();
        let wrapper = source
            .ensure_loop_node_ref(external, test_asm_op("static_wrapper", "while.true"), vec![])
            .unwrap();
        record_test_root(&mut source, wrapper);
        let debug = source.debug_info_mut();
        let location = debug.add_location(Location::new(
            Uri::from("file:///static-external-child.masm"),
            ByteIndex::from(0_u32),
            ByteIndex::from(1_u32),
        ));
        let file = debug.debug_info().locations()[location].file_idx;
        let name = debug.add_string("static_external_decl");
        debug.add_function(FunctionInfo::new(
            Some(external_source),
            name,
            file,
            LineNumber::new(1).unwrap(),
            ColumnNumber::new(1).unwrap(),
            digest,
        ));
        let (source_forest, source_ids, source_debug, _) =
            source.build().unwrap().into_parts_with_debug_info();
        let wrapper_id = source_ids[&wrapper];

        for reverse in [false, true] {
            let (first_ops, second_ops) = if reverse {
                (&second_variant, &first_variant)
            } else {
                (&first_variant, &second_variant)
            };
            for include_debug in [false, true] {
                for exact_source in [false, true] {
                    let mut builder = MastForestBuilder::new_with_static_libraries([
                        StaticLibrary::from_mast_forest(
                            &source_forest,
                            include_debug.then(|| source_debug.as_ref().clone()),
                        ),
                    ])
                    .unwrap();
                    let first_asm =
                        add_test_asm_op(&mut builder, test_asm_op("local_selected", "body"));
                    let first = builder
                        .ensure_block_use(
                            first_ops.clone(),
                            vec![first_asm],
                            vec![],
                            vec![],
                            vec![],
                        )
                        .unwrap();
                    let second_asm =
                        add_test_asm_op(&mut builder, test_asm_op("local_alternate", "body"));
                    let second = builder
                        .ensure_block_use(
                            second_ops.clone(),
                            vec![second_asm],
                            vec![],
                            vec![],
                            vec![],
                        )
                        .unwrap();
                    builder.record_procedure_root_use(first);
                    builder.record_procedure_root_use(second);
                    let imported = builder
                        .ensure_external_link_with_source_ref(
                            source_forest[wrapper_id].digest(),
                            exact_source.then_some(source_forest.commitment()),
                            exact_source.then_some(wrapper_id),
                            None,
                        )
                        .unwrap();
                    let repeated = builder
                        .ensure_external_link_with_source_ref(digest, None, None, None)
                        .unwrap();
                    assert_eq!(repeated, first.node_ref());
                    assert!(!builder.nodes[first.node_ref()].kind.is_external());
                    assert!(builder.external_boundary_source_refs.is_empty());
                    let (forest, ids, debug, _) =
                        builder.build().unwrap().into_parts_with_debug_info();
                    let first_id = ids[&first.node_ref()];
                    let second_id = ids[&second.node_ref()];
                    let imported_id = ids[&imported];
                    let MastNode::Loop(wrapper) = &forest[imported_id] else {
                        panic!("the static wrapper must retain its structural shape")
                    };
                    assert_eq!(wrapper.body(), first_id);
                    assert_ne!(wrapper.body(), second_id);
                    for (body_id, ops, context) in [
                        (first_id, first_ops, "local_selected"),
                        (second_id, second_ops, "local_alternate"),
                    ] {
                        let MastNode::Block(body) = &forest[body_id] else {
                            panic!("local source layouts must remain concrete blocks")
                        };
                        assert_eq!(body.raw_operations().copied().collect::<Vec<_>>(), *ops);
                        assert!(
                            source_asm_contexts(&debug, body_id)
                                .iter()
                                .all(|actual| actual == context)
                        );
                    }
                    let declaration = debug.functions().iter().find(|function| {
                        debug[function.name_idx].as_ref() == "static_external_decl"
                    });
                    if exact_source && include_debug {
                        let declaration_source =
                            declaration.unwrap().source_node.into_option().unwrap();
                        let declaration_source = &debug[declaration_source];
                        assert_eq!(declaration_source.exec_node, first_id);
                        assert_eq!(
                            debug[declaration_source.asm_ops[0].context_name_idx].as_ref(),
                            "local_selected",
                        );
                        assert!(
                            source_asm_contexts(&debug, imported_id)
                                .contains(&"static_wrapper".to_string())
                        );
                    } else {
                        assert!(declaration.is_none());
                        assert!(source_asm_contexts(&debug, imported_id).is_empty());
                    }
                    assert_source_children_match_execution(&forest, &debug);
                }
            }
        }
    }
}
