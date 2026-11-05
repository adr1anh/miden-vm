// DEBUG INFO
// ================================================================================================

use miden_core::program::{CanonicalLabel, ProcedureKey};
use miden_mast_package::{
    NamespacePlan,
    debug_info::{DebugFunctionInfo, DebugSourceNodeId, PackageDebugInfo},
};

use super::*;
use crate::testing::FixtureNamespace;

fn dependency_fixture_namespace() -> FixtureNamespace {
    FixtureNamespace::new(NamespacePlan::new(vec![
        CanonicalLabel::text("debug-info-dependency-fixtures").unwrap(),
        CanonicalLabel::revision(core::num::NonZeroU32::new(1).unwrap()),
    ]))
}

fn configure_debug_fixture(
    assembler: Assembler,
    bindings: &mut FixtureNamespace,
    modules: &[&Module],
) -> Result<Assembler, Report> {
    for module in modules {
        bindings.add_module(module)?;
    }
    bindings.configure(assembler, modules.iter().copied())
}

fn add_debug_package_bindings(
    bindings: &mut FixtureNamespace,
    package: &Package,
    foreign: &FixtureNamespace,
) -> TestResult {
    for export in package.manifest.exports().filter_map(|export| export.as_procedure()) {
        let binding = foreign
            .binding(&export.path)
            .expect("foreign fixture must name each concrete package descriptor");
        bindings.add_binding(export.path.clone(), binding.clone())?;
    }
    Ok(())
}

fn add_debug_reexport_binding(
    bindings: &mut FixtureNamespace,
    definition: &str,
    alias: &str,
) -> TestResult {
    let binding = bindings.binding(Path::new(definition)).unwrap().clone();
    bindings.add_binding(Arc::from(Path::new(alias)), binding)?;
    Ok(())
}

fn debug_function<'a>(debug: &'a PackageDebugInfo, name: &str) -> &'a DebugFunctionInfo {
    let mut functions = debug.functions().iter().filter(|function| {
        let index = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
        debug[index].as_ref() == name
    });
    let function = functions.next().unwrap_or_else(|| panic!("missing function {name}"));
    assert!(functions.next().is_none(), "ambiguous function {name}");
    function
}

fn debug_definition_function<'a>(debug: &'a PackageDebugInfo, name: &str) -> &'a DebugFunctionInfo {
    // A bridge may also carry a source-less declaration for the same name. Select the
    // independently retained definition explicitly, without choosing a function by body D.
    let mut functions = debug.functions().iter().filter(|function| {
        let index = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
        debug[index].as_ref() == name && function.source_node.into_option().is_some()
    });
    let function = functions.next().unwrap_or_else(|| panic!("missing definition {name}"));
    assert!(functions.next().is_none(), "ambiguous definition {name}");
    function
}

fn assert_debug_definition(
    package: &Package,
    debug: &PackageDebugInfo,
    function: &DebugFunctionInfo,
) -> DebugSourceNodeId {
    let source = function.source_node.into_option().expect("retained body has a definition");
    let node = debug[source].exec_node;
    assert!(package.mast_forest().procedure_roots().contains(&node));
    assert_eq!(package.mast_forest()[node].digest(), function.mast_root);
    source
}

fn runtime_exec_sources(
    package: &Package,
    debug: &PackageDebugInfo,
    root: DebugSourceNodeId,
) -> Vec<DebugSourceNodeId> {
    reachable_source_nodes(debug, root)
        .into_iter()
        .filter(|source| {
            matches!(package.mast_forest()[debug[*source].exec_node], MastNode::Exec(_))
        })
        .collect()
}

fn assert_runtime_exec_source(
    package: &Package,
    debug: &PackageDebugInfo,
    source: DebugSourceNodeId,
    key: ProcedureKey,
    operation: &str,
) {
    let source = &debug[source];
    let MastNode::Exec(exec) = &package.mast_forest()[source.exec_node] else {
        panic!("runtime invocation must be a keyed EXEC");
    };
    assert_eq!(exec.target(), key);
    assert!(source.children.is_empty(), "runtime EXEC has no callee source child");
    assert_eq!((source.op_start, source.op_end), (0, 1));
    assert_eq!(source.asm_ops.len(), 1);
    let op = &source.asm_ops[0];
    assert_eq!(op.op_idx, 0);
    assert_eq!(op.num_cycles, 1);
    assert_eq!(debug[op.op_name_idx].as_ref(), operation);
}

fn assert_definition_operation(
    package: &Package,
    debug: &PackageDebugInfo,
    root: DebugSourceNodeId,
    expected: &str,
) {
    assert!(
        reachable_source_nodes(debug, root).into_iter().any(|source| {
            debug[source]
                .asm_ops
                .iter()
                .any(|op| debug[op.op_name_idx].as_ref() == expected)
        }),
        "definition must retain {expected}"
    );
    let operation = match expected {
        "add" => Operation::Add,
        "mul" => Operation::Mul,
        "push.42" => Operation::Push(Felt::from_u32(42)),
        "push.43" => Operation::Push(Felt::from_u32(43)),
        _ => panic!("missing concrete fixture operation for {expected}"),
    };
    let mut pending = vec![debug[root].exec_node];
    let mut found = false;
    while let Some(node) = pending.pop() {
        let node = &package.mast_forest()[node];
        if let MastNode::Block(block) = node {
            found |= block.operations().any(|actual| *actual == operation);
        }
        node.append_children_to(&mut pending);
    }
    assert!(found, "independently retained body must execute {expected}");
}

fn replace_nops_with_named_inline_call_markers(
    context: &TestContext,
    procedure: &mut Procedure,
    markers: &[Option<&str>],
) -> Result<(), Report> {
    use miden_assembly_syntax::ast::DebugInlineCallInfo;

    let mut markers = markers.iter();
    for op in procedure.body_mut().iter_mut() {
        let Op::Inst(instruction) = op else {
            continue;
        };
        if !matches!(instruction.inner(), Instruction::Nop) {
            continue;
        }
        let Some(marker) = markers.next() else {
            break;
        };

        let span = instruction.span();
        let replacement = match marker {
            Some(name) => {
                let source_location = context
                    .source_manager()
                    .file_line_col(span)
                    .map_err(|error| Report::msg(error.to_string()))?;
                Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                    *name,
                    source_location.clone(),
                    source_location,
                ))
            },
            None => Instruction::DebugInlineCallClear,
        };
        *op = Op::Inst(Span::new(span, replacement));
    }

    assert!(markers.next().is_none(), "test fixture has too few marker placeholders");
    Ok(())
}

fn reachable_source_nodes(
    debug_info: &PackageDebugInfo,
    root: DebugSourceNodeId,
) -> BTreeSet<DebugSourceNodeId> {
    let mut reachable = BTreeSet::new();
    let mut worklist = vec![root];
    while let Some(source_node_id) = worklist.pop() {
        if reachable.insert(source_node_id) {
            worklist.extend(debug_info[source_node_id].children.iter().copied());
        }
    }
    reachable
}

#[test]
fn inline_call_chains_are_recorded_on_call_and_structured_control_occurrences() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
        end

        begin
            nop
            nop
            call.callee
            nop
            nop
            if.true
                add
            else
                mul
            end
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::inlined"), None, Some("source::inlined")],
    )?;

    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");

    for expected_op in ["call.", "if.true"] {
        let source_node = debug_info
            .nodes()
            .iter()
            .find(|source_node| {
                source_node
                    .asm_ops
                    .iter()
                    .any(|asm_op| debug_info[asm_op.op_name_idx].starts_with(expected_op))
            })
            .unwrap_or_else(|| panic!("missing source occurrence for {expected_op}"));
        let inline_calls = source_node
            .inline_calls
            .iter()
            .filter(|inline_call| inline_call.contains_operation(0))
            .collect::<Vec<_>>();

        assert_eq!(inline_calls.len(), 1, "{expected_op} should retain its inline chain");
        let function = debug_info
            .get_function(inline_calls[0].callee_idx)
            .expect("inline callee should be registered");
        assert_eq!(debug_info[function.name_idx].as_ref(), "source::inlined");
        if expected_op == "call." {
            let MastNode::Call(call) = &package.mast_forest()[source_node.exec_node] else {
                panic!("call source occurrence must retain its invocation mode");
            };
            assert!(!call.is_syscall());
            assert_eq!(
                call.target(),
                bindings.binding(Path::new("::$exec::callee")).unwrap().key()
            );
            assert!(source_node.children.is_empty());
            assert_eq!((source_node.op_start, source_node.op_end), (0, 1));
            assert_eq!(source_node.asm_ops.len(), 1);
            assert_eq!(source_node.asm_ops[0].num_cycles, 1);
        }
    }
    let callee = assert_debug_definition(
        &package,
        &debug_info,
        debug_function(&debug_info, "::$exec::callee"),
    );
    assert_definition_operation(&package, &debug_info, callee, "add");
    assert!(debug_info[callee].inline_calls.is_empty());
    Ok(())
}

#[test]
fn explicit_inline_call_chains_cover_expanded_source_occurrences() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
            mul
        end

        begin
            nop
            nop
            inline.callee
            nop
            nop
            inline.callee
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::inlined"), None, Some("source::inlined")],
    )?;

    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");

    let callee_source = debug_info
        .nodes()
        .iter()
        .find(|source_node| {
            source_node
                .asm_ops
                .iter()
                .any(|asm_op| debug_info[asm_op.context_name_idx].contains("callee"))
                && !source_node.inline_calls.is_empty()
        })
        .expect("explicit inline target should have a decorated source occurrence");
    for asm_op in callee_source
        .asm_ops
        .iter()
        .filter(|asm_op| debug_info[asm_op.context_name_idx].contains("callee"))
    {
        assert_eq!(
            callee_source
                .inline_calls
                .iter()
                .filter(|inline_call| inline_call.contains_operation(asm_op.op_idx))
                .count(),
            2,
            "every operation in the explicit inline target should retain the active inline chain",
        );
    }

    Ok(())
}

#[test]
fn explicit_inline_occurrences_do_not_reuse_stale_chains() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
            mul
        end

        begin
            nop
            nop
            inline.callee
            nop
            inline.callee
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::decorated"), None],
    )?;

    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");
    let entrypoint_source = package
        .entrypoint_source_node()
        .expect("executable should identify its entrypoint source occurrence");
    let reachable = reachable_source_nodes(&debug_info, entrypoint_source);
    let mut inline_counts = Vec::new();
    for source_node_id in reachable {
        for asm_op in &debug_info[source_node_id].asm_ops {
            if debug_info[asm_op.context_name_idx].contains("callee") {
                inline_counts.push(
                    debug_info.inline_calls_for_operation(source_node_id, asm_op.op_idx).count(),
                );
            }
        }
    }
    assert_eq!(
        inline_counts,
        [2, 2, 1, 1],
        "the plain inline expansion must not inherit the earlier inline chain",
    );

    Ok(())
}

#[test]
fn nested_explicit_inline_chains_are_innermost_first() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc inner
            add
        end

        proc outer_target
            nop
            nop
            inline.inner
        end

        begin
            nop
            nop
            inline.outer_target
        end
        "
    );
    let mut module = context.parse_module(source)?;
    for procedure in module.procedures_mut() {
        if procedure.is_entrypoint() {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::outer")],
            )?;
        } else if procedure.name().as_str() == "outer_target" {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::inner")],
            )?;
        }
    }

    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");
    let entrypoint_source = package
        .entrypoint_source_node()
        .expect("executable should identify its entrypoint source occurrence");
    let reachable = reachable_source_nodes(&debug_info, entrypoint_source);
    let inner_source = reachable
        .into_iter()
        .find(|source_node_id| {
            debug_info[*source_node_id].asm_ops.iter().any(|asm_op| {
                debug_info[asm_op.context_name_idx].contains("inner")
                    && debug_info[asm_op.op_name_idx].as_ref() == "add"
            })
        })
        .expect("nested explicit inline target should be reachable from the entrypoint");
    let inner_op = debug_info[inner_source]
        .asm_ops
        .iter()
        .find(|asm_op| debug_info[asm_op.op_name_idx].as_ref() == "add")
        .expect("inner target should contain add");
    let names = debug_info
        .inline_calls_for_operation(inner_source, inner_op.op_idx)
        .map(|inline_call| {
            let function = debug_info
                .get_function(inline_call.callee_idx)
                .expect("inline callee should be registered");
            debug_info[function.name_idx].to_string()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        ["::$exec::inner", "source::inner", "::$exec::outer_target", "source::outer"]
    );
    Ok(())
}

#[test]
fn external_exec_records_inline_context_at_the_boundary() -> TestResult {
    let context = TestContext::default();
    let library_module = context.parse_module("namespace dep::math\npub proc callee add end")?;
    let mut foreign = dependency_fixture_namespace();
    let library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&library_module],
    )?
    .assemble_library("dep", library_module, None::<Box<Module>>)?;
    let expected_root =
        library.mast_forest()[library.get_export_node_id("dep::math::callee")].digest();
    let key = foreign.binding(Path::new("::dep::math::callee")).unwrap().key();
    let source = source_file!(&context, "use dep::math\nbegin nop nop exec.math::callee end");
    let mut module = context.parse_module(source)?;
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::external")],
    )?;
    let mut bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bindings, &library, &foreign)?;
    let library_naming = foreign.admit_package(&library)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::from(library),
        Linkage::Dynamic,
        library_naming,
    )?;
    let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
        .assemble_program("test", module)?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let root = package.entrypoint_source_node().unwrap();
    let sources = runtime_exec_sources(&package, &debug, root);
    assert_eq!(sources.len(), 1);
    assert_runtime_exec_source(&package, &debug, sources[0], key, "exec.math::callee");
    let rows = &debug[sources[0]].inline_calls;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].op_idx, rows[0].op_end), (0, 1));
    let annotation = debug.get_function(rows[0].callee_idx).unwrap();
    assert_eq!(debug[annotation.name_idx].as_ref(), "source::external");
    let callee = debug_function(&debug, "::dep::math::callee");
    assert_eq!(callee.mast_root, expected_root);
    assert_eq!(callee.source_node.into_option(), None);
    assert!(package.mast_forest().procedure_roots().iter().any(|node| {
        let body = &package.mast_forest()[*node];
        body.is_external() && body.digest() == expected_root
    }));
    Ok(())
}

#[test]
fn compact_explicit_inline_ranges_survive_padding_and_pinned_static_linking() -> TestResult {
    let context = TestContext::default();
    let body = "push.1 drop\n".repeat(200);
    let mut library_module = context.parse_module(source_file!(
        &context,
        format!("namespace dep::math pub proc callee nop {body} nop push.2 drop end")
    ))?;
    let callee = library_module.procedures_mut().next().unwrap();
    replace_nops_with_named_inline_call_markers(&context, callee, &[Some("source::inner"), None])?;
    let mut foreign = dependency_fixture_namespace();
    let library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&library_module],
    )?
    .assemble_library("dep", library_module, None::<Box<Module>>)?;
    let expected_implementation = miden_core::program::ImplementationRoot::new(
        library.mast_forest()[library.get_export_node_id("dep::math::callee")].digest(),
    );
    let info = library.debug_info().into_diagnostic()?.unwrap();
    assert_eq!(info.nodes().iter().map(|node| node.inline_calls.len()).sum::<usize>(), 1);

    let mut module = context
        .parse_module(source_file!(&context, "use dep::math begin nop inline.math::callee end"))?;
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(&context, entrypoint, &[Some("source::outer")])?;
    let mut bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bindings, &library, &foreign)?;
    let library_naming = foreign.admit_package(&library)?;
    let assembler = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Static, library_naming)?
        .with_pinned_callable(
            Arc::from(Path::new("::dep::math::callee")),
            expected_implementation,
        )?;
    let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
        .assemble_program("test", module)?;
    let info = package.debug_info().into_diagnostic()?.unwrap();
    let mut checked = BTreeSet::new();
    let entrypoint = package.entrypoint_source_node().unwrap();
    for source_id in reachable_source_nodes(&info, entrypoint) {
        let node = &info[source_id];
        for operation in &node.asm_ops {
            let name = info[operation.op_name_idx].as_ref();
            if !matches!(name, "push.1" | "push.2") {
                continue;
            }
            let chain = info
                .inline_calls_for_operation(source_id, operation.op_idx)
                .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
                .collect::<Vec<_>>();
            let expected = if name == "push.1" {
                vec!["source::inner", "::dep::math::callee", "source::outer"]
            } else {
                vec!["::dep::math::callee", "source::outer"]
            };
            assert_eq!(chain, expected);
            checked.insert(operation.op_idx);
        }
    }
    assert_eq!(checked.len(), 201);
    let callee = debug_function(&info, "::dep::math::callee");
    assert_eq!(&callee.mast_root, expected_implementation.as_word());
    let definition = assert_debug_definition(&package, &info, callee);
    let canonical_frames = reachable_source_nodes(&info, definition)
        .into_iter()
        .flat_map(|source| info[source].inline_calls.iter())
        .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
        .collect::<Vec<_>>();
    assert_eq!(canonical_frames, ["source::inner"]);
    Ok(())
}

#[test]
fn many_explicit_inline_ranges_survive_padding_and_pinned_static_linking() -> TestResult {
    let context = TestContext::default();
    let body = "nop nop push.1 drop nop nop push.2 drop\n".repeat(128);
    let mut library_module = context.parse_module(source_file!(
        &context,
        format!("namespace dep::math pub proc callee {body} end")
    ))?;
    let markers = [None, Some("source::first"), None, Some("source::second")].repeat(128);
    let callee = library_module.procedures_mut().next().unwrap();
    replace_nops_with_named_inline_call_markers(&context, callee, &markers)?;
    let mut foreign = dependency_fixture_namespace();
    let library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&library_module],
    )?
    .assemble_library("dep", library_module, None::<Box<Module>>)?;
    let expected_implementation = miden_core::program::ImplementationRoot::new(
        library.mast_forest()[library.get_export_node_id("dep::math::callee")].digest(),
    );
    let info = library.debug_info().into_diagnostic()?.unwrap();
    assert_eq!(info.nodes().iter().map(|node| node.inline_calls.len()).sum::<usize>(), 256);

    let mut module = context
        .parse_module(source_file!(&context, "use dep::math begin nop inline.math::callee end"))?;
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(&context, entrypoint, &[Some("source::outer")])?;
    let mut bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bindings, &library, &foreign)?;
    let library_naming = foreign.admit_package(&library)?;
    let assembler = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Static, library_naming)?
        .with_pinned_callable(
            Arc::from(Path::new("::dep::math::callee")),
            expected_implementation,
        )?;
    let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
        .assemble_program("test", module)?;
    let info = package.debug_info().into_diagnostic()?.unwrap();
    let mut checked = BTreeSet::new();
    let entrypoint = package.entrypoint_source_node().unwrap();
    for source_id in reachable_source_nodes(&info, entrypoint) {
        let node = &info[source_id];
        for operation in &node.asm_ops {
            let name = info[operation.op_name_idx].as_ref();
            let inner = match name {
                "push.1" => "source::first",
                "push.2" => "source::second",
                _ => continue,
            };
            let chain = info
                .inline_calls_for_operation(source_id, operation.op_idx)
                .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
                .collect::<Vec<_>>();
            assert_eq!(chain, vec![inner, "::dep::math::callee", "source::outer"]);
            checked.insert(operation.op_idx);
        }
    }
    assert_eq!(checked.len(), 256);
    let callee = debug_function(&info, "::dep::math::callee");
    assert_eq!(&callee.mast_root, expected_implementation.as_word());
    let definition = assert_debug_definition(&package, &info, callee);
    let canonical_frames = reachable_source_nodes(&info, definition)
        .into_iter()
        .flat_map(|source| info[source].inline_calls.iter())
        .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
        .collect::<Vec<_>>();
    assert_eq!(canonical_frames.len(), 256);
    assert_eq!(canonical_frames.iter().filter(|name| **name == "source::first").count(), 128);
    assert_eq!(canonical_frames.iter().filter(|name| **name == "source::second").count(), 128);
    Ok(())
}

#[test]
fn source_name_attribute_sets_debug_name_and_linkage_name() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace debug::names

        @source_name("duplicate")
        pub proc first
            push.1
        end

        @source_name("duplicate")
        pub proc second
            push.2
        end

        pub proc normal
            push.3
        end
        "#
    ))?;
    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_library("debug-names", module, None::<Box<Module>>)?;

    let assert_function_names = |package: &Package| {
        let debug_info = package
            .debug_info()
            .expect("package debug info should decode")
            .expect("package should contain debug info");
        let duplicate_functions = debug_info
            .functions()
            .iter()
            .filter(|function| {
                debug_info[function.name_idx].as_ref() == "::debug::names::duplicate"
            })
            .collect::<Vec<_>>();

        assert_eq!(duplicate_functions.len(), 2);
        assert_eq!(duplicate_functions[0].name_idx, duplicate_functions[1].name_idx);
        let linkage_names = duplicate_functions
            .iter()
            .map(|function| {
                let linkage_name_idx = function
                    .linkage_name_idx
                    .into_option()
                    .expect("source-named function should have a linkage name");
                debug_info[linkage_name_idx].to_string()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(linkage_names.len(), 2);
        assert!(linkage_names.iter().any(|name| name.ends_with("::first")));
        assert!(linkage_names.iter().any(|name| name.ends_with("::second")));

        let normal = debug_info
            .functions()
            .iter()
            .find(|function| debug_info[function.name_idx].ends_with("::normal"))
            .expect("normal function should retain its assembler path as its name");
        assert_eq!(normal.linkage_name_idx.into_option(), None);
    };

    assert_function_names(&package);
    let round_tripped = Package::read_from_bytes(&package.to_bytes())
        .expect("package with source-named functions should round trip");
    assert_function_names(&round_tripped);

    Ok(())
}

#[test]
fn malformed_source_name_attributes_are_rejected() -> TestResult {
    let context = TestContext::default();

    for attribute in [
        "@source_name",
        "@source_name(unquoted)",
        "@source_name(\"one\", \"two\")",
        "@source_name(value = \"named\")",
    ] {
        let source = source_file!(
            &context,
            format!(
                r#"
                namespace debug::invalid

                {attribute}
                pub proc test
                    nop
                end
                "#
            )
        );
        let module = context.parse_module(source)?;
        let mut bindings = FixtureNamespace::assembly_tests();
        let error = configure_debug_fixture(
            Assembler::new(context.source_manager()),
            &mut bindings,
            &[&module],
        )?
        .assemble_library("invalid-source-name", module, None::<Box<Module>>)
        .expect_err("malformed @source_name should be rejected");
        assert_diagnostic!(&error, "invalid `@source_name` procedure attribute");
        assert_diagnostic!(&error, "expected exactly one quoted string");
    }

    Ok(())
}

#[test]
fn plain_exec_preserves_canonical_definitions() -> TestResult {
    for visibility in ["pub ", ""] {
        let context = TestContext::default();
        let module = context.parse_module(format!(
            "namespace debug::repro\n{visibility}proc leaf push.42 end\npub proc twin push.42 end\npub proc wrapper exec.leaf end"
        ))?;
        let mut bindings = FixtureNamespace::assembly_tests();
        let package = configure_debug_fixture(
            Assembler::new(context.source_manager()),
            &mut bindings,
            &[&module],
        )?
        .assemble_library("probe", module, None::<Box<Module>>)?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let leaf = debug_function(&debug, "::debug::repro::leaf");
        let twin = debug_function(&debug, "::debug::repro::twin");
        let wrapper = debug_function(&debug, "::debug::repro::wrapper");
        assert_eq!(leaf.mast_root, twin.mast_root);
        assert_ne!(leaf.mast_root, wrapper.mast_root);
        let leaf_source = assert_debug_definition(&package, &debug, leaf);
        let twin_source = assert_debug_definition(&package, &debug, twin);
        let wrapper_source = assert_debug_definition(&package, &debug, wrapper);
        assert_ne!(leaf_source, twin_source);
        assert_ne!(leaf_source, wrapper_source);
        assert!(debug[leaf_source].inline_calls.is_empty());
        assert!(debug[twin_source].inline_calls.is_empty());
        assert_definition_operation(&package, &debug, leaf_source, "push.42");
        assert_definition_operation(&package, &debug, twin_source, "push.42");
        let leaf_key = bindings.binding(Path::new("::debug::repro::leaf")).unwrap().key();
        let twin_key = bindings.binding(Path::new("::debug::repro::twin")).unwrap().key();
        assert_ne!(leaf_key, twin_key, "equal bodies retain different callable keys");
        assert_runtime_exec_source(&package, &debug, wrapper_source, leaf_key, "exec.leaf");
        assert!(debug[wrapper_source].inline_calls.is_empty());
    }
    Ok(())
}

#[test]
fn plain_exec_preserves_invocation_identity_through_merging() -> TestResult {
    use miden_assembly_syntax::debuginfo::{SourceLanguage, Uri};

    let source = "proc leaf push.42 end\nproc wrapper exec.leaf end\nbegin\n exec.wrapper\n drop\n exec.wrapper\n drop\nend";
    let assemble = |text: &str| -> Result<_, Report> {
        let context = TestContext::default();
        let file = context.source_manager().load(
            SourceLanguage::Masm,
            Uri::new("memory://reproducer.masm"),
            text.to_string(),
        );
        let module = context.parse_module(file)?;
        let mut bindings = FixtureNamespace::assembly_tests();
        let package = configure_debug_fixture(
            Assembler::new(context.source_manager()),
            &mut bindings,
            &[&module],
        )?
        .assemble_program("program", module)?;
        Ok((package, bindings))
    };
    let (wrapper_package, bindings) = assemble(source)?;
    let (leaf_package, _) =
        assemble(&source.replace("exec.wrapper\n drop\nend", "exec.leaf   \n drop\nend"))?;
    // Replacing a runtime target changes K, even when the selected bodies used to inline equally.
    assert_ne!(wrapper_package.mast_forest().to_bytes(), leaf_package.mast_forest().to_bytes());
    let debug = wrapper_package.debug_info().into_diagnostic()?.unwrap();
    let decoded = PackageDebugInfo::read_from_bytes(&debug.to_bytes()).into_diagnostic()?;
    assert_eq!(decoded, debug);
    assert_ne!(
        debug.to_bytes(),
        leaf_package.debug_info().into_diagnostic()?.unwrap().to_bytes()
    );
    let root = wrapper_package.entrypoint_source_node().unwrap();
    let calls = runtime_exec_sources(&wrapper_package, &debug, root);
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0], calls[1], "repeated keyed controls retain separate source occurrences");
    let wrapper_key = bindings.binding(Path::new("::$exec::wrapper")).unwrap().key();
    let mut locations = Vec::new();
    for call in calls {
        assert_runtime_exec_source(&wrapper_package, &debug, call, wrapper_key, "exec.wrapper");
        assert!(debug[call].inline_calls.is_empty());
        let op = &debug[call].asm_ops[0];
        let location = debug.get_location(op.location_idx.into_option().unwrap()).unwrap();
        assert_eq!(location.uri, Uri::new("memory://reproducer.masm"));
        locations.push((location.start.to_u32(), location.end.to_u32()));
    }
    locations.sort();
    assert_eq!(
        locations,
        source
            .match_indices("exec.wrapper")
            .map(|(start, _)| { (start as u32, (start + "exec.wrapper".len()) as u32) })
            .collect::<Vec<_>>()
    );
    let leaf = debug_function(&debug, "::$exec::leaf");
    let wrapper = debug_function(&debug, "::$exec::wrapper");
    let leaf_source = assert_debug_definition(&wrapper_package, &debug, leaf);
    let wrapper_source = assert_debug_definition(&wrapper_package, &debug, wrapper);
    assert_ne!(leaf_source, wrapper_source);
    assert_ne!(leaf_source, root);
    assert_ne!(wrapper_source, root);
    assert_definition_operation(&wrapper_package, &debug, leaf_source, "push.42");
    assert_runtime_exec_source(
        &wrapper_package,
        &debug,
        wrapper_source,
        bindings.binding(Path::new("::$exec::leaf")).unwrap().key(),
        "exec.leaf",
    );
    assert!(debug[leaf_source].inline_calls.is_empty());
    assert!(debug[wrapper_source].inline_calls.is_empty());
    Ok(())
}

#[test]
fn explicit_inline_ranges_cover_only_expanded_operations() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(
        "proc leaf push.42 neg end\nproc wrapper inline.leaf end\nbegin push.7 inline.wrapper drop drop end",
    )?;
    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let root = package.entrypoint_source_node().unwrap();
    let inlined_start = debug[root]
        .asm_ops
        .iter()
        .find(|op| debug[op.op_name_idx].as_ref() == "push.42")
        .unwrap()
        .op_idx;
    let inlined_end = debug[root]
        .asm_ops
        .iter()
        .find(|op| debug[op.op_name_idx].as_ref() == "neg")
        .unwrap()
        .op_idx
        + 1;
    assert_eq!(inlined_end - inlined_start, 2);
    let calls = debug.inline_calls_for_source_node(root).collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert_eq!((call.op_idx, call.op_end), (inlined_start, inlined_end));
    }
    for op_idx in 0..debug[root].op_end {
        let names = debug
            .inline_calls_for_operation(root, op_idx)
            .map(|call| debug[debug.get_function(call.callee_idx).unwrap().name_idx].to_string())
            .collect::<Vec<_>>();
        if (inlined_start..inlined_end).contains(&op_idx) {
            assert_eq!(names.len(), 2);
            assert!(names[0].ends_with("::leaf"));
            assert!(names[1].ends_with("::wrapper"));
        } else {
            assert!(names.is_empty(), "caller operation {op_idx} must not inherit inline frames");
        }
    }
    Ok(())
}

#[test]
fn plain_exec_preserves_imported_alias_identity() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(
        "namespace dep::math\n@source_name(\"same\")\npub proc leaf() -> felt\n push.42\nend\n@source_name(\"same\")\npub proc wrapper() -> felt\n exec.leaf\nend",
    )?;
    let mut foreign = dependency_fixture_namespace();
    let library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&module],
    )?
    .assemble_library("dep", module, None::<Box<Module>>)?;
    let library = Arc::new(Package::read_from_bytes(&library.to_bytes()).into_diagnostic()?);
    let leaf_key = foreign.binding(Path::new("::dep::math::leaf")).unwrap().key();
    let wrapper_key = foreign.binding(Path::new("::dep::math::wrapper")).unwrap().key();
    for (linkage, tail) in
        [(Linkage::Static, ""), (Linkage::Static, "drop"), (Linkage::Dynamic, "drop")]
    {
        let source = if tail.is_empty() {
            "use dep::math\nproc caller exec.math::wrapper end\nbegin call.caller end".to_string()
        } else {
            format!("use dep::math\nbegin exec.math::wrapper {tail} exec.math::wrapper {tail} end")
        };
        let module = context.parse_module(source)?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &library, &foreign)?;
        let assembler = Assembler::new(context.source_manager()).with_package(
            Arc::clone(&library),
            linkage,
            foreign.admit_package(&library)?,
        )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let caller = if tail.is_empty() {
            assert_debug_definition(&package, &debug, debug_function(&debug, "::$exec::caller"))
        } else {
            root
        };
        let calls = runtime_exec_sources(&package, &debug, caller);
        assert_eq!(calls.len(), if tail.is_empty() { 1 } else { 2 });
        for call in calls {
            assert_runtime_exec_source(&package, &debug, call, wrapper_key, "exec.math::wrapper");
            assert!(debug[call].inline_calls.is_empty());
        }
        for name in ["::dep::math::leaf", "::dep::math::wrapper"] {
            let function = debug_function(&debug, name);
            assert_eq!(debug[function.name_idx].as_ref(), "::dep::math::same");
            assert!(function.type_idx.into_option().is_some());
            assert_ne!(function.mast_root, Word::default());
            if linkage == Linkage::Static {
                let definition = assert_debug_definition(&package, &debug, function);
                assert_ne!(definition, root);
                assert!(debug[definition].inline_calls.is_empty());
                if name.ends_with("::leaf") {
                    assert_definition_operation(&package, &debug, definition, "push.42");
                } else {
                    assert_runtime_exec_source(&package, &debug, definition, leaf_key, "exec.leaf");
                }
            } else {
                assert_eq!(function.source_node.into_option(), None);
            }
        }
    }
    Ok(())
}

#[test]
fn plain_exec_preserves_reexported_function_identity() -> TestResult {
    let context = TestContext::default();
    let root =
        context.parse_module("namespace root\npub use {foo as bar, other as baz} from dep")?;
    let dep = context.parse_module(
        "namespace dep\n@source_name(\"same\")\npub proc foo() -> felt\n push.42\nend\n@source_name(\"same\")\npub proc other() -> felt\n push.42\nend",
    )?;
    let mut foreign = dependency_fixture_namespace();
    let assembler = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&root, &dep],
    )?;
    add_debug_reexport_binding(&mut foreign, "::dep::foo", "::root::bar")?;
    add_debug_reexport_binding(&mut foreign, "::dep::other", "::root::baz")?;
    let library = assembler.assemble_library("dep", root, [dep])?;
    let library = Arc::new(Package::read_from_bytes(&library.to_bytes()).into_diagnostic()?);
    let library_debug = library.debug_info().into_diagnostic()?.unwrap();
    let first = debug_function(&library_debug, "::root::bar");
    let second = debug_function(&library_debug, "::root::baz");
    assert_eq!(first.mast_root, second.mast_root);
    assert_ne!(first.source_node, second.source_node);
    let bar_key = foreign.binding(Path::new("::root::bar")).unwrap().key();
    let baz_key = foreign.binding(Path::new("::root::baz")).unwrap().key();
    assert_ne!(bar_key, baz_key);
    assert_eq!(bar_key, foreign.binding(Path::new("::dep::foo")).unwrap().key());
    assert_eq!(baz_key, foreign.binding(Path::new("::dep::other")).unwrap().key());
    for (linkage, tail) in
        [(Linkage::Static, ""), (Linkage::Static, "drop"), (Linkage::Dynamic, "drop")]
    {
        let source = if tail.is_empty() {
            "use root\nproc first exec.root::bar end\nproc second exec.root::baz end\nbegin call.first call.second end".to_string()
        } else {
            format!("use root\nbegin exec.root::bar {tail} exec.root::baz {tail} end")
        };
        let module = context.parse_module(source)?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &library, &foreign)?;
        let assembler = Assembler::new(context.source_manager()).with_package(
            Arc::clone(&library),
            linkage,
            foreign.admit_package(&library)?,
        )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let package = Package::read_from_bytes(&package.to_bytes()).into_diagnostic()?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let entry = package.entrypoint_source_node().unwrap();
        let callers = if tail.is_empty() {
            ["::$exec::first", "::$exec::second"]
                .into_iter()
                .map(|name| assert_debug_definition(&package, &debug, debug_function(&debug, name)))
                .collect::<Vec<_>>()
        } else {
            vec![entry]
        };
        let calls = callers
            .into_iter()
            .flat_map(|source| runtime_exec_sources(&package, &debug, source))
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        let mut seen_keys = BTreeSet::new();
        for call in calls {
            let operation = debug[debug[call].asm_ops[0].op_name_idx].as_ref();
            let key = match operation {
                "exec.root::bar" => bar_key,
                "exec.root::baz" => baz_key,
                _ => panic!("unexpected invocation {operation}"),
            };
            assert_runtime_exec_source(&package, &debug, call, key, operation);
            assert!(debug[call].inline_calls.is_empty());
            assert!(debug[call].asm_ops[0].location_idx.into_option().is_some());
            seen_keys.insert(key);
        }
        assert_eq!(seen_keys, [bar_key, baz_key].into_iter().collect());
        let functions =
            [debug_function(&debug, "::root::bar"), debug_function(&debug, "::root::baz")];
        assert_eq!(functions[0].mast_root, functions[1].mast_root);
        for (function, linkage_name) in functions.into_iter().zip(["::root::bar", "::root::baz"]) {
            assert_eq!(debug[function.name_idx].as_ref(), "::dep::same");
            let linkage_index = function
                .linkage_name_idx
                .into_option()
                .expect("source-named re-export must retain its canonical linkage name");
            assert_eq!(debug[linkage_index].as_ref(), linkage_name);
            assert!(function.type_idx.into_option().is_some());
            if linkage == Linkage::Static {
                let definition = assert_debug_definition(&package, &debug, function);
                assert_ne!(definition, entry);
                assert_definition_operation(&package, &debug, definition, "push.42");
                assert!(debug[definition].inline_calls.is_empty());
            } else {
                assert_eq!(function.source_node.into_option(), None);
            }
        }
        if linkage == Linkage::Static {
            assert_ne!(functions[0].source_node, functions[1].source_node);
        }
    }
    Ok(())
}

#[test]
fn plain_exec_prefers_named_function_with_shared_provenance() -> TestResult {
    use miden_mast_package::{SectionId, debug_info::PackageDebugInfoBuilder};

    let context = TestContext::default();
    let module = context.parse_module("namespace dep\npub proc foo push.42 end")?;
    let mut foreign = dependency_fixture_namespace();
    let mut library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&module],
    )?
    .assemble_library("dep", module, None::<Box<Module>>)?;
    let key = foreign.binding(Path::new("::dep::foo")).unwrap().key();
    let mut debug =
        PackageDebugInfoBuilder::from(Box::new(library.debug_info().into_diagnostic()?.unwrap()));
    let mut alias = *debug_function(debug.debug_info(), "::dep::foo");
    alias.name_idx = debug.add_string("::dep::alias");
    debug.add_function(alias);
    library
        .sections
        .iter_mut()
        .find(|section| section.id == SectionId::DEBUG_INFO)
        .unwrap()
        .data = debug.build().to_bytes().into();
    let library: Arc<Package> = Arc::from(library);
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        let module = context.parse_module("use dep\nbegin exec.dep::foo drop end")?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &library, &foreign)?;
        let assembler = Assembler::new(context.source_manager()).with_package(
            Arc::clone(&library),
            linkage,
            foreign.admit_package(&library)?,
        )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let calls =
            runtime_exec_sources(&package, &debug, package.entrypoint_source_node().unwrap());
        assert_eq!(calls.len(), 1);
        assert_runtime_exec_source(&package, &debug, calls[0], key, "exec.dep::foo");
        assert!(debug[calls[0]].inline_calls.is_empty());
        let function = debug_function(&debug, "::dep::foo");
        let alias = debug_function(&debug, "::dep::alias");
        assert_eq!(function.mast_root, alias.mast_root);
        assert_eq!(function.source_node, alias.source_node);
        if linkage == Linkage::Static {
            let definition = assert_debug_definition(&package, &debug, function);
            assert_definition_operation(&package, &debug, definition, "push.42");
        } else {
            assert_eq!(function.source_node.into_option(), None);
        }
    }
    Ok(())
}

#[test]
fn plain_exec_preserves_dynamic_dependency_reexports() -> TestResult {
    let context = TestContext::default();
    let dependency_module = context.parse_module(
        "namespace dep\n@source_name(\"same\")\npub proc foo() -> felt\n push.42\nend\n@source_name(\"same\")\npub proc other() -> felt\n push.42\nend",
    )?;
    let mut foreign = dependency_fixture_namespace();
    let dependency = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&dependency_module],
    )?
    .assemble_library("dep", dependency_module, None::<Box<Module>>)?;
    let bridge_module =
        context.parse_module("namespace bridge\npub use {foo as bar, other as baz} from dep")?;
    let mut bridge_bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bridge_bindings, &dependency, &foreign)?;
    add_debug_reexport_binding(&mut bridge_bindings, "::dep::foo", "::bridge::bar")?;
    add_debug_reexport_binding(&mut bridge_bindings, "::dep::other", "::bridge::baz")?;
    let dependency_naming = foreign.admit_package(&dependency)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::from(dependency),
        Linkage::Dynamic,
        dependency_naming,
    )?;
    let bridge = configure_debug_fixture(assembler, &mut bridge_bindings, &[&bridge_module])?
        .assemble_library("bridge", bridge_module, None::<Box<Module>>)?;
    let bridge = Arc::new(Package::read_from_bytes(&bridge.to_bytes()).into_diagnostic()?);
    let bridge_debug = bridge.debug_info().into_diagnostic()?.unwrap();
    for path in ["::bridge::bar", "::bridge::baz"] {
        let function = debug_function(&bridge_debug, path);
        assert_eq!(bridge_debug[function.name_idx].as_ref(), "::dep::same");
        let linkage_index = function
            .linkage_name_idx
            .into_option()
            .expect("source-named re-export must retain its canonical linkage name");
        assert_eq!(bridge_debug[linkage_index].as_ref(), path);
        assert!(function.type_idx.into_option().is_some());
        assert_eq!(function.source_node.into_option(), None);
    }
    let bar_key = bridge_bindings.binding(Path::new("::bridge::bar")).unwrap().key();
    let baz_key = bridge_bindings.binding(Path::new("::bridge::baz")).unwrap().key();
    assert_ne!(bar_key, baz_key);
    assert_eq!(bar_key, foreign.binding(Path::new("::dep::foo")).unwrap().key());
    assert_eq!(baz_key, foreign.binding(Path::new("::dep::other")).unwrap().key());
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        let module = context
            .parse_module("use bridge\nbegin exec.bridge::bar drop exec.bridge::baz drop end")?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &bridge, &bridge_bindings)?;
        let assembler = Assembler::new(context.source_manager()).with_package(
            Arc::clone(&bridge),
            linkage,
            bridge_bindings.admit_package(&bridge)?,
        )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let package = Package::read_from_bytes(&package.to_bytes()).into_diagnostic()?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let calls =
            runtime_exec_sources(&package, &debug, package.entrypoint_source_node().unwrap());
        assert_eq!(calls.len(), 2);
        let mut seen_keys = BTreeSet::new();
        for call in calls {
            let operation = debug[debug[call].asm_ops[0].op_name_idx].as_ref();
            let key = match operation {
                "exec.bridge::bar" => bar_key,
                "exec.bridge::baz" => baz_key,
                _ => panic!("unexpected invocation {operation}"),
            };
            assert_runtime_exec_source(&package, &debug, call, key, operation);
            assert!(debug[call].inline_calls.is_empty());
            assert!(debug[call].asm_ops[0].location_idx.into_option().is_some());
            seen_keys.insert(key);
        }
        assert_eq!(seen_keys, [bar_key, baz_key].into_iter().collect());
        let functions =
            [debug_function(&debug, "::bridge::bar"), debug_function(&debug, "::bridge::baz")];
        assert_eq!(functions[0].mast_root, functions[1].mast_root);
        for (function, linkage_name) in
            functions.into_iter().zip(["::bridge::bar", "::bridge::baz"])
        {
            assert_eq!(debug[function.name_idx].as_ref(), "::dep::same");
            let linkage_index = function
                .linkage_name_idx
                .into_option()
                .expect("source-named re-export must retain its canonical linkage name");
            assert_eq!(debug[linkage_index].as_ref(), linkage_name);
            assert!(function.type_idx.into_option().is_some());
            assert_eq!(function.source_node.into_option(), None);
        }
    }
    Ok(())
}

#[test]
fn static_imports_preserve_runtime_keys_and_definition_provenance_in_either_order() -> TestResult {
    let context = TestContext::default();
    let dependency_module = context
        .parse_module("namespace dep\npub proc foo push.42 end\npub proc marker push.43 end")?;
    let mut foreign = dependency_fixture_namespace();
    let dependency: Arc<Package> = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&dependency_module],
    )?
    .assemble_library("dep", dependency_module, None::<Box<Module>>)?
    .into();
    let foo_key = foreign.binding(Path::new("::dep::foo")).unwrap().key();
    let bridge_module = context.parse_module(
        "namespace bridge\nuse dep\npub proc wrapper exec.dep::foo end\npub proc other exec.dep::foo end",
    )?;
    let mut bridge_bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bridge_bindings, &dependency, &foreign)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::clone(&dependency),
        Linkage::Dynamic,
        foreign.admit_package(&dependency)?,
    )?;
    let bridge: Arc<Package> =
        configure_debug_fixture(assembler, &mut bridge_bindings, &[&bridge_module])?
            .assemble_library("bridge", bridge_module, None::<Box<Module>>)?
            .into();
    let wrapper_key = bridge_bindings.binding(Path::new("::bridge::wrapper")).unwrap().key();
    let other_key = bridge_bindings.binding(Path::new("::bridge::other")).unwrap().key();
    assert_ne!(wrapper_key, other_key);
    for calls in [
        "exec.dep::foo drop exec.bridge::wrapper drop exec.bridge::other drop",
        "exec.bridge::other drop exec.bridge::wrapper drop exec.dep::foo drop",
    ] {
        let module = context.parse_module(format!("use dep\nuse bridge\nbegin {calls} end"))?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &dependency, &foreign)?;
        add_debug_package_bindings(&mut bindings, &bridge, &bridge_bindings)?;
        let assembler = Assembler::new(context.source_manager())
            .with_package(
                Arc::clone(&dependency),
                Linkage::Static,
                foreign.admit_package(&dependency)?,
            )?
            .with_package(
                Arc::clone(&bridge),
                Linkage::Static,
                bridge_bindings.admit_package(&bridge)?,
            )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let invocations = runtime_exec_sources(&package, &debug, root);
        assert_eq!(invocations.len(), 3);
        let mut keys = BTreeSet::new();
        for invocation in invocations {
            let operation = debug[debug[invocation].asm_ops[0].op_name_idx].as_ref();
            let key = match operation {
                "exec.dep::foo" => foo_key,
                "exec.bridge::wrapper" => wrapper_key,
                "exec.bridge::other" => other_key,
                _ => panic!("unexpected invocation {operation}"),
            };
            assert_runtime_exec_source(&package, &debug, invocation, key, operation);
            assert!(debug[invocation].inline_calls.is_empty());
            keys.insert(key);
        }
        assert_eq!(keys, [foo_key, wrapper_key, other_key].into_iter().collect());
        let wrapper = debug_function(&debug, "::bridge::wrapper");
        let other = debug_function(&debug, "::bridge::other");
        assert_eq!(wrapper.mast_root, other.mast_root);
        let wrapper_source = assert_debug_definition(&package, &debug, wrapper);
        let other_source = assert_debug_definition(&package, &debug, other);
        assert_ne!(wrapper_source, other_source);
        for (source, context_name) in
            [(wrapper_source, "::bridge::wrapper"), (other_source, "::bridge::other")]
        {
            assert_runtime_exec_source(&package, &debug, source, foo_key, "exec.dep::foo");
            assert_eq!(debug[debug[source].asm_ops[0].context_name_idx].as_ref(), context_name);
            assert!(debug[source].inline_calls.is_empty());
        }
        for (name, operation) in [("::dep::foo", "push.42"), ("::dep::marker", "push.43")] {
            let definition =
                assert_debug_definition(&package, &debug, debug_definition_function(&debug, name));
            assert_definition_operation(&package, &debug, definition, operation);
        }
    }
    Ok(())
}

#[test]
fn linking_does_not_invent_definitions_for_source_less_functions() -> TestResult {
    let context = TestContext::default();
    let dependency_module = context.parse_module(
        "namespace dep::math\npub proc leaf push.42 end\npub proc wrapper exec.leaf end",
    )?;
    let mut foreign = dependency_fixture_namespace();
    let dependency = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&dependency_module],
    )?
    .assemble_library("dep", dependency_module, None::<Box<Module>>)?;
    let dependency_debug = dependency.debug_info().into_diagnostic()?.unwrap();
    let leaf_root = debug_function(&dependency_debug, "::dep::math::leaf").mast_root;
    let wrapper_root = debug_function(&dependency_debug, "::dep::math::wrapper").mast_root;
    assert_ne!(leaf_root, wrapper_root);
    let foreign_key = foreign.binding(Path::new("::dep::math::wrapper")).unwrap().key();
    let bridge_module = context.parse_module(
        "namespace bridge::math\nuse dep::math\npub proc wrapper exec.math::wrapper end",
    )?;
    let mut bridge_bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bridge_bindings, &dependency, &foreign)?;
    let dependency_naming = foreign.admit_package(&dependency)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::from(dependency),
        Linkage::Dynamic,
        dependency_naming,
    )?;
    let bridge = configure_debug_fixture(assembler, &mut bridge_bindings, &[&bridge_module])?
        .assemble_library("bridge", bridge_module, None::<Box<Module>>)?;
    let bridge_key = bridge_bindings.binding(Path::new("::bridge::math::wrapper")).unwrap().key();
    let module = context.parse_module("use bridge::math\nbegin exec.math::wrapper end")?;
    let mut bindings = FixtureNamespace::assembly_tests();
    add_debug_package_bindings(&mut bindings, &bridge, &bridge_bindings)?;
    let bridge_naming = bridge_bindings.admit_package(&bridge)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::from(bridge),
        Linkage::Static,
        bridge_naming,
    )?;
    let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
        .assemble_program("test", module)?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let dependency_functions = debug
        .functions()
        .iter()
        .filter(|function| debug[function.name_idx].starts_with("::dep::math::"))
        .collect::<Vec<_>>();
    assert_eq!(dependency_functions.len(), 2);
    for function in dependency_functions {
        assert_eq!(function.source_node.into_option(), None);
    }
    assert_eq!(debug_function(&debug, "::dep::math::leaf").mast_root, leaf_root);
    assert_eq!(debug_function(&debug, "::dep::math::wrapper").mast_root, wrapper_root);
    let root = package.entrypoint_source_node().unwrap();
    let calls = runtime_exec_sources(&package, &debug, root);
    assert_eq!(calls.len(), 1);
    assert_runtime_exec_source(&package, &debug, calls[0], bridge_key, "exec.math::wrapper");
    assert!(debug[calls[0]].inline_calls.is_empty());
    let bridge_source = assert_debug_definition(
        &package,
        &debug,
        debug_function(&debug, "::bridge::math::wrapper"),
    );
    assert_ne!(bridge_source, root);
    assert_runtime_exec_source(&package, &debug, bridge_source, foreign_key, "exec.math::wrapper");
    assert!(debug[bridge_source].inline_calls.is_empty());
    assert!(package.mast_forest().procedure_roots().iter().any(|node| {
        let body = &package.mast_forest()[*node];
        body.is_external() && body.digest() == wrapper_root
    }));
    Ok(())
}

#[test]
fn exec_without_a_call_site_still_separates_definitions() -> TestResult {
    let context = TestContext::default();
    let mut module = context.parse_module(
        "namespace debug::missing\npub proc leaf push.42 end\npub proc wrapper exec.leaf end",
    )?;
    for procedure in module.procedures_mut() {
        for op in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = op
                && matches!(instruction.inner(), Instruction::Exec(_))
            {
                *instruction = Span::new(SourceSpan::UNKNOWN, instruction.inner().clone());
            }
        }
    }
    let mut bindings = FixtureNamespace::assembly_tests();
    let assembler = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?;
    let package =
        assembler
            .clone()
            .assemble_library("test", module.clone(), None::<Box<Module>>)?;
    let without_debug = assembler
        .with_profile(&miden_project::Profile::release())
        .assemble_library("test", module, None::<Box<Module>>)?;
    assert!(without_debug.debug_info().into_diagnostic()?.is_none());
    assert_eq!(package.mast_forest().commitment(), without_debug.mast_forest().commitment());
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    assert_eq!(debug.functions().len(), 2);
    let leaf = debug_function(&debug, "::debug::missing::leaf");
    let wrapper = debug_function(&debug, "::debug::missing::wrapper");
    assert_ne!(leaf.mast_root, wrapper.mast_root);
    let leaf_source = assert_debug_definition(&package, &debug, leaf);
    let wrapper_source = assert_debug_definition(&package, &debug, wrapper);
    assert_ne!(leaf_source, wrapper_source);
    assert_definition_operation(&package, &debug, leaf_source, "push.42");
    assert_runtime_exec_source(
        &package,
        &debug,
        wrapper_source,
        bindings.binding(Path::new("::debug::missing::leaf")).unwrap().key(),
        "exec.leaf",
    );
    assert_eq!(debug[wrapper_source].asm_ops[0].location_idx.into_option(), None);
    assert!(debug.nodes().iter().all(|node| node.inline_calls.is_empty()));
    Ok(())
}

#[test]
fn literal_key_exec_does_not_choose_an_ambiguous_alias() -> TestResult {
    let context = TestContext::default();
    let dependency_module = context.parse_module(
        "namespace dep::math\npub proc leaf push.42 end\npub proc twin push.42 end",
    )?;
    let mut foreign = dependency_fixture_namespace();
    let library = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut foreign,
        &[&dependency_module],
    )?
    .assemble_library("dep", dependency_module, None::<Box<Module>>)?;
    let library_debug = library.debug_info().into_diagnostic()?.unwrap();
    let word = debug_function(&library_debug, "::dep::math::leaf").mast_root;
    assert_eq!(word, debug_function(&library_debug, "::dep::math::twin").mast_root);
    let key = ProcedureKey::new(word);
    let leaf_key = foreign.binding(Path::new("::dep::math::leaf")).unwrap().key();
    let twin_key = foreign.binding(Path::new("::dep::math::twin")).unwrap().key();
    assert_ne!(leaf_key, twin_key);
    assert_ne!(key, leaf_key);
    assert_ne!(key, twin_key);
    let library: Arc<Package> = Arc::from(library);
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        // The independently retained named helper makes code at this D available without
        // changing the literal word's meaning as K.
        let module = context.parse_module(format!(
            "use dep::math\nproc available exec.math::leaf end\nbegin exec.{word} end"
        ))?;
        let mut bindings = FixtureNamespace::assembly_tests();
        add_debug_package_bindings(&mut bindings, &library, &foreign)?;
        let assembler = Assembler::new(context.source_manager()).with_package(
            Arc::clone(&library),
            linkage,
            foreign.admit_package(&library)?,
        )?;
        let package = configure_debug_fixture(assembler, &mut bindings, &[&module])?
            .assemble_program("test", module)?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let calls = runtime_exec_sources(&package, &debug, root);
        assert_eq!(calls.len(), 1);
        assert_runtime_exec_source(&package, &debug, calls[0], key, &format!("exec.{word}"));
        let available =
            assert_debug_definition(&package, &debug, debug_function(&debug, "::$exec::available"));
        assert_runtime_exec_source(&package, &debug, available, leaf_key, "exec.math::leaf");
        let leaf = debug_function(&debug, "::dep::math::leaf");
        assert_eq!(leaf.mast_root, word);
        if linkage == Linkage::Static {
            let definition = assert_debug_definition(&package, &debug, leaf);
            assert_definition_operation(&package, &debug, definition, "push.42");
            assert_ne!(definition, root);
        } else {
            assert_eq!(leaf.source_node.into_option(), None);
        }
        assert!(debug.nodes().iter().all(|node| node.inline_calls.is_empty()));
    }
    Ok(())
}

#[test]
fn runtime_exec_occurrences_keep_inline_annotations_on_the_control_only() -> TestResult {
    let context = TestContext::default();
    let mut module = context.parse_module(source_file!(
        &context,
        "proc callee add mul end\nbegin nop nop exec.callee nop exec.callee end"
    ))?;
    let entry = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(
        &context,
        entry,
        &[None, Some("source::decorated"), None],
    )?;
    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let root = package.entrypoint_source_node().unwrap();
    let mut calls = runtime_exec_sources(&package, &debug, root);
    assert_eq!(calls.len(), 2);
    calls.sort_by_key(|source| {
        let location = debug[*source].asm_ops[0].location_idx.into_option().unwrap();
        debug.get_location(location).unwrap().start.to_u32()
    });
    assert_ne!(calls[0], calls[1]);
    assert_eq!(debug[calls[0]].exec_node, debug[calls[1]].exec_node);
    let key = bindings.binding(Path::new("::$exec::callee")).unwrap().key();
    for (source, expected_annotations) in calls.into_iter().zip([1, 0]) {
        assert_runtime_exec_source(&package, &debug, source, key, "exec.callee");
        let rows = debug.inline_calls_for_operation(source, 0).collect::<Vec<_>>();
        assert_eq!(rows.len(), expected_annotations);
        for row in rows {
            assert_eq!((row.op_idx, row.op_end), (0, 1));
            let function = debug.get_function(row.callee_idx).unwrap();
            assert_eq!(debug[function.name_idx].as_ref(), "source::decorated");
        }
    }
    let definition =
        assert_debug_definition(&package, &debug, debug_function(&debug, "::$exec::callee"));
    assert_definition_operation(&package, &debug, definition, "add");
    assert_definition_operation(&package, &debug, definition, "mul");
    assert!(debug[definition].inline_calls.is_empty());
    Ok(())
}

#[test]
fn nested_runtime_exec_annotations_remain_in_their_defining_controls() -> TestResult {
    let context = TestContext::default();
    let mut module = context.parse_module(source_file!(
        &context,
        "proc inner add end\nproc outer_target nop nop exec.inner end\nbegin nop nop exec.outer_target end"
    ))?;
    for procedure in module.procedures_mut() {
        if procedure.is_entrypoint() {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::outer")],
            )?;
        } else if procedure.name().as_str() == "outer_target" {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::inner")],
            )?;
        }
    }
    let mut bindings = FixtureNamespace::assembly_tests();
    let package = configure_debug_fixture(
        Assembler::new(context.source_manager()),
        &mut bindings,
        &[&module],
    )?
    .assemble_program("test", module)?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let entry = package.entrypoint_source_node().unwrap();
    let outer =
        assert_debug_definition(&package, &debug, debug_function(&debug, "::$exec::outer_target"));
    let inner = assert_debug_definition(&package, &debug, debug_function(&debug, "::$exec::inner"));
    assert_ne!(outer, inner);
    for (root, path, operation, annotation) in [
        (entry, "::$exec::outer_target", "exec.outer_target", "source::outer"),
        (outer, "::$exec::inner", "exec.inner", "source::inner"),
    ] {
        let calls = runtime_exec_sources(&package, &debug, root);
        assert_eq!(calls.len(), 1);
        let call = calls[0];
        assert_runtime_exec_source(
            &package,
            &debug,
            call,
            bindings.binding(Path::new(path)).unwrap().key(),
            operation,
        );
        let rows = debug.inline_calls_for_operation(call, 0).collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        let function = debug.get_function(rows[0].callee_idx).unwrap();
        assert_eq!(debug[function.name_idx].as_ref(), annotation);
        assert_eq!((rows[0].op_idx, rows[0].op_end), (0, 1));
    }
    assert_definition_operation(&package, &debug, inner, "add");
    assert!(debug[inner].inline_calls.is_empty());
    Ok(())
}
