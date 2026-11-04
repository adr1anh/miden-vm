use alloc::{format, sync::Arc, vec, vec::Vec};

use miden_assembly_syntax::{Path, PathBuf};
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt, MastNodeId},
    operations::Operation,
    program::{CanonicalLabel, ImplementationRoot, Namespace, ProcedureKey},
};

use super::*;
use crate::{CallableProcedurePath, NamespacePath, ProcedureName};

fn home(components: &[&str]) -> NamespacePath {
    NamespacePath::new(
        components
            .iter()
            .map(|component| CanonicalLabel::text(component).unwrap())
            .collect(),
    )
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn binding(home_components: &[&str], components: &[&str]) -> ProcedureName {
    ProcedureName::new(home(home_components), path(components)).unwrap()
}

fn body(forest: &mut MastForest, operation: Operation) -> MastNodeId {
    let node = BasicBlockNodeBuilder::new(vec![operation]).add_to_forest(forest).unwrap();
    forest.make_root(node);
    node
}

fn implementation(forest: &MastForest, node: MastNodeId) -> ImplementationRoot {
    ImplementationRoot::new(forest[node].digest())
}

fn export(source: &str, forest: &MastForest, node: MastNodeId) -> PackageExport {
    let source = PathBuf::new(source).unwrap();
    PackageExport::Procedure(ProcedureExport::new(
        Arc::<Path>::from(source.into_boxed_path()),
        Some(node),
        forest[node].digest(),
        None,
    ))
}

fn naming(
    bindings: impl IntoIterator<Item = ProcedureName>,
    aliases: impl IntoIterator<Item = (CallableProcedurePath, ProcedureKey)>,
    selected: impl IntoIterator<Item = (ProcedureKey, ImplementationRoot)>,
    entry: Option<ProcedureKey>,
) -> PackageSymbols {
    PackageSymbols::new(
        home(&["conversion-fixtures"]),
        PackageCallables::new(bindings, aliases, selected).unwrap(),
        entry,
    )
    .unwrap()
}

fn package(
    kind: TargetType,
    forest: MastForest,
    exports: impl IntoIterator<Item = PackageExport>,
    metadata: &PackageSymbols,
) -> Package {
    Package::create(
        PackageId::from("conversion-fixture"),
        Version::new(1, 0, 0),
        kind,
        Arc::new(forest),
        exports,
        [],
        metadata,
    )
    .unwrap()
}

fn private_entry_fixture() -> (Package, PackageSymbols, MastNodeId) {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add);
    let entry = binding(&["application"], &["private", "start"]);
    let metadata = naming(
        [entry.clone()],
        [],
        [(entry.key(), implementation(&forest, root))],
        Some(entry.key()),
    );
    let package = package(TargetType::Executable, forest, [], &metadata);
    (package, metadata, root)
}

#[test]
fn program_conversion_uses_explicit_private_entry_without_a_manifest_alias() {
    let (package, metadata, root) = private_entry_fixture();
    assert!(package.manifest.entrypoint().is_none());
    assert_eq!(metadata.callables().visible_paths().len(), 0);

    let program = package.try_into_program(&metadata).unwrap();
    assert_eq!(program.entrypoint(), root);
    assert_eq!(program.hash(), package.mast_forest()[root].digest());
    assert!(Arc::ptr_eq(program.mast_forest(), package.mast_forest()));
}

#[test]
fn program_conversion_selects_entry_code_instead_of_a_main_like_source_alias() {
    let mut forest = MastForest::new();
    let main = body(&mut forest, Operation::Add);
    let root = body(&mut forest, Operation::Mul);
    let main_binding = binding(&["application"], &["public", "main"]);
    let entry = binding(&["application"], &["private", "start"]);
    let main_path = Path::exec_path().join("main");
    let visible = naming::callable_path_from_manifest(&main_path).unwrap();
    let exports = [PackageExport::Procedure(ProcedureExport::new(
        main_path.into(),
        Some(main),
        forest[main].digest(),
        None,
    ))];
    let metadata = naming(
        [main_binding.clone(), entry.clone()],
        [(visible, main_binding.key())],
        [
            (main_binding.key(), implementation(&forest, main)),
            (entry.key(), implementation(&forest, root)),
        ],
        Some(entry.key()),
    );
    let package = package(TargetType::Executable, forest, exports, &metadata);

    assert_ne!(main, root);
    assert_eq!(package.try_into_program(&metadata).unwrap().entrypoint(), root);
}

#[test]
fn executable_tag_and_main_like_alias_do_not_supply_missing_entry_metadata() {
    for main_alias in [false, true] {
        let mut forest = MastForest::new();
        let root = body(&mut forest, Operation::Add);
        let retained = binding(&["application"], &["retained"]);
        let main_path = Path::exec_path().join("main");
        let (exports, aliases) = if main_alias {
            (
                vec![PackageExport::Procedure(ProcedureExport::new(
                    main_path.clone().into(),
                    Some(root),
                    forest[root].digest(),
                    None,
                ))],
                vec![(naming::callable_path_from_manifest(&main_path).unwrap(), retained.key())],
            )
        } else {
            (vec![], vec![])
        };
        let metadata = naming(
            [retained.clone()],
            aliases,
            [(retained.key(), implementation(&forest, root))],
            None,
        );
        let package = package(TargetType::Executable, forest, exports, &metadata);

        assert!(package.try_into_program(&metadata).is_err());
    }
}

#[test]
fn program_conversion_requires_exact_naming_even_for_identical_code() {
    let (package, metadata, _) = private_entry_fixture();
    let changed = PackageSymbols::new(
        home(&["different-compilation"]),
        metadata.callables().clone(),
        metadata.entry_key(),
    )
    .unwrap();
    changed
        .validate_package(package.kind, package.mast_forest(), &package.manifest)
        .unwrap();

    assert!(package.try_into_program(&changed).is_err());
    package.try_into_program(&metadata).unwrap();
}

#[test]
fn program_code_conversion_does_not_reconstruct_an_embedded_kernel() {
    let (mut package, metadata, root) = private_entry_fixture();
    package.sections.push(Section::new(SectionId::KERNEL, vec![0xff]));

    assert_eq!(package.try_into_program(&metadata).unwrap().entrypoint(), root);
}

#[test]
fn kernel_code_accepts_distinct_root_keys_selecting_the_same_implementation() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add);
    let first = binding(&[], &["first"]);
    let second = binding(&[], &["second"]);
    let selected = implementation(&forest, root);
    let metadata = naming(
        [first.clone(), second.clone()],
        [
            (path(&["arbitrary", "nested", "one"]), first.key()),
            (path(&["another", "two"]), second.key()),
        ],
        [(first.key(), selected), (second.key(), selected)],
        None,
    );
    let exports = [
        export("arbitrary::nested::one", &forest, root),
        export("another::two", &forest, root),
    ];
    let package = package(TargetType::Kernel, forest, exports, &metadata);

    assert_ne!(first.key(), second.key());
    assert_eq!(first.parent_namespace(), Namespace::initial());
    assert_eq!(second.parent_namespace(), Namespace::initial());
    package.check_kernel_code(&metadata).unwrap();
    assert!(package.try_into_program(&metadata).is_err());
}

#[test]
fn kernel_code_accepts_more_than_255_canonical_root_exports() {
    let mut forest = MastForest::new();
    let mut bindings = Vec::new();
    let mut aliases = Vec::new();
    let mut selected = Vec::new();
    let mut exports = Vec::new();
    for index in 0..256u32 {
        let root = body(&mut forest, Operation::Push(Felt::from_u32(index)));
        let name = format!("procedure_{index}");
        let canonical = binding(&[], &[&name]);
        aliases.push((path(&["surface", &name]), canonical.key()));
        selected.push((canonical.key(), implementation(&forest, root)));
        exports.push(export(&format!("surface::{name}"), &forest, root));
        bindings.push(canonical);
    }
    let metadata = naming(bindings, aliases, selected, None);
    let package = package(TargetType::Kernel, forest, exports, &metadata);

    assert_eq!(package.manifest.num_exports(), 256);
    assert_eq!(metadata.callables().bindings().len(), 256);
    package.check_kernel_code(&metadata).unwrap();
}

#[test]
fn kernel_code_requires_kernel_kind_public_exports_and_exact_naming() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add);
    let canonical = binding(&[], &["safe"]);
    let selected = [(canonical.key(), implementation(&forest, root))];
    let metadata = naming(
        [canonical.clone()],
        [(path(&["surface", "run"]), canonical.key())],
        selected,
        None,
    );
    let exports = [export("surface::run", &forest, root)];
    let library = package(TargetType::Library, forest.clone(), exports.clone(), &metadata);
    assert!(library.check_kernel_code(&metadata).is_err());

    let kernel = package(TargetType::Kernel, forest.clone(), exports, &metadata);
    let changed =
        PackageSymbols::new(home(&["different-compilation"]), metadata.callables().clone(), None)
            .unwrap();
    changed
        .validate_package(kernel.kind, kernel.mast_forest(), &kernel.manifest)
        .unwrap();
    assert!(kernel.check_kernel_code(&changed).is_err());
    kernel.check_kernel_code(&metadata).unwrap();

    let private = binding(&["kernel", "helpers"], &["private"]);
    let private_metadata = naming([private.clone()], [], [(private.key(), selected[0].1)], None);
    let no_exports = package(TargetType::Kernel, forest, [], &private_metadata);
    assert!(no_exports.check_kernel_code(&private_metadata).is_err());
}

#[test]
fn kernel_public_source_alias_cannot_turn_a_child_binding_into_a_root_binding() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add);
    let child = binding(&["child"], &["safe"]);
    let metadata = naming(
        [child.clone()],
        [(path(&["arbitrary", "nested", "run"]), child.key())],
        [(child.key(), implementation(&forest, root))],
        None,
    );
    let manifest = PackageManifest::new([export("arbitrary::nested::run", &forest, root)]).unwrap();

    assert!(matches!(
        metadata.validate_package(TargetType::Kernel, &forest, &manifest),
        Err(PackageSymbolsError::KernelExportOutsideRoot { key, .. }) if key == child.key(),
    ));
}
