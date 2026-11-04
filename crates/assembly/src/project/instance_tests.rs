use core::num::NonZeroU32;

use miden_core::{
    Word,
    mast::MastNode,
    program::{CanonicalLabel, ProcedureKey},
    serde::Serializable,
};
use miden_mast_package::{CallableProcedurePath, ProcedureName};
use miden_project::{LibraryRef, LibrarySelection, PackageSourceMount};
use tempfile::TempDir;

use super::*;
use crate::{
    linker::{LinkLibrary, Linker},
    testing::{TestRegistry, admit_fixture_package},
};

const LIBRARY_ID: &str = "0x0100000000000000020000000000000003000000000000000400000000000000";
const SOURCE: &str =
    "use left as chosen\nuse right\npub proc entry exec.chosen::run exec.right::run end\n";

fn home(name: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

fn owner(revision: u32) -> LibraryRef {
    LibraryRef::new(
        home("instance-owner"),
        Word::try_from(LIBRARY_ID).unwrap(),
        LibrarySelection::Revision(NonZeroU32::new(revision).unwrap()),
    )
}

fn run(revision: u32) -> ProcedureName {
    owner(revision).callable_binding(path(&["dep", "lib", "run"])).unwrap()
}

fn caller() -> ProcedureName {
    ProcedureName::new(home("instance-client"), path(&["app", "entry"])).unwrap()
}

fn write(path: &FsPath, source: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn workspace(directory: &FsPath, linkage: &str, aliases: [&str; 2], swapped: bool) -> PathBuf {
    let manifest = directory.join("miden-project.toml");
    let routes = if swapped { ["right", "left"] } else { ["left", "right"] };
    let dependency = |index: usize| {
        let alias = aliases[index];
        let source = routes[index];
        let revision = index + 1;
        format!(
            "{alias} = {{package = 'dep', path = 'dep', linkage = '{linkage}', \
             source-mount = {{package-base = '::dep::lib', source-base = '::{source}'}}, \
             binding = {{selection = 'pinned', base = [{{text = 'instance-owner'}}], library-id = '{LIBRARY_ID}', revision = {revision}}}, \
             expected-callables = [{{visible-path = ['dep', 'lib', 'run'], home = [{{text = 'instance-owner'}}, {{text = 'pinned'}}, {{library-id = '{LIBRARY_ID}'}}, {{revision = {revision}}}], canonical-path = ['dep', 'lib', 'run']}}]}}\n"
        )
    };
    write(
        &manifest,
        &format!(
            "[package]\nname = 'app'\nversion = '1.0.0'\n\
             [lib]\nnamespace = 'app'\npath = 'mod.masm'\n\
             naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'instance-client'}}]}}}}\n\
             [dependencies]\n{}{}",
            dependency(0),
            dependency(1),
        ),
    );
    write(&directory.join("mod.masm"), SOURCE);
    write(
        &directory.join("dep/miden-project.toml"),
        "[package]\nname = 'dep'\nversion = '1.0.0'\n\
         [lib]\nnamespace = 'dep::lib'\npath = 'mod.masm'\n\
         naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'source-fallback'}]}}\n",
    );
    write(&directory.join("dep/mod.masm"), "pub proc run push.7 drop end\n");
    manifest
}

fn admit(assembler: &mut ProjectAssembler<'_, TestRegistry>) {
    let homes = vec![home("instance-client"), owner(1).namespace_plan(), owner(2).namespace_plan()];
    assembler.with_package_naming_provider(move |package| admit_fixture_package(package, &homes));
}

fn assemble(
    assembler: &mut ProjectAssembler<'_, TestRegistry>,
    cache: &mut SourcePackageCache,
) -> ResolvedPackage {
    let project = assembler.project.clone();
    let target = project.library_target().unwrap().inner().clone();
    let instance = *assembler.dependency_graph.root();
    match assembler
        .assemble_source_package(
            instance,
            project,
            &target,
            "release",
            InterruptedTargetRole::Root,
            None,
            None,
            None,
            cache,
            DependencyNamingRequest::default(),
        )
        .unwrap()
    {
        ControlFlow::Continue(package) => package,
        ControlFlow::Break(_) => panic!("source instance fixture unexpectedly interrupted"),
    }
}

fn exec_targets(package: &MastPackage) -> alloc::collections::BTreeSet<ProcedureKey> {
    package
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect()
}

fn assert_exact_instances(resolved: &ResolvedPackage, linkage: &str) {
    let first = run(1);
    let second = run(2);
    assert_ne!(first.key(), second.key(), "the pinned revision qualifies canonical K");
    assert_eq!(
        exec_targets(resolved.code.package()),
        alloc::collections::BTreeSet::from([first.key(), second.key()]),
        "mounts and dependency aliases must resolve to the owner's exact keys",
    );
    assert_eq!(resolved.code.symbols().callables().binding(caller().key()), Some(&caller()));
    let mut dependencies = Vec::new();
    let mut bodies = Vec::new();
    assert_eq!(resolved.dependency_packages.len(), 2, "both exact code supplies must survive");
    for expected in [&first, &second] {
        let code = resolved
            .dependency_packages
            .iter()
            .find(|code| code.symbols().callables().binding(expected.key()) == Some(expected))
            .expect("the retained code pool must contain each selected pinned instance");
        let package = code.package();
        let naming = code.symbols();
        assert_eq!(package.name, PackageId::from("dep"));
        assert_eq!(package.version.to_string(), "1.0.0");
        assert_eq!(naming.namespace_plan(), expected.namespace_plan());
        assert_eq!(
            naming.callables().key_for_visible_path(&path(&["dep", "lib", "run"])),
            Some(expected.key()),
        );
        assert_eq!(resolved.code.symbols().callables().binding(expected.key()), Some(expected));
        let body = naming.callables().selected_implementation(expected.key()).unwrap();
        assert_eq!(
            resolved.code.symbols().callables().selected_implementation(expected.key()),
            Some(body)
        );
        package.check_naming(naming).unwrap();
        bodies.push(body);
        dependencies.push(package.to_dependency());
    }
    assert_eq!(bodies[0], bodies[1], "identical source retains identical implementation D");
    assert_ne!(dependencies[0].digest, dependencies[1].digest);
    let runtime = resolved.code.package().manifest.dependencies().cloned().collect::<Vec<_>>();
    if linkage == "dynamic" {
        assert_eq!(runtime.len(), 2, "same-name runtime records must not overwrite each other");
        for dependency in dependencies {
            assert!(runtime.contains(&dependency), "missing exact pinned runtime supply");
        }
    } else {
        assert!(runtime.is_empty(), "static bodies require no runtime dependency records");
    }
    resolved.code.package().check_naming(resolved.code.symbols()).unwrap();
}

#[test]
fn same_source_pinned_instances_keep_exact_keys_code_pool_and_runtime_records_cold_and_warm() {
    for linkage in ["static", "dynamic"] {
        let temp = TempDir::new().unwrap();
        let manifest = workspace(temp.path(), linkage, ["first", "second"], false);
        let mut registry = TestRegistry::default();
        let mut assembler =
            Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
        admit(&mut assembler);
        let graph = assembler.dependency_graph.as_ref();
        let root = graph.get(graph.root()).unwrap();
        assert_eq!(root.dependencies.len(), 2);
        let left = &root.dependencies[0];
        let right = &root.dependencies[1];
        assert_ne!(left.dependency, right.dependency);
        let left = graph.get(&left.dependency).unwrap();
        let right = graph.get(&right.dependency).unwrap();
        assert_eq!(left.name, PackageId::from("dep"));
        assert_eq!(left.name, right.name, "aliases never replace the actual package name");
        assert_eq!(left.version, right.version);
        assert_eq!(left.provenance, right.provenance, "both bindings select the same source");

        let mut cache = SourcePackageCache::new();
        let cold = assemble(&mut assembler, &mut cache);
        assert_exact_instances(&cold, linkage);
        assert_eq!(cache.len(), 3, "root and both graph-local source slots must be retained");
        assert_eq!(cache.values().filter(|entry| entry.code.package().name == "dep").count(), 2);
        let warm = assemble(&mut assembler, &mut cache);
        for code in &cold.dependency_packages {
            let reused = warm
                .dependency_packages
                .iter()
                .find(|candidate| {
                    candidate.package().dependency_commitment()
                        == code.package().dependency_commitment()
                })
                .unwrap();
            assert!(
                Arc::ptr_eq(code.package(), reused.package()),
                "each source instance must reuse its own slot"
            );
            assert!(
                Arc::ptr_eq(code.symbols(), reused.symbols()),
                "cached code must retain its exact checked symbols"
            );
        }
        assert_exact_instances(&warm, linkage);
        assert_eq!(cold.code.package().to_bytes(), warm.code.package().to_bytes());
        assert_eq!(cold.code.symbols(), warm.code.symbols());

        // Retained candidates are available code with their exact naming, even when only one
        // same-semver artifact can be the registry's canonical publication.
        let mut inventory = Linker::new(assembler.assembler.source_manager());
        for (revision, source) in [(1, "::left"), (2, "::right")] {
            let expected = run(revision);
            let code = cold
                .dependency_packages
                .iter()
                .find(|code| code.symbols().callables().binding(expected.key()) == Some(&expected))
                .unwrap();
            let package = code.package();
            let naming = code.symbols();
            inventory
                .link_library_at(
                    LinkLibrary::from_package(package.clone(), naming.clone()).unwrap(),
                    PackageSourceMount::new(
                        crate::Path::new("::dep::lib"),
                        crate::Path::new(source),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(
                inventory
                    .library_by_commitment(package.dependency_commitment())
                    .unwrap()
                    .naming(),
                naming,
            );
        }
        assert_eq!(inventory.libraries().count(), 2);
        assert_eq!(inventory.library_routes().count(), 2);
        drop(assembler);

        let mut assembler =
            Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
        admit(&mut assembler);
        let reloaded = assemble(&mut assembler, &mut SourcePackageCache::new());
        assert_exact_instances(&reloaded, linkage);
        assert_eq!(cold.code.package().to_bytes(), reloaded.code.package().to_bytes());
        assert_eq!(cold.code.symbols(), reloaded.code.symbols());

        let root = assembler.dependency_graph.get(*assembler.dependency_graph.root()).unwrap();
        let local = root
            .dependencies
            .iter()
            .find(|edge| {
                edge.binding
                    .as_ref()
                    .is_some_and(|binding| binding.namespace_plan() == owner(2).namespace_plan())
            })
            .unwrap()
            .clone();
        write(&temp.path().join("dep/mod.masm"), "pub proc run push.9 drop end\n");
        let error = assembler
            .resolve_dependency_package(
                local.dependency,
                "release",
                &mut SourcePackageCache::new(),
                local.binding.as_ref(),
                local.expected_callables.as_ref(),
            )
            .err()
            .expect("the second local instance must reject mutation after its warm build");
        assert!(error.to_string().contains("different source provenance"), "{error}");
        assert!(error.to_string().contains("bump the semantic version"), "{error}");
    }
}

#[test]
fn dependency_alias_rename_keeps_owner_keys_and_route_assignment_changes_caller_and_cache() {
    let temp = TempDir::new().unwrap();
    let mut products = Vec::new();
    for (aliases, swapped) in [
        (["first", "second"], false),
        (["renamed", "other"], false),
        (["renamed", "other"], true),
    ] {
        let manifest = workspace(temp.path(), "dynamic", aliases, swapped);
        let mut registry = TestRegistry::default();
        let mut assembler =
            Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
        admit(&mut assembler);
        let result = assemble(&mut assembler, &mut SourcePackageCache::new());
        assert_exact_instances(&result, "dynamic");
        assert_eq!(fs::read_to_string(temp.path().join("mod.masm")).unwrap(), SOURCE);
        let provenance =
            PackageBuildProvenance::from_package(result.code.package()).unwrap().unwrap();
        let compilation = provenance.compilation_commitment().unwrap();
        let body = result
            .code
            .symbols()
            .callables()
            .selected_implementation(caller().key())
            .unwrap();
        products.push((result, compilation, body));
    }
    assert_eq!(products[0].0.code.symbols(), products[1].0.code.symbols());
    assert_eq!(products[0].2, products[1].2, "dependency alias spelling preserves caller D");
    assert_eq!(products[0].1, products[1].1, "aliases do not change resolved compiler routes");
    for product in &products {
        for revision in [1, 2] {
            let expected = run(revision);
            assert_eq!(
                product.0.code.symbols().callables().binding(expected.key()),
                Some(&expected)
            );
        }
    }
    assert_ne!(products[1].2, products[2].2, "the caller commits to its ordered EXEC keys");
    assert_ne!(products[1].1, products[2].1, "the compiler cache commits to route assignment");
}
