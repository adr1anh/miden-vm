use core::num::NonZeroU32;
use std::{cell::Cell, rc::Rc};

use miden_core::{
    Word,
    mast::MastNode,
    program::{CanonicalLabel, Namespace, ProcedureKey},
    serde::{Deserializable, Serializable},
};
use miden_mast_package::{CallableProcedurePath, NamespacePath, ProcedureName};
use miden_project::{DependencyBinding, LibraryRef, LibrarySelection};
use tempfile::TempDir;

use super::*;
use crate::testing::{TestRegistry, admit_fixture_package};

fn home(name: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

fn binding(home: NamespacePath, components: &[&str]) -> ProcedureName {
    ProcedureName::new(home, path(components)).unwrap()
}

fn write(path: &FsPath, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn has_exec(package: &MastPackage, key: ProcedureKey) -> bool {
    package
        .mast_forest()
        .nodes()
        .iter()
        .any(|node| matches!(node, MastNode::Exec(exec) if exec.target() == key))
}

fn has_syscall(package: &MastPackage, key: ProcedureKey) -> bool {
    package.mast_forest().nodes().iter().any(
        |node| matches!(node, MastNode::Call(call) if call.is_syscall() && call.target() == key),
    )
}

fn completed(result: ControlFlow<AssemblyInterrupted, ResolvedPackage>) -> ResolvedPackage {
    match result {
        ControlFlow::Continue(package) => package,
        ControlFlow::Break(_) => panic!("source build unexpectedly interrupted"),
    }
}

fn assemble_source(
    assembler: &mut ProjectAssembler<'_, TestRegistry>,
    role: InterruptedTargetRole,
    cache: &mut SourcePackageCache,
) -> Result<ResolvedPackage, Report> {
    let project = assembler.project.clone();
    let target = project.library_target().unwrap().inner().clone();
    let id = *assembler.dependency_graph.root();
    assembler
        .assemble_source_package(
            id,
            project,
            &target,
            "release",
            role,
            None,
            None,
            None,
            cache,
            DependencyNamingRequest::default(),
        )
        .map(completed)
}

/// Change only the independently untrusted package-default metadata, preserving valid bindings,
/// the exact body supply, and source provenance. The raw package must carry the changed naming.
fn package_with_default_home(original: &ResolvedPackage, home: NamespacePath) -> ResolvedPackage {
    let naming = PackageSymbols::new(
        home,
        original.code.symbols().callables().clone(),
        original.code.symbols().entry_key(),
    )
    .unwrap();
    let source = original.code.package();
    let mut package = MastPackage::create_with_modules(
        source.name.clone(),
        source.version.clone(),
        source.kind,
        source.mast_forest().clone(),
        source.manifest.exports().cloned(),
        source.manifest.modules().cloned(),
        source.manifest.dependencies().cloned(),
        &naming,
    )
    .unwrap();
    package.description = source.description.clone();
    package.sections = source.sections.clone();
    let package = MastPackage::read_from_bytes(&package.to_bytes()).unwrap();
    package.check_naming(&naming).unwrap();
    assert_eq!(
        PackageBuildProvenance::from_package(&package).unwrap(),
        PackageBuildProvenance::from_package(source).unwrap()
    );
    ResolvedPackage {
        code: CodePackage::new(Arc::new(package), Arc::new(naming)).unwrap(),
        linked_kernel_package: original.linked_kernel_package.clone(),
        dependency_packages: original.dependency_packages.clone(),
    }
}

#[test]
fn configured_library_and_executable_name_required_library_aliases_private_helpers_and_entry() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    write(
        &manifest,
        "[package]\nname = 'configured'\nversion = '1.0.0'\n\
         [lib]\nnamespace = 'configured::lib'\npath = 'library/root.masm'\n\
         naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'library-home'}]}}\n\
         [[bin]]\nname = 'main'\npath = 'main.masm'\n\
         naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'program-home'}]}}\n",
    );
    write(
        &temp.path().join("library/root.masm"),
        "pub mod api\npub use {run as renamed} from configured::lib::api\n\
         proc hidden push.7 drop end\npub proc wrapper exec.hidden exec.api::run end\n",
    );
    write(&temp.path().join("library/api.masm"), "pub proc run push.9 drop end\n");
    write(
        &temp.path().join("main.masm"),
        "use configured::lib as chosen\nbegin exec.chosen::renamed exec.chosen::wrapper end\n",
    );

    // All owner homes and complete expected keys are chosen before an artifact exists.
    let run = binding(home("library-home"), &["configured", "lib", "api", "run"]);
    let hidden = binding(home("library-home"), &["configured", "lib", "hidden"]);
    let wrapper = binding(home("library-home"), &["configured", "lib", "wrapper"]);
    let entry = binding(home("program-home"), &["$exec", "$main"]);
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    let library = assembler
        .assemble_with_naming(ProjectTargetSelector::Library, "release")
        .unwrap();
    assert_eq!(library.code.symbols().namespace_plan(), &home("library-home"));
    assert_eq!(
        library.code.symbols().callables().key_for_visible_path(&path(&[
            "configured",
            "lib",
            "renamed"
        ])),
        Some(run.key())
    );
    for expected in [&run, &hidden, &wrapper] {
        assert_eq!(library.code.symbols().callables().binding(expected.key()), Some(expected));
        assert!(
            library
                .code
                .symbols()
                .callables()
                .selected_implementation(expected.key())
                .is_some()
        );
    }
    assert_eq!(library.code.symbols().callables().key_for_visible_path(hidden.path()), None);
    assert!(has_exec(library.code.package(), hidden.key()));
    assert!(has_exec(library.code.package(), run.key()));

    // Selecting the executable also builds and links its required library without a provider.
    let executable = assembler
        .assemble_with_naming(ProjectTargetSelector::Executable("main"), "release")
        .unwrap();
    assert_eq!(executable.code.symbols().namespace_plan(), &home("program-home"));
    assert_eq!(executable.code.symbols().entry_key(), Some(entry.key()));
    for expected in [&run, &hidden, &wrapper, &entry] {
        assert_eq!(executable.code.symbols().callables().binding(expected.key()), Some(expected));
        assert!(
            executable
                .code
                .symbols()
                .callables()
                .selected_implementation(expected.key())
                .is_some()
        );
    }
    assert!(has_exec(executable.code.package(), run.key()));
    assert!(has_exec(executable.code.package(), wrapper.key()));
    executable.code.package().check_naming(executable.code.symbols()).unwrap();
}

#[test]
fn configured_home_keeps_provider_bound_overrides_and_rejects_mismatch_before_source_caches() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    write(
        &manifest,
        "[package]\nname = 'provider'\nversion = '1.0.0'\n\
         [lib]\nnamespace = 'provider'\npath = 'mod.masm'\n\
         naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'configured-home'}]}}\n",
    );
    write(
        &temp.path().join("mod.masm"),
        "pub proc run push.1 drop end\npub proc entry exec.run end\n",
    );
    let configured_home = home("configured-home");
    let foreign = binding(home("foreign-home"), &["owner", "actual"]);
    let conventional_run = binding(configured_home.clone(), &["provider", "run"]);
    let wrong_home = Rc::new(Cell::new(false));
    let calls = Rc::new(Cell::new(0));
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    // The forged default is deliberately admitted by this finite profile below. It still cannot
    // replace the default explicitly selected by the current source target.
    let forged_home = home("forged-default-home");
    let admitted_homes = vec![configured_home.clone(), home("foreign-home"), forged_home.clone()];
    let admission_homes = admitted_homes.clone();
    assembler.with_package_naming_provider(move |package| {
        admit_fixture_package(package, &admitted_homes)
    });
    assembler.with_namespace_inputs_provider({
        let wrong_home = wrong_home.clone();
        let calls = calls.clone();
        let foreign = foreign.clone();
        move |_, sources, _| {
            calls.set(calls.get() + 1);
            let selected_home = if wrong_home.get() {
                home("provider-mismatch")
            } else {
                configured_home.clone()
            };
            NamespaceInputs::new()
                .with_namespace_plan(selected_home)
                .with_callable_binding(crate::Path::new("::provider::run").into(), foreign.clone())?
                .with_default_callable_paths(
                    core::iter::once(sources.root.as_ref())
                        .chain(sources.support.iter().map(Box::as_ref)),
                )
        }
    });
    let mut cache = BTreeMap::new();
    let first =
        assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache).unwrap();
    assert_eq!(first.code.symbols().callables().binding(foreign.key()), Some(&foreign));
    assert_eq!(
        first
            .code
            .symbols()
            .callables()
            .key_for_visible_path(&path(&["provider", "run"])),
        Some(foreign.key())
    );
    assert_eq!(first.code.symbols().callables().binding(conventional_run.key()), None);
    assert!(has_exec(first.code.package(), foreign.key()));
    let second =
        assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache).unwrap();
    assert!(Arc::ptr_eq(first.code.package(), second.code.package()));
    assert_eq!(calls.get(), 2);

    wrong_home.set(true);
    let error = assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache)
        .err()
        .expect("a configured home mismatch must reject before a memory cache hit");
    assert!(
        error
            .to_string()
            .contains("namespace inputs differ from its requested source home")
    );
    assert_eq!(calls.get(), 3);

    // Clear both local caches: the source artifact remains registered in the same store.
    cache.clear();
    assembler.source_candidates.clear();
    wrong_home.set(false);
    let reloaded =
        assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache).unwrap();
    assert_eq!(reloaded.code.symbols().callables().binding(foreign.key()), Some(&foreign));
    let loads = assembler.store.loaded_packages().len();
    assert!(loads > 0, "positive control must exercise the registered artifact path");
    cache.clear();
    assembler.source_candidates.clear();
    wrong_home.set(true);
    let error = assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache)
        .err()
        .expect("a configured home mismatch must reject before loading a registered artifact");
    assert!(
        error
            .to_string()
            .contains("namespace inputs differ from its requested source home")
    );
    assert_eq!(assembler.store.loaded_packages().len(), loads);
    assert_eq!(calls.get(), 5);

    wrong_home.set(false);
    let forged = package_with_default_home(&first, forged_home);
    assert_eq!(
        admit_fixture_package(forged.code.package(), &admission_homes).unwrap(),
        **forged.code.symbols()
    );
    assert_eq!(forged.code.symbols().callables(), first.code.symbols().callables());
    assert_eq!(forged.code.package().code_commitment(), first.code.package().code_commitment());
    let id = *assembler.dependency_graph.root();
    let target = assembler.project.library_target().unwrap().inner();
    cache.insert(SourcePackageCacheKey::new(id, target), forged.clone());
    let error = assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache)
        .err()
        .expect("self-consistent memory metadata cannot replace the configured default home");
    assert!(error.to_string().contains("default home differs from its selected source home"));
    assert_eq!(calls.get(), 6);

    cache.clear();
    assembler.source_candidates.clear();
    assembler.store.replace_semver_package(forged.code.package().clone());
    let error = assemble_source(&mut assembler, InterruptedTargetRole::Dependency, &mut cache)
        .err()
        .expect("admitted raw registered metadata must still match the configured default home");
    assert!(error.to_string().contains("default home differs from its selected source home"));
    assert!(assembler.store.loaded_packages().len() > loads);
    assert_eq!(calls.get(), 7);
}

#[test]
fn explicit_parent_source_selection_overrides_target_fallback_without_changing_source_aliases() {
    let identity = "0x0100000000000000020000000000000003000000000000000400000000000000";
    let id = Word::try_from(identity).unwrap();
    let latest = LibraryRef::new(home("parent"), id, LibrarySelection::Latest);
    let pinned = LibraryRef::new(
        home("parent"),
        id,
        LibrarySelection::Revision(NonZeroU32::new(3).unwrap()),
    );
    let choices = [
        (
            DependencyBinding::Standard(latest),
            format!(
                "{{selection = 'latest', base = [{{text = 'parent'}}], library-id = '{identity}'}}"
            ),
        ),
        (
            DependencyBinding::Standard(pinned),
            format!(
                "{{selection = 'pinned', base = [{{text = 'parent'}}], library-id = '{identity}', revision = 3}}"
            ),
        ),
        (
            DependencyBinding::Custom(home("parent-custom")),
            "{selection = 'custom', home = [{text = 'parent-custom'}]}".into(),
        ),
    ];
    for (request, configuration) in choices {
        for linkage in ["static", "dynamic"] {
            let temp = TempDir::new().unwrap();
            let manifest = temp.path().join("miden-project.toml");
            write(
                &manifest,
                &format!(
                    "[package]\nname = 'client'\nversion = '1.0.0'\n\
                     [lib]\nnamespace = 'client'\npath = 'mod.masm'\n\
                     naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'client-home'}}]}}}}\n\
                     [dependencies]\ndep = {{path = 'dep', linkage = '{linkage}', binding = {configuration}}}\n"
                ),
            );
            write(
                &temp.path().join("mod.masm"),
                "use dep as chosen\npub proc entry exec.chosen::alias end\n",
            );
            write(
                &temp.path().join("dep/miden-project.toml"),
                "[package]\nname = 'dep'\nversion = '1.0.0'\n\
                 [lib]\nnamespace = 'dep'\npath = 'mod.masm'\n\
                 naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'source-fallback'}]}}\n",
            );
            write(
                &temp.path().join("dep/mod.masm"),
                "pub mod implementation\npub use {run as alias} from dep::implementation\n",
            );
            write(
                &temp.path().join("dep/implementation.masm"),
                "proc hidden push.7 drop end\npub proc run push.2 exec.hidden end\n",
            );
            let run = binding(request.namespace_plan(), &["dep", "implementation", "run"]);
            let hidden = binding(request.namespace_plan(), &["dep", "implementation", "hidden"]);
            let fallback_run = binding(home("source-fallback"), &["dep", "implementation", "run"]);
            let mut registry = TestRegistry::default();
            let mut assembler =
                Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
            let mut cache = BTreeMap::new();
            let resolved =
                assemble_source(&mut assembler, InterruptedTargetRole::Root, &mut cache).unwrap();
            let root = assembler.dependency_graph.get(*assembler.dependency_graph.root()).unwrap();
            let instance = root
                .dependencies
                .iter()
                .find(|edge| edge.alias.as_ref() == "dep")
                .unwrap()
                .dependency;
            let dependency = cache
                .iter()
                .find(|(key, _)| key.instance == instance)
                .map(|(_, dependency)| dependency)
                .unwrap();
            assert_eq!(dependency.code.symbols().namespace_plan(), &request.namespace_plan());
            assert_eq!(
                dependency
                    .code
                    .symbols()
                    .callables()
                    .key_for_visible_path(&path(&["dep", "alias"])),
                Some(run.key())
            );
            for expected in [&run, &hidden] {
                assert_eq!(
                    dependency.code.symbols().callables().binding(expected.key()),
                    Some(expected)
                );
                assert_eq!(
                    resolved.code.symbols().callables().binding(expected.key()),
                    Some(expected)
                );
            }
            assert_eq!(dependency.code.symbols().callables().binding(fallback_run.key()), None);
            assert!(has_exec(resolved.code.package(), run.key()));
            assert_eq!(has_exec(resolved.code.package(), hidden.key()), linkage == "static");
        }
    }
}

#[test]
fn configured_kernel_names_root_exports_public_submodules_and_private_helpers_without_providers() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    write(
        &manifest,
        "[package]\nname = 'kernel-project'\nversion = '1.0.0'\n\
         [lib]\nkind = 'kernel'\npath = 'kernel/root.masm'\n\
         naming = {convention = 'kernel-root-exports', binding = {selection = 'custom', home = [{text = 'kernel-helper-home'}]}}\n\
         [[bin]]\nname = 'main'\npath = 'main.masm'\n\
         naming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{text = 'kernel-program-home'}]}}\n",
    );
    write(
        &temp.path().join("kernel/root.masm"),
        "pub mod api\npub use {child as promoted} from $kernel::api\n\
         proc hidden push.7 drop end\npub proc run exec.hidden exec.api::child end\n",
    );
    write(&temp.path().join("kernel/api.masm"), "pub proc child push.9 drop end\n");
    write(&temp.path().join("main.masm"), "begin syscall.run syscall.promoted end\n");
    let run = binding(NamespacePath::new(vec![]), &["run"]);
    let child = binding(NamespacePath::new(vec![]), &["child"]);
    let hidden = binding(home("kernel-helper-home"), &["$kernel", "hidden"]);
    let entry = binding(home("kernel-program-home"), &["$exec", "$main"]);
    assert_eq!(run.parent_namespace(), Namespace::initial());
    assert_eq!(child.parent_namespace(), Namespace::initial());
    assert_ne!(hidden.parent_namespace(), Namespace::initial());
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    let kernel = assembler
        .assemble_with_naming(ProjectTargetSelector::Library, "release")
        .unwrap();
    assert_eq!(kernel.code.symbols().namespace_plan(), &home("kernel-helper-home"));
    for expected in [&run, &child, &hidden] {
        assert_eq!(kernel.code.symbols().callables().binding(expected.key()), Some(expected));
        assert!(
            kernel
                .code
                .symbols()
                .callables()
                .selected_implementation(expected.key())
                .is_some()
        );
    }
    for (visible, expected) in [
        (path(&["$kernel", "run"]), &run),
        (path(&["$kernel", "api", "child"]), &child),
        (path(&["$kernel", "promoted"]), &child),
    ] {
        assert_eq!(
            kernel.code.symbols().callables().key_for_visible_path(&visible),
            Some(expected.key())
        );
    }
    assert_eq!(kernel.code.symbols().callables().key_for_visible_path(hidden.path()), None);
    assert!(has_exec(kernel.code.package(), hidden.key()));
    assert!(has_exec(kernel.code.package(), child.key()));
    kernel.code.package().check_kernel_code(kernel.code.symbols()).unwrap();

    let executable = assembler
        .assemble_with_naming(ProjectTargetSelector::Executable("main"), "release")
        .unwrap();
    assert_eq!(executable.code.symbols().entry_key(), Some(entry.key()));
    assert!(has_syscall(executable.code.package(), run.key()));
    assert!(has_syscall(executable.code.package(), child.key()));
    let linked_naming = executable.linked_kernel_package.as_ref().unwrap().symbols();
    assert_eq!(linked_naming.callables().binding(hidden.key()), Some(&hidden));
    executable.code.package().check_naming(executable.code.symbols()).unwrap();
}

#[test]
fn source_targets_still_reject_missing_configuration_and_provider() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    write(&manifest, "[package]\nname = 'unconfigured'\nversion = '1.0.0'\n");
    write(&temp.path().join("mod.masm"), "pub proc run push.1 drop end\n");
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    let error = assembler
        .assemble_with_naming(ProjectTargetSelector::Library, "release")
        .err()
        .expect("an implicit library target still requires explicit source naming");
    assert!(
        error
            .to_string()
            .contains("explicit namespace inputs provider or target naming")
    );
}
