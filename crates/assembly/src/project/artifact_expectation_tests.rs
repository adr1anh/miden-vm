use alloc::string::String;

use miden_core::{
    mast::MastNode,
    program::{CanonicalLabel, ProcedureKey},
    serde::Serializable,
};
use miden_mast_package::{CallableProcedurePath, NamespacePath, ProcedureName};
use miden_package_registry::PackageRegistry;
use miden_project::{ExpectedVisibleCallables, LibraryRef, LibrarySelection};
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

fn write(path: &FsPath, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// These choices belong to the source fixture's owner, before any artifact exists. In particular,
/// neither its public surface nor its private binding is reconstructed from serialized metadata.
#[derive(Clone)]
struct Owner {
    default_home: NamespacePath,
    public: ProcedureName,
    private: ProcedureName,
}

impl Owner {
    fn new(public_home: NamespacePath) -> Self {
        Self {
            default_home: home("package-default-metadata"),
            public: ProcedureName::new(public_home, path(&["published", "run"])).unwrap(),
            private: ProcedureName::new(home("private-helper"), path(&["internal", "helper"]))
                .unwrap(),
        }
    }

    fn expected(&self) -> ExpectedVisibleCallables {
        ExpectedVisibleCallables::new([
            (path(&["dep", "implementation", "run"]), self.public.clone()),
            (path(&["dep", "alias"]), self.public.clone()),
        ])
        .unwrap()
    }

    fn homes(&self) -> Vec<NamespacePath> {
        vec![
            self.default_home.clone(),
            self.public.namespace_plan().clone(),
            self.private.namespace_plan().clone(),
            home("client"),
        ]
    }

    fn inputs(&self, sources: &ProjectSourceInputs) -> Result<NamespaceInputs, Report> {
        NamespaceInputs::new()
            .with_namespace_plan(self.default_home.clone())
            .with_callable_binding(
                crate::Path::new("::dep::implementation::run").into(),
                self.public.clone(),
            )?
            .with_callable_binding(
                crate::Path::new("::dep::implementation::hidden").into(),
                self.private.clone(),
            )?
            .with_default_callable_paths(
                core::iter::once(sources.root.as_ref())
                    .chain(sources.support.iter().map(Box::as_ref)),
            )
    }
}

fn configure_owner(assembler: &mut ProjectAssembler<'_, TestRegistry>, owner: &Owner) {
    let homes = owner.homes();
    assembler.with_package_naming_provider(move |package| admit_fixture_package(package, &homes));
    let owner = owner.clone();
    assembler.with_namespace_inputs_provider(move |_, sources, _| owner.inputs(sources));
}

fn configure_client(assembler: &mut ProjectAssembler<'_, TestRegistry>, homes: Vec<NamespacePath>) {
    // A finite policy chosen independently of the package being admitted. Missing homes reject;
    // there is no retry with the homes advertised by the artifact.
    assembler.with_package_naming_provider(move |package| admit_fixture_package(package, &homes));
    assembler.with_namespace_inputs_provider(|_, sources, _| {
        NamespaceInputs::new()
            .with_namespace_plan(home("client"))
            .with_default_callable_paths(
                core::iter::once(sources.root.as_ref())
                    .chain(sources.support.iter().map(Box::as_ref)),
            )
    });
}

fn owner_project(directory: &FsPath, body: u32) -> PathBuf {
    let manifest = directory.join("miden-project.toml");
    write(
        &manifest,
        "[package]\nname = 'dep'\nversion = '1.0.0'\n[lib]\nnamespace = 'dep'\npath = 'mod.masm'\n",
    );
    write(
        &directory.join("mod.masm"),
        "pub mod implementation\npub use {run as alias} from dep::implementation\n",
    );
    write(
        &directory.join("implementation.masm"),
        &format!("proc hidden push.7 end\npub proc run push.{body} exec.hidden end\n"),
    );
    manifest
}

fn compile_owner(directory: &FsPath, owner: &Owner, body: u32) -> ResolvedPackage {
    let manifest = owner_project(directory, body);
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    configure_owner(&mut assembler, owner);
    let resolved = assembler
        .assemble_with_naming(ProjectTargetSelector::Library, "release")
        .unwrap();
    owner.expected().check(&resolved.naming).unwrap();
    assert_eq!(resolved.naming.namespace_plan(), &owner.default_home);
    assert_eq!(resolved.naming.callables().binding(owner.private.key()), Some(&owner.private));
    assert_eq!(resolved.naming.callables().key_for_visible_path(owner.private.path()), None);
    assert!(has_exec(&resolved.package, owner.private.key()));
    resolved
}

/// Serialize only the owner's independently supplied configuration, never the artifact's naming.
fn home_config(home: &NamespacePath) -> String {
    format!(
        "[{}]",
        home.home()
            .iter()
            .map(|label| format!("{{canonical = {:?}}}", label.as_bytes()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn expectation_config(expected: &ExpectedVisibleCallables) -> String {
    format!(
        "[{}]",
        expected
            .mappings()
            .iter()
            .map(|(visible, binding)| format!(
                "{{visible-path = {:?}, home = {}, canonical-path = {:?}}}",
                visible.components(),
                home_config(binding.namespace_plan()),
                binding.path().components(),
            ))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn client_project(
    directory: &FsPath,
    binding: &str,
    expected: Option<&str>,
    linkage: &str,
) -> PathBuf {
    let manifest = directory.join("miden-project.toml");
    let expected = expected
        .map(|value| format!(", expected-callables = {value}"))
        .unwrap_or_default();
    write(
        &manifest,
        &format!(
            "[package]\nname = 'client'\nversion = '1.0.0'\n[lib]\nnamespace = 'client'\npath = 'mod.masm'\n[dependencies]\ndep = {{path = 'dep.masp', linkage = '{linkage}', binding = {binding}{expected}}}\n"
        ),
    );
    write(&directory.join("mod.masm"), "use dep\npub proc entry exec.dep::alias end\n");
    manifest
}

fn has_exec(package: &MastPackage, key: ProcedureKey) -> bool {
    package
        .mast_forest()
        .nodes()
        .iter()
        .any(|node| matches!(node, MastNode::Exec(exec) if exec.target() == key))
}

#[test]
fn artifact_expectations_preserve_owner_bindings_aliases_and_private_helpers() {
    let temp = TempDir::new().unwrap();
    let owner = Owner::new(home("public-owner"));
    let artifact = compile_owner(&temp.path().join("owner"), &owner, 1);
    let expected = expectation_config(&owner.expected());
    let binding = format!("{{selection = 'custom', home = {}}}", home_config(&owner.default_home));
    for linkage in ["static", "dynamic"] {
        let directory = temp.path().join(linkage);
        let manifest = client_project(&directory, &binding, Some(&expected), linkage);
        fs::write(directory.join("dep.masp"), artifact.package.to_bytes()).unwrap();
        let mut registry = TestRegistry::default();
        let resolved = {
            let mut assembler =
                Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
            configure_client(&mut assembler, owner.homes());
            assembler
                .assemble_with_naming(ProjectTargetSelector::Library, "release")
                .unwrap()
        };
        let callables = resolved.naming.callables();
        assert_eq!(callables.binding(owner.public.key()), Some(&owner.public));
        assert_eq!(callables.binding(owner.private.key()), Some(&owner.private));
        assert!(has_exec(&resolved.package, owner.public.key()));
        let private_root = artifact
            .naming
            .callables()
            .selected_implementation(owner.private.key())
            .unwrap();
        assert_eq!(
            callables.selected_implementation(owner.private.key()),
            (linkage == "static").then_some(private_root),
        );
        assert_eq!(has_exec(&resolved.package, owner.private.key()), linkage == "static");
        assert_eq!(
            resolved.package.manifest.dependencies().count(),
            usize::from(linkage == "dynamic")
        );
        assert_eq!(registry.cached_packages().len(), 1, "accepted artifact is promoted once");
    }
}

#[test]
fn latest_and_pinned_artifacts_keep_keys_and_exec_across_bodies_and_linkage() {
    let identity = "0x0100000000000000020000000000000003000000000000000400000000000000";
    let mut selected_keys = Vec::new();
    for selection in [
        LibrarySelection::Latest,
        LibrarySelection::Revision(core::num::NonZeroU32::new(2).unwrap()),
    ] {
        let temp = TempDir::new().unwrap();
        let import = LibraryRef::new(
            home("ancestor"),
            miden_core::Word::try_from(identity).unwrap(),
            selection,
        );
        let owner = Owner::new(import.namespace_plan());
        let binding = match selection {
            LibrarySelection::Latest => format!(
                "{{selection = 'latest', base = [{{text = 'ancestor'}}], library-id = '{identity}'}}"
            ),
            LibrarySelection::Revision(_) => format!(
                "{{selection = 'pinned', base = [{{text = 'ancestor'}}], library-id = '{identity}', revision = 2}}"
            ),
        };
        let expected = expectation_config(&owner.expected());
        let mut roots = Vec::new();
        let mut caller_roots = Vec::new();
        for body in [1, 2] {
            let artifact = compile_owner(&temp.path().join(format!("owner-{body}")), &owner, body);
            let root =
                artifact.naming.callables().selected_implementation(owner.public.key()).unwrap();
            assert_ne!(
                owner.public.key().as_word(),
                root.as_word(),
                "D must not become callable identity"
            );
            roots.push(root);
            for linkage in ["static", "dynamic"] {
                let directory = temp.path().join(format!("client-{body}-{linkage}"));
                let manifest = client_project(&directory, &binding, Some(&expected), linkage);
                fs::write(directory.join("dep.masp"), artifact.package.to_bytes()).unwrap();
                let mut registry = TestRegistry::default();
                let mut assembler =
                    Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
                configure_client(&mut assembler, owner.homes());
                let resolved = assembler
                    .assemble_with_naming(ProjectTargetSelector::Library, "release")
                    .unwrap();
                assert!(has_exec(&resolved.package, owner.public.key()));
                assert_eq!(
                    resolved.naming.callables().binding(owner.private.key()),
                    Some(&owner.private)
                );
                let caller =
                    ProcedureName::new(home("client"), path(&["client", "entry"])).unwrap();
                caller_roots.push(
                    resolved.naming.callables().selected_implementation(caller.key()).unwrap(),
                );
                assert_eq!(
                    resolved.naming.callables().selected_implementation(owner.public.key()),
                    Some(root),
                    "the selected commitment is independent of code availability",
                );
                let forest = resolved.package.mast_forest();
                let supplied_root = forest
                    .find_procedure_root(root.into_word())
                    .expect("selected supply retains either the body or its external descriptor");
                assert_eq!(
                    forest[supplied_root].is_external(),
                    linkage == "dynamic",
                    "an external descriptor is not a bundled implementation",
                );
            }
        }
        assert_ne!(roots[0], roots[1], "the supplied implementations really differ");
        assert!(caller_roots.iter().all(|root| root == &caller_roots[0]));
        selected_keys.push(owner.public.key());
    }
    assert_ne!(
        selected_keys[0], selected_keys[1],
        "Pinned revision qualifies K independently of D"
    );
}

#[test]
fn invalid_artifact_expectations_never_promote_code_to_the_registry() {
    let temp = TempDir::new().unwrap();
    let owner = Owner::new(home("public-owner"));
    let artifact = compile_owner(&temp.path().join("owner"), &owner, 1);
    let correct = owner.expected();
    let mut missing_alias = correct.mappings().clone();
    missing_alias.remove(&path(&["dep", "alias"]));
    let mut extra = correct.mappings().clone();
    extra.insert(path(&["dep", "nonexistent"]), owner.public.clone());
    let wrong = ProcedureName::new(home("wrong-owner"), owner.public.path().clone()).unwrap();
    let changed = ExpectedVisibleCallables::new(
        correct.mappings().keys().cloned().map(|path| (path, wrong.clone())),
    )
    .unwrap();
    let duplicate = expectation_config(&correct);
    let duplicate = format!(
        "[{}, {}]",
        &duplicate[1..duplicate.len() - 1],
        &duplicate[1..duplicate.len() - 1]
    );
    let binding = format!("{{selection = 'custom', home = {}}}", home_config(&owner.default_home));
    let cases = [
        ("absent", None, "requires explicit expected callable mappings"),
        (
            "missing-alias",
            Some(expectation_config(&ExpectedVisibleCallables::new(missing_alias).unwrap())),
            "unexpected visible callable path",
        ),
        (
            "extra",
            Some(expectation_config(&ExpectedVisibleCallables::new(extra).unwrap())),
            "missing expected visible callable path",
        ),
        ("wrong", Some(expectation_config(&changed)), "expected complete binding"),
        ("duplicate", Some(duplicate), "duplicate expected visible callable path"),
    ];
    for (case, expected, message) in cases {
        let directory = temp.path().join(case);
        let manifest = client_project(&directory, &binding, expected.as_deref(), "static");
        fs::write(directory.join("dep.masp"), artifact.package.to_bytes()).unwrap();
        let mut registry = TestRegistry::default();
        let error = match Assembler::default().for_project_at_path(&manifest, &mut registry) {
            Err(error) => error,
            Ok(mut assembler) => {
                configure_client(&mut assembler, owner.homes());
                assembler
                    .assemble(ProjectTargetSelector::Library, "release")
                    .expect_err("bad public map must reject")
            },
        };
        assert!(format!("{error:?}").contains(message), "{case}: {error:?}");
        assert!(registry.cached_packages().is_empty(), "{case}: failed admission promoted code");
        assert!(registry.available_versions(&"dep".into()).is_none());
    }

    let directory = temp.path().join("unadmitted-private-home");
    let expected = expectation_config(&correct);
    let manifest = client_project(&directory, &binding, Some(&expected), "static");
    fs::write(directory.join("dep.masp"), artifact.package.to_bytes()).unwrap();
    let mut registry = TestRegistry::default();
    {
        let mut assembler =
            Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
        configure_client(
            &mut assembler,
            vec![
                owner.default_home.clone(),
                owner.public.namespace_plan().clone(),
                home("client"),
            ],
        );
        let error = assembler.assemble(ProjectTargetSelector::Library, "release").unwrap_err();
        assert!(format!("{error:?}").contains("unexpected fixture home"), "{error:?}");
    }
    assert!(
        registry.cached_packages().is_empty(),
        "expectations cannot replace home admission"
    );
}

fn assemble_source(
    assembler: &mut ProjectAssembler<'_, TestRegistry>,
    cache: &mut SourcePackageCache,
    expected: &ExpectedVisibleCallables,
) -> Result<ResolvedPackage, Report> {
    let project = assembler.project.clone();
    let target = project.library_target().unwrap().inner().clone();
    match assembler.assemble_source_package(
        *assembler.dependency_graph.root(),
        project,
        &target,
        "release",
        InterruptedTargetRole::Dependency,
        None,
        None,
        None,
        cache,
        DependencyNamingRequest {
            binding: None,
            expected_callables: Some(expected),
        },
    )? {
        ControlFlow::Continue(resolved) => Ok(resolved),
        ControlFlow::Break(_) => panic!("source fixture unexpectedly interrupted"),
    }
}

#[test]
fn source_expectations_are_checked_before_cold_promotion_memory_and_registered_reuse() {
    let temp = TempDir::new().unwrap();
    let manifest = owner_project(temp.path(), 1);
    let owner = Owner::new(home("public-owner"));
    let expected = owner.expected();
    let wrong = ExpectedVisibleCallables::new(expected.mappings().keys().cloned().map(|visible| {
        (
            visible,
            ProcedureName::new(home("changed-request"), owner.public.path().clone()).unwrap(),
        )
    }))
    .unwrap();
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
    configure_owner(&mut assembler, &owner);
    let mut cache = BTreeMap::new();
    let error = assemble_source(&mut assembler, &mut cache, &wrong)
        .err()
        .expect("cold mismatch must reject");
    assert!(error.to_string().contains("expected complete binding"));
    assert!(cache.is_empty());
    assert!(assembler.store.cached_packages().is_empty());

    let first = assemble_source(&mut assembler, &mut cache, &expected).unwrap();
    let second = assemble_source(&mut assembler, &mut cache, &expected).unwrap();
    assert!(
        Arc::ptr_eq(&first.package, &second.package),
        "unchanged expectations allow a memory hit"
    );
    assert_eq!(assembler.store.cached_packages().len(), 1);
    assembler.store.clear_loaded_packages();
    let error = assemble_source(&mut assembler, &mut cache, &wrong)
        .err()
        .expect("current expectations constrain memory hits");
    assert!(error.to_string().contains("expected complete binding"));
    assert!(
        assembler.store.loaded_packages().is_empty(),
        "this rejection exercised the memory hit"
    );
    assert!(Arc::ptr_eq(
        &first.package,
        &assemble_source(&mut assembler, &mut cache, &expected).unwrap().package
    ));

    cache.clear();
    assembler.source_candidates.clear();
    let error = assemble_source(&mut assembler, &mut cache, &wrong)
        .err()
        .expect("current expectations constrain registered hits");
    assert!(error.to_string().contains("expected complete binding"));
    assert!(
        !assembler.store.loaded_packages().is_empty(),
        "the registered artifact was actually read"
    );
    assert!(cache.is_empty(), "rejected registered reuse must not populate the memory cache");
    let registered = assemble_source(&mut assembler, &mut cache, &expected).unwrap();
    assert!(Arc::ptr_eq(&first.package, &registered.package));
    assert_eq!(
        assembler.store.cached_packages().len(),
        1,
        "reuse must not promote another artifact"
    );
}
