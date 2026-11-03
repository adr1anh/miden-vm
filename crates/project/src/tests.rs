use alloc::string::ToString;
use core::assert_matches;
use std::{boxed::Box, fs, path::Path, sync::Arc};

use miden_assembly_syntax::{
    Path as MasmPath,
    debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt},
    diagnostics::Report,
};
use tempfile::TempDir;

use crate::{
    DependencyBinding, DependencyVersionScheme, LibraryImport, LibrarySelection, Linkage, Project,
    SourceNamingConvention, TargetType, Word, Workspace,
};

struct TestContext {
    pub source_manager: Arc<dyn SourceManager>,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

impl TestContext {
    pub fn load_workspace(&self, path: impl AsRef<Path>) -> Result<Box<Workspace>, Report> {
        let path = path.as_ref();
        let source_file = self.source_manager.load_file(path).map_err(Report::msg)?;
        Workspace::load(source_file, &self.source_manager)
    }
}

#[test]
fn can_load_protocol_example_project() -> Result<(), Report> {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/protocol/miden-project.toml");
    let context = TestContext::default();
    let workspace = context.load_workspace(MANIFEST_PATH)?;

    assert_eq!(workspace.members().len(), 3);

    let core_project = workspace
        .get_member_by_name("miden-utils")
        .expect("failed to locate 'miden-utils' project");
    assert!(Arc::ptr_eq(
        &core_project,
        &workspace
            .get_member_by_relative_path("utils")
            .expect("failed to locate 'miden-utils' project by relative path")
    ));

    let core_lib = core_project.library_target().unwrap();
    assert_eq!(core_lib.ty, TargetType::Library);
    assert_eq!(&**core_lib.name.inner(), "miden::utils");
    assert_eq!(&**core_lib.namespace.inner(), MasmPath::new("::miden::utils"));
    assert_eq!(core_project.executable_targets().len(), 0);

    let kernel_project = workspace
        .get_member_by_name("miden-tx")
        .expect("failed to locate 'miden-tx' project");

    let kernel_lib = kernel_project.library_target().unwrap();
    assert_eq!(kernel_lib.ty, TargetType::Kernel);
    assert_eq!(&**kernel_lib.name.inner(), "miden-tx");
    assert_eq!(&**kernel_lib.namespace.inner(), MasmPath::kernel_path());
    assert_eq!(kernel_project.executable_targets().len(), 2);

    assert_eq!(kernel_project.executable_targets()[0].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.executable_targets()[0].name.inner(), "entry");
    assert_eq!(
        &**kernel_project.executable_targets()[0].namespace.inner(),
        MasmPath::exec_path()
    );

    assert_eq!(kernel_project.executable_targets()[1].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.executable_targets()[1].name.inner(), "entry-alt");
    assert_eq!(
        &**kernel_project.executable_targets()[1].namespace.inner(),
        MasmPath::exec_path()
    );

    assert_eq!(kernel_project.dependencies().len(), 1);
    assert_eq!(&**kernel_project.dependencies()[0].name(), "miden-utils");
    assert_matches!(kernel_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "utils");
    assert_eq!(kernel_project.dependencies()[0].linkage(), Linkage::Static);

    let userspace_project = workspace
        .get_member_by_name("miden-protocol")
        .expect("failed to locate 'miden-protocol' project");

    let userspace_lib = userspace_project.library_target().unwrap();
    assert_eq!(userspace_lib.ty, TargetType::Library);
    assert_eq!(&**userspace_lib.name.inner(), "miden::protocol");
    assert_eq!(&**userspace_lib.namespace.inner(), MasmPath::new("::miden::protocol"));
    assert_eq!(userspace_project.executable_targets().len(), 0);

    assert_eq!(userspace_project.dependencies().len(), 2);
    assert_eq!(&**userspace_project.dependencies()[0].name(), "miden-tx");
    assert_matches!(userspace_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "kernel");
    assert_eq!(&**userspace_project.dependencies()[1].name(), "miden-utils");
    assert_matches!(userspace_project.dependencies()[1].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "utils");
    assert_eq!(userspace_project.dependencies()[1].linkage(), Linkage::Dynamic);

    Ok(())
}

#[test]
fn invalid_library_namespace_returns_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    let invalid_namespace = "a".repeat(MasmPath::MAX_COMPONENT_LENGTH + 1);
    fs::write(
        &manifest_path,
        format!(
            r#"[package]
name = "mylib"
version = "1.0.0"

[lib]
namespace = "{invalid_namespace}"
path = "mod.masm"
"#
        ),
    )
    .unwrap();

    let context = TestContext::default();
    let err = Project::load(&manifest_path, &context.source_manager)
        .expect_err("invalid namespace must be reported instead of panicking");

    assert!(format!("{err}").contains("invalid item path component"));
}

#[test]
fn workspace_dev_override_is_used_for_child_profile_inheritance() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace-profile");
    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["app"]

[workspace.package]
version = "0.1.0"

[profile.dev]
debug = false
"#,
    )
    .unwrap();

    let app_manifest_path = app_dir.join("miden-project.toml");
    fs::write(
        &app_manifest_path,
        r#"[package]
name = "app"
version = "0.1.0"

[profile.child]
inherits = "dev"
"#,
    )
    .unwrap();

    let context = TestContext::default();
    let Project::WorkspacePackage { package, workspace: _ } =
        Project::load(&app_manifest_path, &context.source_manager)?
    else {
        panic!("expected workspace package")
    };
    let child = package.profiles().iter().find(|p| p.name().as_ref() == "child").unwrap();

    assert!(!child.should_emit_debug_info());

    Ok(())
}

#[test]
fn workspace_package_version_can_be_inherited_with_dotted_key_syntax() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace-version");
    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["app"]

[workspace.package]
version = "0.1.0"
"#,
    )
    .unwrap();

    let app_manifest_path = app_dir.join("miden-project.toml");
    fs::write(
        &app_manifest_path,
        r#"[package]
name = "app"
version.workspace = true
"#,
    )
    .unwrap();

    let context = TestContext::default();
    let Project::WorkspacePackage { package, workspace: _ } =
        Project::load(&app_dir, &context.source_manager)?
    else {
        panic!("expected workspace package")
    };

    assert_eq!(format!("{}", package.version()), "0.1.0");

    Ok(())
}

#[test]
fn load_project_reference_keeps_non_member_workspace_paths_authoritative() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let member_dir = root.join("member");
    let vendor_dir = root.join("vendor").join("dep");
    fs::create_dir_all(&member_dir).unwrap();
    fs::create_dir_all(&vendor_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["member"]
"#,
    )
    .unwrap();

    fs::write(
        member_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(member_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let vendor_manifest = vendor_dir.join("miden-project.toml");
    fs::write(
        &vendor_manifest,
        r#"[package]
name = "dep"
version = "9.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(vendor_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let project = Project::load_project_reference("dep", &vendor_dir, &context.source_manager)?;

    assert!(!project.is_workspace_member());
    assert_eq!(project.manifest_path(), Some(vendor_manifest.as_path()));
    assert_eq!(format!("{}", project.package().version()), "9.0.0");

    Ok(())
}

#[test]
fn load_package_ignores_broken_workspace_members_when_not_a_member() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    let vendor_dir = root.join("vendor").join("dep");
    fs::create_dir_all(&vendor_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["missing"]
"#,
    )
    .unwrap();

    let vendor_manifest = vendor_dir.join("miden-project.toml");
    fs::write(
        &vendor_manifest,
        r#"[package]
name = "dep"
version = "9.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(vendor_dir.join("lib.masm"), "export.foo\nend\n").unwrap();
    let vendor_manifest = vendor_manifest.canonicalize().unwrap();

    let context = TestContext::default();
    let project = Project::load(&vendor_manifest, &context.source_manager)?;

    assert!(!project.is_workspace_member());
    assert_eq!(project.manifest_path(), Some(vendor_manifest.as_path()));

    Ok(())
}

#[test]
fn load_project_reference_resolves_workspace_manifest_file_inputs() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    let dep_dir = root.join("dep");
    fs::create_dir_all(&dep_dir).unwrap();

    let workspace_manifest = root.join("miden-project.toml");
    fs::write(
        &workspace_manifest,
        r#"[workspace]
members = ["dep"]
"#,
    )
    .unwrap();

    let dep_manifest = dep_dir.join("miden-project.toml");
    fs::write(
        &dep_manifest,
        r#"[package]
name = "dep"
version = "1.2.3"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(dep_dir.join("lib.masm"), "export.foo\nend\n").unwrap();
    let dep_manifest = dep_manifest.canonicalize().unwrap();

    let context = TestContext::default();
    let project =
        Project::load_project_reference("dep", &workspace_manifest, &context.source_manager)?;

    assert!(project.is_workspace_member());
    assert_eq!(project.manifest_path(), Some(dep_manifest.as_path()));
    assert_eq!(format!("{}", project.package().version()), "1.2.3");

    Ok(())
}

#[test]
fn load_project_reference_rejects_standalone_package_name_mismatch() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    fs::create_dir_all(&dep_dir).unwrap();

    fs::write(
        dep_dir.join("miden-project.toml"),
        r#"[package]
name = "actual"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(dep_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let err = Project::load_project_reference("expected", &dep_dir, &context.source_manager)
        .expect_err("package name mismatch should be rejected");

    assert!(
        format!("{err}").contains("dependency 'expected' resolved to package 'actual'"),
        "{err}"
    );
}

#[test]
fn load_project_reference_rejects_workspace_member_package_name_mismatch() {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    let dep_dir = root.join("dep");
    fs::create_dir_all(&dep_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["dep"]
"#,
    )
    .unwrap();

    fs::write(
        dep_dir.join("miden-project.toml"),
        r#"[package]
name = "actual"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(dep_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let err = Project::load_project_reference("expected", &dep_dir, &context.source_manager)
        .expect_err("workspace member package name mismatch should be rejected");

    assert!(
        format!("{err}").contains("dependency 'expected' resolved to package 'actual'"),
        "{err}"
    );
}

#[test]
fn workspace_rejects_duplicate_member_package_names() {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).unwrap();
    fs::create_dir_all(&second_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["first", "second"]
"#,
    )
    .unwrap();

    fs::write(
        first_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(first_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    fs::write(
        second_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "2.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(second_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let error = context
        .load_workspace(root.join("miden-project.toml"))
        .expect_err("duplicate member package names should be rejected");

    assert!(format!("{error}").contains("duplicate"), "{error}");
}

#[test]
fn project_dependencies_require_explicit_runtime_selection() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    for dependency in ["dep = '1.0'", "dep = { path = '../dep' }"] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\n{dependency}\n")).unwrap();
        let context = TestContext::default();
        let error = Project::load(&manifest, &context.source_manager).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an explicit Latest/Pinned binding or custom home"),
            "{error}"
        );
    }
}

#[test]
fn source_target_naming_roundtrip_preserves_explicit_conventions_and_bindings() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    let id = "0x0100000000000000020000000000000003000000000000000400000000000000";
    for (kind, convention) in [
        ("library", SourceNamingConvention::DefiningPaths),
        ("kernel", SourceNamingConvention::KernelRootExports),
    ] {
        for binding in [
            "selection = 'custom', home = [{text = 'root-home'}, {revision = 2}]".into(),
            format!("selection = 'latest', base = [{{text = 'tenant'}}], library-id = '{id}'"),
            format!("selection = 'pinned', base = [], library-id = '{id}', revision = 7"),
        ] {
            fs::write(
                &manifest,
                format!(
                    "[package]\nname = 'app'\nversion = '1.0.0'\n\
                     [lib]\nkind = '{kind}'\npath = 'mod.masm'\n\
                     naming = {{convention = '{}', binding = {{{binding}}}}}\n\
                     [[bin]]\nname = 'main'\npath = 'main.masm'\n\
                     naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = []}}}}\n",
                    convention.as_str()
                ),
            )
            .unwrap();
            let context = TestContext::default();
            let package = Project::load(&manifest, &context.source_manager).unwrap().package();
            let library = package.library_target().unwrap();
            let naming = library.naming.as_ref().unwrap();
            assert_eq!(naming.convention(), convention);
            let expected: toml::Table =
                toml::from_str(&format!("binding = {{{binding}}}")).unwrap();
            let expected: crate::ast::DependencyBindingSpec =
                expected["binding"].clone().try_into().unwrap();
            assert_eq!(naming.binding(), &expected.resolve().unwrap());
            let bin_naming = package.executable_targets()[0].naming.as_ref().unwrap();
            assert_eq!(bin_naming.convention(), SourceNamingConvention::DefiningPaths);
            assert!(bin_naming.binding().namespace_plan().home().is_empty());

            let written = package.to_toml().unwrap();
            // The AST writer and reader must retain both independently selected target records.
            let ast: crate::ast::ProjectFile = toml::from_str(&written).unwrap();
            assert_eq!(ast.lib.as_ref().unwrap().naming.as_ref().unwrap().convention, convention);
            assert!(ast.bins[0].naming.is_some());
            fs::write(&manifest, written).unwrap();
            let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
            assert_eq!(restored.library_target().unwrap().naming, library.naming);
            assert_eq!(
                restored.executable_targets()[0].naming,
                package.executable_targets()[0].naming
            );
        }
    }
}

#[test]
fn source_target_naming_rejects_conventions_for_the_wrong_target_kind() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    for target in [
        "[lib]\nkind = 'kernel'\npath = 'mod.masm'\nnaming = {convention = 'defining-paths', binding = {selection = 'custom', home = []}}",
        "[lib]\npath = 'mod.masm'\nnaming = {convention = 'kernel-root-exports', binding = {selection = 'custom', home = []}}",
        "[[bin]]\npath = 'main.masm'\nnaming = {convention = 'kernel-root-exports', binding = {selection = 'custom', home = []}}",
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n{target}\n"))
            .unwrap();
        let context = TestContext::default();
        let error = Project::load(&manifest, &context.source_manager).unwrap_err();
        assert!(error.to_string().contains("is invalid for target kind"), "{error}");
    }
}

#[test]
fn omitted_source_target_naming_remains_unconfigured_for_default_and_explicit_targets() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    for targets in ["", "[lib]\npath = 'mod.masm'\n[[bin]]\npath = 'main.masm'\n"] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n{targets}"))
            .unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert!(package.library_target().unwrap().naming.is_none());
        assert!(package.executable_targets().iter().all(|target| target.naming.is_none()));
        assert!(!package.to_toml().unwrap().contains("naming"));
    }
}

#[test]
fn project_selection_roundtrip_keeps_source_version_linkage_and_runtime_naming_separate() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    let id = "0x0100000000000000020000000000000003000000000000000400000000000000";
    for (selection, revision) in [("latest", ""), ("pinned", ", revision = 4")] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\ndep = {{ version = '=2.0.0', linkage = 'static', binding = {{ selection = '{selection}', library-id = '{id}', base = [{{text = 'tenant'}}]{revision} }} }}\n")).unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        let dependency = &package.dependencies()[0];
        assert_eq!(dependency.linkage(), Linkage::Static);
        assert_eq!(dependency.required_version().to_string(), "=2.0.0");
        let binding = dependency.binding().unwrap().clone();
        let expected = LibraryImport::new(
            miden_mast_package::NamespacePlan::new(vec![
                miden_core::program::CanonicalLabel::text("tenant").unwrap(),
            ]),
            Word::try_from(id).unwrap(),
            if selection == "latest" {
                LibrarySelection::Latest
            } else {
                LibrarySelection::Pinned(core::num::NonZeroU32::new(4).unwrap())
            },
        );
        assert_eq!(binding, DependencyBinding::Standard(expected));
        fs::write(&manifest, package.to_toml().unwrap()).unwrap();
        let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert_eq!(restored.dependencies()[0].binding(), Some(&binding));
        assert_eq!(restored.dependencies()[0].scheme(), dependency.scheme());
        assert_eq!(restored.dependencies()[0].linkage(), dependency.linkage());
    }
}

#[test]
fn workspace_binding_inheritance_is_explicit_and_member_override_wins() {
    let temp = TempDir::new().unwrap();
    let app = temp.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(temp.path().join("miden-project.toml"), "[workspace]\nmembers = ['app']\n[workspace.dependencies]\ndep = {version = '1.0', binding = { selection = 'custom', home = [{text = 'workspace-home'}] }}\n").unwrap();
    let manifest = app.join("miden-project.toml");
    for (extra, expected) in [
        ("", "workspace-home"),
        (
            ", binding = { selection = 'custom', home = [{text = 'member-home'}] }",
            "member-home",
        ),
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\ndep = {{workspace = true{extra}}}\n")).unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert_eq!(
            package.dependencies()[0].binding().unwrap().namespace_plan(),
            miden_mast_package::NamespacePlan::new(vec![
                miden_core::program::CanonicalLabel::text(expected).unwrap()
            ])
        );
    }
}

#[test]
fn expected_callables_roundtrip_independently_from_source_supply_and_default_home() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    let records = "[{visible-path = ['api::module', 'alias'], home = [{text = 'foreign-owner'}], canonical-path = ['defining', 'run']}, {visible-path = ['api', 'helper'], home = [{text = 'other-owner'}, {revision = 3}], canonical-path = ['helper']}]";
    for scheme in [
        "version = '=2.0.0'",
        "path = '../dep', version = '=2.0.0'",
        "git = 'https://example.invalid/dep', branch = 'main', version = '=2.0.0'",
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\ndep = {{{scheme}, linkage = 'static', binding = {{selection = 'custom', home = [{{text = 'source-default'}}]}}, expected-callables = {records}}}\n")).unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        let dependency = &package.dependencies()[0];
        let expected = dependency.expected_callables().unwrap();
        assert_eq!(expected.mappings().len(), 2);
        let alias = miden_mast_package::CallableProcedurePath::from_semantic_components(vec![
            "api::module".into(),
            "alias".into(),
        ])
        .unwrap();
        let binding = expected.mappings().get(&alias).unwrap();
        assert_eq!(binding.path().components(), &["defining", "run"]);
        assert_eq!(
            binding.namespace_plan().home(),
            &[miden_core::program::CanonicalLabel::text("foreign-owner").unwrap()]
        );
        assert_ne!(binding.namespace_plan(), &dependency.binding().unwrap().namespace_plan());
        fs::write(&manifest, package.to_toml().unwrap()).unwrap();
        let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert_eq!(restored.dependencies(), package.dependencies());
    }
}

#[test]
fn workspace_expected_callables_inherit_and_override_separately_from_default_home() {
    let temp = TempDir::new().unwrap();
    let app = temp.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(temp.path().join("miden-project.toml"), "[workspace]\nmembers = ['app']\n[workspace.dependencies]\ndep = {version = '1.0', binding = {selection = 'custom', home = [{text = 'workspace-default'}]}, expected-callables = [{visible-path = ['api', 'alias'], home = [{text = 'workspace-defining'}], canonical-path = ['origin', 'run']}] }\n").unwrap();
    let manifest = app.join("miden-project.toml");
    for (extra, default_home, defining_home) in [
        ("", "workspace-default", Some("workspace-defining")),
        (
            ", binding = {selection = 'custom', home = [{text = 'member-default'}]}",
            "member-default",
            Some("workspace-defining"),
        ),
        (
            ", expected-callables = [{visible-path = ['api', 'alias'], home = [{text = 'member-defining'}], canonical-path = ['origin', 'run']}]",
            "workspace-default",
            Some("member-defining"),
        ),
        (", expected-callables = []", "workspace-default", None),
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\ndep = {{workspace = true{extra}}}\n")).unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        let dependency = &package.dependencies()[0];
        assert_eq!(
            dependency.binding().unwrap().namespace_plan().home(),
            &[miden_core::program::CanonicalLabel::text(default_home).unwrap()]
        );
        let expected = dependency.expected_callables().unwrap();
        if let Some(home) = defining_home {
            assert_eq!(expected.mappings().len(), 1);
            assert_eq!(
                expected.mappings().values().next().unwrap().namespace_plan().home(),
                &[miden_core::program::CanonicalLabel::text(home).unwrap()]
            );
        } else {
            assert!(
                expected.mappings().is_empty(),
                "an explicit empty list overrides inherited expectations"
            );
        }
        fs::write(&manifest, package.to_toml().unwrap()).unwrap();
        let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert_eq!(restored.dependencies()[0].expected_callables(), Some(expected));
        assert_eq!(restored.dependencies()[0].binding(), dependency.binding());
    }
}

#[test]
fn project_expected_callables_reject_duplicate_paths_and_do_not_supply_a_default_home() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    let record = "{visible-path = ['api', 'alias'], home = [], canonical-path = ['origin', 'run']}";
    for (extra, expected_error) in [
        (
            format!(
                ", binding = {{selection = 'custom', home = []}}, expected-callables = [{record}, {record}]"
            ),
            "duplicate expected visible callable path",
        ),
        (
            format!(", expected-callables = [{record}]"),
            "requires an explicit Latest/Pinned binding or custom home",
        ),
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[lib]\npath = 'mod.masm'\n[dependencies]\ndep = {{version = '1.0'{extra}}}\n")).unwrap();
        let context = TestContext::default();
        let error = Project::load(&manifest, &context.source_manager).unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
    }
}
