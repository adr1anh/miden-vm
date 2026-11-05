use miden_core::program::CanonicalLabel;
use miden_mast_package::NamespacePath;

use super::*;

const MATH: &str = "0x0100000000000000020000000000000003000000000000000400000000000000";
const PARENT: &str = "0x0500000000000000060000000000000007000000000000000800000000000000";
const FOREIGN: &str = "0x09000000000000000a000000000000000b000000000000000c00000000000000";

#[test]
fn project_catalogs_resolve_every_home_before_returning_typed_configuration() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    fs::write(&manifest, format!(r#"
[package]
name = 'app'
version = '1.0.0'
[library-catalog]
math = '{MATH}'
parent = '{PARENT}'
foreign = '{FOREIGN}'
[lib]
path = 'mod.masm'
naming = {{convention = 'defining-paths', binding = {{selection = 'pinned', base = [{{library-id = {{catalog = 'parent'}}}}], library-id = {{catalog = 'math'}}, revision = 3}}}}
[[bin]]
name = 'main'
path = 'main.masm'
naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{library-id = {{catalog = 'parent'}}}}]}}}}
[dependencies]
source_alias = {{version = '=2.0.0', linkage = 'static', binding = {{selection = 'latest', base = [{{library-id = {{catalog = 'parent'}}}}], library-id = {{catalog = 'math'}}}}, expected-callables = [{{visible-path = ['api', 'alias'], home = [{{library-id = {{catalog = 'foreign'}}}}], canonical-path = ['origin', 'run']}}]}}
"#)).unwrap();
    let context = TestContext::default();
    let package = Project::load(&manifest, &context.source_manager).unwrap().package();
    let dependency = &package.dependencies()[0];
    assert_eq!(dependency.name().as_ref(), "source_alias");
    assert_eq!(dependency.required_version().to_string(), "=2.0.0");
    assert_eq!(dependency.linkage(), Linkage::Static);
    let base =
        NamespacePath::new(vec![CanonicalLabel::library_id(Word::try_from(PARENT).unwrap())]);
    assert_eq!(
        dependency.binding(),
        Some(&DependencyBinding::Standard(LibraryRef::new(
            base.clone(),
            Word::try_from(MATH).unwrap(),
            LibrarySelection::Latest,
        )))
    );
    let expected = dependency.expected_callables().unwrap();
    let defining = expected.mappings().values().next().unwrap();
    assert_eq!(defining.path().components(), &["origin", "run"]);
    assert_eq!(
        defining.namespace_plan().home(),
        &[CanonicalLabel::library_id(Word::try_from(FOREIGN).unwrap())]
    );
    assert_eq!(
        package.executable_targets()[0].naming.as_ref().unwrap().binding(),
        &DependencyBinding::Custom(base)
    );
    let written = package.to_toml().unwrap();
    assert!(!written.contains("catalog"));
    fs::write(&manifest, written).unwrap();
    let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
    assert_eq!(restored.dependencies(), package.dependencies());
    assert_eq!(
        restored.library_target().unwrap().naming,
        package.library_target().unwrap().naming
    );
    assert_eq!(restored.executable_targets()[0].naming, package.executable_targets()[0].naming);
}

#[test]
fn project_catalogs_reject_missing_names_in_each_configured_position() {
    let temp = TempDir::new().unwrap();
    let manifest = temp.path().join("miden-project.toml");
    for (configuration, expected) in [
        (
            "[dependencies]\ndep = {version = '1', binding = {selection = 'latest', base = [], library-id = {catalog = 'missing'}}}",
            "unknown library catalog name 'missing'",
        ),
        (
            "[dependencies]\ndep = {version = '1', binding = {selection = 'custom', home = [{library-id = {catalog = 'missing'}}]}}",
            "unknown library catalog name 'missing'",
        ),
        (
            "[dependencies]\ndep = {version = '1', binding = {selection = 'custom', home = []}, expected-callables = [{visible-path = ['api'], home = [{library-id = {catalog = 'missing'}}], canonical-path = ['run']}]}",
            "unknown library catalog name 'missing'",
        ),
        (
            "[lib]\npath = 'mod.masm'\nnaming = {convention = 'defining-paths', binding = {selection = 'latest', base = [], library-id = {catalog = 'missing'}}}",
            "unknown library catalog name 'missing'",
        ),
        (
            "[[bin]]\npath = 'main.masm'\nnaming = {convention = 'defining-paths', binding = {selection = 'custom', home = [{library-id = {catalog = 'missing'}}]}}",
            "unknown library catalog name 'missing'",
        ),
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[library-catalog]\nmath = '{MATH}'\n{configuration}\n")).unwrap();
        let context = TestContext::default();
        let error = Project::load(&manifest, &context.source_manager).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn workspace_catalogs_coalesce_and_resolve_inherited_and_overridden_bindings() {
    let temp = TempDir::new().unwrap();
    let app = temp.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(temp.path().join("miden-project.toml"), format!(r#"
[workspace]
members = ['app']
[workspace.library-catalog]
math = '{MATH}'
parent = '{PARENT}'
[workspace.dependencies]
source_alias = {{version = '=2.0.0', binding = {{selection = 'latest', base = [{{library-id = {{catalog = 'parent'}}}}], library-id = {{catalog = 'math'}}}}, expected-callables = [{{visible-path = ['api'], home = [{{library-id = {{catalog = 'foreign'}}}}], canonical-path = ['run']}}]}}
"#)).unwrap();
    let manifest = app.join("miden-project.toml");
    for (extra, selection, expected_home) in [
        ("", LibrarySelection::Latest, FOREIGN),
        (
            ", binding = {selection = 'pinned', base = [], library-id = {catalog = 'math'}, revision = 7}",
            LibrarySelection::Revision(core::num::NonZeroU32::new(7).unwrap()),
            FOREIGN,
        ),
        (
            ", expected-callables = [{visible-path = ['api'], home = [{library-id = {catalog = 'parent'}}], canonical-path = ['run']}]",
            LibrarySelection::Latest,
            PARENT,
        ),
    ] {
        fs::write(&manifest, format!(r#"
[package]
name = 'app'
version = '1.0.0'
[library-catalog]
math = '{MATH}'
foreign = '{FOREIGN}'
[lib]
path = 'mod.masm'
naming = {{convention = 'defining-paths', binding = {{selection = 'latest', base = [], library-id = {{catalog = 'math'}}}}}}
[dependencies]
source_alias = {{workspace = true{extra}}}
"#)).unwrap();
        let context = TestContext::default();
        let package = Project::load(&manifest, &context.source_manager).unwrap().package();
        let dependency = &package.dependencies()[0];
        let Some(DependencyBinding::Standard(binding)) = dependency.binding() else {
            panic!("expected standard binding")
        };
        assert_eq!(binding.library_id(), Word::try_from(MATH).unwrap());
        assert_eq!(binding.selection(), selection);
        assert_eq!(dependency.name().as_ref(), "source_alias");
        let expected = dependency.expected_callables().unwrap();
        assert_eq!(
            expected.mappings().values().next().unwrap().namespace_plan().home(),
            &[CanonicalLabel::library_id(Word::try_from(expected_home).unwrap())]
        );
        assert_eq!(
            package
                .library_target()
                .unwrap()
                .naming
                .as_ref()
                .unwrap()
                .binding()
                .namespace_plan(),
            LibraryRef::new(
                NamespacePath::new(vec![]),
                Word::try_from(MATH).unwrap(),
                LibrarySelection::Latest
            )
            .namespace_plan()
        );
        let written = package.to_toml().unwrap();
        assert!(!written.contains("catalog"));
        fs::write(&manifest, written).unwrap();
        let restored = Project::load(&manifest, &context.source_manager).unwrap().package();
        assert_eq!(restored.dependencies(), package.dependencies());
        assert_eq!(
            restored.library_target().unwrap().naming,
            package.library_target().unwrap().naming
        );
    }
}

#[test]
fn catalog_conflicts_and_malformed_entries_reject_without_shadowing_or_inference() {
    let temp = TempDir::new().unwrap();
    let app = temp.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(
        temp.path().join("miden-project.toml"),
        format!("[workspace]\nmembers = ['app']\n[workspace.library-catalog]\nmath = '{MATH}'\n",),
    )
    .unwrap();
    let manifest = app.join("miden-project.toml");
    for (catalog, configuration, expected) in [
        (
            format!("math = '{PARENT}'"),
            "",
            "conflicting or ambiguous library catalog name 'math'",
        ),
        (
            "unused = 'readable-name'".into(),
            "",
            "invalid library catalog identity for 'unused'",
        ),
        (format!("math = '{MATH}'\nmath = '{MATH}'"), "", "duplicate key"),
        (
            format!("math = '{MATH}'"),
            "[dependencies]\nmath = {version = '1', binding = {selection = 'latest', base = [], library-id = 'math'}}",
            "invalid library identity literal",
        ),
        (
            format!("math = '{MATH}'"),
            "[dependencies]\nmath = {version = '1', binding = {selection = 'latest', base = [], library-id = {catalog = 'missing'}}}",
            "unknown library catalog name 'missing'",
        ),
    ] {
        fs::write(&manifest, format!("[package]\nname = 'app'\nversion = '1.0.0'\n[library-catalog]\n{catalog}\n{configuration}\n")).unwrap();
        let context = TestContext::default();
        let error = Project::load(&manifest, &context.source_manager).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}
