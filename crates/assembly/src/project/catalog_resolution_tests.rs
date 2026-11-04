use alloc::string::String;
use core::num::NonZeroU32;

use miden_core::{
    Word,
    mast::MastNode,
    program::{CanonicalLabel, ProcedureKey},
};
use miden_mast_package::{CallableProcedurePath, ProcedureName};
use miden_project::{DependencyBinding, LibraryRef, LibrarySelection};
use tempfile::TempDir;

use super::*;
use crate::testing::TestRegistry;

const MATH: &str = "0x0100000000000000020000000000000003000000000000000400000000000000";
const OTHER: &str = "0x0500000000000000060000000000000007000000000000000800000000000000";
const ANCESTOR: &str = "0x09000000000000000a000000000000000b000000000000000c00000000000000";
const APP: &str = "0x0d000000000000000e000000000000000f000000000000001000000000000000";
const SOURCE: &str = "use dep as chosen\npub proc entry exec.chosen::run end\n";

fn id(literal: &str) -> Word {
    Word::try_from(literal).unwrap()
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

fn write(path: &FsPath, source: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn app_home() -> NamespacePath {
    NamespacePath::new(vec![
        CanonicalLabel::text("client").unwrap(),
        CanonicalLabel::library_id(id(APP)),
    ])
}

fn parent_base() -> NamespacePath {
    NamespacePath::new(vec![
        CanonicalLabel::text("tenant").unwrap(),
        CanonicalLabel::library_id(id(ANCESTOR)),
        CanonicalLabel::revision(NonZeroU32::new(2).unwrap()),
        CanonicalLabel::text("nested").unwrap(),
    ])
}

fn fallback_home() -> NamespacePath {
    NamespacePath::new(vec![
        CanonicalLabel::text("source-fallback").unwrap(),
        CanonicalLabel::library_id(id(OTHER)),
    ])
}

/// Every supplied ID, complete default home and expected public binding is chosen independently
/// before the corresponding source package is created. Catalog spelling supplies no authority.
struct Owner {
    request: LibraryRef,
    run: ProcedureName,
    caller: ProcedureName,
    expected: ExpectedVisibleCallables,
}

impl Owner {
    fn new(identity: Word, selection: LibrarySelection) -> Self {
        let request = LibraryRef::new(parent_base(), identity, selection);
        let run = request.callable_binding(path(&["dep", "run"])).unwrap();
        let caller = ProcedureName::new(app_home(), path(&["app", "entry"])).unwrap();
        let expected =
            ExpectedVisibleCallables::new([(path(&["dep", "run"]), run.clone())]).unwrap();
        Self { request, run, caller, expected }
    }
}

fn workspace(
    directory: &FsPath,
    selection: LibrarySelection,
    selected_name: &str,
    member_extra: &str,
) -> PathBuf {
    let (selection, revision, revision_label) = match selection {
        LibrarySelection::Latest => ("latest", String::new(), String::new()),
        LibrarySelection::Revision(revision) => (
            "pinned",
            format!(", revision = {revision}"),
            format!(", {{revision = {revision}}}"),
        ),
    };
    write(
        &directory.join("miden-project.toml"),
        &format!(
            r#"
[workspace]
members = ['app', 'dep']
[workspace.library-catalog]
math = '{MATH}'
other = '{OTHER}'
ancestor = '{ANCESTOR}'
[workspace.dependencies]
dep = {{path = 'dep', linkage = 'static', binding = {{selection = '{selection}', base = [{{text = 'tenant'}}, {{library-id = {{catalog = 'ancestor'}}}}, {{revision = 2}}, {{text = 'nested'}}], library-id = {{catalog = '{selected_name}'}}{revision}}}, expected-callables = [{{visible-path = ['dep', 'run'], home = [{{text = 'tenant'}}, {{library-id = {{catalog = 'ancestor'}}}}, {{revision = 2}}, {{text = 'nested'}}, {{text = '{selection}'}}, {{library-id = {{catalog = '{selected_name}'}}}}{revision_label}], canonical-path = ['dep', 'run']}}]}}
"#
        ),
    );
    let manifest = directory.join("app/miden-project.toml");
    write(
        &manifest,
        &format!(
            r#"
[package]
name = 'app'
version = '1.0.0'
[library-catalog]
renamed = '{MATH}'
app-owner = '{APP}'
{member_extra}
[lib]
path = 'mod.masm'
naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'client'}}, {{library-id = {{catalog = 'app-owner'}}}}]}}}}
[dependencies]
dep = {{workspace = true}}
"#
        ),
    );
    write(&directory.join("app/mod.masm"), SOURCE);
    write(
        &directory.join("dep/miden-project.toml"),
        &format!(
            r#"
[package]
name = 'dep'
version = '1.0.0'
[library-catalog]
fallback-owner = '{OTHER}'
[lib]
path = 'mod.masm'
naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'source-fallback'}}, {{library-id = {{catalog = 'fallback-owner'}}}}]}}}}
"#
        ),
    );
    write(&directory.join("dep/mod.masm"), "pub proc run push.7 drop end\n");
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
fn workspace_catalogs_lower_supplied_ids_and_preserve_keys_across_readable_renames() {
    let mut selection_keys = Vec::new();
    let mut callee_bodies = Vec::new();
    for selection in [
        LibrarySelection::Latest,
        LibrarySelection::Revision(NonZeroU32::new(3).unwrap()),
    ] {
        let mut results = Vec::new();
        for (name, identity) in [("math", id(MATH)), ("renamed", id(MATH)), ("other", id(OTHER))] {
            let owner = Owner::new(identity, selection);
            let fallback = ProcedureName::new(fallback_home(), path(&["dep", "run"])).unwrap();
            let temp = TempDir::new().unwrap();
            let manifest = workspace(temp.path(), selection, name, "");
            let mut registry = TestRegistry::default();
            let mut assembler =
                Assembler::default().for_project_at_path(&manifest, &mut registry).unwrap();
            let requested = &assembler.project().dependencies()[0];
            assert_eq!(requested.name().as_ref(), "dep");
            assert_eq!(
                requested.binding(),
                Some(&DependencyBinding::Standard(owner.request.clone()))
            );
            assert_eq!(requested.expected_callables(), Some(&owner.expected));
            assert_eq!(
                assembler
                    .project()
                    .library_target()
                    .unwrap()
                    .naming
                    .as_ref()
                    .unwrap()
                    .binding()
                    .namespace_plan(),
                app_home()
            );
            assert!(assembler.namespace_inputs_provider.is_none());
            let resolved = assembler
                .assemble_with_naming(ProjectTargetSelector::Library, "release")
                .unwrap();
            assert_eq!(fs::read_to_string(temp.path().join("app/mod.masm")).unwrap(), SOURCE);
            assert_eq!(resolved.naming.namespace_plan(), &app_home());
            assert_eq!(resolved.naming.callables().binding(owner.run.key()), Some(&owner.run));
            assert_eq!(
                resolved.naming.callables().binding(owner.caller.key()),
                Some(&owner.caller)
            );
            assert_eq!(resolved.naming.callables().binding(fallback.key()), None);
            assert!(has_exec(&resolved.package, owner.run.key()));
            assert!(!has_exec(&resolved.package, fallback.key()));
            let callee =
                resolved.naming.callables().selected_implementation(owner.run.key()).unwrap();
            let caller =
                resolved.naming.callables().selected_implementation(owner.caller.key()).unwrap();
            assert_ne!(owner.run.key().as_word(), callee.as_word());
            resolved.package.check_naming(&resolved.naming).unwrap();
            results.push((owner.run.key(), callee, caller));
            callee_bodies.push(callee);
        }
        assert_eq!(results[0], results[1], "catalog renaming preserves K and caller D");
        assert_ne!(results[0].0, results[2].0, "different opaque supplied IDs name different K");
        assert_eq!(results[0].1, results[2].1, "identical supplied bodies retain identical D");
        assert_ne!(results[0].2, results[2].2, "the caller commits to its requested EXEC K");
        selection_keys.push(results[0].0);
    }
    assert_ne!(selection_keys[0], selection_keys[1], "Pinned revision qualifies K");
    assert!(callee_bodies.iter().all(|body| body == &callee_bodies[0]));
}

#[test]
fn selected_catalog_errors_reject_before_source_lowering_or_cache_promotion() {
    for (selected_name, extra, message) in [
        ("missing", String::new(), "unknown library catalog name 'missing'"),
        (
            "math",
            format!("math = '{OTHER}'"),
            "conflicting or ambiguous library catalog name 'math'",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let manifest = workspace(temp.path(), LibrarySelection::Latest, selected_name, &extra);
        // Parsing this invalid source would fail independently. Catalog validation must reject
        // while constructing the project, before source providers can lower or promote code.
        write(&temp.path().join("dep/mod.masm"), "this is deliberately invalid MASM\n");
        let mut registry = TestRegistry::default();
        let error = match Assembler::default().for_project_at_path(&manifest, &mut registry) {
            Err(error) => error,
            Ok(_) => panic!("selected catalog error must reject before compilation"),
        };
        assert!(error.to_string().contains(message), "{error}");
        assert!(registry.loaded_packages().is_empty());
        assert!(registry.cached_packages().is_empty());
    }
}
