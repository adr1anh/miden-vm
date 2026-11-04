//! Native execution of explicitly selected project instances and their exact code supplies.
//!
//! The finite homes and environment below are fixture-owner choices, not production admission.

use std::{
    collections::BTreeSet,
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use miden_assembly::{
    Assembler, ProjectTargetSelector, ResolvedPackage,
    testing::{TestRegistry, admit_fixture_package},
};
use miden_core::{
    Felt, Word,
    mast::MastNode,
    program::{CanonicalLabel, ProcedureKey},
};
use miden_mast_package::{
    CallableProcedurePath, CodePackage, NamespacePath, Package, ProcedureName,
};
use miden_processor::{
    DefaultHost, EnvironmentSourceError, EnvironmentWitnessRequest, EnvironmentWitnessSource,
    FastProcessor, ResolutionWitness, StackInputs, StackOutputs,
};
use miden_utils_testing::librarytree::FixtureEnvironment;

const LIBRARY_ID: &str = "0x0100000000000000020000000000000003000000000000000400000000000000";

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let directory = std::env::temp_dir().join(format!(
                "miden-project-instances-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return Self(directory),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => panic!("failed to create project fixture: {error}"),
            }
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn library_home(owner: &str, revision: Option<u32>) -> NamespacePath {
    let mut labels = vec![
        CanonicalLabel::text(owner).unwrap(),
        CanonicalLabel::text(if revision.is_some() { "pinned" } else { "latest" }).unwrap(),
        CanonicalLabel::library_id(Word::try_from(LIBRARY_ID).unwrap()),
    ];
    if let Some(revision) = revision {
        labels.push(CanonicalLabel::revision(NonZeroU32::new(revision).unwrap()));
    }
    NamespacePath::new(labels)
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

fn home_config(home: &NamespacePath) -> String {
    format!(
        "[{}]",
        home.home()
            .iter()
            .map(|label| format!("{{canonical = {:?}}}", label.as_bytes()))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn expected_config(visible: &[&str], binding: &ProcedureName) -> String {
    format!(
        "{{visible-path = {:?}, home = {}, canonical-path = {:?}}}",
        visible,
        home_config(binding.namespace_plan()),
        binding.path().components(),
    )
}

fn write(path: &Path, source: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn executable_manifest(dependencies: &str) -> String {
    format!(
        "[package]\nname = 'app'\nversion = '1.0.0'\n\
         [[bin]]\nname = 'main'\npath = 'main.masm'\n\
         naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'instance-client'}}]}}}}\n\
         [dependencies]\n{dependencies}",
    )
}

fn library_manifest(name: &str, namespace: &str, dependencies: &str) -> String {
    format!(
        "[package]\nname = '{name}'\nversion = '1.0.0'\n\
         [lib]\nnamespace = '{namespace}'\npath = 'mod.masm'\n\
         naming = {{convention = 'defining-paths', binding = {{selection = 'custom', home = [{{text = 'source-fallback'}}]}}}}\n\
         [dependencies]\n{dependencies}",
    )
}

fn assemble(manifest: &Path, homes: Vec<NamespacePath>) -> ResolvedPackage {
    let mut registry = TestRegistry::default();
    let mut assembler = Assembler::default().for_project_at_path(manifest, &mut registry).unwrap();
    // These complete homes were selected before compilation, independently of artifact metadata.
    assembler.with_package_naming_provider(move |package| admit_fixture_package(package, &homes));
    assembler
        .assemble_with_naming(ProjectTargetSelector::Executable("main"), "release")
        .unwrap()
}

fn selected_package<'a>(
    resolved: &'a ResolvedPackage,
    expected: &ProcedureName,
) -> &'a CodePackage {
    let mut candidates = resolved.dependency_packages.iter().filter(|code| {
        let naming = code.symbols();
        naming.callables().binding(expected.key()) == Some(expected)
            && naming.namespace_plan() == expected.namespace_plan()
    });
    let code = candidates.next().expect("exact selected owner code must be retained");
    assert!(
        candidates.next().is_none(),
        "the selected owner must have one exact code supply"
    );
    code.package().check_naming(code.symbols()).unwrap();
    code
}

fn exec_targets(package: &Package) -> BTreeSet<ProcedureKey> {
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

struct RecordingSource {
    inner: Arc<dyn EnvironmentWitnessSource>,
    requested: Mutex<BTreeSet<ProcedureKey>>,
}

impl EnvironmentWitnessSource for RecordingSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        self.requested.lock().unwrap().insert(request.key);
        self.inner.get(request)
    }
}

fn execute(
    resolved: &ResolvedPackage,
    owners: &[&ProcedureName],
    external_code: bool,
) -> StackOutputs {
    let supplies = owners.iter().map(|owner| selected_package(resolved, owner)).collect::<Vec<_>>();
    let environment = FixtureEnvironment::new(
        resolved.code.symbols().entry_key().unwrap(),
        core::iter::once(resolved.code.symbols().as_ref())
            .chain(supplies.iter().map(|code| code.symbols().as_ref())),
    )
    .unwrap();
    let source = Arc::new(RecordingSource {
        inner: environment.source(),
        requested: Mutex::new(BTreeSet::new()),
    });
    let mut host = DefaultHost::default().with_environment_source(source.clone());
    host.load_library(resolved.code.clone()).unwrap();
    if external_code {
        for code in supplies {
            host.load_library(code.clone()).unwrap();
        }
    }
    let output = FastProcessor::new(StackInputs::new(&[Felt::from_u32(1)]).unwrap())
        .with_options(
            miden_processor::ExecutionOptions::default()
                .with_resolution_limits(environment.resolution_limits()),
        )
        .unwrap()
        .execute_sync(environment.target(), &mut host)
        .expect("exact project selections and code must execute natively")
        .stack;
    let requested = source.requested.lock().unwrap();
    assert!(requested.contains(&resolved.code.symbols().entry_key().unwrap()));
    for owner in owners {
        assert!(
            requested.contains(&owner.key()),
            "each canonical owner key needs resolution, including keys with equal implementations",
        );
    }
    output
}

#[test]
fn same_source_pinned_project_instances_execute_with_distinct_keys_and_equal_bodies() {
    let workspace = Workspace::new();
    let first = binding(library_home("instance-owner", Some(1)), &["dep", "lib", "run"]);
    let second = binding(library_home("instance-owner", Some(2)), &["dep", "lib", "run"]);
    assert_ne!(first.key(), second.key(), "the pinned revision qualifies canonical identity");
    let mut products = Vec::new();
    for linkage in ["static", "dynamic"] {
        let directory = workspace.0.join(linkage);
        let mut dependencies = String::new();
        for (alias, mount, revision, expected) in
            [("first", "left", 1, &first), ("second", "right", 2, &second)]
        {
            dependencies.push_str(&format!(
                "{alias} = {{package = 'dep', path = 'dep', linkage = '{linkage}', \
                 source-mount = {{package-base = '::dep::lib', source-base = '::{mount}'}}, \
                 binding = {{selection = 'pinned', base = [{{text = 'instance-owner'}}], library-id = '{LIBRARY_ID}', revision = {revision}}}, \
                 expected-callables = [{}]}}\n",
                expected_config(&["dep", "lib", "run"], expected),
            ));
        }
        let manifest = directory.join("miden-project.toml");
        write(&manifest, &executable_manifest(&dependencies));
        write(
            &directory.join("main.masm"),
            "use left as chosen\nuse right\nbegin exec.chosen::run exec.right::run end\n",
        );
        write(
            &directory.join("dep/miden-project.toml"),
            &library_manifest("dep", "dep::lib", ""),
        );
        write(&directory.join("dep/mod.masm"), "pub proc run mul.2 add.3 end\n");
        let resolved = assemble(
            &manifest,
            vec![
                home("instance-client"),
                first.namespace_plan().clone(),
                second.namespace_plan().clone(),
            ],
        );
        assert_eq!(resolved.dependency_packages.len(), 2);
        assert_eq!(
            exec_targets(resolved.code.package()),
            BTreeSet::from([first.key(), second.key()])
        );
        let mut bodies = Vec::new();
        let mut commitments = Vec::new();
        for expected in [&first, &second] {
            let code = selected_package(&resolved, expected);
            let (package, naming) = (code.package(), code.symbols());
            assert_eq!(package.name, "dep");
            assert_eq!(package.version.to_string(), "1.0.0");
            assert_eq!(
                naming.callables().key_for_visible_path(expected.path()),
                Some(expected.key()),
            );
            assert_eq!(resolved.code.symbols().callables().binding(expected.key()), Some(expected));
            let body = naming.callables().selected_implementation(expected.key()).unwrap();
            assert_eq!(
                resolved.code.symbols().callables().selected_implementation(expected.key()),
                Some(body),
            );
            let forest = resolved.code.package().mast_forest();
            let node = forest.find_procedure_root(body.into_word()).unwrap();
            assert_eq!(forest[node].is_external(), linkage == "dynamic");
            bodies.push(body);
            commitments.push(package.to_dependency());
        }
        assert_eq!(bodies[0], bodies[1], "the same source can supply equal D under distinct K");
        assert_ne!(commitments[0].digest, commitments[1].digest);
        let runtime = resolved.code.package().manifest.dependencies().cloned().collect::<Vec<_>>();
        if linkage == "dynamic" {
            assert_eq!(runtime.len(), 2, "same-name runtime supplies must both survive");
            assert!(commitments.iter().all(|dependency| runtime.contains(dependency)));
        } else {
            assert!(runtime.is_empty());
        }
        let output = execute(&resolved, &[&first, &second], linkage == "dynamic");
        assert_eq!(output.get_element(0), Some(Felt::from_u32(13)));
        products.push((resolved, output));
    }
    assert_eq!(products[0].1, products[1].1, "bundled and external code have the same behavior");
    let entry = products[0].0.code.symbols().entry_key().unwrap();
    assert_eq!(products[1].0.code.symbols().entry_key(), Some(entry));
    assert_eq!(
        products[0].0.code.symbols().callables().selected_implementation(entry),
        products[1].0.code.symbols().callables().selected_implementation(entry),
        "the caller's ordered canonical invocation keys do not depend on code availability",
    );
}

#[test]
fn pinned_project_reexports_private_helpers_and_retained_latest_calls_execute() {
    let workspace = Workspace::new();
    let pinned = library_home("instance-owner", Some(1));
    let run = binding(pinned.clone(), &["dep", "lib", "implementation", "run"]);
    let hidden = binding(pinned.clone(), &["dep", "lib", "implementation", "hidden"]);
    let latest = binding(library_home("inner-owner", None), &["inner", "bump"]);
    let rebased_latest = binding(pinned.clone(), &["inner", "bump"]);
    assert_ne!(latest.key(), rebased_latest.key());
    let mut outputs = Vec::new();
    for linkage in ["static", "dynamic"] {
        let directory = workspace.0.join(linkage);
        let manifest = directory.join("miden-project.toml");
        let dependency = format!(
            "selected = {{package = 'dep', path = 'dep', linkage = '{linkage}', \
             source-mount = {{package-base = '::dep::lib', source-base = '::left'}}, \
             binding = {{selection = 'pinned', base = [{{text = 'instance-owner'}}], library-id = '{LIBRARY_ID}', revision = 1}}, \
             expected-callables = [{}, {}]}}\n",
            expected_config(&["dep", "lib", "implementation", "run"], &run),
            expected_config(&["dep", "lib", "alias"], &run),
        );
        write(&manifest, &executable_manifest(&dependency));
        write(
            &directory.join("main.masm"),
            "use left as chosen\nbegin exec.chosen::alias end\n",
        );
        let inner_dependency = format!(
            "inner = {{path = 'inner', linkage = '{linkage}', \
             binding = {{selection = 'latest', base = [{{text = 'inner-owner'}}], library-id = '{LIBRARY_ID}'}}, \
             expected-callables = [{}]}}\n",
            expected_config(&["inner", "bump"], &latest),
        );
        write(
            &directory.join("dep/miden-project.toml"),
            &library_manifest("dep", "dep::lib", &inner_dependency),
        );
        write(
            &directory.join("dep/mod.masm"),
            "pub mod implementation\npub use {run as alias} from dep::lib::implementation\n",
        );
        write(
            &directory.join("dep/implementation.masm"),
            "use inner as chosen\nproc hidden add.3 end\n\
             pub proc run mul.2 exec.hidden exec.chosen::bump end\n",
        );
        write(
            &directory.join("dep/inner/miden-project.toml"),
            &library_manifest("inner", "inner", ""),
        );
        write(&directory.join("dep/inner/mod.masm"), "pub proc bump add.5 end\n");
        let resolved = assemble(
            &manifest,
            vec![home("instance-client"), pinned.clone(), latest.namespace_plan().clone()],
        );
        let code = selected_package(&resolved, &run);
        let (package, naming) = (code.package(), code.symbols());
        assert_eq!(
            naming.callables().key_for_visible_path(&path(&["dep", "lib", "alias"])),
            Some(run.key()),
        );
        assert_eq!(naming.callables().binding(hidden.key()), Some(&hidden));
        assert_eq!(naming.callables().key_for_visible_path(hidden.path()), None);
        assert_eq!(naming.callables().binding(latest.key()), Some(&latest));
        assert!(naming.callables().binding(rebased_latest.key()).is_none());
        assert!(exec_targets(package).is_superset(&BTreeSet::from([hidden.key(), latest.key()])));
        assert!(exec_targets(resolved.code.package()).contains(&run.key()));
        let fallback = binding(home("source-fallback"), &["dep", "lib", "implementation", "run"]);
        assert!(naming.callables().binding(fallback.key()).is_none());
        let output = execute(&resolved, &[&run, &latest], linkage == "dynamic");
        assert_eq!(output.get_element(0), Some(Felt::from_u32(10)));
        outputs.push(output);
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn conflicting_project_implementations_for_one_key_are_rejected_before_execution() {
    let workspace = Workspace::new();
    let mut products = Vec::new();
    for body in [1, 2] {
        let directory = workspace.0.join(format!("body-{body}"));
        let manifest = directory.join("miden-project.toml");
        write(&manifest, &executable_manifest(""));
        write(&directory.join("main.masm"), &format!("begin add.{body} end\n"));
        products.push(assemble(&manifest, vec![home("instance-client")]));
    }
    let first = products[0].code.symbols();
    let second = products[1].code.symbols();
    let entry = first.entry_key().unwrap();
    assert_eq!(second.entry_key(), Some(entry));
    assert_ne!(
        first.callables().selected_implementation(entry),
        second.callables().selected_implementation(entry),
    );
    let error = FixtureEnvironment::new(entry, [first.as_ref(), second.as_ref()])
        .err()
        .expect("an environment cannot select different D for the same canonical K");
    assert!(error.to_string().contains("conflicting fixture selection"), "{error}");
}
