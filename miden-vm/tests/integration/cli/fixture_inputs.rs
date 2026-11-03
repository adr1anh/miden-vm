//! Caller-owned CLI fixture choices. Source declarations choose K before code generation;
//! full artifact expectations come from independent local compilation, never CLI output.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use miden_assembly::{
    Assembler, DefaultSourceManager, Linkage,
    ast::{Item, Module, ModuleKind, Path as SourcePath},
    testing::{FixtureNamespace, parser},
};
use miden_core::program::{CanonicalLabel, ExecutionDescriptor, ProcedureKey};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{
    CallableBinding, NamespacePlan, Package, PackageCallables, PackageNaming, TargetType,
    interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile},
};
use miden_processor::EnvironmentWitnessRequest;
use miden_utils_testing::librarytree::{FixtureEnvironment, NamedProgram, fixture_from_product};

const CODEC_BYTES: u32 = 4 * 1024 * 1024;
const CODEC_RECORDS: u32 = 100_000;
const OPENING_FILE_BYTES: usize = 4 * 1024 * 1024;
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn directory(parent: &Path) -> PathBuf {
    let path = parent
        .join(".cli-inputs")
        .join(NEXT.fetch_add(1, Ordering::Relaxed).to_string());
    fs::create_dir_all(&path).unwrap();
    path
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let mut result = String::from("0x");
    for byte in bytes.as_ref() {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn quote(value: &str) -> String {
    // Paths and semantic names here are fixture-owned UTF-8. Debug string escaping is JSON
    // compatible for these printable ASCII inputs; reject other inputs explicitly.
    assert!(value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
    format!("{value:?}")
}

fn home(plan: &NamespacePlan) -> String {
    format!(
        "[{}]",
        plan.home()
            .iter()
            .map(|label| quote(&hex(label.as_bytes())))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn homes() -> Vec<NamespacePlan> {
    vec![
        FixtureNamespace::assembly_tests().namespace_plan().clone(),
        NamespacePlan::new(vec![]),
    ]
}

struct ExactFixtureHomes;
impl TypedIdProfile for ExactFixtureHomes {
    type Context = [NamespacePlan];
    type Error = &'static str;
    fn validate_typed_id(&self, _: &Self::Context, _: u32, _: &[u8]) -> Result<(), Self::Error> {
        Err("CLI builtin-exact-v1 fixtures reject TypedId")
    }
}
impl HomeProfile for ExactFixtureHomes {
    fn validate_home(
        &self,
        context: &Self::Context,
        value: &[CanonicalLabel],
    ) -> Result<(), Self::Error> {
        context
            .iter()
            .any(|plan| plan.home() == value)
            .then_some(())
            .ok_or("unselected fixture home")
    }
}

fn expected(path: &Path, naming: &PackageNaming) -> String {
    let bytes = naming
        .encode_v1(
            &ExactFixtureHomes,
            homes().as_slice(),
            CodecLimits::new(CODEC_BYTES, CODEC_RECORDS, CODEC_RECORDS, CODEC_BYTES),
        )
        .unwrap();
    fs::write(path, bytes).unwrap();
    format!(
        "{{\"kind\":\"artifact\",\"expected_naming\":{}}}",
        quote(path.to_str().unwrap())
    )
}

pub struct NamingFile {
    path: PathBuf,
    size: usize,
}
impl NamingFile {
    fn new(
        directory: &Path,
        name: &str,
        target: &str,
        kernel: Option<&str>,
        libraries: &[String],
    ) -> Self {
        let document = format!(
            "{{\"version\":1,\"profile\":\"builtin-exact-v1\",\"codec_limits\":{{\"max_bytes\":{CODEC_BYTES},\"max_records\":{CODEC_RECORDS},\"max_components\":{CODEC_RECORDS},\"max_blob_bytes\":{CODEC_BYTES}}},\"allowed_homes\":[{}],\"target\":{target},\"kernel\":{},\"libraries\":[{}]}}",
            homes().iter().map(home).collect::<Vec<_>>().join(","),
            kernel.unwrap_or("null"),
            libraries.join(","),
        );
        let path = directory.join(name);
        fs::write(&path, &document).unwrap();
        Self { path, size: document.len() }
    }
    pub fn apply<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        command
            .arg("--naming-inputs")
            .arg(&self.path)
            .arg("--max-naming-input-bytes")
            .arg(self.size.to_string())
    }
}

struct SourceSelection {
    root: Box<Module>,
    support: Box<[Box<Module>]>,
    names: FixtureNamespace,
    bindings: Vec<CallableBinding>,
    choice: String,
}
impl SourceSelection {
    fn new(
        root: Box<Module>,
        support: impl IntoIterator<Item = Box<Module>>,
        assembler: &Assembler,
        kernel: bool,
    ) -> Self {
        let support = support.into_iter().collect::<Box<[_]>>();
        let modules = std::iter::once(root.as_ref())
            .chain(support.iter().map(Box::as_ref))
            .collect::<Vec<_>>();
        let mut names = FixtureNamespace::assembly_tests();
        if kernel {
            names.add_kernel_modules(assembler, &modules).unwrap();
        } else {
            for module in &modules {
                names.add_module(module).unwrap();
            }
        }
        let mut bindings = Vec::new();
        let mut records = Vec::new();
        for module in modules {
            for item in module.items().iter().filter(|item| matches!(item, Item::Procedure(_))) {
                let declaration = module.path().join(item.name());
                let binding = names.binding(&declaration).unwrap().clone();
                records.push(format!(
                    "{{\"declaration\":{},\"home\":{},\"path\":[{}]}}",
                    quote(declaration.to_absolute().unwrap().as_str()),
                    home(binding.namespace_plan()),
                    binding
                        .path()
                        .components()
                        .iter()
                        .map(|value| quote(value))
                        .collect::<Vec<_>>()
                        .join(","),
                ));
                bindings.push(binding);
            }
        }
        let choice = format!(
            "{{\"kind\":\"source\",\"compilation_home\":{},\"bindings\":[{}]}}",
            home(names.namespace_plan()),
            records.join(",")
        );
        Self { root, support, names, bindings, choice }
    }
    fn library(path: &Path, kernel: bool, namespace: Option<&str>, assembler: &Assembler) -> Self {
        let namespace: Option<Arc<SourcePath>> = if kernel {
            Some(SourcePath::KERNEL.into())
        } else {
            namespace.map(|name| miden_assembly::PathBuf::new(name).unwrap().into())
        };
        let (root, support) = parser::read_modules_from_root(
            path,
            namespace,
            Some(if kernel {
                ModuleKind::Kernel
            } else {
                ModuleKind::Library
            }),
            assembler.source_manager(),
            false,
        )
        .unwrap();
        Self::new(root, support, assembler, kernel)
    }
    fn configure(&self, assembler: Assembler) -> Assembler {
        self.names
            .configure(
                assembler,
                std::iter::once(self.root.as_ref()).chain(self.support.iter().map(Box::as_ref)),
            )
            .unwrap()
    }
}

fn assembler() -> Assembler {
    let mut assembler = Assembler::default();
    let core = CoreLibrary::default();
    assembler
        .link_package(core.package(), Linkage::Dynamic, core.naming().clone())
        .unwrap();
    assembler
}

/// Naming for a bundle command, including negative cases which must fail before a product exists.
pub fn bundle_inputs(
    dir: &Path,
    source: &Path,
    kernel: bool,
    namespace: Option<&str>,
) -> NamingFile {
    let selection = SourceSelection::library(source, kernel, namespace, &assembler());
    NamingFile::new(&directory(dir), "bundle.json", &selection.choice, None, &[])
}

/// Independently compiled library/kernel metadata, before any CLI bundle output is inspected.
pub struct LibraryFixture {
    pub package: Arc<Package>,
    pub naming: Arc<PackageNaming>,
    selected: PackageNaming,
}
impl LibraryFixture {
    pub fn new(source: &Path, kernel: bool, namespace: Option<&str>) -> Self {
        let assembler = assembler();
        let selection = SourceSelection::library(source, kernel, namespace, &assembler);
        let assembler = selection.configure(assembler);
        let name = if kernel { "kernel".into() } else { "lib".into() };
        let product = assembler
            .assemble_library_modules(
                name,
                selection.root,
                selection.support,
                if kernel {
                    TargetType::Kernel
                } else {
                    TargetType::Library
                },
            )
            .unwrap();
        let naming = Arc::new(product.naming().clone());
        let selected = project(&naming, &selection.bindings);
        let package = Arc::from(product.into_artifact(true).unwrap());
        Self { package, naming, selected }
    }
    pub fn with_package(self, package: Arc<Package>) -> Self {
        package.check_naming(&self.naming).unwrap();
        Self { package, ..self }
    }
}

// Only independently declared local K receive authority, including private callable roots.
// Full compiler naming still travels through artifact expectations. In particular, equal D does
// not turn unrelated Core bindings into authorized fixture entries.
fn project(naming: &PackageNaming, bindings: &[CallableBinding]) -> PackageNaming {
    let implementations = bindings
        .iter()
        .filter_map(|binding| {
            naming
                .callables()
                .selected_implementation(binding.key())
                .map(|implementation| (binding.key(), implementation))
        })
        .collect::<Vec<_>>();
    PackageNaming::new(
        naming.namespace_plan().clone(),
        PackageCallables::new(bindings.iter().cloned(), [], implementations).unwrap(),
        None,
    )
    .unwrap()
}

pub struct ProgramFixture {
    pub named: NamedProgram,
    expected_descriptor: ExecutionDescriptor,
    source: NamingFile,
    artifact: NamingFile,
    execution_args: Vec<OsString>,
    pub expected_naming: PathBuf,
}
impl ProgramFixture {
    pub fn new(
        dir: &Path,
        source: &Path,
        kernel: Option<&LibraryFixture>,
        libraries: &[&LibraryFixture],
    ) -> Self {
        let manager = Arc::new(DefaultSourceManager::default());
        let mut assembler = match kernel {
            Some(kernel) => Assembler::with_kernel(
                manager.clone(),
                kernel.package.clone(),
                kernel.naming.clone(),
            )
            .unwrap(),
            None => Assembler::new(manager.clone()),
        };
        let core = CoreLibrary::default();
        assembler
            .link_package(core.package(), Linkage::Dynamic, core.naming().clone())
            .unwrap();
        for library in libraries {
            assembler
                .link_package(library.package.clone(), Linkage::Dynamic, library.naming.clone())
                .unwrap();
        }
        let root = Module::parser(Some(ModuleKind::Executable))
            .parse_file(Some(SourcePath::exec_path()), source, manager)
            .unwrap();
        let selection = SourceSelection::new(root, vec![], &assembler, false);
        let assembler = selection.configure(assembler);
        let product = assembler
            .assemble_executable_modules("program".into(), selection.root, [])
            .unwrap();
        let local = project(product.naming(), &selection.bindings);
        let mut named = fixture_from_product(product, &[]);
        named.environment = FixtureEnvironment::new(
            named.naming.entry_key().unwrap(),
            std::iter::once(&local)
                .chain(kernel.map(|kernel| &kernel.selected))
                .chain(libraries.iter().map(|library| &library.selected)),
        )
        .unwrap();
        let keys = local
            .callables()
            .selected_implementations()
            .map(|(&key, _)| key)
            .chain(kernel.into_iter().flat_map(|kernel| {
                kernel.selected.callables().selected_implementations().map(|(&key, _)| key)
            }))
            .chain(libraries.iter().flat_map(|library| {
                library.selected.callables().selected_implementations().map(|(&key, _)| key)
            }))
            .collect();
        Self::finish(dir, named, &selection.choice, kernel, libraries, keys)
    }
    fn finish(
        dir: &Path,
        named: NamedProgram,
        source_choice: &str,
        kernel: Option<&LibraryFixture>,
        libraries: &[&LibraryFixture],
        keys: BTreeSet<ProcedureKey>,
    ) -> Self {
        assert!(keys.len() <= 128, "explicit CLI fixture opening budget");
        let dir = directory(dir);
        let expected_naming = dir.join("target.naming");
        let target = expected(&expected_naming, &named.naming);
        let kernel_choice =
            kernel.map(|kernel| expected(&dir.join("kernel.naming"), &kernel.naming));
        let library_choices = libraries
            .iter()
            .enumerate()
            .map(|(index, library)| {
                expected(&dir.join(format!("library-{index}.naming")), &library.naming)
            })
            .collect::<Vec<_>>();
        let source = NamingFile::new(
            &dir,
            "source.json",
            source_choice,
            kernel_choice.as_deref(),
            &library_choices,
        );
        let artifact = NamingFile::new(
            &dir,
            "artifact.json",
            &target,
            kernel_choice.as_deref(),
            &library_choices,
        );
        let execution = named.environment.execution();
        let descriptor = execution.descriptor();
        let witness_source = named.environment.source();
        let mut openings = Vec::new();
        for key in keys {
            let witness = witness_source
                .get(EnvironmentWitnessRequest {
                    root: descriptor.environment_root(),
                    key,
                    limits: execution.opening_limits(),
                })
                .unwrap()
                .unwrap();
            let steps = witness
                .path
                .iter()
                .map(|step| {
                    format!(
                        "{{\"node\":{},\"selected_child\":{}}}",
                        quote(&hex(step.node.to_bytes().unwrap())),
                        step.selected_child.map_or("null".into(), |slot| slot.to_string())
                    )
                })
                .collect::<Vec<_>>();
            openings.push(format!(
                "{{\"key\":{},\"steps\":[{}]}}",
                quote(&hex(key.as_word().as_bytes())),
                steps.join(",")
            ));
        }
        let document = format!(
            "{{\"version\":1,\"entry_key\":{},\"environment_root\":{},\"openings\":[{}]}}",
            quote(&hex(descriptor.entry_key().as_word().as_bytes())),
            quote(&hex(descriptor.environment_root().as_word().as_bytes())),
            openings.join(",")
        );
        assert!(document.len() <= OPENING_FILE_BYTES);
        let openings_path = dir.join("openings.json");
        fs::write(&openings_path, document).unwrap();
        let policy_path = dir.join("policy.json");
        // This finite CLI fixture policy is chosen independently of the evidence file and private
        // advice; native admission still enforces every per-opening and aggregate limit.
        let policy = r#"{"version":1,"opening":{"max_nodes":257,"max_depth":256,"max_list_children":128,"max_total_list_children":128,"max_encoded_bytes":2097152,"max_storage_bytes":4194304},"ledger":{"max_occurrences":262144,"max_total_list_children":16777216,"max_encoded_bytes":536870912,"max_library_rows":67108864,"max_compression_requests":67108864,"max_retained_bytes":536870912,"max_peak_bytes":1073741824},"session":{"max_cached_keys":128,"max_requests":1048576,"max_retained_bytes":805306368,"max_prepare_peak_bytes":1610612736},"trace":{"max_events":1048576,"max_retained_bytes":1073741824,"max_prepare_peak_bytes":1610612736,"max_validation_work":1073741824},"source":{"max_file_bytes":4194304,"max_openings":128,"max_steps":32768,"max_encoded_bytes":2097152,"max_retained_bytes":16777216,"max_prepare_peak_bytes":33554432,"max_requests":1048576}}"#;
        fs::write(&policy_path, policy).unwrap();
        let execution_args = vec![
            "--expected-entry-key".into(),
            hex(descriptor.entry_key().as_word().as_bytes()).into(),
            "--expected-environment-root".into(),
            hex(descriptor.environment_root().as_word().as_bytes()).into(),
            "--environment-openings".into(),
            openings_path.into_os_string(),
            "--environment-policy".into(),
            policy_path.into_os_string(),
            "--max-environment-policy-bytes".into(),
            policy.len().to_string().into(),
        ];
        Self {
            named,
            expected_descriptor: descriptor,
            source,
            artifact,
            execution_args,
            expected_naming,
        }
    }
    pub fn write_package(&self, path: &Path) {
        self.named.package.write_to_file(path).unwrap();
    }
    /// Verifier authority fixed by the fixture before any CLI output or proof is read.
    pub fn descriptor_args(&self) -> [String; 4] {
        [
            "--expected-entry-key".into(),
            hex(self.expected_descriptor.entry_key().as_word().as_bytes()),
            "--expected-environment-root".into(),
            hex(self.expected_descriptor.environment_root().as_word().as_bytes()),
        ]
    }
    pub fn verify_command(&self, dir: &Path, proof: impl AsRef<Path>) -> Command {
        let mut command = super::bin_under_test(dir);
        command
            .arg("verify")
            .arg("--proof")
            .arg(proof.as_ref())
            .args(self.descriptor_args());
        command
    }
    pub fn apply<'a>(&self, command: &'a mut Command, artifact: bool) -> &'a mut Command {
        if artifact {
            self.artifact.apply(command);
        } else {
            self.source.apply(command);
        }
        command.args(&self.execution_args)
    }
    pub fn compile<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        self.source.apply(command)
    }
    pub fn command(&self, dir: &Path, action: &str, program: impl AsRef<Path>) -> Command {
        let program = program.as_ref();
        let mut command = super::bin_under_test(dir);
        command.arg(action).arg(program);
        self.apply(&mut command, program.extension().is_some_and(|ext| ext == "masp"));
        command
    }
}

#[cfg(feature = "internal")]
#[test]
fn selected_fixture_files_admit_and_execute_without_cli_output() {
    use miden_vm::{
        DefaultHost, FastProcessor, StackInputs,
        internal::{
            execution_inputs::{AdmittedExecutionInputs, ExecutionInputLimits},
            naming_inputs::{NamingInputs, NamingRole},
        },
    };

    let dir = tempfile::TempDir::new().unwrap();
    let source = dir.path().join("selected.masm");
    fs::write(&source, "proc helper push.3 swap drop end begin exec.helper end").unwrap();
    let fixture = ProgramFixture::new(dir.path(), &source, None, &[]);
    NamingInputs::read(&fixture.source.path, fixture.source.size)
        .unwrap()
        .source(NamingRole::Target)
        .unwrap();
    let admitted = NamingInputs::read(&fixture.artifact.path, fixture.artifact.size)
        .unwrap()
        .admit(NamingRole::Target, fixture.named.package.clone())
        .unwrap();
    assert_eq!(admitted.naming, fixture.named.naming);

    let openings = fixture
        .execution_args
        .windows(2)
        .find(|pair| pair[0] == "--environment-openings")
        .map(|pair| Path::new(&pair[1]))
        .unwrap();
    let execution = AdmittedExecutionInputs::read(
        openings,
        fixture.named.environment.execution(),
        miden_utils_testing::librarytree::trace_limits(),
        ExecutionInputLimits {
            max_file_bytes: OPENING_FILE_BYTES,
            max_openings: 128,
            max_steps: 32768,
            max_encoded_bytes: 2 * 1024 * 1024,
            max_retained_bytes: 16 * 1024 * 1024,
            max_prepare_peak_bytes: 32 * 1024 * 1024,
            max_requests: 1024,
        },
    )
    .unwrap();
    let mut host = DefaultHost::default().with_environment_source(execution.source());
    let output = FastProcessor::new(StackInputs::default())
        .execute_sync(&fixture.named.program, execution.environment(), &mut host)
        .unwrap();
    assert_eq!(output.stack[0].as_canonical_u64(), 3);
}
