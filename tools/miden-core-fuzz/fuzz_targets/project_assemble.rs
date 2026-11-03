//! Fuzz target for assembling Miden projects from a filesystem tree.
//!
//! This target exercises `ProjectAssembler::assemble` on controlled library, executable, and
//! kernel project layouts. It also reads emitted debug sections and converts assembled executable
//! and kernel packages through the public package APIs.
//!
//! Run with: cargo +nightly fuzz run project_assemble --fuzz-dir tools/miden-core-fuzz

#![no_main]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use libfuzzer_sys::fuzz_target;
use miden_assembly::{
    Assembler, NamespaceInputs, ProjectSourceInputs, ProjectTargetSelector, TargetAssemblyContext,
};
use miden_assembly_syntax::{
    PathComponent,
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core::serde::{Deserializable, Serializable, SliceReader};
use miden_core_fuzz::naming::{SyntheticProfile, check_naming_admission, source_home};
use miden_mast_package::{
    CallableBinding, CallableProcedurePath, NamespacePlan, Package as MastPackage, SectionId,
    TargetType, debug_info::PackageDebugInfo, interface::serialization::CodecLimits,
};
use miden_package_registry::InMemoryPackageRegistry;

const MAX_MANIFEST_SNIPPET_LEN: usize = 40 * 1024;
const EXECUTABLE_TARGET: &str = "main";
const NAMING_LIMITS: CodecLimits =
    CodecLimits::new(4 * 1024 * 1024, 100_000, 100_000, 4 * 1024 * 1024);

static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(0);

struct TempProjectTree {
    root: PathBuf,
}

impl TempProjectTree {
    fn new() -> std::io::Result<Self> {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .join(format!("miden-project-assemble-fuzz-{}-{id}", std::process::id()));

        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;

        Ok(Self { root })
    }

    fn path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(path)
    }
}

impl Drop for TempProjectTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_MANIFEST_SNIPPET_LEN {
        return;
    }
    let Ok(snippet) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(tree) = TempProjectTree::new() else {
        return;
    };
    let metadata_value = toml::Value::String(snippet.to_owned()).to_string();

    match scenario_index(data, 8) {
        0 => assemble_library_project(&tree, &metadata_value, "dev"),
        1 => assemble_library_project(&tree, &metadata_value, "release"),
        2 => assemble_executable_project(&tree, &metadata_value, "dev"),
        3 => assemble_executable_project(&tree, &metadata_value, "release"),
        4 => assemble_kernel_project(&tree, &metadata_value, ProjectTargetSelector::Library, "dev"),
        5 => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Library,
            "release",
        ),
        6 => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Executable(EXECUTABLE_TARGET),
            "dev",
        ),
        _ => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Executable(EXECUTABLE_TARGET),
            "release",
        ),
    }
});

fn assemble_library_project(tree: &TempProjectTree, metadata_value: &str, profile: &str) {
    let manifest_path = tree.path("library/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "libpkg"
version = "1.0.0"
description = "library fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
path = "lib.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("library/lib.masm"),
            r#"pub proc helper
    push.1
    push.2
    add
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, ProjectTargetSelector::Library, profile);
}

fn assemble_executable_project(tree: &TempProjectTree, metadata_value: &str, profile: &str) {
    let manifest_path = tree.path("executable/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "apppkg"
version = "1.0.0"
description = "executable fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
path = "lib.masm"

[[bin]]
name = "main"
path = "main.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("executable/lib.masm"),
            r#"pub proc helper
    push.3
end
"#,
        )
        .is_err()
        || write_file(
            &tree.path("executable/main.masm"),
            r#"use $exec::lib

begin
    exec.lib::helper
    drop
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, ProjectTargetSelector::Executable(EXECUTABLE_TARGET), profile);
}

fn assemble_kernel_project(
    tree: &TempProjectTree,
    metadata_value: &str,
    target: ProjectTargetSelector<'_>,
    profile: &str,
) {
    let manifest_path = tree.path("kernel/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "kernelpkg"
version = "1.0.0"
description = "kernel fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
kind = "kernel"
path = "kernel.masm"

[[bin]]
name = "main"
path = "main.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("kernel/kernel.masm"),
            r#"pub proc foo
    caller
end
"#,
        )
        .is_err()
        || write_file(
            &tree.path("kernel/main.masm"),
            r#"begin
    syscall.foo
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, target, profile);
}

fn assemble_project(manifest_path: &Path, target: ProjectTargetSelector<'_>, profile: &str) {
    let assembler = Assembler::default();
    let mut registry = InMemoryPackageRegistry::default();

    let mut project_assembler = assembler
        .for_project_at_path(manifest_path, &mut registry)
        .expect("the controlled project manifest must load");
    project_assembler
        .with_namespace_inputs_provider(source_namespace_inputs)
        .with_package_naming_provider(|package| {
            package
                .admit_naming(&SyntheticProfile::packages(), &true, NAMING_LIMITS)
                .map_err(Report::msg)
        });
    let package = project_assembler
        .assemble(target, profile)
        .expect("the controlled library, executable and kernel fixtures must assemble");

    validate_package(&package);
}

/// The harness explicitly names its complete fixed source cohort, including private helpers and
/// entrypoints. Dependency requests choose the default home before these declarations are bound.
/// Public kernel definitions use unique root labels; their private helpers keep a child home.
fn source_namespace_inputs(
    context: &TargetAssemblyContext<'_>,
    sources: &ProjectSourceInputs,
    _base: &Assembler,
) -> Result<NamespaceInputs, Report> {
    let home = context
        .dependency_binding
        .map_or_else(source_home, |binding| binding.namespace_plan());
    let mut inputs = NamespaceInputs::new().with_namespace_plan(home.clone());
    for module in
        core::iter::once(sources.root.as_ref()).chain(sources.support.iter().map(Box::as_ref))
    {
        for procedure in module.procedures() {
            let declaration = module.path().join(procedure.name());
            let (binding_home, components) =
                if context.target.is_kernel() && procedure.visibility().is_exported() {
                    (NamespacePlan::new(vec![]), vec![procedure.name().to_string()])
                } else {
                    let mut components = Vec::new();
                    for component in declaration.components() {
                        let component = component.into_diagnostic()?;
                        if component != PathComponent::Root {
                            components.push(component.as_str().to_owned());
                        }
                    }
                    (home.clone(), components)
                };
            let canonical =
                CallableProcedurePath::from_semantic_components(components).into_diagnostic()?;
            let binding = CallableBinding::new(binding_home, canonical).into_diagnostic()?;
            inputs = inputs.with_callable_binding(declaration.into(), binding)?;
        }
    }
    Ok(inputs)
}

fn validate_package(package: &MastPackage) {
    validate_debug_sections(package);

    // STABILITY ORACLE: an ASSEMBLER-produced package must satisfy the wire contract its
    // own reader enforces — canonical bytes must decode to an Eq-equal package. Catches
    // assembler/serializer output that the package deserializer would reject (the
    // writer/reader asymmetry class at the assembly layer).
    let canonical = package.to_bytes();
    let redecoded = MastPackage::read_from_bytes(&canonical)
        .expect("an assembled package must satisfy its own wire format");
    assert_eq!(redecoded, *package, "assembled package must round-trip through its wire format");

    let profile = SyntheticProfile::packages();
    let naming = check_naming_admission(package, &profile, &true, NAMING_LIMITS)
        .expect("assembled fixtures must use the harness's independently selected homes");
    assert_eq!(
        check_naming_admission(&redecoded, &profile, &true, NAMING_LIMITS).unwrap(),
        naming
    );
    let trusted = MastPackage::read_from_bytes_trusted(&canonical).unwrap();
    assert_eq!(trusted, *package);
    assert_eq!(
        check_naming_admission(&trusted, &profile, &true, NAMING_LIMITS).unwrap(),
        naming
    );

    // These conversion helpers borrow the package, despite the `try_into_*` names.
    match package.kind {
        TargetType::Executable => {
            package
                .try_into_program(&naming)
                .expect("assembled executable has an explicit entry");
            let _ = package.try_embedded_kernel_package();
        },
        TargetType::Kernel => {
            package
                .check_kernel_code(&naming)
                .expect("assembled kernel exports named root code");
            let _ = package.kernel_module_descriptor();
        },
        _ if package.is_library() => {
            let _ = package.kernel_runtime_dependency();
        },
        _ => (),
    }
}

fn validate_debug_sections(package: &MastPackage) {
    for section in &package.sections {
        if section.id == SectionId::DEBUG_INFO {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = PackageDebugInfo::read_from(&mut reader);
        }
    }
}

fn write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

fn scenario_index(data: &[u8], count: usize) -> usize {
    data.iter()
        .fold(0usize, |acc, byte| acc.wrapping_mul(31).wrapping_add(*byte as usize))
        % count
}
