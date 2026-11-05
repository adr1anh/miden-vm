#![cfg(feature = "std")]

use std::{path::Path, sync::Arc};

use miden_assembly::{
    CallableBinding, NamespaceInputs, ProjectAssembler, Report,
    testing::{
        FixtureNamespace, TestContext, TestRegistry, admit_fixture_package,
        project_fixture_namespace_inputs,
    },
};
use miden_mast_package::{CallableProcedurePath, NamespacePlan, TargetType};

pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// This test assembles the `main` exectuable target of the `protocol` kernel project.
///
/// This exercises:
///
/// * Workspace management
/// * Intra-workspace dependencies
/// * Inter-workspace dependencies
/// * Multi-target projects
/// * Multiple linkage modes
#[test]
fn assemble_a_protocol_like_workspace_project() -> Result<(), Report> {
    let mut context = TestContext::new();

    let manifest_path = Path::new(FIXTURES_DIR)
        .join("protocol")
        .join("kernel")
        .join("miden-project.toml");

    let mut assembler = context.project_assembler_for_path(&manifest_path)?;
    configure_protocol_fixture(&mut assembler);
    assembler.assemble(miden_assembly::ProjectTargetSelector::Executable("entry"), "dev")?;

    Ok(())
}

/// This test assembles the `userspace` library target of the `protocol` workspace.
///
/// The userspace package overrides the workspace `miden-utils` dependency to dynamic linkage and
/// depends on the workspace `miden-tx` kernel package. Its manifest should therefore record both
/// packages as runtime dependencies.
#[test]
fn assemble_protocol_userspace_dynamic_dependencies() -> Result<(), Report> {
    let mut context = TestContext::new();

    let manifest_path = Path::new(FIXTURES_DIR)
        .join("protocol")
        .join("userspace")
        .join("miden-project.toml");

    let mut assembler = context.project_assembler_for_path(&manifest_path)?;
    configure_protocol_fixture(&mut assembler);
    let package = assembler.assemble(miden_assembly::ProjectTargetSelector::Library, "dev")?;
    assert_eq!(&package.name, "miden-protocol");
    assert_eq!(package.kind, TargetType::Library);

    let dependencies = package.manifest.dependencies().collect::<Vec<_>>();
    assert_eq!(dependencies.len(), 2);

    let utils = dependencies
        .iter()
        .copied()
        .find(|dependency| &dependency.name == "miden-utils")
        .expect("userspace package should record dynamic miden-utils dependency");
    assert_eq!(utils.kind, TargetType::Library);
    assert_eq!(utils.version.to_string(), "0.1.0");

    let tx = dependencies
        .iter()
        .copied()
        .find(|dependency| &dependency.name == "miden-tx")
        .expect("userspace package should record workspace kernel dependency");
    assert_eq!(tx.kind, TargetType::Kernel);
    assert_eq!(tx.version.to_string(), "1.0.0");

    Ok(())
}

// This fixture intentionally publishes utils::panic at N0 before compiling its kernel reexport.
// Neither the source alias nor the kernel tag rebases the imported procedure's canonical key.
fn configure_protocol_fixture(assembler: &mut ProjectAssembler<'_, TestRegistry>) {
    assembler
        .with_namespace_inputs_provider(|context, sources, base| {
            if context.package.name().inner()
                != &miden_package_registry::PackageId::from("miden-utils")
            {
                return project_fixture_namespace_inputs(context, sources, base);
            }
            let path = CallableProcedurePath::from_semantic_components(vec!["panic".to_string()])
                .map_err(Report::msg)?;
            let binding =
                CallableBinding::new(NamespacePlan::new(vec![]), path).map_err(Report::msg)?;
            NamespaceInputs::new()
                .with_namespace_plan(FixtureNamespace::assembly_tests().namespace_plan().clone())
                .with_callable_binding(
                    Arc::from(miden_assembly::Path::new("::miden::utils::panic")),
                    binding,
                )
        })
        .with_package_naming_provider(|package| {
            let homes = [
                FixtureNamespace::assembly_tests().namespace_plan().clone(),
                NamespacePlan::new(vec![]),
            ];
            admit_fixture_package(package, &homes)
        });
}
