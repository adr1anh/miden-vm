//! Named source/code fixtures for this unit-test crate, with separate code and environment inputs.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_assembly::{
    Assembler, Report,
    ast::{Module, ModuleKind},
    testing::FixtureNamespace,
};
use miden_core::{mast::MastForest, program::ImplementationRoot};
use miden_debug_types::DefaultSourceManager;
use miden_mast_package::{
    Package, PackageCallables, PackageSymbols, ProcedureName, TargetType, Version,
};
use miden_utils_testing::librarytree::FixtureEnvironment;

use super::native_fixture_environment;
use crate::{EnvironmentWitnessSource, ExecutionEnvironment, Program};

pub(crate) struct NamedFixture {
    pub package: Arc<Package>,
    pub naming: PackageSymbols,
    pub program: Program,
    pub environment: ExecutionEnvironment,
    pub source: Arc<dyn EnvironmentWitnessSource>,
}

/// Selects the shared source-fixture convention, independent of bodies or import source aliases.
pub(crate) fn named_source(source: &str) -> Result<NamedFixture, Report> {
    let manager = Arc::new(DefaultSourceManager::default());
    let root = Module::parser(Some(ModuleKind::Executable)).parse_str(
        Some(miden_assembly::Path::exec_path()),
        source,
        manager.clone(),
    )?;
    named_module(Assembler::new(manager), root, [])
}

/// Retains caller-supplied metadata, or opts a raw source cohort into the explicit fixture policy.
/// Prebound imported bindings are preserved and included as fixture-owner-selected environment
/// inputs; code availability remains the caller's host responsibility.
pub(crate) fn named_module(
    mut assembler: Assembler,
    root: Box<Module>,
    support: impl IntoIterator<Item = Box<Module>>,
) -> Result<NamedFixture, Report> {
    let support = support.into_iter().collect::<Vec<_>>();
    if assembler.namespace_inputs() == &miden_assembly::NamespaceInputs::default() {
        let mut names = FixtureNamespace::assembly_tests();
        for module in core::iter::once(root.as_ref()).chain(support.iter().map(Box::as_ref)) {
            names.add_module(module)?;
        }
        assembler = names.configure(
            assembler,
            core::iter::once(root.as_ref()).chain(support.iter().map(Box::as_ref)),
        )?;
    }
    let mut extra = assembler
        .linker()
        .libraries()
        .map(|library| library.naming().clone())
        .collect::<Vec<_>>();
    if let Some(kernel) = assembler.linker().kernel_naming() {
        extra.push(kernel);
    }
    let product =
        assembler.assemble_executable_modules("processor-fixture".into(), root, support)?;
    let naming = product.naming().clone();
    let package = Arc::from(product.into_artifact(true)?);
    let extra = extra.iter().map(Arc::as_ref).collect::<Vec<_>>();
    named_package(package, naming, &extra)
}

/// Uses exact caller-selected names and code selections, not a decoder-derived permission profile.
pub(crate) fn named_package(
    package: Arc<Package>,
    naming: PackageSymbols,
    extra: &[&PackageSymbols],
) -> Result<NamedFixture, Report> {
    let program = package.try_into_program(&naming)?;
    let entry = naming.entry_key().expect("converted code has an explicit entry");
    let fixture =
        FixtureEnvironment::new(entry, core::iter::once(&naming).chain(extra.iter().copied()))?;
    let (environment, source) = native_fixture_environment(&fixture);
    Ok(NamedFixture {
        package,
        naming,
        program,
        environment,
        source,
    })
}

/// Names a synthetic forest using independently supplied bindings. Every retained root must be
/// covered; no procedure key, home or target identity is reconstructed from its body digest.
pub(crate) fn named_program(
    program: Program,
    entry: ProcedureName,
    targets: impl IntoIterator<Item = (ProcedureName, ImplementationRoot)>,
) -> Result<NamedFixture, Report> {
    let key = entry.key();
    let home = entry.namespace_plan().clone();
    let mut bindings = alloc::vec![entry];
    let mut implementations = alloc::vec![(key, ImplementationRoot::new(program.hash()))];
    for (binding, implementation) in targets {
        implementations.push((binding.key(), implementation));
        bindings.push(binding);
    }
    let callables = PackageCallables::new(bindings, [], implementations).map_err(Report::msg)?;
    let naming = PackageSymbols::new(home, callables, Some(key)).map_err(Report::msg)?;
    let forest: Arc<MastForest> = program.mast_forest().clone();
    let package = Package::create(
        "processor-synthetic".into(),
        Version::new(0, 0, 0),
        TargetType::Executable,
        forest,
        [],
        [],
        &naming,
    )
    .map_err(Report::msg)?;
    let mut fixture = named_package(Arc::new(package), naming, &[])?;
    // Preserve legacy auxiliary Program data for its remaining transport tests. Authorization
    // comes exclusively from the independently named environment above, never that data.
    fixture.program = program;
    Ok(fixture)
}
