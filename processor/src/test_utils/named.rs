//! Named source/code fixtures for this unit-test crate, with separate code and environment inputs.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_assembly::{
    Assembler, Report,
    ast::{Module, ModuleKind},
    testing::FixtureNamespace,
};
use miden_core::program::ImplementationRoot;
use miden_debug_types::DefaultSourceManager;
use miden_mast_package::{
    CodePackage, Package, PackageCallables, PackageProcedureOccurrence, PackageSymbols,
    ProcedureName, TargetType, Version,
};
use miden_utils_testing::librarytree::FixtureEnvironment;

use super::{fixture_entry_digest, fixture_entry_root, native_fixture_environment};
use crate::{EnvironmentSource, ExecutionTarget, ResolutionLimits};

pub(crate) struct NamedFixture {
    pub package: Arc<Package>,
    pub naming: PackageSymbols,
    pub code: CodePackage,
    pub target: ExecutionTarget,
    pub resolution_limits: ResolutionLimits,
    pub source: Arc<dyn EnvironmentSource>,
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
        .map(|library| library.code().clone())
        .collect::<Vec<_>>();
    if let Some(kernel) = assembler.linker().kernel_code() {
        extra.push(kernel.clone());
    }
    let product =
        assembler.assemble_executable_modules("processor-fixture".into(), root, support)?;
    let code = product.into_code_package(true)?;
    let extra = extra.iter().map(|code| code.symbols().as_ref()).collect::<Vec<_>>();
    named_code_package(code, &extra)
}

/// Uses exact caller-selected names and code selections, not a decoder-derived permission profile.
pub(crate) fn named_package(
    package: Arc<Package>,
    naming: PackageSymbols,
    extra: &[&PackageSymbols],
) -> Result<NamedFixture, Report> {
    let code = CodePackage::new(package, Arc::new(naming)).map_err(Report::msg)?;
    named_code_package(code, extra)
}

fn named_code_package(
    code: CodePackage,
    extra: &[&PackageSymbols],
) -> Result<NamedFixture, Report> {
    let package = code.package().clone();
    let naming = code.symbols().as_ref().clone();
    let entry = naming
        .entry_key()
        .ok_or_else(|| Report::msg("named fixture code must have an explicit entry"))?;
    let fixture =
        FixtureEnvironment::new(entry, core::iter::once(&naming).chain(extra.iter().copied()))?;
    let (target, resolution_limits, source) = native_fixture_environment(&fixture);
    Ok(NamedFixture {
        package,
        naming,
        code,
        target,
        resolution_limits,
        source,
    })
}

/// Names a synthetic forest using independently supplied bindings. Every retained root must be
/// covered; no procedure key, home or target identity is reconstructed from its body digest.
pub(crate) fn named_program(
    code: CodePackage,
    entry: ProcedureName,
    targets: impl IntoIterator<Item = (ProcedureName, ImplementationRoot)>,
) -> Result<NamedFixture, Report> {
    let key = entry.key();
    let home = entry.namespace_plan().clone();
    let mut bindings = alloc::vec![entry];
    let mut implementations =
        alloc::vec![(key, ImplementationRoot::new(fixture_entry_digest(&code)))];
    let supplied_entry = code
        .package()
        .procedure_occurrence(code.symbols().entry_key().expect("fixture code has an entry"))
        .expect("fixture entry retains its exact occurrence");
    let mut occurrences = alloc::vec![PackageProcedureOccurrence::new(
        key,
        fixture_entry_root(&code),
        supplied_entry.source_node(),
    )];
    for (binding, implementation) in targets {
        if code.symbols().callables().selected_implementation(binding.key()) == Some(implementation)
            && let Some(occurrence) = code.package().procedure_occurrence(binding.key())
        {
            occurrences.push(*occurrence);
        }
        implementations.push((binding.key(), implementation));
        bindings.push(binding);
    }
    let callables = PackageCallables::new(bindings, [], implementations).map_err(Report::msg)?;
    let naming = PackageSymbols::new(home, callables, Some(key)).map_err(Report::msg)?;
    let mut package = Package::create(
        "processor-synthetic".into(),
        Version::new(0, 0, 0),
        TargetType::Executable,
        code.package().mast_forest().clone(),
        [],
        [],
        &naming,
    )
    .map_err(Report::msg)?;
    package.sections = code.package().sections.clone();
    occurrences.sort_by_key(|row| row.key().as_word().as_bytes());
    let package = package.with_procedure_occurrences(occurrences, &naming).map_err(Report::msg)?;
    named_package(Arc::new(package), naming, &[])
}
