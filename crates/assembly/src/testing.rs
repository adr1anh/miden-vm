use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    sync::Arc,
    vec::Vec,
};
use core::num::NonZeroU32;

#[cfg(feature = "std")]
use miden_assembly_syntax::Word;
#[cfg(any(test, feature = "testing"))]
pub use miden_assembly_syntax::parser;
use miden_assembly_syntax::{
    Parse, Path, PathComponent,
    ast::{Item, Module, ModuleKind},
    debuginfo::{DefaultSourceManager, SourceManager},
    diagnostics::{
        IntoDiagnostic, Report,
        reporting::{ReportHandlerOpts, set_hook},
    },
};
pub use miden_assembly_syntax::{
    assert_diagnostic, assert_diagnostic_lines, parse_module, regex, source_file, testing::Pattern,
};
#[cfg(feature = "testing")]
use miden_assembly_syntax::{ast::Form, debuginfo::SourceFile};
use miden_core::program::{CanonicalLabel, Program};
use miden_mast_package::{CallableProcedurePath, NamespacePlan, Package, PackageId, PackageNaming};
#[cfg(feature = "std")]
use miden_project::TargetType;

#[cfg(feature = "std")]
use crate::diagnostics::reporting::set_panic_hook;
use crate::{CallableBinding, assembler::Assembler, linker::SymbolResolutionContext};

/// Admits fixture naming only under the complete homes explicitly chosen by its owner.
/// Unknown TypedIds reject unless their exact codec/bytes occur in those expected homes.
/// This test utility supplies no production publisher, registration or home policy.
pub fn admit_fixture_package(
    package: &Package,
    homes: &[NamespacePlan],
) -> Result<PackageNaming, Report> {
    use miden_mast_package::interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile};

    struct ExpectedHomes;

    impl TypedIdProfile for ExpectedHomes {
        type Context = [NamespacePlan];
        type Error = &'static str;

        fn validate_typed_id(
            &self,
            context: &Self::Context,
            codec: u32,
            canonical_bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let expected = context.iter().flat_map(NamespacePlan::home).any(|label| {
                let bytes = label.as_bytes();
                bytes[1] == 3
                    && u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) == codec
                    && &bytes[10..] == canonical_bytes
            });
            if expected {
                Ok(())
            } else {
                Err("unexpected fixture TypedId")
            }
        }
    }

    impl HomeProfile for ExpectedHomes {
        fn validate_home(
            &self,
            context: &Self::Context,
            home: &[CanonicalLabel],
        ) -> Result<(), Self::Error> {
            if context.iter().any(|expected| expected.home() == home) {
                Ok(())
            } else {
                Err("unexpected fixture home")
            }
        }
    }

    package
        .admit_naming(
            &ExpectedHomes,
            homes,
            CodecLimits::new(4 * 1024 * 1024, 100_000, 100_000, 4 * 1024 * 1024),
        )
        .map_err(Report::msg)
}

/// Admits only the explicit ordinary and root homes selected by assembly fixtures.
///
/// Foreign homes require an explicitly chosen fixture profile instead of this helper.
pub fn fixture_package_naming(package: &Package) -> Result<PackageNaming, Report> {
    admit_fixture_package(
        package,
        &[
            FixtureNamespace::assembly_tests().namespace_plan().clone(),
            NamespacePlan::new(vec![]),
        ],
    )
}

/// Selects fixture executable code without reconstructing environment or kernel authority.
pub fn fixture_program(package: &Package) -> Program {
    let naming =
        fixture_package_naming(package).expect("fixture must use an explicitly allowed home");
    package.unwrap_program(&naming)
}

/// Chaining convenience restricted to the explicit assembly fixture home convention.
pub trait FixtureProgram {
    fn fixture_program(&self) -> Program;
}

impl FixtureProgram for Package {
    fn fixture_program(&self) -> Program {
        fixture_program(self)
    }
}

/// Explicit naming metadata for assembly test fixtures.
///
/// This utility convention is independent of bodies, source import aliases, and package digests.
/// It neither derives a LibraryId nor constructs or validates a Protocol interface/profile. Raw
/// assembler tests opt in by collecting their concrete modules, then calling [`Self::configure`]
/// with the exact module cohort they will assemble. Production assemblers retain their requirement
/// for explicitly supplied namespace and callable metadata.
#[derive(Clone, Debug)]
pub struct FixtureNamespace {
    namespace_plan: NamespacePlan,
    bindings: BTreeMap<Arc<Path>, CallableBinding>,
}

impl FixtureNamespace {
    /// Retains the complete typed home chosen by the fixture owner.
    pub fn new(namespace_plan: NamespacePlan) -> Self {
        Self {
            namespace_plan,
            bindings: BTreeMap::new(),
        }
    }

    /// The explicit, deterministic home used by [`TestContext`]'s source fixture helpers.
    ///
    /// These labels are a test utility convention, with no Protocol identity or admission claim.
    pub fn assembly_tests() -> Self {
        Self::new(NamespacePlan::new(vec![
            CanonicalLabel::text("miden-assembly-test-fixtures").unwrap(),
            CanonicalLabel::revision(NonZeroU32::new(1).unwrap()),
        ]))
    }

    pub fn namespace_plan(&self) -> &NamespacePlan {
        &self.namespace_plan
    }

    /// Revalidates a package against this fixture's caller home and explicitly configured bindings.
    pub fn admit_package(&self, package: &Package) -> Result<PackageNaming, Report> {
        let mut homes = vec![self.namespace_plan.clone()];
        for binding in self.bindings.values() {
            if !homes.contains(binding.namespace_plan()) {
                homes.push(binding.namespace_plan().clone());
            }
        }
        admit_fixture_package(package, &homes)
    }

    /// Names every concrete procedure, including private helpers and executable entrypoints.
    ///
    /// Canonical components follow the exact semantic defining path. Import/re-export aliases,
    /// visibility, invocation reachability, and procedure bodies do not enter this convention.
    pub fn add_module(&mut self, module: &Module) -> Result<(), Report> {
        for item in module.items() {
            if !matches!(item, Item::Procedure(_)) {
                continue;
            }
            let declaration = module.path().join(item.name());
            let mut components = Vec::new();
            for component in declaration.components() {
                let component = component.into_diagnostic()?;
                if !matches!(component, PathComponent::Root) {
                    components.push(component.as_str().to_string());
                }
            }
            let canonical =
                CallableProcedurePath::from_semantic_components(components).into_diagnostic()?;
            let binding =
                CallableBinding::new(self.namespace_plan.clone(), canonical).into_diagnostic()?;
            self.add_binding(declaration.into(), binding)?;
        }
        Ok(())
    }

    /// Names a kernel source cohort using the fixture's explicit D8 placement convention.
    ///
    /// The first module is the root. Public modules determine the exported surface. Public item
    /// re-exports resolve through the base assembler's actual imported bindings to their defining
    /// procedure; aliases never create a second key. Exported definitions use their existing leaf
    /// as a globally unique root label, and private definitions retain this fixture's child home.
    pub fn add_kernel_modules(
        &mut self,
        base: &Assembler,
        modules: &[&Module],
    ) -> Result<(), Report> {
        let Some(root) = modules.first() else {
            return Err(Report::msg("kernel fixture requires a root module"));
        };
        let mut public_modules = BTreeSet::new();
        let mut pending = vec![Arc::<Path>::from(root.path())];
        while let Some(path) = pending.pop() {
            if !public_modules.insert(path.clone()) {
                continue;
            }
            let Some(module) = modules.iter().find(|module| module.path() == path.as_ref()) else {
                continue;
            };
            for child in module.submodules() {
                if child.visibility.is_exported() {
                    pending.push(module.path().join(&child.name).into());
                }
            }
        }

        let mut exports = BTreeSet::new();
        for module in modules {
            if public_modules.contains(module.path()) {
                for procedure in module.procedures() {
                    if procedure.visibility().is_exported() {
                        exports
                            .insert(absolute_fixture_path(&module.path().join(procedure.name()))?);
                    }
                }
            }
        }

        // Reuse the linker's visibility and alias resolution for public item re-exports. This
        // scratch graph retains the actual prebound package inputs, never guessed foreign naming.
        if modules.iter().any(|module| {
            public_modules.contains(module.path())
                && module.imports().any(|import| import.visibility().is_exported())
        }) {
            let mut linker = base.linker().clone();
            linker.link_modules(modules.iter().map(|module| Box::new((**module).clone())))?;
            for module in linker.modules() {
                if !public_modules.contains(module.path()) {
                    continue;
                }
                for import in module.imports().filter(|import| import.visibility().is_exported()) {
                    let caller = SymbolResolutionContext {
                        span: import.span(),
                        module: module.id(),
                        kind: None,
                    };
                    let path = module.path().join(import.local_name());
                    if let Some(gid) = linker.resolve_path(&caller, &path)?.into_global_id()
                        && linker[gid].is_procedure()
                    {
                        exports.insert(absolute_fixture_path(
                            &linker[gid.module].path().join(linker[gid].name()),
                        )?);
                    }
                }
            }
        }

        let mut root_keys = BTreeSet::new();
        for module in modules {
            for procedure in module.procedures() {
                let declaration = absolute_fixture_path(&module.path().join(procedure.name()))?;
                if exports.contains(&declaration) {
                    let path = CallableProcedurePath::from_semantic_components(vec![
                        procedure.name().to_string(),
                    ])
                    .into_diagnostic()?;
                    let binding =
                        CallableBinding::new(NamespacePlan::new(vec![]), path).into_diagnostic()?;
                    if !root_keys.insert(binding.key()) {
                        return Err(Report::msg(
                            "kernel fixture has conflicting root export labels",
                        ));
                    }
                    self.add_binding(declaration, binding)?;
                } else {
                    let components = declaration
                        .components()
                        .filter_map(|component| match component {
                            Ok(PathComponent::Root) => None,
                            component => {
                                Some(component.map(|component| component.as_str().to_string()))
                            },
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .into_diagnostic()?;
                    let path = CallableProcedurePath::from_semantic_components(components)
                        .into_diagnostic()?;
                    let binding = CallableBinding::new(self.namespace_plan().clone(), path)
                        .into_diagnostic()?;
                    self.add_binding(declaration, binding)?;
                }
            }
        }
        Ok(())
    }

    /// Supplies explicit metadata for a declaration, including a foreign package descriptor.
    ///
    /// A re-export descriptor may have a different source spelling from the defining procedure;
    /// its supplied binding must still retain that procedure's actual canonical path and home.
    /// Repeating identical metadata is harmless; conflicting metadata is rejected.
    pub fn add_binding(
        &mut self,
        declaration: Arc<Path>,
        binding: CallableBinding,
    ) -> Result<(), Report> {
        let declaration = absolute_fixture_path(&declaration)?;
        if let Some(existing) = self.bindings.get(&declaration) {
            if existing != &binding {
                return Err(Report::msg(format!(
                    "conflicting fixture callable metadata for '{declaration}'"
                )));
            }
        } else {
            self.bindings.insert(declaration, binding);
        }
        Ok(())
    }

    pub fn binding(&self, declaration: &Path) -> Option<&CallableBinding> {
        let declaration = declaration.to_absolute().ok()?;
        self.bindings.get(declaration.as_ref())
    }

    /// Configures a raw test assembler for its existing and explicitly supplied upcoming modules.
    ///
    /// Only concrete declarations in that cohort receive metadata. A fixture sidecar can contain
    /// additional private definitions without attaching absent declarations to an importing
    /// assembler. Call this once on an assembler whose callable metadata has not been configured.
    /// A previously supplied different home is rejected; an identical home is retained.
    pub fn configure<'a>(
        &self,
        mut assembler: Assembler,
        modules: impl IntoIterator<Item = &'a Module>,
    ) -> Result<Assembler, Report> {
        if assembler.namespace_plan().is_some_and(|plan| plan != &self.namespace_plan) {
            return Err(Report::msg(
                "fixture namespace conflicts with the assembler's explicit NamespacePlan",
            ));
        }
        let mut declarations = BTreeSet::new();
        for module in assembler.linker().modules() {
            for symbol in module.symbols() {
                if symbol.is_procedure() {
                    declarations.insert(absolute_fixture_path(&module.path().join(symbol.name()))?);
                }
            }
        }
        for module in modules {
            for item in module.items() {
                if matches!(item, Item::Procedure(_)) {
                    declarations.insert(absolute_fixture_path(&module.path().join(item.name()))?);
                }
            }
        }

        assembler = assembler.with_namespace_plan(self.namespace_plan.clone());
        for declaration in declarations {
            let Some(binding) = self.bindings.get(&declaration) else {
                continue;
            };
            assembler = if binding.namespace_plan() == &self.namespace_plan {
                assembler.with_callable_path(declaration, binding.path().clone())?
            } else {
                assembler.with_callable_binding(declaration, binding.clone())?
            };
        }
        Ok(assembler)
    }
}

fn absolute_fixture_path(path: &Path) -> Result<Arc<Path>, Report> {
    let path = path.to_absolute().into_diagnostic()?;
    Ok(Arc::from(path.as_ref()))
}

#[cfg(all(test, feature = "std"))]
mod fixture_namespace_tests;

/// A [TestContext] provides common functionality for all tests which interact with an [Assembler].
///
/// It is used by constructing it with `TestContext::default()`, which will initialize the
/// diagnostic reporting infrastructure, and construct a default [Assembler] instance for you. You
/// can then optionally customize the context, or start invoking any of its test helpers.
///
/// Some of the assertion macros defined above require a [TestContext], so be aware of that.
pub struct TestContext {
    source_manager: Arc<dyn SourceManager>,
    assembler: Assembler,
    fixture_namespace: FixtureNamespace,
    #[cfg(feature = "std")]
    registry: TestRegistry,
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TestContext {
    pub fn new() -> Self {
        #[cfg(feature = "logging")]
        {
            // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }

        #[cfg(feature = "std")]
        {
            let result = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
            #[cfg(feature = "std")]
            if result.is_ok() {
                set_panic_hook();
            }
        }

        #[cfg(not(feature = "std"))]
        {
            let _ = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
        }
        let source_manager = Arc::new(DefaultSourceManager::default());
        let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);
        #[cfg(feature = "std")]
        {
            Self {
                source_manager,
                assembler,
                fixture_namespace: FixtureNamespace::assembly_tests(),
                registry: Default::default(),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Self {
                source_manager,
                assembler,
                fixture_namespace: FixtureNamespace::assembly_tests(),
            }
        }
    }

    #[cfg(feature = "std")]
    pub fn with_warnings_as_errors(self, yes: bool) -> Self {
        let Self {
            source_manager,
            assembler,
            fixture_namespace,
            registry,
        } = self;
        Self {
            source_manager,
            assembler: assembler.with_warnings_as_errors(yes),
            fixture_namespace,
            registry,
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn with_warnings_as_errors(self, yes: bool) -> Self {
        let Self {
            source_manager,
            assembler,
            fixture_namespace,
        } = self;
        Self {
            source_manager,
            assembler: assembler.with_warnings_as_errors(yes),
            fixture_namespace,
        }
    }

    #[inline]
    fn assembler(&self) -> Assembler {
        self.assembler.clone()
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    /// Parse the given source file into a vector of top-level [Form]s.
    ///
    /// This does not run semantic analysis, or construct a [Module] from the parsed
    /// forms, and is largely intended for low-level testing of the parser.
    #[cfg(feature = "testing")]
    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> Result<Vec<Form>, Report> {
        parser::parse_forms(source)
    }

    /// Parse the given source file into an executable [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_program(&self, source: Arc<SourceFile>) -> Result<Box<Module>, Report> {
        source.parse(self.assembler.warnings_as_errors(), self.source_manager())
    }

    /// Parse the given source file into a kernel [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_kernel(&self, source: Arc<SourceFile>) -> Result<Box<Module>, Report> {
        let mut parser = Module::parser(Some(ModuleKind::Kernel));
        parser.set_warnings_as_errors(self.assembler.warnings_as_errors());
        parser.parse(Some(Path::KERNEL), source, self.source_manager())
    }

    /// Parse the given source file into an anonymous library [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_module(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse(self.assembler.warnings_as_errors(), self.source_manager())
    }

    /// Add `module` to the [Assembler] constructed by this context, making it available to
    /// other modules.
    #[track_caller]
    pub fn add_module(&mut self, module: impl Parse) -> Result<(), Report> {
        let module = self.parse_module(module)?;
        let mut fixture_namespace = self.fixture_namespace.clone();
        fixture_namespace.add_module(&module)?;
        self.assembler.compile_and_statically_link(module)?;
        self.fixture_namespace = fixture_namespace;
        Ok(())
    }

    /// Add the modules of `library` to the [Assembler] constructed by this context.
    #[track_caller]
    pub fn add_library(&mut self, package: Arc<miden_mast_package::Package>) -> Result<(), Report> {
        let naming = self.fixture_namespace.admit_package(&package)?;
        self.assembler.link_package(package, miden_project::Linkage::Dynamic, naming)
    }

    /// Adds a foreign fixture package using explicitly supplied binding metadata.
    ///
    /// Each procedure descriptor must be named in `bindings`. No home or defining path is inferred
    /// from package names, aliases, implementation digests, or code availability.
    #[track_caller]
    pub fn add_library_with_bindings(
        &mut self,
        package: Arc<Package>,
        bindings: &FixtureNamespace,
    ) -> Result<(), Report> {
        let mut fixture_namespace = self.fixture_namespace.clone();
        for export in package.manifest.exports().filter_map(|export| export.as_procedure()) {
            let binding = bindings.binding(&export.path).ok_or_else(|| {
                Report::msg(format!(
                    "missing explicit fixture binding for package export '{}'",
                    export.path
                ))
            })?;
            fixture_namespace.add_binding(export.path.clone(), binding.clone())?;
        }
        let naming = bindings.admit_package(&package)?;
        self.assembler.link_package(package, miden_project::Linkage::Dynamic, naming)?;
        self.fixture_namespace = fixture_namespace;
        Ok(())
    }

    /// Compile a [Program] from `source` using the [Assembler] constructed by this context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the executable
    /// module represented in `source`.
    #[track_caller]
    pub fn assemble(&self, source: impl Parse) -> Result<Program, Report> {
        let module = self.parse_module(source)?;
        if !module.is_executable() {
            return Err(Report::msg(
                "unable to assemble program: source is not an executable module",
            ));
        }
        let mut fixture_namespace = self.fixture_namespace.clone();
        fixture_namespace.add_module(&module)?;
        let assembler = fixture_namespace.configure(self.assembler(), [&*module])?;
        assembler
            .assemble_executable_modules("test".into(), module, [])?
            .into_program(self.assembler.emit_debug_info)
    }

    /// Compile a library package from `modules` using the [Assembler] constructed by this context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the library
    #[track_caller]
    pub fn assemble_library(
        &self,
        name: impl Into<PackageId>,
        version: Option<&str>,
        root: Box<Module>,
        support: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Box<miden_mast_package::Package>, Report> {
        self.assemble_library_with_fixture(name, version, root, support)
            .map(|(package, _)| package)
    }

    /// Assembles a source fixture and returns its explicit naming sidecar for importing tests.
    ///
    /// Re-export descriptors need an explicit [`FixtureNamespace::add_binding`] when their source
    /// path differs from the concrete defining declaration. This sidecar is test utility data, not
    /// a serialized interface artifact or evidence of Protocol-profile acceptance.
    #[track_caller]
    pub fn assemble_library_with_fixture(
        &self,
        name: impl Into<PackageId>,
        version: Option<&str>,
        root: Box<Module>,
        support: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<(Box<Package>, FixtureNamespace), Report> {
        let support = support.into_iter().collect::<Vec<_>>();
        let mut fixture_namespace = self.fixture_namespace.clone();
        for module in core::iter::once(&root).chain(&support) {
            fixture_namespace.add_module(module)?;
        }
        let assembler = fixture_namespace.configure(
            self.assembler(),
            core::iter::once(&*root).chain(support.iter().map(|module| &**module)),
        )?;
        let version = version.unwrap_or("0.0.0").parse().unwrap();
        let mut package = assembler.assemble_library(name, root, support)?;
        package.version = version;
        Ok((package, fixture_namespace))
    }
}

#[cfg(feature = "std")]
pub use self::package_features::{
    TestRegistry, configure_project_fixture, project_fixture_namespace_inputs,
};

#[cfg(feature = "std")]
mod package_features {
    use std::{
        collections::BTreeMap,
        string::String,
        sync::{Arc, Mutex},
    };

    use miden_mast_package::{Package, PackageId};
    use miden_package_registry::{
        PackageCache, PackageIndex, PackageProvider, PackageRecord, PackageRegistry, PackageStore,
        PackageVersions, Version, VersionRequirement,
    };

    use super::*;
    use crate::{
        NamespaceInputs, ProjectAssembler, ProjectSourceInputs, ProjectTargetSelector,
        TargetAssemblyContext,
    };

    /// Opts a project test into the explicit source-cohort and artifact naming conventions.
    ///
    /// Production project assemblers retain absent providers. Each target receives fresh inputs
    /// for its root and support modules, without inheriting the base assembler's module inventory.
    /// Raw artifacts admit only this fixture's chosen home, plus N0 for kernel artifacts.
    pub fn configure_project_fixture<'a, S: PackageCache>(assembler: &mut ProjectAssembler<'a, S>) {
        assembler
            .with_namespace_inputs_provider(project_fixture_namespace_inputs)
            .with_package_naming_provider(|package| {
                let mut homes = vec![FixtureNamespace::assembly_tests().namespace_plan().clone()];
                if package.is_kernel() {
                    homes.push(NamespacePlan::new(vec![]));
                }
                admit_fixture_package(package, &homes)
            });
    }

    /// Produces the explicit test convention for a source cohort and its resolved imports.
    pub fn project_fixture_namespace_inputs(
        context: &TargetAssemblyContext<'_>,
        sources: &ProjectSourceInputs,
        base: &Assembler,
    ) -> Result<NamespaceInputs, Report> {
        let modules = core::iter::once(sources.root.as_ref())
            .chain(sources.support.iter().map(Box::as_ref))
            .collect::<Vec<_>>();
        let mut fixture = FixtureNamespace::assembly_tests();
        if context.target.is_kernel() {
            fixture.add_kernel_modules(base, &modules)?;
        } else {
            for module in modules {
                fixture.add_module(module)?;
            }
        }
        let mut inputs =
            NamespaceInputs::new().with_namespace_plan(fixture.namespace_plan().clone());
        for (declaration, binding) in fixture.bindings {
            inputs = inputs.with_callable_binding(declaration, binding)?;
        }
        Ok(inputs)
    }

    /// A simple in-memory package index/registry
    #[derive(Default)]
    pub struct TestRegistry {
        index: BTreeMap<PackageId, PackageVersions>,
        packages: BTreeMap<(PackageId, Version), Arc<Package>>,
        loads: Mutex<Vec<String>>,
        caches: Mutex<Vec<String>>,
    }

    impl TestRegistry {
        pub fn add_package(&mut self, package: Arc<Package>) -> Version {
            let version = Version::new(package.version.clone(), package.dependency_commitment());
            self.publish_package(package).expect("failed to add test package");
            version
        }

        pub fn loaded_packages(&self) -> Vec<String> {
            self.loads.lock().unwrap().clone()
        }

        pub fn cached_packages(&self) -> Vec<String> {
            self.caches.lock().unwrap().clone()
        }

        pub fn clear_loaded_packages(&self) {
            self.loads.lock().unwrap().clear();
        }

        pub fn remove_package(
            &mut self,
            package: &PackageId,
            version: &Version,
        ) -> Option<Arc<Package>> {
            self.packages.remove(&(package.clone(), version.clone()))
        }

        pub fn replace_semver_package(&mut self, package: Arc<Package>) -> Version {
            let version = Version::new(package.version.clone(), package.dependency_commitment());
            self.packages.retain(|(name, existing), _| {
                name != &package.name || existing.version != package.version
            });

            let dependencies = package.manifest.dependencies().map(|dependency| {
                let version = Version::new(dependency.version.clone(), dependency.digest);
                (dependency.name.clone(), VersionRequirement::Exact(version))
            });
            let record = PackageRecord::new(version.clone(), dependencies)
                .with_description(package.description.clone().unwrap_or_default());
            self.index
                .entry(package.name.clone())
                .or_default()
                .insert(package.version.clone(), record);
            self.packages.insert((package.name.clone(), version.clone()), package);
            version
        }
    }

    impl PackageRegistry for TestRegistry {
        fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
            self.index.get(package)
        }
    }

    impl PackageIndex for TestRegistry {
        type Error = Report;

        fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
            use std::collections::btree_map::Entry;

            let semver = record.semantic_version().clone();
            match self.index.entry(name.clone()).or_default().entry(semver.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(record);
                    Ok(())
                },
                Entry::Occupied(_) => Err(Report::msg(format!(
                    "package '{name}' version '{semver}' is already registered"
                ))),
            }
        }
    }

    impl PackageProvider for TestRegistry {
        fn load_package(
            &self,
            package: &PackageId,
            version: &Version,
        ) -> Result<Arc<Package>, Report> {
            self.loads.lock().unwrap().push(format!("{package}@{version}"));
            self.packages.get(&(package.clone(), version.clone())).cloned().ok_or_else(|| {
                Report::msg(format!("missing test package '{package}' at '{version}'"))
            })
        }
    }

    impl PackageCache for TestRegistry {
        type Error = Report;

        fn cache_package(&mut self, package: Arc<Package>) -> Result<Version, Self::Error> {
            let version = Version::new(package.version.clone(), package.dependency_commitment());
            self.caches.lock().unwrap().push(format!("{}@{version}", package.name));
            if let Some(record) = self.get_by_semver(&package.name, &package.version) {
                if record.version() == &version {
                    self.packages.insert((package.name.clone(), version.clone()), package);
                    return Ok(version);
                }
                return Err(Report::msg(format!(
                    "package '{}' version '{}' is already registered",
                    package.name, package.version
                )));
            }
            let dependencies = package.manifest.dependencies().map(|dependency| {
                let version = Version::new(dependency.version.clone(), dependency.digest);
                (dependency.name.clone(), VersionRequirement::Exact(version))
            });
            let record = PackageRecord::new(version.clone(), dependencies)
                .with_description(package.description.clone().unwrap_or_default());
            self.register(package.name.clone(), record)?;
            self.packages.insert((package.name.clone(), version.clone()), package);
            Ok(version)
        }
    }

    impl PackageStore for TestRegistry {
        fn publish_package(&mut self, package: Arc<Package>) -> Result<Version, Self::Error> {
            let version = Version::new(package.version.clone(), package.dependency_commitment());
            let dependencies = package
                .manifest
                .dependencies()
                .map(|dependency| {
                    let version = Version::new(dependency.version.clone(), dependency.digest);
                    if self.get_exact_version(&dependency.name, &version).is_none() {
                        return Err(Report::msg(format!(
                            "missing dependency '{}' at '{}'",
                            dependency.name, version
                        )));
                    }
                    Ok((dependency.name.clone(), VersionRequirement::Exact(version)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let record = PackageRecord::new(version.clone(), dependencies)
                .with_description(package.description.clone().unwrap_or_default());
            self.register(package.name.clone(), record)?;
            self.packages.insert((package.name.clone(), version.clone()), package);
            Ok(version)
        }
    }

    impl TestContext {
        pub fn registry(&self) -> &TestRegistry {
            &self.registry
        }

        pub fn registry_mut(&mut self) -> &mut TestRegistry {
            &mut self.registry
        }

        pub fn project_assembler_for_path<'a>(
            &'a mut self,
            manifest_path: impl AsRef<std::path::Path>,
        ) -> Result<crate::ProjectAssembler<'a, TestRegistry>, Report> {
            let mut assembler =
                self.assembler().for_project_at_path(manifest_path, &mut self.registry)?;
            configure_project_fixture(&mut assembler);
            Ok(assembler)
        }

        pub fn project_assembler<'a>(
            &'a mut self,
            project: Arc<miden_project::Package>,
        ) -> Result<crate::ProjectAssembler<'a, TestRegistry>, Report> {
            let mut assembler = self.assembler().for_project(project, &mut self.registry)?;
            configure_project_fixture(&mut assembler);
            Ok(assembler)
        }

        /// Assembles the library target of the package at `manifest_path`, using `profile`.
        ///
        /// If `profile` is `None`, the `dev` profile will be used.
        ///
        /// This requires that the referenced package define a library target, or an error will be
        /// raised.
        pub fn assemble_library_package(
            &mut self,
            manifest_path: impl AsRef<std::path::Path>,
            profile: Option<&str>,
        ) -> Result<Arc<Package>, Report> {
            let mut project_assembler = self.project_assembler_for_path(manifest_path)?;
            project_assembler.assemble(ProjectTargetSelector::Library, profile.unwrap_or("dev"))
        }

        /// Assembles the executable target `name` of the package from `manifest_path`, using
        /// `profile`.
        ///
        /// If `name` is `None`, the default executable target name is selected.
        ///
        /// If `profile` is `None`, the `dev` profile will be used.
        ///
        /// This requires that the referenced package define the given executable target, or an
        /// error will be raised.
        pub fn assemble_executable_package(
            &mut self,
            manifest_path: impl AsRef<std::path::Path>,
            name: Option<&str>,
            profile: Option<&str>,
        ) -> Result<Arc<Package>, Report> {
            let mut project_assembler = self.project_assembler_for_path(manifest_path)?;
            project_assembler.assemble(
                ProjectTargetSelector::Executable(name.unwrap_or(Path::EXEC_PATH)),
                profile.unwrap_or("dev"),
            )
        }

        /// Assembles a package named `name` with `version` and `dependencies`, containing a single
        /// export whose path is `export`.
        ///
        /// The exported procedure is defined as follows, given an `export` path of `foo::bar`:
        ///
        /// ```text,ignore
        /// pub proc bar
        ///     add
        /// end
        /// ```
        pub fn assemble_library_package_with_export<'a>(
            &self,
            name: &str,
            version: &str,
            export: &str,
            dependencies: impl IntoIterator<Item = (&'static str, &'a str, TargetType, Word)>,
        ) -> Box<Package> {
            use alloc::string::ToString;

            use miden_assembly_syntax::source_file;
            use miden_mast_package::Dependency;

            let export_path = Path::new(export);
            let (export_leaf, export_module) = export_path.split_last().unwrap();
            let source_file = source_file!(
                self,
                format!("namespace {export_module}\n\npub proc {export_leaf} add end")
            );
            let module = self.parse_module(source_file).unwrap();
            let name = PackageId::from(name);
            let mut package = self
                .assemble_library(name, Some(version), module, None::<Box<Module>>)
                .expect("failed to assemble library");
            for (name, version, kind, digest) in dependencies {
                package
                    .manifest
                    .add_dependency(Dependency {
                        name: name.into(),
                        kind,
                        version: version.parse().unwrap(),
                        digest,
                    })
                    .expect("failed to add dependency");
            }
            package
        }
    }
}
