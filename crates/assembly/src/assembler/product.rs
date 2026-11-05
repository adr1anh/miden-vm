use miden_assembly_syntax::PathComponent;
use miden_core::mast::MastForest;
use miden_mast_package::{
    Dependency, PackageCallables, PackageNaming, debug_info::PackageDebugInfo,
};

use super::*;

/// Assembled code with compiler-selected callable, source, home and entry metadata.
///
/// The package retains required naming as structurally checked transport. The compiler's canonical
/// naming inventory does not grant selected-profile admission or execution-environment authority.
pub struct AssemblyProduct {
    package: Box<Package>,
    kernel_package: Option<Arc<Package>>,
    debug_info: Box<PackageDebugInfo>,
    naming: PackageNaming,
    callable_sources: CallableSources,
}

/// Direct compiler selections, indexed by defining linker path rather than implementation digest.
/// The source IDs refer to this product's existing debug information, without duplicating it.
pub(super) type CallableSources =
    BTreeMap<Arc<Path>, (ProcedureKey, Option<(MastNodeId, DebugSourceNodeId)>)>;

/// Transient compiler references which must be resolved before the forest builder is consumed.
pub(super) struct PendingCallables {
    definitions: Vec<(Arc<Path>, CallableBinding, Option<MastNodeUse>, bool)>,
    imported: Vec<(CallableBinding, Option<ImplementationRoot>)>,
    visible_paths: Vec<(CallableProcedurePath, ProcedureKey)>,
}

impl Assembler {
    pub(super) fn pending_callables(
        &self,
        builder: &MastForestBuilder,
        visible_paths: impl IntoIterator<Item = (Arc<Path>, ProcedureKey)>,
    ) -> Result<PendingCallables, Report> {
        let retained = self
            .linker
            .runtime_reachable_from(self.local_callable_roots())
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut definitions = Vec::new();
        for (module_index, module) in self.linker.modules().iter().enumerate() {
            for (item_index, symbol) in module.symbols().enumerate() {
                let gid = ModuleIndex::new(module_index) + ItemIndex::new(item_index);
                let procedure = builder.get_procedure(gid);
                if !symbol.is_procedure() || (!retained.contains(&gid) && procedure.is_none()) {
                    continue;
                }
                definitions.push((
                    module.path().join(symbol.name()).into(),
                    self.callable_binding(gid)?.clone(),
                    procedure.map(Procedure::body_node_use),
                    matches!(symbol.item(), SymbolItem::Procedure(_)),
                ));
            }
        }

        // Module descriptors expose only source-visible exports. Required package naming also
        // retains private callbacks and helpers whose code can survive a static import without a
        // descriptor or a defining source path in this compilation.
        let mut imported = Vec::new();
        let mut retain_imported =
            |naming: &PackageNaming| {
                let callables = naming.callables();
                imported.extend(callables.bindings().map(|(&key, binding)| {
                    (binding.clone(), callables.selected_implementation(key))
                }));
            };
        for library in self.linker.libraries() {
            retain_imported(library.naming());
        }
        if let Some(naming) = self.linker.kernel_naming() {
            retain_imported(&naming);
        }

        let visible_paths = visible_paths
            .into_iter()
            .map(|(path, key)| {
                let components = path
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
                Ok((path, key))
            })
            .collect::<Result<Vec<_>, Report>>()?;
        Ok(PendingCallables { definitions, imported, visible_paths })
    }
}

impl PendingCallables {
    /// Checks the kernel construction convention against resolved exports and canonical homes.
    /// Foreign descriptors may name other fragments' public root exports; only concrete source
    /// definitions retained in this product are subject to the nonexported helper restriction.
    pub(super) fn validate_kernel_placement(&self) -> Result<(), Report> {
        let exported = self.visible_paths.iter().map(|(_, key)| *key).collect::<BTreeSet<_>>();
        for (path, binding, _, is_source_definition) in &self.definitions {
            let at_root = binding.parent_namespace() == Namespace::initial();
            if exported.contains(&binding.key()) {
                if !at_root {
                    return Err(Report::msg(format!(
                        "kernel export '{path}' must be in the fixed root syscall namespace"
                    )));
                }
            } else if *is_source_definition && at_root {
                return Err(Report::msg(format!(
                    "retained kernel helper '{path}' must be beneath a child Env namespace"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        mast: &MastForest,
        node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
        source_id_by_ref: &BTreeMap<SourceNodeRef, DebugSourceNodeId>,
    ) -> Result<(PackageCallables, CallableSources), Report> {
        let mut bindings = BTreeMap::new();
        let mut implementations = BTreeMap::new();
        let mut source_definitions = BTreeSet::new();
        let mut sources = BTreeMap::new();
        for (path, binding, body, is_source_definition) in self.definitions {
            let key = binding.key();
            // Imported descriptors and declaration aliases may refer to one canonical callable.
            // Distinct concrete source definitions, including prelinked ASTs, cannot share a key.
            if is_source_definition && !source_definitions.insert(key) {
                return Err(Report::msg(
                    miden_mast_package::PackageCallablesError::DuplicateBinding { key }.to_string(),
                ));
            }
            if let Some(previous) = bindings.insert(key, binding.clone())
                && previous != binding
            {
                return Err(Report::msg(format!("conflicting callable bindings for key {key:?}")));
            }
            let source = if let Some(body) = body {
                let node = node_id_by_ref.get(&body.node_ref()).copied().ok_or_else(|| {
                    Report::msg(format!("callable definition '{path}' was not finalized"))
                })?;
                let source =
                    source_id_by_ref.get(&body.source_ref()).copied().ok_or_else(|| {
                        Report::msg(format!("callable source for '{path}' was not finalized"))
                    })?;
                if !mast.is_procedure_root(node) {
                    return Err(Report::msg(format!(
                        "callable definition '{path}' is not a retained procedure root"
                    )));
                }
                let implementation = ImplementationRoot::new(mast[node].digest());
                if let Some(previous) = implementations.insert(key, implementation)
                    && previous != implementation
                {
                    return Err(Report::msg(format!(
                        "conflicting selected implementations for callable key {key:?}"
                    )));
                }
                Some((node, source))
            } else {
                None
            };
            sources.insert(path, (key, source));
        }
        for (binding, implementation) in self.imported {
            let key = binding.key();
            if let Some(previous) = bindings.insert(key, binding.clone())
                && previous != binding
            {
                return Err(Report::msg(format!("conflicting callable bindings for key {key:?}")));
            }
            // Naming and code supply are independent. Dynamic declarations remain in the
            // inventory even when their selected body was not retained in the final forest.
            if let Some(implementation) = implementation
                && mast.find_procedure_root(implementation.into_word()).is_some()
                && let Some(previous) = implementations.insert(key, implementation)
                && previous != implementation
            {
                return Err(Report::msg(format!(
                    "conflicting selected implementations for callable key {key:?}"
                )));
            }
        }
        let callables =
            PackageCallables::new(bindings.into_values(), self.visible_paths, implementations)
                .into_diagnostic()?;
        Ok((callables, sources))
    }
}

impl AssemblyProduct {
    pub(super) fn new(
        package: Box<Package>,
        kernel: Option<Arc<Package>>,
        debug_info: Box<PackageDebugInfo>,
        naming: PackageNaming,
        callable_sources: CallableSources,
    ) -> Self {
        assert!(
            kernel.is_none() || !package.is_kernel(),
            "kernels cannot depend on another kernel"
        );
        Self {
            package,
            kernel_package: kernel,
            debug_info,
            naming,
            callable_sources,
        }
    }

    /// Returns the compiler's complete canonical naming inventory without profile admission.
    pub fn naming(&self) -> &PackageNaming {
        &self.naming
    }

    /// Returns the compiler's raw binding, visible-alias and selected-code relations.
    ///
    /// Structural package validation does not grant home/profile or environment admission.
    pub fn callables(&self) -> &PackageCallables {
        self.naming.callables()
    }

    /// Returns the key attached to the exact defining linker path, including private definitions.
    pub fn callable_key_for_definition(&self, path: &Path) -> Option<ProcedureKey> {
        self.callable_sources.get(path).map(|(key, _)| *key)
    }

    /// Returns the selected node and exact source occurrence for a defining linker path.
    ///
    /// Declaration-only dependencies have a key but no selected node or source occurrence.
    pub fn callable_source_for_definition(
        &self,
        path: &Path,
    ) -> Option<(MastNodeId, DebugSourceNodeId)> {
        self.callable_sources.get(path).and_then(|(_, source)| *source)
    }

    /// Returns the executable entry key retained before final node-ID assignment, if applicable.
    pub fn entry_key(&self) -> Option<ProcedureKey> {
        self.naming.entry_key()
    }

    /// Returns the explicit caller home supplied to this compilation, without admitting it.
    pub fn namespace_plan(&self) -> &NamespacePlan {
        self.naming.namespace_plan()
    }

    /// Extracts executable code using this compilation's exact retained entry metadata.
    ///
    /// No raw naming decoder or default home policy is involved. This supplies code/source hints,
    /// while the execution environment and authenticated entry opening remain caller inputs.
    pub fn into_program(
        self,
        emit_debug_info: bool,
    ) -> Result<miden_core::program::Program, Report> {
        let naming = self.naming.clone();
        self.into_artifact(emit_debug_info)?.try_into_program(&naming)
    }

    pub fn extend_dependencies(
        &mut self,
        deps: impl IntoIterator<Item = Dependency>,
    ) -> Result<(), Report> {
        for dep in deps {
            self.package.manifest.add_dependency(dep).map_err(Report::msg)?;
        }

        Ok(())
    }

    /// Extracts the Package9 artifact, retaining required callable, home and entry metadata.
    ///
    /// Required naming persists independently of optional debug information. Decoding its raw
    /// transport still requires explicit selected-profile policy, context and resource limits.
    pub fn into_artifact(self, emit_debug_info: bool) -> Result<Box<Package>, Report> {
        let Self {
            mut package, kernel_package, debug_info, ..
        } = self;
        // Section: embedded kernel package
        if package.is_program()
            && let Some(kernel_package) = kernel_package
        {
            let exact_kernel = kernel_package.to_dependency();
            if let Some(kernel_dep) = package.kernel_runtime_dependency()? {
                if kernel_dep != &exact_kernel {
                    return Err(Report::msg(format!(
                        "unable to register kernel dependency: '{}' already exists as a dependency, but with different metadata than the actual kernel package",
                        kernel_package.name
                    )));
                }
            } else {
                package.manifest.add_dependency(exact_kernel).map_err(|err| {
                    Report::msg(format!("unable to register kernel dependency: {err}"))
                })?;
            }
            package.sections.push(linked_kernel_package_section(kernel_package.as_ref()));
        }

        // Section: debug info
        if emit_debug_info {
            let bytes = debug_info
                .to_bytes_with_standard_limits()
                .map_err(|error| {
                    Report::msg(format!(
                        "assembled package debug info exceeds standard decoder limits: {error}; reduce imported debug metadata or disable debug-info emission"
                    ))
                })?;
            package.sections.push(Section::new(SectionId::DEBUG_INFO, bytes));
        }

        Ok(package)
    }
}

fn linked_kernel_package_section(package: &Package) -> Section {
    Section::new(SectionId::KERNEL, package.to_bytes())
}

#[cfg(test)]
mod tests {
    use miden_core::{program::CanonicalLabel, serde::Deserializable};
    use miden_mast_package::{
        debug_info::{MAX_DEBUG_INFO_STRING_SIZE, PackageDebugInfoBuilder},
        interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile},
    };

    use super::*;
    use crate::testing::{FixtureNamespace, TestContext, source_file};

    fn kernel_fixture(context: &TestContext) -> Arc<Package> {
        let module =
            context.parse_kernel(source_file!(context, "pub proc boot push.1 end")).unwrap();
        let base = Assembler::new(context.source_manager());
        let mut names = FixtureNamespace::assembly_tests();
        names.add_kernel_modules(&base, &[&module]).unwrap();
        names
            .configure(base, [&*module])
            .unwrap()
            .assemble_library_modules("kernel".into(), module, [], TargetType::Kernel)
            .unwrap()
            .into_artifact(false)
            .unwrap()
            .into()
    }

    fn executable_product(context: &TestContext) -> AssemblyProduct {
        let module = context.parse_module("begin push.42 end").unwrap();
        let mut names = FixtureNamespace::assembly_tests();
        names.add_module(&module).unwrap();
        names
            .configure(Assembler::new(context.source_manager()), [&*module])
            .unwrap()
            .assemble_executable_modules("app".into(), module, [])
            .unwrap()
    }

    #[test]
    fn kernel_attachment_preserves_same_name_ordinary_supply() {
        let context = TestContext::default();
        let kernel = kernel_fixture(&context);
        let exact_kernel = kernel.to_dependency();
        let mut ordinary_supply = exact_kernel.clone();
        ordinary_supply.kind = TargetType::Library;
        ordinary_supply.digest = miden_core::Word::from([1_u32, 2, 3, 4]);

        for requirements in [
            vec![ordinary_supply.clone()],
            vec![ordinary_supply.clone(), exact_kernel.clone()],
        ] {
            let mut product = executable_product(&context);
            product.kernel_package = Some(kernel.clone());
            product.extend_dependencies(requirements).unwrap();
            let artifact = product.into_artifact(false).unwrap();
            let dependencies = artifact.manifest.dependencies().cloned().collect::<Vec<_>>();

            assert_eq!(dependencies, vec![ordinary_supply.clone(), exact_kernel.clone()]);
            assert_eq!(artifact.kernel_runtime_dependency().unwrap(), Some(&exact_kernel));
            let embedded = artifact.try_embedded_kernel_package().unwrap().unwrap();
            assert_eq!(embedded.dependency_commitment(), kernel.dependency_commitment());
        }
    }

    #[test]
    fn kernel_attachment_rejects_conflicting_or_multiple_kernel_supplies() {
        let context = TestContext::default();
        let kernel = kernel_fixture(&context);
        let exact_kernel = kernel.to_dependency();
        let mut conflicting_kernel = exact_kernel.clone();
        conflicting_kernel.version = miden_mast_package::Version::new(2, 0, 0);

        for requirements in [
            vec![conflicting_kernel.clone()],
            vec![exact_kernel.clone(), conflicting_kernel.clone()],
        ] {
            let mut product = executable_product(&context);
            product.kernel_package = Some(kernel.clone());
            product.extend_dependencies(requirements).unwrap();
            assert!(product.into_artifact(false).is_err());
        }
    }

    struct ExactFixtureHome;

    impl TypedIdProfile for ExactFixtureHome {
        type Context = NamespacePlan;
        type Error = &'static str;

        fn validate_typed_id(
            &self,
            _context: &Self::Context,
            _codec: u32,
            _canonical_bytes: &[u8],
        ) -> Result<(), Self::Error> {
            Err("fixture permits no TypedId codec")
        }
    }

    impl HomeProfile for ExactFixtureHome {
        fn validate_home(
            &self,
            context: &Self::Context,
            home: &[CanonicalLabel],
        ) -> Result<(), Self::Error> {
            if context.home() == home {
                Ok(())
            } else {
                Err("home differs from explicit fixture evidence")
            }
        }
    }

    #[test]
    fn imports_retain_private_bindings_without_inventing_defining_source_paths() {
        let context = TestContext::default();
        let dependency = context
            .parse_module(
                "namespace dep\npub proc run exec.callback end\nproc callback push.7 end\nproc twin push.7 end",
            )
            .unwrap();
        let caller = context.parse_module("use dep\nbegin exec.dep::run end").unwrap();
        let mut names = FixtureNamespace::assembly_tests();
        names.add_module(&dependency).unwrap();
        names.add_module(&caller).unwrap();
        let dependency = names
            .configure(Assembler::new(context.source_manager()), [&*dependency])
            .unwrap()
            .assemble_library_modules("dep".into(), dependency, [], TargetType::Library)
            .unwrap();
        let naming = dependency.naming().clone();
        let callback_path = Path::new("::dep::callback");
        let callback_key = dependency.callable_key_for_definition(callback_path).unwrap();
        let callback_root = naming.callables().selected_implementation(callback_key).unwrap();
        let twin_path = Path::new("::dep::twin");
        let twin_key = dependency.callable_key_for_definition(twin_path).unwrap();
        assert_ne!(callback_key, twin_key);
        assert_eq!(naming.callables().selected_implementation(twin_key), Some(callback_root));
        let dependency: Arc<Package> = dependency.into_artifact(false).unwrap().into();

        for linkage in [Linkage::Static, Linkage::Dynamic] {
            let assembler = Assembler::new(context.source_manager())
                .with_package(dependency.clone(), linkage, naming.clone())
                .unwrap();
            let product = names
                .configure(assembler, [&*caller])
                .unwrap()
                .assemble_executable_modules("caller".into(), caller.clone(), [])
                .unwrap();
            assert_eq!(
                product.callables().binding(callback_key),
                naming.callables().binding(callback_key),
            );
            assert_eq!(product.callable_key_for_definition(callback_path), None);
            assert_eq!(product.callable_source_for_definition(callback_path), None);
            assert_eq!(product.callables().binding(twin_key), naming.callables().binding(twin_key),);
            assert_eq!(product.callable_key_for_definition(twin_path), None);
            assert_eq!(
                product.callables().selected_implementation(callback_key),
                (linkage == Linkage::Static).then_some(callback_root),
            );
            assert_eq!(
                product.callables().selected_implementation(twin_key),
                (linkage == Linkage::Static).then_some(callback_root),
            );
            let package = product.into_artifact(false).unwrap();
            assert_eq!(
                package.mast_forest().find_procedure_root(callback_root.into_word()).is_some(),
                linkage == Linkage::Static,
            );
        }
    }

    #[test]
    fn required_naming_survives_artifact_extraction_and_both_readers() {
        let limits = CodecLimits::new(1 << 20, 1 << 20, 1024, 1024);
        for emit_debug_info in [false, true] {
            for executable in [false, true] {
                let context = TestContext::default();
                let root = context
                    .parse_module(if executable {
                        "proc callback push.7 end\nbegin procref.callback end"
                    } else {
                        "namespace api\npub use {run as original, run as alias} from implementation"
                    })
                    .unwrap();
                let support = if executable {
                    vec![]
                } else {
                    vec![context
                        .parse_module(
                            "namespace implementation\nproc callback push.7 end\npub proc run procref.callback end",
                        )
                        .unwrap()]
                };
                let mut names = FixtureNamespace::assembly_tests();
                names.add_module(&root).unwrap();
                for module in &support {
                    names.add_module(module).unwrap();
                }
                let assembler = names
                    .configure(
                        Assembler::new(context.source_manager()),
                        core::iter::once(&*root).chain(support.iter().map(|module| &**module)),
                    )
                    .unwrap();
                let product = if executable {
                    assembler.assemble_executable_modules("test".into(), root, support)
                } else {
                    assembler.assemble_library_modules(
                        "test".into(),
                        root,
                        support,
                        TargetType::Library,
                    )
                }
                .unwrap();
                let expected = product.naming().clone();
                assert_eq!(expected.callables().bindings().len(), 2);
                assert_eq!(expected.callables().selected_implementations().len(), 2);
                assert_eq!(expected.entry_key().is_some(), executable);
                assert_eq!(
                    expected.callables().visible_paths().len(),
                    if executable { 1 } else { 2 },
                );

                let package = product.into_artifact(emit_debug_info).unwrap();
                assert_eq!(
                    package
                        .admit_naming(&ExactFixtureHome, names.namespace_plan(), limits)
                        .unwrap(),
                    expected,
                );
                assert!(
                    package
                        .admit_naming(&ExactFixtureHome, &NamespacePlan::new(vec![]), limits)
                        .is_err(),
                );
                assert_eq!(package.debug_info().unwrap().is_some(), emit_debug_info);
                let bytes = package.to_bytes();
                for decoded in [
                    Package::read_from_bytes(&bytes).unwrap(),
                    Package::read_from_bytes_trusted(&bytes).unwrap(),
                ] {
                    assert_eq!(decoded.naming_transport(), package.naming_transport());
                    assert_eq!(
                        decoded
                            .admit_naming(&ExactFixtureHome, names.namespace_plan(), limits)
                            .unwrap(),
                        expected,
                    );
                }
            }
        }
    }

    #[test]
    fn artifact_rejects_debug_info_beyond_standard_decoder_limits() {
        for emit_debug_info in [true, false] {
            let context = TestContext::default();
            let module = context.parse_module("begin push.42 end").unwrap();
            let mut fixture_namespace = FixtureNamespace::assembly_tests();
            fixture_namespace.add_module(&module).unwrap();
            let mut product = fixture_namespace
                .configure(Assembler::new(context.source_manager()), [&*module])
                .unwrap()
                .assemble_executable_modules("test".into(), module, [])
                .unwrap();
            let mut debug = PackageDebugInfoBuilder::from(product.debug_info);
            debug.add_string("x".repeat(MAX_DEBUG_INFO_STRING_SIZE + 1));
            product.debug_info = debug.build();
            let result = product.into_artifact(emit_debug_info);
            if emit_debug_info {
                let error = result.expect_err("unreadable debug info must fail assembly");
                let message = error.to_string();
                assert!(message.contains("standard decoder limits"), "{message}");
                assert!(message.contains("debug string size"), "{message}");
                assert!(message.contains("disable debug-info emission"), "{message}");
            } else {
                assert!(result.unwrap().debug_info().unwrap().is_none());
            }
        }
    }
}
