use miden_assembly_syntax::PathComponent;
use miden_core::mast::MastForest;
use miden_mast_package::{Dependency, PackageCallables, debug_info::PackageDebugInfo};

use super::*;

/// Assembled code with raw compiler-selected callable, source, home and entry metadata.
///
/// This is not an admitted package9 or execution environment. [`Self::into_artifact`] extracts the
/// existing Package8 representation, which does not retain this raw metadata.
pub struct AssemblyProduct {
    package: Box<Package>,
    kernel_package: Option<Arc<Package>>,
    debug_info: Box<PackageDebugInfo>,
    callables: PackageCallables,
    callable_sources: CallableSources,
    namespace_plan: NamespacePlan,
    entry_key: Option<ProcedureKey>,
}

/// Direct compiler selections, indexed by defining linker path rather than implementation digest.
/// The source IDs refer to this product's existing debug information, without duplicating it.
pub(super) type CallableSources =
    BTreeMap<Arc<Path>, (ProcedureKey, Option<(MastNodeId, DebugSourceNodeId)>)>;

/// Transient compiler references which must be resolved before the forest builder is consumed.
pub(super) struct PendingCallables {
    definitions: Vec<(Arc<Path>, CallableBinding, Option<MastNodeUse>, bool)>,
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
        Ok(PendingCallables { definitions, visible_paths })
    }
}

impl PendingCallables {
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
        callables: PackageCallables,
        callable_sources: CallableSources,
        namespace_plan: NamespacePlan,
        entry_key: Option<ProcedureKey>,
    ) -> Self {
        assert!(
            kernel.is_none() || !package.is_kernel(),
            "kernels cannot depend on another kernel"
        );
        Self {
            package,
            kernel_package: kernel,
            debug_info,
            callables,
            callable_sources,
            namespace_plan,
            entry_key,
        }
    }

    /// Returns the compiler's raw binding, visible-alias and selected-code relations.
    ///
    /// These inputs have not received package9, home/profile or environment admission.
    pub fn callables(&self) -> &PackageCallables {
        &self.callables
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
        self.entry_key
    }

    /// Returns the explicit caller home supplied to this compilation, without admitting it.
    pub fn namespace_plan(&self) -> &NamespacePlan {
        &self.namespace_plan
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

    /// Extracts the existing Package8 artifact.
    ///
    /// Package8 does not encode this product's raw callable/home/entry metadata. The coordinated
    /// package9 finalizer and admission boundary must carry it before namespaced publication.
    pub fn into_artifact(self, emit_debug_info: bool) -> Result<Box<Package>, Report> {
        let Self {
            mut package, kernel_package, debug_info, ..
        } = self;
        // Section: embedded kernel package
        if package.is_program()
            && let Some(kernel_package) = kernel_package
        {
            package.sections.push(linked_kernel_package_section(kernel_package.as_ref()));
            if let Some(kernel_dep) =
                package.manifest.dependencies().find(|dep| dep.id() == &kernel_package.name)
            {
                if kernel_dep.digest != kernel_package.dependency_commitment()
                    || kernel_dep.kind != kernel_package.kind
                    || kernel_dep.version() != &kernel_package.version
                {
                    return Err(Report::msg(format!(
                        "unable to register kernel dependency: '{}' already exists as a dependency, but with different metadata than the actual kernel package",
                        kernel_package.name
                    )));
                }
            } else {
                package
                    .manifest
                    .add_dependency(Dependency {
                        name: kernel_package.name.clone(),
                        kind: kernel_package.kind,
                        version: kernel_package.version.clone(),
                        digest: kernel_package.dependency_commitment(),
                    })
                    .map_err(|err| {
                        Report::msg(format!("unable to register kernel dependency: {err}"))
                    })?;
            }
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
    use miden_mast_package::debug_info::{MAX_DEBUG_INFO_STRING_SIZE, PackageDebugInfoBuilder};

    use super::*;
    use crate::testing::{FixtureNamespace, TestContext};

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
