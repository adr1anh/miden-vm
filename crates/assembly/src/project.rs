use alloc::{boxed::Box, collections::BTreeMap, format, string::ToString, sync::Arc, vec::Vec};
use core::ops::ControlFlow;
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
};

use miden_assembly_syntax::{ast::ModuleKind, diagnostics::Report};
use miden_core::serde::Deserializable;
use miden_mast_package::{
    NamespacePlan, Package as MastPackage, PackageNaming, SectionId, TargetType,
};
use miden_package_registry::{PackageCache, PackageId, Version as PackageVersion};
use miden_project::{
    ExpectedVisibleCallables, Linkage, Package as ProjectPackage, PreassembledDependencyMetadata,
    Profile, ProjectDependencyNodeProvenance, ProjectSource, SourceNamingConvention, Target,
};

use crate::{Assembler, NamespaceInputs, ast::Module};

mod build_provenance;
mod dependency_graph;
mod post_process;
mod providers;
mod runtime_dependencies;
mod target_selector;

use self::{
    build_provenance::PackageBuildProvenance, dependency_graph::DependencyGraph,
    runtime_dependencies::RuntimeDependencies,
};
pub use self::{
    post_process::{PackagePostProcessor, PostProcessContext},
    providers::{MasmSourceProvider, ProjectSourceProvider, TargetAssemblyContext},
    target_selector::ProjectTargetSelector,
};

#[cfg(test)]
mod artifact_expectation_tests;
#[cfg(test)]
mod catalog_resolution_tests;
#[cfg(test)]
mod target_naming_tests;
#[cfg(test)]
mod tests;

// ASSEMBLER EXTENSIONS
// ================================================================================================

impl Assembler {
    /// Get a [ProjectAssembler] configured for the project whose manifest is at `manifest_path`.
    pub fn for_project_at_path<'a, S>(
        self,
        manifest_path: impl AsRef<FsPath>,
        store: &'a mut S,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache,
    {
        let masm_provider = Box::new(MasmSourceProvider) as Box<_>;
        self.for_project_at_path_with_providers(manifest_path, store, [masm_provider])
    }

    /// Get a [ProjectAssembler] configured for the project whose manifest is at `manifest_path`.
    pub fn for_project_at_path_with_providers<'a, S>(
        self,
        manifest_path: impl AsRef<FsPath>,
        store: &'a mut S,
        providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache,
    {
        let manifest_path = manifest_path.as_ref();
        let source_manager = self.source_manager();
        let project = miden_project::Project::load(manifest_path, &source_manager)?;
        let package = project.package();
        let dependency_graph =
            DependencyGraph::from_project_path(manifest_path, store, source_manager)?;

        Ok(ProjectAssembler {
            assembler: self,
            project: package,
            source_provider: SourceProviderRegistry::new(providers),
            dependency_graph,
            post_processors: Vec::new(),
            package_naming_provider: None,
            namespace_inputs_provider: None,
            store,
        })
    }

    /// Get a [ProjectAssembler] configured for `project`
    pub fn for_project<'a, S>(
        self,
        project: Arc<ProjectPackage>,
        store: &'a mut S,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache,
    {
        let masm_provider = Box::new(MasmSourceProvider) as Box<_>;
        self.for_project_with_providers(project, store, [masm_provider])
    }

    /// Get a [ProjectAssembler] configured for `project`
    pub fn for_project_with_providers<'a, S>(
        self,
        project: Arc<ProjectPackage>,
        store: &'a mut S,
        providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache,
    {
        let source_manager = self.source_manager();
        let dependency_graph =
            DependencyGraph::from_project(project.clone(), store, source_manager)?;
        Ok(ProjectAssembler {
            assembler: self,
            project,
            source_provider: SourceProviderRegistry::new(providers),
            dependency_graph,
            post_processors: Vec::new(),
            package_naming_provider: None,
            namespace_inputs_provider: None,
            store,
        })
    }
}

// PROJECT ASSEMBLER
// ================================================================================================

/// Independent caller naming requirements for a dependency source target.
///
/// A default-home request does not describe public ownership. The optional exact public mapping
/// remains separate and constrains fresh products and every reuse candidate. Empty requests supply
/// no implicit home, callable metadata, profile admission or execution authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct DependencyNamingRequest<'a> {
    pub binding: Option<&'a miden_project::DependencyBinding>,
    pub expected_callables: Option<&'a ExpectedVisibleCallables>,
}

pub struct ProjectSourceInputs {
    pub root: Box<Module>,
    pub support: Vec<Box<Module>>,
}

pub struct ProjectSourceProvenanceInputs {
    pub root: SourceFileProvenance,
    pub support: Vec<SourceFileProvenance>,
}

pub struct SourceFileProvenance {
    pub path: Box<std::path::Path>,
    pub content: Box<str>,
}

impl SourceFileProvenance {
    pub fn from_path(path: PathBuf) -> Result<Self, Report> {
        let content = fs::read_to_string(&path).map_err(|err| {
            Report::msg(format!("unable to read source file '{}': {err}", path.display()))
        })?;
        Ok(Self {
            path: path.into_boxed_path(),
            content: content.into_boxed_str(),
        })
    }
}

pub struct SourceProviderRegistry {
    registered: BTreeMap<&'static str, Box<dyn ProjectSourceProvider>>,
}

impl Default for SourceProviderRegistry {
    fn default() -> Self {
        Self {
            registered: BTreeMap::from_iter([(
                "masm",
                Box::new(MasmSourceProvider) as Box<dyn ProjectSourceProvider>,
            )]),
        }
    }
}

impl SourceProviderRegistry {
    pub fn new(providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>) -> Self {
        let mut this = Self {
            registered: providers.into_iter().map(|p| (p.file_type(), p)).collect(),
        };

        if !this.registered.contains_key("masm") {
            this.registered.insert("masm", Box::new(MasmSourceProvider));
        }

        this
    }

    pub fn with_source_provider(
        &mut self,
        provider: impl ProjectSourceProvider + 'static,
    ) -> &mut Self {
        let file_type = provider.file_type();
        let provider = Box::new(provider) as Box<dyn ProjectSourceProvider>;

        self.registered.insert(file_type, provider);

        self
    }

    #[inline]
    pub fn get_provider(&self, file_type: &str) -> Option<&dyn ProjectSourceProvider> {
        self.registered.get(file_type).map(AsRef::as_ref)
    }
}

/// Returned when assembly is interrupted early by a [ProjectSourceProvider]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AssemblyInterrupted {
    /// The package that was being assembled
    pub package: PackageId,
    /// The target being assembled to produce this package
    pub target_name: Arc<str>,
    /// The type of target being assembled
    pub target_type: TargetType,
    /// What role this package plays in assembly of the top-level selected target
    pub role: InterruptedTargetRole,
}

/// This represents the reason a target was being assembled when assembly was interrupted
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InterruptedTargetRole {
    /// The target that was interrupted was the top-level/root selected target
    Root,
    /// The target was a required/implicit library of the top-level selected target
    RequiredLibrary,
    /// The target was a dependency (direct or transitive) of the top-level selected target
    Dependency,
}

impl core::fmt::Display for InterruptedTargetRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Root => f.write_str("root"),
            Self::RequiredLibrary => f.write_str("required library"),
            Self::Dependency => f.write_str("dependency"),
        }
    }
}

type PackageNamingProvider<'a> = dyn Fn(&MastPackage) -> Result<PackageNaming, Report> + 'a;
type NamespaceInputsProvider<'a> = dyn Fn(
        &TargetAssemblyContext<'_>,
        &ProjectSourceInputs,
        &Assembler,
    ) -> Result<NamespaceInputs, Report>
    + 'a;

pub struct ProjectAssembler<'a, S: PackageCache> {
    assembler: Assembler,
    project: Arc<ProjectPackage>,
    dependency_graph: DependencyGraph,
    source_provider: SourceProviderRegistry,
    /// Package post-processors, run in registration order. Empty by default.
    post_processors: Vec<Box<dyn PackagePostProcessor>>,
    package_naming_provider: Option<Box<PackageNamingProvider<'a>>>,
    namespace_inputs_provider: Option<Box<NamespaceInputsProvider<'a>>>,
    store: &'a mut S,
}

impl<'a, S> ProjectAssembler<'a, S>
where
    S: PackageCache,
{
    /// Selects complete naming for each source target after its root/support modules are loaded.
    ///
    /// The callback runs before memoized or registered source artifacts are considered. Package
    /// identifiers, source namespaces and supplied bodies never imply a caller home or binding.
    /// The read-only assembler contains the actual resolved imports, including their existing
    /// canonical bindings. This configures compiler inputs; it does not grant publication or
    /// execution authority.
    pub fn with_namespace_inputs_provider(
        &mut self,
        provider: impl Fn(
            &TargetAssemblyContext<'_>,
            &ProjectSourceInputs,
            &Assembler,
        ) -> Result<NamespaceInputs, Report>
        + 'a,
    ) -> &mut Self {
        self.namespace_inputs_provider = Some(Box::new(provider));
        self
    }

    /// Provides canonical naming for packages read from storage or preassembled artifacts.
    ///
    /// The provider must admit raw naming using the caller's explicit current home profile,
    /// context and codec limits. Its result is checked against the exact package before use.
    /// Source compilation retains its own canonical naming and does not use this provider.
    pub fn with_package_naming_provider(
        &mut self,
        provider: impl Fn(&MastPackage) -> Result<PackageNaming, Report> + 'a,
    ) -> &mut Self {
        self.package_naming_provider = Some(Box::new(provider));
        self
    }

    pub fn with_source_provider(
        &mut self,
        provider: impl ProjectSourceProvider + 'static,
    ) -> &mut Self {
        self.source_provider.with_source_provider(provider);
        self
    }

    /// Registers a [`PackagePostProcessor`].
    ///
    /// The assembler runs the registered processors in registration order on every package of
    /// the project under assembly — the selected target and its required library — after the
    /// source provider's post-processing hook and before the package is frozen and cached.
    /// Source dependencies are never post-processed: their packages must be complete as their
    /// own projects build them, and a dependency manifest must not direct work in the
    /// dependent's build. Manually-provided sources skip all post-assembly hooks, processors
    /// included. The default processor list is empty.
    pub fn with_package_post_processor(
        &mut self,
        processor: impl PackagePostProcessor + 'static,
    ) -> &mut Self {
        self.post_processors.push(Box::new(processor));
        self
    }

    /// Get the project being assembled
    pub fn project(&self) -> &ProjectPackage {
        self.project.as_ref()
    }

    /// Assemble a target of the current project matching `target_selector`, using the configuration
    /// under the profile `profile_name`.
    ///
    /// Returns an error if:
    ///
    /// * `target_selector` cannot find a matching target in the current project
    /// * `profile_name` is not a profile defined in this project
    /// * An error occurs during assembly of the project or one of its dependencies
    /// * Assembly was interrupted by a source provider for the project or one of its dependencies
    pub fn assemble(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
    ) -> Result<Arc<MastPackage>, Report> {
        self.assemble_with_naming(target_selector, profile_name)
            .map(|resolved| resolved.package)
    }

    /// Like [`Self::assemble`], retaining the compiler's complete canonical naming inventory.
    ///
    /// The result includes private declarations, source-visible aliases and the executable entry
    /// key, together with any required linked kernel package and its naming. This metadata is
    /// structurally checked against the exact package; it does not grant home/profile admission
    /// or execution authority.
    pub fn assemble_with_naming(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
    ) -> Result<ResolvedPackage, Report> {
        let result = self.assemble_interruptible_with_naming(target_selector, profile_name)?;

        match result {
            ControlFlow::Continue(package) => Ok(package),
            ControlFlow::Break(AssemblyInterrupted { package, target_name, target_type, role }) => {
                Err(Report::msg(format!(
                    "assembly of {role} package '{package}' was interrupted by the source provider for target '{target_name}' (type={target_type})"
                )))
            },
        }
    }

    /// Like [`Self::assemble`], but allows for assembly to be interrupted by source providers
    /// early.
    ///
    /// Returns [`ControlFlow`] representing whether assembly should break early (i.e. it was
    /// interrupted), or continue as normal (i.e. it succeeded, and a package was produced).
    ///
    /// When assembly is interrupted early, a [AssemblyInterrupted] value is returned via
    /// `ControlFlow::Break`, identifying what package (and target) caused the interruption, and
    /// what role that package/target played in assembly of the root selected target.
    ///
    /// Returns an error if:
    ///
    /// * `target_selector` cannot find a matching target in the current project
    /// * `profile_name` is not a profile defined in this project
    /// * An error occurs during assembly of the project or one of its dependencies
    pub fn assemble_interruptible(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
    ) -> Result<ControlFlow<AssemblyInterrupted, Arc<MastPackage>>, Report> {
        self.assemble_interruptible_with_naming(target_selector, profile_name)
            .map(|resolved| resolved.map_continue(|r| r.package))
    }

    /// Like [`Self::assemble_interruptible`], retaining the complete naming described by
    /// [`Self::assemble_with_naming`] when assembly succeeds.
    pub fn assemble_interruptible_with_naming(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
    ) -> Result<ControlFlow<AssemblyInterrupted, ResolvedPackage>, Report> {
        let target = target_selector.select_target(self.project.as_ref())?;

        // When building an executable target from a project with a library target, we require
        // that the executable target be linked statically against the library target
        let mut cache = BTreeMap::new();
        let root_id = self.dependency_graph.root().clone();
        let required_lib = if target.is_executable()
            && let Some(library_target) =
                self.project.library_target().map(|target| target.inner().clone())
        {
            match self.assemble_source_package(
                root_id.clone(),
                Arc::clone(&self.project),
                &library_target,
                profile_name,
                InterruptedTargetRole::RequiredLibrary,
                None,
                None,
                None,
                &mut cache,
                DependencyNamingRequest::default(),
            )? {
                ControlFlow::Break(breaker) => return Ok(ControlFlow::Break(breaker)),
                ControlFlow::Continue(resolved) => Some(resolved),
            }
        } else {
            None
        };

        self.assemble_source_package(
            root_id,
            Arc::clone(&self.project),
            &target,
            profile_name,
            InterruptedTargetRole::Root,
            required_lib,
            None,
            None,
            &mut cache,
            DependencyNamingRequest::default(),
        )
    }

    /// This is a low-level utility function of the project assembly infrastructure for assembling
    /// a project target whose sources and source provenance may have already been computed by the
    /// caller.
    ///
    /// This API supports early interruption by source providers, represented by the `ControlFlow`
    /// value which is returned. The [AssemblyInterrupted] value carried in the `Break` variant
    /// indicates the package/target which was interrupted, and the role that target played in
    /// assembly of the provided project and target.
    ///
    /// In almost all cases you should prefer to use [`ProjectAssembler::assemble_with_naming`] or
    /// [`ProjectAssembler::assemble_interruptible_with_naming`] instead.
    ///
    /// Callers are required to uphold the following invariants:
    ///
    /// * `package_id` must be the package identifier for `project` in the current dependency graph
    /// * `target` must be a target extracted from `project`
    /// * `naming.binding`, when present, is the parent's source-target default-home request; its
    ///   exact home is checked against namespace inputs before any cache reuse. It does not approve
    ///   public callable mappings or replace complete Bound declarations.
    /// * `naming.expected_callables`, when present, is the parent's independently chosen exact
    ///   public mapping. It is checked on fresh products and before returning any cached candidate.
    /// * `required_lib` must be set if assembly of `target` would depend on another target of the
    ///   same project (i.e. an executable target implicitly depends on the library target).
    ///
    /// It is invalid to provide `source_provenance` without `sources` - doing so will trigger an
    /// assertion.
    pub fn assemble_source_package(
        &mut self,
        package_id: PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        package_role: InterruptedTargetRole,
        required_lib: Option<ResolvedPackage>,
        sources: Option<ProjectSourceInputs>,
        source_provenance: Option<ProjectSourceProvenanceInputs>,
        cache: &mut BTreeMap<PackageId, ResolvedPackage>,
        naming: DependencyNamingRequest<'_>,
    ) -> Result<ControlFlow<AssemblyInterrupted, ResolvedPackage>, Report> {
        let DependencyNamingRequest {
            binding: requested_binding,
            expected_callables,
        } = naming;
        target.validate_naming()?;
        assert!(
            source_provenance.is_none() || sources.is_some(),
            "source provenance may only be provided with sources"
        );

        // Keep dependency graph identities distinct even when two projects publish the same name.
        // Executables also need a separate slot from their required library in this same graph.
        let cache_key = if target.ty.is_executable() {
            format!("{package_id}:{}", target.name.inner()).into()
        } else {
            package_id.clone()
        };
        let profile = project.resolve_profile(profile_name)?;
        let mut assembler = self.assembler.clone().with_profile(profile);
        let mut runtime_dependencies = RuntimeDependencies::default();
        debug_assert!(
            required_lib.is_none() || target.ty.is_executable(),
            "expected required_lib only for executable targets"
        );
        match required_lib {
            Some(required_lib) if required_lib.package.is_kernel() => {
                // We do not link the package here, as by definition a required library is only
                // present for executable targets, and we always unconditionally link kernel
                // dependencies just prior to assembling the package
                runtime_dependencies
                    .record_linked_kernel_dependency(required_lib.package, required_lib.naming)?;
            },
            Some(required_lib) => {
                assembler.link_package(
                    required_lib.package.clone(),
                    Linkage::Static,
                    required_lib.naming.clone(),
                )?;
                if let Some((kernel_package, kernel_naming)) = required_lib.linked_kernel_package {
                    runtime_dependencies
                        .record_linked_kernel_dependency(kernel_package, kernel_naming)?;
                }
            },
            None => (),
        }

        let node = self.dependency_graph.get(&package_id)?;
        let dependencies = node.dependencies.clone();
        for edge in dependencies.iter() {
            let dependency_package = match self.resolve_dependency_package(
                &edge.dependency,
                profile_name,
                cache,
                edge.binding.as_ref(),
                edge.expected_callables.as_ref(),
            )? {
                ControlFlow::Break(breaker) => return Ok(ControlFlow::Break(breaker)),
                ControlFlow::Continue(pkg) => pkg,
            };
            if !dependency_package.package.is_library() {
                return Err(Report::msg(format!(
                    "dependency '{}' resolved to executable package '{}', but only library-like packages can be linked",
                    edge.dependency, dependency_package.package.name
                )));
            }

            if !dependency_package.package.is_kernel() {
                assembler.link_package(
                    dependency_package.package.clone(),
                    edge.linkage,
                    dependency_package.naming.clone(),
                )?;
            }
            runtime_dependencies.merge_package(dependency_package, edge.linkage)?;
        }

        let manually_provided_sources = sources.is_some();
        let sources = match sources {
            Some(sources) => sources,
            None => {
                match self.load_target_sources(project.clone(), target, profile, package_role)? {
                    ControlFlow::Break(breaker) => return Ok(ControlFlow::Break(breaker)),
                    ControlFlow::Continue(sources) => sources,
                }
            },
        };

        if let Some((kernel_package, kernel_naming)) = runtime_dependencies.kernel.clone() {
            if matches!(target.ty, TargetType::Kernel) {
                return Err(Report::msg(format!(
                    "kernel targets cannot depend on a kernel, dependency '{}' is a kernel",
                    kernel_package.name
                )));
            }
            assembler.link_package(kernel_package, Linkage::Dynamic, kernel_naming)?;
        }

        let selected_binding =
            requested_binding.or_else(|| target.naming.as_ref().map(|naming| naming.binding()));
        let namespace_inputs = if let Some(provider) = &self.namespace_inputs_provider {
            let mut context = self.get_target_assembly_context(
                &project,
                target,
                profile,
                manually_provided_sources,
            )?;
            context.dependency_binding = requested_binding;
            provider(&context, &sources, &assembler)?
        } else if let Some(naming) = &target.naming {
            let inputs = NamespaceInputs::new().with_namespace_plan(
                selected_binding
                    .expect("configured target has an explicit fallback binding")
                    .namespace_plan(),
            );
            let modules = core::iter::once(sources.root.as_ref())
                .chain(sources.support.iter().map(Box::as_ref))
                .collect::<Vec<_>>();
            match naming.convention() {
                SourceNamingConvention::DefiningPaths => {
                    inputs.with_default_callable_paths(modules)?
                },
                SourceNamingConvention::KernelRootExports => {
                    inputs.with_kernel_root_exports(&assembler, &modules)?
                },
            }
        } else {
            return Err(Report::msg(format!(
                "source target '{}' requires an explicit namespace inputs provider or target naming configuration; configure with_namespace_inputs_provider or target naming",
                target.name.inner()
            )));
        };
        // Validate even when inherited AST inputs prevent persistent cache reuse.
        if let Some(binding) = selected_binding
            && namespace_inputs.namespace_plan() != Some(&binding.namespace_plan())
        {
            return Err(Report::msg(format!(
                "source target '{}' namespace inputs differ from its requested source home",
                target.name.inner()
            )));
        }
        namespace_inputs.cache_commitment()?;
        let selected_home = namespace_inputs
            .namespace_plan()
            .expect("checked namespace inputs have an explicit home")
            .clone();
        assembler = assembler.with_namespace_inputs(namespace_inputs);

        // Extend, rather than replace, source/Git, graph and effective profile provenance with
        // the actual canonical naming, pins and resolved package inputs selected for this build.
        let compilation_commitment = assembler.project_cache_commitment(profile_name)?;
        let build_provenance = if source_provenance.is_some() || !manually_provided_sources {
            self.dependency_graph
                .build_source_provenance(
                    &package_id,
                    project.clone(),
                    target,
                    profile_name,
                    &self.source_provider,
                    self.store,
                    source_provenance.as_ref(),
                )?
                .map(|provenance| match compilation_commitment {
                    Some(commitment) => provenance.with_compilation_commitment(commitment),
                    None => provenance,
                })
        } else {
            None
        };
        // Caller-provided ASTs are not identified by source file provenance: they may have been
        // edited after parsing. Likewise inherited AST/advice/declarations have no exact snapshot.
        let can_reuse = !manually_provided_sources
            && build_provenance
                .as_ref()
                .and_then(PackageBuildProvenance::compilation_commitment)
                .is_some();
        if can_reuse
            && package_role == InterruptedTargetRole::Dependency
            && let Some(expected) = &build_provenance
            && let Some(cached) = cache.get(&cache_key)
            && cached.package.kind == target.ty
            && PackageBuildProvenance::from_package(&cached.package)?.as_ref() == Some(expected)
        {
            Self::check_source_dependency_sections(&cached.package)?;
            cached.package.check_naming(&cached.naming).map_err(Report::msg)?;
            Self::check_selected_source_home(target, &cached.naming, &selected_home)?;
            if let Some(expected) = expected_callables {
                expected.check(&cached.naming)?;
            }
            return Ok(ControlFlow::Continue(cached.clone()));
        }

        let reuse = if can_reuse && package_role == InterruptedTargetRole::Dependency {
            self.try_reuse_registered_source_package(
                &package_id,
                project.version().inner(),
                build_provenance.as_ref().expect("real provider sources have provenance"),
            )?
        } else {
            RegisteredSourcePackage::Missing
        };
        if let RegisteredSourcePackage::Loaded(package) = &reuse {
            let resolved = self.resolve_loaded_package(package.clone())?;
            Self::check_selected_source_home(target, &resolved.naming, &selected_home)?;
            if let Some(expected) = expected_callables {
                expected.check(&resolved.naming)?;
            }
            cache.insert(cache_key, resolved.clone());
            return Ok(ControlFlow::Continue(resolved));
        }

        let mut sections = Vec::new();
        if let Some(build_provenance) = build_provenance {
            sections.push(build_provenance.to_section());
        }
        let ProjectSourceInputs { root, support } = sources;

        let mut product = match target.ty {
            TargetType::Executable => {
                assembler.assemble_executable_modules(package_id.clone(), root, support)?
            },
            _ if target.ty.is_library() => {
                assembler.assemble_library_modules(package_id.clone(), root, support, target.ty)?
            },
            _ => unreachable!("non-exhaustive target type"),
        };

        product
            .extend_dependencies(runtime_dependencies.deps.into_values())
            .expect("assembled package manifest should have unique runtime dependencies");

        let naming = Arc::new(product.naming().clone());
        let mut package = product.into_artifact(profile.should_emit_debug_info())?;
        package.name = project.target_package_name(target);
        package.version = project.version().into_inner().clone();
        package.description = project.description().map(|description| description.to_string());
        package.sections.extend(sections);

        // We don't apply post-assembly hooks when assembling manually-provided sources
        if !manually_provided_sources {
            self.apply_post_assembly_hooks(
                &mut package,
                project.clone(),
                target,
                profile,
                package_role,
            )?;
        }

        package.check_naming(&naming).map_err(|error| Report::msg(error.to_string()))?;
        Self::check_selected_source_home(target, &naming, &selected_home)?;
        if let Some(expected) = expected_callables {
            expected.check(&naming)?;
        }
        let package = Arc::from(package);

        let resolved = ResolvedPackage {
            package,
            naming,
            linked_kernel_package: runtime_dependencies.kernel,
        };
        if let RegisteredSourcePackage::IndexedButUnreadable(expected) = reuse {
            let actual = PackageVersion::new(
                resolved.package.version.clone(),
                resolved.package.dependency_commitment(),
            );
            if actual != expected {
                return Err(Report::msg(format!(
                    "package '{package_id}' version '{}' is already registered as '{expected}', but the canonical artifact could not be loaded and rebuilding from source produced '{actual}'; bump the semantic version or repair the package store",
                    project.version()
                )));
            }
        }
        if package_role == InterruptedTargetRole::Dependency {
            self.cache_resolved_package(&resolved)?;
        }
        cache.insert(cache_key, resolved.clone());

        Ok(ControlFlow::Continue(resolved))
    }

    fn check_selected_source_home(
        target: &Target,
        naming: &PackageNaming,
        selected_home: &NamespacePlan,
    ) -> Result<(), Report> {
        if naming.namespace_plan() != selected_home {
            return Err(Report::msg(format!(
                "source target '{}' default home differs from its selected source home",
                target.name.inner()
            )));
        }
        Ok(())
    }

    fn resolve_dependency_package(
        &mut self,
        package_id: &PackageId,
        profile_name: &str,
        cache: &mut BTreeMap<PackageId, ResolvedPackage>,
        requested_binding: Option<&miden_project::DependencyBinding>,
        expected_callables: Option<&ExpectedVisibleCallables>,
    ) -> Result<ControlFlow<AssemblyInterrupted, ResolvedPackage>, Report> {
        let node = self.dependency_graph.get(package_id)?;
        let node_version = node.version.clone();
        let is_source = matches!(
            &node.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                library_path: Some(_),
                ..
            })
        );
        if !is_source && expected_callables.is_none() {
            return Err(Report::msg(format!(
                "artifact dependency '{package_id}' requires explicit expected callable mappings",
            )));
        }

        let (package, should_cache) = match &node.provenance {
            ProjectDependencyNodeProvenance::Source(ProjectSource::Virtual { .. }) => {
                return Err(Report::msg(format!(
                    "package '{package_id}' is missing a manifest path",
                )));
            },
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                manifest_path,
                library_path: Some(_),
                ..
            }) => {
                let project = miden_project::Project::load_project_reference(
                    package_id,
                    manifest_path,
                    &self.assembler.source_manager(),
                )
                .map(|project| project.package())?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{package_id}' does not define a library target"
                        ))
                    })?;
                let package = match self.assemble_source_package(
                    package_id.clone(),
                    project,
                    &target,
                    profile_name,
                    InterruptedTargetRole::Dependency,
                    None,
                    None,
                    None,
                    cache,
                    DependencyNamingRequest {
                        binding: requested_binding,
                        expected_callables,
                    },
                )? {
                    ControlFlow::Break(breaker) => return Ok(ControlFlow::Break(breaker)),
                    ControlFlow::Continue(package) => package,
                };
                // Source assembly checks/stores its own exact provenance after resolving inputs.
                (package, false)
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                let package =
                    self.load_canonical_package(package_id, &node_version)?.ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{package_id}' version '{node_version}' was not found in the package registry"
                        ))
                    })?;
                (self.resolve_loaded_package(package)?, false)
            },
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                let package = self.store.load_package(package_id, selected)?;
                (self.resolve_loaded_package(package)?, false)
            },
            ProjectDependencyNodeProvenance::Preassembled {
                path,
                selected,
                kind,
                requirements,
            } => {
                let package = load_selected_preassembled_package(
                    path,
                    package_id,
                    selected,
                    *kind,
                    requirements,
                )?;
                let should_cache = self.should_cache_preassembled_package(package_id, selected);
                (self.resolve_loaded_package(package)?, should_cache)
            },
        };

        if let Some(expected) = expected_callables {
            expected.check(&package.naming)?;
        }
        // Custom requests constrain only the exact package-default metadata, independently of
        // the complete public mapping and any retained private or foreign binding homes.
        if let Some(miden_project::DependencyBinding::Custom(home)) = requested_binding
            && package.naming.namespace_plan() != home
        {
            return Err(Report::msg(format!(
                "dependency '{package_id}' default home differs from its explicit custom home"
            )));
        }
        if should_cache {
            self.cache_resolved_package(&package)?;
        }
        cache.insert(package_id.clone(), package.clone());
        Ok(ControlFlow::Continue(package))
    }

    fn naming_for_loaded_package(
        &self,
        package: &MastPackage,
    ) -> Result<Arc<PackageNaming>, Report> {
        let provider = self.package_naming_provider.as_ref().ok_or_else(|| {
            Report::msg(format!(
                "package '{}@{}' requires an explicit package naming provider; configure with_package_naming_provider with the current home profile, context and codec limits",
                package.name, package.version
            ))
        })?;
        let naming = provider(package)?;
        package.check_naming(&naming).map_err(|error| Report::msg(error.to_string()))?;
        Ok(Arc::new(naming))
    }

    fn resolve_loaded_package(&self, package: Arc<MastPackage>) -> Result<ResolvedPackage, Report> {
        let naming = self.naming_for_loaded_package(&package)?;
        let linked_kernel_package =
            self.resolve_linked_kernel_package(package.clone(), naming.clone())?;
        Ok(ResolvedPackage { package, naming, linked_kernel_package })
    }

    fn resolve_linked_kernel_package(
        &self,
        package: Arc<MastPackage>,
        naming: Arc<PackageNaming>,
    ) -> Result<Option<(Arc<MastPackage>, Arc<PackageNaming>)>, Report> {
        if package.is_kernel() {
            return Ok(Some((package, naming)));
        }

        let Some(kernel_dependency) = package.kernel_runtime_dependency()? else {
            return Ok(None);
        };

        let version =
            PackageVersion::new(kernel_dependency.version.clone(), kernel_dependency.digest);
        if self.store.get_exact_version(&kernel_dependency.name, &version).is_some() {
            match self.store.load_package(&kernel_dependency.name, &version) {
                Ok(kernel_package) => {
                    if !kernel_package.is_kernel() {
                        return Err(Report::msg(format!(
                            "runtime kernel dependency '{}@{}#{}' resolved to non-kernel package '{}'",
                            kernel_dependency.name,
                            kernel_dependency.version,
                            kernel_dependency.digest,
                            kernel_package.name
                        )));
                    }
                    let kernel_naming = self.naming_for_loaded_package(&kernel_package)?;
                    return Ok(Some((kernel_package, kernel_naming)));
                },
                Err(load_error) => {
                    if let Some(kernel_package) = package
                        .try_embedded_kernel_package()
                        .map(|kernel_package| kernel_package.map(Arc::from))?
                    {
                        let kernel_naming = self.naming_for_loaded_package(&kernel_package)?;
                        return Ok(Some((kernel_package, kernel_naming)));
                    }
                    return Err(load_error);
                },
            }
        }

        package
            .try_embedded_kernel_package()?
            .map(|kernel_package| {
                let kernel_package: Arc<MastPackage> = Arc::from(kernel_package);
                let kernel_naming = self.naming_for_loaded_package(&kernel_package)?;
                Ok((kernel_package, kernel_naming))
            })
            .transpose()
    }

    fn load_canonical_package(
        &self,
        package_id: &PackageId,
        version: &miden_project::SemVer,
    ) -> Result<Option<Arc<MastPackage>>, Report> {
        let Some(record) = self.store.get_by_semver(package_id, version) else {
            return Ok(None);
        };
        self.store.load_package(package_id, record.version()).map(Some)
    }

    fn try_reuse_registered_source_package(
        &self,
        package_id: &PackageId,
        version: &miden_project::SemVer,
        expected: &PackageBuildProvenance,
    ) -> Result<RegisteredSourcePackage, Report> {
        let Some(record) = self.store.get_by_semver(package_id, version) else {
            return Ok(RegisteredSourcePackage::Missing);
        };
        let package = match self.store.load_package(package_id, record.version()) {
            Ok(package) => package,
            Err(_) => {
                return Ok(RegisteredSourcePackage::IndexedButUnreadable(record.version().clone()));
            },
        };

        match PackageBuildProvenance::from_package(&package)? {
            Some(actual) if &actual == expected => Ok(()),
            Some(actual) => Err(Report::msg(format!(
                "package '{}' version '{}' is already registered with different source provenance (expected {}, found {}); bump the semantic version",
                package_id,
                version,
                expected.describe(),
                actual.describe(),
            ))),
            None => Err(Report::msg(format!(
                "package '{package_id}' version '{version}' is already registered, but the canonical artifact is missing source provenance; bump the semantic version"
            ))),
        }?;

        Self::check_source_dependency_sections(&package)?;
        Ok(RegisteredSourcePackage::Loaded(package))
    }

    fn check_source_dependency_sections(package: &MastPackage) -> Result<(), Report> {
        // Source provenance covers the sources only, so it cannot tell a dependency build from a
        // root build that registered post-processors extended (for example with an
        // `event_handlers` section). Reusing such an artifact as a dependency would give it a
        // different dependency commitment than the cold build below, which skips post-processors,
        // so the same source would resolve to two package identities depending on what the store
        // holds. A dependency build produces only the sections listed here; an artifact with any
        // other section is refused loudly, like a provenance mismatch. `KERNEL` is not listed:
        // only program packages embed a kernel, and this path reuses library targets.
        const DEPENDENCY_SECTIONS: [&SectionId; 3] = [
            &SectionId::DEBUG_INFO,
            &SectionId::ACCOUNT_COMPONENT_METADATA,
            &SectionId::PROJECT_SOURCE_PROVENANCE,
        ];
        if let Some(section) = package
            .sections
            .iter()
            .find(|section| !DEPENDENCY_SECTIONS.contains(&&section.id))
        {
            return Err(Report::msg(format!(
                "package '{}' version '{}' is already registered, but the canonical artifact carries a '{}' section a dependency build does not produce (it was assembled as a project root with a package post-processor); bump the semantic version",
                package.name, package.version, section.id,
            )));
        }

        Ok(())
    }

    fn should_cache_preassembled_package(
        &self,
        package_id: &PackageId,
        selected: &PackageVersion,
    ) -> bool {
        let Some(record) = self.store.get_by_semver(package_id, &selected.version) else {
            return true;
        };
        if record.version() != selected {
            return false;
        }

        self.store.load_package(package_id, selected).is_err()
    }

    fn cache_resolved_package(&mut self, package: &ResolvedPackage) -> Result<(), Report> {
        self.cache_package(package.package.clone())?;
        if let Some((kernel_package, _)) = package.linked_kernel_package.clone()
            && self.should_cache_linked_kernel_package(kernel_package.as_ref())
        {
            self.cache_package(kernel_package)?;
        }
        Ok(())
    }

    fn should_cache_linked_kernel_package(&self, package: &MastPackage) -> bool {
        let version = PackageVersion::new(package.version.clone(), package.dependency_commitment());
        let Some(record) = self.store.get_by_semver(&package.name, &package.version) else {
            return true;
        };
        if record.version() != &version {
            return false;
        }

        self.store.load_package(&package.name, &version).is_err()
    }

    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<(), Report> {
        self.store
            .cache_package(package)
            .map(|_| ())
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn load_target_sources(
        &self,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile: &Profile,
        role: InterruptedTargetRole,
    ) -> Result<ControlFlow<AssemblyInterrupted, ProjectSourceInputs>, Report> {
        let (provider, context) =
            self.get_provider_and_target_assembly_context(&project, target, profile)?;

        let inputs = match provider.provide_sources_interruptible(&context)? {
            ControlFlow::Break(_) => {
                return Ok(ControlFlow::Break(AssemblyInterrupted {
                    package: project.name().into_inner(),
                    target_name: target.name.inner().clone(),
                    target_type: target.ty,
                    role,
                }));
            },
            ControlFlow::Continue(inputs) => inputs,
        };
        match target.ty {
            TargetType::Executable if !inputs.root.kind().is_executable() => {
                Err(Report::msg(format!(
                    "requested target type is executable, but root module provided to assembler for '{}' is {}",
                    project.name(),
                    inputs.root.kind()
                )))
            },
            TargetType::Kernel if !inputs.root.kind().is_kernel() => Err(Report::msg(format!(
                "requested target type is kernel, but root module provided to assembler for '{}' is {}",
                project.name(),
                inputs.root.kind()
            ))),
            _ if inputs.root.path() != target.namespace.inner().as_ref() => {
                Err(Report::msg(format!(
                    "requested target namespace is '{}', but root module provided to assembler for '{}' is '{}'",
                    target.namespace,
                    project.name(),
                    inputs.root.path()
                )))
            },
            _ => Ok(ControlFlow::Continue(inputs)),
        }
    }

    fn apply_post_assembly_hooks(
        &self,
        package: &mut MastPackage,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile: &Profile,
        package_role: InterruptedTargetRole,
    ) -> Result<(), Report> {
        let (provider, context) =
            self.get_provider_and_target_assembly_context(&project, target, profile)?;

        provider.post_process_package(package, &context)?;

        // Registered processors run only on the packages of the project under assembly, never on
        // source dependencies: a dependency package must be complete as its own project builds
        // it, and a dependency manifest must not direct work in the dependent's build. Source
        // provenance does not cover processor inputs, so a post-processed root artifact in the
        // package store looks reusable for a dependency of the same source;
        // `try_reuse_registered_source_package` refuses such artifacts by their extra sections,
        // which keeps dependency packages identical whether they are assembled fresh or reused.
        if !matches!(package_role, InterruptedTargetRole::Dependency) {
            let post_context = PostProcessContext { assembly: &context };
            for processor in &self.post_processors {
                processor.post_process(package, &post_context)?;
            }
        }

        Ok(())
    }

    fn get_target_assembly_context<'this>(
        &'this self,
        project: &'this Arc<ProjectPackage>,
        target: &'this Target,
        profile: &'this Profile,
        provided_sources: bool,
    ) -> Result<TargetAssemblyContext<'this>, Report> {
        let mut context = if provided_sources {
            TargetAssemblyContext::for_provided_sources(
                project,
                target,
                profile,
                self.dependency_graph.as_ref(),
                self.store,
                self.assembler.source_manager(),
            )?
        } else {
            match project.manifest_path() {
                Some(manifest_path) => TargetAssemblyContext::new(
                    project.clone(),
                    manifest_path,
                    target,
                    profile,
                    self.dependency_graph.as_ref(),
                    self.store,
                    self.assembler.source_manager(),
                )?,
                None => TargetAssemblyContext::new_virtual(
                    project.clone(),
                    target,
                    profile,
                    self.dependency_graph.as_ref(),
                    self.store,
                    self.assembler.source_manager(),
                )?,
            }
        };
        context.with_warnings_as_errors(self.assembler.warnings_as_errors());

        Ok(context)
    }

    fn get_provider_and_target_assembly_context<'this>(
        &'this self,
        project: &'this Arc<ProjectPackage>,
        target: &'this Target,
        profile: &'this Profile,
    ) -> Result<(&'this dyn ProjectSourceProvider, TargetAssemblyContext<'this>), Report> {
        let context = self.get_target_assembly_context(project, target, profile, false)?;
        let extension = context.resolved_target_root.extension().ok_or_else(|| {
            Report::msg(format!(
                "invalid target 'path' {}: path must have an extension",
                context.resolved_target_root.display()
            ))
        })?;
        let extension = extension.to_string_lossy();

        let provider = self.source_provider.get_provider(extension.as_ref()).ok_or_else(|| Report::msg(format!("unsupported target file type '{extension}': no provider has been registered for that file type")))?;

        Ok((provider, context))
    }
}

// ================================================================================================

#[derive(Clone)]
pub struct ResolvedPackage {
    pub package: Arc<MastPackage>,
    pub naming: Arc<PackageNaming>,
    pub linked_kernel_package: Option<(Arc<MastPackage>, Arc<PackageNaming>)>,
}

enum RegisteredSourcePackage {
    Missing,
    Loaded(Arc<MastPackage>),
    IndexedButUnreadable(PackageVersion),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageBuildSettings {
    emit_debug_info: bool,
    trim_paths: bool,
}

impl PackageBuildSettings {
    fn legacy() -> Self {
        Self { emit_debug_info: true, trim_paths: false }
    }

    fn from_profile(profile: &Profile) -> Self {
        Self {
            emit_debug_info: profile.should_emit_debug_info(),
            trim_paths: profile.should_trim_paths(),
        }
    }

    fn is_legacy(&self) -> bool {
        *self == Self::legacy()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn load_selected_preassembled_package(
    path: &FsPath,
    expected_name: &PackageId,
    selected: &PackageVersion,
    expected_kind: TargetType,
    expected_requirements: &BTreeMap<PackageId, PreassembledDependencyMetadata>,
) -> Result<Arc<MastPackage>, Report> {
    let package = load_package_from_path(path)?;
    if &package.name != expected_name {
        return Err(Report::msg(format!(
            "preassembled dependency '{}' at '{}' resolved to package '{}'",
            expected_name,
            path.display(),
            package.name
        )));
    }

    let actual = PackageVersion::new(package.version.clone(), package.dependency_commitment());
    if &actual != selected {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph selection '{}'",
            expected_name,
            actual,
            path.display(),
            selected
        )));
    }

    if package.kind != expected_kind {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph target kind '{}'",
            expected_name,
            actual,
            path.display(),
            expected_kind
        )));
    }

    let actual_requirements = package_requirements(&package);
    if &actual_requirements != expected_requirements {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph dependency requirements",
            expected_name,
            actual,
            path.display()
        )));
    }

    Ok(package)
}

fn load_package_from_path(path: &FsPath) -> Result<Arc<MastPackage>, Report> {
    let bytes = fs::read(path)
        .map_err(|error| Report::msg(format!("failed to read '{}': {error}", path.display())))?;
    let package = MastPackage::read_from_bytes(&bytes).map_err(|error| {
        Report::msg(format!("failed to decode package '{}': {error}", path.display()))
    })?;
    Ok(Arc::new(package))
}

fn package_requirements(
    package: &MastPackage,
) -> BTreeMap<PackageId, PreassembledDependencyMetadata> {
    package
        .manifest
        .dependencies()
        .map(|dependency| {
            (
                dependency.name.clone(),
                PreassembledDependencyMetadata {
                    version: PackageVersion::new(dependency.version.clone(), dependency.digest),
                    kind: dependency.kind,
                },
            )
        })
        .collect()
}
