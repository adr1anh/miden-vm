use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

use miden_assembly_syntax::{
    Report,
    debuginfo::{DefaultSourceManager, SourceManager, Uri},
};
use miden_core::{
    serde::Deserializable,
    utils::{DisplayHex, hash_string_to_word},
};
use miden_mast_package::Package as MastPackage;
use miden_package_registry::{
    InMemoryPackageRegistry, PackageId, PackageRecord, PackageRegistry, PackageResolver, Version,
};

use crate::{
    Dependency, DependencyVersionScheme, GitRevision, Linkage, Package, SemVer, VersionRequirement,
};

/// A graph-local resolution/build slot. This has no published or callable identity.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DependencyInstanceId(usize);

impl core::fmt::Display for DependencyInstanceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "instance-{}", self.0)
    }
}

/// A materialized dependency graph, rooted at a graph-local package instance.
/// Package provenance and public registry identities remain node data. Distinct aliases and
/// explicit binding contexts can therefore retain separate selections of the same package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyGraph {
    root: DependencyInstanceId,
    nodes: BTreeMap<DependencyInstanceId, ProjectDependencyNode>,
}

impl ProjectDependencyGraph {
    pub fn root(&self) -> &DependencyInstanceId {
        &self.root
    }

    pub fn nodes(&self) -> &BTreeMap<DependencyInstanceId, ProjectDependencyNode> {
        &self.nodes
    }

    pub fn get(&self, instance: &DependencyInstanceId) -> Option<&ProjectDependencyNode> {
        self.nodes.get(instance)
    }
}

/// A single selected package instance in a [ProjectDependencyGraph].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyNode {
    pub name: PackageId,
    pub version: SemVer,
    pub dependencies: Vec<ProjectDependencyEdge>,
    pub provenance: ProjectDependencyNodeProvenance,
}

impl ProjectDependencyNode {
    fn same_identity(&self, other: &Self) -> bool {
        self.name == other.name
            && self.version == other.version
            && self.provenance == other.provenance
    }
}

/// A source declaration's independent lookup, binding, expectation and code-supply choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyEdge {
    pub dependency: DependencyInstanceId,
    /// The source dependency table key, independent of the target package's name.
    pub alias: Arc<str>,
    pub linkage: Linkage,
    pub binding: Option<crate::DependencyBinding>,
    pub expected_callables: Option<crate::ExpectedVisibleCallables>,
    pub source_mount: Option<crate::PackageSourceMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectDependencyNodeProvenance {
    Source(ProjectSource),
    Registry {
        requirement: VersionRequirement,
        selected: Version,
    },
    Preassembled {
        path: PathBuf,
        selected: Version,
        kind: crate::TargetType,
        /// Full exact supply records, including distinct records with the same package name.
        requirements: Vec<PreassembledDependencyMetadata>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreassembledDependencyMetadata {
    pub name: PackageId,
    pub version: Version,
    pub kind: crate::TargetType,
}

/// Represents information about a package whose provenance is a Miden project in source form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSource {
    Virtual {
        origin: ProjectSourceOrigin,
    },
    Real {
        /// Where the sources were obtained from
        origin: ProjectSourceOrigin,
        /// The path to the package manifest, or `None` if the manifest is virtual
        manifest_path: PathBuf,
        /// The directory containing the package
        project_root: PathBuf,
        /// The directory of the workspace containing the package, if applicable
        workspace_root: Option<PathBuf>,
        /// The path to the library target for this project
        ///
        /// This is `None` only when we're assembling an executable target of the root package, and
        /// this is the source info for the root package itself.
        library_path: Option<PathBuf>,
    },
}

/// Represents the provenance of Miden project sources
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSourceOrigin {
    /// The sources are those of the root package being assembled
    Root,
    /// The sources were referenced by path
    Path,
    /// The sources were cloned from a Git repository into a locally-cached checkout
    Git {
        /// The repository URI
        repo: Uri,
        /// The revision that was checked out
        revision: GitRevision,
        /// The path where the repo was checked-out locally
        checkout_path: PathBuf,
        /// The resolved revision of the checkout as a commit hash.
        ///
        /// This is primarily relevant when the requested revision was a branch or tag.
        resolved_revision: Arc<str>,
    },
}

struct CollectedDependencyGraph {
    root: DependencyInstanceId,
    nodes: BTreeMap<DependencyInstanceId, CollectedDependencyNode>,
    slots: Vec<ResolutionSlot>,
    contexts: Vec<ResolutionContext>,
    /// Names with distinct explicit bindings in one ordinary shared constraint scope.
    isolated_bindings: BTreeSet<(usize, PackageId)>,
    source_dependencies: BTreeMap<(PackageId, Option<PathBuf>), Vec<ResolvedDependencyNode>>,
    next_scope: usize,
    scope_domains: BTreeMap<usize, usize>,
    exact_slots: Vec<(usize, PackageId, Version, Option<crate::TargetType>, DependencyInstanceId)>,
    registry_edges: BTreeMap<(DependencyInstanceId, SemVer), Vec<DependencyInstanceId>>,
}

/// A private solver namespace. Alias spelling is used only for resolution and never enters K.
struct ResolutionContext {
    parent: usize,
    declaration: Option<DependencyInstanceId>,
    alias: Option<Arc<str>>,
    package: PackageId,
    binding: Option<crate::DependencyBinding>,
    scope: usize,
}

struct ResolutionSlot {
    name: PackageId,
    scope: usize,
    registry_requirement: Option<VersionRequirement>,
}

#[derive(Default)]
struct BindingDiscovery {
    active: Vec<(PackageId, Option<PathBuf>)>,
    visited: BTreeSet<(DependencyInstanceId, PackageId, Option<PathBuf>)>,
    choices: BTreeMap<(usize, PackageId), Vec<crate::DependencyBinding>>,
}

impl CollectedDependencyGraph {
    fn allocate_slot(&mut self, scope: usize, name: PackageId) -> DependencyInstanceId {
        let id = DependencyInstanceId(self.slots.len());
        self.slots.push(ResolutionSlot { name, scope, registry_requirement: None });
        id
    }

    fn slot_in_scope(&mut self, scope: usize, name: PackageId) -> DependencyInstanceId {
        self.slots
            .iter()
            .position(|slot| slot.scope == scope && slot.name == name)
            .map(DependencyInstanceId)
            .unwrap_or_else(|| self.allocate_slot(scope, name))
    }

    fn allocate_scope(&mut self) -> usize {
        let scope = self.next_scope;
        self.next_scope += 1;
        scope
    }

    fn exact_supply_slot(
        &mut self,
        scope: usize,
        name: PackageId,
        version: Version,
        kind: Option<crate::TargetType>,
    ) -> Result<DependencyInstanceId, Report> {
        let domain = self.scope_domains.get(&scope).copied().unwrap_or(scope);
        if let Some((_, _, _, _, id)) = self.exact_slots.iter().find(
            |(candidate_domain, candidate_name, candidate_version, candidate_kind, _)| {
                *candidate_domain == domain
                    && candidate_name == &name
                    && candidate_version == &version
                    && candidate_kind == &kind
            },
        ) {
            return Ok(*id);
        }
        // Exact artifacts already supplied by path are candidates independently of publication
        // semver uniqueness. Matching uses the full commitment, never only the package name.
        let candidates = self
            .nodes
            .iter()
            .filter_map(|(&id, node)| {
                if node.graph_node.name != name {
                    return None;
                }
                match &node.graph_node.provenance {
                    ProjectDependencyNodeProvenance::Preassembled {
                        selected,
                        kind: candidate_kind,
                        ..
                    } if selected == &version
                        && kind.is_none_or(|kind| kind == *candidate_kind) =>
                    {
                        Some((id, *candidate_kind))
                    },
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        if let Some(&(id, candidate_kind)) = candidates.first() {
            if candidates.iter().any(|(_, kind)| *kind != candidate_kind) {
                return Err(Report::msg(format!(
                    "ambiguous exact supply kind for '{name}@{version}'"
                )));
            }
            self.exact_slots.push((domain, name, version, kind, id));
            return Ok(id);
        }
        let exact_scope = self.allocate_scope();
        self.scope_domains.insert(exact_scope, domain);
        let id = self.allocate_slot(exact_scope, name.clone());
        self.exact_slots.push((domain, name, version, kind, id));
        Ok(id)
    }

    fn context_scope(
        &mut self,
        parent: usize,
        declaration: Option<DependencyInstanceId>,
        alias: Option<Arc<str>>,
        package: PackageId,
        binding: Option<crate::DependencyBinding>,
    ) -> usize {
        if let Some(context) = self.contexts.iter().find(|context| {
            context.parent == parent
                && context.declaration == declaration
                && context.alias == alias
                && context.package == package
                && context.binding == binding
        }) {
            return context.scope;
        }
        let scope = self.allocate_scope();
        self.contexts.push(ResolutionContext {
            parent,
            declaration,
            alias,
            package,
            binding,
            scope,
        });
        scope
    }

    fn dependency_slot(
        &mut self,
        declaring: DependencyInstanceId,
        dependency: &Dependency,
    ) -> DependencyInstanceId {
        let scope = self.slots[declaring.0].scope;
        let name = dependency.package().clone();
        let binding = dependency.binding().cloned();
        let scope = if dependency.is_aliased() {
            self.context_scope(
                scope,
                Some(declaring),
                Some(dependency.alias().clone()),
                name.clone(),
                binding,
            )
        } else if self.isolated_bindings.contains(&(scope, name.clone())) {
            self.context_scope(scope, None, None, name.clone(), binding)
        } else {
            scope
        };
        self.slot_in_scope(scope, name)
    }

    fn insert_node(
        &mut self,
        id: DependencyInstanceId,
        node: CollectedDependencyNode,
    ) -> Result<bool, Report> {
        if self.slots[id.0].registry_requirement.is_some() {
            return Err(Report::msg(format!(
                "dependency conflict for '{}': local source or preassembled dependency conflicts with a registry dependency",
                node.graph_node.name
            )));
        }
        match self.nodes.get(&id) {
            Some(existing) if existing.graph_node.same_identity(&node.graph_node) => Ok(false),
            Some(existing) => Err(Report::msg(format!(
                "dependency conflict for '{}': existing node {:?} conflicts with {:?}",
                node.graph_node.name, existing.graph_node.provenance, node.graph_node.provenance
            ))),
            None => {
                self.nodes.insert(id, node);
                Ok(true)
            },
        }
    }

    fn record_registry_requirement(
        &mut self,
        id: DependencyInstanceId,
        requirement: VersionRequirement,
    ) -> Result<(), Report> {
        if self.nodes.contains_key(&id) {
            return Err(Report::msg(format!(
                "dependency conflict for '{}': local source or preassembled dependency conflicts with a registry dependency",
                self.slots[id.0].name
            )));
        }
        self.slots[id.0].registry_requirement.get_or_insert(requirement);
        Ok(())
    }

    fn root_version(&self) -> SemVer {
        self.nodes[&self.root].graph_node.version.clone()
    }

    /// Names exist only inside the private resolution registry. They are never package identities.
    fn solver_key(&self, id: DependencyInstanceId) -> PackageId {
        PackageId::from(format!("{} (graph instance {})", self.slots[id.0].name, id.0))
    }
}

#[derive(Clone)]
struct CollectedDependencyNode {
    graph_node: ProjectDependencyNode,
    solver_dependencies: BTreeMap<DependencyInstanceId, VersionRequirement>,
}

impl CollectedDependencyNode {
    fn selected_version(&self) -> Version {
        match &self.graph_node.provenance {
            ProjectDependencyNodeProvenance::Source(_) => {
                Version::from(self.graph_node.version.clone())
            },
            ProjectDependencyNodeProvenance::Preassembled { selected, .. } => selected.clone(),
            ProjectDependencyNodeProvenance::Registry { .. } => {
                unreachable!("registry nodes are materialized after solving")
            },
        }
    }
}

/// This type handles the details of constructing a [ProjectDependencyGraph] for a package.
pub struct ProjectDependencyGraphBuilder<'a, R: PackageRegistry + ?Sized> {
    registry: &'a R,
    source_manager: Arc<dyn SourceManager>,
    git_cache_root: PathBuf,
}

impl<'a, R: PackageRegistry + ?Sized> ProjectDependencyGraphBuilder<'a, R> {
    /// Construct a new [ProjectDependencyGraphBuilder] which will use the provided `registry` for
    /// resolving packages.
    pub fn new(registry: &'a R) -> Self {
        let git_cache_root = std::env::var_os("MIDENUP_HOME")
            .map(PathBuf::from)
            .map(|path| path.join("git").join("checkouts"))
            .unwrap_or_else(|| std::env::temp_dir().join("midenup").join("git").join("checkouts"));
        Self {
            registry,
            source_manager: Arc::new(DefaultSourceManager::default()),
            git_cache_root,
        }
    }

    /// Use the provided source manager for tracking source information of parsed files
    pub fn with_source_manager(mut self, source_manager: Arc<dyn SourceManager>) -> Self {
        self.source_manager = source_manager;
        self
    }

    /// Override the default location of the Git checkout cache.
    ///
    /// By default, the cache is located in:
    ///
    /// * `$MIDENUP_HOME/git/checkouts`, if `$MIDENUP_HOME` is set.
    /// * `$TMP_DIR/midenup/git/checkouts`, if `$MIDENUP_HOME` is _not_ set.
    pub fn with_git_cache_root(mut self, git_cache_root: impl AsRef<Path>) -> Self {
        self.git_cache_root = git_cache_root.as_ref().to_path_buf();
        self
    }

    /// Build a [ProjectDependencyGraph] for the project whose manifest is located at
    /// `manifest_path`
    pub fn build_from_path(
        &self,
        manifest_path: impl AsRef<Path>,
    ) -> Result<ProjectDependencyGraph, Report> {
        let loaded = self.load_package_from_manifest(manifest_path.as_ref())?;
        self.build_from_loaded_package(loaded)
    }

    /// Build a [ProjectDependencyGraph] for `package`
    pub fn build(&self, package: Arc<Package>) -> Result<ProjectDependencyGraph, Report> {
        let loaded = self.loaded_package_from_arc(package, None)?;
        self.build_from_loaded_package(loaded)
    }

    fn build_from_loaded_package(
        &self,
        loaded: LoadedSourcePackage,
    ) -> Result<ProjectDependencyGraph, Report> {
        let mut graph = self.collect_dependency_graph(loaded)?;
        let selected = self.solve_dependency_graph(&mut graph)?;
        self.materialize_dependency_graph(graph, &selected)
    }

    fn collect_dependency_graph(
        &self,
        loaded: LoadedSourcePackage,
    ) -> Result<CollectedDependencyGraph, Report> {
        let mut graph = CollectedDependencyGraph {
            root: DependencyInstanceId(0),
            nodes: BTreeMap::new(),
            slots: Vec::new(),
            contexts: Vec::new(),
            isolated_bindings: BTreeSet::new(),
            source_dependencies: BTreeMap::new(),
            next_scope: 1,
            scope_domains: BTreeMap::new(),
            exact_slots: Vec::new(),
            registry_edges: BTreeMap::new(),
        };
        let root = graph.allocate_slot(0, loaded.package.name().into_inner());
        // Discover every binding choice before committing shared nodes or solver constraints.
        // Decisions are fixed within a pass. Splitting an ancestor moves its descendants into new
        // scopes, so recompute until the source declarations stabilize. Some acyclic source graphs
        // have competing isolation choices; reject a repeated state instead of choosing by order.
        let mut seen_isolation_states = BTreeSet::new();
        loop {
            if !seen_isolation_states.insert(graph.isolated_bindings.clone()) {
                return Err(Report::msg(
                    "ambiguous dependency binding contexts; use explicit dependency aliases to select independent contexts",
                ));
            }
            let mut discovery = BindingDiscovery::default();
            self.discover_binding_contexts(&mut graph, root, &mut discovery, &loaded)?;
            let isolated = discovery
                .choices
                .into_iter()
                .filter(|(_, bindings)| bindings.len() > 1)
                .map(|(key, _)| key)
                .collect::<BTreeSet<_>>();
            if isolated == graph.isolated_bindings {
                break;
            }
            graph.isolated_bindings = isolated;
        }
        self.collect_source_package(
            &mut graph,
            root,
            &mut Vec::new(),
            loaded,
            ProjectSourceOrigin::Root,
            true,
        )?;
        self.attach_preassembled_requirements(&mut graph)?;
        Ok(graph)
    }

    fn resolve_source_dependencies(
        &self,
        graph: &mut CollectedDependencyGraph,
        package: &LoadedSourcePackage,
    ) -> Result<Vec<ResolvedDependencyNode>, Report> {
        let source = (package.package.name().into_inner(), package.manifest_path.clone());
        if let Some(resolved) = graph.source_dependencies.get(&source) {
            return Ok(resolved.clone());
        }
        let mut resolved = Vec::with_capacity(package.package.dependencies().len());
        for dependency in package.package.dependencies() {
            if dependency.binding().is_none() {
                return Err(Report::msg(format!(
                    "dependency '{}' requires an explicit Latest/Pinned binding or custom home",
                    dependency.alias()
                )));
            }
            resolved.push(self.resolve_dependency(dependency, package)?);
        }
        graph.source_dependencies.insert(source, resolved.clone());
        Ok(resolved)
    }

    fn discover_binding_contexts(
        &self,
        graph: &mut CollectedDependencyGraph,
        id: DependencyInstanceId,
        discovery: &mut BindingDiscovery,
        package: &LoadedSourcePackage,
    ) -> Result<(), Report> {
        let source = (package.package.name().into_inner(), package.manifest_path.clone());
        if discovery.active.contains(&source) {
            return Err(Report::msg(format!("cyclic source dependency involving '{}'", source.0)));
        }
        if !discovery.visited.insert((id, source.0.clone(), source.1.clone())) {
            return Ok(());
        }
        discovery.active.push(source);
        let resolved = self.resolve_source_dependencies(graph, package)?;
        for (dependency, resolved) in package.package.dependencies().iter().zip(resolved) {
            if !dependency.is_aliased() {
                let key = (graph.slots[id.0].scope, dependency.package().clone());
                let bindings = discovery.choices.entry(key).or_default();
                let binding = dependency.binding().expect("source dependencies were validated");
                if !bindings.contains(binding) {
                    bindings.push(binding.clone());
                }
            }
            let target = graph.dependency_slot(id, dependency);
            if let ResolvedDependencyNode::Source { package, .. } = resolved {
                self.discover_binding_contexts(graph, target, discovery, &package)?;
            }
        }
        discovery.active.pop();
        Ok(())
    }

    fn collect_source_package(
        &self,
        graph: &mut CollectedDependencyGraph,
        id: DependencyInstanceId,
        active: &mut Vec<(PackageId, Option<PathBuf>)>,
        package: LoadedSourcePackage,
        origin: ProjectSourceOrigin,
        allow_missing_library: bool,
    ) -> Result<(), Report> {
        let package_id = package.package.name().into_inner();
        let source = (package_id.clone(), package.manifest_path.clone());
        if active.contains(&source) {
            return Err(Report::msg(format!("cyclic source dependency involving '{package_id}'")));
        }
        let node = CollectedDependencyNode {
            graph_node: ProjectDependencyNode {
                dependencies: Vec::new(),
                name: package_id,
                provenance: ProjectDependencyNodeProvenance::Source(
                    match package.manifest_path.as_ref() {
                        Some(manifest_path) => ProjectSource::Real {
                            library_path: self.library_path(
                                &package.package,
                                manifest_path,
                                allow_missing_library,
                            )?,
                            manifest_path: manifest_path.to_path_buf(),
                            origin,
                            project_root: package.project_root.clone().unwrap(),
                            workspace_root: package.workspace_root.clone(),
                        },
                        None => ProjectSource::Virtual { origin },
                    },
                ),
                version: package.package.version().into_inner().clone(),
            },
            solver_dependencies: BTreeMap::new(),
        };
        if !graph.insert_node(id, node)? {
            return Ok(());
        }
        active.push(source);
        let mut edges = Vec::new();
        let mut solver_dependencies = BTreeMap::new();
        let resolved = self.resolve_source_dependencies(graph, &package)?;
        for (dependency, resolved) in package.package.dependencies().iter().zip(resolved) {
            if dependency.binding().is_none() {
                return Err(Report::msg(format!(
                    "dependency '{}' requires an explicit Latest/Pinned binding or custom home",
                    dependency.alias()
                )));
            }
            let target = graph.dependency_slot(id, dependency);
            edges.push(ProjectDependencyEdge {
                dependency: target,
                alias: dependency.alias().clone(),
                linkage: dependency.linkage(),
                binding: dependency.binding().cloned(),
                expected_callables: dependency.expected_callables().cloned(),
                source_mount: dependency.source_mount().cloned(),
            });
            solver_dependencies.insert(target, resolved.solver_requirement());
            match resolved {
                ResolvedDependencyNode::Source { package, origin } => {
                    self.collect_source_package(graph, target, active, package, origin, false)?;
                },
                ResolvedDependencyNode::Local(node) => {
                    graph.insert_node(target, node)?;
                },
                ResolvedDependencyNode::Registry { requirement } => {
                    graph.record_registry_requirement(target, requirement)?;
                },
            }
        }
        active.pop();
        let node = graph.nodes.get_mut(&id).expect("inserted source node");
        node.graph_node.dependencies = edges;
        node.solver_dependencies = solver_dependencies;
        Ok(())
    }

    fn attach_preassembled_requirements(
        &self,
        graph: &mut CollectedDependencyGraph,
    ) -> Result<(), Report> {
        let artifacts = graph
            .nodes
            .iter()
            .filter_map(|(&id, node)| match &node.graph_node.provenance {
                ProjectDependencyNodeProvenance::Preassembled { requirements, .. } => {
                    Some((id, requirements.clone()))
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        for (id, requirements) in artifacts {
            let scope = graph.slots[id.0].scope;
            let mut edges = Vec::new();
            let mut solver_dependencies = BTreeMap::new();
            for requirement in requirements {
                let target = graph.exact_supply_slot(
                    scope,
                    requirement.name.clone(),
                    requirement.version.clone(),
                    Some(requirement.kind),
                )?;
                let version = VersionRequirement::Exact(requirement.version);
                if !graph.nodes.contains_key(&target) {
                    graph.record_registry_requirement(target, version.clone())?;
                }
                solver_dependencies.insert(target, version);
                edges.push(ProjectDependencyEdge {
                    dependency: target,
                    alias: requirement.name.into_inner(),
                    linkage: Linkage::Dynamic,
                    binding: None,
                    expected_callables: None,
                    source_mount: None,
                });
            }
            let node = graph.nodes.get_mut(&id).expect("inserted artifact node");
            node.graph_node.dependencies = edges;
            node.solver_dependencies = solver_dependencies;
        }
        Ok(())
    }

    fn solve_dependency_graph(
        &self,
        graph: &mut CollectedDependencyGraph,
    ) -> Result<BTreeMap<DependencyInstanceId, Version>, Report> {
        let registry = self.build_resolution_registry(graph)?;
        let selected = PackageResolver::for_package(
            graph.solver_key(graph.root),
            graph.root_version(),
            &registry,
        )
        .resolve()
        .map_err(|error| Report::msg(error.to_string()))?;
        let selected: BTreeMap<_, _> = selected.into_iter().collect();
        Ok((0..graph.slots.len())
            .filter_map(|index| {
                let id = DependencyInstanceId(index);
                selected.get(&graph.solver_key(id)).cloned().map(|version| (id, version))
            })
            .collect())
    }

    fn build_resolution_registry(
        &self,
        graph: &mut CollectedDependencyGraph,
    ) -> Result<InMemoryPackageRegistry, Report> {
        let mut registry = InMemoryPackageRegistry::default();
        for (&id, node) in &graph.nodes {
            let record = PackageRecord::new(
                node.selected_version(),
                node.solver_dependencies
                    .iter()
                    .map(|(&target, requirement)| (graph.solver_key(target), requirement.clone())),
            );
            registry
                .insert_record(graph.solver_key(id), record)
                .map_err(|error| Report::msg(error.to_string()))?;
        }
        let mut pending = graph
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.registry_requirement.as_ref().map(|_| DependencyInstanceId(index))
            })
            .collect::<BTreeSet<_>>();
        let mut copied = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if !copied.insert(id) {
                continue;
            }
            let scope = graph.slots[id.0].scope;
            let name = graph.slots[id.0].name.clone();
            if let Some(versions) = self.registry.available_versions(&name) {
                for record in versions.values() {
                    let mut dependencies = Vec::new();
                    let mut targets = Vec::new();
                    for (name, requirement) in record.dependencies() {
                        let target = match requirement {
                            VersionRequirement::Exact(version) => graph.exact_supply_slot(
                                scope,
                                name.clone(),
                                version.clone(),
                                None,
                            )?,
                            _ => graph.slot_in_scope(scope, name.clone()),
                        };
                        if !graph.nodes.contains_key(&target) {
                            graph.record_registry_requirement(target, requirement.clone())?;
                            if !copied.contains(&target) {
                                pending.insert(target);
                            }
                        } else if !matches!(requirement, VersionRequirement::Exact(version) if graph.nodes[&target].selected_version() == *version)
                        {
                            // A plain registry name cannot silently select a local source/artifact.
                            graph.record_registry_requirement(target, requirement.clone())?;
                        }
                        targets.push(target);
                        dependencies.push((graph.solver_key(target), requirement.clone()));
                    }
                    graph.registry_edges.insert((id, record.semantic_version().clone()), targets);
                    registry
                        .insert_record(
                            graph.solver_key(id),
                            PackageRecord::new(record.version().clone(), dependencies),
                        )
                        .map_err(|error| Report::msg(error.to_string()))?;
                }
            }
        }
        Ok(registry)
    }

    fn materialize_dependency_graph(
        &self,
        collected: CollectedDependencyGraph,
        selected: &BTreeMap<DependencyInstanceId, Version>,
    ) -> Result<ProjectDependencyGraph, Report> {
        let mut nodes = collected
            .nodes
            .iter()
            .map(|(&id, node)| (id, node.graph_node.clone()))
            .collect::<BTreeMap<_, _>>();
        for (&id, version) in selected {
            if nodes.contains_key(&id) {
                continue;
            }
            let slot = &collected.slots[id.0];
            let record = self.registry.get_by_version(&slot.name, version).ok_or_else(|| {
                Report::msg(format!(
                    "resolved registry dependency '{}@{version}' is not available",
                    slot.name
                ))
            })?;
            let mut dependencies = Vec::new();
            let targets = collected
                .registry_edges
                .get(&(id, record.semantic_version().clone()))
                .ok_or_else(|| Report::msg("missing registry dependency instance mapping"))?;
            for ((name, _), &target) in record.dependencies().iter().zip(targets) {
                dependencies.push(ProjectDependencyEdge {
                    dependency: target,
                    alias: name.clone().into_inner(),
                    linkage: Linkage::Dynamic,
                    binding: None,
                    expected_callables: None,
                    source_mount: None,
                });
            }
            nodes.insert(
                id,
                ProjectDependencyNode {
                    dependencies,
                    name: slot.name.clone(),
                    version: record.semantic_version().clone(),
                    provenance: ProjectDependencyNodeProvenance::Registry {
                        requirement: slot
                            .registry_requirement
                            .clone()
                            .unwrap_or_else(|| VersionRequirement::from(version.clone())),
                        selected: version.clone(),
                    },
                },
            );
        }
        Ok(ProjectDependencyGraph { root: collected.root, nodes })
    }

    fn resolve_dependency(
        &self,
        dependency: &Dependency,
        parent: &LoadedSourcePackage,
    ) -> Result<ResolvedDependencyNode, Report> {
        match dependency.scheme() {
            DependencyVersionScheme::Registry(requirement) => {
                Ok(ResolvedDependencyNode::Registry { requirement: requirement.clone() })
            },
            DependencyVersionScheme::Workspace { member, .. } => {
                let workspace_root = parent.workspace_root.as_ref().ok_or_else(|| {
                    Report::msg(format!(
                        "workspace dependency '{}' cannot be resolved outside of a workspace",
                        dependency.package()
                    ))
                })?;
                let path = crate::absolutize_path(Path::new(member.path()), workspace_root)
                    .map_err(|error| Report::msg(error.to_string()))?;
                let package = self.load_dependency_source(&path, dependency.package().as_ref())?;
                self.validate_source_dependency(dependency, &package.package)?;
                Ok(ResolvedDependencyNode::Source {
                    origin: ProjectSourceOrigin::Path,
                    package,
                })
            },
            DependencyVersionScheme::WorkspacePath { path, version } => {
                let workspace_root = parent.workspace_root.as_ref().ok_or_else(|| {
                    Report::msg(format!(
                        "workspace dependency '{}' cannot be resolved outside of a workspace",
                        dependency.package()
                    ))
                })?;
                let resolved_path = crate::absolutize_path(Path::new(path.path()), workspace_root)
                    .map_err(|error| Report::msg(error.to_string()))?;
                if resolved_path.extension().is_some_and(|extension| extension == "masp") {
                    let node = self.load_preassembled_dependency(
                        &resolved_path,
                        dependency.package().as_ref(),
                        version.as_ref(),
                    )?;
                    Ok(ResolvedDependencyNode::Local(node))
                } else {
                    let package =
                        self.load_dependency_source(&resolved_path, dependency.package().as_ref())?;
                    if let Some(requirement) = version.as_ref() {
                        self.ensure_version_satisfies(
                            dependency.package(),
                            requirement,
                            Version::from(package.package.version().into_inner().clone()),
                        )?;
                    }
                    Ok(ResolvedDependencyNode::Source {
                        origin: ProjectSourceOrigin::Path,
                        package,
                    })
                }
            },
            DependencyVersionScheme::Path { path, version } => {
                let Some(parent_manifest_path) = parent.manifest_path.as_ref() else {
                    return Err(Report::msg(format!(
                        "package '{}' is missing a manifest path",
                        parent.package.name().inner()
                    )));
                };
                let resolved_path = self.resolve_dependency_path(parent_manifest_path, path)?;
                if resolved_path.extension().is_some_and(|extension| extension == "masp") {
                    let node = self.load_preassembled_dependency(
                        &resolved_path,
                        dependency.package().as_ref(),
                        version.as_ref(),
                    )?;
                    Ok(ResolvedDependencyNode::Local(node))
                } else {
                    let package =
                        self.load_dependency_source(&resolved_path, dependency.package().as_ref())?;
                    if let Some(requirement) = version.as_ref() {
                        self.ensure_version_satisfies(
                            dependency.package(),
                            requirement,
                            Version::from(package.package.version().into_inner().clone()),
                        )?;
                    }
                    Ok(ResolvedDependencyNode::Source {
                        origin: ProjectSourceOrigin::Path,
                        package,
                    })
                }
            },
            DependencyVersionScheme::Git { repo, revision, version } => {
                let checkout = self.checkout_git_dependency(repo.inner(), revision)?;
                let package = self.load_dependency_source(
                    &checkout.manifest_path,
                    dependency.package().as_ref(),
                )?;
                self.ensure_dependency_name(
                    dependency.package(),
                    package.package.name().into_inner().as_ref(),
                    Some(&checkout.manifest_path),
                )?;
                if let Some(requirement) = version.as_ref() {
                    self.ensure_version_req_matches(
                        dependency.package(),
                        requirement.inner(),
                        package.package.version().into_inner(),
                    )?;
                }
                Ok(ResolvedDependencyNode::Source {
                    origin: ProjectSourceOrigin::Git {
                        checkout_path: checkout.checkout_path,
                        repo: repo.inner().clone(),
                        resolved_revision: checkout.resolved_revision,
                        revision: revision.inner().clone(),
                    },
                    package,
                })
            },
        }
    }

    fn load_dependency_source(
        &self,
        path: &Path,
        expected_name: &str,
    ) -> Result<LoadedSourcePackage, Report> {
        let loaded = self.load_project_reference(path, expected_name)?;
        self.ensure_dependency_name(
            expected_name,
            loaded.package.name().into_inner().as_ref(),
            loaded.manifest_path.as_deref(),
        )?;
        Ok(loaded)
    }

    fn load_project_reference(
        &self,
        path: &Path,
        expected_name: &str,
    ) -> Result<LoadedSourcePackage, Report> {
        let project =
            crate::Project::load_project_reference(expected_name, path, &self.source_manager)?;

        match project {
            crate::Project::Package(package) => self.loaded_package_from_arc(package, None),
            crate::Project::WorkspacePackage { package, workspace } => {
                let workspace_root = workspace.workspace_root().map(Path::to_path_buf);
                self.loaded_package_from_arc(package, workspace_root)
            },
        }
    }

    fn load_package_from_manifest(
        &self,
        manifest_path: &Path,
    ) -> Result<LoadedSourcePackage, Report> {
        let project = crate::Project::load(manifest_path, &self.source_manager)?;

        match project {
            crate::Project::Package(package) => self.loaded_package_from_arc(package, None),
            crate::Project::WorkspacePackage { package, workspace } => {
                let workspace_root = workspace.workspace_root().map(Path::to_path_buf);
                self.loaded_package_from_arc(package, workspace_root)
            },
        }
    }

    fn loaded_package_from_arc(
        &self,
        package: Arc<Package>,
        workspace_root: Option<PathBuf>,
    ) -> Result<LoadedSourcePackage, Report> {
        let manifest_path = package.manifest_path().map(Path::to_path_buf);
        let project_root = match manifest_path.as_ref() {
            Some(manifest_path) => Some(
                manifest_path
                    .parent()
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "manifest '{}' has no parent directory",
                            manifest_path.display()
                        ))
                    })?
                    .to_path_buf(),
            ),
            None => None,
        };

        Ok(LoadedSourcePackage {
            manifest_path,
            package,
            project_root,
            workspace_root,
        })
    }

    fn load_preassembled_dependency(
        &self,
        path: &Path,
        expected_name: &str,
        requirement: Option<&VersionRequirement>,
    ) -> Result<CollectedDependencyNode, Report> {
        let path = path.canonicalize().map_err(|error| Report::msg(error.to_string()))?;
        let bytes = std::fs::read(&path).map_err(|error| Report::msg(error.to_string()))?;
        let package =
            MastPackage::read_from_bytes(&bytes).map_err(|error| Report::msg(error.to_string()))?;
        self.ensure_dependency_name(expected_name, &package.name, Some(&path))?;
        let semver = package.version.clone();
        let selected = Version::new(semver, package.dependency_commitment());
        if let Some(requirement) = requirement {
            self.ensure_version_satisfies(expected_name, requirement, selected.clone())?;
        }

        let requirements = package_requirements(&package);

        Ok(CollectedDependencyNode {
            graph_node: ProjectDependencyNode {
                dependencies: Vec::new(),
                name: PackageId::from(expected_name),
                provenance: ProjectDependencyNodeProvenance::Preassembled {
                    path,
                    selected: selected.clone(),
                    kind: package.kind,
                    requirements,
                },
                version: selected.version,
            },
            solver_dependencies: BTreeMap::new(),
        })
    }

    fn resolve_dependency_path(&self, manifest_path: &Path, uri: &Uri) -> Result<PathBuf, Report> {
        if let Some(scheme) = uri.scheme()
            && scheme != "file"
        {
            return Err(Report::msg(format!(
                "unsupported path dependency scheme '{scheme}' in '{}'",
                manifest_path.display()
            )));
        }
        let base = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;
        crate::absolutize_path(Path::new(uri.path()), base)
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn library_path(
        &self,
        package: &Package,
        manifest_path: &Path,
        allow_missing: bool,
    ) -> Result<Option<PathBuf>, Report> {
        let target = match package.library_target() {
            Some(target) => target,
            None if allow_missing => return Ok(None),
            None => {
                return Err(Report::msg(format!(
                    "dependency '{}' must define a library target",
                    package.name().inner()
                )));
            },
        };

        let project_root = manifest_path.parent().expect("manifest path has a parent");
        let Some(target_path) = target.path.to_path() else {
            return Err(Report::msg(format!(
                "invalid target path: '{}' is not a valid file path",
                target.path
            )));
        };
        Ok(Some(project_root.join(target_path)))
    }

    fn ensure_dependency_name(
        &self,
        expected_name: &str,
        actual_name: &str,
        location: Option<&Path>,
    ) -> Result<(), Report> {
        if expected_name == actual_name {
            Ok(())
        } else if let Some(location) = location {
            Err(Report::msg(format!(
                "dependency '{}' resolved to package '{}' at '{}'",
                expected_name,
                actual_name,
                location.display()
            )))
        } else {
            Err(Report::msg(format!(
                "dependency '{expected_name}' resolved to package '{actual_name}'",
            )))
        }
    }

    fn ensure_version_satisfies(
        &self,
        dependency_name: impl AsRef<str>,
        requirement: &VersionRequirement,
        actual: Version,
    ) -> Result<(), Report> {
        if actual.satisfies(requirement) {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "dependency '{}' requires '{}', but resolved version was '{}'",
                dependency_name.as_ref(),
                requirement,
                actual
            )))
        }
    }

    fn ensure_version_req_matches(
        &self,
        dependency_name: impl AsRef<str>,
        requirement: &miden_package_registry::VersionReq,
        actual: &SemVer,
    ) -> Result<(), Report> {
        if requirement.matches(actual) {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "dependency '{}' requires '{}', but resolved version was '{}'",
                dependency_name.as_ref(),
                requirement,
                actual
            )))
        }
    }

    fn validate_source_dependency(
        &self,
        dependency: &Dependency,
        package: &Package,
    ) -> Result<(), Report> {
        let requirement = dependency.required_version();
        self.ensure_version_satisfies(
            dependency.package(),
            &requirement,
            Version::from(package.version().into_inner().clone()),
        )?;
        Ok(())
    }
}

/// Git dependencies
impl<'a, R: PackageRegistry + ?Sized> ProjectDependencyGraphBuilder<'a, R> {
    fn checkout_git_dependency(
        &self,
        repo: &Uri,
        revision: &GitRevision,
    ) -> Result<GitCheckout, Report> {
        use alloc::vec;

        std::fs::create_dir_all(&self.git_cache_root)
            .map_err(|error| Report::msg(error.to_string()))?;
        let cache_key = format!("{repo}@{revision}");
        let key = hash_string_to_word(cache_key.as_str());
        let checkout_path =
            self.git_cache_root.join(format!("0x{}", DisplayHex::new(&key.as_bytes())));
        if !checkout_path.exists() {
            let mut args = vec!["clone"];
            match revision {
                GitRevision::Branch(name) => {
                    args.extend_from_slice(&["--branch", name.as_ref()]);
                },
                GitRevision::Commit(_) => (),
            };
            args.push(repo.as_str());
            let checkout_path = checkout_path.to_string_lossy();
            args.push(checkout_path.as_ref());
            self.run_git(&args)?;
        } else {
            self.run_git_in(&checkout_path, &["fetch", "--all", "--tags", "--force"])?;
        }

        let target = match revision {
            GitRevision::Branch(branch) => format!("origin/{branch}"),
            GitRevision::Commit(commit) => commit.to_string(),
        };
        self.run_git_in(&checkout_path, &["checkout", "--force", &target])?;
        let resolved_revision = self.run_git_capture(&checkout_path, &["rev-parse", "HEAD"])?;
        let manifest_path = checkout_path.join("miden-project.toml");

        Ok(GitCheckout {
            checkout_path,
            manifest_path,
            resolved_revision: resolved_revision.trim().to_owned().into(),
        })
    }

    fn run_git(&self, args: &[&str]) -> Result<(), Report> {
        let status = Command::new("git")
            .args(args)
            .status()
            .map_err(|error| Report::msg(error.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(Report::msg(format!("git command failed: git {}", args.join(" "))))
        }
    }

    fn run_git_in(&self, dir: &Path, args: &[&str]) -> Result<(), Report> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .map_err(|error| Report::msg(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "git command failed in '{}': git {}: {}",
                dir.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn run_git_capture(&self, dir: &Path, args: &[&str]) -> Result<String, Report> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .map_err(|error| Report::msg(error.to_string()))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(Report::msg(format!(
                "git command failed in '{}': git {}: {}",
                dir.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

#[derive(Clone)]
enum ResolvedDependencyNode {
    Source {
        package: LoadedSourcePackage,
        origin: ProjectSourceOrigin,
    },
    Local(CollectedDependencyNode),
    Registry {
        requirement: VersionRequirement,
    },
}

impl ResolvedDependencyNode {
    fn solver_requirement(&self) -> VersionRequirement {
        match self {
            Self::Source { package, .. } => VersionRequirement::from(Version::from(
                package.package.version().into_inner().clone(),
            )),
            Self::Local(node) => VersionRequirement::from(node.selected_version()),
            Self::Registry { requirement, .. } => requirement.clone(),
        }
    }
}

#[derive(Clone)]
struct LoadedSourcePackage {
    manifest_path: Option<PathBuf>,
    package: Arc<Package>,
    project_root: Option<PathBuf>,
    workspace_root: Option<PathBuf>,
}

struct GitCheckout {
    checkout_path: PathBuf,
    manifest_path: PathBuf,
    resolved_revision: Arc<str>,
}

fn package_requirements(package: &MastPackage) -> Vec<PreassembledDependencyMetadata> {
    package
        .manifest
        .dependencies()
        .map(|dependency| PreassembledDependencyMetadata {
            name: dependency.name.clone(),
            version: Version::new(dependency.version.clone(), dependency.digest),
            kind: dependency.kind,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, string::ToString};
    use core::assert_matches;
    use std::{collections::BTreeMap, fs, sync::Arc};

    use miden_assembly_syntax::{
        ast::Path as AstPath,
        debuginfo::{DefaultSourceManager, Span},
    };
    use miden_core::{serde::Serializable, utils::hash_string_to_word};
    use miden_mast_package::{Package as MastPackage, TargetType};
    use miden_package_registry::{PackageIndex, PackageRecord, PackageRegistry, PackageVersions};
    use tempfile::TempDir;

    use super::*;
    use crate::Target;

    /// A basic in-memory package registry
    #[derive(Default)]
    struct TestRegistry {
        packages: BTreeMap<PackageId, PackageVersions>,
    }

    impl TestRegistry {
        fn insert(&mut self, name: &str, version: Version) {
            let record_version = version;
            self.insert_record(
                PackageId::from(name),
                PackageRecord::new(record_version, std::iter::empty()),
            )
            .expect("failed to insert test package");
        }

        fn insert_record(&mut self, id: PackageId, record: PackageRecord) -> Result<(), Report> {
            use std::collections::btree_map::Entry;

            let semver = record.semantic_version().clone();
            match self.packages.entry(id.clone()).or_default().entry(semver.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(record);
                    Ok(())
                },
                Entry::Occupied(_) => Err(Report::msg(format!(
                    "package '{id}' version '{semver}' is already registered"
                ))),
            }
        }
    }

    impl PackageRegistry for TestRegistry {
        fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
            self.packages.get(package)
        }
    }

    impl PackageIndex for TestRegistry {
        type Error = Report;

        fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
            self.insert_record(name, record)
        }
    }

    fn node_named<'a>(
        graph: &'a ProjectDependencyGraph,
        name: &str,
    ) -> Option<&'a ProjectDependencyNode> {
        let mut matches = graph.nodes().values().filter(|node| node.name == name);
        let node = matches.next();
        assert!(matches.next().is_none(), "fixture expected a unique package named '{name}'");
        node
    }

    fn fixture_dependency(
        name: Span<Arc<str>>,
        version: DependencyVersionScheme,
        linkage: Linkage,
    ) -> Dependency {
        // An explicit graph-fixture choice, independent of package names, versions and bodies.
        Dependency::new(name, version, linkage).with_binding(crate::DependencyBinding::Custom(
            miden_mast_package::NamespacePlan::new(vec![
                miden_core::program::CanonicalLabel::text("project-graph-fixtures").unwrap(),
            ]),
        ))
    }

    #[test]
    fn programmatic_dependency_omission_rejects_before_resolution() {
        let temp = TempDir::new().unwrap();
        let registry = TestRegistry::default();
        let package = crate::Package::new(
            "root",
            crate::Target::library(
                Arc::<miden_assembly_syntax::Path>::from(miden_assembly_syntax::Path::new("root")),
                Uri::new("mod.masm"),
            ),
        )
        .with_dependencies([Dependency::new(
            Span::unknown("missing".into()),
            DependencyVersionScheme::Registry(VersionRequirement::from(crate::VersionReq::STAR)),
            Linkage::Dynamic,
        )]);
        let error = builder(&registry, &temp.path().join("git")).build(package.into()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an explicit Latest/Pinned binding or custom home")
        );
    }

    #[test]
    fn builds_path_dependency_graph() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", "export.foo\nend\n", []);

        let expected = crate::ExpectedVisibleCallables::new([(
            miden_mast_package::CallableProcedurePath::from_semantic_components(vec![
                "dep".into(),
                "foo".into(),
            ])
            .unwrap(),
            miden_mast_package::CallableBinding::new(
                miden_mast_package::NamespacePlan::new(vec![
                    miden_core::program::CanonicalLabel::text("defining-home").unwrap(),
                ]),
                miden_mast_package::CallableProcedurePath::from_semantic_components(vec![
                    "original".into(),
                    "foo".into(),
                ])
                .unwrap(),
            )
            .unwrap(),
        )])
        .unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: None,
                },
                Linkage::Dynamic,
            )
            .with_expected_callables(expected.clone())],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();

        assert!(node_named(&graph, "root").is_some());
        assert!(node_named(&graph, "dep").is_some());
        assert_eq!(node_named(&graph, "root").unwrap().dependencies.len(), 1);
        assert_eq!(
            node_named(&graph, "root").unwrap().dependencies[0].expected_callables,
            Some(expected)
        );
        assert_eq!(
            node_named(&graph, "root").unwrap().dependencies[0].binding,
            Some(crate::DependencyBinding::Custom(miden_mast_package::NamespacePlan::new(vec![
                miden_core::program::CanonicalLabel::text("project-graph-fixtures").unwrap(),
            ])))
        );
    }

    #[test]
    fn path_dependency_without_version_uses_referenced_source_version() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "9.9.9", "export.foo\nend\n", []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version, "9.9.9".parse().unwrap());
    }

    #[test]
    fn path_dependency_version_requirement_must_match_source_version() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", "export.foo\nend\n", []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Semantic(Span::unknown(
                        "=2.0.0".parse().unwrap(),
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("mismatched path dependency version should fail");

        assert!(error.to_string().contains("requires '=2.0.0'"));
    }

    #[test]
    fn path_source_dependency_rejects_digest_requirement() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", "export.foo\nend\n", []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Digest(Span::unknown(hash_string_to_word(
                        "dep-digest",
                    )))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("digest requirements on source paths should fail");

        assert!(error.to_string().contains("resolved version was '1.0.0'"));
    }

    #[test]
    fn path_source_dependency_rejects_exact_published_requirement() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", "export.foo\nend\n", []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Exact(Version::new(
                        "1.0.0".parse().unwrap(),
                        hash_string_to_word("dep-digest"),
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("exact published requirements on source paths should fail");

        assert!(error.to_string().contains("resolved version was '1.0.0'"));
    }

    #[test]
    fn resolves_workspace_root_by_dependency_name() {
        let tempdir = TempDir::new().unwrap();
        let workspace_root = tempdir.path().join("workspace");
        write_file(
            &workspace_root.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\"]\n",
        );
        write_package(&workspace_root.join("dep"), "dep", "1.0.0", "export.foo\nend\n", []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../workspace")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();

        assert!(node_named(&graph, "dep").is_some());
    }

    #[test]
    fn resolves_registry_semver_leaf() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "^1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let mut registry = TestRegistry::default();
        registry.insert("dep", "1.2.0".parse().unwrap());

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_eq!(dep.version, "1.2.0".parse().unwrap());
        assert!(matches!(dep.provenance, ProjectDependencyNodeProvenance::Registry { .. }));
    }

    #[test]
    fn resolves_registry_digest_leaf() {
        let tempdir = TempDir::new().unwrap();
        let digest = hash_string_to_word("dep");
        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Digest(Span::unknown(
                    digest,
                ))),
                Linkage::Dynamic,
            )],
        );

        let mut registry = TestRegistry::default();
        registry.insert("dep", Version::new("1.2.0".parse().unwrap(), digest));

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_eq!(dep.version, "1.2.0".parse().unwrap());
    }

    #[test]
    fn resolves_shared_registry_version_across_source_dependencies() {
        let tempdir = TempDir::new().unwrap();
        let depa_dir = tempdir.path().join("depa");
        let depb_dir = tempdir.path().join("depb");
        write_package(
            &depa_dir,
            "depa",
            "1.0.0",
            "export.call_shared\nend\n",
            [fixture_dependency(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "^1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );
        write_package(
            &depb_dir,
            "depb",
            "1.0.0",
            "export.call_shared\nend\n",
            [fixture_dependency(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=1.2.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                fixture_dependency(
                    Span::unknown("depa".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depa")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
                fixture_dependency(
                    Span::unknown("depb".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depb")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
            ],
        );

        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "1.2.0".parse().unwrap());
        registry.insert("shared", "1.3.0".parse().unwrap());

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect("compatible source dependency requirements should resolve");
        let shared = node_named(&graph, "shared").expect("shared dependency missing");
        assert_eq!(shared.version, "1.2.0".parse().unwrap());
        assert_matches!(
            shared.provenance,
            ProjectDependencyNodeProvenance::Registry { ref selected, .. }
                if selected.version == "1.2.0".parse().unwrap()
        );
    }

    #[test]
    fn rejects_incompatible_shared_registry_version_requirements() {
        let tempdir = TempDir::new().unwrap();
        let depa_dir = tempdir.path().join("depa");
        let depb_dir = tempdir.path().join("depb");
        write_package(
            &depa_dir,
            "depa",
            "1.0.0",
            "export.call_shared\nend\n",
            [fixture_dependency(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );
        write_package(
            &depb_dir,
            "depb",
            "1.0.0",
            "export.call_shared\nend\n",
            [fixture_dependency(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=2.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                fixture_dependency(
                    Span::unknown("depa".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depa")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
                fixture_dependency(
                    Span::unknown("depb".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depb")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
            ],
        );

        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "2.0.0".parse().unwrap());

        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("incompatible source dependency requirements should fail");
        let error = error.to_string();
        assert!(error.contains("dependency resolution failed"));
        assert!(error.contains("shared"));
        assert!(error.contains("1.0.0"));
        assert!(error.contains("2.0.0"));
    }

    #[test]
    fn path_to_masp_is_leaf() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert!(dep.dependencies.is_empty());
        assert!(matches!(dep.provenance, ProjectDependencyNodeProvenance::Preassembled { .. }));
    }

    #[test]
    fn preassembled_path_dependency_accepts_exact_published_requirement() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let digest = package.dependency_commitment();
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Exact(Version::new(
                        "1.0.0".parse().unwrap(),
                        digest,
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version, "1.0.0".parse().unwrap());
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Preassembled {
                ref path,
                ref selected,
                ..
            } if path == &package_path.canonicalize().unwrap()
                && *selected == Version::new("1.0.0".parse().unwrap(), digest)
        );
    }

    #[test]
    fn preassembled_path_dependency_propagates_runtime_dependencies_into_resolution() {
        let tempdir = TempDir::new().unwrap();
        let runtime_package = build_registry_test_package("runtime", "1.0.0");
        let runtime_version =
            Version::new(runtime_package.version.clone(), runtime_package.dependency_commitment());
        let dep_package = MastPackage::generate(
            "dep".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            [miden_mast_package::Dependency {
                name: PackageId::from("runtime"),
                version: runtime_version.version.clone(),
                kind: TargetType::Library,
                digest: runtime_package.dependency_commitment(),
            }],
        );
        let dep_package_path = tempdir.path().join("dep.masp");
        fs::write(&dep_package_path, dep_package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(dep_package_path.as_path())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let mut registry = TestRegistry::default();
        registry
            .insert_record(
                PackageId::from("runtime"),
                PackageRecord::new(runtime_version.clone(), std::iter::empty()),
            )
            .unwrap();

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        let runtime = node_named(&graph, "runtime").unwrap();

        assert_eq!(
            dep.dependencies,
            vec![ProjectDependencyEdge {
                dependency: dep.dependencies[0].dependency,
                alias: "runtime".into(),
                source_mount: None,
                linkage: Linkage::Dynamic,
                binding: None,
                expected_callables: None,
            }]
        );
        assert_matches!(
            runtime.provenance,
            ProjectDependencyNodeProvenance::Registry { ref selected, .. }
                if *selected == runtime_version
        );
    }

    #[test]
    fn preassembled_path_dependency_keeps_embedded_kernel_in_solver_requirements() {
        let tempdir = TempDir::new().unwrap();
        let kernel_package = MastPackage::generate(
            "kernelpkg".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Kernel,
            [],
        );
        let kernel_version =
            Version::new(kernel_package.version.clone(), kernel_package.dependency_commitment());
        let dep_package = MastPackage::generate(
            "dep".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            [miden_mast_package::Dependency {
                name: PackageId::from("kernelpkg"),
                version: kernel_version.version.clone(),
                kind: TargetType::Kernel,
                digest: kernel_package.dependency_commitment(),
            }],
        );

        let dep_package_path = tempdir.path().join("dep.masp");
        fs::write(&dep_package_path, dep_package.to_bytes()).unwrap();

        let registry = TestRegistry::default();
        let node = builder(&registry, &tempdir.path().join("git"))
            .load_preassembled_dependency(&dep_package_path, "dep", None)
            .unwrap();

        assert!(node.graph_node.dependencies.is_empty());
        assert!(node.solver_dependencies.is_empty());
        let ProjectDependencyNodeProvenance::Preassembled { requirements, .. } =
            &node.graph_node.provenance
        else {
            panic!("expected artifact provenance");
        };
        assert_eq!(
            requirements,
            &[PreassembledDependencyMetadata {
                name: PackageId::from("kernelpkg"),
                version: kernel_version,
                kind: TargetType::Kernel,
            }]
        );
    }

    #[test]
    fn preassembled_path_dependency_validates_digest_requirement_against_artifact_digest() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let digest = package.dependency_commitment();
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let ok_root_dir = tempdir.path().join("root-ok");
        let ok_manifest = write_package(
            &ok_root_dir,
            "root-ok",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Digest(Span::unknown(digest))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&ok_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_eq!(dep.version, "1.0.0".parse().unwrap());

        let bad_root_dir = tempdir.path().join("root-bad");
        let bad_manifest = write_package(
            &bad_root_dir,
            "root-bad",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Digest(Span::unknown(hash_string_to_word(
                        "wrong-digest",
                    )))),
                },
                Linkage::Dynamic,
            )],
        );

        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&bad_manifest)
            .expect_err("mismatched digest requirement should fail for preassembled packages");

        assert!(error.to_string().contains("resolved version was '1.0.0#"));
    }

    #[test]
    fn resolves_git_dependency_using_local_repo() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", "export.foo\nend\n", []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Git { .. },
                ..
            })
        );
    }

    #[test]
    fn resolves_commit_pinned_git_dependency_after_repo_advances() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", "export.foo\nend\n", []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);
        let initial_revision = run_git_capture(&repo_dir, &["rev-parse", "HEAD"]);

        write_package(&repo_dir, "dep", "2.0.0", "export.foo\nend\n", []);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "change"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Commit(initial_revision.clone().into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version, "1.0.0".parse().unwrap());
        assert_matches!(
            &dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Git {
                    revision,
                    resolved_revision,
                    ..
                },
                ..
            }) if *revision == GitRevision::Commit(initial_revision.clone().into())
                && resolved_revision.as_ref() == initial_revision
        );
    }

    #[test]
    fn git_dependency_without_version_uses_checked_out_source_version() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "9.9.9", "export.foo\nend\n", []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version, "9.9.9".parse().unwrap());
    }

    #[test]
    fn git_dependency_version_requirement_must_match_checked_out_source_version() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", "export.foo\nend\n", []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            [fixture_dependency(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: Some(Span::unknown("=2.0.0".parse().unwrap())),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .expect_err("mismatched git dependency version should fail");

        assert!(error.to_string().contains("requires '=2.0.0'"));
    }

    #[test]
    fn workspace_dependency_stays_on_the_workspace_member_version() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(root_dir.join("dep")).unwrap();
        fs::create_dir_all(root_dir.join("app")).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\", \"app\"]\n\n[workspace.dependencies]\ndep = { path = \"dep\", binding = { selection = \"custom\", home = [] } }\n",
        );
        write_file(
            &root_dir.join("dep").join("miden-project.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"\n",
        );
        let app_manifest = root_dir.join("app").join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let mut registry = TestRegistry::default();
        let dep_id = PackageId::from("dep");
        let version010 = "0.1.0".parse::<SemVer>().unwrap();
        let version999 = "9.9.9".parse::<SemVer>().unwrap();
        registry.insert(&dep_id, Version::from(version010));
        registry.insert(&dep_id, Version::from(version999));
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_eq!(dep.version.to_string(), "0.2.0");
    }

    #[test]
    fn workspace_dependency_rejects_mismatched_workspace_requirement() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(root_dir.join("dep")).unwrap();
        fs::create_dir_all(root_dir.join("app")).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\", \"app\"]\n\n[workspace.dependencies]\ndep = { path = \"dep\", version = \"=0.1.0\", binding = { selection = \"custom\", home = [] } }\n",
        );
        write_file(
            &root_dir.join("dep").join("miden-project.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"\n",
        );
        let app_manifest = root_dir.join("app").join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .expect_err("mismatched workspace dependency version should fail");
        assert!(error.to_string().contains("requires '=0.1.0'"));
        assert!(error.to_string().contains("resolved version was '0.2.0'"));
    }

    #[test]
    fn non_member_path_dependency_inside_workspace_root_is_resolved_by_path() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        let app_dir = root_dir.join("app");
        let dep_dir = root_dir.join("vendor").join("dep");
        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&dep_dir).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\ndep = { path = \"vendor/dep\", binding = { selection = \"custom\", home = [] } }\n",
        );
        write_package(&dep_dir, "dep", "0.3.0", "export.foo\nend\n", []);
        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version.to_string(), "0.3.0");
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Path,
                workspace_root: None,
                ..
            })
        );
    }

    #[test]
    fn preassembled_path_dependency_inside_workspace_root_is_not_treated_as_workspace_member() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        let app_dir = root_dir.join("app");
        let artifacts_dir = root_dir.join("artifacts");
        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&artifacts_dir).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\ndep = { path = \"artifacts/dep.masp\", binding = { selection = \"custom\", home = [] } }\n",
        );
        let dep_package = build_registry_test_package("dep", "1.0.0");
        let dep_package_path = artifacts_dir.join("dep.masp");
        fs::write(&dep_package_path, dep_package.to_bytes()).unwrap();
        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = node_named(&graph, "dep").unwrap();

        assert_eq!(dep.version.to_string(), "1.0.0");
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Preassembled { ref path, .. }
                if path == &dep_package_path.canonicalize().unwrap()
        );
    }

    fn pinned_binding(revision: u32) -> crate::DependencyBinding {
        crate::DependencyBinding::Standard(crate::LibraryImport::new(
            miden_mast_package::NamespacePlan::new(vec![]),
            hash_string_to_word("same-opaque-library-id"),
            crate::LibrarySelection::Pinned(core::num::NonZeroU32::new(revision).unwrap()),
        ))
    }

    fn dependency_at(alias: &str, package: &str, path: &str) -> Dependency {
        fixture_dependency(
            Span::unknown(Arc::from(alias)),
            DependencyVersionScheme::Path {
                path: Span::unknown(Uri::new(path)),
                version: None,
            },
            Linkage::Dynamic,
        )
        .with_package(package)
    }

    fn registry_dependency(alias: &str, package: &str, version: &str) -> Dependency {
        fixture_dependency(
            Span::unknown(Arc::from(alias)),
            DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                version.parse().unwrap(),
            ))),
            Linkage::Dynamic,
        )
        .with_package(package)
    }

    #[test]
    fn same_source_package_under_distinct_pinned_homes_and_mounts_has_distinct_instances() {
        use miden_assembly_syntax::Path as MasmPath;
        let temp = TempDir::new().unwrap();
        write_package(
            &temp.path().join("source"),
            "dep",
            "1.0.0",
            "export.foo\n    push.7\nend\n",
            [],
        );
        let left_mount =
            crate::PackageSourceMount::new(MasmPath::new("::dep"), MasmPath::new("::left"))
                .unwrap();
        let right_mount =
            crate::PackageSourceMount::new(MasmPath::new("::dep"), MasmPath::new("::right"))
                .unwrap();
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                dependency_at("left", "dep", "../source")
                    .with_binding(pinned_binding(1))
                    .with_source_mount(left_mount.clone()),
                dependency_at("right", "dep", "../source")
                    .with_binding(pinned_binding(2))
                    .with_source_mount(right_mount.clone()),
            ],
        );
        let registry = TestRegistry::default();
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let root = graph.get(graph.root()).unwrap();
        assert_eq!(graph.nodes().len(), 3);
        let [left, right] = root.dependencies.as_slice() else {
            panic!("expected two imports")
        };
        assert_ne!(left.dependency, right.dependency);
        assert_eq!(left.alias.as_ref(), "left");
        assert_eq!(right.alias.as_ref(), "right");
        assert_eq!(left.source_mount, Some(left_mount));
        assert_eq!(right.source_mount, Some(right_mount));
        assert_eq!(left.binding, Some(pinned_binding(1)));
        assert_eq!(right.binding, Some(pinned_binding(2)));
        let left_node = graph.get(&left.dependency).unwrap();
        let right_node = graph.get(&right.dependency).unwrap();
        assert_eq!(left_node.name, PackageId::from("dep"));
        assert_eq!(left_node.version, right_node.version);
        assert_eq!(left_node.provenance, right_node.provenance);
    }

    #[test]
    fn aliased_registry_selections_and_transitive_closures_resolve_independently() {
        let temp = TempDir::new().unwrap();
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                registry_dependency("left", "dep", "=1.0.0"),
                registry_dependency("right", "dep", "=2.0.0"),
            ],
        );
        let mut registry = TestRegistry::default();
        for version in ["1.0.0", "2.0.0"] {
            registry
                .insert_record(
                    PackageId::from("dep"),
                    PackageRecord::new(
                        version.parse::<Version>().unwrap(),
                        [(
                            PackageId::from("helper"),
                            VersionRequirement::Semantic(Span::unknown(
                                format!("={version}").parse().unwrap(),
                            )),
                        )],
                    ),
                )
                .unwrap();
            registry.insert("helper", version.parse().unwrap());
        }
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let root = graph.get(graph.root()).unwrap();
        let left = graph.get(&root.dependencies[0].dependency).unwrap();
        let right = graph.get(&root.dependencies[1].dependency).unwrap();
        assert_eq!(left.version, "1.0.0".parse().unwrap());
        assert_eq!(right.version, "2.0.0".parse().unwrap());
        let left_helper = graph.get(&left.dependencies[0].dependency).unwrap();
        let right_helper = graph.get(&right.dependencies[0].dependency).unwrap();
        assert_eq!(left_helper.version, left.version);
        assert_eq!(right_helper.version, right.version);
        assert_ne!(left.dependencies[0].dependency, right.dependencies[0].dependency);
    }

    #[test]
    fn distinct_unaliased_binding_contexts_can_select_incompatible_package_versions() {
        let temp = TempDir::new().unwrap();
        for (source, version, revision) in [("a", "=1.0.0", 1), ("b", "=2.0.0", 2)] {
            write_package(
                &temp.path().join(source),
                source,
                "1.0.0",
                "export.entry\nend\n",
                [registry_dependency("shared", "shared", version)
                    .with_binding(pinned_binding(revision))],
            );
        }
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("a", "a", "../a"), dependency_at("b", "b", "../b")],
        );
        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "2.0.0".parse().unwrap());
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let a = node_named(&graph, "a").unwrap();
        let b = node_named(&graph, "b").unwrap();
        assert_ne!(a.dependencies[0].dependency, b.dependencies[0].dependency);
        assert_eq!(
            graph.get(&a.dependencies[0].dependency).unwrap().version,
            "1.0.0".parse().unwrap()
        );
        assert_eq!(
            graph.get(&b.dependencies[0].dependency).unwrap().version,
            "2.0.0".parse().unwrap()
        );
    }

    #[test]
    fn wrapper_order_does_not_choose_which_explicit_binding_shares_parent_constraints() {
        let temp = TempDir::new().unwrap();
        let mut registry = TestRegistry::default();
        for version in ["1.0.0", "2.0.0"] {
            registry
                .insert_record(
                    "shared".into(),
                    PackageRecord::new(
                        version.parse::<Version>().unwrap(),
                        [(
                            "helper".into(),
                            VersionRequirement::Semantic(Span::unknown(
                                format!("={version}").parse().unwrap(),
                            )),
                        )],
                    ),
                )
                .unwrap();
            registry.insert("helper", version.parse().unwrap());
        }
        for same_binding in [false, true] {
            // The manifest writer orders dependency table keys, so renaming the wrappers swaps
            // which binding discovery encounters first without changing the requested supplies.
            for (first_version, second_version) in [("1.0.0", "2.0.0"), ("2.0.0", "1.0.0")] {
                for (wrapper, version) in [("a", first_version), ("b", second_version)] {
                    let revision = if same_binding || version == "1.0.0" { 1 } else { 2 };
                    write_package(
                        &temp.path().join(wrapper),
                        wrapper,
                        "1.0.0",
                        "export.entry\nend\n",
                        [registry_dependency("shared", "shared", &format!("={version}"))
                            .with_binding(pinned_binding(revision))],
                    );
                }
                let manifest = write_package(
                    &temp.path().join("app"),
                    "root",
                    "1.0.0",
                    "export.entry\nend\n",
                    [
                        dependency_at("a", "a", "../a"),
                        dependency_at("b", "b", "../b"),
                        registry_dependency("helper", "helper", "=1.0.0"),
                    ],
                );
                let result = builder(&registry, &temp.path().join("git")).build_from_path(manifest);
                if same_binding {
                    let error = result
                        .expect_err("ordinary same-binding constraints must intersect")
                        .to_string();
                    assert!(error.contains("dependency resolution failed"));
                    assert!(error.contains("shared"));
                    assert!(error.contains("1.0.0"));
                    assert!(error.contains("2.0.0"));
                    continue;
                }
                let graph = result
                    .expect("distinct explicit bindings must isolate every variant symmetrically");
                let root = graph.get(graph.root()).unwrap();
                let parent_helper = root
                    .dependencies
                    .iter()
                    .find(|edge| edge.alias.as_ref() == "helper")
                    .unwrap()
                    .dependency;
                assert_eq!(graph.get(&parent_helper).unwrap().version, "1.0.0".parse().unwrap());
                for (wrapper, version) in [("a", first_version), ("b", second_version)] {
                    let wrapper = node_named(&graph, wrapper).unwrap();
                    let shared = graph.get(&wrapper.dependencies[0].dependency).unwrap();
                    let helper = graph.get(&shared.dependencies[0].dependency).unwrap();
                    assert_eq!(shared.version, version.parse().unwrap());
                    assert_eq!(helper.version, shared.version);
                    assert_ne!(shared.dependencies[0].dependency, parent_helper);
                }
            }
        }
    }

    #[test]
    fn splitting_source_parents_does_not_leave_obsolete_descendant_isolation() {
        let temp = TempDir::new().unwrap();
        for (path, binding) in [("one", pinned_binding(1)), ("two", pinned_binding(2))] {
            write_package(
                &temp.path().join(path),
                "outer",
                "1.0.0",
                "export.entry\nend\n",
                [registry_dependency("helper", "helper", "=1.0.0").with_binding(binding)],
            );
        }
        write_package(
            &temp.path().join("a"),
            "a",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("outer", "outer", "../one").with_binding(pinned_binding(1))],
        );
        write_package(
            &temp.path().join("b"),
            "b",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("outer", "outer", "../two").with_binding(pinned_binding(2))],
        );
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                dependency_at("a", "a", "../a"),
                dependency_at("b", "b", "../b"),
                registry_dependency("helper", "helper", "=1.0.0"),
                registry_dependency("peer", "peer", "=1.0.0"),
            ],
        );
        let mut registry = TestRegistry::default();
        registry.insert("helper", "1.0.0".parse().unwrap());
        registry.insert("helper", "2.0.0".parse().unwrap());
        registry
            .insert_record(
                "peer".into(),
                PackageRecord::new(
                    "1.0.0".parse::<Version>().unwrap(),
                    [(
                        "helper".into(),
                        VersionRequirement::Semantic(Span::unknown("=2.0.0".parse().unwrap())),
                    )],
                ),
            )
            .unwrap();
        let error = builder(&registry, &temp.path().join("git"))
            .build_from_path(manifest)
            .expect_err("root helper and peer's helper still share ordinary constraints")
            .to_string();
        assert!(error.contains("dependency resolution failed"));
        assert!(error.contains("helper"));
        assert!(error.contains("1.0.0"));
        assert!(error.contains("2.0.0"));
    }

    fn assert_binding_context_ambiguity_rejects_and_explicit_aliases_resolve(names: &[&str]) {
        let temp = TempDir::new().unwrap();
        for (index, name) in names.iter().enumerate() {
            let next = names[(index + 1) % names.len()];
            write_package(
                &temp.path().join(format!("{name}-leaf")),
                name,
                "1.0.0",
                "export.entry\nend\n",
                [],
            );
            write_package(
                &temp.path().join(format!("{name}-parent")),
                name,
                "1.0.0",
                "export.entry\nend\n",
                [dependency_at(next, next, &format!("../{next}-leaf"))
                    .with_binding(pinned_binding(2))],
            );
        }
        let registry = TestRegistry::default();
        let make_root = |aliased: bool| {
            write_package(
                &temp.path().join("app"),
                "root",
                "1.0.0",
                "export.entry\nend\n",
                names.iter().map(|name| {
                    let alias = if aliased {
                        format!("explicit_{name}")
                    } else {
                        (*name).into()
                    };
                    dependency_at(&alias, name, &format!("../{name}-parent"))
                        .with_binding(pinned_binding(1))
                }),
            )
        };
        let manifest = make_root(false);
        for _ in 0..2 {
            let error = builder(&registry, &temp.path().join("git"))
                .build_from_path(&manifest)
                .expect_err("competing contexts must reject without unbounded discovery")
                .to_string();
            assert_eq!(
                error,
                "ambiguous dependency binding contexts; use explicit dependency aliases to select independent contexts"
            );
        }
        let graph = builder(&registry, &temp.path().join("git"))
            .build_from_path(make_root(true))
            .expect("explicit source aliases select independent contexts");
        assert_eq!(graph.nodes().len(), 1 + names.len() * 2);
    }

    #[test]
    fn acyclic_diamond_binding_context_ambiguity_rejects_deterministically() {
        assert_binding_context_ambiguity_rejects_and_explicit_aliases_resolve(&["a", "b"]);
    }

    #[test]
    fn acyclic_three_name_binding_context_ambiguity_rejects_deterministically() {
        assert_binding_context_ambiguity_rejects_and_explicit_aliases_resolve(&["x", "y", "z"]);
    }

    #[test]
    fn aliases_belong_to_the_declaring_instance_instead_of_the_shared_resolution_scope() {
        let temp = TempDir::new().unwrap();
        for (source, version) in [("a", "=1.0.0"), ("b", "=2.0.0")] {
            write_package(
                &temp.path().join(source),
                source,
                "1.0.0",
                "export.entry\nend\n",
                [registry_dependency("local", "shared", version)],
            );
        }
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("a", "a", "../a"), dependency_at("b", "b", "../b")],
        );
        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "2.0.0".parse().unwrap());
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let a = node_named(&graph, "a").unwrap();
        let b = node_named(&graph, "b").unwrap();
        assert_ne!(a.dependencies[0].dependency, b.dependencies[0].dependency);
        assert_eq!(
            graph.get(&a.dependencies[0].dependency).unwrap().version,
            "1.0.0".parse().unwrap()
        );
        assert_eq!(
            graph.get(&b.dependencies[0].dependency).unwrap().version,
            "2.0.0".parse().unwrap()
        );
    }

    #[test]
    fn unaliased_same_binding_conflicting_source_provenance_still_rejects() {
        let temp = TempDir::new().unwrap();
        write_package(&temp.path().join("one"), "shared", "1.0.0", "export.foo\nend\n", []);
        write_package(&temp.path().join("two"), "shared", "1.0.0", "export.foo\nend\n", []);
        for (source, target) in [("a", "../one"), ("b", "../two")] {
            write_package(
                &temp.path().join(source),
                source,
                "1.0.0",
                "export.entry\nend\n",
                [dependency_at("shared", "shared", target)],
            );
        }
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("a", "a", "../a"), dependency_at("b", "b", "../b")],
        );
        let registry = TestRegistry::default();
        let error = builder(&registry, &temp.path().join("git"))
            .build_from_path(manifest)
            .unwrap_err();
        assert!(error.to_string().contains("dependency conflict for 'shared'"));
    }

    #[test]
    fn alias_and_binding_changing_source_cycle_rejects_before_context_expansion() {
        let temp = TempDir::new().unwrap();
        let manifest = write_package(
            &temp.path().join("a"),
            "a",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("other", "b", "../b").with_binding(pinned_binding(1))],
        );
        write_package(
            &temp.path().join("b"),
            "b",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("again", "a", "../a").with_binding(pinned_binding(2))],
        );
        let registry = TestRegistry::default();
        let error = builder(&registry, &temp.path().join("git"))
            .build_from_path(manifest)
            .unwrap_err();
        assert!(error.to_string().contains("cyclic source dependency"));
    }

    #[test]
    fn registry_cycles_keep_a_finite_instance_context() {
        let temp = TempDir::new().unwrap();
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [registry_dependency("alias", "dep", "=1.0.0")],
        );
        let mut registry = TestRegistry::default();
        for (name, dependency) in [("dep", "helper"), ("helper", "dep")] {
            registry
                .insert_record(
                    PackageId::from(name),
                    PackageRecord::new(
                        "1.0.0".parse::<Version>().unwrap(),
                        [(
                            PackageId::from(dependency),
                            VersionRequirement::Semantic(Span::unknown("=1.0.0".parse().unwrap())),
                        )],
                    ),
                )
                .unwrap();
        }
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        assert_eq!(graph.nodes().len(), 3);
        let dep = graph.get(&graph.get(graph.root()).unwrap().dependencies[0].dependency).unwrap();
        let helper = graph.get(&dep.dependencies[0].dependency).unwrap();
        assert_eq!(graph.get(&helper.dependencies[0].dependency).unwrap(), dep);
    }

    #[test]
    fn preassembled_duplicate_name_supplies_keep_exact_versions_and_independent_closures() {
        let temp = TempDir::new().unwrap();
        let supplies =
            ["1.0.0", "2.0.0"].map(|version| build_registry_test_package("runtime", version));
        let artifact = MastPackage::generate(
            "dep".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            supplies.iter().map(|supply| miden_mast_package::Dependency {
                name: supply.name.clone(),
                version: supply.version.clone(),
                kind: supply.kind,
                digest: supply.dependency_commitment(),
            }),
        );
        let artifact_path = temp.path().join("dep.masp");
        fs::write(&artifact_path, artifact.to_bytes()).unwrap();
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [dependency_at("dep", "dep", artifact_path.to_str().unwrap())],
        );
        let mut registry = TestRegistry::default();
        for supply in &supplies {
            registry
                .insert_record(
                    "runtime".into(),
                    PackageRecord::new(
                        Version::new(supply.version.clone(), supply.dependency_commitment()),
                        [(
                            "helper".into(),
                            VersionRequirement::Semantic(Span::unknown(
                                format!("={}", supply.version).parse().unwrap(),
                            )),
                        )],
                    ),
                )
                .unwrap();
            registry.insert("helper", Version::from(supply.version.clone()));
        }
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        let ProjectDependencyNodeProvenance::Preassembled { requirements, .. } = &dep.provenance
        else {
            panic!("expected artifact")
        };
        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0].name, requirements[1].name);
        assert_ne!(requirements[0].version, requirements[1].version);
        assert_eq!(dep.dependencies.len(), 2);
        let first = graph.get(&dep.dependencies[0].dependency).unwrap();
        let second = graph.get(&dep.dependencies[1].dependency).unwrap();
        assert_ne!(first.version, second.version);
        assert_eq!(graph.get(&first.dependencies[0].dependency).unwrap().version, first.version);
        assert_eq!(graph.get(&second.dependencies[0].dependency).unwrap().version, second.version);
    }

    #[test]
    fn exact_same_semver_supplies_use_full_local_commitments_instead_of_registry_name_lookup() {
        let temp = TempDir::new().unwrap();
        let leaf = build_registry_test_package("leaf", "1.0.0");
        let first = build_registry_test_package("runtime", "1.0.0");
        let second = MastPackage::generate(
            "runtime".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            [miden_mast_package::Dependency {
                name: "leaf".into(),
                version: leaf.version.clone(),
                kind: leaf.kind,
                digest: leaf.dependency_commitment(),
            }],
        );
        assert_eq!(first.mast_forest().commitment(), second.mast_forest().commitment());
        assert_ne!(first.dependency_commitment(), second.dependency_commitment());
        let artifact = MastPackage::generate(
            "dep".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            [&first, &second].into_iter().map(|supply| miden_mast_package::Dependency {
                name: supply.name.clone(),
                version: supply.version.clone(),
                kind: supply.kind,
                digest: supply.dependency_commitment(),
            }),
        );
        for (path, artifact) in
            [("dep.masp", &artifact), ("one.masp", &first), ("two.masp", &second)]
        {
            fs::write(temp.path().join(path), artifact.to_bytes()).unwrap();
        }
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [
                dependency_at("dep", "dep", "../dep.masp"),
                dependency_at("one", "runtime", "../one.masp"),
                dependency_at("two", "runtime", "../two.masp"),
            ],
        );
        let mut registry = TestRegistry::default();
        registry.insert("leaf", Version::new(leaf.version.clone(), leaf.dependency_commitment()));
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let root = graph.get(graph.root()).unwrap();
        let dep = graph.get(&root.dependencies[0].dependency).unwrap();
        let expected = [root.dependencies[1].dependency, root.dependencies[2].dependency]
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            dep.dependencies.iter().map(|edge| edge.dependency).collect::<BTreeSet<_>>(),
            expected
        );
        let ProjectDependencyNodeProvenance::Preassembled { requirements, .. } = &dep.provenance
        else {
            panic!("expected artifact")
        };
        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0].name, requirements[1].name);
        assert_eq!(requirements[0].version.version, requirements[1].version.version);
        assert_ne!(requirements[0].version.digest, requirements[1].version.digest);
    }

    #[test]
    fn registry_records_preserve_same_name_exact_supply_instances() {
        let temp = TempDir::new().unwrap();
        let manifest = write_package(
            &temp.path().join("app"),
            "root",
            "1.0.0",
            "export.entry\nend\n",
            [registry_dependency("dep", "dep", "=1.0.0")],
        );
        let mut registry = TestRegistry::default();
        let first = Version::new("1.0.0".parse().unwrap(), hash_string_to_word("runtime one"));
        let second = Version::new("2.0.0".parse().unwrap(), hash_string_to_word("runtime two"));
        registry
            .insert_record(
                "dep".into(),
                PackageRecord::new(
                    "1.0.0".parse::<Version>().unwrap(),
                    [
                        ("runtime".into(), VersionRequirement::Exact(first.clone())),
                        ("runtime".into(), VersionRequirement::Exact(second.clone())),
                    ],
                ),
            )
            .unwrap();
        for version in [&first, &second] {
            registry
                .insert_record(
                    "runtime".into(),
                    PackageRecord::new(
                        version.clone(),
                        [(
                            "helper".into(),
                            VersionRequirement::Semantic(Span::unknown(
                                format!("={}", version.version).parse().unwrap(),
                            )),
                        )],
                    ),
                )
                .unwrap();
            registry.insert("helper", Version::from(version.version.clone()));
        }
        let graph = builder(&registry, &temp.path().join("git")).build_from_path(manifest).unwrap();
        let dep = node_named(&graph, "dep").unwrap();
        assert_eq!(dep.dependencies.len(), 2);
        assert_ne!(dep.dependencies[0].dependency, dep.dependencies[1].dependency);
        let first_node = graph.get(&dep.dependencies[0].dependency).unwrap();
        let second_node = graph.get(&dep.dependencies[1].dependency).unwrap();
        assert_eq!(first_node.version, first.version);
        assert_eq!(second_node.version, second.version);
        assert_eq!(
            graph.get(&first_node.dependencies[0].dependency).unwrap().version,
            first.version
        );
        assert_eq!(
            graph.get(&second_node.dependencies[0].dependency).unwrap().version,
            second.version
        );
    }

    // ------ TEST UTILS

    fn build_registry_test_package(name: &str, version: &str) -> Box<MastPackage> {
        MastPackage::generate(name.into(), version.parse().unwrap(), TargetType::Library, [])
    }

    fn write_package(
        dir: &Path,
        name: &str,
        version: &str,
        module_body: &str,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> PathBuf {
        let target = Target::library(AstPath::new(name), "lib/mod.masm".into());
        let manifest = Package::new(name, target)
            .with_version(version.parse().unwrap())
            .with_dependencies(dependencies);

        let manifest = manifest.to_toml().unwrap();
        let manifest_path = dir.join("miden-project.toml");
        write_file(&manifest_path, &manifest);
        write_file(&dir.join("lib/mod.masm"), module_body);
        manifest_path
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {} failed in '{}': {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_git_capture(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {} failed in '{}': {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn builder<'a, R: PackageRegistry + ?Sized>(
        registry: &'a R,
        git_cache_root: &Path,
    ) -> ProjectDependencyGraphBuilder<'a, R> {
        ProjectDependencyGraphBuilder::new(registry)
            .with_git_cache_root(git_cache_root)
            .with_source_manager(Arc::new(DefaultSourceManager::default()))
    }
}
