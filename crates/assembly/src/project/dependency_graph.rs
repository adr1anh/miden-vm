use alloc::{collections::BTreeSet, format, string::ToString, sync::Arc, vec::Vec};
use std::path::Path as FsPath;

use miden_assembly_syntax::{
    Path, PathComponent,
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core::{Word, chiplets::hasher, serde::Serializable, utils::hash_string_to_word};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};
use miden_package_registry::{PackageRegistry, PackageRegistryAndProvider, Version};
use miden_project::{
    DependencyBinding, DependencyInstanceId, Linkage, Package as ProjectPackage,
    ProjectDependencyEdge, ProjectDependencyGraph, ProjectDependencyGraphBuilder,
    ProjectDependencyNode, ProjectDependencyNodeProvenance, ProjectSource, ProjectSourceOrigin,
    Target,
};

use super::{
    PackageBuildProvenance, PackageBuildSettings, ProjectSourceProvenanceInputs,
    SourceProviderRegistry, providers::TargetAssemblyContext,
};
use crate::SourceManager;

// DEPENDENCY GRAPH
// ================================================================================================

pub(super) struct DependencyGraph {
    dependency_graph: ProjectDependencyGraph,
    source_manager: Arc<dyn SourceManager>,
}

/// Private build-cache material, independent of graph slot allocation and callable identity.
///
/// Sort complete logical records rather than slot IDs. Duplicate edges remain significant, and
/// full typed homes and semantic path components retain their byte and component boundaries.
fn hash_dependency_records(mut dependencies: Vec<Vec<u8>>) -> Result<Word, Report> {
    if dependencies.is_empty() {
        return Ok(PackageBuildProvenance::empty_dependency_hash());
    }
    dependencies.sort();
    let mut material = b"miden.assembly.dependency-closure.v2".to_vec();
    append_provenance_len(&mut material, dependencies.len())?;
    for dependency in dependencies {
        append_provenance_bytes(&mut material, &dependency)?;
    }
    Ok(hasher::hash(&material))
}

fn dependency_edge_hash_input(edge: &ProjectDependencyEdge) -> Result<Vec<u8>, Report> {
    let mut material = Vec::new();
    append_provenance_bytes(&mut material, edge.alias.as_bytes())?;
    material.push(match edge.linkage {
        Linkage::Static => 0,
        Linkage::Dynamic => 1,
    });
    match &edge.binding {
        None => material.push(0),
        Some(binding) => {
            material.push(match binding {
                DependencyBinding::Standard(_) => 1,
                DependencyBinding::Custom(_) => 2,
            });
            append_provenance_home(&mut material, &binding.namespace_plan())?;
        },
    }
    match &edge.expected_callables {
        None => material.push(0),
        Some(expected) => {
            material.push(1);
            append_provenance_len(&mut material, expected.mappings().len())?;
            for (visible, binding) in expected.mappings() {
                append_provenance_callable_path(&mut material, visible)?;
                append_provenance_home(&mut material, binding.namespace_plan())?;
                append_provenance_callable_path(&mut material, binding.path())?;
            }
        },
    }
    match &edge.source_mount {
        None => material.push(0),
        Some(mount) => {
            material.push(1);
            append_provenance_source_path(&mut material, mount.package_base())?;
            append_provenance_source_path(&mut material, mount.source_base())?;
        },
    }
    Ok(material)
}

// Match the compiler cache's length/byte framing, without invoking an interchange profile or
// revalidating externally admitted TypedId labels during this private cache calculation.
fn append_provenance_len(material: &mut Vec<u8>, len: usize) -> Result<(), Report> {
    let len =
        u64::try_from(len).map_err(|_| Report::msg("dependency provenance length exceeds u64"))?;
    material.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn append_provenance_bytes(material: &mut Vec<u8>, value: &[u8]) -> Result<(), Report> {
    append_provenance_len(material, value.len())?;
    material.extend_from_slice(value);
    Ok(())
}

fn append_provenance_version(material: &mut Vec<u8>, version: &Version) -> Result<(), Report> {
    append_provenance_bytes(material, version.version.to_string().as_bytes())?;
    match version.digest {
        Some(digest) => {
            material.push(1);
            material.extend_from_slice(&digest.as_bytes());
        },
        None => material.push(0),
    }
    Ok(())
}

fn append_provenance_home(material: &mut Vec<u8>, home: &NamespacePlan) -> Result<(), Report> {
    append_provenance_len(material, home.home().len())?;
    for label in home.home() {
        append_provenance_bytes(material, label.as_bytes())?;
    }
    Ok(())
}

fn append_provenance_callable_path(
    material: &mut Vec<u8>,
    path: &CallableProcedurePath,
) -> Result<(), Report> {
    append_provenance_len(material, path.components().len())?;
    for component in path.components() {
        append_provenance_bytes(material, component.as_bytes())?;
    }
    Ok(())
}

fn append_provenance_source_path(material: &mut Vec<u8>, path: &Path) -> Result<(), Report> {
    let components = path.components().collect::<Result<Vec<_>, _>>().into_diagnostic()?;
    append_provenance_len(material, components.len())?;
    for component in components {
        match component {
            PathComponent::Root => material.push(0),
            PathComponent::Normal(_) => {
                material.push(1);
                append_provenance_bytes(material, component.as_str().as_bytes())?;
            },
        }
    }
    Ok(())
}

impl AsRef<ProjectDependencyGraph> for DependencyGraph {
    #[inline(always)]
    fn as_ref(&self) -> &ProjectDependencyGraph {
        &self.dependency_graph
    }
}

impl DependencyGraph {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn from_project_path<S: PackageRegistry + ?Sized>(
        manifest_path: impl AsRef<FsPath>,
        store: &S,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        let dependency_graph = ProjectDependencyGraphBuilder::new(store)
            .with_source_manager(source_manager.clone())
            .build_from_path(manifest_path)?;

        Ok(Self { dependency_graph, source_manager })
    }

    pub fn from_project<S: PackageRegistry + ?Sized>(
        project: Arc<ProjectPackage>,
        store: &S,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        let dependency_graph_builder =
            ProjectDependencyGraphBuilder::new(store).with_source_manager(source_manager.clone());
        let dependency_graph = if let Some(manifest_path) = project.manifest_path() {
            dependency_graph_builder.build_from_path(manifest_path)?
        } else {
            dependency_graph_builder.build(project)?
        };

        Ok(Self { dependency_graph, source_manager })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn root(&self) -> &DependencyInstanceId {
        self.dependency_graph.root()
    }

    pub fn get(&self, instance: &DependencyInstanceId) -> Result<&ProjectDependencyNode, Report> {
        self.dependency_graph
            .get(instance)
            .ok_or_else(|| Report::msg(format!("missing dependency graph node for '{instance}'")))
    }

    /// Whether another explicit source instance selects this home for the same publication slot.
    /// This only separates local build candidates; it never approves or rebases an artifact.
    pub fn has_other_source_home(
        &self,
        instance: DependencyInstanceId,
        name: &miden_package_registry::PackageId,
        version: &miden_project::SemVer,
        home: &NamespacePlan,
    ) -> bool {
        self.dependency_graph.nodes().values().any(|parent| {
            parent.dependencies.iter().any(|edge| {
                edge.dependency != instance
                    && edge
                        .binding
                        .as_ref()
                        .is_some_and(|binding| binding.namespace_plan() == *home)
                    && self.dependency_graph.get(&edge.dependency).is_some_and(|node| {
                        &node.name == name
                            && &node.version == version
                            && matches!(node.provenance, ProjectDependencyNodeProvenance::Source(_))
                    })
            })
        })
    }

    // PROVENANCE BUILDERS
    // --------------------------------------------------------------------------------------------

    pub fn build_source_provenance(
        &self,
        instance: &DependencyInstanceId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        source_provider: &SourceProviderRegistry,
        package_registry: &dyn PackageRegistryAndProvider,
        source_provenance: Option<&ProjectSourceProvenanceInputs>,
    ) -> Result<Option<PackageBuildProvenance>, Report> {
        let Some(node) = self.dependency_graph.get(instance) else {
            return Ok(None);
        };
        let ProjectDependencyNodeProvenance::Source(source) = &node.provenance else {
            return Ok(None);
        };

        match source {
            ProjectSource::Virtual { .. } => Ok(None),
            ProjectSource::Real { origin, manifest_path, .. } => self
                .expected_source_provenance(
                    instance,
                    project,
                    target,
                    profile_name,
                    origin,
                    manifest_path,
                    source_provider,
                    package_registry,
                    source_provenance,
                )
                .map(Some),
        }
    }

    pub fn expected_source_provenance(
        &self,
        instance: &DependencyInstanceId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        source_provider: &SourceProviderRegistry,
        package_registry: &dyn PackageRegistryAndProvider,
        source_provenance: Option<&ProjectSourceProvenanceInputs>,
    ) -> Result<PackageBuildProvenance, Report> {
        self.expected_source_provenance_with_visited(
            instance,
            project,
            target,
            profile_name,
            origin,
            manifest_path,
            source_provider,
            package_registry,
            source_provenance,
            &mut BTreeSet::new(),
        )
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn expected_source_provenance_with_visited(
        &self,
        instance: &DependencyInstanceId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        source_provider: &SourceProviderRegistry,
        package_registry: &dyn PackageRegistryAndProvider,
        source_provenance: Option<&ProjectSourceProvenanceInputs>,
        visiting: &mut BTreeSet<DependencyInstanceId>,
    ) -> Result<PackageBuildProvenance, Report> {
        let dependency_hash = self.compute_dependency_closure_hash(
            instance,
            profile_name,
            source_provider,
            package_registry,
            visiting,
        )?;
        let profile = project.resolve_profile(profile_name)?;
        let build_settings = PackageBuildSettings::from_profile(profile);

        match origin {
            ProjectSourceOrigin::Git { repo, resolved_revision, .. } => {
                Ok(PackageBuildProvenance::Git {
                    repo: repo.to_string(),
                    resolved_revision: resolved_revision.to_string(),
                    dependency_hash,
                    build_settings,
                    compilation_commitment: None,
                })
            },
            ProjectSourceOrigin::Path | ProjectSourceOrigin::Root
                if source_provenance.is_some() =>
            {
                Ok(PackageBuildProvenance::Path {
                    source_hash: self.compute_path_source_hash_from_sources(
                        &project,
                        None,
                        target,
                        profile,
                        source_provenance.unwrap(),
                    ),
                    dependency_hash,
                    build_settings,
                    compilation_commitment: None,
                })
            },
            ProjectSourceOrigin::Path | ProjectSourceOrigin::Root => {
                let source_manager = self.source_manager.clone();
                let context = TargetAssemblyContext::new(
                    project.clone(),
                    manifest_path,
                    target,
                    profile,
                    &self.dependency_graph,
                    package_registry,
                    source_manager,
                )?;
                Ok(PackageBuildProvenance::Path {
                    source_hash: self.compute_path_source_hash(&context, source_provider)?,
                    dependency_hash,
                    build_settings,
                    compilation_commitment: None,
                })
            },
        }
    }

    fn compute_dependency_closure_hash(
        &self,
        instance: &DependencyInstanceId,
        profile_name: &str,
        source_provider: &SourceProviderRegistry,
        package_registry: &dyn PackageRegistryAndProvider,
        visiting: &mut BTreeSet<DependencyInstanceId>,
    ) -> Result<Word, Report> {
        if !visiting.insert(*instance) {
            return Err(Report::msg(format!(
                "dependency cycle detected while computing source provenance for '{instance}'"
            )));
        }

        let outcome = (|| {
            let node = self.dependency_graph.get(instance).ok_or_else(|| {
                Report::msg(format!("missing dependency graph node for '{instance}'"))
            })?;
            if node.dependencies.is_empty() {
                return Ok(PackageBuildProvenance::empty_dependency_hash());
            }

            let mut dependencies = Vec::with_capacity(node.dependencies.len());
            for edge in &node.dependencies {
                let mut material = dependency_edge_hash_input(edge)?;
                let resolution = self.dependency_resolution_hash_input(
                    &edge.dependency,
                    profile_name,
                    source_provider,
                    package_registry,
                    visiting,
                )?;
                append_provenance_bytes(&mut material, &resolution)?;
                dependencies.push(material);
            }

            hash_dependency_records(dependencies)
        })();

        visiting.remove(instance);
        outcome
    }

    fn dependency_resolution_hash_input(
        &self,
        instance: &DependencyInstanceId,
        profile_name: &str,
        source_provider: &SourceProviderRegistry,
        package_registry: &dyn PackageRegistryAndProvider,
        visiting: &mut BTreeSet<DependencyInstanceId>,
    ) -> Result<Vec<u8>, Report> {
        let node = self.dependency_graph.get(instance).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{instance}'"))
        })?;

        let mut material = Vec::new();
        // Graph-local slots only direct traversal. Persist actual package/provenance data, so
        // allocating the same logical graph in a different order cannot change this hash.
        append_provenance_bytes(&mut material, node.name.as_bytes())?;
        append_provenance_bytes(&mut material, node.version.to_string().as_bytes())?;
        match &node.provenance {
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                material.push(0);
                append_provenance_version(&mut material, selected)?;
            },
            ProjectDependencyNodeProvenance::Preassembled { selected, .. } => {
                material.push(1);
                append_provenance_version(&mut material, selected)?;
            },
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin,
                manifest_path,
                library_path: Some(_),
                ..
            }) => {
                let project = miden_project::Project::load_project_reference(
                    &node.name,
                    manifest_path,
                    &self.source_manager,
                )
                .map(|project| project.package())?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{}' does not define a library target",
                            node.name
                        ))
                    })?;
                let provenance = self.expected_source_provenance_with_visited(
                    instance,
                    project,
                    &target,
                    profile_name,
                    origin,
                    manifest_path,
                    source_provider,
                    package_registry,
                    None,
                    visiting,
                )?;
                material.push(2);
                append_provenance_bytes(&mut material, &provenance.to_bytes())?;
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                material.push(3);
            },
        }
        Ok(material)
    }

    /// This function computes a hash for a project dependency in source form that is used in
    /// source provenance tracking.
    ///
    /// The hash is derived from a string built by this function that contains the following
    /// information encoded as plain text:
    ///
    /// * The project-relative path to the root module, and its content
    /// * The project-relative path of each supporting submodule, and its content
    /// * The source provenance material derived from the project file for the current target and
    ///   build profile.
    ///
    /// This hash allows us to reuse the same artifact for a given source dependency, so long as
    /// the hash has not changed. As a result, it is necessary to make sure that all relevant
    /// information that contributes to the build output be represented in the hash. For now, this
    /// assumes that only relevant fields of `miden-project.toml` and the raw content of the source
    /// files that are built matter for this purpose. Source providers can contribute additional
    /// non-source code material by returning them as extra support files, whose content contains
    /// the information/metadata that should contribute to the hash.
    fn compute_path_source_hash(
        &self,
        context: &TargetAssemblyContext<'_>,
        source_provider: &SourceProviderRegistry,
    ) -> Result<Word, Report> {
        let Some(extension) = context.resolved_target_root.extension().and_then(|ext| ext.to_str())
        else {
            return Err(Report::msg(format!(
                "invalid target path '{}': file must have an extension",
                context.target.path
            )));
        };

        let Some(source_provider) = source_provider.get_provider(extension) else {
            return Err(Report::msg(format!(
                "unsupported file type '{extension}': no source provider registered for that type"
            )));
        };
        let source_provenance = source_provider.provide_source_provenance(context)?;

        Ok(self.compute_path_source_hash_from_sources(
            &context.package,
            Some(context.project_root.as_ref()),
            context.target,
            context.profile,
            &source_provenance,
        ))
    }

    fn compute_path_source_hash_from_sources(
        &self,
        package: &miden_project::Package,
        project_root: Option<&std::path::Path>,
        target: &Target,
        profile: &miden_project::Profile,
        source_provenance: &ProjectSourceProvenanceInputs,
    ) -> Word {
        let ProjectSourceProvenanceInputs { root, support } = source_provenance;

        let mut inputs = Vec::with_capacity(1 + support.len());
        let root_label = if let Some(project_root) = project_root {
            match root.path.strip_prefix(project_root) {
                Ok(stripped) => stripped.display().to_string(),
                Err(_) => root.path.display().to_string(),
            }
        } else {
            root.path.display().to_string()
        };
        inputs.push((format!("root:{root_label}"), root));
        for support_file in support {
            let label = if let Some(project_root) = project_root {
                match support_file.path.strip_prefix(project_root) {
                    Ok(stripped) => stripped.display().to_string(),
                    Err(_) => support_file.path.display().to_string(),
                }
            } else {
                support_file.path.display().to_string()
            };
            inputs.push((format!("support:{label}"), support_file));
        }
        inputs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut material = package.build_provenance_projection(target, profile);
        for (label, source_file) in inputs {
            material.push_str(&label);
            material.push('\n');
            material.push_str(&source_file.content);
            material.push('\n');
        }

        hash_string_to_word(material.as_str())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use miden_assembly_syntax::debuginfo::{DefaultSourceManager, Span, Uri};
    use miden_core::{Felt, program::CanonicalLabel};
    use miden_mast_package::CallableBinding;
    use miden_package_registry::{PackageIndex, PackageRecord, VersionRequirement};
    use miden_project::{
        Dependency, DependencyVersionScheme, ExpectedVisibleCallables, LibraryImport,
        LibrarySelection, PackageSourceMount, SemVer,
    };

    use super::*;
    use crate::testing::TestRegistry;

    fn home(labels: &[&str]) -> NamespacePlan {
        NamespacePlan::new(
            labels.iter().map(|label| CanonicalLabel::text(label).unwrap()).collect(),
        )
    }

    fn path(components: &[&str]) -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| String::from(*component)).collect(),
        )
        .unwrap()
    }

    fn version(major: u64, digest: u32) -> Version {
        Version::new(SemVer::new(major, 0, 0), Word::new([Felt::from_u32(digest); 4]))
    }

    fn dependency(alias: &str, version: Version) -> Dependency {
        Dependency::new(
            Span::unknown(Arc::from(alias)),
            DependencyVersionScheme::Registry(VersionRequirement::Exact(version)),
            Linkage::Dynamic,
        )
        .with_package("dep")
        .with_binding(DependencyBinding::Custom(home(&["chosen-home"])))
    }

    fn hash_dependencies(dependencies: Vec<Dependency>) -> (Word, DependencyGraph) {
        let mut registry = TestRegistry::default();
        let mut registered = BTreeSet::new();
        for dependency in &dependencies {
            let DependencyVersionScheme::Registry(VersionRequirement::Exact(version)) =
                dependency.scheme()
            else {
                panic!("fixture requires an exact registry dependency");
            };
            if registered.insert((dependency.package().clone(), version.version.clone())) {
                registry
                    .register(dependency.package().clone(), PackageRecord::new(version.clone(), []))
                    .unwrap();
            }
        }
        let project = ProjectPackage::new(
            "root",
            Target::library(Arc::<Path>::from(Path::new("root")), Uri::new("lib.masm")),
        )
        .with_dependencies(dependencies);
        let graph = DependencyGraph::from_project(
            project.into(),
            &registry,
            Arc::new(DefaultSourceManager::default()),
        )
        .unwrap();
        let hash = graph
            .compute_dependency_closure_hash(
                graph.root(),
                "release",
                &SourceProviderRegistry::default(),
                &registry,
                &mut BTreeSet::new(),
            )
            .unwrap();
        (hash, graph)
    }

    #[test]
    fn closure_hash_retains_instances_without_persisting_slot_allocation_order() {
        let left = dependency("left", version(1, 11));
        let right = dependency("right", version(2, 22));
        let (forward_hash, forward) = hash_dependencies(vec![left.clone(), right.clone()]);
        let (reverse_hash, reverse) = hash_dependencies(vec![right, left]);
        let left_instance = |graph: &DependencyGraph| {
            graph
                .get(graph.root())
                .unwrap()
                .dependencies
                .iter()
                .find(|edge| edge.alias.as_ref() == "left")
                .unwrap()
                .dependency
        };
        assert_ne!(left_instance(&forward), left_instance(&reverse));
        assert_eq!(forward_hash, reverse_hash);

        let root = forward.get(forward.root()).unwrap();
        assert_eq!(root.dependencies.len(), 2);
        let instances = root
            .dependencies
            .iter()
            .map(|edge| forward.get(&edge.dependency).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(instances[0].name, instances[1].name);
        assert_ne!(instances[0].version, instances[1].version);
        assert_ne!(forward_hash, hash_dependencies(vec![dependency("left", version(1, 11))]).0);
    }

    #[test]
    fn closure_hash_tracks_alias_linkage_binding_expectations_mount_and_exact_artifact() {
        let baseline = dependency("left", version(1, 11));
        let baseline_hash = hash_dependencies(vec![baseline.clone()]).0;
        let changed_linkage = Dependency::new(
            Span::unknown(Arc::from("left")),
            baseline.scheme().clone(),
            Linkage::Static,
        )
        .with_package("dep")
        .with_binding(baseline.binding().unwrap().clone());
        let expected = ExpectedVisibleCallables::new([(
            path(&["visible", "run"]),
            CallableBinding::new(home(&["foreign-owner"]), path(&["original", "run"])).unwrap(),
        )])
        .unwrap();
        let mount = PackageSourceMount::new(Path::new("::dep"), Path::new("::left")).unwrap();
        for changed in [
            dependency("renamed", version(1, 11)),
            changed_linkage,
            baseline.clone().with_binding(DependencyBinding::Custom(home(&["other-home"]))),
            baseline
                .clone()
                .with_expected_callables(ExpectedVisibleCallables::new([]).unwrap()),
            baseline.clone().with_expected_callables(expected),
            baseline.with_source_mount(mount),
            dependency("left", version(1, 12)),
        ] {
            assert_ne!(baseline_hash, hash_dependencies(vec![changed]).0);
        }
    }

    #[test]
    fn closure_hash_preserves_complete_typed_home_and_semantic_path_boundaries() {
        let baseline = dependency("left", version(1, 11));
        let hash_binding = |binding| {
            hash_dependencies(vec![
                baseline.clone().with_binding(DependencyBinding::Custom(binding)),
            ])
            .0
        };
        assert_ne!(hash_binding(home(&["a::b"])), hash_binding(home(&["a", "b"])));
        let typed = NamespacePlan::new(vec![CanonicalLabel::library_id(Word::default())]);
        let text = home(&[&Word::default().to_string()]);
        assert_ne!(hash_binding(typed), hash_binding(text));
        let typed_id = |payload: &[u8]| {
            NamespacePlan::new(vec![CanonicalLabel::typed_id(77, payload, |_, _| Ok(())).unwrap()])
        };
        assert_ne!(hash_binding(typed_id(&[4, 0, 9])), hash_binding(typed_id(&[4, 0, 8])));
        let standard =
            LibraryImport::new(home(&["ancestor"]), Word::default(), LibrarySelection::Latest);
        assert_ne!(
            hash_binding(standard.namespace_plan()),
            hash_dependencies(vec![
                baseline.clone().with_binding(DependencyBinding::Standard(standard))
            ])
            .0
        );

        let expected_hash = |visible, defining| {
            let expected = ExpectedVisibleCallables::new([(
                visible,
                CallableBinding::new(home(&["foreign"]), defining).unwrap(),
            )])
            .unwrap();
            hash_dependencies(vec![baseline.clone().with_expected_callables(expected)]).0
        };
        assert_ne!(
            expected_hash(path(&["a::b", "run"]), path(&["original", "run"])),
            expected_hash(path(&["a", "b", "run"]), path(&["original", "run"]))
        );
        assert_ne!(
            expected_hash(path(&["visible", "run"]), path(&["a::b", "run"])),
            expected_hash(path(&["visible", "run"]), path(&["a", "b", "run"]))
        );

        let mount_hash = |base: &str| {
            let mount = PackageSourceMount::new(Path::new("::dep"), Path::new(base)).unwrap();
            hash_dependencies(vec![baseline.clone().with_source_mount(mount)]).0
        };
        assert_eq!(mount_hash("::left"), mount_hash("::\"left\""));
        assert_ne!(mount_hash("::\"a::b\""), mount_hash("::a::b"));
        assert_ne!(mount_hash("::"), mount_hash("::\"::\""));
    }

    #[test]
    fn closure_hash_keeps_empty_sentinel_and_rejects_a_revisited_instance() {
        let (hash, graph) = hash_dependencies(vec![]);
        assert_eq!(hash, PackageBuildProvenance::empty_dependency_hash());
        let mut visiting = BTreeSet::from([*graph.root()]);
        let error = graph
            .compute_dependency_closure_hash(
                graph.root(),
                "release",
                &SourceProviderRegistry::default(),
                &TestRegistry::default(),
                &mut visiting,
            )
            .unwrap_err();
        assert!(error.to_string().contains("dependency cycle detected"));
    }
}
