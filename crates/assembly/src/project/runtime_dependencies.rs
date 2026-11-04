use alloc::{format, sync::Arc, vec::Vec};

use miden_assembly_syntax::diagnostics::Report;
use miden_mast_package::{Dependency as PackageDependency, Package as MastPackage, PackageSymbols};
use miden_project::Linkage;

use crate::project::ResolvedPackage;

// RUNTIME DEPENDENCIES
// ================================================================================================

#[derive(Default)]
pub(super) struct RuntimeDependencies {
    pub deps: Vec<PackageDependency>,
    pub kernel: Option<(Arc<MastPackage>, Arc<PackageSymbols>)>,
}

impl RuntimeDependencies {
    pub fn merge_package(
        &mut self,
        dependency: ResolvedPackage,
        linkage: Linkage,
    ) -> Result<(), Report> {
        if dependency.package.is_kernel() {
            self.record_linked_kernel_dependency(
                dependency.package.clone(),
                dependency.naming.clone(),
            )?;
        } else if let Some((kernel_package, kernel_naming)) =
            dependency.linked_kernel_package.clone()
        {
            self.record_linked_kernel_dependency(kernel_package, kernel_naming)?;
        }

        // We record the dynamic/runtime dependencies of a package here.
        //
        // When linking against a package dynamically, both the package and its own dynamically-
        // linked dependencies are recorded in the manifest.
        //
        // When linking statically, only the dynamically-linked dependencies of the package are
        // recorded, not the statically-linked package, as it is by definition included in the
        // assembled package
        //
        // We _always_ record the kernel that a package is assembled against, regardless of
        // linkage, and propagate such dependencies up the dependency tree so as to require
        // that all packages that transitively depend on a kernel, depend on the same kernel.
        //
        // Distinct exact code-supply records may share a package name. Only equivalent records
        // coalesce; these requirements do not authorize a callable key-to-implementation binding.
        if matches!(linkage, Linkage::Dynamic) && !dependency.package.is_kernel() {
            self.merge_dependency(dependency.package.to_dependency());
        }
        for dep in dependency.package.manifest.dependencies() {
            self.merge_dependency(dep.clone());
        }

        Ok(())
    }

    pub fn record_linked_kernel_dependency(
        &mut self,
        package: Arc<MastPackage>,
        naming: Arc<PackageSymbols>,
    ) -> Result<(), Report> {
        debug_assert!(package.is_kernel());
        package.check_naming(&naming).map_err(|error| Report::msg(format!("{error}")))?;

        if let Some((existing, _)) = &self.kernel
            && (existing.name != package.name
                || existing.version != package.version
                || existing.dependency_commitment() != package.dependency_commitment())
        {
            return Err(Report::msg(format!(
                "conflicting linked kernel packages '{}@{}#{}' and '{}@{}#{}'",
                existing.name,
                existing.version,
                existing.dependency_commitment(),
                package.name,
                package.version,
                package.dependency_commitment()
            )));
        }

        self.merge_dependency(package.to_dependency());
        if self.kernel.is_none() {
            self.kernel = Some((package, naming));
        }
        Ok(())
    }

    fn merge_dependency(&mut self, dependency: PackageDependency) {
        let position = self.deps.binary_search_by(|existing| {
            existing
                .name
                .cmp(&dependency.name)
                .then_with(|| existing.version.cmp(&dependency.version))
                .then_with(|| (existing.kind as u8).cmp(&(dependency.kind as u8)))
                .then_with(|| existing.digest.cmp(&dependency.digest))
        });
        if let Err(index) = position {
            self.deps.insert(index, dependency);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use miden_core::{
        Word,
        mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastNodeExt},
        operations::Operation,
        program::{CanonicalLabel, ImplementationRoot},
    };
    use miden_mast_package::{
        CallableProcedurePath, NamespacePath, PackageCallables, PackageExport, PackageId,
        ProcedureExport, ProcedureName, TargetType, Version,
    };

    use super::*;

    fn dependency(digest: u32) -> PackageDependency {
        PackageDependency {
            name: PackageId::from("supply"),
            kind: TargetType::Library,
            version: Version::new(1, 0, 0),
            digest: Word::from([digest, 0, 0, 0]),
        }
    }

    fn package(
        kind: TargetType,
        operation: Operation,
        dependencies: Vec<PackageDependency>,
    ) -> ResolvedPackage {
        let mut builder = DenseMastForestBuilder::new();
        let node = builder.push_node(BasicBlockNodeBuilder::new(vec![operation])).unwrap();
        builder.mark_root(node);
        let (mast, remapping) = builder.build_with_id_map().unwrap();
        let node = remapping.get(node).unwrap();
        let digest = mast[node].digest();
        let home = if kind == TargetType::Kernel {
            NamespacePath::new(vec![])
        } else {
            NamespacePath::new(vec![CanonicalLabel::text("runtime-supply-fixture").unwrap()])
        };
        let visible =
            CallableProcedurePath::from_semantic_components(vec!["supply".into(), "run".into()])
                .unwrap();
        let canonical =
            CallableProcedurePath::from_semantic_components(vec!["run".into()]).unwrap();
        let binding = ProcedureName::new(home.clone(), canonical).unwrap();
        let key = binding.key();
        let naming = PackageSymbols::new(
            home,
            PackageCallables::new(
                [binding],
                [(visible, key)],
                [(key, ImplementationRoot::new(digest))],
            )
            .unwrap(),
            None,
        )
        .unwrap();
        let package = MastPackage::create(
            PackageId::from("supply"),
            Version::new(1, 0, 0),
            kind,
            Arc::new(mast),
            [PackageExport::Procedure(ProcedureExport::new(
                Arc::from(crate::Path::new("::supply::run")),
                Some(node),
                digest,
                None,
            ))],
            dependencies,
            &naming,
        )
        .unwrap();
        ResolvedPackage {
            package: Arc::new(package),
            naming: Arc::new(naming),
            linked_kernel_package: None,
            dependency_packages: Vec::new(),
        }
    }

    #[test]
    fn runtime_merge_coalesces_only_equivalent_supply_records() {
        let original = dependency(1);
        let mut versioned = original.clone();
        versioned.version = Version::new(2, 0, 0);
        let mut different_kind = original.clone();
        different_kind.kind = TargetType::AccountComponent;
        let different_commitment = dependency(2);
        let expected = vec![original, versioned, different_kind, different_commitment];
        let mut runtime = RuntimeDependencies::default();

        for record in expected.iter().chain(&expected) {
            runtime.merge_dependency(record.clone());
        }

        assert_eq!(runtime.deps.len(), expected.len());
        for record in &expected {
            assert!(runtime.deps.contains(record));
        }
        let mut reversed = RuntimeDependencies::default();
        for record in expected.into_iter().rev() {
            reversed.merge_dependency(record);
        }
        assert_eq!(runtime.deps, reversed.deps, "exact supply order must not depend on traversal");
    }

    #[test]
    fn runtime_merge_retains_transitive_dynamic_supplies_across_linkage() {
        let transitive = dependency(1);
        let package = package(TargetType::Library, Operation::Add, vec![transitive.clone()]);
        let direct = package.package.to_dependency();
        assert_eq!(direct.name, transitive.name);
        let mut static_runtime = RuntimeDependencies::default();
        static_runtime.merge_package(package.clone(), Linkage::Static).unwrap();
        assert_eq!(static_runtime.deps, vec![transitive.clone()]);

        let mut dynamic_runtime = RuntimeDependencies::default();
        dynamic_runtime.merge_package(package.clone(), Linkage::Dynamic).unwrap();
        dynamic_runtime.merge_package(package, Linkage::Dynamic).unwrap();
        assert_eq!(dynamic_runtime.deps.len(), 2);
        assert!(dynamic_runtime.deps.contains(&direct));
        assert!(dynamic_runtime.deps.contains(&transitive));
    }

    #[test]
    fn conflicting_kernel_merge_is_atomic_before_supply_mutation() {
        let kernel = package(TargetType::Kernel, Operation::Add, vec![]);
        let conflicting = package(TargetType::Kernel, Operation::Mul, vec![]);
        let mut runtime = RuntimeDependencies::default();
        runtime
            .record_linked_kernel_dependency(kernel.package.clone(), kernel.naming.clone())
            .unwrap();
        runtime
            .record_linked_kernel_dependency(kernel.package.clone(), kernel.naming.clone())
            .unwrap();
        let original_deps = runtime.deps.clone();
        assert_eq!(original_deps, vec![kernel.package.to_dependency()]);

        let mut consumer = package(TargetType::Library, Operation::Add, vec![dependency(3)]);
        consumer.linked_kernel_package = Some((conflicting.package.clone(), conflicting.naming));
        for linkage in [Linkage::Static, Linkage::Dynamic] {
            let error = runtime.merge_package(consumer.clone(), linkage).unwrap_err();
            assert!(error.to_string().contains("conflicting linked kernel packages"));
            assert_eq!(runtime.deps, original_deps);
            assert_eq!(
                runtime.kernel.as_ref().unwrap().0.dependency_commitment(),
                kernel.package.dependency_commitment()
            );
        }
    }
}
