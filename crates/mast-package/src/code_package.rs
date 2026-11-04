//! Shared package code with its exact checked canonical symbol inventory.

use alloc::sync::Arc;

use crate::{
    ManifestValidationError, NamingCodecError, Package, PackageSymbols,
    interface::serialization::{CodecLimits, HomeProfile},
};

/// An immutable package and the exact checked symbols belonging to it.
///
/// Keeping the complete package retains its advice, private callables, exact code/source
/// occurrences and diagnostic metadata together. Clones share both owned values. This is an
/// in-memory ownership boundary, with no additional serialized format or package identity.
///
/// Construction checks package integrity; it does not authorize execution or publication.
/// The execution caller still supplies the expected entry key and environment root. Home-profile
/// admission is explicit through [`Self::from_package`]; [`Self::new`] only checks an already
/// owned pair against the package's exact transport and code relations.
#[derive(Debug, Clone)]
pub struct CodePackage {
    package: Arc<Package>,
    symbols: Arc<PackageSymbols>,
}

impl CodePackage {
    /// Retains a package and already owned symbols after checking their exact correspondence.
    ///
    /// This checks required code/symbol relations and occurrence rows. It is an integrity check,
    /// not admission under a home or publication profile. Compilers can retain the symbols
    /// used to construct a package; raw package consumers use [`Self::from_package`] with their
    /// current explicit home policy, context and limits.
    pub fn new(
        package: Arc<Package>,
        symbols: Arc<PackageSymbols>,
    ) -> Result<Self, ManifestValidationError> {
        package.check_naming(&symbols)?;
        Ok(Self { package, symbols })
    }

    /// Checks a package's symbols under explicit current home policy and resource limits.
    ///
    /// This delegates to [`Package::validate_symbols`], including the shared symbol/occurrence
    /// budget and exact code relations. Successful home admission does not authenticate an
    /// execution environment or satisfy a separate publication/release profile.
    pub fn from_package<P: HomeProfile + ?Sized>(
        package: Arc<Package>,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, NamingCodecError<P::Error>> {
        let symbols = Arc::new(package.validate_symbols(profile, context, limits)?);
        Ok(Self { package, symbols })
    }

    /// Returns the complete immutable package, including advice and diagnostic metadata.
    pub fn package(&self) -> &Arc<Package> {
        &self.package
    }

    /// Returns the exact checked canonical symbols retained with this package.
    pub fn symbols(&self) -> &Arc<PackageSymbols> {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::cell::Cell;

    use miden_core::{
        advice::AdviceMap,
        mast::{BasicBlockNodeBuilder, MastForest, MastNode, MastNodeExt, MastNodeId},
        operations::Operation,
        program::{CanonicalLabel, ImplementationRoot},
        utils::IndexVec,
    };

    use super::*;
    use crate::{
        CallableProcedurePath, NamespacePath, PackageCallables, PackageId,
        PackageProcedureOccurrence, PackageProcedureOccurrencesError, ProcedureName, Section,
        SectionId, TargetType, Version,
        debug_info::{DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder},
        interface::serialization::{CodecError, ProfileOperation, TypedIdProfile},
    };

    const LIMITS: CodecLimits = CodecLimits::new(1 << 20, 1024, 1024, 1024);

    struct ExactHomes {
        calls: Cell<usize>,
    }

    impl TypedIdProfile for ExactHomes {
        type Context = [NamespacePath];
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

    impl HomeProfile for ExactHomes {
        fn validate_home(
            &self,
            context: &Self::Context,
            home: &[CanonicalLabel],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if context.iter().any(|permitted| permitted.home() == home) {
                Ok(())
            } else {
                Err("home is absent from current fixture evidence")
            }
        }
    }

    fn home(label: &str) -> NamespacePath {
        NamespacePath::new(vec![CanonicalLabel::text(label).unwrap()])
    }

    // Reuses the package occurrence fixture's raw-forest construction to preserve distinct
    // execution and source occurrences whose implementations deliberately have equal digests.
    fn fixture(canonical_home: &str) -> (Arc<Package>, Arc<PackageSymbols>) {
        let compilation_home = home("compile");
        let canonical_home = home(canonical_home);
        let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
        let mut roots = Vec::new();
        let mut bindings = Vec::new();
        let mut selected = Vec::new();
        let mut rows = Vec::new();
        let mut debug = PackageDebugInfoBuilder::default();
        let mut entry = None;
        for name in ["left", "right"] {
            let node = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
            let digest = node.digest();
            let node_id = nodes.push(node.into()).unwrap();
            let path = CallableProcedurePath::from_semantic_components(vec![name.into()]).unwrap();
            let binding = ProcedureName::new(canonical_home.clone(), path).unwrap();
            let key = binding.key();
            entry = Some(key);
            let context = debug.add_string(name);
            let operation = debug.add_string("add");
            let source = debug
                .add_node(DebugSourceNode {
                    exec_node: node_id,
                    children: Vec::new(),
                    op_start: 0,
                    op_end: 1,
                    asm_ops: vec![DebugSourceAsmOp::new(0, None, context, operation, 1)],
                    debug_vars: Vec::new(),
                    inline_calls: Vec::new(),
                })
                .unwrap();
            debug.add_root(source);
            rows.push(PackageProcedureOccurrence::new(key, node_id, Some(source)));
            roots.push(node_id);
            bindings.push(binding);
            selected.push((key, ImplementationRoot::new(digest)));
        }
        let mast =
            Arc::new(MastForest::from_raw_parts(nodes, roots, AdviceMap::default()).unwrap());
        let symbols = Arc::new(
            PackageSymbols::new(
                compilation_home,
                PackageCallables::new(bindings, [], selected).unwrap(),
                entry,
            )
            .unwrap(),
        );
        let mut package = Package::create(
            PackageId::from("private-occurrences"),
            Version::new(1, 0, 0),
            TargetType::Executable,
            mast,
            [],
            [],
            &symbols,
        )
        .unwrap();
        package.sections.push(Section::new(
            SectionId::DEBUG_INFO,
            debug.build().to_bytes_with_standard_limits().unwrap(),
        ));
        rows.sort_by_key(|row| row.key().as_word().as_bytes());
        let package = package.with_procedure_occurrences(rows, &symbols).unwrap();
        (Arc::new(package), symbols)
    }

    #[test]
    fn owned_pair_requires_exact_symbols_despite_equal_code() {
        let (first, first_symbols) = fixture("first");
        let (second, second_symbols) = fixture("second");
        assert_eq!(first.code_commitment(), second.code_commitment());
        second_symbols
            .validate_package(first.kind, first.mast_forest(), &first.manifest)
            .unwrap();
        assert!(matches!(
            CodePackage::new(Arc::clone(&first), second_symbols),
            Err(ManifestValidationError::MismatchedNamingTransport)
        ));

        let changed_compilation_home = Arc::new(
            PackageSymbols::new(
                home("other-compile"),
                first_symbols.callables().clone(),
                first_symbols.entry_key(),
            )
            .unwrap(),
        );
        assert!(matches!(
            CodePackage::new(first, changed_compilation_home),
            Err(ManifestValidationError::MismatchedNamingTransport)
        ));
    }

    #[test]
    fn clones_retain_private_entry_and_exact_equal_digest_occurrences() {
        let (package, symbols) = fixture("canonical");
        let code = CodePackage::new(Arc::clone(&package), Arc::clone(&symbols)).unwrap();
        let cloned = code.clone();
        assert!(Arc::ptr_eq(cloned.package(), code.package()));
        assert!(Arc::ptr_eq(cloned.symbols(), code.symbols()));
        assert!(Arc::ptr_eq(cloned.package(), &package));
        assert!(Arc::ptr_eq(cloned.symbols(), &symbols));
        assert_eq!(cloned.package().manifest.num_exports(), 0);
        assert_eq!(cloned.symbols().callables().visible_paths().len(), 0);
        assert!(cloned.symbols().entry_key().is_some());

        let rows = cloned.package().procedure_occurrences();
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].exec_node(), rows[1].exec_node());
        assert_ne!(rows[0].source_node(), rows[1].source_node());
        let forest = cloned.package().mast_forest();
        assert_eq!(forest[rows[0].exec_node()].digest(), forest[rows[1].exec_node()].digest());
        let debug = cloned.package().debug_info().unwrap().unwrap();
        for row in rows {
            assert_eq!(
                debug.source_node(row.source_node().unwrap()).unwrap().exec_node,
                row.exec_node()
            );
            assert_eq!(cloned.package().procedure_occurrence(row.key()), Some(row));
        }
    }

    #[test]
    fn package_admission_uses_explicit_profile_and_context_without_fallback() {
        let (package, symbols) = fixture("canonical");
        let profile = ExactHomes { calls: Cell::new(0) };
        let homes = [home("compile"), home("canonical")];
        let admitted =
            CodePackage::from_package(Arc::clone(&package), &profile, homes.as_slice(), LIMITS)
                .unwrap();
        assert!(Arc::ptr_eq(admitted.package(), &package));
        assert_eq!(admitted.symbols(), &symbols);
        assert!(profile.calls.get() > 0);

        profile.calls.set(0);
        assert!(matches!(
            CodePackage::from_package(package, &profile, &[], LIMITS),
            Err(NamingCodecError::Codec(CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error: "home is absent from current fixture evidence",
            }))
        ));
        assert_eq!(profile.calls.get(), 1);
    }

    #[test]
    fn occurrence_and_symbol_limits_reject_before_profile_callbacks() {
        let (package, _) = fixture("canonical");
        let profile = ExactHomes { calls: Cell::new(0) };
        let homes = [home("compile"), home("canonical")];
        let occurrence_count = package.procedure_occurrences().len() as u32;
        // Each row has a key, execution node, present-source tag and source node; the count is u32.
        let occurrence_bytes = 4 + occurrence_count * (32 + 4 + 1 + 4);
        let naming_bytes = package.naming_transport().as_bytes().len() as u32;
        for limits in [
            CodecLimits::new(occurrence_bytes - 1, 1024, 1024, 1024),
            CodecLimits::new(1 << 20, occurrence_count - 1, 1024, 1024),
        ] {
            assert!(matches!(
                CodePackage::from_package(Arc::clone(&package), &profile, homes.as_slice(), limits),
                Err(NamingCodecError::InvalidOccurrences(PackageProcedureOccurrencesError::Codec(
                    CodecError::LimitExceeded { .. }
                )))
            ));
            assert_eq!(profile.calls.get(), 0);
        }
        assert!(matches!(
            CodePackage::from_package(
                Arc::clone(&package),
                &profile,
                homes.as_slice(),
                CodecLimits::new(naming_bytes + occurrence_bytes - 1, 1024, 1024, 1024),
            ),
            Err(NamingCodecError::Codec(CodecError::LimitExceeded { .. }))
        ));
        assert_eq!(profile.calls.get(), 0);
        CodePackage::from_package(
            package,
            &profile,
            homes.as_slice(),
            CodecLimits::new(naming_bytes + occurrence_bytes, 1024, 1024, 1024),
        )
        .unwrap();
        assert!(profile.calls.get() > 0);
    }
}
