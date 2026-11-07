#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "constraints-tools", all(test, feature = "std")))]
pub mod constraints_regen;
pub mod dsa;
pub mod ecdh;
pub mod handlers;
mod verifier;

pub use verifier::{CoreVerifierProfile, CoreVerifierProfileError};

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{Word, events::EventName, mast::MastForest};
use miden_mast_package::{CodePackage, Package, PackageSymbols};
use miden_processor::{HostLibrary, event::EventHandler};
use miden_utils_sync::LazyLock;

mod embedded_naming {
    include!(concat!(env!("OUT_DIR"), "/core_naming.rs"));
}

use crate::handlers::{
    aead_eidos::{AEAD_EIDOS_DECRYPT_EVENT_NAME, handle_aead_eidos_decrypt},
    debug::default_debug_handlers,
    ecdsa_k256_keccak::{ECDSA_K256_KECCAK_RECOVER_EVENT_NAME, handle_ecdsa_k256_keccak_recover},
    ecdsa_p256_sha256::{ECDSA_P256_SHA256_RECOVER_EVENT_NAME, handle_ecdsa_p256_sha256_recover},
    environment::{ENVIRONMENT_BUILD_TREE_EVENT_NAME, handle_environment_build_tree},
    falcon_div::{FALCON_DIV_EVENT_NAME, handle_falcon_div},
    precompiles::{
        ed25519::{ED25519_DECOMPRESS_EVENT_NAME, handle_ed25519_decompress},
        keccak256::{KECCAK256_DIGEST_EVENT_NAME, handle_keccak256_digest},
        sha256::{SHA256_DIGEST_EVENT_NAME, handle_sha256_digest},
        sha512::{SHA512_DIGEST_EVENT_NAME, handle_sha512_digest},
        uint_field_inv::{UINT_FIELD_INV_EVENT_NAME, handle_uint_field_inv},
    },
    readonly::readonly_noop_handlers,
    smt_peek::{SMT_PEEK_EVENT_NAME, handle_smt_peek},
    sorted_array::{
        LOWERBOUND_ARRAY_EVENT_NAME, LOWERBOUND_KEY_VALUE_EVENT_NAME, handle_lowerbound_array,
        handle_lowerbound_key_value,
    },
    u64_div::{U64_DIV_EVENT_NAME, handle_u64_div},
    u128_div::{U128_DIV_EVENT_NAME, handle_u128_div},
    u256_div::{U256_DIV_EVENT_NAME, handle_u256_div},
};

/// Event emitted by `sys::pvm::request_proof` to request an asynchronously supplied PVM proof
/// package. The caller's expected PVM verifier identity is at stack positions 1 through 4 and the
/// deferred root is at positions 5 through 8.
///
/// Emitting the event does not authorize the identity or authenticate the deferred root. The owner
/// selects the identity and its exact environment/resources before execution; the calling program
/// must establish the deferred root and verify the returned PVM proof against that unchanged value.
///
/// The core library does not register a default handler. Hosts that support on-demand settlement
/// should handle this event and return advice-map and Merkle-store mutations containing a package
/// keyed by `proof_request_key(expected_verifier, deferred_root)`. The procedure fetches that
/// package after the handler returns.
pub const PVM_PROOF_REQUEST_EVENT_NAME: EventName =
    EventName::new("miden::core::sys::pvm::request_proof");

// CORE LIBRARY
// ================================================================================================

/// The Miden core library, providing a set of optimized procedures for Miden programs.
///
/// This library wraps the `miden-core` [`Package`].
///
/// When the core library is dynamically linked during assembly time, procedures can be called from
/// any Miden program and are serialized as 32 bytes, reducing the amount of code that needs to be
/// shared between parties for proving and verifying program execution.
///
/// # Contents
///
/// The core library provides several categories of functionality:
///
/// - **Cryptographic primitives**: Eidos, Blake3, SHA-256, Falcon signature verification, and
///   stable core facades for bundled deferred precompiles under `::miden::core::*`.
/// - **Mathematical operations**: Division operations for u64, u128, and u256.
/// - **Data structures**: Sparse Merkle Tree operations, Merkle Mountain Range (MMR), and sorted
///   array utilities with lower-bound search capabilities.
/// - **Memory operations**: Efficient hashing and "un-hashing" of large amounts of data.
///
/// # Usage
///
/// The core library is typically used with the assembler to enable core library procedures
/// in compiled programs:
///
/// ```rust,ignore
/// use miden_assembly::{Assembler, Linkage};
/// use miden_core_lib::CoreLibrary;
///
/// let core_lib = CoreLibrary::default();
/// let mut assembler = Assembler::new(source_manager);
/// assembler.link_package(core_lib.code_package().clone(), Linkage::Dynamic).unwrap();
/// ```
///
/// For program execution, you'll also need to register the event handlers:
///
/// ```rust,ignore
/// # let core_lib = CoreLibrary::default();
/// let handlers = core_lib.handlers();
/// // Register handlers with your host...
/// ```
///
/// Stack and memory print-style debug handlers are registered with stdout writers by default.
/// These handlers can print private values if a program moves witness data onto the operand stack
/// or into memory. Privacy-sensitive hosts should replace or unregister these handlers. Advice
/// debug handlers can expose witness data directly, so hosts must opt into those explicitly.
///
/// [`Package`]: miden_mast_package::Package
#[derive(Clone)]
pub struct CoreLibrary {
    code: CodePackage,
}

impl From<&CoreLibrary> for HostLibrary {
    fn from(core_lib: &CoreLibrary) -> Self {
        HostLibrary::new(core_lib.code.clone()).set_handlers(core_lib.handlers())
    }
}

impl CoreLibrary {
    /// Serialized representation of the Miden `core` package.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-core.masp"));

    /// Returns a reference to the [MastForest] used to execute the core library
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.code.package().mast_forest()
    }

    /// Returns the `miden-core` package.
    pub fn package(&self) -> Arc<Package> {
        Arc::clone(self.code.package())
    }

    /// Returns the embedded package and its exact checked symbols as one immutable value.
    pub fn code_package(&self) -> &CodePackage {
        &self.code
    }

    /// Returns the compiler-owned naming retained for the exact embedded core package.
    pub fn naming(&self) -> &Arc<PackageSymbols> {
        self.code.symbols()
    }

    /// Constructs the exact embedded VM verifier's dependencies and derived identity.
    ///
    /// Derivation does not authorize an outer environment or its supplied resources. The caller
    /// must independently select its expected identity and authorize the actual execution supply.
    pub fn vm_recursive_verifier_profile(
        &self,
    ) -> Result<CoreVerifierProfile, CoreVerifierProfileError> {
        CoreVerifierProfile::new(self, false)
    }

    /// Constructs the exact embedded PVM verifier's dependencies and derived identity.
    ///
    /// Like the VM profile, this describes required mounts and resources without granting them
    /// authority. The canonical ACE stream remains part of the per-request advice supply.
    pub fn pvm_recursive_verifier_profile(
        &self,
    ) -> Result<CoreVerifierProfile, CoreVerifierProfileError> {
        CoreVerifierProfile::new(self, true)
    }

    /// Returns the selected MAST implementation root of `sys::vm::verify_proof`.
    ///
    /// This implementation-inspection value is distinct from both the `procref` callable key and
    /// the typed identity returned by [`Self::vm_recursive_verifier_profile`]. Proof requests use
    /// the caller's expected typed identity, not this implementation root.
    pub fn vm_recursive_verifier_root(&self) -> Word {
        self.code
            .package()
            .get_procedure_root_by_path("::miden::core::sys::vm::verify_proof")
            .expect("vm::verify_proof is exported from the core library")
    }

    /// Returns the selected MAST implementation root of `sys::pvm::verify_proof`.
    ///
    /// This implementation-inspection value is distinct from both the `procref` callable key and
    /// the typed identity returned by [`Self::pvm_recursive_verifier_profile`]. Proof requests use
    /// the caller's expected typed identity, not this implementation root.
    pub fn pvm_recursive_verifier_root(&self) -> Word {
        self.code
            .package()
            .get_procedure_root_by_path("::miden::core::sys::pvm::verify_proof")
            .expect("pvm::verify_proof is exported from the core library")
    }

    /// Returns the MAST root of the common recursive conjectured security estimator.
    ///
    /// The MVM and PVM verifiers return relation-specific descriptors consumed by this one
    /// procedure. Its root does not encode an acceptance threshold; each consumer compares the
    /// returned level with its own threshold. The estimator does not verify proofs or authenticate
    /// descriptors assembled by the caller.
    pub fn conjectured_security_estimator_root(&self) -> Word {
        self.code
            .package()
            .get_procedure_root_by_path(
                "::miden::core::stark::security::compute_conjectured_security_level",
            )
            .expect("the conjectured security estimator is exported from the core library")
    }

    /// Returns the MAST root of the common recursive proven security estimator.
    ///
    /// Like the conjectured estimator, it encodes no acceptance threshold and does not
    /// authenticate caller-assembled descriptors.
    pub fn proven_security_estimator_root(&self) -> Word {
        self.code
            .package()
            .get_procedure_root_by_path(
                "::miden::core::stark::security::compute_proven_security_level",
            )
            .expect("the proven security estimator is exported from the core library")
    }

    /// Returns the default event handlers required by the core library.
    ///
    /// Stack and memory print-style debug handlers write to stdout by default. These handlers can
    /// print private values if a program moves witness data onto the operand stack or into memory.
    /// Hosts can replace those handlers to route output to a UI, log, no-op handler, or other sink.
    /// Advice debug handlers can expose witness data directly, so hosts must opt into those
    /// explicitly by extending this handler set with
    /// [`crate::handlers::debug::advice_debug_handlers`].
    pub fn handlers(&self) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        let mut handlers: Vec<(EventName, Arc<dyn EventHandler>)> = vec![
            (AEAD_EIDOS_DECRYPT_EVENT_NAME, Arc::new(handle_aead_eidos_decrypt)),
            (SMT_PEEK_EVENT_NAME, Arc::new(handle_smt_peek)),
            (ENVIRONMENT_BUILD_TREE_EVENT_NAME, Arc::new(handle_environment_build_tree)),
            (U64_DIV_EVENT_NAME, Arc::new(handle_u64_div)),
            (U128_DIV_EVENT_NAME, Arc::new(handle_u128_div)),
            (U256_DIV_EVENT_NAME, Arc::new(handle_u256_div)),
            (FALCON_DIV_EVENT_NAME, Arc::new(handle_falcon_div)),
            (LOWERBOUND_ARRAY_EVENT_NAME, Arc::new(handle_lowerbound_array)),
            (LOWERBOUND_KEY_VALUE_EVENT_NAME, Arc::new(handle_lowerbound_key_value)),
            (ECDSA_K256_KECCAK_RECOVER_EVENT_NAME, Arc::new(handle_ecdsa_k256_keccak_recover)),
            (ECDSA_P256_SHA256_RECOVER_EVENT_NAME, Arc::new(handle_ecdsa_p256_sha256_recover)),
            (KECCAK256_DIGEST_EVENT_NAME, Arc::new(handle_keccak256_digest)),
            (SHA512_DIGEST_EVENT_NAME, Arc::new(handle_sha512_digest)),
            (SHA256_DIGEST_EVENT_NAME, Arc::new(handle_sha256_digest)),
            (ED25519_DECOMPRESS_EVENT_NAME, Arc::new(handle_ed25519_decompress)),
            (UINT_FIELD_INV_EVENT_NAME, Arc::new(handle_uint_field_inv)),
        ];
        handlers.extend(default_debug_handlers());
        handlers.extend(readonly_noop_handlers());
        handlers
    }
}

impl Default for CoreLibrary {
    fn default() -> Self {
        static CORELIB: LazyLock<CoreLibrary> = LazyLock::new(|| {
            let package = Arc::new(
                Package::read_from_bytes_trusted(CoreLibrary::SERIALIZED)
                    .expect("failed to read core package!"),
            );
            let naming = Arc::new(embedded_naming::reconstruct());
            let code = CodePackage::new(package, naming)
                .expect("embedded core package must match its compiler-owned naming");

            CoreLibrary { code }
        });
        CORELIB.clone()
    }
}

/// Returns the MAST root of the common recursive conjectured security estimator.
pub fn conjectured_security_estimator_root() -> Word {
    CoreLibrary::default().conjectured_security_estimator_root()
}

/// Returns the MAST root of the common recursive proven security estimator.
pub fn proven_security_estimator_root() -> Word {
    CoreLibrary::default().proven_security_estimator_root()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    use alloc::format;

    use miden_core::program::Namespace;
    use miden_mast_package::{CallableProcedurePath, NamespacePath};
    use miden_verifier::Verifier;

    use super::*;

    fn callable_path(components: &[&str]) -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).into()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn embedded_naming_preserves_private_address_taken_procedures() {
        let core_lib = CoreLibrary::default();
        let naming = core_lib.naming();
        let path = callable_path(&["miden", "core", "sys", "vm", "ood_frames", "pipe_2"]);
        let key = NamespacePath::new(vec![]).callable_procedure_key(&path).unwrap();
        let binding = naming.callables().binding(key).expect("private pipe_2 must retain its name");

        assert_eq!(binding.path(), &path);
        assert!(binding.namespace_plan().home().is_empty());
        assert_ne!(binding.parent_namespace(), Namespace::initial());
        assert!(naming.callables().selected_implementation(key).is_some());
        assert!(naming.callables().visible_paths().all(|(_, visible_key)| *visible_key != key));
        core_lib.package().check_naming(naming).unwrap();
    }

    #[test]
    fn owned_core_inventory_executes_through_shared_test_import() {
        let core = CoreLibrary::default();
        let test = miden_utils_testing::Test::new(
            "owned_core_import",
            "use miden::core::math::u64\nbegin push.0.2.0.3 exec.u64::wrapping_add swap drop swap drop end",
            false,
        )
        .with_library_and_naming(core.package(), core.naming().clone());
        let (output, _) = test.execute_for_output().expect("owned core import must execute");
        assert_eq!(output.stack.get_element(0), Some(miden_core::Felt::from_u32(5)));
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    struct ExportedPackageFile(std::path::PathBuf);

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    impl ExportedPackageFile {
        fn new(bytes: &[u8]) -> Self {
            use core::sync::atomic::{AtomicUsize, Ordering};

            static NEXT_EXPORT: AtomicUsize = AtomicUsize::new(0);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "miden-core-package-{}-{timestamp}-{}",
                std::process::id(),
                NEXT_EXPORT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&directory).unwrap();
            let exported = Self(directory.join("miden-core.masp"));
            std::fs::write(&exported.0, bytes).unwrap();
            exported
        }

        fn read(&self) -> Package {
            Package::deserialize_from_file(&self.0)
                .expect("exported package must pass safe decoding")
        }
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    impl Drop for ExportedPackageFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_dir(self.0.parent().unwrap());
        }
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    #[test]
    fn exported_core_package_matches_embedded_execution() {
        let core = CoreLibrary::default();
        // This is the same complete artifact written by generate-package.
        let file = ExportedPackageFile::new(CoreLibrary::SERIALIZED);
        let imported = Arc::new(file.read());
        imported.check_naming(core.naming()).unwrap();
        assert_eq!(
            imported.naming_transport().as_bytes(),
            core.code.package().naming_transport().as_bytes()
        );
        assert_eq!(imported.mast_forest_commitment(), core.code.package().mast_forest_commitment());
        assert_eq!(imported.mast_forest().advice_map(), core.mast_forest().advice_map());

        let source = "use miden::core::math::u64\nbegin push.0.2.0.3 exec.u64::wrapping_add swap drop swap drop end";
        let execute = |package| {
            miden_utils_testing::Test::new("exported_core_import", source, false)
                .with_library_and_naming(package, core.naming().clone())
                .execute_for_output()
                .expect("embedded and exported core imports must execute")
                .0
                .stack
        };
        let embedded_stack = execute(core.package());
        assert_eq!(embedded_stack.get_element(0), Some(miden_core::Felt::from_u32(5)));
        assert_eq!(execute(imported), embedded_stack);
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    #[test]
    fn exported_core_package_retains_arbitrary_advice_and_private_callback() {
        use miden_core::{
            Felt, advice::AdviceMap, chiplets::hasher::hash_elements, serde::Serializable,
        };
        use miden_processor::ContextId;

        const CALLBACK_PTR: u32 = 100;
        const ALPHA_PTR: u32 = 1_000;
        const OUTPUT_PTR: u32 = 2_000;
        const RESULT_PTR: u32 = 3_000;

        let core = CoreLibrary::default();
        let path = callable_path(&["miden", "core", "sys", "vm", "ood_frames", "pipe_2"]);
        let key = NamespacePath::new(vec![]).callable_procedure_key(&path).unwrap();
        let implementation = core.naming().callables().selected_implementation(key).unwrap();
        let key = key.into_word();
        let advice_key = Word::from([91_u32, 92, 93, 94]);
        let values: Vec<_> = (1..=16).map(Felt::from_u32).collect();
        assert_ne!(advice_key, hash_elements(&values), "the sentinel is arbitrary-key advice");
        let mut advice = AdviceMap::default();
        assert!(!core.mast_forest().advice_map().contains_key(&advice_key));
        advice.insert(advice_key, values.clone());
        let package = core.code.package().as_ref().clone().with_advice_map(advice);
        let file = ExportedPackageFile::new(&package.to_bytes());
        let imported = Arc::new(file.read());
        imported.check_naming(core.naming()).unwrap();
        assert_eq!(imported.mast_forest().advice_map().get(&advice_key).unwrap().as_ref(), &values);
        assert!(
            imported
                .mast_forest()
                .local_procedure_digests()
                .any(|root| root == implementation.into_word())
        );

        let source = format!(
            "use miden::core::math::u64
            begin
                # Enter the imported forest before requesting its package-owned advice.
                push.0.2.0.3 exec.u64::wrapping_add swap drop swap drop drop
                push.{k3}.{k2}.{k1}.{k0} mem_storew_le.{CALLBACK_PTR} dropw
                push.{a3}.{a2}.{a1}.{a0} adv.push_mapval dropw
                push.0.0.5.3 mem_storew_le.{ALPHA_PTR} dropw
                push.9.7.{ALPHA_PTR}.{OUTPUT_PTR}
                push.22.21.20.19 padw padw
                push.{CALLBACK_PTR} dynexec
                dropw dropw dropw
                mem_store.{RESULT_PTR} mem_store.{result_alpha_ptr} drop drop
            end",
            k0 = key[0].as_canonical_u64(),
            k1 = key[1].as_canonical_u64(),
            k2 = key[2].as_canonical_u64(),
            k3 = key[3].as_canonical_u64(),
            a0 = advice_key[0].as_canonical_u64(),
            a1 = advice_key[1].as_canonical_u64(),
            a2 = advice_key[2].as_canonical_u64(),
            a3 = advice_key[3].as_canonical_u64(),
            result_alpha_ptr = RESULT_PTR + 1,
        );
        let test = miden_utils_testing::Test::new("exported_core_callback", &source, false)
            .with_library_and_naming(imported, core.naming().clone());
        assert!(test.advice_inputs.stack().is_empty());
        assert!(test.advice_inputs.map().is_empty(), "advice must come only from the package");
        let (output, _) = test.execute_for_output().expect("exported private pipe_2 must execute");
        for (offset, expected) in values.iter().enumerate() {
            assert_eq!(
                output
                    .memory
                    .read_element(ContextId::root(), Felt::from_u32(OUTPUT_PTR + offset as u32))
                    .unwrap(),
                *expected,
                "private pipe_2 must retain advice lane {offset}",
            );
        }
        assert_eq!(
            output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(RESULT_PTR))
                .unwrap(),
            Felt::from_u32(OUTPUT_PTR + 16),
        );
        assert_eq!(
            output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(RESULT_PTR + 1))
                .unwrap(),
            Felt::from_u32(ALPHA_PTR),
        );
        assert!(output.advice.stack().is_empty(), "pipe_2 must consume exactly sixteen felts");
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    #[test]
    fn declaration_only_caller_accepts_independently_selected_exported_implementations() {
        use miden_assembly::{
            Assembler, CallableDeclaration, NamespaceInputs, Path, ProcedureName,
            ast::{Ident, Module},
            debuginfo::DefaultSourceManager,
        };
        use miden_core::{
            Felt,
            mast::MastNode,
            program::{CanonicalLabel, StackInputs},
            serde::Serializable,
        };
        use miden_mast_package::TargetType;
        use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, advice::AdviceInputs};
        use miden_utils_testing::librarytree::{
            FixtureEnvironment, assemble_fixture_program, trace_limits,
        };

        let binding = ProcedureName::new(
            NamespacePath::new(vec![CanonicalLabel::text("core-packaging-fixture").unwrap()]),
            callable_path(&["service", "answer"]),
        )
        .unwrap();
        let source_manager = Arc::new(DefaultSourceManager::default());
        let mut assembler = Assembler::new(source_manager.clone());
        assembler
            .link_callable_declarations(
                Arc::from(Path::new("::supplied")),
                [CallableDeclaration::new(Ident::new("answer").unwrap(), binding.clone())],
            )
            .unwrap();
        let caller = assemble_fixture_program(
            assembler,
            "declaration_only_supply",
            "use supplied\nbegin exec.supplied::answer end",
            &[],
        );
        assert!(caller.0.symbols().callables().selected_implementation(binding.key()).is_none());
        assert!(caller.0.package().mast_forest().nodes().iter().any(
            |node| matches!(node, MastNode::Exec(exec) if exec.target() == binding.key()),
        ));

        let mut previous = None;
        for value in [29, 31] {
            let module = Module::parser(None)
                .parse_str(
                    Some(Path::new("::supplied")),
                    format!("namespace supplied\npub proc answer push.{value} swap drop end"),
                    source_manager.clone(),
                )
                .unwrap();
            let inputs = NamespaceInputs::new()
                .with_namespace_plan(binding.namespace_plan().clone())
                .with_callable_binding(Arc::from(Path::new("::supplied::answer")), binding.clone())
                .unwrap();
            let product = Assembler::new(source_manager.clone())
                .with_namespace_inputs(inputs)
                .assemble_library_modules("selected-supply".into(), module, [], TargetType::Library)
                .unwrap();
            let naming = product.naming().clone();
            let package = product.into_artifact(true).unwrap();
            let file = ExportedPackageFile::new(&package.to_bytes());
            let imported = Arc::new(file.read());
            imported.check_naming(&naming).unwrap();
            let environment = FixtureEnvironment::new(
                caller.0.symbols().entry_key().unwrap(),
                [caller.0.symbols().as_ref(), &naming],
            )
            .unwrap();
            let implementation = naming.callables().selected_implementation(binding.key()).unwrap();
            let descriptor = environment.target();
            assert_eq!(descriptor.entry_key(), caller.0.symbols().entry_key().unwrap());
            if let Some((previous_implementation, previous_environment)) = previous {
                assert_ne!(implementation, previous_implementation);
                assert_ne!(descriptor.environment_root(), previous_environment);
            }
            previous = Some((implementation, descriptor.environment_root()));

            let mut host = DefaultHost::default()
                .with_environment_source(environment.source())
                .with_library(caller.0.clone())
                .expect("caller code must load into the host")
                .with_library(CodePackage::new(imported, Arc::new(naming.clone())).unwrap())
                .unwrap();
            let output = FastProcessor::new_with_options(
                StackInputs::default(),
                AdviceInputs::default(),
                ExecutionOptions::default()
                    .with_resolution_limits(environment.resolution_limits())
                    .with_environment_trace_limits(trace_limits()),
            )
            .unwrap()
            .execute_sync(environment.target(), &mut host)
            .expect("the unchanged declaration-only caller must use the authorized supply");
            assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(value)));
        }
    }

    #[test]
    fn embedded_reexports_keep_the_defining_callable_key() {
        let core_lib = CoreLibrary::default();
        let callables = core_lib.naming().callables();
        let defining = callable_path(&["miden", "core", "stark", "verifier", "verify"]);
        let alias = callable_path(&["miden", "core", "stark", "verify"]);
        let home = NamespacePath::new(vec![]);
        let key = home.callable_procedure_key(&defining).unwrap();

        assert_eq!(callables.key_for_visible_path(&alias), Some(key));
        assert_eq!(callables.binding(key).unwrap().path(), &defining);
        assert_ne!(key, home.callable_procedure_key(&alias).unwrap());
    }

    #[test]
    fn embedded_package_rejects_a_different_retained_compilation_home() {
        let core_lib = CoreLibrary::default();
        let naming = core_lib.naming();
        let different = PackageSymbols::new(
            NamespacePath::new(vec![miden_core::program::CanonicalLabel::text("other").unwrap()]),
            naming.callables().clone(),
            naming.entry_key(),
        )
        .unwrap();

        assert!(core_lib.package().check_naming(&different).is_err());
    }

    fn core_package_versions_match(
        crate_version: &miden_mast_package::Version,
        package_version: &miden_mast_package::Version,
    ) -> bool {
        if !crate_version.pre.is_empty() || !package_version.pre.is_empty() {
            crate_version == package_version
        } else {
            (crate_version.major, crate_version.minor)
                == (package_version.major, package_version.minor)
        }
    }

    #[test]
    fn core_package_version_matches_crate_release_line() {
        let core_lib = CoreLibrary::default();
        let package_version = &core_lib.code.package().version;
        let crate_version = env!("CARGO_PKG_VERSION")
            .parse::<miden_mast_package::Version>()
            .expect("crate version should be a valid package version");

        assert!(
            core_package_versions_match(&crate_version, package_version),
            "embedded package {} version {} does not match the miden-core-lib crate version {}",
            core_lib.code.package().name,
            package_version,
            crate_version,
        );
    }

    #[test]
    fn core_package_version_policy() {
        for (crate_version, package_version, expected) in [
            ("0.36.4", "0.36.3", true),
            ("1.0.1", "1.0.0", true),
            ("1.0.0", "1.0.1", true),
            ("1.0.0-rc.0", "1.0.0-rc.0", true),
            ("1.0.0-rc.0", "1.0.0-rc.1", false),
            ("1.0.0-rc.0", "1.0.1-rc.0", false),
            ("1.0.1-rc.0", "1.0.0-rc.0", false),
            ("1.0.0-rc.0", "1.0.0", false),
            ("1.0.0", "1.0.0-rc.0", false),
            ("1.0.0", "1.1.0", false),
            ("1.0.0", "2.0.0", false),
        ] {
            let crate_version = crate_version.parse().unwrap();
            let package_version = package_version.parse().unwrap();
            assert_eq!(
                core_package_versions_match(&crate_version, &package_version),
                expected,
                "crate {crate_version}, package {package_version}",
            );
        }
    }

    #[test]
    fn core_package_debug_info_is_readable_with_standard_limits() {
        let core_lib = CoreLibrary::default();
        let debug_info = core_lib
            .package()
            .debug_info()
            .expect("embedded core library debug info must satisfy standard decode limits")
            .expect("embedded core library should contain debug info");

        assert!(!debug_info.functions().is_empty());
        assert!(!debug_info.nodes().is_empty());
    }

    #[test]
    fn exported_procedures_have_type_signatures() {
        use miden_mast_package::PackageExport;

        let core_lib = CoreLibrary::default();
        let missing: Vec<_> = core_lib
            .package()
            .manifest
            .exports()
            .filter_map(|export| match export {
                PackageExport::Procedure(procedure) if procedure.signature.is_none() => {
                    Some(procedure.path.clone())
                },
                _ => None,
            })
            .collect();

        assert!(missing.is_empty(), "procedures without binding signatures: {missing:?}");
    }

    #[test]
    fn test_compile() {
        let core_lib = CoreLibrary::default();
        let exists = core_lib
            .code
            .package()
            .get_procedure_root_by_path("::miden::core::math::u64::overflowing_add")
            .is_some();

        assert!(exists);
    }

    #[test]
    fn proof_compatibility_identities_match_the_embedded_core_library() {
        let core_lib = CoreLibrary::default();
        let compatibility = Verifier::proof_compatibility();

        assert_eq!(
            [
                compatibility.vm_verifier_identities().last().copied(),
                compatibility.pvm_verifier_identities().last().copied(),
            ],
            [
                Some(core_lib.vm_recursive_verifier_profile().unwrap().identity()),
                Some(core_lib.pvm_recursive_verifier_profile().unwrap().identity()),
            ],
            "current VM/PVM compatibility identities must match both embedded profiles",
        );
    }
}
