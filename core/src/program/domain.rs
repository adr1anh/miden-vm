//! Eidos domains maintained by `miden-vm`.
//!
//! Numeric tags use the `miden-vm` namespace allocated by `miden-crypto`. MAST control nodes keep
//! their opcode-based framing; those tags are below 256 and therefore disjoint from every
//! registered domain tag.
//!
//! Local ID `0x0000` and tag `0x0100_0001` (numbered version 1) belonged to the retired
//! kernel-inventory commitment. This allocation remains reserved and must never be reused.
//! Local ID `0x0107` and tag `0x0101_0701` belonged to the retired environment Merkle domain.
//! That allocation also remains reserved. Binary environment collections now use the native
//! Merkle compression frame, whose four injected lanes are zero and which is not registered.

pub use miden_crypto::hash::eidos::DomainTag;
#[cfg(test)]
use miden_crypto::hash::eidos::domains::MidenCryptoDomainRegistry;
use miden_crypto::hash::eidos::{
    Custom, DomainVersion, FeltSequence, Transcript, domain::EidosDomain, namespace,
};

use crate::Felt;

/// Number of Felts in the Falcon product-check transcript payload.
pub const FALCON_PRODUCT_CHECK_PAYLOAD_LEN: u32 = 8 + 512 + 1024;

miden_crypto::eidos_domain_registry! {
    /// Domains maintained by `miden-vm`.
    pub registry MidenVmDomainRegistry {
        namespace: namespace::MIDEN_VM;
        domains: {
            // Version 1 committed a program root and kernel commitment. Its tag is retired;
            // the environment-bound statement uses a distinct v2 commitment at the same length.
            pub EXECUTION_CLAIM: ExecutionClaimDomain {
                local_id: 0x0001,
                version: DomainVersion::numbered(2),
                encoding: FeltSequence,
                description: "Miden VM execution-claim commitment.",
                schema: "param0 = 40; param1 = 0; param2 = 0; payload = entry procedure key || environment root || stack inputs || stack outputs",
            }
            // Version 1 addressed requests by an implementation root. Its tag is retired;
            // version 2 binds the expected relation, entry key, and configuration identity.
            pub PROOF_REQUEST: ProofRequestDomain {
                local_id: 0x0002,
                version: DomainVersion::numbered(2),
                encoding: FeltSequence,
                description: "Miden VM recursive-proof request key.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = claim commitment || expected verifier identity; verifier identity commits relation identity || verifier entry key || verifier configuration commitment",
            }
            pub DEFERRED_AND: DeferredAndDomain {
                local_id: 0x0003,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Deferred AND node and rolling-root fold.",
                schema: "params = [0, 0, 0]; payload = exactly one block containing left digest || right digest",
            }
            pub DEFERRED_CHUNKS: DeferredChunksDomain {
                local_id: 0x0004,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Deferred framework chunk-list node.",
                schema: "param0 = encoded Felt length; param1 = 0; param2 = 0; payload = exactly param0 / 8 complete 8-Felt chunks; param0 > 0 and divisible by 8",
            }
            pub STARK_TRANSCRIPT: StarkTranscriptDomain {
                local_id: 0x0005,
                version: DomainVersion::numbered(1),
                encoding: Transcript,
                description: "Miden VM and Precompile VM STARK transcript.",
                schema: "params = [0, 0, 0]; absorb the relation digest before sampling transcript challenges",
            }
            pub KECCAK256_PRECOMPILE: Keccak256PrecompileDomain {
                local_id: 0x0006,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Keccak-256 deferred precompile nodes.",
                schema: "param0 = operation; param1 = preimage length in bytes; param2 = 0; ASSERT payload = exactly one block containing preimage digest || expected digest",
            }
            pub UINT256_PRECOMPILE: Uint256PrecompileDomain {
                local_id: 0x0007,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Uint256 deferred precompile nodes.",
                schema: "param0 = operation; VALUE uses param1 = bound pointer and one value block; binary operations use param1 = 0 and one digest-pair block; param2 = 0",
            }
            pub CURVE_PRECOMPILE: CurvePrecompileDomain {
                local_id: 0x0008,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Elliptic-curve deferred precompile nodes.",
                schema: "param0 = operation; VALUE uses param1 = group pointer and one digest-pair block; fixed binary operations use param1 = 0 and one digest-pair block; MSM uses param1 = pair count and exactly that many digest-pair blocks; param2 = 0",
            }
            pub PVM_UINT_PIN_CLAIM: PvmUintPinClaimDomain {
                local_id: 0x0009,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Precompile VM uint pin claim.",
                schema: "param0 = uint bound pointer; param1 = pin pointer; param2 = 0; payload = exactly one uint value block",
            }
            pub FALCON_PRODUCT_CHECK: FalconProductCheckDomain {
                local_id: 0x000a,
                version: DomainVersion::numbered(2),
                encoding: FeltSequence,
                description: "Falcon512-Eidos polynomial product-check transcript.",
                schema: "param0 = 1544; param1 = 0; param2 = 0; payload = public-key commitment || zero word || 512 shifted coefficients s2_i + 6144 || 1024 coefficients of h * s2 over the Miden field; s2 is centered in [-6144, 6144]",
            }
            pub SHA512_PRECOMPILE: Sha512PrecompileDomain {
                local_id: 0x000b,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "SHA-512 deferred precompile nodes.",
                schema: "param0 = operation; param1 = preimage length in bytes; param2 = 0; ASSERT payload = exactly one block containing preimage digest || expected digest",
            }
            pub SHA256_PRECOMPILE: Sha256PrecompileDomain {
                local_id: 0x000c,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "SHA-256 deferred precompile nodes.",
                schema: "param0 = operation; param1 = preimage length in bytes; param2 = 0; ASSERT payload = exactly one block containing preimage digest || expected digest",
            }
            pub ENV_LABEL: EnvLabelDomain {
                local_id: 0x0100,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Typed environment-label commitment.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0; payload = byte length of canonical label envelope followed by its little-endian u32 chunks, each embedded in one Felt",
            }
            pub ENV_NAMESPACE: EnvNamespaceDomain {
                local_id: 0x0101,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Accumulated environment namespace.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = inherited namespace || local label commitment",
            }
            pub ENV_PROCEDURE: EnvProcedureDomain {
                local_id: 0x0102,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Namespace-qualified callable procedure key.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = inherited namespace || export label commitment",
            }
            pub ENV_INITIAL_NAMESPACE: EnvInitialNamespaceDomain {
                local_id: 0x0103,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Fixed initial environment namespace.",
                schema: "param0 = 0; param1 = 0; param2 = 0; payload = empty Felt sequence, compressed as one all-zero block",
            }
            pub ENV_ENVIRONMENT: EnvEnvironmentDomain {
                local_id: 0x0104,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Labeled child environment commitment.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = local label commitment || child commitment",
            }
            pub ENV_MAST: EnvMastDomain {
                local_id: 0x0105,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Labeled executable implementation commitment.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = local label commitment || implementation root; no export class or custom framing",
            }
            pub ENV_DATA: EnvDataDomain {
                local_id: 0x0106,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Typed labeled environment-data commitment.",
                schema: "param0 = 9; param1 = 0; param2 = 0; payload = type u32 || local label commitment || value word",
            }
            // Local ID 0x0107 / tag 0x0101_0701 is retired and must never be reused.
            // Binary environment collections use the reserved native Merkle frame instead.
            pub ENV_LIST: EnvListDomain {
                local_id: 0x0108,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Ordered environment-collection commitment.",
                schema: "param0 = four times child count, checked u32; param1 = 0; param2 = 0; payload = ordered child commitment words; empty input compresses one all-zero block",
            }
            pub EXEC_VERIFIER_IDENTITY: ExecutionVerifierIdentityDomain {
                local_id: 0x0109,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Runtime-linked execution-verifier identity.",
                schema: "param0 = 12; param1 = 0; param2 = 0; payload = relation identity || verifier entry key || verifier configuration commitment",
            }
            // Version 2 committed a configurable kernel namespace and is retired. Its numeric
            // tag remains reserved; fixed-root configurations use a distinct v3 commitment.
            pub EXEC_VERIFIER_CONFIG: ExecutionVerifierConfigDomain {
                local_id: 0x010a,
                version: DomainVersion::numbered(3),
                encoding: FeltSequence,
                description: "Execution-verifier configuration with fixed-root syscall semantics.",
                schema: "param0 = 10 + 8 * mount count, checked u32; param1 = 0; param2 = 0; payload = 3 || entry implementation root || mount count || unique mount pairs sorted lexicographically by canonical Felt coordinates, namespace before fragment commitment || resource inventory root",
            }
        }
    }
}

/// Returns the field-element representation of a typed Eidos domain.
pub const fn domain_tag<D: EidosDomain>(_: D) -> Felt {
    D::TAG.as_felt()
}

/// Returns whether `tag` is assigned to a deferred precompile in the VM registry.
pub(crate) fn is_vm_precompile_domain(tag: DomainTag) -> bool {
    tag == Keccak256PrecompileDomain::TAG
        || tag == Sha512PrecompileDomain::TAG
        || tag == Sha256PrecompileDomain::TAG
        || tag == Uint256PrecompileDomain::TAG
        || tag == CurvePrecompileDomain::TAG
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_crypto::hash::eidos::{DomainEncoding, Eidos};

    use super::*;
    use crate::{Word, program::test_vectors::vector};

    #[test]
    fn librarytree_domains_have_selected_tags_and_felt_sequence_encoding() {
        let domains = [
            (EnvLabelDomain::TAG, "label_text_empty"),
            (EnvNamespaceDomain::TAG, "namespace_opaque_child"),
            (EnvProcedureDomain::TAG, "namespace_opaque_procedure"),
            (EnvInitialNamespaceDomain::TAG, "namespace_initial"),
            (EnvEnvironmentDomain::TAG, "object_env"),
            (EnvMastDomain::TAG, "object_mast"),
            (EnvDataDomain::TAG, "object_data_zero"),
            (EnvListDomain::TAG, "object_list_0"),
            (ExecutionVerifierIdentityDomain::TAG, "domain_verifier_identity_sequential"),
            (ExecutionVerifierConfigDomain::TAG, "domain_verifier_config_empty_mounts"),
        ];

        for (tag, id) in domains {
            assert_eq!(tag.as_u32(), vector(id).domain_tag);
            let registered = MidenVmDomainRegistry::resolve(tag).unwrap();
            assert_eq!(registered.encoding, DomainEncoding::FeltSequence);
            assert!(MidenCryptoDomainRegistry::resolve(tag).is_none());
        }
    }

    #[test]
    fn librarytree_domains_use_standard_felt_sequence_framing() {
        assert_framing(ENV_LABEL, "label_text_empty", &[3, 8, 9]);
        assert_framing(ENV_NAMESPACE, "namespace_opaque_child", &[8]);
        assert_framing(ENV_PROCEDURE, "namespace_opaque_procedure", &[8]);
        assert_framing(ENV_INITIAL_NAMESPACE, "namespace_initial", &[0]);
        assert_framing(ENV_ENVIRONMENT, "object_env", &[8]);
        assert_framing(ENV_MAST, "object_mast", &[8]);
        assert_framing(ENV_DATA, "object_data_zero", &[9]);
        assert_framing(ENV_LIST, "object_list_0", &[0, 4, 8, 12, 16]);
        assert_framing(EXEC_VERIFIER_IDENTITY, "domain_verifier_identity_sequential", &[12]);
        assert_framing(EXEC_VERIFIER_CONFIG, "domain_verifier_config_empty_mounts", &[10, 18, 26]);
    }

    fn assert_framing<D: EidosDomain<Encoding = FeltSequence>>(
        domain: D,
        id: &str,
        lengths: &[usize],
    ) {
        let expected_tag = vector(id).domain_tag;
        let values: [Felt; 30] = core::array::from_fn(|i| Felt::new_unchecked(i as u64 + 1));
        for &len in lengths {
            // Derive the reference frame directly from the fixed IV lanes and the selected
            // numeric tag. In particular, these initial high lanes must not be output-masked.
            let mut expected = Word::new([
                Felt::new_unchecked(0xbb67_ae85_0000_0000 | u64::from(expected_tag)),
                Felt::new_unchecked(0xa54f_f53a_0000_0000 | len as u64),
                Felt::new_unchecked(0x9b05_688c_0000_0000),
                Felt::new_unchecked(0x5be0_cd19_0000_0000),
            ]);
            if len == 0 {
                expected = Eidos::compress(expected, [Felt::ZERO; 8]);
            } else {
                for chunk in values[..len].chunks(8) {
                    let mut block = [Felt::ZERO; 8];
                    block[..chunk.len()].copy_from_slice(chunk);
                    expected = Eidos::compress(expected, block);
                }
            }

            assert_eq!(Eidos::hash_elements_in_domain(&values[..len], domain), expected);
        }
    }

    #[test]
    fn frozen_librarytree_domain_vectors() {
        assert_vector(ENV_INITIAL_NAMESPACE, "namespace_initial");
        assert_vector(ENV_MAST, "object_mast_same_payload_as_env");
        assert_vector(ENV_DATA, "domain_data_sequential_9");
        for id in [
            "object_list_0",
            "domain_list_sequential_4",
            "domain_list_sequential_8",
            "domain_list_sequential_12",
            "domain_list_sequential_16",
        ] {
            assert_vector(ENV_LIST, id);
        }
        assert_vector(EXEC_VERIFIER_IDENTITY, "domain_verifier_identity_sequential");
        assert_vector(EXEC_VERIFIER_CONFIG, "domain_verifier_config_empty_mounts");
    }

    #[test]
    fn retired_environment_merkle_allocation_remains_unregistered() {
        let legacy = DomainTag::from_u32(0x0101_0701).unwrap();
        assert!(MidenVmDomainRegistry::resolve(legacy).is_none());
        assert!(MidenCryptoDomainRegistry::resolve(legacy).is_none());
        assert!(
            MidenVmDomainRegistry::domains()
                .iter()
                .all(|domain| domain.tag.local_id() != 0x0107)
        );
        // Zero denotes the reserved native Merkle frame in the fixture, not a registered tag.
        assert_eq!(vector("object_merkle").domain_tag, 0);
        assert!(DomainTag::from_u32(0).is_none());
    }

    fn assert_vector<D: EidosDomain<Encoding = FeltSequence>>(domain: D, id: &str) {
        let expected = vector(id);
        assert_eq!(domain_tag(domain).as_canonical_u64(), u64::from(expected.domain_tag));
        let payload = expected.payload.into_iter().map(Felt::new_unchecked).collect::<Vec<_>>();
        assert_eq!(
            Eidos::hash_elements_in_domain(&payload, domain),
            Word::new(expected.digest.map(Felt::new_unchecked)),
        );
    }

    #[test]
    fn crypto_and_vm_registries_are_disjoint() {
        for crypto in MidenCryptoDomainRegistry::domains() {
            assert!(MidenVmDomainRegistry::resolve(crypto.tag).is_none());
        }
        for vm in MidenVmDomainRegistry::domains() {
            assert!(MidenCryptoDomainRegistry::resolve(vm.tag).is_none());
        }
    }

    #[test]
    fn mast_opcodes_are_disjoint_from_registered_tags() {
        for domain in MidenVmDomainRegistry::domains() {
            assert!(domain.tag.as_u32() > u8::MAX as u32);
        }
    }
}
