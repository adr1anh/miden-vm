//! Eidos domains maintained by `miden-vm`.
//!
//! Numeric tags use the `miden-vm` namespace allocated by `miden-crypto`. MAST control nodes keep
//! their opcode-based framing; those tags are below 256 and therefore disjoint from every
//! registered domain tag.

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
            pub KERNEL_COMMITMENT: KernelCommitmentDomain {
                local_id: 0x0000,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM kernel commitment.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0; payload = procedure digests in canonical order",
            }
            pub EXECUTION_CLAIM: ExecutionClaimDomain {
                local_id: 0x0001,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM execution-claim commitment.",
                schema: "param0 = 40; param1 = 0; param2 = 0; payload = program root || kernel commitment || stack inputs || stack outputs",
            }
            pub PROOF_REQUEST: ProofRequestDomain {
                local_id: 0x0002,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM recursive-proof request key.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = claim commitment || verifier root",
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
            pub ENV_MERKLE: EnvMerkleDomain {
                local_id: 0x0107,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Binary environment-collection commitment.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = left child commitment || right child commitment",
            }
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
            pub EXEC_VERIFIER_CONFIG: ExecutionVerifierConfigDomain {
                local_id: 0x010a,
                version: DomainVersion::numbered(2),
                encoding: FeltSequence,
                description: "Execution-verifier configuration with authorized kernel namespace.",
                schema: "param0 = 14 + 8 * mount count, checked u32; param1 = 0; param2 = 0; payload = 2 || entry implementation root || authorized kernel namespace || mount count || unique mount pairs sorted lexicographically by canonical Felt coordinates, namespace before fragment commitment || resource inventory root",
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
    use miden_crypto::hash::eidos::{DomainEncoding, Eidos};

    use super::*;
    use crate::Word;

    #[test]
    fn librarytree_domains_have_selected_tags_and_felt_sequence_encoding() {
        let domains = [
            (EnvLabelDomain::TAG, 0x0101_0001),
            (EnvNamespaceDomain::TAG, 0x0101_0101),
            (EnvProcedureDomain::TAG, 0x0101_0201),
            (EnvInitialNamespaceDomain::TAG, 0x0101_0301),
            (EnvEnvironmentDomain::TAG, 0x0101_0401),
            (EnvMastDomain::TAG, 0x0101_0501),
            (EnvDataDomain::TAG, 0x0101_0601),
            (EnvMerkleDomain::TAG, 0x0101_0701),
            (EnvListDomain::TAG, 0x0101_0801),
            (ExecutionVerifierIdentityDomain::TAG, 0x0101_0901),
            (ExecutionVerifierConfigDomain::TAG, 0x0101_0a02),
        ];

        for (tag, expected) in domains {
            assert_eq!(tag.as_u32(), expected);
            let registered = MidenVmDomainRegistry::resolve(tag).unwrap();
            assert_eq!(registered.encoding, DomainEncoding::FeltSequence);
            assert!(MidenCryptoDomainRegistry::resolve(tag).is_none());
        }
    }

    #[test]
    fn librarytree_domains_use_standard_felt_sequence_framing() {
        assert_framing(ENV_LABEL, 0x0101_0001, &[3, 8, 9]);
        assert_framing(ENV_NAMESPACE, 0x0101_0101, &[8]);
        assert_framing(ENV_PROCEDURE, 0x0101_0201, &[8]);
        assert_framing(ENV_INITIAL_NAMESPACE, 0x0101_0301, &[0]);
        assert_framing(ENV_ENVIRONMENT, 0x0101_0401, &[8]);
        assert_framing(ENV_MAST, 0x0101_0501, &[8]);
        assert_framing(ENV_DATA, 0x0101_0601, &[9]);
        assert_framing(ENV_MERKLE, 0x0101_0701, &[8]);
        assert_framing(ENV_LIST, 0x0101_0801, &[0, 4, 8, 12, 16]);
        assert_framing(EXEC_VERIFIER_IDENTITY, 0x0101_0901, &[12]);
        assert_framing(EXEC_VERIFIER_CONFIG, 0x0101_0a02, &[14, 22, 30]);
    }

    fn assert_framing<D: EidosDomain<Encoding = FeltSequence>>(
        domain: D,
        expected_tag: u32,
        lengths: &[usize],
    ) {
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
        // Frozen with an independent portable seven-round BLAKE3/Eidos reference, checked
        // against the existing generic empty/three/nine-Felt vectors before generation.
        let values: [Felt; 16] = core::array::from_fn(|i| Felt::new_unchecked(i as u64 + 1));
        assert_digest(
            Eidos::hash_elements_in_domain::<Felt, _>(&[], ENV_INITIAL_NAMESPACE),
            [0x5af63cdc05e1732d, 0x7c441ffa1c95ee1f, 0x2e3dd14274ac5042, 0x09b0dc5782213a88],
        );
        assert_digest(
            Eidos::hash_elements_in_domain(&values[..8], ENV_MAST),
            [0x76a21bdd521eb27c, 0x538aee3ce71df85f, 0x7c8c00e95287c8b6, 0x7a73ead02e72e653],
        );
        assert_digest(
            Eidos::hash_elements_in_domain(&values[..9], ENV_DATA),
            [0x59e40b3a16b1b993, 0x50d873816f0bd20a, 0x671171ee8071b0f4, 0x4d7c72cb5c923b6e],
        );

        for (len, expected) in [
            (
                0,
                [0x3258664aa5f02db7, 0x0b248f02121839b7, 0x5db42a4793f149b6, 0x7a1ab3af0539329c],
            ),
            (
                4,
                [0x0c6831af14d87b1f, 0x17b547dfbead3a70, 0x199aee8fd2c58ed5, 0x27dc1cf2a173c8ea],
            ),
            (
                8,
                [0x77d67983f464a2e3, 0x3451a1d734b705cf, 0x14fd39789f626185, 0x1aa37d8e964752ce],
            ),
            (
                12,
                [0x09a701a624b97bf4, 0x1e11ca00e9494ddd, 0x5bd3080c42bf3ca4, 0x3c991f217d93a142],
            ),
            (
                16,
                [0x7ba869013b8d083a, 0x3edf5c1cb5784611, 0x6cf0488eedf1ea9b, 0x658b24e150123ac4],
            ),
        ] {
            assert_digest(Eidos::hash_elements_in_domain(&values[..len], ENV_LIST), expected);
        }

        assert_digest(
            Eidos::hash_elements_in_domain(&values[..12], EXEC_VERIFIER_IDENTITY),
            [0x70478a6f4d5cee97, 0x3142c3b5ecb6e152, 0x169528d9edd6ce56, 0x096ea99f5a42c4fb],
        );
        let empty_mount_config =
            [2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 9, 10, 11, 12].map(Felt::new_unchecked);
        assert_digest(
            Eidos::hash_elements_in_domain(&empty_mount_config, EXEC_VERIFIER_CONFIG),
            [0x0d6127ffae6b9711, 0x1f14f10ceca2f563, 0x446b997553ff121a, 0x5daf09ff386b0156],
        );
    }

    fn assert_digest(actual: Word, expected: [u64; 4]) {
        assert_eq!(actual, Word::new(expected.map(Felt::new_unchecked)));
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
