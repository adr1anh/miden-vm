//! Content-addressing for recursive proof packages.

use miden_crypto::hash::eidos::EidosDomain;

use super::VerifierIdentity;
use crate::{Felt, Word, ZERO, chiplets::hasher};

/// Registered v2 domain tag for proof-request keys.
pub const PROOF_REQUEST_DOMAIN_TAG: Felt = super::domain::ProofRequestDomain::TAG.as_felt();

/// Returns the advice-map key addressing a proof package for `claim_commitment` under the
/// caller's `expected_verifier` identity.
///
/// The v2 key is `H_tag(claim_commitment[4] ‖ expected_verifier[4])`: exactly eight Felts in
/// forward coordinate order, hashed as one Eidos FeltSequence block. The verifier identity
/// commits to its relation, entry procedure key, and configuration; an implementation root or
/// `procref` procedure key alone is not a verifier identity. The retired v1 domain is not used.
///
/// The key is a lookup address, not a trust anchor. The caller supplies its expected identity
/// and claim independently of advice, and the verifier re-checks the retrieved package against
/// its statement. Deriving a request key does not authorize that identity or settle the verified
/// claim's deferred obligations.
pub fn proof_request_key(expected_verifier: VerifierIdentity, claim_commitment: Word) -> Word {
    let mut preimage = [ZERO; 2 * 4];
    preimage[0..4].copy_from_slice(claim_commitment.as_elements());
    preimage[4..8].copy_from_slice(expected_verifier.as_word().as_elements());
    hasher::hash_elements_in_domain(&preimage, super::domain::PROOF_REQUEST)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_crypto::hash::eidos::{DomainEncoding, DomainTag, Eidos, EidosFrame};

    use super::{super::domain, *};
    use crate::program::{ImplementationRoot, ProcedureKey, VerifierConfiguration};

    #[test]
    fn request_uses_v2_length_eight_and_claim_then_identity_in_one_compression() {
        let identity = test_identity();
        let claim = word([21, 22, 23, 24]);
        let [v0, v1, v2, v3] = identity.into_word().into_elements();
        let block = [felt(21), felt(22), felt(23), felt(24), v0, v1, v2, v3];

        // Pin the fixed high IV lanes, numeric v2 tag, exact logical length, and the sole
        // payload block without deriving the reference frame or payload through the helper.
        let initial = request_initial_word();
        assert_eq!(PROOF_REQUEST_DOMAIN_TAG.as_canonical_u64(), 0x0100_0202);
        assert_eq!(PROOF_REQUEST_DOMAIN_TAG, domain::ProofRequestDomain::TAG.as_felt());
        assert_eq!(Eidos::init_chaining_word(domain::PROOF_REQUEST, 8), initial);
        let registered =
            domain::MidenVmDomainRegistry::resolve(domain::ProofRequestDomain::TAG).unwrap();
        assert_eq!(registered.encoding, DomainEncoding::FeltSequence);
        assert_eq!(proof_request_key(identity, claim), Eidos::compress(initial, block));

        let swapped = [v0, v1, v2, v3, felt(21), felt(22), felt(23), felt(24)];
        let reversed = [felt(24), felt(23), felt(22), felt(21), v3, v2, v1, v0];
        assert_ne!(proof_request_key(identity, claim), Eidos::compress(initial, swapped));
        assert_ne!(proof_request_key(identity, claim), Eidos::compress(initial, reversed));
    }

    #[test]
    fn every_request_payload_coordinate_changes_the_key() {
        let identity = test_identity();
        let claim = word([21, 22, 23, 24]);
        let [v0, v1, v2, v3] = identity.into_word().into_elements();
        let block = [felt(21), felt(22), felt(23), felt(24), v0, v1, v2, v3];
        let expected = proof_request_key(identity, claim);

        // Exercise each committed coordinate through the request helper against the independent
        // compression oracle. Wrapping a changed identity is only a representation operation.
        for coordinate in 0..block.len() {
            let mut changed = block;
            changed[coordinate] += felt(100);
            assert_ne!(
                Eidos::compress(request_initial_word(), changed),
                expected,
                "request coordinate {coordinate}",
            );
            if coordinate < 4 {
                let changed_claim = Word::new(changed[..4].try_into().unwrap());
                assert_eq!(
                    proof_request_key(identity, changed_claim),
                    Eidos::compress(request_initial_word(), changed),
                );
            } else {
                let changed_identity =
                    VerifierIdentity::new(Word::new(changed[4..].try_into().unwrap()));
                assert_eq!(
                    proof_request_key(changed_identity, claim),
                    Eidos::compress(request_initial_word(), changed),
                );
            }
        }
    }

    #[test]
    fn request_v1_is_retired_and_separated_even_for_identical_payload_bytes() {
        let identity = test_identity();
        let claim = word([21, 22, 23, 24]);
        let [v0, v1, v2, v3] = identity.into_word().into_elements();
        let block = [felt(21), felt(22), felt(23), felt(24), v0, v1, v2, v3];
        let legacy_tag = DomainTag::from_u32(0x0100_0201).unwrap();
        assert!(domain::MidenVmDomainRegistry::resolve(legacy_tag).is_none());
        let legacy_initial = EidosFrame::new(legacy_tag, [8, 0, 0]).initial_chaining_word();
        let expected = proof_request_key(identity, claim);
        assert_ne!(expected, Eidos::compress(legacy_initial, block));
        assert_ne!(expected, hasher::hash_elements(&block));
        assert_ne!(
            expected,
            hasher::hash_elements_in_domain(&block, domain::EXEC_VERIFIER_IDENTITY),
        );
    }

    #[test]
    fn equal_implementation_roots_do_not_alias_entry_configuration_or_relation() {
        let implementation = ImplementationRoot::new(word([1, 2, 3, 4]));
        let config =
            VerifierConfiguration::new(implementation, vec![], word([9, 10, 11, 12])).unwrap();
        let other_config =
            VerifierConfiguration::new(implementation, vec![], word([109, 10, 11, 12])).unwrap();
        assert_eq!(config.entry_implementation(), other_config.entry_implementation());
        assert_ne!(config.commitment().unwrap(), other_config.commitment().unwrap());

        let relation = word([13, 14, 15, 16]);
        let entry = ProcedureKey::new(word([5, 6, 7, 8]));
        let identity = VerifierIdentity::derive(relation, entry, config.commitment().unwrap());
        let claim = word([21, 22, 23, 24]);
        let expected = proof_request_key(identity, claim);
        for other in [
            VerifierIdentity::derive(
                relation,
                ProcedureKey::new(word([105, 6, 7, 8])),
                config.commitment().unwrap(),
            ),
            VerifierIdentity::derive(relation, entry, other_config.commitment().unwrap()),
            VerifierIdentity::derive(word([113, 14, 15, 16]), entry, config.commitment().unwrap()),
        ] {
            assert_ne!(other, identity);
            assert_ne!(proof_request_key(other, claim), expected);
        }

        // The selected identity is neither D nor K. Hashing either root as the second word
        // cannot name the package registered for the relation/entry/configuration identity.
        for root in [implementation.into_word(), entry.into_word()] {
            let mut substituted = [ZERO; 8];
            substituted[..4].copy_from_slice(claim.as_slice());
            substituted[4..].copy_from_slice(root.as_slice());
            assert_ne!(Eidos::compress(request_initial_word(), substituted), expected);
        }
    }

    fn test_identity() -> VerifierIdentity {
        let config = VerifierConfiguration::new(
            ImplementationRoot::new(word([1, 2, 3, 4])),
            vec![],
            word([9, 10, 11, 12]),
        )
        .unwrap();
        VerifierIdentity::derive(
            word([13, 14, 15, 16]),
            ProcedureKey::new(word([5, 6, 7, 8])),
            config.commitment().unwrap(),
        )
    }

    fn request_initial_word() -> Word {
        Word::new([
            felt(0xbb67_ae85_0100_0202),
            felt(0xa54f_f53a_0000_0008),
            felt(0x9b05_688c_0000_0000),
            felt(0x5be0_cd19_0000_0000),
        ])
    }

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(felt))
    }

    fn felt(value: u64) -> Felt {
        Felt::new_unchecked(value)
    }
}
