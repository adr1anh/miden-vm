//! The execution claim: the statement a Miden VM proof attests, and its canonical commitment.
//!
//! An execution claim binds four fields: the entry procedure key `K_entry`, the environment root
//! `R_E`, the stack inputs `I`, and the stack outputs `O`. The deferred root `D` produced by
//! execution is *not* part of the claim: it is the obligation a verified claim hands back, bound
//! separately into the transcript seed.
//!
//! # Canonical encoding
//!
//! The claim encodes as exactly [`NUM_CLAIM_ELEMENTS`] = 40 field elements:
//!
//! ```text
//! offset  0..4    K_entry                    (entry procedure key)
//! offset  4..8    R_E                        (environment root)
//! offset  8..24   I  StackInputs, 16 felts    (canonical zero-padded, native order)
//! offset 24..40   O  StackOutputs, 16 felts   (canonical zero-padded, native order)
//! ```
//!
//! The code context comes first so that callsites that pin `(K_entry, R_E)` can resume the claim
//! hash from a precomputed chaining value. Forty elements is exactly five Eidos blocks, so no
//! partial block is synthesized and both read points (the `(K_entry, R_E)` prefix state and the
//! claim commitment) fall on compression boundaries.
//!
//! # Claim commitment
//!
//! `CLAIM_HASH = Eidos::hash_elements_in_domain(K_entry ‖ R_E ‖ I ‖ O, CLAIM_DOMAIN_TAG)`. The
//! initial chaining value binds both the registered domain and the exact logical length (`40`),
//! after which Eidos processes five compression blocks in sequence.

use miden_crypto::hash::eidos::EidosDomain;

use super::{EnvironmentRoot, ExecutionDescriptor, ProcedureKey, StackInputs, StackOutputs};
use crate::{Felt, Word, ZERO, chiplets::hasher};

// CONSTANTS
// ================================================================================================

/// Number of field elements in the canonical claim encoding: `K_entry ‖ R_E ‖ I ‖ O`.
pub const NUM_CLAIM_ELEMENTS: usize = 40;

/// Registered domain tag for the claim commitment.
pub const CLAIM_DOMAIN_TAG: Felt = super::domain::ExecutionClaimDomain::TAG.as_felt();

// EXECUTION CLAIM
// ================================================================================================

/// The external statement a Miden VM proof attests: the execution descriptor identifies the entry
/// procedure and its fixed code environment; the stack inputs and outputs are the execution's
/// public I/O. The caller must independently authorize the environment root and its bindings.
///
/// Stack inputs and stack outputs are both stored top-of-stack first: the first value in each
/// slice is the top of the operand stack. The claim stores both in their canonical zero-padded
/// 16-element form.
///
/// The deferred root is deliberately absent: verification returns it as an obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    execution_descriptor: ExecutionDescriptor,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
}

impl ExecutionClaim {
    /// Creates a new execution claim from the execution descriptor and stack I/O.
    pub const fn new(
        execution_descriptor: ExecutionDescriptor,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
    ) -> Self {
        Self {
            execution_descriptor,
            stack_inputs,
            stack_outputs,
        }
    }

    /// Returns the execution descriptor of this claim.
    pub const fn execution_descriptor(&self) -> ExecutionDescriptor {
        self.execution_descriptor
    }

    /// Returns the entry procedure key of this claim.
    pub const fn entry_key(&self) -> ProcedureKey {
        self.execution_descriptor.entry_key()
    }

    /// Returns the fixed environment root of this claim.
    pub const fn environment_root(&self) -> EnvironmentRoot {
        self.execution_descriptor.environment_root()
    }

    /// Returns the stack inputs of this claim.
    pub const fn stack_inputs(&self) -> &StackInputs {
        &self.stack_inputs
    }

    /// Returns the stack outputs of this claim.
    pub const fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Splits this claim into its execution descriptor and stack I/O.
    pub fn into_parts(self) -> (ExecutionDescriptor, StackInputs, StackOutputs) {
        (self.execution_descriptor, self.stack_inputs, self.stack_outputs)
    }

    /// Returns the canonical 40-element encoding `K_entry ‖ R_E ‖ I ‖ O` of this claim.
    pub fn to_elements(&self) -> [Felt; NUM_CLAIM_ELEMENTS] {
        let mut elements = [ZERO; NUM_CLAIM_ELEMENTS];
        elements[0..4].copy_from_slice(self.entry_key().into_word().as_elements());
        elements[4..8].copy_from_slice(self.environment_root().into_word().as_elements());
        elements[8..24].copy_from_slice(&self.stack_inputs[..]);
        elements[24..40].copy_from_slice(&self.stack_outputs[..]);
        elements
    }

    /// Returns the canonical commitment to this claim (`CLAIM_HASH`).
    ///
    /// This is the verifier-independent name of the claim: the value used to request proof
    /// packages and to bind verified claims into a consumer's own statement.
    pub fn commitment(&self) -> Word {
        claim_commitment(&self.to_elements())
    }
}

/// Returns the canonical claim commitment over an already-encoded claim.
///
/// This is the single implementation of `CLAIM_HASH`; every native computation of the claim
/// commitment (including the transcript observation in `miden-air`) must go through it.
pub fn claim_commitment(elements: &[Felt; NUM_CLAIM_ELEMENTS]) -> Word {
    hasher::hash_elements_in_domain(elements, super::domain::EXECUTION_CLAIM)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_crypto::hash::eidos::{DomainTag, Eidos, EidosFrame};

    use super::{super::domain, *};

    fn test_claim() -> ExecutionClaim {
        claim_from_elements(core::array::from_fn(|i| Felt::new_unchecked(i as u64 + 1)))
    }

    fn claim_from_elements(elements: [Felt; NUM_CLAIM_ELEMENTS]) -> ExecutionClaim {
        ExecutionClaim::new(
            ExecutionDescriptor::new(
                ProcedureKey::new(Word::new(elements[0..4].try_into().unwrap())),
                EnvironmentRoot::new(Word::new(elements[4..8].try_into().unwrap())),
            ),
            StackInputs::new(&elements[8..24]).unwrap(),
            StackOutputs::new(&elements[24..40]).unwrap(),
        )
    }

    #[test]
    fn claim_encoding_has_exactly_40_coordinates_in_descriptor_input_output_order() {
        let claim = test_claim();
        assert_eq!(NUM_CLAIM_ELEMENTS, 40);
        assert_eq!(
            claim.to_elements(),
            core::array::from_fn(|i| Felt::new_unchecked(i as u64 + 1)),
        );

        let descriptor = claim.execution_descriptor();
        assert_eq!(claim.entry_key(), descriptor.entry_key());
        assert_eq!(claim.environment_root(), descriptor.environment_root());
        assert_eq!(
            claim.clone().into_parts(),
            (descriptor, *claim.stack_inputs(), *claim.stack_outputs()),
        );
    }

    #[test]
    fn claim_encoding_zero_pads_each_stack_in_native_order() {
        let claim = ExecutionClaim::new(
            test_claim().execution_descriptor(),
            StackInputs::new(&[Felt::new_unchecked(101), Felt::new_unchecked(102)]).unwrap(),
            StackOutputs::new(&[Felt::new_unchecked(201)]).unwrap(),
        );
        let elements = claim.to_elements();
        assert_eq!(&elements[0..8], &test_claim().to_elements()[0..8]);
        assert_eq!(&elements[8..10], &[Felt::new_unchecked(101), Felt::new_unchecked(102)]);
        assert_eq!(&elements[10..24], &[ZERO; 14]);
        assert_eq!(elements[24], Felt::new_unchecked(201));
        assert_eq!(&elements[25..40], &[ZERO; 15]);
    }

    #[test]
    fn commitment_binds_every_coordinate_and_field_order() {
        let claim = test_claim();
        let commitment = claim.commitment();
        let elements = claim.to_elements();
        for i in 0..NUM_CLAIM_ELEMENTS {
            let mut changed = elements;
            changed[i] = Felt::new_unchecked(999);
            assert_ne!(claim_from_elements(changed).commitment(), commitment, "coordinate {i}");
        }

        let mut swapped = elements;
        swapped[0..4].copy_from_slice(&elements[4..8]);
        swapped[4..8].copy_from_slice(&elements[0..4]);
        assert_ne!(claim_from_elements(swapped).commitment(), commitment, "descriptor order");

        let mut swapped = elements;
        swapped[8..24].copy_from_slice(&elements[24..40]);
        swapped[24..40].copy_from_slice(&elements[8..24]);
        assert_ne!(claim_from_elements(swapped).commitment(), commitment, "I/O order");
    }

    #[test]
    fn commitment_uses_v2_domain_length_40_and_exactly_five_payload_blocks() {
        let claim = test_claim();
        let elements = claim.to_elements();

        // Independent fixed IV lanes pin the v2 domain and exact logical length. Forty Felts
        // occupy exactly five full payload blocks, with no extra tail or deferred-root block.
        let mut expected = Word::new([
            Felt::new_unchecked(0xbb67_ae85_0100_0102),
            Felt::new_unchecked(0xa54f_f53a_0000_0028),
            Felt::new_unchecked(0x9b05_688c_0000_0000),
            Felt::new_unchecked(0x5be0_cd19_0000_0000),
        ]);
        let (blocks, remainder) = elements.as_chunks::<8>();
        assert_eq!(blocks.len(), 5);
        assert!(remainder.is_empty());
        for &block in blocks {
            expected = Eidos::compress(expected, block);
        }

        assert_eq!(CLAIM_DOMAIN_TAG.as_canonical_u64(), 0x0100_0102);
        assert_eq!(CLAIM_DOMAIN_TAG, domain::ExecutionClaimDomain::TAG.as_felt());
        assert_eq!(claim.commitment(), expected);
    }

    #[test]
    fn commitment_is_separated_from_legacy_v1_and_other_domains() {
        let claim = test_claim();
        let elements = claim.to_elements();
        let commitment = claim.commitment();

        // Reconstruct the retired v1 frame only in this test. Matching 40-Felt payload lengths
        // must never make the old program/kernel statement share the new claim's identity.
        let legacy_tag = DomainTag::from_u32(0x0100_0101).unwrap();
        assert!(domain::MidenVmDomainRegistry::resolve(legacy_tag).is_none());
        let mut legacy = EidosFrame::new(legacy_tag, [40, 0, 0]).initial_chaining_word();
        for &block in elements.as_chunks::<8>().0 {
            legacy = Eidos::compress(legacy, block);
        }
        assert_ne!(commitment, legacy);
        assert_ne!(
            commitment,
            hasher::hash_elements(&elements),
            "claim commitment must differ from the untagged hash"
        );
        assert_ne!(
            commitment,
            hasher::hash_elements_in_domain(&elements, domain::KERNEL_COMMITMENT),
            "claim commitment must differ from a kernel-tagged hash of the same data"
        );
    }
}
