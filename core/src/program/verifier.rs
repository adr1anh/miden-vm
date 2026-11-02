//! Immutable native verifier configurations, canonical commitments, and derived identities.

use alloc::vec::Vec;
use core::{alloc::Layout, cmp::Ordering};

use super::{EnvironmentRoot, ImplementationRoot, Namespace, ProcedureKey, domain};
use crate::{Felt, WORD_SIZE, Word, chiplets::hasher};

/// A required environment fragment under its exact inherited namespace.
///
/// This value does not authenticate the fragment, its namespace path, or its availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierMount {
    namespace: Namespace,
    fragment: EnvironmentRoot,
}

impl VerifierMount {
    /// Describes a mount without authenticating its contents or namespace provenance.
    pub const fn new(namespace: Namespace, fragment: EnvironmentRoot) -> Self {
        Self { namespace, fragment }
    }

    /// Returns the full namespace inherited by this fragment.
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Returns the required immutable fragment commitment.
    pub const fn fragment(&self) -> EnvironmentRoot {
        self.fragment
    }
}

/// A commitment to a verifier configuration, distinct from its implementation or environment root.
///
/// Wrapping a word does not derive or authorize a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VerifierConfigurationCommitment(Word);

impl VerifierConfigurationCommitment {
    /// Wraps a word without deriving or authenticating its value.
    pub const fn new(word: Word) -> Self {
        Self(word)
    }

    /// Returns the underlying word.
    pub const fn as_word(&self) -> &Word {
        &self.0
    }

    /// Returns the underlying word by value.
    pub const fn into_word(self) -> Word {
        self.0
    }
}

/// A verifier's proof relation, entry key, and exact configuration committed as one identity.
///
/// Derivation does not authenticate or authorize the relation, entry binding, or configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VerifierIdentity(Word);

impl VerifierIdentity {
    /// Derives the identity under the registered v1 Eidos FeltSequence domain.
    ///
    /// The configuration describes the verifier's dependencies and resources without embedding
    /// this identity. Derivation does not establish their trust or availability.
    pub fn derive(
        relation_id: Word,
        entry: ProcedureKey,
        config: VerifierConfigurationCommitment,
    ) -> Self {
        let payload = Self::preimage_elements(relation_id, entry, config);
        Self(hasher::hash_elements_in_domain(&payload, domain::EXEC_VERIFIER_IDENTITY))
    }

    /// Returns the exact 12-Felt payload `relation_id[4] || entry[4] || config[4]`.
    ///
    /// The payload uses the words' forward coordinate order and requires no allocation.
    pub fn preimage_elements(
        relation_id: Word,
        entry: ProcedureKey,
        config: VerifierConfigurationCommitment,
    ) -> [Felt; 3 * WORD_SIZE] {
        let mut payload = [Felt::ZERO; 3 * WORD_SIZE];
        payload[..WORD_SIZE].copy_from_slice(relation_id.as_slice());
        payload[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(entry.as_word().as_slice());
        payload[2 * WORD_SIZE..].copy_from_slice(config.as_word().as_slice());
        payload
    }

    /// Returns the underlying word.
    pub const fn as_word(&self) -> &Word {
        &self.0
    }

    /// Returns the underlying word by value.
    pub const fn into_word(self) -> Word {
        self.0
    }
}

/// A verifier's exact implementation, kernel namespace, required mounts, and opaque resources.
///
/// Construction canonicalizes unique mount pairs. It does not establish trusted mounts, namespace
/// provenance, code availability, executable-path disjointness, or resource authority. Distinct
/// fragments may share a namespace; their executable paths must be validated by their authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierConfiguration {
    entry_implementation: ImplementationRoot,
    kernel_namespace: Namespace,
    mounts: Vec<VerifierMount>,
    resource_inventory: Word,
}

impl VerifierConfiguration {
    /// Creates a configuration with a mandatory full kernel namespace, including without syscalls.
    ///
    /// Mount pairs are sorted by forward canonical Felt coordinates: namespace first, then
    /// fragment commitment. Duplicate pairs and unrepresentable payload lengths are rejected.
    pub fn new(
        entry_implementation: ImplementationRoot,
        kernel_namespace: Namespace,
        mut mounts: Vec<VerifierMount>,
        resource_inventory: Word,
    ) -> Result<Self, VerifierConfigurationError> {
        checked_configuration_element_len(mounts.len())?;
        // The unstable sort needs no allocation. Word::Ord compares coordinates in reverse,
        // so it cannot define the selected canonical mount ordering.
        mounts.sort_unstable_by(compare_mounts);
        if mounts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VerifierConfigurationError::DuplicateMount);
        }
        Ok(Self {
            entry_implementation,
            kernel_namespace,
            mounts,
            resource_inventory,
        })
    }

    /// Returns the exact verifier implementation commitment.
    pub const fn entry_implementation(&self) -> ImplementationRoot {
        self.entry_implementation
    }

    /// Returns the full authorized kernel namespace described by this configuration.
    pub const fn kernel_namespace(&self) -> Namespace {
        self.kernel_namespace
    }

    /// Returns the unique mount pairs in canonical order.
    pub fn mounts(&self) -> &[VerifierMount] {
        &self.mounts
    }

    /// Returns the opaque inventory commitment for this verifier's resources.
    pub const fn resource_inventory(&self) -> Word {
        self.resource_inventory
    }

    /// Returns the canonical v2 Felt payload, without introducing a byte wire encoding.
    ///
    /// The payload is `2 || D_v[4] || N_kernel[4] || n || (N[4] || C[4])*n || resources[4]`.
    /// Its exact length is `14 + 8*n`, checked against u32 framing and allocation layout bounds.
    /// Allocation failure is reported without retaining a second authoritative representation.
    pub fn preimage_elements(&self) -> Result<Vec<Felt>, VerifierConfigurationError> {
        let element_len = checked_configuration_element_len(self.mounts.len())?;
        let mount_count = u32::try_from(self.mounts.len())
            .map_err(|_| VerifierConfigurationError::LengthOverflow)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(element_len)
            .map_err(|_| VerifierConfigurationError::AllocationFailed)?;
        payload.push(Felt::from_u32(2));
        payload.extend_from_slice(self.entry_implementation.as_word().as_slice());
        payload.extend_from_slice(self.kernel_namespace.as_word().as_slice());
        payload.push(Felt::from_u32(mount_count));
        for mount in &self.mounts {
            payload.extend_from_slice(mount.namespace.as_word().as_slice());
            payload.extend_from_slice(mount.fragment.as_word().as_slice());
        }
        payload.extend_from_slice(self.resource_inventory.as_slice());
        Ok(payload)
    }

    /// Commits to the canonical payload under the registered v2 Eidos FeltSequence domain.
    ///
    /// This fallibly allocates the payload and does not authenticate or authorize its fields.
    pub fn commitment(
        &self,
    ) -> Result<VerifierConfigurationCommitment, VerifierConfigurationError> {
        let payload = self.preimage_elements()?;
        Ok(VerifierConfigurationCommitment::new(hasher::hash_elements_in_domain(
            &payload,
            domain::EXEC_VERIFIER_CONFIG,
        )))
    }
}

/// A verifier configuration cannot be canonicalized or its hash payload cannot be allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifierConfigurationError {
    #[error("verifier configuration contains a duplicate namespace/fragment mount pair")]
    DuplicateMount,
    #[error("verifier configuration payload length exceeds the framing or allocation bounds")]
    LengthOverflow,
    #[error("verifier configuration payload allocation failed")]
    AllocationFailed,
}

fn checked_configuration_element_len(
    mount_count: usize,
) -> Result<usize, VerifierConfigurationError> {
    u32::try_from(mount_count).map_err(|_| VerifierConfigurationError::LengthOverflow)?;
    let element_len = mount_count
        .checked_mul(2 * WORD_SIZE)
        .and_then(|len| len.checked_add(14))
        .ok_or(VerifierConfigurationError::LengthOverflow)?;
    u32::try_from(element_len).map_err(|_| VerifierConfigurationError::LengthOverflow)?;
    Layout::array::<Felt>(element_len).map_err(|_| VerifierConfigurationError::LengthOverflow)?;
    Ok(element_len)
}

fn compare_mounts(left: &VerifierMount, right: &VerifierMount) -> Ordering {
    compare_coordinates(left.namespace.as_word(), right.namespace.as_word())
        .then_with(|| compare_coordinates(left.fragment.as_word(), right.fragment.as_word()))
}

fn compare_coordinates(left: &Word, right: &Word) -> Ordering {
    left.iter()
        .map(Felt::as_canonical_u64)
        .cmp(right.iter().map(Felt::as_canonical_u64))
}

#[cfg(test)]
mod tests;
