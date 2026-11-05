//! Typed identities for execution in an authenticated code environment.
//!
//! The word identities distinguish callable keys from code commitments and environment metadata.
//! They serialize as ordinary canonical [`Word`] values. Constructing or decoding an identity does
//! not authenticate a binding or establish that code is available.
//! Ordering follows [`Word`]; it does not define canonical environment or verifier-configuration
//! ordering.

use crate::{
    Word,
    chiplets::hasher,
    program::domain,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod label;
pub use label::{CanonicalLabel, LabelError};

mod object;
pub use object::{EnvNode, EnvNodeError};

mod builder;
pub use builder::{
    EnvironmentBinding, EnvironmentBuildError, EnvironmentBuildLimits, EnvironmentBuildResource,
    EnvironmentBuilder, ValidatedEnvironment,
};

macro_rules! word_identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(Word);

        impl $name {
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

        impl Serializable for $name {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                self.0.write_into(target);
            }

            fn get_size_hint(&self) -> usize {
                Word::SERIALIZED_SIZE
            }
        }

        impl Deserializable for $name {
            fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                Word::read_from(source).map(Self)
            }

            fn min_serialized_size() -> usize {
                Word::SERIALIZED_SIZE
            }
        }
    };
}

word_identity! {
    /// A callable procedure's namespace-qualified key, independent of its selected implementation.
    ProcedureKey
}

word_identity! {
    /// A commitment to an executable MAST implementation, rather than a callable procedure key.
    ImplementationRoot
}

word_identity! {
    /// A commitment to an environment object or subtree, including a complete execution environment.
    ///
    /// A wrapped or computed root alone does not establish completeness, executable-path uniqueness,
    /// or authority over the environment's procedure bindings.
    EnvironmentRoot
}

word_identity! {
    /// An accumulated namespace identifier inherited along an authenticated environment path.
    Namespace
}

word_identity! {
    /// A commitment to a typed local label in an environment.
    LabelCommitment
}

impl Namespace {
    /// Derives the fixed initial namespace, independent of the environment root.
    ///
    /// This is the root namespace itself, without an additional root label. Derivation does not
    /// authenticate an environment path or authorize the namespace.
    pub fn initial() -> Self {
        Self::new(hasher::hash_elements_in_domain(&[], domain::ENV_INITIAL_NAMESPACE))
    }

    /// Derives a child namespace from this parent and its local label commitment.
    ///
    /// This extends the accumulated namespace without authenticating or authorizing its path.
    pub fn child(self, label: LabelCommitment) -> Self {
        let payload = [self.into_word(), label.into_word()];
        Self::new(hasher::hash_elements_in_domain(
            Word::words_as_elements(&payload),
            domain::ENV_NAMESPACE,
        ))
    }

    /// Derives an export's procedure key directly under this immediate parent namespace.
    ///
    /// The export label does not extend the namespace first. The implementation commitment does
    /// not enter this derivation, and the derived key does not authenticate a binding.
    pub fn procedure_key(self, export_label: LabelCommitment) -> ProcedureKey {
        let payload = [self.into_word(), export_label.into_word()];
        ProcedureKey::new(hasher::hash_elements_in_domain(
            Word::words_as_elements(&payload),
            domain::ENV_PROCEDURE,
        ))
    }
}

/// The fixed identities that define an execution in an authenticated code environment.
///
/// The entry key must resolve under the environment root. Actual syscalls additionally require
/// their authenticated immediate parent namespace to equal [`Namespace::initial()`]. The verifier
/// or protocol must independently authorize the environment root and its bindings; this descriptor
/// does not authenticate itself.
/// Code bundles and implementation-root hints are separate from these execution identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionDescriptor {
    entry_key: ProcedureKey,
    environment_root: EnvironmentRoot,
}

impl ExecutionDescriptor {
    /// Creates a descriptor without authenticating or authorizing its environment bindings.
    pub const fn new(entry_key: ProcedureKey, environment_root: EnvironmentRoot) -> Self {
        Self { entry_key, environment_root }
    }

    /// Returns the key of the ordinary procedure at which execution starts.
    pub const fn entry_key(&self) -> ProcedureKey {
        self.entry_key
    }

    /// Returns the environment root that remains fixed throughout execution.
    pub const fn environment_root(&self) -> EnvironmentRoot {
        self.environment_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Felt, program::test_vectors::vector};

    #[test]
    fn identities_preserve_canonical_word_encoding() {
        assert_word_encoding(ProcedureKey::new, ProcedureKey::into_word);
        assert_word_encoding(ImplementationRoot::new, ImplementationRoot::into_word);
        assert_word_encoding(EnvironmentRoot::new, EnvironmentRoot::into_word);
        assert_word_encoding(Namespace::new, Namespace::into_word);
        assert_word_encoding(LabelCommitment::new, LabelCommitment::into_word);
    }

    #[test]
    fn execution_descriptor_contains_only_entry_and_environment() {
        let entry = ProcedureKey::new(Word::new([1, 2, 3, 4].map(Felt::new_unchecked)));
        let environment = EnvironmentRoot::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked)));
        let descriptor = ExecutionDescriptor::new(entry, environment);

        assert_eq!(descriptor.entry_key(), entry);
        assert_eq!(descriptor.environment_root(), environment);
        assert_eq!(core::mem::size_of::<ExecutionDescriptor>(), 2 * core::mem::size_of::<Word>());
        assert_ne!(Namespace::initial().into_word(), Word::empty());
    }

    #[test]
    fn initial_namespace_matches_frozen_vector() {
        let expected = fixture_word("namespace_initial");

        assert_eq!(Namespace::initial().into_word(), expected);
    }

    #[test]
    fn namespace_and_procedure_derivations_match_frozen_vectors() {
        let parent = Namespace::new(Word::new([1, 2, 3, 4].map(Felt::new_unchecked)));
        // Opaque label commitment fixtures keep these derivations independent of label encoding.
        let label = LabelCommitment::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked)));
        let expected_child = fixture_word("namespace_opaque_child");
        let expected_key = fixture_word("namespace_opaque_procedure");

        assert_eq!(parent.child(label).into_word(), expected_child);
        assert_eq!(parent.procedure_key(label).into_word(), expected_key);
    }

    #[test]
    fn namespace_path_accumulates_inherited_parent() {
        let label = LabelCommitment::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked)));
        let next_label = LabelCommitment::new(Word::new([9, 10, 11, 12].map(Felt::new_unchecked)));
        let first = Namespace::initial().child(label);
        let second = first.child(next_label);
        let expected_first = fixture_word("namespace_path_first");
        let expected_second = fixture_word("namespace_path_second");
        let expected_key = fixture_word("namespace_path_procedure");

        assert_eq!(first.into_word(), expected_first);
        assert_eq!(second.into_word(), expected_second);
        assert_eq!(second.procedure_key(label).into_word(), expected_key);
        assert_ne!(first.procedure_key(label), second.procedure_key(label));
    }

    fn fixture_word(id: &str) -> Word {
        Word::new(vector(id).digest.map(Felt::new_unchecked))
    }

    fn assert_word_encoding<T>(wrap: fn(Word) -> T, unwrap: fn(T) -> Word)
    where
        T: Serializable + Deserializable,
    {
        let word = Word::new([
            Felt::new_unchecked(0),
            Felt::new_unchecked(1),
            Felt::new_unchecked(255),
            Felt::new_unchecked(0x0102_0304_0506_0708),
        ]);
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5,
            4, 3, 2, 1,
        ];
        let identity = wrap(word);

        assert_eq!(identity.to_bytes(), bytes);
        assert_eq!(identity.to_bytes(), word.to_bytes());
        assert_eq!(unwrap(T::read_from_bytes(&bytes).unwrap()), word);
        assert_eq!(T::min_serialized_size(), Word::SERIALIZED_SIZE);

        for len in 0..bytes.len() {
            assert!(matches!(
                T::read_from_bytes(&bytes[..len]),
                Err(DeserializationError::UnexpectedEOF)
            ));
        }

        for element in 0..Word::NUM_ELEMENTS {
            let mut noncanonical = bytes;
            noncanonical[element * 8..(element + 1) * 8]
                .copy_from_slice(&Felt::ORDER.to_le_bytes());
            assert!(matches!(
                T::read_from_bytes(&noncanonical),
                Err(DeserializationError::InvalidValue(_))
            ));
        }
    }
}
