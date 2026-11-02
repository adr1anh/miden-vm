//! Typed identities for execution in an authenticated code environment.
//!
//! The word identities distinguish callable keys from code commitments and environment metadata.
//! They serialize as ordinary canonical [`Word`] values. Constructing or decoding an identity does
//! not authenticate a binding, authorize a kernel namespace, or establish that code is available.
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
    EnvironmentBuildError, EnvironmentBuildLimits, EnvironmentBuildResource, EnvironmentBuilder,
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
/// their authenticated parent namespace to match the kernel namespace. The verifier or protocol
/// must independently authorize that namespace; this descriptor does not authenticate itself.
/// Code bundles and implementation-root hints are separate from these execution identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionDescriptor {
    entry_key: ProcedureKey,
    environment_root: EnvironmentRoot,
    kernel_namespace: Namespace,
}

impl ExecutionDescriptor {
    /// Creates a descriptor without authenticating its bindings or authorizing its namespace.
    pub const fn new(
        entry_key: ProcedureKey,
        environment_root: EnvironmentRoot,
        kernel_namespace: Namespace,
    ) -> Self {
        Self {
            entry_key,
            environment_root,
            kernel_namespace,
        }
    }

    /// Returns the key of the ordinary procedure at which execution starts.
    pub const fn entry_key(&self) -> ProcedureKey {
        self.entry_key
    }

    /// Returns the environment root that remains fixed throughout execution.
    pub const fn environment_root(&self) -> EnvironmentRoot {
        self.environment_root
    }

    /// Returns the namespace whose direct exports may satisfy syscall resolution.
    pub const fn kernel_namespace(&self) -> Namespace {
        self.kernel_namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Felt;

    #[test]
    fn identities_preserve_canonical_word_encoding() {
        assert_word_encoding(ProcedureKey::new, ProcedureKey::into_word);
        assert_word_encoding(ImplementationRoot::new, ImplementationRoot::into_word);
        assert_word_encoding(EnvironmentRoot::new, EnvironmentRoot::into_word);
        assert_word_encoding(Namespace::new, Namespace::into_word);
        assert_word_encoding(LabelCommitment::new, LabelCommitment::into_word);
    }

    #[test]
    fn initial_namespace_matches_frozen_vector() {
        // Frozen with an independent portable seven-round BLAKE3/Eidos reference, checked
        // against the existing generic empty/three/nine-Felt vectors before generation.
        let expected = Word::new(
            [0x5af63cdc05e1732d, 0x7c441ffa1c95ee1f, 0x2e3dd14274ac5042, 0x09b0dc5782213a88]
                .map(Felt::new_unchecked),
        );

        assert_eq!(Namespace::initial().into_word(), expected);
    }

    #[test]
    fn namespace_and_procedure_derivations_match_frozen_vectors() {
        let parent = Namespace::new(Word::new([1, 2, 3, 4].map(Felt::new_unchecked)));
        // Opaque label commitment fixtures keep these derivations independent of label encoding.
        let label = LabelCommitment::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked)));
        let expected_child = Word::new(
            [0x68ace2d21f9b42de, 0x362d310e1d59e478, 0x3fe429f790e66da0, 0x3fda71606ac89b81]
                .map(Felt::new_unchecked),
        );
        let expected_key = Word::new(
            [0x14c540e058d350f2, 0x6854420e543dd8a5, 0x54dd6e100545038b, 0x40ac3ae85e48f3aa]
                .map(Felt::new_unchecked),
        );

        assert_eq!(parent.child(label).into_word(), expected_child);
        assert_eq!(parent.procedure_key(label).into_word(), expected_key);
    }

    #[test]
    fn namespace_path_accumulates_inherited_parent() {
        let label = LabelCommitment::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked)));
        let next_label = LabelCommitment::new(Word::new([9, 10, 11, 12].map(Felt::new_unchecked)));
        let first = Namespace::initial().child(label);
        let second = first.child(next_label);
        let expected_first = Word::new(
            [0x76244d1351f97db0, 0x5af28aa070279dc7, 0x5403a0f5258d1309, 0x44dc7399b395cb61]
                .map(Felt::new_unchecked),
        );
        let expected_second = Word::new(
            [0x4a00a24a30a8db25, 0x50550edf0f1ce7c4, 0x60453affd5d35d84, 0x59c0f8c9f4f0a183]
                .map(Felt::new_unchecked),
        );
        let expected_key = Word::new(
            [0x486109a0f063d450, 0x7b799d30c067cc21, 0x5b549f1a8dc66efa, 0x3c116a019b44053e]
                .map(Felt::new_unchecked),
        );

        assert_eq!(first.into_word(), expected_first);
        assert_eq!(second.into_word(), expected_second);
        assert_eq!(second.procedure_key(label).into_word(), expected_key);
        assert_ne!(first.procedure_key(label), second.procedure_key(label));
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
