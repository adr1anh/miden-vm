//! Typed identities for execution in an authenticated code environment.
//!
//! These values distinguish callable keys from code commitments and environment metadata. They
//! serialize as ordinary canonical [`Word`] values. Constructing or decoding a value does not
//! authenticate a binding, authorize a kernel namespace, or establish that code is available.
//! Ordering follows [`Word`]; it does not define canonical environment or verifier-configuration
//! ordering.

use crate::{
    Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod label;
pub use label::{CanonicalLabel, LabelError};

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
    /// A commitment to the immutable environment containing an execution's procedure bindings.
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
