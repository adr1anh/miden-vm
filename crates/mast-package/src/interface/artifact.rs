//! Verified, declaration-only interface artifacts with an explicitly supplied Protocol profile.
//!
//! The native model retains tooling signatures, but only paths and exact optional ABI text enter
//! the canonical declaration bytes. Neither a signature nor serialized bytes confer authority.

use alloc::vec::Vec;
use core::{alloc::Layout, fmt};

use miden_core::{Felt, Word, chiplets::hasher, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::eidos::{DomainTag, DomainVersion, EidosDomain, FeltSequence, namespace};

use super::{
    DeclarationError, DeclarationSet,
    serialization::{
        Budget, CodecError, CodecLimits, Reader, TypedIdProfile, Writer, checked_add, reserve,
        wire_len,
    },
};

mod declarations;

macro_rules! word_role {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(Word);

        impl $name {
            /// Wraps a canonical word without deriving or authenticating its value.
            pub const fn new(word: Word) -> Self { Self(word) }

            /// Returns the underlying canonical word.
            pub const fn as_word(&self) -> &Word { &self.0 }

            /// Returns the underlying canonical word by value.
            pub const fn into_word(self) -> Word { self.0 }
        }

        impl From<Word> for $name {
            fn from(word: Word) -> Self { Self::new(word) }
        }

        impl From<$name> for Word {
            fn from(value: $name) -> Self { value.into_word() }
        }
    };
}

word_role! {
    /// An externally assigned immutable interface identity, independent of its declarations.
    LibraryId
}

word_role! {
    /// A declaration commitment, distinct from a LibraryId or executable implementation root.
    DeclarationCommitment
}

/// Required Protocol ownership, publisher, association and closure checks.
///
/// The domain must be externally allocated by the Protocol owner for this exact numbered-v1
/// FeltSequence construction. The generic codec checks its namespace and version, not allocation
/// ownership or registry membership. There is no default domain, descriptor codec or policy.
pub trait InterfaceProfile: TypedIdProfile {
    type DeclarationDomain: EidosDomain<Encoding = FeltSequence>;

    /// Supplies the externally allocated domain for the canonical declaration commitment.
    fn declaration_domain(&self) -> Self::DeclarationDomain;

    /// Recognizes and validates the exact canonical publisher-qualified descriptor Q0.
    ///
    /// Q0 must exclude the LibraryId, declaration commitment and association proofs.
    fn validate_publisher_descriptor(
        &self,
        context: &Self::Context,
        descriptor: &[u8],
    ) -> Result<(), Self::Error>;

    /// Authenticates the immutable association of Q0, supplied I and computed Cdecl.
    fn validate_association(
        &self,
        context: &Self::Context,
        descriptor: &[u8],
        id: LibraryId,
        commitment: DeclarationCommitment,
    ) -> Result<(), Self::Error>;

    /// Establishes complete transitive requirements from authenticated contributing declarations.
    ///
    /// Both ID slices are strictly ordered by canonical Word bytes. The generic codec checks
    /// self exclusion and direct inclusion, but cannot establish transitive completeness. Cycles
    /// are not forbidden; self references are implicit and excluded from both external ID sets.
    /// Authenticated contributing declarations and completeness evidence belong in `context`.
    /// Uncommitted tooling signatures are deliberately absent from these authority inputs.
    fn validate_dependency_closure(
        &self,
        context: &Self::Context,
        id: LibraryId,
        direct: &[LibraryId],
        closure: &[LibraryId],
    ) -> Result<(), Self::Error>;
}

/// The mandatory external check which rejected an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactProfileOperation {
    PublisherDescriptor,
    Association,
    DependencyClosure,
}

impl fmt::Display for ArtifactProfileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PublisherDescriptor => "publisher descriptor",
            Self::Association => "interface association",
            Self::DependencyClosure => "authenticated dependency closure",
        })
    }
}

/// Structural/resource failures and external authority failures remain distinguishable.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError<E> {
    #[error(transparent)]
    Codec(#[from] CodecError<E>),
    #[error("declaration domain {tag} must use the Protocol namespace and numbered version 1")]
    InvalidDeclarationDomain { tag: DomainTag },
    #[error("duplicate LibraryId in {kind} requirements: {id:?}")]
    DuplicateLibraryId { kind: &'static str, id: LibraryId },
    #[error("{kind} external requirements contain the interface's own LibraryId")]
    OwnLibraryId { kind: &'static str },
    #[error("direct external requirement is absent from the transitive closure: {id:?}")]
    MissingDirectRequirement { id: LibraryId },
    #[error("stored declaration commitment differs under the supplied profile")]
    CommitmentMismatch,
    #[error("invalid canonical Word for {kind}")]
    InvalidWord { kind: &'static str },
    #[error("artifact LibraryId {actual:?} differs from expected {expected:?}")]
    UnexpectedLibraryId { expected: LibraryId, actual: LibraryId },
    #[error(transparent)]
    InvalidDeclarations(#[from] DeclarationError),
    #[error("public procedure components require Text labels, found tag {tag}")]
    NonTextPublicLabel { tag: u8 },
    #[error("invalid ABI presence discriminator {tag}")]
    InvalidAbiDiscriminator { tag: u8 },
    #[error("invalid UTF-8 ABI metadata: {0}")]
    InvalidAbiUtf8(core::str::Utf8Error),
    #[error("public procedure paths must be strictly increasing in canonical envelope order")]
    NonCanonicalPublicPathOrder,
    #[error("{kind} requirements must be strictly increasing in canonical Word-byte order")]
    NonCanonicalLibraryIdOrder { kind: &'static str },
    #[error("external {operation} validation rejected the value: {error}")]
    ProfileRejected {
        operation: ArtifactProfileOperation,
        error: E,
    },
}

/// An immutable declaration-only artifact verified under explicitly supplied external evidence.
///
/// Verification is contextual, not permanent authority. Every encoding revalidates the current
/// profile/context and recomputes the stored commitment. No context-free deserializer or trusted
/// unchecked constructor is provided. This does not select a release or materialize code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceArtifactV1 {
    id: LibraryId,
    commitment: DeclarationCommitment,
    publisher_descriptor: Vec<u8>,
    declarations: DeclarationSet,
    direct_requirements: Vec<LibraryId>,
    dependency_closure: Vec<LibraryId>,
}

impl InterfaceArtifactV1 {
    /// Canonicalizes native requirement order, rejecting duplicates, and verifies all authority.
    ///
    /// Explicit limits cover aggregate logical work and bytes before sorting or hashing. They do
    /// not cover allocations already used by caller-owned inputs. Reused core Text-label
    /// construction and byte packing allocate infallibly after finite layout checks; these limits
    /// are not an RSS/OOM guarantee.
    #[allow(clippy::too_many_arguments)]
    pub fn new_verified<P: InterfaceProfile + ?Sized>(
        id: LibraryId,
        publisher_descriptor: Vec<u8>,
        declarations: DeclarationSet,
        mut direct_requirements: Vec<LibraryId>,
        mut dependency_closure: Vec<LibraryId>,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, ArtifactError<P::Error>> {
        check_domain::<P>()?;
        let plan = EncodingPlan::new(
            &publisher_descriptor,
            &declarations,
            &direct_requirements,
            &dependency_closure,
            limits,
        )?;
        canonicalize_ids(&mut direct_requirements, "direct")?;
        canonicalize_ids(&mut dependency_closure, "closure")?;
        validate_requirements(id, &direct_requirements, &dependency_closure)?;
        let db =
            declarations::encode(&declarations, &direct_requirements, &dependency_closure, &plan)?;
        let commitment = compute_commitment(&publisher_descriptor, &db, profile, &plan)?;
        validate_authority(
            profile,
            context,
            &publisher_descriptor,
            id,
            commitment,
            &direct_requirements,
            &dependency_closure,
        )?;
        Ok(Self {
            id,
            commitment,
            publisher_descriptor,
            declarations,
            direct_requirements,
            dependency_closure,
        })
    }

    /// Encodes `1 || I || Cdecl || B(Q0) || B(DB)` after full contextual revalidation.
    pub fn encode_v1<P: InterfaceProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Vec<u8>, ArtifactError<P::Error>> {
        check_domain::<P>()?;
        let plan = EncodingPlan::new(
            &self.publisher_descriptor,
            &self.declarations,
            &self.direct_requirements,
            &self.dependency_closure,
            limits,
        )?;
        validate_requirements(self.id, &self.direct_requirements, &self.dependency_closure)?;
        let db = declarations::encode(
            &self.declarations,
            &self.direct_requirements,
            &self.dependency_closure,
            &plan,
        )?;
        let commitment = compute_commitment(&self.publisher_descriptor, &db, profile, &plan)?;
        if commitment != self.commitment {
            return Err(ArtifactError::CommitmentMismatch);
        }
        validate_authority(
            profile,
            context,
            &self.publisher_descriptor,
            self.id,
            commitment,
            &self.direct_requirements,
            &self.dependency_closure,
        )?;
        let mut writer = Writer::new(plan.wire_len, &plan.budget)?;
        writer.u8(1)?;
        writer.bytes(&self.id.as_word().as_bytes())?;
        writer.bytes(&commitment.as_word().as_bytes())?;
        writer.u32(wire_len(self.publisher_descriptor.len(), "publisher descriptor")?)?;
        writer.bytes(&self.publisher_descriptor)?;
        writer.u32(wire_len(db.len(), "declaration bytes")?)?;
        writer.bytes(&db)?;
        Ok(writer.finish()?)
    }

    /// Decodes exact canonical v1 bytes and verifies the caller's identity and external evidence.
    ///
    /// All wire framing, canonical ordering, aggregate budgets and the stored commitment are
    /// checked before authority callbacks. The core label decoder, decoded strings and native
    /// declaration map use bounded infallible allocations after logical size/layout checks;
    /// limits are not an allocator or RSS/OOM guarantee. Tooling signatures are absent on decode.
    pub fn decode_verified<P: InterfaceProfile + ?Sized>(
        bytes: &[u8],
        expected_id: LibraryId,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, ArtifactError<P::Error>> {
        check_domain::<P>()?;
        let mut budget = Budget::new(limits);
        let mut reader = Reader::new(bytes, &budget)?;
        let version = reader.u8("interface artifact version")?;
        if version != 1 {
            return Err(
                CodecError::UnsupportedVersion { kind: "interface artifact", version }.into()
            );
        }
        let id = LibraryId::new(decode_word(&mut reader, "interface LibraryId")?);
        let commitment =
            DeclarationCommitment::new(decode_word(&mut reader, "declaration commitment")?);
        let descriptor = borrow_blob(&mut reader, "publisher descriptor")?;
        budget.blob_bytes(descriptor.len())?;
        let db = borrow_blob(&mut reader, "declaration bytes")?;
        reader.finish("interface artifact")?;
        if id != expected_id {
            return Err(ArtifactError::UnexpectedLibraryId { expected: expected_id, actual: id });
        }
        let decoded = declarations::decode(db, &mut budget)?;
        validate_requirements(id, &decoded.direct, &decoded.closure)?;
        // Reuse the already charged aggregate budget and hash the original wire DB, rather than
        // re-encoding native maps or charging parsed values a second time.
        let plan = EncodingPlan::from_lengths(descriptor.len(), db.len(), budget)?;
        if compute_commitment(descriptor, db, profile, &plan)? != commitment {
            return Err(ArtifactError::CommitmentMismatch);
        }
        let mut publisher_descriptor = Vec::new();
        reserve(&mut publisher_descriptor, descriptor.len(), "publisher descriptor")?;
        publisher_descriptor.extend_from_slice(descriptor);
        validate_authority(
            profile,
            context,
            descriptor,
            id,
            commitment,
            &decoded.direct,
            &decoded.closure,
        )?;
        Ok(Self {
            id,
            commitment,
            publisher_descriptor,
            declarations: decoded.declarations,
            direct_requirements: decoded.direct,
            dependency_closure: decoded.closure,
        })
    }

    pub const fn id(&self) -> LibraryId {
        self.id
    }
    pub const fn commitment(&self) -> DeclarationCommitment {
        self.commitment
    }
    pub fn publisher_descriptor(&self) -> &[u8] {
        &self.publisher_descriptor
    }
    pub const fn declarations(&self) -> &DeclarationSet {
        &self.declarations
    }
    pub fn direct_requirements(&self) -> &[LibraryId] {
        &self.direct_requirements
    }
    pub fn dependency_closure(&self) -> &[LibraryId] {
        &self.dependency_closure
    }
}

struct EncodingPlan {
    budget: Budget,
    db_len: usize,
    dcl_len: usize,
    wire_len: usize,
    hash_elements: usize,
}

impl EncodingPlan {
    fn new<E>(
        descriptor: &[u8],
        declarations: &DeclarationSet,
        direct: &[LibraryId],
        closure: &[LibraryId],
        limits: CodecLimits,
    ) -> Result<Self, CodecError<E>> {
        let mut budget = Budget::new(limits);
        wire_len(descriptor.len(), "publisher descriptor")?;
        budget.blob_bytes(descriptor.len())?;
        let db_len = declarations::preflight(declarations, direct, closure, &mut budget)?;
        Self::from_lengths(descriptor.len(), db_len, budget)
    }

    fn from_lengths<E>(
        descriptor_len: usize,
        db_len: usize,
        budget: Budget,
    ) -> Result<Self, CodecError<E>> {
        let dcl_len = checked_add(
            checked_add(4, descriptor_len, "declaration preimage")?,
            db_len,
            "declaration preimage",
        )?;
        wire_len(dcl_len, "declaration preimage")?;
        let artifact_len = checked_add(69, dcl_len, "artifact bytes")?;
        wire_len(artifact_len, "artifact bytes")?;
        budget.wire_bytes(artifact_len)?;
        Layout::array::<u8>(artifact_len)
            .map_err(|_| CodecError::LengthOverflow("artifact bytes"))?;
        // The packer and standard FeltSequence hasher allocate only after these logical checks.
        let hash_elements = checked_add(2, dcl_len.div_ceil(4), "declaration hash payload")?;
        wire_len(hash_elements, "declaration hash payload")?;
        Layout::array::<Felt>(hash_elements)
            .map_err(|_| CodecError::LengthOverflow("declaration hash payload"))?;
        Ok(Self {
            budget,
            db_len,
            dcl_len,
            wire_len: artifact_len,
            hash_elements,
        })
    }
}

fn decode_word<E>(reader: &mut Reader<'_>, kind: &'static str) -> Result<Word, ArtifactError<E>> {
    Word::try_from(reader.bytes(32, kind)?).map_err(|_| ArtifactError::InvalidWord { kind })
}

fn borrow_blob<'a, E>(
    reader: &mut Reader<'a>,
    kind: &'static str,
) -> Result<&'a [u8], CodecError<E>> {
    let length = reader.u32(kind)?;
    let length = reader.count::<u8, E>(length, 1, kind)?;
    reader.bytes(length, kind)
}

fn check_domain<P: InterfaceProfile + ?Sized>() -> Result<(), ArtifactError<P::Error>> {
    let tag = P::DeclarationDomain::TAG;
    if tag.namespace() != namespace::MIDEN_PROTOCOL || tag.version() != DomainVersion::numbered(1) {
        return Err(ArtifactError::InvalidDeclarationDomain { tag });
    }
    Ok(())
}

fn canonicalize_ids<E>(ids: &mut [LibraryId], kind: &'static str) -> Result<(), ArtifactError<E>> {
    ids.sort_unstable_by_key(|id| id.as_word().as_bytes());
    for pair in ids.windows(2) {
        if pair[0] == pair[1] {
            return Err(ArtifactError::DuplicateLibraryId { kind, id: pair[0] });
        }
    }
    Ok(())
}

fn validate_requirements<E>(
    id: LibraryId,
    direct: &[LibraryId],
    closure: &[LibraryId],
) -> Result<(), ArtifactError<E>> {
    for (kind, ids) in [("direct", direct), ("closure", closure)] {
        if ids.contains(&id) {
            return Err(ArtifactError::OwnLibraryId { kind });
        }
    }
    for requirement in direct {
        if closure
            .binary_search_by_key(&requirement.as_word().as_bytes(), |id| id.as_word().as_bytes())
            .is_err()
        {
            return Err(ArtifactError::MissingDirectRequirement { id: *requirement });
        }
    }
    Ok(())
}

fn compute_commitment<P: InterfaceProfile + ?Sized>(
    descriptor: &[u8],
    db: &[u8],
    profile: &P,
    plan: &EncodingPlan,
) -> Result<DeclarationCommitment, CodecError<P::Error>> {
    let mut writer = Writer::new(plan.dcl_len, &plan.budget)?;
    writer.u32(wire_len(descriptor.len(), "publisher descriptor")?)?;
    writer.bytes(descriptor)?;
    writer.bytes(db)?;
    let dcl = writer.finish()?;
    let mut elements = Vec::new();
    reserve(&mut elements, plan.hash_elements, "declaration hash payload")?;
    elements.push(Felt::ONE);
    elements.push(Felt::from_u32(wire_len(dcl.len(), "declaration preimage")?));
    elements.extend(bytes_to_packed_u32_elements(&dcl));
    Ok(DeclarationCommitment::new(hasher::hash_elements_in_domain(
        &elements,
        profile.declaration_domain(),
    )))
}

#[allow(clippy::too_many_arguments)]
fn validate_authority<P: InterfaceProfile + ?Sized>(
    profile: &P,
    context: &P::Context,
    descriptor: &[u8],
    id: LibraryId,
    commitment: DeclarationCommitment,
    direct: &[LibraryId],
    closure: &[LibraryId],
) -> Result<(), ArtifactError<P::Error>> {
    let rejected = |operation, error| ArtifactError::ProfileRejected { operation, error };
    profile
        .validate_publisher_descriptor(context, descriptor)
        .map_err(|error| rejected(ArtifactProfileOperation::PublisherDescriptor, error))?;
    profile
        .validate_association(context, descriptor, id, commitment)
        .map_err(|error| rejected(ArtifactProfileOperation::Association, error))?;
    profile
        .validate_dependency_closure(context, id, direct, closure)
        .map_err(|error| rejected(ArtifactProfileOperation::DependencyClosure, error))?;
    Ok(())
}

#[cfg(test)]
mod tests;
