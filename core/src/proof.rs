use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use crate::{
    Word,
    crypto::hash::Blake3_256,
    deferred::{DeferredRoot, MAX_PRECOMPILE_ROOTS, PrecompileWitness, fold_deferred_root},
    program::VerifierIdentity,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// CONSTANTS
// ================================================================================================

/// Hard encoded-size and per-allocation safety ceiling for every STARK proof.
pub const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

const DEFERRED_PROOF_DISCRIMINANT: u8 = 0;
const COMPLETE_PROOF_DISCRIMINANT: u8 = 1;

/// The declared identity of the current recursive VM verifier profile.
///
/// Captured from the native profile's relation, entry key, and exact configuration; the profile
/// parity test checks that derivation against the current verifier artifacts.
pub const CURRENT_VM_VERIFIER_IDENTITY: VerifierIdentity = VerifierIdentity::new(Word::new([
    crate::Felt::new_unchecked(6582222660690384890),
    crate::Felt::new_unchecked(4280942402337873190),
    crate::Felt::new_unchecked(8638374671303150193),
    crate::Felt::new_unchecked(7430097580673779123),
]));
/// The declared identity of the current recursive precompile verifier profile.
///
/// Captured from the native profile's relation, entry key, and exact configuration; the profile
/// parity test checks that derivation against the current verifier artifacts.
pub const CURRENT_PVM_VERIFIER_IDENTITY: VerifierIdentity = VerifierIdentity::new(Word::new([
    crate::Felt::new_unchecked(9011431928743332758),
    crate::Felt::new_unchecked(5916201885138958320),
    crate::Felt::new_unchecked(3988397670162195093),
    crate::Felt::new_unchecked(509620422468869867),
]));

// HASH FUNCTION
// ================================================================================================

/// A hash function used during STARK proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
#[repr(u8)]
pub enum HashFunction {
    /// BLAKE3 hash function with 256-bit output.
    Blake3_256 = 0x01,
    // IDs 0x02..=0x04 belonged to removed hash functions and must not be reused.
    /// Keccak hash function with 256-bit output.
    Keccak = 0x05,
    /// Eidos hash function with 252-bit packed output.
    Eidos = 0x06,
}

impl HashFunction {
    /// Returns the collision resistance level (in bits) of this hash function.
    pub const fn collision_resistance(&self) -> u32 {
        match self {
            HashFunction::Blake3_256 => Blake3_256::COLLISION_RESISTANCE,
            HashFunction::Keccak => 128,
            HashFunction::Eidos => 126,
        }
    }
}

/// Error type for invalid hash function strings.
#[derive(Debug, thiserror::Error)]
#[error("invalid hash function '{hash_function}'. Valid options are: blake3-256, keccak, eidos")]
pub struct InvalidHashFunctionError {
    pub hash_function: String,
}

impl TryFrom<u8> for HashFunction {
    type Error = DeserializationError;

    fn try_from(repr: u8) -> Result<Self, Self::Error> {
        match repr {
            0x01 => Ok(Self::Blake3_256),
            0x05 => Ok(Self::Keccak),
            0x06 => Ok(Self::Eidos),
            _ => Err(DeserializationError::InvalidValue(format!(
                "the hash function representation {repr} is not valid!"
            ))),
        }
    }
}

impl TryFrom<&str> for HashFunction {
    type Error = InvalidHashFunctionError;

    fn try_from(hash_fn_str: &str) -> Result<Self, Self::Error> {
        match hash_fn_str {
            "blake3-256" => Ok(Self::Blake3_256),
            "keccak" => Ok(Self::Keccak),
            "eidos" => Ok(Self::Eidos),
            _ => Err(InvalidHashFunctionError { hash_function: hash_fn_str.to_string() }),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for HashFunction {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<u8>()
            .prop_map(|tag| match tag % 3 {
                0 => Self::Blake3_256,
                1 => Self::Keccak,
                _ => Self::Eidos,
            })
            .boxed()
    }
}

impl Serializable for HashFunction {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for HashFunction {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u8()?.try_into()
    }
}

// PROOF ARTIFACTS
// ================================================================================================

/// A Miden VM STARK proof together with its authenticated precompile obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct VmProof {
    pub proof: StarkProof,
    pub precompile_root: DeferredRoot,
}

impl Serializable for VmProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.precompile_root.write_into(target);
    }
}

impl Deserializable for VmProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = StarkProof::read_from(source)?;
        let precompile_root = DeferredRoot::read_from(source)?;
        Ok(Self { proof, precompile_root })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after VM proof payload".into(),
            ));
        }
        Ok(proof)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + DeferredRoot::min_serialized_size()
    }
}

/// A precompile STARK proof with its ordered constituent roots.
///
/// Binary decoding enforces the fixed root ceiling before reserving root storage, but otherwise
/// preserves the encoded artifact shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct PrecompileProof {
    pub proof: StarkProof,
    pub roots: Vec<DeferredRoot>,
}

impl PrecompileProof {
    /// Computes the aggregate deferred root.
    ///
    /// For roots `[A, B, C]`, this hashes `AND(A, B)`, then `AND(result, C)`. Order and
    /// duplicates matter. A single root is returned unchanged; an empty list returns `None`.
    /// This method does not verify the proof.
    pub fn aggregate_root(&self) -> Option<DeferredRoot> {
        self.roots.iter().copied().reduce(fold_deferred_root)
    }
}

impl Serializable for PrecompileProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.roots.write_into(target);
    }
}

impl Deserializable for PrecompileProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = StarkProof::read_from(source)?;
        let root_count = source.read_usize()?;
        if root_count > MAX_PRECOMPILE_ROOTS {
            return Err(DeserializationError::InvalidValue(format!(
                "precompile proof contains too many roots: found {root_count}, maximum is {MAX_PRECOMPILE_ROOTS}"
            )));
        }
        let roots = source
            .read_many_iter::<DeferredRoot>(root_count)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { proof, roots })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after precompile proof payload".into(),
            ));
        }
        Ok(proof)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + usize::min_serialized_size()
    }
}

/// The transport format and opaque verifier identities declared by an execution proof.
///
/// Identities are listed in chronological order, with the newest identity last. Identity order
/// does not affect compatibility checks. Construction and decoding preserve these declarations;
/// they do not authenticate identity derivation, authorize execution, or establish compatibility.
/// Consumers must apply their own admission checks and verify the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProofCompatibility {
    format: u8,
    vm_verifier_identities: Vec<VerifierIdentity>,
    pvm_verifier_identities: Vec<VerifierIdentity>,
}

impl ExecutionProofCompatibility {
    /// Execution proof transport format for environment-bound claims and portable singleton
    /// witnesses.
    pub const FORMAT_V3: u8 = 3;

    /// Creates a proof compatibility declaration for format `3`.
    ///
    /// # Errors
    ///
    /// Returns an error if either verifier identity list contains duplicates.
    pub fn new(
        vm_verifier_identities: Vec<VerifierIdentity>,
        pvm_verifier_identities: Vec<VerifierIdentity>,
    ) -> Result<Self, ExecutionProofCompatibilityError> {
        if has_duplicate(&vm_verifier_identities) {
            return Err(ExecutionProofCompatibilityError::DuplicateVmVerifierIdentity);
        }
        if has_duplicate(&pvm_verifier_identities) {
            return Err(ExecutionProofCompatibilityError::DuplicatePvmVerifierIdentity);
        }

        Ok(Self {
            format: Self::FORMAT_V3,
            vm_verifier_identities,
            pvm_verifier_identities,
        })
    }

    /// Returns the compatibility declared by proofs produced by the current prover.
    pub fn current() -> Self {
        Self::new(
            alloc::vec![CURRENT_VM_VERIFIER_IDENTITY],
            alloc::vec![CURRENT_PVM_VERIFIER_IDENTITY],
        )
        .expect("current execution proof compatibility must not contain duplicate identities")
    }

    /// Returns the transport format.
    pub const fn format(&self) -> u8 {
        self.format
    }

    /// Returns the VM verifier identities declared by this proof.
    ///
    /// The identities are unique and listed in chronological order with the most recent verifier
    /// listed last. This metadata does not authenticate or authorize the named verifiers.
    pub fn vm_verifier_identities(&self) -> &[VerifierIdentity] {
        &self.vm_verifier_identities
    }

    /// Returns the precompile VM verifier identities declared by this proof.
    ///
    /// The identities are unique and listed in chronological order with the most recent verifier
    /// listed last. This metadata does not authenticate or authorize the named verifiers.
    pub fn pvm_verifier_identities(&self) -> &[VerifierIdentity] {
        &self.pvm_verifier_identities
    }
}

/// Errors returned while constructing execution proof compatibility metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionProofCompatibilityError {
    /// The VM verifier identity list contains a duplicate.
    #[error("VM verifier identities must not contain duplicates")]
    DuplicateVmVerifierIdentity,
    /// The precompile VM verifier identity list contains a duplicate.
    #[error("PVM verifier identities must not contain duplicates")]
    DuplicatePvmVerifierIdentity,
}

/// The state of precompile work associated with an execution proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecompileStatus {
    /// The VM made no precompile requests.
    Empty,
    /// The VM made precompile requests which have not been proven.
    Deferred(PrecompileWitness),
    /// The VM made precompile requests and their proof is available.
    Proven(PrecompileProof),
}

/// A versioned Miden VM execution proof.
///
/// This type preserves proof artifacts without establishing their validity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct ExecutionProof {
    compatibility: ExecutionProofCompatibility,
    vm: VmProof,
    precompile: PrecompileStatus,
}

impl ExecutionProof {
    /// Creates an execution proof with the compatibility declared by the current prover.
    pub fn new(vm: VmProof, precompile: PrecompileStatus) -> Self {
        Self::from_parts(ExecutionProofCompatibility::current(), vm, precompile)
    }

    /// Creates an execution proof from its compatibility, VM proof, and precompile state.
    pub const fn from_parts(
        compatibility: ExecutionProofCompatibility,
        vm: VmProof,
        precompile: PrecompileStatus,
    ) -> Self {
        Self { compatibility, vm, precompile }
    }

    /// Returns the compatibility declared by this proof.
    pub const fn compatibility(&self) -> &ExecutionProofCompatibility {
        &self.compatibility
    }

    /// Returns the VM proof.
    pub const fn vm(&self) -> &VmProof {
        &self.vm
    }

    /// Returns the precompile data carried by this proof.
    ///
    /// This status describes the attached data; it does not establish proof validity.
    pub const fn precompile(&self) -> &PrecompileStatus {
        &self.precompile
    }

    /// Splits this proof into its compatibility, VM proof, and precompile state.
    pub fn into_parts(self) -> (ExecutionProofCompatibility, VmProof, PrecompileStatus) {
        (self.compatibility, self.vm, self.precompile)
    }

    /// Returns whether this proof contains precompile work.
    pub const fn has_precompiles(&self) -> bool {
        !matches!(self.precompile, PrecompileStatus::Empty)
    }

    /// Transitions a deferred proof to complete by attaching a precompile proof.
    ///
    /// This method does not verify the precompile proof or check it against the VM proof. The
    /// verifier performs those checks.
    pub fn complete(mut self, precompile: PrecompileProof) -> Result<Self, ExecutionProofError> {
        if !matches!(self.precompile, PrecompileStatus::Deferred(_)) {
            return Err(ExecutionProofError::AlreadyComplete);
        }
        self.precompile = PrecompileStatus::Proven(precompile);
        Ok(self)
    }

    /// Encodes this proof canonically.
    pub fn to_bytes(&self) -> Vec<u8> {
        Serializable::to_bytes(self)
    }

    /// Decodes a complete versioned proof from canonical bytes.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = <Self as Deserializable>::read_from(&mut reader)?;

        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after versioned proof payload".into(),
            ));
        }
        if proof.to_bytes() != bytes {
            return Err(DeserializationError::InvalidValue(
                "versioned proof bytes are not canonically encoded".into(),
            ));
        }

        Ok(proof)
    }
}

impl Serializable for ExecutionProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.compatibility.format);
        self.compatibility.vm_verifier_identities.write_into(target);
        self.compatibility.pvm_verifier_identities.write_into(target);
        self.write_into_v3(target);
    }
}

impl Deserializable for ExecutionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let format = source.read_u8()?;
        if format != ExecutionProofCompatibility::FORMAT_V3 {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported execution proof format {format}"
            )));
        }

        let vm_verifier_identities = Vec::<VerifierIdentity>::read_from(source)?;
        let pvm_verifier_identities = Vec::<VerifierIdentity>::read_from(source)?;
        let compatibility =
            ExecutionProofCompatibility::new(vm_verifier_identities, pvm_verifier_identities)
                .map_err(|error| DeserializationError::InvalidValue(error.to_string()))?;

        Self::read_from_v3(source, compatibility)
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size()
            + Vec::<VerifierIdentity>::min_serialized_size()
            + Vec::<VerifierIdentity>::min_serialized_size()
            + ExecutionProof::min_serialized_size_v3()
    }
}

impl ExecutionProof {
    fn write_into_v3<W: ByteWriter>(&self, target: &mut W) {
        match &self.precompile {
            PrecompileStatus::Deferred(precompile) => {
                target.write_u8(DEFERRED_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                precompile.write_into(target);
            },
            PrecompileStatus::Empty => {
                target.write_u8(COMPLETE_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                Option::<PrecompileProof>::None.write_into(target);
            },
            PrecompileStatus::Proven(precompile) => {
                target.write_u8(COMPLETE_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                Some(precompile).write_into(target);
            },
        }
    }

    fn read_from_v3<R: ByteReader>(
        source: &mut R,
        compatibility: ExecutionProofCompatibility,
    ) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;
        if !matches!(discriminant, DEFERRED_PROOF_DISCRIMINANT | COMPLETE_PROOF_DISCRIMINANT) {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid execution proof discriminant {discriminant}"
            )));
        }

        let vm = VmProof::read_from(source)?;
        let precompile = match discriminant {
            DEFERRED_PROOF_DISCRIMINANT => {
                PrecompileStatus::Deferred(PrecompileWitness::read_from(source)?)
            },
            COMPLETE_PROOF_DISCRIMINANT => match Option::<PrecompileProof>::read_from(source)? {
                Some(precompile) => PrecompileStatus::Proven(precompile),
                None => PrecompileStatus::Empty,
            },
            _ => unreachable!("execution proof discriminant was checked before decoding"),
        };

        Ok(Self { compatibility, vm, precompile })
    }

    fn min_serialized_size_v3() -> usize {
        u8::min_serialized_size()
            + VmProof::min_serialized_size()
            + Option::<PrecompileProof>::min_serialized_size()
    }
}

/// Lifecycle errors returned while transitioning an execution proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionProofError {
    /// Only a deferred execution proof can be completed.
    #[error("the execution proof is already complete")]
    AlreadyComplete,
}

// STARK PROOF
// ================================================================================================

/// A serialized STARK proof and the hash function used during proof generation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct StarkProof {
    bytes: Vec<u8>,
    hash_fn: HashFunction,
}

impl StarkProof {
    /// Creates a new instance of [StarkProof] from proof bytes and hash function.
    pub const fn new(bytes: Vec<u8>, hash_fn: HashFunction) -> Self {
        Self { bytes, hash_fn }
    }

    /// Returns the serialized STARK proof bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the hash function used during proof generation process.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns the serialized STARK proof bytes and hash function.
    pub fn into_parts(self) -> (Vec<u8>, HashFunction) {
        (self.bytes, self.hash_fn)
    }
}

impl Serializable for StarkProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.bytes.write_into(target);
        self.hash_fn.write_into(target);
    }
}

impl Deserializable for StarkProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let byte_count = source.read_usize()?;
        if byte_count > MAX_STARK_PROOF_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "STARK proof contains too many bytes: found {byte_count}, maximum is {MAX_STARK_PROOF_BYTES}"
            )));
        }
        let bytes = source.read_many_iter::<u8>(byte_count)?.collect::<Result<Vec<_>, _>>()?;
        let hash_fn = HashFunction::read_from(source)?;
        Ok(Self::new(bytes, hash_fn))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }

    fn min_serialized_size() -> usize {
        Vec::<u8>::min_serialized_size() + HashFunction::min_serialized_size()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn has_duplicate(identities: &[VerifierIdentity]) -> bool {
    let mut unique = BTreeSet::new();
    identities.iter().any(|identity| !unique.insert(identity.as_word()))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        deferred::{DEFERRED_AND_FRAME, Node, PrecompileWitnessEntry, TRUE_DIGEST},
        serde::ByteWriter,
    };

    fn dummy_stark_proof(bytes: &[u8]) -> StarkProof {
        StarkProof::new(bytes.to_vec(), HashFunction::Eidos)
    }

    #[test]
    fn hash_function_wire_tags_are_pinned_and_retired_tags_are_rejected() {
        for (hash_fn, tag, name) in [
            (HashFunction::Blake3_256, 0x01, "blake3-256"),
            (HashFunction::Keccak, 0x05, "keccak"),
            (HashFunction::Eidos, 0x06, "eidos"),
        ] {
            assert_eq!(hash_fn.to_bytes(), [tag]);
            assert_eq!(HashFunction::read_from_bytes(&[tag]).unwrap(), hash_fn);
            assert_eq!(HashFunction::try_from(name).unwrap(), hash_fn);
        }
        for (tag, name) in [(0x02, "rpo"), (0x03, "rpx"), (0x04, "poseidon2")] {
            assert!(HashFunction::read_from_bytes(&[tag]).is_err());
            assert!(HashFunction::try_from(name).is_err());
        }
    }

    fn root(value: u64) -> DeferredRoot {
        [Felt::new(value).unwrap(), Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
    }

    fn verifier_identity(value: u64) -> VerifierIdentity {
        // Opaque synthetic metadata; wrapping does not derive or authorize this identity.
        VerifierIdentity::new(Word::new([
            Felt::new(value).unwrap(),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]))
    }

    fn vm_proof(precompile_root: DeferredRoot) -> VmProof {
        VmProof {
            proof: dummy_stark_proof(&[1]),
            precompile_root,
        }
    }

    fn precompile_proof(roots: &[DeferredRoot]) -> PrecompileProof {
        PrecompileProof {
            proof: dummy_stark_proof(&[2]),
            roots: roots.to_vec(),
        }
    }

    #[test]
    fn aggregate_root_preserves_order_grouping_and_duplicates() {
        let a = root(1);
        let b = root(2);
        let c = root(3);
        let and = |lhs, rhs| Node::and(lhs, rhs).digest();

        assert_eq!(precompile_proof(&[]).aggregate_root(), None);
        assert_eq!(precompile_proof(&[a]).aggregate_root(), Some(a));
        assert_eq!(precompile_proof(&[a, b, c]).aggregate_root(), Some(and(and(a, b), c)));
        assert_ne!(precompile_proof(&[a, b, c]).aggregate_root(), Some(and(a, and(b, c))));
        assert_ne!(
            precompile_proof(&[a, b]).aggregate_root(),
            precompile_proof(&[b, a]).aggregate_root()
        );
        assert_eq!(precompile_proof(&[a, b, a]).aggregate_root(), Some(and(and(a, b), a)));
    }

    fn wire() -> (PrecompileWitness, DeferredRoot) {
        let witness = PrecompileWitness::from_entries(vec![PrecompileWitnessEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 0,
        }])
        .unwrap();
        let root = Node::and(TRUE_DIGEST, TRUE_DIGEST).digest();
        (witness, root)
    }

    fn versioned(vm: VmProof, precompile: PrecompileStatus) -> ExecutionProof {
        ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(
                vec![verifier_identity(11), verifier_identity(12)],
                vec![verifier_identity(21)],
            )
            .unwrap(),
            vm,
            precompile,
        )
    }

    fn version_prefix() -> Vec<u8> {
        let compatibility = ExecutionProofCompatibility::new(
            vec![verifier_identity(11), verifier_identity(12)],
            vec![verifier_identity(21)],
        )
        .unwrap();
        let mut bytes = vec![compatibility.format()];
        compatibility.vm_verifier_identities().to_vec().write_into(&mut bytes);
        compatibility.pvm_verifier_identities().to_vec().write_into(&mut bytes);
        bytes
    }

    #[test]
    fn execution_proof_reports_precompile_state() {
        let (precompile_wire, wire_root) = wire();
        let deferred = versioned(vm_proof(wire_root), PrecompileStatus::Deferred(precompile_wire));
        assert!(deferred.has_precompiles());

        let complete_without_precompile = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        assert!(!complete_without_precompile.has_precompiles());

        let complete_with_precompile =
            versioned(vm_proof(root(1)), PrecompileStatus::Proven(precompile_proof(&[root(1)])));
        assert!(complete_with_precompile.has_precompiles());
    }

    #[test]
    fn versioned_proof_round_trips_with_format_first() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);

        let bytes = proof.to_bytes();
        let decoded = ExecutionProof::read_from_bytes(&bytes).unwrap();

        assert_eq!(ExecutionProofCompatibility::FORMAT_V3, 3);
        assert_eq!(bytes[0], 3);
        assert_eq!(decoded, proof);
        assert_eq!(decoded.compatibility().format(), ExecutionProofCompatibility::FORMAT_V3);
        assert_eq!(
            decoded.compatibility().vm_verifier_identities(),
            &[verifier_identity(11), verifier_identity(12)]
        );
        assert_eq!(decoded.compatibility().pvm_verifier_identities(), &[verifier_identity(21)]);
    }

    #[test]
    fn versioned_proof_decoder_rejects_legacy_and_unknown_formats_before_body() {
        for version in [0, 1, 2, 4, u8::MAX] {
            let error = ExecutionProof::read_from_bytes(&[version]).unwrap_err();
            assert!(matches!(error, DeserializationError::InvalidValue(message)
                if message == format!("unsupported execution proof format {version}")));

            // Neither identity-list lengths nor proof/witness payloads may be read or allocated
            // before the transport version is accepted, even if the body is hostile.
            let mut bytes = vec![version];
            bytes.write_usize(usize::MAX);
            let mut reader = SliceReader::new(&bytes);
            let error = ExecutionProof::read_from(&mut reader).unwrap_err();
            assert!(matches!(error, DeserializationError::InvalidValue(message)
                if message == format!("unsupported execution proof format {version}")));
            assert_eq!(reader.read_usize().unwrap(), usize::MAX);
            assert!(!reader.has_more_bytes());
        }
    }

    #[test]
    fn execution_proof_constructors_advertise_only_format_3() {
        let compatibility = ExecutionProofCompatibility::new(vec![], vec![]).unwrap();
        assert_eq!(compatibility.format(), 3);
        assert_eq!(ExecutionProofCompatibility::current().format(), 3);
        assert_eq!(
            ExecutionProof::new(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty).to_bytes()[0],
            3
        );
    }

    #[test]
    fn versioned_proof_decoder_rejects_trailing_and_noncanonical_bytes() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        let mut trailing = proof.to_bytes();
        trailing.push(0);
        assert!(ExecutionProof::read_from_bytes(&trailing).is_err());

        let canonical = proof.to_bytes();
        assert_eq!(canonical[1], 5, "two VM identities use a one-byte vint encoding");
        let mut noncanonical = alloc::vec![canonical[0], 0];
        noncanonical.extend_from_slice(&2u64.to_le_bytes());
        noncanonical.extend_from_slice(&canonical[2..]);
        let error = ExecutionProof::read_from_bytes(&noncanonical).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("not canonically encoded"))
        );
    }

    #[test]
    fn versioned_proof_decoder_applies_the_input_budget_to_identity_lists() {
        for vm in [true, false] {
            let mut bytes = vec![ExecutionProofCompatibility::FORMAT_V3];
            if !vm {
                Vec::<VerifierIdentity>::new().write_into(&mut bytes);
            }
            bytes.write_usize(usize::MAX);

            let error = ExecutionProof::read_from_bytes(&bytes).unwrap_err();
            assert!(matches!(error, DeserializationError::InvalidValue(_)));
        }
    }

    #[test]
    fn versioned_proof_decoder_rejects_noncanonical_identity_words() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        let proof_bytes = proof.to_bytes();
        let body = &proof_bytes[version_prefix().len()..];

        for vm in [true, false] {
            let mut bytes = vec![ExecutionProofCompatibility::FORMAT_V3];
            if !vm {
                Vec::<VerifierIdentity>::new().write_into(&mut bytes);
            }
            bytes.write_usize(1);
            bytes.extend_from_slice(&[u8::MAX; 32]);
            if vm {
                Vec::<VerifierIdentity>::new().write_into(&mut bytes);
            }
            bytes.extend_from_slice(body);

            assert!(ExecutionProof::read_from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn compatibility_constructor_rejects_duplicate_identities() {
        assert_eq!(
            ExecutionProofCompatibility::new(
                vec![verifier_identity(1), verifier_identity(1)],
                vec![]
            ),
            Err(ExecutionProofCompatibilityError::DuplicateVmVerifierIdentity)
        );
        assert_eq!(
            ExecutionProofCompatibility::new(
                vec![],
                vec![verifier_identity(2), verifier_identity(2)]
            ),
            Err(ExecutionProofCompatibilityError::DuplicatePvmVerifierIdentity)
        );
    }

    #[test]
    fn versioned_proof_decoder_rejects_duplicate_identities() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        let proof_bytes = proof.to_bytes();
        let body = &proof_bytes[version_prefix().len()..];

        let mut duplicate_vm = vec![ExecutionProofCompatibility::FORMAT_V3];
        vec![verifier_identity(1), verifier_identity(1)].write_into(&mut duplicate_vm);
        Vec::<VerifierIdentity>::new().write_into(&mut duplicate_vm);
        duplicate_vm.extend_from_slice(body);
        let error = ExecutionProof::read_from_bytes(&duplicate_vm).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("VM verifier identities must not contain duplicates"))
        );

        let mut duplicate_pvm = vec![ExecutionProofCompatibility::FORMAT_V3];
        Vec::<VerifierIdentity>::new().write_into(&mut duplicate_pvm);
        vec![verifier_identity(2), verifier_identity(2)].write_into(&mut duplicate_pvm);
        duplicate_pvm.extend_from_slice(body);
        let error = ExecutionProof::read_from_bytes(&duplicate_pvm).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("PVM verifier identities must not contain duplicates"))
        );
    }

    #[test]
    fn proof_minimum_serialized_sizes_match_shortest_canonical_encodings() {
        let identity = verifier_identity(1);
        assert_eq!(VerifierIdentity::min_serialized_size(), identity.to_bytes().len());
        assert_eq!(VerifierIdentity::min_serialized_size(), 32);

        let stark = StarkProof::new(Vec::new(), HashFunction::Eidos);
        assert_eq!(StarkProof::min_serialized_size(), stark.to_bytes().len());
        assert_eq!(StarkProof::min_serialized_size(), 2);

        let vm = VmProof {
            proof: stark,
            precompile_root: TRUE_DIGEST,
        };
        assert_eq!(VmProof::min_serialized_size(), vm.to_bytes().len());
        assert_eq!(VmProof::min_serialized_size(), 34);

        let execution = ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(Vec::new(), Vec::new()).unwrap(),
            vm,
            PrecompileStatus::Empty,
        );
        assert_eq!(ExecutionProof::min_serialized_size(), execution.to_bytes().len());
        assert_eq!(ExecutionProof::min_serialized_size(), 39);

        let empty = PrecompileProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Eidos),
            roots: Vec::new(),
        };
        assert_eq!(PrecompileProof::min_serialized_size(), empty.to_bytes().len());
        assert_eq!(PrecompileProof::min_serialized_size(), 3);

        let singleton = PrecompileProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Eidos),
            roots: alloc::vec![root(1)],
        };
        assert_eq!(singleton.to_bytes().len(), 35);

        let proofs = alloc::vec![singleton.clone(), singleton];
        let bytes = proofs.to_bytes();
        assert_eq!(bytes.len(), 71);
        let decoded = Vec::<PrecompileProof>::read_from_bytes_with_budget(&bytes, 71).unwrap();
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn stark_proof_decoder_rejects_oversized_length_before_payload() {
        let mut bytes = Vec::new();
        bytes.write_usize(MAX_STARK_PROOF_BYTES + 1);

        let error = StarkProof::read_from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected excessive STARK proof length to be rejected")
        };
        assert!(message.contains("STARK proof contains too many bytes"));
    }

    #[test]
    fn precompile_proof_decoder_rejects_oversized_root_count_before_payload() {
        let at_limit = precompile_proof(&[root(3); MAX_PRECOMPILE_ROOTS]);
        assert_eq!(PrecompileProof::read_from_bytes(&at_limit.to_bytes()).unwrap(), at_limit);
        let mut bytes = dummy_stark_proof(&[2]).to_bytes();
        bytes.write_usize(MAX_PRECOMPILE_ROOTS + 1);

        let error = PrecompileProof::read_from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected excessive root count to be rejected")
        };
        assert!(message.contains("precompile proof contains too many roots"));
    }

    #[test]
    fn standalone_proof_decoders_reject_trailing_bytes() {
        let mut vm_bytes = vm_proof(root(3)).to_bytes();
        vm_bytes.push(0);
        assert!(VmProof::read_from_bytes(&vm_bytes).is_err());

        let mut precompile_bytes = precompile_proof(&[root(3)]).to_bytes();
        precompile_bytes.push(0);
        assert!(PrecompileProof::read_from_bytes(&precompile_bytes).is_err());
    }

    #[test]
    fn proof_artifacts_round_trip_canonically() {
        let stark = dummy_stark_proof(&[1, 2, 3]);
        let stark_bytes = stark.to_bytes();
        let decoded_stark = StarkProof::read_from_bytes(&stark_bytes).unwrap();
        assert_eq!(decoded_stark.to_bytes(), stark_bytes);

        let vm = vm_proof(root(3));
        let vm_bytes = vm.to_bytes();
        let decoded_vm = VmProof::read_from_bytes(&vm_bytes).unwrap();
        assert_eq!(decoded_vm.to_bytes(), vm_bytes);

        let precompile = precompile_proof(&[]);
        let precompile_bytes = precompile.to_bytes();
        let decoded_precompile = PrecompileProof::read_from_bytes(&precompile_bytes).unwrap();
        assert_eq!(decoded_precompile.to_bytes(), precompile_bytes);

        let (precompile_wire, wire_root) = wire();
        let proofs = [
            versioned(vm_proof(wire_root), PrecompileStatus::Deferred(precompile_wire)),
            versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty),
            versioned(
                vm_proof(TRUE_DIGEST),
                PrecompileStatus::Proven(precompile_proof(&[TRUE_DIGEST])),
            ),
        ];
        for proof in proofs {
            let bytes = proof.to_bytes();
            assert_eq!(ExecutionProof::read_from_bytes(&bytes).unwrap(), proof);
        }
    }

    #[test]
    fn complete_transitions_deferred_proof_without_validating_artifact_shape() {
        let vm = vm_proof(TRUE_DIGEST);
        let precompile = precompile_proof(&[]);
        let deferred = versioned(vm.clone(), PrecompileStatus::Deferred(wire().0));

        let completed = deferred.complete(precompile.clone()).unwrap();

        let (completed_compatibility, completed_vm, completed_precompile) = completed.into_parts();
        let PrecompileStatus::Proven(completed_precompile) = completed_precompile else {
            panic!("deferred proof should transition to complete")
        };
        assert_eq!(
            completed_compatibility,
            ExecutionProofCompatibility::new(
                vec![verifier_identity(11), verifier_identity(12)],
                vec![verifier_identity(21)],
            )
            .unwrap()
        );
        assert_eq!(completed_vm.to_bytes(), vm.to_bytes());
        assert_eq!(completed_precompile.to_bytes(), precompile.to_bytes());
    }

    #[test]
    fn complete_rejects_an_already_complete_proof() {
        let complete = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);

        assert!(matches!(
            complete.complete(precompile_proof(&[])),
            Err(ExecutionProofError::AlreadyComplete)
        ));
    }

    #[test]
    fn versioned_proof_transport_rejects_bad_discriminants_and_stark_bounds() {
        let mut bad_discriminant = version_prefix();
        bad_discriminant.write_u8(9);
        assert!(ExecutionProof::read_from_bytes(&bad_discriminant).is_err());

        let canonical = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty).to_bytes();
        let prefix_len = version_prefix().len();
        assert_eq!(canonical[prefix_len + 1], 3, "one STARK byte uses a one-byte vint encoding");
        let mut noncanonical = canonical[..prefix_len + 1].to_vec();
        noncanonical.push(0);
        noncanonical.extend_from_slice(&1u64.to_le_bytes());
        noncanonical.extend_from_slice(&canonical[prefix_len + 2..]);
        let error = ExecutionProof::read_from_bytes(&noncanonical).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("not canonically encoded"))
        );

        let mut oversized_proof = version_prefix();
        oversized_proof.write_u8(COMPLETE_PROOF_DISCRIMINANT);
        oversized_proof.write_usize(MAX_STARK_PROOF_BYTES + 1);
        let error = ExecutionProof::read_from_bytes(&oversized_proof).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("STARK proof contains too many bytes"))
        );
    }
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
mod proof_arbitrary {
    use proptest::prelude::*;

    use super::{
        ExecutionProof, ExecutionProofCompatibility, HashFunction, PrecompileProof,
        PrecompileStatus, PrecompileWitness, StarkProof, VmProof,
    };
    use crate::{Felt, Word, program::VerifierIdentity};

    impl Arbitrary for StarkProof {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // The reader enforces only the byte-count ceiling (64 MiB); bound well under it. The
            // bytes are an opaque serialized artifact - the type does not validate their contents.
            (
                proptest::collection::vec(any::<u8>(), 0..=64),
                prop_oneof![
                    Just(HashFunction::Blake3_256),
                    Just(HashFunction::Keccak),
                    Just(HashFunction::Eidos),
                ],
            )
                .prop_map(|(bytes, hash_fn)| StarkProof::new(bytes, hash_fn))
                .boxed()
        }
    }

    impl Arbitrary for VmProof {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // DeferredRoot is a Word alias; both fields are any-valid.
            (any::<StarkProof>(), any::<Word>())
                .prop_map(|(proof, precompile_root)| Self { proof, precompile_root })
                .boxed()
        }
    }

    impl Arbitrary for PrecompileProof {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // The reader enforces the MAX_PRECOMPILE_ROOTS ceiling; bound well under it.
            (any::<StarkProof>(), proptest::collection::vec(any::<Word>(), 0..=4))
                .prop_map(|(proof, roots)| Self { proof, roots })
                .boxed()
        }
    }

    impl Arbitrary for PrecompileStatus {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(Self::Empty),
                any::<PrecompileWitness>().prop_map(Self::Deferred).boxed(),
                any::<PrecompileProof>().prop_map(Self::Proven).boxed(),
            ]
            .boxed()
        }
    }

    impl Arbitrary for ExecutionProof {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // Sound by construction: compatibility identities are index-derived (distinct within
            // each list, satisfying the duplicate check); the rest composes covered
            // parts.
            (0usize..=3, 0usize..=3, any::<VmProof>(), any::<PrecompileStatus>())
                .prop_map(|(vm_count, pvm_count, vm, precompile)| {
                    let compatibility = ExecutionProofCompatibility::new(
                        (0..vm_count)
                            .map(|i| VerifierIdentity::new([Felt::from(i as u32); 4].into()))
                            .collect(),
                        (0..pvm_count)
                            .map(|i| {
                                VerifierIdentity::new([Felt::from((i as u32) + 1000); 4].into())
                            })
                            .collect(),
                    )
                    .expect("index-derived identities are distinct");
                    Self::from_parts(compatibility, vm, precompile)
                })
                .boxed()
        }
    }
}
