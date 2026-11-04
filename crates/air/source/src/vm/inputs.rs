//! Complete caller-selected VM statement inputs.
//!
//! The execution claim supplies the entry key, environment root and public stack I/O. The
//! authenticated deferred root is a separate proof obligation and transcript input.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt, WORD_SIZE, Word,
    deferred::DeferredRoot,
    program::{
        EnvironmentRoot, ExecutionClaim, ExecutionTarget, MIN_STACK_DEPTH, ProcedureKey,
        StackInputs, StackOutputs,
    },
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};
#[cfg(feature = "arbitrary")]
mod arbitrary;

/// Version of the descriptor-based public-input transport.
const PUBLIC_INPUTS_VERSION: u8 = 2;

/// The canonical claim and the deferred obligation authenticated by this proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct PublicInputs {
    claim: ExecutionClaim,
    deferred_root: DeferredRoot,
}

impl PublicInputs {
    pub fn new(
        descriptor: ExecutionTarget,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        deferred_root: DeferredRoot,
    ) -> Self {
        Self::from_claim(
            &ExecutionClaim::new(descriptor, stack_inputs, stack_outputs),
            deferred_root,
        )
    }

    /// Uses the caller's complete expected claim without deriving identities from supplied code.
    pub fn from_claim(claim: &ExecutionClaim, deferred_root: DeferredRoot) -> Self {
        Self { claim: claim.clone(), deferred_root }
    }

    pub fn execution_descriptor(&self) -> ExecutionTarget {
        self.claim.execution_descriptor()
    }

    pub fn claim(&self) -> &ExecutionClaim {
        &self.claim
    }

    pub fn stack_inputs(&self) -> StackInputs {
        *self.claim.stack_inputs()
    }

    pub fn stack_outputs(&self) -> StackOutputs {
        *self.claim.stack_outputs()
    }

    pub fn deferred_root(&self) -> DeferredRoot {
        self.deferred_root
    }

    /// Returns all public groups in canonical Core/Chiplets/Eidos/And8 order, plus deferred aux4.
    ///
    /// Core36 is I || O || K_entry; Chiplets4 is R_E. Empty public groups for the two remaining
    /// AIRs are explicit. No kernel list, program implementation root or missing-value fallback
    /// participates in the statement.
    pub fn to_air_inputs(&self) -> (Vec<Vec<Felt>>, Vec<Felt>) {
        let mut core = Vec::with_capacity(NUM_PUBLIC_VALUES);
        core.extend_from_slice(self.claim.stack_inputs().as_ref());
        core.extend_from_slice(self.claim.stack_outputs().as_ref());
        core.extend_from_slice(self.claim.entry_key().as_word().as_elements());
        let chiplets = self.claim.environment_root().as_word().as_elements().to_vec();
        (
            vec![core, chiplets, Vec::new(), Vec::new()],
            self.deferred_root.as_ref().to_vec(),
        )
    }

    /// Returns the diagnostic statement tuple claim40 || deferred4.
    ///
    /// This 44-element tuple is not an execution-claim encoding. Claim commitments use only
    /// `ExecutionClaim::to_elements`, under the v2 claim domain.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut elements = self.claim.to_elements().to_vec();
        elements.extend_from_slice(self.deferred_root.as_ref());
        elements
    }
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(PUBLIC_INPUTS_VERSION);
        self.claim.entry_key().write_into(target);
        self.claim.environment_root().write_into(target);
        self.claim.stack_inputs().write_into(target);
        self.claim.stack_outputs().write_into(target);
        self.deferred_root.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn min_serialized_size() -> usize {
        // Version, entry/environment/deferred words, and the two empty-stack length bytes.
        3 * Word::SERIALIZED_SIZE + 3
    }

    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_u8()? != PUBLIC_INPUTS_VERSION {
            return Err(DeserializationError::InvalidValue(
                "unsupported VM public-input transport version".into(),
            ));
        }
        let descriptor = ExecutionTarget::new(
            ProcedureKey::read_from(source)?,
            EnvironmentRoot::read_from(source)?,
        );
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let deferred_root = DeferredRoot::read_from(source)?;
        Ok(Self::new(descriptor, stack_inputs, stack_outputs, deferred_root))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from_bytes_with_budget(bytes, bytes.len())
    }

    fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        let value = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after VM public inputs".into(),
            ));
        }
        Ok(value)
    }
}

/// Core public values: I[16] || O[16] || K_entry[4].
pub const NUM_PUBLIC_VALUES: usize = MIN_STACK_DEPTH + MIN_STACK_DEPTH + WORD_SIZE;
/// Chiplets public values: R_E[4].
pub const NUM_CHIPLETS_PUBLIC_VALUES: usize = WORD_SIZE;
/// Statement-only inputs: the authenticated deferred root[4].
pub const NUM_AUX_INPUTS: usize = WORD_SIZE;
pub(super) const AUX_DEFERRED_ROOT: usize = 0;
