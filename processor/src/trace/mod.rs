use alloc::{format, vec::Vec};

use miden_core::{
    deferred::{Digest, TRUE_DIGEST},
    program::ExecutionClaim,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

use crate::{
    EnvironmentTraceLimits, ExecutionEnvironment, ProgramInfo, StackInputs, StackOutputs,
    fast::ExecutionOutput,
};

pub(crate) mod utils;
use utils::ChipletTraceFragment;

pub mod chiplets;
pub(crate) mod execution_tracer;
pub(crate) mod keyed;
pub(crate) mod limits;
pub use keyed::{KeyedReplayError, ReplayReadLimits, ReplayResource};

mod block_stack;
mod parallel;
mod range;
mod stack;
mod trace_state;

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

pub(crate) use execution_tracer::TraceReplay;
pub use miden_air_definitions::vm::{ChipletsLengths, TraceLenSummary, VmTrace, trace::RowIndex};
pub use miden_core::deferred::PrecompileWitness;
pub use parallel::{CORE_TRACE_WIDTH, build_trace};
// Re-exported for the streaming trace-build path
// (`FastProcessor::execute_and_build_trace_sync`), which is std-only; the buffered path
// uses `build_hasher_chiplet` and `MAX_TRACE_LEN` directly within `parallel`.
#[cfg(feature = "std")]
pub(crate) use parallel::{MAX_TRACE_LEN, build_hasher_chiplet, build_trace_with_prebuilt_hasher};
#[cfg(feature = "std")]
pub(crate) use trace_state::ResolvedHasherOp;

/// Complete in-memory witness produced by a traced program execution.
///
/// The processor constructs its VM witness and optional singleton precompile witness from the same
/// execution output, so they retain the same deferred root. The aggregate may contain private and
/// potentially large prover data. Its binary form is trusted replay data: sparse MAST node and
/// digest maps inside the trace replay are not checked against a source `MastForest` commitment;
/// see <https://github.com/0xMiden/miden-vm/issues/3303>.
#[derive(Debug)]
pub struct ExecutionWitness {
    vm: VmWitness,
    precompile: Option<PrecompileWitness>,
}

impl ExecutionWitness {
    pub(crate) fn from_execution(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        execution_output: ExecutionOutput,
        trace: TraceReplay,
    ) -> Result<Self, crate::ExecutionError> {
        trace.require_validated()?;
        if program_info.program_hash() != trace.entry_implementation()?.as_word() {
            return Err(crate::ExecutionError::Internal(
                "legacy ProgramInfo differs from authenticated entry",
            ));
        }
        let ExecutionOutput {
            stack: stack_outputs,
            advice: _,
            memory: _,
            precompile_root,
            precompile_witness: precompile,
        } = execution_output;
        let vm = VmWitness {
            program_info,
            stack_inputs,
            stack_outputs,
            trace,
            precompile_root,
        };

        Ok(Self { vm, precompile })
    }

    /// Returns the public claim associated with this witness.
    pub fn claim(&self) -> ExecutionClaim {
        self.vm.claim()
    }

    /// Returns whether this witness contains precompile work.
    pub const fn has_precompiles(&self) -> bool {
        self.precompile.is_some()
    }

    /// Consumes this witness and returns its supported low-level proving components.
    ///
    /// The [`VmWitness`] can be passed to [`build_trace`]. The optional [`PrecompileWitness`] is
    /// present only when execution authenticated deferred precompile work.
    pub fn into_parts(self) -> (VmWitness, Option<PrecompileWitness>) {
        (self.vm, self.precompile)
    }

    /// Immutable descriptor authenticated separately from legacy ProgramInfo transport.
    pub fn execution_descriptor(&self) -> crate::ExecutionTarget {
        self.vm.trace.environment.descriptor()
    }

    /// Reads replay v5 using caller authority and explicit transport/revalidation budgets.
    pub fn read_from_bytes_with_limits(
        bytes: &[u8],
        environment: &ExecutionEnvironment,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<Self, DeserializationError> {
        if bytes.len() > read_limits.max_wire_bytes {
            return Err(DeserializationError::InvalidValue(
                "execution witness exceeds wire limit".into(),
            ));
        }
        let budget = bytes.len().saturating_mul(EXECUTION_WITNESS_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        let witness = Self::read_with_limits(&mut reader, environment, trace_limits, read_limits)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after execution witness payload".into(),
            ));
        }
        Ok(witness)
    }

    /// Writes only validated, completed replay under the supplied export bounds.
    pub fn write_into_with_limits<W: ByteWriter>(
        &self,
        target: &mut W,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<(), DeserializationError> {
        self.export_size(trace_limits, read_limits)?;
        self.write_payload(target);
        Ok(())
    }

    pub fn to_bytes_with_limits(
        &self,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<Vec<u8>, DeserializationError> {
        let size = self.export_size(trace_limits, read_limits)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            DeserializationError::InvalidValue("witness export allocation failed".into())
        })?;
        self.write_payload(&mut bytes);
        Ok(bytes)
    }

    fn export_size(
        &self,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<usize, DeserializationError> {
        self.vm
            .require_validated()
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?;
        self.vm.trace.validate_export(trace_limits, read_limits)?;
        let mut size = WitnessSize { bytes: 0, overflow: false };
        self.write_payload(&mut size);
        if size.overflow || size.bytes > read_limits.max_wire_bytes {
            return Err(DeserializationError::InvalidValue(
                "execution witness exceeds wire limit".into(),
            ));
        }
        Ok(size.bytes)
    }
}

/// Covers nested replay length checks while keeping untrusted work proportional to input size.
const EXECUTION_WITNESS_BYTE_READ_BUDGET_MULTIPLIER: usize = 4;

/// Current wire format version for [`ExecutionWitness`] serialization.
///
/// The version is written as the first byte of every serialized witness. Deserialization only
/// accepts this exact value; older formats are intentionally unsupported. Version 5 fixes the
/// descriptor to (entry key, environment root), retaining authenticated environment metadata and
/// per-fragment keyed observations. This replay version is separate from proof transport and
/// execution-claim versions.
const EXECUTION_WITNESS_WIRE_VERSION: u8 = 5;

impl ExecutionWitness {
    fn write_payload<W: ByteWriter>(&self, target: &mut W) {
        EXECUTION_WITNESS_WIRE_VERSION.write_into(target);
        self.vm.write_payload(target);
        match &self.precompile {
            Some(precompile) => {
                target.write_u8(1);
                precompile.write_into(target);
            },
            None => target.write_u8(0),
        }
    }
}

impl ExecutionWitness {
    fn read_with_limits<R: ByteReader>(
        source: &mut R,
        environment: &ExecutionEnvironment,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<Self, DeserializationError> {
        let version = u8::read_from(source)?;
        if version != EXECUTION_WITNESS_WIRE_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported execution witness wire version {version} (expected \
                 {EXECUTION_WITNESS_WIRE_VERSION})"
            )));
        }
        let vm = VmWitness::read_with_limits(source, environment, trace_limits, read_limits)?;
        let precompile = match source.read_u8()? {
            0 => {
                if vm.precompile_root != TRUE_DIGEST {
                    return Err(DeserializationError::InvalidValue(
                        "VM witness claims deferred work but no precompile witness is present"
                            .into(),
                    ));
                }
                None
            },
            1 => {
                let witness = PrecompileWitness::read_from(source)?;
                if vm.precompile_root == TRUE_DIGEST {
                    return Err(DeserializationError::InvalidValue(
                        "VM witness carries a precompile witness for an empty deferred root".into(),
                    ));
                }
                Some(witness)
            },
            tag => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid precompile witness option tag {tag}"
                )));
            },
        };
        Ok(Self { vm, precompile })
    }
}

/// Witness required to materialize and prove a VM execution trace.
///
/// This potentially large value contains private replay data and is consumed by trace-building and
/// proving operations. Its binary form is trusted replay data: sparse MAST node and digest maps
/// inside the trace replay are not checked against a source `MastForest` commitment; see
/// <https://github.com/0xMiden/miden-vm/issues/3303>.
///
/// Transport uses the versioned [`ExecutionWitness`] envelope with explicit caller budgets.
#[derive(Debug)]
pub struct VmWitness {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    trace: TraceReplay,
    precompile_root: Digest,
}

impl VmWitness {
    pub(crate) fn require_validated(&self) -> Result<(), crate::ExecutionError> {
        self.trace.require_validated()?;
        if self.program_info.program_hash() != self.trace.entry_implementation()?.as_word() {
            return Err(crate::ExecutionError::Internal(
                "legacy ProgramInfo differs from authenticated entry",
            ));
        }
        Ok(())
    }

    /// Returns the public claim associated with this witness.
    pub fn claim(&self) -> ExecutionClaim {
        ExecutionClaim::new(
            self.trace.environment.descriptor(),
            self.stack_inputs,
            self.stack_outputs,
        )
    }

    /// Returns whether this witness authenticates deferred precompile work.
    pub fn has_precompiles(&self) -> bool {
        self.precompile_root != TRUE_DIGEST
    }

    /// Returns the deferred root authenticated by the replayed VM execution.
    pub fn precompile_root(&self) -> Digest {
        self.precompile_root
    }

    /// Takes the hasher replay out, leaving an empty buffered one.
    ///
    /// The streaming path uses this to drop the replay's channel sender once execution has
    /// finished, so the concurrently running hasher builder sees its input stream end.
    #[cfg(feature = "std")]
    pub(crate) fn take_hasher_replay(&mut self) -> trace_state::HasherRequestReplay {
        core::mem::take(&mut self.trace.hasher_for_chiplet)
    }

    /// Returns the replay data captured during execution.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn trace_replay(&self) -> &TraceReplay {
        &self.trace
    }

    // Kept for tests that force invalid replay data without widening the public API.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn trace_replay_mut(&mut self) -> &mut TraceReplay {
        &mut self.trace
    }

    /// Returns the number of sparse MAST forests captured in the replay.
    ///
    /// Available under the `testing` feature for external tests that check which replay data a
    /// serialized witness preserves.
    #[cfg(any(test, feature = "testing"))]
    #[allow(dead_code)]
    pub fn mast_forest_count(&self) -> usize {
        self.trace.mast_forest_store.len()
    }
}

impl VmWitness {
    fn write_payload<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
        self.trace.write_payload(target);
        self.precompile_root.write_into(target);
    }
}

impl VmWitness {
    fn read_with_limits<R: ByteReader>(
        source: &mut R,
        environment: &ExecutionEnvironment,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<Self, DeserializationError> {
        let witness = Self {
            program_info: ProgramInfo::read_from(source)?,
            stack_inputs: StackInputs::read_from(source)?,
            stack_outputs: StackOutputs::read_from(source)?,
            trace: TraceReplay::read_with_limits(source, environment, trace_limits, read_limits)?,
            precompile_root: Digest::read_from(source)?,
        };
        let entry = witness
            .trace
            .entry_implementation()
            .map_err(|error| DeserializationError::InvalidValue(format!("{error}")))?;
        if witness.program_info.program_hash() != entry.as_word() {
            return Err(DeserializationError::InvalidValue(
                "legacy ProgramInfo differs from authenticated entry implementation".into(),
            ));
        }
        Ok(witness)
    }
}

struct WitnessSize {
    bytes: usize,
    overflow: bool,
}
impl ByteWriter for WitnessSize {
    fn write_u8(&mut self, _: u8) {
        self.write_bytes(&[0]);
    }
    fn write_bytes(&mut self, values: &[u8]) {
        match self.bytes.checked_add(values.len()) {
            Some(bytes) => self.bytes = bytes,
            None => self.overflow = true,
        }
    }
}

#[cfg(test)]
mod wire_tests {
    use miden_core::{
        deferred::TRUE_DIGEST,
        program::{KernelDescriptor, ProgramInfo},
    };
    use rstest::rstest;

    use super::{
        ExecutionWitness, build_trace,
        trace_state::{AeadStreamReplayEntry, BitwiseOp, BitwiseReplayEntry},
    };
    use crate as processor;
    use crate::{ExecutionError, Felt, mast::MastNodeId};

    // Keep the public fixture shared without exposing private replay mutations to integration
    // tests.
    mod common {
        include!("../../tests/common/keyed_witness.rs");
    }
    use common::{
        WitnessFixture, aead_stream_witness, deferred_witness, read_limits, trace_limits,
    };

    #[test]
    fn witness_claim_retains_descriptor_independently_of_legacy_kernel_metadata() {
        let WitnessFixture { mut witness, environment } = deferred_witness();
        let claim = witness.claim();
        let implementation = *witness.vm.program_info.program_hash();
        assert_ne!(claim.entry_key().as_word(), &implementation);
        assert_eq!(claim.execution_descriptor(), environment.descriptor());

        // Kernel metadata is retained for code/debug transport, without granting authority to
        // select the claim's entry key or environment root.
        witness.vm.program_info =
            ProgramInfo::new(implementation, KernelDescriptor::new(&[implementation]).unwrap());
        assert_eq!(witness.claim(), claim);
        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let mut restored = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .unwrap();
        assert_eq!(restored.claim(), claim);
        assert_eq!(restored.vm.program_info, witness.vm.program_info);

        // The retained entry implementation still has to match the authenticated replay.
        restored.vm.program_info =
            ProgramInfo::new(claim.entry_key().into_word(), KernelDescriptor::default());
        assert!(matches!(
            restored.vm.require_validated(),
            Err(ExecutionError::Internal("legacy ProgramInfo differs from authenticated entry"))
        ));
        assert!(restored.to_bytes_with_limits(trace_limits(), read_limits()).is_err());
    }

    #[test]
    fn witness_wire_accepts_large_minimally_encoded_continuation_stack() {
        let WitnessFixture { mut witness, environment } = deferred_witness();
        let continuation = &mut witness
            .vm
            .trace_replay_mut()
            .core_trace_contexts
            .first_mut()
            .expect("witness should contain a trace fragment")
            .continuation;
        let initial_len = continuation.len();
        for _ in 0..4096 {
            continuation.push_start_node(MastNodeId::from(0));
        }

        // Continuations do not change authenticated keyed metadata. Preserve the allocation-budget
        // regression through the checked export and the explicit, input-proportional reader.
        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let restored = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect("minimally encoded continuations should fit the input-proportional read budget");
        assert_eq!(
            restored.vm.trace_replay().core_trace_contexts[0].continuation.len(),
            initial_len + 4096
        );
        assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    }

    #[rstest]
    #[case::keystream_not_u32(
        |entry: &mut AeadStreamReplayEntry, lane: usize| {
            entry.keystream[lane] = Felt::new_unchecked(1 << 32);
        },
        "operation expected u32 values"
    )]
    #[case::ciphertext_not_u32(
        |entry: &mut AeadStreamReplayEntry, lane: usize| {
            entry.ciphertext[lane] = Felt::new_unchecked(1 << 32);
        },
        "operation expected u32 values"
    )]
    #[case::ciphertext_mismatch(
        |entry: &mut AeadStreamReplayEntry, lane: usize| {
            entry.ciphertext[lane] =
                Felt::new_unchecked(entry.ciphertext[lane].as_canonical_u64() ^ 1);
        },
        "AEAD stream ciphertext does not match plaintext XOR keystream"
    )]
    fn build_trace_rejects_inconsistent_aead_stream_replay(
        #[case] tamper: fn(&mut AeadStreamReplayEntry, usize),
        #[case] expected_error: &str,
        #[values(0, 7)] lane: usize,
    ) {
        let WitnessFixture { mut witness, environment } = aead_stream_witness();
        let replay = &mut witness.vm.trace_replay_mut().bitwise_replay;
        let mut tampered = false;
        for entry in core::mem::take(replay) {
            match entry {
                BitwiseReplayEntry::AeadStream(mut entry) => {
                    if !tampered {
                        tamper(&mut entry, lane);
                        tampered = true;
                    }
                    replay.record_aead_stream(*entry);
                },
                BitwiseReplayEntry::U32(BitwiseOp::U32And, a, b) => replay.record_u32and(a, b),
                BitwiseReplayEntry::U32(BitwiseOp::U32Xor, a, b) => replay.record_u32xor(a, b),
            }
        }
        assert!(tampered, "the witness should contain an AEAD stream entry");

        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let witness = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect("the bounded wire reader accepts Felt-valued replay lanes");
        let Err(error) =
            build_trace(witness.into_parts().0, &miden_vm_stark::memory::default_budget())
        else {
            panic!("invalid AEAD stream replay must return an error");
        };
        assert!(matches!(error, ExecutionError::OperationError { .. }));
        assert!(format!("{error}").contains(expected_error), "unexpected error: {error}");
    }

    #[test]
    fn witness_wire_rejects_precompile_witness_with_true_root() {
        let WitnessFixture { witness, environment } = deferred_witness();
        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let restored = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        let precompile = precompile.expect("deferred execution should carry a precompile witness");
        assert_ne!(vm.precompile_root, TRUE_DIGEST);

        // This changes only the VM-side deferred root, leaving authenticated keyed metadata intact.
        let tampered = ExecutionWitness {
            vm: super::VmWitness { precompile_root: TRUE_DIGEST, ..vm },
            precompile: Some(precompile),
        };
        let tampered_bytes = tampered.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let err = ExecutionWitness::read_from_bytes_with_limits(
            &tampered_bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect_err("carried precompile witness with an empty deferred root should be rejected");
        assert!(
            format!("{err:?}")
                .contains("VM witness carries a precompile witness for an empty deferred root"),
            "unexpected error: {err:?}"
        );

        assert!(
            ExecutionWitness::read_from_bytes_with_limits(
                &bytes,
                &environment,
                trace_limits(),
                read_limits(),
            )
            .is_ok()
        );
    }

    #[test]
    fn witness_wire_rejects_missing_precompile_witness() {
        let WitnessFixture { witness, environment } = deferred_witness();
        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let restored = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        assert!(precompile.is_some(), "deferred execution should carry a precompile witness");

        // Drop only the precompile half while the VM root still authenticates deferred work.
        let stripped = ExecutionWitness { vm, precompile: None };
        let stripped_bytes = stripped.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let err = ExecutionWitness::read_from_bytes_with_limits(
            &stripped_bytes,
            &environment,
            trace_limits(),
            read_limits(),
        )
        .expect_err("witness without its precompile half should be rejected");
        assert!(
            format!("{err:?}")
                .contains("VM witness claims deferred work but no precompile witness is present"),
            "unexpected error: {err:?}"
        );
    }
}
