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
pub use keyed::ReplayReadLimits;

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
    pub fn execution_descriptor(&self) -> crate::ExecutionDescriptor {
        self.vm.trace.environment.descriptor()
    }

    /// Reads replay v4 using caller authority and explicit transport/revalidation budgets.
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
/// accepts this exact value; older formats are intentionally unsupported. Version 4 includes
/// mandatory authenticated environment metadata and per-fragment keyed observations. This
/// replay version is separate from proof transport and execution-claim versions.
const EXECUTION_WITNESS_WIRE_VERSION: u8 = 4;

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
        ExecutionClaim::from_program_info(
            self.program_info.clone(),
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
    use miden_assembly::Assembler;
    use miden_core::{
        deferred::TRUE_DIGEST,
        mast::{BasicBlockNodeBuilder, MastForest},
        operations::Operation,
        program::Program,
    };
    use rstest::rstest;

    use super::{
        ExecutionWitness, Serializable, build_trace,
        trace_state::{AeadStreamReplayEntry, BitwiseOp, BitwiseReplayEntry},
    };
    use crate::{DefaultHost, ExecutionError, FastProcessor, Felt, StackInputs, mast::MastNodeId};

    fn execution_witness(source: &str) -> ExecutionWitness {
        let program = Assembler::default()
            .assemble_program("program", source)
            .expect("program should compile")
            .unwrap_program();
        let mut host = DefaultHost::default();
        FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(&program, &mut host)
            .expect("execution should produce a witness")
    }

    fn deferred_witness() -> ExecutionWitness {
        execution_witness("begin log_deferred end")
    }

    fn deferred_witness_bytes() -> alloc::vec::Vec<u8> {
        deferred_witness().to_bytes()
    }

    #[test]
    fn witness_reports_precompile_state() {
        let plain = execution_witness("begin push.1 drop end");
        assert!(!plain.has_precompiles());

        let deferred = execution_witness("begin log_deferred end");
        assert!(deferred.has_precompiles());
    }

    fn aead_stream_witness() -> ExecutionWitness {
        let mut mast_forest = MastForest::new();
        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::CryptoStream])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);
        let program = Program::new(mast_forest.into(), basic_block_id);

        let stack = [
            1, 2, 3, 4, // K_CTR
            0, // counter
            0, // src_ptr
            8, // dst_ptr
            1, // remaining
            0, 0, 0, 0, 0, 0, 0, 0, // tail
        ]
        .map(Felt::new_unchecked);
        let mut host = DefaultHost::default();
        FastProcessor::new(StackInputs::new(&stack).unwrap())
            .execute_for_proving_sync(&program, &mut host)
            .expect("AEAD stream execution should produce a witness")
    }

    #[test]
    fn witness_wire_rejects_unsupported_version() {
        let mut bytes = deferred_witness_bytes();
        assert!(ExecutionWitness::read_from_bytes(&bytes).is_ok());
        assert_eq!(bytes[0], 3, "keyed replay witnesses must use wire version 3");

        // Rejected versions are checked before decoding replay or witness payloads.
        for version in [0, 1, 2, super::EXECUTION_WITNESS_WIRE_VERSION + 1] {
            bytes[0] = version;
            let err = ExecutionWitness::read_from_bytes(&bytes)
                .expect_err("unsupported witness format must be rejected");
            assert!(format!("{err:?}").contains("unsupported execution witness wire version"));
            assert!(
                ExecutionWitness::read_from_bytes_trusted(&bytes).is_err(),
                "trusted decoding must also reject legacy replay formats"
            );
        }
    }

    #[test]
    fn witness_wire_rejects_trailing_bytes() {
        let mut bytes = deferred_witness_bytes();
        bytes.push(0);

        let err = ExecutionWitness::read_from_bytes(&bytes)
            .expect_err("witness payload with trailing bytes should be rejected");
        assert!(
            format!("{err:?}").contains("extra bytes after execution witness payload"),
            "unexpected error: {err:?}"
        );

        assert!(
            ExecutionWitness::read_from_bytes_trusted(&bytes).is_ok(),
            "the explicit trusted reader should preserve the old permissive behavior"
        );
    }

    #[test]
    fn witness_wire_accepts_large_minimally_encoded_continuation_stack() {
        let mut witness = deferred_witness();
        let continuation = &mut witness
            .vm
            .trace_replay_mut()
            .core_trace_contexts
            .first_mut()
            .expect("witness should contain a trace fragment")
            .continuation;
        for _ in 0..4096 {
            continuation.push_start_node(MastNodeId::from(0));
        }

        let bytes = witness.to_bytes();
        let restored = ExecutionWitness::read_from_bytes(&bytes)
            .expect("valid witness should fit its input-proportional allocation budget");

        assert_eq!(restored.to_bytes(), bytes);
    }

    #[test]
    fn aead_stream_witness_round_trip_rebuilds_the_same_trace() {
        let witness = aead_stream_witness();
        let bytes = witness.to_bytes();
        let claim = witness.claim();
        let (original_vm, original_precompile) = witness.into_parts();
        assert!(original_precompile.is_none());
        let original_trace = build_trace(original_vm, &miden_vm_stark::memory::default_budget())
            .expect("original trace should build");

        let restored =
            ExecutionWitness::read_from_bytes(&bytes).expect("witness should round trip");
        assert_eq!(restored.claim(), claim);
        let (restored_vm, restored_precompile) = restored.into_parts();
        assert!(restored_precompile.is_none());
        let restored_trace = build_trace(restored_vm, &miden_vm_stark::memory::default_budget())
            .expect("restored trace should build");

        assert_eq!(restored_trace.public_inputs(), original_trace.public_inputs());
        assert_eq!(restored_trace.trace_len_summary(), original_trace.trace_len_summary());
        assert_eq!(
            restored_trace.main_trace().clone_air_matrices(),
            original_trace.main_trace().clone_air_matrices()
        );
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
        let mut witness = aead_stream_witness();
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

        let witness = ExecutionWitness::read_from_bytes(&witness.to_bytes())
            .expect("the wire reader accepts Felt-valued replay lanes");
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
        let bytes = deferred_witness_bytes();
        let restored = ExecutionWitness::read_from_bytes(&bytes).expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        let precompile = precompile.expect("deferred execution should carry a precompile witness");
        assert_ne!(vm.precompile_root, TRUE_DIGEST);

        // A carried witness with an explicitly empty VM-side root is not a valid transport shape.
        let tampered = ExecutionWitness {
            vm: super::VmWitness { precompile_root: TRUE_DIGEST, ..vm },
            precompile: Some(precompile),
        };
        let err = ExecutionWitness::read_from_bytes(&tampered.to_bytes())
            .expect_err("tampered witness should be rejected");
        assert!(
            format!("{err:?}")
                .contains("VM witness carries a precompile witness for an empty deferred root"),
            "unexpected error: {err:?}"
        );

        // Sanity: the untampered wire still round-trips.
        assert!(ExecutionWitness::read_from_bytes(&bytes).is_ok());
    }

    #[test]
    fn witness_wire_rejects_missing_precompile_witness() {
        let bytes = deferred_witness_bytes();
        let restored = ExecutionWitness::read_from_bytes(&bytes).expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        assert!(precompile.is_some(), "deferred execution should carry a precompile witness");

        // Drop only the precompile witness while the VM side still claims deferred work: the
        // wire must not validate as a complete execution.
        let stripped = ExecutionWitness { vm, precompile: None };
        let err = ExecutionWitness::read_from_bytes(&stripped.to_bytes())
            .expect_err("witness without its precompile half should be rejected");
        assert!(
            format!("{err:?}")
                .contains("VM witness claims deferred work but no precompile witness is present"),
            "unexpected error: {err:?}"
        );
    }
}
