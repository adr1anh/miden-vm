use alloc::{format, string::String};
use core::borrow::BorrowMut;

use miden_air_definitions::vm::{
    CoreCols, TraceLenSummary,
    trace::{MainTrace, RowIndex},
};
use miden_core::{
    Felt,
    program::{ExecutionClaim, ExecutionTarget, StackOutputs},
    proof::{ExecutionProof, HashFunction, PrecompileStatus, VmProof},
    utils::{Matrix, RowMajorMatrix},
};
use miden_core_lib::CoreLibrary;
use miden_processor::{ExecutionError, trace::VmTrace};
use miden_utils_testing::Test;
use miden_verifier::{VerificationError, VerificationOutcome, Verifier};
use miden_vm_stark::{prover::prove, recursive::RecursiveVerifierInputs};

mod controller_regression;
mod syscall_fixture;

/// Returns a mutable view of one core trace row.
pub fn core_row_mut(matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow_mut()
}

/// Proof inputs shared by adversarial trace regression tests.
///
/// Scenario-specific fixtures own one of these and keep only their relevant row indices and
/// honest values alongside it.
pub struct ReproTrace {
    pub core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    eidos_compression: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
    entry_implementation: miden_core::program::ImplementationRoot,
    execution_descriptor: ExecutionTarget,
    init_stack: miden_processor::StackInputs,
    precompile_root: miden_core::deferred::DeferredRoot,
    outputs: StackOutputs,
    last_program_row: RowIndex,
    summary: TraceLenSummary,
}

impl ReproTrace {
    /// Captures the matrices and public inputs needed to prove mutations of `trace`.
    pub fn new(trace: &VmTrace) -> Self {
        let main = trace.main_trace();
        let (core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
        Self {
            core,
            chiplets,
            eidos_compression,
            and8,
            entry_implementation: trace.entry_implementation(),
            execution_descriptor: trace.execution_descriptor(),
            init_stack: trace.init_stack_state(),
            precompile_root: trace.precompile_root(),
            outputs: *trace.stack_outputs(),
            last_program_row: main.last_program_row(),
            summary: *trace.trace_len_summary(),
        }
    }

    pub fn outputs(&self) -> StackOutputs {
        self.outputs
    }

    /// Returns the independently captured execution claim for the honest trace.
    pub fn claim(&self) -> ExecutionClaim {
        ExecutionClaim::new(self.execution_descriptor, self.init_stack, self.outputs)
    }

    /// Proves the currently stored AIR matrices against the captured public outputs.
    pub fn prove_current(&self) -> Result<VmProof, String> {
        self.prove_parts(
            self.core.clone(),
            self.chiplets.clone(),
            self.eidos_compression.clone(),
            self.and8.clone(),
            self.outputs,
        )
    }

    /// Prepares the real MASM VM verifier for a retained proof and the captured expected claim.
    ///
    /// The caller chooses whether execution must succeed or reach a specific verification error.
    pub fn recursive_verifier_test(&self, proof: VmProof) -> Result<Test, String> {
        let core_lib = CoreLibrary::default();
        let profile = core_lib.vm_recursive_verifier_profile().map_err(|error| {
            format!("embedded VM verifier profile construction failed: {error}")
        })?;
        let expected_verifier = profile.identity();
        let claim = self.claim();
        let proof = ExecutionProof::new(proof, PrecompileStatus::Empty);
        let (advice_inputs, claim_commitment) =
            RecursiveVerifierInputs::for_request(expected_verifier, &proof, &claim)
                .map_err(|error| {
                    format!("recursive verifier request construction failed: {error}")
                })?
                .into_parts();
        let [v0, v1, v2, v3] = expected_verifier
            .into_word()
            .into_elements()
            .map(|felt| felt.as_canonical_u64());
        let source = format!(
            "
            use miden::core::sys
            use miden::core::sys::vm

            begin
                # Initial stack: [CLAIM_COMMITMENT].
                dupw
                push.{v3} push.{v2} push.{v1} push.{v0}
                exec.sys::build_proof_request_key
                adv.push_mapval dropw
                exec.vm::verify_proof
                # => [security_descriptor(12), D]
                exec.sys::truncate_stack
            end
            "
        );
        let mut test = Test::new("retained_vm_proof_recursive_verifier", &source, false)
            .with_stack_inputs(claim_commitment.into_elements().map(|felt| felt.as_canonical_u64()))
            .with_library_and_naming(core_lib.package(), core_lib.naming().clone())
            .with_environment_fragment(profile.shared_fragment())
            .with_event_handlers(core_lib.handlers());
        test.advice_inputs = advice_inputs;

        let fixture = test
            .fixture_environment()
            .map_err(|error| format!("recursive verifier environment assembly failed: {error}"))?;
        let environment = fixture.validated_environment();
        let mut effective_advice = test.advice_inputs.map().clone();
        for package in &test.libraries {
            effective_advice.merge(package.mast_forest().advice_map()).map_err(|error| {
                format!("recursive verifier package and request advice conflict: {error:?}")
            })?;
        }
        profile
            .authorize(
                fixture.target().environment_root(),
                environment,
                &effective_advice,
                environment.visits(),
            )
            .map_err(|error| {
                format!("recursive verifier environment authorization failed: {error}")
            })?;
        Ok(test)
    }

    /// Requires both production consumers to accept the same retained artifact and expected claim.
    #[track_caller]
    pub(crate) fn assert_native_and_recursive_accept(&self, proof: VmProof) {
        let native = self.verify_vm_proof(proof.clone(), self.outputs);
        assert!(native.is_ok(), "honest artifact must verify natively: {native:?}");
        self.recursive_verifier_test(proof)
            .expect("honest recursive setup must authorize")
            .execute_for_output()
            .expect("honest artifact must verify in MASM");
    }

    /// Requires proof-stage native and exact MASM AIR rejection, after artifact construction.
    #[track_caller]
    pub(crate) fn assert_native_and_recursive_air_rejection(&self, proof: VmProof) {
        let native = self.verify_vm_proof(proof.clone(), self.outputs);
        assert!(
            matches!(&native, Err(VerificationError::StarkVerificationError(..))),
            "current native verification must reject the constructed AIR witness: {native:?}"
        );
        let execution = self
            .recursive_verifier_test(proof)
            .expect("the same artifact must reach the authorized recursive verifier")
            .execute_for_output();
        assert!(
            matches!(&execution, Err(ExecutionError::AceChipError { error, .. }) if error.0 == "circuit does not evaluate to zero"),
            "current MASM must reject the same AIR evaluation in ACE: {execution:?}"
        );
    }

    /// Proves `core` against the honest public outputs and runs the resulting proof through the
    /// verifier. A low-level proving failure is unexpected in tests using this method.
    pub fn prove_and_verify(
        &self,
        core: RowMajorMatrix<Felt>,
    ) -> Result<VerificationOutcome, VerificationError> {
        self.prove_and_verify_with_outputs(core, self.outputs)
    }

    /// Proves and verifies the currently stored core matrix.
    pub fn prove_and_verify_current(&self) -> Result<VerificationOutcome, VerificationError> {
        self.prove_and_verify(self.core.clone())
    }

    /// Like [`Self::prove_and_verify`], but proves against caller-supplied public outputs.
    pub fn prove_and_verify_with_outputs(
        &self,
        core: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, VerificationError> {
        let proof = self
            .prove_parts(
                core,
                self.chiplets.clone(),
                self.eidos_compression.clone(),
                self.and8.clone(),
                outputs,
            )
            .unwrap_or_else(|error| {
                panic!("the low-level prover should encode the forged trace: {error}")
            });
        self.verify_vm_proof(proof, outputs)
    }

    /// Proves and verifies caller-supplied AIR matrices while permitting lookup construction to
    /// reject an unbalanced adversarial trace. Other proving failures remain test failures.
    pub fn prove_and_verify_parts_allowing_lookup_rejection(
        &self,
        core: RowMajorMatrix<Felt>,
        chiplets: RowMajorMatrix<Felt>,
        eidos_compression: RowMajorMatrix<Felt>,
        and8: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, String> {
        let proof = match self.prove_parts(core, chiplets, eidos_compression, and8, outputs) {
            Ok(proof) => proof,
            Err(error) => {
                assert!(
                    error.contains("external assertion 0 is non-zero"),
                    "unexpected prover failure: {error}"
                );
                return Err(format!("prover rejected an unbalanced lookup: {error}"));
            },
        };

        self.verify_vm_proof(proof, outputs)
            .map_err(|error| format!("verifier rejected: {error}"))
    }

    /// Runs the full proof pipeline while allowing the lookup construction itself to reject an
    /// unbalanced adversarial trace. Other proving failures remain test failures.
    pub fn prove_and_verify_allowing_lookup_rejection(
        &self,
        core: RowMajorMatrix<Felt>,
    ) -> Result<VerificationOutcome, String> {
        self.prove_and_verify_parts_allowing_lookup_rejection(
            core,
            self.chiplets.clone(),
            self.eidos_compression.clone(),
            self.and8.clone(),
            self.outputs,
        )
    }

    /// Proves caller-supplied AIR matrices using the independently captured execution inputs.
    pub fn prove_parts(
        &self,
        core: RowMajorMatrix<Felt>,
        chiplets: RowMajorMatrix<Felt>,
        eidos_compression: RowMajorMatrix<Felt>,
        and8: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VmProof, String> {
        let main = MainTrace::from_parts(
            core.values,
            chiplets.values,
            eidos_compression.values,
            and8.values,
            self.last_program_row,
        );
        // Rebuilt compression witnesses can have different heights from the honest fixture.
        let summary = TraceLenSummary::new(
            self.summary.core_rows(),
            self.summary.chiplets(),
            self.summary.eidos_compression_rows(),
            self.summary.byte_pair_lookup_rows(),
            [
                main.core_height(),
                main.chiplets_height(),
                main.eidos_compression_height(),
                main.byte_pair_lookup_height(),
            ],
        );
        let trace = VmTrace::new_from_parts(
            self.entry_implementation,
            self.execution_descriptor,
            self.init_stack,
            outputs,
            self.precompile_root,
            main,
            summary,
        );
        prove(trace, HashFunction::Eidos, false).map_err(|error| format!("{error}"))
    }

    /// Verifies a constructed VM proof against the captured inputs and supplied public outputs.
    pub fn verify_vm_proof(
        &self,
        proof: VmProof,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, VerificationError> {
        let proof = ExecutionProof::new(proof, PrecompileStatus::Empty);
        let claim = ExecutionClaim::new(self.execution_descriptor, self.init_stack, outputs);
        Verifier::new().verify(&claim, &proof)
    }
}
