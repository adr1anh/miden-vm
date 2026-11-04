//! Test-only proof construction and verification for the evaluator comparison.

use alloc::{format, string::String, vec};

use miden_air::vm::{PublicInputs, config};
use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, StarkProof, VmProof},
};
use miden_stark::{
    Preprocessed, ProverInstance, StarkConfig, VerifierInstance,
    air::{ProverStatement, Statement},
    config::{EidosConfig, observe_protocol_params},
    proof::{StarkOutput, StarkProofData},
};
use miden_vm_stark::setup::config::eidos_config;
use serde_wincode::{SerdeCompat, wincode};

use super::{
    ReproTrace,
    comparison_air::{ComparisonMultiAir, CoreMode},
};

/// A retained proof and its verification outcome under the selected evaluator.
#[derive(Debug)]
pub(crate) struct ComparisonResult {
    pub(crate) proof: VmProof,
    pub(crate) verification: Result<(), String>,
}

impl ReproTrace {
    /// Proves the captured matrices against the independently captured expected claim.
    ///
    /// Setup, proof construction and encoding failures are outer errors. A verifier rejection
    /// remains beside the constructed proof so callers can also test production consumers.
    pub(crate) fn prove_comparison(&self, mode: CoreMode) -> Result<ComparisonResult, String> {
        self.prove_comparison_air(ComparisonMultiAir::new(mode))
    }

    pub(super) fn prove_syscall_comparison(&self) -> Result<ComparisonResult, String> {
        self.prove_comparison_air(ComparisonMultiAir::without_syscall_namespace_check())
    }

    pub(super) fn prove_controller_entry_comparison(&self) -> Result<ComparisonResult, String> {
        self.prove_comparison_air(ComparisonMultiAir::without_controller_entry_check())
    }

    fn prove_comparison_air(
        &self,
        multi_air: ComparisonMultiAir,
    ) -> Result<ComparisonResult, String> {
        let mut stark_config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        stark_config.hash_lde_blocks = false;

        let public_inputs = PublicInputs::from_claim(&self.claim(), self.precompile_root);
        let (public_values, aux_inputs) = public_inputs.to_air_inputs();
        let statement = Statement::<Felt, QuadFelt, _>::new(
            multi_air,
            public_values.into_iter().enumerate().collect(),
            aux_inputs,
        )
        .map_err(|error| format!("comparison statement construction failed: {error}"))?;
        let prover_statement = ProverStatement::new(
            statement,
            vec![
                self.core.clone(),
                self.chiplets.clone(),
                self.eidos_compression.clone(),
                self.and8.clone(),
            ],
        )
        .map_err(|error| format!("comparison trace setup failed: {error}"))?;

        let preprocessed = Preprocessed::build(prover_statement.statement(), &stark_config)
            .ok_or_else(|| String::from("comparison setup is missing production preprocessing"))?;
        if <[u64; 4]>::from(preprocessed.commitment()) != config::EIDOS_PREPROCESSED_COMMITMENT {
            return Err(String::from(
                "comparison preprocessing differs from the production commitment",
            ));
        }

        let mut prover_challenger = stark_config.challenger();
        observe_protocol_params(stark_config.pcs(), &mut prover_challenger);
        let (output, statement): (StarkOutput<Felt, QuadFelt, EidosConfig>, _) =
            ProverInstance::new(&stark_config, prover_statement, Some(&preprocessed))
                .map_err(|error| format!("comparison prover setup failed: {error}"))?
                .prove(prover_challenger)
                .map_err(|error| format!("comparison proof construction failed: {error}"))?;

        let proof_bytes = <SerdeCompat<StarkProofData<Felt, QuadFelt, EidosConfig>> as
            wincode::config::Serialize<_>>::serialize(
            &output.proof,
            wincode::config::Configuration::default(),
        )
        .map_err(|error| format!("comparison proof encoding failed: {error}"))?;
        let proof = VmProof {
            proof: StarkProof::new(proof_bytes, HashFunction::Eidos),
            precompile_root: self.precompile_root,
        };

        let verifier = VerifierInstance::new(
            &stark_config,
            &statement,
            Some(config::EIDOS_PREPROCESSED_COMMITMENT.into()),
        )
        .map_err(|error| format!("comparison verifier setup failed: {error}"))?;
        let mut verifier_challenger = stark_config.challenger();
        observe_protocol_params(stark_config.pcs(), &mut verifier_challenger);
        let verification = verifier
            .verify(&output.proof, verifier_challenger)
            .map(|_| ())
            .map_err(|error| format!("comparison verifier rejected: {error}"));

        Ok(ComparisonResult { proof, verification })
    }
}
