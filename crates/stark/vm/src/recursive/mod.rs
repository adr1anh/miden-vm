//! Building the advice a MASM recursive verifier consumes to verify a Miden VM proof.
//!
//! `exec.vm::verify_proof` reads a STARK proof from the advice provider in a fixed
//! order. This module is the producer side of that ABI: it selects the VM component of an
//! [`ExecutionProof`] and packages it against its [`ExecutionClaim`] into the advice-stack stream,
//! the Merkle store, and the advice-map entries the verifier consumes. Its authenticated
//! precompile root is part of the VM statement; a completed precompile STARK is not verified here.
//!
//! Before calling `vm::verify_proof`, the consumer places this proof stream on top of the advice
//! stack:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   authenticated precompile root -> Miden AIR heights -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! [`RecursiveVerifierInputs::for_request`] stores this stream in the advice map under the
//! consumer's expected verifier identity and claim commitment. The consumer selects that identity
//! independently of the proof and fetches the stream before calling `vm::verify_proof`. The
//! consumer also supplies the claim commitment; the advice map stores its 40-felt preimage under
//! that commitment, and `vm::verify_proof` authenticates the preimage before using it. Query rows,
//! the Merkle store, and the ACE circuit are content-addressed too.
//!
//! Advice construction uses the canonical native claim. It does not authorize the expected
//! verifier's configuration or verify the supplied proof. The MASM consumer must implement the
//! matching claim domain and public-input relation.

use alloc::string::{String, ToString};

use miden_air::vm::{MIDEN_AIR_COUNT, MidenMultiAir, config};
use miden_air_definitions::vm::PublicInputs;
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    field::QuadFelt,
    program::{ExecutionClaim, VerifierIdentity},
    proof::{ExecutionProof, HashFunction, MAX_STARK_PROOF_BYTES},
};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    PreprocessedValidationError, StarkConfig, VerifierInstance,
    air::Statement,
    config::observe_protocol_params,
    proof::{StarkProof, StarkProofData},
    recursive::advice::{
        AdviceError, MerkleAdvice, append_proof_payload, build_merkle_advice, package_for_request,
        security_parameter_words,
    },
    verifier::VerifierError as CryptoVerifierError,
};
use serde_wincode::{SerdeCompat, wincode};

use crate::setup::config::eidos_config;

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type RecursiveConfig = miden_stark::config::EidosConfig;
type RecursiveLmcs = <RecursiveConfig as StarkConfig<Felt, Challenge>>::Lmcs;
type RecursiveProofData = StarkProofData<Felt, Challenge, RecursiveConfig>;

/// The And8 lookup trace is the verifier-fixed full byte-pair table.
const AND8_LOOKUP_LOG_HEIGHT: usize = 16;

/// Request-packaged inputs for MASM recursive verification.
///
/// Pass [`Self::claim_commitment`] on the operand stack. The consumer derives the request key,
/// fetches the proof stream from the advice map, and then invokes `exec.vm::verify_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecursiveVerifierInputs {
    advice: AdviceInputs,
    claim_commitment: Word,
}

impl RecursiveVerifierInputs {
    /// Builds a proof package addressed by the expected verifier identity and claim commitment.
    ///
    /// The consumer supplies `expected_verifier` independently of the proof. Packaging does not
    /// authorize its configuration or verify the proof.
    ///
    /// The VM component must be an Eidos proof because the recursive verifier supports only
    /// Eidos STARKs.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof cannot be converted into verifier advice.
    pub fn for_request(
        expected_verifier: VerifierIdentity,
        proof: &ExecutionProof,
        claim: &ExecutionClaim,
    ) -> Result<Self, RecursiveVerifierInputsError> {
        Ok(build_verifier_inputs(proof, claim)?.into_request_package(expected_verifier))
    }

    /// Returns the VM advice inputs.
    pub fn advice(&self) -> &AdviceInputs {
        &self.advice
    }

    /// Returns the execution claim commitment.
    pub fn claim_commitment(&self) -> Word {
        self.claim_commitment
    }

    /// Consumes these inputs into their VM advice and claim commitment.
    pub fn into_parts(self) -> (AdviceInputs, Word) {
        (self.advice, self.claim_commitment)
    }

    /// Moves the proof stream into the advice map under
    /// `proof_request_key(expected_verifier, claim_commitment)`, leaving the advice stack empty.
    fn into_request_package(mut self, expected_verifier: VerifierIdentity) -> Self {
        self.advice = package_for_request(expected_verifier, self.claim_commitment, self.advice);
        self
    }
}

/// Builds the raw advice consumed by `vm::verify_proof` before request packaging.
fn build_verifier_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let vm = proof.vm();
    let stark = &vm.proof;
    if stark.hash_fn() != HashFunction::Eidos {
        return Err(RecursiveVerifierInputsError::UnsupportedHashFunction(stark.hash_fn()));
    }
    let pub_inputs = PublicInputs::from_claim(claim, vm.precompile_root);

    let claim_commitment = claim.commitment();
    let mut inputs = build_from_proof_bytes(stark.bytes(), &pub_inputs, claim_commitment)?;

    // The MASM verifier authenticates this preimage against the caller-provided commitment.
    inputs.advice = core::mem::take(&mut inputs.advice)
        .with_map([(claim_commitment, claim.to_elements().to_vec())]);

    Ok(inputs)
}

/// Errors returned while building the advice for recursive verification.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveVerifierInputsError {
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error("statement assembly error: {0}")]
    StatementAssembly(String),
    #[error("preprocessed-trace validation failed: {0}")]
    Preprocessed(#[from] PreprocessedValidationError),
    #[error("recursive verification supports only Eidos proofs, got {0:?}")]
    UnsupportedHashFunction(HashFunction),
    #[error("transcript error: {0}")]
    Transcript(#[from] CryptoVerifierError),
}

impl From<AdviceError> for RecursiveVerifierInputsError {
    fn from(error: AdviceError) -> Self {
        Self::InvalidProofShape(error.message())
    }
}

/// The per-AIR log trace heights in the fixed instance order streamed to the verifier.
struct MidenTraceHeights {
    instance_log_heights: [usize; MIDEN_AIR_COUNT],
}

// ADVICE CONSTRUCTION
// ================================================================================================

fn build_from_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);

    let proof = deserialize_proof(proof_bytes)?;

    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);

    let statement = Statement::<Felt, Challenge, _>::new(
        MidenMultiAir::new(),
        public_values.into_iter().enumerate().collect(),
        aux_inputs,
    )
    .map_err(|e| RecursiveVerifierInputsError::StatementAssembly(e.to_string()))?;
    let preprocessed_commitment = Some(config::EIDOS_PREPROCESSED_COMMITMENT.into());
    let verifier_instance = VerifierInstance::new(&config, &statement, preprocessed_commitment)?;

    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof, challenger)?;

    let heights = miden_trace_heights(&stark)?;

    build_advice(&config, &stark, heights, pub_inputs, claim_commitment)
}

/// Deserializes a wincode-encoded Eidos STARK proof, enforcing the total byte limit,
/// bounding preallocation, and rejecting trailing bytes.
fn deserialize_proof(
    proof_bytes: &[u8],
) -> Result<RecursiveProofData, RecursiveVerifierInputsError> {
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(RecursiveVerifierInputsError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    deserialize_schema_exact::<SerdeCompat<RecursiveProofData>, _>(proof_bytes, encoding_config)
        .map_err(|e| RecursiveVerifierInputsError::ProofDeserialization(e.to_string()))
}

fn miden_trace_heights(
    stark: &StarkProof<Challenge, RecursiveLmcs>,
) -> Result<MidenTraceHeights, RecursiveVerifierInputsError> {
    let log_heights = stark.log_trace_heights();
    let Ok(log_heights): Result<[u8; MIDEN_AIR_COUNT], _> = log_heights.try_into() else {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of AIR log heights",
        ));
    };
    Ok(MidenTraceHeights {
        instance_log_heights: log_heights.map(usize::from),
    })
}

/// Packs the parsed STARK transcript into the advice-stack stream, Merkle store, and advice map.
fn build_advice(
    config: &RecursiveConfig,
    stark: &StarkProof<Challenge, RecursiveLmcs>,
    heights: MidenTraceHeights,
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    if stark.all_aux_values.len() != MIDEN_AIR_COUNT {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }

    // This stream contains the verifier inputs derived from the proof. The canonical claim
    // preimage lives in the advice map and is authenticated against the consumer commitment.
    //
    // The section order below mirrors the consumption-order list in the module doc; both are
    // pinned against the MASM verifier by the stark e2e differential tests.

    let mut advice_stack = security_parameter_words(config.pcs()).to_vec();

    // Final deferred root, loaded by `public_inputs::stage_boundary_inputs`.
    advice_stack.extend_from_slice(pub_inputs.deferred_root().as_ref());

    if heights.instance_log_heights[3] != AND8_LOOKUP_LOG_HEIGHT {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected And8Lookup log height",
        ));
    }
    // The MASM wrapper hardcodes the trusted And8 table height and consumes only the three
    // execution-dependent heights from advice.
    for &height in &heights.instance_log_heights[..3] {
        advice_stack.push(Felt::new_unchecked(height as u64));
    }

    append_proof_payload(&mut advice_stack, stark)?;

    let (store, advice_map) = build_merkle_data(stark)?;

    let advice = AdviceInputs::default()
        .with_stack(advice_stack.into())
        .with_map(advice_map)
        .with_merkle_store(store);

    Ok(RecursiveVerifierInputs { advice, claim_commitment })
}

// MERKLE DATA
// ================================================================================================

/// Build the Merkle store and advice map from the DEEP and FRI opening proofs.
///
/// Each opening proof becomes a `PartialMerkleTree` (for the store) and `leaf_hash -> leaf_data`
/// entries (for the advice map). The verifier fetches authentication paths with `mtree_get` and
/// leaf data with `adv.push_mapval`.
fn build_merkle_data(
    stark: &StarkProof<Challenge, RecursiveLmcs>,
) -> Result<MerkleAdvice, RecursiveVerifierInputsError> {
    let (store, mut advice_map) = build_merkle_advice(stark)?;

    // One canonical circuit serves every proof order; the verifier authenticates it against the
    // pinned circuit digest.
    #[cfg(feature = "std")]
    {
        let circuit = crate::setup::ace::shared_recursive_circuit();
        advice_map.push((circuit.commitment, circuit.instructions.clone()));
    }
    #[cfg(not(feature = "std"))]
    {
        let circuit = crate::setup::ace::compiled_recursive_circuit();
        advice_map.push((circuit.commitment, circuit.instructions));
    }

    Ok((store, advice_map))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        crypto::merkle::{InnerNodeInfo, MerkleStore},
        field::{BasedVectorSpace, QuotientMap},
        program::{
            EnvironmentRoot, ExecutionDescriptor, ImplementationRoot, ProcedureKey, StackInputs,
            StackOutputs, VerifierConfiguration, proof_request_key,
        },
        proof::{PrecompileStatus, StarkProof as CoreStarkProof, VmProof},
        serde::{Deserializable, Serializable},
    };
    use miden_crypto::hash::eidos::{DomainTag, Eidos, EidosFrame};
    use miden_stark::{Preprocessed, lmcs::proof::BatchProofView};

    use super::*;

    /// A synthetic identity selected by this fixture's owner, independently of any proof.
    fn expected_verifier() -> VerifierIdentity {
        let configuration = VerifierConfiguration::new(
            ImplementationRoot::new(Word::new([21, 22, 23, 24].map(Felt::new_unchecked))),
            vec![],
            Word::new([31, 32, 33, 34].map(Felt::new_unchecked)),
        )
        .unwrap();
        VerifierIdentity::derive(
            Word::new([41, 42, 43, 44].map(Felt::new_unchecked)),
            ProcedureKey::new(Word::new([51, 52, 53, 54].map(Felt::new_unchecked))),
            configuration.commitment().unwrap(),
        )
    }

    /// The retired v1 address used an implementation root instead of a verifier identity.
    fn retired_request_key(claim_commitment: Word) -> Word {
        let mut payload = [Felt::ZERO; 8];
        payload[..4].copy_from_slice(claim_commitment.as_slice());
        payload[4..]
            .copy_from_slice(Word::new([21, 22, 23, 24].map(Felt::new_unchecked)).as_slice());
        let frame = EidosFrame::new(DomainTag::from_u32(0x0100_0201).unwrap(), [8, 0, 0]);
        Eidos::compress(frame.initial_chaining_word(), payload)
    }

    fn claim() -> ExecutionClaim {
        ExecutionClaim::new(
            ExecutionDescriptor::new(
                ProcedureKey::new(Word::new([1, 2, 3, 4].map(Felt::new_unchecked))),
                EnvironmentRoot::new(Word::new([5, 6, 7, 8].map(Felt::new_unchecked))),
            ),
            StackInputs::default(),
            StackOutputs::default(),
        )
    }

    fn claim_from_elements(elements: &[Felt; 40]) -> ExecutionClaim {
        ExecutionClaim::new(
            ExecutionDescriptor::new(
                ProcedureKey::new(Word::new(elements[0..4].try_into().unwrap())),
                EnvironmentRoot::new(Word::new(elements[4..8].try_into().unwrap())),
            ),
            StackInputs::new(&elements[8..24]).unwrap(),
            StackOutputs::new(&elements[24..40]).unwrap(),
        )
    }

    /// This metadata is the fixture owner's expected statement, selected from the named source
    /// environment and known zero I/O during maintenance. It is separate from the supplied proof;
    /// neither a program implementation root nor the deferred root supplies claim authority.
    fn native_fixture() -> (VmProof, ExecutionClaim) {
        let bytes: &[u8; 320] = include_bytes!("../../tests/fixtures/vm_eidos_v3.claim");
        let elements = core::array::from_fn(|i| {
            let value = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
            Felt::from_canonical_checked(value).expect("canonical fixture claim coordinate")
        });
        let claim = claim_from_elements(&elements);
        assert_eq!(claim.to_elements(), elements);
        assert_eq!(claim.to_elements().to_bytes(), bytes.as_slice());
        assert_eq!(*claim.stack_inputs(), StackInputs::default());
        assert_eq!(*claim.stack_outputs(), StackOutputs::default());
        let vm = VmProof::read_from_bytes(include_bytes!("../../tests/fixtures/vm_eidos_v3.bin"))
            .expect("valid native Eidos v3 fixture encoding");
        assert_eq!(vm.proof.hash_fn(), HashFunction::Eidos);
        (vm, claim)
    }

    fn assert_next(stream: &mut impl Iterator<Item = Felt>, expected: &[Felt]) {
        assert_eq!(stream.by_ref().take(expected.len()).collect::<Vec<_>>(), expected);
    }

    /// A native verifier authenticates every claim field and D independently of advice creation.
    #[test]
    fn native_fixture_verifies_only_its_owner_selected_statement() {
        let (vm, claim) = native_fixture();
        crate::verifier::verify(&claim, &vm).expect("native descriptor-based fixture must verify");

        for coordinate in [0, 4, 8, 24] {
            let mut changed = claim.to_elements();
            changed[coordinate] += Felt::new_unchecked(1);
            assert!(
                crate::verifier::verify(&claim_from_elements(&changed), &vm).is_err(),
                "claim coordinate {coordinate} must be authenticated",
            );
        }
        let mut changed_vm = vm.clone();
        changed_vm.precompile_root[0] += Felt::new_unchecked(1);
        assert!(crate::verifier::verify(&claim, &changed_vm).is_err());
        assert_eq!(
            PublicInputs::from_claim(&claim, vm.precompile_root).claim().commitment(),
            PublicInputs::from_claim(&claim, changed_vm.precompile_root)
                .claim()
                .commitment(),
            "D is authenticated by the proof but is outside CLAIM_HASH",
        );
    }

    /// Decode the native transcript separately and consume the complete advice stream in MASM
    /// order. This pins semantic content without inventing a replacement advice-byte digest.
    #[test]
    fn native_fixture_advice_preserves_claim_all_air_groups_and_transcript_order() {
        let (vm, claim) = native_fixture();
        let proof = ExecutionProof::new(vm.clone(), PrecompileStatus::Empty);
        let inputs = build_verifier_inputs(&proof, &claim).expect("native fixture advice");
        assert_eq!(inputs, build_verifier_inputs(&proof, &claim).unwrap());
        assert_eq!(inputs.claim_commitment(), claim.commitment());
        assert_eq!(
            inputs.advice().map().get(&claim.commitment()).unwrap().as_ref(),
            claim.to_elements(),
            "the content-addressed claim preimage is exactly K4 || R_E4 || I16 || O16",
        );

        let pub_inputs = PublicInputs::from_claim(&claim, vm.precompile_root);
        let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
        let elements = claim.to_elements();
        let mut expected_core = elements[8..40].to_vec();
        expected_core.extend_from_slice(&elements[0..4]);
        assert_eq!(
            public_values,
            vec![expected_core, elements[4..8].to_vec(), vec![], vec![]],
            "all four instance-order public groups, including empty groups, are retained",
        );
        assert_eq!(aux_inputs, vm.precompile_root.as_ref());

        let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        let native = deserialize_proof(vm.proof.bytes()).expect("native STARK data");
        let statement = Statement::<Felt, Challenge, _>::new(
            MidenMultiAir::new(),
            public_values.into_iter().enumerate().collect(),
            aux_inputs,
        )
        .unwrap();
        let verifier = VerifierInstance::new(
            &config,
            &statement,
            Some(config::EIDOS_PREPROCESSED_COMMITMENT.into()),
        )
        .unwrap();
        let mut challenger = config.challenger();
        observe_protocol_params(config.pcs(), &mut challenger);
        let (stark, _) = StarkProof::from_data(&verifier, &native, challenger).unwrap();

        let mut expected_order: Vec<u8> = (0..MIDEN_AIR_COUNT as u8).collect();
        expected_order.sort_by_key(|&i| (stark.log_trace_heights()[i as usize], i));
        assert_eq!(stark.air_order(), expected_order);
        assert_eq!(stark.log_trace_heights().len(), MIDEN_AIR_COUNT);
        assert_eq!(stark.log_trace_heights()[3] as usize, AND8_LOOKUP_LOG_HEIGHT);
        assert_eq!(stark.all_aux_values.len(), MIDEN_AIR_COUNT);

        let advice_stack = inputs.advice().stack();
        let mut stream = advice_stack.iter().copied();
        let pcs = config.pcs();
        assert_next(
            &mut stream,
            &[
                pcs.num_queries(),
                pcs.query_pow_bits(),
                pcs.deep_pow_bits(),
                pcs.folding_pow_bits(),
            ]
            .map(|value| Felt::new_unchecked(value as u64)),
        );
        assert_next(&mut stream, vm.precompile_root.as_ref());
        assert_next(
            &mut stream,
            &stark.log_trace_heights()[..3]
                .iter()
                .map(|&height| Felt::new_unchecked(height as u64))
                .collect::<Vec<_>>(),
        );
        let commitment = |value: <RecursiveLmcs as miden_stark::lmcs::Lmcs>::Commitment| {
            let limbs: [u64; 4] = value.into();
            limbs.map(Felt::new_unchecked)
        };
        assert_next(&mut stream, &commitment(stark.main_commit));
        assert_next(&mut stream, &commitment(stark.aux_commit));
        for group in &stark.all_aux_values {
            assert_next(&mut stream, &QuadFelt::flatten_to_base(group.clone()));
        }
        assert_next(&mut stream, &commitment(stark.quotient_commit));
        let pcs = &stark.pcs_proof;
        let deep_alpha = pcs.deep_proof.challenge_columns.as_basis_coefficients_slice();
        assert_next(&mut stream, &[deep_alpha[1], deep_alpha[0]]);
        for next_row in [false, true] {
            for group in &pcs.deep_proof.evals {
                for matrix in group {
                    let rows = matrix.values.chunks_exact(matrix.width);
                    assert!(rows.remainder().is_empty());
                    assert!((1..=2).contains(&rows.len()));
                    if let Some(row) = rows.into_iter().nth(usize::from(next_row)) {
                        assert_next(&mut stream, &QuadFelt::flatten_to_base(row.to_vec()));
                    }
                }
            }
        }
        assert_next(&mut stream, &[pcs.deep_proof.pow_witness]);
        for round in &pcs.fri_proof.rounds {
            assert_next(&mut stream, &commitment(round.commitment));
            assert_next(&mut stream, &[round.pow_witness]);
        }
        assert_next(&mut stream, &QuadFelt::flatten_to_base(pcs.fri_proof.final_poly.to_vec()));
        assert_next(&mut stream, &[pcs.query_pow_witness]);
        assert_eq!(stream.next(), None, "no legacy statement or kernel sidecar on the stream");

        let (expected_store, _) = build_merkle_advice(&stark).unwrap();
        let mut expected_map = Vec::new();
        for batch in pcs.deep_witnesses.iter().chain(pcs.fri_witnesses.iter()) {
            for index in batch.indices() {
                let key = Word::new(commitment(*batch.leaf_hash(index).unwrap()));
                let row = batch.opening(index).unwrap().as_slice().to_vec();
                expected_map.push((key, row));
            }
        }
        #[cfg(feature = "std")]
        let circuit = crate::setup::ace::shared_recursive_circuit();
        #[cfg(not(feature = "std"))]
        let circuit = crate::setup::ace::compiled_recursive_circuit();
        expected_map.push((circuit.commitment, circuit.instructions.clone()));
        expected_map.push((claim.commitment(), elements.to_vec()));
        let expected_advice =
            AdviceInputs::default().with_map(expected_map).with_merkle_store(expected_store);
        assert_eq!(inputs.advice().map(), expected_advice.map());
        assert_eq!(inputs.advice().store(), expected_advice.store());

        let expected_verifier = expected_verifier();
        let package =
            RecursiveVerifierInputs::for_request(expected_verifier, &proof, &claim).unwrap();
        assert_eq!(package, inputs.clone().into_request_package(expected_verifier));
        let proof_stream = inputs.advice().stack().iter().copied().collect::<Vec<_>>();
        assert!(package.advice().stack().is_empty());
        assert_eq!(package.claim_commitment(), claim.commitment());
        assert_eq!(package.advice().store(), inputs.advice().store());
        assert_eq!(package.advice().map().len(), inputs.advice().map().len() + 1);
        assert_eq!(
            package
                .advice()
                .map()
                .get(&proof_request_key(expected_verifier, claim.commitment()))
                .unwrap()
                .as_ref(),
            proof_stream,
        );
        for (key, value) in inputs.advice().map().iter() {
            assert_eq!(package.advice().map().get(key), Some(value));
        }
    }

    /// The top-level entry rejects non-Eidos proofs up front, before touching the proof bytes.
    #[test]
    fn recursive_verifier_inputs_reject_non_eidos_proofs() {
        let proof = ExecutionProof::new(
            VmProof {
                proof: CoreStarkProof::new(Vec::new(), HashFunction::Blake3_256),
                precompile_root: Word::default(),
            },
            PrecompileStatus::Empty,
        );
        let claim = claim();

        let err = RecursiveVerifierInputs::for_request(expected_verifier(), &proof, &claim)
            .expect_err("a Blake3 proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::UnsupportedHashFunction(HashFunction::Blake3_256)
        ));
    }

    #[test]
    fn eidos_preprocessed_commitment_matches_recursive_verifier_constant() {
        let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        let (public_values, aux_inputs) =
            PublicInputs::from_claim(&claim(), miden_core::deferred::TRUE_DIGEST).to_air_inputs();
        let statement = Statement::<Felt, Challenge, _>::new(
            MidenMultiAir::new(),
            public_values.into_iter().enumerate().collect(),
            aux_inputs,
        )
        .expect("valid Miden statement shape");
        let commitment: [u64; 4] = Preprocessed::build(&statement, &config)
            .expect("And8 declares a preprocessed table")
            .commitment()
            .into();

        let fixed = config::EIDOS_PREPROCESSED_COMMITMENT;
        assert_eq!(commitment, fixed);
    }

    #[test]
    fn proof_deserialization_rejects_oversized_input() {
        let proof_bytes = vec![0; MAX_STARK_PROOF_BYTES + 1];

        let err = deserialize_proof(&proof_bytes).expect_err("oversized proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::ProofTooLarge {
                size,
                max: MAX_STARK_PROOF_BYTES,
            } if size == proof_bytes.len()
        ));
    }

    /// Request packaging is a pure repackaging: the proof stream moves — unchanged and in
    /// order — into the advice map under `proof_request_key(expected_verifier, claim_commitment)`,
    /// and everything else is untouched.
    #[test]
    fn request_package_uses_proof_request_key() {
        let proof_stream: Vec<Felt> = (1..=8u64).map(Felt::new_unchecked).collect();
        let claim_commitment = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let expected_verifier = expected_verifier();
        let query_entry = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );
        let merkle_node = InnerNodeInfo {
            value: Word::from([41u64, 42, 43, 44].map(Felt::new_unchecked)),
            left: Word::from([51u64, 52, 53, 54].map(Felt::new_unchecked)),
            right: Word::from([61u64, 62, 63, 64].map(Felt::new_unchecked)),
        };
        let store: MerkleStore = [merkle_node].into_iter().collect();

        let advice = AdviceInputs::default()
            .with_stack(proof_stream.clone().into())
            .with_map([query_entry.clone()])
            .with_merkle_store(store.clone());
        let inputs = RecursiveVerifierInputs { advice, claim_commitment };

        let package = inputs.into_request_package(expected_verifier);

        assert!(package.advice().stack().is_empty(), "the proof must leave the advice stack");
        assert_eq!(package.claim_commitment(), claim_commitment);
        assert_eq!(package.advice().store(), &store);
        assert_eq!(package.advice().map().len(), 2, "existing entries stay, proof entry added");
        assert_eq!(package.advice().map().get(&query_entry.0).unwrap().as_ref(), query_entry.1);
        assert!(package.advice().map().get(&retired_request_key(claim_commitment)).is_none());
        assert!(package.advice().map().get(&claim_commitment).is_none());
        assert!(package.advice().map().get(expected_verifier.as_word()).is_none());
        assert_eq!(
            package
                .advice()
                .map()
                .get(&proof_request_key(expected_verifier, claim_commitment))
                .unwrap()
                .as_ref(),
            proof_stream
        );
    }

    /// This counterfactual uses an arbitrary descriptor, so rejection is only a weak regression
    /// oracle. It does not establish rejection of every legacy proof or transport version; outer
    /// proof decoding tests cover the explicit version boundary separately.
    #[test]
    fn native_verifier_rejects_legacy_statement_fixture() {
        let vm = VmProof::read_from_bytes(include_bytes!("../../tests/fixtures/vm_eidos_v1_0.bin"))
            .expect("valid legacy VM proof fixture encoding");
        let claim = claim();
        assert!(crate::verifier::verify(&claim, &vm).is_err());
    }
}
