//! Concrete VM configuration and setup policy.

#[cfg(all(feature = "std", feature = "prover"))]
pub(crate) mod preprocessed;

pub mod ace;

#[cfg(test)]
fn canonical_setup_statement() -> miden_stark::air::Statement<
    miden_core::Felt,
    miden_core::field::QuadFelt,
    miden_air::vm::MidenMultiAir,
> {
    use miden_air::vm::{MidenMultiAir, PublicInputs};
    use miden_core::{
        Felt, Word,
        program::{
            EnvironmentRoot, ExecutionClaim, ExecutionDescriptor, ProcedureKey, StackInputs,
            StackOutputs,
        },
    };
    use miden_stark::air::Statement;

    let word = |start: u32| Word::new(core::array::from_fn(|i| Felt::from_u32(start + i as u32)));
    let claim = ExecutionClaim::new(
        ExecutionDescriptor::new(ProcedureKey::new(word(1)), EnvironmentRoot::new(word(5))),
        StackInputs::new(&[Felt::from_u32(9)]).unwrap(),
        StackOutputs::new(&[Felt::from_u32(10)]).unwrap(),
    );
    let inputs = PublicInputs::from_claim(&claim, word(11));
    let (groups, auxiliary) = inputs.to_air_inputs();
    assert_eq!(
        groups.iter().map(alloc::vec::Vec::len).collect::<alloc::vec::Vec<_>>(),
        [36, 4, 0, 0]
    );
    assert_eq!(auxiliary.len(), 4);
    Statement::new(MidenMultiAir::new(), groups.into_iter().enumerate().collect(), auxiliary)
        .expect("canonical VM statement")
}

pub mod config {
    use miden_core::program::domain::STARK_TRANSCRIPT;
    pub use miden_stark::{
        config::{EidosConfig, RelationDigest},
        pcs::PcsParams,
    };

    /// Creates the Eidos configuration bound to the VM transcript domain.
    pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
        miden_stark::config::eidos_config(params, relation_digest, STARK_TRANSCRIPT)
    }

    #[cfg(test)]
    mod tests {
        use miden_air::vm::config;
        use miden_core::{Felt, field::QuadFelt};
        use miden_stark::{
            Preprocessed, StarkConfig,
            config::{blake3_256_config, keccak_config},
            lmcs::Lmcs,
        };

        use super::eidos_config;
        const UPDATE_HINT: &str =
            "an intentional relation change must update the production pins and verifier root";
        /// The And8 setup commitment the given configuration builds from the canonical VM setup.
        fn canonical_setup_commitment<SC: StarkConfig<Felt, QuadFelt>>(
            config: &SC,
        ) -> <SC::Lmcs as Lmcs>::Commitment {
            let statement = super::super::canonical_setup_statement();
            Preprocessed::build(&statement, config).expect("fixed And8 setup").commitment()
        }

        /// Each pinned And8 setup commitment must be the one its configuration builds from the
        /// canonical VM setup.
        macro_rules! setup_commitment_matches_canonical_setup {
            ($test:ident, $config:ident, $pinned:ident, $repr:ty) => {
                #[test]
                fn $test() {
                    let config = $config(config::pcs_params(), config::RELATION_DIGEST);
                    assert_eq!(
                        <$repr>::from(canonical_setup_commitment(&config)),
                        config::$pinned,
                        "{} is stale; {UPDATE_HINT}",
                        stringify!($pinned)
                    );
                }
            };
        }

        setup_commitment_matches_canonical_setup!(
            blake3_setup_commitment_is_current,
            blake3_256_config,
            BLAKE3_PREPROCESSED_COMMITMENT,
            [u8; 32]
        );
        setup_commitment_matches_canonical_setup!(
            eidos_setup_commitment_is_current,
            eidos_config,
            EIDOS_PREPROCESSED_COMMITMENT,
            [u64; 4]
        );
        setup_commitment_matches_canonical_setup!(
            keccak_setup_commitment_is_current,
            keccak_config,
            KECCAK_PREPROCESSED_COMMITMENT,
            [u64; 4]
        );
    }
}
