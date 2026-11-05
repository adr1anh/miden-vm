mod claim;
pub use claim::{CLAIM_DOMAIN_TAG, ExecutionClaim, NUM_CLAIM_ELEMENTS, claim_commitment};

pub mod domain;

#[cfg(test)]
pub(crate) mod test_vectors;

mod environment;
pub use environment::{
    CanonicalLabel, EnvNode, EnvNodeError, EnvironmentBinding, EnvironmentBuildError,
    EnvironmentBuildLimits, EnvironmentBuildResource, EnvironmentBuilder, EnvironmentRoot,
    ExecutionTarget, ImplementationRoot, LabelCommitment, LabelError, Namespace, ProcedureKey,
    ValidatedEnvironment,
};

mod request;
pub use request::{PROOF_REQUEST_DOMAIN_TAG, proof_request_key};

mod verifier;
pub use verifier::{
    VerifierConfiguration, VerifierConfigurationCommitment, VerifierConfigurationError,
    VerifierIdentity, VerifierMount,
};

mod stack;
pub use stack::{InputError, MIN_STACK_DEPTH, OutputError, StackInputs, StackOutputs};
