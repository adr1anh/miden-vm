// Shared by the public integration tests and the private replay-mutation tests. Each enclosing
// module aliases its processor crate as `processor` so this fixture uses the same public APIs.
extern crate alloc;

use miden_core::{
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::{CanonicalLabel, EnvNode, ExecutionDescriptor, ImplementationRoot, Namespace},
};

use self::alloc::{sync::Arc, vec, vec::Vec};
use super::processor::{
    DefaultHost, EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionEnvironment, ExecutionOptions, ExecutionWitness,
    FastProcessor, Felt, LedgerLimits, OpeningLimits, OpeningStep, Program, ReplayReadLimits,
    ResolutionWitness, SessionLimits, StackInputs,
};

pub struct WitnessFixture {
    pub witness: ExecutionWitness,
    pub environment: ExecutionEnvironment,
}

pub struct ExecutionFixture {
    pub program: Program,
    pub environment: ExecutionEnvironment,
    pub host: DefaultHost,
}

struct EntrySource {
    environment: ExecutionEnvironment,
    node: EnvNode,
}

impl EnvironmentWitnessSource for EntrySource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        let descriptor = self.environment.descriptor();
        if request.root != descriptor.environment_root() || request.key != descriptor.entry_key() {
            return Ok(None);
        }
        Ok(Some(ResolutionWitness {
            path: vec![OpeningStep {
                node: self.node.clone(),
                selected_child: None,
            }],
        }))
    }
}

pub fn execution_fixture(operations: Vec<Operation>) -> ExecutionFixture {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();
    forest.make_root(root);
    let program = Program::new(Arc::new(forest), root);

    execution_fixture_for_program(program)
}

/// Authenticates the entry binding for a program without retained runtime invocations.
pub fn execution_fixture_for_program(program: Program) -> ExecutionFixture {
    let label = CanonicalLabel::text("entry").unwrap().commitment();
    let entry = Namespace::initial().procedure_key(label);
    let node = EnvNode::Mast {
        label,
        implementation: ImplementationRoot::new(program.hash()),
    };
    let environment = ExecutionEnvironment::new(
        ExecutionDescriptor::new(entry, node.commitment().unwrap()),
        OpeningLimits {
            max_nodes: 1,
            max_depth: 0,
            max_list_children: 0,
            max_total_list_children: 0,
            max_encoded_bytes: 1024,
            max_storage_bytes: 4096,
        },
        LedgerLimits {
            max_occurrences: 1,
            max_total_list_children: 0,
            max_encoded_bytes: 1024,
            max_library_rows: 64,
            max_compression_requests: 64,
            max_retained_bytes: 16_384,
            max_peak_bytes: 32_768,
        },
        SessionLimits {
            max_cached_keys: 1,
            max_requests: 1,
            max_retained_bytes: 65_536,
            max_prepare_peak_bytes: 131_072,
        },
    );
    let host =
        DefaultHost::default().with_environment_source(Arc::new(EntrySource { environment, node }));
    ExecutionFixture { program, environment, host }
}

pub fn execution_witness(operations: Vec<Operation>, stack: StackInputs) -> WitnessFixture {
    let ExecutionFixture { program, environment, mut host } = execution_fixture(operations);
    let witness = FastProcessor::new(stack)
        .with_options(ExecutionOptions::default().with_environment_trace_limits(trace_limits()))
        .unwrap()
        .execute_for_proving_sync(&program, environment, &mut host)
        .expect("authenticated single-block execution should produce a witness");
    WitnessFixture { witness, environment }
}

pub fn deferred_witness() -> WitnessFixture {
    execution_witness(vec![Operation::LogDeferred], StackInputs::default())
}

pub fn aead_stream_witness() -> WitnessFixture {
    let stack = [
        1, 2, 3, 4, // K_CTR
        0, // counter
        0, // src_ptr
        8, // dst_ptr
        1, // remaining
        0, 0, 0, 0, 0, 0, 0, 0, // tail
    ]
    .map(Felt::new_unchecked);
    execution_witness(vec![Operation::CryptoStream], StackInputs::new(&stack).unwrap())
}

pub fn trace_limits() -> EnvironmentTraceLimits {
    EnvironmentTraceLimits {
        max_events: 8,
        max_retained_bytes: 65_536,
        max_prepare_peak_bytes: 131_072,
        max_validation_work: 65_536,
    }
}

pub fn read_limits() -> ReplayReadLimits {
    ReplayReadLimits {
        max_wire_bytes: 1_048_576,
        max_validation_peak_bytes: 262_144,
    }
}
