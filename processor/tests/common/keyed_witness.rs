// Shared by the public integration tests and the private replay-mutation tests. Each enclosing
// module aliases its processor crate as `processor` so this fixture uses the same public APIs.
extern crate alloc;

use miden_core::{
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::{CanonicalLabel, EnvNode, ExecutionTarget, ImplementationRoot, Namespace},
};
use miden_mast_package::{
    CallableProcedurePath, CodePackage, NamespacePath, Package, PackageCallables, PackageId,
    PackageProcedureOccurrence, PackageSymbols, ProcedureName, TargetType, Version,
};

use self::alloc::{sync::Arc, vec, vec::Vec};
use super::processor::{
    DefaultHost, EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionOptions, ExecutionWitness, FastProcessor, Felt,
    LedgerLimits, OpeningLimits, OpeningStep, ReplayReadLimits, ResolutionLimits,
    ResolutionWitness, SessionLimits, StackInputs,
};

pub struct WitnessFixture {
    pub witness: ExecutionWitness,
    pub target: ExecutionTarget,
    pub resolution_limits: ResolutionLimits,
}

pub struct ExecutionFixture {
    // The integration reader inspects code; unit replay consumers use the host-owned clone.
    #[allow(dead_code)]
    pub code: CodePackage,
    pub target: ExecutionTarget,
    pub resolution_limits: ResolutionLimits,
    pub host: DefaultHost,
}

struct EntrySource {
    target: ExecutionTarget,
    node: EnvNode,
}

impl EnvironmentWitnessSource for EntrySource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        let descriptor = self.target;
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
    let label = CanonicalLabel::text("entry").unwrap().commitment();
    let entry = Namespace::initial().procedure_key(label);
    let implementation = ImplementationRoot::new(forest[root].digest());
    let node = EnvNode::Mast { label, implementation };
    let target = ExecutionTarget::new(entry, node.commitment().unwrap());
    let home = NamespacePath::new(vec![]);
    let name = ProcedureName::new(
        home.clone(),
        CallableProcedurePath::from_semantic_components(vec!["entry".into()]).unwrap(),
    )
    .unwrap();
    assert_eq!(name.key(), entry);
    let symbols = Arc::new(
        PackageSymbols::new(
            home,
            PackageCallables::new([name], [], [(entry, implementation)]).unwrap(),
            Some(entry),
        )
        .unwrap(),
    );
    let package = Package::create(
        PackageId::from("keyed-witness-fixture"),
        Version::new(1, 0, 0),
        TargetType::Executable,
        Arc::new(forest),
        [],
        [],
        &symbols,
    )
    .unwrap()
    .with_procedure_occurrences([PackageProcedureOccurrence::new(entry, root, None)], &symbols)
    .unwrap();
    let code = CodePackage::new(Arc::new(package), symbols).unwrap();
    let resolution_limits = ResolutionLimits::new(
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
    let mut host =
        DefaultHost::default().with_environment_source(Arc::new(EntrySource { target, node }));
    host.load_library(code.clone()).unwrap();
    ExecutionFixture { code, target, resolution_limits, host }
}

pub fn execution_witness(operations: Vec<Operation>, stack: StackInputs) -> WitnessFixture {
    let ExecutionFixture {
        code: _,
        target,
        resolution_limits,
        mut host,
    } = execution_fixture(operations);
    let witness = FastProcessor::new(stack)
        .with_options(
            ExecutionOptions::default()
                .with_resolution_limits(resolution_limits)
                .with_environment_trace_limits(trace_limits()),
        )
        .unwrap()
        .execute_for_proving_sync(target, &mut host)
        .expect("authenticated single-block execution should produce a witness");
    WitnessFixture { witness, target, resolution_limits }
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
