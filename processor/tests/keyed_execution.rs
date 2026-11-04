//! Native keyed execution regressions through the public processor/host APIs.
//!
//! The labels, environment topology and finite budgets below are test fixtures, not a Protocol
//! profile or deployment policy. Successful execution/replay is not proof acceptance.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    future::{Future, pending},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use miden_core::{
    FMP_ADDR, FMP_INIT_VALUE,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExecNodeBuilder, JoinNodeBuilder,
        MastForest, MastNodeExt, MastNodeId, SplitNodeBuilder,
    },
    operations::Operation,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ExecutionTarget, ImplementationRoot, Namespace,
        ProcedureKey,
    },
};
use miden_debug_types::{
    ByteIndex, ColumnNumber, LineNumber, Location, SourceFile, SourceSpan, Uri,
};
use miden_mast_package::debug_info::{
    DebugFunctionInfo, DebugSourceAsmOp, DebugSourceInlineCall, DebugSourceNode, DebugSourceNodeId,
    PackageDebugInfo, PackageDebugInfoBuilder,
};
use miden_processor::{
    BaseHost, ContextId, Continuation, DebugRuntimeFrame, DebugRuntimeFrameKind,
    EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    ExecutionEnvironment, ExecutionError, ExecutionOptions, ExecutionWitness, FastProcessor, Felt,
    FutureMaybeSend, Host, InvocationTag, KeyedMode, LedgerLimits, LoadedMastForest, OpeningError,
    OpeningLimits, OpeningResource, OpeningStep, ProcessorState, Program, ReplayReadLimits,
    ResolutionWitness, SessionError, SessionLimits, SessionPhase, SessionResource, StackInputs,
    SyncHost, Word,
    advice::AdviceMutation,
    event::{EventError, EventId},
    operation::OperationError,
};

const OBSERVE: u32 = 0x8bad_f00d;
const KEY_ADDR: u32 = 256;
const VALUE_ADDR: u32 = 100;

fn felt(value: u32) -> Felt {
    Felt::from_u32(value)
}

fn namespace(path: &[&str]) -> Namespace {
    path.iter().fold(Namespace::initial(), |parent, text| {
        parent.child(CanonicalLabel::text(text).unwrap().commitment())
    })
}

fn key(path: &[&str], export: &str) -> ProcedureKey {
    namespace(path).procedure_key(CanonicalLabel::text(export).unwrap().commitment())
}

fn block(forest: &mut MastForest, operations: Vec<Operation>) -> MastNodeId {
    BasicBlockNodeBuilder::new(operations).add_to_forest(forest).unwrap()
}

fn join(forest: &mut MastForest, first: MastNodeId, second: MastNodeId) -> MastNodeId {
    JoinNodeBuilder::new([first, second]).add_to_forest(forest).unwrap()
}

fn finish_program(mut forest: MastForest, root: MastNodeId) -> Program {
    forest.make_root(root);
    Program::new(Arc::new(forest), root)
}

fn body(operations: Vec<Operation>) -> Program {
    let mut forest = MastForest::new();
    let root = block(&mut forest, operations);
    finish_program(forest, root)
}

fn observe() -> Vec<Operation> {
    vec![
        Operation::Caller,
        Operation::Push(felt(OBSERVE)),
        Operation::Emit,
        Operation::Drop,
    ]
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Exec,
    Call,
    Syscall,
    Dyn,
    DynCall,
}

fn invocation(forest: &mut MastForest, mode: Mode, target: ProcedureKey) -> MastNodeId {
    match mode {
        Mode::Exec => ExecNodeBuilder::new(target).add_to_forest(forest),
        Mode::Call => CallNodeBuilder::new(target).add_to_forest(forest),
        Mode::Syscall => CallNodeBuilder::new_syscall(target).add_to_forest(forest),
        Mode::Dyn => DynNodeBuilder::new_dyn().add_to_forest(forest),
        Mode::DynCall => DynNodeBuilder::new_dyncall().add_to_forest(forest),
    }
    .unwrap()
}

fn invocation_program(mode: Mode, target: ProcedureKey) -> Program {
    let mut forest = MastForest::new();
    let root = invocation(&mut forest, mode, target);
    finish_program(forest, root)
}

// Each export has its own full root-to-leaf path under one real List commitment. Repeated
// namespace prefixes deliberately remain separate structural occurrences, with distinct keys.
#[derive(Clone)]
struct EnvironmentFixture {
    root: EnvironmentRoot,
    paths: BTreeMap<ProcedureKey, Vec<(EnvNode, Option<usize>)>>,
}

impl EnvironmentFixture {
    fn new(exports: &[(&[&str], &str, Word)]) -> Self {
        let mut branches = Vec::new();
        for &(path, export, implementation) in exports {
            let leaf = EnvNode::Mast {
                label: CanonicalLabel::text(export).unwrap().commitment(),
                implementation: ImplementationRoot::new(implementation),
            };
            let mut nodes = vec![(leaf, None)];
            for text in path.iter().rev() {
                let child = nodes[0].0.commitment().unwrap();
                nodes.insert(
                    0,
                    (
                        EnvNode::Env {
                            label: CanonicalLabel::text(text).unwrap().commitment(),
                            child,
                        },
                        Some(0),
                    ),
                );
            }
            branches.push((key(path, export), nodes));
        }
        let root_node = EnvNode::List(
            branches.iter().map(|(_, nodes)| nodes[0].0.commitment().unwrap()).collect(),
        );
        let root = root_node.commitment().unwrap();
        let mut paths = BTreeMap::new();
        for (slot, (key, mut nodes)) in branches.into_iter().enumerate() {
            nodes.insert(0, (root_node.clone(), Some(slot)));
            assert!(paths.insert(key, nodes).is_none(), "test fixture keys must be unique");
        }
        Self { root, paths }
    }

    fn witness(&self, key: ProcedureKey) -> Option<ResolutionWitness> {
        self.paths.get(&key).map(|nodes| ResolutionWitness {
            path: nodes
                .iter()
                .map(|(node, selected_child)| OpeningStep {
                    node: node.clone(),
                    selected_child: *selected_child,
                })
                .collect(),
        })
    }

    fn configuration(&self, entry: ProcedureKey) -> ExecutionEnvironment {
        ExecutionEnvironment::new(
            ExecutionTarget::new(entry, self.root),
            opening_limits(),
            ledger_limits(),
            session_limits(),
        )
    }
}

fn opening_limits() -> OpeningLimits {
    OpeningLimits {
        max_nodes: 16,
        max_depth: 15,
        max_list_children: 16,
        max_total_list_children: 64,
        max_encoded_bytes: 8192,
        max_storage_bytes: 32_768,
    }
}

fn ledger_limits() -> LedgerLimits {
    LedgerLimits {
        max_occurrences: 128,
        max_total_list_children: 256,
        max_encoded_bytes: 65_536,
        max_library_rows: 1024,
        max_compression_requests: 1024,
        max_retained_bytes: 262_144,
        max_peak_bytes: 524_288,
    }
}

fn session_limits() -> SessionLimits {
    SessionLimits {
        max_cached_keys: 16,
        max_requests: 64,
        max_retained_bytes: 524_288,
        max_prepare_peak_bytes: 1_048_576,
    }
}

fn trace_limits() -> EnvironmentTraceLimits {
    EnvironmentTraceLimits {
        max_events: 64,
        max_retained_bytes: 1_048_576,
        max_prepare_peak_bytes: 2_097_152,
        max_validation_work: 1_048_576,
    }
}

fn read_limits() -> ReplayReadLimits {
    ReplayReadLimits {
        max_wire_bytes: 16_777_216,
        max_validation_peak_bytes: 33_554_432,
    }
}

#[derive(Debug)]
struct Observation {
    principal: Word,
    context: ContextId,
    depth: u32,
    value: Option<Felt>,
    fmp: Option<Felt>,
    stack: Vec<Felt>,
}

struct CountingHost {
    environment: EnvironmentFixture,
    forests: BTreeMap<Word, LoadedMastForest>,
    witness_requests: Vec<EnvironmentWitnessRequest>,
    code_requests: RefCell<Vec<Word>>,
    unavailable_keys: BTreeSet<ProcedureKey>,
    unavailable_code: BTreeSet<Word>,
    substitute_witness: Option<ProcedureKey>,
    observations: Vec<Observation>,
    fail_event: bool,
}

impl CountingHost {
    fn new(environment: &EnvironmentFixture, programs: &[&Program]) -> Self {
        let mut forests = BTreeMap::new();
        for program in programs {
            let forest = LoadedMastForest::new(program.mast_forest().clone());
            for digest in program.mast_forest().local_procedure_digests() {
                forests.insert(digest, forest.clone());
            }
        }
        Self {
            environment: environment.clone(),
            forests,
            witness_requests: Vec::new(),
            code_requests: RefCell::new(Vec::new()),
            unavailable_keys: BTreeSet::new(),
            unavailable_code: BTreeSet::new(),
            substitute_witness: None,
            observations: Vec::new(),
            fail_event: false,
        }
    }

    fn requests_for(&self, key: ProcedureKey) -> usize {
        self.witness_requests.iter().filter(|request| request.key == key).count()
    }
}

impl BaseHost for CountingHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for CountingHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        self.witness_requests.push(request);
        if self.unavailable_keys.contains(&request.key) {
            return Ok(None);
        }
        Ok(self.environment.witness(self.substitute_witness.unwrap_or(request.key)))
    }

    fn get_mast_forest(&self, digest: &Word) -> Option<LoadedMastForest> {
        self.code_requests.borrow_mut().push(*digest);
        if self.unavailable_code.contains(digest) {
            None
        } else {
            self.forests.get(digest).cloned()
        }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        assert_eq!(process.get_stack_item(0), felt(OBSERVE));
        self.observations.push(Observation {
            principal: process.get_stack_word(1),
            context: process.ctx(),
            depth: process.stack_depth(),
            value: process.get_mem_value(process.ctx(), VALUE_ADDR),
            fmp: process.get_mem_value(process.ctx(), FMP_ADDR.as_canonical_u64() as u32),
            stack: process.get_stack_state(),
        });
        if self.fail_event {
            return Err(std::io::Error::other("fixture callback failure").into());
        }
        Ok(Vec::new())
    }
}

fn run_steps(
    processor: &mut FastProcessor,
    host: &mut CountingHost,
    resume: &mut miden_processor::ResumeContext,
) {
    for _ in 0..1024 {
        if processor.step_sync(host, resume).unwrap() {
            assert!(resume.is_complete());
            assert_eq!(resume.resolution_session().phase(), SessionPhase::Completed);
            return;
        }
    }
    panic!("bounded test program did not terminate");
}

#[test]
fn entry_authenticates_fixed_root_and_key_before_loading_authenticated_body() {
    let entry = key(&["app"], "entry");
    let other = key(&["app"], "other");
    let authenticated = body(vec![Operation::Push(felt(7)), Operation::Add]);
    let hint = body(vec![Operation::Push(felt(99)), Operation::Add]);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", authenticated.hash()),
        (&["app"], "other", hint.hash()),
    ]);
    let configuration = environment.configuration(entry);

    let mut wrong_key = CountingHost::new(&environment, &[&authenticated, &hint]);
    wrong_key.substitute_witness = Some(other);
    let error = FastProcessor::new(StackInputs::default())
        .execute_sync(&hint, configuration, &mut wrong_key)
        .unwrap_err();
    assert!(matches!(
        error,
        ExecutionError::InvalidEnvironmentOpening {
            error,
            ..
        } if matches!(error.as_ref(), OpeningError::KeyMismatch { .. })
    ));
    assert!(wrong_key.code_requests.borrow().is_empty());

    let wrong_root = ExecutionEnvironment::new(
        ExecutionTarget::new(entry, EnvironmentRoot::new(hint.hash())),
        opening_limits(),
        ledger_limits(),
        session_limits(),
    );
    let mut host = CountingHost::new(&environment, &[&authenticated, &hint]);
    let error = FastProcessor::new(StackInputs::default())
        .execute_sync(&hint, wrong_root, &mut host)
        .unwrap_err();
    assert!(matches!(
        error,
        ExecutionError::InvalidEnvironmentOpening {
            error,
            ..
        } if matches!(error.as_ref(), OpeningError::CommitmentMismatch { depth: 0, .. })
    ));
    assert!(host.code_requests.borrow().is_empty());

    let mut host = CountingHost::new(&environment, &[&authenticated]);
    let output = FastProcessor::new(StackInputs::default())
        .execute_sync(&hint, configuration, &mut host)
        .unwrap();
    assert_eq!(output.stack[0], felt(7), "Program is a supply hint, not entry authority");
    assert_eq!(*host.code_requests.borrow(), vec![authenticated.hash()]);
    assert_eq!(
        host.witness_requests,
        vec![EnvironmentWitnessRequest {
            root: environment.root,
            key: entry,
            limits: opening_limits(),
        }]
    );
}

#[test]
fn available_implementation_never_substitutes_for_missing_key_evidence() {
    let hint = body(vec![Operation::Swap, Operation::Swap]);
    let environment = EnvironmentFixture::new(&[(&[], "entry", hint.hash())]);
    // Even choosing the bytes of an available D as K cannot enable digest dispatch.
    let digest_shaped_key = ProcedureKey::new(hint.hash());
    let mut host = CountingHost::new(&environment, &[&hint]);
    let error = FastProcessor::new(StackInputs::default())
        .execute_sync(&hint, environment.configuration(digest_shaped_key), &mut host)
        .unwrap_err();
    assert!(matches!(error, ExecutionError::EnvironmentWitnessUnavailable { key, .. }
        if key == digest_shaped_key));
    assert!(host.code_requests.borrow().is_empty());
}

#[test]
fn same_body_aliases_preserve_exec_principal_and_establish_each_call_key() {
    let entry = key(&["app"], "entry");
    let aliases = [key(&["lib"], "a"), key(&["lib"], "b")];
    let callee = body(observe());
    for mode in [Mode::Exec, Mode::Call] {
        let mut forest = MastForest::new();
        let a = invocation(&mut forest, mode, aliases[0]);
        let b = invocation(&mut forest, mode, aliases[1]);
        let calls = join(&mut forest, a, b);
        let returned = block(&mut forest, observe());
        let root = join(&mut forest, calls, returned);
        let program = finish_program(forest, root);
        let environment = EnvironmentFixture::new(&[
            (&["app"], "entry", program.hash()),
            (&["lib"], "a", callee.hash()),
            (&["lib"], "b", callee.hash()),
        ]);
        let mut host = CountingHost::new(&environment, &[&callee]);
        let mut processor = FastProcessor::new(StackInputs::default());
        let mut resume = processor
            .get_initial_resume_context(&program, environment.configuration(entry))
            .unwrap();
        run_steps(&mut processor, &mut host, &mut resume);
        assert_eq!(host.observations.len(), 3);
        for (observation, alias) in host.observations[..2].iter().zip(aliases) {
            match mode {
                Mode::Exec => {
                    assert_eq!(observation.principal, entry.into_word());
                    assert!(observation.context.is_root());
                },
                Mode::Call => {
                    assert_eq!(observation.principal, alias.into_word());
                    assert!(!observation.context.is_root());
                },
                _ => unreachable!(),
            }
        }
        assert_eq!(host.observations[2].principal, entry.into_word());
        assert!(host.observations[2].context.is_root());
        if matches!(mode, Mode::Call) {
            assert_ne!(host.observations[0].context, host.observations[1].context);
        }
        assert_eq!(*host.code_requests.borrow(), vec![callee.hash()]);
        assert_eq!(host.requests_for(aliases[0]), 1);
        assert_eq!(host.requests_for(aliases[1]), 1);
        let bindings = resume.resolution_session().bindings();
        assert_eq!(bindings.len(), 3, "same D must not merge distinct authenticated keys");
        assert_eq!(resume.resolution_session().uses().count(), 3);
    }
}

#[test]
fn bounded_keyed_self_recursion_restores_frames_and_closes_entry_only_at_root_end() {
    // K is known before the body D exists. CALL refers to K rather than a structural child,
    // so this finite MAST can resolve back to itself without a structural cycle.
    let recursive = key(&["app"], "recursive");
    let mut forest = MastForest::new();
    let condition = block(&mut forest, vec![Operation::Dup0, Operation::Eqz, Operation::Not]);
    let decrement = block(&mut forest, vec![Operation::Push(-felt(1)), Operation::Add]);
    let call_self = invocation(&mut forest, Mode::Call, recursive);
    let on_nonzero = join(&mut forest, decrement, call_self);
    let on_zero = block(&mut forest, vec![Operation::Noop]);
    let branch = SplitNodeBuilder::new([on_nonzero, on_zero]).add_to_forest(&mut forest).unwrap();
    let recurse = join(&mut forest, condition, branch);
    // Preserve the terminating numeric counter while observing each frame during unwinding.
    let mut operations = vec![Operation::Dup0; 4];
    operations.extend(observe());
    operations.extend([Operation::Drop; 4]);
    let returned = block(&mut forest, operations);
    let root = join(&mut forest, recurse, returned);
    let program = finish_program(forest, root);
    program.mast_forest().validate().unwrap();
    let environment = EnvironmentFixture::new(&[(&["app"], "recursive", program.hash())]);
    let mut host = CountingHost::new(&environment, &[]);
    let mut processor = FastProcessor::new(StackInputs::new(&[felt(3)]).unwrap());
    let mut resume = processor
        .get_initial_resume_context(&program, environment.configuration(recursive))
        .unwrap();
    let mut restored_before_root_end = false;
    for _ in 0..512 {
        if processor.step_sync(&mut host, &mut resume).unwrap() {
            break;
        }
        let session = resume.resolution_session();
        let counters = session.counters();
        assert_eq!(session.phase(), SessionPhase::PendingEntry);
        assert_eq!(counters.reserved_requests, 1);
        assert!(counters.committed_requests <= 3);
        if counters.committed_requests == 3 && processor.state().ctx().is_root() {
            restored_before_root_end = true;
            assert_eq!(session.uses().count(), 3);
        }
    }
    assert!(resume.is_complete(), "bounded recursion must terminate");
    assert!(
        restored_before_root_end,
        "returning from recursion must retain entry's reservation"
    );
    assert!(processor.state().ctx().is_root());
    assert_eq!(processor.stack_depth(), 16);
    assert_eq!(processor.stack_get(0), felt(0));
    assert_eq!(host.observations.len(), 4);
    assert!(host.observations[..3].iter().all(|observation| !observation.context.is_root()));
    assert!(host.observations[3].context.is_root());
    assert_eq!(
        host.observations
            .iter()
            .map(|observation| observation.context)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert!(
        host.observations
            .iter()
            .all(|observation| observation.principal == recursive.into_word())
    );
    assert_eq!(host.requests_for(recursive), 1, "recursive invocations reuse authenticated K");
    assert!(
        host.code_requests.borrow().is_empty(),
        "all activations use the authenticated local D"
    );
    let session = resume.resolution_session();
    assert_eq!(session.phase(), SessionPhase::Completed);
    assert_eq!(session.bindings().len(), 1);
    assert_eq!(session.bindings()[0].counts().normal, 4);
    assert_eq!(session.bindings()[0].counts().syscall, 0);
    assert_eq!(
        session.uses().count(),
        4,
        "three recursive CALL uses plus actual entry root END"
    );
    assert!(session.uses().all(|use_record| use_record.tag() == InvocationTag::Normal));
    assert_eq!(session.counters().committed_requests, 4);
    assert_eq!(session.counters().reserved_requests, 0);
}

#[test]
fn syscall_requires_fixed_root_namespace_before_code_lookup() {
    let entry = key(&["app"], "entry");
    let callee = body(observe());
    for path in [
        &["kernel"][..],
        &["runtime", "kernel"][..],
        &["runtime", "kernel", "v2", "child"][..],
    ] {
        let target = key(path, "read_principal");
        let program = invocation_program(Mode::Syscall, target);
        let environment = EnvironmentFixture::new(&[
            (&["app"], "entry", program.hash()),
            (path, "read_principal", callee.hash()),
        ]);
        let mut host = CountingHost::new(&environment, &[&callee]);
        let error = FastProcessor::new(StackInputs::default())
            .execute_sync(&program, environment.configuration(entry), &mut host)
            .unwrap_err();
        assert!(matches!(error, ExecutionError::EnvironmentSession(
            SessionError::UnauthorizedSyscall { expected, actual })
            if expected == Namespace::initial() && actual == namespace(path)));
        assert!(host.code_requests.borrow().is_empty());
        assert!(host.observations.is_empty());
    }
    let kernel_path = [];
    let target = key(&kernel_path, "read_principal");
    // Start the successful syscall inside an ordinary user CALL: kernel entry must switch
    // back to root context, preserve the established user key, then restore the user frame.
    let user = key(&["app"], "user");
    let mut forest = MastForest::new();
    let syscall = invocation(&mut forest, Mode::Syscall, target);
    let returned = block(&mut forest, observe());
    let root = join(&mut forest, syscall, returned);
    let user_body = finish_program(forest, root);
    let program = invocation_program(Mode::Call, user);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&["app"], "user", user_body.hash()),
        (&kernel_path, "read_principal", callee.hash()),
    ]);
    let mut host = CountingHost::new(&environment, &[&user_body, &callee]);
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut resume = processor
        .get_initial_resume_context(&program, environment.configuration(entry))
        .unwrap();
    run_steps(&mut processor, &mut host, &mut resume);
    assert_eq!(host.observations.len(), 2);
    assert_eq!(host.observations[0].principal, user.into_word());
    assert!(host.observations[0].context.is_root());
    assert_eq!(host.observations[1].principal, user.into_word());
    assert!(!host.observations[1].context.is_root());
    assert!(processor.state().ctx().is_root());
    assert_eq!(*host.code_requests.borrow(), vec![user_body.hash(), callee.hash()]);
}

#[test]
fn entry_and_ordinary_call_may_use_root_exports() {
    let kernel_path = [];
    let target = key(&kernel_path, "ordinary");
    let callee = body(observe());
    let program = invocation_program(Mode::Call, target);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&kernel_path, "ordinary", callee.hash()),
    ]);
    for (entry, hint, expected_root) in
        [(target, &callee, true), (key(&["app"], "entry"), &program, false)]
    {
        let mut host = CountingHost::new(&environment, &[&callee]);
        let output = FastProcessor::new(StackInputs::default())
            .execute_sync(hint, environment.configuration(entry), &mut host)
            .unwrap();
        assert_eq!(output.stack.get_word(0), Some(target.into_word()));
        assert_eq!(host.observations[0].context.is_root(), expected_root);
    }
}

fn store_element(operations: &mut Vec<Operation>, address: Felt, value: Felt) {
    operations.extend([
        Operation::Push(value),
        Operation::Push(address),
        Operation::MStore,
        Operation::Drop,
    ]);
}

fn dynamic_prefix(target: ProcedureKey) -> Vec<Operation> {
    let mut operations = Vec::new();
    for element in target.as_word().as_slice().iter().rev() {
        operations.push(Operation::Push(*element));
    }
    operations.extend([
        Operation::Push(felt(KEY_ADDR)),
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ]);
    operations
}

fn assert_native_core_bindings(
    trace: &miden_processor::trace::VmTrace,
    entry: ProcedureKey,
    expected: &[(u8, ProcedureKey, Word)],
) {
    use miden_core::operations::opcodes;
    use miden_processor::{ONE, ZERO, trace::RowIndex};

    let main = trace.main_trace();
    assert_eq!(main.fn_hash(RowIndex::from(0)), entry.into_word().into_elements());
    let mut invocations = Vec::new();
    let mut root_ends = Vec::new();
    let mut halt_stack = None;
    for index in 0..main.core_height() {
        let row = RowIndex::from(index);
        let core = main.core_row(row);
        let opcode = main.get_op_code(row).as_canonical_u64() as u8;
        assert_eq!(core.system.clk, Felt::new_unchecked(index as u64));
        if matches!(
            opcode,
            opcodes::EXEC | opcodes::CALL | opcodes::SYSCALL | opcodes::DYN | opcodes::DYNCALL
        ) {
            let (expected_opcode, key, implementation) = expected[invocations.len()];
            assert_eq!(opcode, expected_opcode);
            assert_ne!(key.into_word(), implementation, "fixture must separate K from D");
            assert_eq!(main.decoder_hasher_state_first_half(row), key.into_word());
            assert_eq!(main.decoder_resolved_digest(row), implementation);
            let next = RowIndex::from(index + 1);
            let establishes_principal = matches!(opcode, opcodes::CALL | opcodes::DYNCALL);
            let principal = if establishes_principal { key } else { entry };
            assert_eq!(main.fn_hash(next), principal.into_word().into_elements());
            if establishes_principal {
                assert_ne!(main.ctx(next), main.ctx(row));
            } else {
                assert_eq!(main.ctx(next), main.ctx(row));
            }
            assert_eq!(main.is_left_shift(row), opcode == opcodes::DYN);
            assert!(!main.is_right_shift(row));
            if opcode == opcodes::DYNCALL {
                let state = main.decoder_hasher_state_second_half(row);
                assert_eq!(state[0], main.stack_depth(row) - ONE);
                if state[0].as_canonical_u64() > 16 {
                    assert_ne!(state[1], ZERO, "saved post-pop overflow pointer must survive");
                } else {
                    assert_eq!(state[1], ZERO);
                }
                assert_eq!(&state.as_slice()[2..], &[ZERO, ZERO]);
            } else {
                assert_eq!(main.decoder_hasher_state_second_half(row), Word::default());
            }
            invocations.push(row);
        } else {
            assert_eq!(main.decoder_resolved_digest(row), Word::default());
        }
        if opcode == opcodes::END {
            if main.is_root_end(row) == ONE {
                root_ends.push(row);
                assert_eq!(main.is_loop_body_flag(row), ZERO);
                assert_eq!(main.decoder_hasher_state_first_half(row), *trace.program_hash());
                let next = RowIndex::from(index + 1);
                assert_eq!(main.get_op_code(next), Felt::from_u8(opcodes::HALT));
                assert_eq!(main.fn_hash(next), entry.into_word().into_elements());
            } else {
                assert_eq!(main.is_root_end(row), ZERO);
            }
        }
        if opcode == opcodes::HALT {
            assert_eq!(main.fn_hash(row), entry.into_word().into_elements());
            assert_eq!(main.ctx(row), ZERO);
            assert_eq!(main.is_root_end(row), ZERO);
            let state = (core.stack.top, core.stack.b0, core.stack.b1, core.stack.h0);
            assert_eq!(*halt_stack.get_or_insert(state), state);
        }
    }
    assert_eq!(invocations.len(), expected.len());
    assert_eq!(root_ends.len(), 1);
    assert!(halt_stack.is_some());
}

#[test]
fn native_core_rows_bind_all_invocation_modes_aliases_and_cache_hit_demands() {
    use miden_air_definitions::vm::trace::chiplets::library::MAST;
    use miden_core::operations::opcodes;
    use miden_processor::{
        ZERO,
        trace::{RowIndex, build_trace},
    };

    let entry = key(&["app"], "entry");
    let aliases = [key(&[], "a"), key(&[], "b")];
    let callee = body(vec![Operation::Noop]);
    let mut callee_builder = PackageDebugInfoBuilder::default();
    let callee_source =
        source_node(&mut callee_builder, callee.entrypoint(), Vec::new(), 1, "callee::shared");
    callee_builder.add_root(callee_source);
    let callee_debug = *callee_builder.build();
    let budget = miden_vm_stark::memory::default_budget();
    for mode in [Mode::Exec, Mode::Call, Mode::Syscall, Mode::Dyn, Mode::DynCall] {
        let opcode = match mode {
            Mode::Exec => opcodes::EXEC,
            Mode::Call => opcodes::CALL,
            Mode::Syscall => opcodes::SYSCALL,
            Mode::Dyn => opcodes::DYN,
            Mode::DynCall => opcodes::DYNCALL,
        };
        let keys = [aliases[0], aliases[1], aliases[0]];
        let mut forest = MastForest::new();
        let mut source_builder = PackageDebugInfoBuilder::default();
        let mut root = None;
        for key in keys {
            let invoked = invocation(&mut forest, mode, key);
            let invoked_source =
                source_node(&mut source_builder, invoked, Vec::new(), 1, "caller::invoke");
            let (next, next_source) = if matches!(mode, Mode::Dyn | Mode::DynCall) {
                let mut operations = dynamic_prefix(key);
                operations.extend([Operation::Push(felt(7)); 4]);
                operations.push(Operation::Push(felt(KEY_ADDR)));
                let op_end = u32::try_from(operations.len()).unwrap();
                let setup = block(&mut forest, operations);
                let setup_source =
                    source_node(&mut source_builder, setup, Vec::new(), op_end, "caller::setup");
                let next = join(&mut forest, setup, invoked);
                let source = source_node(
                    &mut source_builder,
                    next,
                    vec![setup_source, invoked_source],
                    1,
                    "caller::dynamic",
                );
                (next, source)
            } else {
                (invoked, invoked_source)
            };
            root = Some(match root {
                Some((previous, previous_source)) => {
                    let next = join(&mut forest, previous, next);
                    let source = source_node(
                        &mut source_builder,
                        next,
                        vec![previous_source, next_source],
                        1,
                        "caller::entry",
                    );
                    (next, source)
                },
                None => (next, next_source),
            });
        }
        let (root, source_root) = root.unwrap();
        let (root, source_root) = if matches!(mode, Mode::Dyn | Mode::DynCall) {
            // Keep all three invocations' caller overflow live, then remove their four fillers
            // each.
            let cleanup = block(&mut forest, vec![Operation::Drop; 12]);
            let cleanup_source =
                source_node(&mut source_builder, cleanup, Vec::new(), 12, "caller::cleanup");
            let next = join(&mut forest, root, cleanup);
            let source = source_node(
                &mut source_builder,
                next,
                vec![source_root, cleanup_source],
                1,
                "caller::entry",
            );
            (next, source)
        } else {
            (root, source_root)
        };
        let program = finish_program(forest, root);
        source_builder.add_root(source_root);
        let source_debug = *source_builder.build();
        let environment = EnvironmentFixture::new(&[
            (&["app"], "entry", program.hash()),
            (&[], "a", callee.hash()),
            (&[], "b", callee.hash()),
        ]);
        let configuration = environment.configuration(entry);
        let expected: Vec<_> = keys.into_iter().map(|key| (opcode, key, callee.hash())).collect();
        let mut baseline = None;
        // A one-row fragment places a cut on both sides of every invocation and return.
        for fragment_size in [1, 3, 64] {
            let options = ExecutionOptions::default()
                .with_environment_trace_limits(trace_limits())
                .with_core_trace_fragment_size(fragment_size)
                .unwrap();
            let mut host = CountingHost::new(&environment, &[&callee]);
            let witness = FastProcessor::new(StackInputs::default())
                .with_options(options.clone())
                .unwrap()
                .execute_for_proving_sync(&program, configuration, &mut host)
                .unwrap();
            assert_eq!(host.requests_for(aliases[0]), 1);
            assert_eq!(host.requests_for(aliases[1]), 1);
            assert_eq!(*host.code_requests.borrow(), vec![callee.hash()]);
            let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
            let restored = ExecutionWitness::read_from_bytes_with_limits(
                &bytes,
                &configuration,
                trace_limits(),
                read_limits(),
            )
            .unwrap();
            for (imported, witness) in [(false, witness), (true, restored)] {
                let trace = build_trace(witness.into_parts().0, &budget).unwrap_or_else(|error| {
                    panic!("{mode:?}, fragment_size={fragment_size}, imported={imported}: {error}")
                });
                assert_native_core_bindings(&trace, entry, &expected);
                let main = trace.main_trace();
                for (key, count) in [(entry, 1), (aliases[0], 2), (aliases[1], 1)] {
                    let responses: Vec<_> = (0..main.chiplets_height())
                        .map(RowIndex::from)
                        .filter(|&row| main.is_library_row(row))
                        .map(|row| main.chiplet_cols(row).library())
                        .filter(|row| row.k == MAST && row.z == key.into_word().into_elements())
                        .collect();
                    assert_eq!(responses.len(), 1);
                    let count = Felt::from_u32(count);
                    let syscall = key != entry && matches!(mode, Mode::Syscall);
                    assert_eq!(
                        (responses[0].a, responses[0].b),
                        if syscall { (ZERO, count) } else { (count, ZERO) }
                    );
                }
                let matrices = main.clone_air_matrices();
                if let Some(expected) = &baseline {
                    assert_eq!(&matrices, expected);
                } else {
                    baseline = Some(matrices);
                }
            }
            if fragment_size <= 3 {
                for explicit_root in [false, true] {
                    let mut host = CountingHost::new(&environment, &[&callee]);
                    host.forests.insert(
                        callee.hash(),
                        LoadedMastForest::with_package_debug_info(
                            callee.mast_forest().clone(),
                            Ok(Some(callee_debug.clone())),
                        ),
                    );
                    let processor = FastProcessor::new(StackInputs::default())
                        .with_options(options.clone())
                        .unwrap();
                    let witness = if explicit_root {
                        processor.execute_for_proving_with_package_debug_info_at_source_node_sync(
                            &program,
                            configuration,
                            &source_debug,
                            source_root,
                            &mut host,
                        )
                    } else {
                        processor.execute_for_proving_with_package_debug_info_sync(
                            &program,
                            configuration,
                            &source_debug,
                            &mut host,
                        )
                    }
                    .unwrap();
                    let trace = build_trace(witness.into_parts().0, &budget).unwrap();
                    assert_native_core_bindings(&trace, entry, &expected);
                    assert_eq!(
                        &trace.main_trace().clone_air_matrices(),
                        baseline.as_ref().unwrap()
                    );
                }
            }
            #[cfg(feature = "std")]
            {
                let (trace, precompile) = FastProcessor::new(StackInputs::default())
                    .with_options(options.clone())
                    .unwrap()
                    .execute_and_build_trace_sync(
                        &program,
                        configuration,
                        &mut CountingHost::new(&environment, &[&callee]),
                        &budget,
                    )
                    .unwrap();
                assert!(precompile.is_none());
                assert_native_core_bindings(&trace, entry, &expected);
                assert_eq!(&trace.main_trace().clone_air_matrices(), baseline.as_ref().unwrap());
            }
        }
    }
}

#[test]
fn shared_opening_keeps_normal_and_syscall_counts_across_cached_fragment_replay() {
    use miden_air_definitions::vm::trace::chiplets::library::MAST;
    use miden_core::operations::opcodes;
    use miden_processor::trace::{RowIndex, build_trace};

    let entry = key(&["app"], "entry");
    let target = key(&[], "shared");
    let callee = body(vec![Operation::Noop]);
    let modes = [Mode::Exec, Mode::Syscall, Mode::Call, Mode::Syscall];
    let mut forest = MastForest::new();
    let mut root = invocation(&mut forest, modes[0], target);
    for mode in modes.into_iter().skip(1) {
        let next = invocation(&mut forest, mode, target);
        root = join(&mut forest, root, next);
    }
    let program = finish_program(forest, root);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&[], "shared", callee.hash()),
    ]);
    let configuration = environment.configuration(entry);
    let expected = [opcodes::EXEC, opcodes::SYSCALL, opcodes::CALL, opcodes::SYSCALL]
        .map(|opcode| (opcode, target, callee.hash()));
    let budget = miden_vm_stark::memory::default_budget();
    let mut baseline = None;
    // One-row fragments save a continuation at every invocation, callee entry and return row.
    for fragment_size in [1, 3, 64] {
        let options = ExecutionOptions::default()
            .with_environment_trace_limits(trace_limits())
            .with_core_trace_fragment_size(fragment_size)
            .unwrap();
        let mut host = CountingHost::new(&environment, &[&callee]);
        let witness = FastProcessor::new(StackInputs::default())
            .with_options(options.clone())
            .unwrap()
            .execute_for_proving_sync(&program, configuration, &mut host)
            .unwrap();
        assert_eq!(host.requests_for(entry), 1);
        assert_eq!(host.requests_for(target), 1, "both tags must reuse the same opening");
        assert_eq!(*host.code_requests.borrow(), vec![callee.hash()]);
        let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
        let restored = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &configuration,
            trace_limits(),
            read_limits(),
        )
        .unwrap();
        assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
        for witness in [witness, restored] {
            let trace = build_trace(witness.into_parts().0, &budget).unwrap();
            assert_native_core_bindings(&trace, entry, &expected);
            let main = trace.main_trace();
            for (key, normal, syscall) in [(entry, 1, 0), (target, 2, 2)] {
                let responses: Vec<_> = (0..main.chiplets_height())
                    .map(RowIndex::from)
                    .filter(|&row| main.is_library_row(row))
                    .map(|row| main.chiplet_cols(row).library())
                    .filter(|row| row.k == MAST && row.z == key.into_word().into_elements())
                    .collect();
                assert_eq!(responses.len(), 1, "one occurrence must serve both invocation tags");
                assert_eq!((responses[0].a, responses[0].b), (felt(normal), felt(syscall)));
            }
            let matrices = main.clone_air_matrices();
            if let Some(expected) = &baseline {
                assert_eq!(&matrices, expected);
            } else {
                baseline = Some(matrices);
            }
        }
        #[cfg(feature = "std")]
        if fragment_size == 1 {
            let (trace, precompile) = FastProcessor::new(StackInputs::default())
                .with_options(options)
                .unwrap()
                .execute_and_build_trace_sync(
                    &program,
                    configuration,
                    &mut CountingHost::new(&environment, &[&callee]),
                    &budget,
                )
                .unwrap();
            assert!(precompile.is_none());
            assert_native_core_bindings(&trace, entry, &expected);
            assert_eq!(&trace.main_trace().clone_air_matrices(), baseline.as_ref().unwrap());
        }
    }
}

#[test]
fn bounded_public_replay_rejects_mutated_or_missing_core_invocation_evidence() {
    use miden_core::serde::{DeserializationError, Serializable};

    let entry = key(&["app"], "entry");
    let target = key(&["lib"], "child");
    // Both forests contain distinct nodes at IDs zero and two. A wrong existing ID must reach
    // the actual body/digest check rather than being rejected only because a node is absent.
    let mut callee_forest = MastForest::new();
    let alternate_root = block(&mut callee_forest, vec![Operation::Noop]);
    let callee_tail = block(&mut callee_forest, vec![Operation::Push(felt(7)), Operation::Drop]);
    let callee_root = join(&mut callee_forest, alternate_root, callee_tail);
    let callee = finish_program(callee_forest, callee_root);
    let mut caller_forest = MastForest::new();
    let caller_head = block(&mut caller_forest, vec![Operation::Noop]);
    let called = invocation(&mut caller_forest, Mode::Call, target);
    let caller_root = join(&mut caller_forest, caller_head, called);
    let program = finish_program(caller_forest, caller_root);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&["lib"], "child", callee.hash()),
    ]);
    let configuration = environment.configuration(entry);
    let witness = FastProcessor::new(StackInputs::default())
        .with_options(ExecutionOptions::default().with_environment_trace_limits(trace_limits()))
        .unwrap()
        .execute_for_proving_sync(
            &program,
            configuration,
            &mut CountingHost::new(&environment, &[&callee]),
        )
        .unwrap();
    let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &configuration,
        trace_limits(),
        read_limits(),
    )
    .expect("unmodified CALL evidence must pass bounded native revalidation");
    assert_eq!(restored.claim(), witness.claim());
    assert_eq!(restored.execution_descriptor(), configuration.descriptor());
    let budget = miden_vm_stark::memory::default_budget();
    let original_trace = miden_processor::trace::build_trace(witness.into_parts().0, &budget)
        .expect("unmodified captured CALL evidence must build a trace");
    let restored_trace = miden_processor::trace::build_trace(restored.into_parts().0, &budget)
        .expect("unmodified imported CALL evidence must build a trace");
    assert_native_core_bindings(
        &restored_trace,
        entry,
        &[(miden_core::operations::opcodes::CALL, target, callee.hash())],
    );
    assert_eq!(
        restored_trace.main_trace().clone_air_matrices(),
        original_trace.main_trace().clone_air_matrices(),
    );

    // Locate the public v4 observation by its mode/tag/K/D prefix, rather than depending on the
    // unrelated serialized stack, sparse MAST or Controller layouts. All reads use caller limits.
    let mut prefix = vec![1, 0]; // CALL, normal Resolve
    target.write_into(&mut prefix);
    ImplementationRoot::new(callee.hash()).write_into(&mut prefix);
    let offsets: Vec<_> = bytes
        .windows(prefix.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == prefix).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 1);
    let offset = offsets[0];
    const RECORD_BYTES: usize = 150;
    assert_eq!(&bytes[offset - 8..offset], &2u64.to_le_bytes());
    assert_eq!(bytes[offset + RECORD_BYTES], 5, "root END follows the CALL record");

    #[derive(Clone, Copy)]
    enum Rejection {
        NativeRecord(&'static str),
        NativeOpening(OpeningError),
        InvocationTransition,
        Replay(&'static str),
    }
    let rejects = |name: &str, bytes: &[u8], expected: Rejection| {
        let decoded = ExecutionWitness::read_from_bytes_with_limits(
            bytes,
            &configuration,
            trace_limits(),
            read_limits(),
        );
        match expected {
            Rejection::NativeRecord(reason) => match decoded {
                Err(DeserializationError::InvalidValue(actual)) => {
                    assert_eq!(actual, format!("invalid keyed replay: {reason}"), "{name}");
                },
                Err(error) => panic!("{name} failed outside native keyed validation: {error}"),
                Ok(_) => panic!("{name} unexpectedly passed native keyed validation"),
            },
            Rejection::NativeOpening(expected) => match decoded {
                Err(DeserializationError::InvalidValue(actual)) => {
                    assert_eq!(actual, expected.to_string(), "{name}");
                },
                Err(error) => panic!("{name} failed outside native opening validation: {error}"),
                Ok(_) => panic!("{name} unexpectedly passed native opening validation"),
            },
            Rejection::InvocationTransition | Rejection::Replay(_) => {
                let expected_reason = match expected {
                    Rejection::InvocationTransition => "invocation differs from keyed replay event",
                    Rejection::Replay(reason) => reason,
                    _ => unreachable!(),
                };
                let witness = decoded.unwrap_or_else(|error| {
                    panic!("{name} must reach actual Core replay, but import failed: {error}")
                });
                match miden_processor::trace::build_trace(witness.into_parts().0, &budget) {
                    Err(ExecutionError::Internal(reason)) => {
                        assert_eq!(reason, expected_reason, "{name}");
                    },
                    Err(error) => panic!("{name} failed outside actual invocation replay: {error}"),
                    Ok(_) => panic!("{name} unexpectedly built a Core trace"),
                }
            },
        }
    };
    for (name, field, expected) in [
        ("mode", 0, Rejection::NativeRecord("same-principal mode changes principal")),
        ("tag", 1, Rejection::NativeRecord("mode and native invocation tag differ")),
        (
            "key",
            2,
            Rejection::NativeRecord("call does not establish the requested principal"),
        ),
        (
            "implementation",
            34,
            Rejection::NativeRecord("record differs from natively reconstructed use"),
        ),
        ("row", 74, Rejection::InvocationTransition),
        ("principal before", 78, Rejection::InvocationTransition),
        (
            "principal after",
            110,
            Rejection::NativeRecord("call does not establish the requested principal"),
        ),
    ] {
        let mut forged = bytes.clone();
        forged[offset + field] ^= 1;
        assert_ne!(forged, bytes, "{name} mutation must change the observation");
        rejects(name, &forged, expected);
    }
    // V4 IDs are required scalar fields. "Missing" below selects the first ID without a
    // retained occurrence/forest/node; distant out-of-range and wrong existing IDs are separate.
    let root_end = offset + RECORD_BYTES;
    let opening = u64::from_le_bytes(bytes[offset + 66..offset + 74].try_into().unwrap());
    let entry_opening = u64::from_le_bytes(bytes[root_end + 66..root_end + 74].try_into().unwrap());
    let target_forest = u32::from_le_bytes(bytes[offset + 142..offset + 146].try_into().unwrap());
    let entry_forest =
        u32::from_le_bytes(bytes[root_end + 142..root_end + 146].try_into().unwrap());
    let target_root = u32::from_le_bytes(bytes[offset + 146..offset + 150].try_into().unwrap());
    let entry_root = u32::from_le_bytes(bytes[root_end + 146..root_end + 150].try_into().unwrap());
    assert!(entry_opening < opening, "target opening is the final selected occurrence");
    assert_eq!((entry_forest, target_forest), (0, 1));
    assert_eq!((entry_root, target_root), (2, 2));
    for (name, id, expected) in [
        (
            "missing opening ID",
            opening + 1,
            Rejection::NativeRecord("opening index is outside occurrence tree"),
        ),
        (
            "out-of-range opening ID",
            u64::from(u32::MAX),
            Rejection::NativeRecord("opening index is outside occurrence tree"),
        ),
        (
            "wrong existing opening ID",
            entry_opening,
            Rejection::NativeOpening(OpeningError::KeyMismatch { expected: target, actual: entry }),
        ),
    ] {
        let mut forged = bytes.clone();
        forged[offset + 66..offset + 74].copy_from_slice(&id.to_le_bytes());
        assert_ne!(forged, bytes, "{name} mutation must change the observation");
        rejects(name, &forged, expected);
    }
    for (name, field, id, reason) in [
        (
            "missing target forest ID",
            142,
            target_forest + 1,
            "MastForestId out of range of mast_forest_store",
        ),
        (
            "out-of-range target forest ID",
            142,
            u32::MAX,
            "MastForestId out of range of mast_forest_store",
        ),
        (
            "wrong existing target forest ID",
            142,
            entry_forest,
            "resolved invocation body does not match its implementation",
        ),
        (
            "missing target root ID",
            146,
            target_root + 1,
            "resolved invocation root is missing",
        ),
        (
            "out-of-range target root ID",
            146,
            u32::MAX,
            "resolved invocation root is missing",
        ),
        (
            "wrong existing target root ID",
            146,
            0,
            "resolved invocation body does not match its implementation",
        ),
    ] {
        let mut forged = bytes.clone();
        forged[offset + field..offset + field + 4].copy_from_slice(&id.to_le_bytes());
        assert_ne!(forged, bytes, "{name} mutation must change the observation");
        rejects(name, &forged, Rejection::Replay(reason));
    }
    let mut omitted = bytes.clone();
    omitted[offset - 8..offset].copy_from_slice(&1u64.to_le_bytes());
    omitted.drain(offset..offset + RECORD_BYTES);
    rejects(
        "omitted invocation",
        &omitted,
        Rejection::NativeRecord("unused or missing opening occurrences"),
    );

    let mut doubled = bytes.clone();
    doubled[offset - 8..offset].copy_from_slice(&3u64.to_le_bytes());
    doubled.splice(offset..offset, bytes[offset..offset + RECORD_BYTES].iter().copied());
    rejects(
        "doubled invocation",
        &doubled,
        Rejection::NativeRecord("keyed record lies outside its chronological fragment"),
    );

    let mut missing_completion = bytes.clone();
    missing_completion[offset - 8..offset].copy_from_slice(&1u64.to_le_bytes());
    missing_completion.drain(offset + RECORD_BYTES..offset + 2 * RECORD_BYTES);
    rejects(
        "missing root completion",
        &missing_completion,
        Rejection::NativeRecord("last keyed record is not root END"),
    );
}

#[test]
fn dyn_shares_ram_fmp_and_principal_while_dyncall_uses_call_conventions() {
    let entry = key(&["app"], "entry");
    let target = key(&["lib"], "dynamic");
    let mut operations = observe();
    store_element(&mut operations, felt(VALUE_ADDR), felt(111));
    store_element(&mut operations, FMP_ADDR, felt(222));
    let callee = body(operations);
    for mode in [Mode::Dyn, Mode::DynCall] {
        let mut operations = dynamic_prefix(target);
        store_element(&mut operations, felt(VALUE_ADDR), felt(77));
        store_element(&mut operations, FMP_ADDR, felt(88));
        operations.push(Operation::Push(felt(KEY_ADDR)));
        let mut forest = MastForest::new();
        let prepare = block(&mut forest, operations);
        let dynamic = invocation(&mut forest, mode, target);
        let call = join(&mut forest, prepare, dynamic);
        let returned = block(&mut forest, observe());
        let root = join(&mut forest, call, returned);
        let program = finish_program(forest, root);
        let environment = EnvironmentFixture::new(&[
            (&["app"], "entry", program.hash()),
            (&["lib"], "dynamic", callee.hash()),
        ]);
        let mut host = CountingHost::new(&environment, &[&callee]);
        let output = FastProcessor::new(StackInputs::default())
            .execute_sync(&program, environment.configuration(entry), &mut host)
            .unwrap();
        let before = &host.observations[0];
        let after = &host.observations[1];
        assert_eq!(before.depth, 17, "address is consumed before the 16-element body + event");
        assert_eq!(after.depth, 17);
        assert!(after.context.is_root());
        assert_eq!(after.principal, entry.into_word());
        assert_eq!(output.stack.get_word(0), Some(entry.into_word()));
        match mode {
            Mode::Dyn => {
                assert_eq!(before.principal, entry.into_word());
                assert!(before.context.is_root());
                assert_eq!(before.value, Some(felt(77)));
                assert_eq!(before.fmp, Some(felt(88)));
                assert_eq!(after.value, Some(felt(111)));
                assert_eq!(after.fmp, Some(felt(222)));
            },
            Mode::DynCall => {
                assert_eq!(before.principal, target.into_word());
                assert!(!before.context.is_root());
                assert_eq!(before.value, None);
                assert_eq!(before.fmp, Some(FMP_INIT_VALUE));
                assert_eq!(after.value, Some(felt(77)));
                assert_eq!(after.fmp, Some(felt(88)));
            },
            _ => unreachable!(),
        }
    }
}

#[test]
fn root_call_and_terminal_dyncall_restore_before_discharge_at_actual_entry_end() {
    let entry = key(&["app"], "entry");
    let target = key(&["lib"], "child");
    let callee = body(observe());
    for mode in [Mode::Call, Mode::DynCall] {
        let program = if matches!(mode, Mode::DynCall) {
            // Public processor initialization has no RAM input. Authenticate and execute the
            // ordinary memory-store setup before a terminal DYNCALL in a structural JOIN entry.
            let mut operations = dynamic_prefix(target);
            operations.push(Operation::Push(felt(KEY_ADDR)));
            let mut forest = MastForest::new();
            let setup = block(&mut forest, operations);
            let dynamic = invocation(&mut forest, mode, target);
            let root = join(&mut forest, setup, dynamic);
            finish_program(forest, root)
        } else {
            invocation_program(mode, target)
        };
        let environment = EnvironmentFixture::new(&[
            (&["app"], "entry", program.hash()),
            (&["lib"], "child", callee.hash()),
        ]);
        let mut host = CountingHost::new(&environment, &[&callee]);
        let mut processor = FastProcessor::new(StackInputs::default());
        let mut resume = processor
            .get_initial_resume_context(&program, environment.configuration(entry))
            .unwrap();
        for _ in 0..64 {
            assert!(!processor.step_sync(&mut host, &mut resume).unwrap());
            if resume.resolution_session().uses().count() == 1 {
                break;
            }
        }
        assert_eq!(resume.resolution_session().phase(), SessionPhase::PendingEntry);
        assert!(!resume.is_complete());
        assert_eq!(resume.resolution_session().uses().count(), 1);
        assert!(!processor.state().ctx().is_root());
        run_steps(&mut processor, &mut host, &mut resume);
        assert!(processor.state().ctx().is_root());
        assert_eq!(host.observations[0].principal, target.into_word());
        assert_eq!(resume.resolution_session().uses().count(), 2);
        assert_eq!(resume.resolution_session().uses().last().unwrap().procedure_key(), entry);

        let witness = FastProcessor::new(StackInputs::default())
            .with_options(ExecutionOptions::default().with_environment_trace_limits(trace_limits()))
            .unwrap()
            .execute_for_proving_sync(
                &program,
                environment.configuration(entry),
                &mut CountingHost::new(&environment, &[&callee]),
            )
            .unwrap();
        let trace = miden_processor::trace::build_trace(
            witness.into_parts().0,
            &miden_vm_stark::memory::default_budget(),
        )
        .unwrap();
        let opcode = if matches!(mode, Mode::Call) {
            miden_core::operations::opcodes::CALL
        } else {
            miden_core::operations::opcodes::DYNCALL
        };
        assert_native_core_bindings(&trace, entry, &[(opcode, target, callee.hash())]);
        let main = trace.main_trace();
        let root_end = (0..main.core_height())
            .map(miden_processor::trace::RowIndex::from)
            .find(|&row| main.is_root_end(row) == miden_processor::ONE)
            .unwrap();
        if matches!(mode, Mode::Call) {
            assert_eq!(main.fn_hash(root_end), target.into_word().into_elements());
            assert_eq!(main.restores_caller_frame_flag(root_end), miden_processor::ONE);
        } else {
            assert_eq!(main.fn_hash(root_end), entry.into_word().into_elements());
            assert_eq!(main.restores_caller_frame_flag(root_end), miden_processor::ZERO);
        }
    }
}

#[test]
fn unavailable_witness_and_code_retries_keep_invocation_and_charge_once() {
    let entry = key(&["app"], "entry");
    let target = key(&["lib"], "child");
    let callee = body(observe());
    let program = invocation_program(Mode::Call, target);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&["lib"], "child", callee.hash()),
    ]);
    let mut host = CountingHost::new(&environment, &[&callee]);
    host.unavailable_keys.insert(target);
    host.unavailable_code.insert(callee.hash());
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut resume = processor
        .get_initial_resume_context(&program, environment.configuration(entry))
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(processor.step_sync(&mut host, &mut resume),
            Err(ExecutionError::EnvironmentWitnessUnavailable { key, .. }) if key == target));
        assert_eq!(resume.resolution_session().uses().count(), 0);
        assert_eq!(resume.resolution_session().phase(), SessionPhase::PendingEntry);
        assert_eq!(processor.state().clock().as_u32(), 0);
        assert!(processor.state().ctx().is_root());
    }
    let retained = resume.continuation_stack().len();
    host.unavailable_keys.remove(&target);
    assert!(matches!(processor.step_sync(&mut host, &mut resume),
        Err(ExecutionError::ProcedureNotFound { root_digest, .. }) if root_digest == callee.hash()));
    assert_eq!(resume.continuation_stack().len(), retained);
    assert_eq!(resume.resolution_session().uses().count(), 0);
    assert_eq!(processor.state().clock().as_u32(), 0);
    assert_eq!(host.requests_for(target), 3);
    host.unavailable_code.clear();
    let unrelated = body(vec![Operation::Swap, Operation::Swap]);
    host.forests
        .insert(callee.hash(), LoadedMastForest::new(unrelated.mast_forest().clone()));
    assert!(matches!(processor.step_sync(&mut host, &mut resume),
        Err(ExecutionError::OperationError {
            err: OperationError::MalformedMastForestInHost { root_digest }, ..
        }) if root_digest == callee.hash()));
    assert_eq!(resume.continuation_stack().len(), retained);
    assert_eq!(resume.resolution_session().uses().count(), 0);
    assert_eq!(processor.state().clock().as_u32(), 0);
    host.forests
        .insert(callee.hash(), LoadedMastForest::new(callee.mast_forest().clone()));
    run_steps(&mut processor, &mut host, &mut resume);
    assert_eq!(host.requests_for(entry), 1);
    assert_eq!(
        host.requests_for(target),
        3,
        "verified pending binding survives D unavailability"
    );
    assert_eq!(*host.code_requests.borrow(), vec![callee.hash(), callee.hash(), callee.hash()]);
    assert_eq!(host.observations.len(), 1);
    assert_eq!(resume.resolution_session().uses().count(), 2);
    let counters = resume.resolution_session().counters();
    assert_eq!(counters.committed_requests, 2);
    assert_eq!(counters.reserved_requests, 0);
}

#[test]
fn explicit_native_budgets_and_missing_trace_policy_fail_closed() {
    let entry = key(&[], "entry");
    let program = body(observe());
    let environment = EnvironmentFixture::new(&[(&[], "entry", program.hash())]);
    for opening_budget in [true, false] {
        let opening = if opening_budget {
            OpeningLimits { max_nodes: 0, ..opening_limits() }
        } else {
            opening_limits()
        };
        let session = if opening_budget {
            session_limits()
        } else {
            SessionLimits { max_requests: 0, ..session_limits() }
        };
        let configuration = ExecutionEnvironment::new(
            ExecutionTarget::new(entry, environment.root),
            opening,
            ledger_limits(),
            session,
        );
        let mut host = CountingHost::new(&environment, &[&program]);
        let mut processor = FastProcessor::new(StackInputs::default());
        let mut resume = processor.get_initial_resume_context(&program, configuration).unwrap();
        let error = processor.step_sync(&mut host, &mut resume).unwrap_err();
        if opening_budget {
            assert!(matches!(
                error,
                ExecutionError::InvalidEnvironmentOpening {
                    error,
                    ..
                } if matches!(error.as_ref(), OpeningError::LimitExceeded { resource: OpeningResource::Nodes, .. })
            ));
        } else {
            assert!(matches!(
                error,
                ExecutionError::EnvironmentSession(SessionError::LimitExceeded {
                    resource: SessionResource::Requests,
                    ..
                })
            ));
        }
        assert!(host.code_requests.borrow().is_empty());
        assert!(host.observations.is_empty());
        assert_eq!(processor.state().clock().as_u32(), 0);
        assert!(processor.state().ctx().is_root());
        assert_eq!(resume.resolution_session().uses().count(), 0);
    }
    let mut host = CountingHost::new(&environment, &[&program]);
    assert!(matches!(
        FastProcessor::new(StackInputs::default()).execute_for_proving_sync(
            &program,
            environment.configuration(entry),
            &mut host,
        ),
        Err(ExecutionError::MissingEnvironmentTraceLimits)
    ));
    assert!(host.witness_requests.is_empty());
}

#[test]
fn replay_v5_roundtrip_uses_caller_authority_and_explicit_budgets() {
    let entry = key(&[], "entry");
    let target = key(&["lib"], "child");
    let callee = body(observe());
    let program = invocation_program(Mode::Call, target);
    let environment = EnvironmentFixture::new(&[
        (&[], "entry", program.hash()),
        (&["lib"], "child", callee.hash()),
    ]);
    let configuration = environment.configuration(entry);
    let mut host = CountingHost::new(&environment, &[&callee]);
    let witness = FastProcessor::new(StackInputs::default())
        .with_options(ExecutionOptions::default().with_environment_trace_limits(trace_limits()))
        .unwrap()
        .execute_for_proving_sync(&program, configuration, &mut host)
        .unwrap();
    let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 5);
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &configuration,
        trace_limits(),
        read_limits(),
    )
    .unwrap();
    assert_eq!(restored.execution_descriptor(), configuration.descriptor());
    assert_eq!(restored.claim(), witness.claim());
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    for version in [3, 4, 6] {
        assert!(
            ExecutionWitness::read_from_bytes_with_limits(
                &[version],
                &configuration,
                trace_limits(),
                read_limits(),
            )
            .unwrap_err()
            .to_string()
            .contains("version")
        );
    }
    let too_small = ReplayReadLimits {
        max_wire_bytes: bytes.len() - 1,
        ..read_limits()
    };
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &configuration,
            trace_limits(),
            too_small,
        )
        .is_err()
    );
    let wrong_authority = environment.configuration(target);
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &wrong_authority,
            trace_limits(),
            read_limits(),
        )
        .is_err()
    );
    let changed_callee = body(vec![Operation::Noop]);
    let changed_environment = EnvironmentFixture::new(&[
        (&[], "entry", program.hash()),
        (&["lib"], "child", changed_callee.hash()),
    ]);
    assert_ne!(changed_environment.root, environment.root);
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &changed_environment.configuration(entry),
            trace_limits(),
            read_limits(),
        )
        .is_err()
    );
}

struct AsyncCodeHost {
    inner: CountingHost,
    suspend_code: AtomicBool,
}

impl BaseHost for AsyncCodeHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }
}

impl Host for AsyncCodeHost {
    fn get_environment_witness(
        &mut self,
        request: EnvironmentWitnessRequest,
    ) -> impl FutureMaybeSend<Result<Option<ResolutionWitness>, EnvironmentSourceError>> {
        let candidate = SyncHost::get_environment_witness(&mut self.inner, request);
        async move { candidate }
    }

    fn get_mast_forest(&self, digest: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        let candidate = SyncHost::get_mast_forest(&self.inner, digest);
        let suspend = self.suspend_code.load(Ordering::Relaxed);
        async move {
            if suspend {
                pending::<()>().await;
            }
            candidate
        }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = SyncHost::on_event(&mut self.inner, process);
        async move { result }
    }
}

fn poll_ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("test host unexpectedly suspended"),
    }
}

#[test]
fn cancelling_async_code_await_retains_verified_binding_for_retry() {
    let entry = key(&[], "entry");
    let authenticated = body(observe());
    let hint = body(vec![Operation::Swap, Operation::Swap]);
    let environment = EnvironmentFixture::new(&[(&[], "entry", authenticated.hash())]);
    let mut host = AsyncCodeHost {
        inner: CountingHost::new(&environment, &[&authenticated]),
        suspend_code: AtomicBool::new(true),
    };
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut resume = processor
        .get_initial_resume_context(&hint, environment.configuration(entry))
        .unwrap();
    {
        let mut future = Box::pin(processor.step(&mut host, &mut resume));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        // Drop the in-flight driver while the D-indexed host lookup is suspended.
    }
    assert_eq!(host.inner.requests_for(entry), 1);
    assert_eq!(resume.resolution_session().phase(), SessionPhase::Unentered);
    assert_eq!(resume.resolution_session().uses().count(), 0);
    assert_eq!(processor.state().clock().as_u32(), 0);
    host.suspend_code.store(false, Ordering::Relaxed);
    for _ in 0..64 {
        if poll_ready(processor.step(&mut host, &mut resume)).unwrap() {
            break;
        }
    }
    assert!(resume.is_complete());
    assert_eq!(host.inner.requests_for(entry), 1);
    assert_eq!(
        *host.inner.code_requests.borrow(),
        vec![authenticated.hash(), authenticated.hash()]
    );
    assert_eq!(host.inner.observations.len(), 1);
    assert_eq!(host.inner.observations[0].principal, entry.into_word());
    assert_eq!(resume.resolution_session().uses().count(), 1);
}

struct SourceDynCallFixture {
    entry: ProcedureKey,
    target: ProcedureKey,
    program: Program,
    caller_debug: PackageDebugInfo,
    dynamic_source: DebugSourceNodeId,
    returned_source: DebugSourceNodeId,
    callee: Program,
    callee_debug: PackageDebugInfo,
    callee_source: DebugSourceNodeId,
    environment: EnvironmentFixture,
}

fn source_node(
    builder: &mut PackageDebugInfoBuilder,
    exec_node: MastNodeId,
    children: Vec<DebugSourceNodeId>,
    op_end: u32,
    context: &str,
) -> DebugSourceNodeId {
    let asm_op = DebugSourceAsmOp::new(
        0,
        None,
        builder.add_string(context),
        builder.add_string("fixture"),
        1,
    );
    builder
        .add_node(DebugSourceNode {
            exec_node,
            children,
            op_start: 0,
            op_end,
            asm_ops: vec![asm_op],
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        })
        .unwrap()
}

fn source_dyncall_fixture() -> SourceDynCallFixture {
    let entry = key(&["app"], "entry");
    let target = key(&["lib"], "dynamic");
    let mut operations = vec![Operation::Dup0; 4];
    operations.extend(observe());
    operations.extend([Operation::Drop; 4]);
    store_element(&mut operations, felt(VALUE_ADDR), felt(111));
    store_element(&mut operations, FMP_ADDR, felt(222));
    let callee_op_end = u32::try_from(operations.len()).unwrap();
    let callee = body(operations);
    let mut builder = PackageDebugInfoBuilder::default();
    let callee_source = source_node(
        &mut builder,
        callee.entrypoint(),
        Vec::new(),
        callee_op_end,
        "callee::dynamic",
    );
    builder.add_root(callee_source);
    let callee_debug = *builder.build();

    let mut operations = dynamic_prefix(target);
    store_element(&mut operations, felt(VALUE_ADDR), felt(77));
    store_element(&mut operations, FMP_ADDR, felt(88));
    operations.extend((40..44).map(|value| Operation::Push(felt(value))));
    operations.extend([Operation::Dup0; 4]);
    operations.extend(observe());
    operations.extend([Operation::Drop; 4]);
    operations.push(Operation::Push(felt(KEY_ADDR)));
    let setup_op_end = u32::try_from(operations.len()).unwrap();
    let mut forest = MastForest::new();
    let setup = block(&mut forest, operations);
    let dynamic = invocation(&mut forest, Mode::DynCall, target);
    let mut operations = vec![Operation::Dup0; 4];
    operations.extend(observe());
    operations.extend([Operation::Drop; 8]);
    let returned_op_end = u32::try_from(operations.len()).unwrap();
    let returned = block(&mut forest, operations);
    let tail = join(&mut forest, dynamic, returned);
    let root = join(&mut forest, setup, tail);
    let program = finish_program(forest, root);
    let mut builder = PackageDebugInfoBuilder::default();
    let setup_source = source_node(&mut builder, setup, Vec::new(), setup_op_end, "caller::setup");
    let dynamic_source = source_node(&mut builder, dynamic, Vec::new(), 1, "caller::dyncall");
    let returned_source =
        source_node(&mut builder, returned, Vec::new(), returned_op_end, "caller::returned");
    let tail_source =
        source_node(&mut builder, tail, vec![dynamic_source, returned_source], 1, "caller::tail");
    let root_source =
        source_node(&mut builder, root, vec![setup_source, tail_source], 1, "caller::entry");
    builder.add_root(root_source);
    let caller_debug = *builder.build();
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&["lib"], "dynamic", callee.hash()),
    ]);
    SourceDynCallFixture {
        entry,
        target,
        program,
        caller_debug,
        dynamic_source,
        returned_source,
        callee,
        callee_debug,
        callee_source,
        environment,
    }
}

fn source_dyncall_processor() -> FastProcessor {
    let inputs = (1..=16).map(felt).collect::<Vec<_>>();
    let options = ExecutionOptions::new(Some(1024), 64, 64)
        .unwrap()
        .with_max_num_continuations(16)
        .with_max_stack_depth(64)
        .unwrap()
        .with_max_memory_elements(64)
        // Covers the empty provider's retained allocation; supplied forests carry no advice.
        .with_max_advice_size_bytes(65_536)
        .with_max_hash_len_bytes(8192);
    FastProcessor::new(StackInputs::new(&inputs).unwrap())
        .with_options(options)
        .unwrap()
}

fn reach_source_dyncall(
    processor: &mut FastProcessor,
    host: &mut AsyncCodeHost,
    resume: &mut miden_processor::ResumeContext,
    fixture: &SourceDynCallFixture,
) {
    for _ in 0..256 {
        if resume.next_source_node_id() == Some(fixture.dynamic_source) {
            assert!(matches!(
                resume.continuation_stack().peek_continuation(),
                Some(Continuation::StartNode(_))
            ));
            assert_eq!(processor.stack_get(0), felt(KEY_ADDR));
            assert_eq!(processor.stack_depth(), 21);
            assert!(
                processor.state().get_stack_state()[17..].iter().all(|value| *value != felt(0))
            );
            assert_eq!(host.inner.observations.len(), 1);
            assert_eq!(host.inner.observations[0].principal, fixture.entry.into_word());
            assert!(host.inner.code_requests.borrow().is_empty());
            return;
        }
        assert!(
            !poll_ready(processor.step_with_package_debug_info(
                host,
                resume,
                &fixture.caller_debug,
            ))
            .unwrap()
        );
    }
    panic!("bounded source fixture did not reach its retained DYNCALL");
}

struct PendingSourceDynCall {
    stack: Vec<Felt>,
    memory: Vec<(miden_processor::MemoryAddress, Felt)>,
    clock: u32,
    continuations: Vec<Continuation<Arc<MastForest>>>,
    debug: Arc<PackageDebugInfo>,
    forest: Arc<MastForest>,
}

impl PendingSourceDynCall {
    fn capture(processor: &FastProcessor, resume: &miden_processor::ResumeContext) -> Self {
        Self {
            stack: processor.state().get_stack_state(),
            memory: processor.state().get_mem_state(ContextId::root()),
            clock: processor.state().clock().as_u32(),
            continuations: resume.continuation_stack().clone().into_inner(),
            debug: resume.debug_info().unwrap(),
            forest: resume.current_forest().clone(),
        }
    }

    fn assert_unchanged(
        &self,
        processor: &FastProcessor,
        resume: &miden_processor::ResumeContext,
        fixture: &SourceDynCallFixture,
    ) {
        let state = processor.state();
        assert_eq!(state.get_stack_state(), self.stack);
        assert_eq!(state.get_mem_state(ContextId::root()), self.memory);
        assert_eq!(state.stack_depth(), 21);
        assert_eq!(state.clock().as_u32(), self.clock);
        assert!(state.ctx().is_root());
        assert_eq!(
            state.get_mem_word(state.ctx(), KEY_ADDR).unwrap(),
            Some(fixture.target.into_word())
        );
        assert_eq!(state.get_mem_value(state.ctx(), VALUE_ADDR), Some(felt(77)));
        assert_eq!(
            state.get_mem_value(state.ctx(), FMP_ADDR.as_canonical_u64() as u32),
            Some(felt(88))
        );
        assert!(state.get_mem_state(ContextId::from(self.clock + 1)).is_empty());
        assert_eq!(resume.continuation_stack().clone().into_inner(), self.continuations);
        assert_eq!(resume.next_source_node_id(), Some(fixture.dynamic_source));
        assert!(Arc::ptr_eq(&resume.debug_info().unwrap(), &self.debug));
        assert!(Arc::ptr_eq(resume.current_forest(), &self.forest));
        assert_eq!(
            resume.environment().descriptor(),
            fixture.environment.configuration(fixture.entry).descriptor()
        );
        let session = resume.resolution_session();
        assert_eq!(session.phase(), SessionPhase::PendingEntry);
        // Private verified evidence and allocation capacity may survive preparation. Neither is
        // a published invocation or a charge against committed demand.
        assert_eq!(session.uses().count(), 0);
        assert_eq!(session.counters().committed_requests, 0);
        assert_eq!(session.counters().reserved_requests, 1);
        assert_eq!(session.bindings().len(), 1);
        assert_eq!(session.bindings()[0].procedure_key(), fixture.entry);
        assert_eq!(session.bindings()[0].counts().normal, 0);
        assert!(!resume.is_complete());
    }
}

#[test]
fn source_dyncall_cancellation_and_bad_code_retries_publish_one_context_and_use() {
    let fixture = source_dyncall_fixture();
    let mut inner = CountingHost::new(&fixture.environment, &[]);
    let supplied = LoadedMastForest::with_package_debug_info(
        fixture.callee.mast_forest().clone(),
        Ok(Some(fixture.callee_debug.clone())),
    );
    inner.forests.insert(fixture.callee.hash(), supplied.clone());
    let mut host = AsyncCodeHost {
        inner,
        suspend_code: AtomicBool::new(true),
    };
    let mut processor = source_dyncall_processor();
    let mut resume = processor
        .get_initial_resume_context(
            &fixture.program,
            fixture.environment.configuration(fixture.entry),
        )
        .unwrap();
    reach_source_dyncall(&mut processor, &mut host, &mut resume, &fixture);
    let before = PendingSourceDynCall::capture(&processor, &resume);
    {
        let mut future = Box::pin(processor.step_with_package_debug_info(
            &mut host,
            &mut resume,
            &fixture.caller_debug,
        ));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    before.assert_unchanged(&processor, &resume, &fixture);
    assert_eq!(host.inner.requests_for(fixture.target), 1);
    assert_eq!(*host.inner.code_requests.borrow(), vec![fixture.callee.hash()]);
    host.suspend_code.store(false, Ordering::Relaxed);
    host.inner.unavailable_code.insert(fixture.callee.hash());
    assert!(matches!(poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::ProcedureNotFound { root_digest, .. }) if root_digest == fixture.callee.hash()));
    before.assert_unchanged(&processor, &resume, &fixture);
    host.inner.unavailable_code.clear();
    let unrelated = body(vec![Operation::Swap, Operation::Swap]);
    host.inner
        .forests
        .insert(fixture.callee.hash(), LoadedMastForest::new(unrelated.mast_forest().clone()));
    assert!(matches!(poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::OperationError {
            err: OperationError::MalformedMastForestInHost { root_digest }, ..
        }) if root_digest == fixture.callee.hash()));
    before.assert_unchanged(&processor, &resume, &fixture);
    assert_eq!(host.inner.observations.len(), 1);
    host.inner.forests.insert(fixture.callee.hash(), supplied);
    assert!(!poll_ready(processor.step(&mut host, &mut resume)).unwrap());
    let callee_context = processor.state().ctx();
    assert_eq!(callee_context, ContextId::from(before.clock + 1));
    assert_eq!(processor.state().get_stack_state(), before.stack[1..17]);
    assert_eq!(
        processor.stack_depth(),
        16,
        "one address pop precedes hiding four overflow rows"
    );
    assert_eq!(
        processor
            .state()
            .get_mem_value(callee_context, FMP_ADDR.as_canonical_u64() as u32),
        Some(FMP_INIT_VALUE)
    );
    assert_eq!(processor.state().get_mem_value(callee_context, VALUE_ADDR), None);
    assert!(Arc::ptr_eq(resume.current_forest(), fixture.callee.mast_forest()));
    assert_eq!(resume.next_source_node_id(), Some(fixture.callee_source));
    let debug = resume.debug_info().unwrap();
    assert!(!Arc::ptr_eq(&debug, &before.debug));
    assert_eq!(
        debug.source_node(fixture.callee_source).unwrap().exec_node,
        fixture.callee.entrypoint()
    );
    assert_eq!(
        debug[debug
            .first_asm_op_for_source_node(fixture.callee_source)
            .unwrap()
            .context_name_idx]
            .as_ref(),
        "callee::dynamic"
    );
    assert_eq!(resume.resolution_session().uses().count(), 1);
    assert_eq!(
        resume.resolution_session().uses().next().unwrap().procedure_key(),
        fixture.target
    );
    assert_eq!(resume.resolution_session().counters().committed_requests, 1);
    assert_eq!(resume.resolution_session().counters().reserved_requests, 1);

    let mut restored = false;
    for _ in 0..256 {
        if !restored
            && resume.next_source_node_id() == Some(fixture.returned_source)
            && Arc::ptr_eq(resume.current_forest(), &before.forest)
        {
            restored = true;
            assert!(processor.state().ctx().is_root());
            assert_eq!(processor.state().get_stack_state(), before.stack[1..]);
            assert!(Arc::ptr_eq(&resume.debug_info().unwrap(), &before.debug));
            assert_eq!(resume.resolution_session().uses().count(), 1);
        }
        if poll_ready(processor.step(&mut host, &mut resume)).unwrap() {
            break;
        }
    }
    assert!(restored);
    assert!(resume.is_complete());
    assert_eq!(processor.stack_depth(), 16);
    assert!(processor.state().ctx().is_root());
    assert_eq!(host.inner.observations.len(), 3);
    let callee = &host.inner.observations[1];
    assert_eq!(callee.principal, fixture.target.into_word());
    assert_eq!(callee.context, callee_context);
    assert_eq!(callee.depth, 21);
    assert_eq!(callee.value, None);
    assert_eq!(callee.fmp, Some(FMP_INIT_VALUE));
    let returned = &host.inner.observations[2];
    assert_eq!(returned.principal, fixture.entry.into_word());
    assert!(returned.context.is_root());
    assert_eq!(returned.depth, 25);
    assert_eq!(returned.value, Some(felt(77)));
    assert_eq!(returned.fmp, Some(felt(88)));
    assert_eq!(
        processor
            .state()
            .get_mem_value(callee_context, FMP_ADDR.as_canonical_u64() as u32),
        Some(felt(222))
    );
    assert_eq!(host.inner.requests_for(fixture.entry), 1);
    assert_eq!(host.inner.requests_for(fixture.target), 1, "verified K survives each D retry");
    assert_eq!(*host.inner.code_requests.borrow(), vec![fixture.callee.hash(); 4]);
    let session = resume.resolution_session();
    assert_eq!(session.uses().count(), 2);
    assert_eq!(session.counters().committed_requests, 2);
    assert_eq!(session.counters().reserved_requests, 0);
    assert_eq!(
        session
            .bindings()
            .iter()
            .find(|binding| binding.procedure_key() == fixture.target)
            .unwrap()
            .counts()
            .normal,
        1
    );
}

#[test]
fn source_dyncall_request_limit_after_entry_is_atomic_and_terminal() {
    let fixture = source_dyncall_fixture();
    let mut inner = CountingHost::new(&fixture.environment, &[]);
    inner.forests.insert(
        fixture.callee.hash(),
        LoadedMastForest::with_package_debug_info(
            fixture.callee.mast_forest().clone(),
            Ok(Some(fixture.callee_debug.clone())),
        ),
    );
    let mut host = AsyncCodeHost {
        inner,
        suspend_code: AtomicBool::new(false),
    };
    let mut processor = source_dyncall_processor();
    let configuration = ExecutionEnvironment::new(
        ExecutionTarget::new(fixture.entry, fixture.environment.root),
        opening_limits(),
        ledger_limits(),
        SessionLimits { max_requests: 1, ..session_limits() },
    );
    let mut resume = processor.get_initial_resume_context(&fixture.program, configuration).unwrap();
    reach_source_dyncall(&mut processor, &mut host, &mut resume, &fixture);
    let before = PendingSourceDynCall::capture(&processor, &resume);
    assert!(matches!(
        poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::EnvironmentSession(SessionError::LimitExceeded {
            resource: SessionResource::Requests,
            limit: 1,
            requested: 2
        }))
    ));
    before.assert_unchanged(&processor, &resume, &fixture);
    assert_eq!(host.inner.requests_for(fixture.target), 1);
    assert_eq!(*host.inner.code_requests.borrow(), vec![fixture.callee.hash()]);
    // A failed native preparation consumes its witness and invalidates this execution. It does
    // not turn the rejected request into a retryable host/code-supply failure.
    assert!(matches!(
        poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::InvalidExecutionState)
    ));
    before.assert_unchanged(&processor, &resume, &fixture);
    assert_eq!(host.inner.requests_for(fixture.target), 1);
    assert_eq!(host.inner.code_requests.borrow().len(), 1);
    assert_eq!(host.inner.observations.len(), 1);
}

struct ModeMatrixFixture {
    entry: ProcedureKey,
    user: ProcedureKey,
    target: ProcedureKey,
    program: Program,
    debug: PackageDebugInfo,
    callee: Program,
    callee_debug: PackageDebugInfo,
    // Entry setup, local user entry, target entry, user return, ENTRY return.
    points: [(MastNodeId, DebugSourceNodeId, &'static str); 5],
    environment: EnvironmentFixture,
}

fn preserved_observation() -> Vec<Operation> {
    let mut operations = vec![Operation::Dup0; 4];
    operations.extend(observe());
    operations.extend([Operation::Drop; 4]);
    operations
}

fn mode_matrix_fixture(mode: Mode, local_target: bool) -> ModeMatrixFixture {
    // Synthetic names and explicit finite budgets exercise native execution only.
    let entry = key(&["native_fixture"], "entry");
    let user = key(&["native_fixture"], "user");
    let target = key(&[], "target");
    let mut target_ops = preserved_observation();
    store_element(&mut target_ops, felt(VALUE_ADDR), felt(111));
    store_element(&mut target_ops, FMP_ADDR, felt(222));
    let target_op_end = u32::try_from(target_ops.len()).unwrap();
    let remote_callee = body(target_ops.clone());
    let mut forest = MastForest::new();
    let target_root = if local_target {
        let root = block(&mut forest, target_ops);
        forest.make_root(root);
        root
    } else {
        remote_callee.entrypoint()
    };
    let mut user_ops = if matches!(mode, Mode::Dyn | Mode::DynCall) {
        dynamic_prefix(target)
    } else {
        Vec::new()
    };
    store_element(&mut user_ops, felt(VALUE_ADDR), felt(77));
    store_element(&mut user_ops, FMP_ADDR, felt(88));
    user_ops.extend((40..44).map(|value| Operation::Push(felt(value))));
    user_ops.extend(preserved_observation());
    if matches!(mode, Mode::Dyn | Mode::DynCall) {
        user_ops.push(Operation::Push(felt(KEY_ADDR)));
    }
    let user_op_end = u32::try_from(user_ops.len()).unwrap();
    let user_setup = block(&mut forest, user_ops);
    let tested = invocation(&mut forest, mode, target);
    let mut returned_ops = preserved_observation();
    returned_ops.extend([Operation::Drop; 4]);
    let returned_op_end = u32::try_from(returned_ops.len()).unwrap();
    let user_return = block(&mut forest, returned_ops);
    let user_tail = join(&mut forest, tested, user_return);
    let user_root = join(&mut forest, user_setup, user_tail);
    forest.make_root(user_root);
    let mut entry_ops = Vec::new();
    store_element(&mut entry_ops, felt(VALUE_ADDR), felt(17));
    store_element(&mut entry_ops, FMP_ADDR, felt(18));
    entry_ops.extend(preserved_observation());
    let entry_op_end = u32::try_from(entry_ops.len()).unwrap();
    let entry_setup = block(&mut forest, entry_ops);
    let outer_call = invocation(&mut forest, Mode::Call, user);
    let entry_return_ops = preserved_observation();
    let entry_return_op_end = u32::try_from(entry_return_ops.len()).unwrap();
    let entry_return = block(&mut forest, entry_return_ops);
    let entry_tail = join(&mut forest, outer_call, entry_return);
    let entry_root = join(&mut forest, entry_setup, entry_tail);
    let program = finish_program(forest, entry_root);
    let callee = if local_target {
        Program::new(program.mast_forest().clone(), target_root)
    } else {
        remote_callee
    };

    let mut builder = PackageDebugInfoBuilder::default();
    let remote_source =
        source_node(&mut builder, target_root, Vec::new(), target_op_end, "matrix::target");
    builder.add_root(remote_source);
    let remote_debug = *builder.build();
    let mut builder = PackageDebugInfoBuilder::default();
    let target_source = if local_target {
        let source =
            source_node(&mut builder, target_root, Vec::new(), target_op_end, "matrix::target");
        builder.add_root(source);
        source
    } else {
        remote_source
    };
    let user_setup_source =
        source_node(&mut builder, user_setup, Vec::new(), user_op_end, "matrix::user_setup");
    let tested_source = source_node(&mut builder, tested, Vec::new(), 1, "matrix::invoke");
    let user_return_source =
        source_node(&mut builder, user_return, Vec::new(), returned_op_end, "matrix::user_return");
    let user_tail_source = source_node(
        &mut builder,
        user_tail,
        vec![tested_source, user_return_source],
        1,
        "matrix::user_tail",
    );
    let user_source = source_node(
        &mut builder,
        user_root,
        vec![user_setup_source, user_tail_source],
        1,
        "matrix::user",
    );
    builder.add_root(user_source);
    let entry_setup_source =
        source_node(&mut builder, entry_setup, Vec::new(), entry_op_end, "matrix::entry_setup");
    let outer_source = source_node(&mut builder, outer_call, Vec::new(), 1, "matrix::outer_call");
    let entry_return_source = source_node(
        &mut builder,
        entry_return,
        Vec::new(),
        entry_return_op_end,
        "matrix::entry_return",
    );
    let entry_tail_source = source_node(
        &mut builder,
        entry_tail,
        vec![outer_source, entry_return_source],
        1,
        "matrix::entry_tail",
    );
    let entry_source = source_node(
        &mut builder,
        entry_root,
        vec![entry_setup_source, entry_tail_source],
        1,
        "matrix::entry",
    );
    builder.add_root(entry_source);
    let debug = *builder.build();
    let callee_debug = if local_target { debug.clone() } else { remote_debug };
    let environment = EnvironmentFixture::new(&[
        (&["native_fixture"], "entry", program.hash()),
        (&["native_fixture"], "user", program.mast_forest()[user_root].digest()),
        (&[], "target", callee.hash()),
    ]);
    ModeMatrixFixture {
        entry,
        user,
        target,
        program,
        debug,
        callee,
        callee_debug,
        points: [
            (entry_setup, entry_setup_source, "matrix::entry_setup"),
            (user_root, user_source, "matrix::user"),
            (target_root, target_source, "matrix::target"),
            (user_return, user_return_source, "matrix::user_return"),
            (entry_return, entry_return_source, "matrix::entry_return"),
        ],
        environment,
    }
}

fn mode_matrix_host(fixture: &ModeMatrixFixture, local_target: bool) -> AsyncCodeHost {
    let mut inner = CountingHost::new(&fixture.environment, &[]);
    if !local_target {
        inner.forests.insert(
            fixture.callee.hash(),
            LoadedMastForest::with_package_debug_info(
                fixture.callee.mast_forest().clone(),
                Ok(Some(fixture.callee_debug.clone())),
            ),
        );
    }
    AsyncCodeHost {
        inner,
        suspend_code: AtomicBool::new(false),
    }
}

fn runtime_debug_inline_info(
    info: PackageDebugInfo,
    source: DebugSourceNodeId,
    implementation: Word,
) -> PackageDebugInfo {
    let mut builder = PackageDebugInfoBuilder::from(Box::new(info));
    let uri = Uri::new("file:///native-fixture/inline.masm");
    let file = builder.add_file(uri.clone(), None);
    let location = builder.add_location(Location::new(uri, ByteIndex::new(0), ByteIndex::new(1)));
    let name = builder.add_string("source::inline_only");
    let function = builder.add_function(DebugFunctionInfo::new(
        None,
        name,
        file,
        LineNumber::new(1).unwrap(),
        ColumnNumber::new(1).unwrap(),
        implementation,
    ));
    let op_end = builder[source].op_end;
    builder[source].inline_calls.push(DebugSourceInlineCall {
        op_idx: 0,
        op_end,
        callee_idx: function,
        loc_idx: location,
    });
    *builder.build()
}

type RuntimeDebugObservation = (
    DebugRuntimeFrameKind,
    ProcedureKey,
    ImplementationRoot,
    Option<u32>,
    Option<usize>,
);

fn runtime_debug_observation(frames: &[DebugRuntimeFrame]) -> Vec<RuntimeDebugObservation> {
    frames
        .iter()
        .map(|frame| {
            (
                frame.kind(),
                frame.requested_key(),
                frame.resolved_implementation(),
                frame.invocation_row().map(|row| row.as_u32()),
                frame.native_use_index(),
            )
        })
        .collect()
}

fn assert_runtime_debug_native_uses(
    frames: &[DebugRuntimeFrame],
    resume: &miden_processor::ResumeContext,
) {
    for frame in frames {
        if let Some(index) = frame.native_use_index() {
            let invocation = resume.resolution_session().uses().nth(index).unwrap();
            assert_eq!(frame.requested_key(), invocation.procedure_key());
            assert_eq!(frame.resolved_implementation(), invocation.implementation_root());
            assert_eq!(frame.opening_id(), invocation.opening_id());
            assert_eq!(frame.invocation_row(), Some(invocation.row()));
        } else {
            assert_eq!(frame.kind(), DebugRuntimeFrameKind::Entry);
            assert_eq!(frame.invocation_row(), None);
            let entry = resume
                .resolution_session()
                .bindings()
                .iter()
                .find(|binding| binding.procedure_key() == frame.requested_key())
                .unwrap();
            assert_eq!(frame.resolved_implementation(), entry.implementation_root());
            assert_eq!(frame.opening_id(), entry.opening_id());
        }
    }
}

#[test]
fn runtime_debug_frames_separate_real_modes_and_inline_sources_at_every_return_cut() {
    for (mode, expected_mode) in [
        (Mode::Exec, KeyedMode::Exec),
        (Mode::Call, KeyedMode::Call),
        (Mode::Syscall, KeyedMode::Syscall),
        (Mode::Dyn, KeyedMode::Dyn),
        (Mode::DynCall, KeyedMode::DynCall),
    ] {
        let mut fixture = mode_matrix_fixture(mode, false);
        fixture.callee_debug = runtime_debug_inline_info(
            fixture.callee_debug,
            fixture.points[2].1,
            fixture.callee.hash(),
        );
        assert_ne!(fixture.target.into_word(), fixture.callee.hash());
        let mut baseline = None;
        let mut other_execution = None::<(DebugRuntimeFrame, DebugRuntimeFrame)>;
        for source_aware in [false, true] {
            for asynchronous in [false, true] {
                let mut host = mode_matrix_host(&fixture, false);
                let mut processor = source_dyncall_processor();
                let mut resume = processor
                    .get_initial_resume_context(
                        &fixture.program,
                        fixture.environment.configuration(fixture.entry),
                    )
                    .unwrap();
                assert!(resume.debug_runtime_frames().is_empty());
                let mut previous = Vec::<DebugRuntimeFrame>::new();
                let mut observations = Vec::new();
                let mut saw_target = 0;
                let mut saw_inline = false;
                let mut saw_return = false;
                let mut saw_root_end = false;
                let mut entry_activation = None;
                let mut target_activation = None;
                for _ in 0..1024 {
                    let frames = resume.debug_runtime_frames();
                    assert_runtime_debug_native_uses(&frames, &resume);
                    if let Some(entry) = frames.first() {
                        entry_activation.get_or_insert_with(|| entry.clone());
                    }
                    for (old, current) in previous.iter().zip(&frames) {
                        assert!(old.is_same_frame(current), "{mode:?}: caller identity changed");
                    }
                    observations.push(runtime_debug_observation(&frames));
                    let target =
                        frames.iter().find(|frame| frame.requested_key() == fixture.target);
                    if let Some(target) = target {
                        target_activation.get_or_insert_with(|| target.clone());
                        saw_target += 1;
                        assert_eq!(frames.len(), 3, "source inline rows are not runtime frames");
                        assert_eq!(target.kind(), DebugRuntimeFrameKind::Invoke(expected_mode));
                        assert_eq!(
                            target.resolved_implementation().into_word(),
                            fixture.callee.hash()
                        );
                        assert_eq!(target.native_use_index(), Some(1));
                        if source_aware
                            && Arc::ptr_eq(resume.current_forest(), fixture.callee.mast_forest())
                        {
                            let source = resume.next_source_node_id().unwrap();
                            assert_eq!(source, fixture.points[2].1);
                            assert_eq!(
                                resume
                                    .debug_info()
                                    .unwrap()
                                    .inline_calls_for_operation(source, 0)
                                    .count(),
                                1
                            );
                            saw_inline = true;
                        }
                    }
                    let root_end = matches!(
                        resume.continuation_stack().peek_continuation(),
                        Some(Continuation::FinishJoin(root)) if *root == fixture.program.entrypoint()
                    );
                    if root_end {
                        saw_root_end = true;
                        assert_eq!(frames.len(), 1, "entry survives until its actual root END");
                        assert_eq!(frames[0].kind(), DebugRuntimeFrameKind::Entry);
                        assert_eq!(frames[0].requested_key(), fixture.entry);
                        assert_eq!(
                            frames[0].resolved_implementation().into_word(),
                            fixture.program.hash()
                        );
                        assert_eq!(frames[0].native_use_index(), None);
                        let session = resume.resolution_session();
                        assert_eq!(session.phase(), SessionPhase::PendingEntry);
                        assert_eq!(session.counters().reserved_requests, 1);
                        assert!(
                            session.uses().all(|record| record.procedure_key() != fixture.entry)
                        );
                    }
                    let returning = target.is_some()
                        && matches!(
                            resume.continuation_stack().peek_continuation(),
                            Some(
                                Continuation::FinishExec(_)
                                    | Continuation::FinishCall(_)
                                    | Continuation::FinishDyn(_)
                            )
                        );
                    previous = frames;
                    let complete = match (source_aware, asynchronous) {
                        (false, false) => processor.step_sync(&mut host.inner, &mut resume),
                        (false, true) => poll_ready(processor.step(&mut host, &mut resume)),
                        (true, false) => processor.step_with_package_debug_info_sync(
                            &mut host.inner,
                            &mut resume,
                            &fixture.debug,
                        ),
                        (true, true) => poll_ready(processor.step_with_package_debug_info(
                            &mut host,
                            &mut resume,
                            &fixture.debug,
                        )),
                    }
                    .unwrap();
                    if root_end {
                        assert!(complete, "actual root END discharges the final entry frame");
                        let entry = *resume.resolution_session().uses().next_back().unwrap();
                        assert_eq!(entry.procedure_key(), fixture.entry);
                        assert_eq!(entry.implementation_root().into_word(), fixture.program.hash());
                    }
                    if returning {
                        saw_return = true;
                        assert!(
                            resume
                                .debug_runtime_frames()
                                .iter()
                                .all(|frame| { frame.requested_key() != fixture.target })
                        );
                    }
                    if complete {
                        break;
                    }
                }
                assert!(resume.is_complete(), "{mode:?}/{source_aware}/{asynchronous}");
                assert!(resume.debug_runtime_frames().is_empty());
                assert!(saw_target > 1 && saw_return && saw_root_end);
                assert_eq!(saw_inline, source_aware);
                let entry = entry_activation.unwrap();
                let target = target_activation.unwrap();
                if let Some((other_entry, other_target)) = &other_execution {
                    assert!(!entry.is_same_frame(other_entry));
                    assert_eq!(target.invocation_row(), other_target.invocation_row());
                    assert!(
                        !target.is_same_frame(other_target),
                        "equal rows in separate executions are distinct"
                    );
                }
                other_execution = Some((entry, target));
                if let Some(baseline) = &baseline {
                    assert_eq!(&observations, baseline, "{mode:?}/{source_aware}/{asynchronous}");
                } else {
                    baseline = Some(observations);
                }
            }
        }
    }
}

#[test]
fn runtime_debug_frames_publish_once_after_pending_witness_code_and_async_cancellation() {
    let fixture = source_dyncall_fixture();
    let mut inner = CountingHost::new(&fixture.environment, &[]);
    inner.forests.insert(
        fixture.callee.hash(),
        LoadedMastForest::with_package_debug_info(
            fixture.callee.mast_forest().clone(),
            Ok(Some(fixture.callee_debug.clone())),
        ),
    );
    let mut host = AsyncCodeHost {
        inner,
        suspend_code: AtomicBool::new(false),
    };
    let mut processor = source_dyncall_processor();
    let mut resume = processor
        .get_initial_resume_context(
            &fixture.program,
            fixture.environment.configuration(fixture.entry),
        )
        .unwrap();
    reach_source_dyncall(&mut processor, &mut host, &mut resume, &fixture);
    let before = resume.debug_runtime_frames();
    assert_eq!(before.len(), 1);
    let clock = processor.state().clock();
    host.inner.unavailable_keys.insert(fixture.target);
    assert!(matches!(poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::EnvironmentWitnessUnavailable { key, .. }) if key == fixture.target));
    host.inner.unavailable_keys.clear();
    host.suspend_code.store(true, Ordering::Relaxed);
    {
        let mut future = Box::pin(processor.step(&mut host, &mut resume));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    let pending = resume.debug_runtime_frames();
    assert_eq!(runtime_debug_observation(&pending), runtime_debug_observation(&before));
    assert!(before[0].is_same_frame(&pending[0]));
    assert_eq!(processor.state().clock(), clock);
    assert_eq!(resume.resolution_session().uses().count(), 0);
    host.suspend_code.store(false, Ordering::Relaxed);
    host.inner.unavailable_code.insert(fixture.callee.hash());
    assert!(matches!(poll_ready(processor.step(&mut host, &mut resume)),
        Err(ExecutionError::ProcedureNotFound { root_digest, .. }) if root_digest == fixture.callee.hash()));
    assert_eq!(
        runtime_debug_observation(&resume.debug_runtime_frames()),
        runtime_debug_observation(&before)
    );
    host.inner.unavailable_code.clear();
    assert!(!poll_ready(processor.step(&mut host, &mut resume)).unwrap());
    let frames = resume.debug_runtime_frames();
    assert_eq!(frames.len(), 2);
    assert!(before[0].is_same_frame(&frames[0]));
    assert_eq!(frames[1].kind(), DebugRuntimeFrameKind::Invoke(KeyedMode::DynCall));
    assert_eq!(frames[1].requested_key(), fixture.target);
    assert_ne!(frames[1].requested_key().into_word(), fixture.callee.hash());
    assert_eq!(frames[1].resolved_implementation().into_word(), fixture.callee.hash());
    assert_eq!(frames[1].invocation_row(), Some(clock));
    assert_eq!(frames[1].native_use_index(), Some(0));
    assert_runtime_debug_native_uses(&frames, &resume);
    run_steps(&mut processor, &mut host.inner, &mut resume);
    assert!(resume.debug_runtime_frames().is_empty());
    assert_eq!(resume.resolution_session().uses().count(), 2);
    assert_eq!(host.inner.requests_for(fixture.target), 2);
}

#[test]
fn runtime_debug_frames_keep_cached_recursive_exec_activations_distinct() {
    let recursive = key(&["native_fixture"], "recursive_exec");
    let mut forest = MastForest::new();
    let condition = block(&mut forest, vec![Operation::Dup0, Operation::Eqz, Operation::Not]);
    let decrement = block(&mut forest, vec![Operation::Push(-felt(1)), Operation::Add]);
    let exec_self = invocation(&mut forest, Mode::Exec, recursive);
    let on_nonzero = join(&mut forest, decrement, exec_self);
    let on_zero = block(&mut forest, vec![Operation::Noop]);
    let branch = SplitNodeBuilder::new([on_nonzero, on_zero]).add_to_forest(&mut forest).unwrap();
    let root = join(&mut forest, condition, branch);
    let program = finish_program(forest, root);
    let environment =
        EnvironmentFixture::new(&[(&["native_fixture"], "recursive_exec", program.hash())]);
    assert_ne!(recursive.into_word(), program.hash());
    for asynchronous in [false, true] {
        let mut host = AsyncCodeHost {
            inner: CountingHost::new(&environment, &[]),
            suspend_code: AtomicBool::new(false),
        };
        let mut processor = FastProcessor::new(StackInputs::new(&[felt(3)]).unwrap());
        let mut resume = processor
            .get_initial_resume_context(&program, environment.configuration(recursive))
            .unwrap();
        let mut previous = Vec::<DebugRuntimeFrame>::new();
        let mut invocations = Vec::<DebugRuntimeFrame>::new();
        let mut maximum_depth = 0;
        for _ in 0..512 {
            let frames = resume.debug_runtime_frames();
            maximum_depth = maximum_depth.max(frames.len());
            assert_runtime_debug_native_uses(&frames, &resume);
            for (old, current) in previous.iter().zip(&frames) {
                assert!(old.is_same_frame(current));
            }
            for frame in &frames {
                assert_eq!(frame.requested_key(), recursive);
                assert_eq!(frame.resolved_implementation().into_word(), program.hash());
                if let Some(index) = frame.native_use_index() {
                    assert_eq!(frame.kind(), DebugRuntimeFrameKind::Invoke(KeyedMode::Exec));
                    if index == invocations.len() {
                        assert!(invocations.iter().all(|old| !old.is_same_frame(frame)));
                        invocations.push(frame.clone());
                    } else {
                        assert!(invocations[index].is_same_frame(frame));
                    }
                }
            }
            previous = frames;
            let complete = if asynchronous {
                poll_ready(processor.step(&mut host, &mut resume))
            } else {
                processor.step_sync(&mut host.inner, &mut resume)
            }
            .unwrap();
            if complete {
                break;
            }
        }
        assert!(resume.is_complete());
        assert!(resume.debug_runtime_frames().is_empty());
        assert_eq!(maximum_depth, 4);
        assert_eq!(invocations.len(), 3);
        assert_eq!(host.inner.requests_for(recursive), 1);
        assert!(host.inner.code_requests.borrow().is_empty());
        assert_eq!(resume.resolution_session().bindings()[0].counts().normal, 4);
        assert_eq!(resume.resolution_session().uses().count(), 4);
        assert!(processor.state().ctx().is_root());
    }
}

#[test]
fn native_modes_cover_local_and_host_code_with_all_public_step_apis() {
    let mut cases = 0;
    for mode in [Mode::Exec, Mode::Call, Mode::Syscall, Mode::Dyn, Mode::DynCall] {
        for local_target in [true, false] {
            let fixture = mode_matrix_fixture(mode, local_target);
            for source_aware in [false, true] {
                for asynchronous in [false, true] {
                    let mut host = mode_matrix_host(&fixture, local_target);
                    let mut processor = source_dyncall_processor();
                    let original = processor.state().get_stack_state();
                    let mut user_stack = (40..44).rev().map(felt).collect::<Vec<_>>();
                    user_stack.extend_from_slice(&original);
                    assert!(user_stack[16..].iter().all(|value| *value != felt(0)));
                    let configuration = fixture.environment.configuration(fixture.entry);
                    let mut resume = processor
                        .get_initial_resume_context(&fixture.program, configuration)
                        .unwrap();
                    let mut seen = [false; 5];
                    let mut entry_debug = None;
                    let mut user_debug = None;
                    for _ in 0..1024 {
                        if source_aware {
                            for (index, &(exec, source, label)) in fixture.points.iter().enumerate()
                            {
                                let target_owner = index == 2 && !local_target;
                                let owner = if target_owner {
                                    fixture.callee.mast_forest()
                                } else {
                                    fixture.program.mast_forest()
                                };
                                if seen[index]
                                    || !Arc::ptr_eq(resume.current_forest(), owner)
                                    || resume.next_source_node_id() != Some(source)
                                {
                                    continue;
                                }
                                assert!(matches!(
                                    resume.continuation_stack().peek_continuation(),
                                    Some(Continuation::StartNode(node)) if *node == exec
                                ));
                                let debug = resume.debug_info().unwrap();
                                assert_eq!(debug.source_node(source).unwrap().exec_node, exec);
                                assert_eq!(
                                    debug[debug
                                        .first_asm_op_for_source_node(source)
                                        .unwrap()
                                        .context_name_idx]
                                        .as_ref(),
                                    label
                                );
                                assert_eq!(
                                    debug.as_ref(),
                                    if target_owner {
                                        &fixture.callee_debug
                                    } else {
                                        &fixture.debug
                                    }
                                );
                                match index {
                                    0 => entry_debug = Some(debug.clone()),
                                    1 => user_debug = Some(debug.clone()),
                                    2 if target_owner => {
                                        let supplied = host.inner.forests[&fixture.callee.hash()]
                                            .package_debug_info()
                                            .unwrap()
                                            .unwrap();
                                        assert!(Arc::ptr_eq(&debug, &supplied));
                                        assert!(!Arc::ptr_eq(&debug, user_debug.as_ref().unwrap()));
                                    },
                                    3 => assert!(Arc::ptr_eq(&debug, user_debug.as_ref().unwrap())),
                                    4 => {
                                        assert!(Arc::ptr_eq(&debug, entry_debug.as_ref().unwrap()))
                                    },
                                    _ => {},
                                }
                                seen[index] = true;
                            }
                        }
                        let complete = match (source_aware, asynchronous) {
                            (false, false) => processor.step_sync(&mut host.inner, &mut resume),
                            (false, true) => poll_ready(processor.step(&mut host, &mut resume)),
                            (true, false) => processor.step_with_package_debug_info_sync(
                                &mut host.inner,
                                &mut resume,
                                &fixture.debug,
                            ),
                            (true, true) => poll_ready(processor.step_with_package_debug_info(
                                &mut host,
                                &mut resume,
                                &fixture.debug,
                            )),
                        }
                        .unwrap();
                        if complete {
                            break;
                        }
                    }
                    assert!(
                        resume.is_complete(),
                        "{mode:?}/{local_target}/{source_aware}/{asynchronous}"
                    );
                    if source_aware {
                        assert!(seen.into_iter().all(|point| point));
                    }
                    assert_eq!(processor.state().get_stack_state(), original);
                    assert_eq!(processor.stack_depth(), 16);
                    assert!(processor.state().ctx().is_root());
                    let observations = &host.inner.observations;
                    assert_eq!(observations.len(), 5);
                    let user_context = observations[1].context;
                    assert!(!user_context.is_root());
                    let shared = matches!(mode, Mode::Exec | Mode::Dyn);
                    let syscall = matches!(mode, Mode::Syscall);
                    let target_context = observations[2].context;
                    if shared {
                        assert_eq!(target_context, user_context);
                    } else if syscall {
                        assert!(target_context.is_root());
                    } else {
                        assert!(!target_context.is_root());
                        assert_ne!(target_context, user_context);
                    }
                    let target_stack = if shared { &user_stack[..] } else { &user_stack[..16] };
                    let expected = [
                        (fixture.entry, ContextId::root(), Some(felt(17)), felt(18), &original[..]),
                        (fixture.user, user_context, Some(felt(77)), felt(88), &user_stack[..]),
                        (
                            if shared || syscall {
                                fixture.user
                            } else {
                                fixture.target
                            },
                            target_context,
                            if shared {
                                Some(felt(77))
                            } else if syscall {
                                Some(felt(17))
                            } else {
                                None
                            },
                            if shared {
                                felt(88)
                            } else if syscall {
                                felt(18)
                            } else {
                                FMP_INIT_VALUE
                            },
                            target_stack,
                        ),
                        (
                            fixture.user,
                            user_context,
                            Some(felt(if shared { 111 } else { 77 })),
                            felt(if shared { 222 } else { 88 }),
                            &user_stack[..],
                        ),
                        (
                            fixture.entry,
                            ContextId::root(),
                            Some(felt(if syscall { 111 } else { 17 })),
                            felt(if syscall { 222 } else { 18 }),
                            &original[..],
                        ),
                    ];
                    for (observed, (principal, context, value, fmp, stack)) in
                        observations.iter().zip(expected)
                    {
                        assert_eq!(observed.principal, principal.into_word());
                        assert_eq!(observed.context, context);
                        assert_eq!(observed.value, value);
                        assert_eq!(observed.fmp, Some(fmp));
                        assert_eq!(observed.depth as usize, stack.len() + 5);
                        assert_eq!(
                            &observed.stack[5..],
                            stack,
                            "{mode:?}: dynamic address consumed once and operands preserved"
                        );
                    }
                    assert_eq!(
                        processor.state().get_mem_value(target_context, VALUE_ADDR),
                        Some(felt(111))
                    );
                    assert_eq!(
                        processor
                            .state()
                            .get_mem_value(target_context, FMP_ADDR.as_canonical_u64() as u32),
                        Some(felt(222))
                    );
                    for key in [fixture.entry, fixture.user, fixture.target] {
                        assert_eq!(host.inner.requests_for(key), 1);
                    }
                    assert_eq!(host.inner.witness_requests.len(), 3);
                    assert!(
                        host.inner
                            .witness_requests
                            .iter()
                            .all(|request| request.root == fixture.environment.root
                                && request.limits == opening_limits())
                    );
                    assert_eq!(
                        *host.inner.code_requests.borrow(),
                        if local_target {
                            Vec::new()
                        } else {
                            vec![fixture.callee.hash()]
                        }
                    );
                    let session = resume.resolution_session();
                    assert_eq!(session.phase(), SessionPhase::Completed);
                    assert_eq!(session.bindings().len(), 3);
                    assert_eq!(
                        session
                            .uses()
                            .map(|use_record| (use_record.procedure_key(), use_record.tag()))
                            .collect::<Vec<_>>(),
                        vec![
                            (fixture.user, InvocationTag::Normal),
                            (
                                fixture.target,
                                if syscall {
                                    InvocationTag::Syscall
                                } else {
                                    InvocationTag::Normal
                                }
                            ),
                            (fixture.entry, InvocationTag::Normal)
                        ]
                    );
                    assert_eq!(session.counters().committed_requests, 3);
                    assert_eq!(session.counters().reserved_requests, 0);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 40);
}

#[test]
fn source_async_host_call_event_error_invalidates_the_published_target() {
    let fixture = mode_matrix_fixture(Mode::Call, false);
    let mut host = mode_matrix_host(&fixture, false);
    let mut processor = source_dyncall_processor();
    let mut resume = processor
        .get_initial_resume_context(
            &fixture.program,
            fixture.environment.configuration(fixture.entry),
        )
        .unwrap();
    for _ in 0..256 {
        if resume.resolution_session().uses().count() == 2 {
            break;
        }
        assert!(
            !poll_ready(processor.step_with_package_debug_info(
                &mut host,
                &mut resume,
                &fixture.debug,
            ))
            .unwrap()
        );
    }
    assert_eq!(resume.resolution_session().uses().count(), 2);
    assert!(Arc::ptr_eq(resume.current_forest(), fixture.callee.mast_forest()));
    let (target_exec, target_source, _) = fixture.points[2];
    assert_eq!(resume.next_source_node_id(), Some(target_source));
    let debug = resume.debug_info().unwrap();
    assert_eq!(debug.source_node(target_source).unwrap().exec_node, target_exec);
    assert_eq!(
        debug[debug.first_asm_op_for_source_node(target_source).unwrap().context_name_idx].as_ref(),
        "matrix::target"
    );
    let target_context = processor.state().ctx();
    assert!(!target_context.is_root());
    assert_ne!(target_context, host.inner.observations[1].context);
    assert_eq!(processor.stack_depth(), 16);
    assert_eq!(processor.state().get_mem_value(target_context, VALUE_ADDR), None);
    assert_eq!(
        processor
            .state()
            .get_mem_value(target_context, FMP_ADDR.as_canonical_u64() as u32),
        Some(FMP_INIT_VALUE)
    );
    host.inner.fail_event = true;
    let mut failed = false;
    for _ in 0..64 {
        match poll_ready(processor.step(&mut host, &mut resume)) {
            Ok(false) => {},
            Err(ExecutionError::EventError { event_id, error, .. }) => {
                assert_eq!(event_id, EventId::from_felt(felt(OBSERVE)));
                assert_eq!(error.to_string(), "fixture callback failure");
                failed = true;
                break;
            },
            result => panic!("expected late target callback failure: {result:?}"),
        }
    }
    assert!(failed);
    assert_eq!(host.inner.observations.len(), 3);
    assert_eq!(host.inner.observations[2].principal, fixture.target.into_word());
    assert_eq!(host.inner.observations[2].context, target_context);
    assert_eq!(host.inner.observations[2].value, None);
    assert_eq!(host.inner.observations[2].fmp, Some(FMP_INIT_VALUE));
    assert_eq!(host.inner.witness_requests.len(), 3);
    assert_eq!(*host.inner.code_requests.borrow(), vec![fixture.callee.hash()]);
    let stack = processor.state().get_stack_state();
    let clock = processor.state().clock();
    let requests = host.inner.witness_requests.len();
    let code_requests = host.inner.code_requests.borrow().len();
    for _ in 0..2 {
        assert!(matches!(
            poll_ready(processor.step(&mut host, &mut resume)),
            Err(ExecutionError::InvalidExecutionState)
        ));
        assert_eq!(processor.state().get_stack_state(), stack);
        assert_eq!(processor.state().clock(), clock);
        assert_eq!(processor.state().ctx(), target_context);
        assert!(Arc::ptr_eq(resume.current_forest(), fixture.callee.mast_forest()));
        assert!(Arc::ptr_eq(&resume.debug_info().unwrap(), &debug));
        assert_eq!(resume.resolution_session().uses().count(), 2);
        assert_eq!(host.inner.witness_requests.len(), requests);
        assert_eq!(host.inner.code_requests.borrow().len(), code_requests);
        assert_eq!(host.inner.observations.len(), 3);
        assert!(!resume.is_complete());
    }
}
