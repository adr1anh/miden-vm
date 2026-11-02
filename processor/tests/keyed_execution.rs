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
        MastForest, MastNodeId, SplitNodeBuilder,
    },
    operations::Operation,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ExecutionDescriptor, ImplementationRoot,
        Namespace, ProcedureKey,
    },
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, ContextId, EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    ExecutionEnvironment, ExecutionError, ExecutionOptions, ExecutionWitness, FastProcessor, Felt,
    FutureMaybeSend, Host, InvocationTag, LedgerLimits, LoadedMastForest, OpeningError,
    OpeningLimits, OpeningResource, OpeningStep, ProcessorState, Program, ReplayReadLimits,
    ResolutionWitness, SessionError, SessionLimits, SessionPhase, SessionResource, StackInputs,
    SyncHost, Word, advice::AdviceMutation, event::EventError, operation::OperationError,
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

    fn configuration(&self, entry: ProcedureKey, kernel: Namespace) -> ExecutionEnvironment {
        ExecutionEnvironment::new(
            ExecutionDescriptor::new(entry, self.root, kernel),
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
        });
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
    let configuration = environment.configuration(entry, namespace(&["kernel"]));

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
        ExecutionDescriptor::new(entry, EnvironmentRoot::new(hint.hash()), namespace(&["kernel"])),
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
        .execute_sync(
            &hint,
            environment.configuration(digest_shaped_key, namespace(&["kernel"])),
            &mut host,
        )
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
            .get_initial_resume_context(
                &program,
                environment.configuration(entry, namespace(&["kernel"])),
            )
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
        .get_initial_resume_context(
            &program,
            environment.configuration(recursive, namespace(&["kernel"])),
        )
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
fn syscall_requires_exact_full_namespace_before_code_lookup() {
    let entry = key(&["app"], "entry");
    let kernel_path = ["runtime", "kernel", "v2"];
    let target = key(&kernel_path, "read_principal");
    let callee = body(observe());
    let program = invocation_program(Mode::Syscall, target);
    let environment = EnvironmentFixture::new(&[
        (&["app"], "entry", program.hash()),
        (&kernel_path, "read_principal", callee.hash()),
    ]);
    let exact = namespace(&kernel_path);
    for authorized in [
        namespace(&["kernel"]),
        namespace(&["runtime", "kernel"]),
        namespace(&["runtime", "kernel", "v2", "child"]),
    ] {
        let mut host = CountingHost::new(&environment, &[&callee]);
        let error = FastProcessor::new(StackInputs::default())
            .execute_sync(&program, environment.configuration(entry, authorized), &mut host)
            .unwrap_err();
        assert!(matches!(error, ExecutionError::EnvironmentSession(
            SessionError::UnauthorizedSyscall { expected, actual })
            if expected == authorized && actual == exact));
        assert!(host.code_requests.borrow().is_empty());
        assert!(host.observations.is_empty());
    }
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
        .get_initial_resume_context(&program, environment.configuration(entry, exact))
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
fn entry_and_ordinary_call_may_use_exports_in_the_authorized_kernel_namespace() {
    let kernel_path = ["runtime", "kernel", "v2"];
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
            .execute_sync(
                hint,
                environment.configuration(entry, namespace(&kernel_path)),
                &mut host,
            )
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
            .execute_sync(
                &program,
                environment.configuration(entry, namespace(&["kernel"])),
                &mut host,
            )
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
            .get_initial_resume_context(
                &program,
                environment.configuration(entry, namespace(&["kernel"])),
            )
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
        .get_initial_resume_context(
            &program,
            environment.configuration(entry, namespace(&["kernel"])),
        )
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
            ExecutionDescriptor::new(entry, environment.root, namespace(&["kernel"])),
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
            environment.configuration(entry, namespace(&["kernel"])),
            &mut host,
        ),
        Err(ExecutionError::MissingEnvironmentTraceLimits)
    ));
    assert!(host.witness_requests.is_empty());
}

#[test]
fn replay_v4_roundtrip_uses_caller_authority_and_explicit_budgets() {
    let entry = key(&[], "entry");
    let target = key(&["lib"], "child");
    let callee = body(observe());
    let program = invocation_program(Mode::Call, target);
    let environment = EnvironmentFixture::new(&[
        (&[], "entry", program.hash()),
        (&["lib"], "child", callee.hash()),
    ]);
    let configuration = environment.configuration(entry, namespace(&["kernel"]));
    let mut host = CountingHost::new(&environment, &[&callee]);
    let witness = FastProcessor::new(StackInputs::default())
        .with_options(ExecutionOptions::default().with_environment_trace_limits(trace_limits()))
        .unwrap()
        .execute_for_proving_sync(&program, configuration, &mut host)
        .unwrap();
    let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 4);
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
    for version in [3, 5] {
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
    let wrong_authority = environment.configuration(target, namespace(&["kernel"]));
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &wrong_authority,
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
        .get_initial_resume_context(&hint, environment.configuration(entry, namespace(&["kernel"])))
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
