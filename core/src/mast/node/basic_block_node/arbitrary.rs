use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
};
use core::{iter::repeat_n, ops::RangeInclusive};

use proptest::{arbitrary::Arbitrary, prelude::*};

use super::*;
use crate::{
    Felt, ONE, Word,
    advice::{AdviceInputs, AdviceMap, AdviceStack},
    crypto::merkle::MerkleStore,
    mast::{
        CallNodeBuilder, DenseMastForestBuilder, DynNodeBuilder, ExecNodeBuilder,
        ExternalNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, SplitNodeBuilder,
    },
    operations::Operation,
    program::{KernelDescriptor, ProcedureKey, Program},
};

// OPERATIONS
// ================================================================================================

/// Non-control-flow operations without an immediate value.
const OPS_NO_IMM: &[Operation] = &[
    Operation::Add,
    Operation::Mul,
    Operation::Neg,
    Operation::Inv,
    Operation::Incr,
    Operation::And,
    Operation::Or,
    Operation::Not,
    Operation::Eq,
    Operation::Eqz,
    Operation::Drop,
    Operation::Pad,
    Operation::Swap,
    Operation::SwapW,
    Operation::SwapW2,
    Operation::SwapW3,
    Operation::SwapDW,
    Operation::MovUp2,
    Operation::MovUp3,
    Operation::MovUp4,
    Operation::MovUp5,
    Operation::MovUp6,
    Operation::MovUp7,
    Operation::MovUp8,
    Operation::MovDn2,
    Operation::MovDn3,
    Operation::MovDn4,
    Operation::MovDn5,
    Operation::MovDn6,
    Operation::MovDn7,
    Operation::MovDn8,
    Operation::CSwap,
    Operation::CSwapW,
    Operation::Dup0,
    Operation::Dup1,
    Operation::Dup2,
    Operation::Dup3,
    Operation::Dup4,
    Operation::Dup5,
    Operation::Dup6,
    Operation::Dup7,
    Operation::Dup9,
    Operation::Dup11,
    Operation::Dup13,
    Operation::Dup15,
    Operation::MLoad,
    Operation::MStore,
    Operation::MLoadW,
    Operation::MStoreW,
    Operation::MStream,
    Operation::Pipe,
    Operation::AdvPop,
    Operation::AdvPopW,
    Operation::U32split,
    Operation::U32add,
    Operation::U32sub,
    Operation::U32mul,
    Operation::U32div,
    Operation::U32and,
    Operation::U32xor,
    Operation::U32add3,
    Operation::U32madd,
    Operation::SDepth,
    Operation::Caller,
    Operation::Clk,
    Operation::Emit,
    Operation::Ext2Mul,
    Operation::Expacc,
    Operation::Compress,
];

/// Operations that cannot fail whatever the stack, advice provider, or memory hold. Their stack
/// effect comes from [`Operation::increments_stack_size`] and
/// [`Operation::decrements_stack_size`].
///
/// Left out: `Inv` (traps on zero), `And`, `Or`, `Not`, `CSwap` and `CSwapW` (binary operands),
/// the `U32*` family (u32-range operands), memory and advice operations, `Caller`, `Emit`,
/// `Assert`, and the crypto/STARK helpers.
const INFALLIBLE_OPS: &[Operation] = &[
    Operation::Add,
    Operation::Mul,
    Operation::Neg,
    Operation::Incr,
    Operation::Eq,
    Operation::Eqz,
    Operation::Ext2Mul,
    Operation::Expacc,
    Operation::Drop,
    Operation::Pad,
    Operation::Swap,
    Operation::SwapW,
    Operation::SwapW2,
    Operation::SwapW3,
    Operation::SwapDW,
    Operation::MovUp2,
    Operation::MovUp3,
    Operation::MovUp4,
    Operation::MovUp5,
    Operation::MovUp6,
    Operation::MovUp7,
    Operation::MovUp8,
    Operation::MovDn2,
    Operation::MovDn3,
    Operation::MovDn4,
    Operation::MovDn5,
    Operation::MovDn6,
    Operation::MovDn7,
    Operation::MovDn8,
    Operation::Dup0,
    Operation::Dup1,
    Operation::Dup2,
    Operation::Dup3,
    Operation::Dup4,
    Operation::Dup5,
    Operation::Dup6,
    Operation::Dup7,
    Operation::Dup9,
    Operation::Dup11,
    Operation::Dup13,
    Operation::Dup15,
    Operation::SDepth,
    Operation::Clk,
];

/// Strategy for operations without immediate values (non-control flow).
pub fn op_no_imm_strategy() -> impl Strategy<Value = Operation> {
    prop::sample::select(OPS_NO_IMM)
}

/// Strategy for operations with immediate values.
pub fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    any::<u64>().prop_map(Felt::new_unchecked).prop_map(Operation::Push)
}

/// Strategy for all non-control flow operations.
pub fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy()]
}

/// Strategy for sequences of non-control flow operations.
pub fn op_non_control_sequence_strategy(
    max_length: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

/// Change `op` makes to the stack depth, or `None` if `op` can fail.
fn stack_delta(op: &Operation) -> Option<i8> {
    if !matches!(op, Operation::Noop | Operation::Push(_)) && !INFALLIBLE_OPS.contains(op) {
        return None;
    }
    Some(if op.increments_stack_size() {
        1
    } else if op.decrements_stack_size() {
        -1
    } else {
        0
    })
}

fn op_infallible_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![prop::sample::select(INFALLIBLE_OPS), op_with_imm_strategy(),]
}

/// Keeps at most `max_len` of `ops`, skipping operations that would take the stack below its
/// depth on entry or leave no room for the `Drop`s that restore it, then appends those `Drop`s.
/// Every operation in `ops` must be infallible.
fn balance_ops(ops: Vec<Operation>, max_len: usize) -> Vec<Operation> {
    let mut depth = 0i32;
    let mut balanced = Vec::with_capacity(max_len);
    for op in ops {
        let delta = i32::from(stack_delta(&op).expect("infallible operation"));
        let next_depth = depth + delta;
        if next_depth >= 0 && balanced.len() + 1 + next_depth as usize <= max_len {
            depth = next_depth;
            balanced.push(op);
        }
    }
    balanced.extend(repeat_n(Operation::Drop, depth as usize));
    if balanced.is_empty() {
        balanced.push(Operation::Noop);
    }
    balanced
}

// BASIC BLOCKS
// ================================================================================================

/// Parameters for generating `BasicBlockNode` instances.
#[derive(Clone, Debug)]
pub struct BasicBlockNodeParams {
    /// Maximum number of operations in a generated basic block.
    pub max_ops_len: usize,
    /// Restricts blocks to infallible operations that leave the stack depth unchanged, so a block
    /// runs on any operand stack.
    pub executable: bool,
}

impl Default for BasicBlockNodeParams {
    fn default() -> Self {
        Self { max_ops_len: 8, executable: false }
    }
}

/// Strategy for the operations of a basic block described by `params`.
pub(super) fn block_ops_strategy(params: &BasicBlockNodeParams) -> BoxedStrategy<Vec<Operation>> {
    if params.executable {
        let max_len = params.max_ops_len;
        prop::collection::vec(op_infallible_strategy(), 1..=max_len)
            .prop_map(move |ops| balance_ops(ops, max_len))
            .boxed()
    } else {
        op_non_control_sequence_strategy(params.max_ops_len).boxed()
    }
}

impl Arbitrary for BasicBlockNode {
    type Parameters = BasicBlockNodeParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        block_ops_strategy(&params)
            .prop_map(|ops| BasicBlockNode::new(ops).expect("non-empty operations"))
            .boxed()
    }
}

// FOREST PARAMETERS
// ================================================================================================

/// What a `MastForest` sample guarantees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GenerationMode {
    /// Every procedure root runs to completion on any operand stack. See [`MastForestParams`].
    #[default]
    Executable,
    /// Broad structural coverage without execution guarantees: fallible operations, dyn nodes,
    /// externals with random digests, and keyed invocations with independent procedure keys.
    StructureOnly,
}

/// Parameters for generating `MastForest` instances via proptest.
///
/// In [`GenerationMode::Executable`] every procedure root of a sample executes to completion on
/// any operand stack once the forest is loaded into the host:
///
/// - basic blocks hold only infallible operations and leave the stack depth unchanged;
/// - each split sits behind a block that pushes its condition, and each loop body ends by pushing
///   `0`, so conditions are binary and loops run exactly once;
/// - each external resolves to a procedure root of the same forest, and the graph of externals is
///   acyclic;
/// - immediate keyed invocations and dyn nodes are never emitted.
///
/// The executable mode currently covers structural execution only. Generating executable
/// EXEC/CALL/SYSCALL requires a paired authenticated execution environment, which this API does not
/// yet provide. Structure-only mode covers all three immediate invocation modes and retains each
/// selected implementation body as a separate procedure root. A symbolic key does not retain its
/// implementation through a structural edge.
///
/// `kernel_procedures` supplies digest-only descriptor metadata. It does not authorize or select
/// symbolic invocation keys.
///
/// Samples of both modes are pruned: every node is reachable from a procedure root.
#[derive(Clone, Debug)]
pub struct MastForestParams {
    /// Number of basic blocks to generate; a bound of `0` is raised to `1`.
    pub blocks: RangeInclusive<usize>,
    /// Maximum number of join nodes.
    pub max_joins: usize,
    /// Maximum number of split nodes.
    pub max_splits: usize,
    /// Maximum number of loop nodes.
    pub max_loops: usize,
    /// Maximum number of call nodes. Ignored in [`GenerationMode::Executable`].
    pub max_calls: usize,
    /// Maximum number of exec nodes. Ignored in [`GenerationMode::Executable`].
    pub max_execs: usize,
    /// Maximum number of syscall nodes. Ignored in [`GenerationMode::Executable`].
    pub max_syscalls: usize,
    /// Maximum number of external nodes.
    pub max_externals: usize,
    /// Maximum number of dyn and dyncall nodes. Ignored in [`GenerationMode::Executable`].
    pub max_dyns: usize,
    /// Guarantees the samples provide.
    pub mode: GenerationMode,
    /// Procedure hashes of a caller-supplied legacy kernel descriptor. When `None`, the descriptor
    /// is empty. These implementation digests are independent of generated procedure keys.
    /// Duplicate hashes or more than [`KernelDescriptor::MAX_NUM_PROCEDURES`] entries make
    /// [`forest_kernel_strategy`] panic.
    pub kernel_procedures: Option<Vec<Word>>,
}

impl Default for MastForestParams {
    fn default() -> Self {
        Self {
            blocks: 1..=3,
            max_joins: 1,
            max_splits: 1,
            max_loops: 1,
            max_calls: 1,
            max_execs: 1,
            max_syscalls: 1,
            max_externals: 1,
            max_dyns: 0,
            mode: GenerationMode::Executable,
            kernel_procedures: None,
        }
    }
}

// SEEDS
// ================================================================================================

/// How an external node picks its digest.
#[derive(Clone, Copy, Debug)]
enum ExternalPick {
    /// Executable mode: indices into the current roots (target) and nodes (join sibling).
    Local { root: usize, sibling: usize },
    /// Structure-only mode: a random digest.
    Random(Word),
}

/// Selects a retained implementation body and an independently sampled symbolic target.
#[derive(Clone, Copy, Debug)]
struct InvocationPick {
    body: usize,
    target: ProcedureKey,
}

fn invocation_picks_strategy(max_len: usize) -> impl Strategy<Value = Vec<InvocationPick>> {
    prop::collection::vec(any::<(usize, Word)>(), 0..=max_len).prop_map(|picks| {
        picks
            .into_iter()
            .map(|(body, target)| InvocationPick { body, target: ProcedureKey::new(target) })
            .collect()
    })
}

/// Raw samples for one forest. Index vectors are reduced modulo the number of candidates when
/// they are consumed.
#[derive(Clone, Debug)]
struct ForestSeeds {
    basic_blocks: Vec<BasicBlockNode>,
    join_pairs: Vec<(usize, usize)>,
    /// Branch indices and the condition pushed before the split (executable mode).
    splits: Vec<(usize, usize, bool)>,
    loop_indices: Vec<usize>,
    call_picks: Vec<InvocationPick>,
    exec_picks: Vec<InvocationPick>,
    syscall_picks: Vec<InvocationPick>,
    external_picks: Vec<ExternalPick>,
    /// `true` selects `dyncall`, `false` selects `dyn`.
    dyn_selectors: Vec<bool>,
    /// One flag per skeleton node: whether it becomes a procedure root.
    root_selection: Vec<bool>,
}

fn forest_seeds_strategy(params: &MastForestParams) -> BoxedStrategy<ForestSeeds> {
    let executable = params.mode == GenerationMode::Executable;
    let block_params = BasicBlockNodeParams { executable, ..Default::default() };
    let blocks = (*params.blocks.start()).max(1)..=(*params.blocks.end()).max(1);
    let external_picks: BoxedStrategy<Vec<ExternalPick>> = if executable {
        prop::collection::vec(any::<(usize, usize)>(), 0..=params.max_externals)
            .prop_map(|picks| {
                picks
                    .into_iter()
                    .map(|(root, sibling)| ExternalPick::Local { root, sibling })
                    .collect()
            })
            .boxed()
    } else {
        prop::collection::vec(any::<Word>(), 0..=params.max_externals)
            .prop_map(|digests| digests.into_iter().map(ExternalPick::Random).collect())
            .boxed()
    };
    let max_dyns = if executable { 0 } else { params.max_dyns };
    let (max_calls, max_execs, max_syscalls) = if executable {
        (0, 0, 0)
    } else {
        (params.max_calls, params.max_execs, params.max_syscalls)
    };

    (
        prop::collection::vec(any_with::<BasicBlockNode>(block_params), blocks),
        (
            prop::collection::vec(any::<(usize, usize)>(), 0..=params.max_joins),
            prop::collection::vec(any::<(usize, usize, bool)>(), 0..=params.max_splits),
            prop::collection::vec(any::<usize>(), 0..=params.max_loops),
            invocation_picks_strategy(max_calls),
            invocation_picks_strategy(max_execs),
        ),
        (
            invocation_picks_strategy(max_syscalls),
            external_picks,
            prop::collection::vec(any::<bool>(), 0..=max_dyns),
        ),
    )
        // Root selection is the one vector that needs an exact size: a flag per skeleton node.
        .prop_flat_map(|(basic_blocks, control_flow, tail)| {
            let (join_pairs, splits, loop_indices, call_picks, exec_picks) = &control_flow;
            let skeleton_nodes = basic_blocks.len()
                + join_pairs.len()
                + splits.len()
                + loop_indices.len()
                + call_picks.len()
                + exec_picks.len()
                + tail.0.len();
            (
                Just((basic_blocks, control_flow, tail)),
                prop::collection::vec(any::<bool>(), skeleton_nodes),
            )
        })
        .prop_map(
            |(
                (
                    basic_blocks,
                    (join_pairs, splits, loop_indices, call_picks, exec_picks),
                    (syscall_picks, external_picks, dyn_selectors),
                ),
                root_selection,
            )| {
                ForestSeeds {
                    basic_blocks,
                    join_pairs,
                    splits,
                    loop_indices,
                    call_picks,
                    exec_picks,
                    syscall_picks,
                    external_picks,
                    dyn_selectors,
                    root_selection,
                }
            },
        )
        .boxed()
}

// SKELETON
// ================================================================================================

/// Shared part of a sample: basic blocks, control flow, and the initial procedure roots.
struct Skeleton {
    forest: DenseMastForestBuilder,
    /// Nodes that later nodes may reference and that root selection draws from.
    node_ids: Vec<MastNodeId>,
    roots: Vec<MastNodeId>,
}

/// Single-operation blocks pushing `0` or `1`, created on first use. `0` also ends every loop
/// body, since a loop inspects its condition only after each iteration.
#[derive(Default)]
struct ConditionBlocks {
    zero: Option<MastNodeId>,
    one: Option<MastNodeId>,
}

impl ConditionBlocks {
    fn get(&mut self, forest: &mut DenseMastForestBuilder, bit: bool) -> MastNodeId {
        let (slot, op) = if bit {
            (&mut self.one, Operation::Push(ONE))
        } else {
            (&mut self.zero, Operation::Pad)
        };
        *slot.get_or_insert_with(|| {
            forest.push_node(BasicBlockNodeBuilder::new(vec![op])).expect("condition block")
        })
    }
}

fn choose(ids: &[MastNodeId], index: usize) -> MastNodeId {
    ids[index % ids.len()]
}

fn digest_of(forest: &DenseMastForestBuilder, id: MastNodeId) -> Word {
    forest.get_node_by_id(id).expect("node id from this builder").digest()
}

/// Joins a block pushing `bit` in front of `node`, which consumes it as its condition.
fn with_condition(
    forest: &mut DenseMastForestBuilder,
    conditions: &mut ConditionBlocks,
    bit: bool,
    node: MastNodeId,
) -> MastNodeId {
    let condition = conditions.get(forest, bit);
    forest
        .push_node(JoinNodeBuilder::new([condition, node]))
        .expect("condition join")
}

fn build_skeleton(seeds: &ForestSeeds, executable: bool) -> Skeleton {
    let mut forest = DenseMastForestBuilder::new();
    let empty_forest = MastForest::new();
    let mut node_ids: Vec<MastNodeId> = seeds
        .basic_blocks
        .iter()
        .map(|block| {
            forest.push_node(block.clone().to_builder(&empty_forest)).expect("basic block")
        })
        .collect();
    let mut conditions = ConditionBlocks::default();

    for &(first, second) in &seeds.join_pairs {
        let join = JoinNodeBuilder::new([choose(&node_ids, first), choose(&node_ids, second)]);
        node_ids.push(forest.push_node(join).expect("join"));
    }

    for &(on_true, on_false, condition) in &seeds.splits {
        let split =
            SplitNodeBuilder::new([choose(&node_ids, on_true), choose(&node_ids, on_false)]);
        let mut id = forest.push_node(split).expect("split");
        if executable {
            id = with_condition(&mut forest, &mut conditions, condition, id);
        }
        node_ids.push(id);
    }

    for &body in &seeds.loop_indices {
        let mut body = choose(&node_ids, body);
        if executable {
            let exit = conditions.get(&mut forest, false);
            body = forest.push_node(JoinNodeBuilder::new([body, exit])).expect("loop body");
        }
        node_ids.push(forest.push_node(LoopNodeBuilder::new(body)).expect("loop"));
    }

    // Symbolic invocations have no structural body edge. Keep selected bodies explicitly.
    let mut invoked_bodies = Vec::new();
    for pick in &seeds.call_picks {
        invoked_bodies.push(choose(&node_ids, pick.body));
        let call = CallNodeBuilder::new(pick.target);
        node_ids.push(forest.push_node(call).expect("call"));
    }
    for pick in &seeds.exec_picks {
        invoked_bodies.push(choose(&node_ids, pick.body));
        node_ids.push(forest.push_node(ExecNodeBuilder::new(pick.target)).expect("exec"));
    }
    for pick in &seeds.syscall_picks {
        invoked_bodies.push(choose(&node_ids, pick.body));
        let syscall = CallNodeBuilder::new_syscall(pick.target);
        node_ids.push(forest.push_node(syscall).expect("syscall"));
    }

    let mut roots: Vec<MastNodeId> = node_ids
        .iter()
        .copied()
        .zip(&seeds.root_selection)
        .filter_map(|(id, &selected)| selected.then_some(id))
        .collect();
    if roots.is_empty() {
        roots.push(node_ids[0]);
    }
    roots.extend(invoked_bodies);
    roots.sort_unstable();
    roots.dedup();
    for &root in &roots {
        forest.mark_root(root);
    }

    Skeleton { forest, node_ids, roots }
}

/// Marks every node unreachable from `roots` as a root, top-most nodes first.
fn promote_unreachable(forest: &mut DenseMastForestBuilder, roots: &mut Vec<MastNodeId>) {
    let mut reachable = BTreeSet::new();
    for &root in roots.iter() {
        mark_reachable(forest, root, &mut reachable);
    }
    for index in (0..MastNodeContext::node_count(forest) as u32).rev() {
        let id = MastNodeId::new_unchecked(index);
        if !reachable.contains(&id) {
            forest.mark_root(id);
            roots.push(id);
            mark_reachable(forest, id, &mut reachable);
        }
    }
}

fn mark_reachable(
    forest: &DenseMastForestBuilder,
    from: MastNodeId,
    reachable: &mut BTreeSet<MastNodeId>,
) {
    let mut stack = vec![from];
    while let Some(id) = stack.pop() {
        if reachable.insert(id) {
            forest
                .get_node_by_id(id)
                .expect("node id from this builder")
                .append_children_to(&mut stack);
        }
    }
}

// EXECUTABLE MODE
// ================================================================================================

fn build_executable_forest(
    seeds: &ForestSeeds,
    kernel: Option<&KernelDescriptor>,
) -> (MastForest, KernelDescriptor) {
    let Skeleton { mut forest, node_ids, mut roots } = build_skeleton(seeds, true);
    let mut externals = BTreeMap::new();

    add_local_externals(&mut forest, &node_ids, &mut roots, &mut externals, &seeds.external_picks);
    promote_unreachable(&mut forest, &mut roots);

    let forest = forest.build().expect("generated forest is valid");
    (forest, kernel.cloned().unwrap_or_default())
}

/// Adds externals resolving to a root of the same forest. Each one is joined with an existing
/// node, so the external is used by a procedure instead of being a root itself.
fn add_local_externals(
    forest: &mut DenseMastForestBuilder,
    node_ids: &[MastNodeId],
    roots: &mut Vec<MastNodeId>,
    externals: &mut BTreeMap<Word, MastNodeId>,
    picks: &[ExternalPick],
) {
    for pick in picks {
        let ExternalPick::Local { root, sibling } = *pick else {
            continue;
        };
        let digest = digest_of(forest, choose(roots, root));
        // Dense forests hold at most one external per digest.
        if externals.contains_key(&digest) {
            continue;
        }
        let external = forest.push_node(ExternalNodeBuilder::new(digest)).expect("external");
        externals.insert(digest, external);
        let join = JoinNodeBuilder::new([external, choose(node_ids, sibling)]);
        let wrapper = forest.push_node(join).expect("external join");
        forest.mark_root(wrapper);
        roots.push(wrapper);
    }
}

// STRUCTURE-ONLY MODE
// ================================================================================================

fn build_structure_only_forest(
    seeds: &ForestSeeds,
    kernel: Option<&KernelDescriptor>,
) -> (MastForest, KernelDescriptor) {
    let Skeleton { mut forest, mut node_ids, mut roots } = build_skeleton(seeds, false);

    let mut digests = BTreeSet::new();
    for pick in &seeds.external_picks {
        let ExternalPick::Random(digest) = *pick else { continue };
        if digests.insert(digest) {
            node_ids.push(forest.push_node(ExternalNodeBuilder::new(digest)).expect("external"));
        }
    }

    for &dyncall in &seeds.dyn_selectors {
        let node = if dyncall {
            DynNodeBuilder::new_dyncall()
        } else {
            DynNodeBuilder::new_dyn()
        };
        node_ids.push(forest.push_node(node).expect("dyn"));
    }

    promote_unreachable(&mut forest, &mut roots);
    let forest = forest.build().expect("generated forest is valid");
    (forest, kernel.cloned().unwrap_or_default())
}

// STRATEGIES
// ================================================================================================

/// Strategy yielding `(MastForest, KernelDescriptor)` pairs. The descriptor preserves supplied
/// implementation hashes independently of symbolic keys. It does not authenticate invocation
/// bindings. See [`MastForestParams`] for what each [`GenerationMode`] guarantees.
///
/// # Panics
///
/// Panics if `params.kernel_procedures` is rejected by [`KernelDescriptor::from_hashes`]. The
/// check does not depend on the sample, so it runs once here instead of rejecting every sample.
pub fn forest_kernel_strategy(
    params: MastForestParams,
) -> BoxedStrategy<(MastForest, KernelDescriptor)> {
    let kernel = params.kernel_procedures.clone().map(|hashes| {
        KernelDescriptor::from_hashes(hashes)
            .unwrap_or_else(|err| panic!("MastForestParams::kernel_procedures is invalid: {err}"))
    });
    let mode = params.mode;

    forest_seeds_strategy(&params)
        .prop_map(move |seeds| match mode {
            GenerationMode::Executable => build_executable_forest(&seeds, kernel.as_ref()),
            GenerationMode::StructureOnly => build_structure_only_forest(&seeds, kernel.as_ref()),
        })
        .boxed()
}

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    /// In [`GenerationMode::Executable`] every root runs under the empty kernel of `Program::new`.
    /// Immediate keyed invocations remain restricted to [`GenerationMode::StructureOnly`] until
    /// execution-environment generation is available.
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        forest_kernel_strategy(params).prop_map(|(forest, _)| forest).boxed()
    }
}

// OTHER ARBITRARY IMPLEMENTATIONS
// ================================================================================================

impl Arbitrary for AdviceStack {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Any field elements are valid advice stack entries.
        prop::collection::vec(any::<Felt>(), 0..=32).prop_map(AdviceStack::from).boxed()
    }
}

impl Arbitrary for AdviceMap {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let key = prop_oneof![Just(Word::default()), any::<Word>()];
        let value = prop::collection::vec(any::<u64>(), 1..=4).prop_map(|values| {
            values.into_iter().map(Felt::new_unchecked).collect::<Arc<[Felt]>>()
        });

        prop::collection::vec((key, value), 0..=10)
            .prop_map(|entries| AdviceMap::from(entries.into_iter().collect::<BTreeMap<_, _>>()))
            .boxed()
    }
}

impl Arbitrary for Program {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    /// Generates a program whose entrypoint is a single basic block.
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any_with::<BasicBlockNode>(BasicBlockNodeParams { max_ops_len: 4, ..Default::default() })
            .prop_map(|node| {
                let mut builder = DenseMastForestBuilder::new();
                let node_id = builder
                    .push_node(node.to_builder(&MastForest::new()))
                    .expect("Failed to add node");
                builder.mark_root(node_id);
                let (forest, remapping) =
                    builder.build_with_id_map().expect("generated program forest should be valid");
                let entrypoint = remapping.get(node_id).expect("entrypoint should be retained");

                Program::new(Arc::new(forest), entrypoint)
            })
            .boxed()
    }
}

impl Arbitrary for KernelDescriptor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Distinct random words, well below `MAX_NUM_PROCEDURES`.
        prop::collection::btree_set(any::<Word>(), 0..=3)
            .prop_map(|words| {
                KernelDescriptor::from_hashes(words.into_iter().collect())
                    .expect("Generated kernel should be valid")
            })
            .boxed()
    }
}

impl Arbitrary for AdviceInputs {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Each component has its own strategy producing structurally valid values:
        // arbitrary felts for the stack, key-mapped element lists for the map, and
        // hash-consistent nodes for the store.
        (any::<AdviceStack>(), any::<AdviceMap>(), any::<MerkleStore>())
            .prop_map(|(stack, map, store)| AdviceInputs::new(stack, map, store))
            .boxed()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::fmt::Debug;

    use proptest::{strategy::ValueTree, test_runner::TestRunner};

    use super::*;
    use crate::mast::{CallNode, MastNode, OpBatch, SubtreeIterator};

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }

    fn sample<T: Debug>(strategy: &BoxedStrategy<T>, runner: &mut TestRunner) -> T {
        strategy.new_tree(runner).expect("strategy does not reject").current()
    }

    fn syscalls(forest: &MastForest) -> impl Iterator<Item = &CallNode> {
        forest.nodes().iter().filter_map(|node| match node {
            MastNode::Call(call) if call.is_syscall() => Some(call),
            _ => None,
        })
    }

    fn invocation_seeds(body_op: Operation) -> ForestSeeds {
        ForestSeeds {
            basic_blocks: vec![
                BasicBlockNode::new(vec![Operation::Noop]).expect("basic block"),
                BasicBlockNode::new(vec![body_op]).expect("implementation body"),
            ],
            join_pairs: Vec::new(),
            splits: Vec::new(),
            loop_indices: Vec::new(),
            call_picks: vec![InvocationPick {
                body: 1,
                target: ProcedureKey::new(word(100)),
            }],
            exec_picks: vec![InvocationPick {
                body: 1,
                target: ProcedureKey::new(word(200)),
            }],
            syscall_picks: vec![InvocationPick {
                body: 1,
                target: ProcedureKey::new(word(300)),
            }],
            external_picks: Vec::new(),
            dyn_selectors: Vec::new(),
            root_selection: vec![false, false, true, true, true],
        }
    }

    fn immediate_invocations(forest: &MastForest) -> BTreeSet<(u8, ProcedureKey, Word)> {
        forest
            .nodes()
            .iter()
            .filter_map(|node| match node {
                MastNode::Call(call) => {
                    Some((u8::from(call.is_syscall()), call.target(), node.digest()))
                },
                MastNode::Exec(exec) => Some((2, exec.target(), node.digest())),
                _ => None,
            })
            .collect()
    }

    fn assert_pruned(forest: &MastForest) {
        let reachable: BTreeSet<MastNodeId> = forest
            .procedure_roots()
            .iter()
            .flat_map(|root| SubtreeIterator::new(root, forest))
            .collect();
        assert_eq!(reachable.len(), forest.num_nodes() as usize);
    }

    fn executable_params() -> MastForestParams {
        MastForestParams {
            blocks: 1..=4,
            max_syscalls: 3,
            max_externals: 3,
            ..Default::default()
        }
    }

    #[test]
    fn default_params_select_executable_mode() {
        let params = MastForestParams::default();
        assert_eq!(params.mode, GenerationMode::Executable);
        assert_eq!(params.kernel_procedures, None);
        assert_eq!(
            (
                params.max_calls,
                params.max_execs,
                params.max_syscalls,
                params.max_externals,
                params.max_dyns
            ),
            (1, 1, 1, 1, 0),
        );
    }

    #[test]
    #[should_panic(expected = "kernel_procedures is invalid")]
    fn duplicate_kernel_procedures_panic() {
        let _ = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(vec![word(0), word(0)]),
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "kernel_procedures is invalid")]
    fn oversized_kernel_procedures_panic() {
        let hashes = (0..=KernelDescriptor::MAX_NUM_PROCEDURES as u32).map(word).collect();
        let _ = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(hashes),
            ..Default::default()
        });
    }

    #[test]
    fn structure_only_emits_every_node_kind() {
        let strategy = forest_kernel_strategy(MastForestParams {
            mode: GenerationMode::StructureOnly,
            max_syscalls: 3,
            max_externals: 3,
            max_dyns: 4,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        // dyn, dyncall, external, syscall, call, exec
        let mut seen = [false; 6];
        for _ in 0..256 {
            let (forest, _) = sample(&strategy, &mut runner);
            for node in forest.nodes() {
                match node {
                    MastNode::Dyn(dyn_node) => seen[usize::from(dyn_node.is_dyncall())] = true,
                    MastNode::External(_) => seen[2] = true,
                    MastNode::Call(call) if call.is_syscall() => seen[3] = true,
                    MastNode::Call(_) => seen[4] = true,
                    MastNode::Exec(_) => seen[5] = true,
                    _ => {},
                }
            }
            if seen.iter().all(|&kind| kind) {
                return;
            }
        }
        panic!("missing node kinds: {seen:?}");
    }

    #[test]
    fn kernel_descriptor_digests_do_not_select_symbolic_targets() {
        let seeds = invocation_seeds(Operation::Incr);
        let first = KernelDescriptor::from_hashes(vec![word(1), word(10)]).expect("kernel");
        let second = KernelDescriptor::from_hashes(vec![word(20)]).expect("replacement kernel");
        let (first_forest, first_descriptor) = build_structure_only_forest(&seeds, Some(&first));
        let (second_forest, second_descriptor) = build_structure_only_forest(&seeds, Some(&second));

        assert_eq!(first_descriptor, first);
        assert_eq!(second_descriptor, second);
        assert_eq!(first_forest, second_forest);
        assert_eq!(
            syscalls(&first_forest).next().expect("syscall").target(),
            ProcedureKey::new(word(300))
        );
    }

    #[test]
    fn symbolic_invocation_hashes_are_independent_of_implementation_bodies() {
        let first_seeds = invocation_seeds(Operation::Incr);
        let second_seeds = invocation_seeds(Operation::Pad);
        let first_body = first_seeds.basic_blocks[1].digest();
        let second_body = second_seeds.basic_blocks[1].digest();
        assert_ne!(first_body, second_body);

        let (first, first_kernel) = build_structure_only_forest(&first_seeds, None);
        let (second, second_kernel) = build_structure_only_forest(&second_seeds, None);
        let invocations = immediate_invocations(&first);
        assert_eq!(invocations.len(), 3);
        let targets: BTreeSet<_> =
            invocations.iter().map(|&(mode, target, _)| (mode, target)).collect();
        assert_eq!(
            targets,
            BTreeSet::from([
                (0, ProcedureKey::new(word(100))),
                (1, ProcedureKey::new(word(300))),
                (2, ProcedureKey::new(word(200))),
            ])
        );
        assert_eq!(invocations, immediate_invocations(&second));
        assert!(first_kernel.is_empty() && second_kernel.is_empty());
        for (_, target, _) in invocations {
            assert_ne!(target.into_word(), first_body);
            assert_ne!(target.into_word(), second_body);
        }
    }

    #[test]
    fn symbolic_invocation_bodies_are_explicit_procedure_roots() {
        let seeds = invocation_seeds(Operation::Incr);
        let body_digest = seeds.basic_blocks[1].digest();
        for mode in 0..3 {
            let mut one_mode = seeds.clone();
            if mode != 0 {
                one_mode.call_picks.clear();
            }
            if mode != 1 {
                one_mode.exec_picks.clear();
            }
            if mode != 2 {
                one_mode.syscall_picks.clear();
            }
            one_mode.root_selection = vec![false, false, true];
            let Skeleton { forest, node_ids, roots } = build_skeleton(&one_mode, false);
            assert!(roots.contains(&node_ids[1]), "implementation root for mode {mode}");
            let skeleton = forest.build().expect("skeleton");
            assert!(skeleton.find_procedure_root(body_digest).is_some());
        }

        let (forest, _) = build_structure_only_forest(&seeds, None);
        assert!(forest.find_procedure_root(body_digest).is_some());
        for node in forest.nodes() {
            if matches!(node, MastNode::Call(_) | MastNode::Exec(_)) {
                assert!(!node.has_children());
            }
        }
        assert_pruned(&forest);
    }

    #[test]
    fn blocks_range_lower_bound_is_respected() {
        let strategy = forest_kernel_strategy(MastForestParams {
            blocks: 4..=4,
            max_joins: 0,
            max_splits: 0,
            max_loops: 0,
            max_calls: 0,
            max_syscalls: 0,
            max_externals: 0,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        for _ in 0..16 {
            let (forest, _) = sample(&strategy, &mut runner);
            assert_eq!(forest.nodes().iter().filter(|node| node.is_basic_block()).count(), 4);
        }
    }

    proptest! {
        #[test]
        fn executable_forests_emit_only_structural_nodes(
            (forest, _) in forest_kernel_strategy(MastForestParams {
                max_calls: 6,
                max_execs: 6,
                max_syscalls: 6,
                max_dyns: 6,
                ..Default::default()
            })
        ) {
            prop_assert!(!forest.nodes().iter().any(|node| matches!(
                node, MastNode::Call(_) | MastNode::Exec(_) | MastNode::Dyn(_)
            )));
        }

        /// The plain strategy preserves the same structural execution guarantee.
        #[test]
        fn plain_executable_forests_have_no_syscalls(
            forest in any_with::<MastForest>(MastForestParams { max_syscalls: 3, ..Default::default() })
        ) {
            prop_assert!(syscalls(&forest).next().is_none());
        }

        /// Balancing never pushes an executable block past `max_ops_len`.
        #[test]
        fn executable_block_ops_respect_max_ops_len(
            (max_ops_len, ops) in (1usize..=12).prop_flat_map(|max_ops_len| {
                let params = BasicBlockNodeParams { max_ops_len, executable: true };
                (Just(max_ops_len), block_ops_strategy(&params))
            })
        ) {
            prop_assert!(!ops.is_empty() && ops.len() <= max_ops_len, "{ops:?}");
            let mut depth = 0i32;
            for op in &ops {
                depth += i32::from(stack_delta(op).unwrap_or_default());
                prop_assert!(depth >= 0, "underflow in {ops:?}");
            }
            prop_assert_eq!(depth, 0, "unbalanced {:?}", ops);
        }

        /// Blocks hold only infallible operations and leave the stack depth unchanged, except for
        /// the single-operation blocks that push a split or loop condition.
        #[test]
        fn executable_blocks_are_infallible_and_balanced(
            forest in any_with::<MastForest>(executable_params())
        ) {
            for node in forest.nodes() {
                let Some(block) = node.get_basic_block() else { continue };
                let ops: Vec<Operation> =
                    block.op_batches().iter().flat_map(OpBatch::ops).copied().collect();
                let mut depth = 0i32;
                for op in &ops {
                    let delta = stack_delta(op);
                    prop_assert!(delta.is_some(), "fallible operation {op:?}");
                    depth += i32::from(delta.unwrap_or_default());
                    prop_assert!(depth >= 0, "block underflows its entry depth: {ops:?}");
                }
                let real: Vec<Operation> =
                    ops.iter().copied().filter(|op| *op != Operation::Noop).collect();
                let pushes_condition = matches!(real[..], [Operation::Pad])
                    || matches!(real[..], [Operation::Push(value)] if value == ONE);
                prop_assert!(depth == 0 || (depth == 1 && pushes_condition), "unbalanced block {ops:?}");
            }
        }

        #[test]
        fn externals_resolve_to_a_local_root(
            forest in any_with::<MastForest>(executable_params())
        ) {
            for node in forest.nodes().iter().filter(|node| node.is_external()) {
                let target = forest.find_procedure_root(node.digest());
                prop_assert!(
                    target.is_some_and(|target| !forest[target].is_external()),
                    "external does not resolve to a local root",
                );
            }
        }

        /// Edges lead from the root containing an external to the root it resolves to.
        #[test]
        fn externals_form_a_dag(
            forest in any_with::<MastForest>(MastForestParams { max_externals: 6, ..Default::default() })
        ) {
            fn acyclic(
                node: MastNodeId,
                edges: &[(MastNodeId, MastNodeId)],
                path: &mut BTreeSet<MastNodeId>,
                done: &mut BTreeSet<MastNodeId>,
            ) -> bool {
                if done.contains(&node) {
                    return true;
                }
                if !path.insert(node) {
                    return false;
                }
                let ok = edges
                    .iter()
                    .filter(|(source, _)| *source == node)
                    .all(|&(_, target)| acyclic(target, edges, path, done));
                path.remove(&node);
                done.insert(node);
                ok
            }

            let roots = forest.procedure_roots();
            let mut edges = Vec::new();
            for (index, node) in forest.nodes().iter().enumerate() {
                if !node.is_external() {
                    continue;
                }
                let id = MastNodeId::new_unchecked(index as u32);
                let source = roots
                    .iter()
                    .copied()
                    .find(|root| SubtreeIterator::new(root, &forest).any(|reached| reached == id))
                    .expect("pruned forest");
                let target = forest.find_procedure_root(node.digest()).expect("resolvable external");
                edges.push((source, target));
            }

            let (mut path, mut done) = (BTreeSet::new(), BTreeSet::new());
            for &root in roots {
                prop_assert!(acyclic(root, &edges, &mut path, &mut done), "cycle through externals");
            }
        }

        #[test]
        fn supplied_kernel_descriptor_preserves_implementation_digests(
            (forest, kernel) in forest_kernel_strategy(MastForestParams {
                kernel_procedures: Some(vec![word(1), word(10)]),
                mode: GenerationMode::StructureOnly,
                ..Default::default()
            })
        ) {
            let listed: BTreeSet<Word> = kernel.proc_hashes().iter().copied().collect();
            prop_assert_eq!(listed, BTreeSet::from([word(1), word(10)]));
            assert_pruned(&forest);
        }

        #[test]
        fn absent_kernel_descriptor_stays_empty_for_symbolic_forests(
            (_, kernel) in forest_kernel_strategy(MastForestParams {
                mode: GenerationMode::StructureOnly,
                ..Default::default()
            })
        ) {
            prop_assert!(kernel.is_empty());
        }

        #[test]
        fn executable_forests_are_pruned(forest in any_with::<MastForest>(executable_params())) {
            assert_pruned(&forest);
        }

        #[test]
        fn structure_only_forests_are_pruned(
            forest in any_with::<MastForest>(MastForestParams {
                mode: GenerationMode::StructureOnly,
                max_syscalls: 3,
                max_externals: 3,
                max_dyns: 3,
                ..Default::default()
            })
        ) {
            assert_pruned(&forest);
        }
    }
}
