use alloc::{sync::Arc, vec, vec::Vec};
use core::cell::Cell;

use miden_core::{
    Felt, ONE, Word, ZERO,
    advice::AdviceMap,
    crypto::merkle::MerkleStore,
    mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest, MastNodeExt, MastNodeId},
    operations::Operation,
    program::StackInputs,
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_mast_package::{
    PackageDebugInfoError,
    debug_info::{DebugSourceNode, PackageDebugInfoBuilder},
};

use super::FastProcessor;
use crate::{
    BaseHost, ExecutionError, ExecutionOptions, LoadedMastForest, ProcessorState, SyncHost,
    advice::{AdviceError, AdviceMutation},
    event::EventError,
    operation::OperationError,
};

struct LoadedHost {
    loaded: LoadedMastForest,
    lookups: Cell<usize>,
}

impl LoadedHost {
    fn new(loaded: LoadedMastForest) -> Self {
        Self { loaded, lookups: Cell::new(0) }
    }
}

impl BaseHost for LoadedHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for LoadedHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        self.lookups.set(self.lookups.get() + 1);
        Some(self.loaded.clone())
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

fn two_root_forest(advice_map: AdviceMap) -> (Arc<MastForest>, [MastNodeId; 2]) {
    let mut forest = MastForest::new();
    let first = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::Incr])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(first);
    forest.make_root(second);
    (Arc::new(forest.with_advice_map(advice_map)), [first, second])
}

fn source_node(exec_node: MastNodeId) -> DebugSourceNode {
    DebugSourceNode {
        exec_node,
        children: Vec::new(),
        op_start: 0,
        op_end: 1,
        asm_ops: Vec::new(),
        debug_vars: Vec::new(),
        inline_calls: Vec::new(),
    }
}

fn assert_unpublished(processor: &FastProcessor) {
    assert!(processor.loaded_mast_forests.is_empty());
    assert!(processor.merged_mast_forests.is_empty());
    assert!(processor.advice.map().is_empty());
}

#[test]
fn requested_digest_must_materialize_an_exact_local_procedure_root() {
    let (forest, roots) = two_root_forest(AdviceMap::default());
    let requested = forest[roots[0]].digest();
    let wrong_digest = Word::from([ONE; 4]);

    let mut unrooted_forest = (*forest).clone();
    let unrooted = BasicBlockNodeBuilder::new(vec![Operation::Push(ONE)])
        .add_to_forest(&mut unrooted_forest)
        .unwrap();
    let unrooted_digest = unrooted_forest[unrooted].digest();

    let mut external_forest = MastForest::new();
    let external = ExternalNodeBuilder::new(requested).add_to_forest(&mut external_forest).unwrap();
    external_forest.make_root(external);

    for (forest, requested) in [
        (forest, wrong_digest),
        (Arc::new(unrooted_forest), unrooted_digest),
        (Arc::new(external_forest), requested),
    ] {
        let mut processor = FastProcessor::new(StackInputs::default());
        let mut host = LoadedHost::new(LoadedMastForest::new(forest));
        let err = processor
            .load_mast_forest_sync(requested, &mut host, None, None, false)
            .unwrap_err();
        assert!(matches!(
            err,
            ExecutionError::OperationError {
                err: OperationError::MalformedMastForestInHost { root_digest },
                ..
            } if root_digest == requested
        ));
        assert_unpublished(&processor);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_loaded_debug_fails_before_publication_and_plain_loading_ignores_it() {
    let key = Word::from([ONE, ZERO, ZERO, ZERO]);
    let (forest, roots) = two_root_forest(AdviceMap::from_iter([(key, vec![ONE])]));
    let requested = forest[roots[1]].digest();
    let loaded = LoadedMastForest::with_package_debug_info(
        forest.clone(),
        Err(PackageDebugInfoError::UntrustedSections),
    );
    let mut host = LoadedHost::new(loaded);
    let mut processor = FastProcessor::new(StackInputs::default());

    let err = processor
        .load_mast_forest(requested, &mut host, None, None, true)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::Internal("loaded package debug info is malformed")
    ));
    assert_unpublished(&processor);

    let (root_id, loaded_forest, debug_info, source_id) = processor
        .load_mast_forest(requested, &mut host, None, None, false)
        .await
        .unwrap();
    assert_eq!(host.lookups.get(), 2);
    assert_eq!(root_id, roots[1]);
    assert!(Arc::ptr_eq(&loaded_forest, &forest));
    assert!(debug_info.is_none());
    assert!(source_id.is_none());
    assert_eq!(processor.loaded_mast_forests.len(), 2);
    assert_eq!(processor.merged_mast_forests.len(), 1);
    assert_eq!(processor.advice.get_mapped_values(&key), Some([ONE].as_slice()));
}

#[test]
fn preparation_resolves_actual_package_root_and_keeps_ambiguous_source_optional() {
    let mut forest = MastForest::new();
    let first = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    let requested_root = BasicBlockNodeBuilder::new(vec![Operation::Incr])
        .add_to_forest(&mut forest)
        .unwrap();
    let roots = [first, requested_root];
    let requested = forest[requested_root].digest();
    let external = ExternalNodeBuilder::new(requested).add_to_forest(&mut forest).unwrap();
    // The external marker appears first: resolution must still select the actual local body.
    forest.make_root(external);
    forest.make_root(first);
    forest.make_root(requested_root);
    let forest = Arc::new(forest);
    let mut debug = PackageDebugInfoBuilder::default();
    let first_source = debug.add_node(source_node(roots[0])).unwrap();
    let requested_source = debug.add_node(source_node(roots[1])).unwrap();
    debug.add_root(first_source);
    debug.add_root(requested_source);

    for ambiguous in [false, true] {
        if ambiguous {
            let other_source = debug.add_node(source_node(roots[1])).unwrap();
            debug.add_root(other_source);
        }
        let loaded = LoadedMastForest::with_package_debug_info(
            forest.clone(),
            Ok(Some(*debug.clone().build())),
        );
        let debug_owner = loaded.package_debug_info().unwrap().unwrap();
        let host = LoadedHost::new(loaded.clone());
        let prepared =
            FastProcessor::prepare_loaded_target(loaded, requested, true, None, None, true, &host)
                .unwrap();
        assert_eq!(prepared.root_id, roots[1]);
        assert!(Arc::ptr_eq(prepared.package_debug_info.as_ref().unwrap(), &debug_owner));
        assert_eq!(prepared.source_node_id, (!ambiguous).then_some(requested_source));
        assert_eq!(host.lookups.get(), 0);
    }
}

#[test]
fn advice_conflicts_and_budgets_leave_cache_map_and_merge_markers_unchanged() {
    let existing_key = Word::from([ONE; 4]);
    let new_key = Word::from([ZERO; 4]);
    let entry_bytes = Word::SERIALIZED_SIZE + size_of::<Felt>();
    let base_bytes = MerkleStore::default().num_internal_nodes() * 3 * Word::SERIALIZED_SIZE;

    for budget_failure in [false, true] {
        let options = if budget_failure {
            ExecutionOptions::default().with_max_advice_size_bytes(base_bytes + entry_bytes)
        } else {
            ExecutionOptions::default()
        };
        let mut processor =
            FastProcessor::new(StackInputs::default()).with_options(options).unwrap();
        let mut seed_forest = MastForest::new();
        let seed_root = BasicBlockNodeBuilder::new(vec![Operation::Push(ONE)])
            .add_to_forest(&mut seed_forest)
            .unwrap();
        seed_forest.make_root(seed_root);
        let seed_digest = seed_forest[seed_root].digest();
        let seed_forest = Arc::new(
            seed_forest.with_advice_map(AdviceMap::from_iter([(existing_key, vec![ONE])])),
        );
        let mut seed_host = LoadedHost::new(LoadedMastForest::new(seed_forest.clone()));
        processor
            .load_mast_forest_sync(seed_digest, &mut seed_host, None, None, false)
            .unwrap();
        let before_map = processor.advice.map().clone();
        let before_markers = processor.merged_mast_forests.clone();

        let mut target_advice = AdviceMap::from_iter([(new_key, vec![ONE])]);
        if !budget_failure {
            target_advice.insert(existing_key, vec![ZERO]);
        }
        let (target_forest, roots) = two_root_forest(target_advice);
        let requested = target_forest[roots[1]].digest();
        let mut target_host = LoadedHost::new(LoadedMastForest::new(target_forest));
        let err = processor
            .load_mast_forest_sync(requested, &mut target_host, None, None, false)
            .unwrap_err();
        match (budget_failure, err) {
            (
                true,
                ExecutionError::AdviceError {
                    err: AdviceError::SizeBudgetExceeded { .. },
                    ..
                },
            )
            | (
                false,
                ExecutionError::AdviceError {
                    err: AdviceError::MapKeyAlreadyPresent { .. },
                    ..
                },
            ) => {},
            (_, err) => panic!("unexpected advice preflight error: {err:?}"),
        }
        assert_eq!(processor.advice.map(), &before_map);
        assert_eq!(processor.merged_mast_forests, before_markers);
        assert_eq!(processor.loaded_mast_forests.len(), 1);
        let cached = processor.loaded_mast_forests.get(&seed_digest).unwrap();
        assert!(Arc::ptr_eq(cached.mast_forest(), &seed_forest));
        assert!(!processor.loaded_mast_forests.contains_key(&requested));
    }
}

#[test]
fn successful_loading_caches_all_local_roots_and_merges_advice_once() {
    let key = Word::from([ONE, ZERO, ZERO, ZERO]);
    let (forest, roots) = two_root_forest(AdviceMap::from_iter([(key, vec![ONE])]));
    let digests = roots.map(|root| forest[root].digest());
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut host = LoadedHost::new(LoadedMastForest::new(forest.clone()));

    processor
        .load_mast_forest_sync(digests[0], &mut host, None, None, false)
        .unwrap();
    // A later VM-computed replacement must survive subsequent loads of the same forest.
    processor.advice.replace_into_map(key, vec![ZERO]).unwrap();
    let (root_id, loaded_forest, ..) = processor
        .load_mast_forest_sync(digests[1], &mut host, None, None, false)
        .unwrap();

    assert_eq!(root_id, roots[1]);
    assert!(Arc::ptr_eq(&loaded_forest, &forest));
    assert_eq!(host.lookups.get(), 1);
    assert_eq!(processor.loaded_mast_forests.len(), 2);
    assert!(digests.iter().all(|digest| processor.loaded_mast_forests.contains_key(digest)));
    assert_eq!(processor.merged_mast_forests.len(), 1);
    assert!(processor.merged_mast_forests.contains(&forest.commitment()));
    assert_eq!(processor.advice.get_mapped_values(&key), Some([ZERO].as_slice()));
}
