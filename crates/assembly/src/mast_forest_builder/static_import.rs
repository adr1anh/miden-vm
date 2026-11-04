use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::fmt::Debug;

use miden_core::{
    Word,
    mast::{
        BasicBlockNode, CallNodeBuilder, ExecNodeBuilder, ExecutableMastForest, MastForest,
        MastNode, MastNodeExt, MastNodeId, SubtreeIterator,
    },
};
use miden_mast_package::debug_info::{
    DebugFunctionIdx, DebugInfoTableRemapping, DebugSourceAsmOp, DebugSourceInlineCall,
    DebugSourceNodeId, DebugSourceVar, FunctionInfo, PackageDebugInfo,
};

use super::{
    MastForestBuilder, MastNodeRef, MastNodeUse, PendingMastNodeDraft, PendingMastNodeKind,
    SourceNodeRef, remap_inline_ranges,
};
use crate::{
    GlobalItemIndex,
    diagnostics::{IntoDiagnostic, Report},
    linker::LinkLibrary,
};

#[derive(Clone, Copy)]
struct StaticSourceRoot {
    forest_idx: usize,
    source_root_id: MastNodeId,
    source_debug_root_id: Option<DebugSourceNodeId>,
}

#[derive(Clone, Copy)]
struct StaticLinkedRoot {
    root_id: MastNodeId,
    source: Option<StaticSourceRoot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum StaticInventoryKind {
    CodeOnly,
    ExactSource,
}

#[derive(Default)]
pub(super) struct StaticSourceMetadata {
    op_range: Option<(usize, usize)>,
    asm_ops: Vec<DebugSourceAsmOp>,
    debug_vars: Vec<DebugSourceVar>,
    inline_calls: Vec<DebugSourceInlineCall>,
    functions: Vec<DebugFunctionIdx>,
}

struct StaticPendingDraft {
    draft: PendingMastNodeDraft,
    source_op_range: Option<(usize, usize)>,
}

/// Result of resolving an exact static-library root provenance hint.
enum StaticRootLookup {
    /// Exactly one linked source forest maps the hinted source root to the requested digest.
    Found(StaticLinkedRoot),
    /// More than one linked source forest matches the hint, so importing by provenance would risk
    /// selecting metadata from the wrong forest.
    Ambiguous,
    /// The hint did not match any linked source forest/root pair.
    Missing,
}

impl MastForestBuilder {
    /// Remaps only explicitly supplied package occurrences whose static inventories were retained.
    /// Neither digest lookup nor a source-visible alias establishes a callable's occurrence.
    pub(crate) fn retained_static_procedure_occurrences(
        &mut self,
    ) -> Result<Vec<(miden_core::program::ProcedureKey, MastNodeRef, Option<SourceNodeRef>)>, Report>
    {
        let mut occurrences = Vec::new();
        for forest_idx in 0..self.statically_linked_source_forests.len() {
            if !self.retained_static_inventories.iter().any(|(index, _)| *index == forest_idx) {
                continue;
            }
            for occurrence in self.statically_linked_procedure_occurrences[forest_idx].clone() {
                let source_root_id = occurrence.exec_node();
                let root_id = self
                    .statically_linked_root_map
                    .map_root(forest_idx, &source_root_id)
                    .ok_or_else(|| {
                        Report::msg("static callable occurrence has no merged procedure root")
                    })?;
                let imported_source = occurrence.source_node().and_then(|source_id| {
                    self.statically_linked_source_uses.get(&(forest_idx, source_id)).copied()
                });
                let (root_use, source_ref) = if let Some(root_use) = imported_source {
                    (root_use, Some(root_use.source_ref()))
                } else {
                    let root_ref =
                        self.copy_statically_linked_subtree_contents_ref(StaticLinkedRoot {
                            root_id,
                            source: None,
                        })?;
                    let root_use = self
                        .latest_node_use(root_ref)
                        .expect("copied static code has a source occurrence");
                    // Preserve code supply without importing previously unselected source
                    // provenance just to populate optional occurrence metadata. Equal-D roots
                    // do not select another callable's source occurrence.
                    (root_use, None)
                };
                self.record_procedure_root_use(root_use);
                occurrences.push((occurrence.key(), root_use.node_ref(), source_ref));
            }
        }
        Ok(occurrences)
    }

    /// Creates a complete [`PendingMastNodeDraft`] for a node imported from a statically
    /// linked forest, including indexed assembly ops and debug variable metadata.
    fn pending_draft_for_statically_linked_source(
        &mut self,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
        source_metadata: Option<StaticSourceMetadata>,
    ) -> StaticPendingDraft {
        let digest = source_node.digest();
        let kind = PendingMastNodeKind::from_node(source_node);

        let StaticSourceMetadata {
            op_range,
            asm_ops,
            debug_vars,
            inline_calls,
            functions,
        } = source_metadata.unwrap_or_default();

        StaticPendingDraft {
            draft: PendingMastNodeDraft {
                digest,
                kind,
                child_refs,
                asm_ops,
                debug_vars,
                inline_calls,
                functions,
            },
            source_op_range: op_range,
        }
    }

    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// pending record when a new node is created.
    pub(super) fn ensure_node_from_statically_linked_source_ref(
        &mut self,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
        source_metadata: Option<StaticSourceMetadata>,
    ) -> Result<MastNodeRef, Report> {
        let source_child_refs = self.source_child_refs_for_node_refs(&child_refs);
        let child_uses = child_refs
            .into_iter()
            .zip(source_child_refs)
            .map(|(node_ref, source_ref)| MastNodeUse::new(node_ref, source_ref))
            .collect();
        Ok(self
            .ensure_node_from_statically_linked_source_use(
                source_node,
                child_uses,
                source_metadata,
            )?
            .node_ref())
    }

    /// Copies a statically linked source occurrence while preserving the exact source occurrence
    /// selected for each execution child.
    fn ensure_node_from_statically_linked_source_use(
        &mut self,
        source_node: MastNode,
        child_uses: Vec<MastNodeUse>,
        source_metadata: Option<StaticSourceMetadata>,
    ) -> Result<MastNodeUse, Report> {
        let mut expected_children = 0;
        source_node.for_each_child(|_| expected_children += 1);
        if child_uses.len() != expected_children {
            return Err(Report::msg(format!(
                "statically linked execution node has {} children, expected {expected_children}",
                child_uses.len(),
            )));
        }
        let invocation_digest = match &source_node {
            MastNode::Exec(node) => Some(ExecNodeBuilder::new(node.target()).build().digest()),
            MastNode::Call(node) => {
                let builder = if node.is_syscall() {
                    CallNodeBuilder::new_syscall(node.target())
                } else {
                    CallNodeBuilder::new(node.target())
                };
                Some(builder.build().digest())
            },
            _ => None,
        };
        if invocation_digest.is_some_and(|digest| digest != source_node.digest()) {
            return Err(Report::msg(
                "statically linked keyed invocation has a noncanonical digest",
            ));
        }
        let child_refs = child_uses.iter().copied().map(MastNodeUse::node_ref).collect();
        let source_child_refs =
            child_uses.iter().copied().map(MastNodeUse::source_ref).collect::<Vec<_>>();
        let StaticPendingDraft { draft, source_op_range } = self
            .pending_draft_for_statically_linked_source(source_node, child_refs, source_metadata);
        if draft.kind.is_external()
            && let Some(node_ref) = self.available_external_code_ref(draft.digest)?
        {
            // Record this source occurrence against the selected code's full pending identity,
            // preserving its own metadata rather than interning another D-only placeholder.
            let source_ref = self.record_static_source_occurrence(
                node_ref,
                Vec::new(),
                &draft,
                source_op_range,
            )?;
            return Ok(MastNodeUse::new(node_ref, source_ref));
        }
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        let node_ref =
            if let Some(node_ref) = self.find_reusable_node_ref_by_key(&dedup_key, &draft) {
                node_ref
            } else {
                self.insert_or_replace_pending_node_record_ref(
                    dedup_key,
                    draft.clone(),
                    &source_child_refs,
                )?
            };
        let source_ref = self.record_static_source_occurrence(
            node_ref,
            source_child_refs,
            &draft,
            source_op_range,
        )?;
        Ok(MastNodeUse::new(node_ref, source_ref))
    }

    fn record_static_source_occurrence(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceNodeRef>,
        draft: &PendingMastNodeDraft,
        source_op_range: Option<(usize, usize)>,
    ) -> Result<SourceNodeRef, Report> {
        let (op_start, op_end) =
            source_op_range.unwrap_or_else(|| self.source_op_range_for_draft(draft));
        self.record_source_occurrence_with_range(exec_ref, child_refs, draft, op_start, op_end)
    }

    fn unadjust_source_block_indices<T>(
        &self,
        source_forest: &MastForest,
        source_node_id: MastNodeId,
        mut mappings: Vec<T>,
        get_element_op_idx: impl Fn(&mut T) -> &mut u32,
    ) -> Vec<T> {
        if let Some(MastNode::Block(block)) = source_forest.get_node_by_id(source_node_id) {
            let unadjusted_indices = BasicBlockNode::unadjust_asm_op_indices(
                mappings
                    .iter_mut()
                    .map(|element| *get_element_op_idx(element) as usize)
                    .collect(),
                block.op_batches(),
            );
            for (op_idx, element) in unadjusted_indices.into_iter().zip(mappings.iter_mut()) {
                *get_element_op_idx(element) = op_idx as u32;
            }
            mappings
        } else {
            mappings
        }
    }

    /// Collects builder-local refs for a statically linked source node.
    pub(super) fn pending_refs_for_statically_linked_source(
        &self,
        node: &MastNode,
        node_refs_by_source_id: &BTreeMap<MastNodeId, MastNodeRef>,
    ) -> Vec<MastNodeRef> {
        let mut child_refs = Vec::new();
        node.for_each_child(|source_child_id| {
            let child_ref = *node_refs_by_source_id
                .get(&source_child_id)
                .expect("statically linked child must be copied before its parent");
            child_refs.push(child_ref);
        });

        child_refs
    }

    /// Adds an externally-linked procedure root and returns its builder-local [`MastNodeRef`].
    #[cfg(test)]
    pub(crate) fn ensure_external_link_with_source_ref(
        &mut self,
        mast_root: Word,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
        source_debug_root_id: Option<DebugSourceNodeId>,
    ) -> Result<MastNodeRef, Report> {
        self.ensure_external_link_with_source_use(
            mast_root,
            source_library_commitment,
            source_root_id,
            source_debug_root_id,
        )
        .map(MastNodeUse::node_ref)
    }

    /// Adds an externally-linked root, retaining its selected source occurrence independently
    /// of any other callable inventories imported while materializing its code.
    pub(crate) fn ensure_external_link_with_source_use(
        &mut self,
        mast_root: Word,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
        source_debug_root_id: Option<DebugSourceNodeId>,
    ) -> Result<MastNodeUse, Report> {
        if let Some(linked_root) = self.find_statically_linked_root(
            source_library_commitment,
            source_root_id,
            source_debug_root_id,
            mast_root,
        ) {
            return self.copy_statically_linked_subtree_use(linked_root);
        }

        let draft = PendingMastNodeDraft::new(PendingMastNodeKind::External, mast_root, Vec::new());
        if let Some(node_ref) = self.available_external_code_ref(mast_root)? {
            // Availability is independent of the richer full interning key. Normalize the
            // boundary against this selected node's own source data, never a same-D variant's.
            let source_ref = self.record_source_occurrence(node_ref, Vec::new(), &draft)?;
            return Ok(MastNodeUse::new(node_ref, source_ref));
        }
        self.intern_pending_node_use(draft, Vec::new())
    }

    /// Selects structural External(D) code independently of full-key interning and procedure keys.
    /// A concrete merged-static provider takes precedence; otherwise reuse the first locally
    /// materialized concrete node. Provider selection alone never chooses diagnostic provenance.
    fn available_external_code_ref(
        &mut self,
        mast_root: Word,
    ) -> Result<Option<MastNodeRef>, Report> {
        if let Some(root_id) = self.statically_linked_mast.find_procedure_root(mast_root)
            && !self.statically_linked_mast[root_id].is_external()
        {
            return self
                .copy_statically_linked_subtree_contents_ref(StaticLinkedRoot {
                    root_id,
                    source: None,
                })
                .map(Some);
        }
        Ok(self.concrete_node_ref_by_digest.get(&mast_root).copied())
    }

    fn find_statically_linked_root(
        &self,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
        source_debug_root_id: Option<DebugSourceNodeId>,
        mast_root: Word,
    ) -> Option<StaticLinkedRoot> {
        if let (Some(source_library_commitment), Some(source_root_id)) =
            (source_library_commitment, source_root_id)
        {
            match self.find_exact_statically_linked_root(
                source_library_commitment,
                source_root_id,
                source_debug_root_id,
                mast_root,
            ) {
                StaticRootLookup::Found(linked_root) => return Some(linked_root),
                // `MastForest::commitment()` does not include diagnostics metadata, so multiple
                // source forests can share a commitment while still carrying different metadata.
                // In that case we drop the source hint and fall back to digest-only linking.
                StaticRootLookup::Ambiguous => {},
                StaticRootLookup::Missing => {},
            }
        }

        self.statically_linked_mast
            .find_procedure_root(mast_root)
            .map(|root_id| StaticLinkedRoot { root_id, source: None })
    }

    fn find_exact_statically_linked_root(
        &self,
        source_library_commitment: Word,
        source_root_id: MastNodeId,
        source_debug_root_id: Option<DebugSourceNodeId>,
        mast_root: Word,
    ) -> StaticRootLookup {
        let Some(forest_indices) = self
            .statically_linked_forest_indices_by_commitment
            .get(&source_library_commitment)
        else {
            return StaticRootLookup::Missing;
        };

        let mut matching_roots = forest_indices.iter().filter_map(|forest_idx| {
            self.statically_linked_root_map.map_root(*forest_idx, &source_root_id).and_then(
                |root_id| {
                    (self.statically_linked_mast[root_id].digest() == mast_root).then_some(
                        StaticLinkedRoot {
                            root_id,
                            source: Some(StaticSourceRoot {
                                forest_idx: *forest_idx,
                                source_root_id,
                                source_debug_root_id,
                            }),
                        },
                    )
                },
            )
        });

        let Some(linked_root) = matching_roots.next() else {
            return StaticRootLookup::Missing;
        };

        if matching_roots.next().is_some() {
            StaticRootLookup::Ambiguous
        } else {
            StaticRootLookup::Found(linked_root)
        }
    }

    /// Copies the selected subtree and retains the supplied independently callable code
    /// inventories.
    fn copy_statically_linked_subtree_use(
        &mut self,
        linked_root: StaticLinkedRoot,
    ) -> Result<MastNodeUse, Report> {
        let root_ref = self.copy_statically_linked_subtree_contents_ref(linked_root)?;
        let root_use = self
            .latest_node_use(root_ref)
            .expect("an imported execution root must have a source occurrence");
        self.record_procedure_root_use(root_use);
        self.retain_statically_linked_inventory(linked_root, root_ref)?;
        Ok(root_use)
    }

    /// Retains all explicitly supplied static inventories, independently of structural or keyed
    /// edges.
    fn retain_statically_linked_inventory(
        &mut self,
        linked_root: StaticLinkedRoot,
        imported_root: MastNodeRef,
    ) -> Result<(), Report> {
        // Merging can resolve a structural External(D) using any supplied static forest. Retain
        // their complete callable inventories so a resolved implementation's private roots remain
        // available, without inferring dependencies or bindings from immediate procedure keys.
        for forest_idx in 0..self.statically_linked_source_forests.len() {
            // Only an exact source hint selects diagnostic provenance. All other inventories are
            // code supply, including those whose roots satisfy merged structural externals.
            let kind = if linked_root.source.is_some_and(|source| source.forest_idx == forest_idx) {
                StaticInventoryKind::ExactSource
            } else {
                StaticInventoryKind::CodeOnly
            };
            if self.retained_static_inventories.contains(&(forest_idx, kind))
                || (kind == StaticInventoryKind::CodeOnly
                    && self
                        .retained_static_inventories
                        .contains(&(forest_idx, StaticInventoryKind::ExactSource)))
            {
                continue;
            }
            let source_forest = Arc::clone(&self.statically_linked_source_forests[forest_idx]);
            for &source_root_id in source_forest.procedure_roots() {
                let root_id = self
                    .statically_linked_root_map
                    .map_root(forest_idx, &source_root_id)
                    .expect("every source procedure root must have a merged root");
                if root_id == linked_root.root_id
                    && (!self.nodes[imported_root].kind.is_external()
                        || source_forest[source_root_id].is_external())
                {
                    // Reuse a concrete requested occurrence. An exact-source External(D) still
                    // needs its concrete provider imported through the interner, even when both
                    // original roots map to this same merged ID.
                    continue;
                }
                let source_roots = if kind == StaticInventoryKind::ExactSource {
                    self.statically_linked_package_debug_info[forest_idx]
                        .as_ref()
                        .map(|debug| {
                            debug
                                .source_roots_for_exec_node(source_root_id)
                                .map(|(source_id, _)| Some(source_id))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let source_roots = if source_roots.is_empty() {
                    vec![None]
                } else {
                    source_roots
                };
                for source_debug_root_id in source_roots {
                    let source =
                        (kind == StaticInventoryKind::ExactSource).then_some(StaticSourceRoot {
                            forest_idx,
                            source_root_id,
                            source_debug_root_id,
                        });
                    // Copying contents never starts another inventory import, so this loop is not
                    // reentrant. Interning still reuses execution nodes shared by multiple roots.
                    let root_ref =
                        self.copy_statically_linked_subtree_contents_ref(StaticLinkedRoot {
                            root_id,
                            source,
                        })?;
                    let root_use = self
                        .latest_node_use(root_ref)
                        .expect("an imported execution root must have a source occurrence");
                    self.record_procedure_root_use(root_use);
                }
            }
            // Partial imports can leave interned nodes behind, but must remain retryable. Only a
            // completed inventory is cached; a later exact import may still add its source data.
            self.retained_static_inventories.insert((forest_idx, kind));
        }
        Ok(())
    }

    /// Copies one structural subtree without discovering or retaining other callable roots.
    fn copy_statically_linked_subtree_contents_ref(
        &mut self,
        linked_root: StaticLinkedRoot,
    ) -> Result<MastNodeRef, Report> {
        if let Some(source) = linked_root.source
            && let Some(package_debug_info) = self
                .statically_linked_package_debug_info
                .get(source.forest_idx)
                .cloned()
                .flatten()
            && let Some(source_forest) =
                self.statically_linked_source_forests.get(source.forest_idx)
        {
            let source_forest = Arc::clone(source_forest);
            let source_debug_root_id =
                if let Some(source_debug_root_id) = source.source_debug_root_id {
                    Some(source_debug_root_id)
                } else {
                    package_debug_info
                    .unique_source_root_for_exec_node(source.source_root_id)
                    .map_err(|err| {
                        Report::msg(format!(
                            "ambiguous statically linked source root for {source_root_id:?}: {err}",
                            source_root_id = source.source_root_id
                        ))
                    })?
                };
            if let Some(source_debug_root_id) = source_debug_root_id {
                let source_node =
                    package_debug_info.source_node(source_debug_root_id).ok_or_else(|| {
                        Report::msg(format!(
                            "statically linked package export references missing source node {source_debug_root_id:?}"
                        ))
                    })?;
                if source_node.exec_node != source.source_root_id {
                    return Err(Report::msg(format!(
                        "statically linked package export source node {source_debug_root_id:?} maps to {:?}, expected {:?}",
                        source_node.exec_node, source.source_root_id
                    )));
                }
                let tables =
                    self.import_static_debug_tables(source.forest_idx, &package_debug_info)?;
                let root_use = self.copy_package_debug_source_subtree_use(
                    source.forest_idx,
                    source_forest.as_ref(),
                    &package_debug_info,
                    &tables,
                    source_debug_root_id,
                )?;
                self.latest_source_ref_by_node_ref
                    .insert(root_use.node_ref(), root_use.source_ref());
                return Ok(root_use.node_ref());
            }
        }

        let mut node_refs_by_source_id = BTreeMap::new();
        let source_forest = Arc::clone(&self.statically_linked_mast);
        for old_id in SubtreeIterator::new(&linked_root.root_id, source_forest.as_ref()) {
            let node = self.statically_linked_mast[old_id].clone();
            let child_refs =
                self.pending_refs_for_statically_linked_source(&node, &node_refs_by_source_id);
            let new_ref =
                self.ensure_node_from_statically_linked_source_ref(node, child_refs, None)?;
            node_refs_by_source_id.insert(old_id, new_ref);
        }
        Ok(*node_refs_by_source_id
            .get(&linked_root.root_id)
            .expect("statically linked subtree root must be copied"))
    }

    /// Import the declared function from the exact dependency, never from a digest alias.
    /// Dynamic imports retain declaration/type/root data without claiming a local definition.
    pub(crate) fn import_procedure_function(
        &mut self,
        gid: GlobalItemIndex,
        library_id: Word,
        library: &LinkLibrary,
        path: &miden_assembly_syntax::Path,
        source_node: Option<DebugSourceNodeId>,
        mast_root: Word,
    ) -> Result<Option<DebugFunctionIdx>, Report> {
        if !self.imported_debug_tables.contains_key(&library_id) {
            let imported = if let Some(debug) = library.package().debug_info().into_diagnostic()? {
                let static_index = self
                    .statically_linked_forest_indices_by_commitment
                    .get(&library_id)
                    .and_then(|indices| {
                        indices.iter().copied().find(|&index| {
                            self.statically_linked_package_debug_info[index].as_ref()
                                == Some(&debug)
                        })
                    });
                let tables = if let Some(index) = static_index {
                    self.import_static_debug_tables(index, &debug)?
                } else {
                    Arc::new(debug.merge_tables_into(&mut self.debug_info).map_err(|error| {
                        Report::msg(format!("failed to import procedure debug tables: {error}"))
                    })?)
                };
                Some((debug, tables))
            } else {
                None
            };
            self.imported_debug_tables.insert(library_id, imported);
        }
        let Some((debug, tables)) = self.imported_debug_tables[&library_id].as_ref() else {
            return Ok(None);
        };
        // An external export occurrence is an invocation boundary, not a local definition.
        // Such declarations are identified by their exported linkage name below.
        let source_node =
            source_node.filter(|source| !library.mast()[debug[*source].exec_node].is_external());
        let matches_name = |function: &FunctionInfo<DebugSourceNodeId>| {
            let name = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
            debug[name].as_ref() == path.as_str()
        };
        let candidates = debug.functions().iter().enumerate().filter(|(_, function)| {
            function.mast_root == mast_root
                && source_node
                    .is_none_or(|source| function.source_node.into_option() == Some(source))
        });
        // Prefer the declared path. Re-exports may only have a function for the defining path,
        // so fall back to the export's exact source occurrence, never to its digest alone.
        let require_name =
            source_node.is_none() || candidates.clone().any(|(_, function)| matches_name(function));
        let mut matches =
            candidates.filter(|(_, function)| !require_name || matches_name(function));
        let Some((index, _)) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            log::warn!(
                target: "assembler::import_procedure_function",
                "ambiguous debug declarations for {path} in library {} ({library_id}); omitting exec inline-call frame",
                library.package().name,
            );
            return Ok(None);
        }
        let index = tables
            .function(DebugFunctionIdx::from(index as u32))
            .expect("imported function must have a table mapping");
        self.procedure_function_indices.insert(gid, index);
        Ok(Some(index))
    }

    pub(super) fn import_static_debug_tables(
        &mut self,
        forest_idx: usize,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Arc<DebugInfoTableRemapping>, Report> {
        let slot = self
            .statically_linked_debug_table_remappings
            .get_mut(forest_idx)
            .expect("static debug table mappings must remain parallel to static libraries");
        if let Some(tables) = slot.as_ref() {
            return Ok(Arc::clone(tables));
        }

        let tables = Arc::new(package_debug_info.merge_tables_into(&mut self.debug_info).map_err(
            |error| {
                Report::msg(format!("failed to import statically linked debug tables: {error}"))
            },
        )?);
        *slot = Some(Arc::clone(&tables));
        Ok(tables)
    }

    fn copy_package_debug_source_subtree_use(
        &mut self,
        forest_idx: usize,
        source_forest: &MastForest,
        package_debug_info: &PackageDebugInfo,
        tables: &DebugInfoTableRemapping,
        source_root_id: DebugSourceNodeId,
    ) -> Result<MastNodeUse, Report> {
        let mut node_uses_by_source_id = BTreeMap::new();
        let mut pending = vec![(source_root_id, false)];

        while let Some((source_node_id, children_copied)) = pending.pop() {
            if node_uses_by_source_id.contains_key(&source_node_id) {
                continue;
            }
            if let Some(node_use) =
                self.statically_linked_source_uses.get(&(forest_idx, source_node_id))
            {
                node_uses_by_source_id.insert(source_node_id, *node_use);
                continue;
            }

            let source_node = package_debug_info.source_node(source_node_id).ok_or_else(|| {
                Report::msg(format!(
                    "statically linked package debug graph is missing source node {source_node_id:?}"
                ))
            })?;
            let source_exec_node_id = source_node.exec_node;
            let source_exec_node = source_forest
                .get_node_by_id(source_exec_node_id)
                .ok_or_else(|| {
                    Report::msg(format!(
                        "statically linked package debug graph references missing execution node {source_exec_node_id:?}"
                    ))
                })?
                .clone();
            let mut exec_child_ids = Vec::new();
            source_exec_node.for_each_child(|child_id| exec_child_ids.push(child_id));
            if exec_child_ids.len() != source_node.children.len() {
                return Err(Report::msg(format!(
                    "statically linked package debug source node {source_node_id:?} has {} children, expected {} from execution node {source_exec_node_id:?}",
                    source_node.children.len(),
                    exec_child_ids.len(),
                )));
            }
            for (child_index, child_source_node_id) in
                source_node.children.iter().copied().enumerate()
            {
                let child_source_node = package_debug_info
                    .source_node(child_source_node_id)
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "statically linked package debug graph source node {source_node_id:?} references missing child source node {child_source_node_id:?}"
                        ))
                    })?;
                if child_source_node.exec_node != exec_child_ids[child_index] {
                    return Err(Report::msg(format!(
                        "statically linked package debug graph source node {source_node_id:?} child {child_index} maps to {:?}, expected {:?}",
                        child_source_node.exec_node, exec_child_ids[child_index],
                    )));
                }
            }

            if !children_copied {
                pending.push((source_node_id, true));
                pending.extend(
                    source_node
                        .children
                        .iter()
                        .rev()
                        .copied()
                        .filter(|child_id| !node_uses_by_source_id.contains_key(child_id))
                        .map(|child_id| (child_id, false)),
                );
                continue;
            }

            let child_uses = source_node
                .children
                .iter()
                .map(|child_id| {
                    node_uses_by_source_id
                        .get(child_id)
                        .copied()
                        .expect("source child must be copied before its parent")
                })
                .collect();
            let metadata = self.package_source_metadata(
                source_forest,
                package_debug_info,
                tables,
                source_node_id,
                source_exec_node_id,
            )?;
            let node_use = self.ensure_node_from_statically_linked_source_use(
                source_exec_node,
                child_uses,
                Some(metadata),
            )?;
            node_uses_by_source_id.insert(source_node_id, node_use);
        }

        // Inline invocation copies do not own function definitions. Import canonical source
        // trees whose execution nodes are already present, without linking any additional code.
        // If merging later prunes those execution nodes, finalization leaves the declaration's
        // source_node absent rather than attributing the definition to a caller's aggregate.
        self.copy_available_function_sources(
            forest_idx,
            source_forest,
            package_debug_info,
            tables,
            &node_uses_by_source_id,
        )?;
        Ok(node_uses_by_source_id[&source_root_id])
    }

    fn copy_available_function_sources(
        &mut self,
        forest_idx: usize,
        source_forest: &MastForest,
        debug: &PackageDebugInfo,
        tables: &DebugInfoTableRemapping,
        node_uses: &BTreeMap<DebugSourceNodeId, MastNodeUse>,
    ) -> Result<(), Report> {
        let exec_refs = node_uses
            .iter()
            .map(|(source, node_use)| (debug[*source].exec_node, node_use.node_ref()))
            .collect::<BTreeMap<_, _>>();
        let mut source_refs = node_uses
            .iter()
            .map(|(source, node_use)| (*source, node_use.source_ref()))
            .collect::<BTreeMap<_, _>>();
        let callees = node_uses
            .keys()
            .flat_map(|source| debug[*source].inline_calls.iter().map(|row| row.callee_idx))
            .collect::<BTreeSet<_>>();
        for index in callees {
            let function = debug.get_function(index).expect("inline function must exist");
            let Some(root) = function.source_node.into_option() else {
                continue;
            };
            let function_index =
                tables.function(index).expect("imported function must have a mapping");
            if self.debug_info[function_index].source_node.into_option().is_some() {
                continue;
            }
            let mut pending = vec![(root, false)];
            let mut ordered = Vec::new();
            let mut visited = BTreeSet::new();
            let mut available = true;
            while let Some((source, expanded)) = pending.pop() {
                if source_refs.contains_key(&source) {
                    continue;
                }
                let node = &debug[source];
                if !exec_refs.contains_key(&node.exec_node) {
                    available = false;
                    break;
                }
                if expanded {
                    ordered.push(source);
                } else if visited.insert(source) {
                    pending.push((source, true));
                    pending.extend(node.children.iter().rev().map(|child| (*child, false)));
                }
            }
            if !available {
                continue;
            }
            for source in ordered {
                let node = &debug[source];
                let metadata = self.package_source_metadata(
                    source_forest,
                    debug,
                    tables,
                    source,
                    node.exec_node,
                )?;
                let (start, end) =
                    metadata.op_range.expect("package source has an operation range");
                let source_ref = self.push_source_occurrence(
                    exec_refs[&node.exec_node],
                    node.children.iter().map(|child| source_refs[child]).collect(),
                    start,
                    end,
                    metadata.asm_ops,
                    metadata.debug_vars,
                    metadata.inline_calls,
                    &metadata.functions,
                    source_forest[node.exec_node].is_external(),
                    false,
                )?;
                source_refs.insert(source, source_ref);
            }
        }
        for (source, source_ref) in source_refs {
            self.statically_linked_source_uses.insert(
                (forest_idx, source),
                MastNodeUse::new(exec_refs[&debug[source].exec_node], source_ref),
            );
        }
        Ok(())
    }

    fn package_source_metadata(
        &mut self,
        source_forest: &MastForest,
        package_debug_info: &PackageDebugInfo,
        tables: &DebugInfoTableRemapping,
        source_node_id: DebugSourceNodeId,
        source_exec_node_id: MastNodeId,
    ) -> Result<StaticSourceMetadata, Report> {
        let asm_ops = package_debug_info
            .asm_ops_for_source_node(source_node_id)
            .map(|row| {
                let location_idx = row
                    .location_idx
                    .into_option()
                    .map(|index| remapped_debug_index(tables.location(index), index, "location"))
                    .transpose()?;
                let context_name_idx = remapped_debug_index(
                    tables.string(row.context_name_idx),
                    row.context_name_idx,
                    "string",
                )?;
                let op_name_idx = remapped_debug_index(
                    tables.string(row.op_name_idx),
                    row.op_name_idx,
                    "string",
                )?;
                Ok(DebugSourceAsmOp::new(
                    row.op_idx,
                    location_idx,
                    context_name_idx,
                    op_name_idx,
                    row.num_cycles,
                ))
            })
            .collect::<Result<Vec<_>, Report>>()?;
        let debug_vars = package_debug_info
            .debug_vars_for_source_node(source_node_id)
            .map(|row| {
                let name_idx =
                    remapped_debug_index(tables.string(row.name_idx), row.name_idx, "string")?;
                let location_idx = row
                    .location_idx
                    .map(|index| remapped_debug_index(tables.location(index), index, "location"))
                    .transpose()?;
                let type_id = row
                    .type_id
                    .map(|index| remapped_debug_index(tables.ty(index), index, "type"))
                    .transpose()?;
                Ok(DebugSourceVar {
                    op_idx: row.op_idx,
                    name_idx,
                    type_id,
                    arg_idx: row.arg_idx,
                    location_idx,
                    value_location: row.value_location.clone(),
                })
            })
            .collect::<Result<Vec<_>, Report>>()?;
        let mut inline_calls = package_debug_info
            .inline_calls_for_source_node(source_node_id)
            .map(|row| {
                let loc_idx =
                    remapped_debug_index(tables.location(row.loc_idx), row.loc_idx, "location")?;
                let callee_idx = remapped_debug_index(
                    tables.function(row.callee_idx),
                    row.callee_idx,
                    "function",
                )?;
                Ok(DebugSourceInlineCall {
                    op_idx: row.op_idx,
                    op_end: row.op_end,
                    callee_idx,
                    loc_idx,
                })
            })
            .collect::<Result<Vec<_>, Report>>()?;
        remap_inline_ranges(&mut inline_calls, |endpoints| {
            if let Some(MastNode::Block(block)) = source_forest.get_node_by_id(source_exec_node_id)
            {
                BasicBlockNode::unadjust_asm_op_indices(endpoints, block.op_batches())
            } else {
                endpoints
            }
        });
        let op_range = package_debug_info.source_node(source_node_id).map(|source_node| {
            self.unadjust_source_block_range(
                source_forest,
                source_exec_node_id,
                source_node.op_start as usize,
                source_node.op_end as usize,
            )
        });

        let functions = package_debug_info
            .functions()
            .iter()
            .enumerate()
            .filter_map(|(index, function)| {
                let function_source_node = function.source_node.into_option();
                if function_source_node == Some(source_node_id) {
                    let function_index = DebugFunctionIdx::from(
                        u32::try_from(index).expect("invalid function index"),
                    );
                    tables.function(function_index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(StaticSourceMetadata {
            op_range,
            asm_ops: self.unadjust_source_block_indices(
                source_forest,
                source_exec_node_id,
                asm_ops,
                |asm_op| &mut asm_op.op_idx,
            ),
            debug_vars: self.unadjust_source_block_indices(
                source_forest,
                source_exec_node_id,
                debug_vars,
                |debug_var| &mut debug_var.op_idx,
            ),
            inline_calls,
            functions,
        })
    }

    fn unadjust_source_block_range(
        &self,
        source_forest: &MastForest,
        source_node_id: MastNodeId,
        op_start: usize,
        op_end: usize,
    ) -> (usize, usize) {
        if op_start == op_end {
            return (op_start, op_end);
        }

        if let Some(MastNode::Block(block)) = source_forest.get_node_by_id(source_node_id) {
            let unadjusted_indices = BasicBlockNode::unadjust_asm_op_indices(
                vec![op_start, op_end - 1],
                block.op_batches(),
            );
            (unadjusted_indices[0], unadjusted_indices[1] + 1)
        } else {
            (op_start, op_end)
        }
    }
}

fn remapped_debug_index<I: Debug, T>(
    mapped: Option<T>,
    index: I,
    table: &str,
) -> Result<T, Report> {
    mapped.ok_or_else(|| {
        Report::msg(format!(
            "statically linked debug info references missing {table} index {index:?}"
        ))
    })
}
