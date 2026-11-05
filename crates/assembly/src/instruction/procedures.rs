use alloc::vec::Vec;

use miden_assembly_syntax::{
    Word,
    ast::{InvocationTarget, InvokeKind},
    debuginfo::SourceSpan,
    diagnostics::Report,
};
use miden_core::operations::{AssemblyOp, Operation};
use miden_mast_package::debug_info::DebugSourceInlineCall;
use smallvec::SmallVec;

use crate::{
    Assembler, GlobalItemIndex,
    basic_block_builder::BasicBlockBuilder,
    mast_forest_builder::{MastForestBuilder, MastNodeUse},
};

/// Procedure Invocation
impl Assembler {
    /// Emits a retained runtime invocation using the declaration's prebound callable key.
    pub(super) fn invoke(
        &self,
        kind: InvokeKind,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        _call_site: SourceSpan,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: Option<AssemblyOp>,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let resolved = self.resolve_target(kind, callee, caller.module)?;
        match kind {
            InvokeKind::Exec => mast_forest_builder.ensure_exec_node_use(
                resolved.key,
                asm_op.expect("exec invocations must provide an AssemblyOp"),
                inline_calls,
            ),
            InvokeKind::Call | InvokeKind::SysCall => mast_forest_builder.ensure_call_node_use(
                resolved.key,
                matches!(kind, InvokeKind::SysCall),
                asm_op.expect("call and syscall invocations must provide an AssemblyOp"),
                inline_calls,
            ),
            InvokeKind::ProcRef => unreachable!("procref emits a key into its basic block"),
            InvokeKind::Inline => unreachable!("inline expands an explicitly selected body"),
        }
    }

    /// Creates a new DYN block for the dynamic code execution and return.
    pub(super) fn dynexec(
        &self,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<Option<MastNodeUse>, Report> {
        let dyn_node_ref = mast_forest_builder.ensure_dyn_node_use(false, asm_op, inline_calls)?;

        Ok(Some(dyn_node_ref))
    }

    /// Creates a new DYNCALL block for the dynamic function call and return.
    pub(super) fn dyncall(
        &self,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<Option<MastNodeUse>, Report> {
        let dyn_call_node_ref =
            mast_forest_builder.ensure_dyn_node_use(true, asm_op, inline_calls)?;

        Ok(Some(dyn_call_node_ref))
    }

    pub(super) fn procref(
        &self,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        block_builder: &mut BasicBlockBuilder,
    ) -> Result<(), Report> {
        let resolved = self.resolve_target(InvokeKind::ProcRef, callee, caller.module)?;
        self.procref_key(resolved.key.into_word(), block_builder);
        Ok(())
    }

    fn procref_key(&self, key: Word, block_builder: &mut BasicBlockBuilder) {
        // Push in reverse order so that key[0] ends up on top.
        let ops = key
            .iter()
            .rev()
            .map(|elem| Operation::Push(*elem))
            .collect::<SmallVec<[_; 4]>>();
        block_builder.push_ops(ops);
    }
}
