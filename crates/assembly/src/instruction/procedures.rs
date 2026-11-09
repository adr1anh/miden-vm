use alloc::vec::Vec;

use miden_assembly_syntax::{
    Word,
    ast::{InvocationTarget, InvokeKind},
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
    /// Lowers a static invocation according to the instruction's selected reference kind.
    pub(super) fn invoke(
        &self,
        kind: InvokeKind,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        if kind == InvokeKind::CallDigest {
            let body =
                self.resolve_digest_target(kind, callee, caller.module, mast_forest_builder)?;
            return mast_forest_builder.ensure_digest_call_node_use(body, asm_op, inline_calls);
        }

        let resolved = self.resolve_target(kind, callee, caller.module)?;
        match kind {
            InvokeKind::Exec => {
                mast_forest_builder.ensure_exec_node_use(resolved.key, asm_op, inline_calls)
            },
            InvokeKind::Call | InvokeKind::SysCall => mast_forest_builder.ensure_call_node_use(
                resolved.key,
                matches!(kind, InvokeKind::SysCall),
                asm_op,
                inline_calls,
            ),
            _ => unreachable!("only retained static invocations use this lowering"),
        }
    }

    pub(super) fn procref(
        &self,
        kind: InvokeKind,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        block_builder: &mut BasicBlockBuilder,
    ) -> Result<(), Report> {
        let reference = match (kind, callee) {
            (InvokeKind::ProcDigest, InvocationTarget::MastRoot(digest)) => digest.into_inner(),
            (InvokeKind::ProcDigest, _) => {
                let forest = block_builder.mast_forest_builder_mut();
                let body = self.resolve_digest_target(kind, callee, caller.module, forest)?;
                forest
                    .mast_root_for_ref(body.node_ref())
                    .expect("resolved digest target is in the MAST builder")
            },
            (InvokeKind::ProcRef, _) => {
                self.resolve_target(kind, callee, caller.module)?.key.into_word()
            },
            _ => unreachable!("only procedure references use this lowering"),
        };
        push_procedure_reference(reference, block_builder);
        Ok(())
    }
}

fn push_procedure_reference(reference: Word, block_builder: &mut BasicBlockBuilder) {
    // Push in reverse order so that reference[0] ends up on top.
    let ops = reference
        .iter()
        .rev()
        .map(|elem| Operation::Push(*elem))
        .collect::<SmallVec<[_; 4]>>();
    block_builder.push_ops(ops);
}
