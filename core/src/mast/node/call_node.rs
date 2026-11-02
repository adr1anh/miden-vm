use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, text},
};

use super::{MastForestContributor, MastNodeContext, MastNodeExt, invocation_digest};
use crate::{
    Felt, Word,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    program::ProcedureKey,
    utils::LookupByIdx,
};

// CALL NODE
// ================================================================================================

/// A Call node describes a function call such that the callee is executed in a different execution
/// context from the currently executing code.
///
/// A call node can be of two types:
/// - A simple call: the callee is executed in the new user context.
/// - A syscall: the callee is executed in the root context.
///
/// The target is a procedure key resolved through the execution environment, not a structural
/// MAST child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    target: ProcedureKey,
    is_syscall: bool,
    digest: Word,
}

//-------------------------------------------------------------------------------------------------
/// Constants
impl CallNode {
    /// The domain of the call block (used for control block hashing).
    pub const CALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::CALL as u64);
    /// The domain of the syscall block (used for control block hashing).
    pub const SYSCALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::SYSCALL as u64);
}

//-------------------------------------------------------------------------------------------------
/// Public accessors
impl CallNode {
    /// Returns the procedure key to be invoked by this call node.
    pub fn target(&self) -> ProcedureKey {
        self.target
    }

    /// Returns true if this call node represents a syscall.
    pub fn is_syscall(&self) -> bool {
        self.is_syscall
    }

    /// Returns the domain of this call node.
    pub fn domain(&self) -> Felt {
        if self.is_syscall() {
            Self::SYSCALL_DOMAIN
        } else {
            Self::CALL_DOMAIN
        }
    }
}

// PRETTY PRINTING
// ================================================================================================

impl CallNode {
    pub(super) fn to_pretty_print<'a>(
        &'a self,
        _mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        CallNodePrettyPrint { node: self }
    }

    pub(super) fn to_display<'a>(&'a self, _mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        CallNodePrettyPrint { node: self }
    }
}

struct CallNodePrettyPrint<'a> {
    node: &'a CallNode,
}

impl PrettyPrint for CallNodePrettyPrint<'_> {
    fn render(&self) -> Document {
        let target = self.node.target.as_word();
        if self.node.is_syscall {
            const_text("syscall") + const_text(".") + text(target.as_bytes().to_hex_with_prefix())
        } else {
            const_text("call") + const_text(".") + text(target.as_bytes().to_hex_with_prefix())
        }
    }
}

impl fmt::Display for CallNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for CallNode {
    /// Returns a commitment to this Call node.
    ///
    /// The commitment is computed as a hash of the procedure key and an empty word ([ZERO; 4]) in
    /// the domain defined by either [Self::CALL_DOMAIN] or [Self::SYSCALL_DOMAIN], depending on
    /// whether the node represents a simple call or a syscall. The selected implementation's
    /// digest is not part of this commitment.
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(CallNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(CallNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {}

    fn for_each_child<F>(&self, _f: F)
    where
        F: FnMut(MastNodeId),
    {
    }

    fn domain(&self) -> Felt {
        self.domain()
    }

    type Builder = CallNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        let builder = if self.is_syscall {
            CallNodeBuilder::new_syscall(self.target)
        } else {
            CallNodeBuilder::new(self.target)
        };
        builder.with_digest(self.digest)
    }
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`CallNode`] instances.
#[derive(Debug)]
pub struct CallNodeBuilder {
    target: ProcedureKey,
    is_syscall: bool,
    digest: Option<Word>,
}

impl CallNodeBuilder {
    /// Creates a new builder for a CallNode with the specified procedure key.
    pub fn new(target: ProcedureKey) -> Self {
        Self { target, is_syscall: false, digest: None }
    }

    /// Creates a new builder for a syscall CallNode with the specified procedure key.
    pub fn new_syscall(target: ProcedureKey) -> Self {
        Self { target, is_syscall: true, digest: None }
    }

    /// Builds the CallNode.
    pub fn build(self) -> CallNode {
        let digest = self.digest.unwrap_or_else(|| {
            let domain = if self.is_syscall {
                CallNode::SYSCALL_DOMAIN
            } else {
                CallNode::CALL_DOMAIN
            };
            invocation_digest(self.target, domain)
        });

        CallNode {
            target: self.target,
            is_syscall: self.is_syscall,
            digest,
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl CallNodeBuilder {
    /// Adds this builder to a mutable forest for test and arbitrary data construction.
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build();
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for CallNodeBuilder {
    fn fingerprint_for_node(
        &self,
        _context: &impl MastNodeContext,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        Ok(self.digest.unwrap_or_else(|| {
            let domain = if self.is_syscall {
                CallNode::SYSCALL_DOMAIN
            } else {
                CallNode::CALL_DOMAIN
            };

            invocation_digest(self.target, domain)
        }))
    }

    fn remap_children(self, _remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        self
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for CallNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<Word>(), any::<bool>())
            .prop_map(|(word, is_syscall)| {
                let target = ProcedureKey::new(word);
                if is_syscall {
                    Self::new_syscall(target)
                } else {
                    Self::new(target)
                }
            })
            .boxed()
    }
}
