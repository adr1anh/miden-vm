use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, text},
};

use super::{
    MastForestContributor, MastNodeContext, MastNodeExt, digest_invocation_digest,
    fingerprint_with_child_fingerprints, invocation_digest,
};
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
/// A procedure key is resolved through the execution environment. A digest-target call instead
/// has a structural MAST child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    target: CallTarget,
    digest: Word,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallTarget {
    Key(ProcedureKey),
    Syscall(ProcedureKey),
    Digest(MastNodeId),
}

impl CallTarget {
    fn domain(self) -> Felt {
        match self {
            Self::Syscall(_) => CallNode::SYSCALL_DOMAIN,
            _ => CallNode::CALL_DOMAIN,
        }
    }
}

//-------------------------------------------------------------------------------------------------
/// Constants
impl CallNode {
    /// The domain of the call block (used for control block hashing).
    pub const CALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::CALL as u64);
    /// The domain of the syscall block (used for control block hashing).
    pub const SYSCALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::SYSCALL as u64);

    /// Computes the commitment for a digest-target call to the specified callee digest.
    pub fn digest_for_callee(callee_digest: Word) -> Word {
        digest_invocation_digest(callee_digest, Self::CALL_DOMAIN)
    }
}

//-------------------------------------------------------------------------------------------------
/// Public accessors
impl CallNode {
    /// Returns the procedure key to be invoked by a keyed call or syscall.
    ///
    /// # Panics
    /// Panics for a digest-target call.
    pub fn target(&self) -> ProcedureKey {
        self.procedure_key().expect("digest call has no procedure key")
    }

    /// Returns the procedure key of a keyed call or syscall.
    pub fn procedure_key(&self) -> Option<ProcedureKey> {
        match self.target {
            CallTarget::Key(key) | CallTarget::Syscall(key) => Some(key),
            CallTarget::Digest(_) => None,
        }
    }

    /// Returns the structural callee of a digest-target call.
    pub fn digest_callee(&self) -> Option<MastNodeId> {
        match self.target {
            CallTarget::Digest(callee) => Some(callee),
            _ => None,
        }
    }

    /// Returns true if this call node represents a syscall.
    pub fn is_syscall(&self) -> bool {
        matches!(self.target, CallTarget::Syscall(_))
    }

    /// Returns the domain of this call node.
    pub fn domain(&self) -> Felt {
        self.target.domain()
    }
}

// PRETTY PRINTING
// ================================================================================================

impl CallNode {
    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        CallNodePrettyPrint { node: self, mast_forest }
    }

    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        CallNodePrettyPrint { node: self, mast_forest }
    }
}

struct CallNodePrettyPrint<'a> {
    node: &'a CallNode,
    mast_forest: &'a MastForest,
}

impl PrettyPrint for CallNodePrettyPrint<'_> {
    fn render(&self) -> Document {
        let (name, target) = match self.node.target {
            CallTarget::Key(key) => ("call", key.into_word()),
            CallTarget::Syscall(key) => ("syscall", key.into_word()),
            CallTarget::Digest(callee) => ("call_digest", self.mast_forest[callee].digest()),
        };
        const_text(name) + const_text(".") + text(target.as_bytes().to_hex_with_prefix())
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
    /// Keyed calls commit to the procedure key and a zero word. Digest calls commit to the
    /// callee digest and the marker word `[1, 0, 0, 0]`. The hash domain distinguishes a call
    /// from a syscall.
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
        self.digest_callee().is_some()
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.extend(self.digest_callee());
    }

    fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(MastNodeId),
    {
        if let Some(callee) = self.digest_callee() {
            f(callee);
        }
    }

    fn domain(&self) -> Felt {
        self.domain()
    }

    type Builder = CallNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        CallNodeBuilder {
            target: self.target,
            digest: Some(self.digest),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`CallNode`] instances.
#[derive(Debug)]
pub struct CallNodeBuilder {
    target: CallTarget,
    digest: Option<Word>,
}

impl CallNodeBuilder {
    /// Creates a new builder for a CallNode with the specified procedure key.
    pub fn new(target: ProcedureKey) -> Self {
        Self {
            target: CallTarget::Key(target),
            digest: None,
        }
    }

    /// Creates a new builder for a syscall CallNode with the specified procedure key.
    pub fn new_syscall(target: ProcedureKey) -> Self {
        Self {
            target: CallTarget::Syscall(target),
            digest: None,
        }
    }

    /// Creates a new builder for a call with a structural callee.
    pub fn new_digest(callee: MastNodeId) -> Self {
        Self {
            target: CallTarget::Digest(callee),
            digest: None,
        }
    }

    /// Builds a keyed CallNode or a node with an already-computed digest.
    ///
    /// # Panics
    /// Panics for a digest call whose node digest requires a forest context.
    pub fn build(self) -> CallNode {
        self.build_linked().expect("digest call requires a forest context")
    }

    pub(in crate::mast) fn build_in_context(
        mut self,
        context: &impl MastNodeContext,
    ) -> Result<CallNode, MastForestError> {
        if let CallTarget::Digest(callee) = self.target {
            let callee = context
                .get_node_by_id(callee)
                .ok_or_else(|| MastForestError::NodeIdOverflow(callee, context.node_count()))?;
            self.digest.get_or_insert_with(|| CallNode::digest_for_callee(callee.digest()));
        }
        self.build_linked()
    }

    pub(in crate::mast) fn build_linked(self) -> Result<CallNode, MastForestError> {
        let digest = match (self.target, self.digest) {
            (_, Some(digest)) => digest,
            (CallTarget::Key(key) | CallTarget::Syscall(key), None) => {
                invocation_digest(key, self.target.domain())
            },
            (CallTarget::Digest(_), None) => {
                return Err(MastForestError::DigestRequiredForDeserialization);
            },
        };
        Ok(CallNode { target: self.target, digest })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl CallNodeBuilder {
    /// Adds this builder to a mutable forest for test and arbitrary data construction.
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build_in_context(forest)?;
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for CallNodeBuilder {
    fn fingerprint_for_node(
        &self,
        context: &impl MastNodeContext,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        match self.target {
            CallTarget::Key(key) | CallTarget::Syscall(key) => {
                Ok(self.digest.unwrap_or_else(|| invocation_digest(key, self.target.domain())))
            },
            CallTarget::Digest(callee) => {
                let callee_digest = context
                    .get_node_by_id(callee)
                    .ok_or_else(|| MastForestError::NodeIdOverflow(callee, context.node_count()))?
                    .digest();
                let digest =
                    self.digest.unwrap_or_else(|| CallNode::digest_for_callee(callee_digest));
                fingerprint_with_child_fingerprints(digest, &[callee], context, hash_by_node_id)
            },
        }
    }

    fn remap_children(mut self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        if let CallTarget::Digest(callee) = &mut self.target {
            *callee = remapping.get(*callee).copied().unwrap_or(*callee);
        }
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
