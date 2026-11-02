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

// EXEC NODE
// ================================================================================================

/// A keyed invocation that preserves the current execution context and principal.
///
/// The target is resolved through the execution environment rather than a structural MAST child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecNode {
    target: ProcedureKey,
    digest: Word,
}

impl ExecNode {
    /// The domain of the Exec block (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new_unchecked(opcodes::EXEC as u64);

    /// Returns the procedure key to be invoked by this exec node.
    pub fn target(&self) -> ProcedureKey {
        self.target
    }

    pub(super) fn to_display<'a>(&'a self, _mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        self.clone()
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        _mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        self.clone()
    }
}

impl PrettyPrint for ExecNode {
    fn render(&self) -> Document {
        const_text("exec")
            + const_text(".")
            + text(self.target.as_word().as_bytes().to_hex_with_prefix())
    }
}

impl fmt::Display for ExecNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pretty_print(f)
    }
}

impl MastNodeExt for ExecNode {
    /// Returns the hash of the procedure key and an empty word in the Exec domain.
    ///
    /// The selected implementation's digest is not part of this commitment.
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(ExecNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(ExecNode::to_pretty_print(self, mast_forest))
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
        Self::DOMAIN
    }

    type Builder = ExecNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        ExecNodeBuilder::new(self.target).with_digest(self.digest)
    }
}

/// Builder for creating [`ExecNode`] instances without requiring the target's implementation.
#[derive(Debug)]
pub struct ExecNodeBuilder {
    target: ProcedureKey,
    digest: Option<Word>,
}

impl ExecNodeBuilder {
    /// Creates a new builder for an ExecNode with the specified procedure key.
    pub fn new(target: ProcedureKey) -> Self {
        Self { target, digest: None }
    }

    /// Builds the ExecNode.
    pub fn build(self) -> ExecNode {
        let digest =
            self.digest.unwrap_or_else(|| invocation_digest(self.target, ExecNode::DOMAIN));
        ExecNode { target: self.target, digest }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl ExecNodeBuilder {
    /// Adds this builder to a mutable forest for test and arbitrary data construction.
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build();
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for ExecNodeBuilder {
    fn fingerprint_for_node(
        &self,
        _context: &impl MastNodeContext,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        Ok(self.digest.unwrap_or_else(|| invocation_digest(self.target, ExecNode::DOMAIN)))
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
impl proptest::prelude::Arbitrary for ExecNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<Word>().prop_map(|word| Self::new(ProcedureKey::new(word))).boxed()
    }
}
