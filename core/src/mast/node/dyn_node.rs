use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use super::{MastForestContributor, MastNodeContext, MastNodeExt, digest_invocation_digest};
use crate::{
    Felt, Word,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    prettier::{Document, PrettyPrint, const_text},
    utils::LookupByIdx,
};

// DYN NODE
// ================================================================================================

/// A Dyn node executes a callee selected by a word read from memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynNode {
    is_dyncall: bool,
    is_digest: bool,
    digest: Word,
}

/// Constants
impl DynNode {
    /// The domain of the Dyn block (used for control block hashing).
    pub const DYN_DOMAIN: Felt = Felt::new_unchecked(opcodes::DYN as u64);

    /// The domain of the Dyncall block (used for control block hashing).
    pub const DYNCALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::DYNCALL as u64);
}

/// Default digest constants
impl DynNode {
    /// The default digest for a DynNode representing a dyncall operation.
    pub const DYNCALL_DEFAULT_DIGEST: Word = Word::new([
        Felt::new_unchecked(4929465990501260251),
        Felt::new_unchecked(4252574327229227746),
        Felt::new_unchecked(7664706718614035214),
        Felt::new_unchecked(5262722615979198255),
    ]);

    /// The default digest for a DynNode representing a dynexec operation.
    pub const DYN_DEFAULT_DIGEST: Word = Word::new([
        Felt::new_unchecked(5054859371585090225),
        Felt::new_unchecked(3018626251158572130),
        Felt::new_unchecked(8979003943310009950),
        Felt::new_unchecked(3514735682419267206),
    ]);

    pub(in crate::mast) fn default_digest(is_dyncall: bool, is_digest: bool) -> Word {
        match (is_dyncall, is_digest) {
            (false, false) => Self::DYN_DEFAULT_DIGEST,
            (true, false) => Self::DYNCALL_DEFAULT_DIGEST,
            (false, true) => digest_invocation_digest(Word::default(), Self::DYN_DOMAIN),
            (true, true) => digest_invocation_digest(Word::default(), Self::DYNCALL_DOMAIN),
        }
    }
}

/// Public accessors
impl DynNode {
    /// Returns true if the [`DynNode`] represents a dyncall operation, and false for dynexec.
    pub fn is_dyncall(&self) -> bool {
        self.is_dyncall
    }

    /// Returns true when the memory word is interpreted as an implementation digest.
    pub fn is_digest(&self) -> bool {
        self.is_digest
    }

    /// Returns the domain of this dyn node.
    pub fn domain(&self) -> Felt {
        if self.is_dyncall() {
            Self::DYNCALL_DOMAIN
        } else {
            Self::DYN_DOMAIN
        }
    }
}

// PRETTY PRINTING
// ================================================================================================

impl DynNode {
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

impl PrettyPrint for DynNode {
    fn render(&self) -> Document {
        match (self.is_dyncall(), self.is_digest()) {
            (false, false) => const_text("dyn"),
            (true, false) => const_text("dyncall"),
            (false, true) => const_text("dyn_digest"),
            (true, true) => const_text("dyncall_digest"),
        }
    }
}

impl fmt::Display for DynNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for DynNode {
    /// Returns a commitment to a Dyn node.
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(DynNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(DynNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {
        // No children for dyn nodes
    }

    fn for_each_child<F>(&self, _f: F)
    where
        F: FnMut(MastNodeId),
    {
        // DynNode has no children
    }

    fn domain(&self) -> Felt {
        self.domain()
    }

    type Builder = DynNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        DynNodeBuilder {
            is_dyncall: self.is_dyncall,
            is_digest: self.is_digest,
            digest: Some(self.digest),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`DynNode`] instances.
#[derive(Debug)]
pub struct DynNodeBuilder {
    is_dyncall: bool,
    is_digest: bool,
    digest: Option<Word>,
}

impl DynNodeBuilder {
    /// Creates a new builder for a DynNode representing a dynexec operation.
    pub fn new_dyn() -> Self {
        Self {
            is_dyncall: false,
            is_digest: false,
            digest: None,
        }
    }

    /// Creates a new builder for a DynNode representing a dyncall operation.
    pub fn new_dyncall() -> Self {
        Self {
            is_dyncall: true,
            is_digest: false,
            digest: None,
        }
    }

    /// Creates a builder for a digest-target dynexec.
    pub fn new_digest() -> Self {
        Self {
            is_dyncall: false,
            is_digest: true,
            digest: None,
        }
    }

    /// Creates a builder for a digest-target dyncall.
    pub fn new_digest_dyncall() -> Self {
        Self {
            is_dyncall: true,
            is_digest: true,
            digest: None,
        }
    }

    /// Builds the DynNode.
    pub fn build(self) -> DynNode {
        let digest = self
            .digest
            .unwrap_or_else(|| DynNode::default_digest(self.is_dyncall, self.is_digest));
        DynNode {
            is_dyncall: self.is_dyncall,
            is_digest: self.is_digest,
            digest,
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl DynNodeBuilder {
    /// Adds this builder to a mutable forest for test and arbitrary data construction.
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build();
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for DynNodeBuilder {
    fn fingerprint_for_node(
        &self,
        _context: &impl MastNodeContext,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        Ok(self
            .digest
            .unwrap_or_else(|| DynNode::default_digest(self.is_dyncall, self.is_digest)))
    }

    fn remap_children(self, _remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        // DynNode has no children to remap, but preserve the digest
        self
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for DynNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<bool>()
            .prop_map(|is_dyncall| {
                if is_dyncall {
                    Self::new_dyncall()
                } else {
                    Self::new_dyn()
                }
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chiplets::hasher;

    /// Ensures that the hash of `DynNode` is indeed the hash of 2 empty words, in the `DynNode`
    /// domain.
    #[test]
    pub fn test_dyn_node_digest() {
        let mut forest = crate::mast::DenseMastForestBuilder::new();
        let dyn_node_id = forest.push_node(DynNodeBuilder::new_dyn()).unwrap();
        let dyn_node = forest.get_node_by_id(dyn_node_id).unwrap().unwrap_dyn();
        assert_eq!(
            dyn_node.digest(),
            hasher::merge_in_mast_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN)
        );

        let dyncall_node_id = forest.push_node(DynNodeBuilder::new_dyncall()).unwrap();
        let dyncall_node = forest.get_node_by_id(dyncall_node_id).unwrap().unwrap_dyn();
        assert_eq!(
            dyncall_node.digest(),
            hasher::merge_in_mast_domain(
                &[Word::default(), Word::default()],
                DynNode::DYNCALL_DOMAIN,
            )
        );
    }
}
