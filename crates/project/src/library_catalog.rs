//! Optional readable names for caller-supplied opaque library identities.

use alloc::{collections::BTreeMap, string::String};

use miden_core::Word;

use crate::Report;

/// An exact readable-name map supplied by a caller or project manifest.
///
/// Names are tooling inputs only. This map neither derives identities nor establishes publisher,
/// binding, release, profile or execution authority. Multiple names may identify the same Word.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LibraryCatalog {
    entries: BTreeMap<String, Word>,
}

impl LibraryCatalog {
    /// Retains supplied identities, coalescing identical entries and rejecting conflicting names.
    pub fn new(
        entries: impl IntoIterator<Item = (impl Into<String>, Word)>,
    ) -> Result<Self, Report> {
        let mut catalog = Self::default();
        for (name, identity) in entries {
            catalog.insert(name, identity)?;
        }
        Ok(catalog)
    }

    /// Adds an exact name. An existing name can only be repeated with the identical identity.
    pub fn insert(&mut self, name: impl Into<String>, identity: Word) -> Result<(), Report> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(Report::msg("library catalog names must not be empty"));
        }
        if let Some(previous) = self.entries.get(&name) {
            if *previous != identity {
                return Err(Report::msg(format!(
                    "conflicting or ambiguous library catalog name '{name}'"
                )));
            }
        } else {
            self.entries.insert(name, identity);
        }
        Ok(())
    }

    /// Composes catalogs without shadowing any previously supplied identity.
    pub fn merge(&mut self, other: &Self) -> Result<(), Report> {
        for (name, identity) in &other.entries {
            if self.entries.get(name).is_some_and(|previous| previous != identity) {
                return Err(Report::msg(format!(
                    "conflicting or ambiguous library catalog name '{name}'"
                )));
            }
        }
        self.entries
            .extend(other.entries.iter().map(|(name, identity)| (name.clone(), *identity)));
        Ok(())
    }

    /// Looks up an exact name, without alias expansion, normalization or inference.
    pub fn get(&self, name: &str) -> Option<Word> {
        self.entries.get(name).copied()
    }

    /// Resolves a required configured name, rejecting missing entries.
    pub fn resolve(&self, name: &str) -> Result<Word, Report> {
        self.get(name)
            .ok_or_else(|| Report::msg(format!("unknown library catalog name '{name}'")))
    }

    pub fn entries(&self) -> &BTreeMap<String, Word> {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::Felt;

    use super::*;

    fn id(value: u32) -> Word {
        Word::new([Felt::from_u32(value); 4])
    }

    #[test]
    fn catalogs_keep_exact_supplied_ids_and_reject_ambiguous_names() {
        let mut catalog = LibraryCatalog::new([("math", id(1)), ("math", id(1))]).unwrap();
        catalog
            .merge(&LibraryCatalog::new([("math", id(1)), ("other", id(1))]).unwrap())
            .unwrap();
        assert_eq!(catalog.get("math"), Some(id(1)));
        assert_eq!(catalog.get("other"), Some(id(1)));
        assert_eq!(catalog.entries().len(), 2);
        for name in ["Math", " math", "missing"] {
            assert!(catalog.resolve(name).unwrap_err().to_string().contains("unknown"));
        }
        assert!(LibraryCatalog::new([("math", id(1)), ("math", id(2))]).is_err());
        let conflict = LibraryCatalog::new([("additional", id(3)), ("math", id(2))]).unwrap();
        assert!(catalog.merge(&conflict).unwrap_err().to_string().contains("ambiguous"));
        assert_eq!(catalog.get("math"), Some(id(1)));
        assert_eq!(catalog.get("additional"), None);
        assert!(LibraryCatalog::new([("", id(1))]).is_err());
    }
}
