//! Explicit source lookup routes for compiled packages.

use alloc::sync::Arc;

use miden_assembly_syntax::{
    Path, PathBuf, PathComponent,
    diagnostics::{IntoDiagnostic, Report},
};

/// Projects a package's source paths beneath an explicitly selected source prefix.
///
/// Both bases are absolute semantic MASM paths. Routing changes only source lookup: canonical
/// callable bindings, private helpers, embedded invocation keys and package identity are retained.
/// Package names and dependency aliases never imply either base.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageSourceMount {
    package_base: Arc<Path>,
    source_base: Arc<Path>,
}

impl PackageSourceMount {
    /// Validates and normalizes both absolute bases, including the root-only path `::`.
    pub fn new(
        package_base: impl AsRef<Path>,
        source_base: impl AsRef<Path>,
    ) -> Result<Self, Report> {
        Ok(Self {
            package_base: normalized_absolute(package_base.as_ref())?,
            source_base: normalized_absolute(source_base.as_ref())?,
        })
    }

    /// Returns the normalized prefix every module and export in the package must share.
    pub fn package_base(&self) -> &Arc<Path> {
        &self.package_base
    }

    /// Returns the normalized prefix used to resolve the package in the importing source.
    pub fn source_base(&self) -> &Arc<Path> {
        &self.source_base
    }

    /// Projects an absolute package path, rejecting paths outside the component prefix.
    ///
    /// Prefix comparison uses complete semantic components, including quoted components. For
    /// example, `::lib` never matches `::library` or the one component `::"lib::inner"`.
    pub fn project(&self, path: &Path) -> Result<Arc<Path>, Report> {
        let path = normalized_absolute(path)?;
        let suffix = path.strip_prefix(&self.package_base).ok_or_else(|| {
            Report::msg(format!(
                "package source path '{path}' is outside mount base '{}'",
                self.package_base
            ))
        })?;
        let mut projected = self.source_base.to_path_buf();
        for component in suffix.components() {
            match component.into_diagnostic()? {
                component @ PathComponent::Normal(_) => {
                    push_normal_component(&mut projected, component.as_str());
                },
                PathComponent::Root => unreachable!("a stripped absolute prefix has no root"),
            }
        }
        // Joining two representable paths can exceed the path format's length limit.
        projected.to_absolute().into_diagnostic()?;
        Ok(projected.into())
    }
}

fn normalized_absolute(path: &Path) -> Result<Arc<Path>, Report> {
    if !path.is_absolute() {
        return Err(Report::msg(format!(
            "package source mount requires an absolute path, got '{path}'"
        )));
    }
    path.to_absolute().into_diagnostic()?;
    let mut normalized = PathBuf::default();
    for component in path.components() {
        match component.into_diagnostic()? {
            PathComponent::Root => normalized.push_component("::"),
            component @ PathComponent::Normal(_) => {
                push_normal_component(&mut normalized, component.as_str());
            },
        }
    }
    normalized.to_absolute().into_diagnostic()?;
    Ok(normalized.into())
}

fn push_normal_component(path: &mut PathBuf, component: &str) {
    // Use semantic text so unnecessary quotes normalize away. The one normal component `"::"`
    // needs its quoted spelling because push_component interprets bare `::` as the root anchor.
    path.push_component(if component == "::" { "\"::\"" } else { component });
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn normalizes_semantic_components_and_handles_root_and_exact_prefixes() {
        let mount =
            PackageSourceMount::new(Path::new("::\"lib\""), Path::new("::\"left\"")).unwrap();
        assert_eq!(mount.package_base().as_str(), "::lib");
        assert_eq!(mount.source_base().as_str(), "::left");
        assert_eq!(
            mount,
            PackageSourceMount::new(Path::new("::lib"), Path::new("::left")).unwrap()
        );
        assert_eq!(mount.project(Path::new("::lib")).unwrap().as_str(), "::left");
        assert_eq!(mount.project(Path::new("::\"lib\"::\"run\"")).unwrap().as_str(), "::left::run");
        assert_eq!(
            mount.project(Path::new("::lib::\"inner::name\"::run")).unwrap().as_str(),
            "::left::\"inner::name\"::run"
        );
        for path in ["::library::run", "::\"lib::inner\"::run", "::other::run"] {
            assert!(mount.project(Path::new(path)).unwrap_err().to_string().contains("outside"));
        }
        let root = PackageSourceMount::new(Path::new("::"), Path::new("::left")).unwrap();
        assert_eq!(root.project(Path::new("::")).unwrap().as_str(), "::left");
        assert_eq!(root.project(Path::new("::one::run")).unwrap().as_str(), "::left::one::run");
        let strip = PackageSourceMount::new(Path::new("::lib"), Path::new("::")).unwrap();
        assert_eq!(strip.project(Path::new("::lib::run")).unwrap().as_str(), "::run");
        let quoted =
            PackageSourceMount::new(Path::new("::\"::\""), Path::new("::\"left\"")).unwrap();
        assert_eq!(quoted.package_base().as_str(), "::\"::\"");
        assert_eq!(quoted.project(Path::new("::\"::\"::run")).unwrap().as_str(), "::left::run");
        assert_eq!(
            mount.project(Path::new("::lib::\"::\"::run")).unwrap().as_str(),
            "::left::\"::\"::run"
        );
        assert_eq!(
            mount.project(Path::new("::lib::\"算::法\"::\"run\"")).unwrap().as_str(),
            "::left::\"算::法\"::run"
        );
    }

    #[test]
    fn rejects_relative_malformed_and_overlong_paths() {
        for path in ["lib", "", "::lib::::run", "::\"unclosed", "::\"not\"closed"] {
            assert!(PackageSourceMount::new(Path::new(path), Path::new("::left")).is_err());
            assert!(PackageSourceMount::new(Path::new("::lib"), Path::new(path)).is_err());
        }
        let mount = PackageSourceMount::new(Path::new("::lib"), Path::new("::left")).unwrap();
        assert!(mount.project(Path::new("lib::run")).is_err());
        assert!(mount.project(Path::new("::lib::\"unclosed")).is_err());
        let long = format!("::{}", "a".repeat(u16::MAX as usize));
        assert!(PackageSourceMount::new(Path::new(&long), Path::new("::left")).is_err());
        let base = format!("::{}", "a".repeat(32_000));
        let path = format!("::lib::{}", "b".repeat(34_000));
        let mount = PackageSourceMount::new(Path::new("::lib"), Path::new(&base)).unwrap();
        assert!(mount.project(Path::new(&path)).is_err());
    }
}
