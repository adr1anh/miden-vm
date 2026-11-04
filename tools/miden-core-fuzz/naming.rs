//! Explicit synthetic naming policy and semantic oracles shared by the fuzz targets.

use std::sync::Arc;

use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::{CanonicalLabel, ImplementationRoot, Namespace},
    serde::DeserializationError,
};
use miden_mast_package::{
    CallableProcedurePath, NamespacePath, Package, PackageCallables, PackageExport, PackageId,
    PackageSymbols, PathBuf, ProcedureExport, ProcedureName, TargetType, Version,
    interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile},
};

pub const SYNTHETIC_CODEC: u32 = 0xffff_fffe;
pub const SYNTHETIC_ID: &[u8] = b"fuzz-fixture";

pub fn validate_id(codec: u32, bytes: &[u8]) -> Result<(), &'static str> {
    if codec == SYNTHETIC_CODEC && bytes == SYNTHETIC_ID {
        Ok(())
    } else {
        Err("unknown synthetic codec or noncanonical synthetic ID")
    }
}

/// Finite fixture policy, independent of untrusted transport, package tags and body roots.
/// It recognizes no Protocol identity codec or publication authority.
pub struct SyntheticProfile {
    pub homes: Vec<Vec<CanonicalLabel>>,
    allow_synthetic_typed_id: bool,
}

impl SyntheticProfile {
    pub fn callable_codec() -> Self {
        let text = CanonicalLabel::text("synthetic-home").unwrap();
        let typed = CanonicalLabel::typed_id(SYNTHETIC_CODEC, SYNTHETIC_ID, |codec, bytes| {
            validate_id(codec, bytes)
                .map_err(|error| DeserializationError::InvalidValue(error.into()))
        })
        .unwrap();
        Self {
            homes: vec![vec![], vec![text.clone()], vec![text, typed]],
            allow_synthetic_typed_id: true,
        }
    }

    /// Covers the writer-owned package corpus and this harness's generated/source fixtures.
    /// Only built-in labels are admitted here; every TypedId rejects, including the detached
    /// codec's synthetic ID, even when the package wire format is valid.
    pub fn packages() -> Self {
        let mut profile = Self {
            homes: vec![vec![]],
            allow_synthetic_typed_id: false,
        };
        for text in ["package-seed-fixtures", "arbitrary-package-fixtures", "package-fuzz-source"] {
            profile.homes.push(vec![CanonicalLabel::text(text).unwrap()]);
        }
        profile
    }
}

impl TypedIdProfile for SyntheticProfile {
    type Context = bool;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        permitted: &bool,
        codec: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        if !self.allow_synthetic_typed_id {
            return Err("package fuzz policy recognizes no TypedId codecs");
        }
        validate_id(codec, bytes)?;
        if *permitted {
            Ok(())
        } else {
            Err("synthetic context revoked")
        }
    }
}

impl HomeProfile for SyntheticProfile {
    fn validate_home(&self, permitted: &bool, home: &[CanonicalLabel]) -> Result<(), Self::Error> {
        if *permitted && self.homes.iter().any(|allowed| allowed == home) {
            Ok(())
        } else {
            Err("complete synthetic home is not permitted in this context")
        }
    }
}

pub fn source_home() -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text("package-fuzz-source").unwrap()])
}

/// Unsupported profiles may reject valid raw transport. Successful admission must preserve exact
/// canonical bytes and all code/name relations, and must be rechecked under the current context.
pub fn check_naming_admission(
    package: &Package,
    profile: &SyntheticProfile,
    permitted: &bool,
    limits: CodecLimits,
) -> Option<PackageSymbols> {
    let naming = package.validate_symbols(profile, permitted, limits).ok()?;
    assert_eq!(
        naming.encode_v1(profile, permitted, limits).unwrap(),
        package.naming_transport().as_bytes()
    );
    assert_eq!(package.naming_transport().decode(profile, permitted, limits).unwrap(), naming);
    assert!(package.validate_symbols(profile, &false, limits).is_err());
    assert_named_package(package, &naming);
    Some(naming)
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_owned()).collect(),
    )
    .unwrap()
}

/// A bounded valid package runs before hostile-input guards, so semantic admission cannot become
/// unreachable when corpus bytes use an old format or an unsupported naming profile. Names are
/// selected before code: two distinct public keys share D, and a private helper retains its root.
pub fn named_package_fixture(data: &[u8]) -> (Package, PackageSymbols) {
    let selector = data.first().copied().unwrap_or(0);
    let kind = [TargetType::Library, TargetType::Executable, TargetType::Kernel]
        [usize::from(selector % 3)];
    let home = source_home();
    let public_home = if kind == TargetType::Kernel {
        NamespacePath::new(vec![])
    } else {
        let profile = SyntheticProfile::packages();
        NamespacePath::new(profile.homes[usize::from((selector / 3) % 3)].clone())
    };
    let first = ProcedureName::new(public_home.clone(), path(&["first"])).unwrap();
    let second = ProcedureName::new(public_home, path(&["second"])).unwrap();
    let helper = ProcedureName::new(home.clone(), path(&["helpers", "callback"])).unwrap();
    assert_ne!(first.key(), second.key());

    let mut mast = MastForest::new();
    let public_node = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(u32::from(
        data.get(1).copied().unwrap_or(0),
    )))])
    .add_to_forest(&mut mast)
    .unwrap();
    let helper_node = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut mast)
        .unwrap();
    mast.make_root(public_node);
    mast.make_root(helper_node);
    let public_d = ImplementationRoot::new(mast[public_node].digest());
    let helper_d = ImplementationRoot::new(mast[helper_node].digest());
    let callables = PackageCallables::new(
        vec![first.clone(), second.clone(), helper.clone()],
        vec![
            (path(&["fixture", "first"]), first.key()),
            (path(&["fixture", "second"]), second.key()),
        ],
        vec![(first.key(), public_d), (second.key(), public_d), (helper.key(), helper_d)],
    )
    .unwrap();
    // Exercise both an explicitly selected private entry and a non-runnable code candidate.
    let entry = (kind == TargetType::Executable && selector & 16 == 0).then_some(helper.key());
    let naming = PackageSymbols::new(home, callables, entry).unwrap();
    let exports = ["first", "second"].map(|name| {
        let source = PathBuf::new(&format!("::fixture::{name}")).unwrap();
        PackageExport::Procedure(ProcedureExport::new(
            Arc::from(source.into_boxed_path()),
            Some(public_node),
            public_d.into_word(),
            None,
        ))
    });
    let package = Package::create(
        PackageId::from("fuzz_named_package"),
        Version::new(1, 0, 0),
        kind,
        Arc::new(mast),
        exports,
        [],
        &naming,
    )
    .expect("the independently named fixture must be a valid package");
    (package, naming)
}

/// Check owned code/name relations without manufacturing an execution descriptor or authority.
pub fn assert_named_package(package: &Package, naming: &PackageSymbols) {
    package
        .check_naming(naming)
        .expect("canonical naming must match exact package transport");
    let mast = package.mast_forest();
    for (&key, binding) in naming.callables().bindings() {
        assert_eq!(key, binding.key());
        assert_eq!(
            key,
            ProcedureName::new(binding.namespace_plan().clone(), binding.path().clone())
                .unwrap()
                .key()
        );
    }
    for (&key, &implementation) in naming.callables().selected_implementations() {
        assert!(naming.callables().binding(key).is_some());
        assert!(mast.find_procedure_root(implementation.into_word()).is_some());
    }
    for &root in mast.procedure_roots() {
        assert!(
            naming
                .callables()
                .selected_implementations()
                .any(|(_, selected)| { selected.into_word() == mast[root].digest() })
        );
    }
    let program = package.try_into_program(naming);
    if package.is_program() && naming.entry_key().is_some() {
        let program = program.expect("an explicit admitted entry must select retained code");
        let key = naming.entry_key().unwrap();
        assert_eq!(
            program.hash(),
            naming.callables().selected_implementation(key).unwrap().into_word()
        );
        assert_eq!(program.mast_forest(), mast);
        assert!(mast.is_procedure_root(program.entrypoint()));
    } else {
        assert!(program.is_err());
    }
    let has_exports = package.manifest.exports().any(|export| export.as_procedure().is_some());
    assert_eq!(package.check_kernel_code(naming).is_ok(), package.is_kernel() && has_exports);
    if package.is_kernel() {
        for (_, key) in naming.callables().visible_paths() {
            assert_eq!(
                naming.callables().binding(*key).unwrap().parent_namespace(),
                Namespace::initial()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::serde::{Deserializable, Serializable};

    use super::*;

    #[test]
    fn generated_semantic_cases_remain_reachable_and_body_changes_preserve_keys() {
        let profile = SyntheticProfile::packages();
        let limits = CodecLimits::new(4 * 1024 * 1024, 100_000, 100_000, 4 * 1024 * 1024);
        // Includes all target/home choices and both explicit-private-entry and entryless modes.
        for selector in 0..32 {
            let (original, expected) = named_package_fixture(&[selector, 0]);
            let decoded = Package::read_from_bytes(&original.to_bytes()).unwrap();
            assert_eq!(
                check_naming_admission(&decoded, &profile, &true, limits),
                Some(expected.clone())
            );
            let (changed, changed_naming) = named_package_fixture(&[selector, 255]);
            assert_named_package(&changed, &changed_naming);
            assert_eq!(
                expected.callables().bindings().collect::<Vec<_>>(),
                changed_naming.callables().bindings().collect::<Vec<_>>()
            );
            assert_eq!(expected.entry_key(), changed_naming.entry_key());
            let changed_selections = expected
                .callables()
                .selected_implementations()
                .filter(|(key, implementation)| {
                    changed_naming.callables().selected_implementation(**key)
                        != Some(**implementation)
                })
                .count();
            assert_eq!(changed_selections, 2, "only the two public names sharing D change bodies");
            assert!(check_naming_admission(&decoded, &profile, &false, limits).is_none());
        }
    }
}
