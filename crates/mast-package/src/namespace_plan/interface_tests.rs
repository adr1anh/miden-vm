use alloc::{string::String, vec};
use core::{cell::Cell, num::NonZeroU32};

use miden_assembly_syntax::{
    Path,
    ast::types::{CallConv, FunctionType, Type},
};
use miden_core::{Felt, Word, serde::DeserializationError};

use super::*;
use crate::{CallableProcedurePath, DeclarationSet, ProcedureDeclaration};

fn path(source: &str) -> PublicProcedurePath {
    PublicProcedurePath::new(Path::new(source)).unwrap()
}

fn callable(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn library_id() -> Word {
    Word::new([1, 2, 3, 4].map(Felt::from_u32))
}

fn key_under(label: CanonicalLabel) -> ProcedureKey {
    NamespacePath::new(vec![label]).procedure_key(&path("run")).unwrap()
}

#[test]
fn latest_declaration_keys_are_available_before_code_or_release_selection() {
    // The identity is supplied by the caller. A key can be named without authenticating the
    // LibraryId, selecting an implementation, or constructing an executable artifact.
    let plan = NamespacePath::new(vec![
        CanonicalLabel::text("latest").unwrap(),
        CanonicalLabel::library_id(library_id()),
        CanonicalLabel::text("public").unwrap(),
    ]);
    let declaration = ProcedureDeclaration::new(path("math::add"), Some("values -> value".into()));
    let declarations = DeclarationSet::new([declaration.clone()]).unwrap();
    let key = plan
        .procedure_key(declarations.get(declaration.path()).unwrap().path())
        .unwrap();

    let updated_metadata =
        ProcedureDeclaration::new(declaration.path().clone(), Some(String::new()))
            .with_signature(FunctionType::new(CallConv::Fast, [Type::Felt], [Type::Felt]));
    assert_eq!(key, plan.procedure_key(updated_metadata.path()).unwrap());
    assert_ne!(declaration, updated_metadata);

    let pinned_home = NamespacePath::new(vec![
        CanonicalLabel::text("pinned").unwrap(),
        CanonicalLabel::library_id(library_id()),
        CanonicalLabel::revision(NonZeroU32::new(1).unwrap()),
        CanonicalLabel::text("public").unwrap(),
    ]);
    assert_ne!(key, pinned_home.procedure_key(declaration.path()).unwrap());
}

#[test]
fn semantic_components_preserve_boundaries_unicode_and_literal_backslashes() {
    let plan = NamespacePath::new(vec![CanonicalLabel::text("supplied_home").unwrap()]);
    let key = |source| plan.procedure_key(&path(source)).unwrap();

    assert_ne!(key("\"a::b\""), key("a::b"));
    assert_eq!(key("module::run"), key("\"module\"::\"run\""));
    // U+00C5 and U+212B are canonically equivalent Unicode spellings with different UTF-8 bytes.
    assert_ne!(key("\"Å\""), key("\"Å\""));
    // These are semantic AST paths: no raw-source escape decoder runs here.
    assert_ne!(key(r#""a\b""#), key(r#""a\\b""#));
    assert_ne!(key(r#""a\u{62}""#), key("ab"));
}

#[test]
fn home_label_tags_and_order_change_the_derived_key() {
    let revision = NonZeroU32::new(7).unwrap();
    assert_ne!(
        key_under(CanonicalLabel::revision(revision)),
        key_under(CanonicalLabel::text("7").unwrap())
    );
    assert_ne!(
        key_under(CanonicalLabel::library_id(library_id())),
        key_under(CanonicalLabel::text(&library_id().to_hex()).unwrap())
    );

    let left = CanonicalLabel::text("left").unwrap();
    let right = CanonicalLabel::text("right").unwrap();
    let first = NamespacePath::new(vec![left.clone(), right.clone()]);
    let second = NamespacePath::new(vec![right, left]);
    assert_ne!(first.procedure_key(&path("run")), second.procedure_key(&path("run")));
    assert_ne!(first.parent_namespace(&path("math::run")), first.parent_namespace(&path("run")));
}

#[test]
fn typed_home_ids_use_external_codec_validation_without_parsing_account_ids() {
    let validations = Cell::new(0);
    // Codec 77 is only a fixture supplied by this test's external validator. The namespace plan
    // itself neither recognizes a codec nor claims publication or account authority.
    let typed_id = CanonicalLabel::typed_id(77, b"fixture-id", |codec, bytes| {
        validations.set(validations.get() + 1);
        if codec == 77 && bytes == b"fixture-id" {
            Ok(())
        } else {
            Err(DeserializationError::InvalidValue("invalid fixture ID".into()))
        }
    })
    .unwrap();
    let typed_key = key_under(typed_id);
    assert_eq!(validations.get(), 1);
    assert_ne!(typed_key, key_under(CanonicalLabel::text("fixture-id").unwrap()));
    assert!(
        CanonicalLabel::typed_id(78, b"fixture-id", |_, _| {
            Err(DeserializationError::InvalidValue("unrecognized fixture codec".into()))
        })
        .is_err()
    );
}

#[test]
fn explicitly_supplied_root_home_derives_keys_without_granting_authority() {
    let plan = NamespacePath::new(vec![]);
    let local_label = CanonicalLabel::text("run").unwrap();
    let root_key = plan.procedure_key(&path("run")).unwrap();
    assert_eq!(root_key, Namespace::initial().procedure_key(local_label.commitment()));

    // A name that resembles a Protocol role is still only a caller-supplied Text home component.
    let named_home = NamespacePath::new(vec![CanonicalLabel::text("kernel").unwrap()]);
    assert_ne!(root_key, named_home.procedure_key(&path("run")).unwrap());
    assert_ne!(plan.namespace(), named_home.namespace());
}

#[test]
fn general_and_public_paths_derive_the_same_keys_without_bodies_or_abi() {
    let plan = NamespacePath::new(vec![CanonicalLabel::text("supplied_home").unwrap()]);
    for source in [
        "module::run",
        r#""module"::"run""#,
        r#""a::b""#,
        r#""Å"::"Å""#,
        r#""mod\ule"::"f\\tag""#,
        r#"module::"f#tag""#,
    ] {
        let public = path(source);
        let callable =
            CallableProcedurePath::from_semantic_components(public.components().to_vec()).unwrap();
        let absent_abi = ProcedureDeclaration::new(public.clone(), None);
        let changed_abi = ProcedureDeclaration::new(public, Some(" changed ABI\r\n".into()))
            .with_signature(FunctionType::new(CallConv::Fast, [Type::Felt], [Type::U32]));
        let key = plan.callable_procedure_key(&callable).unwrap();
        assert_eq!(key, plan.procedure_key(absent_abi.path()).unwrap(), "{source:?}");
        assert_eq!(key, plan.procedure_key(changed_abi.path()).unwrap(), "{source:?}");
        assert_eq!(
            plan.callable_parent_namespace(&callable).unwrap(),
            plan.parent_namespace(absent_abi.path()).unwrap(),
            "{source:?}"
        );
    }

    let key = |components: &[&str]| plan.callable_procedure_key(&callable(components)).unwrap();
    assert_ne!(key(&["a::b"]), key(&["a", "b"]));
    assert_ne!(key(&["Å"]), key(&["Å"]));
    assert_ne!(key(&[r"a\b"]), key(&[r"a\\b"]));
}

#[test]
fn entry_and_reserved_roots_derive_as_ordinary_text_under_the_explicit_home() {
    let plan = NamespacePath::new(vec![CanonicalLabel::text("supplied_home").unwrap()]);
    let main = CanonicalLabel::text("$main").unwrap();
    assert_eq!(plan.callable_parent_namespace(&callable(&["$main"])).unwrap(), plan.namespace());
    assert_eq!(
        plan.callable_procedure_key(&callable(&["$main"])).unwrap(),
        plan.namespace().procedure_key(main.commitment())
    );
    for root in ["$exec", "$kernel"] {
        let entry = callable(&[root, "$main"]);
        let parent = plan.namespace().child(CanonicalLabel::text(root).unwrap().commitment());
        assert_eq!(plan.callable_parent_namespace(&entry).unwrap(), parent);
        assert_eq!(
            plan.callable_procedure_key(&entry).unwrap(),
            parent.procedure_key(main.commitment())
        );
        assert_ne!(parent, Namespace::initial());
    }
}

#[test]
fn helpers_require_an_explicit_private_prefix_and_preserve_typed_homes() {
    let revision = NonZeroU32::new(7).unwrap();
    let home = vec![
        CanonicalLabel::text("pinned").unwrap(),
        CanonicalLabel::library_id(library_id()),
        CanonicalLabel::revision(revision),
    ];
    let plan = NamespacePath::new(home.clone());
    let helper = callable(&["private", "math", "helper"]);
    let parent = plan
        .namespace()
        .child(CanonicalLabel::text("private").unwrap().commitment())
        .child(CanonicalLabel::text("math").unwrap().commitment());
    assert_eq!(plan.callable_parent_namespace(&helper).unwrap(), parent);
    let key = plan.callable_procedure_key(&helper).unwrap();
    assert_eq!(key, parent.procedure_key(CanonicalLabel::text("helper").unwrap().commitment()));
    assert_ne!(key, plan.callable_procedure_key(&callable(&["math", "helper"])).unwrap());

    let mut text_revision = home.clone();
    text_revision[2] = CanonicalLabel::text("7").unwrap();
    assert_ne!(key, NamespacePath::new(text_revision).callable_procedure_key(&helper).unwrap());
    let mut text_library_id = home;
    text_library_id[1] = CanonicalLabel::text(&library_id().to_hex()).unwrap();
    assert_ne!(
        key,
        NamespacePath::new(text_library_id).callable_procedure_key(&helper).unwrap()
    );
    assert_ne!(
        key,
        plan.callable_procedure_key(&callable(&["private", "math::helper"])).unwrap()
    );
}
