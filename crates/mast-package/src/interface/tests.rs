use miden_assembly_syntax::ast::types::{CallConv, FunctionType, Type};

use super::*;

fn public_path(source: &str) -> PublicProcedurePath {
    PublicProcedurePath::new(Path::new(source)).expect("valid public source path")
}

fn semantic_public_path(components: &[&str]) -> Result<PublicProcedurePath, DeclarationError> {
    PublicProcedurePath::from_semantic_components(
        components.iter().map(|text| (*text).into()).collect(),
    )
}

#[test]
fn semantic_components_match_source_paths_without_interpreting_text() {
    for (source, components) in [
        ("module::run", &["module", "run"][..]),
        (r#""a::b""#, &["a::b"][..]),
        (r#""a::b"::"f#tag""#, &["a::b", "f#tag"][..]),
        (r#""mod\ule"::"f\\tag""#, &[r"mod\ule", r"f\\tag"][..]),
        (r#""Å"::"Å""#, &["Å", "Å"][..]),
        (r#"module::"Å""#, &["module", "Å"][..]),
        (r#"module::"Å""#, &["module", "Å"][..]),
        (r#""::""#, &["::"][..]),
    ] {
        let semantic = semantic_public_path(components).expect("valid semantic components");
        assert_eq!(semantic, public_path(source), "{source:?}");
        assert_eq!(semantic.components(), components, "{source:?}");
    }

    assert_ne!(semantic_public_path(&["Å"]).unwrap(), semantic_public_path(&["Å"]).unwrap());
    assert_ne!(
        semantic_public_path(&[r"a\b"]).unwrap(),
        semantic_public_path(&[r"a\\b"]).unwrap()
    );
    assert_ne!(
        semantic_public_path(&["a::b"]).unwrap(),
        semantic_public_path(&["a", "b"]).unwrap()
    );
}

#[test]
fn semantic_components_reject_empty_and_invalid_names() {
    for components in [
        &[][..],
        &[""][..],
        &["", "run"][..],
        &["module", ""][..],
        &["bad namespace", "run"][..],
        &["bad#namespace", "run"][..],
        &["bad\0namespace", "run"][..],
        &["module", "bad procedure"][..],
        &["module", "bad\0procedure"][..],
        &["module", "bad\nprocedure"][..],
        &["module", "e\u{301}"][..],
        &["module", "🙂"][..],
        &["module", r#""run""#][..],
        &["module", r#"prefix"run""#][..],
        &["module", r#"f\"tag"#][..],
    ] {
        assert!(semantic_public_path(components).is_err(), "{components:?}");
    }
}

#[test]
fn semantic_components_reject_reserved_roots_and_entrypoint() {
    for components in [
        &["$kernel"][..],
        &["$kernel", "run"][..],
        &["$exec"][..],
        &["$exec", "run"][..],
        &["$main"][..],
        &["module", "$main"][..],
    ] {
        assert!(matches!(
            semantic_public_path(components),
            Err(DeclarationError::ReservedPublicPath)
        ));
    }
}

#[test]
fn semantic_components_enforce_component_and_decoded_path_lengths() {
    let longest_component = "a".repeat(Path::MAX_COMPONENT_LENGTH);
    let too_long_component = "a".repeat(Path::MAX_COMPONENT_LENGTH + 1);
    assert!(semantic_public_path(&[&longest_component]).is_ok());
    assert!(matches!(
        semantic_public_path(&[&too_long_component]),
        Err(DeclarationError::InvalidPath(PathError::InvalidComponent(
            IdentError::InvalidLength { max: Path::MAX_COMPONENT_LENGTH }
        )))
    ));

    let namespace = "a".repeat(32_766);
    let local = "b".repeat(32_767);
    assert!(semantic_public_path(&[&namespace, &local]).is_ok());
    let too_long_local = "b".repeat(32_768);
    assert!(matches!(
        semantic_public_path(&[&namespace, &too_long_local]),
        Err(DeclarationError::InvalidPath(PathError::TooLong { max }))
            if max == u16::MAX as usize
    ));

    // The total bound counts UTF-8 bytes even when the component character limit is satisfied.
    let wide_local = "Å".repeat(21_845);
    assert!(semantic_public_path(&[&wide_local]).is_ok());
    let too_wide_local = "Å".repeat(21_846);
    assert!(matches!(
        semantic_public_path(&[&too_wide_local]),
        Err(DeclarationError::InvalidPath(PathError::TooLong { .. }))
    ));
}

#[test]
fn quoted_separator_remains_one_public_component() {
    let quoted = public_path(r#""a::b""#);
    let nested = public_path("a::b");

    assert_eq!(quoted.components(), &[String::from("a::b")]);
    assert_eq!(nested.components(), &[String::from("a"), String::from("b")]);
    assert_ne!(quoted, nested);
    assert_eq!(public_path(r#"module::"f""#), public_path("module::f"));
}

#[test]
fn public_paths_validate_semantic_components_after_removing_quotes() {
    for source in [
        "",
        "\"\"",
        "::",
        "::f",
        "module::::f",
        "module::",
        "\"bad namespace\"::f",
        "\"bad\0namespace\"::f",
        "\"bad#namespace\"::f",
        "module::\"bad procedure\"",
        "module::\"bad\0procedure\"",
        "module::\"unclosed",
    ] {
        assert!(PublicProcedurePath::new(Path::new(source)).is_err(), "{source:?}");
    }

    // Quoted procedure names have their own existing syntax rules. Unlike namespace
    // identifiers, they permit '#'; validating every component as an Ident would reject this.
    assert_eq!(
        public_path(r#"module::"f#tag""#).components(),
        &[String::from("module"), String::from("f#tag")],
    );
}

#[test]
fn local_name_validation_checks_the_retained_forward_component() {
    for source in [
        r#"prefix"run""#,
        r#"module::prefix"run""#,
        r#"prefix"run"suffix"#,
        r#""prefix"run"#,
        r#""run"suffix"#,
    ] {
        assert!(PublicProcedurePath::new(Path::new(source)).is_err(), "{source:?}");
    }

    assert_eq!(public_path("prefixrun"), public_path(r#""prefixrun""#));
    assert_eq!(
        public_path(r#"module::"prefix::run""#).components(),
        &[String::from("module"), String::from("prefix::run")],
    );
    assert_eq!(public_path(r#""run#tag""#).components(), &[String::from("run#tag")]);
}

#[test]
fn public_paths_reject_special_module_roots_and_entrypoint() {
    for source in ["$kernel::f", "\"$kernel\"::f", "$exec::f", "$main", "module::$main"] {
        assert!(matches!(
            PublicProcedurePath::new(Path::new(source)),
            Err(DeclarationError::ReservedPublicPath)
        ));
    }
}

#[test]
fn duplicate_semantic_paths_reject_even_when_abi_and_signatures_differ() {
    let first = ProcedureDeclaration::new(public_path("module::f"), None);
    let second = ProcedureDeclaration::new(
        public_path(r#""module"::"f""#),
        Some(String::from("author's distinct ABI")),
    )
    .with_signature(FunctionType::new(CallConv::Fast, [Type::Felt], [Type::U32]));

    assert!(matches!(
        DeclarationSet::new([first, second]),
        Err(DeclarationError::DuplicatePublicPath { path }) if path == public_path("module::f")
    ));
}

#[test]
fn abi_preserves_presence_unicode_whitespace_and_line_endings() {
    let path = public_path("module::f");
    let descriptions =
        [None, Some(""), Some("Å"), Some("Å"), Some(" Å "), Some("Å\n"), Some("Å\r\n")];
    let declarations: Vec<_> = descriptions
        .iter()
        .map(|description| ProcedureDeclaration::new(path.clone(), description.map(String::from)))
        .collect();

    for (index, declaration) in declarations.iter().enumerate() {
        assert_eq!(declaration.abi_metadata(), descriptions[index]);
        for other in &declarations[index + 1..] {
            assert_ne!(declaration, other);
        }
    }
}

#[test]
fn tooling_signature_does_not_replace_authored_abi() {
    let original = ProcedureDeclaration::new(
        public_path("module::f"),
        Some(String::from("  opaque UTF-8 ABI\r\n")),
    );
    let signature = FunctionType::new(CallConv::Fast, [Type::Felt], [Type::U32]);
    let typed = original.clone().with_signature(signature.clone());

    assert_ne!(original, typed);
    assert_eq!(typed.path(), original.path());
    assert_eq!(typed.abi_metadata(), original.abi_metadata());
    assert_eq!(typed.signature(), Some(&signature));
}
