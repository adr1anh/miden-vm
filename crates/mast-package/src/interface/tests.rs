use miden_assembly_syntax::ast::types::{CallConv, FunctionType, Type};

use super::*;

fn public_path(source: &str) -> PublicProcedurePath {
    PublicProcedurePath::new(Path::new(source)).expect("valid public source path")
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
