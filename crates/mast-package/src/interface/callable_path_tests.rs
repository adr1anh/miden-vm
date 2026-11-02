use super::*;

fn callable(components: &[&str]) -> Result<CallableProcedurePath, DeclarationError> {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
}

#[test]
fn callable_paths_permit_entrypoints_and_reserved_source_roots_without_public_admission() {
    for components in [
        &["$main"][..],
        &["module", "$main"][..],
        &["$exec"][..],
        &["$exec", "run"][..],
        &["$exec", "$main"][..],
        &["$kernel"][..],
        &["$kernel", "run"][..],
    ] {
        assert_eq!(callable(components).unwrap().components(), components);
        assert!(matches!(
            PublicProcedurePath::from_semantic_components(
                components.iter().map(|component| (*component).into()).collect()
            ),
            Err(DeclarationError::ReservedPublicPath)
        ));
    }
}

#[test]
fn callable_paths_retain_decoded_components_exactly_like_public_paths() {
    for (source, components) in [
        ("module::run", &["module", "run"][..]),
        (r#""module"::"run""#, &["module", "run"][..]),
        (r#""a::b""#, &["a::b"][..]),
        (r#""a::b"::"f#tag""#, &["a::b", "f#tag"][..]),
        (r#""mod\ule"::"f\\tag""#, &[r"mod\ule", r"f\\tag"][..]),
        (r#""Å"::"Å""#, &["Å", "Å"][..]),
    ] {
        let callable = callable(components).unwrap();
        let public = PublicProcedurePath::new(Path::new(source)).unwrap();
        assert_eq!(callable.components(), components, "{source:?}");
        assert_eq!(callable.components(), public.components(), "{source:?}");
    }

    assert_ne!(callable(&["a::b"]).unwrap(), callable(&["a", "b"]).unwrap());
    assert_ne!(callable(&["Å"]).unwrap(), callable(&["Å"]).unwrap());
    assert_ne!(callable(&[r"a\b"]).unwrap(), callable(&[r"a\\b"]).unwrap());
    assert_ne!(callable(&[r"a\u{62}"]).unwrap(), callable(&["ab"]).unwrap());
}

#[test]
fn callable_paths_reuse_empty_and_component_validation() {
    assert!(matches!(callable(&[]), Err(DeclarationError::InvalidPath(PathError::Empty))));
    for components in [&[""][..], &["", "run"][..], &["module", ""][..]] {
        assert!(matches!(
            callable(components),
            Err(DeclarationError::InvalidPath(PathError::EmptyComponent))
        ));
    }
    for components in [
        &["bad namespace", "run"][..],
        &["bad#namespace", "run"][..],
        &["bad\0namespace", "run"][..],
        &["module", "bad procedure"][..],
        &["module", "bad\nprocedure"][..],
        &["module", "bad\0procedure"][..],
        &["module", "e\u{301}"][..],
        &["module", "🙂"][..],
        &["module", r#""run""#][..],
        &["module", r#"prefix"run""#][..],
        &["module", r#"f\"tag"#][..],
    ] {
        assert!(
            matches!(
                callable(components),
                Err(DeclarationError::InvalidPath(PathError::InvalidComponent(_)))
            ),
            "{components:?}"
        );
    }
}

#[test]
fn callable_paths_enforce_existing_character_and_semantic_byte_limits() {
    let longest_component = "a".repeat(Path::MAX_COMPONENT_LENGTH);
    assert!(callable(&[&longest_component]).is_ok());
    let too_long_component = "a".repeat(Path::MAX_COMPONENT_LENGTH + 1);
    assert!(matches!(
        callable(&[&too_long_component]),
        Err(DeclarationError::InvalidPath(PathError::InvalidComponent(
            IdentError::InvalidLength { max: Path::MAX_COMPONENT_LENGTH }
        )))
    ));

    let namespace = "a".repeat(32_766);
    let local = "b".repeat(32_767);
    assert!(callable(&[&namespace, &local]).is_ok());
    let too_long_local = "b".repeat(32_768);
    assert!(matches!(
        callable(&[&namespace, &too_long_local]),
        Err(DeclarationError::InvalidPath(PathError::TooLong { max }))
            if max == u16::MAX as usize
    ));

    let wide_local = "Å".repeat(21_845);
    assert!(callable(&[&wide_local]).is_ok());
    let too_wide_local = "Å".repeat(21_846);
    assert!(matches!(
        callable(&[&too_wide_local]),
        Err(DeclarationError::InvalidPath(PathError::TooLong { .. }))
    ));
}
