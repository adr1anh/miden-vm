use super::*;

#[test]
fn fixture_metadata_names_private_definitions_and_exact_semantic_paths() -> Result<(), Report> {
    let context = TestContext::new();
    let module = context.parse_module(
        r#"
        namespace fixtures::"math::wide"
        pub proc first procref.callback end
        proc callback push.7 end
        proc unused_helper push.9 end
        pub use {first as exported_alias} from fixtures::"math::wide"
        "#,
    )?;
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(&module)?;
    for name in ["first", "callback", "unused_helper"] {
        let declaration = module.path().join(name);
        let binding = fixture.binding(&declaration).expect("all concrete definitions are named");
        assert_eq!(binding.path().components(), &["fixtures", "math::wide", name]);
    }
    assert!(fixture.binding(&module.path().join("exported_alias")).is_none());
    Ok(())
}

#[test]
fn fixture_identity_preserves_typed_homes_and_ignores_bodies() -> Result<(), Report> {
    let context = TestContext::new();
    let first = context.parse_module("namespace fixture pub proc run push.1 end")?;
    let second = context.parse_module("namespace fixture pub proc run push.99 end")?;
    let home = vec![
        CanonicalLabel::text("fixture-owner").unwrap(),
        CanonicalLabel::library_id(Word::default()),
        CanonicalLabel::revision(NonZeroU32::new(7).unwrap()),
        CanonicalLabel::text("nested").unwrap(),
    ];
    let mut first_fixture = FixtureNamespace::new(NamespacePlan::new(home.clone()));
    first_fixture.add_module(&first)?;
    let mut second_fixture = FixtureNamespace::new(NamespacePlan::new(home.clone()));
    second_fixture.add_module(&second)?;
    let declaration = first.path().join("run");
    let binding = first_fixture.binding(&declaration).unwrap();
    assert_eq!(binding.namespace_plan().home(), home);
    assert_eq!(Some(binding), second_fixture.binding(&declaration));

    let mut text_revision_home = home;
    text_revision_home[2] = CanonicalLabel::text("7").unwrap();
    let mut changed = FixtureNamespace::new(NamespacePlan::new(text_revision_home));
    changed.add_module(&first)?;
    assert_ne!(binding.key(), changed.binding(&declaration).unwrap().key());
    assert!(
        first_fixture
            .add_binding(
                declaration.into(),
                changed.binding(Path::new("::fixture::run")).unwrap().clone(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn raw_fixture_configuration_limits_metadata_to_the_actual_module_cohort() -> Result<(), Report> {
    let context = TestContext::new();
    let root = context.parse_module("namespace selected pub proc run push.1 end")?;
    let absent = context.parse_module("namespace absent proc helper push.2 end")?;
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(&root)?;
    fixture.add_module(&absent)?;
    let package = fixture
        .configure(Assembler::new(context.source_manager()), [&*root])?
        .assemble_library("selected", root, None::<Box<Module>>)?;
    assert_eq!(package.mast_forest().procedure_roots().len(), 1);
    Ok(())
}

#[test]
fn fixture_configuration_rejects_a_conflicting_explicit_home() -> Result<(), Report> {
    let context = TestContext::new();
    let fixture = FixtureNamespace::assembly_tests();
    let different = NamespacePlan::new(vec![CanonicalLabel::text("custom-fixture-home").unwrap()]);
    let assembler = Assembler::new(context.source_manager()).with_namespace_plan(different.clone());
    assert_eq!(assembler.namespace_plan(), Some(&different));
    let error = fixture
        .configure(assembler, core::iter::empty())
        .err()
        .expect("a fixture must not overwrite an explicit different home");
    assert!(
        error
            .to_string()
            .contains("conflicts with the assembler's explicit NamespacePlan")
    );

    let assembler = fixture.configure(
        Assembler::new(context.source_manager())
            .with_namespace_plan(fixture.namespace_plan().clone()),
        core::iter::empty(),
    )?;
    assert_eq!(assembler.namespace_plan(), Some(fixture.namespace_plan()));
    Ok(())
}

#[test]
fn raw_assembler_still_requires_an_explicit_namespace_plan() {
    let context = TestContext::new();
    let error = Assembler::new(context.source_manager())
        .assemble_program("missing-home", "begin push.1 end")
        .expect_err("test utility metadata must not become an assembler default");
    assert!(error.to_string().contains("assembly requires an explicit caller NamespacePlan"));
}

#[test]
fn test_context_names_entrypoints_and_all_linked_source_helpers() -> Result<(), Report> {
    let mut context = TestContext::new();
    context
        .add_module("namespace helpers pub proc run push.1 end proc unused_helper push.2 end")?;
    let program = context.assemble("use helpers begin exec.helpers::run end")?;
    assert_eq!(program.mast_forest().procedure_roots().len(), 3);
    assert!(
        program
            .mast_forest()
            .nodes()
            .iter()
            .any(|node| { matches!(node, miden_core::mast::MastNode::Exec(_)) })
    );
    Ok(())
}

#[test]
fn imported_fixtures_require_explicit_metadata_and_preserve_equal_body_keys() -> Result<(), Report>
{
    let source_context = TestContext::new();
    let root = source_context
        .parse_module("namespace imported pub proc first push.1 end pub proc second push.1 end")?;
    let home = NamespacePlan::new(vec![
        CanonicalLabel::text("foreign-fixture").unwrap(),
        CanonicalLabel::revision(NonZeroU32::new(3).unwrap()),
    ]);
    let mut fixture = FixtureNamespace::new(home);
    fixture.add_module(&root)?;
    let package: Arc<Package> = fixture
        .configure(Assembler::new(source_context.source_manager()), [&*root])?
        .assemble_library("foreign", root, None::<Box<Module>>)?
        .into();
    let exports = package
        .manifest
        .exports()
        .filter_map(|export| export.as_procedure())
        .collect::<Vec<_>>();
    assert_eq!(exports.len(), 2);
    assert_eq!(exports[0].digest, exports[1].digest);
    assert_ne!(
        fixture.binding(Path::new("::imported::first")).unwrap().key(),
        fixture.binding(Path::new("::imported::second")).unwrap().key(),
    );
    let mut missing_bindings = TestContext::new();
    let error = missing_bindings
        .add_library(package.clone())
        .expect_err("raw code availability must not admit an unconfigured foreign home");
    assert!(error.to_string().contains("unexpected fixture home"));
    let error = missing_bindings
        .assemble("use imported begin exec.imported::first end")
        .expect_err("failed naming admission must not install the foreign module");
    assert!(error.to_string().contains("imported"), "{error:?}");

    let mut context = TestContext::new();
    assert!(
        context
            .add_library_with_bindings(package.clone(), &FixtureNamespace::assembly_tests())
            .is_err()
    );
    context.add_library_with_bindings(package, &fixture)?;
    let program = context.assemble(
        "use {first as chosen, second} from imported begin exec.chosen exec.second end",
    )?;
    let keys = program
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            miden_core::mast::MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            fixture.binding(Path::new("::imported::first")).unwrap().key(),
            fixture.binding(Path::new("::imported::second")).unwrap().key(),
        ]
        .into_iter()
        .collect(),
    );
    Ok(())
}
