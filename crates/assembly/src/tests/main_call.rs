// PROGRAM WITH $main CALL
// ================================================================================================
use super::*;
use crate::testing::{FixtureNamespace, FixtureProgram};

#[test]
fn simple_main_call() -> TestResult {
    let mut context = TestContext::default();

    // compile account module
    let account_code = context.parse_module(source_file!(
        &context,
        "\
        namespace context::account
        pub proc account_method_1
            push.2.1 add
        end

        pub proc account_method_2
            push.3.1 sub
        end
        "
    ))?;

    context.add_module(account_code)?;

    // compile note 1 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_1
        end
        "
    ))?;

    // compile note 2 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_2
        end
        "
    ))?;
    Ok(())
}

#[test]
fn call_without_path() -> TestResult {
    let context = TestContext::default();

    let account_code1_src = source_file!(
        &context,
        "\
namespace account_code1

pub proc account_method_1
    push.2.1 add
end

pub proc account_method_2
    push.3.1 sub
end
"
    );
    let account_code2_src = source_file!(
        &context,
        "\
namespace account_code2

pub proc account_method_1
    push.2.2 add
end

pub proc account_method_2
    push.4.1 sub
end
"
    );

    let account_code1 = context.parse_module(account_code1_src)?;
    let account_code2 = context.parse_module(account_code2_src)?;
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(&account_code1)?;
    fixture.add_module(&account_code2)?;
    let keys = [
        fixture.binding(&account_code1.path().join("account_method_1")).unwrap().key(),
        fixture.binding(&account_code1.path().join("account_method_2")).unwrap().key(),
        fixture.binding(&account_code2.path().join("account_method_1")).unwrap().key(),
        fixture.binding(&account_code2.path().join("account_method_2")).unwrap().key(),
    ];

    // Compile the existing word-target syntax with keys from the explicit fixture declarations.
    let main_src = source_file!(
        &context,
        format!(
            "
        begin
            # call the account_method_1 from the first module (account_code1)
            call.{}

            # call the account_method_2 from the first module (account_code1)
            call.{}

            # call the account_method_1 from the second module (account_code2)
            call.{}

            # call the account_method_2 from the second module (account_code2)
            call.{}
        end
        ",
            keys[0].as_word(),
            keys[1].as_word(),
            keys[2].as_word(),
            keys[3].as_word(),
        )
    );

    let main = context.parse_program(main_src)?;
    fixture.add_module(&main)?;

    let mut assembler = fixture.configure(
        Assembler::new(context.source_manager()),
        [&*account_code1, &*account_code2, &*main],
    )?;
    assembler.compile_and_statically_link_all([account_code1, account_code2])?;
    let program = assembler.assemble_program("main", main)?.fixture_program();
    let targets = program
        .package()
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) => {
                assert!(!call.is_syscall());
                Some(call.target())
            },
            MastNode::Exec(_) => panic!("call source must retain CALL mode"),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(targets.len(), 4);
    assert_eq!(targets, keys.into_iter().collect());
    assert_eq!(program.package().mast_forest().num_procedures(), 5);
    assert_all_nodes_reachable_from_roots(program.package().mast_forest());

    Ok(())
}
