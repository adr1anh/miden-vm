use alloc::vec::Vec;

use crate::{
    Path,
    ast::{
        Instruction, InvocationTarget, InvokeKind, Module, Op, Procedure, SymbolResolutionError,
        constants::ConstEvalError,
    },
    sema::{SemanticAnalysisError, SyntaxError},
    testing::SyntaxTestContext,
};

fn procedure<'a>(module: &'a Module, name: &str) -> &'a Procedure {
    module
        .procedures()
        .find(|procedure| procedure.name().as_str() == name)
        .unwrap_or_else(|| panic!("expected procedure {name}"))
}

#[test]
fn retained_invocations_allow_direct_runtime_recursion() {
    let context = SyntaxTestContext::default();
    for (mnemonic, kind) in [
        ("exec", InvokeKind::Exec),
        ("call", InvokeKind::Call),
        ("procref", InvokeKind::ProcRef),
    ] {
        let source = format!("namespace recursive\nproc recurse\n    {mnemonic}.recurse\nend\n");
        let module = context.parse_module(&source).expect("runtime self references are valid");
        let invoked = procedure(&module, "recurse").invoked().collect::<Vec<_>>();
        assert_eq!(invoked.len(), 1);
        assert_eq!(invoked[0].kind, kind);
        assert!(matches!(
            &invoked[0].target,
            InvocationTarget::Symbol(name) if name.as_str() == "recurse"
        ));
    }
}

#[test]
fn retained_invocations_allow_qualified_runtime_recursion() {
    let context = SyntaxTestContext::default();
    for (mnemonic, kind) in [
        ("exec", InvokeKind::Exec),
        ("call", InvokeKind::Call),
        ("procref", InvokeKind::ProcRef),
    ] {
        let source =
            format!("namespace recursive\nproc recurse\n    {mnemonic}.recursive::recurse\nend\n");
        let module = context
            .parse_module(&source)
            .expect("qualified runtime self references are valid");
        let invoked = procedure(&module, "recurse").invoked().collect::<Vec<_>>();
        assert_eq!(invoked.len(), 1);
        assert_eq!(invoked[0].kind, kind);
        assert!(matches!(
            &invoked[0].target,
            InvocationTarget::Path(path)
                if path.inner().as_ref() == Path::new("recursive::recurse")
        ));
    }
}

#[test]
fn retained_invocations_allow_mutual_runtime_recursion() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module(
            "namespace recursive\n\
             proc first exec.second end\n\
             proc second call.third end\n\
             proc third procref.first end\n",
        )
        .expect("runtime reference cycles are valid");
    for (name, kind, target) in [
        ("first", InvokeKind::Exec, "second"),
        ("second", InvokeKind::Call, "third"),
        ("third", InvokeKind::ProcRef, "first"),
    ] {
        let invoked = procedure(&module, name).invoked().collect::<Vec<_>>();
        assert_eq!(invoked.len(), 1);
        assert_eq!(invoked[0].kind, kind);
        assert!(matches!(
            &invoked[0].target,
            InvocationTarget::Symbol(name) if name.as_str() == target
        ));
    }
}

#[test]
fn inline_keeps_distinct_metadata_alongside_runtime_references() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module(
            "namespace recursive\n\
             proc recurse\n\
                 exec.recurse\n\
                 call.recurse\n\
                 procref.recurse\n\
                 inline.recurse\n\
             end\n",
        )
        .expect("source analysis retains inline edges for assembly to validate");
    assert_eq!(
        procedure(&module, "recurse")
            .invoked()
            .map(|invoke| invoke.kind)
            .collect::<Vec<_>>(),
        [InvokeKind::Exec, InvokeKind::Call, InvokeKind::ProcRef, InvokeKind::Inline]
    );
}

#[test]
fn inline_resolves_item_and_module_aliases_without_deciding_eligibility() {
    let context = SyntaxTestContext::default().with_warnings_as_errors(true);
    let module = context
        .parse_program(
            "use ::ordinary::interface as service\n\
             use {read as item} from ::ordinary\n\
             begin\n\
                 inline.service::read\n\
                 inline.item\n\
             end\n",
        )
        .expect("source aliases resolve before assembly checks ownership and explicit pins");
    for name in ["service", "item"] {
        assert!(module.get_import(name).expect("expected import alias").is_used());
    }
    let entry = module.procedures().find(|procedure| procedure.is_entrypoint()).unwrap();
    let invoked = entry.invoked().collect::<Vec<_>>();
    assert_eq!(invoked.len(), 2);
    assert!(invoked.iter().all(|invoke| invoke.kind == InvokeKind::Inline));
    assert!(invoked.iter().any(|invoke| matches!(
        &invoke.target,
        InvocationTarget::Symbol(name) if name.as_str() == "item"
    )));
    assert!(invoked.iter().any(|invoke| matches!(
        &invoke.target,
        InvocationTarget::Path(path) if path.inner().as_ref() == Path::new("service::read")
    )));
}

#[test]
fn qualified_syscalls_resolve_ordinary_and_kernel_module_aliases() {
    let context = SyntaxTestContext::default().with_warnings_as_errors(true);
    let module = context
        .parse_program(
            "use ::ordinary::interface as service\n\
             use ::$kernel as legacy\n\
             begin\n\
                 syscall.service::read\n\
                 syscall.legacy::read\n\
             end\n",
        )
        .expect("qualified syscalls use ordinary import lookup regardless of path spelling");
    for name in ["service", "legacy"] {
        assert!(module.get_import(name).expect("expected module alias").is_used());
    }
    let entry = module.procedures().find(|procedure| procedure.is_entrypoint()).unwrap();
    let invoked = entry.invoked().collect::<Vec<_>>();
    assert_eq!(invoked.len(), 2);
    assert!(invoked.iter().all(|invoke| invoke.kind == InvokeKind::SysCall));
    for target in ["service::read", "legacy::read"] {
        assert!(invoked.iter().any(|invoke| {
            matches!(
                &invoke.target,
                InvocationTarget::Path(path) if path.inner().as_ref() == Path::new(target)
            )
        }));
    }
}

#[test]
fn unqualified_syscalls_preserve_item_aliases_and_mark_them_used() {
    let context = SyntaxTestContext::default().with_warnings_as_errors(true);
    let module = context
        .parse_program(
            "use {read as ordinary_read} from ::ordinary::interface\n\
             use {read as kernel_read} from ::$kernel\n\
             begin\n\
                 syscall.ordinary_read\n\
                 syscall.kernel_read\n\
             end\n",
        )
        .expect("unqualified syscall item aliases use ordinary symbol lookup");
    for name in ["ordinary_read", "kernel_read"] {
        assert!(module.get_import(name).expect("expected item alias").is_used());
    }
    let entry = module.procedures().find(|procedure| procedure.is_entrypoint()).unwrap();
    let invoked = entry.invoked().collect::<Vec<_>>();
    assert_eq!(invoked.len(), 2);
    for target in ["ordinary_read", "kernel_read"] {
        assert!(invoked.iter().any(|invoke| {
            invoke.kind == InvokeKind::SysCall
                && matches!(
                    &invoke.target,
                    InvocationTarget::Symbol(name) if name.as_str() == target
                )
        }));
    }
}

#[test]
fn unqualified_syscalls_preserve_local_procedure_lookup() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program("proc read nop end\nbegin syscall.read end\n")
        .expect("local syscall names use ordinary symbol lookup");
    let entry = module.procedures().find(|procedure| procedure.is_entrypoint()).unwrap();
    let invoked = entry.invoked().next().expect("expected syscall metadata");
    assert_eq!(invoked.kind, InvokeKind::SysCall);
    assert!(matches!(&invoked.target, InvocationTarget::Symbol(name) if name.as_str() == "read"));
}

#[test]
fn unqualified_syscalls_preserve_source_names_for_frontend_alias_lookup() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program("begin syscall.read end\n")
        .expect("unqualified syscall names remain valid source");
    let entry = module.procedures().find(|procedure| procedure.is_entrypoint()).unwrap();
    let Op::Inst(instruction) = entry.body().iter().next().expect("expected syscall body") else {
        panic!("expected a syscall instruction");
    };
    let Instruction::SysCall(InvocationTarget::Symbol(name)) = instruction.inner() else {
        panic!("expected the unresolved source name");
    };
    assert_eq!(name.as_str(), "read");
}

#[test]
fn runtime_recursion_does_not_allow_constant_evaluation_cycles() {
    let context = SyntaxTestContext::default();
    for source in [
        "const CYCLE = CYCLE\nbegin push.CYCLE end\n",
        "const FIRST = SECOND\nconst SECOND = FIRST\nbegin push.FIRST end\n",
    ] {
        let error = context.parse_program(source).expect_err("constant cycles remain invalid");
        let syntax_error = error.downcast_ref::<SyntaxError>().expect("expected semantic errors");
        assert!(syntax_error.errors.iter().any(|error| matches!(
            error,
            SemanticAnalysisError::ConstEvalError(ConstEvalError::ConstEvalCycle { .. })
        )));
    }
}

#[test]
fn retained_invocations_still_reject_non_procedure_local_targets() {
    let context = SyntaxTestContext::default();
    for mnemonic in ["exec", "call", "syscall", "procref", "inline"] {
        let source = format!("const TARGET = 1\nbegin {mnemonic}.TARGET end\n");
        let error = context.parse_program(&source).expect_err("constants are not callable targets");
        let syntax_error = error.downcast_ref::<SyntaxError>().expect("expected semantic errors");
        assert!(syntax_error.errors.iter().any(|error| matches!(
            error,
            SemanticAnalysisError::SymbolResolutionError(inner)
                if matches!(**inner, SymbolResolutionError::InvalidSymbolType { .. })
        )));
    }
}

#[test]
fn qualified_syscall_cannot_treat_an_item_alias_as_a_module() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program("use {read as item} from ::ordinary\nbegin syscall.item::child end\n")
        .expect_err("an item alias cannot qualify a syscall target");
    let syntax_error = error.downcast_ref::<SyntaxError>().expect("expected semantic errors");
    assert!(
        syntax_error.errors.iter().any(|error| matches!(
            error,
            SemanticAnalysisError::InvalidInvokeTargetViaImport { .. }
        ))
    );
}
