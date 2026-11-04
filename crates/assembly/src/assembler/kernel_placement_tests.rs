use miden_core::program::CanonicalLabel;

use super::*;
use crate::testing::TestContext;

fn canonical(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

fn binding(home: &[&str], components: &[&str]) -> ProcedureName {
    let home =
        NamespacePath::new(home.iter().map(|label| CanonicalLabel::text(label).unwrap()).collect());
    ProcedureName::new(home, canonical(components)).unwrap()
}

fn assembler(context: &TestContext, bindings: &[(&str, ProcedureName)]) -> Assembler {
    let mut assembler =
        Assembler::new(context.source_manager()).with_namespace_plan(NamespacePath::new(vec![]));
    for (path, binding) in bindings {
        assembler = assembler
            .with_callable_binding(Arc::from(Path::new(path)), binding.clone())
            .unwrap();
    }
    assembler
}

fn kernel(context: &TestContext, source: &str) -> Box<ast::Module> {
    ast::Module::parser(Some(ModuleKind::Kernel))
        .parse_str(Some(Path::KERNEL), source, context.source_manager())
        .unwrap()
}

#[test]
fn kernel_retains_root_exports_child_helpers_and_foreign_root_declarations() {
    let context = TestContext::default();
    let service = binding(&[], &["service"]);
    let private = binding(&["kernel-helpers"], &["private"]);
    let support = binding(&["kernel-helpers"], &["support", "run"]);
    let foreign = binding(&[], &["foreign"]);
    let mut assembler = assembler(
        &context,
        &[
            ("::$kernel::service", service.clone()),
            ("::$kernel::private", private.clone()),
            ("::support::run", support.clone()),
        ],
    );
    assembler
        .link_callable_declarations(
            Arc::from(Path::new("::dep")),
            [CallableDeclaration::new(Ident::new("run").unwrap(), foreign.clone())],
        )
        .unwrap();
    let root = kernel(
        &context,
        "use support\nuse dep\nproc private push.7 end\n\
         pub proc service exec.private exec.support::run exec.dep::run end",
    );
    let support_module =
        context.parse_module("namespace support\npub proc run push.1 end").unwrap();
    let product = assembler
        .assemble_library_modules("kernel".into(), root, [support_module], TargetType::Kernel)
        .unwrap();
    for binding in [&service, &private, &support, &foreign] {
        assert_eq!(product.callables().binding(binding.key()), Some(binding));
    }
    for binding in [&service, &private, &support] {
        assert!(product.callables().selected_implementation(binding.key()).is_some());
    }
    assert_eq!(product.callables().selected_implementation(foreign.key()), None);
    assert_eq!(
        product.callable_key_for_definition(Path::new("::support::run")),
        Some(support.key()),
    );
}

#[test]
fn kernel_rejects_an_explicit_child_binding_for_a_public_export() {
    let context = TestContext::default();
    let assembler =
        assembler(&context, &[("::$kernel::service", binding(&["kernel"], &["service"]))]);
    let error = assembler
        .assemble_library_modules(
            "kernel".into(),
            kernel(&context, "pub proc service push.1 end"),
            [],
            TargetType::Kernel,
        )
        .err()
        .expect("a textual kernel home cannot replace the fixed root");
    assert!(error.to_string().contains("must be in the fixed root syscall namespace"));
}

#[test]
fn kernel_rejects_a_retained_private_root_binding_but_ordinary_libraries_allow_it() {
    let context = TestContext::default();
    for kernel_target in [true, false] {
        let namespace = if kernel_target { "::$kernel" } else { "::library" };
        let service_path = format!("{namespace}::service");
        let private_path = format!("{namespace}::private");
        let assembler = assembler(
            &context,
            &[
                (&service_path, binding(&[], &["service"])),
                (&private_path, binding(&[], &["private"])),
            ],
        );
        // Explicitly selected private definitions remain callable roots even without references.
        let source = "proc private push.7 end\npub proc service push.1 end";
        let root = if kernel_target {
            kernel(&context, source)
        } else {
            context.parse_module(format!("namespace library\n{source}")).unwrap()
        };
        let result = assembler.assemble_library_modules(
            "test".into(),
            root,
            [],
            if kernel_target {
                TargetType::Kernel
            } else {
                TargetType::Library
            },
        );
        if kernel_target {
            let error = result.err().expect("nonexported concrete helpers cannot occupy root");
            assert!(error.to_string().contains("must be beneath a child Env namespace"));
        } else {
            let product = result.unwrap();
            assert_eq!(
                product.callable_key_for_definition(Path::new(&private_path)),
                Some(binding(&[], &["private"]).key()),
            );
        }
    }
}

#[test]
fn kernel_reexports_preserve_the_defining_root_key_and_reject_fragment_collisions() {
    let context = TestContext::default();
    for collision in [false, true] {
        let target = binding(&[], &["service"]);
        let mut assembler = assembler(&context, &[("::left::run", target.clone())]);
        let left = context.parse_module("namespace left\npub proc run push.1 end").unwrap();
        let mut support = vec![left];
        let root = if collision {
            assembler = assembler
                .with_callable_binding(Arc::from(Path::new("::right::run")), target.clone())
                .unwrap();
            support.push(context.parse_module("namespace right\npub proc run push.1 end").unwrap());
            kernel(&context, "pub use {run as first} from left\npub use {run as second} from right")
        } else {
            kernel(&context, "pub use {run as first, run as second} from left")
        };
        let result =
            assembler.assemble_library_modules("kernel".into(), root, support, TargetType::Kernel);
        if collision {
            let error = result.err().expect("distinct fragments cannot reuse a root label");
            assert!(error.to_string().contains("duplicate callable binding"), "{error}");
        } else {
            let product = result.unwrap();
            assert_eq!(product.callables().bindings().len(), 1);
            for alias in ["first", "second"] {
                assert_eq!(
                    product.callables().key_for_visible_path(&canonical(&["$kernel", alias])),
                    Some(target.key()),
                );
            }
            assert_eq!(product.callable_key_for_definition(Path::new("::$kernel::first")), None);
            assert_eq!(
                product.callable_key_for_definition(Path::new("::left::run")),
                Some(target.key()),
            );
        }
    }
}

#[test]
fn kernel_validates_compiled_exports_without_restricting_foreign_helpers() {
    let context = TestContext::default();
    for at_root in [false, true] {
        let foreign = binding(if at_root { &[] } else { &["child"] }, &["foreign"]);
        let product = assembler(&context, &[("::dep::run", foreign.clone())])
            .assemble_library_modules(
                "dependency".into(),
                context.parse_module("namespace dep\npub proc run push.1 end").unwrap(),
                [],
                TargetType::Library,
            )
            .unwrap();
        let naming = product.naming().clone();
        let package = product.into_artifact(false).unwrap();
        for exported in [false, true] {
            let source = if exported {
                "use dep\npub use {run as published} from ::dep\npub proc service exec.dep::run end"
            } else {
                "use dep\npub proc service exec.dep::run end"
            };
            let result = assembler(
                &context,
                &[
                    ("::$kernel::service", binding(&[], &["service"])),
                    ("::dep::run", foreign.clone()),
                ],
            )
            .with_package(package.clone().into(), Linkage::Static, naming.clone())
            .unwrap()
            .assemble_library_modules(
                "kernel".into(),
                kernel(&context, source),
                [],
                TargetType::Kernel,
            );
            if exported && !at_root {
                let error = result.err().expect("compiled public exports also require N0");
                assert!(
                    error.to_string().contains("must be in the fixed root syscall namespace"),
                    "{error:?}"
                );
                continue;
            }
            let product = result.unwrap();
            assert_eq!(product.callables().binding(foreign.key()), Some(&foreign));
            assert!(product.callables().selected_implementation(foreign.key()).is_some());
            assert_eq!(
                product.callables().key_for_visible_path(&canonical(&["$kernel", "published"])),
                exported.then_some(foreign.key()),
            );
            assert_eq!(product.callables().key_for_visible_path(&canonical(&["dep", "run"])), None);
        }
    }
}
