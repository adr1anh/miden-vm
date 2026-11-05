use std::fmt::Write;

use miden_assembly::{Report, diagnostics::IntoDiagnostic};
use miden_core::{Word, advice::AdviceMap, program::CanonicalLabel};
use miden_mast_package::{CallableProcedurePath, NamespacePlan, PackageNaming};

/// Emits the compiler's complete owned inventory for the embedded package.
///
/// The generated code reconstructs owned values, then the loader checks them against the exact
/// Package9 transport. This does not decode or admit arbitrary package naming under a profile.
pub fn render(
    naming: &PackageNaming,
    vm: &VerifierMetadata,
    pvm: &VerifierMetadata,
) -> Result<String, Report> {
    let mut output = String::from(
        r#"// Generated from the core compiler's owned naming inventory.
use miden_core::{Word, program::{CanonicalLabel, ImplementationRoot, ProcedureKey}};
use miden_mast_package::{CallableBinding, CallableProcedurePath, NamespacePlan, PackageCallables, PackageNaming};

type Home = &'static [&'static [u8]];
type Path = &'static [&'static str];

const HOME: Home = "#,
    );
    write_home(&mut output, naming.namespace_plan())?;
    output.push_str(";\nconst BINDINGS: &[(Home, Path)] = &[\n");
    for (_, binding) in naming.callables().bindings() {
        output.push_str("    (");
        write_home(&mut output, binding.namespace_plan())?;
        output.push_str(", ");
        write_path(&mut output, binding.path());
        output.push_str("),\n");
    }
    output.push_str("];\nconst ALIASES: &[(Path, [u8; 32])] = &[\n");
    for (path, key) in naming.callables().visible_paths() {
        output.push_str("    (");
        write_path(&mut output, path);
        writeln!(output, ", {:?}),", key.as_word().as_bytes()).unwrap();
    }
    output.push_str("];\nconst IMPLEMENTATIONS: &[([u8; 32], [u8; 32])] = &[\n");
    for (key, implementation) in naming.callables().selected_implementations() {
        writeln!(
            output,
            "    ({:?}, {:?}),",
            key.as_word().as_bytes(),
            implementation.as_word().as_bytes(),
        )
        .unwrap();
    }
    output.push_str("];\nconst ENTRY: Option<[u8; 32]> = ");
    match naming.entry_key() {
        Some(key) => writeln!(output, "Some({:?});", key.as_word().as_bytes()).unwrap(),
        None => output.push_str("None;\n"),
    }
    output.push_str(
        r#"
fn home(labels: Home) -> NamespacePlan {
    NamespacePlan::new(labels.iter().map(|bytes| {
        CanonicalLabel::from_bytes(bytes).expect("generated core home label is valid")
    }).collect())
}

fn path(components: Path) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    ).expect("generated core semantic path is valid")
}

fn word(bytes: &[u8; 32]) -> Word {
    Word::try_from(bytes.as_slice()).expect("generated core word is canonical")
}

pub(super) fn reconstruct() -> PackageNaming {
    let bindings = BINDINGS.iter().map(|&(labels, components)| {
        CallableBinding::new(home(labels), path(components))
            .expect("generated core binding is valid")
    });
    let aliases = ALIASES.iter().map(|&(components, key)| {
        (path(components), ProcedureKey::new(word(&key)))
    });
    let implementations = IMPLEMENTATIONS.iter().map(|&(key, implementation)| {
        (ProcedureKey::new(word(&key)), ImplementationRoot::new(word(&implementation)))
    });
    let callables = PackageCallables::new(bindings, aliases, implementations)
        .expect("generated core callable inventory is valid");
    let entry = ENTRY.as_ref().map(|key| ProcedureKey::new(word(key)));
    PackageNaming::new(home(HOME), callables, entry)
        .expect("generated core entry metadata is valid")
}
"#,
    );
    write_verifier_metadata(&mut output, "vm", vm);
    write_verifier_metadata(&mut output, "pvm", pvm);
    Ok(output)
}

/// Trusted producer metadata for a relation's exact required static advice subset.
pub struct VerifierMetadata {
    relation: Word,
    inventory: Word,
    resources: Vec<(Word, usize)>,
}

impl VerifierMetadata {
    pub fn new(relation: Word, resources: &AdviceMap) -> Self {
        Self {
            relation,
            inventory: resources.commitment(),
            resources: resources.iter().map(|(key, values)| (*key, values.len())).collect(),
        }
    }
}

fn write_verifier_metadata(output: &mut String, name: &str, metadata: &VerifierMetadata) {
    // Only commitments, keys and lengths enter the native sidecar. The package retains its
    // original advice, and proof producers continue to deliver the canonical ACE streams.
    writeln!(
        output,
        "\npub(super) fn {name}_verifier_metadata() -> (Word, Word, &'static [([u8; 32], usize)]) {{"
    )
    .unwrap();
    writeln!(output, "    (word(&{:?}),", metadata.relation.as_bytes()).unwrap();
    writeln!(output, "     word(&{:?}), &[", metadata.inventory.as_bytes()).unwrap();
    for (key, length) in &metadata.resources {
        writeln!(output, "        ({:?}, {length}),", key.as_bytes()).unwrap();
    }
    output.push_str("    ])\n}\n");
}

fn write_home(output: &mut String, home: &NamespacePlan) -> Result<(), Report> {
    output.push_str("&[");
    for label in home.home() {
        // This built-in producer uses no TypedId homes. Require the same owned built-in label
        // constructor that reconstructs the sidecar, without inventing a codec validator.
        CanonicalLabel::from_bytes(label.as_bytes()).into_diagnostic()?;
        write!(output, "&{:?},", label.as_bytes()).unwrap();
    }
    output.push(']');
    Ok(())
}

fn write_path(output: &mut String, path: &CallableProcedurePath) {
    output.push_str("&[");
    for component in path.components() {
        // Rust's string Debug representation preserves exact semantic UTF-8, quotes and escapes.
        write!(output, "{component:?},").unwrap();
    }
    output.push(']');
}
