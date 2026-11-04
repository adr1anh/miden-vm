//! Caller-selected execution authority and policies, separate from opening evidence.

use std::path::PathBuf;

use clap::Args;
use miden_assembly::diagnostics::Report;
use miden_core::{
    Word,
    program::{EnvironmentRoot, ExecutionTarget, ProcedureKey},
    serde::read_file_bounded,
};
use miden_processor::{
    EnvironmentTraceLimits, LedgerLimits, OpeningLimits, ResolutionLimits, SessionLimits,
};
use miden_vm::internal::execution_inputs::{AdmittedExecutionInputs, ExecutionInputLimits};
use serde::Deserialize;

#[derive(Debug, Clone, Args)]
pub struct DescriptorArgs {
    /// Independently authorized entry key (0x-prefixed canonical Word)
    #[arg(long, value_parser = parse_entry_key)]
    expected_entry_key: ProcedureKey,

    /// Independently authorized environment root (0x-prefixed canonical Word)
    #[arg(long, value_parser = parse_environment_root)]
    expected_environment_root: EnvironmentRoot,
}

impl DescriptorArgs {
    pub fn descriptor(&self) -> ExecutionTarget {
        ExecutionTarget::new(self.expected_entry_key, self.expected_environment_root)
    }
}

#[derive(Debug, Clone, Args)]
pub struct ExecutionArgs {
    #[command(flatten)]
    descriptor: DescriptorArgs,

    /// Versioned JSON opening evidence; supplies no authority or private advice
    #[arg(long, value_name = "PATH")]
    environment_openings: PathBuf,

    /// Caller-selected JSON resource policy; all limits must be explicit
    #[arg(long, value_name = "PATH")]
    environment_policy: PathBuf,

    /// Maximum bytes read from the resource-policy file
    #[arg(long, value_name = "BYTES")]
    max_environment_policy_bytes: usize,
}

impl ExecutionArgs {
    pub fn admit(&self) -> Result<AdmittedExecutionInputs, Report> {
        let bytes = read_file_bounded(&self.environment_policy, self.max_environment_policy_bytes)
            .map_err(|error| Report::msg(format!("execution policy file: {error}")))?;
        let policy = Policy::parse(&bytes).map_err(Report::msg)?;
        let resolution_limits =
            ResolutionLimits::new(policy.opening, policy.ledger, policy.session);
        AdmittedExecutionInputs::read(
            &self.environment_openings,
            self.descriptor.descriptor(),
            resolution_limits,
            policy.trace,
            policy.source,
        )
        .map_err(|error| Report::msg(error.to_string()))
    }
}

fn parse_word(value: &str) -> Result<Word, String> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err("expected an exact 0x-prefixed canonical Word".into());
    }
    Word::try_from(value).map_err(|error| error.to_string())
}
fn parse_entry_key(value: &str) -> Result<ProcedureKey, String> {
    parse_word(value).map(ProcedureKey::new)
}
fn parse_environment_root(value: &str) -> Result<EnvironmentRoot, String> {
    parse_word(value).map(EnvironmentRoot::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u8,
    #[serde(with = "OpeningPolicy")]
    opening: OpeningLimits,
    #[serde(with = "LedgerPolicy")]
    ledger: LedgerLimits,
    #[serde(with = "SessionPolicy")]
    session: SessionLimits,
    #[serde(with = "TracePolicy")]
    trace: EnvironmentTraceLimits,
    #[serde(with = "SourcePolicy")]
    source: ExecutionInputLimits,
}

impl Policy {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("execution resource policy: {error}"))?;
        if policy.version != 1 {
            return Err("unsupported execution resource policy version".into());
        }
        Ok(policy)
    }
}

// Serde remote definitions construct the native policies directly. No missing-field defaults,
// policy expansion, independent cap interpretation or descriptor fields are accepted here.
#[derive(Deserialize)]
#[serde(remote = "OpeningLimits", deny_unknown_fields)]
struct OpeningPolicy {
    max_nodes: usize,
    max_depth: usize,
    max_list_children: usize,
    max_total_list_children: usize,
    max_encoded_bytes: usize,
    max_storage_bytes: usize,
}
#[derive(Deserialize)]
#[serde(remote = "LedgerLimits", deny_unknown_fields)]
struct LedgerPolicy {
    max_occurrences: usize,
    max_total_list_children: usize,
    max_encoded_bytes: usize,
    max_library_rows: usize,
    max_compression_requests: usize,
    max_retained_bytes: usize,
    max_peak_bytes: usize,
}
#[derive(Deserialize)]
#[serde(remote = "SessionLimits", deny_unknown_fields)]
struct SessionPolicy {
    max_cached_keys: usize,
    max_requests: usize,
    max_retained_bytes: usize,
    max_prepare_peak_bytes: usize,
}
#[derive(Deserialize)]
#[serde(remote = "EnvironmentTraceLimits", deny_unknown_fields)]
struct TracePolicy {
    max_events: usize,
    max_retained_bytes: usize,
    max_prepare_peak_bytes: usize,
    max_validation_work: usize,
}
#[derive(Deserialize)]
#[serde(remote = "ExecutionInputLimits", deny_unknown_fields)]
struct SourcePolicy {
    max_file_bytes: usize,
    max_openings: usize,
    max_steps: usize,
    max_encoded_bytes: usize,
    max_retained_bytes: usize,
    max_prepare_peak_bytes: usize,
    max_requests: usize,
}

#[cfg(test)]
pub(super) mod tests {
    use clap::Parser;
    use serde_json::{Value, json};

    use super::*;

    /// Explicit parse-only fixture; it grants no production policy and reads no files.
    pub(crate) fn required_args() -> [&'static str; 10] {
        [
            "--expected-entry-key",
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "--expected-environment-root",
            "0x0200000000000000000000000000000000000000000000000000000000000000",
            "--environment-openings",
            "openings.json",
            "--environment-policy",
            "policy.json",
            "--max-environment-policy-bytes",
            "8192",
        ]
    }

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        execution: ExecutionArgs,
    }

    #[test]
    fn authority_and_policy_inputs_are_all_required_and_words_are_canonical() {
        Command::try_parse_from(["test"].into_iter().chain(required_args())).unwrap();
        for index in (0..10).step_by(2) {
            let mut args = required_args().to_vec();
            args.drain(index..index + 2);
            assert!(Command::try_parse_from(["test"].into_iter().chain(args)).is_err());
        }
        for value in [
            "0x01",
            "01",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            assert!(parse_entry_key(value).is_err());
            assert!(parse_environment_root(value).is_err());
        }
    }

    #[test]
    fn zero_policies_are_preserved_and_every_budget_field_is_required() {
        let value = policy();
        let parsed = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.opening.max_storage_bytes, 0);
        assert_eq!(parsed.ledger.max_occurrences, 0);
        assert_eq!(parsed.session.max_requests, 0);
        assert_eq!(parsed.trace.max_events, 0);
        assert_eq!(parsed.source.max_requests, 0);
        for section in ["opening", "ledger", "session", "trace", "source"] {
            for field in value[section].as_object().unwrap().keys() {
                let mut missing = value.clone();
                missing[section].as_object_mut().unwrap().remove(field);
                assert!(Policy::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
            }
        }
    }

    #[test]
    fn policies_reject_authority_fields_unknown_fields_versions_and_duplicates() {
        let value = policy();
        for section in [
            None,
            Some("opening"),
            Some("ledger"),
            Some("session"),
            Some("trace"),
            Some("source"),
        ] {
            let mut extra = value.clone();
            let object = match section {
                None => &mut extra,
                Some(name) => &mut extra[name],
            };
            object["environment_root"] = json!("unauthorized");
            assert!(Policy::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
        }
        let mut wrong_version = value.clone();
        wrong_version["version"] = json!(2);
        assert!(Policy::parse(&serde_json::to_vec(&wrong_version).unwrap()).is_err());
        let duplicate = serde_json::to_string(&value).unwrap().replacen(
            "\"version\":1",
            "\"version\":1,\"version\":1",
            1,
        );
        assert!(Policy::parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn file_admission_preserves_caller_policies_and_enforces_policy_file_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use miden_core::program::{CanonicalLabel, EnvNode, ImplementationRoot, Namespace};
        use miden_processor::EnvironmentWitnessRequest;

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = std::env::temp_dir().join(format!(
            "miden-cli-execution-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        let scratch = Scratch(directory);
        let policy_path = scratch.0.join("policy.json");
        let openings_path = scratch.0.join("openings.json");
        let label = CanonicalLabel::text("cli-entry").unwrap().commitment();
        let key = Namespace::initial().procedure_key(label);
        let node = EnvNode::Mast {
            label,
            implementation: ImplementationRoot::new(Word::empty()),
        };
        let root = node.commitment().unwrap();
        let encode = |word: &Word| format!("0x{}", hex::encode(word.as_bytes()));
        std::fs::write(
            &openings_path,
            serde_json::to_vec(&json!({
                "version": 1, "entry_key": encode(key.as_word()),
                "environment_root": encode(root.as_word()),
                "openings": [{"key": encode(key.as_word()), "steps": [{
                    "node": format!("0x{}", hex::encode(node.to_bytes().unwrap())),
                    "selected_child": null
                }]}]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut value = policy();
        value["opening"]["max_nodes"] = json!(1);
        value["opening"]["max_encoded_bytes"] = json!(1024);
        value["opening"]["max_storage_bytes"] = json!(4096);
        for field in [
            "max_file_bytes",
            "max_encoded_bytes",
            "max_retained_bytes",
            "max_prepare_peak_bytes",
        ] {
            value["source"][field] = json!(1024 * 1024);
        }
        for field in ["max_openings", "max_steps", "max_requests"] {
            value["source"][field] = json!(1);
        }
        let policy_bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(&policy_path, &policy_bytes).unwrap();
        let mut args = Command::try_parse_from([
            "test".to_string(),
            "--expected-entry-key".into(),
            encode(key.as_word()),
            "--expected-environment-root".into(),
            encode(root.as_word()),
            "--environment-openings".into(),
            openings_path.to_str().unwrap().into(),
            "--environment-policy".into(),
            policy_path.to_str().unwrap().into(),
            "--max-environment-policy-bytes".into(),
            policy_bytes.len().to_string(),
        ])
        .unwrap()
        .execution;
        let admitted = args.admit().unwrap();
        let expected = Policy::parse(&policy_bytes).unwrap();
        assert_eq!(admitted.resolution_limits().opening_limits(), expected.opening);
        assert_eq!(admitted.resolution_limits().ledger_limits(), expected.ledger);
        assert_eq!(admitted.resolution_limits().session_limits(), expected.session);
        assert_eq!(admitted.trace_limits(), expected.trace);
        let request = EnvironmentWitnessRequest { root, key, limits: expected.opening };
        admitted
            .source()
            .get(request)
            .unwrap()
            .unwrap()
            .verify(root, key, expected.opening)
            .unwrap();

        args.max_environment_policy_bytes -= 1;
        let error = args.admit().err().expect("policy file must exceed its limit");
        assert!(error.to_string().contains("execution policy file"));
        args.max_environment_policy_bytes += 1;
        args.descriptor.expected_entry_key = ProcedureKey::new(Word::empty());
        let error = args.admit().err().expect("evidence must not supply caller authority");
        assert!(error.to_string().contains("descriptor differs from caller"));
    }

    fn policy() -> Value {
        json!({
            "version": 1,
            "opening": {"max_nodes":0,"max_depth":0,"max_list_children":0,
                "max_total_list_children":0,"max_encoded_bytes":0,"max_storage_bytes":0},
            "ledger": {"max_occurrences":0,"max_total_list_children":0,"max_encoded_bytes":0,
                "max_library_rows":0,"max_compression_requests":0,"max_retained_bytes":0,
                "max_peak_bytes":0},
            "session": {"max_cached_keys":0,"max_requests":0,"max_retained_bytes":0,
                "max_prepare_peak_bytes":0},
            "trace": {"max_events":0,"max_retained_bytes":0,"max_prepare_peak_bytes":0,
                "max_validation_work":0},
            "source": {"max_file_bytes":0,"max_openings":0,"max_steps":0,
                "max_encoded_bytes":0,"max_retained_bytes":0,"max_prepare_peak_bytes":0,
                "max_requests":0}
        })
    }
}
