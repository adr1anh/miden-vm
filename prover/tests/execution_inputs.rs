#![cfg(feature = "std")]

#[path = "../../miden-vm/src/internal/execution_inputs.rs"]
mod execution_inputs;

use std::{
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
};

use execution_inputs::{AdmittedExecutionInputs, ExecutionInputLimits};
use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ExecutionDescriptor, ImplementationRoot,
        LabelCommitment, Namespace, ProcedureKey, Program, StackInputs,
    },
    serde::Serializable,
};
use miden_processor::{
    DefaultHost, EnvironmentTraceLimits, EnvironmentWitnessRequest, ExecutionEnvironment,
    ExecutionError, ExecutionOptions, FastProcessor, LedgerLimits, OpeningLimits, OpeningStep,
    SessionLimits,
};
use serde_json::{Value, json};

#[test]
fn admitted_named_program_executes_with_the_callers_authority_and_policies() {
    let fixture = Fixture::new();
    let admitted = fixture.admit(&fixture.document(), input_limits()).unwrap();
    assert_eq!(admitted.environment(), fixture.environment);
    assert_eq!(admitted.trace_limits(), trace_limits());
    assert_ne!(fixture.entry.into_word(), fixture.program.hash());
    assert_ne!(fixture.entry, fixture.service);

    let mut host = DefaultHost::default().with_environment_source(admitted.source());
    let output = FastProcessor::new(StackInputs::default())
        .with_options(
            ExecutionOptions::default().with_environment_trace_limits(admitted.trace_limits()),
        )
        .unwrap()
        .execute_sync(&fixture.program, admitted.environment(), &mut host)
        .unwrap();
    assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(13)));
}

#[test]
fn admission_preserves_independent_zero_native_trace_and_source_policies() {
    let fixture = Fixture::new();
    let environment = ExecutionEnvironment::new(
        fixture.environment.descriptor(),
        fixture.environment.opening_limits(),
        LedgerLimits {
            max_occurrences: 0,
            max_total_list_children: 0,
            max_encoded_bytes: 0,
            max_library_rows: 0,
            max_compression_requests: 0,
            max_retained_bytes: 0,
            max_peak_bytes: 0,
        },
        SessionLimits {
            max_cached_keys: 0,
            max_requests: 0,
            max_retained_bytes: 0,
            max_prepare_peak_bytes: 0,
        },
    );
    let trace = EnvironmentTraceLimits {
        max_events: 0,
        max_retained_bytes: 0,
        max_prepare_peak_bytes: 0,
        max_validation_work: 0,
    };
    let bytes = serde_json::to_vec(&fixture.document()).unwrap();
    let admitted =
        AdmittedExecutionInputs::from_bytes(&bytes, environment, trace, input_limits()).unwrap();
    assert_eq!(admitted.environment(), environment);
    assert_eq!(admitted.trace_limits(), trace);
    let request = fixture.request(fixture.entry);
    admitted
        .source()
        .get(request)
        .unwrap()
        .unwrap()
        .verify(request.root, request.key, request.limits)
        .unwrap();
    let mut host = DefaultHost::default().with_environment_source(admitted.source());
    let result = FastProcessor::new(StackInputs::default()).execute_sync(
        &fixture.program,
        admitted.environment(),
        &mut host,
    );
    assert!(matches!(result, Err(ExecutionError::EnvironmentSession(_))));

    let source_disabled = fixture
        .admit(&fixture.document(), ExecutionInputLimits { max_requests: 0, ..input_limits() })
        .unwrap();
    assert_eq!(source_disabled.environment(), fixture.environment);
    assert!(source_disabled.source().get(request).is_err());
}

#[test]
fn source_preserves_complete_lists_and_exact_structural_slots() {
    let fixture = Fixture::new();
    let admitted = fixture.admit(&fixture.document(), input_limits()).unwrap();
    let source = admitted.source();
    for (key, expected) in
        [(fixture.entry, &fixture.entry_path), (fixture.service, &fixture.service_path)]
    {
        let request = fixture.request(key);
        let candidate = source.get(request).unwrap().unwrap();
        assert_eq!(&candidate.path, expected);
        let binding = candidate.verify(request.root, key, request.limits).unwrap();
        assert_eq!(binding.namespace(), fixture.namespace);
        assert_eq!(binding.implementation_root().into_word(), fixture.program.hash());
        assert_eq!(binding.procedure_key(), key);
    }
}

#[test]
fn consumer_still_authenticates_returned_candidates() {
    let fixture = Fixture::new();
    let admitted = fixture.admit(&fixture.document(), input_limits()).unwrap();
    let source = admitted.source();
    let request = fixture.request(fixture.entry);
    let candidate = source.get(request).unwrap().unwrap();
    assert!(candidate.verify(other_root(), request.key, request.limits).is_err());
    let candidate = source.get(request).unwrap().unwrap();
    assert!(candidate.verify(request.root, fixture.service, request.limits).is_err());
    let mut candidate = source.get(request).unwrap().unwrap();
    candidate.path[3].selected_child = Some(1);
    assert!(candidate.verify(request.root, request.key, request.limits).is_err());
}

#[test]
fn caller_descriptor_must_match_the_json_header() {
    let fixture = Fixture::new();
    for field in ["entry_key", "environment_root"] {
        let mut document = fixture.document();
        document[field] = json!(word_hex(other_root().into_word()));
        assert!(fixture.admit(&document, input_limits()).is_err(), "changed {field}");
    }
    for descriptor in [
        ExecutionDescriptor::new(fixture.service, fixture.root()),
        ExecutionDescriptor::new(fixture.entry, other_root()),
    ] {
        assert!(
            AdmittedExecutionInputs::from_bytes(
                &serde_json::to_vec(&fixture.document()).unwrap(),
                fixture.with_descriptor(descriptor),
                trace_limits(),
                input_limits(),
            )
            .is_err()
        );
    }
}

#[test]
fn matching_untrusted_headers_do_not_authenticate_a_root_or_key() {
    let fixture = Fixture::new();
    let mut document = fixture.document();
    document["environment_root"] = json!(word_hex(other_root().into_word()));
    let environment =
        fixture.with_descriptor(ExecutionDescriptor::new(fixture.entry, other_root()));
    assert!(
        AdmittedExecutionInputs::from_bytes(
            &serde_json::to_vec(&document).unwrap(),
            environment,
            trace_limits(),
            input_limits(),
        )
        .is_err()
    );

    // A callable K is derived from canonical labels and namespaces, independently of code D.
    for key in [missing_key(), ProcedureKey::new(fixture.program.hash())] {
        let mut document = fixture.document();
        document["entry_key"] = json!(word_hex(key.into_word()));
        document["openings"][0]["key"] = json!(word_hex(key.into_word()));
        let environment = fixture.with_descriptor(ExecutionDescriptor::new(key, fixture.root()));
        assert!(
            AdmittedExecutionInputs::from_bytes(
                &serde_json::to_vec(&document).unwrap(),
                environment,
                trace_limits(),
                input_limits(),
            )
            .is_err()
        );
    }
}

#[test]
fn every_supplied_opening_is_verified_and_entry_is_required() {
    let fixture = Fixture::new();
    let mut missing_entry = fixture.document();
    missing_entry["openings"].as_array_mut().unwrap().remove(0);
    assert!(fixture.admit(&missing_entry, input_limits()).is_err());
    let mut empty = fixture.document();
    empty["openings"] = json!([]);
    assert!(fixture.admit(&empty, input_limits()).is_err());
    let mut bad_unused_service = fixture.document();
    bad_unused_service["openings"][1]["steps"][5]["selected_child"] = json!(0);
    assert!(fixture.admit(&bad_unused_service, input_limits()).is_err());
    let mut duplicate = fixture.document();
    let entry = duplicate["openings"][0].clone();
    duplicate["openings"].as_array_mut().unwrap().push(entry);
    assert!(fixture.admit(&duplicate, input_limits()).is_err());
}

#[test]
fn invalid_slots_and_nonterminal_or_data_leaves_are_rejected() {
    let fixture = Fixture::new();
    for (index, selected_child) in
        [(0, json!(1)), (1, json!(0)), (2, json!(0)), (3, Value::Null), (5, json!(0))]
    {
        let mut document = fixture.document();
        document["openings"][0]["steps"][index]["selected_child"] = selected_child;
        assert!(fixture.admit(&document, input_limits()).is_err(), "path step {index}");
    }
    let mut shortened = fixture.document();
    shortened["openings"][0]["steps"].as_array_mut().unwrap().pop();
    assert!(fixture.admit(&shortened, input_limits()).is_err());
    let mut extended = fixture.document();
    let leaf = extended["openings"][0]["steps"][5].clone();
    extended["openings"][0]["steps"].as_array_mut().unwrap().push(leaf);
    assert!(fixture.admit(&extended, input_limits()).is_err());

    let data = EnvNode::Data {
        kind: 7,
        label: label("entry"),
        value: fixture.program.hash(),
    };
    let key = Namespace::initial().procedure_key(label("entry"));
    let root = data.commitment().unwrap();
    let document = json!({
        "version": 1,
        "entry_key": word_hex(key.into_word()),
        "environment_root": word_hex(root.into_word()),
        "openings": [{ "key": word_hex(key.into_word()), "steps": [{
            "node": node_hex(&data), "selected_child": null,
        }] }],
    });
    assert!(
        AdmittedExecutionInputs::from_bytes(
            &serde_json::to_vec(&document).unwrap(),
            fixture.with_descriptor(ExecutionDescriptor::new(key, root)),
            trace_limits(),
            input_limits(),
        )
        .is_err()
    );
}

#[test]
fn exact_node_codec_rejects_unknown_versions_kinds_truncation_and_trailing_bytes() {
    let fixture = Fixture::new();
    let node = fixture.entry_path[5].node.to_bytes().unwrap();
    let mut version = node.clone();
    version[0] = 2;
    let mut kind = node.clone();
    kind[1] = 255;
    let mut trailing = node.clone();
    trailing.push(0);
    let mut noncanonical = node.clone();
    noncanonical[2..10].fill(255);
    for bytes in [
        version,
        kind,
        node[..node.len() - 1].to_vec(),
        trailing,
        noncanonical,
        vec![1, 4, 255, 255, 255, 255],
    ] {
        let mut document = fixture.document();
        document["openings"][0]["steps"][5]["node"] = json!(format!("0x{}", hex::encode(bytes)));
        assert!(fixture.admit(&document, input_limits()).is_err());
    }
    let mut document = fixture.document();
    document["version"] = json!(2);
    assert!(fixture.admit(&document, input_limits()).is_err());
}

#[test]
fn malformed_hex_and_word_encodings_are_rejected() {
    let fixture = Fixture::new();
    for malformed in ["0x".to_owned(), "01".to_owned(), "0x0".to_owned(), "0xgg".to_owned()] {
        let mut document = fixture.document();
        document["openings"][0]["steps"][0]["node"] = json!(malformed);
        assert!(fixture.admit(&document, input_limits()).is_err());
    }
    for malformed in [format!("0x{}", "00".repeat(31)), format!("0x{}", "ff".repeat(32))] {
        for field in ["entry_key", "environment_root"] {
            let mut document = fixture.document();
            document[field] = json!(malformed);
            assert!(fixture.admit(&document, input_limits()).is_err());
        }
        let mut document = fixture.document();
        document["openings"][0]["key"] = json!(malformed);
        assert!(fixture.admit(&document, input_limits()).is_err());
    }
}

#[test]
fn json_rejects_unknown_fields_at_every_level() {
    let fixture = Fixture::new();
    for field in ["policies", "advice", "package", "kernel_namespace"] {
        let mut document = fixture.document();
        document[field] = json!({});
        assert!(fixture.admit(&document, input_limits()).is_err(), "unknown {field}");
    }
    let mut opening = fixture.document();
    opening["openings"][0]["proof"] = json!([]);
    assert!(fixture.admit(&opening, input_limits()).is_err());
    let mut step = fixture.document();
    step["openings"][0]["steps"][0]["depth"] = json!(0);
    assert!(fixture.admit(&step, input_limits()).is_err());
}

#[test]
fn json_rejects_escaped_field_names_and_values_even_when_their_meaning_is_unchanged() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let bytes = serde_json::to_string(&document).unwrap();
    let escaped_value = |field: &str, value: &str| {
        (
            format!("\"{field}\":\"{value}\""),
            format!("\"{field}\":\"\\u0030{}\"", &value[1..]),
        )
    };
    for (plain, escaped) in [
        (r#""entry_key""#.to_owned(), r#""entry_\u006bey""#.to_owned()),
        (r#""steps""#.to_owned(), r#""st\u0065ps""#.to_owned()),
        (r#""selected_child""#.to_owned(), r#""selected_\u0063hild""#.to_owned()),
        escaped_value("entry_key", &word_hex(fixture.entry.into_word())),
        escaped_value("environment_root", &word_hex(fixture.root().into_word())),
        escaped_value("key", &word_hex(fixture.entry.into_word())),
        escaped_value("node", &node_hex(&fixture.entry_path[0].node)),
    ] {
        let escaped = bytes.replacen(&plain, &escaped, 1);
        assert_eq!(serde_json::from_str::<Value>(&escaped).unwrap(), document);
        assert!(matches!(
            AdmittedExecutionInputs::from_bytes(
                escaped.as_bytes(),
                fixture.environment,
                trace_limits(),
                input_limits(),
            ),
            Err(execution_inputs::ExecutionInputError::Invalid(message))
                if message == "execution input requires unescaped ASCII JSON strings"
        ));
    }
}

#[test]
fn json_depth_is_bounded_before_unknown_nested_payloads_are_deserialized() {
    let fixture = Fixture::new();
    let nested: Value = serde_json::from_str("[[[[[[[[0]]]]]]]]").unwrap();
    for level in [0, 1, 2] {
        let mut document = fixture.document();
        match level {
            0 => document["unknown"] = nested.clone(),
            1 => document["openings"][0]["unknown"] = nested.clone(),
            2 => document["openings"][0]["steps"][0]["unknown"] = nested.clone(),
            _ => unreachable!(),
        }
        assert!(matches!(
            fixture.admit(&document, input_limits()),
            Err(execution_inputs::ExecutionInputError::Limit { resource: "JSON depth", .. })
        ));
    }
}

#[test]
fn ordinary_json_whitespace_preserves_admission_and_authenticated_openings() {
    let fixture = Fixture::new();
    let document = serde_json::to_string_pretty(&fixture.document()).unwrap();
    let whitespace = format!(" \t\r\n{}\r\n\t ", document.replace('\n', "\r\n\t"));
    let admitted = AdmittedExecutionInputs::from_bytes(
        whitespace.as_bytes(),
        fixture.environment,
        trace_limits(),
        input_limits(),
    )
    .unwrap();
    assert_eq!(admitted.environment(), fixture.environment);
    for key in [fixture.entry, fixture.service] {
        let request = fixture.request(key);
        admitted
            .source()
            .get(request)
            .unwrap()
            .unwrap()
            .verify(request.root, request.key, request.limits)
            .unwrap();
    }
}

#[test]
fn json_rejects_missing_fields_including_required_nullable_selection() {
    let fixture = Fixture::new();
    for field in ["version", "entry_key", "environment_root", "openings"] {
        let mut document = fixture.document();
        document.as_object_mut().unwrap().remove(field);
        assert!(fixture.admit(&document, input_limits()).is_err(), "missing {field}");
    }
    for field in ["key", "steps"] {
        let mut document = fixture.document();
        document["openings"][0].as_object_mut().unwrap().remove(field);
        assert!(fixture.admit(&document, input_limits()).is_err(), "missing opening {field}");
    }
    for (index, field) in [(0, "node"), (0, "selected_child"), (5, "selected_child")] {
        let mut document = fixture.document();
        document["openings"][0]["steps"][index].as_object_mut().unwrap().remove(field);
        assert!(
            fixture.admit(&document, input_limits()).is_err(),
            "missing step {index} {field}"
        );
    }
}

#[test]
fn json_rejects_duplicate_fields_and_trailing_documents() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let bytes = serde_json::to_string(&document).unwrap();
    let duplicate_top = format!("{{\"version\":1,{}", &bytes[1..]);
    let opening = serde_json::to_string(&document["openings"][0]).unwrap();
    let duplicate_opening =
        format!("{{\"key\":{},{}", document["openings"][0]["key"], &opening[1..]);
    let step = serde_json::to_string(&document["openings"][0]["steps"][0]).unwrap();
    let duplicate_step = format!("{{\"selected_child\":0,{}", &step[1..]);
    for malformed in [
        duplicate_top,
        bytes.replacen(&opening, &duplicate_opening, 1),
        bytes.replacen(&step, &duplicate_step, 1),
        format!("{bytes} {{}}"),
        bytes[..bytes.len() - 1].to_owned(),
    ] {
        assert!(
            AdmittedExecutionInputs::from_bytes(
                malformed.as_bytes(),
                fixture.environment,
                trace_limits(),
                input_limits(),
            )
            .is_err()
        );
    }
}

#[test]
fn admission_enforces_file_opening_step_encoding_and_allocation_bounds() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let bytes = serde_json::to_vec(&document).unwrap();
    let encoded_bytes = fixture
        .entry_path
        .iter()
        .chain(&fixture.service_path)
        .map(|step| step.node.encoded_len().unwrap())
        .sum();
    let mut exact = input_limits();
    exact.max_file_bytes = bytes.len();
    exact.max_openings = 2;
    exact.max_steps = fixture.entry_path.len() + fixture.service_path.len();
    exact.max_encoded_bytes = encoded_bytes;
    assert!(fixture.admit(&document, exact).is_ok());
    for limits in [
        ExecutionInputLimits {
            max_file_bytes: bytes.len() - 1,
            ..input_limits()
        },
        ExecutionInputLimits { max_openings: 1, ..input_limits() },
        ExecutionInputLimits {
            max_steps: exact.max_steps - 1,
            ..input_limits()
        },
        ExecutionInputLimits {
            max_encoded_bytes: encoded_bytes - 1,
            ..input_limits()
        },
        ExecutionInputLimits { max_retained_bytes: 0, ..input_limits() },
        ExecutionInputLimits {
            max_prepare_peak_bytes: 0,
            ..input_limits()
        },
        ExecutionInputLimits {
            max_prepare_peak_bytes: 1,
            ..input_limits()
        },
    ] {
        assert!(fixture.admit(&document, limits).is_err());
    }
}

#[test]
fn bounded_file_read_accepts_exact_length_and_rejects_one_more_byte() {
    let fixture = Fixture::new();
    let bytes = serde_json::to_vec(&fixture.document()).unwrap();
    let limits = ExecutionInputLimits {
        max_file_bytes: bytes.len(),
        ..input_limits()
    };
    let file = TempInput::new(&bytes);
    let admitted =
        AdmittedExecutionInputs::read(&file.0, fixture.environment, trace_limits(), limits)
            .unwrap();
    assert_eq!(admitted.environment(), fixture.environment);
    let mut larger = bytes;
    larger.push(b' ');
    std::fs::write(&file.0, larger).unwrap();
    assert!(
        AdmittedExecutionInputs::read(&file.0, fixture.environment, trace_limits(), limits)
            .is_err()
    );
}

#[test]
fn admission_and_source_apply_each_original_and_tighter_opening_limit() {
    let fixture = Fixture::new();
    let admitted = fixture.admit(&fixture.document(), input_limits()).unwrap();
    let source = admitted.source();
    let original = fixture.environment.opening_limits();
    let encoded_bytes: usize =
        fixture.entry_path.iter().map(|step| step.node.encoded_len().unwrap()).sum();
    for limits in [
        OpeningLimits {
            max_nodes: fixture.entry_path.len() - 1,
            ..original
        },
        OpeningLimits {
            max_depth: fixture.entry_path.len() - 2,
            ..original
        },
        OpeningLimits { max_list_children: 1, ..original },
        OpeningLimits { max_total_list_children: 3, ..original },
        OpeningLimits {
            max_encoded_bytes: encoded_bytes - 1,
            ..original
        },
        OpeningLimits { max_storage_bytes: 0, ..original },
    ] {
        let environment = ExecutionEnvironment::new(
            fixture.environment.descriptor(),
            limits,
            fixture.environment.ledger_limits(),
            fixture.environment.session_limits(),
        );
        assert!(
            AdmittedExecutionInputs::from_bytes(
                &serde_json::to_vec(&fixture.document()).unwrap(),
                environment,
                trace_limits(),
                input_limits(),
            )
            .is_err()
        );
        let request = EnvironmentWitnessRequest { limits, ..fixture.request(fixture.entry) };
        assert!(source.get(request).is_err());
    }
    let request = fixture.request(fixture.entry);
    assert!(
        source
            .get(request)
            .unwrap()
            .unwrap()
            .verify(request.root, request.key, original)
            .is_ok()
    );
}

#[test]
fn source_charges_wrong_roots_missing_keys_and_arc_clones_but_factories_are_fresh() {
    let fixture = Fixture::new();
    let limits = ExecutionInputLimits { max_requests: 3, ..input_limits() };
    let admitted = fixture.admit(&fixture.document(), limits).unwrap();
    let source = admitted.source();
    let shared = source.clone();
    let request = fixture.request(fixture.entry);
    assert!(source.get(EnvironmentWitnessRequest { root: other_root(), ..request }).is_err());
    assert!(shared.get(fixture.request(missing_key())).unwrap().is_none());
    assert!(source.get(request).unwrap().is_some());
    assert!(shared.get(request).is_err());
    assert!(admitted.source().get(request).unwrap().is_some());

    let source = admitted.source();
    let tighter = OpeningLimits { max_nodes: 0, ..request.limits };
    assert!(source.get(EnvironmentWitnessRequest { limits: tighter, ..request }).is_err());
    assert!(source.get(request).unwrap().is_some());
    assert!(source.get(request).unwrap().is_some());
    assert!(source.get(request).is_err());
}

#[test]
fn source_quota_is_atomic_across_concurrent_consumers() {
    let fixture = Fixture::new();
    let admitted = fixture
        .admit(&fixture.document(), ExecutionInputLimits { max_requests: 5, ..input_limits() })
        .unwrap();
    let source = admitted.source();
    let barrier = Arc::new(Barrier::new(20));
    let mut workers = Vec::new();
    for _ in 0..20 {
        let source = source.clone();
        let barrier = barrier.clone();
        let request = fixture.request(fixture.entry);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            match source.get(request) {
                Ok(Some(candidate)) => {
                    candidate.verify(request.root, request.key, request.limits).unwrap();
                    1
                },
                Ok(None) => panic!("admitted entry must remain available"),
                Err(_) => 0,
            }
        }));
    }
    let accepted: usize = workers.into_iter().map(|worker| worker.join().unwrap()).sum();
    assert_eq!(accepted, 5);
    assert!(source.get(fixture.request(fixture.entry)).is_err());
}

struct Fixture {
    program: Program,
    environment: ExecutionEnvironment,
    entry: ProcedureKey,
    service: ProcedureKey,
    namespace: Namespace,
    entry_path: Vec<OpeningStep>,
    service_path: Vec<OpeningStep>,
}

impl Fixture {
    fn new() -> Self {
        let mut forest = MastForest::new();
        let body = BasicBlockNodeBuilder::new(vec![
            Operation::Push(Felt::from_u32(5)),
            Operation::Push(Felt::from_u32(8)),
            Operation::Add,
            Operation::Swap,
            Operation::Drop,
        ])
        .add_to_forest(&mut forest)
        .unwrap();
        forest.make_root(body);
        let program = Program::new(Arc::new(forest), body);
        let implementation = ImplementationRoot::new(program.hash());
        let entry_leaf = EnvNode::Mast { label: label("entry"), implementation };
        let service_leaf = EnvNode::Mast { label: label("service"), implementation };
        let exports = EnvNode::List(vec![
            entry_leaf.commitment().unwrap(),
            service_leaf.commitment().unwrap(),
        ]);
        let application = EnvNode::Env {
            label: label("application"),
            child: exports.commitment().unwrap(),
        };
        let sibling = EnvNode::Data {
            kind: 17,
            label: label("opaque-sibling"),
            value: Word::empty(),
        };
        let sibling_root = sibling.commitment().unwrap();
        let list = EnvNode::List(vec![sibling_root, application.commitment().unwrap()]);
        let merkle = EnvNode::Merkle {
            left: sibling_root,
            right: list.commitment().unwrap(),
        };
        let home = EnvNode::Env {
            label: label("execution-input-tests"),
            child: merkle.commitment().unwrap(),
        };
        let namespace = Namespace::initial()
            .child(label("execution-input-tests"))
            .child(label("application"));
        let entry = namespace.procedure_key(label("entry"));
        let service = namespace.procedure_key(label("service"));
        let environment = ExecutionEnvironment::new(
            ExecutionDescriptor::new(entry, home.commitment().unwrap()),
            OpeningLimits {
                max_nodes: 16,
                max_depth: 15,
                max_list_children: 16,
                max_total_list_children: 32,
                max_encoded_bytes: 8192,
                max_storage_bytes: 32_768,
            },
            LedgerLimits {
                max_occurrences: 64,
                max_total_list_children: 128,
                max_encoded_bytes: 32_768,
                max_library_rows: 256,
                max_compression_requests: 256,
                max_retained_bytes: 1_048_576,
                max_peak_bytes: 2_097_152,
            },
            SessionLimits {
                max_cached_keys: 16,
                max_requests: 64,
                max_retained_bytes: 2_097_152,
                max_prepare_peak_bytes: 4_194_304,
            },
        );
        let prefix = [home, merkle, list, application];
        let path = |leaf, slot| {
            prefix
                .iter()
                .zip([0, 1, 1, 0])
                .map(|(node, slot)| OpeningStep {
                    node: node.clone(),
                    selected_child: Some(slot),
                })
                .chain([
                    OpeningStep {
                        node: exports.clone(),
                        selected_child: Some(slot),
                    },
                    OpeningStep { node: leaf, selected_child: None },
                ])
                .collect()
        };
        Self {
            entry_path: path(entry_leaf, 0),
            service_path: path(service_leaf, 1),
            program,
            environment,
            entry,
            service,
            namespace,
        }
    }

    fn root(&self) -> EnvironmentRoot {
        self.environment.descriptor().environment_root()
    }

    fn request(&self, key: ProcedureKey) -> EnvironmentWitnessRequest {
        EnvironmentWitnessRequest {
            root: self.root(),
            key,
            limits: self.environment.opening_limits(),
        }
    }

    fn with_descriptor(&self, descriptor: ExecutionDescriptor) -> ExecutionEnvironment {
        ExecutionEnvironment::new(
            descriptor,
            self.environment.opening_limits(),
            self.environment.ledger_limits(),
            self.environment.session_limits(),
        )
    }

    fn document(&self) -> Value {
        let opening = |key: ProcedureKey, path: &[OpeningStep]| {
            json!({
                "key": word_hex(key.into_word()),
                "steps": path.iter().map(|step| json!({
                    "node": node_hex(&step.node), "selected_child": step.selected_child,
                })).collect::<Vec<_>>(),
            })
        };
        json!({
            "version": 1,
            "entry_key": word_hex(self.entry.into_word()),
            "environment_root": word_hex(self.root().into_word()),
            "openings": [opening(self.entry, &self.entry_path), opening(self.service, &self.service_path)],
        })
    }

    fn admit(
        &self,
        document: &Value,
        limits: ExecutionInputLimits,
    ) -> Result<AdmittedExecutionInputs, execution_inputs::ExecutionInputError> {
        AdmittedExecutionInputs::from_bytes(
            &serde_json::to_vec(document).unwrap(),
            self.environment,
            trace_limits(),
            limits,
        )
    }
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn missing_key() -> ProcedureKey {
    Namespace::initial()
        .child(label("missing-namespace"))
        .procedure_key(label("absent"))
}

fn other_root() -> EnvironmentRoot {
    EnvNode::Data {
        kind: 29,
        label: label("different-environment"),
        value: Word::empty(),
    }
    .commitment()
    .unwrap()
}

fn word_hex(word: Word) -> String {
    format!("0x{}", hex::encode(word.to_bytes()))
}

fn node_hex(node: &EnvNode) -> String {
    format!("0x{}", hex::encode(node.to_bytes().unwrap()))
}

fn input_limits() -> ExecutionInputLimits {
    ExecutionInputLimits {
        max_file_bytes: 65_536,
        max_openings: 8,
        max_steps: 64,
        max_encoded_bytes: 32_768,
        max_retained_bytes: 1_048_576,
        max_prepare_peak_bytes: 2_097_152,
        max_requests: 64,
    }
}

fn trace_limits() -> EnvironmentTraceLimits {
    EnvironmentTraceLimits {
        max_events: 64,
        max_retained_bytes: 4_194_304,
        max_prepare_peak_bytes: 8_388_608,
        max_validation_work: 1_048_576,
    }
}

struct TempInput(PathBuf);

impl TempInput {
    fn new(bytes: &[u8]) -> Self {
        static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "miden-execution-inputs-{}-{}.json",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
