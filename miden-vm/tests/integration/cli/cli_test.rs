use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use assert_cmd::prelude::*;
use miden_mast_package::Package;

#[path = "fixture_inputs.rs"]
pub(super) mod fixture_inputs;
use fixture_inputs::{LibraryFixture, ProgramFixture, bundle_inputs};
use miden_wasm_event_handlers::{
    WasmHandlerLimits, section_from_module, test_append_manifest_section,
};
use predicates::prelude::*;
use tempfile::TempDir;

pub(super) fn bin_under_test(working_dir: &Path) -> Command {
    let binary = env::var("NEXTEST_BIN_EXE_miden-vm")
        .ok()
        .or_else(|| option_env!("CARGO_BIN_EXE_miden-vm").map(str::to_owned))
        .expect("the test runner should provide the path to the miden-vm binary");
    let mut command = Command::new(binary);
    command.current_dir(working_dir);
    command
}

fn fixture(path: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn advice_budget_is_checked_before_merkle_loading_in_run_and_prove() {
    let working_dir = TempDir::new().unwrap();
    let source = "begin push.1 drop end";
    let masm_path = working_dir.path().join("budget.masm");
    let masp_path = working_dir.path().join("budget.masp");
    fs::write(&masm_path, source).unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &masm_path, None, &[]);
    inputs.write_package(&masp_path);

    // The map alone fills the default allowance before accounting for its key and the
    // default Merkle store. A legacy parser decodes the malformed SMT leaf first instead.
    let values = "0,".repeat(miden_vm::ExecutionOptions::DEFAULT_MAX_ADVICE_SIZE_BYTES / 8);
    let key = format!("0x{}", "00".repeat(32));
    let json = format!(
        "{{\"operand_stack\":[],\"advice_map\":{{\"{key}\":[{values}0]}},\
         \"merkle_store\":[{{\"sparse_merkle_tree\":[[0,\"not-a-word\"]]}}]}}"
    );
    fs::write(working_dir.path().join("budget.inputs"), json).unwrap();

    for command in ["run", "prove"] {
        for program in [&masm_path, &masp_path] {
            let mut cmd = inputs.command(working_dir.path(), command, program);
            cmd.assert()
                .failure()
                .stderr(predicate::str::contains("advice provider size budget exceeded"))
                .stderr(predicate::str::contains("failed to decode").not());
        }
    }

    // Both run entrypoints must still accept a valid sparse tree, including the maximum index.
    let leaf = format!("0x01{}", "00".repeat(31));
    fs::write(
        working_dir.path().join("budget.inputs"),
        format!(
            "{{\"operand_stack\":[],\"merkle_store\":[{{\"sparse_merkle_tree\":[[{},\"{leaf}\"]]}}]}}",
            u64::MAX,
        ),
    )
    .unwrap();
    for program in [&masm_path, &masp_path] {
        let mut cmd = inputs.command(working_dir.path(), "run", program);
        cmd.assert().success();
    }
}

#[test]
fn cli_advice_budget_is_configurable_for_run_and_prove() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("advice-budget.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);

    for command in ["run", "prove"] {
        let mut cmd = inputs.command(working_dir.path(), command, &program_path);
        cmd.args(["--max-advice-size", "0"]);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("advice provider size budget"));
    }
}

#[test]
// The exact row counts and elapsed time can change, so this checks only the stable labels printed
// by the `run` command.
fn cli_run() {
    let working_dir = TempDir::new().unwrap();
    let program = fixture("masm-examples/fib/fib.masm");
    let inputs = ProgramFixture::new(working_dir.path(), &program, None, &[]);
    let mut cmd = inputs.command(working_dir.path(), "run", &program);

    cmd.arg("-n").arg("1").arg("-m").arg("8192").arg("-e").arg("8192");

    let expected = inputs.named.1.target();
    let implementation = inputs
        .named
        .0
        .symbols()
        .callables()
        .selected_implementation(expected.entry_key())
        .unwrap();
    let output = cmd.unwrap();

    output
        .assert()
        .stdout(predicate::str::contains(format!(
            "Entry key: {}",
            expected.entry_key().as_word()
        )))
        .stdout(predicate::str::contains(format!(
            "Environment root: {}",
            expected.environment_root().as_word()
        )))
        .stdout(predicate::str::contains(format!(
            "Entry implementation: {}",
            implementation.as_word()
        )))
        .stdout(predicate::str::contains("Executed the program in"))
        .stdout(predicate::str::contains("VM trace rows:"))
        .stdout(predicate::str::contains("Core rows:"))
        .stdout(predicate::str::contains("Byte-pair lookup rows:"));
}

fn assert_missing_inputs_file(mut command: Command, expected_basename: &str) {
    let assertion = command
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open input file"))
        .stderr(predicate::str::contains("No such file or directory"));
    // Diagnostic wrapping can split a filename under a long temporary directory. Remove display
    // continuation prefixes and line breaks while retaining the complete filename assertion.
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    let unwrapped = stderr
        .lines()
        .map(|line| line.trim().trim_start_matches(['|', '│']).trim())
        .collect::<String>();
    assert!(
        unwrapped.contains(expected_basename),
        "missing inferred input filename: {stderr}"
    );
}

#[test]
fn run_rejects_missing_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-missing-run-inputs-test.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    let cmd = inputs.command(working_dir.path(), "run", &program_path);
    assert_missing_inputs_file(cmd, "miden-vm-cli-missing-run-inputs-test.inputs");
}

#[test]
fn prove_rejects_missing_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-missing-prove-inputs-test.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    let cmd = inputs.command(working_dir.path(), "prove", &program_path);
    assert_missing_inputs_file(cmd, "miden-vm-cli-missing-prove-inputs-test.inputs");
}

#[test]
fn prove_rejects_invalid_program_extension_before_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-invalid-prove-extension-test.txt");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    let mut cmd = inputs.command(working_dir.path(), "prove", &program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("program input must be .masm or .masp"))
        .stderr(predicate::str::contains("Failed to open input file").not());
}

#[test]
fn cli_compile_emits_package_with_independently_expected_naming() {
    let working_dir = TempDir::new().unwrap();
    let source = working_dir.path().join("compiled.masm");
    let output = source.with_extension("masp");
    let sidecar = working_dir.path().join("compiled.naming");
    fs::write(&source, "proc helper push.3 end begin exec.helper drop end").unwrap();
    fs::write(source.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &source, None, &[]);

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("compile")
        .arg("--assembly")
        .arg(&source)
        .arg("--naming-output")
        .arg(&sidecar);
    inputs.compile(&mut cmd);
    cmd.assert().success();

    let package = Package::deserialize_from_file(&output).unwrap();
    package.check_naming(inputs.named.0.symbols()).unwrap();
    assert_eq!(fs::read(&sidecar).unwrap(), fs::read(&inputs.expected_naming).unwrap());
    inputs.command(working_dir.path(), "run", &output).assert().success();

    // Export is optional; selecting a second package output creates no new naming sidecar.
    let second = working_dir.path().join("explicit.masp");
    let previous_sidecar = fs::read(&sidecar).unwrap();
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("compile").arg("--assembly").arg(&source).arg("--output").arg(&second);
    inputs.compile(&mut cmd);
    cmd.assert().success();
    Package::deserialize_from_file(&second)
        .unwrap()
        .check_naming(inputs.named.0.symbols())
        .unwrap();
    assert_eq!(fs::read(&sidecar).unwrap(), previous_sidecar);
    assert!(!second.with_extension("naming").exists());
}

#[test]
fn cli_bundle_debug() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_debug.masp");

    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/lib/mod.masm"),
        false,
        Some("lib"),
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg(output_file.as_path());
    naming.apply(&mut cmd);
    cmd.assert().success();

    let lib = Package::deserialize_from_file_trusted(&output_file).unwrap();
    // If there are any package-owned AssemblyOps, the bundle is in debug mode.
    let found_one_asm_op =
        lib.debug_info()
            .expect("package debug info should decode")
            .is_some_and(|debug_info| {
                debug_info.nodes().iter().any(|source_node| !source_node.asm_ops.is_empty())
            });
    assert!(found_one_asm_op);
}

#[test]
fn rejects_oversized_kernel_packages_in_run_and_prove_without_verifier_artifact_authority() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    let kernel_path = working_dir.path().join("kernel.masp");
    fs::write(&program_path, "begin push.1 drop end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/kernel_main.masm"),
        true,
        None,
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(&kernel_path);
    naming.apply(&mut cmd);
    cmd.assert().success();

    let kernel =
        LibraryFixture::new(&fixture("tests/integration/cli/data/kernel_main.masm"), true, None);
    let inputs = ProgramFixture::new(working_dir.path(), &program_path, Some(&kernel), &[]);

    // Exercise both loaders successfully with a valid kernel before checking their size limits.
    let mut cmd = inputs.command(working_dir.path(), "prove", &program_path);
    cmd.arg("--kernel").arg(&kernel_path);
    cmd.assert().success();

    inputs
        .verify_command(working_dir.path(), program_path.with_extension("proof"))
        .assert()
        .success();

    fs::OpenOptions::new()
        .write(true)
        .open(&kernel_path)
        .unwrap()
        .set_len(Package::MAX_FILE_SIZE as u64 + 1)
        .unwrap();
    let oversized_error = |stderr: &str| {
        // The diagnostic renderer can wrap the message after the file path.
        stderr
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("file exceeds size limit of 536870912 bytes")
    };
    for command in ["run", "prove"] {
        let mut cmd = inputs.command(working_dir.path(), command, &program_path);
        cmd.arg("--kernel").arg(&kernel_path);
        cmd.assert().failure().stderr(predicate::function(oversized_error));
    }

    // Verification uses the caller's descriptor and public I/O without reading kernel code.
    inputs
        .verify_command(working_dir.path(), program_path.with_extension("proof"))
        .assert()
        .success();
}

#[test]
fn cli_verify_binds_caller_descriptor_and_public_io_without_execution_evidence() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin adv_push add end").unwrap();
    fs::write(
        program_path.with_extension("inputs"),
        r#"{"operand_stack":[],"advice_stack":["7"]}"#,
    )
    .unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    inputs.command(working_dir.path(), "prove", &program_path).assert().success();

    // The caller fixed K_entry/R_E before proving. Verification needs neither the source nor
    // the private advice or execution-only naming, opening and resource-policy files.
    fs::remove_file(&program_path).unwrap();
    fs::remove_dir_all(working_dir.path().join(".cli-inputs")).unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    inputs
        .verify_command(working_dir.path(), "program.proof")
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"));

    let proof_path = program_path.with_extension("proof");
    let mut proof_bytes = fs::read(&proof_path).unwrap();
    assert_eq!(proof_bytes[0], 3);
    proof_bytes[0] = 2;
    fs::write(&proof_path, &proof_bytes).unwrap();
    let unsupported_format = inputs
        .verify_command(working_dir.path(), "program.proof")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Proof status:").not());
    assert_wrapped_diagnostic(
        &unsupported_format.get_output().stderr,
        "unsupported execution proof format 2",
    );
    proof_bytes[0] = 3;
    fs::write(&proof_path, proof_bytes).unwrap();

    for index in [1, 3] {
        let mut args = inputs.descriptor_args();
        let one = "0x0100000000000000000000000000000000000000000000000000000000000000";
        let two = "0x0200000000000000000000000000000000000000000000000000000000000000";
        args[index] = if args[index] == one { two } else { one }.to_owned();
        bin_under_test(working_dir.path())
            .args(["verify", "--proof", "program.proof"])
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Program failed verification!"))
            .stdout(predicate::str::contains("Proof status:").not());
    }

    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":["1"]}"#).unwrap();
    inputs
        .verify_command(working_dir.path(), "program.proof")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Program failed verification!"))
        .stdout(predicate::str::contains("Proof status:").not());

    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    fs::write(program_path.with_extension("outputs"), r#"{"stack":["8"]}"#).unwrap();
    inputs
        .verify_command(working_dir.path(), "program.proof")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Program failed verification!"))
        .stdout(predicate::str::contains("Proof status:").not());
}

#[test]
fn cli_prove_verify_supports_every_transcript_hash() {
    use miden_vm::{ExecutionProof, HashFunction};

    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("transcript.masm");
    fs::write(&program_path, "begin push.7 drop end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    let expected = inputs.named.1.target();
    let implementation = inputs
        .named
        .0
        .symbols()
        .callables()
        .selected_implementation(expected.entry_key())
        .unwrap();

    for (name, hash) in [
        ("blake3-256", HashFunction::Blake3_256),
        ("keccak", HashFunction::Keccak),
        ("eidos", HashFunction::Eidos),
    ] {
        inputs
            .command(working_dir.path(), "prove", &program_path)
            .args(["--hasher", name])
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "Entry key: {}",
                expected.entry_key().as_word()
            )))
            .stdout(predicate::str::contains(format!(
                "Environment root: {}",
                expected.environment_root().as_word()
            )))
            .stdout(predicate::str::contains(format!(
                "Entry implementation: {}",
                implementation.as_word()
            )))
            .stdout(predicate::str::contains("Proof status: complete"));

        let proof = ExecutionProof::read_from_bytes(
            &fs::read(program_path.with_extension("proof")).unwrap(),
        )
        .unwrap();
        assert_eq!(proof.vm().proof.hash_fn(), hash, "CLI transcript selection: {name}");
        inputs
            .verify_command(working_dir.path(), program_path.with_extension("proof"))
            .assert()
            .success()
            .stdout(predicate::str::contains("Proof status: complete"));
    }
}

#[cfg(unix)]
#[test]
fn atomic_artifact_writes_preserve_existing_files_on_io_failure() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    let proof_path = working_dir.path().join("program.proof");
    let outputs_path = working_dir.path().join("program.outputs");
    fs::write(&program_path, "begin push.1 drop end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    fs::write(&proof_path, b"stale proof").unwrap();
    fs::write(&outputs_path, b"stale outputs").unwrap();

    let inputs = ProgramFixture::new(working_dir.path(), &program_path, None, &[]);
    // Bare filenames exercise temporary-file creation in the current directory.
    let mut cmd = inputs.command(working_dir.path(), "prove", "program.masm");
    cmd.assert().success();
    let previous_proof = fs::read(&proof_path).unwrap();
    let previous_outputs = fs::read(&outputs_path).unwrap();
    let previous_files = fs::read_dir(working_dir.path()).unwrap().count();

    let binary = bin_under_test(working_dir.path()).get_program().to_owned();
    for (args, diagnostic) in [
        (
            ["run", "program.masm", "--output", "program.outputs"],
            "Failed to write output file `program.outputs`",
        ),
        (
            ["prove", "program.masm", "--proof", "program.proof"],
            "Failed to write proof file `program.proof`",
        ),
    ] {
        // Ignore SIGXFSZ so the kernel returns a write error to the CLI. The limit applies only
        // to this child process and forbids any file data from being written.
        let mut cmd = Command::new("sh");
        cmd.current_dir(working_dir.path())
            .args(["-c", "set -eu; trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
            .arg(&binary)
            .args(args);
        inputs.apply(&mut cmd, false);
        cmd.assert().failure().stderr(predicate::str::contains(diagnostic));

        assert_eq!(fs::read(&proof_path).unwrap(), previous_proof);
        assert_eq!(fs::read(&outputs_path).unwrap(), previous_outputs);
        assert_eq!(fs::read_dir(working_dir.path()).unwrap().count(), previous_files);
    }

    // The old artifacts remain usable after both write failures.
    inputs.verify_command(working_dir.path(), "program.proof").assert().success();
}

#[test]
fn cli_bundle_release_strips_debug_info() {
    let working_dir = TempDir::new().unwrap();
    let cases = [
        (
            "library",
            fixture("tests/integration/cli/data/lib/mod.masm"),
            vec!["--namespace", "lib"],
        ),
        (
            "kernel",
            fixture("tests/integration/cli/data/kernel_main.masm"),
            vec!["--kernel"],
        ),
    ];

    for (name, source, extra_args) in cases {
        let debug_output = working_dir.path().join(format!("{name}-debug.masp"));
        let release_output = working_dir.path().join(format!("{name}-release.masp"));

        let naming = bundle_inputs(
            working_dir.path(),
            &source,
            name == "kernel",
            (name == "library").then_some("lib"),
        );
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--output")
            .arg(&debug_output);
        naming.apply(&mut cmd);
        cmd.assert().success();

        let naming = bundle_inputs(
            working_dir.path(),
            &source,
            name == "kernel",
            (name == "library").then_some("lib"),
        );
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--release")
            .arg("--output")
            .arg(&release_output);
        naming.apply(&mut cmd);
        cmd.assert().success();

        let debug_bytes = fs::read(&debug_output).unwrap();
        let release_bytes = fs::read(&release_output).unwrap();
        let source_path = source.to_string_lossy();

        assert_ne!(debug_bytes, release_bytes, "{name} bundles should differ");
        assert!(
            debug_bytes
                .windows(source_path.len())
                .any(|bytes| bytes == source_path.as_bytes()),
            "debug {name} bundle should contain its source path"
        );
        assert!(
            !release_bytes
                .windows(source_path.len())
                .any(|bytes| bytes == source_path.as_bytes()),
            "release {name} bundle should omit its source path"
        );

        let debug_package = Package::deserialize_from_file_trusted(&debug_output).unwrap();
        let release_package = Package::deserialize_from_file_trusted(&release_output).unwrap();

        assert!(
            debug_package.debug_info().unwrap().is_some(),
            "debug {name} bundle should contain package debug info"
        );
        assert!(
            release_package.debug_info().unwrap().is_none(),
            "release {name} bundle should omit package debug info"
        );
        assert_eq!(
            debug_package.mast_forest_commitment(),
            release_package.mast_forest_commitment(),
            "release mode should preserve the {name} MAST digest"
        );
    }
}

#[test]
fn cli_bundle_version() {
    let working_dir = TempDir::new().unwrap();
    let cases = [
        (
            "library",
            fixture("tests/integration/cli/data/lib/mod.masm"),
            vec!["--namespace", "lib"],
        ),
        (
            "kernel",
            fixture("tests/integration/cli/data/kernel_main.masm"),
            vec!["--kernel"],
        ),
    ];

    for (name, source, extra_args) in cases {
        let requested_output = working_dir.path().join(format!("{name}-versioned.masp"));
        let default_output = working_dir.path().join(format!("{name}-default-version.masp"));

        let naming = bundle_inputs(
            working_dir.path(),
            &source,
            name == "kernel",
            (name == "library").then_some("lib"),
        );
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--version")
            .arg("1.2.3")
            .arg("--output")
            .arg(&requested_output);
        naming.apply(&mut cmd);
        cmd.assert().success();

        let package = Package::deserialize_from_file_trusted(&requested_output).unwrap();
        assert_eq!(package.version, "1.2.3".parse().unwrap());

        let naming = bundle_inputs(
            working_dir.path(),
            &source,
            name == "kernel",
            (name == "library").then_some("lib"),
        );
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--output")
            .arg(&default_output);
        naming.apply(&mut cmd);
        cmd.assert().success();

        let package = Package::deserialize_from_file_trusted(&default_output).unwrap();
        assert_eq!(package.version, "0.1.0".parse().unwrap());
    }

    let invalid_output = working_dir.path().join("invalid-version.masp");
    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/lib/mod.masm"),
        false,
        Some("lib"),
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--version")
        .arg("not-a-version")
        .arg("--output")
        .arg(&invalid_output);
    naming.apply(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid value 'not-a-version'"))
        .stderr(predicate::str::contains("--version <VERSION>"));
    assert!(!invalid_output.exists());
}

#[test]
fn cli_bundle_no_exports() {
    let working_dir = TempDir::new().unwrap();
    let source = fixture("tests/integration/cli/data/lib_noexports/mod.masm");
    let output_file = working_dir.path().join("cli_bundle_no_exports.masp");
    let expected = LibraryFixture::new(&source, false, Some("lib"));
    let naming = bundle_inputs(working_dir.path(), &source, false, Some("lib"));
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg("--namespace")
        .arg("lib")
        .arg(&source)
        .arg("--output")
        .arg(&output_file);
    naming.apply(&mut cmd);
    cmd.assert().success();

    let package = Package::deserialize_from_file(&output_file).unwrap();
    assert_eq!(package.manifest.num_exports(), 0);
    assert_eq!(expected.naming.callables().visible_paths().len(), 0);
    // Match the independent caller-owned naming, including its private implementation selection.
    package.check_naming(&expected.naming).unwrap();
    let (_, private) = expected
        .naming
        .callables()
        .bindings()
        .find(|(_, binding)| binding.path().components() == ["lib", "lib_proc"])
        .expect("the fixture must retain its private declaration");
    let implementation = expected
        .naming
        .callables()
        .selected_implementation(private.key())
        .expect("the private fixture procedure must have a selected implementation");
    let forest = package.mast_forest();
    let root = forest
        .find_procedure_root(implementation.into_word())
        .expect("the private implementation must be retained as a procedure root");
    assert!(!forest[root].is_external());
    assert_eq!(package.mast_forest_commitment(), expected.package.mast_forest_commitment());
}

#[test]
fn cli_bundle_kernel() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_kernel.masp");

    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/kernel_main.masm"),
        true,
        None,
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    naming.apply(&mut cmd);
    cmd.assert().success();
}

/// A kernel can bundle with a library w/o exports.
#[test]
fn cli_bundle_kernel_noexports() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_kernel_noexports.masp");

    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/kernel_noexports.masm"),
        true,
        None,
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_noexports.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    naming.apply(&mut cmd);
    cmd.assert().success();
}

#[test]
fn cli_bundle_output() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_output.masp");
    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/lib/mod.masm"),
        false,
        Some("lib"),
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_bundle_output.masp");
    naming.apply(&mut cmd);
    cmd.assert().success();
    assert!(output_file.exists());
}

// First compile a library to a .masp file, then run a program that uses it.
#[test]
fn cli_run_with_lib() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_run_with_lib.masp");
    let naming = bundle_inputs(
        working_dir.path(),
        &fixture("tests/integration/cli/data/lib/mod.masm"),
        false,
        Some("lib"),
    );
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_run_with_lib.masp");
    naming.apply(&mut cmd);
    cmd.assert().success();

    let library = LibraryFixture::new(
        &fixture("tests/integration/cli/data/lib/mod.masm"),
        false,
        Some("lib"),
    );
    let program = fixture("tests/integration/cli/data/main.masm");
    let inputs = ProgramFixture::new(working_dir.path(), &program, None, &[&library]);
    let mut cmd = inputs.command(working_dir.path(), "run", &program);
    cmd.arg("-l").arg(&output_file);
    cmd.assert().success();
}

/// Bundles the `kernel_main.masm` fixture into `<working_dir>/<name>` as a kernel package.
fn bundle_kernel_package(working_dir: &Path, name: &str) -> PathBuf {
    let output_file = working_dir.join(name);
    let naming = bundle_inputs(
        working_dir,
        &fixture("tests/integration/cli/data/kernel_main.masm"),
        true,
        None,
    );
    let mut cmd = bin_under_test(working_dir);
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(&output_file);
    naming.apply(&mut cmd);
    cmd.assert().success();
    output_file
}

fn assert_wrapped_diagnostic(stderr: &[u8], expected: &str) {
    let stderr = String::from_utf8_lossy(stderr);
    // The diagnostic renderer may wrap the message and prefix continuation lines with a bar.
    let unwrapped = stderr.replace(['|', '│'], " ");
    let unwrapped = unwrapped.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(unwrapped.contains(expected), "unexpected diagnostic: {stderr}");
}

fn assert_kernel_for_masp_diagnostic(command: &mut Command) {
    let output = command.assert().failure();
    assert_wrapped_diagnostic(
        &output.get_output().stderr,
        "--kernel applies to source assembly; a .masp carries its embedded kernel code",
    );
}

#[test]
fn run_rejects_kernel_for_masp_package() {
    let working_dir = TempDir::new().unwrap();
    let package_path = bundle_kernel_package(working_dir.path(), "prog.masp");

    let authority_path = working_dir.path().join("authority.masm");
    fs::write(&authority_path, "begin nop end").unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &authority_path, None, &[]);
    let mut cmd = inputs.command(working_dir.path(), "run", &package_path);
    cmd.arg("--kernel").arg(fixture("tests/integration/cli/data/kernel_main.masm"));
    assert_kernel_for_masp_diagnostic(&mut cmd);
}

#[test]
fn prove_rejects_kernel_for_masp_package() {
    let working_dir = TempDir::new().unwrap();
    let package_path = bundle_kernel_package(working_dir.path(), "prog.masp");
    // Keep valid private inputs available while exercising the incompatible kernel option.
    fs::write(working_dir.path().join("prog.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let authority_path = working_dir.path().join("authority.masm");
    fs::write(&authority_path, "begin nop end").unwrap();
    let inputs = ProgramFixture::new(working_dir.path(), &authority_path, None, &[]);
    let mut cmd = inputs.command(working_dir.path(), "prove", &package_path);
    cmd.arg("--kernel").arg(fixture("tests/integration/cli/data/kernel_main.masm"));
    assert_kernel_for_masp_diagnostic(&mut cmd);
}

/// A `.masp` kernel is registered with the host, so its procedures are reachable from a `syscall`.
#[test]
fn run_masm_program_honors_a_masp_kernel() {
    let working_dir = TempDir::new().unwrap();
    let kernel_path = bundle_kernel_package(working_dir.path(), "kernel.masp");

    let program_path = working_dir.path().join("program.masm");
    // `kernel_proc` runs `caller`, which requires a `call` frame under the `syscall`.
    fs::write(
        &program_path,
        "proc bar\n    syscall.kernel_proc\nend\n\nbegin\n    call.bar\nend\n",
    )
    .unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let kernel =
        LibraryFixture::new(&fixture("tests/integration/cli/data/kernel_main.masm"), true, None);
    let inputs = ProgramFixture::new(working_dir.path(), &program_path, Some(&kernel), &[]);
    let mut cmd = inputs.command(working_dir.path(), "run", &program_path);
    cmd.arg("--kernel").arg(&kernel_path).arg("-n").arg("1");
    cmd.assert().success();
}

/// A handler module the loader accepts: it exports linear memory and a `() -> ()` handler.
const HANDLER_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "handler")))"#;

/// A project attaches one handler section to every target it builds, so an executable and the
/// project kernel it embeds carry the identical section. The CLI must run such a package: it
/// registers the handlers once and takes only the MAST forest of the second package.
#[test]
fn run_loads_a_masp_whose_kernel_shares_the_handler_section() {
    let working_dir = TempDir::new().unwrap();

    // The section a project build would attach to both targets.
    let wasm = test_append_manifest_section(
        wat::parse_str(HANDLER_WAT).expect("the fixture WAT parses"),
        &[("test::cli::event", "handler")],
    );
    let section = section_from_module(wasm, WasmHandlerLimits::default())
        .expect("the handler module derives a section");

    // The kernel carries the section before it is embedded, so the executable's kernel dependency
    // commits to the kernel package the CLI later reads back.
    let kernel =
        LibraryFixture::new(&fixture("tests/integration/cli/data/kernel_main.masm"), true, None);
    let kernel_package =
        Arc::new(kernel.package.as_ref().clone().with_event_handlers(&section).unwrap());
    let kernel = kernel.with_package(kernel_package);
    let program_path = working_dir.path().join("prog.masm");
    fs::write(&program_path, "begin push.1 drop end").unwrap();
    let mut inputs = ProgramFixture::new(working_dir.path(), &program_path, Some(&kernel), &[]);
    let mut package = inputs.named.0.package().as_ref().clone();
    package
        .attach_event_handlers(&section)
        .expect("the executable package takes the section");

    let package_path = working_dir.path().join("prog.masp");
    inputs.named.0 =
        miden_mast_package::CodePackage::new(Arc::new(package), inputs.named.0.symbols().clone())
            .unwrap();
    inputs.write_package(&package_path);
    fs::write(working_dir.path().join("prog.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    // The run below exercises the handler deduplication only if the round-tripped package
    // still yields its embedded kernel — a digest-pairing break would surface as an error
    // there and skip the second handler load. Pin that precondition, so this test cannot
    // pass vacuously.
    let round_tripped = Package::deserialize_from_file(&package_path).unwrap();
    let embedded_kernel = round_tripped
        .try_embedded_kernel_package()
        .expect("the embedded kernel must decode with a matching dependency digest")
        .expect("the package must embed its kernel");
    assert_eq!(
        embedded_kernel.event_handlers().expect("the kernel section decodes"),
        Some(section),
        "the embedded kernel must carry the same handler section as the outer package",
    );

    let mut cmd = inputs.command(working_dir.path(), "run", &package_path);
    cmd.arg("-n").arg("1");
    cmd.assert().success();
}

#[test]
fn test_advmap_cli() {
    let working_dir = TempDir::new().unwrap();
    let program = fixture("tests/integration/cli/data/adv_map.masm");
    let inputs = ProgramFixture::new(working_dir.path(), &program, None, &[]);
    let mut cmd = inputs.command(working_dir.path(), "run", &program);
    cmd.assert().success();
}
