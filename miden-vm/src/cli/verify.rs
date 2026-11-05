use std::{path::PathBuf, time::Instant};

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, Result, WrapErr};
use miden_vm::{
    ExecutionClaim, PrecompileStatus, default_verification_precompile_limits, internal::InputFile,
};

use super::{
    data::{OutputFile, ProofFile},
    execution_inputs::DescriptorArgs,
    precompile_limits::PrecompileArgs,
    utils::parse_byte_size,
};

#[derive(Debug, Clone, Parser)]
#[command(about = "Verify a Miden program")]
pub struct VerifyCmd {
    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,
    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,
    /// Path to proof file
    #[arg(short = 'p', long = "proof", value_parser)]
    proof_file: PathBuf,

    /// Maximum proof file size in bytes (512M, 32Gi)
    #[arg(
        long = "max-proof-size",
        value_name = "BYTES",
        default_value_t = ProofFile::DEFAULT_MAX_FILE_SIZE,
        value_parser = parse_byte_size
    )]
    max_proof_size: u64,

    #[command(flatten)]
    descriptor: DescriptorArgs,

    #[command(flatten)]
    precompile_limits: PrecompileArgs,

    /// Require a complete STARK-backed proof
    ///
    /// By default, accept valid deferred proofs after VM STARK verification and native witness
    /// validation, reporting deferred status, VM-only security, and the outstanding root.
    /// This option rejects deferred artifacts before verification, without claiming validity.
    #[arg(long = "require-complete")]
    require_complete: bool,
}

impl VerifyCmd {
    pub fn execute(&self) -> Result<(), Report> {
        let verification_limits =
            self.precompile_limits.apply(default_verification_precompile_limits());
        let max_proof_size = usize::try_from(self.max_proof_size).map_err(|_| {
            Report::msg("--max-proof-size exceeds the addressable byte count on this platform")
        })?;
        let (input_file, output_file) = self.infer_defaults()?;

        println!("===============================================================================");
        println!("Verifying proof: {}", self.proof_file.display());
        println!("-------------------------------------------------------------------------------");

        // load input data from file
        let input_data = InputFile::read(&Some(input_file), self.proof_file.as_ref())?;

        // fetch the stack inputs from the arguments
        let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;

        // load outputs data from file
        let outputs_data =
            OutputFile::read(&Some(output_file), self.proof_file.as_ref()).map_err(Report::msg)?;

        // load proof from file
        let proof = ProofFile::read(
            &Some(self.proof_file.clone()),
            self.proof_file.as_ref(),
            max_proof_size,
        )
        .map_err(Report::msg)?;

        // This unauthenticated variant is sufficient for CLI policy rejection. Only the
        // verifier below can establish proof validity, authenticate roots, and evaluate witnesses.
        if self.require_complete && matches!(proof.precompile(), PrecompileStatus::Deferred(_)) {
            return Err(Report::msg(
                "--require-complete rejects deferred proofs; proof has not been verified",
            ));
        }

        let now = Instant::now();

        // verify proof
        let stack_outputs = outputs_data.stack_outputs().map_err(Report::msg)?;
        let claim = ExecutionClaim::new(self.descriptor.descriptor(), stack_inputs, stack_outputs);
        let outcome = miden_vm::Verifier::new()
            .with_verification_precompile_limits(verification_limits)
            .verify(&claim, &proof)
            .into_diagnostic()
            .wrap_err("Program failed verification!")?;
        let vm_parameters = outcome.vm_security_parameters();
        let vm_security_level = (
            vm_parameters.conjectured_security_level(),
            vm_parameters.proven_security_level(),
        );
        if let Some(root) = outcome.outstanding_precompile_root() {
            println!("Proof status: deferred");
            println!("VM STARK security level: {}", format_security_level(vm_security_level));
            println!("Precompile witness: validated natively");
            println!("Precompile STARK: not supplied");
            println!("Outstanding precompile root: {root}");
            println!("Verification complete in {} ms", now.elapsed().as_millis());
            return Ok(());
        }
        println!("Proof status: complete");
        let security_level = outcome.precompile_security_parameters().map_or(
            vm_security_level,
            |precompile_parameters| {
                (
                    vm_security_level.0.min(precompile_parameters.conjectured_security_level()),
                    vm_security_level.1.min(precompile_parameters.proven_security_level()),
                )
            },
        );

        println!(
            "Verification complete in {} ms. Minimum per-STARK security level: {}",
            now.elapsed().as_millis(),
            format_security_level(security_level)
        );

        Ok(())
    }

    fn infer_defaults(&self) -> Result<(PathBuf, PathBuf), Report> {
        if !self.proof_file.exists() {
            return Err(Report::msg("Proof file does not exist"));
        }
        let default_path = |ext: &str| self.proof_file.with_extension(ext);

        let input_file =
            self.input_file.as_ref().map_or_else(|| default_path("inputs"), PathBuf::clone);
        let output_file = self
            .output_file
            .as_ref()
            .map_or_else(|| default_path("outputs"), PathBuf::clone);

        Ok((input_file, output_file))
    }
}

/// Formats `(conjectured, proven)` whole-bit security levels.
fn format_security_level((conjectured, proven): (u32, u32)) -> String {
    format!("{conjectured} bits conjectured, {proven} bits proven")
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File};

    use super::*;

    fn command() -> VerifyCmd {
        VerifyCmd::try_parse_from(
            ["verify", "--proof", "test.proof"]
                .into_iter()
                .chain(super::super::execution_inputs::tests::required_args().into_iter().take(4)),
        )
        .unwrap()
    }

    #[test]
    fn infer_defaults_uses_proof_file_basename_for_defaults() {
        // prepare a unique temp directory
        let base =
            std::env::temp_dir().join(format!("miden_vm_verify_test_{}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp test dir");

        // create a dummy proof file
        let proof_path = base.join("proof_file");
        File::create(&proof_path).expect("create proof file");

        // build command with no explicit input/output
        let mut cmd = command();
        cmd.proof_file = proof_path.clone();

        // exercise
        let (input, output) = cmd.infer_defaults().expect("infer defaults");

        // verify: defaults are proof file with replaced extensions
        assert_eq!(input, proof_path.with_extension("inputs"));
        assert_eq!(output, proof_path.with_extension("outputs"));

        // cleanup best-effort
        let _ = fs::remove_file(&proof_path);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn proof_file_limit_defaults_and_explicit_units_are_preserved() {
        assert_eq!(command().max_proof_size, ProofFile::DEFAULT_MAX_FILE_SIZE);
        for (value, expected) in [("0", 0), ("123", 123), ("1Mi", 1024 * 1024)] {
            let cmd = VerifyCmd::try_parse_from(
                ["verify", "--proof", "missing.proof", "--max-proof-size", value]
                    .into_iter()
                    .chain(
                        super::super::execution_inputs::tests::required_args().into_iter().take(4),
                    ),
            )
            .unwrap();
            assert_eq!(cmd.max_proof_size, expected);
        }
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn unaddressable_proof_file_limit_rejects_before_file_access() {
        let mut cmd = command();
        cmd.max_proof_size = u64::MAX;
        let err = cmd.execute().unwrap_err();
        assert!(err.to_string().contains("--max-proof-size exceeds the addressable byte count"));
    }

    #[test]
    fn verifier_requires_only_caller_descriptor_and_rejects_legacy_authority() {
        let expected = command().descriptor.descriptor();
        assert_eq!(expected.entry_key().as_word().as_bytes()[0], 1);
        assert_eq!(expected.environment_root().as_word().as_bytes()[0], 2);

        let descriptor_args = super::super::execution_inputs::tests::required_args();
        for index in [0, 2] {
            let mut args = descriptor_args[..4].to_vec();
            args.drain(index..index + 2);
            assert!(
                VerifyCmd::try_parse_from(
                    ["verify", "--proof", "missing.proof"].into_iter().chain(args),
                )
                .is_err()
            );
        }
        for unsupported in [
            ["--program-hash", "00"],
            ["-x", "00"],
            ["--kernel", "kernel.masm"],
            ["--environment-openings", "openings.json"],
            ["--environment-policy", "policy.json"],
            ["--max-environment-policy-bytes", "8192"],
        ] {
            assert!(
                VerifyCmd::try_parse_from(
                    ["verify", "--proof", "missing.proof"]
                        .into_iter()
                        .chain(descriptor_args[..4].iter().copied())
                        .chain(unsupported),
                )
                .is_err()
            );
        }
    }
}
