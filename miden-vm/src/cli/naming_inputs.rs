//! Caller-selected naming policy and optional compiler-owned naming export.

use std::path::PathBuf;

use clap::Args;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_vm::internal::naming_inputs::NamingInputs;

#[derive(Debug, Clone, Args)]
pub struct NamingArgs {
    /// Versioned JSON naming choices, selected profile, home permissions, and resource limits
    #[arg(long, value_name = "PATH")]
    naming_inputs: PathBuf,

    /// Maximum bytes read from the naming-input file
    #[arg(long, value_name = "BYTES")]
    max_naming_input_bytes: usize,
}

impl NamingArgs {
    pub fn read(&self) -> Result<NamingInputs, Report> {
        NamingInputs::read(&self.naming_inputs, self.max_naming_input_bytes)
    }
}

#[derive(Debug, Clone, Args)]
pub struct NamingOutputArgs {
    /// Optional path for the compiler-owned NamingV1 bytes, checked under the selected policy
    #[arg(long, value_name = "PATH")]
    naming_output: Option<PathBuf>,
}

impl NamingOutputArgs {
    /// Writes only an explicitly requested sidecar, after the producer checks the complete naming.
    pub fn write(&self, bytes: &[u8]) -> Result<(), Report> {
        if let Some(path) = &self.naming_output {
            std::fs::write(path, bytes)
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to write naming output `{}`", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        naming: NamingArgs,
        #[command(flatten)]
        output: NamingOutputArgs,
    }

    #[test]
    fn naming_file_and_byte_cap_are_required_without_an_implicit_output() {
        let required = ["--naming-inputs", "naming.json", "--max-naming-input-bytes", "4096"];
        let command = Command::try_parse_from(["test"].into_iter().chain(required)).unwrap();
        assert!(command.output.naming_output.is_none());
        for index in (0..required.len()).step_by(2) {
            let mut args = required.to_vec();
            args.drain(index..index + 2);
            assert!(Command::try_parse_from(["test"].into_iter().chain(args)).is_err());
        }
        let command = Command::try_parse_from(
            ["test"]
                .into_iter()
                .chain(required)
                .chain(["--naming-output", "compiled.naming"]),
        )
        .unwrap();
        assert_eq!(command.output.naming_output, Some("compiled.naming".into()));
    }
}
