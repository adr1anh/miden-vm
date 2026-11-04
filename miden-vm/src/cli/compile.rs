use std::path::PathBuf;

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_mast_package::Package;
use miden_vm::internal::naming_inputs::NamingRole;

use super::{
    data::{Libraries, ProgramFile},
    naming_inputs::{NamingArgs, NamingOutputArgs},
};

#[derive(Debug, Clone, Parser)]
#[command(about = "Assemble a Miden program")]
pub struct CompileCmd {
    /// Path to .masm assembly file
    #[arg(short = 'a', long = "assembly", value_parser)]
    assembly_file: PathBuf,
    /// Paths to .masp library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,
    /// Path to the output `.masp` package, including required naming metadata
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,
    #[command(flatten)]
    naming: NamingArgs,
    #[command(flatten)]
    naming_output: NamingOutputArgs,
}

impl CompileCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Compile program");
        println!("============================================================");

        let naming_inputs = self.naming.read()?;
        if naming_inputs.has_kernel() {
            return Err(Report::msg("compile does not accept a separate kernel naming choice"));
        }
        let namespace_inputs = naming_inputs.source(NamingRole::Target)?;

        // load the program from file and parse it
        let program = ProgramFile::read(&self.assembly_file)?;

        // load libraries from files
        let libraries = Libraries::new(&self.library_paths, &naming_inputs)?;

        // compile the program
        // Note: assembler debug mode is always enabled (issue #1821)
        let compiled =
            program.compile_package(libraries.libraries.iter().cloned(), namespace_inputs)?;
        let naming_bytes = naming_inputs.encode_owned(compiled.symbols())?;
        compiled.package().check_naming(compiled.symbols()).map_err(Report::msg)?;

        // report program hash to user
        compiled.package().check_executable_code(compiled.symbols())?;
        let entry = compiled.symbols().entry_key().expect("checked executable entry");
        let implementation = compiled
            .symbols()
            .callables()
            .selected_implementation(entry)
            .expect("checked executable implementation");
        let program_hash: [u8; 32] = (*implementation.as_word()).into();
        println!("program hash is {}", hex::encode(program_hash));

        // write the compiled program into the specified path if one is provided; if the path is
        // not provided, writes the file into the same directory as the source file, but with
        // `.masp` extension, retaining the compiler's required naming metadata.
        let out_path = self.output_file.clone().unwrap_or_else(|| {
            let mut out_file = self.assembly_file.clone();
            out_file.set_extension(Package::EXTENSION);
            out_file
        });

        compiled
            .package()
            .write_to_file(out_path)
            .into_diagnostic()
            .wrap_err("Failed to write the compiled file")?;
        self.naming_output.write(&naming_bytes)
    }
}
