use std::path::PathBuf;

use clap::Parser;
use miden_assembly::{
    Assembler, Linkage, PathBuf as LibraryPath, ast,
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{Package, Version};
use miden_vm::internal::naming_inputs::NamingRole;

use super::naming_inputs::{NamingArgs, NamingOutputArgs};

fn parse_version(value: &str) -> Result<Version, String> {
    value.parse().map_err(|err| format!("invalid package version: {err}"))
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "Compile Library",
    about = "Bundles .masm files into a single .masp library with access to the core library."
)]
pub struct BundleCmd {
    /// Disable debug symbols (release mode)
    #[arg(short = 'r', long = "release")]
    release: bool,
    /// Path to the root `.masm` file for the library
    #[arg(value_parser)]
    root: PathBuf,
    /// Defines the source namespace for a library, otherwise read from its root module.
    /// For a kernel this sets the package name; its source namespace remains `$kernel`.
    /// Canonical callable homes and labels come from the naming-input file.
    #[arg(short, long)]
    namespace: Option<String>,
    /// Version of the library, defaults to `0.1.0`.
    #[arg(short, long, default_value = "0.1.0", value_parser = parse_version)]
    version: Version,
    /// Indicates that the artifact produced is a kernel package.
    ///
    /// This requires that `root` be a path to the root module of the kernel.
    #[arg(short, long)]
    kernel: bool,
    /// Path of the output `.masp` file.
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(flatten)]
    naming: NamingArgs,
    #[command(flatten)]
    naming_output: NamingOutputArgs,
}

impl BundleCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Build library");
        println!("============================================================");

        let naming_inputs = self.naming.read()?;
        naming_inputs.check_library_count(0)?;
        if naming_inputs.has_kernel() {
            return Err(Report::msg("bundle does not accept a separate kernel naming choice"));
        }
        let mut assembler =
            Assembler::default().with_namespace_inputs(naming_inputs.source(NamingRole::Target)?);

        if !self.root.is_file() {
            return Err(Report::msg("`root` must be a '.masm' file."));
        }

        // write the masp output
        let output_file = match &self.output {
            Some(output) => output,
            None => {
                let parent =
                    &self.root.parent().ok_or("Invalid output path").map_err(Report::msg)?;
                &parent.join("out").with_extension(Package::EXTENSION)
            },
        };

        let core = CoreLibrary::default();
        assembler.link_package(core.code_package().clone(), Linkage::Dynamic)?;
        let product = if self.kernel {
            let namespace = match self.namespace.as_deref() {
                Some(ns) => ns,
                None => ast::Path::KERNEL_PATH,
            };
            assembler.assemble_kernel_from_root_with_naming(namespace, &self.root)?
        } else {
            let library_namespace = match self.namespace.as_ref() {
                Some(ns) => Some(LibraryPath::new(ns).into_diagnostic()?),
                None => None,
            };
            assembler
                .assemble_library_from_root_with_naming(&self.root, library_namespace.as_deref())?
        };
        let naming = product.naming().clone();
        let naming_bytes = naming_inputs.encode_owned(&naming)?;
        let mut library = product.into_artifact(true)?;
        library.version = self.version.clone();
        if self.release {
            library.strip_debug_info().into_diagnostic()?;
        }
        library.check_naming(&naming).map_err(Report::msg)?;
        library.write_to_file(output_file).into_diagnostic()?;
        self.naming_output.write(&naming_bytes)?;
        if self.kernel {
            println!("Built kernel library {} from {}", library.name, self.root.display());
        } else {
            println!("Built package '{}'", library.name);
        }

        Ok(())
    }
}
