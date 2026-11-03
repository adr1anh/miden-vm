use std::{path::Path, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager, Linkage,
    diagnostics::{IntoDiagnostic, Report, WrapErr},
};
use miden_core::program::{ProcedureKey, Program};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{EventHandlerSection, Package};
use miden_processor::{DefaultHost, HostLibrary};
use miden_vm::internal::naming_inputs::{LoadedPackage, NamingInputs, NamingRole};
use miden_wasm_event_handlers::{WasmHandlerLimits, host_library_from_package};

use crate::cli::data::{Libraries, ProgramFile};

/// Returns the `Package` read from a `.masp` package file.
///
/// The callers extract the program with [`Package::try_into_program`] and register the package
/// with [`load_package_with_handlers`].
pub fn get_masp_package(path: &Path) -> Result<Arc<Package>, Report> {
    Package::deserialize_from_file(path)
        .into_diagnostic()
        .wrap_err("Failed to deserialize package")
        .map(Arc::new)
}

/// Registers the MAST forest, the debug info, and the Wasm event handlers of `package` with
/// `host`.
///
/// `DefaultHost::load_library` on a package alone leaves the `event_handlers` section
/// unregistered, because the processor cannot depend on the Wasm handler runner. This function
/// routes the package through that runner, so every package the CLI loads answers its own events.
///
/// A project attaches one handler section to every target it builds, so two packages of the same
/// project — an executable and its embedded kernel, or a `-l` sibling — carry identical
/// sections, and the host would reject the second registration of every event. An identical
/// section is benign (same module, same manifest), so a package whose section is already in
/// `loaded_handler_sections` registers its MAST forest and debug info only. Differing sections
/// that share an event name still fail loudly.
///
/// # Errors
/// Returns an error when the handler module of the package fails validation, or when the host
/// already holds a different handler for one of the events the package declares.
pub fn load_package_with_handlers(
    host: &mut DefaultHost,
    package: &Arc<Package>,
    loaded_handler_sections: &mut Vec<EventHandlerSection>,
) -> Result<(), Report> {
    let section = package
        .event_handlers()
        .into_diagnostic()
        .wrap_err("Failed to load the package's Wasm event handlers")?;
    if let Some(section) = &section
        && loaded_handler_sections.contains(section)
    {
        return host
            .load_library(HostLibrary::from(package.clone()))
            .into_diagnostic()
            .wrap_err("Failed to register the package's MAST forest");
    }
    let library = host_library_from_package(package, WasmHandlerLimits::default())
        .into_diagnostic()
        .wrap_err("Failed to load the package's Wasm event handlers")?;
    host.load_library(library)
        .into_diagnostic()
        .wrap_err("Failed to register the package's Wasm event handlers")?;
    if let Some(section) = section {
        loaded_handler_sections.push(section);
    }
    Ok(())
}

/// Registers the already selected target/kernel and independently admitted code libraries.
pub fn load_program_libraries(
    host: &mut DefaultHost,
    program: &LoadedProgram,
    libraries: &Libraries,
) -> Result<(), Report> {
    host.load_library(&CoreLibrary::default()).into_diagnostic()?;
    let mut sections = Vec::new();
    for library in &libraries.libraries {
        load_package_with_handlers(host, &library.package, &mut sections)?;
    }
    load_package_with_handlers(host, &program.target.package, &mut sections)?;
    if let Some(kernel) = &program.kernel {
        load_package_with_handlers(host, &kernel.package, &mut sections)?;
    }
    Ok(())
}

/// Code with its exact retained/admitted inventory and optional independent kernel inventory.
pub struct LoadedProgram {
    pub program: Program,
    pub target: LoadedPackage,
    pub kernel: Option<LoadedPackage>,
    pub source_manager: Option<Arc<DefaultSourceManager>>,
}

/// Selects code only after its complete naming has been supplied independently.
/// Execution authority continues to come from the caller's expected descriptor and openings.
pub fn load_program(
    path: &Path,
    libraries: &Libraries,
    kernel_file: Option<&Path>,
    naming: &NamingInputs,
    expected_entry: ProcedureKey,
) -> Result<LoadedProgram, Report> {
    let (target, kernel, source_manager) = match extension(path).as_str() {
        "masp" => {
            if kernel_file.is_some() {
                return Err(Report::msg(
                    "--kernel applies to source assembly; a .masp carries its embedded kernel code",
                ));
            }
            let target = naming.admit(NamingRole::Target, get_masp_package(path)?)?;
            let kernel = match target.package.try_embedded_kernel_package()? {
                Some(kernel) => Some(naming.admit(NamingRole::Kernel, Arc::from(kernel))?),
                None => {
                    if naming.has_kernel() {
                        return Err(Report::msg("kernel naming was supplied without kernel code"));
                    }
                    None
                },
            };
            (target, kernel, None)
        },
        "masm" => {
            let program_file = ProgramFile::read(path)?;
            let source_manager = program_file.source_manager().clone();
            let kernel = match kernel_file {
                Some(kernel_path) => {
                    let kernel = match extension(kernel_path).as_str() {
                        "masp" => {
                            naming.admit(NamingRole::Kernel, get_masp_package(kernel_path)?)?
                        },
                        "masm" => {
                            let mut assembler = Assembler::new(source_manager.clone())
                                .with_namespace_inputs(naming.source(NamingRole::Kernel)?);
                            let core = CoreLibrary::default();
                            assembler.link_package(
                                core.package(),
                                Linkage::Dynamic,
                                core.naming().clone(),
                            )?;
                            for library in &libraries.libraries {
                                assembler.link_package(
                                    library.package.clone(),
                                    Linkage::Dynamic,
                                    library.naming.clone(),
                                )?;
                            }
                            let product = assembler
                                .assemble_kernel_from_root_with_naming("kernel", kernel_path)?;
                            let owned = Arc::new(product.naming().clone());
                            naming.encode_owned(&owned)?;
                            let package: Arc<Package> = product.into_artifact(true)?.into();
                            package.check_naming(&owned).map_err(Report::msg)?;
                            LoadedPackage { package, naming: owned }
                        },
                        _ => return Err(Report::msg("kernel input must be .masm or .masp")),
                    };
                    kernel.package.check_kernel_code(&kernel.naming)?;
                    Some(kernel)
                },
                None => {
                    if naming.has_kernel() {
                        return Err(Report::msg("kernel naming was supplied without --kernel"));
                    }
                    None
                },
            };
            let target = program_file.compile_package_with_kernel(
                libraries.libraries.iter().cloned(),
                naming.source(NamingRole::Target)?,
                kernel.as_ref(),
            )?;
            naming.encode_owned(&target.naming)?;
            (target, kernel, Some(source_manager))
        },
        _ => return Err(Report::msg("program input must be .masm or .masp")),
    };
    if target.naming.entry_key() != Some(expected_entry) {
        return Err(Report::msg("program entry differs from caller expected entry key"));
    }
    if let Some(kernel) = &kernel {
        kernel.package.check_kernel_code(&kernel.naming)?;
    }
    let program = target.package.try_into_program(&target.naming)?;
    Ok(LoadedProgram { program, target, kernel, source_manager })
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Parses a byte-size string into a byte count.
///
/// A bare integer is interpreted as bytes. A trailing `K`/`M`/`G` suffix scales it by
/// 1000/1000²/1000³; a trailing `Ki`/`Mi`/`Gi` suffix scales it by 1024/1024²/1024³.
pub fn parse_byte_size(input: &str) -> Result<u64, String> {
    const KI: u64 = 1024;
    const MI: u64 = KI * 1024;
    const GI: u64 = MI * 1024;
    const K: u64 = 1000;
    const M: u64 = K * 1000;
    const G: u64 = M * 1000;

    let trimmed = input.trim();
    let (digits, multiplier) = [("Ki", KI), ("Mi", MI), ("Gi", GI), ("K", K), ("M", M), ("G", G)]
        .into_iter()
        .find_map(|(suffix, multiplier)| {
            trimmed.strip_suffix(suffix).map(|digits| (digits, multiplier))
        })
        .unwrap_or((trimmed, 1));

    let value: u64 = digits.trim().parse().map_err(|_| {
        format!(
            "`{input}` is not a valid byte size (expected a bare integer or a K/M/G/Ki/Mi/Gi suffix, e.g. `512M`, `32Gi`)"
        )
    })?;

    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("`{input}` overflows a 64-bit byte count"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_size_accepts_bare_integers() {
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(parse_byte_size("12345").unwrap(), 12345);
    }

    #[test]
    fn parse_byte_size_accepts_decimal_suffixes() {
        assert_eq!(parse_byte_size("1K").unwrap(), 1_000);
        assert_eq!(parse_byte_size("512M").unwrap(), 512_000_000);
        assert_eq!(parse_byte_size("32G").unwrap(), 32_000_000_000);
    }

    #[test]
    fn parse_byte_size_accepts_binary_suffixes() {
        assert_eq!(parse_byte_size("1Ki").unwrap(), 1024);
        assert_eq!(parse_byte_size("1Mi").unwrap(), 1024 * 1024);
        assert_eq!(parse_byte_size("64Gi").unwrap(), 64 << 30);
    }

    #[test]
    fn parse_byte_size_rejects_garbage() {
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("G").is_err());
        assert!(parse_byte_size("12X").is_err());
        assert!(parse_byte_size("12.5M").is_err());
    }

    #[test]
    fn parse_byte_size_rejects_overflow() {
        // The digits alone fit in a u64, but multiplying by the suffix overflows.
        assert!(parse_byte_size("18446744073709551615G").is_err());
    }
}
