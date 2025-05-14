/*
A Cargo subcommand `cargo vnd package` to embed a manifest JSON into the built ELF as a custom section.

Usage:
  cargo vnd package [--app target/your/binary] [--cargo_toml_path your\app/manifest] [--output bundled_binary]

It can be called with no arguments if called from the folder containing the Cargo.toml file of th V-App.
*/

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use client_sdk::elf::{ElfFile, get_app_metadata};
use client_sdk::memory::MemorySegment;
use common::constants;
use common::manifest::Manifest;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "cargo-vnd", version, about = "Vanadium tools for cargo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed manifest into ELF
    Package {
        /// Path to the ELF binary (optional, deduced from manifest if not provided)
        #[arg(short, long, value_name = "ELF")]
        app: Option<PathBuf>,

        /// Path to the Cargo.toml manifest of the app (optional, defaults to ./Cargo.toml)
        #[arg(long, value_name = "CARGO_TOML")]
        cargo_toml_path: Option<PathBuf>,

        /// Output file path (optional, defaults to <crate-name>.vapp)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },
}

// The standard "objcopy" binary does not support RISCV targets.
// The riscv64 binary supports 32-bit targets as well.
const OBJCOPY_BINARY: &str = "riscv64-unknown-elf-objcopy";

fn main() -> Result<()> {
    // Skip the first argument ("vnd") when invoked as `cargo vnd`
    let cli = Cli::parse_from(std::env::args_os().skip(1));

    match cli.command {
        Commands::Package {
            app,
            cargo_toml_path,
            output,
        } => {
            let cargo_toml_path = cargo_toml_path
                .unwrap_or_else(|| std::env::current_dir().unwrap().join("Cargo.toml"));

            let (app_crate_name, app_version, app_metadata) = get_app_metadata(&cargo_toml_path)
                .map_err(|e| anyhow::anyhow!(e))
                .context("Failed to get app metadata from Cargo.toml")?;

            let elf_path = match app {
                Some(path) => path,
                // if the app path is not provided, default to release binary for the riscv32imc target
                None => cargo_toml_path
                    .parent()
                    .unwrap()
                    .join("target/riscv32imc-unknown-none-elf/release")
                    .join(app_crate_name),
            };
            // if the output path is not provided, default to adding the .vapp extension to the elf
            let output = output.unwrap_or_else(|| elf_path.with_extension("vapp"));
            create_vapp_package(&app_version, &app_metadata, &elf_path, &output)?;
        }
    }
    Ok(())
}

fn compute_merkle_roots(
    elf_file: &ElfFile,
    stack_start: u32,
    stack_size: u32,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let code_merkle_root: [u8; 32] =
        MemorySegment::new(elf_file.code_segment.start, &elf_file.code_segment.data)
            .get_content_root()
            .clone()
            .into();
    let data_merkle_root: [u8; 32] =
        MemorySegment::new(elf_file.data_segment.start, &elf_file.data_segment.data)
            .get_content_root()
            .clone()
            .into();
    let stack_merkle_root: [u8; 32] =
        MemorySegment::new(stack_start, &vec![0u8; stack_size as usize])
            .get_content_root()
            .clone()
            .into();

    Ok((code_merkle_root, data_merkle_root, stack_merkle_root))
}

fn create_vapp_package(
    app_version: &str,
    app_metadata: &client_sdk::cargo_toml::Value,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<()> {
    // Ensure objcopy is available
    which::which(OBJCOPY_BINARY).context(format!("`{}` not found in PATH", OBJCOPY_BINARY))?;

    let elf_file = ElfFile::new(&input)?;

    let section_name = ".manifest";

    let app_name = app_metadata
        .get("name")
        .context("App name missing in metadata")?
        .as_str()
        .context("App name is not a string")?;

    let stack_size = app_metadata
        .get("stack_size")
        .context("Stack size missing in metadata")?
        .as_integer()
        .context("Stack size is not a number")?;

    if stack_size < constants::MIN_STACK_SIZE as i64
        || stack_size > constants::MAX_STACK_SIZE as i64
    {
        return Err(anyhow::anyhow!(
            "Stack size must be between {} and {} bytes",
            constants::MIN_STACK_SIZE,
            constants::MAX_STACK_SIZE
        ));
    }
    let stack_size = stack_size as u32;

    // we might make it configurable in the future; for now, use a fixed value
    let stack_start = constants::DEFAULT_STACK_START;
    let stack_end = stack_start + stack_size;

    let (code_merkle_root, data_merkle_root, stack_merkle_root) =
        compute_merkle_roots(&elf_file, stack_start, stack_size)?;

    let mut manifest = Manifest::new(
        0,
        app_name,
        app_version,
        elf_file.entrypoint,
        elf_file.code_segment.start,
        elf_file.code_segment.end,
        code_merkle_root,
        elf_file.data_segment.start,
        elf_file.data_segment.end,
        data_merkle_root,
        stack_start,
        stack_end,
        stack_merkle_root,
    )
    .map_err(|e| anyhow::anyhow!(e))
    .context("Failed to create VApp manifest")?;

    let serialized_manifest = manifest.to_json()?;

    // Write the serialized manifest to a temporary file
    let temp_manifest_path = std::env::temp_dir().join("manifest.json");
    std::fs::write(&temp_manifest_path, serialized_manifest)
        .context("Failed to write manifest to temporary file")?;

    // Run objcopy to add section
    // Add the ".manifest" section to the ELF binary using objcopy
    let status = Command::new(OBJCOPY_BINARY)
        .arg("--add-section")
        .arg(format!("{}={}", section_name, temp_manifest_path.display()))
        .arg(input)
        .arg(output)
        .status()
        .context("Failed to run objcopy")?;
    if !status.success() {
        return Err(anyhow::anyhow!("objcopy command failed").into());
    }

    // Hack: adding the manifest with objcopy seems to cause changes in the loadable content, possibly due
    // to changes in the program headers. This affects the merkle roots.
    // To fix this, we recompute the merkle roots and update the manifest.
    // This is a workaround, and we should investigate if there is a way to add the .manifest section
    // without affecting the loadable content.

    // Recompute merkle roots from the output file
    let updated_elf_file = ElfFile::new(&output)?;
    let (updated_code_merkle_root, updated_data_merkle_root, updated_stack_merkle_root) =
        compute_merkle_roots(&updated_elf_file, stack_start, stack_size)?;

    // Update the manifest with new merkle roots
    manifest.code_merkle_root = updated_code_merkle_root;
    manifest.data_merkle_root = updated_data_merkle_root;
    manifest.stack_merkle_root = updated_stack_merkle_root;

    let updated_serialized_manifest = manifest.to_json()?;

    // Write the updated manifest to a temporary file
    let updated_temp_manifest_path = std::env::temp_dir().join("updated_manifest.json");
    std::fs::write(&updated_temp_manifest_path, updated_serialized_manifest)
        .context("Failed to write updated manifest to temporary file")?;

    // Update the ".manifest" section in the output ELF binary
    let status = Command::new(OBJCOPY_BINARY)
        .arg("--update-section")
        .arg(format!(
            "{}={}",
            section_name,
            updated_temp_manifest_path.display()
        ))
        .arg(output)
        .status()
        .context("Failed to update manifest section in output binary")?;
    if !status.success() {
        return Err(anyhow::anyhow!("objcopy command failed during manifest update").into());
    }

    println!("Saved packaged V-App in {}", output.display());

    Ok(())
}
