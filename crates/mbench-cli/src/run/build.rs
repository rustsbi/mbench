//! Bare-metal target build and atomic ELF-to-binary conversion.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

use super::output::{replace_file, temporary_path};

const DEFAULT_TARGET: &str = "riscv64imac-unknown-none-elf";

#[derive(Deserialize)]
struct WorkspaceMetadata {
    target_directory: PathBuf,
    workspace_root: PathBuf,
}

pub(crate) fn build_target_binary() -> Result<PathBuf, String> {
    eprintln!("[mbench-cli] building mbench-target ({DEFAULT_TARGET})...");
    let metadata = cargo_metadata()?;
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "mbench-target",
            "--target",
            DEFAULT_TARGET,
            "--locked",
        ])
        .current_dir(&metadata.workspace_root)
        .status()
        .map_err(|e| format!("failed to run cargo build: {e}"))?;
    if !status.success() {
        return Err(String::from("cargo build -p mbench-target failed"));
    }

    let elf = metadata
        .target_directory
        .join(DEFAULT_TARGET)
        .join("release/mbench-target");
    let bin = metadata
        .target_directory
        .join(DEFAULT_TARGET)
        .join("release/mbench.bin");
    convert_elf_to_binary(&elf, &bin)?;
    Ok(bin)
}

fn cargo_metadata() -> Result<WorkspaceMetadata, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked", "--no-deps"])
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with exit status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("invalid cargo metadata: {e}"))
}

fn convert_elf_to_binary(elf: &Path, bin: &Path) -> Result<(), String> {
    let mut failures = Vec::new();
    for tool in ["rust-objcopy", "llvm-objcopy"] {
        let temporary = temporary_path(bin)?;
        match Command::new(tool)
            .args(["-O", "binary"])
            .arg(elf)
            .arg(&temporary)
            .status()
        {
            Ok(status) if status.success() => {
                return replace_file(&temporary, bin);
            }
            Ok(status) => {
                let _ = fs::remove_file(&temporary);
                failures.push(format!("{tool} failed with exit status {status}"));
            }
            Err(err) => {
                let _ = fs::remove_file(&temporary);
                failures.push(format!("failed to run {tool}: {err}"));
            }
        }
    }
    Err(format!(
        "failed to convert ELF to binary: {}",
        failures.join("; ")
    ))
}
