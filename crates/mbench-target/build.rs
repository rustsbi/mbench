//! Generates the RISC-V bare-metal linker script at the configured load address.

use std::{env, fs, path::PathBuf};

const DEFAULT_LOAD_ADDR: u64 = 0x8020_0000;
const DEFAULT_DRAM_BASE: u64 = 0x8000_0000;
const DEFAULT_TEXT_OFFSET: u64 = 0x0020_0000;

fn parse_load_addr(raw: &str) -> u64 {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let addr =
        u64::from_str_radix(hex, 16).expect("MBENCH_LOAD_ADDR must be a valid hexadecimal address");
    assert!(
        addr != 0 && addr.is_multiple_of(4096),
        "MBENCH_LOAD_ADDR (0x{addr:x}) must be non-zero and 4 KiB page-aligned"
    );
    addr
}

fn parse_text_offset(raw: &str) -> u64 {
    let trimmed = raw.trim();
    let offset = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).expect("MBENCH_TEXT_OFFSET hex value is invalid")
    } else {
        trimmed
            .parse::<u64>()
            .expect("MBENCH_TEXT_OFFSET must be a decimal or 0x-prefixed hex integer")
    };
    assert!(
        offset.is_multiple_of(4096),
        "MBENCH_TEXT_OFFSET (0x{offset:x}) must be 4 KiB page-aligned"
    );
    offset
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    println!("cargo:rerun-if-env-changed=MBENCH_LOAD_ADDR");
    println!("cargo:rerun-if-env-changed=MBENCH_TEXT_OFFSET");
    println!("cargo:rerun-if-changed=linker.ld.in");

    let load_addr = match env::var("MBENCH_LOAD_ADDR") {
        Ok(raw) => parse_load_addr(&raw),
        Err(_) => DEFAULT_LOAD_ADDR,
    };
    let text_offset = match env::var("MBENCH_TEXT_OFFSET") {
        Ok(raw) => parse_text_offset(&raw),
        Err(_) => load_addr
            .checked_sub(DEFAULT_DRAM_BASE)
            .unwrap_or(DEFAULT_TEXT_OFFSET),
    };
    let formatted_addr = format!("0x{load_addr:x}");
    let formatted_offset = format!("0x{text_offset:x}");

    let template = include_str!("linker.ld.in");
    let script = template.replace("@MBENCH_LOAD_ADDR@", &formatted_addr);
    let linker_path = out_dir.join("mbench-target.ld");
    fs::write(&linker_path, script).expect("failed to write linker script");

    println!("cargo:rustc-env=MBENCH_LOAD_ADDR={formatted_addr}");
    println!("cargo:rustc-env=MBENCH_TEXT_OFFSET={formatted_offset}");
    println!("cargo:rustc-link-arg=-T{}", linker_path.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
}
