//! Generates the RISC-V bare-metal linker script at the configured load address.

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    println!("cargo:rerun-if-env-changed=MBENCH_LOAD_ADDR");
    println!("cargo:rerun-if-changed=linker.ld.in");

    let raw_addr = env::var("MBENCH_LOAD_ADDR").unwrap_or_else(|_| String::from("0x80200000"));
    let parsed = usize::from_str_radix(raw_addr.trim_start_matches("0x"), 16)
        .expect("MBENCH_LOAD_ADDR must be a valid hexadecimal address");
    let formatted_addr = format!("0x{parsed:x}");

    let template = include_str!("linker.ld.in");
    let script = template.replace("@MBENCH_LOAD_ADDR@", &formatted_addr);
    let linker_path = out_dir.join("mbench-target.ld");
    fs::write(&linker_path, script).expect("failed to write linker script");

    println!("cargo:rustc-env=MBENCH_LOAD_ADDR={formatted_addr}");
    println!("cargo:rustc-link-arg=-T{}", linker_path.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
}
