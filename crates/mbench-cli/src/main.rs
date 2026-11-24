//! Host CLI for running `mbench` on target platforms and comparing firmware captures.

#![forbid(unsafe_code)]

mod compare;
mod run;
mod runner;
mod validate;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "mbench",
    about = "LMbench-style black-box RISC-V M-mode / SBI v3.0 benchmark runner & comparator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Builds (if needed) and runs `mbench` on QEMU with watchdog & crash recovery.
    Run(Box<run::RunArgs>),
    /// Compares multiple `.jsonl` results or raw serial capture logs side-by-side.
    Compare(compare::CompareArgs),
    /// Validates completeness, protocol integrity, and policy gates on a capture or serial log.
    Validate(validate::ValidateArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Run(args) => run::execute(*args),
        Command::Compare(args) => compare::execute(args),
        Command::Validate(args) => validate::execute(args),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
