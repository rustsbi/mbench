//! Host CLI for running `mbench` on target platforms and comparing firmware captures.

#![forbid(unsafe_code)]

mod run;
mod runner;

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
    Run(run::RunArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Run(args) => run::execute(args),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
