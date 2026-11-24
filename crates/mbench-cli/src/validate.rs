//! Capture protocol verification and structured JSON export (`mbench validate`).

use std::{fs, path::PathBuf};

use clap::Args;
use mbench_core::validate::audit_capture;

/// CLI flags for `mbench validate`.
#[derive(Debug, Args)]
pub(crate) struct ValidateArgs {
    /// Saved `.jsonl` capture or raw serial output log to validate.
    pub(crate) input: PathBuf,

    /// Emit the structured validation report as JSON (always written to stdout).
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

pub(crate) fn execute(args: ValidateArgs) -> Result<(), String> {
    let text = fs::read_to_string(&args.input)
        .map_err(|e| format!("failed to read {}: {e}", args.input.display()))?;
    let source = args
        .input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    let report = audit_capture(source, &text);

    if args.json {
        let rendered = serde_json::to_string_pretty(&report)
            .map_err(|e| format!("failed to serialize capture report: {e}"))?;
        println!("{rendered}");
    } else {
        println!(
            "[mbench-cli] validate {} ({}): harts={} exts={} checks={}/{} (skip={}, fail={}) benches={}/{} effective (skip={}, fail={}) warn={} recovered={}",
            if report.protocol_valid && report.completed {
                "PASS"
            } else {
                "FAIL"
            },
            args.input.display(),
            report.meta.as_ref().map_or(0, |m| m.hart_count),
            report.meta.as_ref().map_or(0, |m| m.extensions.len()),
            report.counts.checks_passed,
            report.counts.checks_total,
            report.counts.checks_skipped,
            report.counts.checks_failed,
            report.counts.benches_effective,
            report.counts.benches_total,
            report.counts.benches_skipped,
            report.counts.benches_failed,
            report.counts.quarantine_warnings,
            report.recovered,
        );
    }

    if report.protocol_valid && report.completed {
        Ok(())
    } else if report.protocol_errors.is_empty() {
        Err(format!(
            "capture '{}' did not complete cleanly",
            args.input.display()
        ))
    } else {
        Err(format!(
            "protocol validation failed for {} ({} error(s)):\n  - {}",
            args.input.display(),
            report.protocol_errors.len(),
            report.protocol_errors.join("\n  - ")
        ))
    }
}
