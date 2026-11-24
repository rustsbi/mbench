//! Capture validation CLI subcommand and shared policy arguments.

use std::{fs, path::PathBuf};

use clap::Args;
use mbench_core::{
    record::SbiExtensionId,
    validate::{ValidationPolicy, parse_forbidden_patterns, validate_capture},
};

/// Shared validation policy arguments used by `mbench validate` and `mbench run --strict`.
#[derive(Clone, Debug, Default, Args)]
pub(crate) struct PolicyArgs {
    /// Expected hardware hart count reported in `@@MBENCH:META`.
    #[arg(long)]
    pub(crate) expect_harts: Option<usize>,

    /// Required SBI extension names (comma-separated or repeated, e.g., `base,time,hsm`).
    #[arg(long = "require-ext", value_delimiter = ',')]
    pub(crate) require_ext: Vec<String>,

    /// Required conformance check IDs that must report `PASS` (comma-separated or repeated).
    #[arg(long = "require-check-pass", value_delimiter = ',')]
    pub(crate) require_check_pass: Vec<String>,

    /// Minimum number of `PASS` conformance check cases required.
    #[arg(long)]
    pub(crate) min_checks_passed: Option<usize>,

    /// Minimum number of effective benchmark cases (`PASS`, `HW_NATIVE`, `DELEGATED_TO_S`).
    #[arg(long)]
    pub(crate) min_effective_benches: Option<usize>,

    /// Minimum number of effective SMP benchmark cases required.
    #[arg(long)]
    pub(crate) min_smp_effective_benches: Option<usize>,

    /// Maximum allowed `quarantine_warnings` in `@@MBENCH:END`.
    #[arg(long)]
    pub(crate) max_quarantine_warnings: Option<usize>,

    /// Path to forbidden console substrings file (one pattern per line, `#` comments ignored).
    #[arg(long)]
    pub(crate) forbidden_file: Option<PathBuf>,

    /// Require every `@@MBENCH:START` frame in raw serial logs to be closed before `END` and EOF.
    #[arg(long, default_value_t = false)]
    pub(crate) require_closed_starts: bool,
}

impl PolicyArgs {
    /// Converts CLI policy flags into a validated [`ValidationPolicy`].
    pub(crate) fn to_policy(&self) -> Result<ValidationPolicy, String> {
        let mut require_extensions = Vec::with_capacity(self.require_ext.len());
        for raw in &self.require_ext {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(String::from("--require-ext entries must not be empty"));
            }
            let ext = SbiExtensionId::from_name(trimmed).ok_or_else(|| {
                format!("unknown SBI extension name '{trimmed}' in --require-ext")
            })?;
            if !require_extensions.contains(&ext) {
                require_extensions.push(ext);
            }
        }

        let mut require_check_pass = Vec::with_capacity(self.require_check_pass.len());
        for raw in &self.require_check_pass {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(String::from(
                    "--require-check-pass entries must not be empty",
                ));
            }
            if !require_check_pass.iter().any(|id| id == trimmed) {
                require_check_pass.push(trimmed.to_string());
            }
        }

        let forbidden_patterns = match &self.forbidden_file {
            Some(path) => {
                let text = fs::read_to_string(path).map_err(|e| {
                    format!(
                        "failed to read forbidden pattern file '{}': {e}",
                        path.display()
                    )
                })?;
                parse_forbidden_patterns(&text).map_err(|e| format!("{}: {e}", path.display()))?
            }
            None => Vec::new(),
        };

        Ok(ValidationPolicy {
            require_closed_starts: self.require_closed_starts,
            expect_harts: self.expect_harts,
            require_extensions,
            require_check_pass,
            min_checks_passed: self.min_checks_passed,
            min_effective_benches: self.min_effective_benches,
            min_smp_effective_benches: self.min_smp_effective_benches,
            max_quarantine_warnings: self.max_quarantine_warnings,
            forbidden_patterns,
        })
    }
}

/// CLI flags for `mbench validate`.
#[derive(Debug, Args)]
pub(crate) struct ValidateArgs {
    /// Saved `.jsonl` capture or raw serial output log to validate.
    pub(crate) input: PathBuf,

    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

pub(crate) fn execute(args: ValidateArgs) -> Result<(), String> {
    let policy = args.policy.to_policy()?;
    let text = fs::read_to_string(&args.input)
        .map_err(|e| format!("failed to read {}: {e}", args.input.display()))?;
    match validate_capture(&text, &policy) {
        Ok(summary) => {
            println!(
                "[mbench-cli] validate PASS ({}): harts={} exts={} checks={}/{} (skip={}, fail={}) benches={}/{} effective (smp={}, skip={}, fail={}) warn={}",
                args.input.display(),
                summary.hart_count,
                summary.extensions_count,
                summary.checks_passed,
                summary.checks_total,
                summary.checks_skipped,
                summary.checks_failed,
                summary.benches_effective,
                summary.benches_total,
                summary.benches_smp_effective,
                summary.benches_skipped,
                summary.benches_failed,
                summary.quarantine_warnings,
            );
            Ok(())
        }
        Err(errs) => Err(format!(
            "validation failed for {} ({} error(s)):\n  - {}",
            args.input.display(),
            errs.len(),
            errs.join("\n  - ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_flags_and_rejects_unknown_extensions() {
        let ok = PolicyArgs {
            expect_harts: Some(4),
            require_ext: vec![String::from("base"), String::from("hsm")],
            require_check_pass: vec![String::from("conformance/base")],
            min_checks_passed: Some(1),
            min_effective_benches: Some(2),
            min_smp_effective_benches: Some(1),
            max_quarantine_warnings: Some(0),
            forbidden_file: None,
            require_closed_starts: true,
        };
        let policy = ok.to_policy().unwrap();
        assert_eq!(policy.expect_harts, Some(4));
        assert_eq!(
            policy.require_extensions,
            vec![SbiExtensionId::Base, SbiExtensionId::Hsm]
        );
        assert_eq!(policy.require_check_pass, vec!["conformance/base"]);

        let bad_ext = PolicyArgs {
            require_ext: vec![String::from("nonexistent_ext")],
            ..Default::default()
        };
        assert!(bad_ext.to_policy().is_err());

        let missing_file = PolicyArgs {
            forbidden_file: Some(PathBuf::from("/no/such/forbidden.txt")),
            ..Default::default()
        };
        assert!(missing_file.to_policy().is_err());
    }
}
