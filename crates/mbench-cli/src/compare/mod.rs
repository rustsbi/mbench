//! Capture loading, firmware summaries, and shared table/text rendering.

mod tables;
#[cfg(test)]
mod tests;

use std::{fs, path::PathBuf};

use clap::{Args, ValueEnum};
use mbench_core::{
    record::SbiExtensionId,
    stats::STATS_SCALE,
    wire::{ParsedCapture, parse_capture},
};

use self::tables::{
    render_benchmark_table, render_conformance_table, render_derived_decomposition,
};

/// Primary metric displayed in comparison columns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum Metric {
    #[default]
    Cycles,
    Instret,
    Ns,
}

/// Output table format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Table,
    Markdown,
}

/// CLI flags for `mbench compare`.
#[derive(Debug, Args)]
pub(crate) struct CompareArgs {
    /// Saved `.jsonl` captures or raw serial capture logs to compare.
    #[arg(required = true)]
    pub(crate) files: Vec<PathBuf>,

    /// Metric column (`cycles`, `instret`, or `ns`).
    #[arg(long, value_enum, default_value_t = Metric::Cycles)]
    pub(crate) metric: Metric,

    /// Output format (`table` or `markdown`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub(crate) format: OutputFormat,

    /// Optional benchmark or check ID substring filter.
    #[arg(long)]
    pub(crate) filter: Option<String>,
}

pub(crate) fn execute(args: CompareArgs) -> Result<(), String> {
    if let Some(flt) = &args.filter
        && flt.is_empty()
    {
        return Err(String::from("--filter must not be empty"));
    }
    let mut captures = Vec::with_capacity(args.files.len());
    for path in &args.files {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let label = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("capture");
        captures.push(parse_capture(label, &text)?);
    }

    let rendered = render_comparison(&captures, args.metric, args.format, args.filter.as_deref());
    print!("{rendered}");
    Ok(())
}

pub(crate) fn render_comparison(
    captures: &[ParsedCapture],
    metric: Metric,
    format: OutputFormat,
    filter: Option<&str>,
) -> String {
    let mut out = String::new();
    render_metadata_header(captures, format, &mut out);
    render_extension_matrix(captures, format, &mut out);
    let drew_checks = render_conformance_table(captures, format, filter, &mut out);
    let drew_benches = render_benchmark_table(captures, metric, format, filter, &mut out);
    let drew_derived = render_derived_decomposition(captures, metric, format, filter, &mut out);
    if let Some(flt) = filter
        && !drew_checks
        && !drew_benches
        && !drew_derived
    {
        out.push_str(&format!(
            "No checks or benchmarks matched filter '{flt}'.\n"
        ));
    }
    out
}

fn render_metadata_header(captures: &[ParsedCapture], format: OutputFormat, out: &mut String) {
    write_section_heading("Firmware & Platform Summary", format, out);
    let label_w = captures
        .iter()
        .map(|c| c.label.len())
        .max()
        .unwrap_or(18)
        .max(18);
    for cap in captures {
        let panic_note = cap
            .panic
            .as_ref()
            .map(|p| {
                let msg = p
                    .reason
                    .as_deref()
                    .or(p.message.as_deref())
                    .unwrap_or("panic");
                format!(" panic={msg}")
            })
            .unwrap_or_default();
        let max_harts_note = cap
            .max_harts
            .map(|mh| format!(" max_harts={mh}"))
            .unwrap_or_default();

        if let Some(meta) = &cap.meta {
            let major = (meta.sbi_spec_version >> 24) & 0x7f;
            let minor = meta.sbi_spec_version & 0x00ff_ffff;
            let cal_note = cap
                .cal
                .as_ref()
                .map(|c| {
                    if cap.cals.len() > 1 {
                        format!(
                            "profile={} trials={} cals={}",
                            c.profile.as_str(),
                            c.trials,
                            cap.cals.len()
                        )
                    } else {
                        format!("profile={} trials={}", c.profile.as_str(), c.trials)
                    }
                })
                .unwrap_or_else(|| String::from("no-cal"));
            let end_note = cap
                .end
                .as_ref()
                .map(|e| {
                    let mut s = format!(
                        " checks={}/{} check_fail={} benches={}/{} bench_fail={}",
                        e.checks_passed,
                        e.checks_total,
                        e.checks_failed,
                        e.benches_passed,
                        e.benches_total,
                        e.benches_failed,
                    );
                    if e.benches_hw_native > 0 {
                        s.push_str(&format!(" hw_nat={}", e.benches_hw_native));
                    }
                    if e.benches_delegated > 0 {
                        s.push_str(&format!(" deleg={}", e.benches_delegated));
                    }
                    s.push_str(&format!(" warn={}", e.quarantine_warnings));
                    s
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "- {:<w$} sbi=v{}.{} impl={} (ver={:#x}) harts={}{} timebase={}Hz sstc={} h={} console={} boot_ticks={} resv={}B regime={} ({cal_note}{end_note}{panic_note})\n",
                cap.label,
                major,
                minor,
                meta.impl_id,
                meta.impl_version,
                meta.hart_count,
                max_harts_note,
                meta.timebase_hz,
                meta.has_sstc,
                meta.has_h_ext,
                meta.console_backend,
                meta.boot_ticks,
                meta.reserved_mem_bytes,
                cap.clock_regime.label(),
                w = label_w,
            ));
        } else {
            out.push_str(&format!(
                "- {:<w$} (no META frame; regime={}{})\n",
                cap.label,
                cap.clock_regime.label(),
                panic_note,
                w = label_w,
            ));
        }
    }
    out.push('\n');
}

fn render_extension_matrix(captures: &[ParsedCapture], format: OutputFormat, out: &mut String) {
    write_section_heading("SBI v3.0 Extension Matrix", format, out);
    let mut headers = Vec::with_capacity(1 + SbiExtensionId::ALL.len());
    headers.push(String::from("Firmware"));
    for ext in SbiExtensionId::ALL {
        headers.push(String::from(ext.name()));
    }

    let mut rows = Vec::with_capacity(captures.len());
    for cap in captures {
        let mut row = Vec::with_capacity(headers.len());
        row.push(cap.label.clone());
        let mask = cap.meta.as_ref().map_or(0, |m| m.extensions_mask);
        for ext in SbiExtensionId::ALL {
            let mark = if (mask & ext.as_flag().bits()) != 0 {
                "Y"
            } else {
                "-"
            };
            row.push(String::from(mark));
        }
        rows.push(row);
    }

    write_table(&headers, &rows, format, out);
}

fn write_section_heading(title: &str, format: OutputFormat, out: &mut String) {
    match format {
        OutputFormat::Table => {
            out.push_str("=== ");
            out.push_str(title);
            out.push_str(" ===\n");
        }
        OutputFormat::Markdown => {
            out.push_str("## ");
            out.push_str(title);
            out.push('\n');
        }
    }
}

fn format_p_value(p: Option<f64>) -> String {
    match p {
        Some(v) if v < 0.001 => String::from("p<0.001"),
        Some(v) => format!("p={v:.3}"),
        None => String::from("p=n/a"),
    }
}

fn format_scaled(scaled: u64) -> String {
    format!("{}.{:02}", scaled / STATS_SCALE, scaled % STATS_SCALE)
}

fn write_table(headers: &[String], rows: &[Vec<String>], format: OutputFormat, out: &mut String) {
    let mut widths: Vec<usize> = headers.iter().map(String::len).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    let (lead, prefix, suffix) = match format {
        OutputFormat::Markdown => ("|", " ", " |"),
        OutputFormat::Table => ("", "", "  "),
    };
    let dashes: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    write_row(
        out,
        lead,
        headers.iter().map(String::as_str),
        &widths,
        prefix,
        suffix,
    );
    write_row(
        out,
        lead,
        dashes.iter().map(String::as_str),
        &widths,
        prefix,
        suffix,
    );
    for row in rows {
        write_row(
            out,
            lead,
            row.iter().map(String::as_str),
            &widths,
            prefix,
            suffix,
        );
    }
}

fn write_row<'a>(
    out: &mut String,
    lead: &str,
    cells: impl Iterator<Item = &'a str>,
    widths: &[usize],
    prefix: &str,
    suffix: &str,
) {
    out.push_str(lead);
    for (cell, width) in cells.zip(widths) {
        out.push_str(prefix);
        out.push_str(&format!("{cell:<width$}"));
        out.push_str(suffix);
    }
    out.push('\n');
}
