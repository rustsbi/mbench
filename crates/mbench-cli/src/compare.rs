//! LMbench-style multi-firmware comparison tables, capability matrix, Mann-Whitney U tests, and delta decomposition.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use clap::{Args, ValueEnum};
use mbench_core::{
    record::SbiExtensionId,
    stats::{DiffVerdict, STATS_SCALE, compare_samples},
    wire::{BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, ParsedCapture, parse_capture},
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

#[derive(Clone, Copy)]
struct MetricView<'a> {
    median_x100: u64,
    iqr_x100: u64,
    is_noisy: bool,
    net_samples_x100: &'a [u64],
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
    out.push('\n');
}

fn render_conformance_table(
    captures: &[ParsedCapture],
    format: OutputFormat,
    filter: Option<&str>,
    out: &mut String,
) -> bool {
    let mut keys: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in captures {
        for chk in &cap.checks {
            if let Some(flt) = filter
                && !chk.id.contains(flt)
            {
                continue;
            }
            if seen.insert(chk.id.clone()) {
                keys.push(chk.id.clone());
            }
        }
    }
    if keys.is_empty() {
        return false;
    }

    let lookup: Vec<BTreeMap<&str, &CheckFrame>> = captures
        .iter()
        .map(|cap| cap.checks.iter().map(|c| (c.id.as_str(), c)).collect())
        .collect();

    write_section_heading("Functional Conformance Summary", format, out);
    let mut headers = vec![String::from("Check")];
    for cap in captures {
        headers.push(cap.label.clone());
    }

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(keys.len());
    for key in &keys {
        let mut row = vec![key.clone()];
        for map in &lookup {
            let cell = match map.get(key.as_str()) {
                Some(chk) => format_check_cell(chk),
                None => String::from("-"),
            };
            row.push(cell);
        }
        rows.push(row);
    }

    write_table(&headers, &rows, format, out);
    out.push('\n');
    true
}

fn format_check_cell(chk: &CheckFrame) -> String {
    match chk.status {
        CheckStatusTag::Pass => {
            if chk.issues.is_empty() {
                format!("PASS ({} checks)", chk.checks)
            } else {
                format!("PASS ({} checks; {} obs)", chk.checks, chk.issues.len())
            }
        }
        CheckStatusTag::Skipped => {
            format!(
                "SKIP({})",
                chk.skip_reason.map_or("unknown", |r| r.as_str())
            )
        }
        CheckStatusTag::Fail => {
            let primary = chk.fail_reason.as_deref().unwrap_or("unknown");
            let total_issues = chk.issues.iter().filter(|i| i.class.is_failure()).count();
            let issue_count = (chk.checks_failed as usize).max(total_issues);
            if issue_count > 1 || chk.quirks > 0 {
                format!(
                    "FAIL({primary}; {issue_count} issues, {} quirks)",
                    chk.quirks
                )
            } else {
                format!("FAIL({primary})")
            }
        }
    }
}

fn render_benchmark_table(
    captures: &[ParsedCapture],
    metric: Metric,
    format: OutputFormat,
    filter: Option<&str>,
    out: &mut String,
) -> bool {
    let mut keys: Vec<(String, usize)> = Vec::new();
    let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
    for cap in captures {
        for b in &cap.benches {
            if let Some(flt) = filter
                && !b.id.contains(flt)
            {
                continue;
            }
            let key = (b.id.clone(), b.parallel);
            if seen.insert(key.clone()) {
                keys.push(key);
            }
        }
    }
    if keys.is_empty() {
        return false;
    }

    let lookup: Vec<BTreeMap<(&str, usize), &BenchFrame>> = captures
        .iter()
        .map(|cap| {
            cap.benches
                .iter()
                .map(|b| ((b.id.as_str(), b.parallel), b))
                .collect()
        })
        .collect();

    let metric_name = match metric {
        Metric::Cycles => "cycles",
        Metric::Instret => "instret",
        Metric::Ns => "ns",
    };

    let heading = format!(
        "Benchmark Comparison (metric: {metric_name}, median [iqr], Mann-Whitney U alpha=0.05)"
    );
    write_section_heading(&heading, format, out);

    let mut headers = vec![
        String::from("Benchmark"),
        String::from("p"),
        String::from("Unit"),
    ];
    for (idx, cap) in captures.iter().enumerate() {
        if idx == 0 {
            headers.push(cap.label.clone());
        } else {
            headers.push(format!("{} (vs {})", cap.label, captures[0].label));
        }
    }

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(keys.len());
    for (id, parallel) in &keys {
        let lookup_key = (id.as_str(), *parallel);
        let unit = lookup
            .iter()
            .find_map(|m| m.get(&lookup_key).map(|r| r.unit.as_str()))
            .unwrap_or("-");
        let mut row = vec![id.clone(), parallel.to_string(), unit.to_string()];
        let baseline = lookup[0].get(&lookup_key).copied();

        for (idx, map) in lookup.iter().enumerate() {
            let cell = match map.get(&lookup_key) {
                Some(r) => format_bench_cell(r, metric, if idx == 0 { None } else { baseline }),
                None => String::from("-"),
            };
            row.push(cell);
        }
        rows.push(row);
    }

    write_table(&headers, &rows, format, out);
    out.push('\n');
    true
}

fn render_derived_decomposition(
    captures: &[ParsedCapture],
    metric: Metric,
    format: OutputFormat,
    filter: Option<&str>,
    out: &mut String,
) -> bool {
    let derived_defs = [
        (
            "m_mode_ecall_overhead",
            "base/get_spec_version",
            "baseline/s_trap",
        ),
        (
            "cold_icache_penalty",
            "base/get_spec_version.cold",
            "base/get_spec_version",
        ),
        (
            "timer_irq_minus_set_timer",
            "time/irq.sbi",
            "time/set_timer",
        ),
        ("sbi_vs_sstc_timer_delta", "time/irq.sbi", "time/irq.sstc"),
        ("probe_miss_vs_hit", "base/probe.miss", "base/probe.hit"),
    ];

    let mut headers = vec![String::from("Derived Metric"), String::from("Formula")];
    for cap in captures {
        headers.push(cap.label.clone());
    }

    let mut rows = Vec::new();
    for (name, lhs_id, rhs_id) in derived_defs {
        if let Some(flt) = filter
            && !name.contains(flt)
            && !lhs_id.contains(flt)
            && !rhs_id.contains(flt)
        {
            continue;
        }
        let mut row = vec![String::from(name), format!("{lhs_id} - {rhs_id}")];
        let mut any_present = false;
        for cap in captures {
            let lhs = find_bench_median(cap, lhs_id, 1, metric);
            let rhs = find_bench_median(cap, rhs_id, 1, metric);
            match (lhs, rhs) {
                (Some(a), Some(b)) => {
                    any_present = true;
                    let diff = i128::from(a) - i128::from(b);
                    if diff < 0 {
                        row.push(format!("-{}", format_scaled((-diff) as u64)));
                    } else {
                        row.push(format_scaled(diff as u64));
                    }
                }
                _ => row.push(String::from("-")),
            }
        }
        if any_present {
            rows.push(row);
        }
    }

    if rows.is_empty() {
        return false;
    }
    write_section_heading("Derived Cost Decomposition", format, out);
    write_table(&headers, &rows, format, out);
    out.push('\n');
    true
}

fn find_bench_median(
    cap: &ParsedCapture,
    id: &str,
    parallel: usize,
    metric: Metric,
) -> Option<u64> {
    let frame = cap
        .benches
        .iter()
        .find(|b| b.id == id && b.parallel == parallel && b.status == BenchStatusTag::Pass)?;
    pick_metric(frame, metric).map(|m| m.median_x100)
}

fn pick_metric(frame: &BenchFrame, metric: Metric) -> Option<MetricView<'_>> {
    match metric {
        Metric::Cycles => frame.cycles.as_ref().map(|c| MetricView {
            median_x100: c.median_x100,
            iqr_x100: c.iqr_x100,
            is_noisy: c.is_noisy,
            net_samples_x100: &c.net_samples_x100,
        }),
        Metric::Instret => frame.instret.as_ref().map(|c| MetricView {
            median_x100: c.median_x100,
            iqr_x100: c.iqr_x100,
            is_noisy: c.is_noisy,
            net_samples_x100: &c.net_samples_x100,
        }),
        Metric::Ns => frame.ns.as_ref().map(|n| MetricView {
            median_x100: n.median_x100,
            iqr_x100: n.iqr_x100,
            is_noisy: n.is_noisy,
            net_samples_x100: &n.net_samples_x100,
        }),
    }
}

fn format_bench_cell(frame: &BenchFrame, metric: Metric, baseline: Option<&BenchFrame>) -> String {
    match frame.status {
        BenchStatusTag::Skipped => format!(
            "SKIP({})",
            frame.skip_reason.map_or("unknown", |r| r.as_str())
        ),
        BenchStatusTag::DelegatedToS => String::from("DELEG_S"),
        BenchStatusTag::Fail => format!(
            "FAIL({})",
            frame.fail_reason.as_deref().unwrap_or("unknown")
        ),
        BenchStatusTag::HwNative | BenchStatusTag::Pass => {
            let prefix = if frame.status == BenchStatusTag::HwNative {
                "HW_NAT "
            } else {
                ""
            };
            let Some(cand_stats) = pick_metric(frame, metric) else {
                return format!("{prefix}PASS(n/a)");
            };
            let noisy = if cand_stats.is_noisy { "!" } else { "" };
            let mut s = format!(
                "{prefix}{} [{}]{noisy}",
                format_scaled(cand_stats.median_x100),
                format_scaled(cand_stats.iqr_x100),
            );
            if let Some(base) = baseline
                && base.status == frame.status
                && let Some(base_stats) = pick_metric(base, metric)
            {
                let cmp = compare_samples(
                    base_stats.median_x100,
                    cand_stats.median_x100,
                    base_stats.net_samples_x100,
                    cand_stats.net_samples_x100,
                );
                let ratio_str = match cmp.ratio {
                    Some(r) => format!("{r:.2}x"),
                    None => String::from("n/a"),
                };
                let verdict_str = match cmp.verdict {
                    DiffVerdict::Identical => String::from("eq"),
                    DiffVerdict::InsufficientSamples => String::from("n<5"),
                    DiffVerdict::Faster => format!("faster {}", format_p_value(cmp.p_value)),
                    DiffVerdict::Slower => format!("slower {}", format_p_value(cmp.p_value)),
                    DiffVerdict::DistributionDiff => {
                        format!("dist-diff {}", format_p_value(cmp.p_value))
                    }
                    DiffVerdict::NoSignificantDiff => {
                        format!("ns {}", format_p_value(cmp.p_value))
                    }
                };
                s.push_str(&format!(" ({ratio_str}; {verdict_str})"));
            }
            s
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

    match format {
        OutputFormat::Markdown => {
            out.push('|');
            for (i, h) in headers.iter().enumerate() {
                out.push_str(&format!(" {:<w$} |", h, w = widths[i]));
            }
            out.push('\n');
            out.push('|');
            for w in &widths {
                out.push_str(&format!(" {} |", "-".repeat(*w)));
            }
            out.push('\n');
            for row in rows {
                out.push('|');
                for (i, cell) in row.iter().enumerate() {
                    out.push_str(&format!(" {:<w$} |", cell, w = widths[i]));
                }
                out.push('\n');
            }
        }
        OutputFormat::Table => {
            for (i, h) in headers.iter().enumerate() {
                out.push_str(&format!("{:<w$}  ", h, w = widths[i]));
            }
            out.push('\n');
            for w in &widths {
                out.push_str(&format!("{}  ", "-".repeat(*w)));
            }
            out.push('\n');
            for row in rows {
                for (i, cell) in row.iter().enumerate() {
                    out.push_str(&format!("{:<w$}  ", cell, w = widths[i]));
                }
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mbench_core::{
        protocol::{
            write_bench_line, write_cal_line, write_check_line, write_end_line, write_meta_line,
        },
        record::{
            BenchGroup, BenchResult, BenchStatus, CalibrationRecord, CheckIssues, CheckResult,
            CheckStatus, CounterAvailability, EndRecord, MeasureMode, MetaRecord, SbiCapMask,
        },
        stats,
    };

    use super::*;

    fn sample_capture_text(samples: &[u64; 5], s_trap_samples: &[u64; 5]) -> String {
        let mut raw = String::from("OpenSBI v1.5 boot log noise...\n");
        let meta = MetaRecord {
            sbi_spec_version: 0x0300_0000,
            impl_id: 1,
            impl_version: 0x10500,
            mvendorid: 0,
            marchid: 5,
            mimpid: 0,
            extensions: SbiCapMask::BASE | SbiCapMask::TIME,
            hart_count: 4,
            boot_hart_id: 0,
            timebase_hz: 10_000_000,
            counters: CounterAvailability {
                has_cycle: true,
                has_instret: true,
                has_time: true,
                is_rdtime_emulated: false,
                is_pmu_gated: false,
            },
            has_sstc: true,
            has_h_ext: false,
            boot_ticks: 555,
            reserved_mem_bytes: 65536,
            console_backend: "dbcn",
            pmu_counter_count: 16,
            load_addr: 0x8020_0000,
        };
        write_meta_line(&meta, &mut raw).unwrap();
        write_cal_line(&CalibrationRecord::default(), &mut raw).unwrap();
        write_check_line(
            &CheckResult {
                id: "conformance/base",
                checks: 7,
                checks_total: 7,
                checks_failed: 0,
                status: CheckStatus::Pass,
                issues: CheckIssues::new(),
                quirks: 0,
                note: None,
            },
            &mut raw,
        )
        .unwrap();

        let mk_bench = |id: &'static str, vals: &[u64; 5]| {
            let cyc = stats::compute_stats(vals, 1, 0, 0);
            BenchResult {
                id,
                group: BenchGroup::Base,
                mode: Some(MeasureMode::Batched),
                parallel: 1,
                unit: "call",
                iters_per_trial: 100,
                trials: 5,
                status: BenchStatus::Pass,
                cycles: Some(cyc),
                instret: None,
                ticks: None,
                ns: None,
                throughput_ops_per_sec: None,
                note: None,
            }
        };
        write_bench_line(&mk_bench("baseline/s_trap", s_trap_samples), &mut raw).unwrap();
        write_bench_line(&mk_bench("base/get_spec_version", samples), &mut raw).unwrap();
        write_end_line(
            &EndRecord {
                checks_total: 1,
                checks_passed: 1,
                benches_total: 2,
                benches_passed: 2,
                ..EndRecord::default()
            },
            &mut raw,
        )
        .unwrap();
        raw
    }

    #[test]
    fn renders_conformance_mann_whitney_zero_base_and_panic_captures() {
        let raw_a = sample_capture_text(&[118, 119, 120, 121, 122], &[48, 49, 50, 51, 52]);
        let raw_b = sample_capture_text(&[58, 59, 60, 61, 62], &[0, 0, 0, 0, 0]);
        let cap_a = parse_capture("fw-a", &raw_a).unwrap();
        let cap_b = parse_capture("fw-b", &raw_b).unwrap();

        let table = render_comparison(
            &[cap_a.clone(), cap_b.clone()],
            Metric::Cycles,
            OutputFormat::Table,
            None,
        );
        assert!(table.contains("PASS (7 checks)"));
        assert!(table.contains("base/get_spec_version"));
        assert!(table.contains("120.00 [2.00]"));
        assert!(table.contains("60.00 [2.00] (0.50x; faster p=0.008)"));
        assert!(table.contains("m_mode_ecall_overhead"));
        assert!(table.contains("70.00"));

        let zero_cmp = compare_samples(0, 5000, &[0, 0, 0, 0, 0], &[4800, 4900, 5000, 5100, 5200]);
        assert_eq!(zero_cmp.verdict, DiffVerdict::Slower);
        assert_eq!(zero_cmp.ratio, None);
        let expected_zero_tag = format!("(n/a; slower {})", format_p_value(zero_cmp.p_value));

        let md = render_comparison(
            &[cap_b, cap_a],
            Metric::Cycles,
            OutputFormat::Markdown,
            None,
        );
        assert!(md.contains("| baseline/s_trap"));
        assert!(md.contains(&expected_zero_tag));

        let panic_only = parse_capture(
            "panic-fw",
            "@@MBENCH:PANIC {\"reason\":\"unexpected trap\",\"scause\":2}\n",
        )
        .unwrap();
        let panic_report =
            render_comparison(&[panic_only], Metric::Cycles, OutputFormat::Table, None);
        assert!(panic_report.contains("no META frame"));
        assert!(panic_report.contains("panic=unexpected trap"));
    }

    #[test]
    fn renders_markdown_extension_matrix_aligns_long_labels_and_filters_derived() {
        let mut long_raw = String::from(
            "# MBENCH_ENV {\"clock_regime\":\"qemu-icount\",\"label\":\"opensbi-smp1-icount\",\"smp\":1,\"icount\":true,\"max_harts\":1}\n",
        );
        long_raw.push_str(&sample_capture_text(
            &[118, 119, 120, 121, 122],
            &[48, 49, 50, 51, 52],
        ));
        let mut cap_long = parse_capture("fallback", &long_raw).unwrap();
        if let Some(end) = &mut cap_long.end {
            end.benches_hw_native = 2;
        }

        let md = render_comparison(
            std::slice::from_ref(&cap_long),
            Metric::Cycles,
            OutputFormat::Markdown,
            None,
        );
        assert!(md.contains("## Firmware & Platform Summary"));
        assert!(md.contains("## SBI v3.0 Extension Matrix"));
        assert!(md.contains("| Firmware            | base | time |"));
        assert!(md.contains("| opensbi-smp1-icount | Y    | Y    |"));
        assert!(md.contains("max_harts=1"));
        assert!(md.contains("hw_nat=2"));

        let table = render_comparison(
            std::slice::from_ref(&cap_long),
            Metric::Cycles,
            OutputFormat::Table,
            None,
        );
        let fw_line = table
            .lines()
            .find(|l| l.starts_with("Firmware "))
            .expect("table header");
        let val_line = table
            .lines()
            .find(|l| l.starts_with("opensbi-smp1-icount "))
            .expect("table row");
        assert_eq!(fw_line.find("base"), val_line.find("Y"));

        let filtered_base = render_comparison(
            std::slice::from_ref(&cap_long),
            Metric::Cycles,
            OutputFormat::Table,
            Some("base/get_spec_version"),
        );
        assert!(filtered_base.contains("m_mode_ecall_overhead"));
        assert!(!filtered_base.contains("cold_icache_penalty\n"));

        let filtered_empty = render_comparison(
            &[cap_long],
            Metric::Cycles,
            OutputFormat::Table,
            Some("__no_match__"),
        );
        assert!(!filtered_empty.contains("Functional Conformance Summary"));
        assert!(!filtered_empty.contains("Benchmark Comparison"));
        assert!(!filtered_empty.contains("Derived Cost Decomposition"));
        assert!(filtered_empty.contains("No checks or benchmarks matched filter '__no_match__'."));
    }
}
