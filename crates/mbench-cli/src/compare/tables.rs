//! Conformance, benchmark, and derived-metric comparison tables.

use std::collections::{BTreeMap, BTreeSet};

use mbench_core::{
    stats::{DiffVerdict, compare_samples},
    wire::{BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, ParsedCapture},
};

use super::{
    Metric, OutputFormat, format_p_value, format_scaled, write_section_heading, write_table,
};

pub(super) fn render_conformance_table(
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

pub(super) fn render_benchmark_table(
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

#[derive(Clone, Copy)]
struct MetricView<'a> {
    median_x100: u64,
    iqr_x100: u64,
    is_noisy: bool,
    net_samples_x100: &'a [u64],
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

pub(super) fn render_derived_decomposition(
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
