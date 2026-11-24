//! Golden rendering tests for comparison output and filter behavior.

use mbench_core::{
    protocol::{
        write_bench_line, write_cal_line, write_check_line, write_end_line, write_meta_line,
    },
    record::{
        BenchGroup, BenchResult, BenchStatus, CalibrationRecord, CheckIssues, CheckResult,
        CheckStatus, CounterAvailability, EndRecord, MeasureMode, MetaRecord, SbiCapMask,
    },
    stats,
    stats::{DiffVerdict, compare_samples},
    wire::parse_capture,
};

use crate::compare::{Metric, OutputFormat, format_p_value, render_comparison};

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
        config: mbench_core::config::RunConfig::default(),
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
    let panic_report = render_comparison(&[panic_only], Metric::Cycles, OutputFormat::Table, None);
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
