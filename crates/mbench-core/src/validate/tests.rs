use super::{CaptureFormat, audit_capture};
use crate::{
    config::RunConfig,
    protocol,
    record::{
        BenchGroup, BenchResult, BenchStatus, CalibrationRecord, CheckIssues, CheckResult,
        CheckStatus, CounterAvailability, EndRecord, FailReason, MetaRecord, SbiCapMask,
        SbiExtensionId, SkipReason, StartKind,
    },
    stats,
    wire::{AttemptRecord, BenchStatusTag, ShutdownStatus},
};

fn sample_meta(harts: usize, extensions: SbiCapMask) -> String {
    let mut out = String::new();
    let meta = MetaRecord {
        sbi_spec_version: 0x0300_0000,
        impl_id: 4,
        impl_version: 1,
        mvendorid: 0,
        marchid: 0,
        mimpid: 0,
        extensions,
        hart_count: harts,
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
        has_h_ext: true,
        boot_ticks: 100,
        reserved_mem_bytes: 0,
        console_backend: "dbcn",
        pmu_counter_count: 16,
        load_addr: 0x8020_0000,
        config: RunConfig::default(),
    };
    protocol::write_meta_line(&meta, &mut out).unwrap();
    out
}

fn check_line(id: &str, status: CheckStatus) -> String {
    let mut out = String::new();
    if !matches!(status, CheckStatus::Skipped(_)) {
        protocol::write_start_line(StartKind::Check, id, 1, &mut out).unwrap();
    }
    let failed = matches!(status, CheckStatus::Failed(_)) as u64;
    protocol::write_check_line(
        &CheckResult {
            id,
            checks: if status == CheckStatus::Pass { 5 } else { 0 },
            checks_total: 5,
            checks_failed: failed,
            status,
            issues: CheckIssues::new(),
            quirks: 0,
            note: None,
        },
        &mut out,
    )
    .unwrap();
    out
}

fn bench_line(id: &str, group: BenchGroup, parallel: usize, status: BenchStatus) -> String {
    let mut out = String::new();
    if !matches!(status, BenchStatus::Skipped(_)) {
        protocol::write_start_line(StartKind::Bench, id, parallel, &mut out).unwrap();
    }
    let cyc = (status == BenchStatus::Pass)
        .then(|| stats::compute_stats(&[100, 101, 99, 100, 102], 1, 0, 0));
    protocol::write_bench_line(
        &BenchResult {
            id,
            group,
            mode: (status == BenchStatus::Pass).then_some(crate::record::MeasureMode::Batched),
            parallel,
            unit: "call",
            iters_per_trial: if status == BenchStatus::Pass { 16 } else { 0 },
            trials: match status {
                BenchStatus::Pass => 5,
                BenchStatus::HwNative => 1,
                _ => 0,
            },
            status,
            cycles: cyc,
            instret: None,
            ticks: None,
            ns: None,
            throughput_ops_per_sec: None,
            note: None,
        },
        &mut out,
    )
    .unwrap();
    out
}

fn end_line(end: EndRecord) -> String {
    let mut out = String::new();
    protocol::write_end_line(&end, &mut out).unwrap();
    out
}

#[test]
fn audits_raw_captures_and_retains_valid_facts_on_parse_errors() {
    let mut cal = String::new();
    protocol::write_cal_line(&CalibrationRecord::default(), &mut cal).unwrap();

    let mut ok_log = sample_meta(4, SbiCapMask::BASE | SbiCapMask::HSM);
    ok_log.push_str(&cal);
    ok_log.push_str(&check_line("conformance/base", CheckStatus::Pass));
    ok_log.push_str(&check_line(
        "conformance/time",
        CheckStatus::Skipped(SkipReason::FilteredOut),
    ));
    ok_log.push_str(&check_line(
        "conformance/rfnc",
        CheckStatus::Failed(FailReason::UnexpectedSbiError(-2)),
    ));
    ok_log.push_str(&bench_line(
        "base/get_spec_version",
        BenchGroup::Base,
        1,
        BenchStatus::Pass,
    ));
    ok_log.push_str(&bench_line(
        "rfnc/sfence_vma.all",
        BenchGroup::Rfnc,
        4,
        BenchStatus::Failed(FailReason::Timeout),
    ));
    ok_log.push_str(&end_line(EndRecord {
        checks_total: 3,
        checks_passed: 1,
        checks_skipped: 1,
        checks_failed: 1,
        check_assertions_total: 15,
        check_assertions_passed: 5,
        check_assertions_failed: 1,
        benches_total: 2,
        benches_passed: 1,
        benches_skipped: 0,
        benches_hw_native: 0,
        benches_delegated: 0,
        benches_failed: 1,
        quarantine_warnings: 0,
    }));

    let report = audit_capture("ok", &ok_log);
    assert_eq!(report.format, CaptureFormat::RawSerial);
    assert!(report.protocol_valid, "{:?}", report.protocol_errors);
    assert!(report.completed);
    assert!(!report.recovered);
    assert_eq!(report.counts.checks_failed, 1);
    assert_eq!(report.counts.checks_skipped, 1);
    assert_eq!(report.counts.benches_failed, 1);
    assert_eq!(report.counts.benches_effective, 1);
    assert_eq!(
        report.meta.as_ref().unwrap().extensions,
        vec![SbiExtensionId::Base, SbiExtensionId::Hsm]
    );

    // One truncated frame mid-stream must NOT discard meta, surviving checks/benches, or end.
    let mut partial_corrupt = sample_meta(4, SbiCapMask::BASE);
    partial_corrupt.push_str(&check_line("conformance/base", CheckStatus::Pass));
    partial_corrupt
        .push_str("@@MBENCH:START {\"kind\":\"bench\",\"id\":\"base/probe\",\"parallel\":1}\n");
    partial_corrupt.push_str("@@MBENCH:BENCH {\"id\":\"base/probe\",\"group\":\"base\"\n");
    partial_corrupt.push_str(&end_line(EndRecord {
        checks_total: 1,
        checks_passed: 1,
        check_assertions_total: 5,
        check_assertions_passed: 5,
        ..EndRecord::default()
    }));
    let corrupt_report = audit_capture("corrupt-mid", &partial_corrupt);
    assert!(!corrupt_report.protocol_valid);
    assert!(corrupt_report.meta.is_some());
    assert_eq!(corrupt_report.checks.len(), 1);
    assert_eq!(corrupt_report.checks[0].id, "conformance/base");
    assert_eq!(corrupt_report.counts.checks_passed, 1);
    assert_eq!(corrupt_report.benches.len(), 1);
    assert_eq!(corrupt_report.benches[0].id, "base/probe");
    assert_eq!(corrupt_report.benches[0].status, BenchStatusTag::Fail);
    assert_eq!(
        corrupt_report.benches[0].fail_reason.as_deref(),
        Some("protocol_error")
    );
    assert!(corrupt_report.benches[0].synthetic);
    assert_eq!(corrupt_report.counts.benches_failed, 1);
    assert!(corrupt_report.end.is_some());
    assert!(corrupt_report.completed);

    // Non-SKIPPED CHECK or BENCH without matching START must fail protocol audit.
    let mut missing_start = sample_meta(1, SbiCapMask::BASE);
    missing_start.push_str("@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":1,\"checks_total\":1,\"status\":\"PASS\"}\n");
    missing_start.push_str("@@MBENCH:BENCH {\"id\":\"base/get_spec_version\",\"group\":\"base\",\"mode\":\"batched\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":16,\"trials\":5,\"status\":\"PASS\"}\n");
    missing_start.push_str(&end_line(EndRecord {
        checks_total: 1,
        checks_passed: 1,
        check_assertions_total: 1,
        check_assertions_passed: 1,
        benches_total: 1,
        benches_passed: 1,
        ..EndRecord::default()
    }));
    let missing_start_report = audit_capture("missing-start", &missing_start);
    assert!(!missing_start_report.protocol_valid);
    assert!(
        missing_start_report
            .protocol_errors
            .iter()
            .any(|e| e.contains("CHECK frame") && e.contains("without matching @@MBENCH:START"))
    );
    assert!(
        missing_start_report
            .protocol_errors
            .iter()
            .any(|e| e.contains("BENCH frame") && e.contains("without matching @@MBENCH:START"))
    );

    // Records emitted before META must fail ordering checks.
    let mut before_meta = String::new();
    before_meta.push_str(&check_line("conformance/base", CheckStatus::Pass));
    before_meta.push_str(&sample_meta(1, SbiCapMask::BASE));
    before_meta.push_str(&end_line(EndRecord {
        checks_total: 1,
        checks_passed: 1,
        check_assertions_total: 5,
        check_assertions_passed: 5,
        ..EndRecord::default()
    }));
    let before_meta_report = audit_capture("before-meta", &before_meta);
    assert!(!before_meta_report.protocol_valid);
    assert!(
        before_meta_report
            .protocol_errors
            .iter()
            .any(|e| e.contains("before @@MBENCH:META"))
    );
}

#[test]
fn audits_multi_attempt_raw_log_with_boundaries_and_retains_errors() {
    let mut multi_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
    multi_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    multi_raw.push_str(&bench_line(
        "baseline/loop",
        BenchGroup::Baseline,
        1,
        BenchStatus::Pass,
    ));
    multi_raw.push_str(
        "@@MBENCH:START {\"kind\":\"bench\",\"id\":\"baseline/counter\",\"parallel\":1}\n",
    );
    multi_raw.push_str("@@MBENCH:BENCH {\"id\":\"baseline/counter\",\"group\":\"baseline\"\n");

    multi_raw
        .push_str("# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/counter\"}\n");
    multi_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    multi_raw.push_str(&bench_line(
        "baseline/loop",
        BenchGroup::Baseline,
        1,
        BenchStatus::Skipped(SkipReason::ResumedPast),
    ));
    multi_raw.push_str(&bench_line(
        "baseline/counter",
        BenchGroup::Baseline,
        1,
        BenchStatus::Skipped(SkipReason::ResumedPast),
    ));
    multi_raw.push_str(&bench_line(
        "baseline/s_trap",
        BenchGroup::Baseline,
        1,
        BenchStatus::Pass,
    ));
    multi_raw.push_str(&end_line(EndRecord {
        benches_total: 3,
        benches_passed: 1,
        benches_skipped: 2,
        ..EndRecord::default()
    }));

    let rep = audit_capture("multi-raw", &multi_raw);
    assert_eq!(rep.format, CaptureFormat::RawSerial);
    assert!(!rep.protocol_valid);
    assert!(rep.completed);
    assert!(rep.recovered);
    assert!(rep.meta.is_some());
    assert_eq!(rep.counts.benches_passed, 2);
    assert_eq!(rep.counts.benches_failed, 1);
    assert_eq!(rep.counts.benches_skipped, 0);
    let counter = rep
        .benches
        .iter()
        .find(|b| b.id == "baseline/counter")
        .expect("baseline/counter retained");
    assert_eq!(counter.status, BenchStatusTag::Fail);
    assert_eq!(counter.fail_reason.as_deref(), Some("incomplete"));
    assert!(counter.synthetic);
    assert!(
        rep.protocol_errors
            .iter()
            .any(|e| e.starts_with("attempt 0:"))
    );
    assert!(
        !rep.protocol_errors
            .iter()
            .any(|e| e.contains("duplicate @@MBENCH:META")),
        "second attempt META must not be flagged as duplicate META: {:?}",
        rep.protocol_errors
    );

    // Clean crash recovery with # MBENCH_ATTEMPT footers must remain protocol_valid,
    // preserve attempt closure records, and retain the crashed case as synthetic FAIL("crash").
    let mut clean_crash_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
    clean_crash_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    clean_crash_raw
        .push_str("@@MBENCH:START {\"kind\":\"bench\",\"id\":\"baseline/loop\",\"parallel\":1}\n");
    let att0 = AttemptRecord {
        attempt: 0,
        resume_after: None,
        saw_end: false,
        shutdown: ShutdownStatus::Signaled,
        protocol_errors: vec![String::from("missing @@MBENCH:END frame")],
        synthesized_failures: vec![String::from("baseline/loop")],
    };
    clean_crash_raw.push_str(&format!(
        "# MBENCH_ATTEMPT {}\n",
        serde_json::to_string(&att0).unwrap()
    ));
    clean_crash_raw
        .push_str("# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/loop\"}\n");
    clean_crash_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    clean_crash_raw.push_str(&bench_line(
        "baseline/loop",
        BenchGroup::Baseline,
        1,
        BenchStatus::Skipped(SkipReason::ResumedPast),
    ));
    clean_crash_raw.push_str(&bench_line(
        "baseline/counter",
        BenchGroup::Baseline,
        1,
        BenchStatus::Pass,
    ));
    clean_crash_raw.push_str(&end_line(EndRecord {
        benches_total: 2,
        benches_passed: 1,
        benches_skipped: 1,
        ..EndRecord::default()
    }));
    let att1 = AttemptRecord {
        attempt: 1,
        resume_after: Some(String::from("baseline/loop")),
        saw_end: true,
        shutdown: ShutdownStatus::CleanExit,
        protocol_errors: Vec::new(),
        synthesized_failures: Vec::new(),
    };
    clean_crash_raw.push_str(&format!(
        "# MBENCH_ATTEMPT {}\n",
        serde_json::to_string(&att1).unwrap()
    ));

    let crash_rep = audit_capture("clean-crash-raw", &clean_crash_raw);
    assert_eq!(crash_rep.format, CaptureFormat::RawSerial);
    assert!(crash_rep.protocol_valid, "{:?}", crash_rep.protocol_errors);
    assert!(crash_rep.completed);
    assert!(crash_rep.recovered);
    assert_eq!(crash_rep.attempts.len(), 2);
    assert_eq!(crash_rep.attempts[0].shutdown, ShutdownStatus::Signaled);
    assert_eq!(crash_rep.attempts[1].shutdown, ShutdownStatus::CleanExit);
    assert_eq!(crash_rep.counts.benches_passed, 1);
    assert_eq!(crash_rep.counts.benches_failed, 1);
    assert_eq!(crash_rep.counts.benches_skipped, 0);
    let loop_res = crash_rep
        .benches
        .iter()
        .find(|b| b.id == "baseline/loop")
        .expect("baseline/loop retained");
    assert_eq!(loop_res.status, BenchStatusTag::Fail);
    assert_eq!(loop_res.fail_reason.as_deref(), Some("crash"));
    assert!(loop_res.synthetic);

    // If attempt 1 reaches END cleanly without its own # MBENCH_ATTEMPT footer,
    // completed must still be true rather than inheriting attempt 0's saw_end=false.
    let att1_footer_prefix = "# MBENCH_ATTEMPT {\"attempt\":1,";
    let missing_last_footer: String = clean_crash_raw
        .lines()
        .filter(|line| !line.starts_with(att1_footer_prefix))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let missing_footer_rep = audit_capture("missing-last-footer", &missing_last_footer);
    assert!(
        missing_footer_rep.protocol_valid,
        "{:?}",
        missing_footer_rep.protocol_errors
    );
    assert!(missing_footer_rep.completed);
    assert!(missing_footer_rep.recovered);
    assert_eq!(missing_footer_rep.attempts.len(), 1);
    assert!(!missing_footer_rep.attempts[0].saw_end);
    assert_eq!(missing_footer_rep.counts.benches_passed, 1);
    assert_eq!(missing_footer_rep.counts.benches_failed, 1);
    assert_eq!(missing_footer_rep.counts.benches_skipped, 0);

    // When the final attempt explicitly records saw_end=false, completed stays false.
    let mut att1_incomplete = att1;
    att1_incomplete.saw_end = false;
    let explicit_incomplete = format!(
        "{missing_last_footer}# MBENCH_ATTEMPT {}\n",
        serde_json::to_string(&att1_incomplete).unwrap()
    );
    let explicit_incomplete_rep = audit_capture("explicit-incomplete", &explicit_incomplete);
    assert!(!explicit_incomplete_rep.completed);

    // Two META frames inside the same attempt boundary still fail.
    let mut dup_meta_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
    dup_meta_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    dup_meta_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
    dup_meta_raw.push_str(&end_line(EndRecord::default()));
    let dup_rep = audit_capture("dup-meta", &dup_meta_raw);
    assert!(!dup_rep.protocol_valid);
    assert!(
        dup_rep
            .protocol_errors
            .iter()
            .any(|e| e.contains("duplicate @@MBENCH:META frame"))
    );

    let mut merged_recovered = String::from(
        "# MBENCH_ENV {\"clock_regime\":\"qemu-tcg-non-cycle-accurate\",\"label\":\"fw\",\"smp\":4}\n",
    );
    merged_recovered.push_str(&sample_meta(4, SbiCapMask::BASE));
    merged_recovered.push_str(
        "@@MBENCH:CHECK {\"id\":\"conformance/time\",\"checks\":0,\"checks_total\":1,\"checks_failed\":1,\"status\":\"FAIL\",\"fail_reason\":\"timeout\",\"synthetic\":true}\n",
    );
    let a0 = AttemptRecord {
        attempt: 0,
        resume_after: None,
        saw_end: false,
        shutdown: ShutdownStatus::Interrupted,
        protocol_errors: Vec::new(),
        synthesized_failures: vec![String::from("conformance/time")],
    };
    merged_recovered.push_str(&format!(
        "# MBENCH_ATTEMPT {}\n",
        serde_json::to_string(&a0).unwrap()
    ));
    let rec_report = audit_capture("interrupted", &merged_recovered);
    assert!(
        rec_report
            .protocol_errors
            .iter()
            .any(|e| e.contains("missing @@MBENCH:END"))
    );
    assert!(!rec_report.protocol_valid);
    assert!(!rec_report.completed);
    assert!(rec_report.recovered);
    assert!(rec_report.meta.is_some());
    assert_eq!(rec_report.checks.len(), 1);
    assert_eq!(rec_report.attempts[0].shutdown, ShutdownStatus::Interrupted);
}
