use super::{
    AttemptRecord, BenchStatusTag, CheckIssueClass, CheckStatusTag, PanicFrame, RawAttemptStart,
    ShutdownStatus, WireFrame, parse_capture, parse_wire_line,
};
use crate::{
    config::{ClockRegime, Profile, RunMode},
    protocol,
    record::{
        BenchGroup, BenchResult, BenchStatus, CalibrationRecord, CheckResult, CheckStatus,
        CounterAvailability, EndRecord, FailReason, MeasureMode, MetaRecord, SbiCapMask,
        SkipReason, StartKind,
    },
    stats,
};

#[test]
fn roundtrips_all_wire_frames_and_rejects_inconsistent_records() {
    let mut raw = String::from(
        "# MBENCH_ENV {\"clock_regime\":\"qemu-icount\",\"label\":\"fw-a\",\"smp\":1,\"icount\":true,\"mode\":\"all\"}\n",
    );
    raw.push_str("OpenSBI v1.5 noisy serial line...\n");

    let meta = MetaRecord {
        sbi_spec_version: 0x0300_0000,
        impl_id: 1,
        impl_version: 0x10500,
        mvendorid: 0,
        marchid: 5,
        mimpid: 0,
        extensions: SbiCapMask::BASE | SbiCapMask::TIME,
        hart_count: 1,
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
        config: crate::config::RunConfig {
            mode: RunMode::Bench,
            profile: Profile::Quick,
            filter: Some("base/"),
            allow_io: true,
            ..Default::default()
        },
    };
    protocol::write_meta_line(&meta, &mut raw).unwrap();
    protocol::write_cal_line(&CalibrationRecord::default(), &mut raw).unwrap();
    protocol::write_start_line(StartKind::Check, "conformance/base", 1, &mut raw).unwrap();
    use crate::record::{CheckIssue, CheckIssues, IssueClass};
    protocol::write_check_line(
        &CheckResult {
            id: "conformance/base",
            checks: 11,
            checks_total: 11,
            checks_failed: 0,
            status: CheckStatus::Pass,
            issues: CheckIssues::new(),
            quirks: 0,
            note: None,
        },
        &mut raw,
    )
    .unwrap();

    let cyc = stats::compute_stats(&[100, 102, 101, 99, 100], 1, 0, 0);
    protocol::write_start_line(StartKind::Bench, "base/get_spec_version", 1, &mut raw).unwrap();
    protocol::write_bench_line(
        &BenchResult {
            id: "base/get_spec_version",
            group: BenchGroup::Base,
            mode: Some(MeasureMode::Batched),
            parallel: 1,
            unit: "call",
            iters_per_trial: 64,
            trials: 5,
            status: BenchStatus::Pass,
            cycles: Some(cyc),
            instret: None,
            ticks: None,
            ns: None,
            throughput_ops_per_sec: None,
            note: None,
        },
        &mut raw,
    )
    .unwrap();
    protocol::write_end_line(
        &EndRecord {
            checks_total: 1,
            checks_passed: 1,
            benches_total: 1,
            benches_passed: 1,
            ..EndRecord::default()
        },
        &mut raw,
    )
    .unwrap();

    let cap = parse_capture("default", &raw).unwrap();
    assert_eq!(cap.label, "fw-a");
    assert_eq!(cap.clock_regime, ClockRegime::QemuIcount);
    assert_eq!(cap.checks.len(), 1);
    assert_eq!(cap.checks[0].checks, 11);
    assert_eq!(cap.cals.len(), 1);
    assert_eq!(cap.benches.len(), 1);
    assert_eq!(cap.benches[0].cal_index, Some(0));

    let mut two_cal_raw = raw.clone();
    // Second boot starts with a new META frame, resetting calibration attribution until a new CAL arrives.
    protocol::write_meta_line(&meta, &mut two_cal_raw).unwrap();
    protocol::write_bench_line(
        &BenchResult {
            id: "base/probe.hit",
            group: BenchGroup::Base,
            mode: Some(MeasureMode::Batched),
            parallel: 1,
            unit: "call",
            iters_per_trial: 64,
            trials: 5,
            status: BenchStatus::Pass,
            cycles: Some(cyc),
            instret: None,
            ticks: None,
            ns: None,
            throughput_ops_per_sec: None,
            note: None,
        },
        &mut two_cal_raw,
    )
    .unwrap();
    protocol::write_cal_line(
        &CalibrationRecord {
            enough_iters: 999,
            ..CalibrationRecord::default()
        },
        &mut two_cal_raw,
    )
    .unwrap();
    protocol::write_bench_line(
        &BenchResult {
            id: "base/get_impl_id",
            group: BenchGroup::Base,
            mode: Some(MeasureMode::Batched),
            parallel: 1,
            unit: "call",
            iters_per_trial: 64,
            trials: 5,
            status: BenchStatus::Pass,
            cycles: Some(cyc),
            instret: None,
            ticks: None,
            ns: None,
            throughput_ops_per_sec: None,
            note: None,
        },
        &mut two_cal_raw,
    )
    .unwrap();
    let multi_cal_cap = parse_capture("default", &two_cal_raw).unwrap();
    assert_eq!(multi_cal_cap.cals.len(), 2);
    assert_eq!(multi_cal_cap.benches[0].cal_index, Some(0));
    assert_eq!(multi_cal_cap.benches[1].cal_index, None);
    assert_eq!(multi_cal_cap.benches[2].cal_index, Some(1));
    let cyc_frame = cap.benches[0].cycles.as_ref().unwrap();
    assert_eq!(cyc_frame.raw_batch_totals, vec![100, 102, 101, 99, 100]);
    assert_eq!(
        cyc_frame.net_samples_x100,
        vec![10_000, 10_200, 10_100, 9_900, 10_000]
    );
    assert_eq!(cap.end.unwrap().benches_passed, 1);

    // Nested @@MBENCH:META inside a PANIC payload must parse strictly as PANIC.
    let mut nested_panic = String::new();
    protocol::write_panic_line(
        "boom while parsing @@MBENCH:META {bad}\nline2",
        &mut nested_panic,
    )
    .unwrap();
    let panic_only_cap = parse_capture("boot-fail", &nested_panic).unwrap();
    assert_eq!(panic_only_cap.clock_regime, ClockRegime::Unknown);
    assert!(panic_only_cap.panic.is_some());
    assert!(panic_only_cap.meta.is_none());

    // Reject semantic invariant violations.
    assert!(parse_wire_line(
        "@@MBENCH:CHECK {\"id\":\"x\",\"checks\":1,\"status\":\"PASS\",\"fail_reason\":\"oops\"}"
    )
    .is_err());
    assert!(parse_wire_line(
        "@@MBENCH:BENCH {\"id\":\"x\",\"group\":\"base\",\"parallel\":1,\"unit\":\"op\",\
         \"iters_per_trial\":0,\"trials\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"filtered_out\",\
         \"throughput_ops_per_sec\":42}"
    )
    .is_err());

    let mut trap_buf = String::new();
    protocol::write_unhandled_trap_panic(2, 0, 0x8020_1000, &mut trap_buf).unwrap();
    let trap_frame = parse_wire_line(trap_buf.trim()).unwrap().unwrap();
    assert_eq!(
        trap_frame,
        WireFrame::Panic(PanicFrame {
            message: None,
            reason: Some(String::from("unhandled_trap")),
            scause: Some(2),
            stval: Some(0),
            sepc: Some(0x8020_1000),
        })
    );

    let mut fail_chk = String::new();
    let mut fail_issues = CheckIssues::new();
    fail_issues.push(CheckIssue {
        label: "dbtr_flags",
        class: IssueClass::SpecViolationWithQuirk("opensbi-v1.8-dbtr-ignores-flags"),
        reason: FailReason::AssertionFailed("dbtr_nonzero_flags_rejected"),
    });
    fail_issues.push(CheckIssue {
        label: "dbtr_unaligned",
        class: IssueClass::SpecViolation,
        reason: FailReason::UnexpectedSbiError(-5),
    });
    protocol::write_check_line(
        &CheckResult {
            id: "conformance/dbtr",
            checks: 3,
            checks_total: 5,
            checks_failed: 2,
            status: CheckStatus::Failed(FailReason::AssertionFailed("dbtr_nonzero_flags_rejected")),
            issues: fail_issues,
            quirks: 1,
            note: Some("partial_pass"),
        },
        &mut fail_chk,
    )
    .unwrap();
    match parse_wire_line(fail_chk.trim()).unwrap().unwrap() {
        WireFrame::Check(c) => {
            assert_eq!(c.checks, 3);
            assert_eq!(c.checks_total, 5);
            assert_eq!(c.checks_failed, 2);
            assert_eq!(c.quirks, 1);
            assert_eq!(c.issues.len(), 2);
            assert_eq!(c.issues[0].class, CheckIssueClass::SpecViolationWithQuirk);
            assert_eq!(
                c.issues[0].quirk.as_deref(),
                Some("opensbi-v1.8-dbtr-ignores-flags")
            );
            assert_eq!(
                c.fail_reason.as_deref(),
                Some("assert:dbtr_nonzero_flags_rejected")
            );
            assert_eq!(c.note.as_deref(), Some("partial_pass"));
        }
        other => panic!("unexpected frame: {other:?}"),
    }

    // PASS frame with PermittedBehavior observation must validate cleanly.
    let mut obs_chk = String::new();
    let mut obs_issues = CheckIssues::new();
    obs_issues.push(CheckIssue {
        label: "mpxy_no_channels",
        class: IssueClass::PermittedBehavior,
        reason: FailReason::UnexpectedSbiError(-1),
    });
    protocol::write_check_line(
        &CheckResult {
            id: "conformance/mpxy",
            checks: 4,
            checks_total: 4,
            checks_failed: 0,
            status: CheckStatus::Pass,
            issues: obs_issues,
            quirks: 0,
            note: None,
        },
        &mut obs_chk,
    )
    .unwrap();
    match parse_wire_line(obs_chk.trim()).unwrap().unwrap() {
        WireFrame::Check(c) => {
            assert_eq!(c.status, CheckStatusTag::Pass);
            assert_eq!(c.issues.len(), 1);
            assert_eq!(c.issues[0].class, CheckIssueClass::PermittedBehavior);
        }
        other => panic!("unexpected frame: {other:?}"),
    }

    // PASS frame carrying a SpecViolation issue must be rejected.
    assert!(parse_wire_line(
        "@@MBENCH:CHECK {\"id\":\"x\",\"checks\":1,\"checks_total\":1,\"checks_failed\":0,\
         \"status\":\"PASS\",\"issues\":[{\"label\":\"bad\",\"class\":\"spec_violation\",\"reason\":\"timeout\"}]}"
    )
    .is_err());

    // PASS and SKIPPED frames with nonzero quirks must be rejected.
    assert!(
        parse_wire_line(
            "@@MBENCH:CHECK {\"id\":\"x\",\"checks\":1,\"checks_total\":1,\"status\":\"PASS\",\"quirks\":1}"
        )
        .is_err()
    );
    assert!(parse_wire_line(
        "@@MBENCH:CHECK {\"id\":\"x\",\"checks\":0,\"checks_total\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"filtered_out\",\"quirks\":1}"
    )
    .is_err());

    // EnvLine with max_harts round-trips while older captures omit it cleanly.
    let env_with_mh = parse_capture(
        "mh",
        "# MBENCH_ENV {\"clock_regime\":\"qemu-tcg-non-cycle-accurate\",\"label\":\"mh\",\"smp\":4,\"max_harts\":2}\n\
         @@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":1,\"checks_total\":1,\"status\":\"PASS\"}\n",
    )
    .unwrap();
    assert_eq!(env_with_mh.max_harts, Some(2));
    assert_eq!(cap.max_harts, None);

    // ResumedPast preserves unmatched records but never overwrites an existing prior result for the same key.
    let mut resumed_raw = String::from(
        "@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":5,\"checks_total\":5,\"status\":\"PASS\"}\n\
         @@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":0,\"checks_total\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}\n\
         @@MBENCH:CHECK {\"id\":\"conformance/time\",\"checks\":0,\"checks_total\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}\n",
    );
    let resumed_bench = "@@MBENCH:BENCH {\"id\":\"base/get_spec_version\",\"group\":\"base\",\"mode\":\"batched\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":16,\"trials\":5,\"status\":\"PASS\"}\n\
         @@MBENCH:BENCH {\"id\":\"base/get_spec_version\",\"group\":\"base\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}\n\
         @@MBENCH:BENCH {\"id\":\"base/probe.hit\",\"group\":\"base\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}\n";
    resumed_raw.push_str(resumed_bench);
    let resumed_cap = parse_capture("resumed", &resumed_raw).unwrap();
    assert_eq!(resumed_cap.checks.len(), 2);
    assert_eq!(resumed_cap.checks[0].status, CheckStatusTag::Pass);
    assert_eq!(
        resumed_cap.checks[1].skip_reason,
        Some(SkipReason::ResumedPast)
    );
    assert_eq!(resumed_cap.benches.len(), 2);
    assert_eq!(resumed_cap.benches[0].status, BenchStatusTag::Pass);
    assert_eq!(
        resumed_cap.benches[1].skip_reason,
        Some(SkipReason::ResumedPast)
    );
    let parsed_cfg = cap.meta.as_ref().and_then(|m| m.config.as_ref()).unwrap();
    assert_eq!(parsed_cfg.mode, RunMode::Bench);
    assert_eq!(parsed_cfg.profile, Profile::Quick);
    assert_eq!(parsed_cfg.filter.as_deref(), Some("base/"));
    assert!(parsed_cfg.allow_io);

    let raw_hdr = parse_wire_line(
        "# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"conformance/time\"}",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        raw_hdr,
        WireFrame::RawAttemptStart(RawAttemptStart {
            attempt: 1,
            resume_after: Some(String::from("conformance/time")),
        })
    );
    let inter_att = parse_wire_line(
        "# MBENCH_ATTEMPT {\"attempt\":0,\"saw_end\":false,\"shutdown\":{\"kind\":\"interrupted\"}}",
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        inter_att,
        WireFrame::Attempt(AttemptRecord {
            shutdown: ShutdownStatus::Interrupted,
            ..
        })
    ));

    // Unclosed START from an earlier attempt must become a synthetic FAIL in parse_capture
    // rather than letting ResumedPast in the following attempt downgrade it to SKIPPED.
    let mut crashed_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
    crashed_raw.push_str(
        "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":1,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}\n",
    );
    crashed_raw
        .push_str("@@MBENCH:START {\"kind\":\"bench\",\"id\":\"baseline/loop\",\"parallel\":1}\n");
    crashed_raw.push_str(
        "# MBENCH_ATTEMPT {\"attempt\":0,\"saw_end\":false,\"shutdown\":{\"kind\":\"signaled\"}}\n",
    );
    crashed_raw
        .push_str("# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/loop\"}\n");
    crashed_raw.push_str(
        "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":1,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}\n",
    );
    crashed_raw.push_str(
        "@@MBENCH:BENCH {\"id\":\"baseline/loop\",\"group\":\"baseline\",\"parallel\":1,\"unit\":\"op\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}\n",
    );
    protocol::write_end_line(
        &EndRecord {
            benches_total: 1,
            benches_skipped: 1,
            ..EndRecord::default()
        },
        &mut crashed_raw,
    )
    .unwrap();
    crashed_raw.push_str(
        "# MBENCH_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/loop\",\"saw_end\":true,\"shutdown\":{\"kind\":\"clean_exit\"}}\n",
    );
    let crashed_cap = parse_capture("crash-raw", &crashed_raw).unwrap();
    assert_eq!(crashed_cap.attempts.len(), 2);
    assert_eq!(crashed_cap.benches.len(), 1);
    assert_eq!(crashed_cap.benches[0].id, "baseline/loop");
    assert_eq!(crashed_cap.benches[0].status, BenchStatusTag::Fail);
    assert_eq!(crashed_cap.benches[0].fail_reason.as_deref(), Some("crash"));
    assert!(crashed_cap.benches[0].synthetic);
}
