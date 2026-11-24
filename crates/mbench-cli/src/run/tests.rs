//! Regression tests for validated run arguments, capture recovery, and output persistence.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use mbench_core::{
    config::{OrderMode, RunMode},
    protocol::write_cal_line,
    record::{CalibrationRecord, StartKind},
    validate::audit_raw_attempt,
    wire::{CheckStatusTag, EnvLine, ShutdownStatus, StartFrame, parse_capture},
};

use crate::{
    run::{
        CaptureState, append_unclosed_end_failures,
        attempt::AttemptTracker,
        config::{
            CliOrder, CliProfile, CliRunMode, RunArgs, build_bootargs, parse_seed_u64,
            resolve_effective_seed, validate_run_args,
        },
        finalize_merged_capture,
        output::{
            RawLogWriter, atomic_write, paths_refer_to_same_file, prepare_outputs,
            save_outputs_independently, validate_output_file_path,
        },
        synthesize_fail_frame,
    },
    runner::SessionExit,
};

static NEXT_DIR_ID: AtomicUsize = AtomicUsize::new(0);

const META_JSON: &str = r#"{"sbi_spec_version":50331648,"impl_id":1,"impl_version":1,"mvendorid":0,"marchid":0,"mimpid":0,"extensions":["base"],"extensions_mask":1,"hart_count":2,"boot_hart_id":0,"timebase_hz":10000000,"has_cycle":true,"has_instret":true,"has_time":true,"is_rdtime_emulated":false,"is_pmu_gated":false,"has_sstc":false,"has_h_ext":false,"boot_ticks":1,"reserved_mem_bytes":0,"console_backend":"dbcn","pmu_counter_count":0,"load_addr":2149580800}"#;
const END_JSON: &str = r#"{"checks_total":0,"checks_passed":0,"checks_skipped":0,"checks_failed":0,"check_assertions_total":0,"check_assertions_passed":0,"check_assertions_failed":0,"benches_total":0,"benches_passed":0,"benches_skipped":0,"benches_hw_native":0,"benches_delegated":0,"benches_failed":0,"quarantine_warnings":0}"#;

fn meta_line() -> String {
    format!("@@MBENCH:META {META_JSON}")
}

fn end_line() -> String {
    format!("@@MBENCH:END {END_JSON}")
}

fn start_frame(kind: StartKind, id: &str, parallel: usize) -> StartFrame {
    StartFrame {
        kind,
        id: String::from(id),
        parallel,
    }
}

struct TestWorkDir(PathBuf);

impl TestWorkDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/mbench-cli-unit-tests")
            .join(format!("{tag}-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TestWorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn base_test_args(out: Option<PathBuf>) -> RunArgs {
    RunArgs {
        bios: PathBuf::from("fw.bin"),
        name: Some(String::from("fw")),
        kernel: None,
        smp: 4,
        mode: CliRunMode::Check,
        profile: CliProfile::Quick,
        order: CliOrder::Fixed,
        seed: None,
        filter: None,
        icount: false,
        io: false,
        destructive: false,
        max_harts: None,
        timeout: 30,
        qemu_args: Vec::new(),
        qemu: String::from("qemu-system-riscv64"),
        out,
        raw_log: None,
    }
}

#[test]
fn builds_explicit_bootargs_synthesizes_synthetic_fails_and_merges_end() {
    let mut args = base_test_args(None);
    let default_bootargs = build_bootargs(&args, None, None);
    assert_eq!(
        default_bootargs,
        "mode=check profile=quick order=fixed seed= filter= io=0 destructive=0 max_harts=0 resume_after="
    );

    args.mode = CliRunMode::Bench;
    args.order = CliOrder::Shuffle;
    args.seed = Some(String::from("0xdeadbeef"));
    args.filter = Some(String::from("rfnc/"));
    args.io = true;
    args.destructive = true;
    args.max_harts = Some(2);
    assert_eq!(parse_seed_u64("0xdeadbeef").unwrap(), 0xdead_beef);
    assert_eq!(parse_seed_u64("42").unwrap(), 42);
    assert!(parse_seed_u64("not_a_seed").is_err());

    let seed = resolve_effective_seed(&args).unwrap();
    assert_eq!(seed, Some(0xdead_beef));
    let bootargs = build_bootargs(&args, seed, Some("rfnc/sfence_vma"));
    assert_eq!(
        bootargs,
        "mode=bench profile=quick order=shuffle seed=0xdeadbeef filter=rfnc/ io=1 destructive=1 max_harts=2 resume_after=rfnc/sfence_vma"
    );

    let check_line = synthesize_fail_frame(
        &start_frame(StartKind::Check, "conformance/base", 1),
        "timeout",
    )
    .unwrap();
    let sweep_p1 = "@@MBENCH:BENCH {\"id\":\"scale/base_ecall\",\"group\":\"scale\",\"mode\":\"parallel_sweep\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"FAIL\",\"fail_reason\":\"hardware_inconsistent\"}".to_string();
    let sweep_p2_fail = synthesize_fail_frame(
        &start_frame(StartKind::Bench, "scale/base_ecall", 2),
        "crash",
    )
    .unwrap();

    let mut cal0 = String::new();
    write_cal_line(&CalibrationRecord::default(), &mut cal0).unwrap();
    let mut cal1 = String::new();
    write_cal_line(
        &CalibrationRecord {
            enough_iters: 512,
            ..CalibrationRecord::default()
        },
        &mut cal1,
    )
    .unwrap();

    let env_hdr = serde_json::to_string(&EnvLine {
        clock_regime: mbench_core::config::ClockRegime::QemuTcgNonCycleAccurate,
        label: Some(String::from("fw")),
        smp: Some(4),
        icount: Some(false),
        mode: Some(RunMode::All),
        order: Some(OrderMode::Shuffle),
        seed: Some(0xdead_beef),
        max_harts: Some(2),
    })
    .unwrap();

    let mut state = CaptureState {
        frames: vec![
            format!("# MBENCH_ENV {env_hdr}"),
            meta_line(),
            cal0.trim().to_string(),
            check_line,
            sweep_p1,
            meta_line(),
            cal1.trim().to_string(),
            sweep_p2_fail,
        ],
        quarantine_warnings: 2,
    };
    let merged = finalize_merged_capture("fw", &mut state).unwrap();
    let cap = parse_capture("fw", &merged).unwrap();
    assert_eq!(cap.cals.len(), 2);
    assert_eq!(cap.checks.len(), 1);
    assert!(cap.checks[0].synthetic);
    assert_eq!(cap.benches.len(), 2);
    assert!(!cap.benches[0].synthetic);
    assert!(cap.benches[1].synthetic);
    assert_eq!(cap.benches[0].cal_index, Some(0));
    assert_eq!(cap.benches[1].cal_index, Some(1));
    let end = cap.end.unwrap();
    assert_eq!(end.checks_total, 1);
    assert_eq!(end.checks_failed, 1);
    assert_eq!(end.benches_total, 2);
    assert_eq!(end.benches_failed, 2);
    assert_eq!(end.quarantine_warnings, 2);
}

#[test]
fn preserves_unclosed_started_case_as_protocol_error_when_end_arrives() {
    let lines = [
        meta_line(),
        String::from(
            "@@MBENCH:START {\"kind\":\"check\",\"id\":\"conformance/base\",\"parallel\":1}",
        ),
        String::from("@@MBENCH:CHECK {\"id\":\"conformance/base\",INVALID_JSON}"),
        end_line(),
    ];
    let mut state = CaptureState {
        frames: Vec::new(),
        quarantine_warnings: 0,
    };
    let mut tracker = AttemptTracker::new();
    for line in &lines {
        let _ = tracker.process_line(line, &mut state);
    }
    let outcome = tracker.into_outcome(lines.to_vec(), false, false, SessionExit::Exited(Some(0)));
    assert!(outcome.saw_end);
    assert_eq!(outcome.unclosed_at_end.len(), 1);
    assert_eq!(outcome.unclosed_at_end[0].id, "conformance/base");
    assert!(
        !audit_raw_attempt(&outcome.raw_lines, outcome.saw_end).is_empty(),
        "raw attempt audit must preserve unclosed START and invalid JSON errors"
    );
    let synth = append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state).unwrap();
    assert_eq!(synth, vec!["conformance/base"]);
    let merged = finalize_merged_capture("fw", &mut state).unwrap();
    let cap = parse_capture("fw", &merged).unwrap();
    assert_eq!(cap.checks.len(), 1);
    assert!(cap.checks[0].synthetic);
    assert_eq!(cap.checks[0].status, CheckStatusTag::Fail);
    assert_eq!(cap.checks[0].fail_reason.as_deref(), Some("protocol_error"));
}

#[test]
fn validates_output_paths_hardlinks_and_independent_saving() {
    let dir = TestWorkDir::new("args");
    let bios = dir.0.join("fw.bin");
    fs::write(&bios, b"fw").unwrap();

    let base_args = || {
        let mut a = base_test_args(None);
        a.bios = bios.clone();
        a.mode = CliRunMode::All;
        a
    };
    assert!(validate_run_args(&base_args()).is_ok());

    let mut dir_out = base_args();
    dir_out.out = Some(dir.0.clone());
    let err = validate_run_args(&dir_out).unwrap_err();
    assert!(err.contains("is a directory"), "{err}");

    let mut dir_raw = base_args();
    dir_raw.raw_log = Some(dir.0.clone());
    let err = validate_run_args(&dir_raw).unwrap_err();
    assert!(err.contains("is a directory"), "{err}");

    let mut bad_parent = base_args();
    bad_parent.out = Some(bios.join("nested.jsonl"));
    let err = validate_run_args(&bad_parent).unwrap_err();
    assert!(err.contains("is not a directory"), "{err}");

    // Two distinct paths pointing to the same hardlinked file must be rejected.
    let link_a = dir.0.join("link-a.log");
    let link_b = dir.0.join("link-b.log");
    fs::write(&link_a, b"existing").unwrap();
    fs::hard_link(&link_a, &link_b).unwrap();
    let mut hardlinked = base_args();
    hardlinked.out = Some(link_a.clone());
    hardlinked.raw_log = Some(link_b.clone());
    let err = validate_run_args(&hardlinked).unwrap_err();
    assert!(err.contains("same file"), "{err}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        // Dangling symlink pointing out -> nonexistent raw log must be rejected before creating raw log.
        let raw_target = dir.0.join("dangling-raw.log");
        let out_symlink = dir.0.join("dangling-out.jsonl");
        symlink(&raw_target, &out_symlink).unwrap();
        let mut dangling_args = base_args();
        dangling_args.out = Some(out_symlink.clone());
        dangling_args.raw_log = Some(raw_target.clone());
        let err = validate_run_args(&dangling_args).unwrap_err();
        assert!(err.contains("same file"), "{err}");
        let prep_err = match prepare_outputs(&out_symlink, Some(&raw_target)) {
            Ok(_) => panic!("expected prepare_outputs to reject dangling symlink alias"),
            Err(e) => e,
        };
        assert!(prep_err.contains("same file"), "{prep_err}");
        assert!(!raw_target.exists());

        // Reverse dangling symlink raw -> nonexistent out must also be rejected.
        let out_target = dir.0.join("dangling-target.jsonl");
        let raw_symlink = dir.0.join("dangling-raw-link.log");
        symlink(&out_target, &raw_symlink).unwrap();
        let mut rev_args = base_args();
        rev_args.out = Some(out_target.clone());
        rev_args.raw_log = Some(raw_symlink.clone());
        let err = validate_run_args(&rev_args).unwrap_err();
        assert!(err.contains("same file"), "{err}");

        // Chained dangling symlinks and cyclic symlink loops must be handled cleanly.
        let hop1 = dir.0.join("hop1.jsonl");
        let hop2 = dir.0.join("hop2.jsonl");
        symlink(&hop2, &hop1).unwrap();
        symlink(&raw_target, &hop2).unwrap();
        assert!(paths_refer_to_same_file(&hop1, &raw_target).unwrap());

        let loop_a = dir.0.join("loop-a");
        let loop_b = dir.0.join("loop-b");
        symlink(&loop_b, &loop_a).unwrap();
        symlink(&loop_a, &loop_b).unwrap();
        let loop_err = validate_output_file_path("--out", &loop_a).unwrap_err();
        assert!(loop_err.contains("symbolic links"), "{loop_err}");

        // Aliased directory symlink above uncreated subdirectories must be rejected before mkdir.
        let real_dir = dir.0.join("real-dir");
        fs::create_dir_all(&real_dir).unwrap();
        let alias_dir = dir.0.join("alias-dir");
        symlink(&real_dir, &alias_dir).unwrap();
        let aliased_out = alias_dir.join("sub1/sub2/shared.out");
        let aliased_raw = real_dir.join("sub1/sub2/shared.out");
        let mut sub_args = base_args();
        sub_args.out = Some(aliased_out.clone());
        sub_args.raw_log = Some(aliased_raw.clone());
        let err = validate_run_args(&sub_args).unwrap_err();
        assert!(err.contains("same file"), "{err}");
        let prep_err = match prepare_outputs(&aliased_out, Some(&aliased_raw)) {
            Ok(_) => panic!("expected prepare_outputs to reject aliased dir subpaths"),
            Err(e) => e,
        };
        assert!(prep_err.contains("same file"), "{prep_err}");
        assert!(!real_dir.join("sub1").exists());

        // Distinct filenames under aliased directories remain allowed.
        let distinct_raw = alias_dir.join("sub1/sub2/raw.log");
        assert!(prepare_outputs(&aliased_out, Some(&distinct_raw)).is_ok());

        // Mid-run symlink swap before final save must refuse to overwrite raw_log.
        let swap_raw = dir.0.join("swap-raw.log");
        let swap_out = dir.0.join("swap-out.jsonl");
        let mut swap_writer = Some(RawLogWriter::create(&swap_raw).unwrap());
        assert!(
            swap_writer
                .as_mut()
                .unwrap()
                .write_line("untouched raw serial")
                .is_none()
        );
        symlink(&swap_raw, &swap_out).unwrap();
        let errs = save_outputs_independently(&swap_out, Some("overwritten"), &mut swap_writer);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("refusing to overwrite"), "{errs:?}");
        assert_eq!(
            fs::read_to_string(&swap_raw).unwrap(),
            "untouched raw serial\n"
        );

        // Atomic write through a symlink must update its target while keeping the symlink intact.
        let sym_target = dir.0.join("nested-out/capture.jsonl");
        let sym_out = dir.0.join("out-link.jsonl");
        symlink(&sym_target, &sym_out).unwrap();
        atomic_write(&sym_out, b"first-capture\n").unwrap();
        assert!(
            fs::symlink_metadata(&sym_out)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&sym_target).unwrap(), "first-capture\n");
        atomic_write(&sym_out, b"second-capture\n").unwrap();
        assert!(
            fs::symlink_metadata(&sym_out)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&sym_target).unwrap(), "second-capture\n");
        assert!(
            !fs::read_dir(sym_target.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        );
    }

    // Interruption after END must classify as ShutdownStatus::Interrupted, never TimedOutAfterEnd.
    let mut tracker = AttemptTracker::new();
    let mut cap_state = CaptureState {
        frames: Vec::new(),
        quarantine_warnings: 0,
    };
    let end = end_line();
    let _ = tracker.process_line(&end, &mut cap_state);
    assert_eq!(
        tracker.classify_shutdown(false, true, SessionExit::Killed),
        ShutdownStatus::Interrupted
    );
    assert_eq!(
        tracker.classify_shutdown(true, true, SessionExit::Killed),
        ShutdownStatus::Interrupted
    );

    // Failing to write one output must not skip flushing/saving the other output.
    let raw_ok = dir.0.join("independent.log");
    let mut writer = Some(RawLogWriter::create(&raw_ok).unwrap());
    assert!(
        writer
            .as_mut()
            .unwrap()
            .write_line("serial line 1")
            .is_none()
    );
    let errs = save_outputs_independently(&dir.0, Some("payload"), &mut writer);
    assert_eq!(errs.len(), 1);
    assert_eq!(fs::read_to_string(&raw_ok).unwrap(), "serial line 1\n");
}

#[test]
fn raw_serial_sink_preserves_non_utf8_and_line_endings() {
    let dir = TestWorkDir::new("raw-bytes");
    let path = dir.0.join("serial.raw");
    let mut writer = RawLogWriter::create(&path).unwrap();
    let bytes = b"valid\ninvalid-\xff\r\nlast";
    assert!(writer.write_bytes(bytes).is_none());
    assert!(writer.flush().is_none());
    drop(writer);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn rejects_input_output_aliases_and_extreme_timeout() {
    let dir = TestWorkDir::new("input-alias");
    let bios = dir.0.join("firmware.bin");
    let kernel = dir.0.join("payload.bin");
    fs::write(&bios, b"firmware").unwrap();
    fs::write(&kernel, b"payload").unwrap();
    let hardlinked_bios = dir.0.join("firmware-alias.bin");
    fs::hard_link(&bios, &hardlinked_bios).unwrap();

    for (output, raw_log) in [
        (bios.clone(), dir.0.join("raw.log")),
        (hardlinked_bios, dir.0.join("raw.log")),
        (dir.0.join("out.jsonl"), bios.clone()),
        (dir.0.join("out.jsonl"), kernel.clone()),
    ] {
        let mut args = base_test_args(Some(output));
        args.bios = bios.clone();
        args.kernel = Some(kernel.clone());
        args.raw_log = Some(raw_log);
        let err = validate_run_args(&args).unwrap_err();
        assert!(err.contains("same file"), "{err}");
    }
    assert_eq!(fs::read(&bios).unwrap(), b"firmware");
    assert_eq!(fs::read(&kernel).unwrap(), b"payload");

    let mut args = base_test_args(None);
    args.bios = bios;
    args.timeout = u64::MAX;
    let err = validate_run_args(&args).unwrap_err();
    assert!(err.contains("--timeout"), "{err}");
}

#[test]
fn atomic_capture_write_replaces_content_without_leaving_temporaries() {
    let dir = TestWorkDir::new("atomic-output");
    let path = dir.0.join("capture.jsonl");
    fs::write(&path, b"previous complete capture").unwrap();
    atomic_write(&path, b"new complete capture\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new complete capture\n");
    let siblings = fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(siblings, vec![std::ffi::OsString::from("capture.jsonl")]);
}
