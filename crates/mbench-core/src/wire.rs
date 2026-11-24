//! Host-side strongly typed wire frame schema and boundary-validated parser shared by `mbench-cli`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    config::{ClockRegime, OrderMode, Profile, RunMode},
    record::{BenchGroup, EndRecord, MeasureMode, SbiExtensionId, SkipReason, StartKind},
};

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Environment metadata header recorded at the top of saved `.jsonl` captures.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvLine {
    pub clock_regime: ClockRegime,
    pub label: Option<String>,
    pub smp: Option<usize>,
    pub icount: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RunMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<OrderMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_harts: Option<usize>,
}

/// Effective target runtime configuration reported inside `@@MBENCH:META`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveConfigFrame {
    pub mode: RunMode,
    pub profile: Profile,
    pub order: OrderMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after: Option<String>,
    #[serde(default)]
    pub allow_io: bool,
    #[serde(default)]
    pub allow_destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_harts: Option<usize>,
}

/// Deserialized `@@MBENCH:META` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetaFrame {
    pub sbi_spec_version: usize,
    pub impl_id: usize,
    pub impl_version: usize,
    pub mvendorid: usize,
    pub marchid: usize,
    pub mimpid: usize,
    pub extensions: Vec<SbiExtensionId>,
    pub extensions_mask: u32,
    pub hart_count: usize,
    pub boot_hart_id: usize,
    pub timebase_hz: u64,
    pub has_cycle: bool,
    pub has_instret: bool,
    pub has_time: bool,
    pub is_rdtime_emulated: bool,
    pub is_pmu_gated: bool,
    pub has_sstc: bool,
    pub has_h_ext: bool,
    pub boot_ticks: u64,
    pub reserved_mem_bytes: u64,
    pub console_backend: String,
    pub pmu_counter_count: usize,
    pub load_addr: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<EffectiveConfigFrame>,
}

/// Deserialized `@@MBENCH:CAL` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalFrame {
    pub profile: Profile,
    pub trials: usize,
    pub enough_iters: u64,
    pub loop_overhead_cycles_x100: u64,
    pub loop_overhead_instret_x100: u64,
    pub loop_overhead_ticks_x100: u64,
    pub timer_overhead_cycles_x100: u64,
    pub timer_overhead_instret_x100: u64,
    pub timer_overhead_ticks_x100: u64,
    pub rdtime_read_cycles_x100: u64,
    pub is_rdtime_emulated: bool,
}

/// Deserialized `@@MBENCH:START` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartFrame {
    pub kind: StartKind,
    pub id: String,
    pub parallel: usize,
}

/// Wire status tag for an `@@MBENCH:CHECK` frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CheckStatusTag {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "SKIPPED")]
    Skipped,
    #[serde(rename = "FAIL")]
    Fail,
}

/// Wire status tag for an `@@MBENCH:BENCH` frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BenchStatusTag {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "SKIPPED")]
    Skipped,
    #[serde(rename = "HW_NATIVE")]
    HwNative,
    #[serde(rename = "DELEGATED_TO_S")]
    DelegatedToS,
    #[serde(rename = "FAIL")]
    Fail,
}

/// Deserialized per-counter statistical summary preserving both raw totals and net scaled samples.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CounterStatsFrame {
    pub min_x100: u64,
    pub p25_x100: u64,
    pub median_x100: u64,
    pub p75_x100: u64,
    pub p95_x100: u64,
    pub max_x100: u64,
    pub iqr_x100: u64,
    pub raw_batch_median: u64,
    pub is_noisy: bool,
    pub raw_batch_totals: Vec<u64>,
    pub net_samples_x100: Vec<u64>,
}

/// Deserialized derived nanosecond summary (`ns`), strictly without tick-unit raw fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivedNsStatsFrame {
    pub min_x100: u64,
    pub p25_x100: u64,
    pub median_x100: u64,
    pub p75_x100: u64,
    pub p95_x100: u64,
    pub max_x100: u64,
    pub iqr_x100: u64,
    pub is_noisy: bool,
    pub net_samples_x100: Vec<u64>,
}

/// Wire classification for a single conformance issue or observation inside [`CheckFrame`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckIssueClass {
    SpecViolation,
    SpecViolationWithQuirk,
    PermittedBehavior,
    Unsupported,
}

impl CheckIssueClass {
    /// Returns `true` if this issue represents a specification violation.
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::SpecViolation | Self::SpecViolationWithQuirk)
    }
}

/// Wire entry describing one failed assertion or notable observation inside a [`CheckFrame`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckIssueFrame {
    pub label: String,
    pub class: CheckIssueClass,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quirk: Option<String>,
}

/// Deserialized `@@MBENCH:CHECK` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckFrame {
    pub id: String,
    pub checks: u64,
    #[serde(default)]
    pub checks_total: u64,
    #[serde(default)]
    pub checks_failed: u64,
    pub status: CheckStatusTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    #[serde(default)]
    pub quirks: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<CheckIssueFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub synthetic: bool,
}

/// Deserialized `@@MBENCH:BENCH` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchFrame {
    pub id: String,
    pub group: BenchGroup,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<MeasureMode>,
    pub parallel: usize,
    pub unit: String,
    pub iters_per_trial: u64,
    pub trials: usize,
    pub status: BenchStatusTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instret: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticks: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ns: Option<DerivedNsStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_ops_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub synthetic: bool,
    /// Zero-based index into [`ParsedCapture::cals`] identifying the calibration active when emitted.
    #[serde(skip)]
    pub cal_index: Option<usize>,
}

/// Deserialized `@@MBENCH:END` payload.
pub type EndFrame = EndRecord;

/// Target process shutdown classification observed for one run attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShutdownStatus {
    CleanExit,
    NonZeroExit { code: i32 },
    Signaled,
    TimedOutAfterEnd,
    HostTerminatedAfterEnd,
    TimedOutDuringRun,
    AbortedOnPanic,
}

/// Host-side audit record appended after each target execution attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptRecord {
    pub attempt: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after: Option<String>,
    pub saw_end: bool,
    pub shutdown: ShutdownStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub synthesized_failures: Vec<String>,
}

/// Deserialized `@@MBENCH:PANIC` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PanicFrame {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub scause: Option<usize>,
    #[serde(default)]
    pub stval: Option<usize>,
    #[serde(default)]
    pub sepc: Option<usize>,
}

/// Parsed streaming frame yielded by [`parse_wire_line`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireFrame {
    Env(EnvLine),
    Attempt(AttemptRecord),
    Meta(MetaFrame),
    Cal(CalFrame),
    Start(StartFrame),
    Check(CheckFrame),
    Bench(Box<BenchFrame>),
    End(EndFrame),
    Panic(PanicFrame),
}

/// Parsed representation of one saved `.jsonl` or raw serial log capture.
#[derive(Clone, Debug)]
pub struct ParsedCapture {
    pub label: String,
    pub env: Option<EnvLine>,
    pub clock_regime: ClockRegime,
    pub max_harts: Option<usize>,
    pub attempts: Vec<AttemptRecord>,
    pub meta: Option<MetaFrame>,
    pub cal: Option<CalFrame>,
    pub cals: Vec<CalFrame>,
    pub checks: Vec<CheckFrame>,
    pub benches: Vec<BenchFrame>,
    pub end: Option<EndFrame>,
    pub panic: Option<PanicFrame>,
}

/// Parses one line from either a saved `.jsonl` capture or noisy raw serial output.
///
/// Dispatches strictly on the first `@@MBENCH:<TAG>` prefix on the line and validates semantic invariants.
pub fn parse_wire_line(raw_line: &str) -> Result<Option<WireFrame>, String> {
    let line = raw_line.trim_end_matches(['\r', '\n']);
    if let Some(json) = line.strip_prefix("# MBENCH_ENV ") {
        let env: EnvLine =
            serde_json::from_str(json).map_err(|e| format!("invalid MBENCH_ENV frame: {e}"))?;
        return Ok(Some(WireFrame::Env(env)));
    }
    if let Some(json) = line.strip_prefix("# MBENCH_ATTEMPT ") {
        let attempt: AttemptRecord =
            serde_json::from_str(json).map_err(|e| format!("invalid MBENCH_ATTEMPT frame: {e}"))?;
        return Ok(Some(WireFrame::Attempt(attempt)));
    }

    let Some(pos) = line.find("@@MBENCH:") else {
        return Ok(None);
    };
    let after_prefix = &line[pos + "@@MBENCH:".len()..];
    let Some((tag, payload)) = after_prefix.split_once(' ') else {
        return Ok(None);
    };
    let json = payload.trim();

    match tag {
        "META" => {
            let parsed: MetaFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid META frame: {e}"))?;
            Ok(Some(WireFrame::Meta(parsed)))
        }
        "CAL" => {
            let parsed: CalFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid CAL frame: {e}"))?;
            Ok(Some(WireFrame::Cal(parsed)))
        }
        "START" => {
            let parsed: StartFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid START frame: {e}"))?;
            Ok(Some(WireFrame::Start(parsed)))
        }
        "CHECK" => {
            let parsed: CheckFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid CHECK frame: {e}"))?;
            validate_check_frame(&parsed)?;
            Ok(Some(WireFrame::Check(parsed)))
        }
        "BENCH" => {
            let parsed: BenchFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid BENCH frame: {e}"))?;
            validate_bench_frame(&parsed)?;
            Ok(Some(WireFrame::Bench(Box::new(parsed))))
        }
        "END" => {
            let parsed: EndFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid END frame: {e}"))?;
            Ok(Some(WireFrame::End(parsed)))
        }
        "PANIC" => {
            let parsed: PanicFrame =
                serde_json::from_str(json).map_err(|e| format!("invalid PANIC frame: {e}"))?;
            Ok(Some(WireFrame::Panic(parsed)))
        }
        _ => Ok(None),
    }
}

/// Extracts `@@MBENCH:*` records from either saved `.jsonl` captures or noisy raw serial output.
pub fn parse_capture(default_label: &str, text: &str) -> Result<ParsedCapture, String> {
    let mut label = default_label.to_string();
    let mut env_hdr = None;
    let mut clock_regime = ClockRegime::Unknown;
    let mut max_harts = None;
    let mut attempts: Vec<AttemptRecord> = Vec::new();
    let mut meta = None;
    let mut cal = None;
    let mut cals: Vec<CalFrame> = Vec::new();
    let mut active_cal_index: Option<usize> = None;
    let mut end = None;
    let mut panic = None;

    let mut check_order: Vec<String> = Vec::new();
    let mut check_map: BTreeMap<String, CheckFrame> = BTreeMap::new();

    let mut bench_order: Vec<(String, usize)> = Vec::new();
    let mut bench_map: BTreeMap<(String, usize), BenchFrame> = BTreeMap::new();

    for raw_line in text.lines() {
        let Some(frame) = parse_wire_line(raw_line)? else {
            continue;
        };
        match frame {
            WireFrame::Env(env) => {
                clock_regime = env.clock_regime;
                if env.max_harts.is_some() {
                    max_harts = env.max_harts;
                }
                if let Some(lbl) = &env.label
                    && !lbl.is_empty()
                {
                    label = lbl.clone();
                }
                env_hdr = Some(env);
            }
            WireFrame::Attempt(attempt) => attempts.push(attempt),
            WireFrame::Meta(m) => {
                meta = Some(m);
                active_cal_index = None;
            }
            WireFrame::Cal(c) => {
                let idx = cals.len();
                if cal.is_none() {
                    cal = Some(c.clone());
                }
                cals.push(c);
                active_cal_index = Some(idx);
            }
            WireFrame::Start(_) => {}
            WireFrame::Check(chk) => {
                if chk.skip_reason == Some(SkipReason::ResumedPast)
                    && check_map.contains_key(&chk.id)
                {
                    continue;
                }
                if !check_map.contains_key(&chk.id) {
                    check_order.push(chk.id.clone());
                }
                check_map.insert(chk.id.clone(), chk);
            }
            WireFrame::Bench(mut b) => {
                let key = (b.id.clone(), b.parallel);
                if b.skip_reason == Some(SkipReason::ResumedPast) && bench_map.contains_key(&key) {
                    continue;
                }
                b.cal_index = active_cal_index;
                if !bench_map.contains_key(&key) {
                    bench_order.push(key.clone());
                }
                bench_map.insert(key, *b);
            }
            WireFrame::End(e) => end = Some(e),
            WireFrame::Panic(p) => panic = Some(p),
        }
    }

    let checks = check_order
        .into_iter()
        .filter_map(|id| check_map.remove(&id))
        .collect::<Vec<_>>();
    let benches = bench_order
        .into_iter()
        .filter_map(|key| bench_map.remove(&key))
        .collect::<Vec<_>>();

    if meta.is_none()
        && checks.is_empty()
        && benches.is_empty()
        && panic.is_none()
        && attempts.is_empty()
    {
        return Err(format!("no @@MBENCH frames found in '{default_label}'"));
    }

    Ok(ParsedCapture {
        label,
        env: env_hdr,
        clock_regime,
        max_harts,
        attempts,
        meta,
        cal,
        cals,
        checks,
        benches,
        end,
        panic,
    })
}

fn validate_check_frame(frame: &CheckFrame) -> Result<(), String> {
    let has_failure_issue = frame.issues.iter().any(|i| i.class.is_failure());
    match frame.status {
        CheckStatusTag::Pass => {
            if frame.skip_reason.is_some()
                || frame.fail_reason.is_some()
                || frame.checks_failed > 0
                || frame.quirks > 0
                || has_failure_issue
            {
                return Err(format!(
                    "CHECK PASS frame '{}' carries skip/fail reason, quirks, or failure issue",
                    frame.id
                ));
            }
        }
        CheckStatusTag::Skipped => {
            if frame.skip_reason.is_none()
                || frame.fail_reason.is_some()
                || frame.checks_failed > 0
                || frame.quirks > 0
                || has_failure_issue
            {
                return Err(format!(
                    "CHECK SKIPPED frame '{}' has invalid reason, quirks, or failure fields",
                    frame.id
                ));
            }
        }
        CheckStatusTag::Fail => {
            if frame.fail_reason.is_none() || frame.skip_reason.is_some() {
                return Err(format!(
                    "CHECK FAIL frame '{}' has invalid reason fields",
                    frame.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_bench_frame(frame: &BenchFrame) -> Result<(), String> {
    let has_any_stats = frame.cycles.is_some()
        || frame.instret.is_some()
        || frame.ticks.is_some()
        || frame.ns.is_some()
        || frame.throughput_ops_per_sec.is_some();

    match frame.status {
        BenchStatusTag::Pass => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() {
                return Err(format!(
                    "BENCH PASS frame '{}' carries skip/fail reason",
                    frame.id
                ));
            }
            if frame.mode.is_none() || frame.trials == 0 {
                return Err(format!(
                    "BENCH PASS frame '{}' missing mode or zero trials",
                    frame.id
                ));
            }
        }
        BenchStatusTag::HwNative => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() || frame.trials != 1 {
                return Err(format!(
                    "BENCH HW_NATIVE frame '{}' violates invariants",
                    frame.id
                ));
            }
        }
        BenchStatusTag::Skipped => {
            if frame.skip_reason.is_none() || frame.fail_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH SKIPPED frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
        BenchStatusTag::DelegatedToS => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH DELEGATED_TO_S frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
        BenchStatusTag::Fail => {
            if frame.fail_reason.is_none() || frame.skip_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH FAIL frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
    }

    for stats in [&frame.cycles, &frame.instret, &frame.ticks]
        .into_iter()
        .flatten()
    {
        if stats.net_samples_x100.len() != frame.trials
            || stats.raw_batch_totals.len() != frame.trials
        {
            return Err(format!(
                "BENCH frame '{}' sample array length does not match trials={}",
                frame.id, frame.trials
            ));
        }
    }
    if let Some(ns) = &frame.ns
        && ns.net_samples_x100.len() != frame.trials
    {
        return Err(format!(
            "BENCH frame '{}' ns sample length does not match trials={}",
            frame.id, frame.trials
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol,
        record::{
            BenchResult, BenchStatus, CalibrationRecord, CheckResult, CheckStatus,
            CounterAvailability, FailReason, MetaRecord, SbiCapMask,
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
                status: CheckStatus::Failed(FailReason::AssertionFailed(
                    "dbtr_nonzero_flags_rejected",
                )),
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
    }
}
