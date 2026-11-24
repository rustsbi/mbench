//! Shared case ownership and stable record merging for host capture consumers.

use std::collections::BTreeMap;

use crate::{
    record::{BenchGroup, SkipReason, StartKind},
    wire::{BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, ShutdownStatus, StartFrame},
};

/// Shared `@@MBENCH:START` to result matcher used by both live monitoring and offline auditing.
#[derive(Clone, Debug, Default)]
pub struct CaseTracker {
    active: Vec<StartFrame>,
}

impl CaseTracker {
    /// Creates an empty tracker.
    pub const fn new() -> Self {
        Self { active: Vec::new() }
    }

    /// Records a started case, returning `false` when an identical active start already exists.
    pub fn record_start(&mut self, start: StartFrame) -> bool {
        let already_open = self
            .active
            .iter()
            .any(|s| s.kind == start.kind && s.id == start.id && s.parallel == start.parallel);
        if already_open {
            false
        } else {
            self.active.push(start);
            true
        }
    }

    /// Closes the active `CHECK` start entry for `id`, returning `true` when found.
    pub fn close_check(&mut self, id: &str) -> bool {
        self.close_matching(|s| s.kind == StartKind::Check && s.id == id)
    }

    /// Closes the active `BENCH` start entry for `(id, parallel)`, returning `true` when found.
    pub fn close_bench(&mut self, id: &str, parallel: usize) -> bool {
        self.close_matching(|s| s.kind == StartKind::Bench && s.id == id && s.parallel == parallel)
    }

    fn close_matching(&mut self, matches: impl FnMut(&StartFrame) -> bool) -> bool {
        if let Some(pos) = self.active.iter().position(matches) {
            self.active.remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns `true` when no started case is currently open.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// Drains all remaining open start frames in insertion order.
    pub fn drain_all(&mut self) -> Vec<StartFrame> {
        core::mem::take(&mut self.active)
    }
}
/// Infers [`BenchGroup`] from a benchmark ID prefix such as `"rfnc/sfence_vma.all"`.
pub fn infer_bench_group(id: &str) -> BenchGroup {
    let prefix = id.split_once('/').map_or(id, |(head, _)| head);
    match prefix {
        "baseline" => BenchGroup::Baseline,
        "trap" => BenchGroup::TrapEmul,
        "base" => BenchGroup::Base,
        "time" => BenchGroup::Time,
        "spi" => BenchGroup::Spi,
        "rfnc" => BenchGroup::Rfnc,
        "hsm" => BenchGroup::Hsm,
        "srst" => BenchGroup::Srst,
        "pmu" => BenchGroup::Pmu,
        "dbcn" => BenchGroup::Dbcn,
        "susp" => BenchGroup::Susp,
        "cppc" => BenchGroup::Cppc,
        "nacl" => BenchGroup::Nacl,
        "sta" => BenchGroup::Sta,
        "sse" => BenchGroup::Sse,
        "fwft" => BenchGroup::Fwft,
        "dbtr" => BenchGroup::Dbtr,
        "mpxy" => BenchGroup::Mpxy,
        "scale" => BenchGroup::Scale,
        _ => BenchGroup::Baseline,
    }
}

/// Maps a target shutdown classification to the normalized host-synthesized failure reason tag.
pub const fn shutdown_fail_reason(shutdown: &ShutdownStatus) -> &'static str {
    match shutdown {
        ShutdownStatus::TimedOutDuringRun => "timeout",
        ShutdownStatus::Interrupted => "interrupted",
        ShutdownStatus::CleanExit
        | ShutdownStatus::NonZeroExit { .. }
        | ShutdownStatus::Signaled
        | ShutdownStatus::TimedOutAfterEnd
        | ShutdownStatus::HostTerminatedAfterEnd
        | ShutdownStatus::AbortedOnPanic => "crash",
    }
}

/// Builds a synthetic `@@MBENCH:CHECK` failure frame for a started case that did not finish.
pub fn synthesize_fail_check(id: &str, reason: &str) -> CheckFrame {
    CheckFrame {
        id: id.to_string(),
        checks: 0,
        checks_total: 1,
        checks_failed: 1,
        status: CheckStatusTag::Fail,
        skip_reason: None,
        fail_reason: Some(reason.to_string()),
        quirks: 0,
        issues: Vec::new(),
        note: None,
        synthetic: true,
    }
}

/// Builds a synthetic `@@MBENCH:BENCH` failure frame for a started benchmark that did not finish.
pub fn synthesize_fail_bench(id: &str, parallel: usize, reason: &str) -> BenchFrame {
    BenchFrame {
        id: id.to_string(),
        group: infer_bench_group(id),
        mode: None,
        parallel,
        unit: String::from("op"),
        iters_per_trial: 0,
        trials: 0,
        status: BenchStatusTag::Fail,
        skip_reason: None,
        fail_reason: Some(reason.to_string()),
        cycles: None,
        instret: None,
        ticks: None,
        ns: None,
        throughput_ops_per_sec: None,
        note: None,
        synthetic: true,
        cal_index: None,
    }
}

#[derive(Default)]
pub(crate) struct RecordMerger {
    check_order: Vec<String>,
    check_map: BTreeMap<String, CheckFrame>,
    bench_order: Vec<(String, usize)>,
    bench_map: BTreeMap<(String, usize), BenchFrame>,
}

impl RecordMerger {
    pub(crate) fn extend(&mut self, checks: Vec<CheckFrame>, benches: Vec<BenchFrame>) {
        for check in checks {
            self.insert_check(check);
        }
        for bench in benches {
            self.insert_bench(bench);
        }
    }

    pub(crate) fn insert_check(&mut self, chk: CheckFrame) {
        if chk.skip_reason == Some(SkipReason::ResumedPast) && self.check_map.contains_key(&chk.id)
        {
            return;
        }
        if !self.check_map.contains_key(&chk.id) {
            self.check_order.push(chk.id.clone());
        }
        self.check_map.insert(chk.id.clone(), chk);
    }

    pub(crate) fn insert_bench(&mut self, bench: BenchFrame) {
        let key = (bench.id.clone(), bench.parallel);
        if bench.skip_reason == Some(SkipReason::ResumedPast) && self.bench_map.contains_key(&key) {
            return;
        }
        if !self.bench_map.contains_key(&key) {
            self.bench_order.push(key.clone());
        }
        self.bench_map.insert(key, bench);
    }

    pub(crate) fn synthesize_unclosed(&mut self, unclosed: &[StartFrame], reason: &str) {
        for start in unclosed {
            match start.kind {
                StartKind::Check => {
                    if !self.check_map.get(&start.id).is_some_and(|existing| {
                        existing.skip_reason != Some(SkipReason::ResumedPast)
                    }) {
                        self.insert_check(synthesize_fail_check(&start.id, reason));
                    }
                }
                StartKind::Bench => {
                    let key = (start.id.clone(), start.parallel);
                    if !self.bench_map.get(&key).is_some_and(|existing| {
                        existing.skip_reason != Some(SkipReason::ResumedPast)
                    }) {
                        self.insert_bench(synthesize_fail_bench(&start.id, start.parallel, reason));
                    }
                }
            }
        }
    }

    pub(crate) fn finish(mut self) -> (Vec<CheckFrame>, Vec<BenchFrame>) {
        let checks = self
            .check_order
            .into_iter()
            .filter_map(|id| self.check_map.remove(&id))
            .collect();
        let benches = self
            .bench_order
            .into_iter()
            .filter_map(|key| self.bench_map.remove(&key))
            .collect();
        (checks, benches)
    }
}
