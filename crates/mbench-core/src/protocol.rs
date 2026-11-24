//! Zero-allocation streaming `@@MBENCH:*` JSONL and progress writers.

use core::fmt::{self, Write};

use crate::{
    record::{
        BenchResult, BenchStatus, CalibrationRecord, CheckResult, CheckStatus, EndRecord,
        FailReason, MetaRecord, SbiExtensionId, StartKind,
    },
    stats::{CounterStats, DerivedNsStats, STATS_SCALE},
};

/// Writes an `@@MBENCH:META` JSONL frame to `out`.
pub fn write_meta_line(meta: &MetaRecord<'_>, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    write!(
        out,
        "@@MBENCH:META {{\"sbi_spec_version\":{},\"impl_id\":{},\"impl_version\":{},\
         \"mvendorid\":{},\"marchid\":{},\"mimpid\":{},\"extensions\":[",
        meta.sbi_spec_version,
        meta.impl_id,
        meta.impl_version,
        meta.mvendorid,
        meta.marchid,
        meta.mimpid,
    )?;
    let mut first = true;
    for ext in SbiExtensionId::ALL {
        if meta.extensions.contains_ext(ext) {
            if !first {
                out.write_str(",")?;
            }
            first = false;
            write!(out, "\"{}\"", ext.name())?;
        }
    }
    write!(
        out,
        "],\"extensions_mask\":{},\"hart_count\":{},\"boot_hart_id\":{},\
         \"timebase_hz\":{},\"has_cycle\":{},\"has_instret\":{},\"has_time\":{},\
         \"is_rdtime_emulated\":{},\"is_pmu_gated\":{},\"has_sstc\":{},\
         \"has_h_ext\":{},\"boot_ticks\":{},\"reserved_mem_bytes\":{},\
         \"console_backend\":",
        meta.extensions.bits(),
        meta.hart_count,
        meta.boot_hart_id,
        meta.timebase_hz,
        meta.counters.has_cycle,
        meta.counters.has_instret,
        meta.counters.has_time,
        meta.counters.is_rdtime_emulated,
        meta.counters.is_pmu_gated,
        meta.has_sstc,
        meta.has_h_ext,
        meta.boot_ticks,
        meta.reserved_mem_bytes,
    )?;
    write_json_str(meta.console_backend, out)?;
    write!(
        out,
        ",\"pmu_counter_count\":{},\"load_addr\":{},\"config\":{{\"mode\":\"{}\",\"profile\":\"{}\",\"order\":\"{}\",\"allow_io\":{},\"allow_destructive\":{},\"seed\":",
        meta.pmu_counter_count,
        meta.load_addr,
        meta.config.mode.as_str(),
        meta.config.profile.as_str(),
        meta.config.order.as_str(),
        meta.config.allow_io,
        meta.config.allow_destructive,
    )?;
    match meta.config.seed {
        Some(seed) => write!(out, "{seed}")?,
        None => out.write_str("null")?,
    }
    out.write_str(",\"filter\":")?;
    match meta.config.filter {
        Some(flt) => write_json_str(flt, out)?,
        None => out.write_str("null")?,
    }
    out.write_str(",\"resume_after\":")?;
    match meta.config.resume_after {
        Some(res) => write_json_str(res, out)?,
        None => out.write_str("null")?,
    }
    out.write_str(",\"max_harts\":")?;
    match meta.config.max_harts {
        Some(mh) => write!(out, "{mh}")?,
        None => out.write_str("null")?,
    }
    writeln!(out, "}}}}")
}

/// Writes an `@@MBENCH:CAL` JSONL frame to `out`.
pub fn write_cal_line(cal: &CalibrationRecord, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    writeln!(
        out,
        "@@MBENCH:CAL {{\"profile\":\"{}\",\"trials\":{},\"enough_iters\":{},\
         \"loop_overhead_cycles_x100\":{},\"loop_overhead_instret_x100\":{},\
         \"loop_overhead_ticks_x100\":{},\"timer_overhead_cycles_x100\":{},\
         \"timer_overhead_instret_x100\":{},\"timer_overhead_ticks_x100\":{},\
         \"rdtime_read_cycles_x100\":{},\"is_rdtime_emulated\":{}}}",
        cal.profile.as_str(),
        cal.trials,
        cal.enough_iters,
        cal.loop_overhead_cycles_x100,
        cal.loop_overhead_instret_x100,
        cal.loop_overhead_ticks_x100,
        cal.timer_overhead_cycles_x100,
        cal.timer_overhead_instret_x100,
        cal.timer_overhead_ticks_x100,
        cal.rdtime_read_cycles_x100,
        cal.is_rdtime_emulated,
    )
}

/// Writes an `@@MBENCH:START` JSONL frame before executing a check or benchmark case.
pub fn write_start_line(
    kind: StartKind,
    id: &str,
    parallel: usize,
    out: &mut (impl Write + ?Sized),
) -> fmt::Result {
    write!(
        out,
        "@@MBENCH:START {{\"kind\":\"{}\",\"id\":",
        kind.as_str()
    )?;
    write_json_str(id, out)?;
    writeln!(out, ",\"parallel\":{parallel}}}")
}

/// Writes an `@@MBENCH:CHECK` JSONL frame for one completed functional conformance check.
pub fn write_check_line(res: &CheckResult<'_>, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_str("@@MBENCH:CHECK {\"id\":")?;
    write_json_str(res.id, out)?;
    write!(
        out,
        ",\"checks\":{},\"checks_total\":{},\"checks_failed\":{},\"status\":\"{}\"",
        res.checks,
        res.checks_total,
        res.checks_failed,
        res.status.label()
    )?;
    match res.status {
        CheckStatus::Skipped(reason) => {
            write!(out, ",\"skip_reason\":\"{}\"", reason.as_str())?;
        }
        CheckStatus::Failed(reason) => {
            out.write_str(",\"fail_reason\":")?;
            write_fail_reason(reason, out)?;
        }
        CheckStatus::Pass => {}
    }
    if res.quirks > 0 {
        write!(out, ",\"quirks\":{}", res.quirks)?;
    }
    if !res.issues.is_empty() {
        out.write_str(",\"issues\":[")?;
        for (idx, issue) in res.issues.iter().enumerate() {
            if idx > 0 {
                out.write_str(",")?;
            }
            out.write_str("{\"label\":")?;
            write_json_str(issue.label, out)?;
            write!(out, ",\"class\":\"{}\",\"reason\":", issue.class.as_str())?;
            write_fail_reason(issue.reason, out)?;
            if let Some(quirk) = issue.class.quirk() {
                out.write_str(",\"quirk\":")?;
                write_json_str(quirk, out)?;
            }
            out.write_str("}")?;
        }
        out.write_str("]")?;
    }
    if let Some(note) = res.note {
        out.write_str(",\"note\":")?;
        write_json_str(note, out)?;
    }
    writeln!(out, "}}")
}

/// Writes an `@@MBENCH:BENCH` JSONL frame for one completed performance benchmark invocation.
pub fn write_bench_line(res: &BenchResult<'_>, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_str("@@MBENCH:BENCH {\"id\":")?;
    write_json_str(res.id, out)?;
    write!(out, ",\"group\":\"{}\"", res.group.as_str())?;
    if let Some(mode) = res.mode {
        write!(out, ",\"mode\":\"{}\"", mode.as_str())?;
    }
    write!(out, ",\"parallel\":{},\"unit\":", res.parallel)?;
    write_json_str(res.unit, out)?;
    write!(
        out,
        ",\"iters_per_trial\":{},\"trials\":{},\"status\":\"{}\"",
        res.iters_per_trial,
        res.trials,
        res.status.label(),
    )?;
    match res.status {
        BenchStatus::Skipped(reason) => {
            write!(out, ",\"skip_reason\":\"{}\"", reason.as_str())?;
        }
        BenchStatus::Failed(reason) => {
            out.write_str(",\"fail_reason\":")?;
            write_fail_reason(reason, out)?;
        }
        BenchStatus::Pass | BenchStatus::HwNative | BenchStatus::DelegatedToS => {}
    }

    write_opt_counter_stats("cycles", res.cycles.as_ref(), out)?;
    write_opt_counter_stats("instret", res.instret.as_ref(), out)?;
    write_opt_counter_stats("ticks", res.ticks.as_ref(), out)?;
    write_opt_ns_stats(res.ns.as_ref(), out)?;

    if let Some(ops) = res.throughput_ops_per_sec {
        write!(out, ",\"throughput_ops_per_sec\":{ops}")?;
    }
    if let Some(note) = res.note {
        out.write_str(",\"note\":")?;
        write_json_str(note, out)?;
    }
    writeln!(out, "}}")
}

/// Writes an `@@MBENCH:END` JSONL frame after all requested phases complete.
pub fn write_end_line(end: &EndRecord, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    writeln!(
        out,
        "@@MBENCH:END {{\"checks_total\":{},\"checks_passed\":{},\"checks_skipped\":{},\
         \"checks_failed\":{},\"check_assertions_total\":{},\"check_assertions_passed\":{},\
         \"check_assertions_failed\":{},\"benches_total\":{},\"benches_passed\":{},\
         \"benches_skipped\":{},\"benches_hw_native\":{},\"benches_delegated\":{},\
         \"benches_failed\":{},\"quarantine_warnings\":{}}}",
        end.checks_total,
        end.checks_passed,
        end.checks_skipped,
        end.checks_failed,
        end.check_assertions_total,
        end.check_assertions_passed,
        end.check_assertions_failed,
        end.benches_total,
        end.benches_passed,
        end.benches_skipped,
        end.benches_hw_native,
        end.benches_delegated,
        end.benches_failed,
        end.quarantine_warnings,
    )
}

/// Writes a properly JSON-escaped `@@MBENCH:PANIC` frame from any `Display` payload.
pub fn write_panic_line(msg: impl fmt::Display, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_str("\n@@MBENCH:PANIC {\"message\":\"")?;
    let mut esc = JsonEscapedWriter(out);
    write!(esc, "{msg}")?;
    writeln!(out, "\"}}")
}

/// Writes an `@@MBENCH:PANIC` frame describing an unhandled S-mode trap.
pub fn write_unhandled_trap_panic(
    scause: usize,
    stval: usize,
    sepc: usize,
    out: &mut (impl Write + ?Sized),
) -> fmt::Result {
    writeln!(
        out,
        "\n@@MBENCH:PANIC {{\"reason\":\"unhandled_trap\",\"scause\":{scause},\"stval\":{stval},\"sepc\":{sepc}}}"
    )
}

/// Writes one human-readable progress line for a functional conformance check.
pub fn write_check_progress(res: &CheckResult<'_>, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    write!(out, "[mbench] {:<30} ", res.id)?;
    match res.status {
        CheckStatus::Pass => {
            write!(out, "{:<14} {} checks", res.status.label(), res.checks)?;
            if let Some(note) = res.note {
                write!(out, " ({note})")?;
            }
            writeln!(out)
        }
        CheckStatus::Skipped(reason) => writeln!(out, "SKIPPED ({})", reason.as_str()),
        CheckStatus::Failed(reason) => {
            out.write_str("FAIL (")?;
            write_fail_reason(reason, out)?;
            if res.checks_failed > 1 {
                write!(
                    out,
                    "; {} failed / {} passed",
                    res.checks_failed, res.checks
                )?;
            }
            if res.quirks > 0 {
                write!(out, "; {} quirks", res.quirks)?;
            }
            writeln!(out, ")")
        }
    }
}

/// Writes one human-readable progress line summarizing a performance benchmark result.
pub fn write_bench_progress(res: &BenchResult<'_>, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    write!(out, "[mbench] {:<30} p={:<2} ", res.id, res.parallel)?;
    match res.status {
        BenchStatus::Pass | BenchStatus::HwNative | BenchStatus::DelegatedToS => {
            write!(out, "{:<14} ", res.status.label())?;
            if let Some(cyc) = res.cycles {
                write_scaled(cyc.median_x100, out)?;
                out.write_str(" cyc")?;
                if cyc.is_noisy {
                    out.write_str("!")?;
                }
                out.write_str(" | ")?;
            }
            if let Some(inst) = res.instret {
                write_scaled(inst.median_x100, out)?;
                out.write_str(" inst | ")?;
            }
            if let Some(ns) = res.ns {
                write_scaled(ns.median_x100, out)?;
                out.write_str(" ns")?;
            }
            if let Some(ops) = res.throughput_ops_per_sec {
                write!(out, " | {ops} ops/s")?;
            }
            if let Some(note) = res.note {
                write!(out, " ({note})")?;
            }
            writeln!(out)
        }
        BenchStatus::Skipped(reason) => writeln!(out, "SKIPPED ({})", reason.as_str()),
        BenchStatus::Failed(reason) => {
            out.write_str("FAIL (")?;
            write_fail_reason(reason, out)?;
            writeln!(out, ")")
        }
    }
}

/// Formats a fixed-point `STATS_SCALE` (100x) integer as `int.dec`.
pub fn write_scaled(scaled: u64, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    let whole = scaled / STATS_SCALE;
    let frac = scaled % STATS_SCALE;
    write!(out, "{whole}.{frac:02}")
}

fn write_opt_counter_stats(
    name: &str,
    stats: Option<&CounterStats>,
    out: &mut (impl Write + ?Sized),
) -> fmt::Result {
    let Some(s) = stats else {
        return Ok(());
    };
    write!(
        out,
        ",\"{name}\":{{\"min_x100\":{},\"p25_x100\":{},\"median_x100\":{},\"p75_x100\":{},\
         \"p95_x100\":{},\"max_x100\":{},\"iqr_x100\":{},\"raw_batch_median\":{},\"is_noisy\":{},\
         \"raw_batch_totals\":",
        s.min_x100,
        s.p25_x100,
        s.median_x100,
        s.p75_x100,
        s.p95_x100,
        s.max_x100,
        s.iqr_x100,
        s.raw_batch_median,
        s.is_noisy,
    )?;
    write_u64_array(s.raw_batch_totals(), out)?;
    out.write_str(",\"net_samples_x100\":")?;
    write_u64_array(s.net_samples_x100(), out)?;
    out.write_str("}")
}

fn write_opt_ns_stats(
    stats: Option<&DerivedNsStats>,
    out: &mut (impl Write + ?Sized),
) -> fmt::Result {
    let Some(s) = stats else {
        return Ok(());
    };
    write!(
        out,
        ",\"ns\":{{\"min_x100\":{},\"p25_x100\":{},\"median_x100\":{},\"p75_x100\":{},\
         \"p95_x100\":{},\"max_x100\":{},\"iqr_x100\":{},\"is_noisy\":{},\"net_samples_x100\":",
        s.min_x100,
        s.p25_x100,
        s.median_x100,
        s.p75_x100,
        s.p95_x100,
        s.max_x100,
        s.iqr_x100,
        s.is_noisy,
    )?;
    write_u64_array(s.net_samples_x100(), out)?;
    out.write_str("}")
}

fn write_u64_array(vals: &[u64], out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_str("[")?;
    for (idx, &val) in vals.iter().enumerate() {
        if idx > 0 {
            out.write_str(",")?;
        }
        write!(out, "{val}")?;
    }
    out.write_str("]")
}

fn write_fail_reason(reason: FailReason, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    match reason {
        FailReason::UnexpectedSbiError(err) => write!(out, "\"sbi_error:{err}\""),
        FailReason::UnexpectedTrap(cause) => write!(out, "\"unexpected_trap:{cause}\""),
        FailReason::VerificationMismatch => out.write_str("\"verification_mismatch\""),
        FailReason::Timeout => out.write_str("\"timeout\""),
        FailReason::SecondaryHartError(err) => write!(out, "\"secondary_hart_error:{err}\""),
        FailReason::HardwareInconsistent => out.write_str("\"hardware_inconsistent\""),
        FailReason::AbiRegClobbered => out.write_str("\"abi_reg_clobbered\""),
        FailReason::SecurityViolation(msg) => {
            out.write_str("\"security:")?;
            write_json_str_inner(msg, out)?;
            out.write_str("\"")
        }
        FailReason::AssertionFailed(msg) => {
            out.write_str("\"assert:")?;
            write_json_str_inner(msg, out)?;
            out.write_str("\"")
        }
    }
}

fn write_json_str(raw: &str, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_str("\"")?;
    write_json_str_inner(raw, out)?;
    out.write_str("\"")
}

fn write_json_str_inner(raw: &str, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    for ch in raw.chars() {
        match ch {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32)?,
            c => out.write_char(c)?,
        }
    }
    Ok(())
}

struct JsonEscapedWriter<'a, W: Write + ?Sized>(&'a mut W);

impl<W: Write + ?Sized> Write for JsonEscapedWriter<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_json_str_inner(s, self.0)
    }
}
