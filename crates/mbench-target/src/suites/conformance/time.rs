//! SBI TIME extension and Sstc (`stimecmp`) timer conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::Clock,
    record::{CaseFlags, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::{
        Platform, counters,
        timer::{self, TimerMode},
        trap,
    },
    sbi::{self, SbiError},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/time",
    Some(SbiExtensionId::Time),
    1,
    CaseFlags::empty(),
    conf_time,
)];

fn conf_time(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let avail = env.availability();
    let timeout = env.timebase_hz().max(1);

    let clr0 = timer::clear_timer(TimerMode::Sbi);
    ctx.expect_sbi_err(sbi::error_code(clr0), 0, "time_clear_ret");
    ctx.expect(!timer::is_timer_pending(), "time_stip_cleared");

    match trap::TimerSbiHookGuard::install(avail) {
        Ok(guard) => {
            guard.reset_flag();
            let arm0 = sbi::time::set_timer(0);
            ctx.expect_sbi_err(sbi::error_code(arm0), 0, "time_arm_zero_ret");
            {
                let _irq = guard.enable_stie();
                let wait_res = env.wait_until(timeout, || guard.read_flag() != 0);
                ctx.expect(
                    wait_res.is_ok() && guard.read_flag() != 0,
                    "time_stip_raised",
                );
            }
            ctx.expect(!timer::is_timer_pending(), "time_stip_re_cleared");

            if avail.has_time {
                guard.reset_flag();
                let delta = (env.timebase_hz() / 1_000).clamp(100, 10_000);
                let deadline = counters::read_time_raw().saturating_add(delta);
                let arm_fut = sbi::time::set_timer(deadline);
                ctx.expect_sbi_err(sbi::error_code(arm_fut), 0, "time_arm_future_ret");
                {
                    let _irq = guard.enable_stie();
                    let wait_res = env.wait_until(timeout, || guard.read_flag() != 0);
                    let irq_ticks = guard.read_snap().ticks;
                    ctx.expect(
                        wait_res.is_ok() && guard.read_flag() != 0 && irq_ticks >= deadline,
                        "time_future_deadline_monotonic",
                    );
                }
            }

            let arm_cancel = sbi::time::set_timer(0);
            ctx.expect_sbi_err(sbi::error_code(arm_cancel), 0, "time_arm_cancel_ret");
            let clr1 = timer::clear_timer(TimerMode::Sbi);
            ctx.expect_sbi_err(sbi::error_code(clr1), 0, "time_re_clear_ret");
            ctx.expect(!timer::is_timer_pending(), "time_cancel_before_irq");
        }
        Err(err) => {
            ctx.record_fail("time_hook_install", err);
        }
    }

    if env.info().has_sstc {
        match trap::TimerSstcHookGuard::install(avail, true) {
            Ok(guard) => {
                guard.reset_flag();
                {
                    let _irq = guard.arm_sstc_zero();
                    let wait_res = env.wait_until(timeout, || guard.read_flag() != 0);
                    ctx.expect(
                        wait_res.is_ok() && guard.read_flag() != 0,
                        "sstc_arm_zero_irq",
                    );
                }
                drop(guard);
                let clr_sstc = timer::clear_timer(TimerMode::Sstc);
                ctx.expect_sbi_err(sbi::error_code(clr_sstc), 0, "sstc_clear_ret");
                ctx.expect(!timer::is_timer_pending(), "sstc_stip_cleared");
            }
            Err(err) => {
                ctx.record_fail("sstc_hook_install", err);
            }
        }
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Time);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "time_invalid_fid",
    );

    ctx.finish()
}
