//! SBI IPI (`sPI`) single-hart and SMP remote delivery conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::{Clock, HartCoordinator},
    record::{CaseFlags, SbiExtensionId, SkipReason},
};

use super::check_case;
use crate::{
    platform::{Platform, trap},
    sbi::{self, SbiError},
};

pub(super) static SINGLE_CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/spi",
    Some(SbiExtensionId::Spi),
    1,
    CaseFlags::empty(),
    conf_spi_single,
)];

pub(super) static MULTI_CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/spi_smp",
    Some(SbiExtensionId::Spi),
    2,
    CaseFlags::empty(),
    conf_spi_smp,
)];

fn conf_spi_single(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let timeout = env.timebase_hz().max(1);

    trap::clear_ssip();
    ctx.expect(!trap::is_ssip_pending(), "spi_ssip_clean");

    let empty = sbi::spi::send_ipi(0, 0);
    ctx.expect_sbi_err(sbi::error_code(empty), 0, "spi_empty_mask");

    match trap::IpiCaptureHookGuard::install(env.availability()) {
        Ok(guard) => {
            guard.reset_flag();
            let (mask, base) = env.self_hart_mask();
            {
                // `enable_ssie()` clears `sip.SSIP` on entry, so arm interrupts before sending self-IPI.
                let _irq = guard.enable_ssie();
                let self_ipi = sbi::spi::send_ipi(mask, base);
                ctx.expect_sbi_err(sbi::error_code(self_ipi), 0, "spi_self_ret");
                let wait_res = env.wait_until(timeout, || guard.read_flag() != 0);
                ctx.expect(
                    wait_res.is_ok() && guard.read_flag() != 0,
                    "spi_self_ssip_raised",
                );
            }
            trap::clear_ssip();
            ctx.expect(!trap::is_ssip_pending(), "spi_self_ssip_cleared");

            guard.reset_flag();
            {
                let _irq = guard.enable_ssie();
                let bcast = sbi::spi::send_ipi(0, usize::MAX);
                ctx.expect_sbi_err(sbi::error_code(bcast), 0, "spi_broadcast_ignore_mask");
                let wait_res = env.wait_until(timeout, || guard.read_flag() != 0);
                ctx.expect(
                    wait_res.is_ok() && guard.read_flag() != 0,
                    "spi_broadcast_self_delivered",
                );
            }
            trap::clear_ssip();
        }
        Err(err) => {
            ctx.record_fail("spi_hook_install", err);
        }
    }

    let bad_base = sbi::spi::send_ipi(1, usize::MAX - 1);
    ctx.expect_sbi_err(
        sbi::error_code(bad_base),
        SbiError::InvalidParam.as_code(),
        "spi_invalid_hart_mask_base",
    );

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Spi);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "spi_invalid_fid",
    );

    ctx.finish()
}

fn conf_spi_smp(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let online = env.online_harts();
    let Some((workers_mask, workers_base)) = env.workers_hart_mask() else {
        return ctx.finish_or_skip(SkipReason::SingleHartOnly);
    };
    let expected_workers = online - 1;

    match env.probe_remote_ipi_delivery(workers_mask, workers_base, expected_workers) {
        Ok((ret, acked)) => {
            ctx.expect_sbi_err(sbi::error_code(ret), 0, "spi_smp_all_workers_ret");
            ctx.expect(acked == expected_workers, "spi_smp_all_workers_acked");
        }
        Err(err) => ctx.record_fail("spi_smp_all_workers", err),
    }

    let (one_mask, one_base) = Platform::hart_mask_single(env.hart_id(1));
    match env.probe_remote_ipi_delivery(one_mask, one_base, 1) {
        Ok((ret, acked)) => {
            ctx.expect_sbi_err(sbi::error_code(ret), 0, "spi_smp_single_worker_ret");
            ctx.expect(acked == 1, "spi_smp_single_worker_acked");
        }
        Err(err) => ctx.record_fail("spi_smp_single_worker", err),
    }

    match env.probe_remote_ipi_delivery(0, usize::MAX, expected_workers) {
        Ok((ret, acked)) => {
            ctx.expect_sbi_err(sbi::error_code(ret), 0, "spi_smp_broadcast_ret");
            ctx.expect(acked == expected_workers, "spi_smp_broadcast_acked");
        }
        Err(err) => ctx.record_fail("spi_smp_broadcast", err),
    }
    trap::clear_ssip();

    ctx.finish()
}
