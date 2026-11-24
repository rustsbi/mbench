//! Exclusive PMU counter guard shared by benchmark and conformance suites.

use mbench_core::record::FailReason;

use crate::{
    platform::{Platform, impl_platform_clock_topology},
    sbi::{self, SbiError},
};

/// Exclusive RAII guard for a configured SBI PMU counter, resetting on finish or drop when configured.
///
/// # Invariants
///
/// - `active` is true while this guard owns the SBI counter configuration; `finish_*` clears it
///   before attempting cleanup so `Drop` cannot repeat the reset.
/// - `configured` reflects the SBI counter configuration, and `running` tracks `counter_start`.
#[clippy::has_significant_drop]
#[must_use = "PmuCounterGuard should be finished explicitly to propagate PMU stop errors"]
pub(crate) struct PmuCounterGuard<'a> {
    platform: &'a mut Platform,
    idx: usize,
    configured: bool,
    running: bool,
    active: bool,
}

impl<'a> PmuCounterGuard<'a> {
    const fn adopt_configured(platform: &'a mut Platform, returned_idx: usize) -> Self {
        Self {
            platform,
            idx: returned_idx,
            configured: true,
            running: false,
            active: true,
        }
    }

    pub(crate) fn probe_config_matching_and_cleanup(
        platform: &mut Platform,
        idx_base: usize,
        idx_mask: usize,
        config_flags: usize,
        event_idx: usize,
        event_data: u64,
    ) -> (sbi::SbiRet, Result<(), FailReason>) {
        let ret = sbi::pmu::counter_config_matching(
            idx_base,
            idx_mask,
            config_flags,
            event_idx,
            event_data,
        );
        let cleanup = if ret.error == 0 {
            PmuCounterGuard::adopt_configured(platform, ret.value).finish_reset()
        } else {
            Ok(())
        };
        (ret, cleanup)
    }

    pub(crate) fn try_configure_firmware(
        platform: &'a mut Platform,
        event_idx: usize,
    ) -> Result<Option<Self>, FailReason> {
        let count = sbi::into_result(sbi::pmu::num_counters())
            .map_err(|e| FailReason::UnexpectedSbiError(e.as_code()))?;
        for idx in 0..count {
            if platform.is_pmu_counter_tainted(idx) {
                continue;
            }
            let info = match sbi::into_result(sbi::pmu::counter_get_info(idx)) {
                Ok(v) => v,
                // Counter index 1 (`time`) and unimplemented HW slots return `INVALID_PARAM`.
                Err(SbiError::InvalidParam) => continue,
                Err(err) => return Err(FailReason::UnexpectedSbiError(err.as_code())),
            };
            if !sbi::pmu::info_is_firmware(info) {
                continue;
            }
            let cfg = sbi::pmu::counter_config_matching(idx, 1, 0, event_idx, 0);
            if cfg.error != 0 {
                let code = sbi::error_code(cfg);
                if code == SbiError::NotSupported.as_code() {
                    continue;
                }
                return Err(FailReason::UnexpectedSbiError(code));
            }
            let guard = Self::adopt_configured(platform, cfg.value);
            if cfg.value != idx {
                guard.finish_reset()?;
                return Err(FailReason::HardwareInconsistent);
            }
            let matched_info = match sbi::into_result(sbi::pmu::counter_get_info(guard.idx())) {
                Ok(v) => v,
                Err(err) => {
                    guard.finish_reset()?;
                    return Err(FailReason::UnexpectedSbiError(err.as_code()));
                }
            };
            if !sbi::pmu::info_is_firmware(matched_info) {
                guard.finish_reset()?;
                return Err(FailReason::HardwareInconsistent);
            }
            return Ok(Some(guard));
        }
        Ok(None)
    }

    pub(crate) fn try_configure_hw(platform: &'a mut Platform) -> Result<Option<Self>, FailReason> {
        let count = sbi::into_result(sbi::pmu::num_counters())
            .map_err(|e| FailReason::UnexpectedSbiError(e.as_code()))?;
        for event in [
            sbi::pmu::HW_CACHE_BPU_READ_MISS,
            sbi::pmu::HW_BRANCH_INSTRUCTIONS,
            sbi::pmu::HW_CACHE_REFERENCES,
        ] {
            for idx in 0..count {
                if platform.is_pmu_counter_tainted(idx) {
                    continue;
                }
                let info = match sbi::into_result(sbi::pmu::counter_get_info(idx)) {
                    Ok(v) => v,
                    Err(SbiError::InvalidParam) => continue,
                    Err(err) => return Err(FailReason::UnexpectedSbiError(err.as_code())),
                };
                // Never reconfigure or stop fixed counters (`cycle = 0xc00`, `time = 0xc01`, `instret = 0xc02`).
                if sbi::pmu::info_is_firmware(info) || sbi::pmu::info_csr(info) < 0x0c03 {
                    continue;
                }
                let cfg = sbi::pmu::counter_config_matching(idx, 1, 0, event, 0);
                if cfg.error != 0 {
                    let code = sbi::error_code(cfg);
                    if code == SbiError::NotSupported.as_code() {
                        continue;
                    }
                    return Err(FailReason::UnexpectedSbiError(code));
                }
                let guard = Self::adopt_configured(platform, cfg.value);
                if cfg.value != idx {
                    guard.finish_reset()?;
                    return Err(FailReason::HardwareInconsistent);
                }
                let matched_info = match sbi::into_result(sbi::pmu::counter_get_info(guard.idx())) {
                    Ok(v) => v,
                    Err(err) => {
                        guard.finish_reset()?;
                        return Err(FailReason::UnexpectedSbiError(err.as_code()));
                    }
                };
                if sbi::pmu::info_is_firmware(matched_info)
                    || sbi::pmu::info_csr(matched_info) < 0x0c03
                {
                    guard.finish_reset()?;
                    return Err(FailReason::HardwareInconsistent);
                }
                return Ok(Some(guard));
            }
        }
        Ok(None)
    }

    pub(crate) const fn idx(&self) -> usize {
        self.idx
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.configured
    }

    pub(crate) fn adopt_reconfigured(&mut self, returned_idx: usize) -> Result<(), FailReason> {
        if self.configured || returned_idx != self.idx {
            PmuCounterGuard::adopt_configured(self.platform, returned_idx).finish_reset()?;
            return Err(FailReason::HardwareInconsistent);
        }
        self.configured = true;
        self.running = false;
        Ok(())
    }

    pub(crate) fn reconfigure_with_flags(
        &mut self,
        config_flags: usize,
        event_idx: usize,
        event_data: u64,
    ) -> (sbi::SbiRet, Result<(), FailReason>) {
        let ret =
            sbi::pmu::counter_config_matching(self.idx, 1, config_flags, event_idx, event_data);
        let adopt = if ret.error == 0 {
            self.adopt_reconfigured(ret.value)
        } else {
            Ok(())
        };
        (ret, adopt)
    }

    pub(crate) fn mark_running(&mut self) {
        self.configured = true;
        self.running = true;
    }

    pub(crate) fn mark_stopped(&mut self) {
        self.running = false;
    }

    pub(crate) fn stop_and_reset(&mut self) -> Result<(), FailReason> {
        self.reset_inner()
    }

    /// Stops and resets a running counter, failing and tainting on any error.
    pub(crate) fn finish_running(mut self) -> Result<(), FailReason> {
        self.active = false;
        if !self.configured {
            return Ok(());
        }
        let ret = sbi::pmu::counter_stop(self.idx, 1, sbi::pmu::stop_flags::RESET);
        if ret.error == 0 {
            self.configured = false;
            self.running = false;
            Ok(())
        } else {
            self.running = true;
            self.platform.taint_pmu_counter(self.idx);
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }

    /// Stops and resets an active counter configuration, keeping it tainted if reset fails.
    pub(crate) fn finish_reset(mut self) -> Result<(), FailReason> {
        self.active = false;
        self.reset_inner()
    }

    fn reset_inner(&mut self) -> Result<(), FailReason> {
        if !self.configured {
            return Ok(());
        }
        if !self.running {
            let st = sbi::pmu::counter_start(self.idx, 1, 0, 0);
            if st.error != 0 && sbi::error_code(st) != SbiError::AlreadyStarted.as_code() {
                self.platform.taint_pmu_counter(self.idx);
                return Err(FailReason::UnexpectedSbiError(sbi::error_code(st)));
            }
            self.running = true;
        }
        let ret = sbi::pmu::counter_stop(self.idx, 1, sbi::pmu::stop_flags::RESET);
        if ret.error == 0 {
            self.configured = false;
            self.running = false;
            Ok(())
        } else {
            self.platform.taint_pmu_counter(self.idx);
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }
}

impl Drop for PmuCounterGuard<'_> {
    fn drop(&mut self) {
        if self.active && self.configured {
            let _ = self.reset_inner();
            self.active = false;
        }
    }
}

impl_platform_clock_topology!(PmuCounterGuard<'_>);
