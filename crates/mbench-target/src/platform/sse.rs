//! Supervisor Software Events (`SSE`, SBI v3.0) trampoline and RAII session owner.

use core::{arch::global_asm, mem::offset_of};

use mbench_core::{
    engine::{Clock, CounterSnap},
    record::FailReason,
};

use crate::{
    platform::{Platform, boot::SyncUnsafeCell, impl_platform_clock_topology},
    sbi::{self, SbiError, SbiRet},
};

/// Per-event SSE trampoline record.
///
/// # Invariants
///
/// - `done` is the first field at offset `0`; `trap.S`-style assembly emits it through `OFF_DONE`.
/// - `done` is published with release ordering after `hart_id`/`saved_*` are written.
/// - The block stays 64-byte aligned so the trampoline never shares a cache line with unrelated data.
#[repr(C, align(64))]
struct SseStamp {
    done: usize,
    hart_id: usize,
    saved_t0: usize,
    saved_t1: usize,
    saved_t2: usize,
}

const _: () = assert!(offset_of!(SseStamp, done) == 0);
const _: () = assert!(align_of::<SseStamp>() == 64);

impl SseStamp {
    const fn new() -> Self {
        Self {
            done: 0,
            hart_id: usize::MAX,
            saved_t0: 0,
            saved_t1: 0,
            saved_t2: 0,
        }
    }
}

static SSE_STAMP: SyncUnsafeCell<SseStamp> = SyncUnsafeCell::new(SseStamp::new());

global_asm!(
    r#"
.text

.balign 4
.global mbench_sse_trampoline
mbench_sse_trampoline:
    # SBI v3.0 SSE entry passes `a6 = hart_id` and `a7 = entry_arg` (&SSE_STAMP).
    sd   t0, {OFF_T0}(a7)
    sd   t1, {OFF_T1}(a7)
    sd   t2, {OFF_T2}(a7)
    sd   a6, {OFF_HART_ID}(a7)
    fence w, w
    li   t2, 1
    sd   t2, {OFF_DONE}(a7)
    ld   t0, {OFF_T0}(a7)
    ld   t1, {OFF_T1}(a7)
    ld   t2, {OFF_T2}(a7)
    li   a6, {FID_COMPLETE}
    li   a7, {EID_SSE}
    ecall
4:
    j 4b
"#,
    OFF_DONE = const offset_of!(SseStamp, done),
    OFF_HART_ID = const offset_of!(SseStamp, hart_id),
    OFF_T0 = const offset_of!(SseStamp, saved_t0),
    OFF_T1 = const offset_of!(SseStamp, saved_t1),
    OFF_T2 = const offset_of!(SseStamp, saved_t2),
    FID_COMPLETE = const sbi::sse::FID_COMPLETE,
    EID_SSE = const sbi::sse::EID,
);

unsafe extern "C" {
    fn mbench_sse_trampoline();
}

/// Exclusive BSP registration handle for [`sbi::sse::EVENT_LOCAL_SOFTWARE`]; unregisters on [`Drop`].
#[clippy::has_significant_drop]
#[must_use = "SseSession must be finished explicitly to unregister the SSE event"]
pub(crate) struct SseSession<'a> {
    platform: &'a mut Platform,
    event_id: usize,
    active: bool,
}

impl<'a> SseSession<'a> {
    pub(in crate::platform) fn register_local(
        platform: &'a mut Platform,
    ) -> Result<Self, SbiError> {
        let stamp_ptr = SSE_STAMP.get();
        // SAFETY: Exclusive BSP access via `&mut Platform`; initializes `SSE_STAMP` before registering.
        unsafe {
            core::ptr::write_volatile(&raw mut (*stamp_ptr).done, 0);
            core::ptr::write_volatile(&raw mut (*stamp_ptr).hart_id, usize::MAX);
        }
        let event_id = sbi::sse::EVENT_LOCAL_SOFTWARE;
        // SAFETY: `mbench_sse_trampoline` is `'static`, ends with `FID_COMPLETE`, and `SSE_STAMP` outlives registration.
        let ret = unsafe {
            sbi::sse::register(
                event_id,
                mbench_sse_trampoline as *const () as usize,
                stamp_ptr as usize,
            )
        };
        sbi::into_result(ret)?;
        Ok(Self {
            platform,
            event_id,
            active: true,
        })
    }

    pub(crate) fn timebase_hz(&self) -> u64 {
        self.platform.timebase_hz()
    }

    pub(crate) fn entry_pc(&self) -> usize {
        mbench_sse_trampoline as *const () as usize
    }

    pub(crate) fn entry_arg(&self) -> usize {
        SSE_STAMP.get() as usize
    }

    /// Reads SSE attribute `attr_id` for the registered event into exclusive scratch shmem.
    pub(crate) fn read_attr(&mut self, attr_id: usize) -> Result<usize, SbiError> {
        if self.platform.shmem.ensure_idle().is_err() {
            return Err(SbiError::Failed);
        }
        self.platform.shmem.write_first_usize(0);
        // SAFETY: `shmem.base()` is valid 4 KiB-aligned writable RAM owned exclusively via `&mut self`.
        let ret = unsafe {
            sbi::sse::read_attrs_raw(self.event_id, attr_id, 1, self.platform.shmem.base(), 0)
        };
        sbi::into_result(ret)?;
        Ok(self.platform.shmem.read_first_usize())
    }

    /// Reads `out.len()` consecutive SSE attributes starting at `base_attr_id` into `out`.
    pub(crate) fn read_attrs_multi(
        &mut self,
        base_attr_id: usize,
        out: &mut [usize],
    ) -> Result<(), SbiError> {
        if self.platform.shmem.ensure_idle().is_err() {
            return Err(SbiError::Failed);
        }
        let needed = out.len().saturating_mul(size_of::<usize>());
        if needed > self.platform.shmem.len() {
            return Err(SbiError::InvalidParam);
        }
        self.platform.shmem.zero_prefix(needed);
        // SAFETY: `shmem.base()` is valid writable RAM of at least `needed` bytes owned via `&mut self`.
        let ret = unsafe {
            sbi::sse::read_attrs_raw(
                self.event_id,
                base_attr_id,
                out.len(),
                self.platform.shmem.base(),
                0,
            )
        };
        sbi::into_result(ret)?;
        for (idx, dst) in out.iter_mut().enumerate() {
            *dst = self.platform.shmem.read_usize_at(idx);
        }
        Ok(())
    }

    /// Returns `true` if `ATTR_STATUS` bit 3 indicates `sbi_sse_inject` is allowed.
    pub(crate) fn is_injectable(&mut self) -> Result<bool, SbiError> {
        let status = self.read_attr(sbi::sse::ATTR_STATUS)?;
        Ok((status & sbi::sse::STATUS_INJECTABLE) != 0)
    }

    /// Returns the hart ID delivered in `a6` during the last SSE trampoline invocation.
    pub(crate) fn last_handler_hart_id(&self) -> usize {
        // SAFETY: Written by `mbench_sse_trampoline` before `done = 1`.
        unsafe { core::ptr::read_volatile(&raw const (*SSE_STAMP.get()).hart_id) }
    }

    /// Writes `value` into SSE attribute `attr_id` for the registered event via exclusive scratch shmem.
    pub(crate) fn write_attr(&mut self, attr_id: usize, value: usize) -> Result<(), SbiError> {
        if self.platform.shmem.ensure_idle().is_err() {
            return Err(SbiError::Failed);
        }
        self.platform.shmem.write_first_usize(value);
        // SAFETY: `shmem.base()` holds initialized readable `value` owned exclusively via `&mut self`.
        let ret = unsafe {
            sbi::sse::write_attrs_raw(self.event_id, attr_id, 1, self.platform.shmem.base(), 0)
        };
        sbi::into_result(ret).map(|_| ())
    }

    /// Enables the registered SSE event and unmasks SSE delivery on the current hart.
    pub(crate) fn enable_and_unmask(&mut self) -> Result<(), SbiError> {
        sbi::into_result(sbi::sse::enable(self.event_id))?;
        sbi::into_result(sbi::sse::hart_unmask())?;
        Ok(())
    }

    /// Injects the registered local SSE event and measures full roundtrip latency after `sbi_sse_complete`.
    pub(crate) fn inject_and_measure(
        &mut self,
        timeout_ticks: u64,
    ) -> Result<CounterSnap, FailReason> {
        let stamp_ptr = SSE_STAMP.get();
        // SAFETY: Exclusive BSP access before injecting local software SSE event.
        unsafe {
            core::ptr::write_volatile(&raw mut (*stamp_ptr).done, 0);
            core::ptr::write_volatile(&raw mut (*stamp_ptr).hart_id, usize::MAX);
        }

        let t0 = self.platform.snap_begin();
        let ret = sbi::sse::inject(self.event_id, self.platform.info.boot_hart_id);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }

        // SAFETY: Polling volatile `done` field written by `mbench_sse_trampoline`.
        self.platform.wait_until(timeout_ticks, || unsafe {
            core::ptr::read_volatile(&raw const (*stamp_ptr).done) != 0
        })?;
        let t1 = self.platform.snap_end();

        // SAFETY: `done != 0` observed after `fence w, w` in `mbench_sse_trampoline`.
        let hart_id = unsafe { core::ptr::read_volatile(&raw const (*stamp_ptr).hart_id) };
        if hart_id != self.platform.info.boot_hart_id {
            return Err(FailReason::VerificationMismatch);
        }
        Ok(CounterSnap::delta(t1, t0))
    }

    /// Probes registering the already-registered SSE event to verify `INVALID_STATE`.
    pub(crate) fn probe_double_register(&self) -> SbiRet {
        probe_invalid_register(self.event_id, false)
    }

    /// Masks, disables, and unregisters the SSE event, reporting any firmware teardown error.
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.teardown_inner();
        self.active = false;
        res
    }

    fn teardown_inner(&mut self) -> Result<(), FailReason> {
        let mask = sbi::sse::hart_mask();
        let dis = sbi::sse::disable(self.event_id);
        let unreg = sbi::sse::unregister(self.event_id);
        if self.platform.shmem.is_available() {
            self.platform.shmem.zero_all();
        }
        if mask.error != 0 && sbi::error_code(mask) != SbiError::AlreadyStopped.as_code() {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(mask)));
        }
        if dis.error != 0 && sbi::error_code(dis) != SbiError::InvalidState.as_code() {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(dis)));
        }
        if unreg.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(unreg)));
        }
        Ok(())
    }
}

impl Drop for SseSession<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.teardown_inner();
            self.active = false;
        }
    }
}

/// Probes `ATTR_STATUS` for `EVENT_LOCAL_SOFTWARE` before registering an SSE handler.
pub(in crate::platform) fn probe_local_status(platform: &mut Platform) -> Result<usize, SbiError> {
    if platform.shmem.ensure_idle().is_err() {
        return Err(SbiError::Failed);
    }
    platform.shmem.write_first_usize(0);
    // SAFETY: `shmem.base()` is valid 4 KiB-aligned writable RAM owned via `&mut Platform`.
    let ret = unsafe {
        sbi::sse::read_attrs_raw(
            sbi::sse::EVENT_LOCAL_SOFTWARE,
            sbi::sse::ATTR_STATUS,
            1,
            platform.shmem.base(),
            0,
        )
    };
    sbi::into_result(ret)?;
    Ok(platform.shmem.read_first_usize())
}

/// Probes reading attributes for an unknown SSE event ID into exclusive scratch shmem.
pub(in crate::platform) fn probe_unknown_event(platform: &mut Platform) -> SbiRet {
    if platform.shmem.ensure_idle().is_err() {
        return SbiRet::failed();
    }
    platform.shmem.zero_all();
    // SAFETY: `shmem.base()` is valid 4 KiB-aligned writable RAM owned via `&mut Platform`.
    unsafe { sbi::sse::read_attrs_raw(sbi::sse::EVENT_INVALID, 0, 1, platform.shmem.base(), 0) }
}

/// Probes invalid `sbi_sse_register` rejection (unaligned PC or invalid event ID).
pub(in crate::platform) fn probe_invalid_register(event_id: usize, unaligned: bool) -> SbiRet {
    let base_pc = mbench_sse_trampoline as *const () as usize;
    let pc = if unaligned { base_pc | 1 } else { base_pc };
    // SAFETY: Caller intentionally probes invalid unaligned entry PC or invalid `event_id`;
    // `SSE_STAMP` remains `'static` and handler ends in `FID_COMPLETE`.
    unsafe { sbi::sse::register(event_id, pc, SSE_STAMP.get() as usize) }
}

impl_platform_clock_topology!(SseSession<'_>);
