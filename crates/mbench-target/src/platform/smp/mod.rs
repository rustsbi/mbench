//! Cache-line-isolated multi-hart worker pool synchronized via SBI HSM and cancellable barriers.
//!
//! Each `HartSlot` is a one-producer/one-consumer mailbox. BSP writes command parameters before
//! publishing a new `epoch` with `Release`; the worker observes that epoch with `Acquire` before
//! reading the parameters. The worker publishes results before a `Release` store into `done_epoch`.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use mbench_core::engine::CounterSnap;

use crate::platform::{
    boot::{MAX_HARTS, SyncUnsafeCell},
    mmu::Sv39Config,
};

mod pool;
mod worker;

pub(crate) use pool::HsmHartPool;

pub(super) const CMD_NONE: usize = 0;
pub(super) const CMD_RUN_PARALLEL: usize = 1;
pub(super) const CMD_SET_SATP: usize = 2;
pub(super) const CMD_SET_IPI_MODE: usize = 3;
pub(super) const CMD_STOP: usize = 4;
pub(super) const CMD_READ_TARGET_PAGE: usize = 5;

pub(super) const WORKER_OFFLINE: usize = 0;
pub(super) const WORKER_PARKED: usize = 1;
pub(super) const WORKER_STOPPED: usize = 2;

const BARRIER_EPOCH_SHIFT: usize = 1;
const BARRIER_CANCEL_BIT: usize = 1;

/// A cache-line-isolated BSP-to-worker command slot.
///
/// # Invariants
///
/// - `cmd` and `param0..param2` are written before `epoch` is published with `Release`.
/// - The worker reads `cmd`/params only after observing the new `epoch` with `Acquire`.
/// - `sample_*` and `probe_val` are written before `done_epoch` is published with `Release`.
#[repr(C, align(64))]
pub(crate) struct HartSlot {
    pub(crate) hart_id: AtomicUsize,
    pub(crate) cmd: AtomicUsize,
    pub(crate) epoch: AtomicUsize,
    pub(crate) param0: AtomicUsize,
    pub(crate) param1: AtomicUsize,
    pub(crate) param2: AtomicUsize,
    pub(crate) done_epoch: AtomicUsize,
    pub(crate) state: AtomicUsize,
    pub(crate) sample_cycles: AtomicU64,
    pub(crate) sample_instret: AtomicU64,
    pub(crate) sample_ticks: AtomicU64,
    pub(crate) sample_errors: AtomicUsize,
    pub(crate) probe_val: AtomicU64,
}

impl HartSlot {
    const fn new() -> Self {
        Self {
            hart_id: AtomicUsize::new(0),
            cmd: AtomicUsize::new(CMD_NONE),
            epoch: AtomicUsize::new(0),
            param0: AtomicUsize::new(0),
            param1: AtomicUsize::new(0),
            param2: AtomicUsize::new(0),
            done_epoch: AtomicUsize::new(0),
            state: AtomicUsize::new(WORKER_OFFLINE),
            sample_cycles: AtomicU64::new(0),
            sample_instret: AtomicU64::new(0),
            sample_ticks: AtomicU64::new(0),
            sample_errors: AtomicUsize::new(0),
            probe_val: AtomicU64::new(0),
        }
    }
}

static HART_SLOTS: SyncUnsafeCell<[HartSlot; MAX_HARTS]> =
    SyncUnsafeCell::new([const { HartSlot::new() }; MAX_HARTS]);
pub(crate) static READY_BARRIER: AtomicUsize = AtomicUsize::new(0);
pub(crate) static START_BARRIER: AtomicUsize = AtomicUsize::new(0);
pub(crate) static COUNTER_AVAIL_BITS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static SV39_CFG: SyncUnsafeCell<Option<Sv39Config>> = SyncUnsafeCell::new(None);

const _: () = assert!(align_of::<HartSlot>() == 64);
const _: () = assert!(size_of::<HartSlot>().is_multiple_of(64));
const _: () = assert!(MAX_HARTS == 64);

#[inline(always)]
pub(crate) fn slot_ref(slot_idx: usize) -> &'static HartSlot {
    assert!(slot_idx < MAX_HARTS, "worker slot index out of bounds");
    // SAFETY: `slot_idx < MAX_HARTS`, `HART_SLOTS` is `'static`, and each slot is cache-line aligned.
    unsafe { &(*HART_SLOTS.get())[slot_idx] }
}

/// Returns the hardware hart ID assigned to pool slot `slot_idx`.
pub(crate) fn slot_hart_id(slot_idx: usize) -> usize {
    slot_ref(slot_idx.min(MAX_HARTS - 1))
        .hart_id
        .load(Ordering::Relaxed)
}

/// Samples counters at batch entry safely from any worker or BSP using probed availability.
pub(crate) fn worker_snap_begin() -> CounterSnap {
    crate::platform::counters::snap_begin_with_mask(COUNTER_AVAIL_BITS.load(Ordering::Relaxed))
}

/// Samples counters at batch exit safely from any worker or BSP using probed availability.
pub(crate) fn worker_snap_end() -> CounterSnap {
    crate::platform::counters::snap_end_with_mask(COUNTER_AVAIL_BITS.load(Ordering::Relaxed))
}

/// Encodes a barrier epoch with cancellation clear.
pub(crate) const fn barrier_epoch(epoch: usize) -> usize {
    // INVARIANT: Wrapping the high bits is intentional; callers compare decoded epochs exactly.
    epoch.wrapping_shl(BARRIER_EPOCH_SHIFT as u32)
}

/// Encodes a barrier epoch with cancellation set.
pub(crate) const fn barrier_cancel(epoch: usize) -> usize {
    barrier_epoch(epoch) | BARRIER_CANCEL_BIT
}

/// Decodes `(epoch, cancelled)` from the barrier word.
pub(crate) const fn barrier_decode(raw: usize) -> (usize, bool) {
    (raw >> BARRIER_EPOCH_SHIFT, (raw & BARRIER_CANCEL_BIT) != 0)
}
