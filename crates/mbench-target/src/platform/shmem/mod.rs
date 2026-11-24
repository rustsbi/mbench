//! Exclusively owned 4 KiB-aligned shared-memory pool, RAII leases, DBTR session, and security probes.
//!
//! The pool is a process-wide singleton. Child modules encapsulate registration ownership so
//! `unsafe` reasoning about concurrent firmware access stays inside this module boundary.

pub(super) const PAGE_SIZE: usize = 4096;

mod dbtr;
mod lease;
mod pmu;
mod pool;
mod security;

pub(crate) use dbtr::{
    DbtrAcquire, DbtrSession, dbtr_exec_target_addr, dbtr_scratch_addr, pick_match_trigger,
    probe_dbtr_exec_target, probe_dbtr_load_scratch,
};
pub(crate) use lease::{ShmemAcquire, ShmemLease};
pub(in crate::platform) use pmu::probe_pmu_event_get_info;
pub(crate) use pool::ShmemOwner;
pub(in crate::platform) use pool::ShmemPool;
pub(in crate::platform) use security::probe_security;
