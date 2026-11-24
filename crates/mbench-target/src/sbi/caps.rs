//! SBI base capability probing and extension bitmap construction.

use mbench_core::record::SbiExtensionId;

use super::{SbiRet, base, into_result};

/// Probed SBI base properties and available standard extension bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SbiCaps {
    pub(crate) spec_version: usize,
    pub(crate) impl_id: usize,
    pub(crate) impl_version: usize,
    pub(crate) mvendorid: usize,
    pub(crate) marchid: usize,
    pub(crate) mimpid: usize,
    pub(crate) base_probe_errors: u32,
    pub(crate) extensions: mbench_core::record::SbiCapMask,
}

impl SbiCaps {
    /// Queries Base extension info and probes all 16 SBI v3.0 standard extensions.
    pub(crate) fn probe() -> Self {
        let mut base_probe_errors = 0u32;
        let mut record_query = |ret: SbiRet| -> usize {
            match into_result(ret) {
                Ok(v) => v,
                Err(_) => {
                    base_probe_errors = base_probe_errors.saturating_add(1);
                    0
                }
            }
        };

        let spec_version = record_query(base::get_spec_version());
        let impl_id = record_query(base::get_impl_id());
        let impl_version = record_query(base::get_impl_version());
        let mvendorid = record_query(base::get_mvendorid());
        let marchid = record_query(base::get_marchid());
        let mimpid = record_query(base::get_mimpid());

        let mut extensions = mbench_core::record::SbiCapMask::BASE;
        for ext in SbiExtensionId::ALL {
            if ext == SbiExtensionId::Base {
                continue;
            }
            match into_result(base::probe_extension(ext.eid())) {
                Ok(val) if val != sbi_spec::base::UNAVAILABLE_EXTENSION => {
                    extensions.set_ext(ext);
                }
                Ok(_) => {}
                Err(_) => {
                    base_probe_errors = base_probe_errors.saturating_add(1);
                }
            }
        }

        Self {
            spec_version,
            impl_id,
            impl_version,
            mvendorid,
            marchid,
            mimpid,
            base_probe_errors,
            extensions,
        }
    }
}
