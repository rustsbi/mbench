//! Allocation-free measurement, conformance checks, and SBI result serialization.
//!
//! The optional `std` feature adds capture parsing, auditing, and statistical comparisons.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::std_instead_of_core
)]

#[cfg(feature = "std")]
mod capture;

pub mod check;
pub mod config;
pub mod engine;
pub mod isa;
pub mod protocol;
pub mod record;
pub mod stats;
#[cfg(feature = "std")]
pub mod validate;
#[cfg(feature = "std")]
pub mod wire;
