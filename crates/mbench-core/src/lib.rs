//! Core measurement engine, functional conformance runner, ISA parser, and streaming protocol.
//!
//! By default this crate is `#![no_std]` and strictly `#![forbid(unsafe_code)]`, allowing the
//! statistical engine, ISA parser, and wire serializers to run directly inside the bare-metal
//! S-mode target and under host tests. Enabling the `std` feature adds serde-based wire frame
//! parsing and `anofox-statistics`-backed nonparametric hypothesis testing for `mbench-cli`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

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
