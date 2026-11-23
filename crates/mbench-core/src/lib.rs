//! Core measurement engine, functional conformance runner, ISA parser, and streaming protocol.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod config;
pub mod isa;
