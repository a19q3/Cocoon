#![forbid(unsafe_code)]

//! Experimental fixture helpers for Cocoon tests.
//!
//! Current Redox/QEMU acceptance is driven by `xtask`. This crate stays small
//! until reusable fixture builders or QEMU harness helpers need a shared API.

pub mod fixture;

pub use fixture::*;
