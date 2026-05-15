#![forbid(unsafe_code)]

//! Cocoon Runtime for RedoxOS.
//!
//! This crate is a placeholder for the Redox-specific runtime.
//! Phase P1 will implement:
//! - Capsule installation
//! - Namespace / scheme setup
//! - Process spawn
//! - Log capture
//! - Rollback support

pub mod install;
pub mod status;

pub use install::*;
pub use status::*;
