#![deny(unsafe_code)]

//! Cocoon Runtime for RedoxOS.
//!
//! This crate is a placeholder for the Redox-specific runtime.
//! Phase P1 will implement:
//! - Capsule installation
//! - Namespace / scheme setup
//! - Process spawn
//! - Log capture
//! - Rollback support

pub mod authority;
pub mod install;
pub mod plan;
pub mod receipt;
pub mod run;
pub mod status;

pub use authority::*;
pub use install::*;
pub use plan::*;
pub use receipt::*;
pub use run::*;
pub use status::*;
