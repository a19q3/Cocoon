#![deny(unsafe_code)]

//! Runtime support for Cocoon service installation, receipts, status reporting,
//! Redox authority probes, FD-only launch evidence, and host-process service
//! supervision receipts.
//!
//! This crate owns the runtime-side evidence path. It does not implement a
//! package manager or namespace manager. Platforms that cannot provide Redox
//! namespace/fd authority report plan or smoke-only modes instead of claiming
//! runtime isolation.

pub mod authority;
mod fsutil;
pub mod install;
pub mod plan;
pub mod receipt;
pub mod run;
pub mod status;
pub mod supervisor;

pub use authority::*;
pub use install::*;
pub use plan::*;
pub use receipt::*;
pub use run::*;
pub use status::*;
pub use supervisor::*;
