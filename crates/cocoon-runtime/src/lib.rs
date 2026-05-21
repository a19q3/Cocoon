#![deny(unsafe_code)]

//! Runtime support for Cocoon service installation, receipts, status reporting,
//! Redox authority probes, and FD-only launch evidence.
//!
//! This crate owns the runtime-side evidence path. It does not implement a
//! package manager, namespace manager, or service supervisor. Platforms that
//! cannot provide Redox namespace/fd authority report plan or smoke-only modes
//! instead of claiming runtime isolation.

pub mod authority;
mod fsutil;
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
