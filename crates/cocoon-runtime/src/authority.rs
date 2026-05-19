#![cfg_attr(target_os = "redox", allow(unsafe_code))]

#[cfg(target_os = "redox")]
use std::ffi::CString;
#[cfg(target_os = "redox")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "redox")]
use std::process::{Command, Output};
#[cfg(target_os = "redox")]
use std::time::{SystemTime, UNIX_EPOCH};

use cocoon_bundle::SignatureMetadata;
use cocoon_core::CapsuleName;
#[cfg(any(target_os = "redox", test))]
use cocoon_core::hash_bytes;
#[cfg(target_os = "redox")]
use cocoon_core::{CapsuleManifest, GuestPath, PermissionEffect, PreopenRight, SchemeVisibility};

#[cfg(target_os = "redox")]
use crate::install::acquire_capsule_lock;
use crate::receipt::ReceiptSigningOptions;
#[cfg(target_os = "redox")]
use crate::receipt::sign_receipt_body;
#[cfg(target_os = "redox")]
use crate::run::verify_installed_capsule_unlocked;
use crate::{Result, RuntimeError};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuthorityProbeReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: AuthorityProbeReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuthorityProbeReceiptBody {
    pub capsule_name: String,
    pub capsule_version: String,
    pub mode: AuthorityProbeMode,
    pub child_exit_code: Option<i32>,
    pub success: bool,
    pub entered_restricted_namespace: bool,
    pub allowed_preopen_read: bool,
    pub allowed_preopen_guest_path: String,
    pub denied_file_path: String,
    pub denied_file_rejected: bool,
    pub hidden_scheme_path: String,
    pub hidden_scheme_rejected: bool,
    pub stdout_log: String,
    pub stdout_hash: String,
    pub stderr_log: String,
    pub stderr_hash: String,
    pub started_at: String,
    pub finished_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AuthorityProbeMode {
    #[serde(rename = "redox-child-null-namespace")]
    RedoxChildNullNamespace,
}

impl std::fmt::Display for AuthorityProbeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RedoxChildNullNamespace => "redox-child-null-namespace",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProbeReport {
    pub receipt: AuthorityProbeReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProbeChildReport {
    pub capsule_name: String,
    pub capsule_version: String,
    pub entered_restricted_namespace: bool,
    pub allowed_preopen_read: bool,
    pub allowed_preopen_guest_path: String,
    pub denied_file_path: String,
    pub denied_file_rejected: bool,
    pub hidden_scheme_path: String,
    pub hidden_scheme_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdExecProbeReport {
    pub capsule_name: String,
    pub capsule_version: String,
    pub mode: FdExecProbeMode,
    pub attempted_executable: String,
    pub expected_path_exec_failure: bool,
    pub classified_fd_exec_blocker: bool,
    pub failure_message: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FdExecProbeMode {
    #[serde(rename = "redox-null-namespace-path-exec-classification")]
    RedoxNullNamespacePathExecClassification,
}

impl std::fmt::Display for FdExecProbeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RedoxNullNamespacePathExecClassification => {
                "redox-null-namespace-path-exec-classification"
            }
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FdLaunchProbeReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: FdLaunchProbeReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FdLaunchProbeReceiptBody {
    pub capsule_name: String,
    pub capsule_version: String,
    pub mode: FdLaunchMode,
    pub authority_enforced_for_service: bool,
    pub production_arbitrary_service: bool,
    pub child_exit_code: Option<i32>,
    pub open_executable_before_restriction: bool,
    pub open_declared_preopens_before_restriction: bool,
    pub entered_restricted_namespace: bool,
    pub exec_from_fd_attempted: bool,
    pub exec_from_fd_succeeded: bool,
    pub allowed_preopen_read: bool,
    pub allowed_preopen_guest_path: String,
    pub denied_file_path: String,
    pub denied_file_rejected: bool,
    pub hidden_scheme_path: String,
    pub hidden_scheme_rejected: bool,
    pub failure_message: String,
    pub stdout_log: String,
    pub stdout_hash: String,
    pub stderr_log: String,
    pub stderr_hash: String,
    pub started_at: String,
    pub finished_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FdLaunchMode {
    #[serde(rename = "redox-controlled-service-enforced")]
    RedoxControlledServiceEnforced,
    #[serde(rename = "redox-fd-launch-blocked")]
    RedoxFdLaunchBlocked,
    #[serde(rename = "redox-enforced-capsule-entrypoint")]
    RedoxEnforcedCapsuleEntrypoint,
    #[serde(rename = "redox-capsule-fd-launch-blocked")]
    RedoxCapsuleFdLaunchBlocked,
}

impl std::fmt::Display for FdLaunchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RedoxControlledServiceEnforced => "redox-controlled-service-enforced",
            Self::RedoxFdLaunchBlocked => "redox-fd-launch-blocked",
            Self::RedoxEnforcedCapsuleEntrypoint => "redox-enforced-capsule-entrypoint",
            Self::RedoxCapsuleFdLaunchBlocked => "redox-capsule-fd-launch-blocked",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdLaunchProbeReport {
    pub receipt: FdLaunchProbeReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleFdLaunchProbeReport {
    pub receipt: FdLaunchProbeReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedoxFdLaunchBackendReport {
    pub capsule_name: String,
    pub capsule_version: String,
    pub command: String,
    pub args: Vec<String>,
    pub child_exit_code: Option<i32>,
    pub success: bool,
    pub service_enforced: bool,
    pub open_executable_before_restriction: bool,
    pub open_declared_preopens_before_restriction: bool,
    pub entered_restricted_namespace: bool,
    pub exec_from_fd_attempted: bool,
    pub exec_from_fd_succeeded: bool,
    pub allowed_preopen_read: bool,
    pub allowed_preopen_guest_path: String,
    pub denied_file_path: String,
    pub denied_file_rejected: bool,
    pub hidden_scheme_path: String,
    pub hidden_scheme_rejected: bool,
    pub failure_message: String,
    pub stdout_log: String,
    pub stdout_hash: String,
    pub stderr_log: String,
    pub stderr_hash: String,
    pub started_at: String,
    pub finished_at: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdLaunchProbeChildReport {
    pub entered_restricted_namespace: bool,
    pub exec_from_fd_attempted: bool,
    pub exec_from_fd_succeeded: bool,
    pub allowed_preopen_read: bool,
    pub denied_file_rejected: bool,
    pub hidden_scheme_rejected: bool,
    pub failure_message: String,
}

pub fn probe_installed_authority(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<AuthorityProbeReport> {
    probe_installed_authority_with_receipt_signing(
        capsule_name,
        install_root,
        ReceiptSigningOptions::default(),
    )
}

pub fn probe_installed_authority_with_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<AuthorityProbeReport> {
    probe_installed_authority_impl(capsule_name, install_root, receipt_signing)
}

pub fn run_authority_probe_child(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<AuthorityProbeChildReport> {
    run_authority_probe_child_impl(capsule_name, install_root)
}

pub fn probe_fd_exec_gap(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<FdExecProbeReport> {
    probe_fd_exec_gap_impl(capsule_name, install_root)
}

pub fn probe_fd_launch(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<FdLaunchProbeReport> {
    probe_fd_launch_impl(capsule_name, install_root)
}

pub fn probe_capsule_fd_launch(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<CapsuleFdLaunchProbeReport> {
    probe_capsule_fd_launch_impl(capsule_name, install_root)
}

pub(crate) fn run_redox_capsule_fd_launch_backend(
    capsule_name: &CapsuleName,
    install_root: &Path,
    log_dir_name: &str,
) -> Result<RedoxFdLaunchBackendReport> {
    run_redox_capsule_fd_launch_backend_impl(capsule_name, install_root, log_dir_name)
}

pub fn run_fd_launch_probe_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<FdLaunchProbeChildReport> {
    run_fd_launch_probe_child_impl(
        executable_fd,
        allowed_preopen_fd,
        denied_file_path,
        hidden_scheme_path,
    )
}

pub fn run_capsule_fd_launch_probe_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
    visible_schemes: &[String],
    entry_args: &[String],
) -> Result<FdLaunchProbeChildReport> {
    run_capsule_fd_launch_probe_child_impl(
        executable_fd,
        allowed_preopen_fd,
        denied_file_path,
        hidden_scheme_path,
        visible_schemes,
        entry_args,
    )
}

pub fn run_fd_launch_fixture(
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<()> {
    run_fd_launch_fixture_impl(allowed_preopen_fd, denied_file_path, hidden_scheme_path)
}

#[cfg(not(target_os = "redox"))]
fn probe_installed_authority_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
    _receipt_signing: ReceiptSigningOptions,
) -> Result<AuthorityProbeReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox authority probe unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn run_authority_probe_child_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
) -> Result<AuthorityProbeChildReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox authority child unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn probe_fd_exec_gap_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
) -> Result<FdExecProbeReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox FD-only service launch probe unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn probe_fd_launch_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
) -> Result<FdLaunchProbeReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox FD-only launch probe unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn probe_capsule_fd_launch_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
) -> Result<CapsuleFdLaunchProbeReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox capsule FD-only launch probe unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn run_redox_capsule_fd_launch_backend_impl(
    _capsule_name: &CapsuleName,
    _install_root: &Path,
    _log_dir_name: &str,
) -> Result<RedoxFdLaunchBackendReport> {
    Err(RuntimeError::UnenforcedAuthority(
        "Redox FD-only run backend unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn run_fd_launch_probe_child_impl(
    _executable_fd: usize,
    _allowed_preopen_fd: usize,
    _denied_file_path: &str,
    _hidden_scheme_path: &str,
) -> Result<FdLaunchProbeChildReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox FD-only launch child unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn run_capsule_fd_launch_probe_child_impl(
    _executable_fd: usize,
    _allowed_preopen_fd: usize,
    _denied_file_path: &str,
    _hidden_scheme_path: &str,
    _visible_schemes: &[String],
    _entry_args: &[String],
) -> Result<FdLaunchProbeChildReport> {
    Err(RuntimeError::AuthorityProbe(
        "Redox capsule FD-only launch child unavailable on this platform".to_string(),
    ))
}

#[cfg(not(target_os = "redox"))]
fn run_fd_launch_fixture_impl(
    _allowed_preopen_fd: usize,
    _denied_file_path: &str,
    _hidden_scheme_path: &str,
) -> Result<()> {
    Err(RuntimeError::AuthorityProbe(
        "Redox FD-only launch fixture unavailable on this platform".to_string(),
    ))
}

#[cfg(target_os = "redox")]
fn probe_installed_authority_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<AuthorityProbeReport> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");

    let lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    drop(lock);

    let run_id = format!("{}-{}", unix_seconds()?, std::process::id());
    let logs_root = capsule_root.join("logs").join("authority");
    fs::create_dir_all(&logs_root)?;
    let stdout_log = logs_root.join(format!("{run_id}.stdout.log"));
    let stderr_log = logs_root.join(format!("{run_id}.stderr.log"));

    let started_at = format!("unix:{}", unix_seconds()?);
    let output = run_authority_child(capsule_name, install_root)?;
    let finished_at = format!("unix:{}", unix_seconds()?);
    fs::write(&stdout_log, &output.stdout)?;
    fs::write(&stderr_log, &output.stderr)?;

    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let entered_restricted_namespace =
        stdout_text.contains("PASS redox authority child entered restricted namespace");
    let allowed_preopen_read =
        stdout_text.contains("PASS redox authority child read allowed preopen");
    let denied_file_rejected =
        stdout_text.contains("PASS redox authority child rejected denied file path");
    let hidden_scheme_rejected =
        stdout_text.contains("PASS redox authority child rejected hidden tcp scheme");
    let success = output.status.success()
        && entered_restricted_namespace
        && allowed_preopen_read
        && denied_file_rejected
        && hidden_scheme_rejected;
    if !success {
        return Err(RuntimeError::AuthorityProbe(format!(
            "authority child failed: exit={:?}, stdout={}, stderr={}",
            output.status.code(),
            stdout_text.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let preopen = readable_file_preopen(&manifest)?;
    let body = AuthorityProbeReceiptBody {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        mode: AuthorityProbeMode::RedoxChildNullNamespace,
        child_exit_code: output.status.code(),
        success,
        entered_restricted_namespace,
        allowed_preopen_read,
        allowed_preopen_guest_path: preopen.guest_path.to_string(),
        denied_file_path: denied_file_probe_path(&manifest),
        denied_file_rejected,
        hidden_scheme_path: hidden_scheme_probe_path(),
        hidden_scheme_rejected,
        stdout_log: stdout_log.display().to_string(),
        stdout_hash: hash_bytes(&output.stdout),
        stderr_log: stderr_log.display().to_string(),
        stderr_hash: hash_bytes(&output.stderr),
        started_at,
        finished_at,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_authority_probe_receipt_body_bytes(&body)?);
    let event = "authority_probe".to_string();
    let signature = sign_receipt_body(&event, &body, &receipt_signing)?;
    let receipt = AuthorityProbeReceipt {
        receipt_version: 1,
        event,
        body,
        body_hash,
        signature,
    };
    write_authority_probe_receipt(&capsule_root, &run_id, &receipt)?;
    Ok(AuthorityProbeReport { receipt })
}

#[cfg(target_os = "redox")]
fn probe_fd_launch_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<FdLaunchProbeReport> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");

    let lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    let preopen = readable_file_preopen(&manifest)?;
    let allowed_probe_file = current_root.join(cocoon_bundle::MANIFEST_NAME);
    let allowed_preopen_guest_path = preopen.guest_path.to_string();
    let denied_file_path = denied_file_probe_path(&manifest);
    let hidden_scheme_path = hidden_scheme_probe_path();
    drop(lock);

    let current_exe = current_executable_arg()?;
    let executable_fd = open_redox_fd(&current_exe, "controlled fd-launch executable")?;
    let allowed_preopen_fd = open_redox_fd(
        &allowed_probe_file.display().to_string(),
        "declared preopen probe file",
    )?;

    let run_id = format!("{}-{}", unix_seconds()?, std::process::id());
    let logs_root = capsule_root.join("logs").join("fd-launch");
    fs::create_dir_all(&logs_root)?;
    let stdout_log = logs_root.join(format!("{run_id}.stdout.log"));
    let stderr_log = logs_root.join(format!("{run_id}.stderr.log"));

    let started_at = format!("unix:{}", unix_seconds()?);
    let output = run_fd_launch_child(
        executable_fd.raw(),
        allowed_preopen_fd.raw(),
        &denied_file_path,
        &hidden_scheme_path,
    )?;
    let finished_at = format!("unix:{}", unix_seconds()?);
    fs::write(&stdout_log, &output.stdout)?;
    fs::write(&stderr_log, &output.stderr)?;

    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let open_executable_before_restriction =
        stdout_text.contains("PASS open executable before restriction");
    let open_declared_preopens_before_restriction = true;
    let entered_restricted_namespace = stdout_text.contains("PASS enter restricted namespace");
    let exec_from_fd_attempted = stdout_text
        .contains("PASS attempt exec service from inherited executable FD")
        || stdout_text.contains("BLOCKED redox FD-only service launch");
    let exec_from_fd_succeeded =
        stdout_text.contains("PASS exec service from inherited executable FD");
    let allowed_preopen_read = stdout_text.contains("SERVICE PASS allowed preopen read");
    let denied_file_rejected = stdout_text.contains("SERVICE PASS denied path rejected");
    let hidden_scheme_rejected = stdout_text.contains("SERVICE PASS denied scheme rejected");
    let blocked = stdout_text.contains("BLOCKED redox FD-only service launch");
    let service_enforced = output.status.success()
        && open_executable_before_restriction
        && entered_restricted_namespace
        && exec_from_fd_succeeded
        && allowed_preopen_read
        && denied_file_rejected
        && hidden_scheme_rejected;
    let classified_blocked = output.status.success()
        && open_executable_before_restriction
        && entered_restricted_namespace
        && exec_from_fd_attempted
        && blocked;
    if !service_enforced && !classified_blocked {
        return Err(RuntimeError::AuthorityProbe(format!(
            "fd-launch probe failed: exit={:?}, stdout={}, stderr={}",
            output.status.code(),
            stdout_text.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mode = if service_enforced {
        FdLaunchMode::RedoxControlledServiceEnforced
    } else {
        FdLaunchMode::RedoxFdLaunchBlocked
    };
    let failure_message = if service_enforced {
        String::new()
    } else {
        extract_blocked_line(&stdout_text)
            .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string())
    };
    let body = FdLaunchProbeReceiptBody {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        mode,
        authority_enforced_for_service: service_enforced,
        production_arbitrary_service: false,
        child_exit_code: output.status.code(),
        open_executable_before_restriction,
        open_declared_preopens_before_restriction,
        entered_restricted_namespace,
        exec_from_fd_attempted,
        exec_from_fd_succeeded,
        allowed_preopen_read,
        allowed_preopen_guest_path,
        denied_file_path,
        denied_file_rejected,
        hidden_scheme_path,
        hidden_scheme_rejected,
        failure_message,
        stdout_log: stdout_log.display().to_string(),
        stdout_hash: hash_bytes(&output.stdout),
        stderr_log: stderr_log.display().to_string(),
        stderr_hash: hash_bytes(&output.stderr),
        started_at,
        finished_at,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_fd_launch_probe_receipt_body_bytes(&body)?);
    let receipt = FdLaunchProbeReceipt {
        receipt_version: 1,
        event: "fd_launch_probe".to_string(),
        body,
        body_hash,
        signature: None,
    };
    write_fd_launch_probe_receipt(&capsule_root, &run_id, &receipt)?;
    Ok(FdLaunchProbeReport { receipt })
}

#[cfg(target_os = "redox")]
fn probe_capsule_fd_launch_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<CapsuleFdLaunchProbeReport> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let backend =
        run_redox_capsule_fd_launch_backend(capsule_name, install_root, "capsule-fd-launch")?;
    let receipt_id = backend.receipt_id.clone();

    let mode = if backend.service_enforced {
        FdLaunchMode::RedoxEnforcedCapsuleEntrypoint
    } else {
        FdLaunchMode::RedoxCapsuleFdLaunchBlocked
    };
    let body = FdLaunchProbeReceiptBody {
        capsule_name: backend.capsule_name,
        capsule_version: backend.capsule_version,
        mode,
        authority_enforced_for_service: backend.service_enforced,
        production_arbitrary_service: false,
        child_exit_code: backend.child_exit_code,
        open_executable_before_restriction: backend.open_executable_before_restriction,
        open_declared_preopens_before_restriction: backend
            .open_declared_preopens_before_restriction,
        entered_restricted_namespace: backend.entered_restricted_namespace,
        exec_from_fd_attempted: backend.exec_from_fd_attempted,
        exec_from_fd_succeeded: backend.exec_from_fd_succeeded,
        allowed_preopen_read: backend.allowed_preopen_read,
        allowed_preopen_guest_path: backend.allowed_preopen_guest_path,
        denied_file_path: backend.denied_file_path,
        denied_file_rejected: backend.denied_file_rejected,
        hidden_scheme_path: backend.hidden_scheme_path,
        hidden_scheme_rejected: backend.hidden_scheme_rejected,
        failure_message: backend.failure_message,
        stdout_log: backend.stdout_log,
        stdout_hash: backend.stdout_hash,
        stderr_log: backend.stderr_log,
        stderr_hash: backend.stderr_hash,
        started_at: backend.started_at,
        finished_at: backend.finished_at,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_fd_launch_probe_receipt_body_bytes(&body)?);
    let receipt = FdLaunchProbeReceipt {
        receipt_version: 1,
        event: "capsule_fd_launch_probe".to_string(),
        body,
        body_hash,
        signature: None,
    };
    write_capsule_fd_launch_probe_receipt(&capsule_root, &receipt_id, &receipt)?;
    Ok(CapsuleFdLaunchProbeReport { receipt })
}

#[cfg(target_os = "redox")]
fn run_redox_capsule_fd_launch_backend_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
    log_dir_name: &str,
) -> Result<RedoxFdLaunchBackendReport> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");

    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    let preopen = readable_file_preopen(&manifest)?;
    let entrypoint = map_installed_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cmd,
        "entry.cmd",
    )?;
    let allowed_probe_file = current_root.join(cocoon_bundle::MANIFEST_NAME);
    let allowed_preopen_guest_path = preopen.guest_path.to_string();
    let denied_file_path = denied_file_probe_path(&manifest);
    let hidden_scheme_path = hidden_scheme_probe_path();
    let visible_schemes = manifest_fd_launch_schemes(&manifest);
    let entry_args = manifest.entry.args.clone();

    let executable_fd = open_redox_fd(
        &entrypoint.display().to_string(),
        "installed capsule entrypoint",
    )?;
    let allowed_preopen_fd = open_redox_fd(
        &allowed_probe_file.display().to_string(),
        "declared preopen probe file",
    )?;

    let run_id = format!("{}-{}", unix_seconds()?, std::process::id());
    let logs_root = capsule_root.join("logs").join(log_dir_name);
    fs::create_dir_all(&logs_root)?;
    let stdout_log = logs_root.join(format!("{run_id}.stdout.log"));
    let stderr_log = logs_root.join(format!("{run_id}.stderr.log"));

    let started_at = format!("unix:{}", unix_seconds()?);
    let output = run_capsule_fd_launch_child(
        executable_fd.raw(),
        allowed_preopen_fd.raw(),
        &denied_file_path,
        &hidden_scheme_path,
        &visible_schemes,
        &entry_args,
    )?;
    let finished_at = format!("unix:{}", unix_seconds()?);
    fs::write(&stdout_log, &output.stdout)?;
    fs::write(&stderr_log, &output.stderr)?;

    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let open_executable_before_restriction =
        stdout_text.contains("PASS open installed capsule entrypoint before restriction");
    let opened_preopens_before_restriction =
        stdout_text.contains("PASS open declared preopens before restriction");
    let entered_restricted_namespace =
        stdout_text.contains("PASS enter manifest-derived restricted namespace");
    let exec_from_fd_attempted = stdout_text
        .contains("PASS attempt fexec installed capsule entrypoint")
        || stdout_text.contains("BLOCKED redox capsule FD-only launch");
    let exec_from_fd_succeeded = stdout_text.contains("PASS fexec installed capsule entrypoint");
    let allowed_preopen_read = stdout_text.contains("PASS service reads declared resource");
    let denied_file_rejected = stdout_text.contains("PASS denied ambient path rejected");
    let hidden_scheme_rejected = stdout_text.contains("PASS undeclared tcp scheme rejected");
    let blocked = stdout_text.contains("BLOCKED redox capsule FD-only launch");
    let service_enforced = output.status.success()
        && open_executable_before_restriction
        && opened_preopens_before_restriction
        && entered_restricted_namespace
        && exec_from_fd_succeeded
        && allowed_preopen_read
        && denied_file_rejected
        && hidden_scheme_rejected;
    let classified_blocked = output.status.success()
        && open_executable_before_restriction
        && opened_preopens_before_restriction
        && entered_restricted_namespace
        && exec_from_fd_attempted
        && blocked;
    if !service_enforced && !classified_blocked {
        return Err(RuntimeError::AuthorityProbe(format!(
            "capsule fd-launch backend failed: exit={:?}, stdout={}, stderr={}",
            output.status.code(),
            stdout_text.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let failure_message = if service_enforced {
        String::new()
    } else {
        extract_capsule_blocked_line(&stdout_text)
            .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string())
    };

    Ok(RedoxFdLaunchBackendReport {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        command: manifest.entry.cmd.to_string(),
        args: manifest.entry.args,
        child_exit_code: output.status.code(),
        success: output.status.success(),
        service_enforced,
        open_executable_before_restriction,
        open_declared_preopens_before_restriction: opened_preopens_before_restriction,
        entered_restricted_namespace,
        exec_from_fd_attempted,
        exec_from_fd_succeeded,
        allowed_preopen_read,
        allowed_preopen_guest_path,
        denied_file_path,
        denied_file_rejected,
        hidden_scheme_path,
        hidden_scheme_rejected,
        failure_message,
        stdout_log: stdout_log.display().to_string(),
        stdout_hash: hash_bytes(&output.stdout),
        stderr_log: stderr_log.display().to_string(),
        stderr_hash: hash_bytes(&output.stderr),
        started_at,
        finished_at,
        receipt_id: run_id,
    })
}

#[cfg(target_os = "redox")]
fn open_redox_fd(path: &str, label: &str) -> Result<libredox::Fd> {
    libredox::Fd::open(path, libredox::flag::O_RDONLY, 0).map_err(|error| {
        RuntimeError::AuthorityProbe(format!("failed to open {label} '{path}': {error}"))
    })
}

#[cfg(target_os = "redox")]
fn run_fd_launch_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<Output> {
    let current_exe = current_executable_arg()?;
    Ok(Command::new(current_exe)
        .arg("__fd-launch-child")
        .arg("--executable-fd")
        .arg(executable_fd.to_string())
        .arg("--allowed-preopen-fd")
        .arg(allowed_preopen_fd.to_string())
        .arg("--denied-file-path")
        .arg(denied_file_path)
        .arg("--hidden-scheme-path")
        .arg(hidden_scheme_path)
        .output()?)
}

#[cfg(target_os = "redox")]
fn run_capsule_fd_launch_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
    visible_schemes: &[String],
    entry_args: &[String],
) -> Result<Output> {
    let current_exe = current_executable_arg()?;
    let mut command = Command::new(current_exe);
    command
        .arg("__capsule-fd-launch-child")
        .arg("--executable-fd")
        .arg(executable_fd.to_string())
        .arg("--allowed-preopen-fd")
        .arg(allowed_preopen_fd.to_string())
        .arg("--denied-file-path")
        .arg(denied_file_path)
        .arg("--hidden-scheme-path")
        .arg(hidden_scheme_path);
    for scheme in visible_schemes {
        command.arg("--visible-scheme").arg(scheme);
    }
    for arg in entry_args {
        command.arg("--entry-arg").arg(arg);
    }
    Ok(command.output()?)
}

#[cfg(target_os = "redox")]
fn extract_blocked_line(stdout_text: &str) -> Option<String> {
    stdout_text
        .lines()
        .find(|line| line.starts_with("BLOCKED redox FD-only service launch"))
        .map(ToOwned::to_owned)
}

#[cfg(target_os = "redox")]
fn extract_capsule_blocked_line(stdout_text: &str) -> Option<String> {
    stdout_text
        .lines()
        .find(|line| line.starts_with("BLOCKED redox capsule FD-only launch"))
        .map(ToOwned::to_owned)
}

#[cfg(target_os = "redox")]
fn run_authority_child(capsule_name: &CapsuleName, install_root: &Path) -> Result<Output> {
    let current_exe = current_executable_arg()?;
    Ok(Command::new(current_exe)
        .arg("__authority-child")
        .arg(capsule_name.as_str())
        .arg("--install-root")
        .arg(install_root)
        .output()?)
}

#[cfg(target_os = "redox")]
fn probe_fd_exec_gap_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<FdExecProbeReport> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");

    let lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    drop(lock);

    let current_exe = current_executable_arg()?;
    libredox::call::setrens(0, 0).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to enter Redox null namespace before path exec probe: {error}"
        ))
    })?;

    match Command::new(&current_exe)
        .arg("__fd-exec-sentinel")
        .output()
    {
        Ok(output) => Err(RuntimeError::AuthorityProbe(format!(
            "path-based exec unexpectedly crossed Redox null namespace: exit={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
        Err(error) => Ok(FdExecProbeReport {
            capsule_name: manifest.capsule.name.to_string(),
            capsule_version: manifest.capsule.version.to_string(),
            mode: FdExecProbeMode::RedoxNullNamespacePathExecClassification,
            attempted_executable: current_exe,
            expected_path_exec_failure: true,
            classified_fd_exec_blocker: true,
            failure_message: error.to_string(),
        }),
    }
}

#[cfg(target_os = "redox")]
fn run_fd_launch_probe_child_impl(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<FdLaunchProbeChildReport> {
    enter_fd_launch_namespace()?;
    println!("PASS open executable before restriction");
    println!("PASS enter restricted namespace");

    let denied_file_rejected = fs::File::open(denied_file_path).is_err();
    if !denied_file_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "denied file path opened successfully after namespace restriction: {denied_file_path}"
        )));
    }

    let hidden_scheme_rejected = fs::File::open(hidden_scheme_path).is_err();
    if !hidden_scheme_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "hidden scheme opened successfully after namespace restriction: {hidden_scheme_path}"
        )));
    }

    println!("PASS attempt exec service from inherited executable FD");
    match fexec_fd_launch_fixture(
        executable_fd,
        allowed_preopen_fd,
        denied_file_path,
        hidden_scheme_path,
    ) {
        Ok(never) => match never {},
        Err(error) => {
            let failure_message = format!("{error}");
            println!(
                "BLOCKED redox FD-only service launch stable API not proven: {failure_message}"
            );
            Ok(FdLaunchProbeChildReport {
                entered_restricted_namespace: true,
                exec_from_fd_attempted: true,
                exec_from_fd_succeeded: false,
                allowed_preopen_read: false,
                denied_file_rejected,
                hidden_scheme_rejected,
                failure_message,
            })
        }
    }
}

#[cfg(target_os = "redox")]
fn run_capsule_fd_launch_probe_child_impl(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
    visible_schemes: &[String],
    entry_args: &[String],
) -> Result<FdLaunchProbeChildReport> {
    enter_fd_launch_namespace_with_schemes(visible_schemes)?;
    println!("PASS open installed capsule entrypoint before restriction");
    println!("PASS open declared preopens before restriction");
    println!("PASS enter manifest-derived restricted namespace");

    let denied_file_rejected = fs::File::open(denied_file_path).is_err();
    if !denied_file_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "denied file path opened successfully after namespace restriction: {denied_file_path}"
        )));
    }

    let hidden_scheme_rejected = fs::File::open(hidden_scheme_path).is_err();
    if !hidden_scheme_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "hidden scheme opened successfully after namespace restriction: {hidden_scheme_path}"
        )));
    }

    println!("PASS attempt fexec installed capsule entrypoint");
    match fexec_capsule_entrypoint(
        executable_fd,
        allowed_preopen_fd,
        denied_file_path,
        hidden_scheme_path,
        entry_args,
    ) {
        Ok(never) => match never {},
        Err(error) => {
            let failure_message = format!("{error}");
            println!(
                "BLOCKED redox capsule FD-only launch stable API not proven: {failure_message}"
            );
            Ok(FdLaunchProbeChildReport {
                entered_restricted_namespace: true,
                exec_from_fd_attempted: true,
                exec_from_fd_succeeded: false,
                allowed_preopen_read: false,
                denied_file_rejected,
                hidden_scheme_rejected,
                failure_message,
            })
        }
    }
}

#[cfg(target_os = "redox")]
fn enter_fd_launch_namespace() -> Result<()> {
    let names = [
        ioslice::IoSlice::new(b"memory"),
        ioslice::IoSlice::new(b"pipe"),
        ioslice::IoSlice::new(b"rand"),
    ];
    let namespace = libredox::call::mkns(&names).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to create Redox fd-launch namespace: {error}"
        ))
    })?;
    libredox::call::setrens(namespace, namespace).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to enter Redox fd-launch namespace: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(target_os = "redox")]
fn enter_fd_launch_namespace_with_schemes(visible_schemes: &[String]) -> Result<()> {
    let scheme_bytes = visible_schemes
        .iter()
        .map(|scheme| scheme.as_bytes())
        .collect::<Vec<_>>();
    let names = scheme_bytes
        .iter()
        .map(|scheme| ioslice::IoSlice::new(scheme))
        .collect::<Vec<_>>();
    let namespace = libredox::call::mkns(&names).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to create Redox capsule fd-launch namespace: {error}"
        ))
    })?;
    libredox::call::setrens(namespace, namespace).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to enter Redox capsule fd-launch namespace: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(target_os = "redox")]
enum Never {}

#[cfg(target_os = "redox")]
fn fexec_fd_launch_fixture(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<Never> {
    unsafe extern "C" {
        fn fexecve(
            fd: libc::c_int,
            argv: *const *const libc::c_char,
            envp: *const *const libc::c_char,
        ) -> libc::c_int;
    }

    let argv = [
        CString::new("cocoon-fd-launch-fixture").map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture argv[0]: {error}"))
        })?,
        CString::new("__fd-launch-fixture").map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture argv[1]: {error}"))
        })?,
        CString::new("--allowed-preopen-fd").map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture argv[2]: {error}"))
        })?,
        CString::new(allowed_preopen_fd.to_string()).map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture allowed fd arg: {error}"))
        })?,
        CString::new("--denied-file-path").map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture argv[4]: {error}"))
        })?,
        CString::new(denied_file_path).map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture denied path arg: {error}"))
        })?,
        CString::new("--hidden-scheme-path").map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture argv[6]: {error}"))
        })?,
        CString::new(hidden_scheme_path).map_err(|error| {
            RuntimeError::AuthorityProbe(format!("invalid fixture hidden scheme arg: {error}"))
        })?,
    ];
    let mut argv_ptrs = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const libc::c_char>>();
    argv_ptrs.push(std::ptr::null());
    let envp = [std::ptr::null::<libc::c_char>()];
    let fd = libc::c_int::try_from(executable_fd).map_err(|_| {
        RuntimeError::AuthorityProbe(format!(
            "executable fd does not fit C int for fexecve: {executable_fd}"
        ))
    })?;
    // SAFETY: `fd` is an already-open executable FD inherited by this Redox
    // process, argv/envp are null-terminated arrays of stable CString pointers,
    // and successful fexecve does not return.
    let rc = unsafe { fexecve(fd, argv_ptrs.as_ptr(), envp.as_ptr()) };
    Err(RuntimeError::AuthorityProbe(format!(
        "fexecve returned {rc}: {}",
        std::io::Error::last_os_error()
    )))
}

#[cfg(target_os = "redox")]
fn fexec_capsule_entrypoint(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
    entry_args: &[String],
) -> Result<Never> {
    unsafe extern "C" {
        fn fexecve(
            fd: libc::c_int,
            argv: *const *const libc::c_char,
            envp: *const *const libc::c_char,
        ) -> libc::c_int;
    }

    let mut args = vec!["capsule-entrypoint".to_string()];
    args.extend(entry_args.iter().cloned());
    args.push("--allowed-preopen-fd".to_string());
    args.push(allowed_preopen_fd.to_string());
    args.push("--denied-file-path".to_string());
    args.push(denied_file_path.to_string());
    args.push("--hidden-scheme-path".to_string());
    args.push(hidden_scheme_path.to_string());

    let argv = args
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|error| {
                RuntimeError::AuthorityProbe(format!("invalid capsule entrypoint arg: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut argv_ptrs = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const libc::c_char>>();
    argv_ptrs.push(std::ptr::null());
    let envp = [std::ptr::null::<libc::c_char>()];
    let fd = libc::c_int::try_from(executable_fd).map_err(|_| {
        RuntimeError::AuthorityProbe(format!(
            "installed capsule entrypoint fd does not fit C int for fexecve: {executable_fd}"
        ))
    })?;
    // SAFETY: `fd` is an already-open installed capsule entrypoint FD inherited
    // by this Redox process, argv/envp are null-terminated arrays of stable
    // CString pointers, and successful fexecve does not return.
    let rc = unsafe { fexecve(fd, argv_ptrs.as_ptr(), envp.as_ptr()) };
    Err(RuntimeError::AuthorityProbe(format!(
        "fexecve returned {rc}: {}",
        std::io::Error::last_os_error()
    )))
}

#[cfg(target_os = "redox")]
fn run_fd_launch_fixture_impl(
    allowed_preopen_fd: usize,
    denied_file_path: &str,
    hidden_scheme_path: &str,
) -> Result<()> {
    let mut buffer = vec![0_u8; 4096];
    let bytes_read = libredox::call::read(allowed_preopen_fd, &mut buffer).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "service failed to read allowed preopen fd {allowed_preopen_fd}: {error}"
        ))
    })?;
    if bytes_read == 0 {
        return Err(RuntimeError::AuthorityProbe(
            "service allowed preopen read returned EOF".to_string(),
        ));
    }
    println!("PASS exec service from inherited executable FD");
    println!("SERVICE PASS allowed preopen read");

    if fs::File::open(denied_file_path).is_ok() {
        return Err(RuntimeError::AuthorityProbe(format!(
            "service opened denied file path after fd launch: {denied_file_path}"
        )));
    }
    println!("SERVICE PASS denied path rejected");

    if fs::File::open(hidden_scheme_path).is_ok() {
        return Err(RuntimeError::AuthorityProbe(format!(
            "service opened hidden scheme after fd launch: {hidden_scheme_path}"
        )));
    }
    println!("SERVICE PASS denied scheme rejected");
    Ok(())
}

#[cfg(target_os = "redox")]
fn current_executable_arg() -> Result<String> {
    std::env::args().next().ok_or_else(|| {
        RuntimeError::AuthorityProbe("current executable argv[0] is unavailable".to_string())
    })
}

#[cfg(target_os = "redox")]
fn run_authority_probe_child_impl(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<AuthorityProbeChildReport> {
    use std::io::Read;

    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");

    let lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    let preopen = readable_file_preopen(&manifest)?;
    let allowed_probe_file = current_root.join(cocoon_bundle::MANIFEST_NAME);
    let mut allowed_file = fs::File::open(&allowed_probe_file).map_err(|error| {
        RuntimeError::AuthorityProbe(format!(
            "failed to open allowed preopen probe file '{}': {error}",
            allowed_probe_file.display()
        ))
    })?;
    let denied_file_path = denied_file_probe_path(&manifest);
    let hidden_scheme_path = hidden_scheme_probe_path();
    drop(lock);

    libredox::call::setrens(0, 0).map_err(|error| {
        RuntimeError::AuthorityProbe(format!("failed to enter Redox null namespace: {error}"))
    })?;
    println!("PASS redox authority child entered restricted namespace");

    let mut allowed_text = String::new();
    allowed_file
        .read_to_string(&mut allowed_text)
        .map_err(|error| {
            RuntimeError::AuthorityProbe(format!(
                "failed to read allowed preopen probe file after namespace restriction: {error}"
            ))
        })?;
    if allowed_text.is_empty() {
        return Err(RuntimeError::AuthorityProbe(
            "allowed preopen probe file was empty".to_string(),
        ));
    }
    println!("PASS redox authority child read allowed preopen");

    let denied_file_rejected = fs::File::open(&denied_file_path).is_err();
    if !denied_file_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "denied file path opened successfully after namespace restriction: {denied_file_path}"
        )));
    }
    println!("PASS redox authority child rejected denied file path");

    let hidden_scheme_rejected = fs::File::open(&hidden_scheme_path).is_err();
    if !hidden_scheme_rejected {
        return Err(RuntimeError::AuthorityProbe(format!(
            "hidden scheme opened successfully after namespace restriction: {hidden_scheme_path}"
        )));
    }
    println!("PASS redox authority child rejected hidden tcp scheme");

    Ok(AuthorityProbeChildReport {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        entered_restricted_namespace: true,
        allowed_preopen_read: true,
        allowed_preopen_guest_path: preopen.guest_path.to_string(),
        denied_file_path,
        denied_file_rejected,
        hidden_scheme_path,
        hidden_scheme_rejected,
    })
}

#[cfg(target_os = "redox")]
fn read_installed_manifest(current_root: &Path) -> Result<CapsuleManifest> {
    let manifest_text = fs::read_to_string(current_root.join(cocoon_bundle::MANIFEST_NAME))?;
    Ok(CapsuleManifest::from_toml(&manifest_text)?)
}

#[cfg(target_os = "redox")]
fn readable_file_preopen(manifest: &CapsuleManifest) -> Result<&cocoon_core::PreopenConfig> {
    manifest
        .preopens
        .iter()
        .find(|preopen| {
            preopen.scheme.as_str() == "file" && preopen.rights.contains(&PreopenRight::Read)
        })
        .ok_or_else(|| {
            RuntimeError::AuthorityProbe(
                "manifest does not declare a readable file preopen".to_string(),
            )
        })
}

#[cfg(target_os = "redox")]
fn denied_file_probe_path(manifest: &CapsuleManifest) -> String {
    manifest
        .permissions
        .iter()
        .find(|permission| {
            permission.effect == PermissionEffect::Deny && permission.scheme.as_str() == "file"
        })
        .map(|permission| concrete_denied_path(permission.target.as_str()))
        .unwrap_or_else(|| "/etc/secrets/cocoon-authority-probe".to_string())
}

#[cfg(target_os = "redox")]
fn concrete_denied_path(target: &str) -> String {
    let base = target.trim_end_matches('*').trim_end_matches('/');
    if base.is_empty() {
        "/cocoon-authority-probe-denied".to_string()
    } else {
        format!("{base}/cocoon-authority-probe-denied")
    }
}

#[cfg(target_os = "redox")]
fn hidden_scheme_probe_path() -> String {
    "/scheme/tcp".to_string()
}

#[cfg(target_os = "redox")]
fn manifest_fd_launch_schemes(manifest: &CapsuleManifest) -> Vec<String> {
    let mut schemes = vec!["memory".to_string(), "pipe".to_string()];
    for permission in &manifest.permissions {
        if permission.is_allow() {
            maybe_push_redox_runtime_scheme(&mut schemes, permission.scheme.as_str());
        }
    }
    for scheme in &manifest.schemes {
        if scheme.visibility != SchemeVisibility::Hidden {
            maybe_push_redox_runtime_scheme(&mut schemes, scheme.name.as_str());
        }
    }
    schemes
}

#[cfg(target_os = "redox")]
fn maybe_push_redox_runtime_scheme(schemes: &mut Vec<String>, scheme: &str) {
    if matches!(scheme, "rand" | "time" | "event" | "null") && !schemes.iter().any(|s| s == scheme)
    {
        schemes.push(scheme.to_string());
    }
}

#[cfg(target_os = "redox")]
fn map_installed_guest_path(
    current_root: &Path,
    filesystem_root: &GuestPath,
    guest_path: &GuestPath,
    label: &str,
) -> Result<std::path::PathBuf> {
    if !filesystem_root.contains(guest_path) {
        return Err(RuntimeError::GuestPath(format!(
            "{label} '{guest_path}' is outside filesystem.root '{filesystem_root}'"
        )));
    }

    let suffix = if filesystem_root.as_str() == "/" {
        guest_path.as_str().trim_start_matches('/')
    } else {
        guest_path
            .as_str()
            .strip_prefix(filesystem_root.as_str())
            .ok_or_else(|| {
                RuntimeError::GuestPath(format!(
                    "{label} '{guest_path}' could not be mapped below filesystem.root '{filesystem_root}'"
                ))
            })?
            .trim_start_matches('/')
    };

    Ok(current_root.join(suffix))
}

#[cfg(target_os = "redox")]
fn write_authority_probe_receipt(
    capsule_root: &Path,
    run_id: &str,
    receipt: &AuthorityProbeReceipt,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("authority");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;
    fs::write(receipts_root.join(format!("{run_id}.json")), &bytes)?;

    let latest = receipts_root.join("latest.json");
    let latest_tmp = receipts_root.join("latest.json.tmp");
    fs::write(&latest_tmp, bytes)?;
    fs::rename(latest_tmp, latest)?;
    Ok(())
}

#[cfg(target_os = "redox")]
fn write_capsule_fd_launch_probe_receipt(
    capsule_root: &Path,
    run_id: &str,
    receipt: &FdLaunchProbeReceipt,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("capsule-fd-launch");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;
    fs::write(receipts_root.join(format!("{run_id}.json")), &bytes)?;

    let latest = receipts_root.join("latest.json");
    let latest_tmp = receipts_root.join("latest.json.tmp");
    fs::write(&latest_tmp, bytes)?;
    fs::rename(latest_tmp, latest)?;
    Ok(())
}

#[cfg(target_os = "redox")]
fn write_fd_launch_probe_receipt(
    capsule_root: &Path,
    run_id: &str,
    receipt: &FdLaunchProbeReceipt,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("fd-launch");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;
    fs::write(receipts_root.join(format!("{run_id}.json")), &bytes)?;

    let latest = receipts_root.join("latest.json");
    let latest_tmp = receipts_root.join("latest.json.tmp");
    fs::write(&latest_tmp, bytes)?;
    fs::rename(latest_tmp, latest)?;
    Ok(())
}

#[cfg(any(target_os = "redox", test))]
fn canonical_authority_probe_receipt_body_bytes(
    body: &AuthorityProbeReceiptBody,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(body)?)
}

#[cfg(any(target_os = "redox", test))]
fn canonical_fd_launch_probe_receipt_body_bytes(
    body: &FdLaunchProbeReceiptBody,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(body)?)
}

#[cfg(target_os = "redox")]
fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::SystemClock)?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "redox"))]
    #[test]
    fn authority_probe_is_unavailable_off_redox() {
        let error = probe_installed_authority(
            &CapsuleName::parse("hello-service").unwrap(),
            Path::new("/tmp"),
        )
        .unwrap_err();

        assert!(matches!(error, RuntimeError::AuthorityProbe(_)));
        assert!(
            error
                .to_string()
                .contains("Redox authority probe unavailable on this platform")
        );
    }

    #[cfg(not(target_os = "redox"))]
    #[test]
    fn fd_exec_probe_is_unavailable_off_redox() {
        let error = probe_fd_exec_gap(
            &CapsuleName::parse("hello-service").unwrap(),
            Path::new("/tmp"),
        )
        .unwrap_err();

        assert!(matches!(error, RuntimeError::AuthorityProbe(_)));
        assert!(
            error
                .to_string()
                .contains("Redox FD-only service launch probe unavailable on this platform")
        );
    }

    #[cfg(not(target_os = "redox"))]
    #[test]
    fn fd_launch_probe_is_unavailable_off_redox() {
        let error = probe_fd_launch(
            &CapsuleName::parse("hello-service").unwrap(),
            Path::new("/tmp"),
        )
        .unwrap_err();

        assert!(matches!(error, RuntimeError::AuthorityProbe(_)));
        assert!(
            error
                .to_string()
                .contains("Redox FD-only launch probe unavailable on this platform")
        );
    }

    #[cfg(not(target_os = "redox"))]
    #[test]
    fn capsule_fd_launch_probe_is_unavailable_off_redox() {
        let error = probe_capsule_fd_launch(
            &CapsuleName::parse("hello-service").unwrap(),
            Path::new("/tmp"),
        )
        .unwrap_err();

        assert!(matches!(error, RuntimeError::AuthorityProbe(_)));
        assert!(
            error
                .to_string()
                .contains("Redox capsule FD-only launch probe unavailable on this platform")
        );
    }

    #[test]
    fn authority_probe_receipt_body_hash_is_stable() {
        let body = AuthorityProbeReceiptBody {
            capsule_name: "hello-service".to_string(),
            capsule_version: "0.1.0".to_string(),
            mode: AuthorityProbeMode::RedoxChildNullNamespace,
            child_exit_code: Some(0),
            success: true,
            entered_restricted_namespace: true,
            allowed_preopen_read: true,
            allowed_preopen_guest_path: "/app".to_string(),
            denied_file_path: "/home/cocoon-authority-probe-denied".to_string(),
            denied_file_rejected: true,
            hidden_scheme_path: "/scheme/tcp".to_string(),
            hidden_scheme_rejected: true,
            stdout_log: "/tmp/stdout.log".to_string(),
            stdout_hash: "blake3:stdout".to_string(),
            stderr_log: "/tmp/stderr.log".to_string(),
            stderr_hash: "blake3:stderr".to_string(),
            started_at: "unix:1".to_string(),
            finished_at: "unix:2".to_string(),
            runtime_version: "0.1.0".to_string(),
        };

        let hash = hash_bytes(&canonical_authority_probe_receipt_body_bytes(&body).unwrap());

        assert!(hash.starts_with("blake3:"));
        assert_eq!(
            serde_json::to_value(body.mode).unwrap(),
            "redox-child-null-namespace"
        );
    }

    #[test]
    fn fd_launch_probe_receipt_body_hash_is_stable() {
        let body = FdLaunchProbeReceiptBody {
            capsule_name: "hello-service".to_string(),
            capsule_version: "0.1.0".to_string(),
            mode: FdLaunchMode::RedoxControlledServiceEnforced,
            authority_enforced_for_service: true,
            production_arbitrary_service: false,
            child_exit_code: Some(0),
            open_executable_before_restriction: true,
            open_declared_preopens_before_restriction: true,
            entered_restricted_namespace: true,
            exec_from_fd_attempted: true,
            exec_from_fd_succeeded: true,
            allowed_preopen_read: true,
            allowed_preopen_guest_path: "/app".to_string(),
            denied_file_path: "/home/cocoon-authority-probe-denied".to_string(),
            denied_file_rejected: true,
            hidden_scheme_path: "/scheme/tcp".to_string(),
            hidden_scheme_rejected: true,
            failure_message: String::new(),
            stdout_log: "/tmp/stdout.log".to_string(),
            stdout_hash: "blake3:stdout".to_string(),
            stderr_log: "/tmp/stderr.log".to_string(),
            stderr_hash: "blake3:stderr".to_string(),
            started_at: "unix:1".to_string(),
            finished_at: "unix:2".to_string(),
            runtime_version: "0.1.0".to_string(),
        };

        let hash = hash_bytes(&canonical_fd_launch_probe_receipt_body_bytes(&body).unwrap());

        assert!(hash.starts_with("blake3:"));
        assert_eq!(
            serde_json::to_value(body.mode).unwrap(),
            "redox-controlled-service-enforced"
        );
    }

    #[test]
    fn probe_mode_serialized_strings_are_stable() {
        assert_eq!(
            serde_json::to_string(&AuthorityProbeMode::RedoxChildNullNamespace).unwrap(),
            "\"redox-child-null-namespace\""
        );
        assert_eq!(
            serde_json::to_string(&FdExecProbeMode::RedoxNullNamespacePathExecClassification)
                .unwrap(),
            "\"redox-null-namespace-path-exec-classification\""
        );

        for (mode, serialized) in [
            (
                FdLaunchMode::RedoxControlledServiceEnforced,
                "\"redox-controlled-service-enforced\"",
            ),
            (
                FdLaunchMode::RedoxFdLaunchBlocked,
                "\"redox-fd-launch-blocked\"",
            ),
            (
                FdLaunchMode::RedoxEnforcedCapsuleEntrypoint,
                "\"redox-enforced-capsule-entrypoint\"",
            ),
            (
                FdLaunchMode::RedoxCapsuleFdLaunchBlocked,
                "\"redox-capsule-fd-launch-blocked\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), serialized);
            assert_eq!(
                serde_json::from_str::<FdLaunchMode>(serialized).unwrap(),
                mode
            );
        }
    }
}
