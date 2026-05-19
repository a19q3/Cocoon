use std::fs;
use std::path::Path;

use cocoon_core::{CapsuleName, hash_bytes};

use crate::install::acquire_capsule_lock;
use crate::receipt::{
    ReceiptVerificationPolicy, signature_public_key, verify_receipt_signature_bytes_with_policy,
    verify_receipt_signature_with_policy,
};
use crate::run::verify_installed_capsule_unlocked;
use crate::{
    AuthorityProbeReceipt, FdLaunchProbeReceipt, InstallReceipt, Result, RollbackReceipt,
    RunReceipt, RuntimeError,
};

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Installed,
    LastRunSucceeded,
    LastRunFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatusReport {
    pub capsule_name: String,
    pub state: ServiceState,
    pub current_version: Option<String>,
    pub latest_install_receipt: Option<InstallReceipt>,
    pub latest_run_receipt: Option<RunReceipt>,
    pub latest_authority_probe_receipt: Option<AuthorityProbeReceipt>,
    pub latest_fd_launch_probe_receipt: Option<FdLaunchProbeReceipt>,
    pub latest_capsule_fd_launch_probe_receipt: Option<FdLaunchProbeReceipt>,
    pub latest_rollback_receipt: Option<RollbackReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheck {
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub capsule_name: String,
    pub checks: Vec<AuditCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestLogs {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

pub fn service_status_report(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<ServiceStatusReport> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    service_status_report_unlocked(capsule_name, install_root)
}

fn service_status_report_unlocked(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<ServiceStatusReport> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    if !capsule_root.exists() {
        return Ok(ServiceStatusReport {
            capsule_name: capsule_name.to_string(),
            state: ServiceState::NotInstalled,
            current_version: None,
            latest_install_receipt: None,
            latest_run_receipt: None,
            latest_authority_probe_receipt: None,
            latest_fd_launch_probe_receipt: None,
            latest_capsule_fd_launch_probe_receipt: None,
            latest_rollback_receipt: None,
        });
    }
    verify_installed_capsule_unlocked(capsule_name, install_root)?;

    let current_version = read_optional_string(capsule_root.join("current-version").as_path())?
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty());
    let latest_install_receipt =
        read_optional_json::<InstallReceipt>(&capsule_root.join("receipts/latest.json"))?;
    let latest_run_receipt =
        read_optional_json::<RunReceipt>(&capsule_root.join("receipts/runs/latest.json"))?;
    let latest_authority_probe_receipt = read_optional_json::<AuthorityProbeReceipt>(
        &capsule_root.join("receipts/authority/latest.json"),
    )?;
    let latest_fd_launch_probe_receipt = read_optional_json::<FdLaunchProbeReceipt>(
        &capsule_root.join("receipts/fd-launch/latest.json"),
    )?;
    let latest_capsule_fd_launch_probe_receipt = read_optional_json::<FdLaunchProbeReceipt>(
        &capsule_root.join("receipts/capsule-fd-launch/latest.json"),
    )?;
    let latest_rollback_receipt = read_optional_json::<RollbackReceipt>(
        &capsule_root.join("receipts/rollbacks/latest.json"),
    )?;
    let state = match latest_run_receipt.as_ref() {
        Some(receipt) if receipt.body.success => ServiceState::LastRunSucceeded,
        Some(_) => ServiceState::LastRunFailed,
        None => ServiceState::Installed,
    };

    Ok(ServiceStatusReport {
        capsule_name: capsule_name.to_string(),
        state,
        current_version,
        latest_install_receipt,
        latest_run_receipt,
        latest_authority_probe_receipt,
        latest_fd_launch_probe_receipt,
        latest_capsule_fd_launch_probe_receipt,
        latest_rollback_receipt,
    })
}

pub fn latest_logs(
    capsule_name: &CapsuleName,
    install_root: &Path,
    include_stdout: bool,
    include_stderr: bool,
) -> Result<LatestLogs> {
    latest_logs_with_receipt_policy(
        capsule_name,
        install_root,
        include_stdout,
        include_stderr,
        &ReceiptVerificationPolicy::default(),
    )
}

pub fn latest_logs_with_receipt_policy(
    capsule_name: &CapsuleName,
    install_root: &Path,
    include_stdout: bool,
    include_stderr: bool,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<LatestLogs> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let status = service_status_report_unlocked(capsule_name, install_root)?;
    let receipt = status.latest_run_receipt.as_ref().ok_or_else(|| {
        RuntimeError::ReceiptAudit(format!("no run receipt found for capsule '{capsule_name}'"))
    })?;
    verify_run_receipt_with_policy(receipt, receipt_policy)?;

    let stdout = if include_stdout {
        Some(read_log_text(&receipt.body.stdout_log, "stdout")?)
    } else {
        None
    };
    let stderr = if include_stderr {
        Some(read_log_text(&receipt.body.stderr_log, "stderr")?)
    } else {
        None
    };
    Ok(LatestLogs { stdout, stderr })
}

pub fn audit_capsule(capsule_name: &CapsuleName, install_root: &Path) -> Result<AuditReport> {
    audit_capsule_with_receipt_policy(
        capsule_name,
        install_root,
        &ReceiptVerificationPolicy::default(),
    )
}

pub fn audit_capsule_with_receipt_policy(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<AuditReport> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    if !capsule_root.exists() {
        return Err(RuntimeError::NotInstalled(capsule_name.to_string()));
    }

    let status = service_status_report_unlocked(capsule_name, install_root)?;
    let mut checks = Vec::new();
    let current_version = status
        .current_version
        .as_ref()
        .ok_or_else(|| RuntimeError::ReceiptAudit("missing current version".to_string()))?;
    let install_receipt = status
        .latest_install_receipt
        .as_ref()
        .ok_or_else(|| RuntimeError::ReceiptAudit("missing latest install receipt".to_string()))?;

    verify_install_receipt_with_policy(install_receipt, receipt_policy)?;
    verify_latest_install_receipt_archive_with_policy(
        &capsule_root,
        install_receipt,
        receipt_policy,
    )?;
    checks.push(AuditCheck {
        name: "latest install receipt body hash".to_string(),
        detail: install_receipt.body_hash.clone(),
    });
    checks.push(AuditCheck {
        name: "latest install receipt archive link".to_string(),
        detail: install_receipt.body.capsule_version.clone(),
    });
    if let Some(public_key) = signature_public_key(&install_receipt.signature) {
        checks.push(AuditCheck {
            name: "latest install receipt signature".to_string(),
            detail: public_key.to_string(),
        });
    }

    if let Some(previous_hash) = &install_receipt.body.previous_receipt {
        verify_previous_install_receipt_with_policy(&capsule_root, previous_hash, receipt_policy)?;
        checks.push(AuditCheck {
            name: "previous install receipt link".to_string(),
            detail: previous_hash.clone(),
        });
    }

    if let Some(receipt) = status.latest_run_receipt.as_ref() {
        verify_run_receipt_with_policy(receipt, receipt_policy)?;
        verify_latest_run_receipt_archive_with_policy(&capsule_root, receipt, receipt_policy)?;
        checks.push(AuditCheck {
            name: "latest run receipt body hash".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest run receipt archive link".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest run stdout log hash".to_string(),
            detail: receipt.body.stdout_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest run stderr log hash".to_string(),
            detail: receipt.body.stderr_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest run authority enforcement".to_string(),
            detail: format!(
                "{} ({})",
                receipt.body.authority_enforced, receipt.body.authority_mode
            ),
        });
        if receipt.body.authority_enforced_for_service {
            checks.push(AuditCheck {
                name: "latest run structured child result".to_string(),
                detail: receipt.body.structured_child_result.to_string(),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch executable preopen".to_string(),
                detail: receipt.body.open_executable_before_restriction.to_string(),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch declared preopens".to_string(),
                detail: receipt
                    .body
                    .open_declared_preopens_before_restriction
                    .to_string(),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch namespace".to_string(),
                detail: receipt.body.entered_restricted_namespace.to_string(),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch fexec".to_string(),
                detail: receipt.body.exec_from_fd_succeeded.to_string(),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch denied path".to_string(),
                detail: format!(
                    "{} ({})",
                    receipt.body.denied_file_rejected, receipt.body.denied_file_path
                ),
            });
            checks.push(AuditCheck {
                name: "latest run FD launch hidden scheme".to_string(),
                detail: format!(
                    "{} ({})",
                    receipt.body.hidden_scheme_rejected, receipt.body.hidden_scheme_path
                ),
            });
        }
        if let Some(public_key) = signature_public_key(&receipt.signature) {
            checks.push(AuditCheck {
                name: "latest run receipt signature".to_string(),
                detail: public_key.to_string(),
            });
        }
    }

    if let Some(receipt) = status.latest_authority_probe_receipt.as_ref() {
        verify_authority_probe_receipt_with_policy(receipt, receipt_policy)?;
        verify_latest_authority_probe_receipt_archive_with_policy(
            &capsule_root,
            receipt,
            receipt_policy,
        )?;
        checks.push(AuditCheck {
            name: "latest authority probe receipt body hash".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest authority probe receipt archive link".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest authority probe stdout log hash".to_string(),
            detail: receipt.body.stdout_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest authority probe stderr log hash".to_string(),
            detail: receipt.body.stderr_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest authority probe mode".to_string(),
            detail: receipt.body.mode.to_string(),
        });
        checks.push(AuditCheck {
            name: "latest authority probe structured child result".to_string(),
            detail: receipt.body.structured_child_result.to_string(),
        });
        if let Some(public_key) = signature_public_key(&receipt.signature) {
            checks.push(AuditCheck {
                name: "latest authority probe receipt signature".to_string(),
                detail: public_key.to_string(),
            });
        }
    }

    if let Some(receipt) = status.latest_fd_launch_probe_receipt.as_ref() {
        push_fd_launch_probe_audit_checks(
            &capsule_root,
            "fd launch probe",
            "fd-launch",
            receipt,
            receipt_policy,
            &mut checks,
        )?;
    }

    if let Some(receipt) = status.latest_capsule_fd_launch_probe_receipt.as_ref() {
        push_fd_launch_probe_audit_checks(
            &capsule_root,
            "capsule fd launch probe",
            "capsule-fd-launch",
            receipt,
            receipt_policy,
            &mut checks,
        )?;
    }

    if let Some(receipt) = status.latest_rollback_receipt.as_ref() {
        verify_rollback_receipt_with_policy(receipt, receipt_policy)?;
        verify_latest_rollback_receipt_archive_with_policy(&capsule_root, receipt, receipt_policy)?;
        if current_version != &receipt.body.target_version {
            return Err(RuntimeError::ReceiptAudit(format!(
                "current version {current_version} does not match latest rollback target {}",
                receipt.body.target_version
            )));
        }
        checks.push(AuditCheck {
            name: "latest rollback receipt body hash".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "latest rollback receipt archive link".to_string(),
            detail: receipt.body_hash.clone(),
        });
        checks.push(AuditCheck {
            name: "current version matches rollback target".to_string(),
            detail: current_version.clone(),
        });
        if let Some(public_key) = signature_public_key(&receipt.signature) {
            checks.push(AuditCheck {
                name: "latest rollback receipt signature".to_string(),
                detail: public_key.to_string(),
            });
        }
    } else if current_version != &install_receipt.body.capsule_version {
        return Err(RuntimeError::ReceiptAudit(format!(
            "current version {current_version} does not match latest install version {}",
            install_receipt.body.capsule_version
        )));
    } else {
        checks.push(AuditCheck {
            name: "current version matches latest install".to_string(),
            detail: current_version.clone(),
        });
    }

    Ok(AuditReport {
        capsule_name: capsule_name.to_string(),
        checks,
    })
}

fn read_optional_string(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_optional_json<T>(path: &Path) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn verify_install_receipt_with_policy(
    receipt: &InstallReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let actual = hash_bytes(&serde_json::to_vec(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "install receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature_with_policy(
        &receipt.event,
        &receipt.body,
        &receipt.signature,
        "install",
        receipt_policy,
    )?;
    Ok(())
}

fn verify_latest_install_receipt_archive_with_policy(
    capsule_root: &Path,
    latest_receipt: &InstallReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let archived_path = capsule_root
        .join("receipts")
        .join(format!("{}.json", latest_receipt.body.capsule_version));
    let archived = read_required_json::<InstallReceipt>(&archived_path)?;
    verify_install_receipt_with_policy(&archived, receipt_policy)?;
    if archived.body_hash != latest_receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest install receipt archive mismatch: latest {}, archived {}",
            latest_receipt.body_hash, archived.body_hash
        )));
    }
    Ok(())
}

pub fn verify_run_receipt_integrity(receipt: &RunReceipt) -> Result<()> {
    verify_run_receipt(receipt)
}

pub fn verify_status_report_integrity(status: &ServiceStatusReport) -> Result<()> {
    verify_status_report_integrity_with_receipt_policy(
        status,
        &ReceiptVerificationPolicy::default(),
    )
}

pub fn verify_status_report_integrity_with_receipt_policy(
    status: &ServiceStatusReport,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    if let Some(receipt) = status.latest_install_receipt.as_ref() {
        verify_install_receipt_with_policy(receipt, receipt_policy)?;
    }
    if let Some(receipt) = status.latest_run_receipt.as_ref() {
        verify_run_receipt_with_policy(receipt, receipt_policy)?;
    }
    if let Some(receipt) = status.latest_authority_probe_receipt.as_ref() {
        verify_authority_probe_receipt_with_policy(receipt, receipt_policy)?;
    }
    if let Some(receipt) = status.latest_fd_launch_probe_receipt.as_ref() {
        verify_fd_launch_probe_receipt_with_policy(receipt, receipt_policy)?;
    }
    if let Some(receipt) = status.latest_capsule_fd_launch_probe_receipt.as_ref() {
        verify_fd_launch_probe_receipt_with_policy(receipt, receipt_policy)?;
    }
    if let Some(receipt) = status.latest_rollback_receipt.as_ref() {
        verify_rollback_receipt_with_policy(receipt, receipt_policy)?;
    }
    Ok(())
}

fn verify_run_receipt(receipt: &RunReceipt) -> Result<()> {
    verify_run_receipt_with_policy(receipt, &ReceiptVerificationPolicy::default())
}

fn verify_run_receipt_with_policy(
    receipt: &RunReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let body_bytes = verified_run_receipt_body_bytes(receipt)?;
    verify_receipt_signature_bytes_with_policy(
        &receipt.event,
        &body_bytes,
        &receipt.signature,
        "run",
        receipt_policy,
    )?;
    verify_log_hash(
        &receipt.body.stdout_log,
        &receipt.body.stdout_hash,
        "stdout",
    )?;
    verify_log_hash(
        &receipt.body.stderr_log,
        &receipt.body.stderr_hash,
        "stderr",
    )?;
    verify_run_fd_launch_evidence(receipt)?;
    Ok(())
}

fn verified_run_receipt_body_bytes(receipt: &RunReceipt) -> Result<Vec<u8>> {
    let current = serde_json::to_vec(&receipt.body)?;
    let current_hash = hash_bytes(&current);
    if current_hash == receipt.body_hash {
        return Ok(current);
    }

    if let Some(without_actual_args) = run_receipt_body_without_actual_args_bytes(&receipt.body)? {
        let without_actual_args_hash = hash_bytes(&without_actual_args);
        if without_actual_args_hash == receipt.body_hash {
            return Ok(without_actual_args);
        }
    }

    if let Some(legacy) = legacy_run_receipt_body_bytes(&receipt.body)? {
        let legacy_hash = hash_bytes(&legacy);
        if legacy_hash == receipt.body_hash {
            return Ok(legacy);
        }
    }

    Err(RuntimeError::ReceiptAudit(format!(
        "run receipt body hash mismatch: expected {}, got {current_hash}",
        receipt.body_hash
    )))
}

fn run_receipt_body_without_actual_args_bytes(
    body: &crate::run::RunReceiptBody,
) -> Result<Option<Vec<u8>>> {
    if !body.actual_args.is_empty() {
        return Ok(None);
    }

    #[derive(serde::Serialize)]
    struct RunReceiptBodyWithoutActualArgs<'a> {
        capsule_name: &'a str,
        capsule_version: &'a str,
        command: &'a str,
        args: &'a [String],
        authority_enforced: bool,
        authority_mode: &'a crate::run::RunAuthorityMode,
        authority_enforced_for_service: bool,
        production_arbitrary_service: bool,
        #[serde(skip_serializing_if = "is_false")]
        structured_child_result: bool,
        open_executable_before_restriction: bool,
        open_declared_preopens_before_restriction: bool,
        entered_restricted_namespace: bool,
        exec_from_fd_attempted: bool,
        exec_from_fd_succeeded: bool,
        allowed_preopen_read: bool,
        denied_file_path: &'a str,
        denied_file_rejected: bool,
        hidden_scheme_path: &'a str,
        hidden_scheme_rejected: bool,
        exit_code: Option<i32>,
        success: bool,
        stdout_log: &'a str,
        stdout_hash: &'a str,
        stderr_log: &'a str,
        stderr_hash: &'a str,
        started_at: &'a str,
        finished_at: &'a str,
        runtime_version: &'a str,
    }

    Ok(Some(serde_json::to_vec(
        &RunReceiptBodyWithoutActualArgs {
            capsule_name: &body.capsule_name,
            capsule_version: &body.capsule_version,
            command: &body.command,
            args: &body.args,
            authority_enforced: body.authority_enforced,
            authority_mode: &body.authority_mode,
            authority_enforced_for_service: body.authority_enforced_for_service,
            production_arbitrary_service: body.production_arbitrary_service,
            structured_child_result: body.structured_child_result,
            open_executable_before_restriction: body.open_executable_before_restriction,
            open_declared_preopens_before_restriction: body
                .open_declared_preopens_before_restriction,
            entered_restricted_namespace: body.entered_restricted_namespace,
            exec_from_fd_attempted: body.exec_from_fd_attempted,
            exec_from_fd_succeeded: body.exec_from_fd_succeeded,
            allowed_preopen_read: body.allowed_preopen_read,
            denied_file_path: &body.denied_file_path,
            denied_file_rejected: body.denied_file_rejected,
            hidden_scheme_path: &body.hidden_scheme_path,
            hidden_scheme_rejected: body.hidden_scheme_rejected,
            exit_code: body.exit_code,
            success: body.success,
            stdout_log: &body.stdout_log,
            stdout_hash: &body.stdout_hash,
            stderr_log: &body.stderr_log,
            stderr_hash: &body.stderr_hash,
            started_at: &body.started_at,
            finished_at: &body.finished_at,
            runtime_version: &body.runtime_version,
        },
    )?))
}

fn legacy_run_receipt_body_bytes(body: &crate::run::RunReceiptBody) -> Result<Option<Vec<u8>>> {
    if body.authority_enforced_for_service
        || !body.actual_args.is_empty()
        || body.production_arbitrary_service
        || body.structured_child_result
        || body.open_executable_before_restriction
        || body.open_declared_preopens_before_restriction
        || body.entered_restricted_namespace
        || body.exec_from_fd_attempted
        || body.exec_from_fd_succeeded
        || body.allowed_preopen_read
        || !body.denied_file_path.is_empty()
        || body.denied_file_rejected
        || !body.hidden_scheme_path.is_empty()
        || body.hidden_scheme_rejected
    {
        return Ok(None);
    }

    #[derive(serde::Serialize)]
    struct LegacyRunReceiptBody<'a> {
        capsule_name: &'a str,
        capsule_version: &'a str,
        command: &'a str,
        args: &'a [String],
        authority_enforced: bool,
        authority_mode: &'a crate::run::RunAuthorityMode,
        exit_code: Option<i32>,
        success: bool,
        stdout_log: &'a str,
        stdout_hash: &'a str,
        stderr_log: &'a str,
        stderr_hash: &'a str,
        started_at: &'a str,
        finished_at: &'a str,
        runtime_version: &'a str,
    }

    Ok(Some(serde_json::to_vec(&LegacyRunReceiptBody {
        capsule_name: &body.capsule_name,
        capsule_version: &body.capsule_version,
        command: &body.command,
        args: &body.args,
        authority_enforced: body.authority_enforced,
        authority_mode: &body.authority_mode,
        exit_code: body.exit_code,
        success: body.success,
        stdout_log: &body.stdout_log,
        stdout_hash: &body.stdout_hash,
        stderr_log: &body.stderr_log,
        stderr_hash: &body.stderr_hash,
        started_at: &body.started_at,
        finished_at: &body.finished_at,
        runtime_version: &body.runtime_version,
    })?))
}

fn verify_run_fd_launch_evidence(receipt: &RunReceipt) -> Result<()> {
    if receipt.body.authority_mode == crate::run::RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint
        && !receipt.body.authority_enforced_for_service
    {
        return Err(RuntimeError::ReceiptAudit(
            "run receipt claims redox-enforced-capsule-entrypoint without service enforcement"
                .to_string(),
        ));
    }

    if !receipt.body.authority_enforced_for_service {
        return Ok(());
    }

    let mut missing = Vec::new();
    if !receipt.body.authority_enforced {
        missing.push("authority_enforced");
    }
    if receipt.body.authority_mode != crate::run::RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint {
        missing.push("authority_mode");
    }
    if receipt.body.production_arbitrary_service {
        missing.push("production_arbitrary_service=false");
    }
    if !receipt.body.open_executable_before_restriction {
        missing.push("open_executable_before_restriction");
    }
    if !receipt.body.open_declared_preopens_before_restriction {
        missing.push("open_declared_preopens_before_restriction");
    }
    if !receipt.body.entered_restricted_namespace {
        missing.push("entered_restricted_namespace");
    }
    if !receipt.body.exec_from_fd_attempted {
        missing.push("exec_from_fd_attempted");
    }
    if !receipt.body.exec_from_fd_succeeded {
        missing.push("exec_from_fd_succeeded");
    }
    if !receipt.body.allowed_preopen_read {
        missing.push("allowed_preopen_read");
    }
    if !receipt.body.denied_file_rejected {
        missing.push("denied_file_rejected");
    }
    if !receipt.body.hidden_scheme_rejected {
        missing.push("hidden_scheme_rejected");
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::ReceiptAudit(format!(
            "run receipt FD launch evidence incomplete: {}",
            missing.join(", ")
        )))
    }
}

fn verify_latest_run_receipt_archive_with_policy(
    capsule_root: &Path,
    latest_receipt: &RunReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("runs");
    let Some(archived) = find_archived_receipt::<RunReceipt, _>(&receipts_root, |receipt| {
        receipt.body_hash == latest_receipt.body_hash
    })?
    else {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest run receipt archive not found: {}",
            latest_receipt.body_hash
        )));
    };
    verify_run_receipt_with_policy(&archived, receipt_policy)?;
    Ok(())
}

fn verify_authority_probe_receipt_with_policy(
    receipt: &AuthorityProbeReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let actual = hash_bytes(&serde_json::to_vec(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "authority probe receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature_with_policy(
        &receipt.event,
        &receipt.body,
        &receipt.signature,
        "authority probe",
        receipt_policy,
    )?;
    verify_log_hash(
        &receipt.body.stdout_log,
        &receipt.body.stdout_hash,
        "authority probe stdout",
    )?;
    verify_log_hash(
        &receipt.body.stderr_log,
        &receipt.body.stderr_hash,
        "authority probe stderr",
    )?;
    Ok(())
}

fn verify_latest_authority_probe_receipt_archive_with_policy(
    capsule_root: &Path,
    latest_receipt: &AuthorityProbeReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("authority");
    let Some(archived) =
        find_archived_receipt::<AuthorityProbeReceipt, _>(&receipts_root, |receipt| {
            receipt.body_hash == latest_receipt.body_hash
        })?
    else {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest authority probe receipt archive not found: {}",
            latest_receipt.body_hash
        )));
    };
    verify_authority_probe_receipt_with_policy(&archived, receipt_policy)?;
    Ok(())
}

fn push_fd_launch_probe_audit_checks(
    capsule_root: &Path,
    label: &str,
    receipt_dir: &str,
    receipt: &FdLaunchProbeReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
    checks: &mut Vec<AuditCheck>,
) -> Result<()> {
    verify_fd_launch_probe_receipt_with_policy(receipt, receipt_policy)?;
    verify_latest_fd_launch_probe_receipt_archive_with_policy(
        capsule_root,
        receipt_dir,
        receipt,
        receipt_policy,
    )?;
    checks.push(AuditCheck {
        name: format!("latest {label} receipt body hash"),
        detail: receipt.body_hash.clone(),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} receipt archive link"),
        detail: receipt.body_hash.clone(),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} stdout log hash"),
        detail: receipt.body.stdout_hash.clone(),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} stderr log hash"),
        detail: receipt.body.stderr_hash.clone(),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} mode"),
        detail: receipt.body.mode.to_string(),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} authority enforcement"),
        detail: format!(
            "{} ({})",
            receipt.body.authority_enforced_for_service, receipt.body.mode
        ),
    });
    checks.push(AuditCheck {
        name: format!("latest {label} structured child result"),
        detail: receipt.body.structured_child_result.to_string(),
    });
    if let Some(public_key) = signature_public_key(&receipt.signature) {
        checks.push(AuditCheck {
            name: format!("latest {label} receipt signature"),
            detail: public_key.to_string(),
        });
    }
    Ok(())
}

fn verify_fd_launch_probe_receipt_with_policy(
    receipt: &FdLaunchProbeReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let actual = hash_bytes(&serde_json::to_vec(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "fd launch probe receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature_with_policy(
        &receipt.event,
        &receipt.body,
        &receipt.signature,
        "fd launch probe",
        receipt_policy,
    )?;
    verify_log_hash(
        &receipt.body.stdout_log,
        &receipt.body.stdout_hash,
        "fd launch probe stdout",
    )?;
    verify_log_hash(
        &receipt.body.stderr_log,
        &receipt.body.stderr_hash,
        "fd launch probe stderr",
    )?;
    Ok(())
}

fn verify_latest_fd_launch_probe_receipt_archive_with_policy(
    capsule_root: &Path,
    receipt_dir: &str,
    latest_receipt: &FdLaunchProbeReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join(receipt_dir);
    let Some(archived) =
        find_archived_receipt::<FdLaunchProbeReceipt, _>(&receipts_root, |receipt| {
            receipt.body_hash == latest_receipt.body_hash
        })?
    else {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest fd launch probe receipt archive not found: {}",
            latest_receipt.body_hash
        )));
    };
    verify_fd_launch_probe_receipt_with_policy(&archived, receipt_policy)?;
    Ok(())
}

fn verify_log_hash(path: &str, expected_hash: &str, label: &str) -> Result<()> {
    let bytes = fs::read(path).map_err(|error| {
        RuntimeError::ReceiptAudit(format!("{label} log '{}' cannot be read: {error}", path))
    })?;
    let actual = hash_bytes(&bytes);
    if actual != expected_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "{label} log hash mismatch: expected {expected_hash}, got {actual}"
        )));
    }
    Ok(())
}

fn read_log_text(path: &str, label: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|error| {
        RuntimeError::ReceiptAudit(format!("{label} log '{path}' cannot be read: {error}"))
    })
}

fn verify_rollback_receipt_with_policy(
    receipt: &RollbackReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let actual = hash_bytes(&serde_json::to_vec(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "rollback receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature_with_policy(
        &receipt.event,
        &receipt.body,
        &receipt.signature,
        "rollback",
        receipt_policy,
    )?;
    Ok(())
}

fn verify_latest_rollback_receipt_archive_with_policy(
    capsule_root: &Path,
    latest_receipt: &RollbackReceipt,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("rollbacks");
    let Some(archived) = find_archived_receipt::<RollbackReceipt, _>(&receipts_root, |receipt| {
        receipt.body_hash == latest_receipt.body_hash
    })?
    else {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest rollback receipt archive not found: {}",
            latest_receipt.body_hash
        )));
    };
    verify_rollback_receipt_with_policy(&archived, receipt_policy)?;
    Ok(())
}

fn read_required_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path).map_err(|error| {
        RuntimeError::ReceiptAudit(format!(
            "receipt archive '{}' cannot be read: {error}",
            path.display()
        ))
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn find_archived_receipt<T, F>(receipts_root: &Path, mut matches_receipt: F) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
    F: FnMut(&T) -> bool,
{
    for entry in fs::read_dir(receipts_root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir()
            || path.file_name().and_then(|name| name.to_str()) == Some("latest.json")
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        let receipt = serde_json::from_slice::<T>(&fs::read(path)?)?;
        if matches_receipt(&receipt) {
            return Ok(Some(receipt));
        }
    }
    Ok(None)
}

fn verify_previous_install_receipt_with_policy(
    capsule_root: &Path,
    previous_hash: &str,
    receipt_policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts");
    for entry in fs::read_dir(&receipts_root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir()
            || path.file_name().and_then(|name| name.to_str()) == Some("latest.json")
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        let bytes = fs::read(&path)?;
        let receipt = serde_json::from_slice::<InstallReceipt>(&bytes)?;
        if receipt.body_hash == previous_hash {
            verify_install_receipt_with_policy(&receipt, receipt_policy)?;
            return Ok(());
        }
    }
    Err(RuntimeError::ReceiptAudit(format!(
        "previous install receipt not found: {previous_hash}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RunOptions, install_capsule, run_installed_capsule_with_options};
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn status_reports_not_installed() {
        let install_root = TempDir::new().unwrap();

        let status = service_status_report(
            &CapsuleName::parse("missing-service").unwrap(),
            install_root.path(),
        )
        .unwrap();

        assert_eq!(status.state, ServiceState::NotInstalled);
        assert_eq!(status.current_version, None);
    }

    #[test]
    fn status_reports_latest_run() {
        let (_fixture_dir, capsule) = fixture_capsule();
        let install_root = TempDir::new().unwrap();
        let capsule_name = CapsuleName::parse("status-test").unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();
        run_installed_capsule_with_options(
            &capsule_name,
            install_root.path(),
            RunOptions {
                allow_unenforced_authority: true,
                enforce_redox_authority: false,
            },
        )
        .unwrap();

        let status = service_status_report(&capsule_name, install_root.path()).unwrap();

        assert_eq!(status.state, ServiceState::LastRunSucceeded);
        assert_eq!(status.current_version, Some("0.1.0".to_string()));
        assert!(status.latest_install_receipt.is_some());
        assert!(status.latest_run_receipt.is_some());
        assert!(status.latest_authority_probe_receipt.is_none());
        assert!(status.latest_fd_launch_probe_receipt.is_none());
        assert!(status.latest_capsule_fd_launch_probe_receipt.is_none());
    }

    #[test]
    fn legacy_run_receipt_hash_without_fd_launch_fields_is_accepted() {
        let log_dir = TempDir::new().unwrap();
        let stdout_log = log_dir.path().join("stdout.log");
        let stderr_log = log_dir.path().join("stderr.log");
        fs::write(&stdout_log, b"legacy stdout\n").unwrap();
        fs::write(&stderr_log, b"").unwrap();

        let body = crate::run::RunReceiptBody {
            capsule_name: "status-test".to_string(),
            capsule_version: "0.1.0".to_string(),
            command: "/app/bin/status-test".to_string(),
            args: Vec::new(),
            actual_args: Vec::new(),
            authority_enforced: false,
            authority_mode: crate::run::RunAuthorityMode::SmokeUnenforced,
            authority_enforced_for_service: false,
            production_arbitrary_service: false,
            structured_child_result: false,
            open_executable_before_restriction: false,
            open_declared_preopens_before_restriction: false,
            entered_restricted_namespace: false,
            exec_from_fd_attempted: false,
            exec_from_fd_succeeded: false,
            allowed_preopen_read: false,
            denied_file_path: String::new(),
            denied_file_rejected: false,
            hidden_scheme_path: String::new(),
            hidden_scheme_rejected: false,
            exit_code: Some(0),
            success: true,
            stdout_log: stdout_log.display().to_string(),
            stdout_hash: hash_bytes(b"legacy stdout\n"),
            stderr_log: stderr_log.display().to_string(),
            stderr_hash: hash_bytes(b""),
            started_at: "unix:1".to_string(),
            finished_at: "unix:2".to_string(),
            runtime_version: "0.1.0".to_string(),
        };

        #[derive(serde::Serialize)]
        struct LegacyRunReceiptBody<'a> {
            capsule_name: &'a str,
            capsule_version: &'a str,
            command: &'a str,
            args: &'a [String],
            authority_enforced: bool,
            authority_mode: &'a crate::run::RunAuthorityMode,
            exit_code: Option<i32>,
            success: bool,
            stdout_log: &'a str,
            stdout_hash: &'a str,
            stderr_log: &'a str,
            stderr_hash: &'a str,
            started_at: &'a str,
            finished_at: &'a str,
            runtime_version: &'a str,
        }

        let legacy_body_hash = hash_bytes(
            &serde_json::to_vec(&LegacyRunReceiptBody {
                capsule_name: &body.capsule_name,
                capsule_version: &body.capsule_version,
                command: &body.command,
                args: &body.args,
                authority_enforced: body.authority_enforced,
                authority_mode: &body.authority_mode,
                exit_code: body.exit_code,
                success: body.success,
                stdout_log: &body.stdout_log,
                stdout_hash: &body.stdout_hash,
                stderr_log: &body.stderr_log,
                stderr_hash: &body.stderr_hash,
                started_at: &body.started_at,
                finished_at: &body.finished_at,
                runtime_version: &body.runtime_version,
            })
            .unwrap(),
        );
        let receipt = crate::run::RunReceipt {
            receipt_version: 1,
            event: "capsule_run".to_string(),
            body,
            body_hash: legacy_body_hash,
            signature: None,
        };

        verify_run_receipt_integrity(&receipt).unwrap();
    }

    #[test]
    fn legacy_run_receipt_hash_without_actual_args_is_accepted() {
        let log_dir = TempDir::new().unwrap();
        let stdout_log = log_dir.path().join("stdout.log");
        let stderr_log = log_dir.path().join("stderr.log");
        fs::write(&stdout_log, b"fd stdout\n").unwrap();
        fs::write(&stderr_log, b"").unwrap();

        let body = crate::run::RunReceiptBody {
            capsule_name: "status-test".to_string(),
            capsule_version: "0.1.0".to_string(),
            command: "/app/bin/status-test".to_string(),
            args: vec!["--authority-self-test".to_string()],
            actual_args: Vec::new(),
            authority_enforced: true,
            authority_mode: crate::run::RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint,
            authority_enforced_for_service: true,
            production_arbitrary_service: false,
            structured_child_result: false,
            open_executable_before_restriction: true,
            open_declared_preopens_before_restriction: true,
            entered_restricted_namespace: true,
            exec_from_fd_attempted: true,
            exec_from_fd_succeeded: true,
            allowed_preopen_read: true,
            denied_file_path: "/home/denied".to_string(),
            denied_file_rejected: true,
            hidden_scheme_path: "/scheme/tcp".to_string(),
            hidden_scheme_rejected: true,
            exit_code: Some(0),
            success: true,
            stdout_log: stdout_log.display().to_string(),
            stdout_hash: hash_bytes(b"fd stdout\n"),
            stderr_log: stderr_log.display().to_string(),
            stderr_hash: hash_bytes(b""),
            started_at: "unix:1".to_string(),
            finished_at: "unix:2".to_string(),
            runtime_version: "0.1.0".to_string(),
        };
        let legacy_body_hash = hash_bytes(
            &run_receipt_body_without_actual_args_bytes(&body)
                .unwrap()
                .unwrap(),
        );
        let receipt = crate::run::RunReceipt {
            receipt_version: 1,
            event: "capsule_run".to_string(),
            body,
            body_hash: legacy_body_hash,
            signature: None,
        };

        verify_run_receipt_integrity(&receipt).unwrap();
    }

    fn fixture_capsule() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("Cocoon.toml"),
            r#"
[capsule]
name = "status-test"
version = "0.1.0"

[entry]
cmd = "/app/bin/status-test"
"#,
        )
        .unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        write_executable(
            source.join("bin/status-test"),
            b"#!/bin/sh\necho status-test-ok\n",
        )
        .unwrap();

        let capsule = dir.path().join("status-test.cocoon");
        let bytes = cocoon_bundle::BundleBuilder::new(&source)
            .and_then(cocoon_bundle::BundleBuilder::build)
            .unwrap();
        fs::write(&capsule, bytes).unwrap();
        (dir, capsule)
    }

    fn write_executable(path: impl AsRef<Path>, content: &[u8]) -> std::io::Result<()> {
        let path = path.as_ref();
        fs::write(path, content)?;
        make_executable(path)
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}
