use std::fs;
use std::path::Path;

use cocoon_core::{CapsuleName, hash_bytes};

use crate::install::acquire_capsule_lock;
use crate::receipt::{
    ReceiptVerificationPolicy, signature_public_key, verify_receipt_signature_with_policy,
};
use crate::run::verify_installed_capsule_unlocked;
use crate::{
    AuthorityProbeReceipt, InstallReceipt, Result, RollbackReceipt, RunReceipt, RuntimeError,
};

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
            detail: receipt.body.mode.clone(),
        });
        if let Some(public_key) = signature_public_key(&receipt.signature) {
            checks.push(AuditCheck {
                name: "latest authority probe receipt signature".to_string(),
                detail: public_key.to_string(),
            });
        }
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
    let actual = hash_bytes(&serde_json::to_vec(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "run receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature_with_policy(
        &receipt.event,
        &receipt.body,
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
    Ok(())
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
            },
        )
        .unwrap();

        let status = service_status_report(&capsule_name, install_root.path()).unwrap();

        assert_eq!(status.state, ServiceState::LastRunSucceeded);
        assert_eq!(status.current_version, Some("0.1.0".to_string()));
        assert!(status.latest_install_receipt.is_some());
        assert!(status.latest_run_receipt.is_some());
        assert!(status.latest_authority_probe_receipt.is_none());
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
