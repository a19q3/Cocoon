use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cocoon_bundle::{BundleReader, SignatureMetadata, VerificationIssue, VerificationPolicy};
use cocoon_core::{
    CapsuleManifest, CapsuleName, CapsuleVersion, diff_authority, hash_bytes, hash_permissions,
};

use crate::fsutil::atomic_write;
use crate::receipt::{ReceiptSigningOptions, sign_receipt_body, verify_receipt_signature};

pub type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("bundle error: {0}")]
    Bundle(#[from] cocoon_core::CocoonError),

    #[error("verification failed: {0:?}")]
    Verification(Vec<VerificationIssue>),

    #[error("capsule version already installed: {0}")]
    AlreadyInstalled(String),

    #[error("capsule is not installed: {0}")]
    NotInstalled(String),

    #[error("capsule version is not installed: {0}")]
    VersionNotInstalled(String),

    #[error("capsule version is already current: {0}")]
    AlreadyCurrent(String),

    #[error("capsule operation is locked: {0}")]
    Locked(String),

    #[error("receipt serialization failed: {0}")]
    Receipt(#[from] serde_json::Error),

    #[error("system clock is before UNIX epoch")]
    SystemClock,

    #[error("guest path error: {0}")]
    GuestPath(String),

    #[error("installed tree integrity failed: {0}")]
    InstalledIntegrity(String),

    #[error("permission expansion requires confirmation:\n{0}")]
    PermissionExpansionRequiresConfirmation(String),

    #[error("runtime authority enforcement unavailable: {0}")]
    UnenforcedAuthority(String),

    #[error("authority probe failed: {0}")]
    AuthorityProbe(String),

    #[error("receipt audit failed: {0}")]
    ReceiptAudit(String),

    #[error("service is already running: {0}")]
    ServiceAlreadyRunning(String),

    #[error("service is not running: {0}")]
    ServiceNotRunning(String),

    #[error("service supervisor failed: {0}")]
    ServiceSupervisor(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstallReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: InstallReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstallReceiptBody {
    pub capsule_name: String,
    pub capsule_version: String,
    pub manifest_hash: String,
    pub bundle_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_identity: Option<PayloadIdentity>,
    pub permission_hash: String,
    pub installed_at: String,
    pub install_root: String,
    pub runtime_version: String,
    pub previous_receipt: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PayloadIdentity {
    pub layer: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    pub verifier: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RollbackReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: RollbackReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RollbackReceiptBody {
    pub capsule_name: String,
    pub previous_version: String,
    pub target_version: String,
    pub rolled_back_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub capsule_name: String,
    pub broke_lock: bool,
    pub removed_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAllReport {
    pub recovered: Vec<RecoveryReport>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstallOptions {
    pub allow_permission_expansion: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryOptions {
    pub break_lock: bool,
}

/// Install a capsule after integrity verification.
///
/// P0 materializes the verified capsule payload into:
/// `<install_root>/capsules/<name>/versions/<version>/`.
/// The current version pointer and receipt are written only after staging succeeds.
pub fn install_capsule(capsule_path: &Path, install_root: &Path) -> Result<InstallReceipt> {
    install_capsule_with_policy(capsule_path, install_root, VerificationPolicy::default())
}

pub fn install_capsule_with_options(
    capsule_path: &Path,
    install_root: &Path,
    options: InstallOptions,
) -> Result<InstallReceipt> {
    install_capsule_with_options_policy_and_receipt_signing(
        capsule_path,
        install_root,
        VerificationPolicy::default(),
        ReceiptSigningOptions::default(),
        options,
    )
}

pub fn install_capsule_with_policy(
    capsule_path: &Path,
    install_root: &Path,
    policy: VerificationPolicy,
) -> Result<InstallReceipt> {
    install_capsule_with_policy_and_receipt_signing(
        capsule_path,
        install_root,
        policy,
        ReceiptSigningOptions::default(),
    )
}

pub fn install_capsule_with_policy_and_receipt_signing(
    capsule_path: &Path,
    install_root: &Path,
    policy: VerificationPolicy,
    receipt_signing: ReceiptSigningOptions,
) -> Result<InstallReceipt> {
    install_capsule_with_options_policy_and_receipt_signing(
        capsule_path,
        install_root,
        policy,
        receipt_signing,
        InstallOptions::default(),
    )
}

pub fn install_capsule_with_options_policy_and_receipt_signing(
    capsule_path: &Path,
    install_root: &Path,
    policy: VerificationPolicy,
    receipt_signing: ReceiptSigningOptions,
    options: InstallOptions,
) -> Result<InstallReceipt> {
    let bytes = fs::read(capsule_path)?;
    let reader = BundleReader::from_bytes(&bytes)?;
    let issues = reader.verify_with_policy(policy)?;
    let integrity_issues = issues
        .into_iter()
        .filter(VerificationIssue::is_integrity_failure)
        .collect::<Vec<_>>();
    if !integrity_issues.is_empty() {
        return Err(RuntimeError::Verification(integrity_issues));
    }

    let capsule_name = reader.manifest.capsule.name.to_string();
    let capsule_version = reader.manifest.capsule.version.to_string();
    let _lock = acquire_capsule_lock(install_root, &capsule_name)?;
    let capsule_root = install_root.join("capsules").join(&capsule_name);

    let versions_root = capsule_root.join("versions");
    let version_dir = versions_root.join(&capsule_version);
    if version_dir.exists() {
        return Err(RuntimeError::AlreadyInstalled(format!(
            "{capsule_name} {capsule_version}"
        )));
    }
    enforce_permission_expansion_policy(&capsule_root, &reader.manifest, options)?;

    fs::create_dir_all(&versions_root)?;
    let staging_dir = staging_dir(install_root, &capsule_name, &capsule_version)?;
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)?;
    }
    fs::create_dir_all(&staging_dir)?;

    if let Err(err) = reader.materialize(&staging_dir) {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(RuntimeError::Bundle(err));
    }

    let receipt = build_install_receipt(
        &reader,
        &version_dir,
        &bytes,
        previous_receipt_hash(&capsule_root)?,
        &receipt_signing,
    )?;

    match fs::rename(&staging_dir, &version_dir) {
        Ok(()) => {}
        Err(_) if version_dir.exists() => {
            return Err(RuntimeError::AlreadyInstalled(format!(
                "{capsule_name} {capsule_version}"
            )));
        }
        Err(err) => return Err(err.into()),
    }
    write_receipts(&capsule_root, &capsule_version, &receipt)?;
    promote_current(&capsule_root, &capsule_version)?;
    write_current_pointer(&capsule_root, &capsule_version)?;

    Ok(receipt)
}

pub fn rollback_capsule(
    capsule_name: &CapsuleName,
    target_version: &CapsuleVersion,
    install_root: &Path,
) -> Result<RollbackReceipt> {
    rollback_capsule_with_receipt_signing(
        capsule_name,
        target_version,
        install_root,
        ReceiptSigningOptions::default(),
    )
}

pub fn rollback_capsule_with_receipt_signing(
    capsule_name: &CapsuleName,
    target_version: &CapsuleVersion,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<RollbackReceipt> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    if !capsule_root.exists() {
        return Err(RuntimeError::NotInstalled(capsule_name.to_string()));
    }

    let target_version_dir = capsule_root.join("versions").join(target_version.as_str());
    if !target_version_dir.exists() {
        return Err(RuntimeError::VersionNotInstalled(format!(
            "{} {}",
            capsule_name, target_version
        )));
    }

    let previous_version = read_current_version(&capsule_root)?
        .ok_or_else(|| RuntimeError::NotInstalled(capsule_name.to_string()))?;
    if previous_version == target_version.as_str() {
        return Err(RuntimeError::AlreadyCurrent(format!(
            "{} {}",
            capsule_name, target_version
        )));
    }

    promote_current(&capsule_root, target_version.as_str())?;
    write_current_pointer(&capsule_root, target_version.as_str())?;

    let receipt = build_rollback_receipt(
        capsule_name,
        &previous_version,
        target_version,
        &receipt_signing,
    )?;
    write_rollback_receipt(&capsule_root, &receipt)?;
    Ok(receipt)
}

pub fn recover_capsule(capsule_name: &CapsuleName, install_root: &Path) -> Result<RecoveryReport> {
    recover_capsule_with_options(capsule_name, install_root, RecoveryOptions::default())
}

pub fn recover_all_capsules(install_root: &Path) -> Result<RecoveryAllReport> {
    let capsules_root = install_root.join("capsules");
    let mut capsule_names = Vec::new();
    match fs::read_dir(&capsules_root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(capsule_name) = CapsuleName::parse(name) else {
                    continue;
                };
                capsule_names.push(capsule_name);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    capsule_names.sort();

    let mut recovered = Vec::new();
    for capsule_name in capsule_names {
        recovered.push(recover_capsule(&capsule_name, install_root)?);
    }
    Ok(RecoveryAllReport { recovered })
}

pub fn recover_capsule_with_options(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: RecoveryOptions,
) -> Result<RecoveryReport> {
    if options.break_lock {
        break_capsule_lock(install_root, capsule_name.as_str())?;
    }
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let mut removed_paths = Vec::new();

    let staging_root = install_root.join(".staging");
    if staging_root.exists() {
        let prefix = format!("{}-", capsule_name.as_str());
        for entry in fs::read_dir(&staging_root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) {
                let path = entry.path();
                remove_path_if_exists(&path)?;
                removed_paths.push(path.display().to_string());
            }
        }
    }

    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let temp_paths = [
        capsule_root.join("current.tmp"),
        capsule_root.join("current-version.tmp"),
        capsule_root.join("receipts/latest.json.tmp"),
        capsule_root.join("receipts/runs/latest.json.tmp"),
        capsule_root.join("receipts/services/latest.json.tmp"),
        capsule_root.join("receipts/rollbacks/latest.json.tmp"),
    ];
    for path in temp_paths {
        if path.exists() {
            remove_path_if_exists(&path)?;
            removed_paths.push(path.display().to_string());
        }
    }
    if let Some(path) = crate::supervisor::remove_stale_service_state(&capsule_root)? {
        removed_paths.push(path.display().to_string());
    }

    removed_paths.sort();
    Ok(RecoveryReport {
        capsule_name: capsule_name.to_string(),
        broke_lock: options.break_lock,
        removed_paths,
    })
}

pub(crate) struct CapsuleLock {
    path: PathBuf,
}

impl Drop for CapsuleLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn acquire_capsule_lock(install_root: &Path, capsule_name: &str) -> Result<CapsuleLock> {
    let locks_root = install_root.join(".locks");
    fs::create_dir_all(&locks_root)?;
    let lock_path = locks_root.join(format!("{capsule_name}.lock"));
    match fs::create_dir(&lock_path) {
        Ok(()) => {
            let owner = format!("pid={}\n", std::process::id());
            if let Err(error) = fs::write(lock_path.join("owner"), owner) {
                let _ = fs::remove_dir_all(&lock_path);
                return Err(error.into());
            }
            Ok(CapsuleLock { path: lock_path })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(RuntimeError::Locked(capsule_name.to_string()))
        }
        Err(error) => Err(error.into()),
    }
}

fn break_capsule_lock(install_root: &Path, capsule_name: &str) -> Result<()> {
    remove_path_if_exists(
        &install_root
            .join(".locks")
            .join(format!("{capsule_name}.lock")),
    )
}

fn staging_dir(install_root: &Path, capsule_name: &str, capsule_version: &str) -> Result<PathBuf> {
    Ok(install_root.join(".staging").join(format!(
        "{capsule_name}-{capsule_version}-{}-{}",
        std::process::id(),
        unix_seconds()?
    )))
}

fn read_current_version(capsule_root: &Path) -> Result<Option<String>> {
    let current_version = capsule_root.join("current-version");
    match fs::read_to_string(current_version) {
        Ok(version) => Ok(Some(version.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_current_manifest(capsule_root: &Path) -> Result<Option<CapsuleManifest>> {
    let Some(current_version) = read_current_version(capsule_root)? else {
        return Ok(None);
    };
    let manifest_path = capsule_root
        .join("current")
        .join(cocoon_bundle::MANIFEST_NAME);
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
        RuntimeError::InstalledIntegrity(format!(
            "current manifest for {current_version} cannot be read at '{}': {error}",
            manifest_path.display()
        ))
    })?;
    CapsuleManifest::from_toml(&manifest_text)
        .map(Some)
        .map_err(|error| {
            RuntimeError::InstalledIntegrity(format!(
                "current manifest for {current_version} is invalid: {error}"
            ))
        })
}

fn enforce_permission_expansion_policy(
    capsule_root: &Path,
    new_manifest: &CapsuleManifest,
    options: InstallOptions,
) -> Result<()> {
    let Some(current_manifest) = read_current_manifest(capsule_root)? else {
        return Ok(());
    };
    if !current_manifest
        .update
        .permission_expansion_requires_confirmation
    {
        return Ok(());
    }

    let diff = diff_authority(&current_manifest, new_manifest);
    let policy = cocoon_policy::UpdatePolicy {
        permission_expansion_requires_confirmation: true,
        ..cocoon_policy::UpdatePolicy::default()
    };
    let report = cocoon_policy::build_authority_diff_report(&diff, &policy);
    if !report.confirmation_required || options.allow_permission_expansion {
        return Ok(());
    }

    Err(RuntimeError::PermissionExpansionRequiresConfirmation(
        cocoon_policy::format_authority_report(&report),
    ))
}

fn write_current_pointer(capsule_root: &Path, capsule_version: &str) -> Result<()> {
    let current_version = capsule_root.join("current-version");
    let temp = capsule_root.join("current-version.tmp");
    fs::write(&temp, format!("{capsule_version}\n"))?;
    fs::rename(temp, current_version)?;
    Ok(())
}

#[cfg(unix)]
fn promote_current(capsule_root: &Path, capsule_version: &str) -> Result<()> {
    use std::os::unix::fs::symlink;

    let current = capsule_root.join("current");
    let current_tmp = capsule_root.join("current.tmp");
    remove_path_if_exists(&current_tmp)?;
    symlink(Path::new("versions").join(capsule_version), &current_tmp)?;
    rename_over_current(&current_tmp, &current)?;
    Ok(())
}

#[cfg(not(unix))]
fn promote_current(capsule_root: &Path, capsule_version: &str) -> Result<()> {
    let current = capsule_root.join("current");
    let current_tmp = capsule_root.join("current.tmp");
    remove_path_if_exists(&current_tmp)?;
    copy_dir_recursive(
        &capsule_root.join("versions").join(capsule_version),
        &current_tmp,
    )?;
    remove_path_if_exists(&current)?;
    fs::rename(current_tmp, current)?;
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };

    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    Ok(())
}

#[cfg(unix)]
fn rename_over_current(source: &Path, target: &Path) -> Result<()> {
    match fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(_) if target.is_dir() => {
            fs::remove_dir_all(target)?;
            fs::rename(source, target)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&source_path, &target_path)?;
        } else {
            fs::copy(source_path, target_path)?;
        }
    }
    Ok(())
}

fn build_install_receipt(
    reader: &BundleReader,
    version_dir: &Path,
    bundle_bytes: &[u8],
    previous_receipt: Option<String>,
    receipt_signing: &ReceiptSigningOptions,
) -> Result<InstallReceipt> {
    let bundle_hash = hash_bytes(bundle_bytes);
    let body = InstallReceiptBody {
        capsule_name: reader.manifest.capsule.name.to_string(),
        capsule_version: reader.manifest.capsule.version.to_string(),
        manifest_hash: reader.hash_manifest.manifest_hash.clone(),
        bundle_hash: bundle_hash.clone(),
        payload_identity: Some(payload_identity_for_cocoon_bundle(reader, &bundle_hash)),
        permission_hash: hash_permissions(&reader.manifest),
        installed_at: format!("unix:{}", unix_seconds()?),
        install_root: version_dir.display().to_string(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        previous_receipt,
    };
    let body_hash = hash_bytes(&canonical_receipt_body_bytes(&body)?);
    let event = "capsule_install".to_string();
    let signature = sign_receipt_body(&event, &body, receipt_signing)?;

    Ok(InstallReceipt {
        receipt_version: 1,
        event,
        body,
        body_hash,
        signature,
    })
}

fn payload_identity_for_cocoon_bundle(reader: &BundleReader, bundle_hash: &str) -> PayloadIdentity {
    PayloadIdentity {
        layer: "cocoon-bundle".to_string(),
        name: reader.manifest.capsule.name.to_string(),
        version: reader.manifest.capsule.version.to_string(),
        digest: bundle_hash.to_string(),
        verifier: "cocoon-bundle hash manifest".to_string(),
    }
}

fn previous_receipt_hash(capsule_root: &Path) -> Result<Option<String>> {
    let latest = capsule_root.join("receipts").join("latest.json");
    if !latest.exists() {
        return Ok(None);
    }
    let bytes = fs::read(latest)?;
    let receipt = serde_json::from_slice::<InstallReceipt>(&bytes)?;
    verify_install_receipt(&receipt)?;
    verify_install_receipt_archive(capsule_root, &receipt)?;
    Ok(Some(receipt.body_hash))
}

fn verify_install_receipt(receipt: &InstallReceipt) -> Result<()> {
    let actual = hash_bytes(&canonical_receipt_body_bytes(&receipt.body)?);
    if actual != receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "install receipt body hash mismatch: expected {}, got {actual}",
            receipt.body_hash
        )));
    }
    verify_receipt_signature(&receipt.event, &receipt.body, &receipt.signature, "install")?;
    Ok(())
}

fn verify_install_receipt_archive(
    capsule_root: &Path,
    latest_receipt: &InstallReceipt,
) -> Result<()> {
    let archive_path = capsule_root
        .join("receipts")
        .join(format!("{}.json", latest_receipt.body.capsule_version));
    let bytes = fs::read(&archive_path).map_err(|error| {
        RuntimeError::ReceiptAudit(format!(
            "install receipt archive '{}' cannot be read: {error}",
            archive_path.display()
        ))
    })?;
    let archived = serde_json::from_slice::<InstallReceipt>(&bytes)?;
    verify_install_receipt(&archived)?;
    if archived.body_hash != latest_receipt.body_hash {
        return Err(RuntimeError::ReceiptAudit(format!(
            "latest install receipt archive mismatch: latest {}, archived {}",
            latest_receipt.body_hash, archived.body_hash
        )));
    }
    Ok(())
}

fn write_receipts(
    capsule_root: &Path,
    capsule_version: &str,
    receipt: &InstallReceipt,
) -> Result<()> {
    let receipts_root = capsule_root.join("receipts");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;

    let version_receipt = receipts_root.join(format!("{capsule_version}.json"));
    atomic_write(&version_receipt, &bytes)?;

    let latest = receipts_root.join("latest.json");
    atomic_write(&latest, &bytes)?;
    Ok(())
}

fn build_rollback_receipt(
    capsule_name: &CapsuleName,
    previous_version: &str,
    target_version: &CapsuleVersion,
    receipt_signing: &ReceiptSigningOptions,
) -> Result<RollbackReceipt> {
    let body = RollbackReceiptBody {
        capsule_name: capsule_name.to_string(),
        previous_version: previous_version.to_string(),
        target_version: target_version.to_string(),
        rolled_back_at: format!("unix:{}", unix_seconds()?),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_rollback_receipt_body_bytes(&body)?);
    let event = "capsule_rollback".to_string();
    let signature = sign_receipt_body(&event, &body, receipt_signing)?;

    Ok(RollbackReceipt {
        receipt_version: 1,
        event,
        body,
        body_hash,
        signature,
    })
}

fn write_rollback_receipt(capsule_root: &Path, receipt: &RollbackReceipt) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("rollbacks");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let receipt_name = format!(
        "{}-to-{}.json",
        receipt.body.rolled_back_at.replace(':', "-"),
        receipt.body.target_version
    );

    atomic_write(&receipts_root.join(receipt_name), &bytes)?;

    let latest = receipts_root.join("latest.json");
    atomic_write(&latest, &bytes)?;
    Ok(())
}

fn canonical_receipt_body_bytes(body: &InstallReceiptBody) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(body)?)
}

fn canonical_rollback_receipt_body_bytes(body: &RollbackReceiptBody) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(body)?)
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::SystemClock)?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_writes_version_and_receipt() {
        let (_fixture_dir, capsule) = fixture_capsule("0.1.0");
        let install_root = TempDir::new().unwrap();

        let receipt = install_capsule(&capsule, install_root.path()).unwrap();

        assert_eq!(receipt.receipt_version, 1);
        assert_eq!(receipt.body.capsule_name, "install-test");
        assert_eq!(receipt.body.capsule_version, "0.1.0");
        assert_eq!(
            receipt.body.payload_identity,
            Some(PayloadIdentity {
                layer: "cocoon-bundle".to_string(),
                name: "install-test".to_string(),
                version: "0.1.0".to_string(),
                digest: receipt.body.bundle_hash.clone(),
                verifier: "cocoon-bundle hash manifest".to_string(),
            })
        );
        assert_eq!(
            receipt.body_hash,
            hash_bytes(&canonical_receipt_body_bytes(&receipt.body).unwrap())
        );
        assert_eq!(receipt.signature, None);
        assert!(
            install_root
                .path()
                .join("capsules/install-test/versions/0.1.0/Cocoon.toml")
                .exists()
        );
        assert!(
            install_root
                .path()
                .join("capsules/install-test/current/Cocoon.toml")
                .exists()
        );
        assert!(
            install_root
                .path()
                .join("capsules/install-test/receipts/latest.json")
                .exists()
        );
    }

    #[test]
    fn second_install_links_previous_receipt_body_hash() {
        let (_first_dir, first_capsule) = fixture_capsule("0.1.0");
        let (_second_dir, second_capsule) = fixture_capsule("0.2.0");
        let install_root = TempDir::new().unwrap();

        let first = install_capsule(&first_capsule, install_root.path()).unwrap();
        let second = install_capsule(&second_capsule, install_root.path()).unwrap();

        assert_eq!(second.body.previous_receipt, Some(first.body_hash));
    }

    #[test]
    fn legacy_install_receipt_hash_without_payload_identity_is_accepted() {
        let body = InstallReceiptBody {
            capsule_name: "install-test".to_string(),
            capsule_version: "0.1.0".to_string(),
            manifest_hash: "blake3:manifest".to_string(),
            bundle_hash: "blake3:bundle".to_string(),
            payload_identity: None,
            permission_hash: "blake3:permission".to_string(),
            installed_at: "unix:1".to_string(),
            install_root: "/pkg/cocoon/capsules/install-test/versions/0.1.0".to_string(),
            runtime_version: "0.1.0".to_string(),
            previous_receipt: None,
        };
        let body_hash = hash_bytes(&canonical_receipt_body_bytes(&body).unwrap());
        let legacy_json = format!(
            r#"{{
  "receipt_version": 1,
  "event": "capsule_install",
  "body": {{
    "capsule_name": "install-test",
    "capsule_version": "0.1.0",
    "manifest_hash": "blake3:manifest",
    "bundle_hash": "blake3:bundle",
    "permission_hash": "blake3:permission",
    "installed_at": "unix:1",
    "install_root": "/pkg/cocoon/capsules/install-test/versions/0.1.0",
    "runtime_version": "0.1.0",
    "previous_receipt": null
  }},
  "body_hash": "{body_hash}",
  "signature": null
}}"#
        );

        let receipt: InstallReceipt = serde_json::from_str(&legacy_json).unwrap();

        assert_eq!(receipt.body.payload_identity, None);
        verify_install_receipt(&receipt).unwrap();
    }

    #[test]
    fn permission_expansion_requires_explicit_install_option() {
        let (_first_dir, first_capsule) = fixture_capsule("0.1.0");
        let (_second_dir, second_capsule) = fixture_capsule_with_manifest(
            "0.2.0",
            r#"
[[permission]]
scheme = "tcp"
action = "connect"
target = "*"
"#,
        );
        let install_root = TempDir::new().unwrap();
        install_capsule(&first_capsule, install_root.path()).unwrap();

        let error = install_capsule(&second_capsule, install_root.path()).unwrap_err();
        let RuntimeError::PermissionExpansionRequiresConfirmation(report) = error else {
            panic!("unexpected install error: {error}");
        };
        assert!(report.contains("Added permissions:"), "{report}");
        assert!(report.contains("allow tcp connect *"), "{report}");
        assert!(
            !install_root
                .path()
                .join("capsules/install-test/versions/0.2.0")
                .exists()
        );

        let receipt = install_capsule_with_options(
            &second_capsule,
            install_root.path(),
            InstallOptions {
                allow_permission_expansion: true,
            },
        )
        .unwrap();

        assert_eq!(receipt.body.capsule_version, "0.2.0");
        assert_eq!(
            fs::read_to_string(
                install_root
                    .path()
                    .join("capsules/install-test/current-version")
            )
            .unwrap()
            .trim(),
            "0.2.0"
        );
    }

    #[test]
    fn recover_removes_stale_service_state() {
        let (_fixture_dir, capsule) = fixture_capsule("0.1.0");
        let install_root = TempDir::new().unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();
        let capsule_root = install_root.path().join("capsules/install-test");
        let service_root = capsule_root.join("service");
        fs::create_dir_all(&service_root).unwrap();
        let state = crate::ServiceStateRecord {
            capsule_name: "install-test".to_string(),
            capsule_version: "0.1.0".to_string(),
            pid: u32::MAX,
            command: "/app/bin/install-test".to_string(),
            args: Vec::new(),
            actual_args: Vec::new(),
            authority_enforced: false,
            authority_mode: crate::RunAuthorityMode::SmokeUnenforced,
            stdout_log: capsule_root
                .join("logs/stale.stdout.log")
                .display()
                .to_string(),
            stderr_log: capsule_root
                .join("logs/stale.stderr.log")
                .display()
                .to_string(),
            started_at: "unix:1".to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let state_path = service_root.join("state.json");
        fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

        let report = recover_capsule(
            &CapsuleName::parse("install-test").unwrap(),
            install_root.path(),
        )
        .unwrap();

        assert!(!state_path.exists());
        assert!(
            report
                .removed_paths
                .iter()
                .any(|path| path.ends_with("capsules/install-test/service/state.json")),
            "{:?}",
            report.removed_paths
        );
    }

    #[test]
    fn recover_all_removes_stale_service_state() {
        let (_fixture_dir, capsule) = fixture_capsule("0.1.0");
        let install_root = TempDir::new().unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();
        let capsule_root = install_root.path().join("capsules/install-test");
        let service_root = capsule_root.join("service");
        fs::create_dir_all(&service_root).unwrap();
        let state = crate::ServiceStateRecord {
            capsule_name: "install-test".to_string(),
            capsule_version: "0.1.0".to_string(),
            pid: u32::MAX,
            command: "/app/bin/install-test".to_string(),
            args: Vec::new(),
            actual_args: Vec::new(),
            authority_enforced: false,
            authority_mode: crate::RunAuthorityMode::SmokeUnenforced,
            stdout_log: capsule_root
                .join("logs/stale.stdout.log")
                .display()
                .to_string(),
            stderr_log: capsule_root
                .join("logs/stale.stderr.log")
                .display()
                .to_string(),
            started_at: "unix:1".to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let state_path = service_root.join("state.json");
        let pid_path = service_root.join("pid");
        fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        fs::write(&pid_path, format!("{}\n", state.pid)).unwrap();

        let report = recover_all_capsules(install_root.path()).unwrap();

        assert_eq!(report.recovered.len(), 1);
        assert_eq!(report.recovered[0].capsule_name, "install-test");
        assert!(!state_path.exists());
        assert!(!pid_path.exists());
        assert!(
            report.recovered[0]
                .removed_paths
                .iter()
                .any(|path| path.ends_with("capsules/install-test/service/state.json")),
            "{:?}",
            report.recovered[0].removed_paths
        );
    }

    #[test]
    fn rollback_promotes_previous_version_and_writes_receipt() {
        let (_first_dir, first_capsule) = fixture_capsule("0.1.0");
        let (_second_dir, second_capsule) = fixture_capsule("0.2.0");
        let install_root = TempDir::new().unwrap();
        install_capsule(&first_capsule, install_root.path()).unwrap();
        install_capsule(&second_capsule, install_root.path()).unwrap();

        let receipt = rollback_capsule(
            &CapsuleName::parse("install-test").unwrap(),
            &CapsuleVersion::parse("0.1.0").unwrap(),
            install_root.path(),
        )
        .unwrap();

        assert_eq!(receipt.event, "capsule_rollback");
        assert_eq!(receipt.body.previous_version, "0.2.0");
        assert_eq!(receipt.body.target_version, "0.1.0");
        assert_eq!(
            fs::read_to_string(
                install_root
                    .path()
                    .join("capsules/install-test/current-version")
            )
            .unwrap()
            .trim(),
            "0.1.0"
        );
        assert!(
            install_root
                .path()
                .join("capsules/install-test/receipts/rollbacks/latest.json")
                .exists()
        );
    }

    #[test]
    fn signed_rollback_receipt_is_audited() {
        let (_first_dir, first_capsule) = fixture_capsule("0.1.0");
        let (_second_dir, second_capsule) = fixture_capsule("0.2.0");
        let install_root = TempDir::new().unwrap();
        install_capsule(&first_capsule, install_root.path()).unwrap();
        install_capsule(&second_capsule, install_root.path()).unwrap();
        let receipt_signing =
            ReceiptSigningOptions::with_signing_key(cocoon_bundle::BundleSigningKey::generate());

        let receipt = rollback_capsule_with_receipt_signing(
            &CapsuleName::parse("install-test").unwrap(),
            &CapsuleVersion::parse("0.1.0").unwrap(),
            install_root.path(),
            receipt_signing,
        )
        .unwrap();

        assert!(receipt.signature.is_some());
        let audit = crate::audit_capsule(
            &CapsuleName::parse("install-test").unwrap(),
            install_root.path(),
        )
        .unwrap();
        assert!(
            audit
                .checks
                .iter()
                .any(|check| check.name == "latest rollback receipt signature")
        );
    }

    fn fixture_capsule(version: &str) -> (TempDir, PathBuf) {
        fixture_capsule_with_manifest(version, "")
    }

    fn fixture_capsule_with_manifest(version: &str, extra_manifest: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("Cocoon.toml"),
            r#"
[capsule]
name = "install-test"
version = "__VERSION__"

[entry]
cmd = "/app/bin/install-test"

__EXTRA_MANIFEST__
"#
            .replace("__VERSION__", version)
            .replace("__EXTRA_MANIFEST__", extra_manifest),
        )
        .unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        write_executable(source.join("bin/install-test"), b"#!/bin/sh\n").unwrap();

        let capsule = dir.path().join("install-test.cocoon");
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
