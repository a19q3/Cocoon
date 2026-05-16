use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cocoon_bundle::{BundleReader, VerificationIssue};
use cocoon_core::{hash_bytes, hash_permissions};

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

    #[error("receipt serialization failed: {0}")]
    Receipt(#[from] serde_json::Error),

    #[error("system clock is before UNIX epoch")]
    SystemClock,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstallReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: InstallReceiptBody,
    pub body_hash: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstallReceiptBody {
    pub capsule_name: String,
    pub capsule_version: String,
    pub manifest_hash: String,
    pub bundle_hash: String,
    pub permission_hash: String,
    pub installed_at: String,
    pub install_root: String,
    pub runtime_version: String,
    pub previous_receipt: Option<String>,
}

/// Install a capsule after integrity verification.
///
/// P0 materializes the verified capsule payload into:
/// `<install_root>/capsules/<name>/versions/<version>/`.
/// The current version pointer and receipt are written only after staging succeeds.
pub fn install_capsule(capsule_path: &Path, install_root: &Path) -> Result<InstallReceipt> {
    let bytes = fs::read(capsule_path)?;
    let reader = BundleReader::from_bytes(&bytes)?;
    let issues = reader.verify()?;
    let integrity_issues = issues
        .into_iter()
        .filter(VerificationIssue::is_integrity_failure)
        .collect::<Vec<_>>();
    if !integrity_issues.is_empty() {
        return Err(RuntimeError::Verification(integrity_issues));
    }

    let capsule_name = reader.manifest.capsule.name.to_string();
    let capsule_version = reader.manifest.capsule.version.to_string();
    let capsule_root = install_root.join("capsules").join(&capsule_name);
    let versions_root = capsule_root.join("versions");
    let version_dir = versions_root.join(&capsule_version);
    if version_dir.exists() {
        return Err(RuntimeError::AlreadyInstalled(format!(
            "{capsule_name} {capsule_version}"
        )));
    }

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
    )?;

    fs::rename(&staging_dir, &version_dir)?;
    write_receipts(&capsule_root, &capsule_version, &receipt)?;
    promote_current(&capsule_root, &capsule_version)?;
    write_current_pointer(&capsule_root, &capsule_version)?;

    Ok(receipt)
}

fn staging_dir(install_root: &Path, capsule_name: &str, capsule_version: &str) -> Result<PathBuf> {
    Ok(install_root.join(".staging").join(format!(
        "{capsule_name}-{capsule_version}-{}-{}",
        std::process::id(),
        unix_seconds()?
    )))
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
) -> Result<InstallReceipt> {
    let body = InstallReceiptBody {
        capsule_name: reader.manifest.capsule.name.to_string(),
        capsule_version: reader.manifest.capsule.version.to_string(),
        manifest_hash: reader.hash_manifest.manifest_hash.clone(),
        bundle_hash: hash_bytes(bundle_bytes),
        permission_hash: hash_permissions(&reader.manifest),
        installed_at: format!("unix:{}", unix_seconds()?),
        install_root: version_dir.display().to_string(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        previous_receipt,
    };
    let body_hash = hash_bytes(&canonical_receipt_body_bytes(&body)?);

    Ok(InstallReceipt {
        receipt_version: 1,
        event: "capsule_install".to_string(),
        body,
        body_hash,
        signature: None,
    })
}

fn previous_receipt_hash(capsule_root: &Path) -> Result<Option<String>> {
    let latest = capsule_root.join("receipts").join("latest.json");
    if !latest.exists() {
        return Ok(None);
    }
    let bytes = fs::read(latest)?;
    let receipt = serde_json::from_slice::<InstallReceipt>(&bytes)?;
    Ok(Some(receipt.body_hash))
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
    fs::write(&version_receipt, &bytes)?;

    let latest = receipts_root.join("latest.json");
    let latest_tmp = receipts_root.join("latest.json.tmp");
    fs::write(&latest_tmp, bytes)?;
    fs::rename(latest_tmp, latest)?;
    Ok(())
}

fn canonical_receipt_body_bytes(body: &InstallReceiptBody) -> Result<Vec<u8>> {
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
            receipt.body_hash,
            hash_bytes(&canonical_receipt_body_bytes(&receipt.body).unwrap())
        );
        assert_eq!(receipt.signature, None);
        assert!(install_root
            .path()
            .join("capsules/install-test/versions/0.1.0/Cocoon.toml")
            .exists());
        assert!(install_root
            .path()
            .join("capsules/install-test/current/Cocoon.toml")
            .exists());
        assert!(install_root
            .path()
            .join("capsules/install-test/receipts/latest.json")
            .exists());
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

    fn fixture_capsule(version: &str) -> (TempDir, PathBuf) {
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
"#
            .replace("__VERSION__", version),
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
