use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use cocoon_bundle::SignatureMetadata;
use cocoon_core::{CapsuleManifest, CapsuleName, GuestPath, hash_bytes};

use crate::authority::run_redox_capsule_fd_launch_backend;
use crate::fsutil::atomic_write;
use crate::install::acquire_capsule_lock;
use crate::receipt::{ReceiptSigningOptions, sign_receipt_body};
use crate::{Result, RuntimeError};

fn is_false(value: &bool) -> bool {
    !*value
}

const HASH_MANIFEST_NAME: &str = "manifest/hashes.json";
const SIGNATURE_NAME: &str = "manifest/signature.json";
const SBOM_NAME: &str = "manifest/sbom.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RunReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: RunReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RunReceiptBody {
    pub capsule_name: String,
    pub capsule_version: String,
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub actual_args: Vec<String>,
    pub authority_enforced: bool,
    pub authority_mode: RunAuthorityMode,
    #[serde(default)]
    pub authority_enforced_for_service: bool,
    #[serde(default)]
    pub production_arbitrary_service: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub structured_child_result: bool,
    #[serde(default)]
    pub open_executable_before_restriction: bool,
    #[serde(default)]
    pub open_declared_preopens_before_restriction: bool,
    #[serde(default)]
    pub entered_restricted_namespace: bool,
    #[serde(default)]
    pub exec_from_fd_attempted: bool,
    #[serde(default)]
    pub exec_from_fd_succeeded: bool,
    #[serde(default)]
    pub allowed_preopen_read: bool,
    #[serde(default)]
    pub denied_file_path: String,
    #[serde(default)]
    pub denied_file_rejected: bool,
    #[serde(default)]
    pub hidden_scheme_path: String,
    #[serde(default)]
    pub hidden_scheme_rejected: bool,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout_log: String,
    pub stdout_hash: String,
    pub stderr_log: String,
    pub stderr_hash: String,
    pub started_at: String,
    pub finished_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum RunAuthorityMode {
    #[serde(rename = "smoke-unenforced")]
    SmokeUnenforced,
    #[serde(rename = "redox-enforced-capsule-entrypoint")]
    RedoxEnforcedCapsuleEntrypoint,
    #[serde(rename = "authority-unavailable")]
    AuthorityUnavailable,
    #[serde(rename = "redox-enforced")]
    RedoxEnforced,
}

impl std::fmt::Display for RunAuthorityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SmokeUnenforced => "smoke-unenforced",
            Self::RedoxEnforcedCapsuleEntrypoint => "redox-enforced-capsule-entrypoint",
            Self::AuthorityUnavailable => "authority-unavailable",
            Self::RedoxEnforced => "redox-enforced",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledVerification {
    pub capsule_name: String,
    pub capsule_version: String,
    pub files_checked: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOptions {
    pub allow_unenforced_authority: bool,
    pub enforce_redox_authority: bool,
}

impl RunOptions {
    fn authority_enforced(self) -> bool {
        self.enforce_redox_authority
    }

    fn authority_mode(self) -> RunAuthorityMode {
        if self.allow_unenforced_authority {
            RunAuthorityMode::SmokeUnenforced
        } else if self.enforce_redox_authority {
            RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint
        } else {
            RunAuthorityMode::AuthorityUnavailable
        }
    }
}

pub fn verify_installed_capsule(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<InstalledVerification> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)
}

pub(crate) fn verify_installed_capsule_unlocked(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<InstalledVerification> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");
    if !capsule_root.exists() || !current_root.exists() {
        return Err(RuntimeError::NotInstalled(capsule_name.to_string()));
    }

    let manifest = read_installed_manifest(&current_root)?;
    let hash_manifest = read_installed_hash_manifest(&current_root)?;

    let manifest_text = manifest.to_toml_pretty()?;
    let manifest_hash = hash_bytes(manifest_text.as_bytes());
    if manifest_hash != hash_manifest.manifest_hash {
        return Err(RuntimeError::InstalledIntegrity(format!(
            "manifest hash mismatch for {capsule_name}: expected {}, got {manifest_hash}",
            hash_manifest.manifest_hash
        )));
    }

    for (path, expected_hash) in &hash_manifest.files {
        let bytes = fs::read(current_root.join(path))?;
        let actual_hash = hash_bytes(&bytes);
        if actual_hash != *expected_hash {
            return Err(RuntimeError::InstalledIntegrity(format!(
                "hash mismatch for {path}: expected {expected_hash}, got {actual_hash}"
            )));
        }
    }

    for path in installed_file_keys(&current_root)? {
        if !is_generated_metadata(&path) && !hash_manifest.files.contains_key(&path) {
            return Err(RuntimeError::InstalledIntegrity(format!(
                "extra installed file not covered by hash manifest: {path}"
            )));
        }
    }

    let entrypoint = map_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cmd,
        "entry.cmd",
    )?;
    verify_executable(&entrypoint)?;

    Ok(InstalledVerification {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        files_checked: hash_manifest.files.len(),
    })
}

pub fn run_installed_capsule(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<RunReceipt> {
    run_installed_capsule_with_options(capsule_name, install_root, RunOptions::default())
}

pub fn run_installed_capsule_with_options(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: RunOptions,
) -> Result<RunReceipt> {
    run_installed_capsule_with_options_and_receipt_signing(
        capsule_name,
        install_root,
        options,
        ReceiptSigningOptions::default(),
    )
}

pub fn run_installed_capsule_with_options_and_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: RunOptions,
    receipt_signing: ReceiptSigningOptions,
) -> Result<RunReceipt> {
    validate_run_authority_options(options)?;
    if options.enforce_redox_authority {
        return run_installed_capsule_with_redox_fd_backend(
            capsule_name,
            install_root,
            receipt_signing,
        );
    }

    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let manifest = read_installed_manifest(&current_root)?;
    enforce_run_authority(options)?;
    let executable = map_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cmd,
        "entry.cmd",
    )?;
    let cwd = map_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cwd,
        "entry.cwd",
    )?;
    let run_id = format!("{}-{}", unix_seconds()?, std::process::id());
    let logs_root = capsule_root.join("logs");
    fs::create_dir_all(&logs_root)?;
    let stdout_log = logs_root.join(format!("{run_id}.stdout.log"));
    let stderr_log = logs_root.join(format!("{run_id}.stderr.log"));

    let started_at = format!("unix:{}", unix_seconds()?);
    let output = run_entry(&executable, &manifest.entry.args, &cwd)?;
    let finished_at = format!("unix:{}", unix_seconds()?);

    fs::write(&stdout_log, &output.stdout)?;
    fs::write(&stderr_log, &output.stderr)?;

    let body = RunReceiptBody {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        command: manifest.entry.cmd.to_string(),
        args: manifest.entry.args.clone(),
        actual_args: manifest.entry.args.clone(),
        authority_enforced: options.authority_enforced(),
        authority_mode: options.authority_mode(),
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
        exit_code: output.status.code(),
        success: output.status.success(),
        stdout_log: stdout_log.display().to_string(),
        stdout_hash: hash_bytes(&output.stdout),
        stderr_log: stderr_log.display().to_string(),
        stderr_hash: hash_bytes(&output.stderr),
        started_at,
        finished_at,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_run_receipt_body_bytes(&body)?);
    let event = "capsule_run".to_string();
    let signature = sign_receipt_body(&event, &body, &receipt_signing)?;
    let receipt = RunReceipt {
        receipt_version: 1,
        event,
        body,
        body_hash,
        signature,
    };
    write_run_receipt(&capsule_root, &run_id, &receipt)?;

    Ok(receipt)
}

fn run_installed_capsule_with_redox_fd_backend(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<RunReceipt> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let backend = run_redox_capsule_fd_launch_backend(capsule_name, install_root, "runs")?;
    if !backend.service_enforced {
        return Err(RuntimeError::UnenforcedAuthority(format!(
            "Redox FD-only run backend did not enforce the service boundary: {}",
            backend.failure_message
        )));
    }

    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let receipt_id = backend.receipt_id.clone();
    let body = RunReceiptBody {
        capsule_name: backend.capsule_name,
        capsule_version: backend.capsule_version,
        command: backend.command,
        args: backend.args,
        actual_args: backend.actual_args,
        authority_enforced: true,
        authority_mode: RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint,
        authority_enforced_for_service: backend.service_enforced,
        production_arbitrary_service: false,
        structured_child_result: backend.structured_child_result,
        open_executable_before_restriction: backend.open_executable_before_restriction,
        open_declared_preopens_before_restriction: backend
            .open_declared_preopens_before_restriction,
        entered_restricted_namespace: backend.entered_restricted_namespace,
        exec_from_fd_attempted: backend.exec_from_fd_attempted,
        exec_from_fd_succeeded: backend.exec_from_fd_succeeded,
        allowed_preopen_read: backend.allowed_preopen_read,
        denied_file_path: backend.denied_file_path,
        denied_file_rejected: backend.denied_file_rejected,
        hidden_scheme_path: backend.hidden_scheme_path,
        hidden_scheme_rejected: backend.hidden_scheme_rejected,
        exit_code: backend.child_exit_code,
        success: backend.success,
        stdout_log: backend.stdout_log,
        stdout_hash: backend.stdout_hash,
        stderr_log: backend.stderr_log,
        stderr_hash: backend.stderr_hash,
        started_at: backend.started_at,
        finished_at: backend.finished_at,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let body_hash = hash_bytes(&canonical_run_receipt_body_bytes(&body)?);
    let event = "capsule_run".to_string();
    let signature = sign_receipt_body(&event, &body, &receipt_signing)?;
    let receipt = RunReceipt {
        receipt_version: 1,
        event,
        body,
        body_hash,
        signature,
    };
    write_run_receipt(&capsule_root, &receipt_id, &receipt)?;
    Ok(receipt)
}

fn validate_run_authority_options(options: RunOptions) -> Result<()> {
    if options.allow_unenforced_authority && options.enforce_redox_authority {
        return Err(RuntimeError::UnenforcedAuthority(
            "--allow-unenforced-authority conflicts with --enforce-redox-authority".to_string(),
        ));
    }
    Ok(())
}

fn enforce_run_authority(options: RunOptions) -> Result<()> {
    if options.allow_unenforced_authority {
        return Ok(());
    }

    Err(RuntimeError::UnenforcedAuthority(
        "process launch currently lacks Redox namespace, scheme visibility, and preopen enforcement"
            .to_string(),
    ))
}

fn read_installed_manifest(current_root: &Path) -> Result<CapsuleManifest> {
    let manifest_text = fs::read_to_string(current_root.join(cocoon_bundle::MANIFEST_NAME))?;
    Ok(CapsuleManifest::from_toml(&manifest_text)?)
}

fn read_installed_hash_manifest(current_root: &Path) -> Result<cocoon_bundle::HashManifest> {
    let bytes = fs::read(current_root.join(HASH_MANIFEST_NAME))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn installed_file_keys(current_root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    collect_installed_file_keys(current_root, current_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_installed_file_keys(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_installed_file_keys(root, &path, files)?;
        } else {
            files.push(path_to_archive_key(root, &path)?);
        }
    }
    Ok(())
}

fn path_to_archive_key(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|error| {
        RuntimeError::InstalledIntegrity(format!("cannot relativize installed path: {error}"))
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(RuntimeError::InstalledIntegrity(format!(
                        "installed path '{}' is not UTF-8",
                        path.display()
                    )));
                };
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RuntimeError::InstalledIntegrity(format!(
                    "installed path '{}' must be relative and normalized",
                    path.display()
                )));
            }
        }
    }
    Ok(parts.join("/"))
}

fn is_generated_metadata(path: &str) -> bool {
    matches!(path, HASH_MANIFEST_NAME | SIGNATURE_NAME | SBOM_NAME)
}

#[cfg(unix)]
fn verify_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(RuntimeError::InstalledIntegrity(format!(
            "entrypoint '{}' is not executable",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_executable(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(RuntimeError::InstalledIntegrity(format!(
            "entrypoint '{}' is missing",
            path.display()
        )));
    }
    Ok(())
}

fn run_entry(executable: &Path, args: &[String], cwd: &Path) -> Result<Output> {
    let executable = absolute_process_path(executable)?;

    match Command::new(&executable)
        .args(args)
        .current_dir(cwd)
        .output()
    {
        Ok(output) => Ok(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && is_script(&executable)? => {
            Ok(Command::new("/usr/bin/sh")
                .arg(&executable)
                .args(args)
                .current_dir(cwd)
                .output()?)
        }
        Err(error) => Err(error.into()),
    }
}

fn absolute_process_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()?.join(path))
}

fn is_script(path: &Path) -> Result<bool> {
    let bytes = fs::read(path)?;
    Ok(bytes.starts_with(b"#!"))
}

fn map_guest_path(
    current_root: &Path,
    filesystem_root: &GuestPath,
    guest_path: &GuestPath,
    label: &str,
) -> Result<PathBuf> {
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

fn write_run_receipt(capsule_root: &Path, run_id: &str, receipt: &RunReceipt) -> Result<()> {
    let receipts_root = capsule_root.join("receipts").join("runs");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;

    atomic_write(&receipts_root.join(format!("{run_id}.json")), &bytes)?;

    let latest = receipts_root.join("latest.json");
    atomic_write(&latest, &bytes)?;
    Ok(())
}

fn canonical_run_receipt_body_bytes(body: &RunReceiptBody) -> Result<Vec<u8>> {
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
    use crate::install_capsule;
    use tempfile::TempDir;

    #[test]
    fn run_installed_capsule_writes_logs_and_receipt() {
        let (_fixture_dir, capsule) = fixture_capsule();
        let install_root = TempDir::new().unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();

        let receipt = run_installed_capsule_with_options(
            &CapsuleName::parse("run-test").unwrap(),
            install_root.path(),
            RunOptions {
                allow_unenforced_authority: true,
                enforce_redox_authority: false,
            },
        )
        .unwrap();

        assert_eq!(receipt.event, "capsule_run");
        assert_eq!(receipt.body.capsule_name, "run-test");
        assert_eq!(receipt.body.actual_args, receipt.body.args);
        assert!(!receipt.body.authority_enforced);
        assert_eq!(
            receipt.body.authority_mode,
            RunAuthorityMode::SmokeUnenforced
        );
        assert_eq!(
            serde_json::to_value(receipt.body.authority_mode).unwrap(),
            "smoke-unenforced"
        );
        assert_eq!(receipt.body.stdout_hash, hash_bytes(b"run-test-ok\n"));
        assert_eq!(receipt.body.stderr_hash, hash_bytes(b""));
        assert_eq!(receipt.body.exit_code, Some(0));
        assert!(receipt.body.success);
        assert!(
            fs::read_to_string(&receipt.body.stdout_log)
                .unwrap()
                .contains("run-test-ok")
        );
        assert!(
            install_root
                .path()
                .join("capsules/run-test/receipts/runs/latest.json")
                .exists()
        );
    }

    #[test]
    fn verify_installed_capsule_rejects_tampered_payload() {
        let (_fixture_dir, capsule) = fixture_capsule();
        let install_root = TempDir::new().unwrap();
        let capsule_name = CapsuleName::parse("run-test").unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();
        fs::write(
            install_root
                .path()
                .join("capsules/run-test/current/bin/run-test"),
            b"#!/bin/sh\necho tampered\n",
        )
        .unwrap();

        let error = verify_installed_capsule(&capsule_name, install_root.path()).unwrap_err();

        assert!(matches!(error, RuntimeError::InstalledIntegrity(_)));
    }

    #[test]
    fn run_installed_capsule_rejects_unenforced_authority_by_default() {
        let (_fixture_dir, capsule) = fixture_capsule();
        let install_root = TempDir::new().unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();

        let error = run_installed_capsule(
            &CapsuleName::parse("run-test").unwrap(),
            install_root.path(),
        )
        .unwrap_err();

        assert!(matches!(error, RuntimeError::UnenforcedAuthority(_)));
        assert_eq!(
            RunOptions::default().authority_mode(),
            RunAuthorityMode::AuthorityUnavailable
        );
    }

    #[test]
    fn run_authority_mode_serialized_strings_are_stable() {
        for (mode, serialized) in [
            (RunAuthorityMode::SmokeUnenforced, "\"smoke-unenforced\""),
            (
                RunAuthorityMode::RedoxEnforcedCapsuleEntrypoint,
                "\"redox-enforced-capsule-entrypoint\"",
            ),
            (
                RunAuthorityMode::AuthorityUnavailable,
                "\"authority-unavailable\"",
            ),
            (RunAuthorityMode::RedoxEnforced, "\"redox-enforced\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), serialized);
            assert_eq!(
                serde_json::from_str::<RunAuthorityMode>(serialized).unwrap(),
                mode
            );
        }
    }

    fn fixture_capsule() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("Cocoon.toml"),
            r#"
[capsule]
name = "run-test"
version = "0.1.0"

[entry]
cmd = "/app/bin/run-test"
"#,
        )
        .unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        write_executable(
            source.join("bin/run-test"),
            b"#!/bin/sh\necho run-test-ok\n",
        )
        .unwrap();

        let capsule = dir.path().join("run-test.cocoon");
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
