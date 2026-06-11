use std::fs::{self, File};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cocoon_bundle::SignatureMetadata;
use cocoon_core::{CapsuleName, hash_bytes};

use crate::fsutil::atomic_write;
use crate::install::acquire_capsule_lock;
use crate::receipt::{ReceiptSigningOptions, sign_receipt_body};
use crate::run::{
    RunAuthorityMode, absolute_process_path, map_guest_path, read_installed_manifest,
    verify_executable, verify_installed_capsule_unlocked,
};
use crate::{Result, RuntimeError};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceOptions {
    pub allow_unenforced_authority: bool,
    pub enforce_redox_authority: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ServiceStateRecord {
    pub capsule_name: String,
    pub capsule_version: String,
    pub pid: u32,
    pub command: String,
    pub args: Vec<String>,
    pub actual_args: Vec<String>,
    pub authority_enforced: bool,
    pub authority_mode: RunAuthorityMode,
    pub stdout_log: String,
    pub stderr_log: String,
    pub started_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ServiceLifecycleReceipt {
    pub receipt_version: u32,
    pub event: String,
    pub body: ServiceLifecycleReceiptBody,
    pub body_hash: String,
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ServiceLifecycleReceiptBody {
    pub capsule_name: String,
    pub capsule_version: Option<String>,
    pub action: ServiceLifecycleAction,
    pub pid: Option<u32>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub authority_enforced: bool,
    pub authority_mode: RunAuthorityMode,
    pub success: bool,
    pub detail: String,
    pub stdout_log: Option<String>,
    pub stdout_hash: Option<String>,
    pub stderr_log: Option<String>,
    pub stderr_hash: Option<String>,
    pub occurred_at: String,
    pub runtime_version: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ServiceLifecycleAction {
    #[serde(rename = "start")]
    Start,
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "health")]
    Health,
}

impl std::fmt::Display for ServiceLifecycleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Health => "health",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHealthReport {
    pub capsule_name: String,
    pub running: bool,
    pub state: Option<ServiceStateRecord>,
    pub latest_receipt: Option<ServiceLifecycleReceipt>,
    pub health_receipt: ServiceLifecycleReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSupervisorStatus {
    pub running: bool,
    pub state: Option<ServiceStateRecord>,
    pub latest_receipt: Option<ServiceLifecycleReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRestartReport {
    pub stop_receipt: Option<ServiceLifecycleReceipt>,
    pub start_receipt: ServiceLifecycleReceipt,
}

pub fn start_service(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<ServiceLifecycleReceipt> {
    start_service_with_options(capsule_name, install_root, ServiceOptions::default())
}

pub fn start_service_with_options(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: ServiceOptions,
) -> Result<ServiceLifecycleReceipt> {
    start_service_with_options_and_receipt_signing(
        capsule_name,
        install_root,
        options,
        ReceiptSigningOptions::default(),
    )
}

pub fn start_service_with_options_and_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: ServiceOptions,
    receipt_signing: ReceiptSigningOptions,
) -> Result<ServiceLifecycleReceipt> {
    validate_service_authority_options(options)?;
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let current_root = capsule_root.join("current");
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    if let Some(existing) = read_service_state_for_root(&capsule_root)? {
        if process_is_running(existing.pid)? {
            return Err(RuntimeError::ServiceAlreadyRunning(format!(
                "{} pid {}",
                capsule_name, existing.pid
            )));
        }
        remove_service_state(&capsule_root)?;
    }

    let manifest = read_installed_manifest(&current_root)?;
    let executable = map_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cmd,
        "entry.cmd",
    )?;
    verify_executable(&executable)?;
    let executable = absolute_process_path(&executable)?;
    let cwd = map_guest_path(
        &current_root,
        &manifest.filesystem.root,
        &manifest.entry.cwd,
        "entry.cwd",
    )?;
    let run_id = format!("service-{}-{}", unix_seconds()?, std::process::id());
    let logs_root = capsule_root.join("logs");
    fs::create_dir_all(&logs_root)?;
    let stdout_log = logs_root.join(format!("{run_id}.stdout.log"));
    let stderr_log = logs_root.join(format!("{run_id}.stderr.log"));

    let started_at = format!("unix:{}", unix_seconds()?);
    let child = spawn_entry(
        &executable,
        &manifest.entry.args,
        &cwd,
        &stdout_log,
        &stderr_log,
    )?;
    let pid = child.id();
    drop(child);

    let state = ServiceStateRecord {
        capsule_name: manifest.capsule.name.to_string(),
        capsule_version: manifest.capsule.version.to_string(),
        pid,
        command: manifest.entry.cmd.to_string(),
        args: manifest.entry.args.clone(),
        actual_args: manifest.entry.args.clone(),
        authority_enforced: false,
        authority_mode: options.authority_mode(),
        stdout_log: stdout_log.display().to_string(),
        stderr_log: stderr_log.display().to_string(),
        started_at: started_at.clone(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    if let Err(error) = write_service_state(&capsule_root, &state) {
        let _ = terminate_process(pid);
        return Err(error);
    }

    let receipt = build_lifecycle_receipt(
        ServiceLifecycleAction::Start,
        &state,
        true,
        "service process started".to_string(),
        None,
        None,
        &receipt_signing,
    )?;
    if let Err(error) = write_service_receipt(&capsule_root, &receipt) {
        let _ = terminate_process(pid);
        let _ = remove_service_state(&capsule_root);
        return Err(error);
    }
    Ok(receipt)
}

pub fn stop_service(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<ServiceLifecycleReceipt> {
    stop_service_with_receipt_signing(capsule_name, install_root, ReceiptSigningOptions::default())
}

pub fn stop_service_with_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<ServiceLifecycleReceipt> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let state = read_service_state_for_root(&capsule_root)?
        .ok_or_else(|| RuntimeError::ServiceNotRunning(capsule_name.to_string()))?;

    let was_running = process_is_running(state.pid)?;
    if was_running {
        terminate_process(state.pid)?;
        wait_until_stopped(state.pid)?;
    }
    let still_running = process_is_running(state.pid)?;
    if still_running {
        return Err(RuntimeError::ServiceSupervisor(format!(
            "service '{}' pid {} did not stop after SIGTERM",
            capsule_name, state.pid
        )));
    }

    let stdout_hash = optional_log_hash(&state.stdout_log)?;
    let stderr_hash = optional_log_hash(&state.stderr_log)?;
    remove_service_state(&capsule_root)?;
    let detail = if was_running {
        "service process stopped".to_string()
    } else {
        "stale service state cleared".to_string()
    };
    let receipt = build_lifecycle_receipt(
        ServiceLifecycleAction::Stop,
        &state,
        true,
        detail,
        stdout_hash,
        stderr_hash,
        &receipt_signing,
    )?;
    write_service_receipt(&capsule_root, &receipt)?;
    Ok(receipt)
}

pub fn restart_service_with_options_and_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    options: ServiceOptions,
    receipt_signing: ReceiptSigningOptions,
) -> Result<ServiceRestartReport> {
    let stop_receipt = match stop_service_with_receipt_signing(
        capsule_name,
        install_root,
        receipt_signing.clone(),
    ) {
        Ok(receipt) => Some(receipt),
        Err(RuntimeError::ServiceNotRunning(_)) => None,
        Err(error) => return Err(error),
    };
    let start_receipt = start_service_with_options_and_receipt_signing(
        capsule_name,
        install_root,
        options,
        receipt_signing,
    )?;
    Ok(ServiceRestartReport {
        stop_receipt,
        start_receipt,
    })
}

pub fn service_health_with_receipt_signing(
    capsule_name: &CapsuleName,
    install_root: &Path,
    receipt_signing: ReceiptSigningOptions,
) -> Result<ServiceHealthReport> {
    let _lock = acquire_capsule_lock(install_root, capsule_name.as_str())?;
    verify_installed_capsule_unlocked(capsule_name, install_root)?;
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    let state = read_service_state_for_root(&capsule_root)?;
    let running = state
        .as_ref()
        .map(|state| process_is_running(state.pid))
        .transpose()?
        .unwrap_or(false);
    let receipt = build_health_receipt(capsule_name, state.as_ref(), running, &receipt_signing)?;
    write_service_receipt(&capsule_root, &receipt)?;
    Ok(ServiceHealthReport {
        capsule_name: capsule_name.to_string(),
        running,
        state,
        latest_receipt: Some(receipt.clone()),
        health_receipt: receipt,
    })
}

pub fn service_supervisor_status(
    capsule_name: &CapsuleName,
    install_root: &Path,
) -> Result<ServiceSupervisorStatus> {
    let capsule_root = install_root.join("capsules").join(capsule_name.as_str());
    service_supervisor_status_for_root(&capsule_root)
}

pub(crate) fn service_supervisor_status_for_root(
    capsule_root: &Path,
) -> Result<ServiceSupervisorStatus> {
    let state = read_service_state_for_root(capsule_root)?;
    let running = state
        .as_ref()
        .map(|state| process_is_running(state.pid))
        .transpose()?
        .unwrap_or(false);
    let latest_receipt = read_optional_json::<ServiceLifecycleReceipt>(
        &capsule_root.join("receipts/services/latest.json"),
    )?;
    Ok(ServiceSupervisorStatus {
        running,
        state,
        latest_receipt,
    })
}

pub(crate) fn remove_stale_service_state(
    capsule_root: &Path,
) -> Result<Option<std::path::PathBuf>> {
    let state_path = capsule_root.join("service/state.json");
    let Some(state) = read_service_state_for_root(capsule_root)? else {
        return Ok(None);
    };
    if process_is_running(state.pid)? {
        return Ok(None);
    }
    remove_service_state(capsule_root)?;
    Ok(Some(state_path))
}

fn validate_service_authority_options(options: ServiceOptions) -> Result<()> {
    if options.allow_unenforced_authority && options.enforce_redox_authority {
        return Err(RuntimeError::UnenforcedAuthority(
            "--allow-unenforced-authority conflicts with --enforce-redox-authority".to_string(),
        ));
    }
    if options.enforce_redox_authority {
        return Err(RuntimeError::UnenforcedAuthority(
            "Redox-enforced service supervision is not implemented yet".to_string(),
        ));
    }
    if options.allow_unenforced_authority {
        return Ok(());
    }
    Err(RuntimeError::UnenforcedAuthority(
        "service start currently lacks Redox namespace, scheme visibility, and preopen enforcement"
            .to_string(),
    ))
}

impl ServiceOptions {
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

fn build_health_receipt(
    capsule_name: &CapsuleName,
    state: Option<&ServiceStateRecord>,
    running: bool,
    receipt_signing: &ReceiptSigningOptions,
) -> Result<ServiceLifecycleReceipt> {
    let body = ServiceLifecycleReceiptBody {
        capsule_name: capsule_name.to_string(),
        capsule_version: state.map(|state| state.capsule_version.clone()),
        action: ServiceLifecycleAction::Health,
        pid: state.map(|state| state.pid),
        command: state.map(|state| state.command.clone()),
        args: state.map(|state| state.args.clone()).unwrap_or_default(),
        authority_enforced: state.map(|state| state.authority_enforced).unwrap_or(false),
        authority_mode: state
            .map(|state| state.authority_mode)
            .unwrap_or(RunAuthorityMode::AuthorityUnavailable),
        success: running,
        detail: if running {
            "service process is running".to_string()
        } else if state.is_some() {
            "service state exists but process is not running".to_string()
        } else {
            "service is not started".to_string()
        },
        stdout_log: state.map(|state| state.stdout_log.clone()),
        stdout_hash: None,
        stderr_log: state.map(|state| state.stderr_log.clone()),
        stderr_hash: None,
        occurred_at: format!("unix:{}", unix_seconds()?),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    finalize_lifecycle_receipt("service_health", body, receipt_signing)
}

fn build_lifecycle_receipt(
    action: ServiceLifecycleAction,
    state: &ServiceStateRecord,
    success: bool,
    detail: String,
    stdout_hash: Option<String>,
    stderr_hash: Option<String>,
    receipt_signing: &ReceiptSigningOptions,
) -> Result<ServiceLifecycleReceipt> {
    let event = format!("service_{action}");
    let body = ServiceLifecycleReceiptBody {
        capsule_name: state.capsule_name.clone(),
        capsule_version: Some(state.capsule_version.clone()),
        action,
        pid: Some(state.pid),
        command: Some(state.command.clone()),
        args: state.args.clone(),
        authority_enforced: state.authority_enforced,
        authority_mode: state.authority_mode,
        success,
        detail,
        stdout_log: Some(state.stdout_log.clone()),
        stdout_hash,
        stderr_log: Some(state.stderr_log.clone()),
        stderr_hash,
        occurred_at: format!("unix:{}", unix_seconds()?),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    finalize_lifecycle_receipt(&event, body, receipt_signing)
}

fn finalize_lifecycle_receipt(
    event: &str,
    body: ServiceLifecycleReceiptBody,
    receipt_signing: &ReceiptSigningOptions,
) -> Result<ServiceLifecycleReceipt> {
    let body_hash = hash_bytes(&serde_json::to_vec(&body)?);
    let signature = sign_receipt_body(event, &body, receipt_signing)?;
    Ok(ServiceLifecycleReceipt {
        receipt_version: 1,
        event: event.to_string(),
        body,
        body_hash,
        signature,
    })
}

fn write_service_state(capsule_root: &Path, state: &ServiceStateRecord) -> Result<()> {
    let service_root = capsule_root.join("service");
    fs::create_dir_all(&service_root)?;
    atomic_write(
        &service_root.join("state.json"),
        &serde_json::to_vec_pretty(state)?,
    )?;
    atomic_write(
        &service_root.join("pid"),
        format!("{}\n", state.pid).as_bytes(),
    )
}

fn remove_service_state(capsule_root: &Path) -> Result<()> {
    for path in [
        capsule_root.join("service/state.json"),
        capsule_root.join("service/pid"),
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_service_state_for_root(capsule_root: &Path) -> Result<Option<ServiceStateRecord>> {
    read_optional_json(&capsule_root.join("service/state.json"))
}

fn write_service_receipt(capsule_root: &Path, receipt: &ServiceLifecycleReceipt) -> Result<()> {
    let receipts_root = capsule_root.join("receipts/services");
    fs::create_dir_all(&receipts_root)?;
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let receipt_name = format!(
        "{}-{}-{}.json",
        receipt.body.occurred_at.replace(':', "-"),
        receipt.body.action,
        receipt
            .body
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    atomic_write(&receipts_root.join(receipt_name), &bytes)?;
    atomic_write(&receipts_root.join("latest.json"), &bytes)?;
    Ok(())
}

fn process_is_running(pid: u32) -> Result<bool> {
    let status = Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            RuntimeError::ServiceSupervisor(format!(
                "failed to probe service pid {pid} with kill -0: {error}"
            ))
        })?;
    if !status.success() {
        return Ok(false);
    }
    Ok(!process_is_zombie(pid))
}

fn process_is_zombie(pid: u32) -> bool {
    let Ok(output) = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .any(|state| state.starts_with('Z'))
}

fn terminate_process(pid: u32) -> Result<()> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            RuntimeError::ServiceSupervisor(format!(
                "failed to terminate service pid {pid}: {error}"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(RuntimeError::ServiceSupervisor(format!(
            "kill -TERM {pid} exited with {status}"
        )))
    }
}

fn wait_until_stopped(pid: u32) -> Result<()> {
    for _ in 0..100 {
        if !process_is_running(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn spawn_entry(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    stdout_log: &Path,
    stderr_log: &Path,
) -> Result<Child> {
    match spawn_command(executable, args, cwd, stdout_log, stderr_log) {
        Ok(child) => Ok(child),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if script_has_shebang(executable)? {
                let mut fallback_args = Vec::with_capacity(args.len() + 1);
                fallback_args.push(executable.display().to_string());
                fallback_args.extend(args.iter().cloned());
                Ok(spawn_command(
                    Path::new("/usr/bin/sh"),
                    &fallback_args,
                    cwd,
                    stdout_log,
                    stderr_log,
                )?)
            } else {
                Err(error.into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn spawn_command(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    stdout_log: &Path,
    stderr_log: &Path,
) -> std::io::Result<Child> {
    let stdout = File::create(stdout_log)?;
    let stderr = File::create(stderr_log)?;
    Command::new(executable)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
}

fn script_has_shebang(path: &Path) -> Result<bool> {
    let bytes = fs::read(path)?;
    Ok(bytes.starts_with(b"#!"))
}

fn optional_log_hash(path: &str) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(hash_bytes(&bytes))),
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
    fn start_health_and_stop_service_write_state_and_receipts() {
        let (_fixture_dir, capsule) = fixture_service_capsule();
        let install_root = TempDir::new().unwrap();
        let capsule_name = CapsuleName::parse("service-test").unwrap();
        install_capsule(&capsule, install_root.path()).unwrap();

        let start = start_service_with_options(
            &capsule_name,
            install_root.path(),
            ServiceOptions {
                allow_unenforced_authority: true,
                enforce_redox_authority: false,
            },
        )
        .unwrap();

        assert_eq!(start.event, "service_start");
        assert!(start.body.success);
        assert_eq!(start.body.action, ServiceLifecycleAction::Start);
        assert!(start.body.pid.is_some());
        assert!(
            install_root
                .path()
                .join("capsules/service-test/service/state.json")
                .exists()
        );

        let health = service_health_with_receipt_signing(
            &capsule_name,
            install_root.path(),
            ReceiptSigningOptions::default(),
        )
        .unwrap();
        assert!(health.running);
        assert!(health.state.is_some());
        assert_eq!(health.health_receipt.event, "service_health");

        let stop = stop_service(&capsule_name, install_root.path()).unwrap();
        assert_eq!(stop.event, "service_stop");
        assert!(stop.body.success);
        assert!(stop.body.stdout_hash.is_some());
        assert!(stop.body.stderr_hash.is_some());
        assert!(
            !install_root
                .path()
                .join("capsules/service-test/service/state.json")
                .exists()
        );
    }

    fn fixture_service_capsule() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("Cocoon.toml"),
            r#"
[capsule]
name = "service-test"
version = "0.1.0"

[entry]
cmd = "/app/bin/service-test"
"#,
        )
        .unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        write_executable(
            source.join("bin/service-test"),
            b"#!/bin/sh\nexec sleep 30\n",
        )
        .unwrap();

        let capsule = dir.path().join("service-test.cocoon");
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
