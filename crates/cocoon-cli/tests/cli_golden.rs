use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn cocoon() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cocoon"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn inspect_verify_and_strict_verify_outputs_are_stable() {
    let temp = tempfile::tempdir().expect("tempdir can be created for CLI golden test");
    let capsule = temp.path().join("hello-service.cocoon");
    let source = repo_root().join("examples/hello-service");

    assert_success(
        cocoon()
            .args(["build"])
            .arg(source)
            .args(["--output"])
            .arg(&capsule)
            .output()
            .expect("cocoon build can be executed"),
    );

    let inspect = assert_success(
        cocoon()
            .args(["inspect"])
            .arg(&capsule)
            .output()
            .expect("cocoon inspect can be executed"),
    );
    let inspect_stdout = stdout(inspect);
    assert!(inspect_stdout.contains("=== Capsule: hello-service v0.1.0 ==="));
    assert!(inspect_stdout.contains("Permissions:\n  allow file readwrite /app/**"));
    assert!(inspect_stdout.contains("Preopens:\n  file /app -> /pkg/cocoon/capsules/hello-service/current rights=[Read, Execute]"));

    let verify = assert_success(
        cocoon()
            .args(["verify"])
            .arg(&capsule)
            .output()
            .expect("cocoon verify can be executed"),
    );
    assert_eq!(
        stdout(verify).trim(),
        "Bundle is unsigned (P0 signature placeholder).\n\nVerification passed with warnings."
    );

    let strict_verify = cocoon()
        .args(["verify", "--strict"])
        .arg(&capsule)
        .output()
        .expect("cocoon verify --strict can be executed");
    assert!(!strict_verify.status.success());
    assert_eq!(
        stdout(strict_verify).trim(),
        "Bundle signature is required but missing."
    );

    let plan = assert_success(
        cocoon()
            .args(["plan"])
            .arg(&capsule)
            .output()
            .expect("cocoon plan can be executed"),
    );
    let plan_stdout = stdout(plan);
    assert!(plan_stdout.contains("Runtime plan for hello-service@0.1.0"));
    assert!(plan_stdout.contains("log readwrite target=service-log"));
    assert!(
        plan_stdout
            .contains("file /pkg/cocoon/capsules/hello-service/current -> /app [read, execute]")
    );

    let plan_json = assert_success(
        cocoon()
            .args(["plan"])
            .arg(&capsule)
            .args(["--json"])
            .output()
            .expect("cocoon plan --json can be executed"),
    );
    let plan_json: serde_json::Value =
        serde_json::from_str(&stdout(plan_json)).expect("plan JSON is valid");
    assert_eq!(plan_json["capsule_name"], "hello-service");
    assert_eq!(plan_json["capsule_version"], "0.1.0");
    assert_eq!(plan_json["entry"]["cmd"], "/app/bin/hello-service");
    assert_eq!(plan_json["receipt_input"]["runtime_version"], "0.1.0");

    let install_root = temp.path().join("install-root");
    let missing_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed before install"),
    );
    let missing_status_stdout = stdout(missing_status);
    assert!(missing_status_stdout.contains("Status for hello-service"));
    assert!(missing_status_stdout.contains("State: not-installed"));
    assert!(missing_status_stdout.contains("Current version: <none>"));

    let check_before_install = assert_failure(
        cocoon()
            .args(["check-install", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon check-install can be executed before install"),
    );
    let check_before_install_stderr = stderr(check_before_install);
    assert!(
        check_before_install_stderr
            .contains("installed capsule 'hello-service' failed verification"),
        "{check_before_install_stderr}"
    );
    assert!(
        check_before_install_stderr.contains("capsule is not installed: hello-service"),
        "{check_before_install_stderr}"
    );

    let run_before_install = assert_failure(
        cocoon()
            .args(["run", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon run can be executed before install"),
    );
    let run_before_install_stderr = stderr(run_before_install);
    assert!(
        run_before_install_stderr.contains("failed to run capsule 'hello-service'"),
        "{run_before_install_stderr}"
    );
    assert!(
        run_before_install_stderr.contains("capsule is not installed: hello-service"),
        "{run_before_install_stderr}"
    );

    let lock_dir = install_root.join(".locks/hello-service.lock");
    std::fs::create_dir_all(&lock_dir).expect("test lock directory can be created");
    let locked_install = assert_failure(
        cocoon()
            .args(["install"])
            .arg(&capsule)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon install can be executed while lock is held"),
    );
    let locked_install_stderr = stderr(locked_install);
    assert!(
        locked_install_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_install_stderr}"
    );
    std::fs::remove_dir_all(&lock_dir).expect("test lock directory can be removed");

    let install = assert_success(
        cocoon()
            .args(["install"])
            .arg(&capsule)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon install can be executed"),
    );
    let install_stdout = stdout(install);
    assert!(install_stdout.contains("Installed hello-service@0.1.0"));
    assert!(install_stdout.contains("Event: capsule_install"));
    assert!(install_stdout.contains("Previous receipt: <none>"));
    assert!(
        install_root
            .join("capsules/hello-service/current/bin/hello-service")
            .exists()
    );
    assert!(
        install_root
            .join("capsules/hello-service/receipts/latest.json")
            .exists()
    );

    let installed_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed before first run"),
    );
    let installed_status_stdout = stdout(installed_status);
    assert!(installed_status_stdout.contains("Status for hello-service"));
    assert!(installed_status_stdout.contains("State: installed"));
    assert!(installed_status_stdout.contains("Current version: 0.1.0"));
    assert!(installed_status_stdout.contains("Latest install receipt: blake3:"));
    assert!(installed_status_stdout.contains("Latest run receipt: <none>"));

    let abandoned_staging = install_root.join(".staging/hello-service-0.1.0-abandoned");
    let current_tmp = install_root.join("capsules/hello-service/current.tmp");
    let current_version_tmp = install_root.join("capsules/hello-service/current-version.tmp");
    let latest_install_tmp = install_root.join("capsules/hello-service/receipts/latest.json.tmp");
    std::fs::create_dir_all(&abandoned_staging).expect("abandoned staging dir can be created");
    std::fs::create_dir_all(&current_tmp).expect("current tmp dir can be created");
    std::fs::write(&current_version_tmp, b"0.2.0\n").expect("current version tmp can be created");
    std::fs::write(&latest_install_tmp, b"{}").expect("latest receipt tmp can be created");
    let recover = assert_success(
        cocoon()
            .args(["recover", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon recover can be executed"),
    );
    let recover_stdout = stdout(recover);
    assert!(recover_stdout.contains("Recovered hello-service"));
    assert!(recover_stdout.contains("Broke lock: false"));
    assert!(recover_stdout.contains("Removed paths: 4"));
    assert!(!abandoned_staging.exists());
    assert!(!current_tmp.exists());
    assert!(!current_version_tmp.exists());
    assert!(!latest_install_tmp.exists());

    std::fs::create_dir_all(&lock_dir).expect("test lock directory can be recreated");
    let locked_recover = assert_failure(
        cocoon()
            .args(["recover", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon recover can be executed while lock is held"),
    );
    let locked_recover_stderr = stderr(locked_recover);
    assert!(
        locked_recover_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_recover_stderr}"
    );
    std::fs::write(&current_version_tmp, b"0.2.0\n")
        .expect("stale tmp can be recreated before break-lock recovery");
    let locked_check = assert_failure(
        cocoon()
            .args(["check-install", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon check-install can be executed while lock is held"),
    );
    let locked_check_stderr = stderr(locked_check);
    assert!(
        locked_check_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_check_stderr}"
    );
    let locked_status = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed while lock is held"),
    );
    let locked_status_stderr = stderr(locked_status);
    assert!(
        locked_status_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_status_stderr}"
    );
    let locked_logs = assert_failure(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon logs can be executed while lock is held"),
    );
    let locked_logs_stderr = stderr(locked_logs);
    assert!(
        locked_logs_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_logs_stderr}"
    );
    let locked_run = assert_failure(
        cocoon()
            .args(["run", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon run can be executed while lock is held"),
    );
    let locked_run_stderr = stderr(locked_run);
    assert!(
        locked_run_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_run_stderr}"
    );
    let locked_audit = assert_failure(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can be executed while lock is held"),
    );
    let locked_audit_stderr = stderr(locked_audit);
    assert!(
        locked_audit_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_audit_stderr}"
    );
    let break_lock_recover = assert_success(
        cocoon()
            .args(["recover", "hello-service", "--break-lock"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon recover --break-lock can be executed"),
    );
    let break_lock_recover_stdout = stdout(break_lock_recover);
    assert!(break_lock_recover_stdout.contains("Recovered hello-service"));
    assert!(break_lock_recover_stdout.contains("Broke lock: true"));
    assert!(break_lock_recover_stdout.contains("Removed paths: 1"));
    assert!(!lock_dir.exists());
    assert!(!current_version_tmp.exists());

    let duplicate_install = assert_failure(
        cocoon()
            .args(["install"])
            .arg(&capsule)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("duplicate cocoon install can be executed"),
    );
    let duplicate_install_stderr = stderr(duplicate_install);
    assert!(
        duplicate_install_stderr.contains("failed to install capsule"),
        "{duplicate_install_stderr}"
    );
    assert!(
        duplicate_install_stderr.contains("capsule version already installed: hello-service 0.1.0"),
        "{duplicate_install_stderr}"
    );

    let logs_before_run = assert_failure(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon logs can be executed before first run"),
    );
    let logs_before_run_stderr = stderr(logs_before_run);
    assert!(
        logs_before_run_stderr.contains("no run receipt found for capsule 'hello-service'"),
        "{logs_before_run_stderr}"
    );

    let check_install = assert_success(
        cocoon()
            .args(["check-install", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon check-install can be executed"),
    );
    let check_install_stdout = stdout(check_install);
    assert!(check_install_stdout.contains("Installed tree verified for hello-service@0.1.0"));
    assert!(check_install_stdout.contains("Files checked:"));

    let authority_probe = assert_failure(
        cocoon()
            .args(["probe-authority", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon probe-authority can be executed"),
    );
    let authority_probe_stderr = stderr(authority_probe);
    assert!(
        authority_probe_stderr.contains("failed to probe authority for capsule 'hello-service'"),
        "{authority_probe_stderr}"
    );
    assert!(
        authority_probe_stderr.contains("Redox authority probe unavailable on this platform"),
        "{authority_probe_stderr}"
    );

    let fd_launch_probe = assert_failure(
        cocoon()
            .args(["probe-fd-launch", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon probe-fd-launch can be executed"),
    );
    let fd_launch_probe_stderr = stderr(fd_launch_probe);
    assert!(
        fd_launch_probe_stderr
            .contains("failed to probe FD-only launch for capsule 'hello-service'"),
        "{fd_launch_probe_stderr}"
    );
    assert!(
        fd_launch_probe_stderr.contains("Redox FD-only launch probe unavailable on this platform"),
        "{fd_launch_probe_stderr}"
    );

    let unenforced_run = assert_failure(
        cocoon()
            .args(["run", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon run can be executed without unenforced authority override"),
    );
    let unenforced_run_stderr = stderr(unenforced_run);
    assert!(
        unenforced_run_stderr.contains("failed to run capsule 'hello-service'"),
        "{unenforced_run_stderr}"
    );
    assert!(
        unenforced_run_stderr.contains("runtime authority enforcement unavailable"),
        "{unenforced_run_stderr}"
    );
    assert!(
        unenforced_run_stderr.contains("lacks Redox namespace"),
        "{unenforced_run_stderr}"
    );

    let run = assert_success(
        cocoon()
            .args(["run", "hello-service", "--allow-unenforced-authority"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon run can be executed"),
    );
    let run_stdout = stdout(run);
    assert!(run_stdout.contains("Ran hello-service@0.1.0"));
    assert!(run_stdout.contains("Event: capsule_run"));
    assert!(run_stdout.contains("Authority enforced: false"));
    assert!(run_stdout.contains("Authority mode: smoke-unenforced"));
    assert!(run_stdout.contains("Success: true"));
    assert!(run_stdout.contains("Stdout hash: blake3:"));
    assert!(run_stdout.contains("Stderr hash: blake3:"));
    assert!(
        install_root
            .join("capsules/hello-service/receipts/runs/latest.json")
            .exists()
    );

    let status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed"),
    );
    let status_stdout = stdout(status);
    assert!(status_stdout.contains("Status for hello-service"));
    assert!(status_stdout.contains("State: last-run-succeeded"));
    assert!(status_stdout.contains("Current version: 0.1.0"));
    assert!(status_stdout.contains("Latest install receipt: blake3:"));
    assert!(status_stdout.contains("Latest run receipt: blake3:"));
    assert!(status_stdout.contains("Latest run authority enforced: false"));
    assert!(status_stdout.contains("Latest run authority mode: smoke-unenforced"));
    assert!(status_stdout.contains("Latest run stdout hash: blake3:"));
    assert!(status_stdout.contains("Latest run stderr hash: blake3:"));

    let logs = assert_success(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon logs can be executed"),
    );
    let logs_stdout = stdout(logs);
    assert!(logs_stdout.contains("== stdout =="));
    assert!(logs_stdout.contains("Hello from Cocoon hello-service!"));

    let source_v2 = temp.path().join("hello-service-v2");
    copy_dir_recursive(&repo_root().join("examples/hello-service"), &source_v2);
    let manifest_v2 = source_v2.join("Cocoon.toml");
    let manifest = std::fs::read_to_string(&manifest_v2)
        .expect("hello-service v2 manifest can be read")
        .replace("version = \"0.1.0\"", "version = \"0.2.0\"");
    std::fs::write(&manifest_v2, manifest).expect("hello-service v2 manifest can be written");
    let capsule_v2 = temp.path().join("hello-service-v2.cocoon");
    assert_success(
        cocoon()
            .args(["build"])
            .arg(&source_v2)
            .args(["--output"])
            .arg(&capsule_v2)
            .output()
            .expect("cocoon build v2 can be executed"),
    );

    let latest_install_receipt = install_root.join("capsules/hello-service/receipts/latest.json");
    let original_latest_install_receipt = std::fs::read(&latest_install_receipt)
        .expect("latest install receipt can be read before tamper");
    let mut latest_only_install_receipt: cocoon_runtime::InstallReceipt =
        serde_json::from_slice(&original_latest_install_receipt)
            .expect("latest install receipt is json");
    latest_only_install_receipt.body.installed_at = "unix:latest-only-tamper".to_string();
    latest_only_install_receipt.body_hash = cocoon_core::hash_bytes(
        &serde_json::to_vec(&latest_only_install_receipt.body)
            .expect("tampered latest-only install receipt body can be serialized"),
    );
    std::fs::write(
        &latest_install_receipt,
        serde_json::to_vec_pretty(&latest_only_install_receipt)
            .expect("tampered latest install receipt can be serialized"),
    )
    .expect("latest install receipt can be tampered independently");
    let install_after_latest_tamper = assert_failure(
        cocoon()
            .args(["install"])
            .arg(&capsule_v2)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon install v2 can be executed after latest install receipt tamper"),
    );
    let install_after_latest_tamper_stderr = stderr(install_after_latest_tamper);
    assert!(
        install_after_latest_tamper_stderr.contains("failed to install capsule"),
        "{install_after_latest_tamper_stderr}"
    );
    assert!(
        install_after_latest_tamper_stderr.contains("latest install receipt archive mismatch"),
        "{install_after_latest_tamper_stderr}"
    );
    std::fs::write(&latest_install_receipt, original_latest_install_receipt)
        .expect("latest install receipt can be restored after latest-only tamper");

    assert_success(
        cocoon()
            .args(["install"])
            .arg(&capsule_v2)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon install v2 can be executed"),
    );

    let upgraded_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status after install v2 can be executed"),
    );
    let upgraded_status_stdout = stdout(upgraded_status);
    assert!(upgraded_status_stdout.contains("Status for hello-service"));
    assert!(upgraded_status_stdout.contains("Current version: 0.2.0"));
    assert!(upgraded_status_stdout.contains("Latest install receipt: blake3:"));

    std::fs::create_dir_all(&lock_dir).expect("test lock directory can be recreated for rollback");
    let locked_rollback = assert_failure(
        cocoon()
            .args(["rollback", "hello-service", "--to-version", "0.1.0"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon rollback can be executed while lock is held"),
    );
    let locked_rollback_stderr = stderr(locked_rollback);
    assert!(
        locked_rollback_stderr.contains("capsule operation is locked: hello-service"),
        "{locked_rollback_stderr}"
    );
    std::fs::remove_dir_all(&lock_dir).expect("test rollback lock directory can be removed");

    let rollback = assert_success(
        cocoon()
            .args(["rollback", "hello-service", "--to-version", "0.1.0"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon rollback can be executed"),
    );
    let rollback_stdout = stdout(rollback);
    assert!(rollback_stdout.contains("Rolled back hello-service"));
    assert!(rollback_stdout.contains("Previous version: 0.2.0"));
    assert!(rollback_stdout.contains("Target version: 0.1.0"));

    let rollback_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status after rollback can be executed"),
    );
    let rollback_status_stdout = stdout(rollback_status);
    assert!(rollback_status_stdout.contains("Current version: 0.1.0"));
    assert!(rollback_status_stdout.contains("Latest rollback receipt: blake3:"));

    let audit = assert_success(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can be executed"),
    );
    let audit_stdout = stdout(audit);
    assert!(audit_stdout.contains("Audit passed for hello-service"));
    assert!(audit_stdout.contains("latest install receipt body hash"));
    assert!(audit_stdout.contains("latest install receipt archive link"));
    assert!(audit_stdout.contains("latest run receipt body hash"));
    assert!(audit_stdout.contains("latest run receipt archive link"));
    assert!(audit_stdout.contains("latest run stdout log hash"));
    assert!(audit_stdout.contains("latest run stderr log hash"));
    assert!(audit_stdout.contains("latest run authority enforcement: false (smoke-unenforced)"));
    assert!(audit_stdout.contains("latest rollback receipt body hash"));
    assert!(audit_stdout.contains("latest rollback receipt archive link"));
    assert!(audit_stdout.contains("current version matches rollback target"));

    let latest_run_receipt = install_root.join("capsules/hello-service/receipts/runs/latest.json");
    let original_latest_run_receipt =
        std::fs::read(&latest_run_receipt).expect("latest run receipt can be read before tamper");
    let mut latest_only_receipt: cocoon_runtime::RunReceipt =
        serde_json::from_slice(&original_latest_run_receipt).expect("latest run receipt is json");
    latest_only_receipt.body.authority_mode = "latest-only-tamper".to_string();
    latest_only_receipt.body_hash = cocoon_core::hash_bytes(
        &serde_json::to_vec(&latest_only_receipt.body)
            .expect("tampered latest-only run receipt body can be serialized"),
    );
    std::fs::write(
        &latest_run_receipt,
        serde_json::to_vec_pretty(&latest_only_receipt)
            .expect("tampered latest-only receipt can be serialized"),
    )
    .expect("latest run receipt can be tampered independently");
    let latest_only_tampered_audit = assert_failure(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can be executed after latest-only receipt tamper"),
    );
    let latest_only_tampered_audit_stderr = stderr(latest_only_tampered_audit);
    assert!(
        latest_only_tampered_audit_stderr.contains("failed to audit capsule 'hello-service'"),
        "{latest_only_tampered_audit_stderr}"
    );
    assert!(
        latest_only_tampered_audit_stderr.contains("latest run receipt archive not found"),
        "{latest_only_tampered_audit_stderr}"
    );
    std::fs::write(&latest_run_receipt, &original_latest_run_receipt)
        .expect("latest run receipt can be restored after latest-only tamper");

    let receipt_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&latest_run_receipt).expect("latest run receipt can be read"),
    )
    .expect("latest run receipt is json");
    let stdout_log = receipt_json["body"]["stdout_log"]
        .as_str()
        .expect("latest run receipt has stdout log path");
    let original_stdout_log =
        std::fs::read(stdout_log).expect("latest stdout log can be read before tamper");
    std::fs::write(stdout_log, b"tampered stdout\n").expect("stdout log can be tampered");
    let tampered_log_status = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed after log tamper"),
    );
    let tampered_log_status_stderr = stderr(tampered_log_status);
    assert!(
        tampered_log_status_stderr
            .contains("status receipts for capsule 'hello-service' are invalid"),
        "{tampered_log_status_stderr}"
    );
    assert!(
        tampered_log_status_stderr.contains("stdout log hash mismatch"),
        "{tampered_log_status_stderr}"
    );
    let tampered_log_read = assert_failure(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon logs can be executed after log tamper"),
    );
    let tampered_log_read_stderr = stderr(tampered_log_read);
    assert!(
        tampered_log_read_stderr.contains("failed to read logs for capsule 'hello-service'"),
        "{tampered_log_read_stderr}"
    );
    assert!(
        tampered_log_read_stderr.contains("stdout log hash mismatch"),
        "{tampered_log_read_stderr}"
    );
    let tampered_log_audit = assert_failure(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can be executed after log tamper"),
    );
    let tampered_log_audit_stderr = stderr(tampered_log_audit);
    assert!(
        tampered_log_audit_stderr.contains("failed to audit capsule 'hello-service'"),
        "{tampered_log_audit_stderr}"
    );
    assert!(
        tampered_log_audit_stderr.contains("stdout log hash mismatch"),
        "{tampered_log_audit_stderr}"
    );
    std::fs::write(stdout_log, original_stdout_log).expect("stdout log can be restored");

    let current_rollback = assert_failure(
        cocoon()
            .args(["rollback", "hello-service", "--to-version", "0.1.0"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon rollback to current version can be executed"),
    );
    let current_rollback_stderr = stderr(current_rollback);
    assert!(
        current_rollback_stderr.contains("failed to roll back capsule 'hello-service' to 0.1.0"),
        "{current_rollback_stderr}"
    );
    assert!(
        current_rollback_stderr.contains("capsule version is already current: hello-service 0.1.0"),
        "{current_rollback_stderr}"
    );

    let missing_rollback = assert_failure(
        cocoon()
            .args(["rollback", "hello-service", "--to-version", "9.9.9"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon rollback to missing version can be executed"),
    );
    let missing_rollback_stderr = stderr(missing_rollback);
    assert!(
        missing_rollback_stderr.contains("failed to roll back capsule 'hello-service' to 9.9.9"),
        "{missing_rollback_stderr}"
    );
    assert!(
        missing_rollback_stderr.contains("capsule version is not installed: hello-service 9.9.9"),
        "{missing_rollback_stderr}"
    );

    let status_after_missing_rollback = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status after missing rollback can be executed"),
    );
    assert!(
        stdout(status_after_missing_rollback).contains("Current version: 0.1.0"),
        "missing rollback must not change the current install"
    );

    let current_executable = install_root.join("capsules/hello-service/current/bin/hello-service");
    let original_executable =
        std::fs::read(&current_executable).expect("installed executable can be read before tamper");
    std::fs::write(&current_executable, b"#!/bin/sh\necho tampered\n")
        .expect("installed executable can be tampered for negative check-install test");
    let tampered_check = assert_failure(
        cocoon()
            .args(["check-install", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon check-install can be executed after tamper"),
    );
    let tampered_stderr = stderr(tampered_check);
    assert!(
        tampered_stderr.contains("installed capsule 'hello-service' failed verification"),
        "{tampered_stderr}"
    );
    assert!(
        tampered_stderr.contains("hash mismatch for bin/hello-service"),
        "{tampered_stderr}"
    );

    let tampered_status_payload = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed after payload tamper"),
    );
    let tampered_status_payload_stderr = stderr(tampered_status_payload);
    assert!(
        tampered_status_payload_stderr
            .contains("failed to read status for capsule 'hello-service'"),
        "{tampered_status_payload_stderr}"
    );
    assert!(
        tampered_status_payload_stderr.contains("hash mismatch for bin/hello-service"),
        "{tampered_status_payload_stderr}"
    );

    let tampered_run = assert_failure(
        cocoon()
            .args(["run", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon run can be executed after tamper"),
    );
    let tampered_run_stderr = stderr(tampered_run);
    assert!(
        tampered_run_stderr.contains("failed to run capsule 'hello-service'"),
        "{tampered_run_stderr}"
    );
    assert!(
        tampered_run_stderr.contains("hash mismatch for bin/hello-service"),
        "{tampered_run_stderr}"
    );
    std::fs::write(&current_executable, original_executable)
        .expect("installed executable can be restored after tamper test");

    let mut receipt_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&latest_run_receipt).expect("latest run receipt can be read"),
    )
    .expect("latest run receipt is json");
    receipt_json["body"]["success"] = serde_json::Value::Bool(false);
    std::fs::write(
        &latest_run_receipt,
        serde_json::to_vec_pretty(&receipt_json).expect("tampered receipt can be serialized"),
    )
    .expect("latest run receipt can be tampered");
    let tampered_status = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon status can be executed after receipt tamper"),
    );
    let tampered_status_stderr = stderr(tampered_status);
    assert!(
        tampered_status_stderr.contains("status receipts for capsule 'hello-service' are invalid"),
        "{tampered_status_stderr}"
    );
    assert!(
        tampered_status_stderr.contains("run receipt body hash mismatch"),
        "{tampered_status_stderr}"
    );
    let tampered_audit = assert_failure(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can be executed after receipt tamper"),
    );
    let tampered_audit_stderr = stderr(tampered_audit);
    assert!(
        tampered_audit_stderr.contains("failed to audit capsule 'hello-service'"),
        "{tampered_audit_stderr}"
    );
    assert!(
        tampered_audit_stderr.contains("run receipt body hash mismatch"),
        "{tampered_audit_stderr}"
    );
}

#[test]
fn diff_permissions_output_is_grouped_and_stable() {
    let temp = tempfile::tempdir().expect("tempdir can be created for CLI golden test");
    let old_capsule = temp.path().join("permission-diff-v1.cocoon");
    let new_capsule = temp.path().join("permission-diff-v2.cocoon");

    assert_success(
        cocoon()
            .args(["build"])
            .arg(repo_root().join("examples/permission-diff-v1"))
            .args(["--output"])
            .arg(&old_capsule)
            .output()
            .expect("cocoon build v1 can be executed"),
    );
    assert_success(
        cocoon()
            .args(["build"])
            .arg(repo_root().join("examples/permission-diff-v2"))
            .args(["--output"])
            .arg(&new_capsule)
            .output()
            .expect("cocoon build v2 can be executed"),
    );

    let diff = assert_success(
        cocoon()
            .args(["diff-permissions"])
            .arg(&old_capsule)
            .arg(&new_capsule)
            .output()
            .expect("cocoon diff-permissions can be executed"),
    );

    assert_eq!(
        stdout(diff),
        concat!(
            "Authority changes detected:\n",
            "\n",
            "Added permissions:\n",
            "      HIGH  allow tcp connect api.example.com:443\n",
            "    MEDIUM  allow file readwrite /app/cache/**\n",
            "\n",
            "Modified permissions:\n",
            "       LOW  allow log read service-log -> allow log write service-log\n",
            "\n",
            "Removed permissions:\n",
            "       LOW  allow file read /app/assets/**\n",
            "\n",
            "Modified schemes:\n",
            "      HIGH  log readonly target=service-log -> log readwrite target=service-log\n",
            "\n",
            "Confirmation required: yes\n",
        )
    );
}

#[test]
fn signed_bundle_trust_flow_is_cli_only() {
    let temp = tempfile::tempdir().expect("tempdir can be created for signing golden test");
    let key = temp.path().join("bundle-signing-key.json");
    let capsule = temp.path().join("hello-service-signed.cocoon");
    let source = repo_root().join("examples/hello-service");

    let keygen = assert_success(
        cocoon()
            .args(["keygen", "--output"])
            .arg(&key)
            .output()
            .expect("cocoon keygen can be executed"),
    );
    let keygen_stdout = stdout(keygen);
    assert!(keygen_stdout.contains("Generated signing key:"));
    assert!(keygen_stdout.contains("Public key:"));
    let public_key = keygen_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Public key: "))
        .expect("keygen prints a public key")
        .to_string();

    assert_success(
        cocoon()
            .args(["build"])
            .arg(source)
            .args(["--output"])
            .arg(&capsule)
            .args(["--signing-key"])
            .arg(&key)
            .output()
            .expect("cocoon signed build can be executed"),
    );

    let strict_without_trust = assert_failure(
        cocoon()
            .args(["verify", "--strict"])
            .arg(&capsule)
            .output()
            .expect("cocoon strict verify without trust root can be executed"),
    );
    assert_eq!(
        stdout(strict_without_trust).trim(),
        "Bundle signature trust root is required."
    );

    let strict_verify = assert_success(
        cocoon()
            .args(["verify", "--strict"])
            .arg(&capsule)
            .args(["--trusted-key"])
            .arg(&key)
            .output()
            .expect("cocoon trusted strict verify can be executed"),
    );
    assert_eq!(stdout(strict_verify).trim(), "Verification passed.");

    let other_key = temp.path().join("other-signing-key.json");
    assert_success(
        cocoon()
            .args(["keygen", "--output"])
            .arg(&other_key)
            .output()
            .expect("cocoon second keygen can be executed"),
    );

    let untrusted_verify = assert_failure(
        cocoon()
            .args(["verify", "--strict"])
            .arg(&capsule)
            .args(["--trusted-key"])
            .arg(&other_key)
            .output()
            .expect("cocoon untrusted strict verify can be executed"),
    );
    assert!(
        stdout(untrusted_verify).contains("Bundle signature key is not trusted:"),
        "expected untrusted signature message"
    );

    let multi_root_verify = assert_success(
        cocoon()
            .args(["verify", "--strict"])
            .arg(&capsule)
            .args(["--trusted-key"])
            .arg(&other_key)
            .args(["--trusted-key"])
            .arg(&key)
            .output()
            .expect("cocoon multi-root strict verify can be executed"),
    );
    assert_eq!(stdout(multi_root_verify).trim(), "Verification passed.");

    let trust_install_root = temp.path().join("trust-config-install-root");
    let trust_list_empty = assert_success(
        cocoon()
            .args(["trust", "list", "--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon trust list can be executed"),
    );
    assert!(stdout(trust_list_empty).contains("Bundle trust roots:\n  <none>"));

    let trust_add = assert_success(
        cocoon()
            .args(["trust", "add", "--key"])
            .arg(&key)
            .args(["--kind", "both", "--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon trust add can be executed"),
    );
    let trust_add_stdout = stdout(trust_add);
    assert!(trust_add_stdout.contains("Trust root added:"));
    assert!(trust_add_stdout.contains(&public_key));
    assert!(trust_add_stdout.contains("Receipt trust roots:"));

    let trust_policy = assert_success(
        cocoon()
            .args([
                "trust",
                "policy",
                "--require-signed-bundles",
                "--require-signed-receipts",
                "--install-root",
            ])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon trust policy can be executed"),
    );
    let trust_policy_stdout = stdout(trust_policy);
    assert!(trust_policy_stdout.contains("Trust policy updated."));
    assert!(trust_policy_stdout.contains("Require signed bundles: yes"));
    assert!(trust_policy_stdout.contains("Require signed receipts: yes"));

    let trust_config = trust_install_root.join("trust/trust-roots.json");
    let trust_config_verify = assert_success(
        cocoon()
            .args(["verify"])
            .arg(&capsule)
            .args(["--trust-config"])
            .arg(&trust_config)
            .output()
            .expect("cocoon strict verify can use a trust config"),
    );
    assert_eq!(stdout(trust_config_verify).trim(), "Verification passed.");

    let trust_config_install = assert_success(
        cocoon()
            .args(["install"])
            .arg(&capsule)
            .args(["--receipt-signing-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon install can use configured trust roots"),
    );
    assert!(stdout(trust_config_install).contains("Installed hello-service@0.1.0"));

    let trust_config_run = assert_success(
        cocoon()
            .args(["run", "hello-service", "--allow-unenforced-authority"])
            .args(["--receipt-signing-key"])
            .arg(&key)
            .args(["--json"])
            .args(["--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon run --json can use configured receipt trust roots"),
    );
    let trust_config_run_json: serde_json::Value =
        serde_json::from_str(&stdout(trust_config_run)).expect("run JSON is valid");
    assert_eq!(trust_config_run_json["event"], "capsule_run");
    assert_eq!(trust_config_run_json["body"]["success"], true);
    assert_eq!(
        trust_config_run_json["body"]["authority_mode"],
        "smoke-unenforced"
    );

    let trust_config_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--json"])
            .args(["--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon status can require receipts from configured policy"),
    );
    let trust_config_status_json: serde_json::Value =
        serde_json::from_str(&stdout(trust_config_status)).expect("status JSON is valid");
    assert_eq!(trust_config_status_json["state"], "last-run-succeeded");
    assert_eq!(
        trust_config_status_json["latest_run_receipt"]["body"]["authority_mode"],
        "smoke-unenforced"
    );

    let trust_remove = assert_success(
        cocoon()
            .args(["trust", "remove"])
            .arg(&public_key)
            .args(["--kind", "both", "--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon trust remove can be executed"),
    );
    assert!(stdout(trust_remove).contains("Trust root removed:"));

    let strict_status_without_configured_key = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--install-root"])
            .arg(&trust_install_root)
            .output()
            .expect("cocoon status rejects missing configured receipt trust roots"),
    );
    assert!(
        stderr(strict_status_without_configured_key)
            .contains("requires --receipt-trusted-key or a configured receipt trust root"),
        "expected missing configured receipt trust root rejection"
    );

    let install_root = temp.path().join("signed-install-root");
    let untrusted_install = assert_failure(
        cocoon()
            .args(["install", "--strict"])
            .arg(&capsule)
            .args(["--trusted-key"])
            .arg(&other_key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon untrusted strict install can be executed"),
    );
    assert!(
        stderr(untrusted_install).contains("SignatureUntrusted"),
        "expected untrusted install failure"
    );

    let trusted_install = assert_success(
        cocoon()
            .args(["install", "--strict"])
            .arg(&capsule)
            .args(["--trusted-key"])
            .arg(&other_key)
            .args(["--trusted-key"])
            .arg(&key)
            .args(["--receipt-signing-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon trusted strict install can be executed"),
    );
    let trusted_install_stdout = stdout(trusted_install);
    assert!(trusted_install_stdout.contains("Installed hello-service@0.1.0"));
    assert!(trusted_install_stdout.contains("Signature: ed25519-blake3-receipt-v1"));

    let run = assert_success(
        cocoon()
            .args(["run", "hello-service", "--allow-unenforced-authority"])
            .args(["--receipt-signing-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon signed receipt run can be executed"),
    );
    assert!(stdout(run).contains("Signature: ed25519-blake3-receipt-v1"));

    let audit = assert_success(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can verify signed receipts"),
    );
    let audit_stdout = stdout(audit);
    assert!(audit_stdout.contains("latest install receipt signature"));
    assert!(audit_stdout.contains("latest run receipt signature"));

    let audit_json = assert_success(
        cocoon()
            .args(["audit", "hello-service", "--json"])
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit --json can verify signed receipts"),
    );
    let audit_json: serde_json::Value =
        serde_json::from_str(&stdout(audit_json)).expect("audit JSON is valid");
    assert_eq!(audit_json["capsule_name"], "hello-service");
    assert!(
        audit_json["checks"]
            .as_array()
            .expect("audit checks are an array")
            .iter()
            .any(|check| check["name"] == "latest run receipt signature")
    );

    let untrusted_receipt_status = assert_failure(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&other_key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon strict receipt status can reject an untrusted key"),
    );
    assert!(
        stderr(untrusted_receipt_status).contains("receipt signature key is not trusted:"),
        "expected untrusted receipt signer rejection"
    );

    let strict_status = assert_success(
        cocoon()
            .args(["status", "hello-service"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&other_key)
            .args(["--receipt-trusted-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon strict receipt status can be executed"),
    );
    assert!(stdout(strict_status).contains("Latest run receipt: blake3:"));

    let strict_logs = assert_success(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&other_key)
            .args(["--receipt-trusted-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon strict receipt logs can be executed"),
    );
    assert!(stdout(strict_logs).contains("Hello from Cocoon hello-service!"));

    let strict_logs_json = assert_success(
        cocoon()
            .args(["logs", "hello-service", "--stream", "stdout", "--json"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&other_key)
            .args(["--receipt-trusted-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon strict receipt logs --json can be executed"),
    );
    let strict_logs_json: serde_json::Value =
        serde_json::from_str(&stdout(strict_logs_json)).expect("logs JSON is valid");
    assert!(
        strict_logs_json["stdout"]
            .as_str()
            .expect("stdout is a string")
            .contains("Hello from Cocoon hello-service!")
    );
    assert!(strict_logs_json["stderr"].is_null());

    let strict_audit = assert_success(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&other_key)
            .args(["--receipt-trusted-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon strict receipt audit can be executed"),
    );
    assert!(stdout(strict_audit).contains("latest run receipt signature"));

    let latest_run_receipt = install_root.join("capsules/hello-service/receipts/runs/latest.json");
    let mut run_receipt_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&latest_run_receipt).unwrap()).unwrap();
    run_receipt_json["signature"]["signature"] = serde_json::Value::String("00".repeat(64));
    std::fs::write(
        &latest_run_receipt,
        serde_json::to_vec_pretty(&run_receipt_json).unwrap(),
    )
    .unwrap();

    let tampered_audit = assert_failure(
        cocoon()
            .args(["audit", "hello-service"])
            .args(["--require-receipt-signatures"])
            .args(["--receipt-trusted-key"])
            .arg(&key)
            .args(["--install-root"])
            .arg(&install_root)
            .output()
            .expect("cocoon audit can reject tampered receipt signature"),
    );
    assert!(
        stderr(tampered_audit).contains("run receipt signature invalid"),
        "expected signed receipt tamper rejection"
    );
}

fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assert_failure(output: Output) -> Output {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout(output: Output) -> String {
    String::from_utf8(output.stdout).expect("CLI stdout is valid UTF-8")
}

fn stderr(output: Output) -> String {
    String::from_utf8(output.stderr).expect("CLI stderr is valid UTF-8")
}

fn copy_dir_recursive(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).expect("target directory can be created");
    for entry in std::fs::read_dir(source).expect("source directory can be read") {
        let entry = entry.expect("source entry can be read");
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("source file type can be read")
            .is_dir()
        {
            copy_dir_recursive(&source_path, &target_path);
        } else {
            std::fs::copy(&source_path, &target_path).expect("source file can be copied");
        }
    }
}
