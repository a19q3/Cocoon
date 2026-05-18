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

fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout(output: Output) -> String {
    String::from_utf8(output.stdout).expect("CLI stdout is valid UTF-8")
}
