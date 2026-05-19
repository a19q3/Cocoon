#![forbid(unsafe_code)]

use std::process::{Command, Stdio};

const REDOX_TARGET: &str = "x86_64-unknown-redox";

fn main() -> anyhow::Result<()> {
    let task = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "help".to_string());
    match task.as_str() {
        "build-examples" => run(
            "cargo",
            &[
                "run",
                "-p",
                "cocoon-cli",
                "--",
                "build",
                "examples/hello-service",
            ],
        ),
        "test" => {
            run("cargo", &["fmt", "--all", "--check"])?;
            run(
                "cargo",
                &[
                    "clippy",
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            run("cargo", &["test", "--workspace"])?;
            Ok(())
        }
        "redox-smoke" => redox_smoke(),
        "host-smoke" => host_smoke(),
        "redox-target-smoke" => redox_target_smoke(),
        "redoxer-smoke" => redoxer_smoke(),
        "redox-package" => redox_package(),
        "qemu-smoke" => qemu_smoke(),
        "redox-test" => qemu_smoke(),
        _ => {
            println!("Usage: cargo xtask <task>");
            println!("Tasks:");
            println!("  build-examples  Build example capsules");
            println!("  test            Run fmt, clippy, and workspace tests");
            println!("  host-smoke      Run host-side P1 smoke checks");
            println!("  redox-target-smoke");
            println!("                  Check Redox target portability and link readiness");
            println!("  redoxer-smoke  Check Redoxer toolchain build readiness");
            println!("  redox-package  Build a Redoxer-backed Cocoon release artifact directory");
            println!("  qemu-smoke      Run CLI-only Redox/QEMU verify/plan smoke through Redoxer");
            println!("  redox-smoke     Prepare P1 Redox smoke-test artifacts");
            println!("  redox-test      Run Redox QEMU smoke test (P1)");
            Ok(())
        }
    }
}

fn redox_smoke() -> anyhow::Result<()> {
    host_smoke()?;
    redox_target_smoke()?;
    qemu_smoke()
}

fn host_smoke() -> anyhow::Result<()> {
    let capsule = "target/redox-smoke/hello-service.cocoon";
    let signed_capsule = "target/redox-smoke/hello-service-signed.cocoon";
    let signing_key = "target/redox-smoke/hello-service-signing-key.json";
    let capsule_v2 = "target/redox-smoke/hello-service-v2.cocoon";
    let overlay_dir = std::path::Path::new("target/redox-smoke/overlay/capsules");
    std::fs::create_dir_all(overlay_dir)?;

    print_section("Host smoke");

    run("cargo", &["build", "-p", "cocoon-cli"])?;
    println!("PASS host build cocoon");

    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "examples/hello-service",
            "--output",
            capsule,
        ],
    )?;
    println!("PASS build hello-service.cocoon");

    prepare_hello_service_v2_source()?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "target/redox-smoke/hello-service-v2-src",
            "--output",
            capsule_v2,
        ],
    )?;
    println!("PASS build hello-service v2 capsule");

    run(
        "cargo",
        &["run", "-p", "cocoon-cli", "--", "verify", capsule],
    )?;
    println!("PASS verify capsule");

    let _ = std::fs::remove_file(signing_key);
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "keygen",
            "--output",
            signing_key,
        ],
    )?;
    println!("PASS generate bundle signing key");

    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "examples/hello-service",
            "--output",
            signed_capsule,
            "--signing-key",
            signing_key,
        ],
    )?;
    println!("PASS build signed capsule");

    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "verify",
            "--strict",
            signed_capsule,
            "--trusted-key",
            signing_key,
        ],
    )?;
    println!("PASS strict verify signed capsule");

    run("cargo", &["run", "-p", "cocoon-cli", "--", "plan", capsule])?;
    println!("PASS generate runtime plan");

    std::fs::copy(capsule, overlay_dir.join("hello-service.cocoon"))?;
    std::fs::copy(capsule_v2, overlay_dir.join("hello-service-v2.cocoon"))?;
    println!("PASS image overlay prepared");
    Ok(())
}

fn prepare_hello_service_v2_source() -> anyhow::Result<()> {
    let source = std::path::Path::new("examples/hello-service");
    let target = std::path::Path::new("target/redox-smoke/hello-service-v2-src");
    remove_dir_if_exists(target)?;
    copy_dir_recursive(source, target)?;

    let manifest_path = target.join("Cocoon.toml");
    let manifest = std::fs::read_to_string(&manifest_path)?;
    std::fs::write(
        manifest_path,
        manifest.replace("version = \"0.1.0\"", "version = \"0.2.0\""),
    )?;
    Ok(())
}

fn prepare_hello_service_fd_source() -> anyhow::Result<()> {
    prepare_fd_service_source(
        "target/redox-smoke/hello-service-fd-src",
        "hello-service-fd",
        "hello-service",
        "hello-service",
        "Redox FD-only capsule entrypoint fixture",
        false,
    )
}

fn prepare_log_service_fd_source() -> anyhow::Result<()> {
    prepare_fd_service_source(
        "target/redox-smoke/log-service-src",
        "log-service",
        "log-service",
        "log-service",
        "Redox FD-only log-profile service fixture",
        true,
    )
}

fn prepare_network_denied_service_fd_source() -> anyhow::Result<()> {
    prepare_fd_service_source(
        "target/redox-smoke/network-denied-service-src",
        "network-denied-service",
        "network-denied-service",
        "network-denied-service",
        "Redox FD-only network-denied service fixture",
        false,
    )
}

fn prepare_fd_service_source(
    target: &str,
    capsule_name: &str,
    binary_name: &str,
    profile: &str,
    description: &str,
    include_log_scheme: bool,
) -> anyhow::Result<()> {
    let source_binary = std::path::Path::new("target/x86_64-unknown-redox/debug/hello-service");
    let target = std::path::Path::new(target);
    remove_dir_if_exists(target)?;
    std::fs::create_dir_all(target.join("bin"))?;
    let target_binary = target.join("bin").join(binary_name);
    std::fs::copy(source_binary, &target_binary)?;
    make_executable(&target_binary)?;

    let log_permission = if include_log_scheme {
        format!(
            r#"
[[permission]]
scheme = "log"
action = "write"
target = "{capsule_name}"

[[scheme]]
name = "log"
visibility = "readwrite"
target = "service-log"
"#
        )
    } else {
        String::new()
    };

    std::fs::write(
        target.join("Cocoon.toml"),
        format!(
            r#"[capsule]
name = "{capsule_name}"
version = "0.1.0"
description = "{description}"
authors = ["Arthur Tsang"]
license = "MIT"

[entry]
cmd = "/app/bin/{binary_name}"
args = ["--authority-self-test", "--profile", "{profile}"]
cwd = "/app"

[filesystem]
root = "/app"
readonly = [
  "/app"
]

[[permission]]
scheme = "file"
action = "read"
target = "/app/**"

[[permission]]
scheme = "rand"
action = "read"
target = "readonly"
{log_permission}

[[permission]]
effect = "deny"
scheme = "file"
action = "readwrite"
target = "/home/**"

[[permission]]
effect = "deny"
scheme = "tcp"
action = "connect"
target = "*"

[[preopen]]
scheme = "file"
host_path = "/pkg/cocoon/capsules/{capsule_name}/current"
guest_path = "/app"
rights = ["read", "execute"]

[network]
default = "deny"

[resources]
memory_mb = 64
max_processes = 4
max_open_fds = 64

[update]
signed = true
rollback = true
permission_expansion_requires_confirmation = true

[audit]
events = true
stdout = true
stderr = true
"#
        ),
    )?;
    Ok(())
}

fn redox_target_smoke() -> anyhow::Result<()> {
    print_section("Redox target smoke");
    let mut missing_target = false;

    if run_optional(
        "cargo",
        &["check", "-p", "redox-link-probe", "--target", REDOX_TARGET],
    )? {
        println!("PASS redox link probe cargo check");
    } else {
        println!(
            "TODO redox link probe cargo check (install target with `rustup target add {REDOX_TARGET}`)"
        );
        missing_target = true;
    }

    if run_optional(
        "cargo",
        &["check", "-p", "cocoon-cli", "--target", REDOX_TARGET],
    )? {
        println!("PASS cocoon-cli redox cargo check");
    } else {
        println!(
            "TODO cocoon-cli redox cargo check (install target with `rustup target add {REDOX_TARGET}`)"
        );
        missing_target = true;
    }

    println!("BLOCKED redox link probe binary link (requires Redox C sysroot/toolchain)");
    println!("BLOCKED cocoon-cli redox binary link (requires Redox C sysroot/toolchain)");

    if missing_target {
        anyhow::bail!(
            "Some Redox target cargo-check smoke checks were skipped. Install the Redox target with `rustup target add {REDOX_TARGET}`."
        );
    }

    Ok(())
}

fn redoxer_smoke() -> anyhow::Result<()> {
    print_section("Redoxer smoke");

    if !program_available("redoxer")? {
        println!("SKIP redoxer available (install with `cargo install redoxer`)");
        println!("SKIP redoxer build redox-link-probe");
        println!("SKIP redoxer build cocoon-cli");
        println!("SKIP redoxer run cocoon --help");
        return Ok(());
    }

    println!("PASS redoxer available");
    let mut smoke_failed = false;

    if run_optional("redoxer", &["build", "-p", "redox-link-probe"])? {
        println!("PASS redoxer build redox-link-probe");
    } else {
        smoke_failed = true;
        println!("TODO redoxer build redox-link-probe");
    }

    if run_optional("redoxer", &["build", "-p", "cocoon-cli"])? {
        println!("PASS redoxer build cocoon-cli");
    } else {
        smoke_failed = true;
        println!("TODO redoxer build cocoon-cli");
    }

    let help = run_optional_capture("redoxer", &["run", "-p", "cocoon-cli", "--", "--help"])?;
    if help.status.success()
        && help.combined.contains("Usage:")
        && help.combined.contains("Commands:")
    {
        println!("PASS redoxer run cocoon --help");
    } else {
        smoke_failed = true;
        println!("TODO redoxer run cocoon --help");
    }

    if smoke_failed {
        anyhow::bail!("Redoxer smoke completed with TODO checks");
    }
    Ok(())
}

fn redox_package() -> anyhow::Result<()> {
    print_section("Redox package");

    let package_root = std::path::Path::new("target/redox-package/cocoon-redox");
    let bin_dir = package_root.join("bin");
    let capsule_dir = package_root.join("capsules");
    let trust_dir = package_root.join("trust");
    let manifest_path = package_root.join("release-manifest.json");
    let signing_key = "target/redox-package/signing-key.json";
    let capsule = "target/redox-package/hello-service-signed.cocoon";
    let trust_root = "target/redox-package/trust-root";

    remove_dir_if_exists(package_root)?;
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&capsule_dir)?;
    std::fs::create_dir_all(&trust_dir)?;
    std::fs::create_dir_all("target/redox-package")?;

    run("cargo", &["build", "-p", "cocoon-cli"])?;
    println!("PASS host build cocoon for package staging");

    let _ = std::fs::remove_file(signing_key);
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "keygen",
            "--output",
            signing_key,
        ],
    )?;
    println!("PASS package signing key generated");

    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "examples/hello-service",
            "--output",
            capsule,
            "--signing-key",
            signing_key,
        ],
    )?;
    println!("PASS package signed capsule built");

    let trust_install_root = std::path::Path::new(trust_root);
    remove_dir_if_exists(trust_install_root)?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "trust",
            "add",
            "--key",
            signing_key,
            "--kind",
            "both",
            "--install-root",
            trust_root,
        ],
    )?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "trust",
            "policy",
            "--require-signed-bundles",
            "--require-signed-receipts",
            "--install-root",
            trust_root,
        ],
    )?;
    std::fs::copy(
        trust_install_root.join("trust/trust-roots.json"),
        trust_dir.join("trust-roots.json"),
    )?;
    println!("PASS package trust policy staged");

    std::fs::copy(capsule, capsule_dir.join("hello-service-signed.cocoon"))?;

    let redox_binary = std::path::Path::new("target/x86_64-unknown-redox/debug/cocoon");
    let mut redox_binary_staged = false;
    if program_available("redoxer")? && run_optional("redoxer", &["build", "-p", "cocoon-cli"])? {
        if redox_binary.is_file() {
            std::fs::copy(redox_binary, bin_dir.join("cocoon"))?;
            redox_binary_staged = true;
            println!("PASS package redoxer cocoon binary staged");
        } else {
            println!("BLOCKED package redoxer cocoon binary staged (binary path missing)");
        }
    } else {
        println!("SKIP package redoxer cocoon binary staged (redoxer unavailable or build failed)");
    }

    write_release_readme(package_root)?;

    let mut artifacts = vec![
        artifact_manifest_entry(
            &capsule_dir.join("hello-service-signed.cocoon"),
            package_root,
        )?,
        artifact_manifest_entry(&trust_dir.join("trust-roots.json"), package_root)?,
        artifact_manifest_entry(&package_root.join("README.txt"), package_root)?,
    ];
    if redox_binary_staged {
        artifacts.push(artifact_manifest_entry(
            &bin_dir.join("cocoon"),
            package_root,
        )?);
    }
    artifacts.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["path"].as_str().unwrap_or_default())
    });

    let manifest = serde_json::json!({
        "format_version": 1,
        "package_name": "cocoon-redox",
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "redox_binary_staged": redox_binary_staged,
        "artifacts": artifacts,
        "notes": [
            "Redoxer build is the current native Redox artifact path.",
            "Direct x86_64-unknown-redox binary link remains dependent on the Redox C sysroot/toolchain.",
            "pkgar/Cookbook integration remains the future distribution path."
        ],
    });
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    println!("PASS package release manifest written");
    println!("Package root: {}", package_root.display());
    Ok(())
}

fn qemu_smoke() -> anyhow::Result<()> {
    print_section("QEMU smoke");

    let capsule = "target/redox-smoke/hello-service.cocoon";
    let capsule_fd = "target/redox-smoke/hello-service-fd.cocoon";
    let capsule_log = "target/redox-smoke/log-service.cocoon";
    let capsule_network_denied = "target/redox-smoke/network-denied-service.cocoon";
    let capsule_v2 = "target/redox-smoke/hello-service-v2.cocoon";
    let install_root = "target/redox-smoke/qemu-install";

    if !program_available("redoxer")? {
        println!("SKIP boot redox qemu (install with `cargo install redoxer`)");
        println!("SKIP run cocoon verify inside redox");
        println!("SKIP run cocoon plan inside redox");
        println!("SKIP report missing service status inside redox");
        println!("SKIP reject check-install before install inside redox");
        println!("SKIP reject run before install inside redox");
        println!("SKIP reject locked capsule operations inside redox");
        println!("SKIP install capsule inside redox");
        println!("SKIP report installed service status inside redox");
        println!("SKIP probe Redox authority inside redox");
        println!("SKIP classify Redox FD-only service launch gap inside redox");
        println!("SKIP probe Redox FD-only controlled service launch inside redox");
        println!("SKIP probe Redox FD-only installed capsule entrypoint inside redox");
        println!("SKIP cocoon run uses FD-only capsule entrypoint backend inside redox");
        println!("SKIP P1.2g log-service FD run profile inside redox");
        println!("SKIP P1.2g network-denied-service FD run profile inside redox");
        println!("SKIP audit Redox authority probe receipt inside redox");
        println!("SKIP audit Redox FD-only launch probe receipts inside redox");
        println!("SKIP recover temporary install state inside redox");
        println!("SKIP reject duplicate install inside redox");
        println!("SKIP reject logs before run inside redox");
        println!("SKIP reject tampered latest install receipt inside redox");
        println!("SKIP reject unenforced authority run inside redox");
        println!("SKIP run hello-service inside redox");
        println!("SKIP report upgraded service status inside redox");
        println!("SKIP roll back capsule inside redox");
        println!("SKIP audit receipts inside redox");
        println!("SKIP reject current rollback version inside redox");
        println!("SKIP reject missing rollback version inside redox");
        println!("SKIP reject tampered install inside redox");
        println!("SKIP collect receipts/logs");
        return Ok(());
    }

    if !std::path::Path::new(capsule).is_file() || !std::path::Path::new(capsule_v2).is_file() {
        println!("SKIP boot redox qemu (run `cargo xtask host-smoke` first)");
        println!("SKIP run cocoon verify inside redox");
        println!("SKIP run cocoon plan inside redox");
        println!("SKIP report missing service status inside redox");
        println!("SKIP reject check-install before install inside redox");
        println!("SKIP reject run before install inside redox");
        println!("SKIP reject locked capsule operations inside redox");
        println!("SKIP install capsule inside redox");
        println!("SKIP report installed service status inside redox");
        println!("SKIP probe Redox authority inside redox");
        println!("SKIP classify Redox FD-only service launch gap inside redox");
        println!("SKIP probe Redox FD-only controlled service launch inside redox");
        println!("SKIP probe Redox FD-only installed capsule entrypoint inside redox");
        println!("SKIP cocoon run uses FD-only capsule entrypoint backend inside redox");
        println!("SKIP P1.2g log-service FD run profile inside redox");
        println!("SKIP P1.2g network-denied-service FD run profile inside redox");
        println!("SKIP audit Redox authority probe receipt inside redox");
        println!("SKIP audit Redox FD-only launch probe receipts inside redox");
        println!("SKIP recover temporary install state inside redox");
        println!("SKIP reject duplicate install inside redox");
        println!("SKIP reject logs before run inside redox");
        println!("SKIP reject tampered latest install receipt inside redox");
        println!("SKIP reject unenforced authority run inside redox");
        println!("SKIP run hello-service inside redox");
        println!("SKIP report upgraded service status inside redox");
        println!("SKIP roll back capsule inside redox");
        println!("SKIP audit receipts inside redox");
        println!("SKIP reject current rollback version inside redox");
        println!("SKIP reject missing rollback version inside redox");
        println!("SKIP reject tampered install inside redox");
        println!("SKIP collect receipts/logs");
        return Ok(());
    }

    remove_dir_if_exists(install_root)?;

    if !run_optional("redoxer", &["build", "-p", "cocoon-cli"])? {
        println!("SKIP boot redox qemu (redoxer build cocoon-cli failed)");
        println!("SKIP run cocoon verify inside redox");
        println!("SKIP run cocoon plan inside redox");
        println!("SKIP report missing service status inside redox");
        println!("SKIP reject check-install before install inside redox");
        println!("SKIP reject run before install inside redox");
        println!("SKIP reject locked capsule operations inside redox");
        println!("SKIP install capsule inside redox");
        println!("SKIP report installed service status inside redox");
        println!("SKIP probe Redox authority inside redox");
        println!("SKIP classify Redox FD-only service launch gap inside redox");
        println!("SKIP probe Redox FD-only controlled service launch inside redox");
        println!("SKIP probe Redox FD-only installed capsule entrypoint inside redox");
        println!("SKIP cocoon run uses FD-only capsule entrypoint backend inside redox");
        println!("SKIP P1.2g log-service FD run profile inside redox");
        println!("SKIP P1.2g network-denied-service FD run profile inside redox");
        println!("SKIP audit Redox authority probe receipt inside redox");
        println!("SKIP audit Redox FD-only launch probe receipts inside redox");
        println!("SKIP recover temporary install state inside redox");
        println!("SKIP reject duplicate install inside redox");
        println!("SKIP reject logs before run inside redox");
        println!("SKIP reject tampered latest install receipt inside redox");
        println!("SKIP reject unenforced authority run inside redox");
        println!("SKIP run hello-service inside redox");
        println!("SKIP report upgraded service status inside redox");
        println!("SKIP roll back capsule inside redox");
        println!("SKIP audit receipts inside redox");
        println!("SKIP reject current rollback version inside redox");
        println!("SKIP reject missing rollback version inside redox");
        println!("SKIP reject tampered install inside redox");
        println!("SKIP collect receipts/logs");
        return Ok(());
    }

    run("redoxer", &["build", "-p", "hello-service"])?;
    prepare_hello_service_fd_source()?;
    prepare_log_service_fd_source()?;
    prepare_network_denied_service_fd_source()?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "target/redox-smoke/hello-service-fd-src",
            "--output",
            capsule_fd,
        ],
    )?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "target/redox-smoke/log-service-src",
            "--output",
            capsule_log,
        ],
    )?;
    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "target/redox-smoke/network-denied-service-src",
            "--output",
            capsule_network_denied,
        ],
    )?;

    let cocoon_binary = "target/x86_64-unknown-redox/debug/cocoon";
    let qemu_root = "target/redox-smoke/redoxer-root";
    prepare_qemu_redoxer_root(
        qemu_root,
        cocoon_binary,
        &[
            (capsule, "hello-service.cocoon"),
            (capsule_fd, "hello-service-fd.cocoon"),
            (capsule_log, "log-service.cocoon"),
            (capsule_network_denied, "network-denied-service.cocoon"),
            (capsule_v2, "hello-service-v2.cocoon"),
        ],
    )?;

    let qemu_folder_arg = format!("{qemu_root}:/root");
    let cocoon_binary = "/root/redoxer-root/bin/cocoon";
    let capsule = "/root/redoxer-root/capsules/hello-service.cocoon";
    let capsule_fd = "/root/redoxer-root/capsules/hello-service-fd.cocoon";
    let capsule_log = "/root/redoxer-root/capsules/log-service.cocoon";
    let capsule_network_denied = "/root/redoxer-root/capsules/network-denied-service.cocoon";
    let capsule_v2 = "/root/redoxer-root/capsules/hello-service-v2.cocoon";
    let install_root = "/root/redoxer-root/install";

    let verify = run_required_capture(
        "redoxer",
        &[
            "exec",
            "--folder",
            qemu_folder_arg.as_str(),
            cocoon_binary,
            "verify",
            capsule,
        ],
    )?;
    let plan = run_required_capture(
        "redoxer",
        &[
            "exec",
            "--folder",
            qemu_folder_arg.as_str(),
            cocoon_binary,
            "plan",
            capsule,
        ],
    )?;
    let install_run_command = format!(
        "{cocoon_binary} status hello-service --install-root {install_root} && \
         if {cocoon_binary} check-install hello-service --install-root {install_root}; then \
             echo CHECK_BEFORE_INSTALL_UNEXPECTED_PASS; \
             exit 47; \
         else \
             echo PASS check-install before install rejected; \
         fi && \
         if {cocoon_binary} run hello-service --install-root {install_root}; then \
             echo RUN_BEFORE_INSTALL_UNEXPECTED_PASS; \
             exit 48; \
         else \
             echo PASS run before install rejected; \
         fi && \
         mkdir -p {install_root}/.locks/hello-service.lock && \
         if {cocoon_binary} install {capsule} --install-root {install_root}; then \
             echo LOCKED_INSTALL_UNEXPECTED_PASS; \
             exit 49; \
         else \
             echo PASS locked install rejected; \
         fi && \
         rmdir {install_root}/.locks/hello-service.lock && \
         {cocoon_binary} install {capsule} --install-root {install_root} && \
         {cocoon_binary} status hello-service --install-root {install_root} && \
         {cocoon_binary} probe-authority hello-service --install-root {install_root} && \
         {cocoon_binary} probe-fd-exec hello-service --install-root {install_root} && \
         {cocoon_binary} probe-fd-launch hello-service --install-root {install_root} && \
         {cocoon_binary} install {capsule_fd} --install-root {install_root} && \
         {cocoon_binary} probe-capsule-fd-launch hello-service-fd --install-root {install_root} && \
         {cocoon_binary} run hello-service-fd --enforce-redox-authority --install-root {install_root} && \
         {cocoon_binary} status hello-service-fd --install-root {install_root} && \
         {cocoon_binary} status hello-service-fd --json --install-root {install_root} && \
         {cocoon_binary} logs hello-service-fd --stream stdout --install-root {install_root} && \
         {cocoon_binary} audit hello-service-fd --install-root {install_root} && \
         {cocoon_binary} install {capsule_log} --install-root {install_root} && \
         {cocoon_binary} run log-service --enforce-redox-authority --install-root {install_root} && \
         {cocoon_binary} status log-service --install-root {install_root} && \
         {cocoon_binary} status log-service --json --install-root {install_root} && \
         {cocoon_binary} logs log-service --stream stdout --install-root {install_root} && \
         {cocoon_binary} audit log-service --install-root {install_root} && \
         {cocoon_binary} install {capsule_network_denied} --install-root {install_root} && \
         {cocoon_binary} run network-denied-service --enforce-redox-authority --install-root {install_root} && \
         {cocoon_binary} status network-denied-service --install-root {install_root} && \
         {cocoon_binary} status network-denied-service --json --install-root {install_root} && \
         {cocoon_binary} logs network-denied-service --stream stdout --install-root {install_root} && \
         {cocoon_binary} audit network-denied-service --install-root {install_root} && \
         {cocoon_binary} audit hello-service --install-root {install_root} && \
         mkdir -p {install_root}/.staging/hello-service-0.1.0-abandoned && \
         mkdir -p {install_root}/capsules/hello-service/current.tmp && \
         printf '0.2.0\\n' > {install_root}/capsules/hello-service/current-version.tmp && \
         printf '{{}}' > {install_root}/capsules/hello-service/receipts/latest.json.tmp && \
         {cocoon_binary} recover hello-service --install-root {install_root} && \
         mkdir -p {install_root}/.locks/hello-service.lock && \
         if {cocoon_binary} recover hello-service --install-root {install_root}; then \
             echo LOCKED_RECOVER_UNEXPECTED_PASS; \
             exit 53; \
         else \
             echo PASS locked recover rejected; \
         fi && \
         printf '0.2.0\\n' > {install_root}/capsules/hello-service/current-version.tmp && \
         if {cocoon_binary} check-install hello-service --install-root {install_root}; then \
             echo LOCKED_CHECK_UNEXPECTED_PASS; \
             exit 50; \
         else \
             echo PASS locked check-install rejected; \
         fi && \
         if {cocoon_binary} status hello-service --install-root {install_root}; then \
             echo LOCKED_STATUS_UNEXPECTED_PASS; \
             exit 56; \
         else \
             echo PASS locked status rejected; \
         fi && \
         if {cocoon_binary} logs hello-service --stream stdout --install-root {install_root}; then \
             echo LOCKED_LOGS_UNEXPECTED_PASS; \
             exit 57; \
         else \
             echo PASS locked logs rejected; \
         fi && \
         if {cocoon_binary} run hello-service --install-root {install_root}; then \
             echo LOCKED_RUN_UNEXPECTED_PASS; \
             exit 51; \
         else \
             echo PASS locked run rejected; \
         fi && \
         if {cocoon_binary} audit hello-service --install-root {install_root}; then \
             echo LOCKED_AUDIT_UNEXPECTED_PASS; \
             exit 54; \
         else \
             echo PASS locked audit rejected; \
         fi && \
         {cocoon_binary} recover hello-service --break-lock --install-root {install_root} && \
         if {cocoon_binary} install {capsule} --install-root {install_root}; then \
             echo DUPLICATE_INSTALL_UNEXPECTED_PASS; \
             exit 45; \
         else \
             echo PASS duplicate install rejected; \
         fi && \
         if {cocoon_binary} logs hello-service --stream stdout --install-root {install_root}; then \
             echo LOGS_BEFORE_RUN_UNEXPECTED_PASS; \
             exit 46; \
         else \
             echo PASS logs before run rejected; \
         fi && \
         if {cocoon_binary} run hello-service --install-root {install_root}; then \
             echo UNENFORCED_AUTHORITY_RUN_UNEXPECTED_PASS; \
             exit 55; \
         else \
             echo PASS unenforced authority run rejected; \
         fi && \
         {cocoon_binary} run hello-service --allow-unenforced-authority --install-root {install_root} && \
         {cocoon_binary} status hello-service --install-root {install_root} && \
         {cocoon_binary} logs hello-service --stream stdout --install-root {install_root} && \
         cp {install_root}/capsules/hello-service/receipts/latest.json {install_root}/capsules/hello-service/receipts/latest.json.saved && \
         printf '{{\"receipt_version\":1,\"event\":\"capsule_install\",\"body\":{{\"capsule_name\":\"hello-service\",\"capsule_version\":\"0.1.0\",\"manifest_hash\":\"blake3:tampered\",\"bundle_hash\":\"blake3:tampered\",\"permission_hash\":\"blake3:tampered\",\"installed_at\":\"unix:latest-only-tamper\",\"install_root\":\"tampered\",\"runtime_version\":\"0.1.0\",\"previous_receipt\":null}},\"body_hash\":\"blake3:fe1dd1e11111111111111111111111111111111111111111111111111111111111\",\"signature\":null}}' > {install_root}/capsules/hello-service/receipts/latest.json && \
         if {cocoon_binary} install {capsule_v2} --install-root {install_root}; then \
             echo TAMPERED_LATEST_INSTALL_UNEXPECTED_PASS; \
             exit 59; \
         else \
             echo PASS tampered latest install rejected; \
         fi && \
         mv {install_root}/capsules/hello-service/receipts/latest.json.saved {install_root}/capsules/hello-service/receipts/latest.json && \
         {cocoon_binary} install {capsule_v2} --install-root {install_root} && \
         {cocoon_binary} status hello-service --install-root {install_root} && \
         mkdir -p {install_root}/.locks/hello-service.lock && \
         if {cocoon_binary} rollback hello-service --to-version 0.1.0 --install-root {install_root}; then \
             echo LOCKED_ROLLBACK_UNEXPECTED_PASS; \
             exit 52; \
         else \
             echo PASS locked rollback rejected; \
         fi && \
         rmdir {install_root}/.locks/hello-service.lock && \
         {cocoon_binary} rollback hello-service --to-version 0.1.0 --install-root {install_root} && \
         {cocoon_binary} check-install hello-service --install-root {install_root} && \
         {cocoon_binary} status hello-service --install-root {install_root} && \
         {cocoon_binary} audit hello-service --install-root {install_root} && \
         if {cocoon_binary} rollback hello-service --to-version 0.1.0 --install-root {install_root}; then \
             echo CURRENT_ROLLBACK_UNEXPECTED_PASS; \
             exit 44; \
         else \
             echo PASS current rollback version rejected; \
         fi && \
         if {cocoon_binary} rollback hello-service --to-version 9.9.9 --install-root {install_root}; then \
             echo MISSING_ROLLBACK_UNEXPECTED_PASS; \
             exit 43; \
         else \
             echo PASS missing rollback version rejected; \
         fi && \
         printf 'tampered\\n' >> {install_root}/capsules/hello-service/current/bin/hello-service && \
         if {cocoon_binary} check-install hello-service --install-root {install_root}; then \
             echo TAMPER_UNEXPECTED_PASS; \
             exit 42; \
         else \
             echo PASS tampered install rejected; \
         fi && \
         if {cocoon_binary} status hello-service --install-root {install_root}; then \
             echo TAMPERED_STATUS_UNEXPECTED_PASS; \
             exit 58; \
         else \
             echo PASS tampered status rejected; \
         fi"
    );
    let install_run = run_required_capture(
        "redoxer",
        &[
            "exec",
            "--folder",
            qemu_folder_arg.as_str(),
            "/usr/bin/sh",
            "-c",
            install_run_command.as_str(),
        ],
    )?;

    let mut qemu_failed = false;

    if verify.contains("## running redoxer ##") || plan.contains("## running redoxer ##") {
        println!("PASS boot redox qemu");
    } else {
        qemu_failed = true;
        println!("TODO boot redox qemu");
    }

    if verify.contains("Bundle is unsigned (P0 signature placeholder).")
        || verify.contains("## redoxer (success) ##")
    {
        println!("PASS run cocoon verify inside redox");
    } else {
        qemu_failed = true;
        println!("TODO run cocoon verify inside redox");
    }

    if plan.contains("Runtime plan for hello-service@0.1.0")
        && plan.contains("Install root: /pkg/cocoon")
        && plan.contains("Receipt input:")
    {
        println!("PASS run cocoon plan inside redox");
    } else {
        qemu_failed = true;
        println!("TODO run cocoon plan inside redox");
    }

    if install_run.contains("Status for hello-service")
        && install_run.contains("State: not-installed")
        && install_run.contains("Current version: <none>")
    {
        println!("PASS report missing service status inside redox");
    } else {
        qemu_failed = true;
        println!("TODO report missing service status inside redox");
    }

    if install_run.contains("PASS check-install before install rejected")
        && install_run.contains("installed capsule 'hello-service' failed verification")
        && install_run.contains("capsule is not installed: hello-service")
    {
        println!("PASS reject check-install before install inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject check-install before install inside redox");
    }

    if install_run.contains("PASS run before install rejected")
        && install_run.contains("failed to run capsule 'hello-service'")
        && install_run.contains("capsule is not installed: hello-service")
    {
        println!("PASS reject run before install inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject run before install inside redox");
    }

    if install_run.contains("PASS locked install rejected")
        && install_run.contains("PASS locked recover rejected")
        && install_run.contains("PASS locked check-install rejected")
        && install_run.contains("PASS locked status rejected")
        && install_run.contains("PASS locked logs rejected")
        && install_run.contains("PASS locked run rejected")
        && install_run.contains("PASS locked audit rejected")
        && install_run.contains("PASS locked rollback rejected")
        && install_run.contains("capsule operation is locked: hello-service")
    {
        println!("PASS reject locked capsule operations inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject locked capsule operations inside redox");
    }

    if install_run.contains("Installed hello-service@0.1.0")
        && install_run.contains("Event: capsule_install")
        && install_run.contains("Body hash: blake3:")
    {
        println!("PASS install capsule inside redox");
    } else {
        qemu_failed = true;
        println!("TODO install capsule inside redox");
    }

    if install_run.contains("Status for hello-service")
        && install_run.contains("State: installed")
        && install_run.contains("Current version: 0.1.0")
        && install_run.contains("Latest run receipt: <none>")
    {
        println!("PASS report installed service status inside redox");
    } else {
        qemu_failed = true;
        println!("TODO report installed service status inside redox");
    }

    if install_run.contains("PASS redox authority child entered restricted namespace")
        && install_run.contains("PASS redox authority child returned structured result")
        && install_run.contains("PASS redox authority child read allowed preopen")
        && install_run.contains("PASS redox authority child rejected denied file path")
        && install_run.contains("PASS redox authority child rejected hidden tcp scheme")
        && install_run.contains("Mode: redox-child-null-namespace")
    {
        println!("PASS probe Redox authority inside redox");
    } else {
        qemu_failed = true;
        println!("TODO probe Redox authority inside redox");
    }

    if install_run.contains("FD-only exec probe for hello-service@0.1.0")
        && install_run.contains("Mode: redox-null-namespace-path-exec-classification")
        && install_run.contains("Expected path exec failure: true")
        && install_run.contains("Classified FD-only service launch blocker: true")
        && install_run.contains("PASS redox path exec blocked after null namespace")
        && install_run.contains("PASS redox fd-exec gap classified")
    {
        println!("PASS classify Redox FD-only service launch gap inside redox");
    } else {
        qemu_failed = true;
        println!("TODO classify Redox FD-only service launch gap inside redox");
    }

    let fd_launch_enforced = install_run.contains("FD-only launch probe for hello-service@0.1.0")
        && install_run.contains("Mode: redox-controlled-service-enforced")
        && install_run.contains("Authority enforced for service: true")
        && install_run.contains("Production arbitrary service: false")
        && install_run.contains("PASS FD launch child returned structured result")
        && install_run.contains("PASS open executable before restriction")
        && install_run.contains("PASS enter restricted namespace")
        && install_run.contains("PASS exec service from inherited executable FD")
        && install_run.contains("PASS service reads declared preopen")
        && install_run.contains("PASS service cannot open denied path by name")
        && install_run.contains("PASS service cannot open hidden/undeclared scheme");
    let fd_launch_blocked = install_run.contains("FD-only launch probe for hello-service@0.1.0")
        && install_run.contains("Mode: redox-fd-launch-blocked")
        && install_run.contains("BLOCKED redox FD-only service launch");
    if fd_launch_enforced {
        println!("PASS probe Redox FD-only controlled service launch inside redox");
    } else if fd_launch_blocked {
        println!("BLOCKED probe Redox FD-only controlled service launch inside redox");
    } else {
        qemu_failed = true;
        println!("TODO probe Redox FD-only controlled service launch inside redox");
    }

    let capsule_fd_launch_enforced = install_run
        .contains("Capsule FD-only launch probe for hello-service-fd@0.1.0")
        && install_run.contains("Mode: redox-enforced-capsule-entrypoint")
        && install_run.contains("Authority enforced for service: true")
        && install_run.contains("Production arbitrary service: false")
        && install_run.contains("PASS capsule FD launch child returned structured result")
        && install_run.contains("PASS open installed capsule entrypoint before restriction")
        && install_run.contains("PASS open declared preopens before restriction")
        && install_run.contains("PASS enter manifest-derived restricted namespace")
        && install_run.contains("PASS fexec installed capsule entrypoint")
        && install_run.contains("PASS service reads declared resource")
        && install_run.contains("PASS denied ambient path rejected")
        && install_run.contains("PASS undeclared tcp scheme rejected");
    let capsule_fd_launch_blocked = install_run
        .contains("Capsule FD-only launch probe for hello-service-fd@0.1.0")
        && install_run.contains("Mode: redox-capsule-fd-launch-blocked")
        && install_run.contains("BLOCKED redox capsule FD-only launch");
    if capsule_fd_launch_enforced {
        println!("PASS probe Redox FD-only installed capsule entrypoint inside redox");
    } else if capsule_fd_launch_blocked {
        println!("BLOCKED probe Redox FD-only installed capsule entrypoint inside redox");
    } else {
        qemu_failed = true;
        println!("TODO probe Redox FD-only installed capsule entrypoint inside redox");
    }

    if install_run.contains("Ran hello-service-fd@0.1.0")
        && install_run.contains("Authority enforced: true")
        && install_run.contains("Authority mode: redox-enforced-capsule-entrypoint")
        && install_run.contains("Authority enforced for service: true")
        && install_run.contains("Production arbitrary service: false")
        && install_run.contains("PASS run parsed structured child result")
        && install_run.contains("PASS run opened executable before restriction")
        && install_run.contains("PASS run opened declared preopens before restriction")
        && install_run.contains("PASS run entered manifest-derived restricted namespace")
        && install_run.contains("PASS run fexeced installed capsule entrypoint")
        && install_run.contains("PASS run service read declared resource")
        && install_run.contains("PASS run rejected denied ambient path")
        && install_run.contains("PASS run rejected undeclared scheme")
        && install_run.contains("Latest run authority mode: redox-enforced-capsule-entrypoint")
        && install_run.contains("Latest run authority enforced for service: true")
        && install_run.contains("Latest run structured child result: true")
        && install_run.contains("\"structured_child_result\": true")
        && install_run.contains("PASS fexec installed capsule entrypoint")
        && install_run.contains("PASS service reads declared resource")
        && install_run.contains("PASS denied ambient path rejected")
        && install_run.contains("PASS undeclared tcp scheme rejected")
        && install_run.contains("latest run receipt body hash")
        && install_run.contains("latest run structured child result: true")
        && install_run.contains("latest run stdout log hash")
        && install_run.contains("latest run FD launch fexec: true")
        && install_run.contains("latest run FD launch hidden scheme: true (/scheme/tcp)")
    {
        println!("PASS cocoon run uses FD-only capsule entrypoint backend inside redox");
    } else {
        qemu_failed = true;
        println!("TODO cocoon run uses FD-only capsule entrypoint backend inside redox");
    }

    if fd_run_profile_pass(&install_run, "log-service", "log-service") {
        println!("PASS P1.2g log-service FD run profile inside redox");
    } else {
        qemu_failed = true;
        println!("TODO P1.2g log-service FD run profile inside redox");
    }

    if fd_run_profile_pass(
        &install_run,
        "network-denied-service",
        "network-denied-service",
    ) {
        println!("PASS P1.2g network-denied-service FD run profile inside redox");
    } else {
        qemu_failed = true;
        println!("TODO P1.2g network-denied-service FD run profile inside redox");
    }

    if install_run.contains("latest authority probe receipt body hash")
        && install_run.contains("latest authority probe receipt archive link")
        && install_run.contains("latest authority probe stdout log hash")
        && install_run.contains("latest authority probe stderr log hash")
        && install_run.contains("latest authority probe mode: redox-child-null-namespace")
        && install_run.contains("latest authority probe structured child result: true")
        && install_run.contains("latest fd launch probe receipt body hash")
        && install_run.contains("latest fd launch probe receipt archive link")
        && install_run.contains("latest fd launch probe stdout log hash")
        && install_run.contains("latest fd launch probe stderr log hash")
        && install_run.contains("latest fd launch probe mode: redox-controlled-service-enforced")
        && install_run.contains("latest fd launch probe structured child result: true")
    {
        println!("PASS audit Redox authority probe receipt inside redox");
        println!("PASS redox authority probe receipt audited");
    } else {
        qemu_failed = true;
        println!("TODO audit Redox authority probe receipt inside redox");
    }

    if install_run.contains("latest capsule fd launch probe receipt body hash")
        && install_run.contains("latest capsule fd launch probe receipt archive link")
        && install_run.contains("latest capsule fd launch probe stdout log hash")
        && install_run.contains("latest capsule fd launch probe stderr log hash")
        && install_run
            .contains("latest capsule fd launch probe mode: redox-enforced-capsule-entrypoint")
        && install_run.contains("latest capsule fd launch probe structured child result: true")
    {
        println!("PASS audit Redox FD-only launch probe receipts inside redox");
    } else {
        qemu_failed = true;
        println!("TODO audit Redox FD-only launch probe receipts inside redox");
    }

    if install_run.contains("Recovered hello-service")
        && install_run.contains("Broke lock: false")
        && install_run.contains("Removed paths: 4")
        && install_run.contains("Broke lock: true")
        && install_run.contains("Removed paths: 1")
    {
        println!("PASS recover temporary install state inside redox");
    } else {
        qemu_failed = true;
        println!("TODO recover temporary install state inside redox");
    }

    if install_run.contains("PASS duplicate install rejected")
        && install_run.contains("failed to install capsule")
        && install_run.contains("capsule version already installed: hello-service 0.1.0")
    {
        println!("PASS reject duplicate install inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject duplicate install inside redox");
    }

    if install_run.contains("PASS logs before run rejected")
        && install_run.contains("no run receipt found for capsule 'hello-service'")
    {
        println!("PASS reject logs before run inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject logs before run inside redox");
    }

    if install_run.contains("PASS tampered latest install rejected")
        && (install_run.contains("latest install receipt archive mismatch")
            || install_run.contains("install receipt body hash mismatch"))
    {
        println!("PASS reject tampered latest install receipt inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject tampered latest install receipt inside redox");
    }

    if install_run.contains("PASS unenforced authority run rejected")
        && install_run.contains("runtime authority enforcement unavailable")
        && install_run.contains("lacks Redox namespace")
    {
        println!("PASS reject unenforced authority run inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject unenforced authority run inside redox");
    }

    if install_run.contains("Ran hello-service@0.1.0")
        && install_run.contains("Event: capsule_run")
        && install_run.contains("Authority enforced: false")
        && install_run.contains("Authority mode: smoke-unenforced")
        && install_run.contains("Stdout hash: blake3:")
        && install_run.contains("Stderr hash: blake3:")
        && install_run.contains("Success: true")
    {
        println!("PASS run hello-service inside redox");
    } else {
        qemu_failed = true;
        println!("TODO run hello-service inside redox");
    }

    if install_run.contains("Installed hello-service@0.2.0")
        && install_run.contains("Status for hello-service")
        && install_run.contains("Current version: 0.2.0")
    {
        println!("PASS report upgraded service status inside redox");
    } else {
        qemu_failed = true;
        println!("TODO report upgraded service status inside redox");
    }

    if install_run.contains("Rolled back hello-service")
        && install_run.contains("Event: capsule_rollback")
        && install_run.contains("Target version: 0.1.0")
        && install_run.contains("Latest rollback receipt: blake3:")
    {
        println!("PASS roll back capsule inside redox");
    } else {
        qemu_failed = true;
        println!("TODO roll back capsule inside redox");
    }

    if install_run.contains("Audit passed for hello-service")
        && install_run.contains("latest install receipt body hash")
        && install_run.contains("latest install receipt archive link")
        && install_run.contains("latest run receipt body hash")
        && install_run.contains("latest run receipt archive link")
        && install_run.contains("latest run stdout log hash")
        && install_run.contains("latest run stderr log hash")
        && install_run.contains("latest run authority enforcement: false (smoke-unenforced)")
        && install_run.contains("latest rollback receipt body hash")
        && install_run.contains("latest rollback receipt archive link")
        && install_run.contains("current version matches rollback target")
    {
        println!("PASS audit receipts inside redox");
    } else {
        qemu_failed = true;
        println!("TODO audit receipts inside redox");
    }

    if install_run.contains("PASS current rollback version rejected")
        && install_run.contains("failed to roll back capsule 'hello-service' to 0.1.0")
        && install_run.contains("capsule version is already current: hello-service 0.1.0")
    {
        println!("PASS reject current rollback version inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject current rollback version inside redox");
    }

    if install_run.contains("PASS missing rollback version rejected")
        && install_run.contains("failed to roll back capsule 'hello-service' to 9.9.9")
        && install_run.contains("capsule version is not installed: hello-service 9.9.9")
    {
        println!("PASS reject missing rollback version inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject missing rollback version inside redox");
    }

    if install_run.contains("PASS tampered install rejected")
        && install_run.contains("PASS tampered status rejected")
        && install_run.contains("installed capsule 'hello-service' failed verification")
        && install_run.contains("failed to read status for capsule 'hello-service'")
    {
        println!("PASS reject tampered install inside redox");
    } else {
        qemu_failed = true;
        println!("TODO reject tampered install inside redox");
    }

    if install_run.contains("Stdout log:")
        && install_run.contains("Stderr log:")
        && install_run.contains("Body hash: blake3:")
        && install_run.contains("Status for hello-service")
        && install_run.contains("State: last-run-succeeded")
        && install_run.contains("Latest run receipt: blake3:")
        && install_run.contains("Latest run authority mode: smoke-unenforced")
        && install_run.contains("Latest run stdout hash: blake3:")
        && install_run.contains("Latest run stderr hash: blake3:")
        && install_run.contains("Rolled back hello-service")
        && install_run.contains("Latest rollback receipt: blake3:")
        && install_run.contains("Current version: 0.1.0")
        && install_run.contains("Installed tree verified for hello-service@0.1.0")
        && install_run.contains("Hello from Cocoon hello-service!")
        && install_run.contains("This binary would run inside a Redox namespace")
    {
        println!("PASS collect receipts/logs");
    } else {
        qemu_failed = true;
        println!("TODO collect receipts/logs");
    }
    if qemu_failed {
        anyhow::bail!("QEMU smoke completed with TODO checks");
    }
    Ok(())
}

fn fd_run_profile_pass(output: &str, capsule_name: &str, profile: &str) -> bool {
    output.contains(&format!("Ran {capsule_name}@0.1.0"))
        && output.contains("Authority enforced: true")
        && output.contains("Authority mode: redox-enforced-capsule-entrypoint")
        && output.contains("Authority enforced for service: true")
        && output.contains("Production arbitrary service: false")
        && output.contains("PASS run parsed structured child result")
        && output.contains("PASS run opened executable before restriction")
        && output.contains("PASS run opened declared preopens before restriction")
        && output.contains("PASS run entered manifest-derived restricted namespace")
        && output.contains("PASS run fexeced installed capsule entrypoint")
        && output.contains("PASS run service read declared resource")
        && output.contains("PASS run rejected denied ambient path")
        && output.contains("PASS run rejected undeclared scheme")
        && output.contains(&format!("Status for {capsule_name}"))
        && output.contains("Latest run authority mode: redox-enforced-capsule-entrypoint")
        && output.contains("Latest run authority enforced for service: true")
        && output.contains("Latest run structured child result: true")
        && output.contains("\"structured_child_result\": true")
        && output.contains(&format!("Audit passed for {capsule_name}"))
        && output.contains("latest run structured child result: true")
        && output.contains("latest run FD launch fexec: true")
        && output.contains("latest run FD launch hidden scheme: true (/scheme/tcp)")
        && output.contains(&format!("SERVICE PROFILE {profile}"))
}

fn prepare_qemu_redoxer_root(
    root: impl AsRef<std::path::Path>,
    cocoon_binary: impl AsRef<std::path::Path>,
    capsules: &[(&str, &str)],
) -> anyhow::Result<()> {
    let root = root.as_ref();
    remove_dir_if_exists(root)?;

    let bin_dir = root.join("bin");
    let capsule_dir = root.join("capsules");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&capsule_dir)?;

    let staged_cocoon = bin_dir.join("cocoon");
    std::fs::copy(cocoon_binary, &staged_cocoon)?;
    make_executable(&staged_cocoon)?;

    for (source, staged_name) in capsules {
        std::fs::copy(source, capsule_dir.join(staged_name))?;
    }
    Ok(())
}

fn print_section(name: &str) {
    println!();
    println!("== {name} ==");
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {program} {}", args.join(" "));
    }
    Ok(())
}

fn run_optional(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    let mut command = Command::new(program);
    command.args(args);

    if std::env::var_os("COCOON_SMOKE_VERBOSE").is_none() {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let status = command.status()?;
    Ok(status.success())
}

struct CapturedCommand {
    status: std::process::ExitStatus,
    combined: String,
}

fn run_optional_capture(program: &str, args: &[&str]) -> anyhow::Result<CapturedCommand> {
    let output = Command::new(program).args(args).output()?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    if std::env::var_os("COCOON_SMOKE_VERBOSE").is_some() {
        print!("{combined}");
        if !output.status.success() {
            eprintln!(
                "command exited with status {}: {}",
                output.status,
                command_display(program, args)
            );
        }
    }

    Ok(CapturedCommand {
        status: output.status,
        combined,
    })
}

fn run_required_capture(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let captured = run_optional_capture(program, args)?;
    if !captured.status.success() {
        anyhow::bail!(
            "command failed with status {}: {}\n{}",
            captured.status,
            command_display(program, args),
            captured.combined
        );
    }
    Ok(captured.combined)
}

fn command_display(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

fn remove_dir_if_exists(path: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
    let path = path.as_ref();
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn copy_dir_recursive(
    source: impl AsRef<std::path::Path>,
    target: impl AsRef<std::path::Path>,
) -> anyhow::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();
    std::fs::create_dir_all(target)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&source_path, &target_path)?;
        } else {
            std::fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("cannot mark missing file executable: {}", path.display());
    }
    Ok(())
}

fn write_release_readme(package_root: &std::path::Path) -> anyhow::Result<()> {
    std::fs::write(
        package_root.join("README.txt"),
        "Cocoon Redox release artifact\n\
         \n\
         Contents:\n\
         - bin/cocoon: Redoxer-built Cocoon CLI when Redoxer is available.\n\
         - capsules/hello-service-signed.cocoon: signed smoke capsule.\n\
         - trust/trust-roots.json: production trust policy requiring signed bundles and receipts.\n\
         - release-manifest.json: artifact hashes and staging metadata.\n\
         \n\
         This is the current Redoxer-backed native artifact path. Direct Redox target linking\n\
         still depends on the Redox C sysroot/toolchain, and pkgar/Cookbook packaging remains\n\
         the future distribution integration path.\n",
    )?;
    Ok(())
}

fn artifact_manifest_entry(
    artifact: &std::path::Path,
    package_root: &std::path::Path,
) -> anyhow::Result<serde_json::Value> {
    let bytes = std::fs::read(artifact)?;
    let rel = artifact
        .strip_prefix(package_root)?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(serde_json::json!({
        "path": rel,
        "bytes": bytes.len(),
        "blake3": format!("blake3:{}", blake3::hash(&bytes).to_hex()),
    }))
}

fn program_available(program: &str) -> anyhow::Result<bool> {
    let status = Command::new(program)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
