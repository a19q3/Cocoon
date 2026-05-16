#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "cocoon")]
#[command(about = "Cocoon: Capability-native service capsules for RedoxOS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a .cocoon capsule from a source directory
    Build {
        /// Path to the service source directory (must contain Cocoon.toml)
        source: PathBuf,
        /// Output path for the capsule
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a .cocoon capsule
    Verify {
        /// Path to the .cocoon file
        capsule: PathBuf,
        /// Require signature metadata instead of allowing the P0 unsigned placeholder
        #[arg(long)]
        strict: bool,
    },
    /// Inspect a .cocoon capsule manifest
    Inspect {
        /// Path to the .cocoon file
        capsule: PathBuf,
    },
    /// Show the normalized Redox runtime plan without executing it
    Plan {
        /// Path to the .cocoon file
        capsule: PathBuf,
        /// Cocoon install root used when rendering the plan
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Show permission diff between two capsules
    DiffPermissions {
        /// Old capsule
        old: PathBuf,
        /// New capsule
        new: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { source, output } => cmd_build(source, output),
        Commands::Verify { capsule, strict } => cmd_verify(capsule, strict),
        Commands::Inspect { capsule } => cmd_inspect(capsule),
        Commands::Plan {
            capsule,
            install_root,
        } => cmd_plan(capsule, install_root),
        Commands::DiffPermissions { old, new } => cmd_diff_permissions(old, new),
    }
}

fn cmd_build(source: PathBuf, output: Option<PathBuf>) -> Result<()> {
    info!("Building capsule from {:?}", source);
    let builder = cocoon_bundle::BundleBuilder::new(&source)
        .with_context(|| format!("Failed to read manifest from {:?}", source))?;
    let bytes = builder.build().context("Failed to build bundle")?;

    let out = output.unwrap_or_else(|| {
        let fallback_name = source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "capsule".to_string());
        PathBuf::from("target/capsules").join(format!(
            "{fallback_name}.{}",
            cocoon_bundle::COCOON_EXTENSION
        ))
    });
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, &bytes)?;
    info!("Capsule written to {:?} ({} bytes)", out, bytes.len());
    Ok(())
}

fn cmd_verify(capsule: PathBuf, strict: bool) -> Result<()> {
    info!("Verifying {:?}", capsule);
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)
        .with_context(|| "Failed to parse bundle")?;
    let policy = cocoon_bundle::VerificationPolicy {
        require_signature: strict,
    };
    let issues = reader.verify_with_policy(policy)?;

    if issues.is_empty() {
        println!("Verification passed.");
    } else {
        println!("{}", format_verification_issues(&issues));
    }

    if issues
        .iter()
        .any(cocoon_bundle::VerificationIssue::is_integrity_failure)
    {
        bail!("verification failed");
    }
    Ok(())
}

fn cmd_inspect(capsule: PathBuf) -> Result<()> {
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)?;
    println!("{}", format_inspect(&reader));
    Ok(())
}

fn cmd_plan(capsule: PathBuf, install_root: PathBuf) -> Result<()> {
    let bytes = std::fs::read(&capsule)?;
    let verified = cocoon_bundle::BundleReader::from_verified_bytes(
        &bytes,
        cocoon_bundle::VerificationPolicy::default(),
    )
    .with_context(|| "cannot plan an invalid capsule")?;
    let install_root =
        cocoon_runtime::InstallRoot::parse(install_root).with_context(|| "invalid install root")?;

    let plan = cocoon_runtime::RuntimePlan::from_verified_bundle(&verified, install_root);
    println!("{}", format_runtime_plan(&plan));
    Ok(())
}

fn cmd_diff_permissions(old: PathBuf, new: PathBuf) -> Result<()> {
    let old_bytes = std::fs::read(&old)?;
    let new_bytes = std::fs::read(&new)?;
    let old_reader = cocoon_bundle::BundleReader::from_verified_bytes(
        &old_bytes,
        cocoon_bundle::VerificationPolicy::default(),
    )
    .with_context(|| format!("cannot diff invalid old capsule '{}'", old.display()))?
    .into_reader();
    let new_reader = cocoon_bundle::BundleReader::from_verified_bytes(
        &new_bytes,
        cocoon_bundle::VerificationPolicy::default(),
    )
    .with_context(|| format!("cannot diff invalid new capsule '{}'", new.display()))?
    .into_reader();

    let diff = cocoon_core::diff_authority(&old_reader.manifest, &new_reader.manifest)?;
    let report = cocoon_policy::format_authority_diff_report(&diff);
    println!("{}", report);
    Ok(())
}

fn format_verification_issues(issues: &[cocoon_bundle::VerificationIssue]) -> String {
    let mut lines = Vec::new();
    for issue in issues {
        match issue {
            cocoon_bundle::VerificationIssue::HashMismatch {
                file,
                expected,
                actual,
            } => lines.push(format!(
                "Hash mismatch for {file}: expected {expected}, got {actual}"
            )),
            cocoon_bundle::VerificationIssue::MissingFile(file) => {
                lines.push(format!("Missing file: {file}"));
            }
            cocoon_bundle::VerificationIssue::ExtraFile(file) => {
                lines.push(format!("Extra file not covered by hash manifest: {file}"));
            }
            cocoon_bundle::VerificationIssue::MissingEntrypoint {
                guest_path,
                archive_path,
            } => {
                lines.push(format!(
                    "Entrypoint {guest_path} maps to missing payload file: {archive_path}"
                ));
            }
            cocoon_bundle::VerificationIssue::NonExecutableEntrypoint {
                guest_path,
                archive_path,
                mode,
            } => {
                lines.push(format!(
                    "Entrypoint {guest_path} maps to non-executable payload file: {archive_path} mode={mode:o}"
                ));
            }
            cocoon_bundle::VerificationIssue::Unsigned => {
                lines.push("Bundle is unsigned (P0 signature placeholder).".to_string());
            }
            cocoon_bundle::VerificationIssue::SignatureRequired => {
                lines.push("Bundle signature is required but missing.".to_string());
            }
        }
    }
    lines.join("\n")
}

fn format_inspect(reader: &cocoon_bundle::BundleReader) -> String {
    let manifest = &reader.manifest;
    let mut lines = Vec::new();

    lines.push(format!(
        "=== Capsule: {} v{} ===",
        manifest.capsule.name, manifest.capsule.version
    ));
    lines.push(format!("Description: {}", manifest.capsule.description));
    lines.push(format!("Authors: {:?}", manifest.capsule.authors));
    lines.push(format!("License: {}", manifest.capsule.license));
    lines.push(String::new());
    lines.push(format!("Entry: {}", manifest.entry.cmd));
    lines.push(format!("  args: {:?}", manifest.entry.args));
    lines.push(format!("  cwd: {}", manifest.entry.cwd));
    lines.push(String::new());
    lines.push(format!("Filesystem root: {}", manifest.filesystem.root));
    lines.push(format!(
        "  writable: [{}]",
        join_display(&manifest.filesystem.writable)
    ));
    lines.push(format!(
        "  readonly: [{}]",
        join_display(&manifest.filesystem.readonly)
    ));
    lines.push(String::new());
    lines.push("Permissions:".to_string());
    for permission in &manifest.permissions {
        lines.push(format!("  {}", permission));
    }
    lines.push(String::new());
    lines.push("Preopens:".to_string());
    for preopen in &manifest.preopens {
        let host_path = preopen
            .host_path
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<runtime-provided>".to_string());
        lines.push(format!(
            "  {} {} -> {} rights={:?}",
            preopen.scheme, preopen.guest_path, host_path, preopen.rights
        ));
    }
    lines.push(String::new());
    lines.push("Schemes:".to_string());
    for scheme in &manifest.schemes {
        let target = scheme
            .target
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<runtime>".to_string());
        lines.push(format!(
            "  {} visibility={:?} target={}",
            scheme.name, scheme.visibility, target
        ));
    }
    lines.push(String::new());
    lines.push(format!("Network default: {}", manifest.network.default));
    lines.push(String::new());
    if let Some(memory_mb) = manifest.resources.memory_mb {
        lines.push(format!("Memory limit: {memory_mb} MB"));
    }
    if let Some(max_processes) = manifest.resources.max_processes {
        lines.push(format!("Max processes: {max_processes}"));
    }
    if let Some(max_open_fds) = manifest.resources.max_open_fds {
        lines.push(format!("Max open fds: {max_open_fds}"));
    }
    lines.push(String::new());
    lines.push("Update policy:".to_string());
    lines.push(format!("  signed: {}", manifest.update.signed));
    lines.push(format!("  rollback: {}", manifest.update.rollback));
    lines.push(format!(
        "  permission_expansion_requires_confirmation: {}",
        manifest.update.permission_expansion_requires_confirmation
    ));
    lines.push(String::new());
    lines.push("Audit:".to_string());
    lines.push(format!("  events: {}", manifest.audit.events));
    lines.push(format!("  stdout: {}", manifest.audit.stdout));
    lines.push(format!("  stderr: {}", manifest.audit.stderr));
    lines.push(String::new());
    lines.push(format!(
        "Hash manifest entries: {}",
        reader.hash_manifest.files.len()
    ));
    lines.push(format!(
        "Signature algorithm: {}",
        reader.signature.algorithm
    ));

    lines.join("\n")
}

fn join_display<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_runtime_plan(plan: &cocoon_runtime::RuntimePlan) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Runtime plan for {}@{}",
        plan.capsule_name, plan.version
    ));
    lines.push(format!("Install root: {}", plan.install_root));
    lines.push(String::new());
    lines.push("Entry:".to_string());
    lines.push(format!("  cmd: {}", plan.entry.cmd));
    lines.push(format!("  cwd: {}", plan.entry.cwd));
    lines.push(format!("  args: {:?}", plan.entry.args));
    lines.push(String::new());
    lines.push("Schemes:".to_string());
    for scheme in &plan.schemes {
        let target = scheme
            .target
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<runtime>".to_string());
        lines.push(format!(
            "  {} {} target={}",
            scheme.name,
            visibility_label(scheme.visibility),
            target
        ));
    }
    lines.push(String::new());
    lines.push("Preopens:".to_string());
    for preopen in &plan.preopens {
        let host_path = preopen
            .host_path
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<runtime-provided>".to_string());
        lines.push(format!(
            "  {} {} -> {} [{}]",
            preopen.scheme,
            host_path,
            preopen.guest_path,
            preopen_rights(&preopen.rights)
        ));
    }
    lines.push(String::new());
    lines.push("Permissions:".to_string());
    for permission in &plan.permissions {
        lines.push(format!("  {}", permission));
    }
    lines.push(String::new());
    lines.push("Stdio:".to_string());
    lines.push(format!("  stdout: {}", plan.stdio.capture_stdout));
    lines.push(format!("  stderr: {}", plan.stdio.capture_stderr));
    lines.push(format!("  events: {}", plan.stdio.audit_events));
    lines.push(String::new());
    lines.push("Receipt input:".to_string());
    lines.push(format!(
        "  manifest_hash: {}",
        plan.receipt_input.manifest_hash
    ));
    lines.push(format!(
        "  permission_hash: {}",
        plan.receipt_input.permission_hash
    ));
    lines.push(format!(
        "  runtime_version: {}",
        plan.receipt_input.runtime_version
    ));

    lines.join("\n")
}

fn visibility_label(visibility: cocoon_core::SchemeVisibility) -> &'static str {
    match visibility {
        cocoon_core::SchemeVisibility::Hidden => "hidden",
        cocoon_core::SchemeVisibility::Readonly => "readonly",
        cocoon_core::SchemeVisibility::Readwrite => "readwrite",
    }
}

fn preopen_rights(rights: &[cocoon_core::PreopenRight]) -> String {
    rights
        .iter()
        .map(|right| match right {
            cocoon_core::PreopenRight::Read => "read",
            cocoon_core::PreopenRight::Write => "write",
            cocoon_core::PreopenRight::Execute => "execute",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_verification_warning() {
        let output = format_verification_issues(&[cocoon_bundle::VerificationIssue::Unsigned]);

        assert_eq!(output, "Bundle is unsigned (P0 signature placeholder).");
    }

    #[test]
    fn formats_inspect_output() {
        let source =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-service");
        let bytes = cocoon_bundle::BundleBuilder::new(source)
            .and_then(cocoon_bundle::BundleBuilder::build)
            .unwrap();
        let reader = cocoon_bundle::BundleReader::from_bytes(&bytes).unwrap();
        let output = format_inspect(&reader);

        assert!(output.contains("=== Capsule: hello-service v0.1.0 ==="));
        assert!(output.contains("allow file readwrite /app/**"));
    }

    #[test]
    fn formats_runtime_plan_output() {
        let source =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-service");
        let bytes = cocoon_bundle::BundleBuilder::new(source)
            .and_then(cocoon_bundle::BundleBuilder::build)
            .unwrap();
        let verified = cocoon_bundle::BundleReader::from_verified_bytes(
            &bytes,
            cocoon_bundle::VerificationPolicy::default(),
        )
        .unwrap();
        let plan = cocoon_runtime::RuntimePlan::from_verified_bundle(
            &verified,
            cocoon_runtime::InstallRoot::new("/pkg/cocoon"),
        );
        let output = format_runtime_plan(&plan);

        assert!(output.contains("Runtime plan for hello-service@0.1.0"));
        assert!(output.contains("log readwrite target=service-log"));
        assert!(output
            .contains("file /pkg/cocoon/capsules/hello-service/current -> /app [read, execute]"));
    }
}
