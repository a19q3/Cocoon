use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

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
    },
    /// Inspect a .cocoon capsule manifest
    Inspect {
        /// Path to the .cocoon file
        capsule: PathBuf,
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
        Commands::Verify { capsule } => cmd_verify(capsule),
        Commands::Inspect { capsule } => cmd_inspect(capsule),
        Commands::DiffPermissions { old, new } => cmd_diff_permissions(old, new),
    }
}

fn cmd_build(source: PathBuf, output: Option<PathBuf>) -> Result<()> {
    info!("Building capsule from {:?}", source);
    let builder = cocoon_bundle::BundleBuilder::new(&source)
        .with_context(|| format!("Failed to read manifest from {:?}", source))?;
    let bytes = builder.build().context("Failed to build bundle")?;

    let out = output.unwrap_or_else(|| {
        PathBuf::from("target/capsules").join(format!(
            "{}.cocoon",
            source.file_name().unwrap().to_string_lossy()
        ))
    });
    std::fs::create_dir_all(out.parent().unwrap())?;
    std::fs::write(&out, &bytes)?;
    info!("Capsule written to {:?} ({} bytes)", out, bytes.len());
    Ok(())
}

fn cmd_verify(capsule: PathBuf) -> Result<()> {
    info!("Verifying {:?}", capsule);
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)
        .with_context(|| "Failed to parse bundle")?;
    let issues = reader.verify()?;

    if issues.is_empty() {
        info!("Verification passed.");
    } else {
        for issue in &issues {
            match issue {
                cocoon_bundle::VerificationIssue::HashMismatch { file, expected, actual } => {
                    warn!(
                        "Hash mismatch for {}: expected {}, got {}",
                        file, expected, actual
                    );
                }
                cocoon_bundle::VerificationIssue::MissingFile(f) => {
                    warn!("Missing file: {}", f);
                }
                cocoon_bundle::VerificationIssue::Unsigned => {
                    warn!("Bundle is unsigned (signature placeholder).");
                }
            }
        }
    }
    Ok(())
}

fn cmd_inspect(capsule: PathBuf) -> Result<()> {
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)?;
    let manifest = reader.manifest;

    println!("=== Capsule: {} v{} ===", manifest.capsule.name, manifest.capsule.version);
    println!("Description: {}", manifest.capsule.description);
    println!("Authors: {:?}", manifest.capsule.authors);
    println!("License: {}", manifest.capsule.license);
    println!();
    println!("Entry: {}", manifest.entry.cmd);
    println!("  args: {:?}", manifest.entry.args);
    println!("  cwd: {}", manifest.entry.cwd);
    println!();
    println!("Filesystem root: {}", manifest.filesystem.root);
    println!("  writable: {:?}", manifest.filesystem.writable);
    println!("  readonly: {:?}", manifest.filesystem.readonly);
    println!();
    println!("Capabilities:");
    for c in &manifest.capabilities.allow {
        println!("  + {}", c);
    }
    for c in &manifest.capabilities.deny {
        println!("  - {}", c);
    }
    println!();
    println!("Network default: {}", manifest.network.default);
    println!();
    if let Some(mem) = manifest.resources.memory_mb {
        println!("Memory limit: {} MB", mem);
    }
    if let Some(proc) = manifest.resources.max_processes {
        println!("Max processes: {}", proc);
    }
    if let Some(fd) = manifest.resources.max_open_fds {
        println!("Max open fds: {}", fd);
    }
    println!();
    println!("Update policy:");
    println!("  signed: {}", manifest.update.signed);
    println!("  rollback: {}", manifest.update.rollback);
    println!(
        "  permission_expansion_requires_confirmation: {}",
        manifest.update.permission_expansion_requires_confirmation
    );
    println!();
    println!("Audit:");
    println!("  events: {}", manifest.audit.events);
    println!("  stdout: {}", manifest.audit.stdout);
    println!("  stderr: {}", manifest.audit.stderr);
    println!();
    println!("Hash manifest entries: {}", reader.hash_manifest.files.len());
    println!("Signature algorithm: {}", reader.signature.algorithm);
    Ok(())
}

fn cmd_diff_permissions(old: PathBuf, new: PathBuf) -> Result<()> {
    let old_bytes = std::fs::read(&old)?;
    let new_bytes = std::fs::read(&new)?;
    let old_reader = cocoon_bundle::BundleReader::from_bytes(&old_bytes)?;
    let new_reader = cocoon_bundle::BundleReader::from_bytes(&new_bytes)?;

    let diff = cocoon_core::diff_capabilities(&old_reader.manifest, &new_reader.manifest)?;
    let report = cocoon_policy::format_diff_report(&diff);
    println!("{}", report);

    let policy = cocoon_policy::UpdatePolicy::default();
    if cocoon_policy::requires_confirmation(&diff, &policy) {
        println!("\nPermission expansion detected. Confirmation required.");
    }
    Ok(())
}
