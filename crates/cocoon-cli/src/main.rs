#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
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
        /// Ed25519 signing key JSON used to sign manifest/hashes.json
        #[arg(long)]
        signing_key: Option<PathBuf>,
    },
    /// Generate an Ed25519 bundle signing key
    Keygen {
        /// Output path for the signing key JSON
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite an existing key file
        #[arg(long)]
        force: bool,
    },
    /// Verify a .cocoon capsule
    Verify {
        /// Path to the .cocoon file
        capsule: PathBuf,
        /// Require a valid trusted signature
        #[arg(long)]
        strict: bool,
        /// Trusted public key file or signing key JSON; may be repeated for rotation windows
        #[arg(long)]
        trusted_key: Vec<PathBuf>,
        /// Trust-root config JSON to merge with explicit trusted keys
        #[arg(long)]
        trust_config: Option<PathBuf>,
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
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Cocoon install root used when rendering the plan
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Verify and install a .cocoon capsule into a Cocoon install root
    Install {
        /// Path to the .cocoon file
        capsule: PathBuf,
        /// Require a valid trusted signature before install
        #[arg(long)]
        strict: bool,
        /// Trusted public key file or signing key JSON; may be repeated for rotation windows
        #[arg(long)]
        trusted_key: Vec<PathBuf>,
        /// Ed25519 signing key JSON used to sign lifecycle receipts
        #[arg(long)]
        receipt_signing_key: Option<PathBuf>,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Run an installed capsule entrypoint and capture logs
    Run {
        /// Installed capsule name
        capsule_name: String,
        /// Execute with the current smoke runner even though Redox namespace/preopen enforcement is not implemented
        #[arg(long)]
        allow_unenforced_authority: bool,
        /// Execute through the Redox FD-only capsule entrypoint backend
        #[arg(long)]
        enforce_redox_authority: bool,
        /// Ed25519 signing key JSON used to sign the run receipt
        #[arg(long)]
        receipt_signing_key: Option<PathBuf>,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Probe Redox authority enforcement for an installed capsule
    ProbeAuthority {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Ed25519 signing key JSON used to sign the authority probe receipt
        #[arg(long)]
        receipt_signing_key: Option<PathBuf>,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Classify the remaining Redox FD-only service launch gap
    ProbeFdExec {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe Redox FD-only controlled service launch
    ProbeFdLaunch {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe Redox FD-only launch of the installed capsule entrypoint
    ProbeCapsuleFdLaunch {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Internal Redox authority probe child process
    #[command(name = "__authority-child", hide = true)]
    AuthorityChild {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Internal Redox FD exec sentinel process
    #[command(name = "__fd-exec-sentinel", hide = true)]
    FdExecSentinel,
    /// Internal Redox FD launch child process
    #[command(name = "__fd-launch-child", hide = true)]
    FdLaunchChild {
        #[arg(long)]
        executable_fd: usize,
        #[arg(long)]
        allowed_preopen_fd: usize,
        #[arg(long)]
        denied_file_path: String,
        #[arg(long)]
        hidden_scheme_path: String,
    },
    /// Internal Redox FD launch fixture service
    #[command(name = "__fd-launch-fixture", hide = true)]
    FdLaunchFixture {
        #[arg(long)]
        allowed_preopen_fd: usize,
        #[arg(long)]
        denied_file_path: String,
        #[arg(long)]
        hidden_scheme_path: String,
    },
    /// Internal Redox capsule FD launch child process
    #[command(name = "__capsule-fd-launch-child", hide = true)]
    CapsuleFdLaunchChild {
        #[arg(long)]
        executable_fd: usize,
        #[arg(long)]
        allowed_preopen_fd: usize,
        #[arg(long)]
        denied_file_path: String,
        #[arg(long)]
        hidden_scheme_path: String,
        #[arg(long = "visible-scheme")]
        visible_schemes: Vec<String>,
        #[arg(long = "entry-arg", allow_hyphen_values = true)]
        entry_args: Vec<String>,
    },
    /// Show installed capsule status and latest receipts
    Status {
        /// Installed capsule name
        capsule_name: String,
        /// Require all reported receipts to be signed
        #[arg(long)]
        require_receipt_signatures: bool,
        /// Trusted receipt public key file or signing key JSON; may be repeated for rotation windows
        #[arg(long)]
        receipt_trusted_key: Vec<PathBuf>,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Print logs from the latest captured run
    Logs {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Require the latest run receipt to be signed
        #[arg(long)]
        require_receipt_signatures: bool,
        /// Trusted receipt public key file or signing key JSON; may be repeated for rotation windows
        #[arg(long)]
        receipt_trusted_key: Vec<PathBuf>,
        /// Which stream to print
        #[arg(long, value_enum, default_value_t = LogStream::Both)]
        stream: LogStream,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify the current installed tree against its hash manifest
    CheckInstall {
        /// Installed capsule name
        capsule_name: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Roll back an installed capsule to an existing installed version
    Rollback {
        /// Installed capsule name
        capsule_name: String,
        /// Version to promote as current
        #[arg(long)]
        to_version: String,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Ed25519 signing key JSON used to sign the rollback receipt
        #[arg(long)]
        receipt_signing_key: Option<PathBuf>,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Clean recoverable temporary install state for a capsule
    Recover {
        /// Installed capsule name
        capsule_name: String,
        /// Break a stale capsule lock before recovery
        #[arg(long)]
        break_lock: bool,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Audit latest lifecycle receipts for an installed capsule
    Audit {
        /// Installed capsule name
        capsule_name: String,
        /// Require all audited receipts to be signed
        #[arg(long)]
        require_receipt_signatures: bool,
        /// Trusted receipt public key file or signing key JSON; may be repeated for rotation windows
        #[arg(long)]
        receipt_trusted_key: Vec<PathBuf>,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Manage persistent trust roots under the Cocoon install root
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },
    /// Show permission diff between two capsules
    DiffPermissions {
        /// Old capsule
        old: PathBuf,
        /// New capsule
        new: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogStream {
    Stdout,
    Stderr,
    Both,
}

#[derive(Subcommand)]
enum TrustCommands {
    /// Add a public trust root from a public key file or signing key JSON
    Add {
        /// Public key file or signing key JSON
        #[arg(long)]
        key: PathBuf,
        /// Which trust set to update
        #[arg(long, value_enum, default_value_t = TrustKind::Both)]
        kind: TrustKind,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Remove a public trust root by hex public key
    Remove {
        /// Hex public key to remove
        public_key: String,
        /// Which trust set to update
        #[arg(long, value_enum, default_value_t = TrustKind::Both)]
        kind: TrustKind,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// List configured trust roots
    List {
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
    /// Configure production trust requirements
    Policy {
        /// Require signed bundles for install/verify operations that use this trust config
        #[arg(long)]
        require_signed_bundles: bool,
        /// Allow unsigned bundles for install/verify operations that use this trust config
        #[arg(long)]
        allow_unsigned_bundles: bool,
        /// Require signed receipts for status/logs/audit operations that use this trust config
        #[arg(long)]
        require_signed_receipts: bool,
        /// Allow unsigned receipts for status/logs/audit operations that use this trust config
        #[arg(long)]
        allow_unsigned_receipts: bool,
        /// Cocoon install root
        #[arg(long, default_value = "/pkg/cocoon")]
        install_root: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TrustKind {
    Bundle,
    Receipt,
    Both,
}

impl TrustKind {
    fn includes_bundle(self) -> bool {
        matches!(self, Self::Bundle | Self::Both)
    }

    fn includes_receipt(self) -> bool {
        matches!(self, Self::Receipt | Self::Both)
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Build {
            source,
            output,
            signing_key,
        } => cmd_build(source, output, signing_key),
        Commands::Keygen { output, force } => cmd_keygen(output, force),
        Commands::Verify {
            capsule,
            strict,
            trusted_key,
            trust_config,
        } => cmd_verify(capsule, strict, trusted_key, trust_config),
        Commands::Inspect { capsule } => cmd_inspect(capsule),
        Commands::Plan {
            capsule,
            json,
            install_root,
        } => cmd_plan(capsule, install_root, json),
        Commands::Install {
            capsule,
            strict,
            trusted_key,
            receipt_signing_key,
            json,
            install_root,
        } => cmd_install(
            capsule,
            install_root,
            strict,
            trusted_key,
            receipt_signing_key,
            json,
        ),
        Commands::Run {
            capsule_name,
            allow_unenforced_authority,
            enforce_redox_authority,
            receipt_signing_key,
            json,
            install_root,
        } => cmd_run(
            capsule_name,
            install_root,
            allow_unenforced_authority,
            enforce_redox_authority,
            receipt_signing_key,
            json,
        ),
        Commands::ProbeAuthority {
            capsule_name,
            install_root,
            receipt_signing_key,
            json,
        } => cmd_probe_authority(capsule_name, install_root, receipt_signing_key, json),
        Commands::ProbeFdExec {
            capsule_name,
            install_root,
            json,
        } => cmd_probe_fd_exec(capsule_name, install_root, json),
        Commands::ProbeFdLaunch {
            capsule_name,
            install_root,
            json,
        } => cmd_probe_fd_launch(capsule_name, install_root, json),
        Commands::ProbeCapsuleFdLaunch {
            capsule_name,
            install_root,
            json,
        } => cmd_probe_capsule_fd_launch(capsule_name, install_root, json),
        Commands::AuthorityChild {
            capsule_name,
            install_root,
        } => cmd_authority_child(capsule_name, install_root),
        Commands::FdExecSentinel => cmd_fd_exec_sentinel(),
        Commands::FdLaunchChild {
            executable_fd,
            allowed_preopen_fd,
            denied_file_path,
            hidden_scheme_path,
        } => cmd_fd_launch_child(
            executable_fd,
            allowed_preopen_fd,
            denied_file_path,
            hidden_scheme_path,
        ),
        Commands::FdLaunchFixture {
            allowed_preopen_fd,
            denied_file_path,
            hidden_scheme_path,
        } => cmd_fd_launch_fixture(allowed_preopen_fd, denied_file_path, hidden_scheme_path),
        Commands::CapsuleFdLaunchChild {
            executable_fd,
            allowed_preopen_fd,
            denied_file_path,
            hidden_scheme_path,
            visible_schemes,
            entry_args,
        } => cmd_capsule_fd_launch_child(
            executable_fd,
            allowed_preopen_fd,
            denied_file_path,
            hidden_scheme_path,
            visible_schemes,
            entry_args,
        ),
        Commands::Status {
            capsule_name,
            require_receipt_signatures,
            receipt_trusted_key,
            install_root,
            json,
        } => cmd_status(
            capsule_name,
            install_root,
            require_receipt_signatures,
            receipt_trusted_key,
            json,
        ),
        Commands::Logs {
            capsule_name,
            install_root,
            require_receipt_signatures,
            receipt_trusted_key,
            stream,
            json,
        } => cmd_logs(
            capsule_name,
            install_root,
            stream,
            require_receipt_signatures,
            receipt_trusted_key,
            json,
        ),
        Commands::CheckInstall {
            capsule_name,
            install_root,
            json,
        } => cmd_check_install(capsule_name, install_root, json),
        Commands::Rollback {
            capsule_name,
            to_version,
            install_root,
            receipt_signing_key,
            json,
        } => cmd_rollback(
            capsule_name,
            to_version,
            install_root,
            receipt_signing_key,
            json,
        ),
        Commands::Recover {
            capsule_name,
            break_lock,
            install_root,
            json,
        } => cmd_recover(capsule_name, install_root, break_lock, json),
        Commands::Audit {
            capsule_name,
            require_receipt_signatures,
            receipt_trusted_key,
            install_root,
            json,
        } => cmd_audit(
            capsule_name,
            install_root,
            require_receipt_signatures,
            receipt_trusted_key,
            json,
        ),
        Commands::Trust { command } => cmd_trust(command),
        Commands::DiffPermissions { old, new } => cmd_diff_permissions(old, new),
    }
}

fn cmd_build(source: PathBuf, output: Option<PathBuf>, signing_key: Option<PathBuf>) -> Result<()> {
    info!("Building capsule from {:?}", source);
    let mut builder = cocoon_bundle::BundleBuilder::new(&source)
        .with_context(|| format!("Failed to read manifest from {:?}", source))?;
    if let Some(path) = signing_key {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read signing key '{}'", path.display()))?;
        let signing_key = cocoon_bundle::BundleSigningKey::from_json(&bytes)
            .with_context(|| format!("invalid signing key '{}'", path.display()))?;
        builder = builder.with_signing_key(signing_key);
    }
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

fn cmd_keygen(output: PathBuf, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "refusing to overwrite existing signing key '{}'",
            output.display()
        );
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let signing_key = cocoon_bundle::BundleSigningKey::generate();
    std::fs::write(&output, signing_key.to_json_pretty()?)?;
    println!("Generated signing key: {}", output.display());
    println!("Public key: {}", signing_key.public_key_hex());
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustConfig {
    version: u32,
    #[serde(default)]
    require_signed_bundles: bool,
    #[serde(default)]
    require_signed_receipts: bool,
    bundle_trust_roots: BTreeSet<String>,
    receipt_trust_roots: BTreeSet<String>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            version: 1,
            require_signed_bundles: false,
            require_signed_receipts: false,
            bundle_trust_roots: BTreeSet::new(),
            receipt_trust_roots: BTreeSet::new(),
        }
    }
}

fn cmd_verify(
    capsule: PathBuf,
    strict: bool,
    trusted_key: Vec<PathBuf>,
    trust_config: Option<PathBuf>,
) -> Result<()> {
    info!("Verifying {:?}", capsule);
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)
        .with_context(|| "Failed to parse bundle")?;
    let policy = verification_policy(strict, &trusted_key, trust_config.as_deref())?;
    let issues = reader.verify_with_policy(policy)?;

    let has_integrity_failures = issues
        .iter()
        .any(cocoon_bundle::VerificationIssue::is_integrity_failure);
    let has_warnings = issues.iter().any(|issue| !issue.is_integrity_failure());

    if issues.is_empty() {
        println!("Verification passed.");
    } else {
        println!("{}", format_verification_issues(&issues));
    }

    if has_integrity_failures {
        bail!("verification failed");
    }

    if has_warnings {
        println!("\nVerification passed with warnings.");
    }

    Ok(())
}

fn verification_policy(
    strict: bool,
    trusted_keys: &[PathBuf],
    trust_config: Option<&Path>,
) -> Result<cocoon_bundle::VerificationPolicy> {
    let trust_config = trust_config
        .map(load_trust_config)
        .transpose()?
        .unwrap_or_default();
    let mut policy = if strict || trust_config.require_signed_bundles {
        cocoon_bundle::VerificationPolicy::strict()
    } else {
        cocoon_bundle::VerificationPolicy::default()
    };

    for public_key in trust_config.bundle_trust_roots {
        policy = policy.with_trusted_public_key(public_key);
    }

    for public_key in trusted_public_keys(trusted_keys, "trusted key")? {
        policy = policy.with_trusted_public_key(public_key);
    }

    Ok(policy)
}

fn trusted_public_keys(paths: &[PathBuf], label: &str) -> Result<Vec<String>> {
    let mut public_keys = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {label} '{}'", path.display()))?;
        let public_key = cocoon_bundle::public_key_from_trust_document(&bytes)
            .with_context(|| format!("invalid {label} '{}'", path.display()))?;
        public_keys.push(public_key);
    }
    Ok(public_keys)
}

fn receipt_signing_options(
    signing_key: Option<&std::path::Path>,
) -> Result<cocoon_runtime::ReceiptSigningOptions> {
    let Some(path) = signing_key else {
        return Ok(cocoon_runtime::ReceiptSigningOptions::default());
    };
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read receipt signing key '{}'", path.display()))?;
    let signing_key = cocoon_bundle::BundleSigningKey::from_json(&bytes)
        .with_context(|| format!("invalid receipt signing key '{}'", path.display()))?;
    Ok(cocoon_runtime::ReceiptSigningOptions::with_signing_key(
        signing_key,
    ))
}

fn receipt_verification_policy(
    require_receipt_signatures: bool,
    trusted_keys: &[PathBuf],
    trust_config: Option<&Path>,
) -> Result<cocoon_runtime::ReceiptVerificationPolicy> {
    let trust_config = trust_config
        .map(load_trust_config)
        .transpose()?
        .unwrap_or_default();
    let require_receipt_signatures =
        require_receipt_signatures || trust_config.require_signed_receipts;
    let mut public_keys = BTreeSet::new();
    public_keys.extend(trust_config.receipt_trust_roots);
    public_keys.extend(trusted_public_keys(trusted_keys, "receipt trusted key")?);

    if public_keys.is_empty() {
        if require_receipt_signatures {
            bail!(
                "--require-receipt-signatures requires --receipt-trusted-key or a configured receipt trust root"
            );
        }
        return Ok(cocoon_runtime::ReceiptVerificationPolicy::default());
    }
    Ok(cocoon_runtime::ReceiptVerificationPolicy::require_trusted_signatures_from(public_keys))
}

fn trust_config_path(install_root: &Path) -> PathBuf {
    install_root.join("trust").join("trust-roots.json")
}

fn load_trust_config(path: &Path) -> Result<TrustConfig> {
    if !path.exists() {
        return Ok(TrustConfig::default());
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read trust config '{}'", path.display()))?;
    let config: TrustConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid trust config '{}'", path.display()))?;
    if config.version != 1 {
        bail!(
            "unsupported trust config version {} in '{}'",
            config.version,
            path.display()
        );
    }
    Ok(config)
}

fn write_trust_config(path: &Path, config: &TrustConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(config)?;
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn cmd_inspect(capsule: PathBuf) -> Result<()> {
    let bytes = std::fs::read(&capsule)?;
    let reader = cocoon_bundle::BundleReader::from_bytes(&bytes)?;
    println!("{}", format_inspect(&reader));
    Ok(())
}

fn cmd_plan(capsule: PathBuf, install_root: PathBuf, json: bool) -> Result<()> {
    let bytes = std::fs::read(&capsule)?;
    let verified = cocoon_bundle::BundleReader::from_verified_bytes(
        &bytes,
        cocoon_bundle::VerificationPolicy::default(),
    )
    .with_context(|| "cannot plan an invalid capsule")?;
    let install_root =
        cocoon_runtime::InstallRoot::parse(install_root).with_context(|| "invalid install root")?;

    let plan = cocoon_runtime::RuntimePlan::from_verified_bundle(&verified, install_root);
    if json {
        print_json(&runtime_plan_json(&plan))?;
    } else {
        println!("{}", format_runtime_plan(&plan));
    }
    Ok(())
}

fn cmd_install(
    capsule: PathBuf,
    install_root: PathBuf,
    strict: bool,
    trusted_key: Vec<PathBuf>,
    receipt_signing_key: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let trust_config = trust_config_path(&install_root);
    let policy = verification_policy(strict, &trusted_key, Some(&trust_config))?;
    let receipt_signing = receipt_signing_options(receipt_signing_key.as_deref())?;
    let receipt = cocoon_runtime::install_capsule_with_policy_and_receipt_signing(
        &capsule,
        &install_root,
        policy,
        receipt_signing,
    )
    .with_context(|| format!("failed to install capsule '{}'", capsule.display()))?;
    if json {
        print_json(&receipt)?;
    } else {
        println!("{}", format_install_receipt(&receipt));
    }
    Ok(())
}

fn cmd_run(
    capsule_name: String,
    install_root: PathBuf,
    allow_unenforced_authority: bool,
    enforce_redox_authority: bool,
    receipt_signing_key: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let receipt_signing = receipt_signing_options(receipt_signing_key.as_deref())?;
    let receipt = cocoon_runtime::run_installed_capsule_with_options_and_receipt_signing(
        &capsule_name,
        &install_root,
        cocoon_runtime::RunOptions {
            allow_unenforced_authority,
            enforce_redox_authority,
        },
        receipt_signing,
    )
    .with_context(|| format!("failed to run capsule '{capsule_name}'"))?;
    if json {
        print_json(&receipt)?;
    } else {
        println!("{}", format_run_receipt(&receipt));
    }
    Ok(())
}

fn cmd_probe_authority(
    capsule_name: String,
    install_root: PathBuf,
    receipt_signing_key: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let receipt_signing = receipt_signing_options(receipt_signing_key.as_deref())?;
    let report = cocoon_runtime::probe_installed_authority_with_receipt_signing(
        &capsule_name,
        &install_root,
        receipt_signing,
    )
    .with_context(|| format!("failed to probe authority for capsule '{capsule_name}'"))?;
    if json {
        print_json(&serde_json::json!({ "receipt": report.receipt }))?;
    } else {
        println!("{}", format_authority_probe_report(&report));
    }
    Ok(())
}

fn cmd_probe_fd_exec(capsule_name: String, install_root: PathBuf, json: bool) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let report =
        cocoon_runtime::probe_fd_exec_gap(&capsule_name, &install_root).with_context(|| {
            format!("failed to probe FD-only exec gap for capsule '{capsule_name}'")
        })?;
    if json {
        print_json(&fd_exec_probe_report_json(&report))?;
    } else {
        println!("{}", format_fd_exec_probe_report(&report));
    }
    Ok(())
}

fn cmd_probe_fd_launch(capsule_name: String, install_root: PathBuf, json: bool) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let report = cocoon_runtime::probe_fd_launch(&capsule_name, &install_root)
        .with_context(|| format!("failed to probe FD-only launch for capsule '{capsule_name}'"))?;
    if json {
        print_json(&serde_json::json!({ "receipt": report.receipt }))?;
    } else {
        println!("{}", format_fd_launch_probe_report(&report));
    }
    Ok(())
}

fn cmd_probe_capsule_fd_launch(
    capsule_name: String,
    install_root: PathBuf,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let report = cocoon_runtime::probe_capsule_fd_launch(&capsule_name, &install_root)
        .with_context(|| {
            format!("failed to probe capsule FD-only launch for capsule '{capsule_name}'")
        })?;
    if json {
        print_json(&serde_json::json!({ "receipt": report.receipt }))?;
    } else {
        println!("{}", format_capsule_fd_launch_probe_report(&report));
    }
    Ok(())
}

fn cmd_authority_child(capsule_name: String, install_root: PathBuf) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    cocoon_runtime::run_authority_probe_child(&capsule_name, &install_root)
        .with_context(|| format!("failed to run authority child for capsule '{capsule_name}'"))?;
    Ok(())
}

fn cmd_fd_exec_sentinel() -> Result<()> {
    bail!("path-based exec unexpectedly crossed Redox null namespace")
}

fn cmd_fd_launch_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: String,
    hidden_scheme_path: String,
) -> Result<()> {
    cocoon_runtime::run_fd_launch_probe_child(
        executable_fd,
        allowed_preopen_fd,
        &denied_file_path,
        &hidden_scheme_path,
    )
    .context("failed to run Redox FD-only launch child")?;
    Ok(())
}

fn cmd_fd_launch_fixture(
    allowed_preopen_fd: usize,
    denied_file_path: String,
    hidden_scheme_path: String,
) -> Result<()> {
    cocoon_runtime::run_fd_launch_fixture(
        allowed_preopen_fd,
        &denied_file_path,
        &hidden_scheme_path,
    )
    .context("failed to run Redox FD-only launch fixture")?;
    Ok(())
}

fn cmd_capsule_fd_launch_child(
    executable_fd: usize,
    allowed_preopen_fd: usize,
    denied_file_path: String,
    hidden_scheme_path: String,
    visible_schemes: Vec<String>,
    entry_args: Vec<String>,
) -> Result<()> {
    cocoon_runtime::run_capsule_fd_launch_probe_child(
        executable_fd,
        allowed_preopen_fd,
        &denied_file_path,
        &hidden_scheme_path,
        &visible_schemes,
        &entry_args,
    )
    .context("failed to run Redox capsule FD-only launch child")?;
    Ok(())
}

fn cmd_status(
    capsule_name: String,
    install_root: PathBuf,
    require_receipt_signatures: bool,
    receipt_trusted_key: Vec<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let trust_config = trust_config_path(&install_root);
    let receipt_policy = receipt_verification_policy(
        require_receipt_signatures,
        &receipt_trusted_key,
        Some(&trust_config),
    )?;
    let status = cocoon_runtime::service_status_report(&capsule_name, &install_root)
        .with_context(|| format!("failed to read status for capsule '{capsule_name}'"))?;
    cocoon_runtime::verify_status_report_integrity_with_receipt_policy(&status, &receipt_policy)
        .with_context(|| format!("status receipts for capsule '{capsule_name}' are invalid"))?;
    if json {
        print_json(&status_report_json(&status))?;
    } else {
        println!("{}", format_status_report(&status));
    }
    Ok(())
}

fn cmd_logs(
    capsule_name: String,
    install_root: PathBuf,
    stream: LogStream,
    require_receipt_signatures: bool,
    receipt_trusted_key: Vec<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let trust_config = trust_config_path(&install_root);
    let receipt_policy = receipt_verification_policy(
        require_receipt_signatures,
        &receipt_trusted_key,
        Some(&trust_config),
    )?;
    let logs = cocoon_runtime::latest_logs_with_receipt_policy(
        &capsule_name,
        &install_root,
        matches!(stream, LogStream::Stdout | LogStream::Both),
        matches!(stream, LogStream::Stderr | LogStream::Both),
        &receipt_policy,
    )
    .with_context(|| format!("failed to read logs for capsule '{capsule_name}'"))?;
    if json {
        print_json(&latest_logs_json(&logs))?;
    } else {
        println!("{}", format_latest_logs(&logs));
    }
    Ok(())
}

fn cmd_check_install(capsule_name: String, install_root: PathBuf, json: bool) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let verification = cocoon_runtime::verify_installed_capsule(&capsule_name, &install_root)
        .with_context(|| format!("installed capsule '{capsule_name}' failed verification"))?;
    if json {
        print_json(&installed_verification_json(&verification))?;
    } else {
        println!("{}", format_installed_verification(&verification));
    }
    Ok(())
}

fn cmd_rollback(
    capsule_name: String,
    to_version: String,
    install_root: PathBuf,
    receipt_signing_key: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let target_version = cocoon_core::CapsuleVersion::parse(to_version)?;
    let receipt_signing = receipt_signing_options(receipt_signing_key.as_deref())?;
    let receipt = cocoon_runtime::rollback_capsule_with_receipt_signing(
        &capsule_name,
        &target_version,
        &install_root,
        receipt_signing,
    )
    .with_context(|| format!("failed to roll back capsule '{capsule_name}' to {target_version}"))?;
    if json {
        print_json(&receipt)?;
    } else {
        println!("{}", format_rollback_receipt(&receipt));
    }
    Ok(())
}

fn cmd_recover(
    capsule_name: String,
    install_root: PathBuf,
    break_lock: bool,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let report = cocoon_runtime::recover_capsule_with_options(
        &capsule_name,
        &install_root,
        cocoon_runtime::RecoveryOptions { break_lock },
    )
    .with_context(|| format!("failed to recover capsule '{capsule_name}'"))?;
    if json {
        print_json(&recovery_report_json(&report))?;
    } else {
        println!("{}", format_recovery_report(&report));
    }
    Ok(())
}

fn cmd_audit(
    capsule_name: String,
    install_root: PathBuf,
    require_receipt_signatures: bool,
    receipt_trusted_key: Vec<PathBuf>,
    json: bool,
) -> Result<()> {
    let capsule_name = cocoon_core::CapsuleName::parse(capsule_name)?;
    let trust_config = trust_config_path(&install_root);
    let receipt_policy = receipt_verification_policy(
        require_receipt_signatures,
        &receipt_trusted_key,
        Some(&trust_config),
    )?;
    let report = cocoon_runtime::audit_capsule_with_receipt_policy(
        &capsule_name,
        &install_root,
        &receipt_policy,
    )
    .with_context(|| format!("failed to audit capsule '{capsule_name}'"))?;
    if json {
        print_json(&audit_report_json(&report))?;
    } else {
        println!("{}", format_audit_report(&report));
    }
    Ok(())
}

fn cmd_trust(command: TrustCommands) -> Result<()> {
    match command {
        TrustCommands::Add {
            key,
            kind,
            install_root,
        } => {
            let bytes = std::fs::read(&key)
                .with_context(|| format!("failed to read trust key '{}'", key.display()))?;
            let public_key = cocoon_bundle::public_key_from_trust_document(&bytes)
                .with_context(|| format!("invalid trust key '{}'", key.display()))?;
            let path = trust_config_path(&install_root);
            let mut config = load_trust_config(&path)?;
            let mut changed = false;
            if kind.includes_bundle() {
                changed |= config.bundle_trust_roots.insert(public_key.clone());
            }
            if kind.includes_receipt() {
                changed |= config.receipt_trust_roots.insert(public_key.clone());
            }
            write_trust_config(&path, &config)?;
            println!(
                "Trust root {}: {}",
                if changed {
                    "added"
                } else {
                    "already configured"
                },
                public_key
            );
            println!("Config: {}", path.display());
            println!("{}", format_trust_config(&config));
            Ok(())
        }
        TrustCommands::Remove {
            public_key,
            kind,
            install_root,
        } => {
            let path = trust_config_path(&install_root);
            let mut config = load_trust_config(&path)?;
            let mut changed = false;
            if kind.includes_bundle() {
                changed |= config.bundle_trust_roots.remove(&public_key);
            }
            if kind.includes_receipt() {
                changed |= config.receipt_trust_roots.remove(&public_key);
            }
            write_trust_config(&path, &config)?;
            println!(
                "Trust root {}: {}",
                if changed { "removed" } else { "not configured" },
                public_key
            );
            println!("Config: {}", path.display());
            println!("{}", format_trust_config(&config));
            Ok(())
        }
        TrustCommands::List { install_root } => {
            let path = trust_config_path(&install_root);
            let config = load_trust_config(&path)?;
            println!("Trust config: {}", path.display());
            println!("{}", format_trust_config(&config));
            Ok(())
        }
        TrustCommands::Policy {
            require_signed_bundles,
            allow_unsigned_bundles,
            require_signed_receipts,
            allow_unsigned_receipts,
            install_root,
        } => {
            if require_signed_bundles && allow_unsigned_bundles {
                bail!("--require-signed-bundles conflicts with --allow-unsigned-bundles");
            }
            if require_signed_receipts && allow_unsigned_receipts {
                bail!("--require-signed-receipts conflicts with --allow-unsigned-receipts");
            }

            let path = trust_config_path(&install_root);
            let mut config = load_trust_config(&path)?;
            if require_signed_bundles {
                config.require_signed_bundles = true;
            }
            if allow_unsigned_bundles {
                config.require_signed_bundles = false;
            }
            if require_signed_receipts {
                config.require_signed_receipts = true;
            }
            if allow_unsigned_receipts {
                config.require_signed_receipts = false;
            }
            write_trust_config(&path, &config)?;
            println!("Trust policy updated.");
            println!("Config: {}", path.display());
            println!("{}", format_trust_config(&config));
            Ok(())
        }
    }
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

    let diff = cocoon_core::diff_authority(&old_reader.manifest, &new_reader.manifest);
    let report = cocoon_policy::format_authority_diff_report(&diff);
    println!("{}", report);
    Ok(())
}

fn format_trust_config(config: &TrustConfig) -> String {
    let mut lines = vec![format!("Version: {}", config.version)];
    lines.push(format!(
        "Require signed bundles: {}",
        yes_no(config.require_signed_bundles)
    ));
    lines.push(format!(
        "Require signed receipts: {}",
        yes_no(config.require_signed_receipts)
    ));
    lines.push("Bundle trust roots:".to_string());
    if config.bundle_trust_roots.is_empty() {
        lines.push("  <none>".to_string());
    } else {
        for public_key in &config.bundle_trust_roots {
            lines.push(format!("  {public_key}"));
        }
    }
    lines.push("Receipt trust roots:".to_string());
    if config.receipt_trust_roots.is_empty() {
        lines.push("  <none>".to_string());
    } else {
        for public_key in &config.receipt_trust_roots {
            lines.push(format!("  {public_key}"));
        }
    }
    lines.join("\n")
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn runtime_plan_json(plan: &cocoon_runtime::RuntimePlan) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": plan.capsule_name.to_string(),
        "capsule_version": plan.version.to_string(),
        "install_root": plan.install_root.to_string(),
        "entry": {
            "cmd": plan.entry.cmd.to_string(),
            "cwd": plan.entry.cwd.to_string(),
            "args": plan.entry.args,
        },
        "schemes": plan.schemes.iter().map(|scheme| {
            serde_json::json!({
                "name": scheme.name.to_string(),
                "visibility": visibility_label(scheme.visibility),
                "target": scheme.target.as_ref().map(ToString::to_string),
            })
        }).collect::<Vec<_>>(),
        "preopens": plan.preopens.iter().map(|preopen| {
            serde_json::json!({
                "scheme": preopen.scheme.to_string(),
                "host_path": preopen.host_path.as_ref().map(ToString::to_string),
                "guest_path": preopen.guest_path.to_string(),
                "rights": preopen.rights.iter().map(|right| {
                    match right {
                        cocoon_core::PreopenRight::Read => "read",
                        cocoon_core::PreopenRight::Write => "write",
                        cocoon_core::PreopenRight::Execute => "execute",
                    }
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "permissions": plan.permissions.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "stdio": {
            "stdout": plan.stdio.capture_stdout,
            "stderr": plan.stdio.capture_stderr,
            "events": plan.stdio.audit_events,
        },
        "receipt_input": {
            "manifest_hash": plan.receipt_input.manifest_hash,
            "permission_hash": plan.receipt_input.permission_hash,
            "runtime_version": plan.receipt_input.runtime_version,
        }
    })
}

fn status_report_json(status: &cocoon_runtime::ServiceStatusReport) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": status.capsule_name,
        "state": service_state_label(status.state),
        "current_version": status.current_version,
        "latest_install_receipt": status.latest_install_receipt,
        "latest_run_receipt": status.latest_run_receipt,
        "latest_authority_probe_receipt": status.latest_authority_probe_receipt,
        "latest_fd_launch_probe_receipt": status.latest_fd_launch_probe_receipt,
        "latest_capsule_fd_launch_probe_receipt": status.latest_capsule_fd_launch_probe_receipt,
        "latest_rollback_receipt": status.latest_rollback_receipt,
    })
}

fn latest_logs_json(logs: &cocoon_runtime::LatestLogs) -> serde_json::Value {
    serde_json::json!({
        "stdout": logs.stdout,
        "stderr": logs.stderr,
    })
}

fn installed_verification_json(
    verification: &cocoon_runtime::InstalledVerification,
) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": verification.capsule_name,
        "capsule_version": verification.capsule_version,
        "files_checked": verification.files_checked,
    })
}

fn fd_exec_probe_report_json(report: &cocoon_runtime::FdExecProbeReport) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": report.capsule_name,
        "capsule_version": report.capsule_version,
        "mode": &report.mode,
        "attempted_executable": report.attempted_executable,
        "expected_path_exec_failure": report.expected_path_exec_failure,
        "classified_fd_exec_blocker": report.classified_fd_exec_blocker,
        "failure_message": report.failure_message,
    })
}

fn recovery_report_json(report: &cocoon_runtime::RecoveryReport) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": report.capsule_name,
        "broke_lock": report.broke_lock,
        "removed_paths": report.removed_paths,
    })
}

fn audit_report_json(report: &cocoon_runtime::AuditReport) -> serde_json::Value {
    serde_json::json!({
        "capsule_name": report.capsule_name,
        "checks": report.checks.iter().map(|check| {
            serde_json::json!({
                "name": check.name,
                "detail": check.detail,
            })
        }).collect::<Vec<_>>(),
    })
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
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
            cocoon_bundle::VerificationIssue::UnsupportedHashAlgorithm { algorithm } => {
                lines.push(format!(
                    "Unsupported hash algorithm '{algorithm}' in hash manifest."
                ));
            }
            cocoon_bundle::VerificationIssue::SignatureTrustRequired => {
                lines.push("Bundle signature trust root is required.".to_string());
            }
            cocoon_bundle::VerificationIssue::SignatureInvalid(reason) => {
                lines.push(format!("Bundle signature is invalid: {reason}"));
            }
            cocoon_bundle::VerificationIssue::SignatureUntrusted { public_key } => {
                lines.push(format!("Bundle signature key is not trusted: {public_key}"));
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

fn format_install_receipt(receipt: &cocoon_runtime::InstallReceipt) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Installed {}@{}",
        receipt.body.capsule_name, receipt.body.capsule_version
    ));
    lines.push(format!("Event: {}", receipt.event));
    lines.push(format!("Install root: {}", receipt.body.install_root));
    lines.push(format!("Manifest hash: {}", receipt.body.manifest_hash));
    lines.push(format!("Bundle hash: {}", receipt.body.bundle_hash));
    lines.push(format!("Permission hash: {}", receipt.body.permission_hash));
    lines.push(format!("Installed at: {}", receipt.body.installed_at));
    lines.push(format!(
        "Previous receipt: {}",
        receipt.body.previous_receipt.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!("Body hash: {}", receipt.body_hash));
    lines.push(format!(
        "Signature: {}",
        format_signature(&receipt.signature)
    ));

    lines.join("\n")
}

fn format_run_receipt(receipt: &cocoon_runtime::RunReceipt) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Ran {}@{}",
        receipt.body.capsule_name, receipt.body.capsule_version
    ));
    lines.push(format!("Event: {}", receipt.event));
    lines.push(format!("Command: {}", receipt.body.command));
    lines.push(format!("Args: {:?}", receipt.body.args));
    if receipt.body.actual_args != receipt.body.args {
        lines.push(format!("Actual args: {:?}", receipt.body.actual_args));
    }
    lines.push(format!(
        "Authority enforced: {}",
        receipt.body.authority_enforced
    ));
    lines.push(format!("Authority mode: {}", receipt.body.authority_mode));
    lines.push(format!(
        "Authority enforced for service: {}",
        receipt.body.authority_enforced_for_service
    ));
    lines.push(format!(
        "Production arbitrary service: {}",
        receipt.body.production_arbitrary_service
    ));
    if receipt.body.structured_child_result {
        lines.push("PASS run parsed structured child result".to_string());
    }
    if receipt.body.open_executable_before_restriction {
        lines.push("PASS run opened executable before restriction".to_string());
    }
    if receipt.body.open_declared_preopens_before_restriction {
        lines.push("PASS run opened declared preopens before restriction".to_string());
    }
    if receipt.body.entered_restricted_namespace {
        lines.push("PASS run entered manifest-derived restricted namespace".to_string());
    }
    if receipt.body.exec_from_fd_succeeded {
        lines.push("PASS run fexeced installed capsule entrypoint".to_string());
    }
    if receipt.body.allowed_preopen_read {
        lines.push("PASS run service read declared resource".to_string());
    }
    if receipt.body.denied_file_rejected {
        lines.push("PASS run rejected denied ambient path".to_string());
    }
    if receipt.body.hidden_scheme_rejected {
        lines.push("PASS run rejected undeclared scheme".to_string());
    }
    lines.push(format!(
        "Exit code: {}",
        receipt
            .body
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "<signal>".to_string())
    ));
    lines.push(format!("Success: {}", receipt.body.success));
    lines.push(format!("Stdout log: {}", receipt.body.stdout_log));
    lines.push(format!("Stdout hash: {}", receipt.body.stdout_hash));
    lines.push(format!("Stderr log: {}", receipt.body.stderr_log));
    lines.push(format!("Stderr hash: {}", receipt.body.stderr_hash));
    lines.push(format!("Started at: {}", receipt.body.started_at));
    lines.push(format!("Finished at: {}", receipt.body.finished_at));
    lines.push(format!("Body hash: {}", receipt.body_hash));
    lines.push(format!(
        "Signature: {}",
        format_signature(&receipt.signature)
    ));

    lines.join("\n")
}

fn format_rollback_receipt(receipt: &cocoon_runtime::RollbackReceipt) -> String {
    let mut lines = Vec::new();

    lines.push(format!("Rolled back {}", receipt.body.capsule_name));
    lines.push(format!("Event: {}", receipt.event));
    lines.push(format!(
        "Previous version: {}",
        receipt.body.previous_version
    ));
    lines.push(format!("Target version: {}", receipt.body.target_version));
    lines.push(format!("Rolled back at: {}", receipt.body.rolled_back_at));
    lines.push(format!("Body hash: {}", receipt.body_hash));
    lines.push(format!(
        "Signature: {}",
        format_signature(&receipt.signature)
    ));

    lines.join("\n")
}

fn format_status_report(status: &cocoon_runtime::ServiceStatusReport) -> String {
    let mut lines = Vec::new();

    lines.push(format!("Status for {}", status.capsule_name));
    lines.push(format!("State: {}", service_state_label(status.state)));
    lines.push(format!(
        "Current version: {}",
        status.current_version.as_deref().unwrap_or("<none>")
    ));

    if let Some(receipt) = &status.latest_install_receipt {
        lines.push(format!("Latest install receipt: {}", receipt.body_hash));
        lines.push(format!("Installed at: {}", receipt.body.installed_at));
    } else {
        lines.push("Latest install receipt: <none>".to_string());
    }

    if let Some(receipt) = &status.latest_run_receipt {
        lines.push(format!("Latest run receipt: {}", receipt.body_hash));
        lines.push(format!("Latest run success: {}", receipt.body.success));
        lines.push(format!(
            "Latest run authority enforced: {}",
            receipt.body.authority_enforced
        ));
        lines.push(format!(
            "Latest run authority mode: {}",
            receipt.body.authority_mode
        ));
        lines.push(format!(
            "Latest run production arbitrary service: {}",
            receipt.body.production_arbitrary_service
        ));
        if receipt.body.authority_enforced_for_service {
            lines.push(format!(
                "Latest run authority enforced for service: {}",
                receipt.body.authority_enforced_for_service
            ));
            lines.push(format!(
                "Latest run structured child result: {}",
                receipt.body.structured_child_result
            ));
        }
        lines.push(format!("Latest run stdout: {}", receipt.body.stdout_log));
        lines.push(format!(
            "Latest run stdout hash: {}",
            receipt.body.stdout_hash
        ));
        lines.push(format!("Latest run stderr: {}", receipt.body.stderr_log));
        lines.push(format!(
            "Latest run stderr hash: {}",
            receipt.body.stderr_hash
        ));
    } else {
        lines.push("Latest run receipt: <none>".to_string());
    }

    if let Some(receipt) = &status.latest_authority_probe_receipt {
        lines.push(format!(
            "Latest authority probe receipt: {}",
            receipt.body_hash
        ));
        lines.push(format!(
            "Latest authority probe mode: {}",
            receipt.body.mode
        ));
        lines.push(format!(
            "Latest authority probe success: {}",
            receipt.body.success
        ));
        lines.push(format!(
            "Latest authority probe structured child result: {}",
            receipt.body.structured_child_result
        ));
    } else {
        lines.push("Latest authority probe receipt: <none>".to_string());
    }

    if let Some(receipt) = &status.latest_fd_launch_probe_receipt {
        lines.push(format!(
            "Latest FD launch probe receipt: {}",
            receipt.body_hash
        ));
        lines.push(format!(
            "Latest FD launch probe mode: {}",
            receipt.body.mode
        ));
        lines.push(format!(
            "Latest FD launch probe structured child result: {}",
            receipt.body.structured_child_result
        ));
    } else {
        lines.push("Latest FD launch probe receipt: <none>".to_string());
    }

    if let Some(receipt) = &status.latest_capsule_fd_launch_probe_receipt {
        lines.push(format!(
            "Latest capsule FD launch probe receipt: {}",
            receipt.body_hash
        ));
        lines.push(format!(
            "Latest capsule FD launch probe mode: {}",
            receipt.body.mode
        ));
        lines.push(format!(
            "Latest capsule FD launch probe structured child result: {}",
            receipt.body.structured_child_result
        ));
    } else {
        lines.push("Latest capsule FD launch probe receipt: <none>".to_string());
    }

    if let Some(receipt) = &status.latest_rollback_receipt {
        lines.push(format!("Latest rollback receipt: {}", receipt.body_hash));
        lines.push(format!(
            "Latest rollback target: {}",
            receipt.body.target_version
        ));
    } else {
        lines.push("Latest rollback receipt: <none>".to_string());
    }

    lines.join("\n")
}

fn format_latest_logs(logs: &cocoon_runtime::LatestLogs) -> String {
    let mut lines = Vec::new();

    if let Some(stdout) = &logs.stdout {
        lines.push("== stdout ==".to_string());
        lines.push(stdout.clone());
    }

    if let Some(stderr) = &logs.stderr {
        lines.push("== stderr ==".to_string());
        lines.push(stderr.clone());
    }

    lines.join("\n")
}

fn format_installed_verification(verification: &cocoon_runtime::InstalledVerification) -> String {
    format!(
        "Installed tree verified for {}@{}\nFiles checked: {}",
        verification.capsule_name, verification.capsule_version, verification.files_checked
    )
}

fn format_authority_probe_report(report: &cocoon_runtime::AuthorityProbeReport) -> String {
    let receipt = &report.receipt;
    let mut lines = Vec::new();
    lines.push(format!(
        "Authority probe for {}@{}",
        receipt.body.capsule_name, receipt.body.capsule_version
    ));
    lines.push(format!("Event: {}", receipt.event));
    lines.push(format!("Mode: {}", receipt.body.mode));
    lines.push(format!(
        "Child exit code: {}",
        receipt
            .body
            .child_exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "<signal>".to_string())
    ));
    lines.push(format!("Success: {}", receipt.body.success));
    if receipt.body.structured_child_result {
        lines.push("PASS redox authority child returned structured result".to_string());
    }
    if receipt.body.entered_restricted_namespace {
        lines.push("PASS redox authority child entered restricted namespace".to_string());
    }
    if receipt.body.allowed_preopen_read {
        lines.push(format!(
            "PASS redox authority child read allowed preopen {}",
            receipt.body.allowed_preopen_guest_path
        ));
    }
    if receipt.body.denied_file_rejected {
        lines.push(format!(
            "PASS redox authority child rejected denied file path {}",
            receipt.body.denied_file_path
        ));
    }
    if receipt.body.hidden_scheme_rejected {
        lines.push(format!(
            "PASS redox authority child rejected hidden tcp scheme {}",
            receipt.body.hidden_scheme_path
        ));
    }
    lines.push(format!("Stdout log: {}", receipt.body.stdout_log));
    lines.push(format!("Stdout hash: {}", receipt.body.stdout_hash));
    lines.push(format!("Stderr log: {}", receipt.body.stderr_log));
    lines.push(format!("Stderr hash: {}", receipt.body.stderr_hash));
    lines.push(format!("Started at: {}", receipt.body.started_at));
    lines.push(format!("Finished at: {}", receipt.body.finished_at));
    lines.push(format!("Body hash: {}", receipt.body_hash));
    lines.push(format!(
        "Signature: {}",
        format_signature(&receipt.signature)
    ));
    lines.join("\n")
}

fn format_signature(signature: &Option<cocoon_bundle::SignatureMetadata>) -> String {
    let Some(signature) = signature else {
        return "<none>".to_string();
    };
    format!(
        "{} {} {}",
        signature.algorithm,
        signature
            .public_key
            .as_deref()
            .unwrap_or("<missing-public-key>"),
        signature.signature
    )
}

fn format_fd_exec_probe_report(report: &cocoon_runtime::FdExecProbeReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "FD-only exec probe for {}@{}",
        report.capsule_name, report.capsule_version
    ));
    lines.push(format!("Mode: {}", report.mode));
    lines.push(format!(
        "Attempted executable: {}",
        report.attempted_executable
    ));
    lines.push(format!(
        "Expected path exec failure: {}",
        report.expected_path_exec_failure
    ));
    lines.push(format!(
        "Classified FD-only service launch blocker: {}",
        report.classified_fd_exec_blocker
    ));
    lines.push(format!("Failure: {}", report.failure_message));
    if report.expected_path_exec_failure && report.classified_fd_exec_blocker {
        lines.push("PASS redox path exec blocked after null namespace".to_string());
        lines.push("PASS redox fd-exec gap classified".to_string());
    }
    lines.join("\n")
}

fn format_fd_launch_probe_report(report: &cocoon_runtime::FdLaunchProbeReport) -> String {
    let body = &report.receipt.body;
    let mut lines = Vec::new();
    lines.push(format!(
        "FD-only launch probe for {}@{}",
        body.capsule_name, body.capsule_version
    ));
    lines.push(format!("Mode: {}", body.mode));
    lines.push(format!(
        "Authority enforced for service: {}",
        body.authority_enforced_for_service
    ));
    lines.push(format!(
        "Production arbitrary service: {}",
        body.production_arbitrary_service
    ));
    lines.push(format!("Body hash: {}", report.receipt.body_hash));
    if body.structured_child_result {
        lines.push("PASS FD launch child returned structured result".to_string());
    }
    if body.open_executable_before_restriction {
        lines.push("PASS open executable before restriction".to_string());
    }
    if body.open_declared_preopens_before_restriction {
        lines.push("PASS open declared preopens before restriction".to_string());
    }
    if body.entered_restricted_namespace {
        lines.push("PASS enter restricted namespace".to_string());
    }
    if body.exec_from_fd_succeeded {
        lines.push("PASS exec service from inherited executable FD".to_string());
    }
    if body.allowed_preopen_read {
        lines.push("PASS service reads declared preopen".to_string());
    }
    if body.denied_file_rejected {
        lines.push("PASS service cannot open denied path by name".to_string());
    }
    if body.hidden_scheme_rejected {
        lines.push("PASS service cannot open hidden/undeclared scheme".to_string());
    }
    if !body.failure_message.is_empty() {
        lines.push(format!(
            "BLOCKED redox FD-only service launch: {}",
            body.failure_message
        ));
    }
    lines.join("\n")
}

fn format_capsule_fd_launch_probe_report(
    report: &cocoon_runtime::CapsuleFdLaunchProbeReport,
) -> String {
    let body = &report.receipt.body;
    let mut lines = Vec::new();
    lines.push(format!(
        "Capsule FD-only launch probe for {}@{}",
        body.capsule_name, body.capsule_version
    ));
    lines.push(format!("Mode: {}", body.mode));
    lines.push(format!(
        "Authority enforced for service: {}",
        body.authority_enforced_for_service
    ));
    lines.push(format!(
        "Production arbitrary service: {}",
        body.production_arbitrary_service
    ));
    lines.push(format!("Body hash: {}", report.receipt.body_hash));
    if body.structured_child_result {
        lines.push("PASS capsule FD launch child returned structured result".to_string());
    }
    if body.open_executable_before_restriction {
        lines.push("PASS open installed capsule entrypoint before restriction".to_string());
    }
    if body.open_declared_preopens_before_restriction {
        lines.push("PASS open declared preopens before restriction".to_string());
    }
    if body.entered_restricted_namespace {
        lines.push("PASS enter manifest-derived restricted namespace".to_string());
    }
    if body.exec_from_fd_succeeded {
        lines.push("PASS fexec installed capsule entrypoint".to_string());
    }
    if body.allowed_preopen_read {
        lines.push("PASS service reads declared resource".to_string());
    }
    if body.denied_file_rejected {
        lines.push("PASS denied ambient path rejected".to_string());
    }
    if body.hidden_scheme_rejected {
        lines.push("PASS undeclared tcp scheme rejected".to_string());
    }
    if !body.failure_message.is_empty() {
        lines.push(format!(
            "BLOCKED redox capsule FD-only launch: {}",
            body.failure_message
        ));
    }
    lines.join("\n")
}

fn format_recovery_report(report: &cocoon_runtime::RecoveryReport) -> String {
    let mut lines = vec![
        format!("Recovered {}", report.capsule_name),
        format!("Broke lock: {}", report.broke_lock),
        format!("Removed paths: {}", report.removed_paths.len()),
    ];
    for path in &report.removed_paths {
        lines.push(format!("  {path}"));
    }
    lines.join("\n")
}

fn format_audit_report(report: &cocoon_runtime::AuditReport) -> String {
    let mut lines = vec![
        format!("Audit passed for {}", report.capsule_name),
        format!("Checks: {}", report.checks.len()),
    ];
    for check in &report.checks {
        lines.push(format!("  {}: {}", check.name, check.detail));
    }
    lines.join("\n")
}

fn service_state_label(state: cocoon_runtime::ServiceState) -> &'static str {
    match state {
        cocoon_runtime::ServiceState::NotInstalled => "not-installed",
        cocoon_runtime::ServiceState::Installed => "installed",
        cocoon_runtime::ServiceState::LastRunSucceeded => "last-run-succeeded",
        cocoon_runtime::ServiceState::LastRunFailed => "last-run-failed",
    }
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
        assert!(
            output.contains(
                "file /pkg/cocoon/capsules/hello-service/current -> /app [read, execute]"
            )
        );
    }

    #[test]
    fn formats_install_receipt_output() {
        let receipt = cocoon_runtime::InstallReceipt {
            receipt_version: 1,
            event: "capsule_install".to_string(),
            body: cocoon_runtime::InstallReceiptBody {
                capsule_name: "hello-service".to_string(),
                capsule_version: "0.1.0".to_string(),
                manifest_hash: "blake3:manifest".to_string(),
                bundle_hash: "blake3:bundle".to_string(),
                permission_hash: "blake3:permission".to_string(),
                installed_at: "unix:1".to_string(),
                install_root: "/pkg/cocoon/capsules/hello-service/versions/0.1.0".to_string(),
                runtime_version: "0.1.0".to_string(),
                previous_receipt: None,
            },
            body_hash: "blake3:receipt".to_string(),
            signature: None,
        };
        let output = format_install_receipt(&receipt);

        assert!(output.contains("Installed hello-service@0.1.0"));
        assert!(output.contains("Event: capsule_install"));
        assert!(output.contains("Previous receipt: <none>"));
        assert!(output.contains("Signature: <none>"));
    }

    #[test]
    fn formats_run_receipt_output() {
        let receipt = cocoon_runtime::RunReceipt {
            receipt_version: 1,
            event: "capsule_run".to_string(),
            body: cocoon_runtime::RunReceiptBody {
                capsule_name: "hello-service".to_string(),
                capsule_version: "0.1.0".to_string(),
                command: "/app/bin/hello-service".to_string(),
                args: Vec::new(),
                actual_args: Vec::new(),
                authority_enforced: false,
                authority_mode: cocoon_runtime::RunAuthorityMode::SmokeUnenforced,
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
                exit_code: Some(0),
                success: true,
                stdout_log: "/pkg/cocoon/logs/stdout.log".to_string(),
                stdout_hash: "blake3:stdout".to_string(),
                stderr_log: "/pkg/cocoon/logs/stderr.log".to_string(),
                stderr_hash: "blake3:stderr".to_string(),
                started_at: "unix:1".to_string(),
                finished_at: "unix:2".to_string(),
                runtime_version: "0.1.0".to_string(),
            },
            body_hash: "blake3:run".to_string(),
            signature: None,
        };
        let output = format_run_receipt(&receipt);

        assert!(output.contains("Ran hello-service@0.1.0"));
        assert!(output.contains("Event: capsule_run"));
        assert!(output.contains("Authority enforced: false"));
        assert!(output.contains("Authority mode: smoke-unenforced"));
        assert!(output.contains("Authority enforced for service: false"));
        assert!(output.contains("Production arbitrary service: false"));
        assert!(output.contains("Exit code: 0"));
        assert!(output.contains("Success: true"));
        assert!(output.contains("Stdout hash: blake3:stdout"));
        assert!(output.contains("Stderr hash: blake3:stderr"));
        assert!(output.contains("Signature: <none>"));
    }

    #[test]
    fn formats_status_report_output() {
        let install_receipt = cocoon_runtime::InstallReceipt {
            receipt_version: 1,
            event: "capsule_install".to_string(),
            body: cocoon_runtime::InstallReceiptBody {
                capsule_name: "hello-service".to_string(),
                capsule_version: "0.1.0".to_string(),
                manifest_hash: "blake3:manifest".to_string(),
                bundle_hash: "blake3:bundle".to_string(),
                permission_hash: "blake3:permission".to_string(),
                installed_at: "unix:1".to_string(),
                install_root: "/pkg/cocoon/capsules/hello-service/versions/0.1.0".to_string(),
                runtime_version: "0.1.0".to_string(),
                previous_receipt: None,
            },
            body_hash: "blake3:install".to_string(),
            signature: None,
        };
        let run_receipt = cocoon_runtime::RunReceipt {
            receipt_version: 1,
            event: "capsule_run".to_string(),
            body: cocoon_runtime::RunReceiptBody {
                capsule_name: "hello-service".to_string(),
                capsule_version: "0.1.0".to_string(),
                command: "/app/bin/hello-service".to_string(),
                args: Vec::new(),
                actual_args: Vec::new(),
                authority_enforced: false,
                authority_mode: cocoon_runtime::RunAuthorityMode::SmokeUnenforced,
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
                exit_code: Some(0),
                success: true,
                stdout_log: "/pkg/cocoon/logs/stdout.log".to_string(),
                stdout_hash: "blake3:stdout".to_string(),
                stderr_log: "/pkg/cocoon/logs/stderr.log".to_string(),
                stderr_hash: "blake3:stderr".to_string(),
                started_at: "unix:1".to_string(),
                finished_at: "unix:2".to_string(),
                runtime_version: "0.1.0".to_string(),
            },
            body_hash: "blake3:run".to_string(),
            signature: None,
        };
        let status = cocoon_runtime::ServiceStatusReport {
            capsule_name: "hello-service".to_string(),
            state: cocoon_runtime::ServiceState::LastRunSucceeded,
            current_version: Some("0.1.0".to_string()),
            latest_install_receipt: Some(install_receipt),
            latest_run_receipt: Some(run_receipt),
            latest_authority_probe_receipt: None,
            latest_fd_launch_probe_receipt: None,
            latest_capsule_fd_launch_probe_receipt: None,
            latest_rollback_receipt: None,
        };
        let output = format_status_report(&status);

        assert!(output.contains("Status for hello-service"));
        assert!(output.contains("State: last-run-succeeded"));
        assert!(output.contains("Current version: 0.1.0"));
        assert!(output.contains("Latest install receipt: blake3:install"));
        assert!(output.contains("Latest run receipt: blake3:run"));
        assert!(output.contains("Latest run authority enforced: false"));
        assert!(output.contains("Latest run authority mode: smoke-unenforced"));
        assert!(output.contains("Latest run production arbitrary service: false"));
        assert!(output.contains("Latest run stdout hash: blake3:stdout"));
        assert!(output.contains("Latest run stderr hash: blake3:stderr"));
        assert!(output.contains("Latest authority probe receipt: <none>"));
        assert!(output.contains("Latest FD launch probe receipt: <none>"));
        assert!(output.contains("Latest capsule FD launch probe receipt: <none>"));
    }

    #[test]
    fn formats_authority_probe_report_output() {
        let receipt = cocoon_runtime::AuthorityProbeReceipt {
            receipt_version: 1,
            event: "authority_probe".to_string(),
            body: cocoon_runtime::AuthorityProbeReceiptBody {
                capsule_name: "hello-service".to_string(),
                capsule_version: "0.1.0".to_string(),
                mode: cocoon_runtime::AuthorityProbeMode::RedoxChildNullNamespace,
                child_exit_code: Some(0),
                success: true,
                structured_child_result: true,
                entered_restricted_namespace: true,
                allowed_preopen_read: true,
                allowed_preopen_guest_path: "/app".to_string(),
                denied_file_path: "/home/cocoon-authority-probe-denied".to_string(),
                denied_file_rejected: true,
                hidden_scheme_path: "/scheme/tcp".to_string(),
                hidden_scheme_rejected: true,
                stdout_log: "/pkg/cocoon/logs/authority/stdout.log".to_string(),
                stdout_hash: "blake3:stdout".to_string(),
                stderr_log: "/pkg/cocoon/logs/authority/stderr.log".to_string(),
                stderr_hash: "blake3:stderr".to_string(),
                started_at: "unix:1".to_string(),
                finished_at: "unix:2".to_string(),
                runtime_version: "0.1.0".to_string(),
            },
            body_hash: "blake3:authority".to_string(),
            signature: None,
        };
        let output =
            format_authority_probe_report(&cocoon_runtime::AuthorityProbeReport { receipt });

        assert!(output.contains("Authority probe for hello-service@0.1.0"));
        assert!(output.contains("Event: authority_probe"));
        assert!(output.contains("Mode: redox-child-null-namespace"));
        assert!(output.contains("PASS redox authority child returned structured result"));
        assert!(output.contains("PASS redox authority child entered restricted namespace"));
        assert!(output.contains("PASS redox authority child read allowed preopen /app"));
        assert!(output.contains("PASS redox authority child rejected denied file path"));
        assert!(output.contains("PASS redox authority child rejected hidden tcp scheme"));
        assert!(output.contains("Body hash: blake3:authority"));
    }

    #[test]
    fn formats_fd_exec_probe_report_output() {
        let output = format_fd_exec_probe_report(&cocoon_runtime::FdExecProbeReport {
            capsule_name: "hello-service".to_string(),
            capsule_version: "0.1.0".to_string(),
            mode: cocoon_runtime::FdExecProbeMode::RedoxNullNamespacePathExecClassification,
            attempted_executable: "target/x86_64-unknown-redox/debug/cocoon".to_string(),
            expected_path_exec_failure: true,
            classified_fd_exec_blocker: true,
            failure_message: "No such file or directory".to_string(),
        });

        assert!(output.contains("FD-only exec probe for hello-service@0.1.0"));
        assert!(output.contains("Mode: redox-null-namespace-path-exec-classification"));
        assert!(output.contains("Expected path exec failure: true"));
        assert!(output.contains("Classified FD-only service launch blocker: true"));
        assert!(output.contains("PASS redox path exec blocked after null namespace"));
        assert!(output.contains("PASS redox fd-exec gap classified"));
    }

    #[test]
    fn formats_fd_launch_probe_report_output() {
        let output = format_fd_launch_probe_report(&cocoon_runtime::FdLaunchProbeReport {
            receipt: cocoon_runtime::FdLaunchProbeReceipt {
                receipt_version: 1,
                event: "fd_launch_probe".to_string(),
                body: cocoon_runtime::FdLaunchProbeReceiptBody {
                    capsule_name: "hello-service".to_string(),
                    capsule_version: "0.1.0".to_string(),
                    mode: cocoon_runtime::FdLaunchMode::RedoxControlledServiceEnforced,
                    authority_enforced_for_service: true,
                    production_arbitrary_service: false,
                    child_exit_code: Some(0),
                    structured_child_result: true,
                    open_executable_before_restriction: true,
                    open_declared_preopens_before_restriction: true,
                    entered_restricted_namespace: true,
                    exec_from_fd_attempted: true,
                    exec_from_fd_succeeded: true,
                    allowed_preopen_read: true,
                    allowed_preopen_guest_path: "/app".to_string(),
                    denied_file_path: "/home/cocoon-authority-probe-denied".to_string(),
                    denied_file_rejected: true,
                    hidden_scheme_path: "/scheme/tcp".to_string(),
                    hidden_scheme_rejected: true,
                    failure_message: String::new(),
                    stdout_log: "/pkg/cocoon/logs/fd-launch/stdout.log".to_string(),
                    stdout_hash: "blake3:stdout".to_string(),
                    stderr_log: "/pkg/cocoon/logs/fd-launch/stderr.log".to_string(),
                    stderr_hash: "blake3:stderr".to_string(),
                    started_at: "unix:1".to_string(),
                    finished_at: "unix:2".to_string(),
                    runtime_version: "0.1.0".to_string(),
                },
                body_hash: "blake3:fd-launch".to_string(),
                signature: None,
            },
        });

        assert!(output.contains("FD-only launch probe for hello-service@0.1.0"));
        assert!(output.contains("Mode: redox-controlled-service-enforced"));
        assert!(output.contains("Authority enforced for service: true"));
        assert!(output.contains("Production arbitrary service: false"));
        assert!(output.contains("PASS FD launch child returned structured result"));
        assert!(output.contains("PASS open executable before restriction"));
        assert!(output.contains("PASS enter restricted namespace"));
        assert!(output.contains("PASS exec service from inherited executable FD"));
        assert!(output.contains("PASS service reads declared preopen"));
        assert!(output.contains("PASS service cannot open denied path by name"));
        assert!(output.contains("PASS service cannot open hidden/undeclared scheme"));
    }

    #[test]
    fn formats_capsule_fd_launch_probe_report_output() {
        let output =
            format_capsule_fd_launch_probe_report(&cocoon_runtime::CapsuleFdLaunchProbeReport {
                receipt: cocoon_runtime::FdLaunchProbeReceipt {
                    receipt_version: 1,
                    event: "capsule_fd_launch_probe".to_string(),
                    body: cocoon_runtime::FdLaunchProbeReceiptBody {
                        capsule_name: "hello-service".to_string(),
                        capsule_version: "0.1.0".to_string(),
                        mode: cocoon_runtime::FdLaunchMode::RedoxEnforcedCapsuleEntrypoint,
                        authority_enforced_for_service: true,
                        production_arbitrary_service: false,
                        child_exit_code: Some(0),
                        structured_child_result: true,
                        open_executable_before_restriction: true,
                        open_declared_preopens_before_restriction: true,
                        entered_restricted_namespace: true,
                        exec_from_fd_attempted: true,
                        exec_from_fd_succeeded: true,
                        allowed_preopen_read: true,
                        allowed_preopen_guest_path: "/app".to_string(),
                        denied_file_path: "/home/cocoon-authority-probe-denied".to_string(),
                        denied_file_rejected: true,
                        hidden_scheme_path: "/scheme/tcp".to_string(),
                        hidden_scheme_rejected: true,
                        failure_message: String::new(),
                        stdout_log: "/pkg/cocoon/logs/capsule-fd-launch/stdout.log".to_string(),
                        stdout_hash: "blake3:stdout".to_string(),
                        stderr_log: "/pkg/cocoon/logs/capsule-fd-launch/stderr.log".to_string(),
                        stderr_hash: "blake3:stderr".to_string(),
                        started_at: "unix:1".to_string(),
                        finished_at: "unix:2".to_string(),
                        runtime_version: "0.1.0".to_string(),
                    },
                    body_hash: "blake3:capsule-fd-launch".to_string(),
                    signature: None,
                },
            });

        assert!(output.contains("Capsule FD-only launch probe for hello-service@0.1.0"));
        assert!(output.contains("Mode: redox-enforced-capsule-entrypoint"));
        assert!(output.contains("Authority enforced for service: true"));
        assert!(output.contains("Production arbitrary service: false"));
        assert!(output.contains("PASS capsule FD launch child returned structured result"));
        assert!(output.contains("PASS open installed capsule entrypoint before restriction"));
        assert!(output.contains("PASS open declared preopens before restriction"));
        assert!(output.contains("PASS enter manifest-derived restricted namespace"));
        assert!(output.contains("PASS fexec installed capsule entrypoint"));
        assert!(output.contains("PASS service reads declared resource"));
        assert!(output.contains("PASS denied ambient path rejected"));
        assert!(output.contains("PASS undeclared tcp scheme rejected"));
    }

    #[test]
    fn formats_latest_logs_output() {
        let output = format_latest_logs(&cocoon_runtime::LatestLogs {
            stdout: Some("hello stdout\n".to_string()),
            stderr: Some("hello stderr\n".to_string()),
        });

        assert!(output.contains("== stdout ==\nhello stdout"));
        assert!(output.contains("== stderr ==\nhello stderr"));
    }

    #[test]
    fn formats_installed_verification_output() {
        let output = format_installed_verification(&cocoon_runtime::InstalledVerification {
            capsule_name: "hello-service".to_string(),
            capsule_version: "0.1.0".to_string(),
            files_checked: 4,
        });

        assert!(output.contains("Installed tree verified for hello-service@0.1.0"));
        assert!(output.contains("Files checked: 4"));
    }

    #[test]
    fn formats_recovery_report_output() {
        let output = format_recovery_report(&cocoon_runtime::RecoveryReport {
            capsule_name: "hello-service".to_string(),
            broke_lock: true,
            removed_paths: vec![
                "/pkg/cocoon/.staging/hello-service-0.1.0-abandoned".to_string(),
                "/pkg/cocoon/capsules/hello-service/current.tmp".to_string(),
            ],
        });

        assert!(output.contains("Recovered hello-service"));
        assert!(output.contains("Broke lock: true"));
        assert!(output.contains("Removed paths: 2"));
        assert!(output.contains("hello-service-0.1.0-abandoned"));
    }

    #[test]
    fn formats_audit_report_output() {
        let output = format_audit_report(&cocoon_runtime::AuditReport {
            capsule_name: "hello-service".to_string(),
            checks: vec![cocoon_runtime::AuditCheck {
                name: "latest install receipt body hash".to_string(),
                detail: "blake3:install".to_string(),
            }],
        });

        assert!(output.contains("Audit passed for hello-service"));
        assert!(output.contains("Checks: 1"));
        assert!(output.contains("latest install receipt body hash: blake3:install"));
    }

    #[test]
    fn formats_rollback_receipt_output() {
        let receipt = cocoon_runtime::RollbackReceipt {
            receipt_version: 1,
            event: "capsule_rollback".to_string(),
            body: cocoon_runtime::RollbackReceiptBody {
                capsule_name: "hello-service".to_string(),
                previous_version: "0.2.0".to_string(),
                target_version: "0.1.0".to_string(),
                rolled_back_at: "unix:3".to_string(),
                runtime_version: "0.1.0".to_string(),
            },
            body_hash: "blake3:rollback".to_string(),
            signature: None,
        };
        let output = format_rollback_receipt(&receipt);

        assert!(output.contains("Rolled back hello-service"));
        assert!(output.contains("Event: capsule_rollback"));
        assert!(output.contains("Previous version: 0.2.0"));
        assert!(output.contains("Target version: 0.1.0"));
    }
}
