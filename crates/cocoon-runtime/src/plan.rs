use std::fmt;
use std::path::{Path, PathBuf};

use cocoon_bundle::{BundleReader, VerifiedBundle};
use cocoon_core::{
    AuditConfig, CapsuleName, CapsuleVersion, GuestPath, HostPath, PermissionRule, PreopenRight,
    SchemeName, SchemeTarget, SchemeVisibility, hash_permissions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRoot(PathBuf);

impl InstallRoot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn parse(path: impl Into<PathBuf>) -> cocoon_core::Result<Self> {
        let path = path.into();
        validate_install_root(&path)?;
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for InstallRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    pub capsule_name: CapsuleName,
    pub version: CapsuleVersion,
    pub install_root: InstallRoot,
    pub entry: EntryPlan,
    pub schemes: Vec<SchemePlan>,
    pub preopens: Vec<PreopenPlan>,
    pub permissions: Vec<PermissionRule>,
    pub stdio: StdioPlan,
    pub receipt_input: ReceiptInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPlan {
    pub cmd: GuestPath,
    pub args: Vec<String>,
    pub cwd: GuestPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemePlan {
    pub name: SchemeName,
    pub visibility: SchemeVisibility,
    pub target: Option<SchemeTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreopenPlan {
    pub scheme: SchemeName,
    pub host_path: Option<HostPath>,
    pub guest_path: GuestPath,
    pub rights: Vec<PreopenRight>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioPlan {
    pub capture_stdout: bool,
    pub capture_stderr: bool,
    pub audit_events: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInput {
    pub manifest_hash: String,
    pub permission_hash: String,
    pub runtime_version: String,
}

impl RuntimePlan {
    pub fn from_verified_bundle(bundle: &VerifiedBundle, install_root: InstallRoot) -> Self {
        Self::from_bundle(bundle.reader(), install_root)
    }

    fn from_bundle(reader: &BundleReader, install_root: InstallRoot) -> Self {
        let manifest = &reader.manifest;

        Self {
            capsule_name: manifest.capsule.name.clone(),
            version: manifest.capsule.version.clone(),
            install_root,
            entry: EntryPlan {
                cmd: manifest.entry.cmd.clone(),
                args: manifest.entry.args.clone(),
                cwd: manifest.entry.cwd.clone(),
            },
            schemes: manifest
                .schemes
                .iter()
                .map(|scheme| SchemePlan {
                    name: scheme.name.clone(),
                    visibility: scheme.visibility,
                    target: scheme.target.clone(),
                })
                .collect(),
            preopens: manifest
                .preopens
                .iter()
                .map(|preopen| PreopenPlan {
                    scheme: preopen.scheme.clone(),
                    host_path: preopen.host_path.clone(),
                    guest_path: preopen.guest_path.clone(),
                    rights: preopen.rights.clone(),
                })
                .collect(),
            permissions: manifest.permissions.clone(),
            stdio: StdioPlan::from_audit(&manifest.audit),
            receipt_input: ReceiptInput {
                manifest_hash: reader.hash_manifest.manifest_hash.clone(),
                permission_hash: hash_permissions(manifest),
                runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        }
    }
}

fn validate_install_root(path: &Path) -> cocoon_core::Result<()> {
    let raw = path.to_string_lossy();
    if !path.is_absolute() {
        return Err(cocoon_core::CocoonError::InvalidManifest(format!(
            "install root '{raw}' must be absolute"
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(cocoon_core::CocoonError::InvalidManifest(format!(
            "install root '{raw}' must not contain '..'"
        )));
    }

    Ok(())
}

impl StdioPlan {
    fn from_audit(audit: &AuditConfig) -> Self {
        Self {
            capture_stdout: audit.stdout,
            capture_stderr: audit.stderr,
            audit_events: audit.events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_plan_from_hello_manifest() {
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

        let plan = RuntimePlan::from_verified_bundle(&verified, InstallRoot::new("/pkg/cocoon"));

        assert_eq!(plan.capsule_name.as_str(), "hello-service");
        assert_eq!(plan.version.as_str(), "0.1.0");
        assert_eq!(plan.entry.cmd.as_str(), "/app/bin/hello-service");
        assert_eq!(plan.schemes.len(), 1);
        assert_eq!(plan.preopens.len(), 1);
        assert_eq!(plan.permissions.len(), 8);
        assert!(plan.stdio.capture_stdout);
        assert!(plan.receipt_input.permission_hash.starts_with("blake3:"));
    }
}
