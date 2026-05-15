use crate::{
    CapsuleName, CapsuleVersion, GuestPath, HostPath, PermissionRule, SchemeName, SchemeTarget,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleManifest {
    pub capsule: CapsuleMeta,
    pub entry: EntryConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default, rename = "permission", alias = "capability")]
    pub permissions: Vec<PermissionRule>,
    #[serde(default, rename = "preopen")]
    pub preopens: Vec<PreopenConfig>,
    #[serde(default, rename = "scheme")]
    pub schemes: Vec<SchemeConfig>,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub resources: ResourcesConfig,
    #[serde(default)]
    pub update: UpdateConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleMeta {
    pub name: CapsuleName,
    pub version: CapsuleVersion,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryConfig {
    pub cmd: GuestPath,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: GuestPath,
}

fn default_cwd() -> GuestPath {
    GuestPath::parse("/app").expect("literal '/app' is a valid absolute guest path")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    #[serde(default = "default_root")]
    pub root: GuestPath,
    #[serde(default)]
    pub writable: Vec<GuestPath>,
    #[serde(default)]
    pub readonly: Vec<GuestPath>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            root: default_root(),
            writable: Vec::new(),
            readonly: Vec::new(),
        }
    }
}

fn default_root() -> GuestPath {
    GuestPath::parse("/app").expect("literal '/app' is a valid absolute guest path")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct PreopenConfig {
    pub scheme: SchemeName,
    #[serde(default)]
    pub host_path: Option<HostPath>,
    pub guest_path: GuestPath,
    #[serde(default)]
    pub rights: Vec<PreopenRight>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PreopenRight {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct SchemeConfig {
    pub name: SchemeName,
    pub visibility: SchemeVisibility,
    #[serde(default)]
    pub target: Option<SchemeTarget>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SchemeVisibility {
    Hidden,
    Readonly,
    Readwrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub default: NetworkDefault,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default: NetworkDefault::Deny,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDefault {
    #[default]
    Deny,
    Allow,
}

impl std::fmt::Display for NetworkDefault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deny => f.write_str("deny"),
            Self::Allow => f.write_str("allow"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourcesConfig {
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub max_processes: Option<u64>,
    #[serde(default)]
    pub max_open_fds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    #[serde(default = "default_true")]
    pub signed: bool,
    #[serde(default = "default_true")]
    pub rollback: bool,
    #[serde(default = "default_true")]
    pub permission_expansion_requires_confirmation: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            signed: true,
            rollback: true,
            permission_expansion_requires_confirmation: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default)]
    pub events: bool,
    #[serde(default)]
    pub stdout: bool,
    #[serde(default)]
    pub stderr: bool,
}

impl CapsuleManifest {
    pub fn from_toml(s: &str) -> crate::Result<Self> {
        let manifest: Self = toml::from_str(s)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> crate::Result<()> {
        self.validate_entry_paths()?;
        self.validate_filesystem_paths()?;
        self.validate_permissions()?;
        self.validate_preopens()?;
        self.validate_schemes()?;
        self.validate_resources()
    }

    pub fn to_toml_pretty(&self) -> crate::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn allowed_permissions(&self) -> impl Iterator<Item = &PermissionRule> {
        self.permissions
            .iter()
            .filter(|permission| permission.is_allow())
    }

    pub fn normalized_permission_keys(&self) -> Vec<String> {
        let mut keys = self
            .allowed_permissions()
            .map(PermissionRule::normalized_key)
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    pub fn allowed_capabilities(&self) -> impl Iterator<Item = &PermissionRule> {
        self.allowed_permissions()
    }

    pub fn normalized_capability_keys(&self) -> Vec<String> {
        self.normalized_permission_keys()
    }

    fn validate_entry_paths(&self) -> crate::Result<()> {
        let root = &self.filesystem.root;
        if !root.contains(&self.entry.cmd) {
            return Err(crate::CocoonError::InvalidManifest(format!(
                "entry.cmd '{}' must be inside filesystem.root '{}'",
                self.entry.cmd, root
            )));
        }
        if !root.contains(&self.entry.cwd) {
            return Err(crate::CocoonError::InvalidManifest(format!(
                "entry.cwd '{}' must be inside filesystem.root '{}'",
                self.entry.cwd, root
            )));
        }
        Ok(())
    }

    fn validate_filesystem_paths(&self) -> crate::Result<()> {
        let root = &self.filesystem.root;
        let mut seen = BTreeSet::new();

        for path in self
            .filesystem
            .readonly
            .iter()
            .chain(self.filesystem.writable.iter())
        {
            if !root.contains(path) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "filesystem path '{path}' must be inside filesystem.root '{root}'"
                )));
            }
            if !seen.insert(path.as_str()) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "filesystem path '{path}' is declared more than once"
                )));
            }
        }

        for writable in &self.filesystem.writable {
            if self
                .filesystem
                .readonly
                .iter()
                .any(|readonly| paths_overlap(readonly, writable))
            {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "writable path '{writable}' overlaps a readonly path"
                )));
            }
        }

        Ok(())
    }

    fn validate_permissions(&self) -> crate::Result<()> {
        let mut seen = BTreeSet::new();
        for permission in &self.permissions {
            if !seen.insert(permission.normalized_key()) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "duplicate permission rule '{permission}'"
                )));
            }
        }
        Ok(())
    }

    fn validate_preopens(&self) -> crate::Result<()> {
        let mut seen = BTreeSet::new();
        for preopen in &self.preopens {
            if !self.filesystem.root.contains(&preopen.guest_path) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "preopen guest_path '{}' must be inside filesystem.root '{}'",
                    preopen.guest_path, self.filesystem.root
                )));
            }
            if preopen.rights.is_empty() {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "preopen '{}' must declare at least one right",
                    preopen.guest_path
                )));
            }
            if preopen.scheme.as_str() == "file" && preopen.host_path.is_none() {
                return Err(crate::CocoonError::InvalidManifest(
                    "file preopen must declare host_path".into(),
                ));
            }
            let key = format!("{}:{}", preopen.scheme, preopen.guest_path);
            if !seen.insert(key) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "duplicate preopen '{}:{}'",
                    preopen.scheme, preopen.guest_path
                )));
            }
        }
        Ok(())
    }

    fn validate_schemes(&self) -> crate::Result<()> {
        let mut names = BTreeSet::new();
        for scheme in &self.schemes {
            if !names.insert(scheme.name.as_str()) {
                return Err(crate::CocoonError::InvalidManifest(format!(
                    "duplicate scheme '{}'",
                    scheme.name
                )));
            }
        }
        Ok(())
    }

    fn validate_resources(&self) -> crate::Result<()> {
        validate_positive(self.resources.memory_mb, "resources.memory_mb")?;
        validate_positive(self.resources.max_processes, "resources.max_processes")?;
        validate_positive(self.resources.max_open_fds, "resources.max_open_fds")
    }
}

fn validate_positive(value: Option<u64>, field: &str) -> crate::Result<()> {
    if value.is_some_and(|value| value == 0) {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn paths_overlap(a: &GuestPath, b: &GuestPath) -> bool {
    a.contains(b) || b.contains(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"
"#;
        let manifest = CapsuleManifest::from_toml(raw).unwrap();

        assert_eq!(manifest.capsule.name.as_str(), "hello-service");
        assert_eq!(manifest.capsule.version.as_str(), "0.1.0");
        assert_eq!(manifest.entry.cmd.as_str(), "/app/bin/hello-service");
        assert_eq!(manifest.entry.cwd.as_str(), "/app");
        assert_eq!(manifest.network.default, NetworkDefault::Deny);
    }

    #[test]
    fn rejects_invalid_semver() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "1"

[entry]
cmd = "/app/bin/hello-service"
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn rejects_entry_outside_root() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/bin/hello-service"
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn rejects_readonly_writable_overlap() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[filesystem]
readonly = ["/app/etc"]
writable = ["/app/etc/cache"]
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn parses_typed_permissions() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[[permission]]
scheme = "tcp"
action = "connect"
target = "api.example.com:443"
"#;
        let manifest = CapsuleManifest::from_toml(raw).unwrap();

        assert_eq!(manifest.permissions.len(), 1);
        assert_eq!(
            manifest.normalized_permission_keys(),
            vec!["allow:tcp:connect:api.example.com:443"]
        );
    }

    #[test]
    fn accepts_legacy_capability_table_alias() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[[capability]]
scheme = "tcp"
action = "connect"
target = "api.example.com:443"
"#;
        let manifest = CapsuleManifest::from_toml(raw).unwrap();

        assert_eq!(manifest.permissions.len(), 1);
        assert_eq!(
            manifest.normalized_permission_keys(),
            vec!["allow:tcp:connect:api.example.com:443"]
        );
    }

    #[test]
    fn rejects_file_preopen_without_host_path() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[[preopen]]
scheme = "file"
guest_path = "/app"
rights = ["read"]
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn rejects_duplicate_scheme() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[[scheme]]
name = "log"
visibility = "readwrite"

[[scheme]]
name = "log"
visibility = "readonly"
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"
container = "false"

[entry]
cmd = "/app/bin/hello-service"
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }

    #[test]
    fn keeps_deny_rules_out_of_permission_expansion_keys() {
        let raw = r#"
[capsule]
name = "hello-service"
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"

[[permission]]
effect = "deny"
scheme = "tcp"
action = "connect"
target = "*"
"#;
        let manifest = CapsuleManifest::from_toml(raw).unwrap();

        assert!(manifest.normalized_permission_keys().is_empty());
    }
}
