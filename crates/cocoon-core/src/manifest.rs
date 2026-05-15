use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapsuleManifest {
    pub capsule: CapsuleMeta,
    pub entry: EntryConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
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
pub struct CapsuleMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryConfig {
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
}

fn default_cwd() -> String {
    "/app".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FilesystemConfig {
    #[serde(default = "default_root")]
    pub root: String,
    #[serde(default)]
    pub writable: Vec<String>,
    #[serde(default)]
    pub readonly: Vec<String>,
}

fn default_root() -> String {
    "/app".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CapabilitiesConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    #[serde(default = "default_deny")]
    pub default: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default: default_deny(),
        }
    }
}

fn default_deny() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcesConfig {
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub max_processes: Option<u64>,
    #[serde(default)]
    pub max_open_fds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UpdateConfig {
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub rollback: bool,
    #[serde(default)]
    pub permission_expansion_requires_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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
        if self.capsule.name.is_empty() {
            return Err(crate::CocoonError::InvalidManifest(
                "capsule.name must not be empty".into(),
            ));
        }
        if self.capsule.version.is_empty() {
            return Err(crate::CocoonError::InvalidManifest(
                "capsule.version must not be empty".into(),
            ));
        }
        if self.entry.cmd.is_empty() {
            return Err(crate::CocoonError::InvalidManifest(
                "entry.cmd must not be empty".into(),
            ));
        }
        Ok(())
    }

    pub fn to_toml_pretty(&self) -> crate::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
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
        let m = CapsuleManifest::from_toml(raw).unwrap();
        assert_eq!(m.capsule.name, "hello-service");
        assert_eq!(m.capsule.version, "0.1.0");
        assert_eq!(m.entry.cmd, "/app/bin/hello-service");
        assert_eq!(m.entry.cwd, "/app");
        assert_eq!(m.network.default, "deny");
    }

    #[test]
    fn reject_empty_name() {
        let raw = r#"
[capsule]
name = ""
version = "0.1.0"

[entry]
cmd = "/app/bin/hello-service"
"#;
        assert!(CapsuleManifest::from_toml(raw).is_err());
    }
}
