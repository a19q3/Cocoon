use crate::{PermissionTarget, SchemeName};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct PermissionRule {
    #[serde(default)]
    pub effect: PermissionEffect,
    pub scheme: SchemeName,
    pub action: PermissionAction,
    pub target: PermissionTarget,
}

impl PermissionRule {
    pub fn is_allow(&self) -> bool {
        self.effect == PermissionEffect::Allow
    }

    pub fn normalized_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.effect, self.scheme, self.action, self.target
        )
    }
}

impl fmt::Display for PermissionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.effect, self.scheme, self.action, self.target
        )
    }
}

impl FromStr for PermissionRule {
    type Err = crate::CocoonError;

    fn from_str(raw: &str) -> crate::Result<Self> {
        let Some((scheme, target)) = raw.split_once(':') else {
            return Err(crate::CocoonError::PermissionParse(format!(
                "invalid legacy permission syntax: {raw}"
            )));
        };
        let scheme = SchemeName::parse(scheme)?;
        let action = default_action_for_scheme(scheme.as_str());

        Ok(Self {
            effect: PermissionEffect::Allow,
            scheme,
            action,
            target: PermissionTarget::parse(target)?,
        })
    }
}

pub type CapabilityRule = PermissionRule;
pub type Capability = PermissionRule;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum PermissionEffect {
    #[default]
    Allow,
    Deny,
}

pub type CapabilityEffect = PermissionEffect;

impl fmt::Display for PermissionEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermissionAction {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "readwrite", alias = "read-write")]
    ReadWrite,
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "connect")]
    Connect,
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "use")]
    Use,
    #[serde(rename = "manage")]
    Manage,
}

pub type CapabilityAction = PermissionAction;

impl fmt::Display for PermissionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::ReadWrite => f.write_str("readwrite"),
            Self::Execute => f.write_str("execute"),
            Self::Connect => f.write_str("connect"),
            Self::Open => f.write_str("open"),
            Self::Use => f.write_str("use"),
            Self::Manage => f.write_str("manage"),
        }
    }
}

fn default_action_for_scheme(scheme: &str) -> PermissionAction {
    match scheme {
        "tcp" | "udp" | "network" => PermissionAction::Connect,
        "file" => PermissionAction::ReadWrite,
        "device" | "sys" | "kernel" | "sudo" => PermissionAction::Manage,
        "log" => PermissionAction::Write,
        _ => PermissionAction::Use,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_permission_for_compatibility() {
        let permission: PermissionRule = "tcp:/connect/*".parse().unwrap();

        assert_eq!(permission.scheme.as_str(), "tcp");
        assert_eq!(permission.target.as_str(), "/connect/*");
        assert_eq!(permission.action, PermissionAction::Connect);
    }

    #[test]
    fn normalizes_typed_permission() {
        let permission = PermissionRule {
            effect: PermissionEffect::Allow,
            scheme: SchemeName::parse("file").unwrap(),
            action: PermissionAction::Read,
            target: PermissionTarget::parse("/app/etc").unwrap(),
        };

        assert_eq!(permission.normalized_key(), "allow:file:read:/app/etc");
    }
}
