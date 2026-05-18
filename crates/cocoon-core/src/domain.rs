use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapsuleName(String);

impl CapsuleName {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_identifier(&raw, "capsule name")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapsuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapsuleName {
    type Err = crate::CocoonError;

    fn from_str(s: &str) -> crate::Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for CapsuleName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapsuleName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapsuleVersion(String);

impl CapsuleVersion {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        semver::Version::parse(&raw).map_err(|err| {
            crate::CocoonError::InvalidManifest(format!(
                "capsule.version must be valid SemVer: {err}"
            ))
        })?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapsuleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CapsuleVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapsuleVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemeName(String);

impl SchemeName {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_identifier(&raw, "scheme name")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SchemeName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestPath(String);

impl GuestPath {
    pub fn app_root() -> Self {
        Self("/app".to_string())
    }

    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_absolute_path(&raw, "guest path")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn contains(&self, other: &GuestPath) -> bool {
        path_contains(self.as_str(), other.as_str())
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for GuestPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GuestPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPath(String);

impl HostPath {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_absolute_path(&raw, "host path")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for HostPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HostPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapsulePath(String);

impl CapsulePath {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_relative_path(&raw, "capsule path")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapsulePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CapsulePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapsulePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermissionTarget(String);

impl PermissionTarget {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_non_empty_text(&raw, "permission target")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type CapabilityTarget = PermissionTarget;

impl fmt::Display for PermissionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for PermissionTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PermissionTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemeTarget(String);

impl SchemeTarget {
    pub fn parse(raw: impl Into<String>) -> crate::Result<Self> {
        let raw = raw.into();
        validate_non_empty_text(&raw, "scheme target")?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SchemeTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemeTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(D::Error::custom)
    }
}

fn validate_identifier(raw: &str, label: &str) -> crate::Result<()> {
    validate_non_empty_text(raw, label)?;
    let mut chars = raw.chars();
    let starts_valid = chars.next().is_some_and(|ch| ch.is_ascii_lowercase());
    let body_valid = raw
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'));

    if starts_valid && body_valid {
        return Ok(());
    }

    Err(crate::CocoonError::InvalidManifest(format!(
        "{label} must use lowercase ASCII letters, digits, '.', '_' or '-' and start with a letter"
    )))
}

fn validate_absolute_path(raw: &str, label: &str) -> crate::Result<()> {
    validate_non_empty_text(raw, label)?;
    if !raw.starts_with('/') {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must be absolute"
        )));
    }
    validate_path_segments(raw, label)
}

fn validate_relative_path(raw: &str, label: &str) -> crate::Result<()> {
    validate_non_empty_text(raw, label)?;
    if raw.starts_with('/') {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must be relative"
        )));
    }
    validate_path_segments(raw, label)
}

fn validate_path_segments(raw: &str, label: &str) -> crate::Result<()> {
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must not contain control characters"
        )));
    }
    if raw.contains("//") || raw.split('/').any(|part| matches!(part, "." | "..")) {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must not contain empty, '.' or '..' segments"
        )));
    }
    Ok(())
}

fn validate_non_empty_text(raw: &str, label: &str) -> crate::Result<()> {
    if raw.trim().is_empty() {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must not be empty"
        )));
    }
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(crate::CocoonError::InvalidManifest(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

fn normalize_path(path: &str) -> String {
    // Remove trailing slashes except for root "/"
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn path_contains(root: &str, path: &str) -> bool {
    let root = normalize_path(root);
    let path = normalize_path(path);
    root == "/"
        || path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_uppercase_capsule_name() {
        assert!(CapsuleName::parse("Hello").is_err());
    }

    #[test]
    fn validates_semver() {
        assert!(CapsuleVersion::parse("1.2.3").is_ok());
        assert!(CapsuleVersion::parse("1").is_err());
    }

    #[test]
    fn checks_guest_path_containment() {
        let root = GuestPath::parse("/app").unwrap();
        let child = GuestPath::parse("/app/bin/service").unwrap();
        let sibling = GuestPath::parse("/application/bin/service").unwrap();

        assert!(root.contains(&child));
        assert!(!root.contains(&sibling));
    }
}
