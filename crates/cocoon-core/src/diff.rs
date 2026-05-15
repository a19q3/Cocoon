use crate::capability::{AccessMode, Capability};
use crate::manifest::CapsuleManifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDiff {
    pub added: Vec<Capability>,
    pub removed: Vec<Capability>,
    pub modified: Vec<(Capability, Capability)>,
}

impl PermissionDiff {
    pub fn empty() -> Self {
        Self {
            added: vec![],
            removed: vec![],
            modified: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

pub fn diff_capabilities(old: &CapsuleManifest, new: &CapsuleManifest) -> crate::Result<PermissionDiff> {
    let old_caps: Vec<Capability> = old
        .capabilities
        .allow
        .iter()
        .map(|s| s.parse())
        .collect::<crate::Result<Vec<_>>>()?;
    let new_caps: Vec<Capability> = new
        .capabilities
        .allow
        .iter()
        .map(|s| s.parse())
        .collect::<crate::Result<Vec<_>>>()?;

    let mut added = vec![];
    let mut removed = vec![];
    let mut modified = vec![];

    for c in &new_caps {
        if !old_caps.contains(c) {
            // Check if same scheme+resource but different access
            if let Some(o) = old_caps.iter().find(|o| o.scheme == c.scheme && o.resource == c.resource) {
                modified.push((o.clone(), c.clone()));
            } else {
                added.push(c.clone());
            }
        }
    }

    for c in &old_caps {
        if !new_caps.contains(c) {
            if !modified.iter().any(|(o, _)| o == c) {
                removed.push(c.clone());
            }
        }
    }

    Ok(PermissionDiff {
        added,
        removed,
        modified,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn severity_of_diff(diff: &PermissionDiff) -> Vec<(Severity, String)> {
    let mut out = vec![];
    for c in &diff.added {
        let sev = capability_severity(c);
        let msg = format!("new capability: {}", c);
        out.push((sev, msg));
    }
    for (old, new) in &diff.modified {
        let sev = if access_expanded(&old.access, &new.access) {
            capability_severity(new)
        } else {
            Severity::Low
        };
        let msg = format!("modified capability: {} -> {}", old, new);
        out.push((sev, msg));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out
}

fn capability_severity(c: &Capability) -> Severity {
    match c.scheme.as_str() {
        "tcp" | "udp" | "network" => Severity::High,
        "device" => Severity::Critical,
        "file" if c.resource.contains("/etc/secrets") || c.resource.contains("/home") => {
            Severity::High
        }
        "file" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn access_expanded(old: &AccessMode, new: &AccessMode) -> bool {
    match (old, new) {
        (AccessMode::ReadOnly, AccessMode::ReadWrite) => true,
        (AccessMode::ReadOnly, AccessMode::Any) => true,
        (AccessMode::ReadWrite, AccessMode::Any) => true,
        (AccessMode::Any, AccessMode::Any) => false,
        (a, b) if a == b => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_empty() {
        let m = CapsuleManifest::from_toml(r#"
[capsule]
name = "a"
version = "1"
[entry]
cmd = "/bin/a"
"#).unwrap();
        let d = diff_capabilities(&m, &m).unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn diff_adds_capability() {
        let old = CapsuleManifest::from_toml(r#"
[capsule]
name = "a"
version = "1"
[entry]
cmd = "/bin/a"
[capabilities]
allow = ["file:/app/**"]
"#).unwrap();
        let new = CapsuleManifest::from_toml(r#"
[capsule]
name = "a"
version = "2"
[entry]
cmd = "/bin/a"
[capabilities]
allow = ["file:/app/**", "tcp:/connect/*"]
"#).unwrap();
        let d = diff_capabilities(&old, &new).unwrap();
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].scheme, "tcp");
    }
}
