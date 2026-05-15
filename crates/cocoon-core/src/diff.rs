use crate::capability::{PermissionAction, PermissionRule};
use crate::manifest::CapsuleManifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDiff {
    pub added: Vec<PermissionRule>,
    pub removed: Vec<PermissionRule>,
    pub modified: Vec<(PermissionRule, PermissionRule)>,
}

impl PermissionDiff {
    pub fn empty() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

pub fn diff_permissions(
    old: &CapsuleManifest,
    new: &CapsuleManifest,
) -> crate::Result<PermissionDiff> {
    let old_permissions = sorted_allowed_permissions(old);
    let new_permissions = sorted_allowed_permissions(new);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    for new_permission in &new_permissions {
        if old_permissions.contains(new_permission) {
            continue;
        }

        if let Some(old_permission) = old_permissions
            .iter()
            .find(|old_permission| same_target(old_permission, new_permission))
        {
            modified.push((old_permission.clone(), new_permission.clone()));
        } else {
            added.push(new_permission.clone());
        }
    }

    for old_permission in &old_permissions {
        if !new_permissions.contains(old_permission)
            && !modified.iter().any(|(old, _)| old == old_permission)
        {
            removed.push(old_permission.clone());
        }
    }

    Ok(PermissionDiff {
        added,
        removed,
        modified,
    })
}

pub fn diff_capabilities(
    old: &CapsuleManifest,
    new: &CapsuleManifest,
) -> crate::Result<PermissionDiff> {
    diff_permissions(old, new)
}

fn sorted_allowed_permissions(manifest: &CapsuleManifest) -> Vec<PermissionRule> {
    let mut permissions = manifest
        .allowed_permissions()
        .cloned()
        .collect::<Vec<PermissionRule>>();
    permissions.sort();
    permissions
}

fn same_target(old: &PermissionRule, new: &PermissionRule) -> bool {
    old.scheme == new.scheme && old.target == new.target
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn severity_of_diff(diff: &PermissionDiff) -> Vec<(Severity, String)> {
    let mut out = Vec::new();

    for permission in &diff.added {
        let severity = severity_for_permission(permission);
        out.push((severity, format!("new permission: {permission}")));
    }

    for (old, new) in &diff.modified {
        let severity = if action_expanded(old.action, new.action) {
            severity_for_permission(new)
        } else {
            Severity::Low
        };
        out.push((severity, format!("modified permission: {old} -> {new}")));
    }

    out.sort_by(|a, b| b.0.cmp(&a.0));
    out
}

pub fn severity_for_permission(permission: &PermissionRule) -> Severity {
    match permission.scheme.as_str() {
        "device" | "kernel" | "sudo" | "sys" => Severity::Critical,
        "tcp" | "udp" | "network" => Severity::High,
        "proc" | "memory" => Severity::High,
        "file"
            if permission.target.as_str().contains("/etc/secrets")
                || permission.target.as_str().contains("/home") =>
        {
            Severity::High
        }
        "file" => Severity::Medium,
        _ => Severity::Low,
    }
}

pub fn permission_action_expanded(old: PermissionAction, new: PermissionAction) -> bool {
    action_rank(new) > action_rank(old)
}

fn action_expanded(old: PermissionAction, new: PermissionAction) -> bool {
    permission_action_expanded(old, new)
}

fn action_rank(action: PermissionAction) -> u8 {
    match action {
        PermissionAction::Read => 1,
        PermissionAction::Write => 2,
        PermissionAction::Execute => 2,
        PermissionAction::Connect => 3,
        PermissionAction::Open => 3,
        PermissionAction::Use => 3,
        PermissionAction::ReadWrite => 4,
        PermissionAction::Manage => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_empty() {
        let manifest = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "1.0.0"

[entry]
cmd = "/app/bin/a"
"#,
        )
        .unwrap();
        let diff = diff_permissions(&manifest, &manifest).unwrap();

        assert!(diff.is_empty());
    }

    #[test]
    fn diff_adds_permission() {
        let old = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "1.0.0"

[entry]
cmd = "/app/bin/a"

[[permission]]
scheme = "file"
action = "read"
target = "/app/**"
"#,
        )
        .unwrap();
        let new = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "2.0.0"

[entry]
cmd = "/app/bin/a"

[[permission]]
scheme = "file"
action = "read"
target = "/app/**"

[[permission]]
scheme = "tcp"
action = "connect"
target = "api.example.com:443"
"#,
        )
        .unwrap();
        let diff = diff_permissions(&old, &new).unwrap();

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].scheme.as_str(), "tcp");
    }

    #[test]
    fn deny_rules_do_not_create_permission_expansion() {
        let old = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "1.0.0"

[entry]
cmd = "/app/bin/a"
"#,
        )
        .unwrap();
        let new = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "2.0.0"

[entry]
cmd = "/app/bin/a"

[[permission]]
effect = "deny"
scheme = "tcp"
action = "connect"
target = "*"
"#,
        )
        .unwrap();
        let diff = diff_permissions(&old, &new).unwrap();

        assert!(diff.is_empty());
    }

    #[test]
    fn critical_for_device_permission() {
        let diff = PermissionDiff {
            added: vec![PermissionRule {
                effect: crate::PermissionEffect::Allow,
                scheme: crate::SchemeName::parse("device").unwrap(),
                action: PermissionAction::Manage,
                target: crate::PermissionTarget::parse("/").unwrap(),
            }],
            removed: Vec::new(),
            modified: Vec::new(),
        };

        assert_eq!(severity_of_diff(&diff)[0].0, Severity::Critical);
    }
}
