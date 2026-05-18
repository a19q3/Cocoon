use crate::capability::{PermissionAction, PermissionRule};
use crate::manifest::{
    CapsuleManifest, NetworkDefault, PreopenConfig, PreopenRight, SchemeConfig, SchemeVisibility,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDiff {
    pub added: Vec<PermissionRule>,
    pub removed: Vec<PermissionRule>,
    pub modified: Vec<(PermissionRule, PermissionRule)>,
}

impl PermissionDiff {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDiff<T> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub modified: Vec<(T, T)>,
}

impl<T> RuleDiff<T> {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDiff {
    pub permissions: PermissionDiff,
    pub schemes: RuleDiff<SchemeConfig>,
    pub preopens: RuleDiff<PreopenConfig>,
    pub network_default: Option<(NetworkDefault, NetworkDefault)>,
}

impl AuthorityDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
            && self.schemes.is_empty()
            && self.preopens.is_empty()
            && self.network_default.is_none()
    }
}

pub fn diff_permissions(
    old: &CapsuleManifest,
    new: &CapsuleManifest,
) -> PermissionDiff {
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

    PermissionDiff {
        added,
        removed,
        modified,
    }
}

pub fn diff_capabilities(
    old: &CapsuleManifest,
    new: &CapsuleManifest,
) -> PermissionDiff {
    diff_permissions(old, new)
}

pub fn diff_authority(
    old: &CapsuleManifest,
    new: &CapsuleManifest,
) -> AuthorityDiff {
    AuthorityDiff {
        permissions: diff_permissions(old, new),
        schemes: diff_rules(&old.schemes, &new.schemes, same_scheme_identity),
        preopens: diff_rules(&old.preopens, &new.preopens, same_preopen_identity),
        network_default: (old.network.default != new.network.default)
            .then_some((old.network.default, new.network.default)),
    }
}

fn diff_rules<T>(old_rules: &[T], new_rules: &[T], same_identity: fn(&T, &T) -> bool) -> RuleDiff<T>
where
    T: Clone + Ord,
{
    let mut old = old_rules.to_vec();
    let mut new = new_rules.to_vec();
    old.sort();
    new.sort();

    let mut added = Vec::new();
    let mut modified = Vec::new();
    for new_rule in &new {
        if old.contains(new_rule) {
            continue;
        }

        if let Some(old_rule) = old
            .iter()
            .find(|old_rule| same_identity(old_rule, new_rule))
        {
            modified.push((old_rule.clone(), new_rule.clone()));
        } else {
            added.push(new_rule.clone());
        }
    }

    let mut removed = Vec::new();
    for old_rule in &old {
        if !new.contains(old_rule) && !modified.iter().any(|(old, _)| old == old_rule) {
            removed.push(old_rule.clone());
        }
    }

    RuleDiff {
        added,
        removed,
        modified,
    }
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

fn same_scheme_identity(old: &SchemeConfig, new: &SchemeConfig) -> bool {
    old.name == new.name
}

fn same_preopen_identity(old: &PreopenConfig, new: &PreopenConfig) -> bool {
    old.scheme == new.scheme && old.guest_path == new.guest_path
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

pub fn severity_for_scheme(scheme: &SchemeConfig) -> Severity {
    match scheme.name.as_str() {
        "device" | "kernel" | "sudo" | "sys" => Severity::Critical,
        "tcp" | "udp" | "network" => Severity::High,
        "proc" | "memory" => Severity::High,
        _ if scheme.visibility == SchemeVisibility::Readwrite => Severity::High,
        _ if scheme.visibility == SchemeVisibility::Readonly => Severity::Medium,
        _ => Severity::Low,
    }
}

pub fn severity_for_preopen(preopen: &PreopenConfig) -> Severity {
    match preopen.scheme.as_str() {
        "device" | "kernel" | "sudo" | "sys" => Severity::Critical,
        "tcp" | "udp" | "network" => Severity::High,
        "file"
            if preopen
                .host_path
                .as_ref()
                .is_some_and(|path| sensitive_path(path.as_str()))
                || sensitive_path(preopen.guest_path.as_str()) =>
        {
            Severity::High
        }
        "file" if preopen.rights.contains(&PreopenRight::Write) => Severity::High,
        "file" => Severity::Medium,
        _ => Severity::Low,
    }
}

pub fn severity_for_network_default(default: NetworkDefault) -> Severity {
    match default {
        NetworkDefault::Allow => Severity::High,
        NetworkDefault::Deny => Severity::Low,
    }
}

pub fn permission_action_expanded(old: PermissionAction, new: PermissionAction) -> bool {
    action_rank(new) > action_rank(old)
}

pub fn scheme_visibility_expanded(old: SchemeVisibility, new: SchemeVisibility) -> bool {
    visibility_rank(new) > visibility_rank(old)
}

pub fn preopen_rights_expanded(old: &[PreopenRight], new: &[PreopenRight]) -> bool {
    new.iter().any(|right| !old.contains(right))
}

pub fn network_default_expanded(old: NetworkDefault, new: NetworkDefault) -> bool {
    old == NetworkDefault::Deny && new == NetworkDefault::Allow
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

fn visibility_rank(visibility: SchemeVisibility) -> u8 {
    match visibility {
        SchemeVisibility::Hidden => 0,
        SchemeVisibility::Readonly => 1,
        SchemeVisibility::Readwrite => 2,
    }
}

fn sensitive_path(path: &str) -> bool {
    path.starts_with("/etc/secrets/")
        || path == "/etc/secrets"
        || path.starts_with("/home/")
        || path == "/home"
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
        let diff = diff_permissions(&manifest, &manifest);

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
        let diff = diff_permissions(&old, &new);

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
        let diff = diff_permissions(&old, &new);

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

    #[test]
    fn authority_diff_tracks_scheme_visibility() {
        let old = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "1.0.0"

[entry]
cmd = "/app/bin/a"

[[scheme]]
name = "log"
visibility = "readonly"
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

[[scheme]]
name = "log"
visibility = "readwrite"
"#,
        )
        .unwrap();

        let diff = diff_authority(&old, &new);

        assert!(diff.permissions.is_empty());
        assert_eq!(diff.schemes.modified.len(), 1);
        assert!(scheme_visibility_expanded(
            diff.schemes.modified[0].0.visibility,
            diff.schemes.modified[0].1.visibility
        ));
    }

    #[test]
    fn authority_diff_tracks_network_default() {
        let old = CapsuleManifest::from_toml(
            r#"
[capsule]
name = "a"
version = "1.0.0"

[entry]
cmd = "/app/bin/a"

[network]
default = "deny"
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

[network]
default = "allow"
"#,
        )
        .unwrap();

        let diff = diff_authority(&old, &new);

        assert_eq!(
            diff.network_default,
            Some((crate::NetworkDefault::Deny, crate::NetworkDefault::Allow))
        );
        assert!(network_default_expanded(
            crate::NetworkDefault::Deny,
            crate::NetworkDefault::Allow
        ));
    }
}
