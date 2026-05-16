#![forbid(unsafe_code)]

use cocoon_core::{
    AuthorityDiff, NetworkDefault, PermissionDiff, PermissionRule, PreopenConfig, PreopenRight,
    SchemeConfig, SchemeVisibility, Severity,
};

#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    pub permission_expansion_requires_confirmation: bool,
    pub confirmation_threshold: Severity,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            permission_expansion_requires_confirmation: true,
            confirmation_threshold: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDiffReport {
    pub added: Vec<PermissionChange>,
    pub removed: Vec<PermissionChange>,
    pub modified: Vec<PermissionChange>,
    pub confirmation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDiffReport {
    pub permissions: PermissionDiffReport,
    pub schemes: Vec<AuthorityChange>,
    pub preopens: Vec<AuthorityChange>,
    pub network_default: Vec<AuthorityChange>,
    pub confirmation_required: bool,
}

impl AuthorityDiffReport {
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
            && self.schemes.is_empty()
            && self.preopens.is_empty()
            && self.network_default.is_empty()
    }
}

impl PermissionDiffReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionChange {
    pub severity: Severity,
    pub kind: PermissionChangeKind,
    pub before: Option<PermissionRule>,
    pub after: Option<PermissionRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityChange {
    pub severity: Severity,
    pub kind: PermissionChangeKind,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// Check whether a permission diff requires confirmation under policy.
pub fn requires_confirmation(diff: &PermissionDiff, policy: &UpdatePolicy) -> bool {
    build_diff_report(diff, policy).confirmation_required
}

pub fn build_diff_report(diff: &PermissionDiff, policy: &UpdatePolicy) -> PermissionDiffReport {
    let added = diff
        .added
        .iter()
        .map(|permission| PermissionChange {
            severity: cocoon_core::severity_for_permission(permission),
            kind: PermissionChangeKind::Added,
            before: None,
            after: Some(permission.clone()),
        })
        .collect::<Vec<_>>();

    let modified = diff
        .modified
        .iter()
        .map(|(before, after)| {
            let severity = if cocoon_core::permission_action_expanded(before.action, after.action) {
                cocoon_core::severity_for_permission(after)
            } else {
                Severity::Low
            };
            PermissionChange {
                severity,
                kind: PermissionChangeKind::Modified,
                before: Some(before.clone()),
                after: Some(after.clone()),
            }
        })
        .collect::<Vec<_>>();

    let removed = diff
        .removed
        .iter()
        .map(|permission| PermissionChange {
            severity: Severity::Low,
            kind: PermissionChangeKind::Removed,
            before: Some(permission.clone()),
            after: None,
        })
        .collect::<Vec<_>>();

    let confirmation_required = policy.permission_expansion_requires_confirmation
        && added
            .iter()
            .chain(modified.iter())
            .any(|change| change.severity >= policy.confirmation_threshold);

    PermissionDiffReport {
        added: sorted_changes(added),
        removed: sorted_changes(removed),
        modified: sorted_changes(modified),
        confirmation_required,
    }
}

pub fn build_authority_diff_report(
    diff: &AuthorityDiff,
    policy: &UpdatePolicy,
) -> AuthorityDiffReport {
    let permissions = build_diff_report(&diff.permissions, policy);
    let schemes = scheme_changes(diff);
    let preopens = preopen_changes(diff);
    let network_default = network_default_changes(diff);

    let authority_requires_confirmation = policy.permission_expansion_requires_confirmation
        && schemes
            .iter()
            .chain(preopens.iter())
            .chain(network_default.iter())
            .any(|change| {
                !matches!(change.kind, PermissionChangeKind::Removed)
                    && change.severity >= policy.confirmation_threshold
            });

    let confirmation_required =
        permissions.confirmation_required || authority_requires_confirmation;

    AuthorityDiffReport {
        permissions,
        schemes: sorted_authority_changes(schemes),
        preopens: sorted_authority_changes(preopens),
        network_default: sorted_authority_changes(network_default),
        confirmation_required,
    }
}

/// Format a diff as a human-readable report.
pub fn format_diff_report(diff: &PermissionDiff) -> String {
    format_report(&build_diff_report(diff, &UpdatePolicy::default()))
}

pub fn format_authority_diff_report(diff: &AuthorityDiff) -> String {
    format_authority_report(&build_authority_diff_report(diff, &UpdatePolicy::default()))
}

pub fn format_report(report: &PermissionDiffReport) -> String {
    if report.is_empty() {
        return "No permission changes detected.".to_string();
    }

    let mut lines = vec!["Permission changes detected:".to_string()];
    append_section(&mut lines, "Added permissions:", &report.added);
    append_section(&mut lines, "Modified permissions:", &report.modified);
    append_section(&mut lines, "Removed permissions:", &report.removed);
    lines.push(String::new());
    lines.push(format!(
        "Confirmation required: {}",
        if report.confirmation_required {
            "yes"
        } else {
            "no"
        }
    ));
    lines.join("\n")
}

pub fn format_authority_report(report: &AuthorityDiffReport) -> String {
    if report.is_empty() {
        return "No authority changes detected.".to_string();
    }

    let mut lines = vec!["Authority changes detected:".to_string()];
    append_section(&mut lines, "Added permissions:", &report.permissions.added);
    append_section(
        &mut lines,
        "Modified permissions:",
        &report.permissions.modified,
    );
    append_section(
        &mut lines,
        "Removed permissions:",
        &report.permissions.removed,
    );
    append_authority_section(
        &mut lines,
        "Added schemes:",
        &report.schemes,
        PermissionChangeKind::Added,
    );
    append_authority_section(
        &mut lines,
        "Modified schemes:",
        &report.schemes,
        PermissionChangeKind::Modified,
    );
    append_authority_section(
        &mut lines,
        "Removed schemes:",
        &report.schemes,
        PermissionChangeKind::Removed,
    );
    append_authority_section(
        &mut lines,
        "Added preopens:",
        &report.preopens,
        PermissionChangeKind::Added,
    );
    append_authority_section(
        &mut lines,
        "Modified preopens:",
        &report.preopens,
        PermissionChangeKind::Modified,
    );
    append_authority_section(
        &mut lines,
        "Removed preopens:",
        &report.preopens,
        PermissionChangeKind::Removed,
    );
    append_authority_section(
        &mut lines,
        "Network default:",
        &report.network_default,
        PermissionChangeKind::Modified,
    );
    lines.push(String::new());
    lines.push(format!(
        "Confirmation required: {}",
        if report.confirmation_required {
            "yes"
        } else {
            "no"
        }
    ));
    lines.join("\n")
}

fn append_section(lines: &mut Vec<String>, title: &str, changes: &[PermissionChange]) {
    if changes.is_empty() {
        return;
    }

    lines.push(String::new());
    lines.push(title.to_string());
    for change in changes {
        lines.push(format!(
            "  {:>8}  {}",
            severity_label(change.severity),
            format_change(change)
        ));
    }
}

fn append_authority_section(
    lines: &mut Vec<String>,
    title: &str,
    changes: &[AuthorityChange],
    kind: PermissionChangeKind,
) {
    let changes = changes
        .iter()
        .filter(|change| change.kind == kind)
        .collect::<Vec<_>>();
    if changes.is_empty() {
        return;
    }

    lines.push(String::new());
    lines.push(title.to_string());
    for change in changes {
        lines.push(format!(
            "  {:>8}  {}",
            severity_label(change.severity),
            format_authority_change(change)
        ));
    }
}

fn format_change(change: &PermissionChange) -> String {
    match change.kind {
        PermissionChangeKind::Added => change
            .after
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<missing permission>".to_string()),
        PermissionChangeKind::Removed => change
            .before
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<missing permission>".to_string()),
        PermissionChangeKind::Modified => {
            let before = change
                .before
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<missing permission>".to_string());
            let after = change
                .after
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<missing permission>".to_string());
            format!("{before} -> {after}")
        }
    }
}

fn sorted_changes(mut changes: Vec<PermissionChange>) -> Vec<PermissionChange> {
    changes.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| format_change(left).cmp(&format_change(right)))
    });
    changes
}

fn sorted_authority_changes(mut changes: Vec<AuthorityChange>) -> Vec<AuthorityChange> {
    changes.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| format_authority_change(left).cmp(&format_authority_change(right)))
    });
    changes
}

fn scheme_changes(diff: &AuthorityDiff) -> Vec<AuthorityChange> {
    let added = diff.schemes.added.iter().map(|scheme| AuthorityChange {
        severity: cocoon_core::severity_for_scheme(scheme),
        kind: PermissionChangeKind::Added,
        before: None,
        after: Some(format_scheme(scheme)),
    });
    let modified = diff.schemes.modified.iter().map(|(before, after)| {
        let severity =
            if cocoon_core::scheme_visibility_expanded(before.visibility, after.visibility) {
                cocoon_core::severity_for_scheme(after)
            } else {
                Severity::Low
            };
        AuthorityChange {
            severity,
            kind: PermissionChangeKind::Modified,
            before: Some(format_scheme(before)),
            after: Some(format_scheme(after)),
        }
    });
    let removed = diff.schemes.removed.iter().map(|scheme| AuthorityChange {
        severity: Severity::Low,
        kind: PermissionChangeKind::Removed,
        before: Some(format_scheme(scheme)),
        after: None,
    });

    added.chain(modified).chain(removed).collect()
}

fn preopen_changes(diff: &AuthorityDiff) -> Vec<AuthorityChange> {
    let added = diff.preopens.added.iter().map(|preopen| AuthorityChange {
        severity: cocoon_core::severity_for_preopen(preopen),
        kind: PermissionChangeKind::Added,
        before: None,
        after: Some(format_preopen(preopen)),
    });
    let modified = diff.preopens.modified.iter().map(|(before, after)| {
        let severity = if cocoon_core::preopen_rights_expanded(&before.rights, &after.rights)
            || before.host_path != after.host_path
        {
            cocoon_core::severity_for_preopen(after)
        } else {
            Severity::Low
        };
        AuthorityChange {
            severity,
            kind: PermissionChangeKind::Modified,
            before: Some(format_preopen(before)),
            after: Some(format_preopen(after)),
        }
    });
    let removed = diff.preopens.removed.iter().map(|preopen| AuthorityChange {
        severity: Severity::Low,
        kind: PermissionChangeKind::Removed,
        before: Some(format_preopen(preopen)),
        after: None,
    });

    added.chain(modified).chain(removed).collect()
}

fn network_default_changes(diff: &AuthorityDiff) -> Vec<AuthorityChange> {
    let Some((before, after)) = diff.network_default else {
        return Vec::new();
    };
    let severity = if cocoon_core::network_default_expanded(before, after) {
        cocoon_core::severity_for_network_default(after)
    } else {
        Severity::Low
    };

    vec![AuthorityChange {
        severity,
        kind: PermissionChangeKind::Modified,
        before: Some(format_network_default(before)),
        after: Some(format_network_default(after)),
    }]
}

fn format_authority_change(change: &AuthorityChange) -> String {
    match change.kind {
        PermissionChangeKind::Added => change
            .after
            .clone()
            .unwrap_or_else(|| "<missing authority>".to_string()),
        PermissionChangeKind::Removed => change
            .before
            .clone()
            .unwrap_or_else(|| "<missing authority>".to_string()),
        PermissionChangeKind::Modified => {
            let before = change
                .before
                .clone()
                .unwrap_or_else(|| "<missing authority>".to_string());
            let after = change
                .after
                .clone()
                .unwrap_or_else(|| "<missing authority>".to_string());
            format!("{before} -> {after}")
        }
    }
}

fn format_scheme(scheme: &SchemeConfig) -> String {
    let target = scheme
        .target
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<runtime>".to_string());
    format!(
        "{} {} target={}",
        scheme.name,
        visibility_label(scheme.visibility),
        target
    )
}

fn format_preopen(preopen: &PreopenConfig) -> String {
    let host_path = preopen
        .host_path
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<runtime-provided>".to_string());
    format!(
        "{} {} -> {} [{}]",
        preopen.scheme,
        host_path,
        preopen.guest_path,
        preopen_rights(&preopen.rights)
    )
}

fn format_network_default(default: NetworkDefault) -> String {
    format!("network default {}", default)
}

fn visibility_label(visibility: SchemeVisibility) -> &'static str {
    match visibility {
        SchemeVisibility::Hidden => "hidden",
        SchemeVisibility::Readonly => "readonly",
        SchemeVisibility::Readwrite => "readwrite",
    }
}

fn preopen_rights(rights: &[PreopenRight]) -> String {
    rights
        .iter()
        .map(|right| match right {
            PreopenRight::Read => "read",
            PreopenRight::Write => "write",
            PreopenRight::Execute => "execute",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_for_high() {
        let diff = PermissionDiff {
            added: vec![tcp_permission()],
            removed: Vec::new(),
            modified: Vec::new(),
        };
        let policy = UpdatePolicy::default();
        assert!(requires_confirmation(&diff, &policy));
    }

    #[test]
    fn no_confirmation_when_disabled() {
        let diff = PermissionDiff {
            added: vec![tcp_permission()],
            removed: Vec::new(),
            modified: Vec::new(),
        };
        let policy = UpdatePolicy {
            permission_expansion_requires_confirmation: false,
            ..Default::default()
        };
        assert!(!requires_confirmation(&diff, &policy));
    }

    #[test]
    fn formats_grouped_report() {
        let diff = PermissionDiff {
            added: vec![tcp_permission()],
            removed: vec![file_read_permission()],
            modified: Vec::new(),
        };

        let report = format_diff_report(&diff);

        assert!(report.contains("Added permissions:"));
        assert!(report.contains("      HIGH  allow tcp connect api.example.com:443"));
        assert!(report.contains("Removed permissions:"));
        assert!(report.contains("       LOW  allow log read service-log"));
        assert!(report.contains("Confirmation required: yes"));
    }

    #[test]
    fn formats_authority_report_with_scheme_change() {
        let old = cocoon_core::CapsuleManifest::from_toml(
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
        let new = cocoon_core::CapsuleManifest::from_toml(
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
        let diff = cocoon_core::diff_authority(&old, &new).unwrap();

        let report = format_authority_diff_report(&diff);

        assert!(report.contains("Authority changes detected:"));
        assert!(report.contains("Modified schemes:"));
        assert!(
            report
                .contains("HIGH  log readonly target=<runtime> -> log readwrite target=<runtime>")
        );
        assert!(report.contains("Confirmation required: yes"));
    }

    fn tcp_permission() -> cocoon_core::PermissionRule {
        cocoon_core::PermissionRule {
            effect: cocoon_core::PermissionEffect::Allow,
            scheme: cocoon_core::SchemeName::parse("tcp").unwrap(),
            action: cocoon_core::PermissionAction::Connect,
            target: cocoon_core::PermissionTarget::parse("api.example.com:443").unwrap(),
        }
    }

    fn file_read_permission() -> cocoon_core::PermissionRule {
        cocoon_core::PermissionRule {
            effect: cocoon_core::PermissionEffect::Allow,
            scheme: cocoon_core::SchemeName::parse("log").unwrap(),
            action: cocoon_core::PermissionAction::Read,
            target: cocoon_core::PermissionTarget::parse("service-log").unwrap(),
        }
    }
}
