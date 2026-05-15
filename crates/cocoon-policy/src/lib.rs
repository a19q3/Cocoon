#![forbid(unsafe_code)]

use cocoon_core::{PermissionDiff, PermissionRule, Severity};

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

/// Format a diff as a human-readable report.
pub fn format_diff_report(diff: &PermissionDiff) -> String {
    format_report(&build_diff_report(diff, &UpdatePolicy::default()))
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
