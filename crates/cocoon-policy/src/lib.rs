use cocoon_core::{Capability, PermissionDiff, Severity};

/// Check whether a permission diff requires confirmation under policy.
pub fn requires_confirmation(diff: &PermissionDiff, policy: &UpdatePolicy) -> bool {
    if !policy.permission_expansion_requires_confirmation {
        return false;
    }
    let severities = cocoon_core::severity_of_diff(diff);
    severities.iter().any(|(sev, _)| *sev >= policy.confirmation_threshold)
}

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

/// Format a diff as human-readable report.
pub fn format_diff_report(diff: &PermissionDiff) -> String {
    let severities = cocoon_core::severity_of_diff(diff);
    if severities.is_empty() {
        return "No permission changes detected.".to_string();
    }

    let mut lines = vec!["Permission changes detected:".to_string()];
    for (sev, msg) in &severities {
        lines.push(format!("  {:>8}: {}", format!("{:?}", sev).to_uppercase(), msg));
    }
    if !diff.removed.is_empty() {
        lines.push("\nRemoved capabilities:".to_string());
        for cap in &diff.removed {
            lines.push(format!("  - {}", cap));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_for_high() {
        let diff = PermissionDiff {
            added: vec!["tcp:/connect/*".parse().unwrap()],
            removed: vec![],
            modified: vec![],
        };
        let policy = UpdatePolicy::default();
        assert!(requires_confirmation(&diff, &policy));
    }

    #[test]
    fn no_confirmation_when_disabled() {
        let diff = PermissionDiff {
            added: vec!["tcp:/connect/*".parse().unwrap()],
            removed: vec![],
            modified: vec![],
        };
        let policy = UpdatePolicy {
            permission_expansion_requires_confirmation: false,
            ..Default::default()
        };
        assert!(!requires_confirmation(&diff, &policy));
    }
}
