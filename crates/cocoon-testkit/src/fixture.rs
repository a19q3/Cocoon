/// Generate a minimal Cocoon.toml for testing.
pub fn minimal_manifest(name: &str, version: &str, cmd: &str) -> String {
    format!(
        r#"[capsule]
name = "{name}"
version = "{version}"

[entry]
cmd = "{cmd}"
"#
    )
}

/// Return a path to a temporary fixture directory.
pub fn temp_fixture_dir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir()
}
