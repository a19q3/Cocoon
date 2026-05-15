#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cocoon_core::{hash_bytes, CapsuleManifest, CocoonError, GuestPath, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

pub const COCOON_EXTENSION: &str = "cocoon";
pub const MANIFEST_NAME: &str = "Cocoon.toml";
const HASH_MANIFEST_NAME: &str = "manifest/hashes.json";
const SIGNATURE_NAME: &str = "manifest/signature.json";
const SBOM_NAME: &str = "manifest/sbom.json";

#[derive(Debug, Clone)]
pub struct BundleBuilder {
    source_dir: PathBuf,
    manifest: CapsuleManifest,
    entries: Vec<BundleEntry>,
}

#[derive(Debug, Clone)]
pub struct BundleEntry {
    pub path: PathBuf,
    pub archive_path: String,
    pub content: Vec<u8>,
    pub hash: String,
    pub mode: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashManifest {
    pub files: BTreeMap<String, String>,
    pub manifest_hash: String,
}

impl BundleBuilder {
    pub fn new(source_dir: impl AsRef<Path>) -> Result<Self> {
        let source_dir = source_dir.as_ref().to_path_buf();
        let manifest_path = source_dir.join(MANIFEST_NAME);
        let manifest_text = fs::read_to_string(&manifest_path)
            .map_err(|err| CocoonError::Bundle(format!("cannot read manifest: {err}")))?;
        let manifest = CapsuleManifest::from_toml(&manifest_text)?;

        Ok(Self {
            source_dir,
            manifest,
            entries: Vec::new(),
        })
    }

    pub fn build(mut self) -> Result<Vec<u8>> {
        self.collect_entries()?;
        self.validate_declared_entrypoint()?;
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));

        let manifest_bytes = self.manifest.to_toml_pretty()?;
        let manifest_hash = hash_bytes(manifest_bytes.as_bytes());
        append_file(&mut tar, MANIFEST_NAME, manifest_bytes.as_bytes(), 0o644)?;

        let mut hash_manifest = HashManifest {
            files: BTreeMap::new(),
            manifest_hash: manifest_hash.clone(),
        };
        hash_manifest
            .files
            .insert(MANIFEST_NAME.to_string(), manifest_hash);

        for entry in &self.entries {
            append_file(&mut tar, &entry.archive_path, &entry.content, entry.mode)?;
            hash_manifest
                .files
                .insert(entry.archive_path.clone(), entry.hash.clone());
        }

        let hashes_json = serde_json::to_vec_pretty(&hash_manifest)
            .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
        append_file(&mut tar, HASH_MANIFEST_NAME, &hashes_json, 0o644)?;

        let signature = SignatureMetadata {
            algorithm: "none".into(),
            public_key: None,
            signature: "placeholder".into(),
        };
        let signature_json = serde_json::to_vec_pretty(&signature)
            .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
        append_file(&mut tar, SIGNATURE_NAME, &signature_json, 0o644)?;

        let encoder = tar.into_inner()?;
        Ok(encoder.finish()?)
    }

    fn collect_entries(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for entry in walkdir::WalkDir::new(&self.source_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path().to_path_buf();
            let rel = path.strip_prefix(&self.source_dir).map_err(|err| {
                CocoonError::Bundle(format!("cannot relativize bundle path: {err}"))
            })?;
            let archive_path = archive_path_to_key(rel)?;

            if archive_path == MANIFEST_NAME {
                continue;
            }
            if is_generated_metadata(&archive_path) {
                return Err(CocoonError::Bundle(format!(
                    "source path '{archive_path}' is reserved for generated bundle metadata"
                )));
            }
            if !seen.insert(archive_path.clone()) {
                return Err(CocoonError::Bundle(format!(
                    "duplicate source archive path '{archive_path}'"
                )));
            }

            let content = fs::read(&path)?;
            let hash = hash_bytes(&content);
            let mode = file_mode(&path)?;
            self.entries.push(BundleEntry {
                path,
                archive_path,
                content,
                hash,
                mode,
            });
        }

        self.entries
            .sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
        Ok(())
    }

    fn validate_declared_entrypoint(&self) -> Result<()> {
        let entry_path =
            guest_path_to_archive_path(&self.manifest.filesystem.root, &self.manifest.entry.cmd)?;
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.archive_path == entry_path)
        else {
            return Err(CocoonError::Bundle(format!(
                "entry.cmd '{}' maps to missing payload file '{entry_path}'",
                self.manifest.entry.cmd
            )));
        };

        if entry.mode & 0o111 == 0 {
            return Err(CocoonError::Bundle(format!(
                "entry.cmd '{}' maps to payload file '{entry_path}' without executable mode",
                self.manifest.entry.cmd
            )));
        }

        Ok(())
    }
}

fn append_file<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    archive_path: &str,
    content: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(archive_path)?;
    header.set_size(content.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    tar.append(&header, content)?;
    Ok(())
}

fn guest_path_to_archive_path(root: &GuestPath, guest_path: &GuestPath) -> Result<String> {
    if !root.contains(guest_path) {
        return Err(CocoonError::Bundle(format!(
            "guest path '{guest_path}' is outside filesystem.root '{root}'"
        )));
    }

    let suffix = if root.as_str() == "/" {
        guest_path.as_str().trim_start_matches('/')
    } else {
        guest_path
            .as_str()
            .strip_prefix(root.as_str())
            .unwrap_or_default()
            .trim_start_matches('/')
    };

    if suffix.is_empty() {
        return Err(CocoonError::Bundle(format!(
            "guest path '{guest_path}' must map to a payload file below filesystem.root"
        )));
    }

    archive_path_to_key(Path::new(suffix))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub public_key: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationPolicy {
    pub require_signature: bool,
}

impl VerificationPolicy {
    pub fn strict() -> Self {
        Self {
            require_signature: true,
        }
    }
}

pub struct BundleReader {
    pub manifest: CapsuleManifest,
    pub hash_manifest: HashManifest,
    pub signature: SignatureMetadata,
    entries: BTreeMap<String, ArchiveEntry>,
}

pub struct VerifiedBundle {
    reader: BundleReader,
}

#[derive(Debug, Clone)]
struct ArchiveEntry {
    content: Vec<u8>,
    mode: u32,
}

impl VerifiedBundle {
    pub fn reader(&self) -> &BundleReader {
        &self.reader
    }

    pub fn into_reader(self) -> BundleReader {
        self.reader
    }
}

impl BundleReader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let decoder = GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = BTreeMap::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                continue;
            }
            if !entry_type.is_file() {
                return Err(CocoonError::Bundle(format!(
                    "unsupported archive entry type for '{}'",
                    entry.path()?.display()
                )));
            }

            let archive_path = archive_path_to_key(entry.path()?.as_ref())?;
            if entries.contains_key(&archive_path) {
                return Err(CocoonError::Bundle(format!(
                    "duplicate archive path '{archive_path}'"
                )));
            }

            let mut content = Vec::new();
            let mode = entry.header().mode().map_err(|err| {
                CocoonError::Bundle(format!(
                    "cannot read archive mode for '{archive_path}': {err}"
                ))
            })?;
            entry.read_to_end(&mut content)?;
            entries.insert(archive_path, ArchiveEntry { content, mode });
        }

        let manifest = parse_manifest(&entries)?;
        let hash_manifest = parse_hash_manifest(&entries)?;
        let signature = parse_signature(&entries)?;

        Ok(Self {
            manifest,
            hash_manifest,
            signature,
            entries,
        })
    }

    pub fn from_verified_bytes(bytes: &[u8], policy: VerificationPolicy) -> Result<VerifiedBundle> {
        let reader = Self::from_bytes(bytes)?;
        let issues = reader.verify_with_policy(policy)?;
        let blocking_issues = issues
            .into_iter()
            .filter(VerificationIssue::is_integrity_failure)
            .collect::<Vec<_>>();
        if !blocking_issues.is_empty() {
            return Err(CocoonError::Verification(format!("{blocking_issues:?}")));
        }

        Ok(VerifiedBundle { reader })
    }

    pub fn verify(&self) -> Result<Vec<VerificationIssue>> {
        self.verify_with_policy(VerificationPolicy::default())
    }

    pub fn verify_with_policy(&self, policy: VerificationPolicy) -> Result<Vec<VerificationIssue>> {
        let mut issues = Vec::new();
        self.verify_payload_hashes(&mut issues);
        self.verify_manifest_hash(&mut issues)?;
        self.verify_entrypoint(&mut issues)?;
        self.verify_signature(policy, &mut issues);
        Ok(issues)
    }

    pub fn materialize(&self, target_dir: impl AsRef<Path>) -> Result<()> {
        let target_dir = target_dir.as_ref();
        for (archive_path, entry) in &self.entries {
            let destination = target_dir.join(archive_path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&destination, &entry.content)?;
            set_file_mode(&destination, entry.mode)?;
        }
        Ok(())
    }

    pub fn payload_entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .filter(|(path, _)| !is_generated_metadata(path))
            .map(|(path, entry)| (path.as_str(), entry.content.as_slice()))
    }

    fn verify_payload_hashes(&self, issues: &mut Vec<VerificationIssue>) {
        for (path, content) in self.payload_entries() {
            let Some(expected) = self.hash_manifest.files.get(path) else {
                issues.push(VerificationIssue::ExtraFile(path.to_string()));
                continue;
            };
            let actual = hash_bytes(content);
            if actual != *expected {
                issues.push(VerificationIssue::HashMismatch {
                    file: path.to_string(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        for path in self.hash_manifest.files.keys() {
            if !self.entries.contains_key(path) {
                issues.push(VerificationIssue::MissingFile(path.clone()));
            }
        }
    }

    fn verify_manifest_hash(&self, issues: &mut Vec<VerificationIssue>) -> Result<()> {
        let manifest_text = self.manifest.to_toml_pretty()?;
        let computed_manifest_hash = hash_bytes(manifest_text.as_bytes());
        if computed_manifest_hash != self.hash_manifest.manifest_hash {
            issues.push(VerificationIssue::HashMismatch {
                file: MANIFEST_NAME.into(),
                expected: self.hash_manifest.manifest_hash.clone(),
                actual: computed_manifest_hash,
            });
        }

        if self
            .hash_manifest
            .files
            .get(MANIFEST_NAME)
            .is_some_and(|hash| hash != &self.hash_manifest.manifest_hash)
        {
            issues.push(VerificationIssue::HashMismatch {
                file: format!("{MANIFEST_NAME} manifest_hash"),
                expected: self.hash_manifest.manifest_hash.clone(),
                actual: self
                    .hash_manifest
                    .files
                    .get(MANIFEST_NAME)
                    .cloned()
                    .unwrap_or_default(),
            });
        }

        Ok(())
    }

    fn verify_entrypoint(&self, issues: &mut Vec<VerificationIssue>) -> Result<()> {
        let entry_path =
            guest_path_to_archive_path(&self.manifest.filesystem.root, &self.manifest.entry.cmd)?;
        let Some(entry) = self.entries.get(&entry_path) else {
            issues.push(VerificationIssue::MissingEntrypoint {
                guest_path: self.manifest.entry.cmd.to_string(),
                archive_path: entry_path,
            });
            return Ok(());
        };

        if entry.mode & 0o111 == 0 {
            issues.push(VerificationIssue::NonExecutableEntrypoint {
                guest_path: self.manifest.entry.cmd.to_string(),
                archive_path: entry_path,
                mode: entry.mode,
            });
        }

        Ok(())
    }

    fn verify_signature(&self, policy: VerificationPolicy, issues: &mut Vec<VerificationIssue>) {
        if self.signature.algorithm == "none" {
            if policy.require_signature {
                issues.push(VerificationIssue::SignatureRequired);
            } else {
                issues.push(VerificationIssue::Unsigned);
            }
        }
    }
}

fn parse_manifest(entries: &BTreeMap<String, ArchiveEntry>) -> Result<CapsuleManifest> {
    let content = entry_content(entries, MANIFEST_NAME, "manifest")?;
    let text = std::str::from_utf8(content)
        .map_err(|err| CocoonError::Bundle(format!("manifest is not UTF-8: {err}")))?;
    CapsuleManifest::from_toml(text)
}

fn parse_hash_manifest(entries: &BTreeMap<String, ArchiveEntry>) -> Result<HashManifest> {
    let content = entry_content(entries, HASH_MANIFEST_NAME, "hash manifest")?;
    serde_json::from_slice(content).map_err(|err| CocoonError::Bundle(format!("json parse: {err}")))
}

fn parse_signature(entries: &BTreeMap<String, ArchiveEntry>) -> Result<SignatureMetadata> {
    let content = entry_content(entries, SIGNATURE_NAME, "signature")?;
    serde_json::from_slice(content).map_err(|err| CocoonError::Bundle(format!("json parse: {err}")))
}

fn entry_content<'a>(
    entries: &'a BTreeMap<String, ArchiveEntry>,
    path: &str,
    label: &str,
) -> Result<&'a [u8]> {
    entries
        .get(path)
        .map(|entry| entry.content.as_slice())
        .ok_or_else(|| CocoonError::Bundle(format!("missing {label}")))
}

fn archive_path_to_key(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(CocoonError::Bundle(format!(
                        "archive path '{}' is not UTF-8",
                        path.display()
                    )));
                };
                if part.is_empty() {
                    return Err(CocoonError::Bundle(
                        "archive path contains empty segment".into(),
                    ));
                }
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CocoonError::Bundle(format!(
                    "archive path '{}' must be relative and normalized",
                    path.display()
                )));
            }
        }
    }

    if parts.is_empty() {
        return Err(CocoonError::Bundle("archive path must not be empty".into()));
    }

    Ok(parts.join("/"))
}

fn is_generated_metadata(path: &str) -> bool {
    matches!(path, HASH_MANIFEST_NAME | SIGNATURE_NAME | SBOM_NAME)
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;

    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Result<u32> {
    Ok(0o644)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationIssue {
    HashMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    MissingFile(String),
    ExtraFile(String),
    MissingEntrypoint {
        guest_path: String,
        archive_path: String,
    },
    NonExecutableEntrypoint {
        guest_path: String,
        archive_path: String,
        mode: u32,
    },
    Unsigned,
    SignatureRequired,
}

impl VerificationIssue {
    pub fn is_integrity_failure(&self) -> bool {
        !matches!(self, Self::Unsigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_bundle() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(
            src.join("Cocoon.toml"),
            r#"
[capsule]
name = "test"
version = "0.1.0"

[entry]
cmd = "/app/bin/test"
"#,
        )
        .unwrap();
        fs::create_dir_all(src.join("bin")).unwrap();
        write_executable(src.join("bin/test"), b"#!/bin/sh\n").unwrap();
        fs::write(src.join("hello.txt"), "hello world").unwrap();

        let builder = BundleBuilder::new(&src).unwrap();
        let bytes = builder.build().unwrap();

        let reader = BundleReader::from_bytes(&bytes).unwrap();
        assert_eq!(reader.manifest.capsule.name.as_str(), "test");
        let issues = reader.verify().unwrap();
        assert_eq!(issues, vec![VerificationIssue::Unsigned]);
    }

    #[test]
    fn rejects_missing_entrypoint_payload() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(
            src.join("Cocoon.toml"),
            r#"
[capsule]
name = "test"
version = "0.1.0"

[entry]
cmd = "/app/bin/test"
"#,
        )
        .unwrap();

        let err = BundleBuilder::new(&src)
            .and_then(BundleBuilder::build)
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("maps to missing payload file 'bin/test'"));
    }

    #[test]
    fn rejects_non_executable_entrypoint_payload() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::create_dir_all(src.join("bin")).unwrap();
        fs::write(
            src.join("Cocoon.toml"),
            r#"
[capsule]
name = "test"
version = "0.1.0"

[entry]
cmd = "/app/bin/test"
"#,
        )
        .unwrap();
        fs::write(src.join("bin/test"), "not executable").unwrap();
        set_file_mode(&src.join("bin/test"), 0o644).unwrap();

        let err = BundleBuilder::new(&src)
            .and_then(BundleBuilder::build)
            .unwrap_err();

        assert!(err.to_string().contains("without executable mode"));
    }

    #[test]
    fn detects_modified_payload_file() {
        let bytes = tampered_bundle(|entries| {
            entries.insert("hello.txt".to_string(), b"changed".to_vec());
        });
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues
            .iter()
            .any(|issue| matches!(issue, VerificationIssue::HashMismatch { file, .. } if file == "hello.txt")));
    }

    #[test]
    fn detects_missing_payload_file() {
        let bytes = tampered_bundle(|entries| {
            entries.remove("hello.txt");
        });
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues.iter().any(
            |issue| matches!(issue, VerificationIssue::MissingFile(file) if file == "hello.txt")
        ));
    }

    #[test]
    fn detects_extra_payload_file() {
        let bytes = tampered_bundle(|entries| {
            entries.insert("extra.txt".to_string(), b"extra".to_vec());
        });
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues.iter().any(
            |issue| matches!(issue, VerificationIssue::ExtraFile(file) if file == "extra.txt")
        ));
    }

    #[test]
    fn detects_manifest_mismatch() {
        let bytes = tampered_bundle(|entries| {
            entries.insert(
                MANIFEST_NAME.to_string(),
                br#"
[capsule]
name = "test"
version = "0.2.0"

[entry]
cmd = "/app/bin/test"
"#
                .to_vec(),
            );
        });
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues.iter().any(
            |issue| matches!(issue, VerificationIssue::HashMismatch { file, .. } if file == MANIFEST_NAME)
        ));
    }

    #[test]
    fn rejects_duplicate_paths() {
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        append_file(&mut tar, MANIFEST_NAME, b"one", 0o644).unwrap();
        append_file(&mut tar, MANIFEST_NAME, b"two", 0o644).unwrap();
        let encoder = tar.into_inner().unwrap();
        let bytes = encoder.finish().unwrap();

        assert!(BundleReader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_parent_dir_paths() {
        assert!(archive_path_to_key(Path::new("../evil")).is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        assert!(archive_path_to_key(Path::new("/evil")).is_err());
    }

    #[test]
    fn strict_mode_requires_signature() {
        let reader = BundleReader::from_bytes(&fixture_bundle()).unwrap();
        let issues = reader
            .verify_with_policy(VerificationPolicy::strict())
            .unwrap();

        assert!(issues
            .iter()
            .any(|issue| matches!(issue, VerificationIssue::SignatureRequired)));
    }

    #[test]
    fn rejects_corrupted_hash_manifest() {
        let mut entries = fixture_entries();
        entries.insert(HASH_MANIFEST_NAME.to_string(), b"not-json".to_vec());
        let bytes = archive_from_entries(entries);

        assert!(BundleReader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn verify_detects_missing_entrypoint_payload() {
        let bytes = tampered_bundle(|entries| {
            entries.remove("bin/test");
        });
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues.iter().any(|issue| {
            matches!(
                issue,
                VerificationIssue::MissingEntrypoint {
                    archive_path,
                    ..
                } if archive_path == "bin/test"
            )
        }));
    }

    #[test]
    fn verify_detects_non_executable_entrypoint_payload() {
        let bytes = archive_from_entries(fixture_entries());
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader.verify().unwrap();

        assert!(issues.iter().any(|issue| {
            matches!(
                issue,
                VerificationIssue::NonExecutableEntrypoint {
                    archive_path,
                    ..
                } if archive_path == "bin/test"
            )
        }));
    }

    fn tampered_bundle(mut tamper: impl FnMut(&mut BTreeMap<String, Vec<u8>>)) -> Vec<u8> {
        let mut entries = entries_from_bundle(&fixture_bundle());
        tamper(&mut entries);
        archive_from_entries(entries)
    }

    fn fixture_bundle() -> Vec<u8> {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(
            src.join("Cocoon.toml"),
            r#"
[capsule]
name = "test"
version = "0.1.0"

[entry]
cmd = "/app/bin/test"
"#,
        )
        .unwrap();
        fs::create_dir_all(src.join("bin")).unwrap();
        write_executable(src.join("bin/test"), b"#!/bin/sh\n").unwrap();
        fs::write(src.join("hello.txt"), "hello world").unwrap();

        BundleBuilder::new(&src).unwrap().build().unwrap()
    }

    fn fixture_entries() -> BTreeMap<String, Vec<u8>> {
        entries_from_bundle(&fixture_bundle())
    }

    fn entries_from_bundle(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let decoder = GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = BTreeMap::new();

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = archive_path_to_key(entry.path().unwrap().as_ref()).unwrap();
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            entries.insert(path, content);
        }

        entries
    }

    fn archive_from_entries(entries: BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, content) in entries {
            append_file(&mut tar, &path, &content, 0o644).unwrap();
        }
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn write_executable(path: impl AsRef<Path>, content: &[u8]) -> std::io::Result<()> {
        let path = path.as_ref();
        fs::write(path, content)?;
        set_file_mode(path, 0o755).map_err(std::io::Error::other)
    }
}
