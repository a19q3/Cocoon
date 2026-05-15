#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cocoon_core::{hash_bytes, CapsuleManifest, CocoonError, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

pub const COCOON_EXTENSION: &str = "cocoon";
pub const MANIFEST_NAME: &str = "Cocoon.toml";
const HASH_MANIFEST_NAME: &str = "manifest/hashes.json";
const SIGNATURE_NAME: &str = "manifest/signature.json";

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
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));

        let manifest_bytes = self.manifest.to_toml_pretty()?;
        let manifest_hash = hash_bytes(manifest_bytes.as_bytes());
        append_file(&mut tar, MANIFEST_NAME, manifest_bytes.as_bytes())?;

        let mut hash_manifest = HashManifest {
            files: BTreeMap::new(),
            manifest_hash: manifest_hash.clone(),
        };
        hash_manifest
            .files
            .insert(MANIFEST_NAME.to_string(), manifest_hash);

        for entry in &self.entries {
            append_file(&mut tar, &entry.archive_path, &entry.content)?;
            hash_manifest
                .files
                .insert(entry.archive_path.clone(), entry.hash.clone());
        }

        let hashes_json = serde_json::to_vec_pretty(&hash_manifest)
            .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
        append_file(&mut tar, HASH_MANIFEST_NAME, &hashes_json)?;

        let signature = SignatureMetadata {
            algorithm: "none".into(),
            public_key: None,
            signature: "placeholder".into(),
        };
        let signature_json = serde_json::to_vec_pretty(&signature)
            .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
        append_file(&mut tar, SIGNATURE_NAME, &signature_json)?;

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
            self.entries.push(BundleEntry {
                path,
                archive_path,
                content,
                hash,
            });
        }

        self.entries
            .sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
        Ok(())
    }
}

fn append_file<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    archive_path: &str,
    content: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(archive_path)?;
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, content)?;
    Ok(())
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
    entries: BTreeMap<String, Vec<u8>>,
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
            entry.read_to_end(&mut content)?;
            entries.insert(archive_path, content);
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

    pub fn verify(&self) -> Result<Vec<VerificationIssue>> {
        self.verify_with_policy(VerificationPolicy::default())
    }

    pub fn verify_with_policy(&self, policy: VerificationPolicy) -> Result<Vec<VerificationIssue>> {
        let mut issues = Vec::new();
        self.verify_payload_hashes(&mut issues);
        self.verify_manifest_hash(&mut issues)?;
        self.verify_signature(policy, &mut issues);
        Ok(issues)
    }

    pub fn materialize(&self, target_dir: impl AsRef<Path>) -> Result<()> {
        let target_dir = target_dir.as_ref();
        for (archive_path, content) in &self.entries {
            let destination = target_dir.join(archive_path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(destination, content)?;
        }
        Ok(())
    }

    pub fn payload_entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .filter(|(path, _)| !is_generated_metadata(path))
            .map(|(path, content)| (path.as_str(), content.as_slice()))
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

fn parse_manifest(entries: &BTreeMap<String, Vec<u8>>) -> Result<CapsuleManifest> {
    let content = entries
        .get(MANIFEST_NAME)
        .ok_or_else(|| CocoonError::Bundle("missing manifest".into()))?;
    let text = std::str::from_utf8(content)
        .map_err(|err| CocoonError::Bundle(format!("manifest is not UTF-8: {err}")))?;
    CapsuleManifest::from_toml(text)
}

fn parse_hash_manifest(entries: &BTreeMap<String, Vec<u8>>) -> Result<HashManifest> {
    let content = entries
        .get(HASH_MANIFEST_NAME)
        .ok_or_else(|| CocoonError::Bundle("missing hash manifest".into()))?;
    serde_json::from_slice(content).map_err(|err| CocoonError::Bundle(format!("json parse: {err}")))
}

fn parse_signature(entries: &BTreeMap<String, Vec<u8>>) -> Result<SignatureMetadata> {
    let content = entries
        .get(SIGNATURE_NAME)
        .ok_or_else(|| CocoonError::Bundle("missing signature".into()))?;
    serde_json::from_slice(content).map_err(|err| CocoonError::Bundle(format!("json parse: {err}")))
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
    matches!(path, HASH_MANIFEST_NAME | SIGNATURE_NAME)
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
        fs::write(src.join("hello.txt"), "hello world").unwrap();

        let builder = BundleBuilder::new(&src).unwrap();
        let bytes = builder.build().unwrap();

        let reader = BundleReader::from_bytes(&bytes).unwrap();
        assert_eq!(reader.manifest.capsule.name.as_str(), "test");
        let issues = reader.verify().unwrap();
        assert_eq!(issues, vec![VerificationIssue::Unsigned]);
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
        append_file(&mut tar, MANIFEST_NAME, b"one").unwrap();
        append_file(&mut tar, MANIFEST_NAME, b"two").unwrap();
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
            append_file(&mut tar, &path, &content).unwrap();
        }
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }
}
