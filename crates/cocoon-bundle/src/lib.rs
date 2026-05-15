use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cocoon_core::{hash_bytes, CapsuleManifest, CocoonError, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

pub const COCOON_EXTENSION: &str = "cocoon";
pub const MANIFEST_NAME: &str = "Cocoon.toml";

#[derive(Debug, Clone)]
pub struct BundleBuilder {
    source_dir: PathBuf,
    manifest: CapsuleManifest,
    entries: Vec<BundleEntry>,
}

#[derive(Debug, Clone)]
pub struct BundleEntry {
    pub path: PathBuf,
    pub content: Vec<u8>,
    pub hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HashManifest {
    pub files: HashMap<String, String>,
    pub manifest_hash: String,
}

impl BundleBuilder {
    pub fn new(source_dir: impl AsRef<Path>) -> Result<Self> {
        let source_dir = source_dir.as_ref().to_path_buf();
        let manifest_path = source_dir.join(MANIFEST_NAME);
        let manifest_text = fs::read_to_string(&manifest_path)
            .map_err(|e| CocoonError::Bundle(format!("cannot read manifest: {e}")))?;
        let manifest = CapsuleManifest::from_toml(&manifest_text)?;

        Ok(Self {
            source_dir,
            manifest,
            entries: vec![],
        })
    }

    pub fn build(mut self) -> Result<Vec<u8>> {
        self.collect_entries()?;
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));

        // Add manifest
        let manifest_bytes = self.manifest.to_toml_pretty()?;
        let manifest_hash = hash_bytes(manifest_bytes.as_bytes());
        let mut header = tar::Header::new_gnu();
        header.set_path(MANIFEST_NAME)?;
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, manifest_bytes.as_bytes())?;

        // Collect hashes
        let mut hash_manifest = HashManifest {
            files: HashMap::new(),
            manifest_hash: manifest_hash.clone(),
        };
        hash_manifest.files.insert(MANIFEST_NAME.to_string(), manifest_hash);

        for entry in &self.entries {
            let rel = entry.path.strip_prefix(&self.source_dir).unwrap();
            let rel_str = rel.to_string_lossy().to_string();
            let mut header = tar::Header::new_gnu();
            header.set_path(&rel_str)?;
            header.set_size(entry.content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, entry.content.as_slice())?;
            hash_manifest.files.insert(rel_str, entry.hash.clone());
        }

        // Add hash manifest
        let hashes_json = serde_json::to_vec_pretty(&hash_manifest)
            .map_err(|e| CocoonError::Bundle(format!("json serialize: {e}")))?;
        let mut header = tar::Header::new_gnu();
        header.set_path("manifest/hashes.json")?;
        header.set_size(hashes_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, hashes_json.as_slice())?;

        // Signature placeholder
        let sig = SignatureMetadata {
            algorithm: "none".into(),
            public_key: None,
            signature: "placeholder".into(),
        };
        let sig_json = serde_json::to_vec_pretty(&sig)
            .map_err(|e| CocoonError::Bundle(format!("json serialize: {e}")))?;
        let mut header = tar::Header::new_gnu();
        header.set_path("manifest/signature.json")?;
        header.set_size(sig_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, sig_json.as_slice())?;

        let gz = tar.into_inner()?;
        let bytes = gz.finish()?;
        Ok(bytes)
    }

    fn collect_entries(&mut self) -> Result<()> {
        for entry in walkdir::WalkDir::new(&self.source_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path().to_path_buf();
                if path.file_name() == Some(std::ffi::OsStr::new(MANIFEST_NAME)) {
                    continue;
                }
                let content = fs::read(&path)?;
                let hash = hash_bytes(&content);
                self.entries.push(BundleEntry { path, content, hash });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub public_key: Option<String>,
    pub signature: String,
}

pub struct BundleReader {
    pub manifest: CapsuleManifest,
    pub hash_manifest: HashManifest,
    pub signature: SignatureMetadata,
}

impl BundleReader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let gz = GzDecoder::new(bytes);
        let mut tar = tar::Archive::new(gz);

        let mut manifest = None;
        let mut hash_manifest = None;
        let mut signature = None;

        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            let mut content = vec![];
            entry.read_to_end(&mut content)?;

            match path.file_name().and_then(|s| s.to_str()) {
                Some("Cocoon.toml") if path.components().count() == 1 => {
                    let text = String::from_utf8_lossy(&content);
                    manifest = Some(CapsuleManifest::from_toml(&text)?);
                }
                Some("hashes.json") if path.starts_with("manifest") => {
                    hash_manifest = Some(serde_json::from_slice(&content)
                        .map_err(|e| CocoonError::Bundle(format!("json parse: {e}")))?);
                }
                Some("signature.json") if path.starts_with("manifest") => {
                    signature = Some(serde_json::from_slice(&content)
                        .map_err(|e| CocoonError::Bundle(format!("json parse: {e}")))?);
                }
                _ => {}
            }
        }

        let manifest = manifest.ok_or_else(|| CocoonError::Bundle("missing manifest".into()))?;
        let hash_manifest = hash_manifest.ok_or_else(|| CocoonError::Bundle("missing hash manifest".into()))?;
        let signature = signature.ok_or_else(|| CocoonError::Bundle("missing signature".into()))?;

        Ok(Self {
            manifest,
            hash_manifest,
            signature,
        })
    }

    pub fn verify(&self) -> Result<Vec<VerificationIssue>> {
        let mut issues = vec![];

        // Verify manifest hash
        let manifest_text = self.manifest.to_toml_pretty()?;
        let computed_manifest_hash = hash_bytes(manifest_text.as_bytes());
        if computed_manifest_hash != self.hash_manifest.manifest_hash {
            issues.push(VerificationIssue::HashMismatch {
                file: MANIFEST_NAME.into(),
                expected: self.hash_manifest.manifest_hash.clone(),
                actual: computed_manifest_hash,
            });
        }

        if self.signature.algorithm == "none" {
            issues.push(VerificationIssue::Unsigned);
        }

        Ok(issues)
    }
}

#[derive(Debug, Clone)]
pub enum VerificationIssue {
    HashMismatch { file: String, expected: String, actual: String },
    MissingFile(String),
    Unsigned,
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
        assert_eq!(reader.manifest.capsule.name, "test");
        let issues = reader.verify().unwrap();
        assert!(
            issues.iter().any(|i| matches!(i, VerificationIssue::Unsigned)),
            "expected unsigned warning"
        );
    }
}
