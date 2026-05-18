#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cocoon_core::{CapsuleManifest, CocoonError, GuestPath, Result, hash_bytes};
use ed25519_dalek::{Signer, Verifier};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rand_core::OsRng;

/// Maximum path depth within a bundle (prevents deeply-nested archive attacks).
const MAX_PATH_DEPTH: usize = 256;

/// Wraps a [`Read`] to enforce a decompressed-size limit (gzip-bomb protection).
struct CountingReader<R> {
    inner: R,
    count: u64,
    limit: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            count: 0,
            limit,
        }
    }
}

impl<R: std::io::Read> std::io::Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        if self.count > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompressed data exceeds maximum of {} bytes", self.limit),
            ));
        }
        Ok(n)
    }
}

pub const COCOON_EXTENSION: &str = "cocoon";
pub const MANIFEST_NAME: &str = "Cocoon.toml";
const HASH_MANIFEST_NAME: &str = "manifest/hashes.json";
const SIGNATURE_NAME: &str = "manifest/signature.json";
const SBOM_NAME: &str = "manifest/sbom.json";
const SIGNATURE_ALGORITHM_NONE: &str = "none";
pub const SIGNATURE_ALGORITHM_ED25519_BLAKE3_V1: &str = "ed25519-blake3-v1";
const SIGNING_KEY_ALGORITHM: &str = "ed25519";
const SIGNING_CONTEXT: &[u8] = b"cocoon-bundle-signature-v1";

/// Maximum total uncompressed bundle size (100 MB).
pub const MAX_BUNDLE_SIZE: u64 = 100 * 1024 * 1024;
/// Maximum number of files in a bundle.
pub const MAX_FILE_COUNT: usize = 10_000;
/// Maximum size of a single file in a bundle (10 MB).
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BundleBuilder {
    source_dir: PathBuf,
    manifest: CapsuleManifest,
    entries: Vec<BundleEntry>,
    signing_key: Option<BundleSigningKey>,
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
pub struct HashManifest {
    pub files: BTreeMap<String, String>,
    pub manifest_hash: String,
    /// Canonical hash algorithm identifier. Defaults to `"blake3"` when absent.
    #[serde(default = "default_hash_alg")]
    pub algorithm: String,
}

fn default_hash_alg() -> String {
    "blake3".to_string()
}

impl BundleBuilder {
    pub fn new(source_dir: impl AsRef<Path>) -> Result<Self> {
        let source_dir = source_dir.as_ref().to_path_buf();
        let manifest_path = source_dir.join(MANIFEST_NAME);
        let manifest_text = fs::read_to_string(&manifest_path)
            .map_err(|err| CocoonError::Bundle(format!("cannot read manifest: {err}")))?;
        let manifest = CapsuleManifest::from_toml(&manifest_text)?;
        manifest
            .validate()
            .map_err(|err| CocoonError::Bundle(format!("manifest validation failed: {err}")))?;

        Ok(Self {
            source_dir,
            manifest,
            entries: Vec::new(),
            signing_key: None,
        })
    }

    pub fn with_signing_key(mut self, signing_key: BundleSigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    pub fn build(mut self) -> Result<Vec<u8>> {
        self.collect_entries()?;
        self.validate_declared_entrypoint()?;
        self.validate_size_limits()?;
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));

        let manifest_bytes = self.manifest.to_toml_pretty()?;
        let manifest_hash = hash_bytes(manifest_bytes.as_bytes());
        append_file(&mut tar, MANIFEST_NAME, manifest_bytes.as_bytes(), 0o644)?;

        let mut hash_manifest = HashManifest {
            files: BTreeMap::new(),
            manifest_hash: manifest_hash.clone(),
            algorithm: "blake3".to_string(),
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

        let signature = if let Some(signing_key) = &self.signing_key {
            signing_key.sign_hash_manifest(&hash_manifest)?
        } else {
            SignatureMetadata {
                algorithm: SIGNATURE_ALGORITHM_NONE.into(),
                public_key: None,
                signature: "placeholder".into(),
            }
        };
        let signature_json = serde_json::to_vec_pretty(&signature)
            .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
        append_file(&mut tar, SIGNATURE_NAME, &signature_json, 0o644)?;

        let encoder = tar.into_inner()?;
        Ok(encoder.finish()?)
    }

    fn collect_entries(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for entry in walkdir::WalkDir::new(&self.source_dir).same_file_system(true) {
            let entry = entry.map_err(|err| {
                CocoonError::Bundle(format!(
                    "cannot traverse source directory '{}': {err}",
                    self.source_dir.display()
                ))
            })?;
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

            // Reject symlinks in source to prevent packing unintended targets.
            #[cfg(unix)]
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(CocoonError::Bundle(format!(
                    "source path '{archive_path}' is a symbolic link and cannot be bundled"
                )));
            }
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

    fn validate_size_limits(&self) -> Result<()> {
        if self.entries.len() > MAX_FILE_COUNT {
            return Err(CocoonError::Bundle(format!(
                "bundle contains {} files, exceeding maximum of {MAX_FILE_COUNT}",
                self.entries.len()
            )));
        }
        let mut total_size = 0u64;
        for entry in &self.entries {
            let size = entry.content.len() as u64;
            if size > MAX_FILE_SIZE {
                return Err(CocoonError::Bundle(format!(
                    "file '{}' is {} bytes, exceeding maximum of {MAX_FILE_SIZE}",
                    entry.archive_path, size
                )));
            }
            total_size += size;
        }
        if total_size > MAX_BUNDLE_SIZE {
            return Err(CocoonError::Bundle(format!(
                "bundle uncompressed size is {total_size} bytes, exceeding maximum of {MAX_BUNDLE_SIZE}"
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
            .ok_or_else(|| {
                CocoonError::Bundle(format!(
                    "guest path '{guest_path}' could not be mapped below filesystem.root '{root}'"
                ))
            })?
            .trim_start_matches('/')
    };

    if suffix.is_empty() {
        return Err(CocoonError::Bundle(format!(
            "guest path '{guest_path}' must map to a payload file below filesystem.root"
        )));
    }

    archive_path_to_key(Path::new(suffix))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub public_key: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyDocument {
    pub algorithm: String,
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone)]
pub struct BundleSigningKey {
    key: ed25519_dalek::SigningKey,
}

impl BundleSigningKey {
    pub fn generate() -> Self {
        Self {
            key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_document(document: SigningKeyDocument) -> Result<Self> {
        if document.algorithm != SIGNING_KEY_ALGORITHM {
            return Err(CocoonError::Bundle(format!(
                "unsupported signing key algorithm '{}'",
                document.algorithm
            )));
        }

        let secret = decode_hex_array::<32>(&document.secret_key, "secret key")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let expected_public = encode_hex(&key.verifying_key().to_bytes());
        if expected_public != document.public_key {
            return Err(CocoonError::Bundle(
                "signing key public key does not match secret key".to_string(),
            ));
        }

        Ok(Self { key })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let document = serde_json::from_slice(bytes)
            .map_err(|err| CocoonError::Bundle(format!("signing key json parse: {err}")))?;
        Self::from_document(document)
    }

    pub fn to_document(&self) -> SigningKeyDocument {
        SigningKeyDocument {
            algorithm: SIGNING_KEY_ALGORITHM.to_string(),
            public_key: self.public_key_hex(),
            secret_key: encode_hex(&self.key.to_bytes()),
        }
    }

    pub fn to_json_pretty(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(&self.to_document())
            .map_err(|err| CocoonError::Bundle(format!("signing key json serialize: {err}")))
    }

    pub fn public_key_hex(&self) -> String {
        encode_hex(&self.key.verifying_key().to_bytes())
    }

    fn sign_hash_manifest(&self, hash_manifest: &HashManifest) -> Result<SignatureMetadata> {
        let digest = signature_digest(hash_manifest)?;
        Ok(self.sign_digest(&digest, SIGNATURE_ALGORITHM_ED25519_BLAKE3_V1))
    }

    pub fn sign_context_bytes(
        &self,
        algorithm: &str,
        context: &[u8],
        bytes: &[u8],
    ) -> SignatureMetadata {
        let digest = context_digest(context, bytes);
        self.sign_digest(&digest, algorithm)
    }

    fn sign_digest(&self, digest: &[u8; 32], algorithm: &str) -> SignatureMetadata {
        let signature = self.key.sign(digest);
        SignatureMetadata {
            algorithm: algorithm.to_string(),
            public_key: Some(self.public_key_hex()),
            signature: encode_hex(&signature.to_bytes()),
        }
    }
}

pub fn public_key_from_trust_document(bytes: &[u8]) -> Result<String> {
    if let Ok(document) = serde_json::from_slice::<SigningKeyDocument>(bytes) {
        if document.algorithm != SIGNING_KEY_ALGORITHM {
            return Err(CocoonError::Bundle(format!(
                "unsupported trust key algorithm '{}'",
                document.algorithm
            )));
        }
        decode_hex_array::<32>(&document.public_key, "public key")?;
        return Ok(document.public_key);
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|err| CocoonError::Bundle(format!("trust key is not UTF-8: {err}")))?;
    let key = text.trim();
    decode_hex_array::<32>(key, "public key")?;
    Ok(key.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerificationPolicy {
    pub require_signature: bool,
    pub trusted_public_keys: BTreeSet<String>,
}

impl VerificationPolicy {
    pub fn strict() -> Self {
        Self {
            require_signature: true,
            trusted_public_keys: BTreeSet::new(),
        }
    }

    pub fn with_trusted_public_key(mut self, public_key: impl Into<String>) -> Self {
        self.trusted_public_keys.insert(public_key.into());
        self.require_signature = true;
        self
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
        let gz = GzDecoder::new(CountingReader::new(bytes, MAX_BUNDLE_SIZE + MAX_FILE_SIZE));
        let mut archive = tar::Archive::new(gz);
        let mut entries = BTreeMap::new();
        let mut total_size: u64 = 0;

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                continue;
            }
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(CocoonError::Bundle(format!(
                    "archive contains unsupported link entry '{}'",
                    entry.path()?.display()
                )));
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
            let file_size = entry.size();
            if file_size > MAX_FILE_SIZE {
                return Err(CocoonError::Bundle(format!(
                    "file '{}' is {file_size} bytes, exceeding maximum of {MAX_FILE_SIZE}",
                    archive_path
                )));
            }
            total_size += file_size;
            if total_size > MAX_BUNDLE_SIZE {
                return Err(CocoonError::Bundle(format!(
                    "bundle uncompressed size exceeds maximum of {MAX_BUNDLE_SIZE}"
                )));
            }
            if entries.len() >= MAX_FILE_COUNT {
                return Err(CocoonError::Bundle(format!(
                    "bundle file count exceeds maximum of {MAX_FILE_COUNT}"
                )));
            }
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
            return Err(CocoonError::Verification(format_verification_issues(
                &blocking_issues,
            )));
        }

        Ok(VerifiedBundle { reader })
    }

    pub fn verify(&self) -> Result<Vec<VerificationIssue>> {
        self.verify_with_policy(VerificationPolicy::default())
    }

    pub fn verify_with_policy(&self, policy: VerificationPolicy) -> Result<Vec<VerificationIssue>> {
        let mut issues = Vec::new();
        self.verify_hash_algorithm(&mut issues);
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
            #[cfg(unix)]
            if destination
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                fs::remove_file(&destination)?;
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

    fn verify_hash_algorithm(&self, issues: &mut Vec<VerificationIssue>) {
        let alg = &self.hash_manifest.algorithm;
        if alg != "blake3" {
            issues.push(VerificationIssue::UnsupportedHashAlgorithm {
                algorithm: alg.clone(),
            });
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
        if self.signature.algorithm == SIGNATURE_ALGORITHM_NONE {
            issues.push(if policy.require_signature {
                VerificationIssue::SignatureRequired
            } else {
                VerificationIssue::Unsigned
            });
            return;
        }

        if self.signature.algorithm != SIGNATURE_ALGORITHM_ED25519_BLAKE3_V1 {
            issues.push(VerificationIssue::SignatureInvalid(format!(
                "unsupported signature algorithm '{}'",
                self.signature.algorithm
            )));
            return;
        }

        let Some(public_key) = &self.signature.public_key else {
            issues.push(VerificationIssue::SignatureInvalid(
                "missing public key".to_string(),
            ));
            return;
        };

        if let Err(error) = verify_ed25519_signature(&self.hash_manifest, &self.signature) {
            issues.push(VerificationIssue::SignatureInvalid(error));
            return;
        }

        if policy.require_signature && policy.trusted_public_keys.is_empty() {
            issues.push(VerificationIssue::SignatureTrustRequired);
        } else if !policy.trusted_public_keys.is_empty()
            && !policy.trusted_public_keys.contains(public_key)
        {
            issues.push(VerificationIssue::SignatureUntrusted {
                public_key: public_key.clone(),
            });
        }
    }
}

fn verify_ed25519_signature(
    hash_manifest: &HashManifest,
    signature: &SignatureMetadata,
) -> std::result::Result<(), String> {
    let digest = signature_digest(hash_manifest).map_err(|err| err.to_string())?;
    verify_ed25519_digest(signature, &digest)
}

pub fn verify_context_signature(
    signature: &SignatureMetadata,
    expected_algorithm: &str,
    context: &[u8],
    bytes: &[u8],
) -> std::result::Result<(), String> {
    if signature.algorithm != expected_algorithm {
        return Err(format!(
            "unsupported signature algorithm '{}'",
            signature.algorithm
        ));
    }
    let digest = context_digest(context, bytes);
    verify_ed25519_digest(signature, &digest)
}

fn verify_ed25519_digest(
    signature: &SignatureMetadata,
    digest: &[u8; 32],
) -> std::result::Result<(), String> {
    let public_key = signature
        .public_key
        .as_deref()
        .ok_or_else(|| "missing public key".to_string())
        .and_then(|key| decode_hex_array::<32>(key, "public key").map_err(|err| err.to_string()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|err| format!("invalid public key: {err}"))?;
    let signature_bytes =
        decode_hex_array::<64>(&signature.signature, "signature").map_err(|err| err.to_string())?;
    let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(digest, &ed25519_signature)
        .map_err(|err| format!("signature verification failed: {err}"))
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

/// Normalizes a filesystem path into a bundle archive key.
fn signature_digest(hash_manifest: &HashManifest) -> Result<[u8; 32]> {
    let canonical = serde_json::to_vec(hash_manifest)
        .map_err(|err| CocoonError::Bundle(format!("json serialize: {err}")))?;
    Ok(context_digest(SIGNING_CONTEXT, &canonical))
}

fn context_digest(context: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|err| CocoonError::Bundle(format!("{label} is not valid hex: {err}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CocoonError::Bundle(format!(
            "{label} must be {N} bytes, got {} bytes",
            bytes.len()
        ))
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Normalizes a filesystem path into a bundle archive key.
pub fn archive_path_to_key(path: &Path) -> Result<String> {
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
    if parts.len() > MAX_PATH_DEPTH {
        return Err(CocoonError::Bundle(format!(
            "archive path depth {} exceeds maximum of {MAX_PATH_DEPTH}",
            parts.len()
        )));
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
fn file_mode(path: &Path) -> Result<u32> {
    let is_executable = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "exe" | "bat" | "cmd"));
    Ok(if is_executable { 0o755 } else { 0o644 })
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
    UnsupportedHashAlgorithm {
        algorithm: String,
    },
    SignatureTrustRequired,
    SignatureInvalid(String),
    SignatureUntrusted {
        public_key: String,
    },
}

impl VerificationIssue {
    pub fn is_integrity_failure(&self) -> bool {
        !matches!(self, Self::Unsigned)
    }
}

impl fmt::Display for VerificationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch {
                file,
                expected,
                actual,
            } => write!(
                f,
                "hash mismatch for '{file}': expected {expected}, got {actual}"
            ),
            Self::MissingFile(path) => write!(f, "missing file '{path}'"),
            Self::ExtraFile(path) => write!(f, "unexpected extra file '{path}'"),
            Self::MissingEntrypoint {
                guest_path,
                archive_path,
            } => write!(
                f,
                "entrypoint '{guest_path}' maps to missing payload file '{archive_path}'"
            ),
            Self::NonExecutableEntrypoint {
                guest_path,
                archive_path,
                mode,
            } => write!(
                f,
                "entrypoint '{guest_path}' maps to non-executable payload file '{archive_path}' with mode {mode:o}"
            ),
            Self::Unsigned => f.write_str("bundle is unsigned"),
            Self::SignatureRequired => f.write_str("bundle signature is required"),
            Self::UnsupportedHashAlgorithm { algorithm } => {
                write!(f, "unsupported hash algorithm '{algorithm}'")
            }
            Self::SignatureTrustRequired => f.write_str("bundle signature trust root is required"),
            Self::SignatureInvalid(reason) => write!(f, "bundle signature is invalid: {reason}"),
            Self::SignatureUntrusted { public_key } => {
                write!(f, "bundle signature key is not trusted: {public_key}")
            }
        }
    }
}

fn format_verification_issues(issues: &[VerificationIssue]) -> String {
    issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
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

        assert!(
            err.to_string()
                .contains("maps to missing payload file 'bin/test'")
        );
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

        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue, VerificationIssue::SignatureRequired))
        );
    }

    #[test]
    fn signed_bundle_passes_strict_with_trusted_key() {
        let signing_key = BundleSigningKey::generate();
        let public_key = signing_key.public_key_hex();
        let bytes = signed_fixture_bundle(signing_key);
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader
            .verify_with_policy(VerificationPolicy::strict().with_trusted_public_key(public_key))
            .unwrap();

        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn signed_bundle_strict_requires_trust_root() {
        let bytes = signed_fixture_bundle(BundleSigningKey::generate());
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader
            .verify_with_policy(VerificationPolicy::strict())
            .unwrap();

        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue, VerificationIssue::SignatureTrustRequired))
        );
    }

    #[test]
    fn signed_bundle_strict_rejects_untrusted_key() {
        let bytes = signed_fixture_bundle(BundleSigningKey::generate());
        let other_key = BundleSigningKey::generate().public_key_hex();
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader
            .verify_with_policy(VerificationPolicy::strict().with_trusted_public_key(other_key))
            .unwrap();

        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue, VerificationIssue::SignatureUntrusted { .. }))
        );
    }

    #[test]
    fn signed_bundle_rejects_signature_tamper() {
        let mut entries = entries_from_bundle(&signed_fixture_bundle(BundleSigningKey::generate()));
        let mut signature: SignatureMetadata =
            serde_json::from_slice(entries.get(SIGNATURE_NAME).unwrap()).unwrap();
        signature.signature = format!("00{}", &signature.signature[2..]);
        entries.insert(
            SIGNATURE_NAME.to_string(),
            serde_json::to_vec_pretty(&signature).unwrap(),
        );
        let bytes = archive_from_entries(entries);
        let reader = BundleReader::from_bytes(&bytes).unwrap();
        let issues = reader
            .verify_with_policy(VerificationPolicy::strict())
            .unwrap();

        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue, VerificationIssue::SignatureInvalid(_)))
        );
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
        fixture_bundle_with_key(None)
    }

    fn signed_fixture_bundle(signing_key: BundleSigningKey) -> Vec<u8> {
        fixture_bundle_with_key(Some(signing_key))
    }

    fn fixture_bundle_with_key(signing_key: Option<BundleSigningKey>) -> Vec<u8> {
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
        if let Some(signing_key) = signing_key {
            builder.with_signing_key(signing_key).build().unwrap()
        } else {
            builder.build().unwrap()
        }
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
