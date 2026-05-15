use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CocoonError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("Capability parse error: {0}")]
    CapabilityParse(String),

    #[error("Bundle error: {0}")]
    Bundle(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Missing file in bundle: {0}")]
    MissingFile(PathBuf),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, CocoonError>;
