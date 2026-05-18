use blake3::Hasher;

/// Prefix for the current hashing algorithm (Blake3).
const HASH_ALG: &str = "blake3";

pub fn hash_bytes(data: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(data);
    format!("{HASH_ALG}:{}", h.finalize().to_hex())
}

/// Returns the algorithm identifier embedded in a hash string, if any.
///
/// Examples:
/// - `blake3:abc...` -> `"blake3"`
/// - `legacy:sha256:abc...` -> `"legacy:sha256"`
/// - `abc...` (no prefix) -> `"legacy"`
pub fn hash_algorithm(hash: &str) -> &str {
    // Detect "alg:hex" format.
    if let Some((alg, rest)) = hash.split_once(':') {
        // Only treat it as a known algorithm prefix if the rest looks like hex.
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return alg;
        }
    }
    "legacy"
}

/// Checks whether a hash string uses the current canonical algorithm.
pub fn hash_is_current(hash: &str) -> bool {
    hash_algorithm(hash) == HASH_ALG
}

pub fn hash_manifest(manifest: &crate::CapsuleManifest) -> crate::Result<String> {
    let text = toml::to_string(manifest)?;
    Ok(hash_bytes(text.as_bytes()))
}

pub fn hash_permissions(manifest: &crate::CapsuleManifest) -> String {
    let keys = manifest.normalized_permission_keys();
    hash_bytes(serde_json::to_vec(&keys).unwrap_or_default().as_slice())
}

pub fn hash_capabilities(manifest: &crate::CapsuleManifest) -> String {
    hash_permissions(manifest)
}
