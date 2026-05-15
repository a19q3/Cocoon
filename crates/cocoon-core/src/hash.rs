use blake3::Hasher;

pub fn hash_bytes(data: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(data);
    format!("blake3:{}", h.finalize().to_hex())
}

pub fn hash_manifest(manifest: &crate::CapsuleManifest) -> crate::Result<String> {
    let text = toml::to_string(manifest)?;
    Ok(hash_bytes(text.as_bytes()))
}
