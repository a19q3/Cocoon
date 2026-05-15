use std::path::Path;

/// Install a capsule into the system directory.
/// P0 placeholder: extracts to a target directory.
pub fn install_capsule(capsule_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    let bytes = std::fs::read(capsule_path)?;
    let gz = flate2::read::GzDecoder::new(&bytes[..]);
    let mut tar = tar::Archive::new(gz);
    tar.unpack(target_dir)?;
    Ok(())
}
