use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::Result;

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let mut temp_name = path
        .file_name()
        .map(OsString::from)
        .ok_or_else(|| std::io::Error::other("atomic write target has no file name"))?;
    temp_name.push(".tmp");
    let temp = path.with_file_name(temp_name);

    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)?;
    Ok(())
}
