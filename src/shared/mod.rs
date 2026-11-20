pub mod config;
pub mod data_structures;

pub use data_structures::*;

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Durably replace `path` with `contents`: after a crash the file holds either
/// its previous or its new contents, and once this returns the new contents
/// survive a crash.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    write_renamed(path, contents, true)
        .and_then(|()| match path.parent() {
            // Make the new name durable before callers delete what it replaces.
            Some(parent) => sync_dir(parent),
            None => Ok(()),
        })
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

/// Write `contents` to a temporary file next to `path` and rename it over
/// `path`, so `path` never holds partial contents, not even after a failed write.
///
/// With `sync_data` the contents are on disk before the rename, so the new
/// name can never point at incomplete data after a crash. The new directory
/// entry itself is not made durable; see [`sync_dir`].
pub(crate) fn write_renamed(path: &Path, contents: &[u8], sync_data: bool) -> io::Result<()> {
    use rand::Rng;
    use std::os::unix::fs::OpenOptionsExt;

    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    let tmp_path = path.with_file_name(format!(".tmp-{}", to_hex(&suffix)));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(contents)?;
        if sync_data {
            file.sync_data()?;
        }
        fs::rename(&tmp_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Make the entries created in, renamed into or removed from `dir` durable.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Lowercase hexadecimal encoding of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_matches_lowercase_format() {
        let bytes: Vec<u8> = (0..=255).collect();
        let expected: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(to_hex(&bytes), expected);
    }
}
