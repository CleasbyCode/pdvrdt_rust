use crate::common::FileTypeCheck;
use anyhow::{bail, Result};
use std::path::Path;

pub fn has_valid_filename(p: &Path) -> bool {
    let Some(filename) = p.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    if filename.is_empty() {
        return false;
    }
    filename.bytes().all(|c| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' || c == b'@' || c == b'%'
    })
}

pub fn has_file_extension(p: &Path, exts: &[&str]) -> bool {
    let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext_lower = format!(".{}", ext.to_lowercase());
    exts.iter().any(|e| *e == ext_lower)
}

pub fn read_file(path: &Path, file_type: FileTypeCheck) -> Result<Vec<u8>> {
    if !has_valid_filename(path) {
        bail!("Invalid Input Error: Unsupported characters in filename arguments.");
    }

    if !path.exists() || !path.is_file() {
        bail!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        );
    }

    let file_size = std::fs::metadata(path)?.len() as usize;

    if file_size == 0 {
        bail!("Error: File is empty.");
    }

    if file_type == FileTypeCheck::CoverImage || file_type == FileTypeCheck::EmbeddedImage {
        if !has_file_extension(path, &[".png"]) {
            bail!("File Type Error: Invalid image extension. Only expecting \".png\".");
        }

        if file_type == FileTypeCheck::CoverImage {
            const MINIMUM_IMAGE_SIZE: usize = 87;
            if file_size < MINIMUM_IMAGE_SIZE {
                bail!("File Error: Invalid image file size.");
            }

            const MAX_IMAGE_SIZE: usize = 8 * 1024 * 1024;
            if file_size > MAX_IMAGE_SIZE {
                bail!("Image File Error: Cover image file exceeds maximum size limit.");
            }
        }
    }

    const MAX_FILE_SIZE: usize = 3 * 1024 * 1024 * 1024;
    if file_size > MAX_FILE_SIZE {
        bail!("Error: File exceeds program size limit.");
    }

    let data = std::fs::read(path)?;
    if data.len() != file_size {
        bail!("Failed to read full file: partial read");
    }

    Ok(data)
}
