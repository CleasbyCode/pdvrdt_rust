use crate::common::Option_;
use anyhow::{bail, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

pub fn zlib_deflate(data_vec: &mut Vec<u8>, option: Option_, is_compressed_file: bool) -> Result<()> {
    let level = if option == Option_::Mastodon {
        Compression::default()
    } else if is_compressed_file {
        Compression::none()
    } else {
        Compression::best()
    };

    let mut encoder = ZlibEncoder::new(Vec::new(), level);
    encoder.write_all(data_vec)?;
    let compressed = encoder.finish()?;

    *data_vec = compressed;
    Ok(())
}

pub fn zlib_inflate(data_vec: &mut Vec<u8>) -> Result<()> {
    let mut decoder = ZlibDecoder::new(data_vec.as_slice());
    let mut result = Vec::with_capacity(data_vec.len() * 2);

    match decoder.read_to_end(&mut result) {
        Ok(_) => {}
        Err(e) => {
            if result.is_empty() {
                bail!("zlib inflate failed: {}", e);
            }
        }
    }

    *data_vec = result;
    Ok(())
}
