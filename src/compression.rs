use crate::common::Option_;
use anyhow::{bail, Context, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::cmp::min;
use std::fs::File;
use std::io::{Read, Write};

const ZLIB_BUFSIZE: usize = 2 * 1024 * 1024;
const MAX_INFLATED_OUTPUT_SIZE: usize = 3 * 1024 * 1024 * 1024;

fn inflate_reserve_hint(input_size: usize, max_output_size: usize) -> usize {
    if max_output_size == 0 {
        return 0;
    }
    if input_size > max_output_size / 2 {
        return max_output_size;
    }
    let doubled = input_size.saturating_mul(2);
    min(doubled, max_output_size)
}

fn inflate_to_vec_bounded(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::with_capacity(inflate_reserve_hint(data.len(), max_output_size));
    let mut buffer = vec![0u8; ZLIB_BUFSIZE];

    loop {
        let read_len = decoder.read(&mut buffer).context("zlib inflate failed")?;
        if read_len == 0 {
            break;
        }

        if read_len > max_output_size || output.len() > max_output_size - read_len {
            bail!("Zlib Compression Error: Inflated data exceeds maximum program size limit.");
        }
        output.extend_from_slice(&buffer[..read_len]);
    }

    Ok(output)
}

fn inflate_to_file_bounded(data: &[u8], file: &mut File, max_output_size: usize) -> Result<usize> {
    let mut decoder = ZlibDecoder::new(data);
    let mut buffer = vec![0u8; ZLIB_BUFSIZE];
    let mut total_written = 0usize;

    loop {
        let read_len = decoder.read(&mut buffer).context("zlib inflate failed")?;
        if read_len == 0 {
            break;
        }

        if read_len > max_output_size || total_written > max_output_size - read_len {
            bail!("Zlib Compression Error: Inflated data exceeds maximum program size limit.");
        }

        file.write_all(&buffer[..read_len])
            .context("Write File Error: Failed to write complete output file.")?;
        total_written += read_len;
    }

    Ok(total_written)
}

pub fn zlib_deflate(
    data_vec: &mut Vec<u8>,
    option: Option_,
    is_compressed_file: bool,
) -> Result<()> {
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

pub fn zlib_inflate_span_bounded(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    inflate_to_vec_bounded(data, max_output_size)
}

pub fn zlib_inflate_to_file(data: &[u8], file: &mut File) -> Result<usize> {
    let total_written = inflate_to_file_bounded(data, file, MAX_INFLATED_OUTPUT_SIZE)?;
    if total_written == 0 {
        bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
    }
    Ok(total_written)
}
