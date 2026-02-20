use crate::binary_io::{get_value, search_sig};
use crate::compression::zlib_inflate;
use crate::encryption::decrypt_data_file;
use anyhow::{bail, Result};

struct ChunkLocation {
    data_start: usize,
    data_size: usize,
    is_mastodon: bool,
}

fn locate_embedded_data(png_vec: &[u8]) -> Result<ChunkLocation> {
    const ICCP_SIG: &[u8] = &[0x69, 0x43, 0x43, 0x50, 0x69, 0x63, 0x63];
    const PDV_SIG: &[u8] = &[0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9];

    const EXPECTED_ICCP_INDEX: usize = 0x25;
    // Mastodon: iCCP chunk layout offsets.
    const MASTODON_SIZE_INDEX_OFFSET: usize = 4;
    const MASTODON_DATA_OFFSET: usize = 9;
    const MASTODON_HEADER_OVERHEAD: usize = 9;
    const MASTODON_TAIL_PAD: usize = 3;
    // Default: custom IDAT chunk layout offsets.
    const DEFAULT_SIZE_INDEX_OFFSET: usize = 112;
    const DEFAULT_DATA_OFFSET: usize = 11;
    const DEFAULT_TAIL_PAD: usize = 3;

    let iccp_opt = search_sig(png_vec, ICCP_SIG, 0);
    let pdv_opt = search_sig(png_vec, PDV_SIG, 0);

    let has_iccp_at_expected = iccp_opt.map_or(false, |idx| idx == EXPECTED_ICCP_INDEX);
    let has_pdv = pdv_opt.is_some();

    if !has_iccp_at_expected && !has_pdv {
        bail!("Image File Error: This is not a pdvrdt image.");
    }

    // Mastodon files have iCCP at the expected index and no visible PDV signature
    // (PDV signature is inside the deflated iCCP data).
    if has_iccp_at_expected && !has_pdv {
        let iccp_index = iccp_opt.unwrap();
        let chunk_size_index = iccp_index - MASTODON_SIZE_INDEX_OFFSET;
        let raw_chunk_size = get_value(png_vec, chunk_size_index, 4)?;

        return Ok(ChunkLocation {
            data_start: iccp_index + MASTODON_DATA_OFFSET,
            data_size: raw_chunk_size - MASTODON_HEADER_OVERHEAD + MASTODON_TAIL_PAD,
            is_mastodon: true,
        });
    }

    // Default mode: PDV signature found directly.
    let pdv_index = pdv_opt.unwrap();
    let chunk_size_index = pdv_index - DEFAULT_SIZE_INDEX_OFFSET;
    let chunk_size = get_value(png_vec, chunk_size_index, 4)?;

    Ok(ChunkLocation {
        data_start: chunk_size_index + DEFAULT_DATA_OFFSET,
        data_size: chunk_size - DEFAULT_TAIL_PAD,
        is_mastodon: false,
    })
}

pub fn recover_data(png_vec: &mut Vec<u8>) -> Result<()> {
    const PDV_SIG: &[u8] = &[0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9];

    let location = locate_embedded_data(png_vec)?;

    // Extract just the embedded data, discarding the rest of the PNG.
    let data_end = location.data_start + location.data_size;
    png_vec.drain(data_end..);
    png_vec.drain(..location.data_start);

    if location.is_mastodon {
        zlib_inflate(png_vec)?;

        if png_vec.is_empty() {
            bail!("File Size Error: File is zero bytes. Probable failure inflating file.");
        }

        if search_sig(png_vec, PDV_SIG, 0).is_none() {
            bail!("Image File Error: This is not a pdvrdt image.");
        }
    }

    let result = decrypt_data_file(png_vec, location.is_mastodon)?;
    let decrypted_filename = match result {
        Some(name) => name,
        None => bail!("File Recovery Error: Invalid PIN or file is corrupt."),
    };

    zlib_inflate(png_vec)?;

    if png_vec.is_empty() {
        bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
    }

    std::fs::write(&decrypted_filename, &png_vec)?;

    println!(
        "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
        decrypted_filename,
        png_vec.len()
    );

    Ok(())
}
