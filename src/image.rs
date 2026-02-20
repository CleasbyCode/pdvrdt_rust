use crate::binary_io::{get_value, search_sig};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Cursor;

pub struct ImageCheckResult {
    pub has_bad_dims: bool,
}

const INDEXED_PLTE: u8 = 3;
const TRUECOLOR_RGB: u8 = 2;
const TRUECOLOR_RGBA: u8 = 6;

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> Result<ImageCheckResult> {
    const MIN_DIMS: u32 = 68;
    const MAX_PLTE_DIMS: u32 = 4096;
    const MAX_RGB_DIMS: u32 = 900;
    const MIN_RGB_COLORS: usize = 257;

    // Decode the PNG to get raw pixel data.
    let decoder = png::Decoder::new(Cursor::new(&image_file_vec));
    let mut reader = decoder.read_info()?;
    let info = reader.info().clone();

    let width = info.width;
    let height = info.height;
    let color_type = info.color_type;
    let mut image = vec![0u8; reader.output_buffer_size()];
    let output_info = reader.next_frame(&mut image)?;
    image.truncate(output_info.buffer_size());

    let check_dims = |max_dim: u32| -> bool {
        width < MIN_DIMS || height < MIN_DIMS || width > max_dim || height > max_dim
    };

    // Determine color type as raw byte value.
    let color_type_byte = match color_type {
        png::ColorType::Grayscale => 0,
        png::ColorType::Rgb => TRUECOLOR_RGB,
        png::ColorType::Indexed => INDEXED_PLTE,
        png::ColorType::GrayscaleAlpha => 4,
        png::ColorType::Rgba => TRUECOLOR_RGBA,
    };

    let is_truecolor = color_type_byte == TRUECOLOR_RGB || color_type_byte == TRUECOLOR_RGBA;

    // Count unique colors to decide if palette conversion is beneficial.
    if is_truecolor {
        let channels: usize = if color_type_byte == TRUECOLOR_RGBA { 4 } else { 3 };
        let pixel_count = (width as usize) * (height as usize);
        let mut unique_colors: HashMap<u32, u8> = HashMap::new();

        for i in 0..pixel_count {
            let offset = i * channels;
            let key = if channels == 4 {
                (image[offset] as u32) << 24
                    | (image[offset + 1] as u32) << 16
                    | (image[offset + 2] as u32) << 8
                    | image[offset + 3] as u32
            } else {
                (image[offset] as u32) << 24
                    | (image[offset + 1] as u32) << 16
                    | (image[offset + 2] as u32) << 8
                    | 255u32
            };
            if unique_colors.len() >= MIN_RGB_COLORS && !unique_colors.contains_key(&key) {
                break;
            }
            unique_colors.entry(key).or_insert(0);
        }

        if unique_colors.len() < MIN_RGB_COLORS {
            convert_to_palette(image_file_vec, &image, width, height, &unique_colors, channels)?;
            return Ok(ImageCheckResult {
                has_bad_dims: check_dims(MAX_PLTE_DIMS),
            });
        }
    }

    strip_and_copy_chunks(image_file_vec, color_type_byte)?;
    Ok(ImageCheckResult {
        has_bad_dims: check_dims(MAX_RGB_DIMS),
    })
}

fn convert_to_palette(
    image_file_vec: &mut Vec<u8>,
    image: &[u8],
    width: u32,
    height: u32,
    unique_colors: &HashMap<u32, u8>,
    channels: usize,
) -> Result<()> {
    const MAX_PALETTE_SIZE: usize = 256;

    let palette_size = unique_colors.len();
    if palette_size == 0 {
        bail!("convertToPalette: Palette is empty.");
    }
    if palette_size > MAX_PALETTE_SIZE {
        bail!(
            "convertToPalette: Palette has {} colors, exceeds maximum of {}.",
            palette_size,
            MAX_PALETTE_SIZE
        );
    }

    // Build palette (RGBA entries) and color-to-index map.
    let mut palette_rgba: Vec<u8> = Vec::with_capacity(palette_size * 4);
    let mut color_to_index: HashMap<u32, u8> = HashMap::with_capacity(palette_size);
    let mut idx: u8 = 0;

    for &key in unique_colors.keys() {
        let r = ((key >> 24) & 0xFF) as u8;
        let g = ((key >> 16) & 0xFF) as u8;
        let b = ((key >> 8) & 0xFF) as u8;
        let a = (key & 0xFF) as u8;
        palette_rgba.extend_from_slice(&[r, g, b, a]);
        color_to_index.insert(key, idx);
        idx += 1;
    }

    // Map each pixel to its palette index.
    let pixel_count = (width as usize) * (height as usize);
    let mut indexed_image = vec![0u8; pixel_count];

    for i in 0..pixel_count {
        let offset = i * channels;
        let key = if channels == 4 {
            (image[offset] as u32) << 24
                | (image[offset + 1] as u32) << 16
                | (image[offset + 2] as u32) << 8
                | image[offset + 3] as u32
        } else {
            (image[offset] as u32) << 24
                | (image[offset + 1] as u32) << 16
                | (image[offset + 2] as u32) << 8
                | 255u32
        };
        indexed_image[i] = *color_to_index
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("Pixel {} has color not found in palette.", i))?;
    }

    // Encode as 8-bit palette PNG.
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), width, height);
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(png::BitDepth::Eight);

        // Build separate palette (RGB) and trns (alpha) arrays.
        let mut plte = Vec::with_capacity(palette_size * 3);
        let mut trns = Vec::with_capacity(palette_size);
        let mut has_transparency = false;

        for i in 0..palette_size {
            plte.push(palette_rgba[i * 4]);
            plte.push(palette_rgba[i * 4 + 1]);
            plte.push(palette_rgba[i * 4 + 2]);
            let alpha = palette_rgba[i * 4 + 3];
            trns.push(alpha);
            if alpha != 255 {
                has_transparency = true;
            }
        }

        encoder.set_palette(plte);
        if has_transparency {
            encoder.set_trns(trns);
        }

        let mut writer = encoder.write_header()?;
        writer.write_image_data(&indexed_image)?;
        writer.finish()?;
    }

    *image_file_vec = output;
    Ok(())
}

fn strip_and_copy_chunks(image_file_vec: &mut Vec<u8>, color_type: u8) -> Result<()> {
    const PLTE_SIG: &[u8] = &[0x50, 0x4C, 0x54, 0x45];
    const TRNS_SIG: &[u8] = &[0x74, 0x52, 0x4E, 0x53];
    const IDAT_SIG: &[u8] = &[0x49, 0x44, 0x41, 0x54];
    const IEND_SIG: &[u8] = &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    const PDVRDT_IDAT_SIG: &[u8] = &[0x78, 0x5E, 0x5C];

    const PNG_HEADER_AND_IHDR_SIZE: usize = 33;
    const CHUNK_OVERHEAD: usize = 12;
    const LENGTH_FIELD_SIZE: usize = 4;
    const IEND_CHUNK_SIZE: usize = 12;

    let file_size = image_file_vec.len();

    if file_size < PNG_HEADER_AND_IHDR_SIZE + IEND_CHUNK_SIZE {
        bail!("PNG Error: File too small to contain valid PNG structure.");
    }

    // Truncate any trailing data after IEND.
    if let Some(pos) = search_sig(image_file_vec, IEND_SIG, 0) {
        let end_index = pos + IEND_SIG.len();
        if end_index <= file_size {
            image_file_vec.truncate(end_index);
        }
    }

    let mut cleaned_png = Vec::with_capacity(image_file_vec.len());

    // Copy PNG signature + IHDR chunk.
    cleaned_png.extend_from_slice(&image_file_vec[..PNG_HEADER_AND_IHDR_SIZE]);

    // Copy all chunks of a given type.
    let mut copy_chunks_of_type = |chunk_sig: &[u8]| -> Result<()> {
        let mut search_pos = PNG_HEADER_AND_IHDR_SIZE;

        while let Some(name_index) = search_sig(image_file_vec, chunk_sig, search_pos) {
            if name_index < LENGTH_FIELD_SIZE {
                bail!("PNG Error: Chunk found before valid length field.");
            }

            let chunk_start = name_index - LENGTH_FIELD_SIZE;
            let data_length = get_value(image_file_vec, chunk_start, 4)?;
            let total_chunk_size = data_length + CHUNK_OVERHEAD;

            // Skip pdvrdt steganographic IDAT chunks.
            let payload_start = name_index + 4;
            if payload_start + PDVRDT_IDAT_SIG.len() <= image_file_vec.len()
                && &image_file_vec[payload_start..payload_start + PDVRDT_IDAT_SIG.len()]
                    == PDVRDT_IDAT_SIG
            {
                break;
            }

            if chunk_start + total_chunk_size > image_file_vec.len() {
                bail!(
                    "PNG Error: Chunk at offset 0x{:X} claims length {} but exceeds file size.",
                    chunk_start,
                    data_length
                );
            }

            cleaned_png.extend_from_slice(
                &image_file_vec[chunk_start..chunk_start + total_chunk_size],
            );

            search_pos = chunk_start + total_chunk_size;
        }
        Ok(())
    };

    if color_type == INDEXED_PLTE {
        copy_chunks_of_type(PLTE_SIG)?;
    }
    copy_chunks_of_type(TRNS_SIG)?;
    copy_chunks_of_type(IDAT_SIG)?;

    // Append IEND chunk.
    let file_len = image_file_vec.len();
    cleaned_png.extend_from_slice(&image_file_vec[file_len - IEND_CHUNK_SIZE..]);

    *image_file_vec = cleaned_png;
    Ok(())
}
