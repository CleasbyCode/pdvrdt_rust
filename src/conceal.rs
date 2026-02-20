use crate::binary_io::update_value;
use crate::common::{Option_, PLATFORM_LIMITS};
use crate::compression::zlib_deflate;
use crate::encryption::encrypt_data_file;
use crate::file_utils::{has_file_extension, read_file};
use crate::image::optimize_image;
use anyhow::{bail, Result};
use sodiumoxide::randombytes::randombytes_uniform;
use std::path::Path;

// Profile template for default mode: data stored in a custom IDAT chunk.
const DEFAULT_PROFILE: &[u8] = &[
    0x75, 0x5D, 0x19, 0x3D, 0x72, 0xCE, 0x28, 0xA5, 0x60, 0x59, 0x17, 0x98, 0x13, 0x40, 0xB4, 0xDB,
    0x3D, 0x18, 0xEC, 0x10, 0xFA, 0xE8, 0xA1, 0xC3, 0x99, 0xD1, 0xCC, 0x34, 0x72, 0xA3, 0xC5, 0xB1,
    0xEF, 0xF6, 0x12, 0x18, 0x26, 0xF3, 0xAF, 0x77, 0x16, 0x44, 0x95, 0xEA, 0xBB, 0x27, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9, 0x90, 0x82,
];

// ICC color profile template for Mastodon mode: data stored in an iCCP chunk.
const MASTODON_PROFILE: &[u8] = &[
    0x00, 0x00, 0x02, 0x98, 0x6C, 0x63, 0x6D, 0x73, 0x02, 0x10, 0x00, 0x00, 0x6D, 0x6E, 0x74, 0x72,
    0x52, 0x47, 0x42, 0x20, 0x58, 0x59, 0x5A, 0x20, 0x07, 0xE2, 0x00, 0x03, 0x00, 0x14, 0x00, 0x09,
    0x00, 0x0E, 0x00, 0x1D, 0x61, 0x63, 0x73, 0x70, 0x4D, 0x53, 0x46, 0x54, 0x00, 0x00, 0x00, 0x00,
    0x73, 0x61, 0x77, 0x73, 0x63, 0x74, 0x72, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xD6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xD3, 0x2D,
    0x68, 0x61, 0x6E, 0x64, 0xEB, 0x77, 0x1F, 0x3C, 0xAA, 0x53, 0x51, 0x02, 0xE9, 0x3E, 0x28, 0x6C,
    0x91, 0x46, 0xAE, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09, 0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x1C,
    0x77, 0x74, 0x70, 0x74, 0x00, 0x00, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x14, 0x72, 0x58, 0x59, 0x5A,
    0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x14, 0x67, 0x58, 0x59, 0x5A, 0x00, 0x00, 0x01, 0x34,
    0x00, 0x00, 0x00, 0x14, 0x62, 0x58, 0x59, 0x5A, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00, 0x00, 0x14,
    0x72, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x34, 0x67, 0x54, 0x52, 0x43,
    0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x34, 0x62, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0x5C,
    0x00, 0x00, 0x00, 0x34, 0x63, 0x70, 0x72, 0x74, 0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x01,
    0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x6E, 0x52, 0x47, 0x42,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x59, 0x5A, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x16, 0xC9,
    0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6F, 0xA0, 0x00, 0x00, 0x38, 0xF2,
    0x00, 0x00, 0x03, 0x8F, 0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x96,
    0x00, 0x00, 0xB7, 0x89, 0x00, 0x00, 0x18, 0xDA, 0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x24, 0xA0, 0x00, 0x00, 0x0F, 0x85, 0x00, 0x00, 0xB6, 0xC4, 0x63, 0x75, 0x72, 0x76,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x07, 0x02, 0xB5, 0x05, 0x6B,
    0x09, 0x36, 0x0E, 0x50, 0x14, 0xB1, 0x1C, 0x80, 0x25, 0xC8, 0x30, 0xA1, 0x3D, 0x19, 0x4B, 0x40,
    0x5B, 0x27, 0x6C, 0xDB, 0x80, 0x6B, 0x95, 0xE3, 0xAD, 0x50, 0xC6, 0xC2, 0xE2, 0x31, 0xFF, 0xFF,
    0x00, 0x12, 0xB7, 0x19, 0x18, 0xA4, 0xEF, 0x15, 0x8F, 0x9E, 0x7B, 0xB4, 0xF3, 0xAA, 0x0A, 0x5C,
    0x80, 0x54, 0xAF, 0xC8, 0x0E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9, 0x90,
];

fn validate_inputs(combined_size: usize, data_filename: &str, option: Option_) -> Result<()> {
    const MAX_SIZE_DEFAULT: usize = 2 * 1024 * 1024 * 1024;
    const MAX_SIZE_REDDIT: usize = 20 * 1024 * 1024;
    const MAX_SIZE_MASTODON: usize = 16 * 1024 * 1024;
    const FILENAME_MAX_LEN: usize = 20;

    if data_filename.len() > FILENAME_MAX_LEN {
        bail!("Data File Error: For compatibility requirements, length of data filename must not exceed 20 characters.");
    }

    let (limit, label) = match option {
        Option_::Mastodon => (MAX_SIZE_MASTODON, "Mastodon"),
        Option_::Reddit => (MAX_SIZE_REDDIT, "Reddit"),
        Option_::None => (MAX_SIZE_DEFAULT, "pdvrdt"),
    };

    if combined_size > limit {
        bail!(
            "File Size Error: Combined size of image and data file exceeds maximum size limit for {}.",
            label
        );
    }

    Ok(())
}

fn build_iccp_chunk(profile_vec: &[u8]) -> Result<Vec<u8>> {
    const CHUNK_SIZE_INDEX: usize = 0;
    const CHUNK_START: usize = 4;
    const PROFILE_INDEX: usize = 0x0D;
    const SIZE_DIFF: usize = 5;

    // iCCP chunk shell: length(4) + "iCCP" + "icc\0" + compression_method(0)
    let shell: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x69, 0x43, 0x43, 0x50, 0x69, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let mut iccp = Vec::with_capacity(shell.len() + profile_vec.len() + 4);
    iccp.extend_from_slice(&shell[..PROFILE_INDEX]);
    iccp.extend_from_slice(profile_vec);
    iccp.extend_from_slice(&shell[PROFILE_INDEX..]);

    let chunk_data_size = profile_vec.len() + SIZE_DIFF;
    update_value(&mut iccp, CHUNK_SIZE_INDEX, chunk_data_size, 4)?;

    let crc_data = &iccp[CHUNK_START..CHUNK_START + chunk_data_size + 4];
    let crc = crc32fast::hash(crc_data) as usize;
    let crc_index = CHUNK_START + chunk_data_size + 4;
    update_value(&mut iccp, crc_index, crc, 4)?;

    Ok(iccp)
}

fn build_idat_chunk(profile_vec: &[u8]) -> Result<Vec<u8>> {
    const CHUNK_SIZE_INDEX: usize = 0;
    const CHUNK_START: usize = 4;
    const PROFILE_INDEX: usize = 0x0B;
    const SIZE_DIFF: usize = 3;
    const CRC_FIELD_SIZE: usize = 4;

    // IDAT chunk shell: length(4) + "IDAT" + zlib_header(78 5E 5C)
    let shell: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x41, 0x54, 0x78, 0x5E, 0x5C, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut idat = Vec::with_capacity(shell.len() + profile_vec.len() + 4);
    idat.extend_from_slice(&shell[..PROFILE_INDEX]);
    idat.extend_from_slice(profile_vec);
    idat.extend_from_slice(&shell[PROFILE_INDEX..]);

    let chunk_data_size = profile_vec.len() + SIZE_DIFF;
    update_value(&mut idat, CHUNK_SIZE_INDEX, chunk_data_size, 4)?;

    let crc_data = &idat[CHUNK_START..CHUNK_START + chunk_data_size + CRC_FIELD_SIZE];
    let crc = crc32fast::hash(crc_data) as usize;
    let crc_index = chunk_data_size + CHUNK_START + CRC_FIELD_SIZE;
    update_value(&mut idat, crc_index, crc, 4)?;

    Ok(idat)
}

fn insert_reddit_padding(png_vec: &mut Vec<u8>) {
    const INSERT_INDEX_DIFF: usize = 12;
    const IDAT_REDDIT_CRC: [u8; 4] = [0xA3, 0x1A, 0x50, 0xFA];

    // 524288-byte empty IDAT chunk for Reddit compatibility.
    let mut reddit_chunk = vec![0x00, 0x08, 0x00, 0x00, 0x49, 0x44, 0x41, 0x54];
    reddit_chunk.resize(reddit_chunk.len() + 0x80000, 0x00);
    reddit_chunk.extend_from_slice(&IDAT_REDDIT_CRC);

    let insert_pos = png_vec.len() - INSERT_INDEX_DIFF;
    let tail = png_vec[insert_pos..].to_vec();
    png_vec.truncate(insert_pos);
    png_vec.extend_from_slice(&reddit_chunk);
    png_vec.extend_from_slice(&tail);
}

fn get_compatible_platforms(
    option: Option_,
    output_size: usize,
    has_bad_dims: bool,
    twitter_iccp_compatible: bool,
) -> Vec<String> {
    if option == Option_::Reddit {
        return vec![
            "Reddit. (Only share this \"file-embedded\" PNG image on Reddit).".to_string(),
        ];
    }

    if option == Option_::Mastodon {
        if twitter_iccp_compatible && !has_bad_dims {
            return vec!["Mastodon and X-Twitter.".to_string()];
        }
        return vec![
            "Mastodon. (Only share this \"file-embedded\" PNG image on Mastodon).".to_string(),
        ];
    }

    let mut platforms: Vec<String> = Vec::new();
    for p in PLATFORM_LIMITS {
        if output_size <= p.max_size && (!p.requires_good_dims || !has_bad_dims) {
            platforms.push(p.name.to_string());
        }
    }

    if platforms.is_empty() {
        platforms.push(
            "Unknown!\n\n Due to the large file size of the output PNG image, I'm unaware of any\n\
             compatible platforms that this image can be posted on. Local use only?"
                .to_string(),
        );
    }

    platforms
}

fn write_output_file(png_vec: &[u8], pin: usize) -> Result<()> {
    let rand_num = 100000 + randombytes_uniform(900000);
    let output_filename = format!("prdt_{}.png", rand_num);

    std::fs::write(&output_filename, png_vec)?;

    println!(
        "\nSaved \"file-embedded\" PNG image: {} ({} bytes).",
        output_filename,
        png_vec.len()
    );
    println!(
        "\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n\nComplete!\n",
        pin
    );

    Ok(())
}

pub fn conceal_data(png_vec: &mut Vec<u8>, option: Option_, data_file_path: &Path) -> Result<()> {
    const LARGE_FILE_SIZE: usize = 300 * 1024 * 1024;
    const MASTODON_INSERT_INDEX: usize = 0x21;
    const DEFAULT_INSERT_DIFF: usize = 12;
    const FILENAME_LEN_MASTODON: usize = 0x191;
    const FILENAME_LEN_DEFAULT: usize = 0x00;

    let is_mastodon = option == Option_::Mastodon;
    let is_reddit = option == Option_::Reddit;

    let mut data_vec = read_file(data_file_path, crate::common::FileTypeCheck::DataFile)?;

    if data_vec.len() > LARGE_FILE_SIZE {
        println!("\nPlease wait. Larger files will take longer to complete this process.");
    }

    let image_result = optimize_image(png_vec)?;

    let data_filename = data_file_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file")
        .to_string();

    validate_inputs(data_vec.len() + png_vec.len(), &data_filename, option)?;

    let is_compressed = has_file_extension(
        data_file_path,
        &[
            ".zip", ".jar", ".rar", ".7z", ".bz2", ".gz", ".xz", ".tar", ".lz", ".lz4", ".cab",
            ".rpm", ".deb", ".mp4", ".mp3", ".exe", ".jpg", ".jpeg", ".jfif", ".png", ".webp",
            ".bmp", ".gif", ".ogg", ".flac",
        ],
    );

    // Prepare the profile template.
    let mut profile_vec = if is_mastodon {
        MASTODON_PROFILE.to_vec()
    } else {
        DEFAULT_PROFILE.to_vec()
    };

    let filename_len_index = if is_mastodon {
        FILENAME_LEN_MASTODON
    } else {
        FILENAME_LEN_DEFAULT
    };
    profile_vec[filename_len_index] = data_filename.len() as u8;

    // Compress the data file.
    zlib_deflate(&mut data_vec, option, is_compressed)?;

    if data_vec.is_empty() {
        bail!("File Size Error: File is zero bytes. Probable compression failure.");
    }

    // Encrypt and embed data into the profile.
    let pin = encrypt_data_file(&mut profile_vec, &mut data_vec, &data_filename, is_mastodon)?;

    // Insert Reddit padding IDAT if needed.
    if is_reddit {
        insert_reddit_padding(png_vec);
    }

    // Compress profile for Mastodon (iCCP requires deflated ICC data).
    if is_mastodon {
        zlib_deflate(&mut profile_vec, option, is_compressed)?;
    }

    // Build and insert the appropriate PNG chunk.
    let mut twitter_iccp_compatible = false;

    if is_mastodon {
        const TWITTER_ICCP_MAX_CHUNK_SIZE: usize = 10 * 1024;
        const TWITTER_IMAGE_MAX_SIZE: usize = 5 * 1024 * 1024;
        const ICCP_SIZE_DIFF: usize = 5;

        let mastodon_chunk_size = profile_vec.len() + ICCP_SIZE_DIFF;

        let iccp_chunk = build_iccp_chunk(&profile_vec)?;
        let tail = png_vec[MASTODON_INSERT_INDEX..].to_vec();
        png_vec.truncate(MASTODON_INSERT_INDEX);
        png_vec.extend_from_slice(&iccp_chunk);
        png_vec.extend_from_slice(&tail);

        twitter_iccp_compatible =
            png_vec.len() <= TWITTER_IMAGE_MAX_SIZE && mastodon_chunk_size <= TWITTER_ICCP_MAX_CHUNK_SIZE;
    } else {
        let idat_chunk = build_idat_chunk(&profile_vec)?;
        let insert_index = png_vec.len() - DEFAULT_INSERT_DIFF;
        let tail = png_vec[insert_index..].to_vec();
        png_vec.truncate(insert_index);
        png_vec.extend_from_slice(&idat_chunk);
        png_vec.extend_from_slice(&tail);
    }

    // Determine platform compatibility and write output.
    let platforms = get_compatible_platforms(
        option,
        png_vec.len(),
        image_result.has_bad_dims,
        twitter_iccp_compatible,
    );

    println!("\nPlatform compatibility for output image:-\n");
    for platform in &platforms {
        println!(" \u{2713} {}", platform);
    }
    write_output_file(png_vec, pin)?;

    Ok(())
}
