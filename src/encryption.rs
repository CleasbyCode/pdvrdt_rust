use crate::pin_input::get_pin;
use anyhow::{anyhow, bail, Result};
use sodiumoxide::crypto::pwhash::argon2id13 as pwhash;
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as secretstream;
use sodiumoxide::randombytes;
use sodiumoxide::randombytes::randombytes_into;
use zeroize::Zeroize;

pub struct ProfileOffsets {
    pub kdf_metadata: usize,
    pub encrypted_file: usize,
}

pub const MASTODON_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x1BE,
    encrypted_file: 0x1FE,
};

pub const DEFAULT_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x02D,
    encrypted_file: 0x06E,
};

pub const KDF_METADATA_REGION_BYTES: usize = 56;
pub const KDF_MAGIC_OFFSET: usize = 0;
pub const KDF_ALG_OFFSET: usize = 4;
pub const KDF_SENTINEL_OFFSET: usize = 5;
pub const KDF_SALT_OFFSET: usize = 8;
pub const KDF_NONCE_OFFSET: usize = 24;

pub const KDF_ALG_ARGON2ID13: u8 = 1;
pub const KDF_SENTINEL: u8 = 0xA5;

const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
const STREAM_FRAME_LEN_BYTES: usize = 4;
const KDF_METADATA_MAGIC_V2: &[u8; 4] = b"KDF2";

#[derive(Clone, Copy, PartialEq, Eq)]
enum KdfMetadataVersion {
    None,
    V2Secretstream,
}

fn span_has_range(data: &[u8], index: usize, length: usize) -> bool {
    index <= data.len() && length <= data.len().saturating_sub(index)
}

fn require_span_range(data: &[u8], index: usize, length: usize, message: &str) -> Result<()> {
    if !span_has_range(data, index, length) {
        bail!("{}", message);
    }
    Ok(())
}

fn compute_stream_encrypted_size(plaintext_size: usize) -> Result<usize> {
    let chunks = if plaintext_size == 0 {
        1usize
    } else {
        ((plaintext_size - 1) / STREAM_CHUNK_SIZE) + 1
    };

    let per_chunk_overhead = STREAM_FRAME_LEN_BYTES
        .checked_add(secretstream::ABYTES)
        .ok_or_else(|| anyhow!("Data File Error: Data file too large to encrypt."))?;

    let base = secretstream::HEADERBYTES
        .checked_add(plaintext_size)
        .ok_or_else(|| anyhow!("Data File Error: Data file too large to encrypt."))?;

    let chunk_overhead = chunks
        .checked_mul(per_chunk_overhead)
        .ok_or_else(|| anyhow!("Data File Error: Data file too large to encrypt."))?;

    base.checked_add(chunk_overhead)
        .ok_or_else(|| anyhow!("Data File Error: Data file too large to encrypt."))
}

fn write_frame_len(out: &mut Vec<u8>, frame_len: u32) {
    out.extend_from_slice(&frame_len.to_be_bytes());
}

fn read_frame_len(data: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(
        data[index..index + STREAM_FRAME_LEN_BYTES]
            .try_into()
            .unwrap(),
    )
}

fn derive_key_from_pin(
    pin: usize,
    salt_bytes: &[u8; pwhash::SALTBYTES],
) -> Result<secretstream::Key> {
    let mut pin_buf = pin.to_string().into_bytes();
    let salt = pwhash::Salt::from_slice(salt_bytes)
        .ok_or_else(|| anyhow!("KDF Error: Invalid salt length."))?;

    let mut key_bytes = [0u8; secretstream::KEYBYTES];
    pwhash::derive_key(
        &mut key_bytes,
        &pin_buf,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| anyhow!("KDF Error: Unable to derive encryption key."))?;

    pin_buf.zeroize();
    let key = secretstream::Key::from_slice(&key_bytes)
        .ok_or_else(|| anyhow!("KDF Error: Invalid derived key length."))?;
    key_bytes.zeroize();
    Ok(key)
}

fn encrypt_with_secretstream(
    plaintext: &mut Vec<u8>,
    key: &secretstream::Key,
) -> Result<[u8; secretstream::HEADERBYTES]> {
    let (mut stream, header) = secretstream::Stream::init_push(key)
        .map_err(|_| anyhow!("crypto_secretstream init_push failed."))?;

    let mut encrypted = Vec::with_capacity(compute_stream_encrypted_size(plaintext.len())?);
    encrypted.extend_from_slice(&header.0);

    let mut offset = 0usize;
    let mut emitted_final = false;

    while !emitted_final {
        let remaining = plaintext.len().saturating_sub(offset);
        let chunk_len = remaining.min(STREAM_CHUNK_SIZE);
        let is_final = offset + chunk_len == plaintext.len();
        let tag = if is_final {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        };

        let chunk = &plaintext[offset..offset + chunk_len];
        let cipher_chunk = stream
            .push(chunk, None, tag)
            .map_err(|_| anyhow!("crypto_secretstream push failed."))?;

        if cipher_chunk.len() > u32::MAX as usize {
            bail!("crypto_secretstream frame too large.");
        }
        write_frame_len(&mut encrypted, cipher_chunk.len() as u32);
        encrypted.extend_from_slice(&cipher_chunk);

        offset += chunk_len;
        emitted_final = is_final;
    }

    if !plaintext.is_empty() {
        plaintext.zeroize();
    }
    *plaintext = encrypted;
    Ok(header.0)
}

fn decrypt_with_secretstream(
    framed_ciphertext: &mut Vec<u8>,
    key: &secretstream::Key,
    header_bytes: &[u8; secretstream::HEADERBYTES],
) -> bool {
    let header = match secretstream::Header::from_slice(header_bytes) {
        Some(h) => h,
        None => return false,
    };

    let mut stream = match secretstream::Stream::init_pull(&header, key) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut decrypted = Vec::with_capacity(framed_ciphertext.len());
    let mut offset = 0usize;
    let mut has_final_tag = false;

    while offset < framed_ciphertext.len() {
        if framed_ciphertext.len() - offset < STREAM_FRAME_LEN_BYTES {
            return false;
        }

        let frame_len = read_frame_len(framed_ciphertext, offset) as usize;
        offset += STREAM_FRAME_LEN_BYTES;

        if frame_len < secretstream::ABYTES
            || frame_len > framed_ciphertext.len().saturating_sub(offset)
        {
            return false;
        }

        let frame = &framed_ciphertext[offset..offset + frame_len];
        let (plain_chunk, tag) = match stream.pull(frame, None) {
            Ok(v) => v,
            Err(_) => return false,
        };
        decrypted.extend_from_slice(&plain_chunk);

        offset += frame_len;
        if tag == secretstream::Tag::Final {
            has_final_tag = true;
            break;
        }
    }

    if !has_final_tag || offset != framed_ciphertext.len() {
        return false;
    }

    if !framed_ciphertext.is_empty() {
        framed_ciphertext.zeroize();
    }
    *framed_ciphertext = decrypted;
    true
}

fn generate_recovery_pin() -> usize {
    let mut pin = 0usize;
    while pin == 0 {
        let mut pin_bytes = [0u8; 8];
        randombytes_into(&mut pin_bytes);
        pin = u64::from_ne_bytes(pin_bytes) as usize;
    }
    pin
}

fn extract_filename_prefix(payload: &mut Vec<u8>) -> Result<String> {
    const CORRUPT_FILE_ERROR: &str = "File Recovery Error: Embedded profile is corrupt.";
    if payload.is_empty() {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    let filename_len = payload[0] as usize;
    if filename_len == 0 {
        bail!("{}", CORRUPT_FILE_ERROR);
    }
    let prefix_len = 1 + filename_len;
    require_span_range(payload, 0, prefix_len, CORRUPT_FILE_ERROR)?;

    let filename = String::from_utf8(payload[1..prefix_len].to_vec())
        .map_err(|_| anyhow!(CORRUPT_FILE_ERROR))?;

    if payload.len() > prefix_len {
        payload.copy_within(prefix_len.., 0);
    }
    payload.truncate(payload.len() - prefix_len);
    Ok(filename)
}

fn get_kdf_metadata_version(data: &[u8], base_index: usize) -> KdfMetadataVersion {
    if !span_has_range(data, base_index, KDF_METADATA_REGION_BYTES) {
        return KdfMetadataVersion::None;
    }

    let has_common_fields = data[base_index + KDF_ALG_OFFSET] == KDF_ALG_ARGON2ID13
        && data[base_index + KDF_SENTINEL_OFFSET] == KDF_SENTINEL;
    if !has_common_fields {
        return KdfMetadataVersion::None;
    }

    if data
        [base_index + KDF_MAGIC_OFFSET..base_index + KDF_MAGIC_OFFSET + KDF_METADATA_MAGIC_V2.len()]
        == *KDF_METADATA_MAGIC_V2
    {
        KdfMetadataVersion::V2Secretstream
    } else {
        KdfMetadataVersion::None
    }
}

pub fn encrypt_data_file(
    profile_vec: &mut Vec<u8>,
    data_vec: &mut Vec<u8>,
    data_filename: &str,
    has_mastodon_option: bool,
) -> Result<usize> {
    let offsets = if has_mastodon_option {
        &MASTODON_OFFSETS
    } else {
        &DEFAULT_OFFSETS
    };
    const CORRUPT_PROFILE_ERROR: &str = "Internal Error: Corrupt profile template.";

    require_span_range(
        profile_vec,
        offsets.kdf_metadata,
        KDF_METADATA_REGION_BYTES,
        CORRUPT_PROFILE_ERROR,
    )?;
    if offsets.encrypted_file != profile_vec.len() {
        bail!("{}", CORRUPT_PROFILE_ERROR);
    }

    if data_filename.is_empty() || data_filename.len() > u8::MAX as usize {
        bail!("Data File Error: Invalid data filename length.");
    }

    let prefix_len = 1usize
        .checked_add(data_filename.len())
        .ok_or_else(|| anyhow!("Data File Error: Data file too large to encrypt."))?;
    if data_vec.len() > usize::MAX - prefix_len {
        bail!("Data File Error: Data file too large to encrypt.");
    }

    // Prefix plaintext with [filename_len][filename] in-place to PIN-protect both name and payload.
    let payload_size = data_vec.len();
    data_vec.resize(payload_size + prefix_len, 0);
    if payload_size > 0 {
        data_vec.copy_within(0..payload_size, prefix_len);
    }
    data_vec[0] = data_filename.len() as u8;
    data_vec[1..1 + data_filename.len()].copy_from_slice(data_filename.as_bytes());

    let pin = generate_recovery_pin();
    let salt_vec = randombytes::randombytes(pwhash::SALTBYTES);
    let mut salt = [0u8; pwhash::SALTBYTES];
    salt.copy_from_slice(&salt_vec);

    let key = derive_key_from_pin(pin, &salt)?;
    let stream_header = encrypt_with_secretstream(data_vec, &key)?;

    profile_vec.reserve(data_vec.len());
    profile_vec.extend_from_slice(data_vec);
    data_vec.clear();

    // Write KDF metadata into the fixed 56-byte region.
    let random_region = randombytes::randombytes(KDF_METADATA_REGION_BYTES);
    profile_vec[offsets.kdf_metadata..offsets.kdf_metadata + KDF_METADATA_REGION_BYTES]
        .copy_from_slice(&random_region);

    profile_vec
        [offsets.kdf_metadata + KDF_MAGIC_OFFSET..offsets.kdf_metadata + KDF_MAGIC_OFFSET + 4]
        .copy_from_slice(KDF_METADATA_MAGIC_V2);
    profile_vec[offsets.kdf_metadata + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
    profile_vec[offsets.kdf_metadata + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;

    require_span_range(
        profile_vec,
        offsets.kdf_metadata + KDF_SALT_OFFSET,
        pwhash::SALTBYTES,
        CORRUPT_PROFILE_ERROR,
    )?;
    require_span_range(
        profile_vec,
        offsets.kdf_metadata + KDF_NONCE_OFFSET,
        secretstream::HEADERBYTES,
        CORRUPT_PROFILE_ERROR,
    )?;

    profile_vec[offsets.kdf_metadata + KDF_SALT_OFFSET
        ..offsets.kdf_metadata + KDF_SALT_OFFSET + pwhash::SALTBYTES]
        .copy_from_slice(&salt);
    profile_vec[offsets.kdf_metadata + KDF_NONCE_OFFSET
        ..offsets.kdf_metadata + KDF_NONCE_OFFSET + secretstream::HEADERBYTES]
        .copy_from_slice(&stream_header);

    Ok(pin)
}

pub fn decrypt_data_file(png_vec: &mut Vec<u8>, is_mastodon_file: bool) -> Result<Option<String>> {
    let offsets = if is_mastodon_file {
        &MASTODON_OFFSETS
    } else {
        &DEFAULT_OFFSETS
    };

    const CORRUPT_FILE_ERROR: &str = "File Recovery Error: Embedded profile is corrupt.";
    require_span_range(
        png_vec,
        offsets.kdf_metadata,
        KDF_METADATA_REGION_BYTES,
        CORRUPT_FILE_ERROR,
    )?;
    if offsets.encrypted_file > png_vec.len() {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    if get_kdf_metadata_version(png_vec, offsets.kdf_metadata) != KdfMetadataVersion::V2Secretstream
    {
        bail!(
            "File Decryption Error: Unsupported legacy encrypted file format. Use an older pdvrdt release to recover this file."
        );
    }

    let recovery_pin = get_pin();
    let mut salt = [0u8; pwhash::SALTBYTES];
    let mut stream_header = [0u8; secretstream::HEADERBYTES];

    require_span_range(
        png_vec,
        offsets.kdf_metadata + KDF_SALT_OFFSET,
        pwhash::SALTBYTES,
        CORRUPT_FILE_ERROR,
    )?;
    require_span_range(
        png_vec,
        offsets.kdf_metadata + KDF_NONCE_OFFSET,
        secretstream::HEADERBYTES,
        CORRUPT_FILE_ERROR,
    )?;

    salt.copy_from_slice(
        &png_vec[offsets.kdf_metadata + KDF_SALT_OFFSET
            ..offsets.kdf_metadata + KDF_SALT_OFFSET + pwhash::SALTBYTES],
    );
    stream_header.copy_from_slice(
        &png_vec[offsets.kdf_metadata + KDF_NONCE_OFFSET
            ..offsets.kdf_metadata + KDF_NONCE_OFFSET + secretstream::HEADERBYTES],
    );

    let key = derive_key_from_pin(recovery_pin, &salt)?;

    let ciphertext_length = png_vec.len() - offsets.encrypted_file;
    let min_stream_cipher_size = secretstream::HEADERBYTES
        .checked_add(STREAM_FRAME_LEN_BYTES)
        .and_then(|v| v.checked_add(secretstream::ABYTES))
        .ok_or_else(|| anyhow!(CORRUPT_FILE_ERROR))?;
    if ciphertext_length < min_stream_cipher_size {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    if offsets.encrypted_file != 0 {
        png_vec.copy_within(offsets.encrypted_file.., 0);
    }
    png_vec.truncate(ciphertext_length);

    require_span_range(png_vec, 0, secretstream::HEADERBYTES, CORRUPT_FILE_ERROR)?;
    let mut embedded_header = [0u8; secretstream::HEADERBYTES];
    embedded_header.copy_from_slice(&png_vec[..secretstream::HEADERBYTES]);
    png_vec.copy_within(secretstream::HEADERBYTES.., 0);
    png_vec.truncate(png_vec.len() - secretstream::HEADERBYTES);

    if embedded_header != stream_header {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    if !decrypt_with_secretstream(png_vec, &key, &stream_header) {
        return Ok(None);
    }

    Ok(Some(extract_filename_prefix(png_vec)?))
}
