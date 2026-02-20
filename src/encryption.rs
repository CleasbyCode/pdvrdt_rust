use crate::binary_io::{get_value, update_value};
use crate::pin_input::get_pin;
use anyhow::Result;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::randombytes;
use zeroize::Zeroize;

pub struct ProfileOffsets {
    pub filename_xor_key: usize,
    pub filename: usize,
    pub sodium_key: usize,    // 32 bytes
    pub nonce: usize,         // 24 bytes
    pub encrypted_file: usize,
}

pub const MASTODON_OFFSETS: ProfileOffsets = ProfileOffsets {
    filename_xor_key: 0x1A6,
    filename: 0x192,
    sodium_key: 0x1BE,
    nonce: 0x1DE,
    encrypted_file: 0x1FE,
};

pub const DEFAULT_OFFSETS: ProfileOffsets = ProfileOffsets {
    filename_xor_key: 0x015,
    filename: 0x001,
    sodium_key: 0x02D,
    nonce: 0x04D,
    encrypted_file: 0x06E,
};

const VALUE_BYTE_LENGTH_EIGHT: usize = 8;

struct SensitiveKeyData {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

impl SensitiveKeyData {
    fn generate() -> Self {
        Self {
            key: secretbox::gen_key(),
            nonce: secretbox::gen_nonce(),
        }
    }

    fn from_bytes(key_bytes: &[u8], nonce_bytes: &[u8]) -> Result<Self> {
        let key = secretbox::Key::from_slice(key_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid key length"))?;
        let nonce = secretbox::Nonce::from_slice(nonce_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid nonce length"))?;
        Ok(Self { key, nonce })
    }
}

impl Drop for SensitiveKeyData {
    fn drop(&mut self) {
        self.key.0.zeroize();
        self.nonce.0.zeroize();
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

    let filename_length = profile_vec[offsets.filename - 1] as usize;

    // XOR-encrypt the data filename into the profile.
    let xor_key_bytes = randombytes::randombytes(filename_length);
    profile_vec[offsets.filename_xor_key..offsets.filename_xor_key + filename_length]
        .copy_from_slice(&xor_key_bytes);

    for i in 0..filename_length {
        profile_vec[offsets.filename + i] =
            data_filename.as_bytes()[i] ^ profile_vec[offsets.filename_xor_key + i];
    }

    // Generate key and nonce.
    let crypto = SensitiveKeyData::generate();

    // Copy key and nonce into profile.
    profile_vec[offsets.sodium_key..offsets.sodium_key + 32]
        .copy_from_slice(&crypto.key.0);
    profile_vec[offsets.nonce..offsets.nonce + 24]
        .copy_from_slice(&crypto.nonce.0);

    // Retrieve the key fingerprint before obfuscation.
    let key_fingerprint = get_value(profile_vec, offsets.sodium_key, VALUE_BYTE_LENGTH_EIGHT)?;

    // Encrypt data.
    let ciphertext = secretbox::seal(data_vec, &crypto.nonce, &crypto.key);

    // Append encrypted data to profile, then clear data_vec.
    profile_vec.extend_from_slice(&ciphertext);
    data_vec.clear();
    data_vec.shrink_to_fit();

    // XOR-obfuscate the stored key+nonce (48 bytes) using the first 8 bytes as rolling XOR mask.
    const XOR_MASK_LENGTH: usize = 8;
    const SODIUM_KEYS_LENGTH: usize = 48;

    let mask_start = offsets.sodium_key;
    let keys_start = offsets.sodium_key + XOR_MASK_LENGTH;

    // Copy the mask bytes first to avoid borrow issues.
    let mut mask = [0u8; XOR_MASK_LENGTH];
    mask.copy_from_slice(&profile_vec[mask_start..mask_start + XOR_MASK_LENGTH]);

    for i in 0..SODIUM_KEYS_LENGTH {
        profile_vec[keys_start + i] ^= mask[i % XOR_MASK_LENGTH];
    }

    // Overwrite the XOR mask with random data.
    let random_bytes = randombytes::randombytes(8);
    let random_val = u64::from_be_bytes(random_bytes[..8].try_into().unwrap()) as usize;
    update_value(profile_vec, offsets.sodium_key, random_val, VALUE_BYTE_LENGTH_EIGHT)?;

    Ok(key_fingerprint)
}

pub fn decrypt_data_file(
    png_vec: &mut Vec<u8>,
    is_mastodon_file: bool,
) -> Result<Option<String>> {
    let offsets = if is_mastodon_file {
        &MASTODON_OFFSETS
    } else {
        &DEFAULT_OFFSETS
    };

    const XOR_MASK_LENGTH: usize = 8;
    const SODIUM_KEYS_LENGTH: usize = 48;

    // Restore the XOR mask from the user-provided recovery pin.
    let recovery_pin = get_pin();
    update_value(png_vec, offsets.sodium_key, recovery_pin, VALUE_BYTE_LENGTH_EIGHT)?;

    // De-obfuscate the stored key+nonce using the rolling XOR mask.
    let mask_start = offsets.sodium_key;
    let keys_start = offsets.sodium_key + XOR_MASK_LENGTH;

    let mut mask = [0u8; XOR_MASK_LENGTH];
    mask.copy_from_slice(&png_vec[mask_start..mask_start + XOR_MASK_LENGTH]);

    for i in 0..SODIUM_KEYS_LENGTH {
        png_vec[keys_start + i] ^= mask[i % XOR_MASK_LENGTH];
    }

    // Load key and nonce.
    let crypto = SensitiveKeyData::from_bytes(
        &png_vec[offsets.sodium_key..offsets.sodium_key + 32],
        &png_vec[offsets.nonce..offsets.nonce + 24],
    )?;

    // Decrypt the filename.
    let filename_length = png_vec[offsets.filename - 1] as usize;
    let mut decrypted_filename = vec![0u8; filename_length];

    for i in 0..filename_length {
        decrypted_filename[i] =
            png_vec[offsets.filename + i] ^ png_vec[offsets.filename_xor_key + i];
    }

    let filename = String::from_utf8(decrypted_filename)
        .map_err(|_| anyhow::anyhow!("Invalid filename encoding"))?;

    // Decrypt data in-place.
    let ciphertext_start = offsets.encrypted_file;
    let ciphertext = png_vec[ciphertext_start..].to_vec();

    match secretbox::open(&ciphertext, &crypto.nonce, &crypto.key) {
        Ok(plaintext) => {
            *png_vec = plaintext;
            Ok(Some(filename))
        }
        Err(_) => {
            eprintln!("\nDecryption failed!");
            Ok(None)
        }
    }
}
