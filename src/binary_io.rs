use anyhow::{bail, Result};

pub fn search_sig(data: &[u8], sig: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() || sig.is_empty() {
        return None;
    }
    data[start..]
        .windows(sig.len())
        .position(|w| w == sig)
        .map(|pos| start + pos)
}

pub fn update_value(data: &mut [u8], index: usize, value: usize, length: usize) -> Result<()> {
    if index + length > data.len() {
        bail!("updateValue: Index out of bounds.");
    }
    match length {
        2 => {
            let bytes = (value as u16).to_be_bytes();
            data[index..index + 2].copy_from_slice(&bytes);
        }
        4 => {
            let bytes = (value as u32).to_be_bytes();
            data[index..index + 4].copy_from_slice(&bytes);
        }
        8 => {
            let bytes = (value as u64).to_be_bytes();
            data[index..index + 8].copy_from_slice(&bytes);
        }
        _ => bail!("updateValue: unsupported length {}", length),
    }
    Ok(())
}

pub fn get_value(data: &[u8], index: usize, length: usize) -> Result<usize> {
    if index + length > data.len() {
        bail!("getValue: index out of bounds");
    }
    match length {
        2 => {
            let val = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
            Ok(val as usize)
        }
        4 => {
            let val = u32::from_be_bytes(data[index..index + 4].try_into().unwrap());
            Ok(val as usize)
        }
        8 => {
            let val = u64::from_be_bytes(data[index..index + 8].try_into().unwrap());
            Ok(val as usize)
        }
        _ => bail!("getValue: unsupported length {}", length),
    }
}
