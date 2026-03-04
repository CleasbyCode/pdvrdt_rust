use anyhow::{bail, Result};

fn has_range(data_len: usize, index: usize, length: usize) -> bool {
    index <= data_len && length <= data_len.saturating_sub(index)
}

pub fn update_value(data: &mut [u8], index: usize, value: usize, length: usize) -> Result<()> {
    if !has_range(data.len(), index, length) {
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
    if !has_range(data.len(), index, length) {
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
