use anyhow::Result;

pub const DEFAULT_DATA_SHARDS: usize = 4;
pub const DEFAULT_PARITY_SHARDS: usize = 2;

pub fn choose_config(total_chunks: usize) -> (usize, usize) {
    match total_chunks {
        0 => (0, 0),
        1 => (1, 1),
        2 | 3 => (total_chunks, 1),
        _ => (DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS),
    }
}

/// Encode a set of plaintext data shards into data + parity shards.
/// All returned shards are padded to the same length.
pub fn encode_stripe(data_shards: &[Vec<u8>], parity_count: usize) -> Result<Vec<Vec<u8>>> {
    let data_count = data_shards.len();
    if data_count == 0 {
        return Ok(Vec::new());
    }
    if data_count + parity_count > 256 {
        anyhow::bail!("too many shards (max 256)");
    }

    let shard_len = data_shards.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut shards: Vec<Vec<u8>> = data_shards
        .iter()
        .map(|s| {
            let mut padded = s.clone();
            padded.resize(shard_len, 0);
            padded
        })
        .collect();

    for _ in 0..parity_count {
        shards.push(vec![0u8; shard_len]);
    }

    let r = reed_solomon_erasure::galois_8::ReedSolomon::new(data_count, parity_count)
        .map_err(|e| anyhow::anyhow!("RS init failed: {}", e))?;

    let mut refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
    r.encode(&mut refs)
        .map_err(|e| anyhow::anyhow!("RS encode failed: {:?}", e))?;

    Ok(shards)
}

/// Given available shards (some may be missing as None), reconstruct missing data shards.
/// Returns only the data shards, trimmed to their original sizes.
pub fn decode_stripe(
    available: &[Option<Vec<u8>>],
    data_count: usize,
    parity_count: usize,
    original_sizes: &[usize],
) -> Result<Vec<Vec<u8>>> {
    if available.len() != data_count + parity_count {
        anyhow::bail!(
            "shard count mismatch: expected {}, got {}",
            data_count + parity_count,
            available.len()
        );
    }
    if original_sizes.len() != data_count {
        anyhow::bail!("original_sizes length mismatch");
    }

    let shard_len = available
        .iter()
        .filter_map(|s| s.as_ref().map(|v| v.len()))
        .max()
        .unwrap_or(0);

    if shard_len == 0 {
        anyhow::bail!("no valid shards to reconstruct");
    }

    let present: Vec<bool> = available.iter().map(|s| s.is_some()).collect();
    let present_count = present.iter().filter(|p| **p).count();
    if present_count < data_count {
        anyhow::bail!(
            "not enough shards present ({}/{} needed)",
            present_count,
            data_count
        );
    }

    let mut padded: Vec<Option<Vec<u8>>> = available
        .iter()
        .map(|s| {
            s.as_ref().map(|v| {
                let mut p = v.clone();
                p.resize(shard_len, 0);
                p
            })
        })
        .collect();

    let r = reed_solomon_erasure::galois_8::ReedSolomon::new(data_count, parity_count)
        .map_err(|e| anyhow::anyhow!("RS init failed: {}", e))?;

    r.reconstruct(&mut padded)
        .map_err(|e| anyhow::anyhow!("RS reconstruct failed: {:?}", e))?;

    Ok(padded
        .into_iter()
        .take(data_count)
        .enumerate()
        .map(|(i, s)| {
            let mut data = s.unwrap_or_default();
            let orig = original_sizes[i];
            data.truncate(orig);
            data
        })
        .collect())
}
