//! SIVB (Security Information Vault Block) scanning and clearing.
//!
//! Dell OptiPlex 3000 uses SIVB+SHA-256+encrypted vault for password storage.
//! The SIVB block can be zeroed to revert to the previous password (typically the
//! factory default, which is blank on most deployments).
//!
//! Also includes E7250-style password store clearing (different mechanism).

/// SIVB signature bytes.
const SIVB_SIG: &[u8; 4] = b"SIVB";

/// SIVB block size (header + data).
const SIVB_TOTAL_SIZE: usize = 5552;

/// Information about a found SIVB block.
#[derive(Debug, Clone)]
pub struct SivbInfo {
    pub offset: usize,
    pub hash_size: u32,
    pub blob_size: u32,
    pub has_data: bool,
}

/// Information about an E7250-style password store.
#[derive(Debug, Clone)]
pub struct PasswordStoreInfo {
    pub offset: usize,
    pub non_ff_bytes: usize,
    pub has_password: bool,
    #[allow(dead_code)]
    pub counter: u8,
}


/// Result of a clearing operation.
#[derive(Debug)]
pub struct ClearResult {
    pub modified: Vec<u8>,
    pub changes: Vec<String>,
}

/// Find all SIVB blocks in the image.
pub fn find_sivb(data: &[u8]) -> Vec<SivbInfo> {
    let mut results = Vec::new();

    // SIVB structure: 4-byte header (hash_size=0x20, blob_size=0x1540), then "SIVB" sig
    // Search for the SIVB signature
    for i in 0..data.len().saturating_sub(SIVB_TOTAL_SIZE) {
        if &data[i..i + 4] == SIVB_SIG {
            // Check if the preceding bytes look like a valid header
            // The header is at i-4: hash_size (2 bytes) + blob_size (2 bytes)
            let _has_data = if i >= 4 {
                let hash_size = u16::from_le_bytes([data[i - 4], data[i - 3]]) as u32;
                let blob_size = u16::from_le_bytes([data[i - 2], data[i - 1]]) as u32;
                // Typical: hash_size=0x20, blob_size=0x1540
                if hash_size == 0x20 && blob_size > 0 {
                    // Check if the block has actual data (not all zeros/FF)
                    let block_end = (i + SIVB_TOTAL_SIZE).min(data.len());
                    let non_trivial = data[i + 4..block_end]
                        .iter()
                        .filter(|&&b| b != 0x00 && b != 0xFF)
                        .count();
                    results.push(SivbInfo {
                        offset: i - 4,
                        hash_size,
                        blob_size,
                        has_data: non_trivial > 10,
                    });
                    continue;
                }
                false
            } else {
                false
            };

            // Also record SIVB signatures without recognizable headers
            if results.last().map_or(true, |r| r.offset != i.saturating_sub(4)) {
                let block_end = (i + SIVB_TOTAL_SIZE).min(data.len());
                let non_trivial = data[i + 4..block_end]
                    .iter()
                    .filter(|&&b| b != 0x00 && b != 0xFF)
                    .count();
                results.push(SivbInfo {
                    offset: i,
                    hash_size: 0,
                    blob_size: 0,
                    has_data: non_trivial > 10,
                });
            }
        }
    }

    results
}

/// Clear SIVB block by zeroing its contents.
/// Returns ClearResult with the modified data and list of changes.
pub fn clear_sivb(data: &[u8]) -> Option<ClearResult> {
    let sivb_blocks = find_sivb(data);
    if sivb_blocks.is_empty() {
        return None;
    }

    let mut modified = data.to_vec();
    let mut changes = Vec::new();

    for sivb in &sivb_blocks {
        if !sivb.has_data {
            changes.push(format!(
                "SIVB at 0x{:06x}: already empty (no password data)",
                sivb.offset
            ));
            continue;
        }

        let clear_start = sivb.offset;
        let clear_end = (clear_start + SIVB_TOTAL_SIZE).min(modified.len());

        for byte in &mut modified[clear_start..clear_end] {
            *byte = 0x00;
        }

        changes.push(format!(
            "Cleared SIVB at 0x{:06x} ({} bytes zeroed)",
            sivb.offset,
            clear_end - clear_start
        ));
    }

    Some(ClearResult { modified, changes })
}

/// Find E7250-style password stores (0x06 0x78 header pattern at 4KB boundaries).
pub fn find_password_stores(data: &[u8]) -> Vec<PasswordStoreInfo> {
    let mut results = Vec::new();

    let mut offset = 0;
    while offset + 8 < data.len() {
        if data[offset] == 0x06
            && data[offset + 1] == 0x78
            && (data[offset + 2] & 0xF0) == 0xF0
            && data[offset + 3] == 0xFF
            && data[offset + 4..offset + 8] == [0x03, 0x00, 0x00, 0x00]
        {
            // Verify markers at expected positions
            let mut has_markers = false;
            for check_off in [0xD0, 0xE0] {
                if offset + check_off < data.len() {
                    let b = data[offset + check_off];
                    if b == 0x84 || b == 0x85 || b == 0xFF {
                        has_markers = true;
                    }
                }
            }

            if has_markers {
                let store_end = (offset + 0x1000).min(data.len());
                let store_data = &data[offset..store_end];
                let non_ff = store_data.iter().filter(|&&b| b != 0xFF).count();
                results.push(PasswordStoreInfo {
                    offset,
                    non_ff_bytes: non_ff,
                    has_password: non_ff > 20,
                    counter: data[offset + 2],
                });
            }
        }
        offset += 0x1000; // 4KB aligned
    }

    results
}

/// Find NVRAM Firmware Volumes containing NVAR entries.
fn find_nvar_stores(data: &[u8]) -> Vec<(usize, usize)> {
    let mut stores = Vec::new();

    let mut offset = 0;
    while offset + 0x60 < data.len() {
        // Check for _FVH signature at offset+40
        if offset + 44 <= data.len() && &data[offset + 40..offset + 44] == b"_FVH" {
            if offset + 40 <= data.len() {
                let fv_size =
                    u64::from_le_bytes(data[offset + 32..offset + 40].try_into().unwrap_or([0; 8]))
                        as usize;
                if fv_size > 0 && fv_size <= data.len() - offset {
                    let nvar_off = offset + 0x60;
                    if nvar_off + 4 <= data.len() && &data[nvar_off..nvar_off + 4] == b"NVAR" {
                        stores.push((offset, fv_size));
                    }
                }
            }
        }
        offset += 0x1000;
    }

    stores
}

/// Find the last 'Setup' variable in an NVAR store.
fn find_setup_in_nvar(data: &[u8], fv_start: usize, fv_size: usize) -> Option<(usize, usize)> {
    let mut offset = fv_start + 0x60;
    let mut last_setup = None;
    let fv_end = fv_start + fv_size;

    while offset + 10 < fv_end && offset + 10 < data.len() {
        if &data[offset..offset + 4] != b"NVAR" {
            if data[offset..offset + 4].iter().all(|&b| b == 0xFF) {
                break;
            }
            offset += 1;
            continue;
        }

        let size = u16::from_le_bytes([data[offset + 4], data[offset + 5]]) as usize;
        if size < 10 || size > 0x10000 {
            break;
        }

        let attrs = data[offset + 9];
        if attrs & 0x80 == 0 || attrs & 0x08 != 0 {
            offset += size;
            continue;
        }

        let has_full_guid = attrs & 0x04 != 0;
        let ascii_name = attrs & 0x02 != 0;

        let mut pos = offset + 10;
        pos += if has_full_guid { 16 } else { 1 };

        let name;
        if ascii_name {
            let name_end = data[pos..offset + size]
                .iter()
                .position(|&b| b == 0)
                .map(|p| pos + p);
            if let Some(end) = name_end {
                name = String::from_utf8_lossy(&data[pos..end]).to_string();
                pos = end + 1;
            } else {
                offset += size;
                continue;
            }
        } else {
            let mut name_chars = Vec::new();
            while pos + 1 < offset + size {
                let c = u16::from_le_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                if c == 0 {
                    break;
                }
                name_chars.push(char::from_u32(c as u32).unwrap_or('?'));
            }
            name = name_chars.into_iter().collect();
        }

        if name == "Setup" {
            let data_len = offset + size - pos;
            last_setup = Some((pos, data_len));
        }

        offset += size;
    }

    last_setup
}

/// E7250 password flag offsets within Setup data.
const PWD_FLAG_OFFSETS: [usize; 3] = [0x430, 0x440, 0x588];

/// Clear E7250-style password (password store + Setup NVAR flags).
pub fn clear_password_e7250(data: &[u8]) -> Option<ClearResult> {
    let pwd_stores = find_password_stores(data);
    if pwd_stores.is_empty() {
        return None;
    }

    let mut modified = data.to_vec();
    let mut changes = Vec::new();

    // Step 1: Clear password stores
    for store in &pwd_stores {
        if !store.has_password {
            changes.push(format!(
                "Password store at 0x{:06x}: already empty",
                store.offset
            ));
            continue;
        }

        // Erase password data region (0x08 onwards)
        for i in 0x08..0x1000 {
            if store.offset + i < modified.len() && modified[store.offset + i] != 0xFF {
                modified[store.offset + i] = 0xFF;
            }
        }

        // Restore empty-state markers
        let off = store.offset;
        if off + 0xE3 < modified.len() {
            modified[off + 0xAC] = 0x00;
            modified[off + 0xD0] = 0x84;
            modified[off + 0xD1] = 0x03;
            modified[off + 0xD2] = 0x02;
            modified[off + 0xE0] = 0x85;
            modified[off + 0xE1] = 0x03;
            modified[off + 0xE2] = 0x02;
        }

        changes.push(format!("Cleared password store at 0x{:06x}", store.offset));
    }

    // Step 2: Fix Setup NVAR flags
    let nvar_stores = find_nvar_stores(data);
    for (fv_start, fv_size) in &nvar_stores {
        if let Some((data_off, data_len)) = find_setup_in_nvar(data, *fv_start, *fv_size) {
            for &flag_off in &PWD_FLAG_OFFSETS {
                if flag_off < data_len {
                    let abs_off = data_off + flag_off;
                    if data[abs_off] == 0x00 {
                        modified[abs_off] = 0x01;
                        changes.push(format!("Reset Setup flag at 0x{:06x}", abs_off));
                    }
                }
            }
        }
    }

    if changes.is_empty() {
        return None;
    }

    Some(ClearResult { modified, changes })
}

/// Scan an image and report all Dell BIOS security artifacts found.
pub fn scan_report(data: &[u8]) -> String {
    let mut out = String::new();

    // Check for SIVB
    let sivb_blocks = find_sivb(data);
    if sivb_blocks.is_empty() {
        out.push_str("SIVB: not found\n");
    } else {
        for sivb in &sivb_blocks {
            let status = if sivb.has_data {
                "PASSWORD DATA PRESENT"
            } else {
                "empty (no password)"
            };
            out.push_str(&format!(
                "SIVB: 0x{:06x} (hash_size={}, blob_size={}) — {}\n",
                sivb.offset, sivb.hash_size, sivb.blob_size, status
            ));
        }
    }

    // Check for E7250-style password stores
    let pwd_stores = find_password_stores(data);
    if pwd_stores.is_empty() {
        out.push_str("Password store (E7250): not found\n");
    } else {
        for store in &pwd_stores {
            let status = if store.has_password {
                "PASSWORD SET"
            } else {
                "empty"
            };
            out.push_str(&format!(
                "Password store (E7250): 0x{:06x} ({} non-FF bytes) — {}\n",
                store.offset, store.non_ff_bytes, status
            ));
        }
    }

    // Check for DVAR
    if let Some((start, end)) = crate::dvar::find_dvar_region(data) {
        out.push_str(&format!("DVAR: 0x{:06x} - 0x{:06x}\n", start, end));
    } else {
        out.push_str("DVAR: not found\n");
    }

    // Check for NVAR stores
    let nvar_stores = find_nvar_stores(data);
    if nvar_stores.is_empty() {
        out.push_str("NVAR stores: not found\n");
    } else {
        out.push_str(&format!("NVAR stores: {} found\n", nvar_stores.len()));
        for (fv_start, fv_size) in &nvar_stores {
            out.push_str(&format!(
                "  FV at 0x{:06x} ({} bytes)\n",
                fv_start, fv_size
            ));
            if let Some((data_off, data_len)) = find_setup_in_nvar(data, *fv_start, *fv_size) {
                out.push_str(&format!(
                    "    Setup variable: 0x{:06x} ({} bytes)\n",
                    data_off, data_len
                ));
                for &flag_off in &PWD_FLAG_OFFSETS {
                    if flag_off < data_len {
                        let abs_off = data_off + flag_off;
                        let val = data[abs_off];
                        let status = if val == 0x00 {
                            "PASSWORD SET"
                        } else {
                            "no password"
                        };
                        out.push_str(&format!(
                            "      Flag +0x{:04x} = 0x{:02x} ({})\n",
                            flag_off, val, status
                        ));
                    }
                }
            }
        }
    }

    out
}
