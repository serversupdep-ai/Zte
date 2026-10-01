//! HP BIOS password hash extraction from SPI flash dumps.
//!
//! HP AMI Aptio firmware stores BIOS passwords as SHA-1(UTF-16LE(password))
//! in NVAR variables named "HpPassphraseStructureVariable".
//! Unsalted — crackable with hashcat mode 130 (empty salt).
//!
//! The NVAR attribute byte (offset +9 from signature) controls whether
//! the entry is active. Bit 7 (0x80) set = active, clear = deactivated.
//! HP's BIOS password jumper reset clears this bit without erasing hashes.

use crate::sivb;

/// A recovered HP BIOS password hash.
pub struct HpPasswordHash {
    pub offset: usize,
    pub hash: [u8; 20],
    pub source: HashSource,
    /// Whether the containing NVAR entry has bit 7 set (password enforced).
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashSource {
    /// Found via HpPassphraseStructureVariable name in NVAR
    Named,
    /// Found via data pattern in NVAR journal/update entry
    Journal,
}

const PASSPHRASE_VAR: &[u8] = b"HpPassphraseStructureVariable\x00";

/// Tail pattern that follows every password hash record:
/// 01 00 00 00 + 20 zero bytes
const TAIL: [u8; 24] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Check if HP password hash storage is present in this image.
pub fn is_hp_firmware(data: &[u8]) -> bool {
    data.windows(PASSPHRASE_VAR.len())
        .any(|w| w == PASSPHRASE_VAR)
}

/// Extract all HP BIOS password hashes from a firmware image.
pub fn find_hashes(data: &[u8]) -> Vec<HpPasswordHash> {
    let mut results = Vec::new();
    let mut seen: Vec<[u8; 20]> = Vec::new();

    // Method 1: Named entries — find HpPassphraseStructureVariable
    find_named_entries(data, &mut results, &mut seen);

    // Method 2: Journal entries — find by tail pattern near NVAR signatures
    find_journal_entries(data, &mut results, &mut seen);

    results
}

/// Read NVAR attribute byte at nvar_offset + 9, return whether bit 7 is set.
fn nvar_entry_active(data: &[u8], nvar_offset: usize) -> bool {
    if nvar_offset + 10 <= data.len() {
        data[nvar_offset + 9] & 0x80 != 0
    } else {
        true // default to active if we can't read
    }
}

/// Find the NVAR signature preceding a variable name occurrence.
/// Searches backwards up to `max_back` bytes.
fn find_nvar_before(data: &[u8], pos: usize, max_back: usize) -> Option<usize> {
    let start = pos.saturating_sub(max_back);
    // Walk backwards looking for "NVAR"
    for i in (start..pos.saturating_sub(3)).rev() {
        if &data[i..i + 4] == b"NVAR" {
            return Some(i);
        }
    }
    None
}

/// Find hashes in named NVAR entries containing HpPassphraseStructureVariable.
fn find_named_entries(
    data: &[u8],
    results: &mut Vec<HpPasswordHash>,
    seen: &mut Vec<[u8; 20]>,
) {
    let mut pos = 0;
    while pos + PASSPHRASE_VAR.len() + 24 < data.len() {
        let idx = match find_pattern(&data[pos..], PASSPHRASE_VAR) {
            Some(i) => pos + i,
            None => break,
        };

        let data_start = idx + PASSPHRASE_VAR.len();

        // Skip zero prefix bytes (typically 4)
        let mut hash_start = data_start;
        let limit = (data_start + 8).min(data.len());
        while hash_start < limit && data[hash_start] == 0x00 {
            hash_start += 1;
        }

        // Need at least 1 zero prefix byte
        if hash_start == data_start || hash_start + 20 > data.len() {
            pos = idx + 1;
            continue;
        }

        let hash: [u8; 20] = match data[hash_start..hash_start + 20].try_into() {
            Ok(h) => h,
            Err(_) => {
                pos = idx + 1;
                continue;
            }
        };

        // Validate: hash followed by tail pattern
        if hash_start + 20 + TAIL.len() <= data.len()
            && data[hash_start + 20..hash_start + 20 + TAIL.len()] == TAIL
            && is_plausible_hash(&hash)
            && !seen.contains(&hash)
        {
            // Find the NVAR header before the variable name (within 32 bytes)
            let active = find_nvar_before(data, idx, 32)
                .map(|nvar_off| nvar_entry_active(data, nvar_off))
                .unwrap_or(true);

            seen.push(hash);
            results.push(HpPasswordHash {
                offset: hash_start,
                hash,
                source: HashSource::Named,
                active,
            });
        }

        pos = idx + 1;
    }
}

/// Find hashes in journal/update NVAR entries by data pattern.
///
/// Journal entries don't repeat the variable name. We find them by
/// searching for the distinctive tail pattern (01000000 + 20 zeros)
/// preceded by 20 high-entropy bytes, with an NVAR signature nearby.
fn find_journal_entries(
    data: &[u8],
    results: &mut Vec<HpPasswordHash>,
    seen: &mut Vec<[u8; 20]>,
) {
    let mut pos = 24; // need at least 24 bytes before for hash + prefix
    while pos + TAIL.len() < data.len() {
        let idx = match find_pattern(&data[pos..], &TAIL) {
            Some(i) => pos + i,
            None => break,
        };

        // Hash is the 20 bytes before the tail
        if idx < 20 {
            pos = idx + 1;
            continue;
        }
        let hash_start = idx - 20;
        let hash: [u8; 20] = match data[hash_start..hash_start + 20].try_into() {
            Ok(h) => h,
            Err(_) => {
                pos = idx + 1;
                continue;
            }
        };

        if !is_plausible_hash(&hash) || seen.contains(&hash) {
            pos = idx + 1;
            continue;
        }

        // Must have zero prefix before hash (2-4 bytes)
        let has_prefix = hash_start >= 2
            && data[hash_start - 1] == 0x00
            && data[hash_start - 2] == 0x00;
        if !has_prefix {
            pos = idx + 1;
            continue;
        }

        // Must have an NVAR signature within 64 bytes before the hash
        let search_start = hash_start.saturating_sub(64);
        let nvar_offset = data[search_start..hash_start]
            .windows(4)
            .rposition(|w| w == b"NVAR")
            .map(|p| search_start + p);

        if nvar_offset.is_none() {
            pos = idx + 1;
            continue;
        }

        let active = nvar_offset
            .map(|off| nvar_entry_active(data, off))
            .unwrap_or(true);

        seen.push(hash);
        results.push(HpPasswordHash {
            offset: hash_start,
            hash,
            source: HashSource::Journal,
            active,
        });

        pos = idx + 1;
    }
}

/// Check if 20 bytes look like a plausible SHA-1 hash (not all zeros, not all FF).
fn is_plausible_hash(hash: &[u8; 20]) -> bool {
    let zeros = hash.iter().filter(|&&b| b == 0).count();
    let ffs = hash.iter().filter(|&&b| b == 0xff).count();
    let unique: std::collections::HashSet<u8> = hash.iter().copied().collect();
    zeros < 10 && ffs < 10 && unique.len() >= 6
}

/// Find first occurrence of needle in haystack.
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Format results for display, including password active/cleared status.
pub fn format_results(hashes: &[HpPasswordHash]) -> String {
    if hashes.is_empty() {
        return "No HP password hashes found.\n".to_string();
    }

    // Determine overall status from named entries (journal entries are stale copies)
    let named_active = hashes
        .iter()
        .any(|h| h.source == HashSource::Named && h.active);
    let has_named = hashes.iter().any(|h| h.source == HashSource::Named);
    let status_line = if named_active || !has_named {
        "Password is SET \u{2014} BIOS will prompt on boot"
    } else {
        "Password is CLEARED (jumper reset) \u{2014} hashes still recoverable for cracking"
    };

    let mut out = format!("Found {} HP password hash(es):\n", hashes.len());
    out.push_str(&format!("Status: {}\n\n", status_line));

    for (i, h) in hashes.iter().enumerate() {
        let hash_hex: String = h.hash.iter().map(|b| format!("{:02x}", b)).collect();
        let source = match h.source {
            HashSource::Named => "named entry",
            HashSource::Journal => "journal entry",
        };
        let active_str = if h.active { "active" } else { "inactive" };
        out.push_str(&format!("  [{}] {}\n", i + 1, hash_hex));
        out.push_str(&format!(
            "      Offset: 0x{:06x} ({}, {})\n",
            h.offset, source, active_str
        ));
    }

    out.push_str("\n--- Hashcat ---\n\n");
    out.push_str("Mode: 130 (SHA-1 UTF-16LE, empty salt)\n");
    out.push_str("Command: hashcat -m 130 hashes.txt wordlist.txt\n\n");

    for h in hashes {
        let hash_hex: String = h.hash.iter().map(|b| format!("{:02x}", b)).collect();
        out.push_str(&format!("{}:\n", hash_hex));
    }

    out
}

/// Clear HP BIOS password by deactivating NVAR entries (t530-style jumper reset).
///
/// Finds all HpPassphraseStructureVariable NVAR entries (both named and journal)
/// and clears bit 7 of their attribute byte, marking them as inactive.
/// The hashes remain in flash but the BIOS no longer enforces the password.
pub fn clear_hp_password(data: &[u8]) -> Option<sivb::ClearResult> {
    if !is_hp_firmware(data) {
        return None;
    }

    let mut modified = data.to_vec();
    let mut changes = Vec::new();

    // Find named NVAR entries containing HpPassphraseStructureVariable
    let mut pos = 0;
    while pos + PASSPHRASE_VAR.len() < data.len() {
        let idx = match find_pattern(&data[pos..], PASSPHRASE_VAR) {
            Some(i) => pos + i,
            None => break,
        };

        if let Some(nvar_off) = find_nvar_before(data, idx, 32) {
            let attr_offset = nvar_off + 9;
            if attr_offset < modified.len() {
                let old_attr = modified[attr_offset];
                if old_attr & 0x80 != 0 {
                    modified[attr_offset] &= !0x80;
                    let new_attr = modified[attr_offset];
                    changes.push(format!(
                        "Deactivated named NVAR entry at 0x{:06x} (attr 0x{:02x} -> 0x{:02x})",
                        nvar_off, old_attr, new_attr
                    ));
                }
            }
        }

        pos = idx + 1;
    }

    // Find journal NVAR entries containing password hashes (via tail pattern)
    let mut pos = 24;
    while pos + TAIL.len() < data.len() {
        let idx = match find_pattern(&data[pos..], &TAIL) {
            Some(i) => pos + i,
            None => break,
        };

        if idx < 20 {
            pos = idx + 1;
            continue;
        }
        let hash_start = idx - 20;
        let hash: [u8; 20] = match data[hash_start..hash_start + 20].try_into() {
            Ok(h) => h,
            Err(_) => {
                pos = idx + 1;
                continue;
            }
        };

        if !is_plausible_hash(&hash) {
            pos = idx + 1;
            continue;
        }

        // Must have zero prefix before hash
        let has_prefix = hash_start >= 2
            && data[hash_start - 1] == 0x00
            && data[hash_start - 2] == 0x00;
        if !has_prefix {
            pos = idx + 1;
            continue;
        }

        // Find NVAR signature within 64 bytes before
        let search_start = hash_start.saturating_sub(64);
        if let Some(rel) = data[search_start..hash_start]
            .windows(4)
            .rposition(|w| w == b"NVAR")
        {
            let nvar_off = search_start + rel;
            let attr_offset = nvar_off + 9;
            if attr_offset < modified.len() {
                let old_attr = modified[attr_offset];
                if old_attr & 0x80 != 0 {
                    modified[attr_offset] &= !0x80;
                    let new_attr = modified[attr_offset];
                    changes.push(format!(
                        "Deactivated journal NVAR entry at 0x{:06x} (attr 0x{:02x} -> 0x{:02x})",
                        nvar_off, old_attr, new_attr
                    ));
                }
            }
        }

        pos = idx + 1;
    }

    if changes.is_empty() {
        return None;
    }

    Some(sivb::ClearResult { modified, changes })
}
