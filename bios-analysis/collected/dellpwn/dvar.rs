//! DVAR+XOR password recovery from Dell SPI flash dumps.
//!
//! Dell stores BIOS passwords as XOR-encrypted plaintext in the DVAR (Dell Variable)
//! store region. The XOR key is 20 bytes, derived from a device-specific seed + GUID +
//! the password's first byte. The encrypted field is 32 bytes.
//!
//! Because 20 < 32, the key wraps around. For passwords up to 20 characters, the
//! null-padded bytes directly leak key material. For longer passwords (21-32 chars),
//! the tool exploits the key wrap to solve each byte independently.
//!
//! Some Dell models (e.g. Wyse 5070) apply sparse bit-flipping obfuscation to the
//! DVAR store, causing a few bytes per record to have individual bits flipped.

use std::collections::HashMap;

/// Printable ASCII range used by Dell BIOS passwords (0x20..0x7f).
fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// Characters commonly found in BIOS passwords.
fn is_password_char(b: u8) -> bool {
    matches!(b,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' |
        b'!' | b'@' | b'#' | b'$' | b'%' | b'^' | b'&' | b'*' |
        b'(' | b')' | b'-' | b'_' | b'=' | b'+' | b'.' | b',' |
        b';' | b':' | b'?' | b'/' | b' '
    )
}

/// Common DVAR obfuscation bit masks.
const OBFUSCATION_MASKS: [u8; 7] = [0x08, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48];

/// English letter frequency (per-mille, case-insensitive).
fn letter_freq(c: char) -> u32 {
    match c.to_ascii_lowercase() {
        'e' => 127, 't' => 91, 'a' => 82, 'o' => 75, 'i' => 70,
        'n' => 67, 's' => 63, 'h' => 61, 'r' => 60, 'd' => 43,
        'l' => 40, 'c' => 28, 'u' => 28, 'm' => 24, 'w' => 24,
        'f' => 22, 'g' => 20, 'y' => 20, 'p' => 19, 'b' => 15,
        'v' => 10, 'k' => 8, 'j' => 2, 'x' => 2, 'q' => 1, 'z' => 1,
        _ => 0,
    }
}

fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// A recovered password record.
#[derive(Debug, Clone)]
pub struct PasswordRecord {
    pub offset: usize,
    pub password: String,
    pub stored: Vec<u8>,
    pub key: Vec<u8>,
    pub is_partial: bool,
}

/// An uncertain character position due to DVAR obfuscation correction.
#[derive(Debug, Clone)]
pub struct UncertainChar {
    /// 1-based position in the password
    pub position: usize,
    /// Character chosen by the correction algorithm
    pub chosen: char,
    /// Original character before correction (if printable)
    pub original: Option<char>,
    /// Other plausible characters sorted by English frequency
    pub alternatives: Vec<char>,
}

/// Find the DVAR (Dell Variable) store by signature.
/// Returns (start, end) offsets or None.
pub fn find_dvar_region(data: &[u8]) -> Option<(usize, usize)> {
    let sig = b"DVAR";
    for i in 0..data.len().saturating_sub(4) {
        if &data[i..i + 4] == sig {
            let end = (i + 0x40000).min(data.len());
            return Some((i, end));
        }
    }
    None
}

/// Recover plaintext password (1-20 chars) from a 32-byte XOR-encrypted record.
fn recover_password_short(stored: &[u8]) -> Option<(String, Vec<u8>)> {
    if stored.len() < 32 {
        return None;
    }

    let b0 = stored[0];
    if !is_printable(b0) {
        return None;
    }

    // Extract key[0..10] from wrap-around region (positions 21-31)
    let mut key = vec![0u8; 20];
    for i in 21..32 {
        key[(i - 1) % 20] = stored[i];
    }

    // Decrypt positions 1-11 using key[0..10]
    let mut decrypted = vec![0u8; 32];
    decrypted[0] = b0;
    for i in 1..12 {
        decrypted[i] = stored[i] ^ key[(i - 1) % 20];
    }

    // Find null terminator within first 12 bytes.
    // DVAR obfuscation can flip bits, causing null to decrypt to a small non-zero value.
    let mut pwd_len = 12usize; // default if no terminator found
    for i in 0..12 {
        if decrypted[i] == 0 {
            pwd_len = i;
            break;
        }
        if !is_printable(decrypted[i]) {
            if OBFUSCATION_MASKS.contains(&decrypted[i]) {
                pwd_len = i;
                break;
            }
            return None;
        }
    }

    if pwd_len < 1 {
        return None;
    }

    // Extract authoritative key from null region (password through 20).
    if pwd_len <= 20 {
        for i in pwd_len..21 {
            key[(i - 1) % 20] = stored[i];
        }
    }

    // Cross-validate: count wrap-region mismatches
    let mut wrap_mismatches = 0u32;
    if pwd_len < 11 {
        for k in pwd_len..11 {
            if stored[k + 1] != key[k] {
                wrap_mismatches += 1;
            }
        }
    }
    for i in 21..32 {
        let ki = (i - 1) % 20;
        if stored[i] != key[ki] {
            wrap_mismatches += 1;
        }
    }

    if wrap_mismatches > 5 {
        return None;
    }

    // Re-decrypt with corrected key
    for i in 1..32 {
        decrypted[i] = stored[i] ^ key[(i - 1) % 20];
    }

    // Re-find null terminator with corrected key
    pwd_len = 32; // default if no terminator
    for i in 0..32 {
        if decrypted[i] == 0 {
            pwd_len = i;
            break;
        }
        if !is_printable(decrypted[i]) {
            return None;
        }
    }

    if pwd_len < 1 || pwd_len > 20 {
        return None;
    }

    // Verify null region
    let mut null_nonzero = 0u32;
    for i in (pwd_len + 1)..32 {
        if decrypted[i] != 0 {
            null_nonzero += 1;
        }
    }
    if null_nonzero > 5 {
        return None;
    }

    let password = String::from_utf8_lossy(&decrypted[..pwd_len]).to_string();
    Some((password, key))
}

/// Try recovering a 32-char password where all characters are the same.
fn try_uniform_password(stored: &[u8]) -> Option<(String, Vec<u8>)> {
    let b0 = stored[0];
    let c = b0;

    // Derive key assuming plaintext is all c
    let mut key = vec![0u8; 20];
    for j in 0..20 {
        key[j] = stored[j + 1] ^ c;
    }

    // Validate: positions 21-31 must also decrypt to c
    for j in 0..11 {
        if (stored[j + 21] ^ key[j]) != c {
            return None;
        }
    }

    // Reject if too many key bytes equal the password char
    if key.iter().filter(|&&b| b == c).count() > 3 {
        return None;
    }

    // Hash-derived keys should have near-perfect byte uniqueness
    let mut unique = std::collections::HashSet::new();
    for &b in &key {
        unique.insert(b);
    }
    if unique.len() < 18 {
        return None;
    }

    let password = String::from_utf8(vec![c; 32]).ok()?;
    Some((password, key))
}

/// Validate decryption and return (password, key) or None.
fn validate_and_return(stored: &[u8], key: &[u8], target_len: usize) -> Option<(String, Vec<u8>)> {
    let mut decrypted = vec![0u8; 32];
    decrypted[0] = stored[0];
    for i in 1..32 {
        decrypted[i] = stored[i] ^ key[(i - 1) % 20];
    }

    for i in 0..target_len {
        if !is_printable(decrypted[i]) {
            return None;
        }
    }

    if target_len < 32 {
        for i in target_len..32 {
            if decrypted[i] != 0 {
                return None;
            }
        }
    }

    let password = String::from_utf8_lossy(&decrypted[..target_len]).to_string();
    Some((password, key.to_vec()))
}

/// Return a partial password with '?' for undetermined positions.
fn partial_recovery(
    stored: &[u8],
    key: &[u8],
    known: &std::collections::HashSet<usize>,
    target_len: usize,
) -> Option<(String, Vec<u8>)> {
    let mut password = Vec::with_capacity(target_len);
    password.push(stored[0] as char);

    for i in 1..target_len {
        let ki = (i - 1) % 20;
        if known.contains(&ki) {
            let ch = stored[i] ^ key[ki];
            if (0x20..=0x7e).contains(&ch) {
                password.push(ch as char);
            } else {
                return None;
            }
        } else {
            password.push('?');
        }
    }

    // Validate null region with known key bytes
    for i in target_len..32 {
        let ki = (i - 1) % 20;
        if known.contains(&ki) && (stored[i] ^ key[ki]) != 0 {
            return None;
        }
    }

    let partial: String = password.into_iter().collect();
    let unknown_count = partial.chars().filter(|&c| c == '?').count();
    if unknown_count >= partial.len() - 2 {
        return None;
    }
    Some((partial, key.to_vec()))
}

/// Attempt recovery assuming a specific password length (21-24).
fn try_long_password(stored: &[u8], target_len: usize) -> Option<(String, Vec<u8>)> {
    let mut key = vec![0u8; 20];
    let mut known = std::collections::HashSet::new();

    // Extract known key bytes from null-padded region
    for i in target_len..32 {
        let ki = (i - 1) % 20;
        if known.contains(&ki) && key[ki] != stored[i] {
            return None; // null region self-inconsistency
        }
        key[ki] = stored[i];
        known.insert(ki);
    }

    // Solve unknown key bytes using dual-position constraint
    for j in 0..20 {
        if known.contains(&j) {
            continue;
        }

        let pos1 = j + 1;
        let pos2 = j + 21;

        let mut candidates = Vec::new();
        for k_val in 0..=255u16 {
            let k_val = k_val as u8;
            let dec1 = stored[pos1] ^ k_val;
            if pos1 < target_len {
                if !is_printable(dec1) {
                    continue;
                }
            } else if dec1 != 0 {
                continue;
            }

            if pos2 < 32 {
                let dec2 = stored[pos2] ^ k_val;
                if pos2 < target_len {
                    if !is_printable(dec2) {
                        continue;
                    }
                } else if dec2 != 0 {
                    continue;
                }
            }

            candidates.push(k_val);
        }

        if candidates.is_empty() {
            return None;
        }

        if candidates.len() == 1 {
            key[j] = candidates[0];
            known.insert(j);
        }
    }

    // For positions with multiple candidates, enumerate
    let unknown_multi: Vec<usize> = (0..20).filter(|j| !known.contains(j)).collect();

    if unknown_multi.is_empty() {
        return validate_and_return(stored, &key, target_len);
    }

    // Build candidate lists for remaining positions
    let mut candidate_lists: Vec<Vec<u8>> = Vec::new();
    for &j in &unknown_multi {
        let pos1 = j + 1;
        let pos2 = j + 21;
        let mut cands = Vec::new();
        for k_val in 0..=255u16 {
            let k_val = k_val as u8;
            let dec1 = stored[pos1] ^ k_val;
            if pos1 < target_len {
                if !is_printable(dec1) {
                    continue;
                }
            } else if dec1 != 0 {
                continue;
            }
            if pos2 < 32 {
                let dec2 = stored[pos2] ^ k_val;
                if pos2 < target_len {
                    if !is_printable(dec2) {
                        continue;
                    }
                } else if dec2 != 0 {
                    continue;
                }
            }
            cands.push(k_val);
        }
        if cands.is_empty() {
            return None;
        }
        candidate_lists.push(cands);
    }

    // Calculate total combinations
    let mut total: u64 = 1;
    for cl in &candidate_lists {
        total = total.saturating_mul(cl.len() as u64);
        if total > 5_000_000 {
            if known.len() >= 8 {
                return partial_recovery(stored, &key, &known, target_len);
            }
            return None;
        }
    }

    // Enumerate all combinations
    let mut indices = vec![0usize; unknown_multi.len()];
    loop {
        let mut trial_key = key.clone();
        for (idx, &j) in unknown_multi.iter().enumerate() {
            trial_key[j] = candidate_lists[idx][indices[idx]];
        }
        if let Some(result) = validate_and_return(stored, &trial_key, target_len) {
            return Some(result);
        }

        // Increment indices (odometer style)
        let mut carry = true;
        for i in (0..indices.len()).rev() {
            if carry {
                indices[i] += 1;
                if indices[i] < candidate_lists[i].len() {
                    carry = false;
                } else {
                    indices[i] = 0;
                }
            }
        }
        if carry {
            break;
        }
    }

    None
}

/// Recover plaintext password (21-32 chars) from a 32-byte XOR-encrypted record.
fn recover_password_long(stored: &[u8]) -> Option<(String, Vec<u8>)> {
    if stored.len() < 32 {
        return None;
    }

    let b0 = stored[0];
    if !is_printable(b0) {
        return None;
    }

    // Strategy 1: Try 32-char uniform password
    let mut all_pairs_valid = true;
    for j in 0..11 {
        let xor_pair = stored[j + 1] ^ stored[j + 21];
        if xor_pair > 0x5E {
            all_pairs_valid = false;
            break;
        }
    }
    if all_pairs_valid {
        if let Some(result) = try_uniform_password(stored) {
            return Some(result);
        }
    }

    // Strategy 2: Try lengths 21-24 with brute-force of missing key bytes
    for target_len in 21..=24 {
        if let Some(result) = try_long_password(stored, target_len) {
            return Some(result);
        }
    }

    None
}

/// Correct DVAR bit-flip obfuscation in wrap-only key bytes.
fn correct_dvar_obfuscation(stored: &[u8], password: &str, key: &[u8]) -> (String, Vec<u8>) {
    let pwd_len = password.len();
    if pwd_len >= 11 || pwd_len < 2 {
        return (password.to_string(), key.to_vec());
    }

    // Check if there are any wrap-region mismatches
    let mut has_obfuscation = false;
    for i in 21..32 {
        let ki = (i - 1) % 20;
        if stored[i] != key[ki] {
            has_obfuscation = true;
            break;
        }
    }
    if !has_obfuscation {
        return (password.to_string(), key.to_vec());
    }

    let wrap_only_end = (pwd_len - 1).min(11);
    let wrap_only: Vec<usize> = (0..wrap_only_end).collect();
    if wrap_only.is_empty() {
        return (password.to_string(), key.to_vec());
    }

    let allowed_residuals: std::collections::HashSet<u8> =
        std::iter::once(0).chain(OBFUSCATION_MASKS.iter().copied()).collect();

    const FREQ_RATIO_THRESHOLD: u32 = 5;

    let orig_key = key.to_vec();
    let mut corrected_key = key.to_vec();

    for &ki in &wrap_only {
        let pos = ki + 1;
        let orig_char = stored[pos] ^ orig_key[ki];
        let orig_is_alpha = is_alpha(orig_char);
        let orig_freq = if orig_is_alpha {
            letter_freq(orig_char as char)
        } else {
            0
        };

        // Get valid correction candidates
        let mut candidates: Vec<(u8, u8, u32)> = Vec::new();
        for &mask in &OBFUSCATION_MASKS {
            let new_key_byte = orig_key[ki] ^ mask;
            let new_char = stored[pos] ^ new_key_byte;
            if !is_printable(new_char) {
                continue;
            }
            let wrap_pos = ki + 21;
            if wrap_pos < 32 {
                let wrap_dec = stored[wrap_pos] ^ new_key_byte;
                if !allowed_residuals.contains(&wrap_dec) {
                    continue;
                }
            }
            if !is_alpha(new_char) {
                continue;
            }
            candidates.push((mask, new_char, letter_freq(new_char as char)));
        }

        if candidates.is_empty() {
            continue;
        }

        // Use first-wins semantics on ties (matches Python's max() behavior).
        // This matters when upper/lowercase variants tie on frequency.
        let best = candidates.iter().reduce(|a, b| if b.2 > a.2 { b } else { a }).unwrap();

        if !is_password_char(orig_char) {
            // Phase 1: char not in common password set — pick best alpha correction
            corrected_key[ki] = orig_key[ki] ^ best.0;
        } else if orig_is_alpha {
            // Phase 2: original is alpha — only correct if much better alternative exists
            if best.2 > orig_freq * FREQ_RATIO_THRESHOLD {
                corrected_key[ki] = orig_key[ki] ^ best.0;
            }
        }
    }

    // Check first byte for obfuscation
    let first_byte = stored[0];
    let mut corrected_first = first_byte;
    if !is_password_char(first_byte) {
        let mut best_freq = 0u32;
        for &mask in &OBFUSCATION_MASKS {
            let candidate = first_byte ^ mask;
            if is_alpha(candidate) {
                let freq = letter_freq(candidate as char);
                if freq > best_freq {
                    best_freq = freq;
                    corrected_first = candidate;
                }
            }
        }
    }

    // Decrypt with corrected key
    let mut decrypted = vec![0u8; 32];
    decrypted[0] = corrected_first;
    for j in 1..32 {
        decrypted[j] = stored[j] ^ corrected_key[(j - 1) % 20];
    }

    let new_password = String::from_utf8_lossy(&decrypted[..pwd_len]).to_string();
    if new_password != password {
        (new_password, corrected_key)
    } else {
        (password.to_string(), key.to_vec())
    }
}

/// Identify which password characters are uncertain due to DVAR obfuscation correction.
pub fn analyze_uncertainty(stored: &[u8], password: &str, key: &[u8]) -> Vec<UncertainChar> {
    let pwd_len = password.len();
    if pwd_len >= 11 || pwd_len < 2 {
        return Vec::new();
    }

    // Reconstruct original wrap-derived key
    let mut wrap_key = vec![0u8; 20];
    for i in 21..32 {
        wrap_key[(i - 1) % 20] = stored[i];
    }
    for i in pwd_len..21 {
        wrap_key[(i - 1) % 20] = stored[i];
    }

    let wrap_only_end = (pwd_len - 1).min(11);
    let wrap_only: Vec<usize> = (0..wrap_only_end).collect();

    let allowed_residuals: std::collections::HashSet<u8> =
        std::iter::once(0).chain(OBFUSCATION_MASKS.iter().copied()).collect();

    let mut uncertain = Vec::new();

    // Check first byte
    let first_raw = stored[0];
    let first_corrected = password.as_bytes()[0];
    if first_raw != first_corrected {
        let mut seen_lower = std::collections::HashSet::new();
        seen_lower.insert((first_corrected as char).to_ascii_lowercase());
        let raw_char = if is_printable(first_raw) {
            let c = first_raw as char;
            seen_lower.insert(c.to_ascii_lowercase());
            Some(c)
        } else {
            None
        };

        let mut alts = Vec::new();
        for &mask in &OBFUSCATION_MASKS {
            let cand = first_raw ^ mask;
            if cand == first_corrected {
                continue;
            }
            if !is_alpha(cand) {
                continue;
            }
            let ch = (cand as char).to_ascii_lowercase();
            if !seen_lower.contains(&ch) {
                seen_lower.insert(ch);
                alts.push(ch);
            }
        }
        alts.sort_by(|a, b| letter_freq(*b).cmp(&letter_freq(*a)));
        uncertain.push(UncertainChar {
            position: 1,
            chosen: first_corrected as char,
            original: raw_char,
            alternatives: alts,
        });
    }

    for &ki in &wrap_only {
        let pos = ki + 1;
        let wrap_byte = stored[ki + 21];
        let corrected_byte = key[ki];

        if corrected_byte == wrap_byte {
            continue;
        }

        let chosen_char = (stored[pos] ^ corrected_byte) as char;
        let orig_val = stored[pos] ^ wrap_byte;
        let original_char = if is_printable(orig_val) {
            Some(orig_val as char)
        } else {
            None
        };

        let mut seen_lower = std::collections::HashSet::new();
        seen_lower.insert(chosen_char.to_ascii_lowercase());
        if let Some(oc) = original_char {
            seen_lower.insert(oc.to_ascii_lowercase());
        }

        let mut alternatives = Vec::new();
        for &mask in &OBFUSCATION_MASKS {
            let alt_key_byte = wrap_byte ^ mask;
            if alt_key_byte == corrected_byte {
                continue;
            }
            let alt_val = stored[pos] ^ alt_key_byte;
            if !is_printable(alt_val) {
                continue;
            }
            let alt_char = alt_val as char;
            if !alt_char.is_ascii_alphabetic() {
                continue;
            }
            let wrap_pos = ki + 21;
            if wrap_pos < 32 {
                let wrap_dec = stored[wrap_pos] ^ alt_key_byte;
                if !allowed_residuals.contains(&wrap_dec) {
                    continue;
                }
            }
            let lc = alt_char.to_ascii_lowercase();
            if !seen_lower.contains(&lc) {
                seen_lower.insert(lc);
                alternatives.push(lc);
            }
        }
        alternatives.sort_by(|a, b| letter_freq(*b).cmp(&letter_freq(*a)));

        uncertain.push(UncertainChar {
            position: pos + 1,
            chosen: chosen_char,
            original: original_char,
            alternatives,
        });
    }

    uncertain
}

/// Recover plaintext password from a 32-byte XOR-encrypted record.
/// Tries short recovery first, then long. Applies DVAR obfuscation correction.
pub fn recover_password_from_record(stored: &[u8]) -> Option<(String, Vec<u8>)> {
    let short = recover_password_short(stored);
    let long = recover_password_long(stored);

    // Prefer the longer result
    if let Some((ref lp, _)) = long {
        if short.as_ref().map_or(true, |(sp, _)| lp.len() > sp.len()) {
            return long;
        }
    }
    if let Some((sp, sk)) = short {
        let (corrected_pw, corrected_key) = correct_dvar_obfuscation(stored, &sp, &sk);
        return Some((corrected_pw, corrected_key));
    }

    None
}

/// Scan a region for XOR-encrypted password records.
pub fn scan_for_passwords(
    data: &[u8],
    start: usize,
    end: usize,
    include_partial: bool,
) -> Vec<PasswordRecord> {
    let mut results = Vec::new();
    let mut skip_until = 0usize;
    let scan_end = end.min(data.len().saturating_sub(32));

    let mut offset = start;
    while offset < scan_end {
        if offset < skip_until {
            offset += 1;
            continue;
        }

        let record = &data[offset..offset + 32];
        let recovery = recover_password_from_record(record);

        if let Some((password, key)) = recovery {
            let is_partial = password.contains('?');

            if is_partial {
                if !include_partial {
                    offset += 1;
                    continue;
                }
                if password.len() < 10 {
                    offset += 1;
                    continue;
                }
                let known_chars = password.chars().filter(|&c| c != '?').count();
                if known_chars < 8 {
                    offset += 1;
                    continue;
                }
                let nonzero_key: std::collections::HashSet<u8> =
                    key.iter().filter(|&&b| b != 0).copied().collect();
                if nonzero_key.len() < 4 {
                    offset += 1;
                    continue;
                }
            } else {
                // Filter: key must have sufficient entropy
                let unique_key: std::collections::HashSet<u8> = key.iter().copied().collect();
                if unique_key.len() < 8 {
                    offset += 1;
                    continue;
                }

                // Filter: reject keys with many zero bytes
                if key.iter().filter(|&&b| b == 0x00).count() > 2 {
                    offset += 1;
                    continue;
                }

                // Filter: reject keys with a dominant byte value
                let mut counts = HashMap::new();
                for &b in &key {
                    *counts.entry(b).or_insert(0u32) += 1;
                }
                if counts.values().copied().max().unwrap_or(0) > 3 {
                    offset += 1;
                    continue;
                }

                // Filter: reject keys that are mostly printable ASCII
                let ascii_in_key = key.iter().filter(|&&b| is_printable(b)).count();
                if ascii_in_key > 12 {
                    offset += 1;
                    continue;
                }

                // Filter: reject keys with many low-value bytes
                let low_bytes = key.iter().filter(|&&b| b <= 0x0f).count();
                if low_bytes > 6 {
                    offset += 1;
                    continue;
                }

                // Filter: reject stored records with many zero bytes
                let stored_slice = &data[offset + 1..offset + 32];
                if stored_slice.iter().filter(|&&b| b == 0x00).count() > 4 {
                    offset += 1;
                    continue;
                }

                // Filter: verify wrap region consistency (short passwords only)
                if password.len() <= 20 {
                    let stored_record = &data[offset..offset + 32];
                    let mut wrap_errors = 0u32;
                    for i in 21..32 {
                        let ki = (i - 1) % 20;
                        if stored_record[i] != key[ki] {
                            wrap_errors += 1;
                        }
                    }
                    let max_wrap_errors = (password.len() / 2 + 1) as u32;
                    if wrap_errors > max_wrap_errors.min(5) {
                        offset += 1;
                        continue;
                    }
                }
            }

            // Filter: minimum password length 3
            if password.len() < 3 {
                offset += 1;
                continue;
            }

            results.push(PasswordRecord {
                offset,
                password,
                stored: data[offset..offset + 32].to_vec(),
                key,
                is_partial,
            });
            skip_until = offset + 32;
        }

        offset += 1;
    }

    results
}

/// Format password recovery results for display.
pub fn format_results(records: &[PasswordRecord]) -> String {
    let mut out = String::new();

    if records.is_empty() {
        out.push_str("No passwords found.\n");
        out.push_str("Possible reasons:\n");
        out.push_str("  - No BIOS password is set\n");
        out.push_str("  - Password store uses a different format (different Dell model?)\n");
        out.push_str("  - DVAR region not found or corrupted\n");
        return out;
    }

    out.push_str(&format!("Found {} password(s):\n\n", records.len()));

    for (i, rec) in records.iter().enumerate() {
        let key_hex: String = rec.key.iter().map(|b| format!("{b:02x}")).collect();

        out.push_str(&format!("  [{}] \"{}\"\n", i + 1, rec.password));
        out.push_str(&format!("      Offset: 0x{:06x}\n", rec.offset));

        if rec.is_partial {
            let known = rec.password.chars().filter(|&c| c != '?').count();
            let unknown = rec.password.len() - known;
            out.push_str(&format!(
                "      Length: {} characters ({} recovered, {} unknown)\n",
                rec.password.len(),
                known,
                unknown
            ));
        } else {
            out.push_str(&format!("      Length: {} characters\n", rec.password.len()));
        }

        out.push_str(&format!("      XOR key: 0x{key_hex}\n"));

        // Count wrap-region mismatches
        let mut wrap_mismatches = 0u32;
        for j in 21..32 {
            let ki = (j - 1) % 20;
            if rec.stored[j] != rec.key[ki] {
                wrap_mismatches += 1;
            }
        }

        if wrap_mismatches > 0 {
            let pwd_len = rec.password.len();
            let expected = if pwd_len > 20 {
                (pwd_len - 21).max(0) as u32
            } else {
                0
            };
            let real_obfuscation = wrap_mismatches.saturating_sub(expected);

            if real_obfuscation > 0 && pwd_len <= 10 {
                let uncertain = analyze_uncertainty(&rec.stored, &rec.password, &rec.key);
                let corrections: Vec<_> = uncertain
                    .iter()
                    .filter(|u| u.original.is_some() && u.original.unwrap() != u.chosen)
                    .collect();
                out.push_str(&format!(
                    "      DVAR obfuscation: {} bit flips \u{2014} all {} chars unverifiable (~80-90% accurate)\n",
                    real_obfuscation, pwd_len
                ));
                for u in &corrections {
                    let alt_str = if u.alternatives.is_empty() {
                        "none".to_string()
                    } else {
                        u.alternatives.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
                    };
                    out.push_str(&format!(
                        "        corrected char {}: '{}' -> '{}' (also: {})\n",
                        u.position,
                        u.original.unwrap(),
                        u.chosen,
                        alt_str
                    ));
                }
            } else if real_obfuscation > 0 {
                out.push_str(&format!(
                    "      DVAR obfuscation: {} wrap-region bit flips corrected\n",
                    real_obfuscation
                ));
            }
        }

        out.push('\n');
    }

    out
}

/// Format results with hex details (--raw mode).
pub fn format_results_raw(records: &[PasswordRecord]) -> String {
    let mut out = format_results(records);

    // Insert raw hex after each record
    // This is a simplified approach - just append raw data
    if !records.is_empty() {
        out.push_str("Raw details:\n\n");
        for (i, rec) in records.iter().enumerate() {
            let stored_hex: String = rec
                .stored
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let key_hex: String = rec
                .key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("  [{}] Stored: {}\n", i + 1, stored_hex));
            out.push_str(&format!("      Key:    {}\n\n", key_hex));
        }
    }

    out
}
