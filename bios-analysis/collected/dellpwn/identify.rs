//! BIOS vendor and platform identification from SPI flash dumps.

/// Identification result for a firmware image.
pub struct Identification {
    pub vendor: Option<BiosVendor>,
    pub oem: Option<Oem>,
    pub bios_id: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Oem {
    Dell,
    Hp,
}

impl std::fmt::Display for Oem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Oem::Dell => write!(f, "Dell"),
            Oem::Hp => write!(f, "HP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BiosVendor {
    AmiAptio,
}

impl std::fmt::Display for BiosVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BiosVendor::AmiAptio => write!(f, "AMI Aptio"),
        }
    }
}

/// Count non-overlapping occurrences of `needle` in `data`.
fn count_occurrences(data: &[u8], needle: &[u8]) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while pos + needle.len() <= data.len() {
        if let Some(idx) = data[pos..].windows(needle.len()).position(|w| w == needle) {
            count += 1;
            pos += idx + needle.len();
        } else {
            break;
        }
    }
    count
}

/// Find the first occurrence of `needle` in `data` and return its offset.
fn find_offset(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// Try to decode the $IBIOSI$ BIOS ID string.
///
/// The ID follows the marker and is typically UTF-16LE, null-terminated.
fn decode_ibiosi(data: &[u8], offset: usize) -> Option<String> {
    let start = offset + 8; // skip "$IBIOSI$"
    if start + 2 > data.len() {
        return None;
    }

    // Check if it's UTF-16LE (second byte is 0x00 for ASCII range)
    if data.get(start + 1) == Some(&0x00) {
        // UTF-16LE
        let end = (start + 120).min(data.len());
        let slice = &data[start..end];
        let u16s: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    } else {
        // Plain ASCII
        let end = (start + 60).min(data.len());
        let slice = &data[start..end];
        let s: String = slice
            .iter()
            .take_while(|&&b| b != 0 && b.is_ascii_graphic())
            .map(|&b| b as char)
            .collect();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

/// Identify the BIOS vendor and OEM from a firmware image.
pub fn identify(data: &[u8]) -> Identification {
    let mut evidence = Vec::new();
    let mut is_ami = false;
    let mut bios_id = None;
    let mut oem = None;

    // --- BIOS vendor detection ---

    // Check for NVAR entries (AMI proprietary NVRAM format)
    let nvar_count = count_occurrences(data, b"NVAR");
    if nvar_count > 0 {
        evidence.push(format!("NVAR store ({} entries)", nvar_count));
        is_ami = true;
    }

    // Check for $IBIOSI$ (AMI BIOS ID marker)
    if let Some(offset) = find_offset(data, b"$IBIOSI$") {
        if let Some(id) = decode_ibiosi(data, offset) {
            evidence.push(format!("$IBIOSI$ at 0x{:x}: {}", offset, id));
            bios_id = Some(id);
        } else {
            evidence.push(format!("$IBIOSI$ at 0x{:x}", offset));
        }
        is_ami = true;
    }

    // Check for AMITSESetup (AMI TSE variable)
    let tse_count = count_occurrences(data, b"AMITSESetup");
    if tse_count > 0 {
        evidence.push(format!("AMITSESetup ({} refs)", tse_count));
        is_ami = true;
    }

    // Check for $FID (AMI Firmware ID)
    if let Some(offset) = find_offset(data, b"$FID") {
        evidence.push(format!("$FID at 0x{:x}", offset));
        is_ami = true;
    }

    // --- OEM detection ---

    // Dell: DVAR store, SIVB, or $IBIOSI$ starting with "Dell"
    let has_dvar = find_offset(data, b"DVAR").is_some();
    let has_sivb = find_offset(data, b"SIVB").is_some();
    let bios_id_is_dell = bios_id.as_ref().is_some_and(|id| id.starts_with("Dell"));
    if has_dvar || has_sivb || bios_id_is_dell {
        oem = Some(Oem::Dell);
    }

    // HP: HpPassphraseStructureVariable, Hewlett-Packard, HP_SIGNATURE
    let has_hp_passphrase =
        find_offset(data, b"HpPassphraseStructureVariable").is_some();
    let has_hewlett_packard = find_offset(data, b"Hewlett-Packard").is_some();
    let has_hp_signature = find_offset(data, b"HP_SIGNATURE").is_some();
    if has_hp_passphrase || has_hewlett_packard || has_hp_signature {
        oem = Some(Oem::Hp);
    }

    Identification {
        vendor: if is_ami { Some(BiosVendor::AmiAptio) } else { None },
        oem,
        bios_id,
        evidence,
    }
}

/// Format identification results for display.
pub fn format_identification(id: &Identification) -> String {
    let mut out = String::new();

    match (&id.vendor, &id.oem) {
        (Some(vendor), Some(oem)) => {
            out.push_str(&format!("BIOS vendor: {} ({})\n", vendor, oem))
        }
        (Some(vendor), None) => out.push_str(&format!("BIOS vendor: {}\n", vendor)),
        (None, Some(oem)) => out.push_str(&format!("BIOS vendor: Unknown ({})\n", oem)),
        (None, None) => out.push_str("BIOS vendor: Unknown\n"),
    }

    if let Some(ref bios_id) = id.bios_id {
        out.push_str(&format!("BIOS ID: {}\n", bios_id));
    }

    if !id.evidence.is_empty() {
        out.push_str(&format!("Evidence: {}\n", id.evidence.join(", ")));
    }

    out
}
