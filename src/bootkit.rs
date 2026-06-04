//! Known boot-sector-malware marker detection.
//!
//! Boot-sector viruses and MBR bootkits routinely embed plaintext markers in
//! the 446-byte boot-code area (taunt messages, ransom text, family tags). This
//! module scans for an **extensible** table of such markers; a match is a
//! definitive tampering indicator surfaced as [`crate::AnomalyKind::KnownBootkit`].
//!
//! # Signature policy
//!
//! Markers are matched as substrings anywhere in the boot code, so a signature
//! needs only the literal bytes — no fragile fixed offsets. The seed set is
//! deliberately limited to **publicly-documented historical markers** (the 1987
//! "Stoned" boot virus) so that no pattern here is fabricated. Operators are
//! expected to extend [`KNOWN_SIGNATURES`] with vetted markers from their own
//! threat intel.

/// One boot-sector-malware marker: a family `name` and the literal `needle`
/// bytes that, if present anywhere in the boot code, identify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BootSignature {
    /// Malware family / variant name reported on a match.
    pub name: &'static str,
    /// Literal bytes searched for anywhere in the boot-code area.
    pub needle: &'static [u8],
}

/// Seed table of documented boot-sector-malware markers.
///
/// Extensible by design — see the module-level signature policy. The "Stoned"
/// virus (1987) is the canonical documented example and serves as the seed.
pub const KNOWN_SIGNATURES: &[BootSignature] = &[
    BootSignature {
        name: "Stoned",
        needle: b"Your PC is now Stoned!",
    },
    BootSignature {
        name: "Stoned",
        needle: b"LEGALISE MARIJUANA",
    },
];

/// Scan `boot_code` for every known marker, returning the distinct family names
/// that matched, in table order (each family reported at most once).
#[must_use]
pub fn scan(boot_code: &[u8]) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = Vec::new();
    for sig in KNOWN_SIGNATURES {
        if contains(boot_code, sig.needle) && !hits.contains(&sig.name) {
            hits.push(sig.name);
        }
    }
    hits
}

/// `true` when `needle` occurs anywhere in `haystack`. Empty needles never match.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}
