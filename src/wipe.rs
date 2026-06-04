//! Wipe-pattern classification for raw byte regions.
//!
//! Disk-wiping tools overwrite space with characteristic fills: all-zero,
//! all-`0xFF`, a single repeated byte, an alternating two-byte pattern
//! (`0x55`/`0xAA`), or pseudo-random data. On a static image only the final
//! pass survives, but that pass still betrays a deliberate wipe — an
//! anti-forensic / destruction trace. This module classifies a region's fill so
//! the pipeline can distinguish *deliberately overwritten* space from ordinary
//! unallocated (zero) space.

use crate::entropy::{self, HIGH_ENTROPY_THRESHOLD};

/// The dominant fill pattern of a byte region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum FillPattern {
    /// Entirely `0x00` — ordinary unallocated space (not a deliberate-wipe signal).
    Zeros,
    /// Entirely `0xFF`.
    Ones,
    /// Entirely one repeated byte value (other than `0x00` / `0xFF`).
    Uniform(u8),
    /// A repeating two-byte alternation `a, b, a, b, …` with `a != b`.
    Alternating(u8, u8),
    /// Near-maximal Shannon entropy — pseudo-random or encrypted fill.
    HighEntropy,
    /// No dominant pattern — ordinary structured data.
    Mixed,
}

impl FillPattern {
    /// `true` when this pattern is the signature of a *deliberate* overwrite.
    ///
    /// All-zero space is excluded: it is the default state of unallocated
    /// sectors and carries no destruction signal on its own.
    #[must_use]
    pub fn is_deliberate_wipe(self) -> bool {
        matches!(
            self,
            FillPattern::Ones | FillPattern::Uniform(_) | FillPattern::Alternating(_, _)
        )
    }

    /// Short human-readable label, e.g. `"all 0xFF"` or `"alternating 0x55/0xAA"`.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            FillPattern::Zeros => "all 0x00".to_string(),
            FillPattern::Ones => "all 0xFF".to_string(),
            FillPattern::Uniform(b) => format!("uniform {b:#04X}"),
            FillPattern::Alternating(a, b) => format!("alternating {a:#04X}/{b:#04X}"),
            FillPattern::HighEntropy => "high-entropy (random/encrypted)".to_string(),
            FillPattern::Mixed => "mixed".to_string(),
        }
    }
}

/// Classify the dominant fill pattern of `data`.
///
/// An empty slice classifies as [`FillPattern::Mixed`] (nothing to judge).
#[must_use]
pub fn classify(data: &[u8]) -> FillPattern {
    if data.is_empty() {
        return FillPattern::Mixed;
    }

    let first = data[0];
    if data.iter().all(|&b| b == first) {
        return match first {
            0x00 => FillPattern::Zeros,
            0xFF => FillPattern::Ones,
            other => FillPattern::Uniform(other),
        };
    }

    if data.len() >= 2 {
        let (a, b) = (data[0], data[1]);
        if a != b
            && data
                .iter()
                .enumerate()
                .all(|(i, &x)| x == if i % 2 == 0 { a } else { b })
        {
            return FillPattern::Alternating(a, b);
        }
    }

    if entropy::shannon(data) > HIGH_ENTROPY_THRESHOLD {
        return FillPattern::HighEntropy;
    }

    FillPattern::Mixed
}
