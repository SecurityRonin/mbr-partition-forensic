//! Partitioner / era attribution from partition-table geometry.
//!
//! The first partition's start LBA is a durable provenance signal. Historically
//! `fdisk` and Windows XP aligned the first partition to the end of the first
//! track at **LBA 63** (cylinder alignment). From Windows Vista onward, and in
//! modern Linux tooling, the first partition is aligned to a **1 MiB boundary
//! (LBA 2048)** for performance on Advanced Format / SSD media. The transition
//! is sharp enough to bracket the era — and an *odd* alignment is itself a hint
//! of hand-editing.
//!
//! These are pure, conservative inferences exposed for callers to weight; they
//! are deliberately not emitted as anomalies.

use crate::boot_code::BootCodeId;

/// Alignment class of a partition's start LBA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Aligned to a 1 MiB / 2048-sector boundary (modern convention).
    Mib1,
    /// Exactly LBA 63 — the legacy end-of-first-track convention.
    LegacyTrack,
    /// Neither convention — unusual; a possible hand-editing hint.
    Unaligned,
}

/// Inferred era of the tool that created the partition layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitioningEra {
    /// 1 MiB alignment / Vista-plus boot code — modern tooling.
    Modern,
    /// LBA-63 alignment / legacy boot code — pre-2008 fdisk / Windows XP era.
    LegacyCylinder,
    /// Insufficient signal to attribute.
    Unknown,
}

/// Classify a start LBA's alignment.
///
/// A 1 MiB boundary takes precedence (a partition at LBA 2048 is "modern"
/// regardless of also being a multiple of 63 — it isn't, but the ordering keeps
/// the intent explicit). LBA 0 is the MBR sector itself and classes as
/// [`Alignment::Unaligned`] (no data partition starts there).
#[must_use]
pub fn classify_alignment(lba_start: u64) -> Alignment {
    if lba_start != 0 && lba_start % 2048 == 0 {
        Alignment::Mib1
    } else if lba_start == 63 {
        Alignment::LegacyTrack
    } else {
        Alignment::Unaligned
    }
}

/// Infer the partitioning era from the first partition's start LBA, falling back
/// to the boot-code identity when alignment is inconclusive.
///
/// `first_partition_lba` is the lowest start LBA among real (non-extended,
/// non-protective) primary partitions, or `None` when there are none.
#[must_use]
pub fn infer_era(first_partition_lba: Option<u64>, boot: BootCodeId) -> PartitioningEra {
    match first_partition_lba.map(classify_alignment) {
        Some(Alignment::Mib1) => PartitioningEra::Modern,
        Some(Alignment::LegacyTrack) => PartitioningEra::LegacyCylinder,
        _ => era_from_boot_code(boot),
    }
}

/// Tiebreaker: attribute era from the recognised boot loader when geometry is
/// inconclusive.
fn era_from_boot_code(boot: BootCodeId) -> PartitioningEra {
    match boot {
        BootCodeId::WindowsVista | BootCodeId::Windows7Plus | BootCodeId::Grub2 => {
            PartitioningEra::Modern
        }
        BootCodeId::GrubLegacy => PartitioningEra::LegacyCylinder,
        _ => PartitioningEra::Unknown,
    }
}
