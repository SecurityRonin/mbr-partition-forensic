//! Unpartitioned LBA space analysis.

/// A region of unpartitioned disk space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Gap {
    /// First LBA of the unpartitioned region.
    pub lba_start: u64,
    /// Last LBA of the unpartitioned region (inclusive).
    pub lba_end: u64,
    /// Size in bytes (`(lba_end - lba_start + 1) * sector_size`).
    pub byte_size: u64,
    /// Why this gap exists in the layout.
    pub kind: GapKind,
}

/// Classification of a gap's position on the disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum GapKind {
    /// Space between LBA 0 (MBR sector) and the first partition.
    PrePartition,
    /// Space between two adjacent partitions.
    Between,
    /// Space after the last partition, before the end of the disk.
    PostPartition,
}

/// Compute all unpartitioned gaps in a set of sorted partition extents.
///
/// `extents` should be `(lba_start, lba_end)` inclusive pairs, sorted by
/// `lba_start`. `disk_last_lba` is the inclusive last LBA of the disk.
/// `first_usable` is the first LBA available for partition data (typically 1
/// for MBR, but callers may pass the real first-available value).
#[must_use]
pub fn compute_gaps(
    extents: &[(u64, u64)],
    first_usable: u64,
    disk_last_lba: u64,
    sector_size: u64,
) -> Vec<Gap> {
    let mut gaps = Vec::new();
    let mut cursor = first_usable;

    for &(start, end) in extents {
        if start > cursor {
            let kind = if cursor == first_usable {
                GapKind::PrePartition
            } else {
                GapKind::Between
            };
            let lba_end = start - 1;
            gaps.push(Gap {
                lba_start: cursor,
                lba_end,
                byte_size: (lba_end - cursor + 1) * sector_size,
                kind,
            });
        }
        if end >= cursor {
            cursor = end + 1;
        }
    }

    if cursor <= disk_last_lba {
        gaps.push(Gap {
            lba_start: cursor,
            lba_end: disk_last_lba,
            byte_size: (disk_last_lba - cursor + 1) * sector_size,
            kind: GapKind::PostPartition,
        });
    }

    gaps
}
