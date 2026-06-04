//! Filesystem magic-byte detection from the first sector of a partition.
//!
//! The detection is intentionally broad: it looks for well-known filesystem
//! signatures without attempting full validation.  The goal is to surface
//! declared-type vs detected-type mismatches, not to fully identify the FS.

/// Filesystem type detected from a partition's first-sector bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum DetectedFs {
    /// Linux ext2/3/4 — magic `0x53EF` at offset 0x438 (1080).
    Ext,
    /// NTFS — OEM ID `"NTFS    "` at offset 3.
    Ntfs,
    /// FAT12/16/32 — OEM ID `"MSDOS5.0"` or `"MSWIN4.1"` or similar at 3,
    /// or FAT signature `"FAT"` in the FS info region.
    Fat,
    /// APFS — magic `"NXSB"` at offset 0.
    Apfs,
    /// Linux swap — magic `"SWAPSPACE2"` or `"PAGESPACE1"` at offset 4086.
    LinuxSwap,
    /// Linux LVM2 physical volume — `"LABELONE"` near the start.
    LinuxLvm,
    /// LUKS encrypted volume — magic `"LUKS\xba\xbe"` at offset 0.
    Luks,
    /// XFS — magic `"XFSB"` at offset 0.
    Xfs,
    /// Btrfs — magic `"_BHRfS_M"` at offset 64 KiB.  Only detected when
    /// the sector slice is large enough.
    Btrfs,
    /// exFAT — OEM name `"EXFAT   "` at offset 3.
    ExFat,
    /// All bytes are zero — unformatted or zeroed partition.
    AllZeros,
    /// No recognised signature found.
    Unknown,
}

/// Well-known FAT OEM identifier strings found at sector offset 3.
const FAT_OEM_IDS: &[&[u8]] = &[
    b"MSDOS5.0",
    b"MSWIN4.0",
    b"MSWIN4.1",
    b"mkdosfs ",
    b"FreeDOS ",
];

/// Attempt to identify the filesystem from a partition's first sectors.
/// Returns [`DetectedFs::Unknown`] if nothing matches.
///
/// The shared filesystem magics (ext/NTFS/exFAT/XFS/LUKS/FAT/swap) come from the
/// [`forensicnomicon::filesystems`] knowledge base; a few mbr-specific detections
/// not (yet) in that table — APFS, the FAT OEM-ID heuristic, the `PAGESPACE1`
/// swap variant, LVM, and Btrfs — remain local fallbacks.
#[must_use]
pub fn detect(sector: &[u8]) -> DetectedFs {
    if sector.is_empty() {
        return DetectedFs::Unknown;
    }
    if sector.iter().all(|&b| b == 0) {
        return DetectedFs::AllZeros;
    }

    if let Some(fs) = forensicnomicon::filesystems::detect_name(sector).and_then(map_fs_name) {
        return fs;
    }

    // APFS container superblock magic at the start of the window.
    if sector.len() >= 4 && &sector[0..4] == b"NXSB" {
        return DetectedFs::Apfs;
    }
    // FAT: OEM ID at bytes 3–10, matched against well-known formatter strings.
    if sector.len() >= 11 && FAT_OEM_IDS.iter().any(|id| *id == &sector[3..11]) {
        return DetectedFs::Fat;
    }
    // Older AIX/Linux paging signature `PAGESPACE1` (SWAPSPACE2 is in the KB).
    if sector.len() >= 4096 && &sector[4086..4096] == b"PAGESPACE1" {
        return DetectedFs::LinuxSwap;
    }
    // Linux LVM2: "LABELONE" within the first 512 bytes.
    if find_substr(sector, b"LABELONE").is_some_and(|pos| pos < 512) {
        return DetectedFs::LinuxLvm;
    }
    // Btrfs: superblock magic "_BHRfS_M" at offset 64 KiB. Only detectable when
    // the caller supplies a fingerprint window large enough to reach it.
    if sector.len() >= 65536 + 8 && &sector[65536..65536 + 8] == b"_BHRfS_M" {
        return DetectedFs::Btrfs;
    }

    DetectedFs::Unknown
}

/// Map a `forensicnomicon::filesystems` name to this crate's [`DetectedFs`].
/// Returns `None` for names with no corresponding variant (ISO 9660, HFS+).
fn map_fs_name(name: &str) -> Option<DetectedFs> {
    Some(match name {
        "ext2/3/4" => DetectedFs::Ext,
        "NTFS" => DetectedFs::Ntfs,
        "exFAT" => DetectedFs::ExFat,
        "XFS" => DetectedFs::Xfs,
        "LUKS" => DetectedFs::Luks,
        "Linux swap" => DetectedFs::LinuxSwap,
        "FAT32" | "FAT16" | "FAT12" => DetectedFs::Fat,
        _ => return None,
    })
}

/// Returns `true` when a declared partition family and a detected filesystem
/// are clearly incompatible — the basis for a `SignatureMismatch` anomaly.
///
/// Deliberately conservative: `Unknown` / `AllZeros` detections never conflict
/// (a partition's first sector may simply be unwritten), and only well-known
/// contradictions (e.g. a partition declared NTFS whose first sector is ext4)
/// are reported. This is the single source of truth for the mismatch policy.
#[must_use]
pub fn type_conflicts(declared: crate::partition::PartitionFamily, detected: DetectedFs) -> bool {
    use crate::partition::PartitionFamily as Pf;
    use DetectedFs as Df;
    if matches!(detected, Df::Unknown | Df::AllZeros) {
        return false;
    }
    matches!(
        (declared, detected),
        (
            Pf::Ntfs,
            Df::Ext
                | Df::Fat
                | Df::Luks
                | Df::LinuxSwap
                | Df::LinuxLvm
                | Df::Xfs
                | Df::Btrfs
                | Df::Apfs
        ) | (
            Pf::Fat16 | Pf::Fat32 | Pf::Fat12,
            Df::Ntfs
                | Df::Ext
                | Df::Luks
                | Df::LinuxSwap
                | Df::LinuxLvm
                | Df::Xfs
                | Df::Btrfs
                | Df::Apfs
        ) | (Pf::Linux, Df::Ntfs | Df::Fat | Df::Luks | Df::Apfs)
            | (Pf::LinuxSwap, Df::Ntfs | Df::Fat | Df::Ext | Df::Btrfs | Df::Apfs)
            | (Pf::LinuxLvm, Df::Ntfs | Df::Fat | Df::Ext | Df::Btrfs | Df::Apfs)
    )
}

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
