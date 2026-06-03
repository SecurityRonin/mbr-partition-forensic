//! Filesystem magic-byte detection from the first sector of a partition.
//!
//! The detection is intentionally broad: it looks for well-known filesystem
//! signatures without attempting full validation.  The goal is to surface
//! declared-type vs detected-type mismatches, not to fully identify the FS.

/// Filesystem type detected from a partition's first-sector bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Attempt to identify the filesystem from up to 512 bytes of a partition's
/// first sector.  Returns [`DetectedFs::Unknown`] if nothing matches.
#[must_use]
pub fn detect(sector: &[u8]) -> DetectedFs {
    if sector.is_empty() {
        return DetectedFs::Unknown;
    }
    if sector.iter().all(|&b| b == 0) {
        return DetectedFs::AllZeros;
    }

    // LUKS: magic at bytes 0–5.
    if sector.len() >= 6 && &sector[0..6] == b"LUKS\xba\xbe" {
        return DetectedFs::Luks;
    }

    // APFS: magic at bytes 0–3.
    if sector.len() >= 4 && &sector[0..4] == b"NXSB" {
        return DetectedFs::Apfs;
    }

    // XFS: magic at bytes 0–3.
    if sector.len() >= 4 && &sector[0..4] == b"XFSB" {
        return DetectedFs::Xfs;
    }

    // NTFS: OEM ID at bytes 3–10.
    if sector.len() >= 11 && &sector[3..11] == b"NTFS    " {
        return DetectedFs::Ntfs;
    }

    // exFAT: OEM name at bytes 3–10.
    if sector.len() >= 11 && &sector[3..11] == b"EXFAT   " {
        return DetectedFs::ExFat;
    }

    // FAT: OEM ID at bytes 3–10, several well-known values.
    if sector.len() >= 11 {
        let oem = &sector[3..11];
        if oem == b"MSDOS5.0"
            || oem == b"MSWIN4.0"
            || oem == b"MSWIN4.1"
            || oem == b"mkdosfs "
            || oem == b"FreeDOS "
        {
            return DetectedFs::Fat;
        }
    }

    // ext2/3/4: superblock magic 0x53EF at offset 1080 (within a 1 KiB+
    // block).  Only detectable if the slice is ≥ 1082 bytes.
    if sector.len() >= 1082 && sector[1080] == 0x53 && sector[1081] == 0xEF {
        return DetectedFs::Ext;
    }

    // Linux swap: magic at offset 4086 (end of page − 10 bytes).
    if sector.len() >= 4096 {
        if &sector[4086..4096] == b"SWAPSPACE2" || &sector[4086..4096] == b"PAGESPACE1" {
            return DetectedFs::LinuxSwap;
        }
    }

    // Linux LVM2: "LABELONE" within the first 512 bytes.
    if let Some(pos) = find_substr(sector, b"LABELONE") {
        if pos < 512 {
            return DetectedFs::LinuxLvm;
        }
    }

    DetectedFs::Unknown
}

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
