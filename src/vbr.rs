//! Volume Boot Record (VBR) / BIOS Parameter Block parsing.
//!
//! FAT12/16/32 and NTFS share the DOS 3.31 BPB layout in their first sector.
//! The "hidden sectors" field (BPB offset `0x1C`, little-endian `u32`) records
//! the partition's LBA offset from the start of the disk. For a correctly
//! placed volume it equals the partition-table `lba_start`; a nonzero mismatch
//! means the volume was relocated/copied (or the table edited to point
//! elsewhere) without updating the VBR — a relocation / data-hiding indicator.
//!
//! [`parse_bpb`] validates the candidate sector (boot signature + plausible
//! geometry) so it returns `None` for non-FAT/NTFS first sectors — including
//! exFAT, whose `bytes_per_sector` field is zero.

/// Parsed BIOS Parameter Block fields relevant to forensic cross-checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Bpb {
    /// Bytes per logical sector (512, 1024, 2048, or 4096).
    pub bytes_per_sector: u16,
    /// Sectors per allocation cluster (a power of two).
    pub sectors_per_cluster: u8,
    /// Count of reserved sectors at the start of the volume.
    pub reserved_sectors: u16,
    /// Hidden sectors — the volume's LBA offset from the disk start (BPB 0x1C).
    pub hidden_sectors: u32,
}

/// Parse and validate a FAT/NTFS BPB from a boot sector.
///
/// Returns `None` unless the sector is ≥ 512 bytes, carries the `0x55AA` boot
/// signature, and has a plausible `bytes_per_sector` ∈ {512, 1024, 2048, 4096}
/// and power-of-two `sectors_per_cluster`. This rejects non-FAT/NTFS first
/// sectors (random data, exFAT, all-zero) rather than mis-parsing them.
#[must_use]
pub fn parse_bpb(sector: &[u8]) -> Option<Bpb> {
    if sector.len() < 512 {
        return None;
    }
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }
    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return None;
    }
    let sectors_per_cluster = sector[13];
    if !sectors_per_cluster.is_power_of_two() {
        return None;
    }
    let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
    let hidden_sectors = u32::from_le_bytes([sector[28], sector[29], sector[30], sector[31]]);
    Some(Bpb {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        hidden_sectors,
    })
}
