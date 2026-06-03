//! 512-byte MBR sector parsing — pure `&[u8]` interface, no I/O.

use crate::partition::PartitionEntry;
use crate::Error;

/// MBR sector layout constants.
pub const SECTOR_SIZE: usize = 512;
pub const BOOT_CODE_LEN: usize = 446;
const DISK_SERIAL_OFFSET: usize = 440;
const RESERVED_OFFSET: usize = 444;
const PT_OFFSET: usize = 446;
const SIGNATURE_OFFSET: usize = 510;
const BOOT_SIG: [u8; 2] = [0x55, 0xAA];

/// A parsed 512-byte MBR sector.
#[derive(Debug, Clone)]
pub struct MbrSector {
    /// First 446 bytes: bootstrap code area.
    pub boot_code: [u8; BOOT_CODE_LEN],
    /// Windows-NT-style disk serial at offset 440 (little-endian u32).
    /// Pre-NT MBRs leave this as zero or random data.
    pub disk_serial: u32,
    /// 2 reserved bytes at offset 444 — should be `[0x00, 0x00]`.
    pub reserved: [u8; 2],
    /// Four 16-byte primary partition entries.
    pub entries: [PartitionEntry; 4],
    /// Boot signature at offset 510 — must be `[0x55, 0xAA]`.
    pub signature: [u8; 2],
}

/// Parse a 512-byte MBR sector.
///
/// Returns [`Error::TooShort`] if `sector.len() < 512`.
/// Returns [`Error::BadSignature`] if bytes 510–511 ≠ `0x55 0xAA`.
pub fn parse_mbr_sector(sector: &[u8]) -> Result<MbrSector, Error> {
    if sector.len() < SECTOR_SIZE {
        return Err(Error::TooShort(sector.len()));
    }

    let sig = [sector[SIGNATURE_OFFSET], sector[SIGNATURE_OFFSET + 1]];
    if sig != BOOT_SIG {
        let val = u16::from_be_bytes(sig);
        return Err(Error::BadSignature(val));
    }

    let mut boot_code = [0u8; BOOT_CODE_LEN];
    boot_code.copy_from_slice(&sector[..BOOT_CODE_LEN]);

    let disk_serial = u32::from_le_bytes([
        sector[DISK_SERIAL_OFFSET],
        sector[DISK_SERIAL_OFFSET + 1],
        sector[DISK_SERIAL_OFFSET + 2],
        sector[DISK_SERIAL_OFFSET + 3],
    ]);

    let reserved = [sector[RESERVED_OFFSET], sector[RESERVED_OFFSET + 1]];

    let entries = std::array::from_fn(|i| {
        let off = PT_OFFSET + i * 16;
        let buf: &[u8; 16] = sector[off..off + 16].try_into().unwrap();
        PartitionEntry::from_bytes(buf)
    });

    Ok(MbrSector {
        boot_code,
        disk_serial,
        reserved,
        entries,
        signature: sig,
    })
}
