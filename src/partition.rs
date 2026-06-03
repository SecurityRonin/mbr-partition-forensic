//! MBR partition entry types and partition-type-code semantics.

/// Decoded CHS (Cylinder-Head-Sector) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chs {
    pub cylinder: u16,
    pub head: u8,
    pub sector: u8,
}

impl Chs {
    /// Decode a 3-byte MBR CHS field.
    ///
    /// Byte layout (packed):
    /// ```text
    /// byte 0 = head
    /// byte 1 = [cyl_hi(7:6) | sector(5:0)]
    /// byte 2 = cyl_lo(7:0)
    /// ```
    #[must_use]
    pub fn from_bytes(b: [u8; 3]) -> Self {
        let head = b[0];
        let sector = b[1] & 0x3F;
        let cylinder = ((b[1] as u16 & 0xC0) << 2) | b[2] as u16;
        Chs { cylinder, head, sector }
    }

    /// Convert to an approximate LBA (≤1023 cylinders, ≤255 heads, ≤63 sectors).
    ///
    /// Returns `None` when CHS indicates "not used" (all zeros or all ones).
    #[must_use]
    pub fn to_lba(self, heads_per_cylinder: u8, sectors_per_track: u8) -> Option<u32> {
        if self.sector == 0 {
            return None;
        }
        let hpc = heads_per_cylinder as u32;
        let spt = sectors_per_track as u32;
        if hpc == 0 || spt == 0 {
            return None;
        }
        Some(
            (self.cylinder as u32) * hpc * spt
                + (self.head as u32) * spt
                + (self.sector as u32 - 1),
        )
    }
}

/// A single 16-byte primary partition table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    /// `0x80` = bootable, `0x00` = inactive, other values are invalid.
    pub status: u8,
    /// CHS address of the partition's first sector.
    pub chs_first: Chs,
    /// Partition type code.
    pub type_code: TypeCode,
    /// CHS address of the partition's last sector.
    pub chs_last: Chs,
    /// LBA address of the partition's first sector.
    pub lba_start: u32,
    /// Number of sectors in the partition.
    pub lba_count: u32,
}

impl PartitionEntry {
    /// Decode a 16-byte partition entry slice.
    #[must_use]
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        PartitionEntry {
            status: b[0],
            chs_first: Chs::from_bytes([b[1], b[2], b[3]]),
            type_code: TypeCode(b[4]),
            chs_last: Chs::from_bytes([b[5], b[6], b[7]]),
            lba_start: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            lba_count: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }

    /// Returns `true` if this entry is entirely zero (unused slot).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.type_code.is_empty() && self.lba_start == 0 && self.lba_count == 0
    }

    /// Returns `true` if the status byte marks this partition as bootable.
    #[must_use]
    pub fn is_bootable(&self) -> bool {
        self.status == 0x80
    }

    /// Inclusive last LBA of this partition, saturating on overflow.
    #[must_use]
    pub fn lba_end(&self) -> u32 {
        self.lba_start.saturating_add(self.lba_count).saturating_sub(1)
    }

    /// `true` if this entry describes an extended partition container.
    #[must_use]
    pub fn is_extended(&self) -> bool {
        self.type_code.is_extended()
    }
}

/// Wrapper around an MBR partition type byte with semantic helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeCode(pub u8);

impl TypeCode {
    /// Human-readable short name for the partition type.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self.0 {
            0x00 => "Empty",
            0x01 => "FAT12",
            0x04 => "FAT16 <32 MB",
            0x05 => "Extended (CHS)",
            0x06 => "FAT16",
            0x07 => "NTFS / exFAT / IFS",
            0x08 => "FAT32 (EISA / AIX)",
            0x0B => "FAT32 (CHS)",
            0x0C => "FAT32 (LBA)",
            0x0E => "FAT16 (LBA)",
            0x0F => "Extended (LBA)",
            0x11 => "Hidden FAT12",
            0x14 => "Hidden FAT16 <32 MB",
            0x16 => "Hidden FAT16",
            0x17 => "Hidden NTFS / IFS",
            0x1B => "Hidden FAT32 (CHS)",
            0x1C => "Hidden FAT32 (LBA)",
            0x1E => "Hidden FAT16 (LBA)",
            0x27 => "Windows Recovery / Hidden NTFS",
            0x42 => "Windows LDM / Dynamic Disk",
            0x82 => "Linux Swap / Solaris",
            0x83 => "Linux",
            0x84 => "Hibernate (Windows)",
            0x85 => "Linux Extended",
            0x86 => "Linux LVM (old)",
            0x87 => "NTFS Volume Set",
            0x8E => "Linux LVM",
            0x9F => "BSD/OS",
            0xA5 => "FreeBSD",
            0xA6 => "OpenBSD",
            0xA9 => "NetBSD",
            0xAB => "macOS Boot",
            0xAF => "macOS HFS+",
            0xBE => "Solaris Boot",
            0xBF => "Solaris",
            0xEB => "BeOS / Haiku",
            0xEE => "GPT Protective MBR",
            0xEF => "EFI System Partition (FAT)",
            0xFB => "VMware VMFS",
            0xFC => "VMware Swap",
            0xFD => "Linux RAID",
            0xFE => "Linux LAF / IBM IML",
            _ => "Unknown",
        }
    }

    /// High-level partition family classification.
    #[must_use]
    pub fn family(self) -> PartitionFamily {
        match self.0 {
            0x00 => PartitionFamily::Empty,
            0x01 | 0x11 => PartitionFamily::Fat12,
            0x04 | 0x06 | 0x0E | 0x14 | 0x16 | 0x1E => PartitionFamily::Fat16,
            0x0B | 0x0C | 0x1B | 0x1C => PartitionFamily::Fat32,
            0x07 | 0x17 | 0x87 => PartitionFamily::Ntfs,
            0x05 | 0x0F | 0x85 => PartitionFamily::ExtendedMbr,
            0x82 => PartitionFamily::LinuxSwap,
            0x83 => PartitionFamily::Linux,
            0x8E => PartitionFamily::LinuxLvm,
            0xFD => PartitionFamily::LinuxRaid,
            0x27 => PartitionFamily::WindowsRecovery,
            0x42 => PartitionFamily::WindowsDynamic,
            0xA5 => PartitionFamily::FreeBsd,
            0xA6 => PartitionFamily::OpenBsd,
            0xA9 => PartitionFamily::NetBsd,
            0xAF | 0xAB => PartitionFamily::Hfs,
            0xEE => PartitionFamily::GptProtective,
            0xEF => PartitionFamily::EfiSystem,
            0xFB | 0xFC => PartitionFamily::Vmware,
            _ => PartitionFamily::Unknown(self.0),
        }
    }

    /// `true` if this is an empty (unused) slot.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0x00
    }

    /// `true` if this type code marks an extended partition container.
    #[must_use]
    pub fn is_extended(self) -> bool {
        matches!(self.0, 0x05 | 0x0F | 0x85)
    }
}

/// High-level classification of a partition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionFamily {
    Empty,
    Fat12,
    Fat16,
    Fat32,
    Ntfs,
    ExtendedMbr,
    LinuxSwap,
    Linux,
    LinuxLvm,
    LinuxRaid,
    WindowsRecovery,
    WindowsDynamic,
    FreeBsd,
    OpenBsd,
    NetBsd,
    Hfs,
    GptProtective,
    EfiSystem,
    Vmware,
    Unknown(u8),
}
