//! Boot code identification by fingerprinting the first 446 bytes of the MBR.

/// Identity of the boot code in the first 446 bytes of the MBR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum BootCodeId {
    /// Windows Vista / Server 2008 MBR boot code.
    WindowsVista,
    /// Windows 7 / Server 2008 R2 and later MBR boot code.
    Windows7Plus,
    /// GRUB Legacy (stage1).
    GrubLegacy,
    /// GRUB 2 boot code.
    Grub2,
    /// Syslinux / EXTLINUX MBR.
    Syslinux,
    /// All 446 bytes are zero — likely wiped or freshly zeroed.
    AllZeros,
    /// All 446 bytes are `0xFF` — factory-erased flash or deliberate wipe.
    AllOnes,
    /// Unrecognised boot code.
    Unknown,
}

/// Identify the boot code occupying `code[0..446]`.
///
/// All-zero / all-`0xFF` regions are classified locally; recognised bootloaders
/// are matched against the [`forensicnomicon::boot_signatures`] knowledge base
/// (the single source of truth for the fingerprint patterns).
#[must_use]
pub fn identify(code: &[u8; 446]) -> BootCodeId {
    if code.iter().all(|&b| b == 0x00) {
        return BootCodeId::AllZeros;
    }
    if code.iter().all(|&b| b == 0xFF) {
        return BootCodeId::AllOnes;
    }
    match forensicnomicon::boot_signatures::identify_loader(code) {
        Some("Windows 7+") => BootCodeId::Windows7Plus,
        Some("Windows Vista") => BootCodeId::WindowsVista,
        Some("Syslinux") => BootCodeId::Syslinux,
        Some("GRUB Legacy") => BootCodeId::GrubLegacy,
        Some("GRUB 2") => BootCodeId::Grub2,
        _ => BootCodeId::Unknown,
    }
}
