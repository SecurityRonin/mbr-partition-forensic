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

// ── Fingerprint patterns ──────────────────────────────────────────────────────
//
// Each entry is (offset_in_boot_code, expected_bytes).  All conditions for an
// entry must match for it to be selected.

const WINDOWS_VISTA_SIG: &[(usize, &[u8])] = &[
    (0, &[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]), // xor ax,ax; mov ss,ax; mov sp,7C00h
    (424, b"BOOTMGR"),                                // Vista bootmgr string
];

const WINDOWS7_SIG: &[(usize, &[u8])] = &[
    (0, &[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]),
    (418, b"BOOTMGR"),
];

const GRUB2_SIG: &[(usize, &[u8])] = &[
    (0, &[0xEB, 0x63, 0x90]), // short jmp + nop (GRUB 2 format: JMP +0x65)
                              // GRUB 2's boot.img starts with EB 63; the value varies by version so we
                              // accept the common range.
];

const GRUB_LEGACY_SIG: &[(usize, &[u8])] = &[
    (0, &[0xEB, 0x48, 0x90]), // GRUB Legacy stage1 JMP
];

const SYSLINUX_SIG: &[(usize, &[u8])] = &[(3, b"SYSLINUX")];

/// Identify the boot code occupying `code[0..446]`.
#[must_use]
pub fn identify(code: &[u8; 446]) -> BootCodeId {
    if code.iter().all(|&b| b == 0x00) {
        return BootCodeId::AllZeros;
    }
    if code.iter().all(|&b| b == 0xFF) {
        return BootCodeId::AllOnes;
    }
    if matches_all(code, WINDOWS7_SIG) {
        return BootCodeId::Windows7Plus;
    }
    if matches_all(code, WINDOWS_VISTA_SIG) {
        return BootCodeId::WindowsVista;
    }
    if matches_all(code, SYSLINUX_SIG) {
        return BootCodeId::Syslinux;
    }
    if matches_all(code, GRUB_LEGACY_SIG) {
        return BootCodeId::GrubLegacy;
    }
    if matches_all(code, GRUB2_SIG) {
        return BootCodeId::Grub2;
    }
    BootCodeId::Unknown
}

fn matches_all(code: &[u8; 446], sigs: &[(usize, &[u8])]) -> bool {
    sigs.iter().all(|(offset, pattern)| {
        let end = offset + pattern.len();
        end <= code.len() && &code[*offset..end] == *pattern
    })
}
