//! Context-aware boot-code assessment.
//!
//! All-zero MBR boot code means very different things depending on whether the
//! MBR is in the machine's boot path:
//!   * Legacy BIOS/MBR-boot disk — the boot code is executed first; all-zero is
//!     a genuine anomaly (`WipedBootCode`, HIGH).
//!   * GPT/UEFI disk (pure protective MBR) — the MBR boot code is never
//!     executed, so all-zero is normal and benign (`EmptyProtectiveBootCode`,
//!     INFO). Reporting it as "likely wiped/overwritten" would be an
//!     unsupported inference about a pristine disk.

use mbr_forensic::{
    analyse,
    findings::{AnomalyKind, Severity},
};
use std::io::Cursor;

const SECTORS: u64 = 4096;

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

/// Disk with all-zero boot code, the given entries, and optionally an EFI PART
/// header at LBA 1.
fn disk(entries: &[(usize, [u8; 16])], gpt_header: bool) -> Vec<u8> {
    let mut d = vec![0u8; (SECTORS * 512) as usize];
    d[510] = 0x55;
    d[511] = 0xAA;
    for (slot, e) in entries {
        let off = 446 + slot * 16;
        d[off..off + 16].copy_from_slice(e);
    }
    if gpt_header {
        d[512..520].copy_from_slice(b"EFI PART");
    }
    d
}

fn analyse_disk(d: Vec<u8>) -> mbr_forensic::MbrAnalysis {
    analyse(&mut Cursor::new(d), SECTORS * 512).unwrap()
}

#[test]
fn pure_protective_gpt_zero_boot_is_info_not_high() {
    let ee = entry(0xEE, 1, (SECTORS - 1) as u32);
    let a = analyse_disk(disk(&[(0, ee)], true));

    let empty = a
        .anomalies
        .iter()
        .find(|x| matches!(x.kind, AnomalyKind::EmptyProtectiveBootCode))
        .expect("expected EmptyProtectiveBootCode on a pure protective GPT disk");
    assert_eq!(empty.severity, Severity::Info);

    assert!(
        !a.anomalies
            .iter()
            .any(|x| matches!(x.kind, AnomalyKind::WipedBootCode)),
        "must NOT report WipedBootCode on a genuine GPT disk"
    );
}

#[test]
fn legacy_zero_boot_code_still_high() {
    // No protective entry → legacy MBR; all-zero boot code stays HIGH.
    let a = analyse_disk(disk(&[(0, entry(0x83, 2048, 1000))], false));
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::WipedBootCode)));
    assert!(!a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::EmptyProtectiveBootCode)));
}

#[test]
fn spoofed_protective_zero_boot_stays_wiped() {
    // 0xEE present but NO EFI PART → not a genuine GPT disk; do not downgrade.
    let ee = entry(0xEE, 1, (SECTORS - 1) as u32);
    let a = analyse_disk(disk(&[(0, ee)], false));
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::WipedBootCode)));
    assert!(!a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::EmptyProtectiveBootCode)));
}

#[test]
fn hybrid_mbr_zero_boot_stays_wiped() {
    // 0xEE + a real partition + EFI PART → hybrid; legacy boot path may exist,
    // so all-zero boot code is NOT downgraded.
    let ee = entry(0xEE, 1, (SECTORS - 1) as u32);
    let ntfs = entry(0x07, 2048, 1000);
    let a = analyse_disk(disk(&[(0, ee), (1, ntfs)], true));
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::WipedBootCode)));
    assert!(!a
        .anomalies
        .iter()
        .any(|x| matches!(x.kind, AnomalyKind::EmptyProtectiveBootCode)));
}
