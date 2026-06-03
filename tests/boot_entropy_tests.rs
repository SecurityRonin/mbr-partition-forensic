//! Tier 0 — high-entropy boot-code detection.
//!
//! Packed or encrypted bootkit payloads (e.g. custom MBR malware) leave the
//! 446-byte boot-code region with near-maximal Shannon entropy while matching
//! no known boot loader. That combination is a tampering indicator the dormant
//! `HighEntropySlack` anomaly is meant to surface.

use mbr_forensic::{analyse, findings::AnomalyKind};
use std::io::Cursor;

fn disk_with_boot_code(boot: &[u8]) -> Vec<u8> {
    let mut disk = vec![0u8; 4096 * 512];
    let n = boot.len().min(446);
    disk[..n].copy_from_slice(&boot[..n]);
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk
}

#[test]
fn high_entropy_unknown_boot_code_is_flagged() {
    // A full-range byte ramp gives ~8 bits/byte entropy and matches no loader.
    let boot: Vec<u8> = (0..446u32).map(|i| (i % 256) as u8).collect();
    let analysis = analyse(&mut Cursor::new(disk_with_boot_code(&boot)), 4096 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::HighEntropySlack { .. })),
        "expected HighEntropySlack, got: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn zeroed_boot_code_is_not_high_entropy() {
    // All-zero boot code is WipedBootCode, never HighEntropySlack.
    let analysis = analyse(&mut Cursor::new(disk_with_boot_code(&[])), 4096 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::HighEntropySlack { .. })));
}

#[test]
fn recognised_windows_boot_code_is_not_high_entropy() {
    // Real Windows 7 boot stub: low-entropy x86 + mostly-zero padding.
    let mut boot = vec![0u8; 446];
    boot[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    boot[418..425].copy_from_slice(b"BOOTMGR");
    let analysis = analyse(&mut Cursor::new(disk_with_boot_code(&boot)), 4096 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::HighEntropySlack { .. })));
}
