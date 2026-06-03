//! Tier 0 — large-offset filesystem fingerprints through `analyse`.
//!
//! ext (superblock magic at 0x438), Linux swap (0xFF6), and Btrfs (magic at
//! 64 KiB) live beyond the first 512 bytes. `analyse` must read a large enough
//! fingerprint window for these to drive declared-vs-detected mismatch
//! detection — otherwise a partition mislabelled to hide its true filesystem
//! goes unnoticed.

use mbr_forensic::{analyse, findings::AnomalyKind, signature, DetectedFs};
use std::io::Cursor;

const SECTORS: u64 = 4096; // 2 MiB — room for a 64 KiB Btrfs offset

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

#[test]
fn detect_recognises_btrfs_at_64k() {
    // Unit-level: detect() must understand the Btrfs magic when given enough bytes.
    let mut buf = vec![0u8; 65536 + 8];
    buf[65536..65536 + 8].copy_from_slice(b"_BHRfS_M");
    assert_eq!(signature::detect(&buf), DetectedFs::Btrfs);
}

#[test]
fn analyse_detects_ext_under_ntfs_declared_partition() {
    // Partition declared NTFS (0x07) but content is an ext superblock → mismatch.
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x07, 1, 2000));
    let base = 512; // partition at LBA 1
    disk[base + 1080] = 0x53;
    disk[base + 1081] = 0xEF;
    let analysis = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            a.kind,
            AnomalyKind::SignatureMismatch { detected: DetectedFs::Ext, .. }
        )),
        "got: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn analyse_detects_btrfs_under_fat_declared_partition() {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x0C, 2048, 2000)); // FAT32 (LBA)
    let base = 2048 * 512;
    disk[base + 65536..base + 65536 + 8].copy_from_slice(b"_BHRfS_M");
    let analysis = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            a.kind,
            AnomalyKind::SignatureMismatch { detected: DetectedFs::Btrfs, .. }
        )),
        "got: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn btrfs_conflicts_with_fat_family() {
    use mbr_forensic::partition::PartitionFamily;
    assert!(signature::type_conflicts(PartitionFamily::Fat32, DetectedFs::Btrfs));
    assert!(signature::type_conflicts(PartitionFamily::Ntfs, DetectedFs::Btrfs));
    // Linux-family declaration matching a Linux FS is not a conflict.
    assert!(!signature::type_conflicts(PartitionFamily::Linux, DetectedFs::Btrfs));
}
