#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! Tier 0 — large-offset filesystem fingerprints through `analyse`.
//!
//! ext (superblock magic at 0x438), Linux swap (0xFF6), and Btrfs (magic at
//! 64 KiB) live beyond the first 512 bytes. `analyse` must read a large enough
//! fingerprint window for these to drive declared-vs-detected mismatch
//! detection — otherwise a partition mislabelled to hide its true filesystem
//! goes unnoticed.

use mbr_partition_forensic::{analyse, findings::AnomalyKind, signature, DetectedFs};
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
fn detect_recognises_fat32_from_knowledge_base() {
    // FAT32 BS_FilSysType "FAT32   " at offset 0x52 (per forensicnomicon KB),
    // mapped to DetectedFs::Fat.
    let mut buf = vec![0u8; 0x52 + 8];
    buf[0x52..0x52 + 8].copy_from_slice(b"FAT32   ");
    assert_eq!(signature::detect(&buf), DetectedFs::Fat);
}

#[test]
fn detect_returns_unknown_for_unmapped_kb_name() {
    // ISO 9660 ("CD001" at 0x8001) IS in the knowledge base but has no
    // DetectedFs variant, so map_fs_name yields None and detect falls through
    // to Unknown rather than mis-classifying it.
    let mut buf = vec![0u8; 0x8001 + 5];
    buf[0x8001..0x8001 + 5].copy_from_slice(b"CD001");
    assert_eq!(signature::detect(&buf), DetectedFs::Unknown);
}

#[test]
fn detect_recognises_btrfs_at_64k() {
    // The Btrfs magic is at 65600 (0x10040 = superblock @64 KiB + 0x40), per the
    // btrfs on-disk format and util-linux libblkid (.kboff=64, .sboff=0x40).
    let mut buf = vec![0u8; 65600 + 8];
    buf[65600..65600 + 8].copy_from_slice(b"_BHRfS_M");
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
            AnomalyKind::SignatureMismatch {
                detected: DetectedFs::Ext,
                ..
            }
        )),
        "got: {:?}",
        analysis
            .anomalies
            .iter()
            .map(|a| a.code)
            .collect::<Vec<_>>()
    );
}

#[test]
fn analyse_detects_btrfs_under_fat_declared_partition() {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x0C, 2048, 2000)); // FAT32 (LBA)
    let base = 2048 * 512;
    disk[base + 65600..base + 65600 + 8].copy_from_slice(b"_BHRfS_M");
    let analysis = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            a.kind,
            AnomalyKind::SignatureMismatch {
                detected: DetectedFs::Btrfs,
                ..
            }
        )),
        "got: {:?}",
        analysis
            .anomalies
            .iter()
            .map(|a| a.code)
            .collect::<Vec<_>>()
    );
}

#[test]
fn btrfs_conflicts_with_fat_family() {
    use mbr_partition_forensic::partition::PartitionFamily;
    assert!(signature::type_conflicts(
        PartitionFamily::Fat32,
        DetectedFs::Btrfs
    ));
    assert!(signature::type_conflicts(
        PartitionFamily::Ntfs,
        DetectedFs::Btrfs
    ));
    // Linux-family declaration matching a Linux FS is not a conflict.
    assert!(!signature::type_conflicts(
        PartitionFamily::Linux,
        DetectedFs::Btrfs
    ));
}
