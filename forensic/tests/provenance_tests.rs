#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! Tier 1 — partitioner / era attribution from layout geometry.
//!
//! The first partition's start LBA is a strong provenance signal: 63 is the
//! legacy cylinder-aligned convention (pre-2008 fdisk / Windows XP); a 1 MiB
//! (2048-sector) boundary is the modern convention (Vista+ Disk Management,
//! modern gparted/fdisk). Exposed as metadata + pure utilities — not noisy
//! auto-anomalies — so callers decide how to weight it.

use mbr_partition_forensic::{
    analyse,
    provenance::{classify_alignment, infer_era, Alignment, PartitioningEra},
    BootCodeId,
};
use std::io::Cursor;

#[test]
fn alignment_classification() {
    assert_eq!(classify_alignment(2048), Alignment::Mib1);
    assert_eq!(classify_alignment(4096), Alignment::Mib1);
    assert_eq!(classify_alignment(63), Alignment::LegacyTrack);
    assert_eq!(classify_alignment(1000), Alignment::Unaligned);
}

#[test]
fn era_from_first_partition_lba() {
    assert_eq!(
        infer_era(Some(2048), BootCodeId::Unknown),
        PartitioningEra::Modern
    );
    assert_eq!(
        infer_era(Some(63), BootCodeId::Unknown),
        PartitioningEra::LegacyCylinder
    );
    assert_eq!(
        infer_era(None, BootCodeId::Unknown),
        PartitioningEra::Unknown
    );
}

#[test]
fn era_falls_back_to_boot_code() {
    // Oddly-aligned first partition, but Windows 7 boot code → modern era.
    assert_eq!(
        infer_era(Some(1000), BootCodeId::Windows7Plus),
        PartitioningEra::Modern
    );
}

#[test]
fn era_falls_back_to_legacy_boot_code() {
    // Oddly-aligned first partition with a GRUB Legacy loader → legacy era.
    assert_eq!(
        infer_era(Some(1000), BootCodeId::GrubLegacy),
        PartitioningEra::LegacyCylinder
    );
    // No geometry signal at all, GRUB Legacy loader → still legacy via boot code.
    assert_eq!(
        infer_era(None, BootCodeId::GrubLegacy),
        PartitioningEra::LegacyCylinder
    );
}

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

fn disk(lba_start: u32) -> Vec<u8> {
    let mut d = vec![0u8; 8192 * 512];
    d[510] = 0x55;
    d[511] = 0xAA;
    d[446..462].copy_from_slice(&entry(0x83, lba_start, 100));
    d
}

#[test]
fn analysis_exposes_modern_era() {
    let a = analyse(&mut Cursor::new(disk(2048)), 8192 * 512).unwrap();
    assert_eq!(a.era, PartitioningEra::Modern);
}

#[test]
fn analysis_exposes_legacy_era() {
    let a = analyse(&mut Cursor::new(disk(63)), 8192 * 512).unwrap();
    assert_eq!(a.era, PartitioningEra::LegacyCylinder);
}
