#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! Tier 3 — Volume Boot Record (VBR) / BPB cross-checking.
//!
//! A FAT/NTFS boot sector's BIOS Parameter Block records the partition's offset
//! from the disk start in its "hidden sectors" field (BPB offset 0x1C). When a
//! partition is relocated, copied, or the table is edited to point elsewhere,
//! that field is left stale — it no longer equals the partition-table LBA. A
//! nonzero mismatch is a relocation / data-hiding indicator.

use mbr_partition_forensic::{
    analyse,
    findings::AnomalyKind,
    vbr::{parse_bpb, Bpb},
};
use std::io::Cursor;

/// Build a valid FAT/NTFS-style boot sector with a given hidden-sectors value.
fn vbr(hidden_sectors: u32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"NTFS    "); // OEM id (also makes detect() = Ntfs)
    s[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
    s[13] = 8; // sectors per cluster
    s[14..16].copy_from_slice(&0u16.to_le_bytes()); // reserved sectors
    s[28..32].copy_from_slice(&hidden_sectors.to_le_bytes()); // hidden sectors
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

#[test]
fn parse_bpb_reads_hidden_sectors() {
    let bpb: Bpb = parse_bpb(&vbr(2048)).expect("valid BPB");
    assert_eq!(bpb.bytes_per_sector, 512);
    assert_eq!(bpb.sectors_per_cluster, 8);
    assert_eq!(bpb.hidden_sectors, 2048);
}

#[test]
fn parse_bpb_rejects_garbage() {
    assert!(parse_bpb(&[0u8; 512]).is_none()); // no 0x55AA, bps=0
    let mut bad = vbr(0);
    bad[11] = 7; // bytes-per-sector not a valid value
    bad[12] = 0;
    assert!(parse_bpb(&bad).is_none());
}

#[test]
fn parse_bpb_rejects_short_sector() {
    // Fewer than 512 bytes cannot hold a BPB — rejected before any field read.
    assert!(parse_bpb(&[0u8; 511]).is_none());
    assert!(parse_bpb(&[]).is_none());
}

#[test]
fn parse_bpb_rejects_non_power_of_two_cluster() {
    // Valid boot signature + bytes-per-sector, but sectors-per-cluster is not a
    // power of two — a corrupt/edited BPB, rejected.
    let mut bad = vbr(0);
    bad[13] = 3; // sectors_per_cluster = 3 (not a power of two)
    assert!(parse_bpb(&bad).is_none());
}

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

fn disk_with_vbr(lba_start: u32, hidden_sectors: u32) -> Vec<u8> {
    let mut disk = vec![0u8; 4096 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x07, lba_start, 1000));
    let off = (lba_start as usize) * 512;
    disk[off..off + 512].copy_from_slice(&vbr(hidden_sectors));
    disk
}

#[test]
fn analyse_flags_hidden_sectors_mismatch() {
    // Partition table says LBA 2048; VBR still records a stale 63.
    let analysis = analyse(&mut Cursor::new(disk_with_vbr(2048, 63)), 4096 * 512).unwrap();
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            a.kind,
            AnomalyKind::VbrHiddenSectorsMismatch { index: 0, .. }
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
fn analyse_no_flag_when_hidden_sectors_match() {
    let analysis = analyse(&mut Cursor::new(disk_with_vbr(2048, 2048)), 4096 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::VbrHiddenSectorsMismatch { .. })));
}

#[test]
fn analyse_no_flag_when_hidden_sectors_zero() {
    // Zero is the removable/superfloppy convention — not a mismatch signal.
    let analysis = analyse(&mut Cursor::new(disk_with_vbr(2048, 0)), 4096 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::VbrHiddenSectorsMismatch { .. })));
}
