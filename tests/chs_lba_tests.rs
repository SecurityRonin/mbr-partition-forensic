//! Tier 0 — CHS↔LBA consistency checking.
//!
//! The MBR stores each partition's first/last sector twice: once as a packed
//! 3-byte CHS address and once as an LBA. Legitimate tooling keeps them
//! consistent (or uses the universally-accepted "overflow marker" / "unused"
//! conventions). A gross contradiction is a hallmark of a hand-edited or
//! tool-crafted partition table.

use mbr_forensic::{
    analyse,
    findings::AnomalyKind,
    partition::{chs_consistency, Chs, ChsConsistency, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK},
};
use std::io::Cursor;

/// Encode a CHS triple into its packed 3-byte MBR form.
fn chs_bytes(cylinder: u16, head: u8, sector: u8) -> [u8; 3] {
    let b0 = head;
    let b1 = ((cylinder >> 2) as u8 & 0xC0) | (sector & 0x3F);
    let b2 = (cylinder & 0xFF) as u8;
    [b0, b1, b2]
}

/// A 16-byte primary entry with explicit CHS first/last and LBA fields.
fn entry_with_chs(
    type_code: u8,
    chs_first: [u8; 3],
    chs_last: [u8; 3],
    lba_start: u32,
    lba_count: u32,
) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = 0x00;
    e[1..4].copy_from_slice(&chs_first);
    e[4] = type_code;
    e[5..8].copy_from_slice(&chs_last);
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

fn disk_with_entry(total_sectors: u64, entry: &[u8; 16]) -> Vec<u8> {
    let mut disk = vec![0u8; (total_sectors * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(entry);
    disk
}

// ── Chs helpers ────────────────────────────────────────────────────────────────

#[test]
fn chs_all_zero_is_unused() {
    let chs = Chs::from_bytes([0, 0, 0]);
    assert!(chs.is_unused());
    assert!(!chs.is_overflow_marker());
}

#[test]
fn chs_overflow_marker_recognised() {
    // FE FF FF → head 254, sector 63, cylinder 1023.
    let chs = Chs::from_bytes([0xFE, 0xFF, 0xFF]);
    assert!(chs.is_overflow_marker());
    assert!(!chs.is_unused());
    // FF FF FF (head 255) is also accepted as an overflow marker.
    assert!(Chs::from_bytes([0xFF, 0xFF, 0xFF]).is_overflow_marker());
}

// ── chs_consistency ──────────────────────────────────────────────────────────

#[test]
fn consistent_translation_under_standard_geometry() {
    // cyl 0, head 1, sector 1 → LBA 63 under 255×63 geometry.
    let chs = Chs::from_bytes(chs_bytes(0, 1, 1));
    assert_eq!(
        chs_consistency(chs, 63, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK),
        ChsConsistency::Consistent
    );
}

#[test]
fn mismatched_translation_is_inconsistent() {
    // CHS encodes LBA 63 but the entry claims LBA 1000.
    let chs = Chs::from_bytes(chs_bytes(0, 1, 1));
    assert_eq!(
        chs_consistency(chs, 1000, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK),
        ChsConsistency::Inconsistent
    );
}

#[test]
fn unused_chs_never_inconsistent() {
    let chs = Chs::from_bytes([0, 0, 0]);
    assert_eq!(
        chs_consistency(chs, 123_456, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK),
        ChsConsistency::Unused
    );
}

#[test]
fn overflow_marker_consistent_when_lba_beyond_chs_range() {
    // LBA far beyond the CHS-addressable range must use the overflow marker.
    let chs = Chs::from_bytes([0xFE, 0xFF, 0xFF]);
    assert_eq!(
        chs_consistency(chs, 50_000_000, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK),
        ChsConsistency::Consistent
    );
}

#[test]
fn non_overflow_chs_for_huge_lba_is_inconsistent() {
    // A small, real-looking CHS for an LBA that overflows CHS range = crafted.
    let chs = Chs::from_bytes(chs_bytes(10, 5, 20));
    assert_eq!(
        chs_consistency(chs, 50_000_000, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK),
        ChsConsistency::Inconsistent
    );
}

// ── End-to-end wiring through analyse() ──────────────────────────────────────

#[test]
fn analyse_flags_chs_lba_inconsistency() {
    // CHS says LBA 63, entry says LBA 1000 → ChsLbaInconsistency.
    let entry = entry_with_chs(0x83, chs_bytes(0, 1, 1), chs_bytes(0, 2, 1), 1000, 100);
    let disk = disk_with_entry(4096, &entry);
    let analysis = analyse(&mut Cursor::new(disk), 4096 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ChsLbaInconsistency { index: 0 })),
        "expected ChsLbaInconsistency for entry 0, got: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn analyse_no_chs_anomaly_for_consistent_entry() {
    // CHS first → LBA 63, last → LBA 162 (cyl0,head2,sec37 = 63+100-? ) keep simple:
    // start LBA 63 (cyl0 head1 sec1), count 100 → end LBA 162.
    // end CHS cyl0 head2 sector37 → 2*63 + 36 = 162. Consistent.
    let entry = entry_with_chs(0x83, chs_bytes(0, 1, 1), chs_bytes(0, 2, 37), 63, 100);
    let disk = disk_with_entry(4096, &entry);
    let analysis = analyse(&mut Cursor::new(disk), 4096 * 512).unwrap();
    assert!(
        !analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ChsLbaInconsistency { .. })),
        "unexpected ChsLbaInconsistency: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn analyse_unused_chs_does_not_flag() {
    // All-zero CHS (LBA-only tooling) must never raise a CHS anomaly.
    let entry = entry_with_chs(0x83, [0, 0, 0], [0, 0, 0], 2048, 100);
    let disk = disk_with_entry(4096, &entry);
    let analysis = analyse(&mut Cursor::new(disk), 4096 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::ChsLbaInconsistency { .. })));
}
