//! Tier A — primary partition-table integrity checks.
//!
//! Two manual-edit / tampering indicators the table scan should surface:
//!   * a status byte that is neither 0x00 (inactive) nor 0x80 (bootable) — the
//!     only two values the MBR spec permits;
//!   * two partition entries describing the identical extent — a duplicate left
//!     by hand-editing or a faulty imaging tool.

use mbr_forensic::{analyse, findings::AnomalyKind};
use std::io::Cursor;

const SECTORS: u64 = 8192;

fn raw_entry(status: u8, type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

fn analyse_entries(entries: &[(usize, [u8; 16])]) -> Vec<AnomalyKind> {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (slot, e) in entries {
        let off = 446 + slot * 16;
        disk[off..off + 16].copy_from_slice(e);
    }
    analyse(&mut Cursor::new(disk), SECTORS * 512)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

// ── A3: invalid status byte ──────────────────────────────────────────────────

#[test]
fn invalid_status_byte_is_flagged() {
    let k = analyse_entries(&[(0, raw_entry(0x55, 0x83, 2048, 100))]);
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::InvalidPartitionStatus { index: 0, status: 0x55 })),
        "got {k:?}"
    );
}

#[test]
fn valid_status_bytes_not_flagged() {
    for status in [0x00u8, 0x80u8] {
        let k = analyse_entries(&[(0, raw_entry(status, 0x83, 2048, 100))]);
        assert!(
            !k.iter()
                .any(|a| matches!(a, AnomalyKind::InvalidPartitionStatus { .. })),
            "status {status:#x} must be valid; got {k:?}"
        );
    }
}

// ── A4: duplicate partition entries ──────────────────────────────────────────

#[test]
fn duplicate_entries_are_flagged() {
    let e = raw_entry(0x00, 0x83, 2048, 100);
    let k = analyse_entries(&[(0, e), (1, e)]);
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::DuplicatePartitionEntry { a: 0, b: 1 })),
        "got {k:?}"
    );
}

#[test]
fn distinct_entries_not_flagged_as_duplicate() {
    let k = analyse_entries(&[
        (0, raw_entry(0x00, 0x83, 2048, 100)),
        (1, raw_entry(0x00, 0x83, 4096, 100)),
    ]);
    assert!(!k
        .iter()
        .any(|a| matches!(a, AnomalyKind::DuplicatePartitionEntry { .. })));
}
