//! Tier-1 real-data validation against an INDEPENDENT cross-tool oracle.
//!
//! Every other test in this crate builds its MBR sector in-code (Tier 3: the
//! fixture and the expected answer share this crate's assumptions). This test
//! instead parses a **real third-party disk image** and reconciles the result
//! against the partition table reported by `mmls` (The Sleuth Kit) — a
//! completely independent codebase.
//!
//! Fixture: `tests/data/dftt_mmls_1_mbr.dd` — the 512-byte MBR sector of
//! `imageformat_mmls_1`, a Brian-Carrier DFTT (Digital Forensics Tool Testing)
//! corpus image (public domain). Its sector 0 is byte-identical to the parent
//! `imageformat_mmls_1.E01` (MD5 775574d985ad9aa94a6b18bbdc919f48 over the first
//! 512 bytes), so the oracle output below — captured by running `mmls` on that
//! authentic image — describes exactly this fixture's partition table.
//!
//! Oracle answer key (verbatim `mmls` output, NOT computed by this crate):
//!
//! ```text
//! DOS Partition Table
//! Offset Sector: 0
//! Units are in 512-byte sectors
//!
//!       Slot      Start        End          Length       Description
//! 000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
//! 001:  -------   0000000000   0000000127   0000000128   Unallocated
//! 002:  000:000   0000000128   0000055423   0000055296   NTFS / exFAT (0x07)
//! 003:  000:001   0000055424   0000116863   0000061440   NTFS / exFAT (0x07)
//! ```
//!
//! `mmls` slot 002 is primary partition-table entry 0; slot 003 is entry 1.
//! Slots 000/001/004 are mmls-synthesised meta/unallocated rows, not table
//! entries, so they have no counterpart in the four 16-byte primary slots.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mbr::parse_mbr_sector;
use mbr_partition_forensic::analyse;
use std::io::Cursor;

/// The real 512-byte MBR sector under test.
const MBR_SECTOR: &[u8] = include_bytes!("../../tests/data/dftt_mmls_1_mbr.dd");

/// One partition row from the `mmls` oracle, transcribed from its output above.
/// Values are mmls-reported, never derived from this crate.
struct OracleRow {
    /// Primary partition-table entry index mmls's slot maps to.
    entry_index: usize,
    /// `mmls` "Start" column (inclusive first LBA).
    start_lba: u64,
    /// `mmls` "End" column (inclusive last LBA).
    end_lba: u64,
    /// `mmls` "Length" column (sector count).
    length: u64,
    /// Partition type byte mmls printed in the description (`0x07`).
    type_byte: u8,
    /// Active/bootable status. mmls has no active-flag column, so this is taken
    /// from `fdisk` (independent oracle): it prints `0x07 HPFS/QNX/AUX` for both
    /// entries with NO active (`*`) marker on either, i.e. neither partition is
    /// bootable (both status bytes are `0x00`).
    bootable: bool,
}

/// The two data partitions mmls reported, keyed to primary table entries.
const ORACLE: &[OracleRow] = &[
    OracleRow {
        entry_index: 0,
        start_lba: 128,
        end_lba: 55423,
        length: 55296,
        type_byte: 0x07,
        bootable: false,
    },
    OracleRow {
        entry_index: 1,
        start_lba: 55424,
        end_lba: 116863,
        length: 61440,
        type_byte: 0x07,
        bootable: false,
    },
];

/// Total disk size mmls validated the table against (116864 sectors).
const DISK_SIZE_BYTES: u64 = 116_864 * 512;

#[test]
fn fixture_is_a_valid_mbr() {
    assert_eq!(MBR_SECTOR.len(), 512, "fixture must be one 512-byte sector");
    let sector = parse_mbr_sector(MBR_SECTOR).expect("real DFTT MBR must parse");
    assert_eq!(sector.signature, [0x55, 0xAA]);
}

#[test]
fn primary_entries_match_mmls_oracle() {
    let sector = parse_mbr_sector(MBR_SECTOR).expect("real DFTT MBR must parse");

    for row in ORACLE {
        let entry = &sector.entries[row.entry_index];
        assert_eq!(
            u64::from(entry.lba_start),
            row.start_lba,
            "entry {} start LBA must match mmls",
            row.entry_index
        );
        assert_eq!(
            u64::from(entry.lba_end()),
            row.end_lba,
            "entry {} end LBA must match mmls",
            row.entry_index
        );
        assert_eq!(
            u64::from(entry.lba_count),
            row.length,
            "entry {} length must match mmls",
            row.entry_index
        );
        assert_eq!(
            entry.type_code.0, row.type_byte,
            "entry {} type byte must match mmls description",
            row.entry_index
        );
        assert_eq!(
            entry.is_bootable(),
            row.bootable,
            "entry {} bootable flag must match raw status byte",
            row.entry_index
        );
    }

    // The two slots mmls did NOT report as data partitions must be empty in the
    // primary table (mmls slots 000/001/004 are synthesised meta/unallocated).
    assert!(
        sector.entries[2].is_empty(),
        "entry 2 must be an unused slot"
    );
    assert!(
        sector.entries[3].is_empty(),
        "entry 3 must be an unused slot"
    );
}

#[test]
fn analyse_partitions_match_mmls_oracle() {
    // Reconstruct the real image's geometry: the authentic sector 0 followed by
    // a zero-filled tail to the size mmls validated against. This is the same
    // disk mmls reported on (sector 0 is byte-identical; the data regions mmls
    // never reads for the partition table).
    let mut image = vec![0u8; usize::try_from(DISK_SIZE_BYTES).unwrap()];
    image[..512].copy_from_slice(MBR_SECTOR);
    let mut cursor = Cursor::new(image);

    let report = analyse(&mut cursor, DISK_SIZE_BYTES).expect("analyse must succeed");

    // The analyzer must surface exactly the two data partitions mmls reported,
    // with matching extents and type — no extra, no missing.
    let data: Vec<_> = report
        .partitions
        .iter()
        .filter(|p| !p.declared_type.is_empty())
        .collect();
    assert_eq!(
        data.len(),
        ORACLE.len(),
        "analyse must report exactly the partitions mmls reported"
    );

    for (row, part) in ORACLE.iter().zip(data.iter()) {
        assert_eq!(part.lba_start, row.start_lba, "analyse start LBA vs mmls");
        assert_eq!(part.lba_end, row.end_lba, "analyse end LBA vs mmls");
        assert_eq!(
            part.declared_type.0, row.type_byte,
            "analyse declared type vs mmls"
        );
    }
}
