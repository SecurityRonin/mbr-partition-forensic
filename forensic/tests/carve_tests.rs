#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! Tier 3 — file-signature carving and string extraction from unallocated space.
//!
//! Unpartitioned gaps and slack frequently retain remnants of deleted files and
//! their metadata — leftover data with direct forensic implications. Carving
//! recovers file headers by magic; string extraction surfaces paths, URLs, and
//! notes.

use mbr_partition_forensic::{
    analyse,
    carve::{carve, extract_ascii_strings, CarvedFile, FILE_MAGICS},
    findings::AnomalyKind,
};
use std::io::Cursor;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const ZIP: &[u8] = b"PK\x03\x04";

// ── carve ────────────────────────────────────────────────────────────────────

#[test]
fn carve_clean_data_finds_nothing() {
    assert!(carve(&[0u8; 1024], 0).is_empty());
}

#[test]
fn carve_finds_png_at_absolute_offset() {
    let mut data = vec![0u8; 1024];
    data[100..100 + PNG.len()].copy_from_slice(PNG);
    let found = carve(&data, 0x5000);
    let png: Vec<&CarvedFile> = found.iter().filter(|c| c.kind == "PNG").collect();
    assert_eq!(png.len(), 1);
    assert_eq!(
        png[0].offset,
        0x5000 + 100,
        "offset must be base-relative absolute"
    );
}

#[test]
fn carve_finds_multiple_distinct_types() {
    let mut data = vec![0u8; 2048];
    data[0..ZIP.len()].copy_from_slice(ZIP);
    data[1000..1000 + PNG.len()].copy_from_slice(PNG);
    let kinds: Vec<&str> = carve(&data, 0).iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&"ZIP"));
    assert!(kinds.contains(&"PNG"));
}

#[test]
fn file_magic_table_non_empty() {
    assert!(!FILE_MAGICS.is_empty());
}

#[test]
fn carve_data_shorter_than_longest_magic_finds_nothing() {
    // A 3-byte window is shorter than most magics (e.g. the 16-byte SQLite
    // magic), so every magic longer than the data is skipped — no match, no
    // panic on the short slice.
    assert!(carve(b"PK\x03", 0).is_empty());
    assert!(carve(&[], 0).is_empty());
}

// ── extract_ascii_strings ────────────────────────────────────────────────────

#[test]
fn strings_extracts_printable_runs() {
    let mut data = vec![0u8; 0];
    data.extend_from_slice(&[0x00, 0x01]);
    data.extend_from_slice(b"hello world");
    data.extend_from_slice(&[0x00, 0xFF]);
    data.extend_from_slice(b"hi"); // shorter than min_len
    let strings = extract_ascii_strings(&data, 4);
    assert!(strings.contains(&"hello world".to_string()));
    assert!(!strings.iter().any(|s| s == "hi"));
}

#[test]
fn strings_respects_min_length() {
    assert!(extract_ascii_strings(b"abc", 4).is_empty());
    assert_eq!(extract_ascii_strings(b"abcd", 4), vec!["abcd".to_string()]);
}

// ── End-to-end ───────────────────────────────────────────────────────────────

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

#[test]
fn analyse_carves_png_from_gap() {
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x83, 1, 10));
    // Post-partition gap begins at LBA 11.
    let off = 11 * 512;
    disk[off..off + PNG.len()].copy_from_slice(PNG);
    let analysis = analyse(&mut Cursor::new(disk), 100 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::CarvedArtifact { kind: "PNG" })),
        "got: {:?}",
        analysis
            .anomalies
            .iter()
            .map(|a| a.code)
            .collect::<Vec<_>>()
    );
}
