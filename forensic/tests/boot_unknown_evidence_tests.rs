#![allow(clippy::unwrap_used, clippy::expect_used)]
//! MBR-BOOT-UNKNOWN must surface the actual unrecognised boot-code bytes.
//!
//! Global rule: a finding that reports something "not recognised" MUST include
//! the raw offending value, so an investigator can identify it. "Boot code
//! signature not recognised" without the bytes that were there is a dead end.

use mbr_partition_forensic::analyse;
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
fn unknown_boot_code_finding_surfaces_the_raw_bytes() {
    // Distinctive, low-entropy, unrecognised boot code (mostly zero → not
    // HighEntropySlack; non-zero → not WipedBootCode; matches no known loader).
    let mut boot = vec![0u8; 446];
    boot[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let analysis = analyse(&mut Cursor::new(disk_with_boot_code(&boot)), 4096 * 512).unwrap();

    let a = analysis
        .anomalies
        .iter()
        .find(|a| a.code == "MBR-BOOT-UNKNOWN")
        .expect("expected an MBR-BOOT-UNKNOWN anomaly");

    // The actual leading bytes must travel with the finding's note.
    let note = a.note.to_lowercase();
    assert!(
        note.contains("de ad be ef"),
        "note must include the raw unrecognised boot-code bytes; got: {}",
        a.note
    );
}
