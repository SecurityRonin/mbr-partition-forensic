#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! Tier 2 — wipe-pattern recognition in unpartitioned space.
//!
//! A uniform non-zero fill (0xFF), a single repeated byte, or an alternating
//! 0x55/0xAA pattern across a gap is the signature of a deliberate wipe — an
//! anti-forensic / destruction trace. All-zero gaps are normal unallocated
//! space and are NOT flagged.

use mbr_partition_forensic::{
    analyse,
    findings::AnomalyKind,
    wipe::{classify, FillPattern},
};
use std::io::Cursor;

// ── Pure classifier ──────────────────────────────────────────────────────────

#[test]
fn all_zero_is_zeros() {
    assert_eq!(classify(&[0u8; 64]), FillPattern::Zeros);
}

#[test]
fn all_ff_is_ones() {
    assert_eq!(classify(&[0xFFu8; 64]), FillPattern::Ones);
}

#[test]
fn single_repeated_byte_is_uniform() {
    assert_eq!(classify(&[0xABu8; 64]), FillPattern::Uniform(0xAB));
}

#[test]
fn alternating_is_detected() {
    let data: Vec<u8> = (0..64)
        .map(|i| if i % 2 == 0 { 0x55 } else { 0xAA })
        .collect();
    assert_eq!(classify(&data), FillPattern::Alternating(0x55, 0xAA));
}

#[test]
fn full_range_ramp_is_high_entropy() {
    let data: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
    assert_eq!(classify(&data), FillPattern::HighEntropy);
}

#[test]
fn structured_text_is_mixed() {
    assert_eq!(
        classify(b"the quick brown fox jumps over"),
        FillPattern::Mixed
    );
}

#[test]
fn empty_slice_is_mixed() {
    // Nothing to judge — an empty region classifies as Mixed, never a wipe.
    assert_eq!(classify(&[]), FillPattern::Mixed);
    assert!(!classify(&[]).is_deliberate_wipe());
}

#[test]
fn two_byte_non_alternating_low_entropy_is_mixed() {
    // len >= 2, first two bytes differ, but not a full a,b,a,b alternation and
    // not high entropy — the .all() check fails, falling through to Mixed.
    assert_eq!(classify(&[0x01, 0x02, 0x02, 0x02]), FillPattern::Mixed);
}

#[test]
fn two_byte_equal_first_pair_non_uniform_is_mixed() {
    // len >= 2 with the first two bytes equal (a == b) short-circuits the
    // alternating `a != b` guard before the .all() scan — the other short-circuit
    // arm of the alternating check — and still resolves to Mixed.
    assert_eq!(classify(&[0x02, 0x02, 0x01, 0x03]), FillPattern::Mixed);
}

#[test]
fn label_describes_each_pattern() {
    assert_eq!(FillPattern::Zeros.label(), "all 0x00");
    assert_eq!(FillPattern::Ones.label(), "all 0xFF");
    assert_eq!(FillPattern::Uniform(0xAB).label(), "uniform 0xAB");
    assert_eq!(
        FillPattern::Alternating(0x55, 0xAA).label(),
        "alternating 0x55/0xAA"
    );
    assert_eq!(
        FillPattern::HighEntropy.label(),
        "high-entropy (random/encrypted)"
    );
    assert_eq!(FillPattern::Mixed.label(), "mixed");
}

#[test]
fn deliberate_wipe_predicate() {
    assert!(FillPattern::Ones.is_deliberate_wipe());
    assert!(FillPattern::Uniform(0xAB).is_deliberate_wipe());
    assert!(FillPattern::Alternating(0x55, 0xAA).is_deliberate_wipe());
    // Zeros = normal unallocated space; not a deliberate-wipe signal.
    assert!(!FillPattern::Zeros.is_deliberate_wipe());
    assert!(!FillPattern::Mixed.is_deliberate_wipe());
}

// ── End-to-end through analyse() ─────────────────────────────────────────────

fn entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

#[test]
fn ff_filled_gap_is_flagged_as_wiped() {
    // Partition covers LBA 1..=10; LBA 11..=99 is a post-partition gap.
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x83, 1, 10));
    // Fill the post-partition gap with 0xFF.
    for b in disk.iter_mut().skip(11 * 512) {
        *b = 0xFF;
    }
    let analysis = analyse(&mut Cursor::new(disk), 100 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::WipedRegion { .. })),
        "got: {:?}",
        analysis
            .anomalies
            .iter()
            .map(|a| a.code)
            .collect::<Vec<_>>()
    );
}

#[test]
fn zero_filled_gap_is_not_flagged() {
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&entry(0x83, 1, 10));
    let analysis = analyse(&mut Cursor::new(disk), 100 * 512).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::WipedRegion { .. })));
}
