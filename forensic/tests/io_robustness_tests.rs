#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! I/O-robustness of `analyse` against readers that fault mid-analysis.
//!
//! A real backing store (a network image, a flaky device, a compressed stream)
//! can return short reads, `Interrupted`, hard read errors, or seek failures.
//! `analyse` must degrade gracefully — skip the unreadable region, never panic,
//! and still return a well-formed analysis of what it could read.

use mbr_partition_forensic::analyse;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// A `Read + Seek` wrapper over an in-memory disk that injects faults.
///
/// * `interrupt_reads` — the first N `read` calls return `Interrupted` (a
///   spurious signal a robust reader must retry through), then reads succeed.
/// * `fail_read_from` — once the cursor reaches this byte offset, `read`
///   returns a hard error (a genuine device read failure).
/// * `fail_seek_to_at_least` — `seek` to any target ≥ this offset returns an
///   error (a seek past a failed region), while earlier seeks succeed.
struct FaultyDisk {
    inner: Cursor<Vec<u8>>,
    interrupt_reads: u32,
    fail_read_from: Option<u64>,
    fail_seek_to_at_least: Option<u64>,
}

impl FaultyDisk {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            interrupt_reads: 0,
            fail_read_from: None,
            fail_seek_to_at_least: None,
        }
    }
}

impl Read for FaultyDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_reads > 0 {
            self.interrupt_reads -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if let Some(from) = self.fail_read_from {
            if self.inner.position() >= from {
                return Err(io::Error::other("device read failed"));
            }
        }
        self.inner.read(buf)
    }
}

impl Seek for FaultyDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if let (SeekFrom::Start(off), Some(bound)) = (pos, self.fail_seek_to_at_least) {
            if off >= bound {
                return Err(io::Error::other("seek failed"));
            }
        }
        self.inner.seek(pos)
    }
}

/// A minimal single-partition disk with a trailing post-partition gap so the
/// gap-content sampler runs.
fn disk_with_gap() -> Vec<u8> {
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    // Partition covers LBA 1..=10; LBA 11..=99 is a post-partition gap.
    disk[446] = 0x00;
    disk[446 + 4] = 0x83; // Linux type
    disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // lba_start
    disk[446 + 12..446 + 16].copy_from_slice(&10u32.to_le_bytes()); // lba_count
    disk
}

#[test]
fn analyse_survives_interrupted_reads() {
    // The fingerprint reader must retry through spurious Interrupted signals and
    // still complete the analysis without error.
    let mut faulty = FaultyDisk::new(disk_with_gap());
    faulty.interrupt_reads = 2;
    let analysis = analyse(&mut faulty, 100 * 512).expect("interrupted reads must be retried");
    assert!(!analysis.partitions.is_empty());
}

#[test]
fn analyse_survives_hard_read_error_during_fingerprint() {
    // A hard read error while fingerprinting a partition is tolerated: the
    // partition's detected filesystem is simply left unknown, not a crash.
    let mut faulty = FaultyDisk::new(disk_with_gap());
    // The partition starts at byte 512; fail every read at/after it so the
    // fingerprint read errors out (the MBR sector at 0 is already read).
    faulty.fail_read_from = Some(512);
    let analysis = analyse(&mut faulty, 100 * 512).expect("read errors are skipped, not fatal");
    assert!(analysis.partitions.iter().all(|p| p.detected_fs.is_none()));
}

#[test]
fn analyse_survives_seek_failure_in_gap_sampler() {
    // A seek failure when sampling the trailing gap is skipped silently — the
    // gap's *existence* is still reported, but its content is not classified.
    let mut faulty = FaultyDisk::new(disk_with_gap());
    // The post-partition gap begins at byte 11*512; fail seeks into it. Earlier
    // seeks (MBR sector, LBA 1, the partition at byte 512) still succeed.
    faulty.fail_seek_to_at_least = Some(11 * 512);
    let analysis = analyse(&mut faulty, 100 * 512).expect("gap seek failure is non-fatal");
    // A gap was still discovered even though its content could not be sampled.
    assert!(!analysis.gaps.is_empty());
}
