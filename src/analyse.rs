//! Orchestration: the public [`analyse`] entry point and its per-stage checks.
//!
//! The analysis is a pipeline of small, independently-debuggable stages. Each
//! stage receives the parsed data plus a [`Findings`] accumulator and records
//! any anomalies it discovers. Every anomaly in the crate flows through the
//! single [`Findings::record`] choke point, which is where tracing, breakpoints,
//! or post-processing belong.

use std::io::{Read, Seek, SeekFrom};

use crate::boot_code::{self, BootCodeId};
use crate::diag;
use crate::ebr::{walk_ebr_chain, EbrChain};
use crate::entropy;
use crate::findings::{Anomaly, AnomalyKind, MbrAnalysis, PartitionSummary};
use crate::gap::{compute_gaps, Gap, GapKind};
use crate::mbr::{parse_mbr_sector, MbrSector, SECTOR_SIZE};
use crate::signature::{self, DetectedFs};
use crate::Error;

// ── Layout constants ──────────────────────────────────────────────────────────

/// Logical sector size in bytes.
const SECTOR_BYTES: u64 = SECTOR_SIZE as u64;
/// Byte offset of the partition table within the MBR sector.
const PARTITION_TABLE_OFFSET: u64 = 446;
/// Size of one partition table entry, in bytes.
const ENTRY_SIZE: u64 = 16;
/// Byte offset of the reserved field (bytes 444–445).
const RESERVED_OFFSET: u64 = 444;
/// Byte offset of the NT disk signature (bytes 440–443, little-endian u32).
const DISK_SERIAL_OFFSET: u64 = 440;
/// Byte offset of the EBR slack region (entries 2–3) within an EBR sector.
const EBR_SLACK_OFFSET: u64 = 478;
/// First partition index assigned to logical partitions from the EBR chain.
const EBR_INDEX_BASE: usize = 4;

// ── Geometry helpers ──────────────────────────────────────────────────────────

/// Convert an LBA to its byte offset, saturating instead of overflowing.
#[inline]
fn lba_to_byte(lba: u64) -> u64 {
    lba.saturating_mul(SECTOR_BYTES)
}

/// Byte offset of primary partition entry `index` within the MBR sector.
#[inline]
fn entry_offset(index: usize) -> u64 {
    PARTITION_TABLE_OFFSET + index as u64 * ENTRY_SIZE
}

/// Inclusive last LBA of a disk of `disk_size_bytes`, or [`u64::MAX`] (i.e. "no
/// bound") when the size is unknown (`0`).
#[inline]
fn disk_last_lba(disk_size_bytes: u64) -> u64 {
    if disk_size_bytes > 0 {
        (disk_size_bytes / SECTOR_BYTES).saturating_sub(1)
    } else {
        u64::MAX
    }
}

// ── Anomaly accumulator ───────────────────────────────────────────────────────

/// Accumulates anomalies across the analysis. Every anomaly the crate emits is
/// funnelled through [`Findings::record`], giving one place to trace, set a
/// breakpoint, or post-process findings.
#[derive(Default)]
struct Findings {
    anomalies: Vec<Anomaly>,
}

impl Findings {
    /// Build an anomaly from `kind` + `offset`, emit a trace event, and store it.
    fn record(&mut self, kind: AnomalyKind, offset: u64) {
        let anomaly = Anomaly::new(kind, offset);
        diag::anomaly_recorded(&anomaly);
        self.anomalies.push(anomaly);
    }
}

/// Primary-table scan output threaded into the EBR and gap stages.
struct PrimaryScan {
    /// `(lba_start, lba_end)` inclusive extents of every non-empty partition.
    extents: Vec<(u64, u64)>,
    /// Per-partition forensic summaries.
    summaries: Vec<PartitionSummary>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Perform a full forensic analysis of an MBR-partitioned disk image.
///
/// `disk_size_bytes` is used for gap analysis and out-of-bounds detection.
/// Pass `0` to skip gap analysis.
///
/// # Errors
///
/// Returns [`Error::Io`] on read failures, [`Error::TooShort`] / [`Error::BadSignature`]
/// when the MBR sector is invalid.
#[cfg_attr(feature = "trace", tracing::instrument(level = "debug", skip(reader)))]
pub fn analyse<R: Read + Seek>(reader: &mut R, disk_size_bytes: u64) -> Result<MbrAnalysis, Error> {
    let mbr = read_mbr(reader)?;
    let mut findings = Findings::default();

    let boot_code_id = boot_code::identify(&mbr.boot_code);
    check_boot_code(&mbr, boot_code_id, &mut findings);
    check_disk_signature(&mbr, boot_code_id, &mut findings);
    check_reserved(&mbr, &mut findings);
    check_bootable_flags(&mbr, &mut findings);

    let last_lba = disk_last_lba(disk_size_bytes);
    check_gpt(reader, &mbr, last_lba, &mut findings);
    let mut scan = scan_primary_entries(reader, &mbr, disk_size_bytes, last_lba, &mut findings);
    check_overlaps(&scan.extents, &mut findings);

    let ebr_chain = walk_extended(reader, &mbr, &mut scan, &mut findings);
    let gaps = check_gaps(&scan.extents, disk_size_bytes, last_lba, &mut findings);

    let disk_serial = mbr.disk_serial;
    diag::analysis_complete(
        findings.anomalies.len(),
        scan.summaries.len(),
        gaps.len(),
        boot_code_id,
    );

    Ok(MbrAnalysis {
        mbr,
        partitions: scan.summaries,
        ebr_chain,
        gaps,
        boot_code_id,
        disk_serial,
        anomalies: findings.anomalies,
    })
}

// ── Stages ────────────────────────────────────────────────────────────────────

/// Seek to the start, read 512 bytes, and parse the MBR sector.
fn read_mbr<R: Read + Seek>(reader: &mut R) -> Result<MbrSector, Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut raw = [0u8; SECTOR_SIZE];
    reader.read_exact(&mut raw)?;
    parse_mbr_sector(&raw)
}

/// Flag wiped / erased / unrecognised boot code.
///
/// Unrecognised boot code is additionally entropy-scanned: near-maximal Shannon
/// entropy in the 446-byte code area, with no matching loader, is consistent
/// with a packed or encrypted bootkit payload and raises [`AnomalyKind::HighEntropySlack`].
fn check_boot_code(mbr: &MbrSector, id: BootCodeId, findings: &mut Findings) {
    let kind = match id {
        BootCodeId::AllZeros => Some(AnomalyKind::WipedBootCode),
        BootCodeId::AllOnes => Some(AnomalyKind::ErasedBootCode),
        BootCodeId::Unknown => Some(AnomalyKind::UnknownBootCode),
        _ => None,
    };
    if let Some(kind) = kind {
        findings.record(kind, 0);
    }
    if id == BootCodeId::Unknown {
        let entropy = entropy::shannon(&mbr.boot_code);
        if entropy > entropy::HIGH_ENTROPY_THRESHOLD {
            findings.record(AnomalyKind::HighEntropySlack { offset: 0, entropy }, 0);
        }
    }
}

/// Flag a Windows MBR whose NT disk signature (offset 440) is zero.
///
/// Windows always writes a non-zero signature; its absence under a recognised
/// bootmgr stub is consistent with a wiped or re-created boot record. Non-Windows
/// MBRs routinely leave it zero, so the check is gated on the boot-code identity
/// to avoid false positives. Cross-disk collision detection (the cloning signal)
/// lives in [`crate::disk_signature`].
fn check_disk_signature(mbr: &MbrSector, id: BootCodeId, findings: &mut Findings) {
    let is_windows = matches!(id, BootCodeId::WindowsVista | BootCodeId::Windows7Plus);
    if is_windows && mbr.disk_serial == 0 {
        findings.record(AnomalyKind::ZeroDiskSignature, DISK_SERIAL_OFFSET);
    }
}

/// Minimum hidden tail (in sectors) before an undersized protective MBR is
/// flagged — avoids false positives from a few-sector rounding difference.
const PROTECTIVE_UNDERSIZE_TOLERANCE: u64 = 2048;

/// Cross-validate the MBR against any GPT at LBA 1.
///
/// Reads LBA 1 to determine whether an "EFI PART" header is present, then
/// reconciles it with the presence/shape of a protective 0xEE entry. Surfaces
/// hybrid MBRs, undersized protective entries, hidden GPTs, and spoofed
/// protective MBRs — all data-hiding or tampering vectors.
fn check_gpt<R: Read + Seek>(
    reader: &mut R,
    mbr: &MbrSector,
    last_lba: u64,
    findings: &mut Findings,
) {
    let protective_idx = mbr
        .entries
        .iter()
        .position(|e| !e.is_empty() && e.type_code.0 == crate::gpt::PROTECTIVE_TYPE_CODE);
    let header_present = match read_first_sector(reader, SECTOR_BYTES) {
        Ok(lba1) => crate::gpt::has_gpt_header(&lba1),
        Err(e) => {
            diag::partition_read_failed(SECTOR_BYTES, &e);
            false
        }
    };

    let Some(idx) = protective_idx else {
        // No protective entry. A GPT header with no 0xEE advertising it is hidden.
        if header_present {
            findings.record(AnomalyKind::HiddenGpt, lba_to_byte(1));
        }
        return;
    };

    let off = entry_offset(idx);
    if !header_present {
        findings.record(AnomalyKind::SpoofedProtectiveMbr, off);
        return;
    }

    // Genuine protective entry backed by a GPT header. Check for coexisting real
    // partitions (hybrid) and incomplete disk coverage (undersized).
    let extra = mbr
        .entries
        .iter()
        .filter(|e| !e.is_empty() && e.type_code.0 != crate::gpt::PROTECTIVE_TYPE_CODE)
        .count();
    if extra > 0 {
        findings.record(
            AnomalyKind::HybridMbr {
                extra_partition_count: extra,
            },
            off,
        );
    }

    let ee = &mbr.entries[idx];
    let covered_last_lba = ee.lba_end() as u64;
    let spans_disk = ee.lba_count == u32::MAX; // 0xFFFFFFFF = "rest of disk"
    if last_lba != u64::MAX
        && !spans_disk
        && last_lba.saturating_sub(covered_last_lba) > PROTECTIVE_UNDERSIZE_TOLERANCE
    {
        findings.record(
            AnomalyKind::ProtectiveMbrUndersized {
                covered_last_lba,
                disk_last_lba: last_lba,
            },
            off,
        );
    }
}

/// Flag a non-zero reserved field (bytes 444–445).
fn check_reserved(mbr: &MbrSector, findings: &mut Findings) {
    if mbr.reserved != [0, 0] {
        findings.record(
            AnomalyKind::NonZeroReserved {
                bytes: mbr.reserved,
            },
            RESERVED_OFFSET,
        );
    }
}

/// Audit the bootable flags: more than one is invalid; none with active
/// partitions is noteworthy.
fn check_bootable_flags(mbr: &MbrSector, findings: &mut Findings) {
    let bootable = mbr.entries.iter().filter(|e| e.is_bootable()).count();
    let active = mbr.entries.iter().filter(|e| !e.is_empty()).count();
    if bootable > 1 {
        findings.record(
            AnomalyKind::MultipleBootable { count: bootable },
            PARTITION_TABLE_OFFSET,
        );
    }
    if active > 0 && bootable == 0 {
        findings.record(AnomalyKind::NoBootablePartition, PARTITION_TABLE_OFFSET);
    }
}

/// Walk the four primary entries, emitting per-entry anomalies and collecting
/// extents + summaries for the overlap, EBR, and gap stages.
fn scan_primary_entries<R: Read + Seek>(
    reader: &mut R,
    mbr: &MbrSector,
    disk_size_bytes: u64,
    last_lba: u64,
    findings: &mut Findings,
) -> PrimaryScan {
    let mut extents = Vec::new();
    let mut summaries = Vec::new();

    for (i, entry) in mbr.entries.iter().enumerate() {
        let off = entry_offset(i);

        // Residual entry: type 0x00 but non-zero LBA fields → deleted partition.
        if entry.type_code.is_empty() && (entry.lba_start != 0 || entry.lba_count != 0) {
            findings.record(
                AnomalyKind::ResidualEntry {
                    index: i,
                    lba_start: entry.lba_start,
                    lba_count: entry.lba_count,
                },
                off,
            );
            continue;
        }
        if entry.is_empty() {
            continue;
        }

        check_chs_lba(i, entry, findings);

        let lba_start = entry.lba_start as u64;
        let lba_end = entry.lba_end() as u64;
        let byte_offset = lba_to_byte(lba_start);
        let byte_size = lba_to_byte(entry.lba_count as u64);

        if disk_size_bytes > 0 && lba_end > last_lba {
            findings.record(
                AnomalyKind::OutOfBounds {
                    index: i,
                    last_lba: lba_end,
                    disk_last_lba: last_lba,
                },
                off,
            );
        }

        extents.push((lba_start, lba_end));

        let detected_fs = detect_partition_fs(reader, byte_offset, disk_size_bytes);
        if let Some(detected) = detected_fs {
            if signature::type_conflicts(entry.type_code.family(), detected) {
                findings.record(
                    AnomalyKind::SignatureMismatch {
                        index: i,
                        declared: entry.type_code,
                        detected,
                    },
                    byte_offset,
                );
            }
        }

        summaries.push(PartitionSummary {
            index: i,
            lba_start,
            lba_end,
            byte_offset,
            byte_size,
            declared_type: entry.type_code,
            detected_fs,
        });
    }

    PrimaryScan { extents, summaries }
}

/// Flag a primary entry whose packed CHS first/last addresses contradict their
/// LBA companions — a hallmark of a hand-edited or tool-crafted partition table.
///
/// Uses the de-facto standard LBA-assist geometry; the all-zero "unused"
/// convention and the CHS overflow marker are both accepted (see
/// [`crate::partition::chs_consistency`]).
fn check_chs_lba(index: usize, entry: &crate::partition::PartitionEntry, findings: &mut Findings) {
    use crate::partition::{chs_consistency, ChsConsistency, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK};
    let first = chs_consistency(
        entry.chs_first,
        entry.lba_start,
        STD_HEADS_PER_CYL,
        STD_SECTORS_PER_TRACK,
    );
    let last = chs_consistency(
        entry.chs_last,
        entry.lba_end(),
        STD_HEADS_PER_CYL,
        STD_SECTORS_PER_TRACK,
    );
    if first == ChsConsistency::Inconsistent || last == ChsConsistency::Inconsistent {
        findings.record(AnomalyKind::ChsLbaInconsistency { index }, entry_offset(index));
    }
}

/// Detect overlapping partition extents.
fn check_overlaps(extents: &[(u64, u64)], findings: &mut Findings) {
    let mut sorted = extents.to_vec();
    sorted.sort_by_key(|&(start, _)| start);
    for pair in sorted.windows(2) {
        let (_, a_end) = pair[0];
        let (b_start, _) = pair[1];
        if b_start <= a_end {
            let a = extents.iter().position(|&e| e == pair[0]).unwrap_or(0);
            let b = extents.iter().position(|&e| e == pair[1]).unwrap_or(1);
            findings.record(
                AnomalyKind::OverlappingPartitions {
                    a,
                    b,
                    a_end,
                    b_start,
                },
                entry_offset(a),
            );
        }
    }
}

/// Walk the (single) extended partition's EBR chain, recording chain anomalies
/// and appending each logical partition's extent + summary to `scan`.
fn walk_extended<R: Read + Seek>(
    reader: &mut R,
    mbr: &MbrSector,
    scan: &mut PrimaryScan,
    findings: &mut Findings,
) -> EbrChain {
    let Some(ext) = mbr.entries.iter().find(|e| e.is_extended()) else {
        return EbrChain::empty();
    };
    let ext_start = ext.lba_start as u64;

    let chain = match walk_ebr_chain(reader, ext_start, SECTOR_BYTES) {
        Ok(chain) => chain,
        Err(e) => {
            diag::ebr_walk_failed(ext_start, &e);
            return EbrChain::empty();
        }
    };

    let ext_offset = lba_to_byte(ext_start);
    if chain.had_cycle {
        findings.record(AnomalyKind::EbrCycle, ext_offset);
    }
    if chain.depth_exceeded {
        findings.record(
            AnomalyKind::EbrExcessiveDepth {
                depth: chain.entries.len(),
            },
            ext_offset,
        );
    }

    for ebr in &chain.entries {
        if ebr.has_slack {
            let entropy = entropy::shannon(&ebr.slack);
            findings.record(
                AnomalyKind::EbrSlackData {
                    ebr_lba: ebr.ebr_lba,
                    entropy,
                },
                ebr.ebr_offset + EBR_SLACK_OFFSET,
            );
        }

        let lba_start = ebr.logical_lba_start;
        let lba_end = lba_start
            .saturating_add(ebr.logical.lba_count as u64)
            .saturating_sub(1);
        scan.extents.push((lba_start, lba_end));
        scan.summaries.push(PartitionSummary {
            index: EBR_INDEX_BASE + scan.summaries.len(),
            lba_start,
            lba_end,
            byte_offset: lba_to_byte(lba_start),
            byte_size: lba_to_byte(ebr.logical.lba_count as u64),
            declared_type: ebr.logical.type_code,
            detected_fs: None,
        });
    }

    chain
}

/// Compute unpartitioned gaps and record one anomaly per gap.
/// Returns an empty vec (and records nothing) when `disk_size_bytes == 0`.
fn check_gaps(
    extents: &[(u64, u64)],
    disk_size_bytes: u64,
    last_lba: u64,
    findings: &mut Findings,
) -> Vec<Gap> {
    if disk_size_bytes == 0 {
        return vec![];
    }
    let mut sorted = extents.to_vec();
    sorted.sort_by_key(|&(start, _)| start);
    sorted.dedup();

    let gaps = compute_gaps(&sorted, 1, last_lba, SECTOR_BYTES);
    for gap in &gaps {
        findings.record(gap_anomaly_kind(gap), lba_to_byte(gap.lba_start));
    }
    gaps
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Map a [`Gap`] to its corresponding [`AnomalyKind`].
fn gap_anomaly_kind(gap: &Gap) -> AnomalyKind {
    match gap.kind {
        GapKind::PrePartition => AnomalyKind::PrePartitionSpace {
            lba_start: gap.lba_start,
            lba_end: gap.lba_end,
            byte_size: gap.byte_size,
        },
        GapKind::Between => AnomalyKind::InterPartitionGap {
            lba_start: gap.lba_start,
            lba_end: gap.lba_end,
            byte_size: gap.byte_size,
        },
        GapKind::PostPartition => AnomalyKind::PostPartitionSpace {
            lba_start: gap.lba_start,
            lba_end: gap.lba_end,
            byte_size: gap.byte_size,
        },
    }
}

/// Read and fingerprint a partition's first sector. Returns `None` when the
/// partition starts beyond the known disk size, or the read fails.
fn detect_partition_fs<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
    disk_size_bytes: u64,
) -> Option<DetectedFs> {
    if disk_size_bytes != 0 && byte_offset >= disk_size_bytes {
        return None;
    }
    match read_first_sector(reader, byte_offset) {
        Ok(sector) => Some(signature::detect(&sector)),
        Err(e) => {
            diag::partition_read_failed(byte_offset, &e);
            None
        }
    }
}

/// Read a single 512-byte sector at `byte_offset`.
fn read_first_sector<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
) -> Result<[u8; SECTOR_SIZE], Error> {
    reader.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = [0u8; SECTOR_SIZE];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}
