//! Orchestration: the public [`analyse`] entry point and its per-stage checks.
//!
//! The analysis is a pipeline of small, independently-debuggable stages. Each
//! stage receives the parsed data plus a [`Findings`] accumulator and records
//! any anomalies it discovers. Every anomaly in the crate flows through the
//! single [`Findings::record`] choke point, which is where tracing, breakpoints,
//! or post-processing belong.

use std::io::{Read, Seek, SeekFrom};

use crate::diag;
use crate::entropy;
use crate::findings::{Anomaly, AnomalyKind, MbrAnalysis, PartitionSummary};
use crate::gap::{compute_gaps, Gap, GapKind};
use crate::Error;
use mbr::boot_code::{self, BootCodeId};
use mbr::ebr::{walk_ebr_chain, EbrChain};
use mbr::mbr::{parse_mbr_sector, MbrSector, SECTOR_SIZE};
use mbr::signature::{self, DetectedFs};

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
fn lba_to_byte(lba: u64, sector_size: u64) -> u64 {
    lba.saturating_mul(sector_size)
}

/// Byte offset of primary partition entry `index` within the MBR sector.
#[inline]
fn entry_offset(index: usize) -> u64 {
    PARTITION_TABLE_OFFSET + index as u64 * ENTRY_SIZE
}

/// Inclusive last LBA of a disk of `disk_size_bytes`, or [`u64::MAX`] (i.e. "no
/// bound") when the size is unknown (`0`).
#[inline]
fn disk_last_lba(disk_size_bytes: u64, sector_size: u64) -> u64 {
    if disk_size_bytes > 0 {
        (disk_size_bytes / sector_size).saturating_sub(1)
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
    /// `(lba_start, lba_end)` inclusive extents of every non-empty partition
    /// (including extended containers) — used for gap analysis.
    extents: Vec<(u64, u64)>,
    /// `(id, lba_start, lba_end)` for *data* partitions only — non-extended
    /// primaries and logicals, used for overlap detection. Extended containers
    /// are excluded so their logicals are not flagged as overlapping them.
    overlap_extents: Vec<(usize, u64, u64)>,
    /// Per-partition forensic summaries.
    summaries: Vec<PartitionSummary>,
}

/// Options controlling [`analyse_with_options`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AnalyseOptions {
    /// Logical sector size in bytes. Defaults to 512; set to 4096 for a 4Kn
    /// (Advanced Format) disk so partition-content offsets, gap sizes, and
    /// out-of-bounds bounds are computed against the correct geometry.
    pub sector_size: u64,
}

impl Default for AnalyseOptions {
    fn default() -> Self {
        Self {
            sector_size: SECTOR_BYTES,
        }
    }
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
    analyse_with_options(reader, disk_size_bytes, AnalyseOptions::default())
}

/// Like [`analyse`], but with explicit [`AnalyseOptions`] — e.g. to force a 4Kn
/// (4096-byte) logical sector size for an Advanced Format disk.
///
/// The MBR boot record is always parsed from byte 0 (it is a 512-byte structure
/// regardless of sector size); only partition-content offsets, gap sizes, and
/// out-of-bounds bounds scale with [`AnalyseOptions::sector_size`].
///
/// # Errors
///
/// Same as [`analyse`].
#[cfg_attr(feature = "trace", tracing::instrument(level = "debug", skip(reader)))]
pub fn analyse_with_options<R: Read + Seek>(
    reader: &mut R,
    disk_size_bytes: u64,
    opts: AnalyseOptions,
) -> Result<MbrAnalysis, Error> {
    let sector_size = opts.sector_size;
    let mbr = read_mbr(reader)?;
    let mut findings = Findings::default();

    let boot_code_id = boot_code::identify(&mbr.boot_code);
    // Read LBA 1 once: it decides both the GPT cross-validation and whether an
    // all-zero boot code is benign (genuine GPT disk) or suspicious (legacy).
    let gpt_header = gpt_header_present(reader, sector_size);
    let on_gpt_disk = gpt_header && is_pure_protective_mbr(&mbr);

    check_boot_code(&mbr, boot_code_id, on_gpt_disk, &mut findings);
    check_disk_signature(&mbr, boot_code_id, &mut findings);
    check_reserved(&mbr, &mut findings);
    check_bootable_flags(&mbr, &mut findings);
    check_duplicate_entries(&mbr, &mut findings);

    let last_lba = disk_last_lba(disk_size_bytes, sector_size);
    check_gpt(&mbr, last_lba, gpt_header, sector_size, &mut findings);
    let mut scan = scan_primary_entries(
        reader,
        &mbr,
        disk_size_bytes,
        last_lba,
        sector_size,
        &mut findings,
    );

    let ebr_chain = walk_extended(
        reader,
        &mbr,
        &mut scan,
        disk_size_bytes,
        sector_size,
        &mut findings,
    );
    // Overlap detection runs on data partitions (non-extended primaries +
    // logicals) AFTER the EBR walk, so logical-partition overlaps are caught.
    // Extended containers are excluded — their logicals living inside them is
    // expected, not an overlap.
    check_overlaps(&scan.overlap_extents, &mut findings);
    let gaps = check_gaps(
        &scan.extents,
        disk_size_bytes,
        last_lba,
        sector_size,
        &mut findings,
    );
    check_gap_content(reader, &gaps, sector_size, &mut findings);

    // When the disk turns out to be GPT, parse the real GUID Partition Table
    // automatically via the sibling gpt-forensic crate.
    #[cfg(feature = "gpt")]
    let gpt = if gpt_header {
        gpt_partition_forensic::analyse(reader, disk_size_bytes).ok()
    } else {
        None
    };

    let disk_serial = mbr.disk_serial;
    let era = crate::provenance::infer_era(first_partition_lba(&mbr), boot_code_id);
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
        era,
        #[cfg(feature = "gpt")]
        gpt,
        anomalies: findings.anomalies,
    })
}

/// Lowest start LBA among real (non-empty, non-extended, non-protective) primary
/// partitions — the geometry signal for era attribution. `None` when there are
/// none.
fn first_partition_lba(mbr: &MbrSector) -> Option<u64> {
    mbr.entries
        .iter()
        .filter(|e| {
            !e.is_empty() && !e.is_extended() && e.type_code.0 != mbr::gpt::PROTECTIVE_TYPE_CODE
        })
        .map(|e| e.lba_start as u64)
        .min()
}

/// `true` when an "EFI PART" GPT header is present at LBA 1. A read failure
/// (e.g. a sub-1024-byte image) is treated as "absent".
fn gpt_header_present<R: Read + Seek>(reader: &mut R, sector_size: u64) -> bool {
    match read_first_sector(reader, sector_size) {
        Ok(lba1) => mbr::gpt::has_gpt_header(&lba1),
        Err(e) => {
            diag::partition_read_failed(sector_size, &e);
            false
        }
    }
}

/// `true` when the MBR is a *pure* GPT protective MBR: exactly one non-empty
/// entry, of type 0xEE. Hybrid MBRs (extra real entries) are excluded, because
/// their boot code can still be executed by a legacy BIOS.
fn is_pure_protective_mbr(mbr: &MbrSector) -> bool {
    let mut nonempty = mbr.entries.iter().filter(|e| !e.is_empty());
    matches!(
        (nonempty.next(), nonempty.next()),
        (Some(e), None) if e.type_code.0 == mbr::gpt::PROTECTIVE_TYPE_CODE
    )
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
/// All-zero boot code is context-dependent: on a legacy BIOS/MBR-boot disk the
/// boot code is executed first, so all-zero is suspicious ([`AnomalyKind::WipedBootCode`],
/// High); on a genuine GPT disk (`on_gpt_disk`) the MBR boot code is never run,
/// so all-zero is benign ([`AnomalyKind::EmptyProtectiveBootCode`], Info).
///
/// Unrecognised boot code is additionally entropy-scanned: near-maximal Shannon
/// entropy in the 446-byte code area, with no matching loader, is consistent
/// with a packed or encrypted bootkit payload and raises [`AnomalyKind::HighEntropySlack`].
/// Hex of the leading boot-code bytes. The first 16 bytes carry the jump +
/// entry stub that fingerprints a boot loader, so surfacing them lets an
/// investigator identify an otherwise-"unknown" loader instead of hitting a
/// dead end.
fn boot_code_head_hex(boot_code: &[u8]) -> String {
    boot_code
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn check_boot_code(mbr: &MbrSector, id: BootCodeId, on_gpt_disk: bool, findings: &mut Findings) {
    let kind = match id {
        BootCodeId::AllZeros if on_gpt_disk => Some(AnomalyKind::EmptyProtectiveBootCode),
        BootCodeId::AllZeros => Some(AnomalyKind::WipedBootCode),
        BootCodeId::AllOnes => Some(AnomalyKind::ErasedBootCode),
        BootCodeId::Unknown => Some(AnomalyKind::UnknownBootCode {
            boot_code_hex: boot_code_head_hex(&mbr.boot_code),
        }),
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

    // Documented boot-sector-malware markers — scanned regardless of loader
    // identity, since a marker can coexist with otherwise-valid-looking code.
    for name in crate::bootkit::scan(&mbr.boot_code) {
        findings.record(AnomalyKind::KnownBootkit { name }, 0);
    }
}

/// Flag a Windows MBR whose NT disk signature (offset 440) is zero.
///
/// Windows always writes a non-zero signature; its absence under a recognised
/// bootmgr stub is consistent with a wiped or re-created boot record. Non-Windows
/// MBRs routinely leave it zero, so the check is gated on the boot-code identity
/// to avoid false positives. Cross-disk collision detection (the cloning signal)
/// lives in [`mbr::disk_signature`].
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
/// `header_present` is whether an "EFI PART" header was found at LBA 1 (read
/// once by the caller). Reconciles it with the presence/shape of a protective
/// 0xEE entry, surfacing hybrid MBRs, undersized protective entries, hidden
/// GPTs, and spoofed protective MBRs — all data-hiding or tampering vectors.
fn check_gpt(
    mbr: &MbrSector,
    last_lba: u64,
    header_present: bool,
    sector_size: u64,
    findings: &mut Findings,
) {
    let protective_idx = mbr
        .entries
        .iter()
        .position(|e| !e.is_empty() && e.type_code.0 == mbr::gpt::PROTECTIVE_TYPE_CODE);

    let Some(idx) = protective_idx else {
        // No protective entry. A GPT header with no 0xEE advertising it is hidden.
        if header_present {
            findings.record(AnomalyKind::HiddenGpt, lba_to_byte(1, sector_size));
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
        .filter(|e| !e.is_empty() && e.type_code.0 != mbr::gpt::PROTECTIVE_TYPE_CODE)
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

/// Flag pairs of non-empty primary entries that describe the identical extent
/// (same start LBA and sector count) — a duplicate left by hand-editing or a
/// faulty imaging tool. Each colliding pair is reported once (lowest indices).
fn check_duplicate_entries(mbr: &MbrSector, findings: &mut Findings) {
    let e = &mbr.entries;
    for a in 0..e.len() {
        if e[a].is_empty() {
            continue;
        }
        for b in (a + 1)..e.len() {
            if !e[b].is_empty()
                && e[a].lba_start == e[b].lba_start
                && e[a].lba_count == e[b].lba_count
            {
                findings.record(
                    AnomalyKind::DuplicatePartitionEntry { a, b },
                    entry_offset(a),
                );
            }
        }
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
    sector_size: u64,
    findings: &mut Findings,
) -> PrimaryScan {
    let mut extents = Vec::new();
    let mut overlap_extents = Vec::new();
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

        // Status byte must be 0x00 (inactive) or 0x80 (bootable); anything else
        // is a spec violation and a manual-edit / tooling artifact.
        if entry.status != 0x00 && entry.status != 0x80 {
            findings.record(
                AnomalyKind::InvalidPartitionStatus {
                    index: i,
                    status: entry.status,
                },
                off,
            );
        }

        check_chs_lba(i, entry, findings);

        let lba_start = entry.lba_start as u64;
        let lba_end = entry.lba_end() as u64;
        let byte_offset = lba_to_byte(lba_start, sector_size);
        let byte_size = lba_to_byte(entry.lba_count as u64, sector_size);

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
        // Extended containers are excluded from overlap detection — their
        // logicals living inside them is expected, not an overlap.
        if !entry.is_extended() {
            overlap_extents.push((i, lba_start, lba_end));
        }

        check_vbr(reader, i, lba_start, byte_offset, disk_size_bytes, findings);

        let detected_fs = detect_and_check_fs(
            reader,
            i,
            byte_offset,
            entry.type_code,
            disk_size_bytes,
            findings,
        );

        let (volume_serial, encryption) = partition_volume(reader, byte_offset, disk_size_bytes);
        summaries.push(PartitionSummary {
            index: i,
            lba_start,
            lba_end,
            byte_offset,
            byte_size,
            declared_type: entry.type_code,
            detected_fs,
            volume_serial,
            encryption,
        });
    }

    PrimaryScan {
        extents,
        overlap_extents,
        summaries,
    }
}

/// Fingerprint a partition's filesystem and flag a declared-vs-detected
/// mismatch. Shared by the primary scan and the EBR logical walk so both get
/// identical scrutiny. Returns the detected filesystem (if any).
fn detect_and_check_fs<R: Read + Seek>(
    reader: &mut R,
    index: usize,
    byte_offset: u64,
    declared: mbr::partition::TypeCode,
    disk_size_bytes: u64,
    findings: &mut Findings,
) -> Option<DetectedFs> {
    let detected_fs = detect_partition_fs(reader, byte_offset, disk_size_bytes);
    if let Some(detected) = detected_fs {
        if signature::type_conflicts(declared.family(), detected) {
            findings.record(
                AnomalyKind::SignatureMismatch {
                    index,
                    declared,
                    detected,
                },
                byte_offset,
            );
        }
    }
    detected_fs
}

/// Read a partition's volume serial and BitLocker encryption from its first sector, via
/// `forensicnomicon`'s volume-analysis (the knowledge owner). Both are properties of the
/// volume, not of the partition table, so they are surfaced on every partition uniformly
/// rather than re-read by each downstream consumer. `(None, None)` on an unreadable sector.
fn partition_volume<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
    disk_size_bytes: u64,
) -> (
    Option<forensicnomicon::volume_serial::VolumeSerial>,
    Option<forensicnomicon::volume_encryption::VolumeEncryption>,
) {
    if disk_size_bytes != 0 && byte_offset >= disk_size_bytes {
        return (None, None);
    }
    match read_fingerprint(reader, byte_offset, FS_FINGERPRINT_BYTES) {
        Ok(buf) => (
            forensicnomicon::volume_serial::volume_serial(&buf),
            forensicnomicon::volume_encryption::detect_encryption(&buf),
        ),
        Err(_) => (None, None),
    }
}

/// Flag a primary entry whose packed CHS first/last addresses contradict their
/// LBA companions — a hallmark of a hand-edited or tool-crafted partition table.
///
/// Uses the de-facto standard LBA-assist geometry; the all-zero "unused"
/// convention and the CHS overflow marker are both accepted (see
/// [`mbr::partition::chs_consistency`]).
fn check_chs_lba(index: usize, entry: &mbr::partition::PartitionEntry, findings: &mut Findings) {
    use mbr::partition::{
        chs_consistency, ChsConsistency, STD_HEADS_PER_CYL, STD_SECTORS_PER_TRACK,
    };
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
        findings.record(
            AnomalyKind::ChsLbaInconsistency { index },
            entry_offset(index),
        );
    }
}

/// Parse a partition's VBR and flag a stale BPB hidden-sectors field.
///
/// A FAT/NTFS volume records its disk offset in the BPB; when it disagrees with
/// the partition-table LBA the volume was relocated/copied or the table edited.
/// Only nonzero mismatches are flagged (zero is the removable-media convention),
/// and non-FAT/NTFS first sectors are skipped via [`mbr::vbr::parse_bpb`].
fn check_vbr<R: Read + Seek>(
    reader: &mut R,
    index: usize,
    lba_start: u64,
    byte_offset: u64,
    disk_size_bytes: u64,
    findings: &mut Findings,
) {
    if disk_size_bytes != 0 && byte_offset >= disk_size_bytes {
        return;
    }
    let Ok(sector) = read_first_sector(reader, byte_offset) else {
        return;
    };
    let Some(bpb) = mbr::vbr::parse_bpb(&sector) else {
        return;
    };
    if bpb.hidden_sectors != 0 && u64::from(bpb.hidden_sectors) != lba_start {
        findings.record(
            AnomalyKind::VbrHiddenSectorsMismatch {
                index,
                bpb_hidden: bpb.hidden_sectors,
                lba_start,
            },
            byte_offset,
        );
    }
}

/// Detect overlapping data-partition extents.
///
/// Operates on `(id, lba_start, lba_end)` triples for non-extended primaries and
/// logicals (extended containers excluded — see [`PrimaryScan::overlap_extents`]),
/// so overlaps among logicals and between logicals and primaries are caught.
fn check_overlaps(extents: &[(usize, u64, u64)], findings: &mut Findings) {
    let mut sorted = extents.to_vec();
    sorted.sort_by_key(|&(_, start, _)| start);
    for pair in sorted.windows(2) {
        let (a_id, _, a_end) = pair[0];
        let (b_id, b_start, _) = pair[1];
        if b_start <= a_end {
            findings.record(
                AnomalyKind::OverlappingPartitions {
                    a: a_id,
                    b: b_id,
                    a_end,
                    b_start,
                },
                entry_offset(a_id.min(3)),
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
    disk_size_bytes: u64,
    sector_size: u64,
    findings: &mut Findings,
) -> EbrChain {
    let Some(ext) = mbr.entries.iter().find(|e| e.is_extended()) else {
        return EbrChain::empty();
    };
    let ext_start = ext.lba_start as u64;

    let chain = match walk_ebr_chain(reader, ext_start, sector_size) {
        Ok(chain) => chain,
        Err(e) => {
            diag::ebr_walk_failed(ext_start, &e);
            return EbrChain::empty();
        }
    };

    let ext_offset = lba_to_byte(ext_start, sector_size);
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
        let byte_offset = lba_to_byte(lba_start, sector_size);
        let index = EBR_INDEX_BASE + scan.summaries.len();

        scan.extents.push((lba_start, lba_end));
        scan.overlap_extents.push((index, lba_start, lba_end));

        // Logical partitions get the same scrutiny as primaries: BPB
        // hidden-sectors relocation check and FS signature-mismatch detection.
        check_vbr(
            reader,
            index,
            lba_start,
            byte_offset,
            disk_size_bytes,
            findings,
        );
        let detected_fs = detect_and_check_fs(
            reader,
            index,
            byte_offset,
            ebr.logical.type_code,
            disk_size_bytes,
            findings,
        );

        let (volume_serial, encryption) = partition_volume(reader, byte_offset, disk_size_bytes);
        scan.summaries.push(PartitionSummary {
            index,
            lba_start,
            lba_end,
            byte_offset,
            byte_size: lba_to_byte(ebr.logical.lba_count as u64, sector_size),
            declared_type: ebr.logical.type_code,
            detected_fs,
            volume_serial,
            encryption,
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
    sector_size: u64,
    findings: &mut Findings,
) -> Vec<Gap> {
    if disk_size_bytes == 0 {
        return vec![];
    }
    let mut sorted = extents.to_vec();
    sorted.sort_by_key(|&(start, _)| start);
    sorted.dedup();

    let gaps = compute_gaps(&sorted, 1, last_lba, sector_size);
    for gap in &gaps {
        findings.record(
            gap_anomaly_kind(gap),
            lba_to_byte(gap.lba_start, sector_size),
        );
    }
    gaps
}

/// Number of bytes sampled from the start of each gap to classify its fill.
const GAP_SAMPLE_BYTES: usize = 4096;

/// Sample the start of each unpartitioned gap and flag any that carry a
/// deliberate wipe pattern (uniform non-zero, alternating, etc.).
///
/// All-zero gaps — ordinary unallocated space — are never flagged. Read
/// failures (truncated images) are skipped silently; gap *existence* is already
/// reported by [`check_gaps`].
fn check_gap_content<R: Read + Seek>(
    reader: &mut R,
    gaps: &[Gap],
    sector_size: u64,
    findings: &mut Findings,
) {
    for gap in gaps {
        let byte_offset = lba_to_byte(gap.lba_start, sector_size);
        let sample_len = gap.byte_size.min(GAP_SAMPLE_BYTES as u64) as usize;
        if sample_len == 0 {
            continue;
        }
        if reader.seek(SeekFrom::Start(byte_offset)).is_err() {
            continue;
        }
        let mut buf = vec![0u8; sample_len];
        if reader.read_exact(&mut buf).is_err() {
            continue;
        }
        let pattern = crate::wipe::classify(&buf);
        if pattern.is_deliberate_wipe() {
            findings.record(
                AnomalyKind::WipedRegion {
                    lba_start: gap.lba_start,
                    pattern,
                },
                byte_offset,
            );
        }

        // Carve recoverable file headers from the same window — leftover data
        // from deleted or hidden files in unallocated space.
        for artifact in mbr::carve::carve(&buf, byte_offset) {
            findings.record(
                AnomalyKind::CarvedArtifact {
                    kind: artifact.kind,
                },
                artifact.offset,
            );
        }
    }
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

/// Bytes read from a partition's start for filesystem fingerprinting. Sized to
/// reach the Btrfs superblock magic at 64 KiB (the deepest magic we recognise);
/// shallower magics (NTFS@3, ext@1080, swap@4086) fall within it.
const FS_FINGERPRINT_BYTES: usize = 65600 + 8;

/// Read and fingerprint a partition's start. Returns `None` when the partition
/// starts beyond the known disk size, or the read fails.
///
/// Reads up to [`FS_FINGERPRINT_BYTES`], tolerating a short read at end-of-disk
/// — fingerprints are offset-based, so a partial window still matches every
/// magic that fits within it.
fn detect_partition_fs<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
    disk_size_bytes: u64,
) -> Option<DetectedFs> {
    if disk_size_bytes != 0 && byte_offset >= disk_size_bytes {
        return None;
    }
    match read_fingerprint(reader, byte_offset, FS_FINGERPRINT_BYTES) {
        Ok(buf) => Some(signature::detect(&buf)),
        Err(e) => {
            diag::partition_read_failed(byte_offset, &e);
            None
        }
    }
}

/// Read up to `max` bytes from `byte_offset`, returning however many were
/// available (a short read at EOF is not an error).
fn read_fingerprint<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
    max: usize,
) -> Result<Vec<u8>, Error> {
    reader.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(filled);
    Ok(buf)
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
