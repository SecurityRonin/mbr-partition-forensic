//! Orchestration: ties all modules together into a single [`analyse`] call.

use std::io::{Read, Seek, SeekFrom};

use crate::boot_code;
use crate::ebr::{walk_ebr_chain, EbrChain};
use crate::entropy;
use crate::findings::{Anomaly, AnomalyKind, MbrAnalysis, PartitionSummary, Severity};
use crate::gap::{compute_gaps, GapKind};
use crate::mbr::{parse_mbr_sector, SECTOR_SIZE};
use crate::partition::TypeCode;
use crate::signature::{self, DetectedFs};
use crate::Error;

const SECTOR_BYTES: u64 = SECTOR_SIZE as u64;
/// Entropy threshold above which slack is flagged as potentially data-bearing.
const HIGH_ENTROPY_THRESHOLD: f64 = 6.0;

/// Perform a full forensic analysis of an MBR-partitioned disk image.
///
/// `disk_size_bytes` is used for gap analysis and out-of-bounds detection.
/// Pass `0` to skip gap analysis.
///
/// # Errors
///
/// Returns [`Error::Io`] on read failures, [`Error::TooShort`] / [`Error::BadSignature`]
/// when the MBR sector is invalid.
pub fn analyse<R: Read + Seek>(reader: &mut R, disk_size_bytes: u64) -> Result<MbrAnalysis, Error> {
    // ── 1. Read and parse the MBR sector ─────────────────────────────────────
    reader.seek(SeekFrom::Start(0))?;
    let mut raw = [0u8; 512];
    reader.read_exact(&mut raw)?;
    let mbr = parse_mbr_sector(&raw)?;

    let mut anomalies: Vec<Anomaly> = Vec::new();

    // ── 2. Boot code identification ───────────────────────────────────────────
    let boot_code_id = boot_code::identify(&mbr.boot_code);
    match boot_code_id {
        crate::boot_code::BootCodeId::AllZeros => anomalies.push(Anomaly {
            severity: Severity::High,
            kind: AnomalyKind::WipedBootCode,
            offset: 0,
            note: "Boot code is all zeros — likely wiped or overwritten".into(),
        }),
        crate::boot_code::BootCodeId::AllOnes => anomalies.push(Anomaly {
            severity: Severity::High,
            kind: AnomalyKind::ErasedBootCode,
            offset: 0,
            note: "Boot code is all 0xFF — factory-erased or deliberate wipe".into(),
        }),
        crate::boot_code::BootCodeId::Unknown => anomalies.push(Anomaly {
            severity: Severity::Low,
            kind: AnomalyKind::UnknownBootCode,
            offset: 0,
            note: "Boot code signature not recognised".into(),
        }),
        _ => {}
    }

    // ── 3. Reserved bytes (444–445) ───────────────────────────────────────────
    if mbr.reserved != [0, 0] {
        anomalies.push(Anomaly {
            severity: Severity::Medium,
            kind: AnomalyKind::NonZeroReserved,
            offset: 444,
            note: format!(
                "Reserved bytes at offset 444 are non-zero: [{:#04X}, {:#04X}]",
                mbr.reserved[0], mbr.reserved[1]
            ),
        });
    }

    // ── 4. Bootable flag audit ────────────────────────────────────────────────
    let bootable_count = mbr.entries.iter().filter(|e| e.is_bootable()).count();
    if bootable_count > 1 {
        anomalies.push(Anomaly {
            severity: Severity::Medium,
            kind: AnomalyKind::MultipleBootable,
            offset: 446,
            note: format!("{bootable_count} partition entries have the bootable flag set"),
        });
    }
    let active_entries: Vec<_> = mbr.entries.iter().filter(|e| !e.is_empty()).collect();
    if !active_entries.is_empty() && bootable_count == 0 {
        anomalies.push(Anomaly {
            severity: Severity::Info,
            kind: AnomalyKind::NoBootablePartition,
            offset: 446,
            note: "No partition is marked bootable".into(),
        });
    }

    // ── 5. Per-entry checks ───────────────────────────────────────────────────
    let disk_last_lba = if disk_size_bytes > 0 {
        (disk_size_bytes / SECTOR_BYTES).saturating_sub(1)
    } else {
        u64::MAX
    };

    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut partition_summaries: Vec<PartitionSummary> = Vec::new();

    for (i, entry) in mbr.entries.iter().enumerate() {
        let entry_offset = 446 + i as u64 * 16;

        // Residual entry: type 0 but non-zero LBA.
        if entry.type_code.is_empty() && (entry.lba_start != 0 || entry.lba_count != 0) {
            anomalies.push(Anomaly {
                severity: Severity::Medium,
                kind: AnomalyKind::ResidualEntry { index: i },
                offset: entry_offset,
                note: format!(
                    "Entry {i}: type=0x00 but lba_start={} lba_count={} — possible deleted partition",
                    entry.lba_start, entry.lba_count
                ),
            });
            continue;
        }
        if entry.is_empty() {
            continue;
        }

        let lba_start = entry.lba_start as u64;
        let lba_end = entry.lba_end() as u64;
        let byte_offset = lba_start * SECTOR_BYTES;
        let byte_size = entry.lba_count as u64 * SECTOR_BYTES;

        // Out-of-bounds check.
        if disk_size_bytes > 0 && lba_end > disk_last_lba {
            anomalies.push(Anomaly {
                severity: Severity::High,
                kind: AnomalyKind::OutOfBounds { index: i },
                offset: entry_offset,
                note: format!(
                    "Entry {i}: last LBA {lba_end} exceeds disk last LBA {disk_last_lba}"
                ),
            });
        }

        extents.push((lba_start, lba_end));

        // Read first sector for filesystem fingerprinting.
        let detected_fs: Option<DetectedFs> = if disk_size_bytes == 0 || byte_offset < disk_size_bytes {
            read_partition_first_sector(reader, byte_offset)
                .ok()
                .map(|s| signature::detect(&s))
        } else {
            None
        };

        // Signature mismatch.
        if let Some(detected) = detected_fs {
            if is_mismatch(entry.type_code, detected) {
                anomalies.push(Anomaly {
                    severity: Severity::Medium,
                    kind: AnomalyKind::SignatureMismatch {
                        index: i,
                        declared: entry.type_code,
                        detected,
                    },
                    offset: byte_offset,
                    note: format!(
                        "Entry {i}: declared type {:?} ({}) but detected {:?} from first sector",
                        entry.type_code.family(),
                        entry.type_code.name(),
                        detected,
                    ),
                });
            }
        }

        partition_summaries.push(PartitionSummary {
            index: i,
            lba_start,
            lba_end,
            byte_offset,
            byte_size,
            declared_type: entry.type_code,
            detected_fs,
        });
    }

    // ── 6. Partition overlap check ────────────────────────────────────────────
    {
        let mut sorted = extents.clone();
        sorted.sort_by_key(|&(s, _)| s);
        for pair in sorted.windows(2) {
            let (_, end_a) = pair[0];
            let (start_b, _) = pair[1];
            if start_b <= end_a {
                // Find the original indices.
                let a = extents.iter().position(|&e| e == pair[0]).unwrap_or(0);
                let b = extents.iter().position(|&e| e == pair[1]).unwrap_or(1);
                anomalies.push(Anomaly {
                    severity: Severity::Critical,
                    kind: AnomalyKind::OverlappingPartitions { a, b },
                    offset: 446 + a as u64 * 16,
                    note: format!(
                        "Partitions {a} and {b} overlap (entry {a} ends at LBA {end_a}, entry {b} starts at {start_b})"
                    ),
                });
            }
        }
    }

    // ── 7. EBR chain traversal ────────────────────────────────────────────────
    let mut ebr_chain = EbrChain { entries: vec![], had_cycle: false, depth_exceeded: false };

    for entry in &mbr.entries {
        if entry.is_extended() {
            let ext_start = entry.lba_start as u64;
            match walk_ebr_chain(reader, ext_start, SECTOR_BYTES) {
                Ok(chain) => {
                    if chain.had_cycle {
                        anomalies.push(Anomaly {
                            severity: Severity::Critical,
                            kind: AnomalyKind::EbrCycle,
                            offset: ext_start * SECTOR_BYTES,
                            note: "EBR chain contains a cycle".into(),
                        });
                    }
                    if chain.depth_exceeded {
                        anomalies.push(Anomaly {
                            severity: Severity::High,
                            kind: AnomalyKind::EbrExcessiveDepth { depth: chain.entries.len() },
                            offset: ext_start * SECTOR_BYTES,
                            note: format!(
                                "EBR chain depth exceeded {} — possibly corrupt or adversarial",
                                chain.entries.len()
                            ),
                        });
                    }
                    for ebr in &chain.entries {
                        if ebr.has_slack {
                            let slack_entropy = entropy::shannon(&ebr.slack);
                            let sev = if slack_entropy > HIGH_ENTROPY_THRESHOLD {
                                Severity::High
                            } else {
                                Severity::Medium
                            };
                            anomalies.push(Anomaly {
                                severity: sev,
                                kind: AnomalyKind::EbrSlackData { ebr_lba: ebr.ebr_lba },
                                offset: ebr.ebr_offset + 478,
                                note: format!(
                                    "EBR at LBA {} has non-zero slack (entropy {:.2})",
                                    ebr.ebr_lba, slack_entropy
                                ),
                            });
                        }
                        // Add logical partition extents.
                        let ls = ebr.logical_lba_start;
                        let le = ls.saturating_add(ebr.logical.lba_count as u64).saturating_sub(1);
                        extents.push((ls, le));
                        partition_summaries.push(PartitionSummary {
                            index: 4 + partition_summaries.len(),
                            lba_start: ls,
                            lba_end: le,
                            byte_offset: ls * SECTOR_BYTES,
                            byte_size: ebr.logical.lba_count as u64 * SECTOR_BYTES,
                            declared_type: ebr.logical.type_code,
                            detected_fs: None,
                        });
                    }
                    ebr_chain = chain;
                }
                Err(_) => {}
            }
            break; // Only one extended partition per MBR.
        }
    }

    // ── 8. Gap analysis ───────────────────────────────────────────────────────
    let mut sorted_extents = extents.clone();
    sorted_extents.sort_by_key(|&(s, _)| s);
    sorted_extents.dedup();

    let gaps = if disk_size_bytes > 0 {
        let gaps_raw = compute_gaps(&sorted_extents, 1, disk_last_lba, SECTOR_BYTES);
        for gap in &gaps_raw {
            let (kind, note) = match gap.kind {
                GapKind::PrePartition => (
                    AnomalyKind::PrePartitionSpace { sector_count: gap.lba_end - gap.lba_start + 1 },
                    format!(
                        "Pre-partition space: LBA {}–{} ({} sectors, {} bytes)",
                        gap.lba_start, gap.lba_end,
                        gap.lba_end - gap.lba_start + 1,
                        gap.byte_size
                    ),
                ),
                GapKind::Between => (
                    AnomalyKind::InterPartitionGap { lba_start: gap.lba_start, lba_end: gap.lba_end },
                    format!(
                        "Gap between partitions: LBA {}–{} ({} bytes)",
                        gap.lba_start, gap.lba_end, gap.byte_size
                    ),
                ),
                GapKind::PostPartition => (
                    AnomalyKind::PostPartitionSpace {
                        lba_start: gap.lba_start,
                        sector_count: gap.lba_end - gap.lba_start + 1,
                    },
                    format!(
                        "Post-partition space: LBA {}–{} ({} sectors, {} bytes)",
                        gap.lba_start, gap.lba_end,
                        gap.lba_end - gap.lba_start + 1,
                        gap.byte_size
                    ),
                ),
            };
            let sev = match gap.kind {
                GapKind::PrePartition if gap.lba_start < 63 => Severity::Low,
                GapKind::PrePartition => Severity::Medium,
                GapKind::Between => Severity::Medium,
                GapKind::PostPartition => Severity::Info,
            };
            anomalies.push(Anomaly { severity: sev, kind, offset: gap.lba_start * SECTOR_BYTES, note });
        }
        gaps_raw
    } else {
        vec![]
    };

    let disk_serial = mbr.disk_serial;
    Ok(MbrAnalysis {
        mbr,
        partitions: partition_summaries,
        ebr_chain,
        gaps,
        boot_code_id,
        disk_serial,
        anomalies,
    })
}

fn read_partition_first_sector<R: Read + Seek>(
    reader: &mut R,
    byte_offset: u64,
) -> Result<[u8; 512], Error> {
    reader.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Returns `true` when the declared type and detected filesystem are clearly
/// incompatible — deliberately conservative to avoid false positives.
fn is_mismatch(declared: TypeCode, detected: crate::signature::DetectedFs) -> bool {
    use crate::partition::PartitionFamily as Pf;
    use crate::signature::DetectedFs as Df;
    if matches!(detected, Df::Unknown | Df::AllZeros) {
        return false;
    }
    match (declared.family(), detected) {
        (Pf::Ntfs, Df::Ext | Df::Fat | Df::Luks | Df::LinuxSwap | Df::LinuxLvm | Df::Xfs | Df::Apfs) => true,
        (Pf::Fat16 | Pf::Fat32 | Pf::Fat12, Df::Ntfs | Df::Ext | Df::Luks | Df::LinuxSwap | Df::LinuxLvm | Df::Xfs | Df::Apfs) => true,
        (Pf::Linux, Df::Ntfs | Df::Fat | Df::Luks | Df::Apfs) => true,
        (Pf::LinuxSwap, Df::Ntfs | Df::Fat | Df::Ext | Df::Apfs) => true,
        (Pf::LinuxLvm, Df::Ntfs | Df::Fat | Df::Ext | Df::Apfs) => true,
        _ => false,
    }
}
