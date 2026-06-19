//! Forensic finding types: anomalies, severity, and the top-level analysis result.
//!
//! # Single source of truth
//!
//! Every anomaly's **severity**, **stable code**, and **human note** are derived
//! from its [`AnomalyKind`] — see [`AnomalyKind::severity`], [`AnomalyKind::code`],
//! and [`AnomalyKind::note`]. Detection sites never spell out a severity or note
//! inline; they construct the kind (which carries all the data the note needs)
//! and call [`Anomaly::new`]. This keeps the severity model in one auditable
//! place and makes each anomaly fully self-describing for debugging and
//! serialization.

use std::fmt;

use crate::entropy::HIGH_ENTROPY_THRESHOLD;
use crate::gap::Gap;
use crate::wipe::FillPattern;
use mbr::boot_code::BootCodeId;
use mbr::ebr::EbrChain;
use mbr::mbr::MbrSector;
use mbr::partition::TypeCode;
use mbr::signature::DetectedFs;

/// LBA below which a pre-partition gap is considered benign (classic
/// track-zero alignment leaves sectors 1–62 reserved before the first
/// partition at LBA 63).
const PRE_PARTITION_BENIGN_LBA: u64 = 63;

/// The canonical 5-level severity scale, shared across every SecurityRonin
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

impl forensicnomicon::report::Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        // The anomaly's byte offset travels with the finding as evidence.
        let mut ev = vec![forensicnomicon::report::Evidence {
            field: "offset".to_string(),
            value: format!("{:#x}", self.offset),
            location: Some(forensicnomicon::report::Location::ByteOffset(self.offset)),
        }];
        // Surface the raw offending value for any kind that carries one, so an
        // "unrecognised X" finding hands the investigator the actual X.
        if let AnomalyKind::UnknownBootCode { boot_code_hex } = &self.kind {
            ev.push(forensicnomicon::report::Evidence {
                field: "boot_code".to_string(),
                value: boot_code_hex.clone(),
                location: Some(forensicnomicon::report::Location::ByteOffset(self.offset)),
            });
        }
        ev
    }
}

/// A single forensic anomaly detected in the MBR or its partition table.
///
/// Construct via [`Anomaly::new`] — the `severity`, `code`, and `note` fields
/// are derived from `kind` so they can never drift out of sync with it.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    /// Severity, derived from [`AnomalyKind::severity`].
    pub severity: Severity,
    /// Stable machine-readable code (e.g. `"MBR-PART-OVERLAP"`), derived from
    /// [`AnomalyKind::code`]. Useful for filtering, documentation, and tooling.
    pub code: &'static str,
    /// The classified anomaly with all data needed to describe it.
    pub kind: AnomalyKind,
    /// Byte offset in the disk image where the anomaly is located (0 = MBR sector).
    pub offset: u64,
    /// Human-readable description, derived from [`AnomalyKind::note`].
    pub note: String,
}

impl Anomaly {
    /// Build an anomaly from its kind and byte offset, deriving severity,
    /// code, and note from the kind.
    #[must_use]
    pub fn new(kind: AnomalyKind, offset: u64) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
            offset,
        }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ {:#x}: {}",
            self.severity, self.code, self.offset, self.note
        )
    }
}

/// Classification of an anomaly, carrying every value its description needs.
///
/// Each variant is self-contained: given only the variant, you can recover its
/// severity, stable code, and human note. This makes anomalies trivially
/// serializable and keeps the detection sites free of presentation logic.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    // ── MBR structure ────────────────────────────────────────────────────────
    /// Bytes 444–445 (Windows disk-signature reserved field) are non-zero.
    NonZeroReserved { bytes: [u8; 2] },
    /// More than one partition entry has the bootable flag (`0x80`).
    MultipleBootable { count: usize },
    /// Active partitions exist but none is marked bootable (informational).
    NoBootablePartition,
    /// A Windows MBR (recognised bootmgr stub) whose NT disk signature at
    /// offset 440 is zero — consistent with a wiped or re-created boot record.
    ZeroDiskSignature,
    /// The boot code contains a documented boot-sector-malware marker.
    KnownBootkit { name: &'static str },

    // ── Partition entries ────────────────────────────────────────────────────
    /// Entry has type code `0x00` but non-zero LBA fields — residual deleted entry.
    ResidualEntry {
        index: usize,
        lba_start: u32,
        lba_count: u32,
    },
    /// Entry status byte is neither 0x00 (inactive) nor 0x80 (bootable) — the
    /// only spec-valid values; other values are a manual-edit / tooling artifact.
    InvalidPartitionStatus { index: usize, status: u8 },
    /// Two non-empty entries describe the identical extent (same start + count)
    /// — a duplicate left by hand-editing or a faulty imaging tool.
    DuplicatePartitionEntry { a: usize, b: usize },
    /// Two partitions have overlapping LBA ranges.
    OverlappingPartitions {
        a: usize,
        b: usize,
        a_end: u64,
        b_start: u64,
    },
    /// Partition's last LBA exceeds the disk's reported size.
    OutOfBounds {
        index: usize,
        last_lba: u64,
        disk_last_lba: u64,
    },
    /// CHS-encoded start/end disagree significantly with the LBA values.
    ChsLbaInconsistency { index: usize },

    // ── GPT / protective MBR ─────────────────────────────────────────────────
    /// A GPT protective entry (0xEE) coexists with real partition entries — a
    /// hybrid MBR. Legacy tools see the real partitions; GPT tools see only the
    /// protective entry. A known data-hiding / dual-visibility vector.
    HybridMbr { extra_partition_count: usize },
    /// The protective entry (0xEE) does not span the whole disk, leaving a tail
    /// region hidden from GPT-aware tooling.
    ProtectiveMbrUndersized {
        covered_last_lba: u64,
        disk_last_lba: u64,
    },
    /// A GPT header ("EFI PART") exists at LBA 1 but no protective 0xEE entry
    /// advertises it — GPT-unaware analysis would miss the real layout.
    HiddenGpt,
    /// A protective entry (0xEE) is present but no GPT header backs it at LBA 1
    /// — a spoofed protective MBR.
    SpoofedProtectiveMbr,

    // ── Extended partition / EBR ─────────────────────────────────────────────
    /// EBR chain contains a cycle (next-pointer loops back).
    EbrCycle,
    /// EBR chain depth exceeded the safety cap.
    EbrExcessiveDepth { depth: usize },
    /// EBR entries 2 or 3 contain non-zero bytes (EBR slack data).
    EbrSlackData { ebr_lba: u64, entropy: f64 },

    // ── Unpartitioned space ──────────────────────────────────────────────────
    /// Sectors exist before the first partition (pre-partition space).
    PrePartitionSpace {
        lba_start: u64,
        lba_end: u64,
        byte_size: u64,
    },
    /// Gap between two partitions.
    InterPartitionGap {
        lba_start: u64,
        lba_end: u64,
        byte_size: u64,
    },
    /// Trailing unpartitioned space after the last partition.
    PostPartitionSpace {
        lba_start: u64,
        lba_end: u64,
        byte_size: u64,
    },
    /// An unpartitioned region carries a deliberate wipe pattern (uniform
    /// non-zero, alternating, etc.) — an anti-forensic / destruction trace.
    WipedRegion {
        lba_start: u64,
        pattern: FillPattern,
    },
    /// A recoverable file header (carved by magic) was found in unpartitioned
    /// space — leftover data from a deleted or hidden file.
    CarvedArtifact { kind: &'static str },

    // ── Semantic / content ───────────────────────────────────────────────────
    /// A FAT/NTFS volume's BPB "hidden sectors" field disagrees with its
    /// partition-table LBA — consistent with a relocated/copied volume or an
    /// edited table (data-hiding / relocation indicator).
    VbrHiddenSectorsMismatch {
        index: usize,
        bpb_hidden: u32,
        lba_start: u64,
    },
    /// Declared partition type differs from detected filesystem magic.
    SignatureMismatch {
        index: usize,
        declared: TypeCode,
        detected: DetectedFs,
    },
    /// Boot code is all zeros on a legacy (BIOS/MBR-boot) disk — likely wiped.
    WipedBootCode,
    /// Boot code is all zeros on a genuine GPT/UEFI disk (pure protective MBR).
    /// The MBR boot code is never executed there, so this is benign — reported
    /// only for completeness, not as a tampering signal.
    EmptyProtectiveBootCode,
    /// Boot code is all `0xFF` — likely factory-erased or deliberately wiped.
    ErasedBootCode,
    /// Boot code did not match any known signature. Carries the leading bytes of
    /// the unrecognised boot code (hex) so the actual value is surfaced for
    /// investigation rather than hidden behind "unknown".
    UnknownBootCode { boot_code_hex: String },
    /// Slack region has Shannon entropy above the threshold (data may be hidden).
    HighEntropySlack { offset: u64, entropy: f64 },
}

impl AnomalyKind {
    /// Severity assigned to this kind. This is the **only** place severities
    /// are decided — auditing the severity model means reading this one method.
    #[must_use]
    pub fn severity(&self) -> Severity {
        use AnomalyKind as K;
        match self {
            // Critical — definitive structural compromise.
            K::OverlappingPartitions { .. } | K::EbrCycle | K::KnownBootkit { .. } => {
                Severity::Critical
            }

            // High — strong tampering / data-hiding / anti-forensic signal.
            K::OutOfBounds { .. }
            | K::EbrExcessiveDepth { .. }
            | K::WipedBootCode
            | K::ErasedBootCode
            | K::HybridMbr { .. }
            | K::ProtectiveMbrUndersized { .. }
            | K::HiddenGpt
            | K::SpoofedProtectiveMbr
            | K::WipedRegion { .. }
            | K::VbrHiddenSectorsMismatch { .. }
            | K::HighEntropySlack { .. } => Severity::High,

            // EBR slack severity scales with its entropy.
            K::EbrSlackData { entropy, .. } => {
                if *entropy > HIGH_ENTROPY_THRESHOLD {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }

            // Pre-partition gap is benign when within the classic reserved track.
            K::PrePartitionSpace { lba_start, .. } => {
                if *lba_start < PRE_PARTITION_BENIGN_LBA {
                    Severity::Low
                } else {
                    Severity::Medium
                }
            }

            // Medium — unusual but not definitive.
            K::NonZeroReserved { .. }
            | K::MultipleBootable { .. }
            | K::ResidualEntry { .. }
            | K::ChsLbaInconsistency { .. }
            | K::InvalidPartitionStatus { .. }
            | K::DuplicatePartitionEntry { .. }
            | K::ZeroDiskSignature
            | K::InterPartitionGap { .. }
            | K::SignatureMismatch { .. } => Severity::Medium,

            // Low — minor deviation / notable leftover data.
            K::UnknownBootCode { .. } | K::CarvedArtifact { .. } => Severity::Low,

            // Info — noted, not suspicious.
            K::NoBootablePartition | K::PostPartitionSpace { .. } | K::EmptyProtectiveBootCode => {
                Severity::Info
            }
        }
    }

    /// Stable machine-readable code for this kind. Codes never change once
    /// shipped, so downstream filters and documentation can rely on them.
    #[must_use]
    pub fn code(&self) -> &'static str {
        use AnomalyKind as K;
        match self {
            K::NonZeroReserved { .. } => "MBR-RESERVED-NONZERO",
            K::MultipleBootable { .. } => "MBR-BOOT-MULTI",
            K::NoBootablePartition => "MBR-BOOT-NONE",
            K::ZeroDiskSignature => "MBR-DISKSIG-ZERO",
            K::KnownBootkit { .. } => "MBR-BOOT-MALWARE",
            K::ResidualEntry { .. } => "MBR-PART-RESIDUAL",
            K::InvalidPartitionStatus { .. } => "MBR-PART-STATUS",
            K::DuplicatePartitionEntry { .. } => "MBR-PART-DUPLICATE",
            K::OverlappingPartitions { .. } => "MBR-PART-OVERLAP",
            K::OutOfBounds { .. } => "MBR-PART-OOB",
            K::ChsLbaInconsistency { .. } => "MBR-PART-CHSLBA",
            K::HybridMbr { .. } => "MBR-GPT-HYBRID",
            K::ProtectiveMbrUndersized { .. } => "MBR-GPT-UNDERSIZED",
            K::HiddenGpt => "MBR-GPT-HIDDEN",
            K::SpoofedProtectiveMbr => "MBR-GPT-SPOOFED",
            K::EbrCycle => "MBR-EBR-CYCLE",
            K::EbrExcessiveDepth { .. } => "MBR-EBR-DEPTH",
            K::EbrSlackData { .. } => "MBR-EBR-SLACK",
            K::PrePartitionSpace { .. } => "MBR-GAP-PRE",
            K::InterPartitionGap { .. } => "MBR-GAP-MID",
            K::PostPartitionSpace { .. } => "MBR-GAP-POST",
            K::WipedRegion { .. } => "MBR-GAP-WIPED",
            K::CarvedArtifact { .. } => "MBR-CARVE-ARTIFACT",
            K::SignatureMismatch { .. } => "MBR-PART-SIGMISMATCH",
            K::VbrHiddenSectorsMismatch { .. } => "MBR-VBR-HIDDEN",
            K::WipedBootCode => "MBR-BOOT-WIPED",
            K::EmptyProtectiveBootCode => "MBR-BOOT-PROTECTIVE-EMPTY",
            K::ErasedBootCode => "MBR-BOOT-ERASED",
            K::UnknownBootCode { .. } => "MBR-BOOT-UNKNOWN",
            K::HighEntropySlack { .. } => "MBR-SLACK-ENTROPY",
        }
    }

    /// Human-readable description of this anomaly, formatted from its own data.
    #[must_use]
    pub fn note(&self) -> String {
        use AnomalyKind as K;
        match self {
            K::NonZeroReserved { bytes } => format!(
                "Reserved bytes at offset 444 are non-zero: [{:#04X}, {:#04X}]",
                bytes[0], bytes[1]
            ),
            K::MultipleBootable { count } => {
                format!("{count} partition entries have the bootable flag set")
            }
            K::NoBootablePartition => "No partition is marked bootable".to_string(),
            K::ZeroDiskSignature => {
                "Windows MBR boot code present but NT disk signature (offset 440) is zero — \
                 consistent with a wiped or re-created boot record"
                    .to_string()
            }
            K::InvalidPartitionStatus { index, status } => format!(
                "Entry {index}: invalid status byte {status:#04X} (expected 0x00 or 0x80)"
            ),
            K::DuplicatePartitionEntry { a, b } => {
                format!("Entries {a} and {b} describe the identical extent — duplicate entry")
            }
            K::ResidualEntry {
                index,
                lba_start,
                lba_count,
            } => format!(
                "Entry {index}: type=0x00 but lba_start={lba_start} lba_count={lba_count} — possible deleted partition"
            ),
            K::OverlappingPartitions {
                a,
                b,
                a_end,
                b_start,
            } => format!(
                "Partitions {a} and {b} overlap (entry {a} ends at LBA {a_end}, entry {b} starts at {b_start})"
            ),
            K::OutOfBounds {
                index,
                last_lba,
                disk_last_lba,
            } => format!("Entry {index}: last LBA {last_lba} exceeds disk last LBA {disk_last_lba}"),
            K::ChsLbaInconsistency { index } => {
                format!("Entry {index}: CHS address inconsistent with LBA value")
            }
            K::HybridMbr {
                extra_partition_count,
            } => format!(
                "Hybrid MBR: GPT protective entry (0xEE) coexists with {extra_partition_count} \
                 real partition entr{} — legacy-visible, GPT-invisible data-hiding vector",
                if *extra_partition_count == 1 { "y" } else { "ies" }
            ),
            K::ProtectiveMbrUndersized {
                covered_last_lba,
                disk_last_lba,
            } => format!(
                "Protective MBR (0xEE) covers only up to LBA {covered_last_lba} but the disk \
                 ends at LBA {disk_last_lba} — tail region hidden from GPT-aware tools"
            ),
            K::HiddenGpt => {
                "GPT header (\"EFI PART\") present at LBA 1 but no protective 0xEE entry \
                 advertises it — hidden GPT layout"
                    .to_string()
            }
            K::SpoofedProtectiveMbr => {
                "Protective entry (0xEE) present but no GPT header at LBA 1 — spoofed protective MBR"
                    .to_string()
            }
            K::EbrCycle => "EBR chain contains a cycle".to_string(),
            K::EbrExcessiveDepth { depth } => {
                format!("EBR chain depth exceeded {depth} — possibly corrupt or adversarial")
            }
            K::EbrSlackData { ebr_lba, entropy } => {
                format!("EBR at LBA {ebr_lba} has non-zero slack (entropy {entropy:.2})")
            }
            K::PrePartitionSpace {
                lba_start,
                lba_end,
                byte_size,
            } => gap_note("Pre-partition space", *lba_start, *lba_end, *byte_size),
            K::InterPartitionGap {
                lba_start,
                lba_end,
                byte_size,
            } => gap_note("Gap between partitions", *lba_start, *lba_end, *byte_size),
            K::PostPartitionSpace {
                lba_start,
                lba_end,
                byte_size,
            } => gap_note("Post-partition space", *lba_start, *lba_end, *byte_size),
            K::WipedRegion { lba_start, pattern } => format!(
                "Unpartitioned region at LBA {lba_start} shows a deliberate wipe pattern: {}",
                pattern.label()
            ),
            K::CarvedArtifact { kind } => {
                format!("Recoverable {kind} file header found in unpartitioned space")
            }
            K::SignatureMismatch {
                index,
                declared,
                detected,
            } => format!(
                "Entry {index}: declared type {:?} ({}) but detected {detected:?} from first sector",
                declared.family(),
                declared.name(),
            ),
            K::VbrHiddenSectorsMismatch {
                index,
                bpb_hidden,
                lba_start,
            } => format!(
                "Entry {index}: VBR hidden-sectors field ({bpb_hidden}) disagrees with \
                 partition-table LBA ({lba_start}) — volume relocated/copied or table edited"
            ),
            K::KnownBootkit { name } => {
                format!("Boot code contains a documented {name} boot-sector-malware marker")
            }
            K::WipedBootCode => "Boot code is all zeros — likely wiped or overwritten".to_string(),
            K::EmptyProtectiveBootCode => {
                "MBR boot code is empty (all zeros), which is expected on a GPT/UEFI disk — \
                 the protective MBR's boot code is never executed"
                    .to_string()
            }
            K::ErasedBootCode => {
                "Boot code is all 0xFF — factory-erased or deliberate wipe".to_string()
            }
            K::UnknownBootCode { boot_code_hex } => {
                format!("Boot code signature not recognised; boot code begins {boot_code_hex}")
            }
            K::HighEntropySlack { offset, entropy } => {
                format!("High-entropy slack at offset {offset} (entropy {entropy:.2})")
            }
        }
    }
}

/// Shared formatter for the three unpartitioned-gap notes.
fn gap_note(label: &str, lba_start: u64, lba_end: u64, byte_size: u64) -> String {
    let sectors = lba_end.saturating_sub(lba_start).saturating_add(1);
    format!("{label}: LBA {lba_start}–{lba_end} ({sectors} sectors, {byte_size} bytes)")
}

/// Per-partition summary enriched with forensic metadata.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PartitionSummary {
    /// Index in the primary table (0–3) or EBR chain (4+).
    pub index: usize,
    /// Absolute LBA of the partition's first sector.
    pub lba_start: u64,
    /// Absolute LBA of the partition's last sector.
    pub lba_end: u64,
    /// Byte offset from the disk start.
    pub byte_offset: u64,
    /// Byte size of the partition.
    pub byte_size: u64,
    /// Declared type from the partition table.
    pub declared_type: TypeCode,
    /// Filesystem type detected from the partition's first sector (if readable).
    pub detected_fs: Option<DetectedFs>,
}

/// Top-level result of a full MBR forensic analysis.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MbrAnalysis {
    /// Parsed MBR sector.
    pub mbr: MbrSector,
    /// All partitions (primary and logical from EBR chain).
    pub partitions: Vec<PartitionSummary>,
    /// Extended partition EBR chain (empty when no extended partition exists).
    pub ebr_chain: EbrChain,
    /// Unpartitioned disk regions.
    pub gaps: Vec<Gap>,
    /// Identified boot code.
    pub boot_code_id: BootCodeId,
    /// NT disk serial (offset 440, LE u32).
    pub disk_serial: u32,
    /// Inferred partitioner / era from layout geometry and boot code.
    pub era: crate::provenance::PartitioningEra,
    /// When the disk turns out to be GPT (an `EFI PART` header at LBA 1), the
    /// real GUID Partition Table parsed automatically via `gpt-forensic`.
    /// `None` for legacy-MBR disks. Requires the default `gpt` feature.
    #[cfg(feature = "gpt")]
    pub gpt: Option<gpt_partition_forensic::GptAnalysis>,
    /// All detected anomalies, in discovery order.
    pub anomalies: Vec<Anomaly>,
}

impl MbrAnalysis {
    /// The highest severity among all detected anomalies, or `None` when clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }

    /// Iterate anomalies at or above `min` severity.
    pub fn anomalies_at_least(&self, min: Severity) -> impl Iterator<Item = &Anomaly> {
        self.anomalies.iter().filter(move |a| a.severity >= min)
    }
}
