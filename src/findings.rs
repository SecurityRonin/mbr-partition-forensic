//! Forensic finding types: anomalies, severity, and the top-level analysis result.

use crate::boot_code::BootCodeId;
use crate::ebr::EbrChain;
use crate::gap::Gap;
use crate::mbr::MbrSector;
use crate::partition::TypeCode;
use crate::signature::DetectedFs;

/// Severity level of a forensic anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational — worth noting but not inherently suspicious.
    Info,
    /// Low — minor deviation; may be benign.
    Low,
    /// Medium — warrants investigation; unusual in legitimate images.
    Medium,
    /// High — strong indicator of tampering, anti-forensics, or data hiding.
    High,
    /// Critical — definitive indicator of structural compromise.
    Critical,
}

/// A single forensic anomaly detected in the MBR or its partition table.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub severity: Severity,
    pub kind: AnomalyKind,
    /// Byte offset in the disk image where the anomaly is located (0 = MBR sector).
    pub offset: u64,
    /// Human-readable description.
    pub note: String,
}

/// Classification of the anomaly type.
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyKind {
    // ── MBR structure ────────────────────────────────────────────────────────
    /// Bytes 444–445 are non-zero (Windows disk signature reserved field).
    NonZeroReserved,
    /// More than one partition entry has the bootable flag (0x80).
    MultipleBootable,
    /// No partition entry is marked bootable (informational).
    NoBootablePartition,

    // ── Partition entries ────────────────────────────────────────────────────
    /// Entry has type code 0x00 but non-zero LBA fields — residual deleted entry.
    ResidualEntry { index: usize },
    /// Two partitions have overlapping LBA ranges.
    OverlappingPartitions { a: usize, b: usize },
    /// Partition's last LBA exceeds the disk's reported size.
    OutOfBounds { index: usize },
    /// CHS-encoded start/end disagree significantly with the LBA values.
    ChsLbaInconsistency { index: usize },

    // ── Extended partition / EBR ─────────────────────────────────────────────
    /// EBR chain contains a cycle (next-pointer loops back).
    EbrCycle,
    /// EBR chain depth exceeded the safety cap.
    EbrExcessiveDepth { depth: usize },
    /// EBR entries 2 or 3 contain non-zero bytes (EBR slack data).
    EbrSlackData { ebr_lba: u64 },

    // ── Unpartitioned space ──────────────────────────────────────────────────
    /// Sectors exist before the first partition (pre-partition space).
    PrePartitionSpace { sector_count: u64 },
    /// Gap between two partitions.
    InterPartitionGap { lba_start: u64, lba_end: u64 },
    /// Trailing unpartitioned space after the last partition.
    PostPartitionSpace { lba_start: u64, sector_count: u64 },

    // ── Semantic / content ───────────────────────────────────────────────────
    /// Declared partition type differs from detected filesystem magic.
    SignatureMismatch {
        index: usize,
        declared: TypeCode,
        detected: DetectedFs,
    },
    /// Boot code is all zeros — likely wiped.
    WipedBootCode,
    /// Boot code is all `0xFF` — likely factory-erased or deliberately wiped.
    ErasedBootCode,
    /// Boot code did not match any known signature.
    UnknownBootCode,
    /// Slack region has Shannon entropy above the threshold (data may be hidden).
    HighEntropySlack { offset: u64, entropy: f64 },
}

/// Per-partition summary enriched with forensic metadata.
#[derive(Debug, Clone)]
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
    /// All detected anomalies, in discovery order.
    pub anomalies: Vec<Anomaly>,
}
