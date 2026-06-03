//! # mbr-forensic
//!
//! Forensic-grade Master Boot Record (MBR) parser. Goes beyond partition
//! enumeration to surface structural anomalies, slack-space content,
//! anti-forensic indicators, and cross-field inconsistencies that other
//! MBR crates silently ignore.
//!
//! ## Entry points
//!
//! ```no_run
//! use mbr_forensic::{parse_mbr_sector, analyse};
//! use std::fs::File;
//!
//! // Pure parsing from a 512-byte buffer (no I/O required):
//! let buf = [0u8; 512];
//! let sector = parse_mbr_sector(&buf)?;
//!
//! // Full forensic analysis from a seekable reader:
//! let mut f = File::open("disk.img")?;
//! let analysis = analyse(&mut f, 1 << 30)?;
//! for anomaly in &analysis.anomalies {
//!     println!("[{:?}] {}", anomaly.severity, anomaly.note);
//! }
//! # Ok::<(), mbr_forensic::Error>(())
//! ```

pub mod boot_code;
pub mod disk_signature;
pub mod ebr;
pub mod entropy;
pub mod findings;
pub mod gap;
pub mod gpt;
pub mod mbr;
pub mod partition;
pub mod signature;

mod analyse;
mod diag;

pub use analyse::analyse;
pub use boot_code::BootCodeId;
pub use disk_signature::{find_signature_collisions, SignatureCollision};
pub use ebr::{EbrChain, EbrEntry};
pub use findings::{Anomaly, AnomalyKind, MbrAnalysis, PartitionSummary, Severity};
pub use gap::Gap;
pub use mbr::{parse_mbr_sector, MbrSector};
pub use partition::{Chs, PartitionEntry, PartitionFamily, TypeCode};
pub use signature::DetectedFs;

/// Crate-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sector too short: expected 512 bytes, got {0}")]
    TooShort(usize),
    #[error("invalid MBR boot signature: expected 0x55AA, got 0x{0:04X}")]
    BadSignature(u16),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
