//! # mbr-core
//!
//! Pure-Rust, read-only Master Boot Record (MBR) parser. Decodes the on-disk
//! structures — the 512-byte boot sector, the four primary partition entries,
//! Extended Boot Record (EBR) chains, CHS/LBA geometry, GPT and VBR
//! cross-validation primitives, boot-code identity, and filesystem
//! fingerprints — with no I/O beyond a caller-supplied [`Read`] + [`Seek`].
//!
//! This crate is the structure-decode layer. It deliberately contains **no**
//! anomaly findings: the forensic analyzer that turns these structures into
//! graded observations lives in the sibling `mbr-forensic` crate, which
//! re-exports every type here.
//!
//! [`Read`]: std::io::Read
//! [`Seek`]: std::io::Seek
//!
//! ```no_run
//! use mbr::parse_mbr_sector;
//!
//! // Pure parsing from a 512-byte buffer (no I/O required):
//! let buf = [0u8; 512];
//! let sector = parse_mbr_sector(&buf)?;
//! # Ok::<(), mbr::Error>(())
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod boot_code;
pub mod carve;
pub mod diag;
pub mod disk_signature;
pub mod ebr;
pub mod gpt;
pub mod mbr;
pub mod partition;
pub mod signature;
pub mod vbr;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use boot_code::{identify as identify_boot_code, BootCodeId};
pub use disk_signature::{find_signature_collisions, SignatureCollision};
pub use ebr::{walk_ebr_chain, EbrChain, EbrEntry};
pub use mbr::{parse_mbr_sector, MbrSector, SECTOR_SIZE};
pub use partition::{Chs, ChsConsistency, PartitionEntry, PartitionFamily, TypeCode};
pub use signature::{detect as detect_fs, DetectedFs};

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
