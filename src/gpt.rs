//! GPT/MBR cross-validation primitives.
//!
//! A GUID Partition Table disk protects itself from legacy tooling with a
//! *protective MBR*: a single partition entry of type `0xEE` at LBA 1 that
//! spans the whole disk, paired with an "EFI PART" header at LBA 1. This module
//! provides the low-level predicates the analysis pipeline uses to detect
//! deviations from that contract — hybrid MBRs, undersized protective entries,
//! hidden GPTs, and spoofed protective MBRs.

/// Partition type code of a GPT protective / hybrid MBR entry.
pub const PROTECTIVE_TYPE_CODE: u8 = 0xEE;

/// 8-byte signature at the start of a GPT header (LBA 1).
pub const GPT_HEADER_MAGIC: &[u8; 8] = b"EFI PART";

/// `true` when `lba1` begins with the GPT header magic "EFI PART".
///
/// Accepts any slice; returns `false` for slices shorter than the 8-byte magic.
#[must_use]
pub fn has_gpt_header(lba1: &[u8]) -> bool {
    lba1.len() >= GPT_HEADER_MAGIC.len() && &lba1[..GPT_HEADER_MAGIC.len()] == GPT_HEADER_MAGIC
}
