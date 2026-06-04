//! Extended Boot Record (EBR) chain traversal and forensic inspection.
//!
//! An extended partition (type 0x05 / 0x0F / 0x85) contains an EBR chain.
//! Each EBR sector is structured identically to an MBR: 512 bytes with a
//! `0x55AA` boot signature at offset 510.  Only the first two partition
//! entries are used:
//!
//! - Entry 0: logical partition LBA, **relative to this EBR sector**.
//! - Entry 1: next EBR LBA, **relative to the extended partition start**
//!   (`ext_start`).  Zero = end of chain.
//!
//! Entries 2 and 3 are reserved and should be all zero.  Non-zero bytes in
//! those entries constitute slack data that may conceal forensic artefacts.

use std::io::{Read, Seek, SeekFrom};

use crate::diag;
use crate::partition::PartitionEntry;
use crate::Error;

// EBR sector layout (identical to the MBR partition-table region).
/// Size of one EBR/MBR sector, in bytes.
const SECTOR_LEN: usize = 512;
/// Offset of the logical-partition entry (entry 0).
const LOGICAL_ENTRY: usize = 446;
/// Offset of the next-EBR pointer entry (entry 1).
const NEXT_ENTRY: usize = 462;
/// Offset of the reserved slack region (entries 2–3).
const SLACK: usize = 478;
/// Offset of the boot signature (`0x55 0xAA`).
const BOOT_SIG: usize = 510;

/// A single link in the EBR chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EbrEntry {
    /// Absolute byte offset of this EBR sector in the disk image.
    pub ebr_offset: u64,
    /// Absolute LBA of this EBR sector.
    pub ebr_lba: u64,
    /// The logical partition described by this EBR.
    pub logical: PartitionEntry,
    /// Absolute LBA start of the logical partition.
    pub logical_lba_start: u64,
    /// Raw bytes of EBR entries 2 and 3 (bytes 478–509). Non-zero = slack.
    pub slack: [u8; 32],
    /// `true` when `slack` contains at least one non-zero byte.
    pub has_slack: bool,
}

/// Result of walking the full EBR chain.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EbrChain {
    pub entries: Vec<EbrEntry>,
    /// `true` if the chain was terminated by a cycle rather than a zero next pointer.
    pub had_cycle: bool,
    /// `true` if traversal was capped by the depth limit.
    pub depth_exceeded: bool,
}

impl EbrChain {
    /// An empty chain — no extended partition, or the walk could not start.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Maximum EBR chain depth before we stop and flag `depth_exceeded`.
const MAX_DEPTH: usize = 64;

/// Walk the EBR chain starting at the extended partition.
///
/// `ext_start_lba` is the LBA of the extended partition container entry.
/// `sector_size` is the logical sector size (typically 512).
///
/// Returns `Ok(EbrChain { entries: vec![], .. })` if the entry type is not
/// an extended partition.
pub fn walk_ebr_chain<R: Read + Seek>(
    reader: &mut R,
    ext_start_lba: u64,
    sector_size: u64,
) -> Result<EbrChain, Error> {
    let mut entries = Vec::new();
    let mut had_cycle = false;
    let mut depth_exceeded = false;

    // Track visited EBR LBAs to detect cycles.
    let mut visited = std::collections::HashSet::new();

    let mut next_ebr_lba = ext_start_lba;

    loop {
        if entries.len() >= MAX_DEPTH {
            depth_exceeded = true;
            break;
        }
        if !visited.insert(next_ebr_lba) {
            had_cycle = true;
            break;
        }

        // Guard against byte-offset overflow for adversarial sector sizes
        // (callers may pass any `sector_size`; LBAs are bounded but the product
        // is not).
        let Some(ebr_byte_offset) = next_ebr_lba.checked_mul(sector_size) else {
            break; // byte offset overflow — corrupt image
        };
        reader.seek(SeekFrom::Start(ebr_byte_offset))?;
        let mut sector = [0u8; SECTOR_LEN];
        if reader.read_exact(&mut sector).is_err() {
            diag::ebr_truncated(next_ebr_lba);
            break; // truncated disk image — terminate gracefully
        }

        // Validate boot signature.
        if sector[BOOT_SIG] != 0x55 || sector[BOOT_SIG + 1] != 0xAA {
            diag::ebr_no_signature(next_ebr_lba);
            break;
        }

        let logical_raw: &[u8; 16] = sector[LOGICAL_ENTRY..NEXT_ENTRY].try_into().unwrap();
        let next_raw: &[u8; 16] = sector[NEXT_ENTRY..SLACK].try_into().unwrap();
        let slack_bytes: [u8; 32] = sector[SLACK..BOOT_SIG].try_into().unwrap();

        let logical = PartitionEntry::from_bytes(logical_raw);
        let next_entry = PartitionEntry::from_bytes(next_raw);

        // Logical partition LBA is relative to this EBR sector.
        // Use saturating_add: malicious logical.lba_start cannot cause overflow panic.
        let logical_lba_start = next_ebr_lba.saturating_add(logical.lba_start as u64);

        let has_slack = slack_bytes.iter().any(|&b| b != 0);

        entries.push(EbrEntry {
            ebr_offset: ebr_byte_offset,
            ebr_lba: next_ebr_lba,
            logical,
            logical_lba_start,
            slack: slack_bytes,
            has_slack,
        });

        // Next EBR LBA is relative to the extended partition start.
        // checked_add: overflow → corrupt/adversarial chain, terminate safely.
        if next_entry.lba_start == 0 {
            break;
        }
        let Some(next_lba) = ext_start_lba.checked_add(next_entry.lba_start as u64) else {
            break; // arithmetic overflow in EBR chain — corrupt or adversarial
        };
        next_ebr_lba = next_lba;
    }

    Ok(EbrChain {
        entries,
        had_cycle,
        depth_exceeded,
    })
}
