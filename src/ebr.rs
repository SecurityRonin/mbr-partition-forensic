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

use crate::partition::PartitionEntry;
use crate::Error;

/// A single link in the EBR chain.
#[derive(Debug, Clone)]
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
    /// `true` when [`slack`] contains at least one non-zero byte.
    pub has_slack: bool,
}

/// Result of walking the full EBR chain.
#[derive(Debug, Clone)]
pub struct EbrChain {
    pub entries: Vec<EbrEntry>,
    /// `true` if the chain was terminated by a cycle rather than a zero next pointer.
    pub had_cycle: bool,
    /// `true` if traversal was capped by the depth limit.
    pub depth_exceeded: bool,
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

        let ebr_byte_offset = next_ebr_lba * sector_size;
        reader.seek(SeekFrom::Start(ebr_byte_offset))?;
        let mut sector = [0u8; 512];
        reader.read_exact(&mut sector)?;

        // Validate boot signature.
        if sector[510] != 0x55 || sector[511] != 0xAA {
            break;
        }

        let logical_raw: &[u8; 16] = sector[446..462].try_into().unwrap();
        let next_raw: &[u8; 16] = sector[462..478].try_into().unwrap();
        let slack_bytes: [u8; 32] = sector[478..510].try_into().unwrap();

        let logical = PartitionEntry::from_bytes(logical_raw);
        let next_entry = PartitionEntry::from_bytes(next_raw);

        // Logical partition LBA is relative to this EBR sector.
        let logical_lba_start = next_ebr_lba + logical.lba_start as u64;

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
        if next_entry.lba_start == 0 {
            break;
        }
        next_ebr_lba = ext_start_lba + next_entry.lba_start as u64;
    }

    Ok(EbrChain {
        entries,
        had_cycle,
        depth_exceeded,
    })
}
