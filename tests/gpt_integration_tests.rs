//! Automatic GPT delegation: when an MBR turns out to be GPT, the real GUID
//! Partition Table is parsed via the sibling `gpt-forensic` crate and attached
//! to the analysis.
#![cfg(feature = "gpt")]

use mbr_forensic::analyse;
use std::io::Cursor;

const SECTORS: u64 = 256;

fn write_protective_mbr(d: &mut [u8]) {
    d[450] = 0xEE; // entry 0 type (offset 446 + 4)
    d[454..458].copy_from_slice(&1u32.to_le_bytes()); // lba_start = 1
    d[458..462].copy_from_slice(&((SECTORS - 1) as u32).to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
}

/// Minimal GPT disk: protective MBR + a parseable GPT header at LBA 1.
fn gpt_disk() -> Vec<u8> {
    let mut d = vec![0u8; (SECTORS * 512) as usize];
    write_protective_mbr(&mut d);
    let h = 512; // LBA 1
    d[h..h + 8].copy_from_slice(b"EFI PART");
    d[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    d[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
    d[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
    d[h + 32..h + 40].copy_from_slice(&(SECTORS - 1).to_le_bytes()); // alternate_lba
    d[h + 40..h + 48].copy_from_slice(&34u64.to_le_bytes()); // first_usable
    d[h + 48..h + 56].copy_from_slice(&222u64.to_le_bytes()); // last_usable
    d[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entry_lba
    d[h + 80..h + 84].copy_from_slice(&0u32.to_le_bytes()); // num_entries = 0
    d[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry_size
    d
}

#[test]
fn gpt_disk_is_auto_parsed() {
    let a = analyse(&mut Cursor::new(gpt_disk()), SECTORS * 512).unwrap();
    let gpt = a
        .gpt
        .as_ref()
        .expect("a GPT disk must have its GPT auto-parsed");
    assert_eq!(gpt.primary.my_lba, 1);
}

#[test]
fn plain_mbr_disk_has_no_gpt() {
    let mut d = vec![0u8; (SECTORS * 512) as usize];
    d[450] = 0x83;
    d[454..458].copy_from_slice(&2048u32.to_le_bytes());
    d[458..462].copy_from_slice(&100u32.to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
    let a = analyse(&mut Cursor::new(d), SECTORS * 512).unwrap();
    assert!(a.gpt.is_none(), "a non-GPT disk must not produce a GPT analysis");
}
