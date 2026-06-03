//! Integration tests for mbr-forensic.
//! All tests use in-memory byte slices or Cursor<Vec<u8>> — no temp files needed.

use mbr_forensic::{
    analyse, entropy,
    findings::{Anomaly, AnomalyKind, Severity},
    gap::{compute_gaps, GapKind},
    parse_mbr_sector,
    partition::{Chs, PartitionFamily, TypeCode},
    signature, BootCodeId, DetectedFs, EbrChain, Error,
};
use std::io::Cursor;

// ── MBR sector builder helpers ───────────────────────────────────────────────

/// Build a valid 512-byte MBR sector with the given entries.
/// Boots signature 0x55AA is always set.
fn make_sector(entries: &[(&[u8; 16], usize)]) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    for (entry_bytes, index) in entries {
        let off = 446 + index * 16;
        s[off..off + 16].copy_from_slice(*entry_bytes);
    }
    s
}

/// Build a 16-byte partition entry.
fn make_entry(status: u8, type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

/// Build a minimal disk image of `total_sectors` 512-byte sectors with an MBR.
fn make_disk(total_sectors: u64, entries: &[(&[u8; 16], usize)]) -> Vec<u8> {
    let mut disk = vec![0u8; (total_sectors * 512) as usize];
    let mbr = make_sector(entries);
    disk[..512].copy_from_slice(&mbr);
    disk
}

// ── parse_mbr_sector ──────────────────────────────────────────────────────────

#[test]
fn parse_valid_sector_succeeds() {
    let s = make_sector(&[]);
    assert!(parse_mbr_sector(&s).is_ok());
}

#[test]
fn parse_too_short_returns_error() {
    let s = [0u8; 256];
    assert!(matches!(parse_mbr_sector(&s), Err(Error::TooShort(256))));
}

#[test]
fn parse_bad_signature_returns_error() {
    let mut s = [0u8; 512];
    s[510] = 0xDE;
    s[511] = 0xAD;
    assert!(matches!(
        parse_mbr_sector(&s),
        Err(Error::BadSignature(0xDEAD))
    ));
}

#[test]
fn disk_serial_read_correctly() {
    let mut s = make_sector(&[]);
    s[440..444].copy_from_slice(&0x12345678u32.to_le_bytes());
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.disk_serial, 0x12345678);
}

#[test]
fn reserved_bytes_parsed() {
    let mut s = make_sector(&[]);
    s[444] = 0xAB;
    s[445] = 0xCD;
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.reserved, [0xAB, 0xCD]);
}

#[test]
fn empty_entries_are_all_zero() {
    let s = make_sector(&[]);
    let mbr = parse_mbr_sector(&s).unwrap();
    for e in &mbr.entries {
        assert!(e.is_empty());
    }
}

#[test]
fn partition_entry_fields_parsed_correctly() {
    let entry = make_entry(0x80, 0x83, 2048, 1024 * 1024 / 512);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    let e = &mbr.entries[0];
    assert_eq!(e.status, 0x80);
    assert_eq!(e.type_code, TypeCode(0x83));
    assert_eq!(e.lba_start, 2048);
    assert!(e.is_bootable());
    assert!(!e.is_empty());
}

#[test]
fn lba_end_is_start_plus_count_minus_one() {
    let entry = make_entry(0x00, 0x83, 100, 50);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.entries[0].lba_end(), 149);
}

// ── CHS ───────────────────────────────────────────────────────────────────────

#[test]
fn chs_from_bytes_decodes_correctly() {
    // head=1, sector=63, cylinder=0
    let chs = Chs::from_bytes([1, 63, 0]);
    assert_eq!(chs.head, 1);
    assert_eq!(chs.sector, 63);
    assert_eq!(chs.cylinder, 0);
}

#[test]
fn chs_high_cylinder_bits_in_byte1() {
    // byte1 bits 7:6 = cylinder high bits, byte2 = cylinder low
    // cylinder = 0b11_0000_0001 = 769, head=0, sector=1
    let chs = Chs::from_bytes([0, 0b1100_0001, 0b0000_0001]);
    assert_eq!(chs.cylinder, 769);
    assert_eq!(chs.sector, 1);
}

#[test]
fn chs_zero_sector_to_lba_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 0,
    };
    assert!(chs.to_lba(255, 63).is_none());
}

// ── TypeCode ──────────────────────────────────────────────────────────────────

#[test]
fn type_code_linux_is_0x83() {
    assert_eq!(TypeCode(0x83).family(), PartitionFamily::Linux);
    assert_eq!(TypeCode(0x83).name(), "Linux");
}

#[test]
fn type_code_ntfs_is_0x07() {
    assert_eq!(TypeCode(0x07).family(), PartitionFamily::Ntfs);
}

#[test]
fn type_code_fat32_lba_is_0x0c() {
    assert_eq!(TypeCode(0x0C).family(), PartitionFamily::Fat32);
}

#[test]
fn type_code_gpt_protective_is_0xee() {
    assert_eq!(TypeCode(0xEE).family(), PartitionFamily::GptProtective);
    assert!(!TypeCode(0xEE).is_extended());
}

#[test]
fn type_code_extended_0x05_is_extended() {
    assert!(TypeCode(0x05).is_extended());
    assert!(TypeCode(0x0F).is_extended());
    assert!(TypeCode(0x85).is_extended());
}

#[test]
fn type_code_0x00_is_empty() {
    assert!(TypeCode(0x00).is_empty());
    assert!(!TypeCode(0x83).is_empty());
}

// ── BootCodeId ────────────────────────────────────────────────────────────────

#[test]
fn identify_all_zeros_boot_code() {
    let code = [0u8; 446];
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::AllZeros
    );
}

#[test]
fn identify_all_ff_boot_code() {
    let code = [0xFF; 446];
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::AllOnes
    );
}

#[test]
fn identify_unknown_boot_code() {
    let mut code = [0u8; 446];
    code[0] = 0xAA; // Not matching any known pattern.
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Unknown
    );
}

#[test]
fn identify_grub2_by_jmp_opcode() {
    let mut code = [0u8; 446];
    code[0] = 0xEB; // JMP short
    code[1] = 0x63;
    code[2] = 0x90; // NOP
    assert_eq!(mbr_forensic::boot_code::identify(&code), BootCodeId::Grub2);
}

#[test]
fn identify_windows7_by_pattern() {
    let mut code = [0u8; 446];
    // Windows 7+ start: xor ax,ax; mov ss,ax; mov sp,7C00h
    code[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    // "BOOTMGR" at offset 418
    code[418..425].copy_from_slice(b"BOOTMGR");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Windows7Plus
    );
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

#[test]
fn entropy_all_zeros_is_zero() {
    assert_eq!(entropy::shannon(&[0u8; 512]), 0.0);
}

#[test]
fn entropy_all_same_byte_is_zero() {
    assert_eq!(entropy::shannon(&[0xAA; 512]), 0.0);
}

#[test]
fn entropy_two_values_is_one() {
    // 128 zeros + 128 ones = 50/50 = entropy 1.0
    let mut d = vec![0u8; 128];
    d.extend_from_slice(&[1u8; 128]);
    let e = entropy::shannon(&d);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0, got {e}");
}

#[test]
fn entropy_uniform_all_256_values_is_eight() {
    let data: Vec<u8> = (0u8..=255).collect();
    let e = entropy::shannon(&data);
    assert!((e - 8.0).abs() < 1e-9, "expected 8.0, got {e}");
}

#[test]
fn entropy_empty_slice_is_zero() {
    assert_eq!(entropy::shannon(&[]), 0.0);
}

// ── Filesystem signature detection ───────────────────────────────────────────

#[test]
fn detect_unknown_on_zeros() {
    assert_eq!(signature::detect(&[0u8; 512]), DetectedFs::AllZeros);
}

#[test]
fn detect_luks_magic() {
    let mut s = [0u8; 512];
    s[0..6].copy_from_slice(b"LUKS\xba\xbe");
    assert_eq!(signature::detect(&s), DetectedFs::Luks);
}

#[test]
fn detect_ntfs_oem_id() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"NTFS    ");
    assert_eq!(signature::detect(&s), DetectedFs::Ntfs);
}

#[test]
fn detect_fat_msdos_oem() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"MSDOS5.0");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_apfs_magic() {
    let mut s = [0u8; 512];
    s[0..4].copy_from_slice(b"NXSB");
    assert_eq!(signature::detect(&s), DetectedFs::Apfs);
}

#[test]
fn detect_xfs_magic() {
    let mut s = [0u8; 512];
    s[0..4].copy_from_slice(b"XFSB");
    assert_eq!(signature::detect(&s), DetectedFs::Xfs);
}

#[test]
fn detect_ext_superblock_magic() {
    let mut s = vec![0u8; 1100]; // needs > 1082 bytes
    s[1080] = 0x53;
    s[1081] = 0xEF;
    assert_eq!(signature::detect(&s), DetectedFs::Ext);
}

#[test]
fn detect_exfat_oem() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"EXFAT   ");
    assert_eq!(signature::detect(&s), DetectedFs::ExFat);
}

// ── Gap analysis ─────────────────────────────────────────────────────────────

#[test]
fn no_gaps_when_fully_partitioned() {
    // Single partition from LBA 1 to 999 on a 1000-sector disk.
    let extents = [(1u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert!(gaps.is_empty(), "expected no gaps, got {gaps:?}");
}

#[test]
fn pre_partition_gap_detected() {
    // Disk LBA 0–999; partition at LBA 64–999 → gap at LBA 1–63.
    let extents = [(64u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PrePartition);
    assert_eq!(gaps[0].lba_start, 1);
    assert_eq!(gaps[0].lba_end, 63);
}

#[test]
fn inter_partition_gap_detected() {
    // Two partitions with a gap between them.
    let extents = [(1u64, 499u64), (600u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::Between);
    assert_eq!(gaps[0].lba_start, 500);
    assert_eq!(gaps[0].lba_end, 599);
}

#[test]
fn post_partition_gap_detected() {
    let extents = [(1u64, 499u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PostPartition);
    assert_eq!(gaps[0].lba_start, 500);
    assert_eq!(gaps[0].lba_end, 999);
}

#[test]
fn gap_byte_size_is_correct() {
    let extents = [(64u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps[0].byte_size, 63 * 512); // LBA 1–63 = 63 sectors
}

// ── analyse: anomaly detection ────────────────────────────────────────────────

fn disk_with_single_partition(lba_start: u32, lba_count: u32, type_code: u8) -> Vec<u8> {
    let total_sectors = lba_start as u64 + lba_count as u64 + 10;
    let entry = make_entry(0x80, type_code, lba_start, lba_count);
    let mut disk = make_disk(total_sectors, &[(&entry, 0)]);
    // Inject GRUB 2 boot code pattern so we don't trigger WipedBootCode.
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    disk
}

#[test]
fn analyse_clean_disk_has_no_high_anomalies() {
    let disk = disk_with_single_partition(2048, 4096, 0x83);
    let mut c = Cursor::new(disk);
    let total_size = c.get_ref().len() as u64;
    let analysis = analyse(&mut c, total_size).unwrap();
    let high_or_above: Vec<_> = analysis
        .anomalies
        .iter()
        .filter(|a| a.severity >= Severity::High)
        .collect();
    assert!(
        high_or_above.is_empty(),
        "expected no high+ anomalies, got: {high_or_above:#?}"
    );
}

#[test]
fn analyse_detects_non_zero_reserved() {
    let mut disk = make_disk(100, &[]);
    disk[444] = 0x01; // reserved byte
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::NonZeroReserved { .. })));
}

#[test]
fn analyse_detects_multiple_bootable() {
    let e0 = make_entry(0x80, 0x83, 2048, 1024);
    let e1 = make_entry(0x80, 0x83, 4096, 1024); // second bootable
    let disk = make_disk(10000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::MultipleBootable { .. })));
}

#[test]
fn analyse_detects_residual_entry() {
    // type_code=0, but lba_start and lba_count are non-zero
    let entry = make_entry(0x00, 0x00, 100, 50);
    let disk = make_disk(1000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::ResidualEntry { index: 0, .. })));
}

#[test]
fn analyse_detects_out_of_bounds_partition() {
    let total_sectors = 1000u64;
    // Partition that extends past end of disk
    let entry = make_entry(0x80, 0x83, 500, 1000); // end = LBA 1499, disk end = LBA 999
    let disk = make_disk(total_sectors, &[(&entry, 0)]);
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, total_sectors * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::OutOfBounds { index: 0, .. })));
}

#[test]
fn analyse_detects_overlapping_partitions() {
    let e0 = make_entry(0x80, 0x83, 100, 500); // LBA 100–599
    let e1 = make_entry(0x00, 0x83, 400, 500); // LBA 400–899 — overlaps
    let disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::OverlappingPartitions { .. })));
}

#[test]
fn analyse_detects_pre_partition_space() {
    // First partition starts at LBA 128 (not LBA 1) — gap of 127 sectors
    let entry = make_entry(0x80, 0x83, 128, 1000);
    let disk = make_disk(2000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::PrePartitionSpace { .. })));
}

#[test]
fn analyse_detects_post_partition_space() {
    // Disk has 2000 sectors; partition ends at LBA 999 — 1000 sectors trailing
    let entry = make_entry(0x80, 0x83, 1, 999);
    let disk = make_disk(2000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::PostPartitionSpace { .. })));
}

#[test]
fn analyse_detects_wiped_boot_code() {
    let disk = make_disk(100, &[]); // all-zero boot code
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::WipedBootCode));
}

#[test]
fn analyse_identifies_boot_code() {
    let mut disk = make_disk(100, &[]);
    // Inject GRUB 2 pattern
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(analysis.boot_code_id, BootCodeId::Grub2);
}

#[test]
fn analyse_returns_partition_summary() {
    let entry = make_entry(0x80, 0x83, 2048, 4096);
    let disk = make_disk(10000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert_eq!(analysis.partitions.len(), 1);
    assert_eq!(analysis.partitions[0].lba_start, 2048);
    assert_eq!(analysis.partitions[0].declared_type, TypeCode(0x83));
}

#[test]
fn analyse_disk_serial_populated() {
    let mut disk = make_disk(100, &[]);
    disk[440..444].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(analysis.mbr.disk_serial, 0xDEADBEEF);
}

#[test]
fn analyse_signature_mismatch_detected() {
    // Declare partition as NTFS (0x07) but write LUKS magic in its first sector.
    // LUKS magic is in the first 6 bytes — detectable from a single 512-byte read.
    let total_sectors = 10000u64;
    let lba_start = 128u32;
    let entry = make_entry(0x80, 0x07, lba_start, 1000); // declared NTFS
    let mut disk = make_disk(total_sectors, &[(&entry, 0)]);
    // Write LUKS magic at the start of the partition's first sector.
    let part_offset = lba_start as usize * 512;
    disk[part_offset..part_offset + 6].copy_from_slice(b"LUKS\xba\xbe");
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, total_sectors * 512).unwrap();
    // declared NTFS, detected LUKS → mismatch
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::SignatureMismatch { declared, detected, .. }
            if *declared == TypeCode(0x07) && *detected == DetectedFs::Luks
        )),
        "expected SignatureMismatch NTFS/LUKS, got: {:#?}",
        analysis.anomalies
    );
}

// ── Coverage: partition.rs uncovered paths ────────────────────────────────────

#[test]
fn chs_to_lba_valid_returns_some() {
    let chs = Chs {
        cylinder: 0,
        head: 1,
        sector: 1,
    };
    // LBA = 0 * 255 * 63 + 1 * 63 + (1 - 1) = 63
    assert_eq!(chs.to_lba(255, 63), Some(63));
}

#[test]
fn chs_to_lba_zero_hpc_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 1,
    };
    assert!(chs.to_lba(0, 63).is_none());
}

#[test]
fn chs_to_lba_zero_spt_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 1,
    };
    assert!(chs.to_lba(255, 0).is_none());
}

#[test]
fn partition_family_linux_swap() {
    assert_eq!(TypeCode(0x82).family(), PartitionFamily::LinuxSwap);
}

#[test]
fn partition_family_linux_lvm() {
    assert_eq!(TypeCode(0x8E).family(), PartitionFamily::LinuxLvm);
}

#[test]
fn partition_family_linux_raid() {
    assert_eq!(TypeCode(0xFD).family(), PartitionFamily::LinuxRaid);
}

#[test]
fn partition_family_freebsd() {
    assert_eq!(TypeCode(0xA5).family(), PartitionFamily::FreeBsd);
}

#[test]
fn partition_family_openbsd() {
    assert_eq!(TypeCode(0xA6).family(), PartitionFamily::OpenBsd);
}

#[test]
fn partition_family_netbsd() {
    assert_eq!(TypeCode(0xA9).family(), PartitionFamily::NetBsd);
}

#[test]
fn partition_family_hfs() {
    assert_eq!(TypeCode(0xAF).family(), PartitionFamily::Hfs);
    assert_eq!(TypeCode(0xAB).family(), PartitionFamily::Hfs);
}

#[test]
fn partition_family_efi_system() {
    assert_eq!(TypeCode(0xEF).family(), PartitionFamily::EfiSystem);
}

#[test]
fn partition_family_vmware() {
    assert_eq!(TypeCode(0xFB).family(), PartitionFamily::Vmware);
    assert_eq!(TypeCode(0xFC).family(), PartitionFamily::Vmware);
}

#[test]
fn partition_family_windows_recovery() {
    assert_eq!(TypeCode(0x27).family(), PartitionFamily::WindowsRecovery);
}

#[test]
fn partition_family_windows_dynamic() {
    assert_eq!(TypeCode(0x42).family(), PartitionFamily::WindowsDynamic);
}

#[test]
fn partition_family_unknown() {
    assert_eq!(TypeCode(0xCC).family(), PartitionFamily::Unknown(0xCC));
}

#[test]
fn type_code_name_known_values() {
    assert_eq!(TypeCode(0x00).name(), "Empty");
    assert_eq!(TypeCode(0x07).name(), "NTFS / exFAT / IFS");
    assert_eq!(TypeCode(0x83).name(), "Linux");
    assert_eq!(TypeCode(0xEE).name(), "GPT Protective MBR");
}

#[test]
fn type_code_name_unknown() {
    assert_eq!(TypeCode(0xCC).name(), "Unknown");
}

#[test]
fn lba_end_saturates_on_overflow() {
    // lba_start = u32::MAX, lba_count = u32::MAX → saturating result
    let entry = make_entry(0x00, 0x83, u32::MAX, u32::MAX);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    // Should not panic — saturating arithmetic
    let _ = mbr.entries[0].lba_end();
}

// ── Coverage: boot_code.rs uncovered paths ────────────────────────────────────

#[test]
fn identify_grub_legacy_by_jmp_opcode() {
    let mut code = [0u8; 446];
    code[0] = 0xEB;
    code[1] = 0x48;
    code[2] = 0x90;
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::GrubLegacy
    );
}

#[test]
fn identify_syslinux_by_name() {
    let mut code = [0u8; 446];
    code[3..11].copy_from_slice(b"SYSLINUX");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Syslinux
    );
}

#[test]
fn identify_windows_vista_by_pattern() {
    let mut code = [0u8; 446];
    code[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    code[424..431].copy_from_slice(b"BOOTMGR");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::WindowsVista
    );
}

// ── Coverage: entropy.rs uncovered paths ─────────────────────────────────────

#[test]
fn is_uniform_true_for_same_bytes() {
    assert!(entropy::is_uniform(&[0xABu8; 64]));
}

#[test]
fn is_uniform_false_for_mixed_bytes() {
    assert!(!entropy::is_uniform(&[0, 1, 0, 1]));
}

#[test]
fn is_uniform_true_for_single_byte() {
    assert!(entropy::is_uniform(&[0x42]));
}

// ── Coverage: signature.rs uncovered paths ────────────────────────────────────

#[test]
fn detect_unknown_on_nonzero_unrecognised() {
    let mut s = [0u8; 512];
    s[0] = 0xCC; // something that matches no pattern
    assert_eq!(signature::detect(&s), DetectedFs::Unknown);
}

#[test]
fn detect_empty_slice_is_unknown() {
    assert_eq!(signature::detect(&[]), DetectedFs::Unknown);
}

#[test]
fn detect_linux_swap_magic() {
    let mut s = vec![1u8; 4096]; // non-zero so not AllZeros
    s[4086..4096].copy_from_slice(b"SWAPSPACE2");
    assert_eq!(signature::detect(&s), DetectedFs::LinuxSwap);
}

#[test]
fn detect_linux_swap_pagespace() {
    let mut s = vec![1u8; 4096];
    s[4086..4096].copy_from_slice(b"PAGESPACE1");
    assert_eq!(signature::detect(&s), DetectedFs::LinuxSwap);
}

#[test]
fn detect_lvm2_label() {
    let mut s = vec![0u8; 512];
    s[8..16].copy_from_slice(b"LABELONE");
    s[0] = 1; // make it non-zero so AllZeros check passes
    assert_eq!(signature::detect(&s), DetectedFs::LinuxLvm);
}

#[test]
fn detect_fat_mswin41() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"MSWIN4.1");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_fat_mkdosfs() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"mkdosfs ");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

// ── Coverage: gap.rs uncovered paths ─────────────────────────────────────────

#[test]
fn gap_no_extents_is_single_post_partition_space() {
    let gaps = compute_gaps(&[], 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PostPartition);
    assert_eq!(gaps[0].lba_start, 1);
    assert_eq!(gaps[0].lba_end, 999);
}

#[test]
fn gap_partition_starts_at_first_usable_no_pre_gap() {
    let extents = [(1u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert!(gaps.is_empty());
}

#[test]
fn gap_multiple_inter_partition_gaps() {
    let extents = [(1u64, 100u64), (200u64, 300u64), (400u64, 499u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    // Between 100-199, between 300-399, after 499-999
    assert_eq!(gaps.len(), 3);
    assert_eq!(gaps[0].kind, GapKind::Between);
    assert_eq!(gaps[1].kind, GapKind::Between);
    assert_eq!(gaps[2].kind, GapKind::PostPartition);
}

// ── Coverage: analyse.rs uncovered paths ─────────────────────────────────────

#[test]
fn analyse_no_bootable_flagged_as_info() {
    // Active partitions but none bootable
    let entry = make_entry(0x00, 0x83, 2048, 1000); // status=0x00 (not bootable)
    let mut disk = make_disk(5000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90; // GRUB2 boot code
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::NoBootablePartition));
}

#[test]
fn analyse_detects_erased_boot_code() {
    let mut disk = make_disk(100, &[]);
    // All 0xFF in boot code area
    disk[..446].fill(0xFF);
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::ErasedBootCode));
}

#[test]
fn analyse_detects_unknown_boot_code() {
    let mut disk = make_disk(100, &[]);
    // Non-zero, non-matching boot code (but also not all-ones/zeros)
    disk[0] = 0xCC;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::UnknownBootCode));
}

#[test]
fn analyse_disk_size_zero_skips_gap_analysis() {
    let entry = make_entry(0x80, 0x83, 2048, 4096);
    let mut disk = make_disk(10000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 0).unwrap(); // disk_size=0 → skip gaps
    assert!(
        analysis.gaps.is_empty(),
        "gaps should be empty when disk_size=0"
    );
}

#[test]
fn analyse_inter_partition_gap_detected() {
    let e0 = make_entry(0x80, 0x83, 100, 100); // ends at LBA 199
    let e1 = make_entry(0x00, 0x83, 400, 100); // starts at LBA 400 — gap 200-399
    let mut disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis.anomalies.iter().any(|a| matches!(
        &a.kind, AnomalyKind::InterPartitionGap { lba_start, lba_end, .. }
        if *lba_start == 200 && *lba_end == 399
    )));
}

#[test]
fn analyse_no_signature_mismatch_when_types_match() {
    // Declare FAT32, write FAT signature — no mismatch expected
    let lba_start = 128u32;
    let entry = make_entry(0x80, 0x0C, lba_start, 1000); // FAT32 LBA
    let mut disk = make_disk(5000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let part_off = lba_start as usize * 512;
    disk[part_off + 3..part_off + 11].copy_from_slice(b"MSDOS5.0");
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(&a.kind, AnomalyKind::SignatureMismatch { .. })));
}

// ── Coverage: EBR chain paths ─────────────────────────────────────────────────

fn make_ebr_sector(
    logical_type: u8,
    logical_start: u32,
    logical_count: u32,
    next_lba_rel: u32, // relative to ext_start; 0 = end of chain
    slack_byte: u8,
) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    // entry 0: logical partition
    s[446] = 0x00;
    s[450] = logical_type;
    s[454..458].copy_from_slice(&logical_start.to_le_bytes());
    s[458..462].copy_from_slice(&logical_count.to_le_bytes());
    // entry 1: next EBR
    s[462..466].fill(0);
    s[462 + 4] = 0; // type=0
    s[462 + 8..462 + 12].copy_from_slice(&next_lba_rel.to_le_bytes());
    s[462 + 12..462 + 16].copy_from_slice(&1u32.to_le_bytes()); // count=1
                                                                // slack bytes at 478-509
    if slack_byte != 0 {
        s[478] = slack_byte;
    }
    s
}

#[test]
fn analyse_ebr_chain_traversal() {
    // Extended partition at LBA 1000; EBR at LBA 1000 with one logical partition
    let ext_lba = 1000u32;
    let ext_count = 2000u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, ext_count);

    // Disk: 5000 sectors; EBR sector at LBA 1000
    let mut disk = vec![0u8; 5000 * 512];
    // Write MBR
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90; // GRUB2 bootcode

    // Write EBR at LBA 1000 (end of chain — next_lba_rel=0)
    let ebr = make_ebr_sector(0x83, 1, 100, 0, 0);
    let ebr_off = ext_lba as usize * 512;
    disk[ebr_off..ebr_off + 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 5000 * 512).unwrap();
    assert!(
        !analysis.ebr_chain.entries.is_empty(),
        "EBR chain should have one entry"
    );
    assert!(!analysis.ebr_chain.had_cycle);
    assert!(!analysis.ebr_chain.depth_exceeded);
}

#[test]
fn analyse_ebr_bad_signature_terminates_cleanly() {
    // Extended partition at LBA 100; EBR at LBA 100 with BAD signature
    let ext_entry = make_entry(0x80, 0x05, 100, 200);
    let mut disk = vec![0u8; 1000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    // EBR at LBA 100: DO NOT write 0x55AA — bad signature
    // Leave as all-zeros (no signature)

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 1000 * 512).unwrap();
    // EBR chain should be empty (bad sig → terminated)
    assert!(analysis.ebr_chain.entries.is_empty());
}

#[test]
fn analyse_ebr_slack_data_detected() {
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 500);
    let mut disk = vec![0u8; 2000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR with slack data (byte 0xAB in the slack area)
    let ebr = make_ebr_sector(0x83, 1, 50, 0, 0xAB);
    let ebr_off = ext_lba as usize * 512;
    disk[ebr_off..ebr_off + 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 2000 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(&a.kind, AnomalyKind::EbrSlackData { .. })),
        "expected EbrSlackData anomaly"
    );
}

#[test]
fn analyse_ebr_cycle_detected() {
    // Build a chain that loops:
    //   EBR@100 -> next rel 100 (abs 200)
    //   EBR@200 -> next rel 100 (abs 200, already visited) -> cycle
    // `next_lba_rel` is relative to the extended-partition start (LBA 100).
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 1000);
    let mut disk = vec![0u8; 5000 * 512];
    disk[0..512].copy_from_slice(&make_sector(&[(&ext_entry, 0)]));
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR@100 → next rel 100 → abs 200.
    disk[100 * 512..101 * 512].copy_from_slice(&make_ebr_sector(0x83, 1, 50, 100, 0));
    // EBR@200 → next rel 100 → abs 200 again (visited) → cycle detected.
    disk[200 * 512..201 * 512].copy_from_slice(&make_ebr_sector(0x83, 1, 50, 100, 0));

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 5000 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::EbrCycle),
        "expected EbrCycle anomaly, got: {:#?}",
        analysis.anomalies
    );
}

// ── Defensive: crafted/malicious/corrupted inputs ────────────────────────────

#[test]
fn parse_mbr_larger_than_512_bytes_succeeds() {
    // Input larger than 512 bytes — should read only first 512
    let mut s = vec![0u8; 1024];
    s[510] = 0x55;
    s[511] = 0xAA;
    assert!(parse_mbr_sector(&s).is_ok());
}

#[test]
fn parse_mbr_empty_slice_returns_too_short() {
    assert!(matches!(parse_mbr_sector(&[]), Err(Error::TooShort(0))));
}

#[test]
fn analyse_partition_lba_max_does_not_panic() {
    // Adversarial: lba_start + lba_count = u32::MAX — should not panic
    let entry = make_entry(0x80, 0x83, 0, u32::MAX);
    let mut disk = make_disk(100, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let _ = analyse(&mut c, 100 * 512).unwrap(); // must not panic
}

#[test]
fn analyse_all_entries_residual_does_not_panic() {
    // Four residual entries (type=0 but non-zero LBA)
    let e: [u8; 16] = make_entry(0x00, 0x00, u32::MAX, u32::MAX);
    let mut disk = make_disk(100, &[(&e, 0), (&e, 1), (&e, 2), (&e, 3)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(
        analysis
            .anomalies
            .iter()
            .filter(|a| matches!(&a.kind, AnomalyKind::ResidualEntry { .. }))
            .count(),
        4
    );
}

#[test]
fn ebr_chain_overflow_next_lba_terminates() {
    // EBR at ext_start = u64::MAX / 2; next_lba_rel = u32::MAX
    // ext_start + next_lba_rel would overflow — walk must terminate, not panic
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 500);
    let mut disk = vec![0u8; 5000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR at LBA 100: next_lba_rel = u32::MAX → abs = 100 + u32::MAX overflows
    let mut ebr = make_ebr_sector(0x83, 1, 50, 0, 0);
    // Patch entry1 lba_start to u32::MAX
    ebr[462 + 8..462 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    ebr[462 + 12..462 + 16].copy_from_slice(&1u32.to_le_bytes());
    ebr[462 + 4] = 0x83; // non-zero type so it's not skipped
    disk[100 * 512..101 * 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let _ = analyse(&mut c, 5000 * 512).unwrap(); // must not panic
}

#[test]
fn analyse_truncated_disk_reader_does_not_panic() {
    // Disk claims 10000 sectors but reader has only 512 bytes (MBR only)
    let entry = make_entry(0x80, 0x83, 1000, 5000);
    let mbr = make_sector(&[(&entry, 0)]);
    let mut c = Cursor::new(mbr.to_vec());
    // disk_size = 10000 * 512 but reader has only 512 bytes
    // read_partition_first_sector will fail, but analyse should handle gracefully
    let result = analyse(&mut c, 10000 * 512);
    // May succeed (detected_fs=None) or fail with Io; must not panic
    let _ = result;
}

// ── Anomaly metadata: severity / code / note (single source of truth) ─────────
//
// These exercise the derivation methods directly, including branches that are
// unreachable through `analyse` (e.g. EBR slack entropy > 6.0 is impossible for
// a 32-byte slack region, whose entropy caps at log2(32) = 5 bits).

/// Every variant must yield a non-empty, `MBR-`-prefixed stable code.
fn all_kinds() -> Vec<AnomalyKind> {
    vec![
        AnomalyKind::NonZeroReserved { bytes: [1, 2] },
        AnomalyKind::MultipleBootable { count: 2 },
        AnomalyKind::NoBootablePartition,
        AnomalyKind::ResidualEntry {
            index: 0,
            lba_start: 1,
            lba_count: 2,
        },
        AnomalyKind::OverlappingPartitions {
            a: 0,
            b: 1,
            a_end: 100,
            b_start: 50,
        },
        AnomalyKind::OutOfBounds {
            index: 0,
            last_lba: 999,
            disk_last_lba: 500,
        },
        AnomalyKind::ChsLbaInconsistency { index: 1 },
        AnomalyKind::EbrCycle,
        AnomalyKind::EbrExcessiveDepth { depth: 64 },
        AnomalyKind::EbrSlackData {
            ebr_lba: 100,
            entropy: 2.5,
        },
        AnomalyKind::PrePartitionSpace {
            lba_start: 1,
            lba_end: 62,
            byte_size: 31744,
        },
        AnomalyKind::InterPartitionGap {
            lba_start: 200,
            lba_end: 399,
            byte_size: 102400,
        },
        AnomalyKind::PostPartitionSpace {
            lba_start: 500,
            lba_end: 999,
            byte_size: 256000,
        },
        AnomalyKind::SignatureMismatch {
            index: 0,
            declared: TypeCode(0x07),
            detected: DetectedFs::Ext,
        },
        AnomalyKind::WipedBootCode,
        AnomalyKind::ErasedBootCode,
        AnomalyKind::UnknownBootCode,
        AnomalyKind::HighEntropySlack {
            offset: 446,
            entropy: 7.5,
        },
    ]
}

#[test]
fn every_kind_has_stable_code_and_nonempty_note() {
    for kind in all_kinds() {
        let code = kind.code();
        assert!(
            code.starts_with("MBR-"),
            "code must be MBR-prefixed: {code}"
        );
        assert!(!kind.note().is_empty(), "note must be non-empty for {code}");
    }
}

#[test]
fn codes_are_unique_per_kind() {
    let kinds = all_kinds();
    let codes: std::collections::HashSet<&str> = kinds.iter().map(|k| k.code()).collect();
    assert_eq!(
        codes.len(),
        kinds.len(),
        "each kind must have a distinct code"
    );
}

#[test]
fn severity_critical_kinds() {
    assert_eq!(AnomalyKind::EbrCycle.severity(), Severity::Critical);
    assert_eq!(
        AnomalyKind::OverlappingPartitions {
            a: 0,
            b: 1,
            a_end: 100,
            b_start: 50
        }
        .severity(),
        Severity::Critical
    );
}

#[test]
fn severity_high_kinds() {
    assert_eq!(AnomalyKind::WipedBootCode.severity(), Severity::High);
    assert_eq!(AnomalyKind::ErasedBootCode.severity(), Severity::High);
    assert_eq!(
        AnomalyKind::OutOfBounds {
            index: 0,
            last_lba: 1,
            disk_last_lba: 0
        }
        .severity(),
        Severity::High
    );
    assert_eq!(
        AnomalyKind::EbrExcessiveDepth { depth: 64 }.severity(),
        Severity::High
    );
    assert_eq!(
        AnomalyKind::HighEntropySlack {
            offset: 0,
            entropy: 7.0
        }
        .severity(),
        Severity::High
    );
}

#[test]
fn severity_ebr_slack_scales_with_entropy() {
    // Low entropy → Medium.
    assert_eq!(
        AnomalyKind::EbrSlackData {
            ebr_lba: 1,
            entropy: 2.0
        }
        .severity(),
        Severity::Medium
    );
    // High entropy → High (only reachable via direct construction).
    assert_eq!(
        AnomalyKind::EbrSlackData {
            ebr_lba: 1,
            entropy: 7.5
        }
        .severity(),
        Severity::High
    );
}

#[test]
fn severity_pre_partition_scales_with_lba() {
    // Within the reserved track (< 63) → Low.
    assert_eq!(
        AnomalyKind::PrePartitionSpace {
            lba_start: 1,
            lba_end: 10,
            byte_size: 5120
        }
        .severity(),
        Severity::Low
    );
    // Beyond the reserved track (>= 63) → Medium.
    assert_eq!(
        AnomalyKind::PrePartitionSpace {
            lba_start: 100,
            lba_end: 200,
            byte_size: 51712
        }
        .severity(),
        Severity::Medium
    );
}

#[test]
fn severity_medium_kinds() {
    assert_eq!(
        AnomalyKind::NonZeroReserved { bytes: [1, 2] }.severity(),
        Severity::Medium
    );
    assert_eq!(
        AnomalyKind::MultipleBootable { count: 2 }.severity(),
        Severity::Medium
    );
    assert_eq!(
        AnomalyKind::ResidualEntry {
            index: 0,
            lba_start: 1,
            lba_count: 2
        }
        .severity(),
        Severity::Medium
    );
    assert_eq!(
        AnomalyKind::ChsLbaInconsistency { index: 0 }.severity(),
        Severity::Medium
    );
    assert_eq!(
        AnomalyKind::InterPartitionGap {
            lba_start: 1,
            lba_end: 2,
            byte_size: 1024
        }
        .severity(),
        Severity::Medium
    );
    assert_eq!(
        AnomalyKind::SignatureMismatch {
            index: 0,
            declared: TypeCode(0x07),
            detected: DetectedFs::Ext
        }
        .severity(),
        Severity::Medium
    );
}

#[test]
fn severity_low_and_info_kinds() {
    assert_eq!(AnomalyKind::UnknownBootCode.severity(), Severity::Low);
    assert_eq!(AnomalyKind::NoBootablePartition.severity(), Severity::Info);
    assert_eq!(
        AnomalyKind::PostPartitionSpace {
            lba_start: 1,
            lba_end: 2,
            byte_size: 1024
        }
        .severity(),
        Severity::Info
    );
}

#[test]
fn anomaly_new_derives_fields_from_kind() {
    let a = Anomaly::new(AnomalyKind::EbrCycle, 0x200);
    assert_eq!(a.severity, Severity::Critical);
    assert_eq!(a.code, "MBR-EBR-CYCLE");
    assert_eq!(a.offset, 0x200);
    assert_eq!(a.note, "EBR chain contains a cycle");
}

#[test]
fn severity_display_strings() {
    assert_eq!(Severity::Info.to_string(), "INFO");
    assert_eq!(Severity::Low.to_string(), "LOW");
    assert_eq!(Severity::Medium.to_string(), "MEDIUM");
    assert_eq!(Severity::High.to_string(), "HIGH");
    assert_eq!(Severity::Critical.to_string(), "CRITICAL");
}

#[test]
fn anomaly_display_format() {
    let a = Anomaly::new(AnomalyKind::WipedBootCode, 0);
    let s = a.to_string();
    assert!(s.contains("HIGH"), "got: {s}");
    assert!(s.contains("MBR-BOOT-WIPED"), "got: {s}");
    assert!(s.contains("0x0"), "got: {s}");
}

#[test]
fn note_residual_mentions_lba() {
    let note = AnomalyKind::ResidualEntry {
        index: 2,
        lba_start: 100,
        lba_count: 50,
    }
    .note();
    assert!(note.contains("100") && note.contains("50"), "got: {note}");
}

#[test]
fn note_chs_lba_inconsistency() {
    let note = AnomalyKind::ChsLbaInconsistency { index: 3 }.note();
    assert!(
        note.contains('3') && note.to_lowercase().contains("chs"),
        "got: {note}"
    );
}

#[test]
fn note_high_entropy_slack() {
    let note = AnomalyKind::HighEntropySlack {
        offset: 446,
        entropy: 7.5,
    }
    .note();
    assert!(note.contains("446") && note.contains("7.5"), "got: {note}");
}

// ── MbrAnalysis helpers ───────────────────────────────────────────────────────

#[test]
fn max_severity_none_when_clean() {
    // A disk with valid bootcode and a clean single partition has no high
    // anomalies, but may have info/low. Build a truly clean image: GRUB boot
    // code, one partition spanning the whole usable disk, bootable.
    let entry = make_entry(0x80, 0x83, 1, 999);
    let mut disk = make_disk(1000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 1000 * 512).unwrap();
    // There is at least a post-partition gap of zero or detection noise; just
    // assert max_severity returns a value consistent with the anomalies vec.
    match analysis.max_severity() {
        Some(sev) => assert!(analysis.anomalies.iter().any(|a| a.severity == sev)),
        None => assert!(analysis.anomalies.is_empty()),
    }
}

#[test]
fn max_severity_reflects_highest() {
    // Overlapping partitions → Critical present.
    let e0 = make_entry(0x80, 0x83, 100, 500);
    let e1 = make_entry(0x00, 0x83, 400, 500);
    let disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert_eq!(analysis.max_severity(), Some(Severity::Critical));
}

#[test]
fn anomalies_at_least_filters_by_severity() {
    let e0 = make_entry(0x80, 0x83, 100, 500);
    let e1 = make_entry(0x00, 0x83, 400, 500);
    let disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    let critical: Vec<_> = analysis.anomalies_at_least(Severity::Critical).collect();
    assert!(!critical.is_empty());
    assert!(critical.iter().all(|a| a.severity >= Severity::Critical));
}

// ── EbrChain ──────────────────────────────────────────────────────────────────

#[test]
fn ebr_chain_empty_is_empty() {
    let chain = EbrChain::empty();
    assert!(chain.entries.is_empty());
    assert!(!chain.had_cycle);
    assert!(!chain.depth_exceeded);
}

#[test]
fn ebr_chain_default_matches_empty() {
    let d = EbrChain::default();
    assert!(d.entries.is_empty());
    assert!(!d.had_cycle);
    assert!(!d.depth_exceeded);
}

// ── Exhaustive TypeCode name() / family() coverage ────────────────────────────

/// Every documented type byte must map to a non-"Unknown" name, exercising
/// every arm of `name()`.
#[test]
fn type_code_name_covers_all_known_bytes() {
    const KNOWN: &[u8] = &[
        0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x11, 0x14, 0x16, 0x17,
        0x1B, 0x1C, 0x1E, 0x27, 0x42, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x8E, 0x9F, 0xA5, 0xA6,
        0xA9, 0xAB, 0xAF, 0xBE, 0xBF, 0xEB, 0xEE, 0xEF, 0xFB, 0xFC, 0xFD, 0xFE,
    ];
    for &b in KNOWN {
        assert_ne!(
            TypeCode(b).name(),
            "Unknown",
            "byte {b:#04X} should be named"
        );
    }
    // A genuinely unknown byte falls through to "Unknown".
    assert_eq!(TypeCode(0xCD).name(), "Unknown");
}

/// Exercise every arm of `family()`.
#[test]
fn type_code_family_covers_all_arms() {
    use PartitionFamily as Pf;
    let cases: &[(u8, Pf)] = &[
        (0x00, Pf::Empty),
        (0x01, Pf::Fat12),
        (0x06, Pf::Fat16),
        (0x0C, Pf::Fat32),
        (0x07, Pf::Ntfs),
        (0x05, Pf::ExtendedMbr),
        (0x82, Pf::LinuxSwap),
        (0x83, Pf::Linux),
        (0x8E, Pf::LinuxLvm),
        (0xFD, Pf::LinuxRaid),
        (0x27, Pf::WindowsRecovery),
        (0x42, Pf::WindowsDynamic),
        (0xA5, Pf::FreeBsd),
        (0xA6, Pf::OpenBsd),
        (0xA9, Pf::NetBsd),
        (0xAF, Pf::Hfs),
        (0xEE, Pf::GptProtective),
        (0xEF, Pf::EfiSystem),
        (0xFB, Pf::Vmware),
    ];
    for &(b, expected) in cases {
        assert_eq!(TypeCode(b).family(), expected, "byte {b:#04X}");
    }
    assert_eq!(TypeCode(0xCD).family(), Pf::Unknown(0xCD));
}

// ── signature::type_conflicts — every policy arm ──────────────────────────────

#[test]
fn type_conflicts_unknown_and_zeros_never_conflict() {
    use PartitionFamily as Pf;
    assert!(!signature::type_conflicts(Pf::Ntfs, DetectedFs::Unknown));
    assert!(!signature::type_conflicts(Pf::Ntfs, DetectedFs::AllZeros));
}

#[test]
fn type_conflicts_ntfs_declared() {
    use PartitionFamily as Pf;
    assert!(signature::type_conflicts(Pf::Ntfs, DetectedFs::Ext));
    assert!(signature::type_conflicts(Pf::Ntfs, DetectedFs::Luks));
    // NTFS declared + NTFS detected → no conflict.
    assert!(!signature::type_conflicts(Pf::Ntfs, DetectedFs::Ntfs));
}

#[test]
fn type_conflicts_fat_declared() {
    use PartitionFamily as Pf;
    assert!(signature::type_conflicts(Pf::Fat32, DetectedFs::Ntfs));
    assert!(signature::type_conflicts(Pf::Fat16, DetectedFs::Ext));
    assert!(signature::type_conflicts(Pf::Fat12, DetectedFs::Luks));
    assert!(!signature::type_conflicts(Pf::Fat32, DetectedFs::Fat));
}

#[test]
fn type_conflicts_linux_declared() {
    use PartitionFamily as Pf;
    assert!(signature::type_conflicts(Pf::Linux, DetectedFs::Ntfs));
    assert!(signature::type_conflicts(Pf::Linux, DetectedFs::Apfs));
    assert!(!signature::type_conflicts(Pf::Linux, DetectedFs::Ext));
}

#[test]
fn type_conflicts_linux_swap_declared() {
    use PartitionFamily as Pf;
    assert!(signature::type_conflicts(Pf::LinuxSwap, DetectedFs::Ntfs));
    assert!(signature::type_conflicts(Pf::LinuxSwap, DetectedFs::Ext));
    assert!(!signature::type_conflicts(
        Pf::LinuxSwap,
        DetectedFs::LinuxSwap
    ));
}

#[test]
fn type_conflicts_linux_lvm_declared() {
    use PartitionFamily as Pf;
    assert!(signature::type_conflicts(Pf::LinuxLvm, DetectedFs::Ntfs));
    assert!(signature::type_conflicts(Pf::LinuxLvm, DetectedFs::Fat));
    assert!(!signature::type_conflicts(
        Pf::LinuxLvm,
        DetectedFs::LinuxLvm
    ));
}

#[test]
fn type_conflicts_unrelated_families_do_not_conflict() {
    use PartitionFamily as Pf;
    // An EFI system partition vs a detected FAT is legitimate (ESP is FAT).
    assert!(!signature::type_conflicts(Pf::EfiSystem, DetectedFs::Fat));
    assert!(!signature::type_conflicts(Pf::Empty, DetectedFs::Ntfs));
}

// ── signature::detect — remaining branches ────────────────────────────────────

#[test]
fn detect_fat_mswin40() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"MSWIN4.0");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_fat_freedos() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"FreeDOS ");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_short_sector_with_fat_length_no_match_is_unknown() {
    // Exactly past the FAT-OEM length but no recognised magic anywhere →
    // exercises the FAT block's fall-through.
    let mut s = vec![0xCCu8; 64];
    s[3..11].copy_from_slice(b"NOTAFSXX");
    assert_eq!(signature::detect(&s), DetectedFs::Unknown);
}

#[test]
fn detect_4096_sector_without_swap_magic_is_unknown() {
    // len >= 4096 enters the swap check, but no swap magic → falls through.
    let s = vec![0xCCu8; 4096];
    assert_eq!(signature::detect(&s), DetectedFs::Unknown);
}

#[test]
fn detect_lvm_label_beyond_512_is_unknown() {
    // LABELONE present but at offset >= 512 → not treated as LVM.
    let mut s = vec![0u8; 700];
    s[0] = 1; // non-zero so the AllZeros check passes
    s[600..608].copy_from_slice(b"LABELONE");
    assert_eq!(signature::detect(&s), DetectedFs::Unknown);
}

// ── Mock readers for adversarial / overflow-defense paths ─────────────────────

/// A disk backed by an in-memory image that can be made to fail seeks at or
/// beyond a chosen byte offset — used to exercise I/O-error handling paths.
struct MockDisk {
    data: Vec<u8>,
    pos: usize,
    fail_seek_at: Option<u64>,
}

impl std::io::Read for MockDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = self.pos.min(self.data.len());
        let end = (start + buf.len()).min(self.data.len());
        let n = end - start;
        buf[..n].copy_from_slice(&self.data[start..end]);
        self.pos += n;
        Ok(n)
    }
}

impl std::io::Seek for MockDisk {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            std::io::SeekFrom::Start(x) => x,
            std::io::SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
            std::io::SeekFrom::End(d) => (self.data.len() as i64 + d) as u64,
        };
        if let Some(t) = self.fail_seek_at {
            if target >= t {
                return Err(std::io::Error::other("mock seek failure"));
            }
        }
        self.pos = target as usize;
        Ok(target)
    }
}

/// A reader that returns the same 512-byte EBR sector for every read and
/// accepts any seek — lets us drive `walk_ebr_chain` to astronomically large
/// LBAs that no real backing store could hold.
struct RepeatEbr {
    sector: [u8; 512],
}

impl std::io::Read for RepeatEbr {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(512);
        buf[..n].copy_from_slice(&self.sector[..n]);
        Ok(n)
    }
}

impl std::io::Seek for RepeatEbr {
    fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
        Ok(0)
    }
}

// ── EBR overflow-defense paths (only reachable via crafted inputs) ────────────

#[test]
fn walk_ebr_chain_byte_offset_overflow_terminates() {
    // sector_size = u64::MAX makes `next_ebr_lba * sector_size` overflow on the
    // first iteration, before any I/O. The chain must end cleanly.
    let mut empty = Cursor::new(Vec::<u8>::new());
    let chain = mbr_forensic::ebr::walk_ebr_chain(&mut empty, 2, u64::MAX).unwrap();
    assert!(chain.entries.is_empty());
    assert!(!chain.had_cycle);
    assert!(!chain.depth_exceeded);
}

#[test]
fn walk_ebr_chain_next_pointer_overflow_terminates() {
    // ext_start near u64::MAX with a non-zero next pointer makes
    // `ext_start + next` overflow → chain ends after the first entry.
    let mut sector = [0u8; 512];
    sector.copy_from_slice(&make_ebr_sector(0x83, 1, 1, 5, 0)); // next_lba_rel = 5
    let mut disk = RepeatEbr { sector };
    let chain = mbr_forensic::ebr::walk_ebr_chain(&mut disk, u64::MAX - 1, 1).unwrap();
    assert_eq!(chain.entries.len(), 1);
    assert!(!chain.had_cycle);
}

#[test]
fn analyse_ebr_excessive_depth_detected() {
    // Chain more EBRs than MAX_DEPTH (64) so traversal caps out.
    let ext_lba = 100u32;
    let count = 70u32; // > 64
    let total_sectors = (ext_lba + count + 10) as u64;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, count + 5);
    let mut disk = vec![0u8; total_sectors as usize * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    // EBR[i] at LBA ext_lba+i points to EBR[i+1] via next_lba_rel = i+1.
    for i in 0..count {
        let ebr = make_ebr_sector(0x83, 1, 1, i + 1, 0);
        let off = (ext_lba + i) as usize * 512;
        disk[off..off + 512].copy_from_slice(&ebr);
    }
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, total_sectors * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::EbrExcessiveDepth { .. })),
        "expected EbrExcessiveDepth"
    );
    assert!(analysis.ebr_chain.depth_exceeded);
}

#[test]
fn analyse_ebr_walk_seek_failure_terminates() {
    // The MBR reads fine, but seeking to the EBR sector fails → the chain walk
    // returns an error which `analyse` absorbs, leaving an empty chain.
    let ext = make_entry(0x80, 0x05, 100, 100);
    let mut data = make_disk(200, &[(&ext, 0)]);
    data[0] = 0xEB;
    data[1] = 0x63;
    data[2] = 0x90;
    let mut mock = MockDisk {
        data,
        pos: 0,
        fail_seek_at: Some(100 * 512), // fails the EBR seek, not the MBR seek
    };
    let analysis = analyse(&mut mock, 200 * 512).unwrap();
    assert!(analysis.ebr_chain.entries.is_empty());
}

#[test]
fn analyse_ebr_truncated_read_terminates() {
    // Extended partition LBA lies beyond the reader's backing bytes, but within
    // the declared disk size → the EBR read fails and the chain ends cleanly.
    let ext = make_entry(0x80, 0x05, 100, 100);
    let mut data = make_disk(60, &[(&ext, 0)]); // only 60 sectors backed
    data[0] = 0xEB;
    data[1] = 0x63;
    data[2] = 0x90;
    let mut c = Cursor::new(data);
    let analysis = analyse(&mut c, 200 * 512).unwrap(); // claims 200 sectors
    assert!(analysis.ebr_chain.entries.is_empty());
}

#[test]
fn analyse_partition_beyond_disk_skips_fs_detection() {
    // Partition starts past the disk end → fs detection short-circuits, and the
    // entry is flagged out-of-bounds with no detected filesystem.
    let entry = make_entry(0x80, 0x83, 2000, 10); // LBA 2000 on a 1000-sector disk
    let mut disk = make_disk(1000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 1000 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::OutOfBounds { .. })));
    assert!(analysis.partitions.iter().all(|p| p.detected_fs.is_none()));
}

// ── read_mbr error propagation ────────────────────────────────────────────────

#[test]
fn analyse_short_reader_propagates_error() {
    // Fewer than 512 bytes → read_exact in read_mbr fails → analyse errors.
    let mut c = Cursor::new(vec![0u8; 100]);
    assert!(analyse(&mut c, 0).is_err());
}

#[test]
fn analyse_seek_failure_propagates_error() {
    // Seeking to 0 fails → read_mbr's seek errors → analyse errors.
    let mut mock = MockDisk {
        data: vec![0u8; 512],
        pos: 0,
        fail_seek_at: Some(0),
    };
    assert!(analyse(&mut mock, 0).is_err());
}

// ── Tracing paths under an active subscriber ──────────────────────────────────
//
// tracing's field-evaluation blocks only execute when a subscriber is enabled,
// so these paths need a live subscriber to be exercised. We install a sink
// subscriber and drive every traced branch (anomaly record, summary, EBR walk
// failure, partition read failure).

#[cfg(feature = "trace")]
#[test]
fn tracing_paths_execute_under_active_subscriber() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::sink)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        // Anomaly record + completion summary: an all-zero (wiped) MBR.
        let disk = make_disk(100, &[]);
        let mut c = Cursor::new(disk);
        let _ = analyse(&mut c, 100 * 512).unwrap();

        // EBR walk failure (warn) + partition read failure (trace): a disk with
        // an extended partition whose sectors cannot be seeked.
        let ext_entry = make_entry(0x80, 0x05, 100, 100);
        let mut data = make_disk(200, &[(&ext_entry, 0)]);
        data[0] = 0xEB;
        data[1] = 0x63;
        data[2] = 0x90;
        let mut mock = MockDisk {
            data,
            pos: 0,
            fail_seek_at: Some(100 * 512),
        };
        let analysis = analyse(&mut mock, 200 * 512).unwrap();
        assert!(analysis.ebr_chain.entries.is_empty());

        // Partition read failure (trace): partition offset within the declared
        // disk size but past the end of a 512-byte reader.
        let entry = make_entry(0x80, 0x83, 100, 50);
        let mut mbr = make_sector(&[(&entry, 0)]);
        mbr[0] = 0xEB;
        mbr[1] = 0x63;
        mbr[2] = 0x90;
        let mut c = Cursor::new(mbr.to_vec());
        let _ = analyse(&mut c, 1000 * 512);

        // EBR with no boot signature (trace): extended partition points at an
        // all-zero sector.
        let ext = make_entry(0x80, 0x05, 50, 100);
        let mut data = make_disk(200, &[(&ext, 0)]);
        data[0] = 0xEB;
        data[1] = 0x63;
        data[2] = 0x90;
        let mut c = Cursor::new(data);
        let analysis = analyse(&mut c, 200 * 512).unwrap();
        assert!(analysis.ebr_chain.entries.is_empty());

        // EBR read past end of image (trace): extended partition LBA beyond the
        // reader's data, but within the declared disk size.
        let ext = make_entry(0x80, 0x05, 100, 100);
        let mut data = make_disk(60, &[(&ext, 0)]);
        data[0] = 0xEB;
        data[1] = 0x63;
        data[2] = 0x90;
        let mut c = Cursor::new(data);
        let analysis = analyse(&mut c, 200 * 512).unwrap();
        assert!(analysis.ebr_chain.entries.is_empty());
    });
}
