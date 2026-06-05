//! 4Kn (Advanced Format) support: partition content offsets scale with the
//! logical sector size, while the MBR boot record itself stays at byte 0.

use mbr_forensic::{analyse, analyse_with_options, AnalyseOptions, DetectedFs};
use std::io::Cursor;

/// A 4Kn disk (4096-byte logical sectors) with one NTFS partition at LBA 4.
/// The NTFS OEM id sits at `4 × 4096 + 3` — reachable only with 4Kn geometry.
fn disk_4kn_with_ntfs() -> Vec<u8> {
    let ss = 4096usize;
    let mut d = vec![0u8; 64 * ss];
    // MBR boot record lives in the first 512 bytes regardless of sector size.
    d[510] = 0x55;
    d[511] = 0xAA;
    let e = 446;
    d[e + 4] = 0x07; // NTFS / exFAT partition type
    d[e + 8..e + 12].copy_from_slice(&4u32.to_le_bytes()); // lba_start = 4
    d[e + 12..e + 16].copy_from_slice(&4u32.to_le_bytes()); // lba_count = 4
    let off = 4 * ss + 3;
    d[off..off + 8].copy_from_slice(b"NTFS    ");
    d
}

#[test]
fn detects_filesystem_with_forced_4kn_sector_size() {
    let disk = disk_4kn_with_ntfs();
    let size = disk.len() as u64;

    // 4Kn geometry locates the partition's first sector and identifies NTFS.
    let a = analyse_with_options(
        &mut Cursor::new(disk.clone()),
        size,
        AnalyseOptions { sector_size: 4096 },
    )
    .unwrap();
    assert_eq!(a.partitions[0].detected_fs, Some(DetectedFs::Ntfs));

    // The default 512-byte assumption reads the wrong offset → not identified.
    let b = analyse(&mut Cursor::new(disk), size).unwrap();
    assert_ne!(b.partitions[0].detected_fs, Some(DetectedFs::Ntfs));
}

#[test]
fn default_analyse_assumes_512() {
    // analyse() must equal analyse_with_options(.., 512).
    let disk = disk_4kn_with_ntfs();
    let size = disk.len() as u64;
    let viaopts = analyse_with_options(
        &mut Cursor::new(disk.clone()),
        size,
        AnalyseOptions { sector_size: 512 },
    )
    .unwrap();
    let plain = analyse(&mut Cursor::new(disk), size).unwrap();
    assert_eq!(viaopts.partitions[0].detected_fs, plain.partitions[0].detected_fs);
}
