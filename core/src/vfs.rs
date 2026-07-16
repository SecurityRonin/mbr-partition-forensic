//! `forensic-vfs` [`VolumeSystem`] adapter for the MBR, behind the `vfs` feature.
//!
//! Wraps a parent [`ImageSource`](forensic_vfs::ImageSource) and exposes the
//! disk's MBR **primary** partitions as [`VolumeDesc`]s, each openable as a
//! [`SubRange`] byte window. MBR partition LBAs are addressed in the disk's
//! logical sectors; the classic MBR uses 512-byte units (`crate::SECTOR_SIZE`),
//! which is what `mmls`/`fdisk` assume. Logical partitions inside an extended
//! partition (the EBR chain, [`crate::ebr`]) are a follow-up; this exposes the
//! four primary slots.

use std::sync::Arc;

use forensic_vfs::adapters::SubRange;
use forensic_vfs::{
    DynSource, ImageSource, VfsError, VfsResult, VolumeDesc, VolumeKind, VolumeScheme, VolumeSystem,
};

/// Fill `buf` from `src` starting at `off`, tolerating short reads and stopping
/// at EOF (any unfilled tail stays zeroed — the parser bounds-checks its slices).
fn fill(src: &dyn ImageSource, mut off: u64, mut buf: &mut [u8]) -> VfsResult<()> {
    while !buf.is_empty() {
        let n = src.read_at(off, buf)?;
        if n == 0 {
            break; // EOF
        }
        off = off.saturating_add(n as u64);
        let Some(rest) = buf.get_mut(n..) else {
            break; // cov:unreachable: read_at returns n <= buf.len()
        };
        buf = rest;
    }
    Ok(())
}

/// An MBR partition scheme over one parent byte source.
pub struct MbrVolumes {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl MbrVolumes {
    /// Read the MBR (sector 0) of `parent` and build the primary-partition
    /// table. Returns [`VfsError::Unsupported`] if sector 0 is not a valid MBR
    /// (no `0x55AA` boot signature).
    pub fn open(parent: DynSource) -> VfsResult<Self> {
        // MBR LBAs are addressed in the disk's logical sectors; the classic MBR
        // uses 512-byte units, which is what mmls/fdisk assume.
        let sector_size = crate::SECTOR_SIZE as u64;
        let mut sector = vec![0u8; crate::SECTOR_SIZE];
        fill(&*parent, 0, &mut sector)?;
        let mbr = crate::parse_mbr_sector(&sector).map_err(|_| VfsError::Unsupported {
            layer: "MbrVolumes",
            scheme: "MBR".to_string(),
        })?;

        let volumes = mbr
            .entries
            .iter()
            .filter(|e| !e.is_empty())
            .enumerate()
            .map(|(i, e)| VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: u64::from(e.lba_start).saturating_mul(sector_size),
                len: u64::from(e.lba_count).saturating_mul(sector_size),
                type_hint: Some(format!("0x{:02X}", e.type_code.0)),
                label: None,
            })
            .collect();
        Ok(Self { parent, volumes })
    }
}

impl VolumeSystem for MbrVolumes {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let v = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "mbr volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(self.parent.clone(), v.start, v.len)))
    }
}

#[cfg(test)]
mod tests {
    use super::MbrVolumes;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{DynSource, VolumeKind, VolumeScheme, VolumeSystem};
    use std::sync::Arc;

    /// The real DFTT-corpus MBR sector (public domain), whose table `mmls` 4.12.1
    /// and `fdisk` independently re-decoded (Tier-1 oracle; see
    /// `tests/data/README.md`). The fixture is only sector 0, so this validates
    /// the table mapping — the `SubRange` windowing itself is proven on the full
    /// GPT image in the sibling `gpt` crate.
    fn real_mbr() -> DynSource {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/dftt_mmls_1_mbr.dd"
        );
        Arc::new(FileSource::open(path).expect("open real MBR fixture"))
    }

    #[test]
    fn mbr_volumes_match_mmls_fdisk_oracle() {
        let vs = MbrVolumes::open(real_mbr()).expect("real MBR must parse");
        assert_eq!(vs.scheme(), VolumeScheme::Mbr);

        let vols = vs.volumes();
        assert_eq!(vols.len(), 2, "two used primaries (slots 2,3 empty)");

        // mmls answer key, 512-byte sectors: start = lba_start*512, len = count*512.
        // 0: NTFS/exFAT (0x07)  lba_start 128,   count 55296
        assert_eq!(vols[0].kind, VolumeKind::Partition);
        assert_eq!(vols[0].start, 128 * 512);
        assert_eq!(vols[0].len, 55296 * 512);
        assert_eq!(vols[0].type_hint.as_deref(), Some("0x07"));
        // 1: NTFS/exFAT (0x07)  lba_start 55424, count 61440
        assert_eq!(vols[1].start, 55424 * 512);
        assert_eq!(vols[1].len, 61440 * 512);
        assert_eq!(vols[1].type_hint.as_deref(), Some("0x07"));
    }

    #[test]
    fn open_volume_ok_for_valid_err_for_invalid() {
        let vs = MbrVolumes::open(real_mbr()).expect("parse");
        assert!(vs.open_volume(0).is_ok());
        assert!(vs.open_volume(99).is_err());
    }
}
