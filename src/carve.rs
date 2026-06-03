//! File-signature carving and string extraction over raw byte regions.
//!
//! Unpartitioned gaps and slack retain remnants of deleted files — leftover
//! data with direct forensic implications. [`carve`] recovers file *headers* by
//! magic bytes; [`extract_ascii_strings`] surfaces embedded paths, URLs, and
//! notes. Both are pure functions over a caller-supplied slice, so a caller can
//! apply them to any region (a gap window, EBR slack, the whole disk).
//!
//! Carving reports header *locations*, not full file boundaries — it identifies
//! that a recoverable artifact begins at an offset, which is the forensic signal
//! for unallocated space. Magics are kept ≥ 3 bytes to bound false positives.

/// A file header recovered from a byte region by its magic signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedFile {
    /// Short type label, e.g. `"PNG"`, `"ZIP"`, `"PDF"`.
    pub kind: &'static str,
    /// Absolute byte offset of the header (caller's `base_offset` + position).
    pub offset: u64,
}

/// A file-type magic signature: a `kind` label and the leading `magic` bytes.
#[derive(Debug, Clone, Copy)]
pub struct FileMagic {
    pub kind: &'static str,
    pub magic: &'static [u8],
}

/// Curated table of well-known file-header magics (all ≥ 3 bytes).
pub const FILE_MAGICS: &[FileMagic] = &[
    FileMagic { kind: "ZIP", magic: b"PK\x03\x04" },
    FileMagic { kind: "PDF", magic: b"%PDF-" },
    FileMagic { kind: "PNG", magic: b"\x89PNG\r\n\x1a\n" },
    FileMagic { kind: "JPEG", magic: b"\xFF\xD8\xFF" },
    FileMagic { kind: "GIF", magic: b"GIF87a" },
    FileMagic { kind: "GIF", magic: b"GIF89a" },
    FileMagic { kind: "BZIP2", magic: b"BZh" },
    FileMagic { kind: "7Z", magic: b"7z\xBC\xAF\x27\x1C" },
    FileMagic { kind: "RAR", magic: b"Rar!\x1A\x07" },
    FileMagic { kind: "XZ", magic: b"\xFD7zXZ\x00" },
    FileMagic { kind: "ELF", magic: b"\x7FELF" },
    FileMagic { kind: "RIFF", magic: b"RIFF" },
    FileMagic { kind: "SQLite", magic: b"SQLite format 3\x00" },
    FileMagic { kind: "OLE", magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" },
    FileMagic { kind: "CAB", magic: b"MSCF" },
];

/// Carve `data` for every known file-header magic, returning each match's type
/// and **absolute** offset (`base_offset` + position within `data`).
///
/// `base_offset` is the absolute disk byte offset that `data[0]` came from, so
/// the returned offsets are directly usable as disk locations.
#[must_use]
pub fn carve(data: &[u8], base_offset: u64) -> Vec<CarvedFile> {
    let mut out = Vec::new();
    for sig in FILE_MAGICS {
        let m = sig.magic;
        if m.is_empty() || m.len() > data.len() {
            continue;
        }
        for (i, window) in data.windows(m.len()).enumerate() {
            if window == m {
                out.push(CarvedFile {
                    kind: sig.kind,
                    offset: base_offset + i as u64,
                });
            }
        }
    }
    out.sort_by_key(|c| c.offset);
    out
}

/// Lowest printable ASCII byte (space).
const ASCII_MIN: u8 = 0x20;
/// Highest printable ASCII byte (tilde).
const ASCII_MAX: u8 = 0x7E;

/// Extract runs of printable ASCII (`0x20`–`0x7E`) at least `min_len` bytes long.
///
/// The classic `strings(1)` behaviour: surfaces paths, URLs, banners, and notes
/// left in unallocated space. Non-printable bytes terminate a run.
#[must_use]
pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for &b in data {
        if (ASCII_MIN..=ASCII_MAX).contains(&b) {
            run.push(b);
        } else {
            flush(&mut run, min_len, &mut out);
        }
    }
    flush(&mut run, min_len, &mut out);
    out
}

/// Emit the accumulated run as a string if it meets `min_len`, then clear it.
fn flush(run: &mut Vec<u8>, min_len: usize, out: &mut Vec<String>) {
    if run.len() >= min_len {
        // Bytes are guaranteed printable ASCII, so this is always valid UTF-8.
        out.push(String::from_utf8_lossy(run).into_owned());
    }
    run.clear();
}
