# mbr-forensic

[![Crates.io](https://img.shields.io/crates/v/mbr-forensic.svg)](https://crates.io/crates/mbr-forensic)
[![docs.rs](https://img.shields.io/docsrs/mbr-forensic)](https://docs.rs/mbr-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/mbr-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/mbr-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Forensic-grade Master Boot Record (MBR) parser for Rust. Goes beyond partition enumeration to surface structural anomalies, slack-space content, anti-forensic indicators, and cross-field inconsistencies that every other MBR crate silently ignores.

```text
MBR Forensic Analysis
  disk signature : 0x00000000
  boot code      : AllZeros
  partitioning   : Unknown

Partition table (1 entries):
  [0] GPT Protective MBR       LBA            1..=8191          fs=Unknown

Anomalies (2):
  [INFO] MBR-BOOT-PROTECTIVE-EMPTY @ 0x0: MBR boot code is empty (all zeros), which is expected on a GPT/UEFI disk — the protective MBR's boot code is never executed
  [INFO] MBR-BOOT-NONE @ 0x1be: No partition is marked bootable

GPT cross-check: 2 partition entries, 0 GPT anomalies

Highest severity: INFO
```

`mbr-forensic` is a **library** (use `mbr_forensic::report::text_report` to render
the above; when a protective MBR is found the real GPT is parsed automatically via
[`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) and cross-checked).
For a ready-made command line that auto-detects the scheme and prints this for
*any* disk, install the unified
[`disk4n6`](https://github.com/SecurityRonin/disk-forensic) tool
(`cargo install disk-forensic`).

## Rust library

```toml
[dependencies]
mbr-forensic = "0.1"
```

## Quick start

```rust
use mbr_forensic::{parse_mbr_sector, analyse};
use std::fs::File;

// Pure parsing from a 512-byte buffer — no I/O, no panics:
let mut f = File::open("disk.img")?;
let analysis = analyse(&mut f, disk_size_bytes)?;

for anomaly in &analysis.anomalies {
    println!("[{:?}] offset {:#x}  {}", anomaly.severity, anomaly.offset, anomaly.note);
}
# Ok::<(), mbr_forensic::Error>(())
```

## What makes this different from every other MBR crate

Most MBR crates answer one question: "what partitions are on this disk?" `mbr-forensic` answers the questions a digital forensics examiner actually needs:

| Feature | Other MBR crates | mbr-forensic |
|---|---|---|
| Partition enumeration | ✅ | ✅ |
| Boot code identification (GRUB 2, Windows, Syslinux …) | ✗ | ✅ |
| Wiped / erased boot code detection | ✗ | ✅ |
| Residual (deleted) partition entries | ✗ | ✅ |
| Declared type vs detected filesystem mismatch | ✗ | ✅ |
| Unpartitioned gap analysis (pre / between / post) | ✗ | ✅ |
| Extended partition EBR chain traversal | partial | ✅ full |
| EBR slack-byte inspection | ✗ | ✅ |
| EBR cycle / excessive-depth detection | ✗ | ✅ |
| NT disk serial (offset 440) | ✗ | ✅ |
| Reserved byte audit (offset 444–445) | ✗ | ✅ |
| CHS ↔ LBA cross-validation | ✗ | ✅ |
| Shannon entropy on slack regions | ✗ | ✅ |
| Adversarial-input hardening + fuzz testing | ✗ | ✅ |

## Anomaly types

Every detected condition is returned as an `Anomaly { severity, kind, offset, note }`:

```
NonZeroReserved          bytes 444–445 non-zero
MultipleBootable         > 1 partition has 0x80 status
NoBootablePartition      active partitions but none marked bootable
ResidualEntry            type=0x00 but non-zero LBA fields → deleted partition
OverlappingPartitions    LBA range intersection between two entries
OutOfBounds              partition end exceeds reported disk size
ChsLbaInconsistency      CHS-encoded values disagree with LBA
EbrCycle                 EBR next-pointer forms a loop
EbrExcessiveDepth        EBR chain exceeds 64 levels
EbrSlackData             EBR entries 2–3 contain non-zero bytes
PrePartitionSpace        sectors before the first partition
InterPartitionGap        unpartitioned space between partitions
PostPartitionSpace       trailing space after the last partition
SignatureMismatch        declared type ≠ detected filesystem magic
WipedBootCode            boot code is all zeros
ErasedBootCode           boot code is all 0xFF
UnknownBootCode          boot code matches no known signature
HighEntropySlack         high-entropy bytes in a slack region
```

## Filesystem fingerprinting

`mbr-forensic` reads the first sector of each partition and matches it against known magic bytes, independently of the declared partition type. A mismatch between the declared type and the detected filesystem is surfaced as a `SignatureMismatch` anomaly.

Detected filesystem types: `Ext` (ext2/3/4), `Ntfs`, `Fat`, `ExFat`, `Apfs`, `Xfs`, `LinuxSwap`, `LinuxLvm`, `Luks`, `AllZeros`, `Unknown`.

## Boot code identification

The first 446 bytes of the MBR are matched against signatures for known bootloaders:

| `BootCodeId` | Description |
|---|---|
| `Windows7Plus` | Windows 7 / Server 2008 R2 and later |
| `WindowsVista` | Windows Vista / Server 2008 |
| `Grub2` | GRUB 2 boot.img |
| `GrubLegacy` | GRUB Legacy stage1 |
| `Syslinux` | Syslinux / EXTLINUX |
| `AllZeros` | Wiped — all zeros |
| `AllOnes` | Erased — all 0xFF |
| `Unknown` | No known signature matched |

## API

### Parse a raw 512-byte MBR sector (pure, no I/O)

```rust
use mbr_forensic::parse_mbr_sector;

let sector = std::fs::read("disk.img")?;
let mbr = parse_mbr_sector(&sector[..512])?;

println!("Disk serial: {:#010X}", mbr.disk_serial);
for (i, entry) in mbr.entries.iter().enumerate() {
    if !entry.is_empty() {
        println!("  [{i}] type={} lba={} count={}", entry.type_code.name(), entry.lba_start, entry.lba_count);
    }
}
# Ok::<(), mbr_forensic::Error>(())
```

### Full forensic analysis from any `Read + Seek`

```rust
use mbr_forensic::analyse;
use std::fs::File;

let mut f = File::open("disk.img")?;
let meta = f.metadata()?;
let analysis = analyse(&mut f, meta.len())?;

println!("Boot code: {:?}", analysis.boot_code_id);
println!("Partitions: {}", analysis.partitions.len());
println!("Gaps: {}", analysis.gaps.len());
println!("Anomalies: {}", analysis.anomalies.len());

for a in analysis.anomalies.iter().filter(|a| a.severity >= mbr_forensic::Severity::Medium) {
    println!("  [{:?}] {}", a.severity, a.note);
}
# Ok::<(), mbr_forensic::Error>(())
```

### Entropy analysis on slack regions

```rust
use mbr_forensic::entropy;

let slack = &sector[446..512]; // example: partition table area
let e = entropy::shannon(slack);
if e > 6.0 {
    println!("High-entropy slack ({e:.2} bits/byte) — possible hidden data");
}
```

## Security

`mbr-forensic` is designed for use on untrusted disk images from potentially compromised systems:

- **No panics on malicious input** — all arithmetic uses checked or saturating operations; fuzz-tested with `cargo fuzz`
- **EBR cycle detection** — visited-LBA set prevents infinite loops
- **Overflow-safe EBR chain** — `checked_add` terminates the chain on arithmetic overflow
- **Depth cap** — EBR chains exceeding 64 levels are flagged and stopped
- **Truncation-safe** — read errors on truncated images terminate traversal gracefully rather than propagating

### Running the fuzz targets

```bash
# Requires nightly Rust and cargo-fuzz
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run parse_mbr_sector
cargo +nightly fuzz run analyse_full
```

## Debugging with the `trace` feature

`mbr-forensic` has no logging dependency by default. Enable the `trace` feature to forward every analysis event — each recorded anomaly, the run summary, EBR walk failures, and partition read errors — to the [`tracing`](https://docs.rs/tracing) ecosystem:

```toml
[dependencies]
mbr-forensic = { version = "0.1", features = ["trace"] }
```

```rust
tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
let analysis = mbr_forensic::analyse(&mut reader, disk_size)?;
// → DEBUG analyse: anomaly recorded code="MBR-PART-OVERLAP" severity=CRITICAL offset=0x1be ...
# Ok::<(), mbr_forensic::Error>(())
```

All diagnostics live in one place (`src/diag.rs`), so the full set of observable events is discoverable at a glance.

## Testing

224 tests (unit + integration) covering every public API, every error path, every anomaly kind, and adversarial inputs (overflowing EBR chains, truncated images, seek failures). **100% function coverage with no uncovered lines** — verified in CI.

```bash
cargo test                 # default features
cargo test --features trace
```

For coverage:

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --show-missing-lines
```

> Aggregate line coverage can read slightly under 100% because the generic, reader-agnostic functions are monomorphized once per reader type in the tests; `--show-missing-lines` confirms no source line is left uncovered.

## Related

**mbr-forensic** analyses the partition layout. To read the actual filesystem data that lives inside each partition, these crates provide `Read + Seek` over common disk container formats:

| Crate | Format |
|---|---|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / Expert Witness Format (EnCase, FTK Imager) |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK sparse/monolithic |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX (Hyper-V, Azure) |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD (Virtual PC / Hyper-V Gen-1) |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QEMU / KVM QCOW2 |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / dd images |

## Sibling crates

One forensic parser per partitioning scheme — each a pure `Read + Seek` library that composes with the container crates above:

| Crate | Scheme |
|---|---|
| [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) | GUID Partition Table (UEFI) — backup-header reconciliation, CRC32, phantom entries; called automatically when this crate detects a protective MBR |
| [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) | Apple Partition Map (classic Mac and hybrid optical media) |
| [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) | **Orchestrator** — point it at any disk; it auto-detects MBR/GPT/APM and dispatches to the right parser |

For forensic integrity analysis of container formats:

| Crate | Format |
|---|---|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 structural audit, Adler-32 repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX integrity analysis |

---

[Privacy Policy](https://securityronin.github.io/mbr-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/mbr-forensic/terms/) · © 2026 Security Ronin Ltd
