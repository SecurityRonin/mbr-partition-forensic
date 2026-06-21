# mbr-partition-forensic

[![Crates.io: mbr-partition-forensic](https://img.shields.io/crates/v/mbr-partition-forensic.svg?label=mbr-partition-forensic)](https://crates.io/crates/mbr-partition-forensic)
[![Crates.io: mbr-partition-core](https://img.shields.io/crates/v/mbr-partition-core.svg?label=mbr-partition-core)](https://crates.io/crates/mbr-partition-core)
[![docs.rs](https://img.shields.io/docsrs/mbr-partition-forensic)](https://docs.rs/mbr-partition-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/mbr-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/mbr-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Every other MBR crate tells you what partitions exist. This one tells you what someone did to the disk.** Structural anomalies, gap and slack-space carving, wipe and bootkit indicators, and CHS/LBA/GPT/VBR cross-checks — each returned as a graded, machine-readable finding.

```rust
use mbr_partition_forensic::analyse;
use std::fs::File;

let mut f = File::open("disk.img")?;
let size = f.metadata()?.len();
let analysis = analyse(&mut f, size)?;

for a in &analysis.anomalies {
    println!("[{:?}] {} @ {:#x}  {}", a.severity, a.kind.code(), a.offset, a.note);
}
# Ok::<(), mbr_partition_forensic::Error>(())
```

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

When a protective MBR is found, the real GPT is parsed automatically (via the
default `gpt` feature, backed by
[`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic)) and
cross-checked. For a ready-made command line that auto-detects the scheme and
prints this for *any* disk, install the unified
[`disk4n6`](https://github.com/SecurityRonin/disk-forensic) tool
(`cargo install disk-forensic`).

## Two crates, one dependency

| Crate | Role |
|---|---|
| [`mbr-partition-core`](https://crates.io/crates/mbr-partition-core) | **Reader** — pure, read-only MBR decode over `Read + Seek`: the 512-byte boot sector, four primary entries, EBR chains, CHS/LBA geometry, GPT/VBR cross-validation primitives, boot-code and filesystem fingerprints. No findings. Imported as `mbr`. |
| [`mbr-partition-forensic`](https://crates.io/crates/mbr-partition-forensic) | **Analyzer** — layers anomaly detection on top and emits graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon) values. Re-exports every reader type, so a single dependency gives you both. |

```toml
[dependencies]
mbr-partition-forensic = "0.4"   # analyzer (re-exports the reader)
# or, reader only:
mbr-partition-core = "0.4"
```

## Anomaly codes

Each detected condition carries a stable, machine-readable `code` and a graded
`Severity` (`Info` < `Low` < `Medium` < `High` < `Critical`). Codes are a
published contract — they do not change once shipped. The current set:

| `code` | Condition |
|---|---|
| `MBR-RESERVED-NONZERO` | Reserved bytes (444–445) are non-zero |
| `MBR-BOOT-MULTI` | More than one partition has the `0x80` boot flag |
| `MBR-BOOT-NONE` | Active partitions present, but none marked bootable |
| `MBR-DISKSIG-ZERO` | NT disk signature (offset 440) is zero |
| `MBR-BOOT-MALWARE` | Boot code matches a known bootkit signature |
| `MBR-PART-RESIDUAL` | Type `0x00` but non-zero LBA fields — deleted partition residue |
| `MBR-PART-STATUS` | Partition status byte is neither `0x00` nor `0x80` |
| `MBR-PART-DUPLICATE` | Two partition entries describe the same region |
| `MBR-PART-OVERLAP` | LBA ranges of two partitions intersect |
| `MBR-PART-OOB` | Partition end exceeds the reported disk size |
| `MBR-PART-CHSLBA` | CHS-encoded geometry disagrees with the LBA fields |
| `MBR-PART-SIGMISMATCH` | Declared type ≠ detected filesystem magic |
| `MBR-GPT-HYBRID` | Hybrid MBR (MBR and GPT both describe partitions) |
| `MBR-GPT-UNDERSIZED` | Protective MBR entry smaller than the disk |
| `MBR-GPT-HIDDEN` | GPT header present but no protective MBR entry |
| `MBR-GPT-SPOOFED` | Protective MBR layout inconsistent with the GPT |
| `MBR-EBR-CYCLE` | EBR next-pointer chain forms a loop |
| `MBR-EBR-DEPTH` | EBR chain exceeds the depth cap (64 levels) |
| `MBR-EBR-SLACK` | EBR entries 2–3 contain non-zero (slack) bytes |
| `MBR-GAP-PRE` | Unpartitioned space before the first partition |
| `MBR-GAP-MID` | Unpartitioned gap between partitions |
| `MBR-GAP-POST` | Trailing space after the last partition |
| `MBR-GAP-WIPED` | A gap region carries a deliberate wipe pattern |
| `MBR-CARVE-ARTIFACT` | A file artifact carved from slack/gap space |
| `MBR-VBR-HIDDEN` | VBR hidden-sector count disagrees with the partition LBA |
| `MBR-BOOT-WIPED` | Boot code is all zeros — likely wiped |
| `MBR-BOOT-PROTECTIVE-EMPTY` | Empty boot code on a GPT/UEFI disk (expected; informational) |
| `MBR-BOOT-ERASED` | Boot code is all `0xFF` — likely erased |
| `MBR-BOOT-UNKNOWN` | Boot code matches no known signature — surfaces the leading boot-code bytes (hex) so the unrecognised loader can be identified |
| `MBR-SLACK-ENTROPY` | High-entropy bytes in a slack region — possible hidden data |

Findings are observations, never legal conclusions — the examiner or tribunal
draws the conclusion.

## Filesystem fingerprinting

The analyzer reads the first sector of each partition and matches it against
known magic bytes, independently of the declared partition type; a mismatch is
surfaced as `MBR-PART-SIGMISMATCH`. Detected types (`DetectedFs`): `Ext`
(ext2/3/4), `Ntfs`, `Fat`, `ExFat`, `Apfs`, `Xfs`, `LinuxSwap`, `LinuxLvm`,
`Luks`, `AllZeros`, `Unknown`.

## Boot-code identification

The first 446 bytes are matched against signatures for known bootloaders
(`BootCodeId`):

| `BootCodeId` | Description |
|---|---|
| `Windows7Plus` | Windows 7 / Server 2008 R2 and later |
| `WindowsVista` | Windows Vista / Server 2008 |
| `Grub2` | GRUB 2 boot.img |
| `GrubLegacy` | GRUB Legacy stage1 |
| `Syslinux` | Syslinux / EXTLINUX |
| `AllZeros` | Wiped — all zeros |
| `AllOnes` | Erased — all `0xFF` |
| `Unknown` | No known signature matched |

## API

### Parse a raw 512-byte MBR sector (pure, no I/O)

```rust
use mbr_partition_forensic::parse_mbr_sector;

let sector = std::fs::read("disk.img")?;
let mbr = parse_mbr_sector(&sector[..512])?;

println!("Disk serial: {:#010X}", mbr.disk_serial);
for (i, entry) in mbr.entries.iter().enumerate() {
    if !entry.is_empty() {
        println!("  [{i}] type={} lba={} count={}", entry.type_code.name(), entry.lba_start, entry.lba_count);
    }
}
# Ok::<(), mbr_partition_forensic::Error>(())
```

### Full forensic analysis from any `Read + Seek`

```rust
use mbr_partition_forensic::analyse;
use std::fs::File;

let mut f = File::open("disk.img")?;
let analysis = analyse(&mut f, f.metadata()?.len())?;

println!("Boot code: {:?}", analysis.boot_code_id);
println!("Partitions: {}", analysis.partitions.len());
println!("Gaps: {}", analysis.gaps.len());
println!("Anomalies: {}", analysis.anomalies.len());

for a in analysis.anomalies.iter().filter(|a| a.severity >= mbr_partition_forensic::Severity::Medium) {
    println!("  [{:?}] {} {}", a.severity, a.kind.code(), a.note);
}
# Ok::<(), mbr_partition_forensic::Error>(())
```

### Entropy analysis on slack regions

```rust
use mbr_partition_forensic::entropy;

let slack = &sector[446..512]; // example: partition table area
let e = entropy::shannon(slack);
if e > 6.0 {
    println!("High-entropy slack ({e:.2} bits/byte) — possible hidden data");
}
```

## Trust but verify

`mbr-partition-forensic` is built to run on untrusted disk images from
potentially compromised systems:

- **Panic-free on malicious input** — bounds-checked reads, checked/saturating
  arithmetic; no `unwrap`/`expect`/`panic!` in production code (enforced by
  `clippy::unwrap_used`/`expect_used = deny`).
- **EBR hardening** — a visited-LBA set prevents infinite loops (`MBR-EBR-CYCLE`),
  `checked_add` terminates on overflow, and a 64-level depth cap stops runaway
  chains (`MBR-EBR-DEPTH`).
- **Truncation-safe** — read errors on truncated images terminate traversal
  gracefully rather than propagating.
- **Fuzzed** — `cargo fuzz` targets `fuzz_parse` (the pure sector parser) and
  `fuzz_forensic` (the full analysis pipeline); each invariant is "must not panic".
- **Synthetic-fixture suite, honestly scoped** — every test is built from
  in-code byte buffers and verified in CI; there is no real-image corpus or
  external oracle yet. What backs each capability, the evidence tier, and the
  recommended independent oracles (TSK `mmls`, `fdisk`) are documented in
  [validation](https://securityronin.github.io/mbr-partition-forensic/validation/).

### Running the fuzz targets

```bash
# Requires nightly Rust and cargo-fuzz
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run fuzz_parse
cargo +nightly fuzz run fuzz_forensic
```

## Debugging with the `trace` feature

There is no logging dependency by default. Enable `trace` to forward every
analysis event — each recorded anomaly, the run summary, EBR walk failures, and
partition read errors — to the [`tracing`](https://docs.rs/tracing) ecosystem:

```toml
[dependencies]
mbr-partition-forensic = { version = "0.4", features = ["trace"] }
```

```rust
tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
let analysis = mbr_partition_forensic::analyse(&mut reader, disk_size)?;
// → DEBUG analyse: anomaly recorded code="MBR-PART-OVERLAP" severity=CRITICAL offset=0x1be ...
# Ok::<(), mbr_partition_forensic::Error>(())
```

All diagnostics live in one place (`src/diag.rs`), so the full set of observable
events is discoverable at a glance.

## Testing

```bash
cargo test                 # default features
cargo test --features trace
```

For coverage:

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --show-missing-lines
```

> Aggregate line coverage can read slightly under 100% because the generic,
> reader-agnostic functions are monomorphized once per reader type in the tests;
> `--show-missing-lines` confirms no source line is left uncovered.

## Related

`mbr-partition-forensic` analyses the partition layout. To read the actual
filesystem data inside each partition, these crates provide `Read + Seek` over
common disk container formats:

| Crate | Format |
|---|---|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / Expert Witness Format (EnCase, FTK Imager) |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK sparse/monolithic |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX (Hyper-V, Azure) |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD (Virtual PC / Hyper-V Gen-1) |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QEMU / KVM QCOW2 |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / dd images |

## Sibling crates

One forensic parser per partitioning scheme — each a pure `Read + Seek` library
that composes with the container crates above:

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

[Privacy Policy](https://securityronin.github.io/mbr-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/mbr-partition-forensic/terms/) · © 2026 Security Ronin Ltd
