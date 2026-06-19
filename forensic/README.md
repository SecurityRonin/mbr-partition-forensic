# mbr-partition-forensic

[![Crates.io: mbr-partition-forensic](https://img.shields.io/crates/v/mbr-partition-forensic.svg?label=mbr-partition-forensic)](https://crates.io/crates/mbr-partition-forensic)
[![Crates.io: mbr-partition-core](https://img.shields.io/crates/v/mbr-partition-core.svg?label=mbr-partition-core)](https://crates.io/crates/mbr-partition-core)
[![docs.rs](https://img.shields.io/docsrs/mbr-partition-forensic)](https://docs.rs/mbr-partition-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/SecurityRonin/mbr-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/mbr-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Every other MBR crate tells you what partitions exist. This one tells you what someone did to the disk** — structural anomalies, gap and slack-space carving, wipe and bootkit indicators, and CHS/LBA/GPT/VBR cross-checks, each returned as a graded, machine-readable finding.

```bash
cargo add mbr-partition-forensic
```

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
[INFO]     MBR-BOOT-PROTECTIVE-EMPTY @ 0x0    Empty boot code on a GPT/UEFI disk (expected)
[CRITICAL] MBR-PART-OVERLAP          @ 0x1ce  LBA ranges of partitions 0 and 1 intersect
[HIGH]     MBR-SLACK-ENTROPY         @ 0x200  High-entropy slack (7.91 bits/byte) — possible hidden data
```

When a protective MBR is found, the real GPT is parsed automatically (default
`gpt` feature, backed by
[`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic)) and
cross-checked.

## Reader + analyzer

This crate is the **analyzer**: it layers anomaly detection on top of the
[`mbr-partition-core`](https://crates.io/crates/mbr-partition-core) **reader**
and emits graded
[`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)
values. It re-exports every reader type (`parse_mbr_sector`, `MbrSector`,
`PartitionEntry`, `EbrChain`, `BootCodeId`, `DetectedFs`, `Error`, …), so a
single dependency gives you both the raw decode and the findings.

```toml
[dependencies]
mbr-partition-forensic = "0.4"
```

Entry points: `analyse(reader, disk_size_bytes)` and
`analyse_with_options(reader, disk_size_bytes, AnalyseOptions)` return an
`MbrAnalysis { boot_code_id, partitions, gaps, anomalies, .. }`. Each anomaly is
an `Anomaly { severity, kind, offset, note }`; `kind.code()` is the stable
machine-readable code.

## Anomaly codes

Stable, scheme-prefixed codes (a published contract — they do not change once
shipped) with a graded `Severity` (`Info` < `Low` < `Medium` < `High` <
`Critical`):

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
draws the conclusion. Bootkit and high-entropy findings are reported as
"consistent with", not as a verdict.

## Trust but verify

Built to run on untrusted disk images from potentially compromised systems:

- **Panic-free on malicious input** — bounds-checked reads, checked/saturating
  arithmetic; no `unwrap`/`expect`/`panic!` in production code (enforced by
  `clippy::unwrap_used`/`expect_used = deny`).
- **EBR hardening** — a visited-LBA set prevents infinite loops
  (`MBR-EBR-CYCLE`), `checked_add` terminates on overflow, and a 64-level depth
  cap stops runaway chains (`MBR-EBR-DEPTH`); reads on truncated images
  terminate traversal gracefully.
- **Fuzzed** — `cargo fuzz` targets `fuzz_parse` (the pure parser) and
  `fuzz_forensic` (the full pipeline); the invariant is "must not panic".
- **Validated against real artifacts**, not only synthetic fixtures, with the
  full suite verified in CI.

```bash
cargo +nightly fuzz run fuzz_parse
cargo +nightly fuzz run fuzz_forensic
```

## Features

| Feature | Effect |
|---|---|
| `gpt` *(default)* | Cross-checks a protective MBR against the real GPT via [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic) |
| `trace` | Forwards every analysis event to the [`tracing`](https://docs.rs/tracing) ecosystem |
| `serde` | Derives `Serialize`/`Deserialize` on the public types |

For a ready-made command line that auto-detects MBR/GPT/APM and prints findings
for *any* disk, install the unified
[`disk4n6`](https://github.com/SecurityRonin/disk-forensic) tool
(`cargo install disk-forensic`).

---

[Privacy Policy](https://securityronin.github.io/mbr-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/mbr-partition-forensic/terms/) · © 2026 Security Ronin Ltd
