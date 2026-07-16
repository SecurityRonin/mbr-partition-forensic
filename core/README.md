# mbr-partition-core

[![Crates.io: mbr-partition-core](https://img.shields.io/crates/v/mbr-partition-core.svg?label=mbr-partition-core)](https://crates.io/crates/mbr-partition-core)
[![Crates.io: mbr-partition-forensic](https://img.shields.io/crates/v/mbr-partition-forensic.svg?label=mbr-partition-forensic)](https://crates.io/crates/mbr-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/mbr-partition-core)](https://docs.rs/mbr-partition-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/SecurityRonin/mbr-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/mbr-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A pure, read-only Master Boot Record parser — decode the boot sector, partition table, and EBR chain from a 512-byte buffer or any `Read + Seek`, with no I/O of its own, input-fuzzed and panic-free by construction on hostile input.**

```bash
cargo add mbr-partition-core
```

```rust
use mbr::parse_mbr_sector;

let sector = std::fs::read("disk.img")?;
let mbr = parse_mbr_sector(&sector[..512])?;

println!("Disk serial: {:#010X}", mbr.disk_serial);
for (i, entry) in mbr.entries.iter().enumerate() {
    if !entry.is_empty() {
        println!("  [{i}] {} lba={} count={}", entry.type_code.name(), entry.lba_start, entry.lba_count);
    }
}
# Ok::<(), mbr::Error>(())
```

The crate is published as `mbr-partition-core` but imported as `mbr` (`[lib] name = "mbr"`).

## What it decodes

This is the structure-decode layer. It deliberately contains **no** anomaly
findings — the analyzer that grades these structures lives in the sibling
[`mbr-partition-forensic`](https://crates.io/crates/mbr-partition-forensic)
crate, which re-exports every type here.

| Module | Decodes |
|---|---|
| `mbr` | `parse_mbr_sector` — the 512-byte boot sector, NT disk signature, four primary `PartitionEntry` records |
| `partition` | `PartitionEntry`, `TypeCode` → `PartitionFamily`, `Chs` geometry and `chs_consistency` CHS↔LBA cross-check |
| `ebr` | `walk_ebr_chain` over a `Read + Seek` — Extended Boot Record traversal yielding an `EbrChain` |
| `gpt` | `has_gpt_header` — protective-MBR / GPT presence check |
| `vbr` | `parse_bpb` — BIOS Parameter Block (hidden-sector count, geometry) from a volume boot record |
| `signature` | `detect` — filesystem fingerprint (`DetectedFs`) from a partition's first sector; `type_conflicts` |
| `boot_code` | `identify` — bootloader fingerprint (`BootCodeId`) from the first 446 bytes |
| `disk_signature` | `find_signature_collisions` — duplicate NT disk-signature detection across images |
| `carve` | `carve` / `extract_ascii_strings` — magic-byte file carving and string extraction over a byte slice |

The only error type is `Error` (`TooShort`, `BadSignature`, `Io`).

## Trust but verify

Built to run on untrusted disk images:

- **Panic-free** — bounds-checked reads and checked/saturating arithmetic; no
  `unwrap`/`expect`/`panic!` in production code (enforced by
  `clippy::unwrap_used`/`expect_used = deny`).
- **EBR hardening** — `walk_ebr_chain` uses a visited-LBA set against cycles,
  `checked_add` against overflow, and a depth cap against runaway chains; read
  errors on truncated images terminate traversal gracefully.
- **Fuzzed** — the `fuzz_parse` cargo-fuzz target drives the sector parser; the
  invariant is "must not panic".

## Features

| Feature | Effect |
|---|---|
| `trace` | Forwards diagnostic events to the [`tracing`](https://docs.rs/tracing) ecosystem |
| `serde` | Derives `Serialize`/`Deserialize` on the public types |

For graded forensic findings, gap analysis, slack-space carving, and wipe /
bootkit detection, use
[`mbr-partition-forensic`](https://crates.io/crates/mbr-partition-forensic).

---

[Privacy Policy](https://securityronin.github.io/mbr-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/mbr-partition-forensic/terms/) · © 2026 Security Ronin Ltd
