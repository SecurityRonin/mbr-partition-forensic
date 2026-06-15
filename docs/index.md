# mbr-partition-forensic

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

When a protective MBR is found, the real GPT is parsed automatically (via the default `gpt` feature, backed by [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic)) and cross-checked.

## Two crates, one dependency

| Crate | Role |
|---|---|
| [`mbr-partition-core`](https://crates.io/crates/mbr-partition-core) | **Reader** — pure, read-only MBR decode over `Read + Seek`: the 512-byte boot sector, four primary entries, EBR chains, CHS/LBA geometry, GPT/VBR cross-validation primitives, boot-code and filesystem fingerprints. No findings. Imported as `mbr`. |
| [`mbr-partition-forensic`](https://crates.io/crates/mbr-partition-forensic) | **Analyzer** — layers anomaly detection on top and emits graded `forensicnomicon::report::Finding` values. Re-exports every reader type, so a single dependency gives you both. |

```toml
[dependencies]
mbr-partition-forensic = "0.4"   # analyzer (re-exports the reader)
# or, reader only:
mbr-partition-core = "0.4"
```

## Anomaly codes

Each detected condition carries a stable, machine-readable `code` and a graded `Severity` (`Info` < `Low` < `Medium` < `High` < `Critical`). Codes are a published contract — they do not change once shipped. A representative sample:

| `code` | Condition |
|---|---|
| `MBR-PART-OVERLAP` | LBA ranges of two partitions intersect |
| `MBR-PART-RESIDUAL` | Type `0x00` but non-zero LBA fields — deleted partition residue |
| `MBR-PART-SIGMISMATCH` | Declared type ≠ detected filesystem magic |
| `MBR-BOOT-MALWARE` | Boot code matches a known bootkit signature |
| `MBR-GPT-HYBRID` | Hybrid MBR (MBR and GPT both describe partitions) |
| `MBR-EBR-CYCLE` | EBR next-pointer chain forms a loop |
| `MBR-GAP-WIPED` | A gap region carries a deliberate wipe pattern |
| `MBR-SLACK-ENTROPY` | High-entropy bytes in a slack region — possible hidden data |

The full set (30 codes) is listed in the project [README](https://github.com/SecurityRonin/mbr-partition-forensic). Findings are observations, never legal conclusions — the examiner or tribunal draws the conclusion.

## Trust but verify

`mbr-partition-forensic` is built to run on untrusted disk images from potentially compromised systems: panic-free on malicious input (bounds-checked reads, checked/saturating arithmetic, `unwrap_used`/`expect_used = deny`), EBR hardening (visited-LBA cycle detection, 64-level depth cap, overflow-terminating walks), truncation-safe traversal, `cargo fuzz` targets over both the pure sector parser and the full analysis pipeline, and validation against real artifacts.

See the project [README](https://github.com/SecurityRonin/mbr-partition-forensic) for the full API, anomaly-code table, filesystem and boot-code fingerprinting, and sibling-crate map.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
