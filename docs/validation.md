# Validation

`mbr-partition-forensic` parses untrusted MBR partition tables, EBR chains, and
boot-sector bytes from potentially compromised disk images. Correctness for
forensic tooling is established the way it must be: against **independent
oracles** (a different tool, or a different code path, that already decodes the
same bytes correctly) on **real third-party corpora** with known ground truth —
never against fixtures we hand-encoded and then graded ourselves.

This page records, honestly, what backs each capability today — so the claim is
independently re-checkable. **The primary partition-table parse is now validated
at Tier 1**: a real third-party disk image (a Brian-Carrier DFTT corpus image)
is committed as `tests/data/dftt_mmls_1_mbr.dd`, parsed by this crate, and
reconciled against the partition table reported by The Sleuth Kit's `mmls` (and
`fdisk` for the active flag) in `forensic/tests/real_mbr_oracle.rs`. The
remaining capabilities (CHS↔LBA, the EBR chain, bootkit markers, wipe/gap
carving, VBR cross-check, era attribution) are still backed by in-code synthetic
fixtures (Tier 3) — that is stated plainly per row below, and extending the
real-image corpus to cover them (an extended/EBR image, a bootkit sample) is the
recorded next step.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

> The `Tier 0 / Tier 1 / Tier 2 / Tier 3 / Tier A` labels in the `//!` headers
> of the test files (`forensic/tests/*.rs`) are the repo's own *capability*
> grouping (which analysis layer a test exercises) and are unrelated to the
> evidence tiers defined here. By the evidence-tier definition above,
> `forensic/tests/real_mbr_oracle.rs` is **Tier 1** (real third-party image +
> independent `mmls`/`fdisk` oracle); every other test is **Tier 3**, because its
> fixture and expected answer are both authored in this repo.

## Independent oracles

**The Sleuth Kit `mmls` + `fdisk`** are wired in as the real partition-table
oracle. Both are independent codebases (neither shares code with this crate). The
internal cross-crate `gpt-forensic` path remains a Tier-2 check (separate code,
hand-built fixture).

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **TSK `mmls` 4.12.1** — on a real DFTT corpus image | **Yes** — third-party tool + third-party image | Each primary entry's start/end/length LBA and type byte vs `parse_mbr_sector(...)` and `analyse(...)` (`forensic/tests/real_mbr_oracle.rs`) | 1 |
| **`fdisk`** — on the same real image | **Yes** — third-party tool | The active/bootable flag (mmls has no such column) per entry (`forensic/tests/real_mbr_oracle.rs`) | 1 |
| **`gpt-forensic` (sibling crate)** — auto-invoked on a protective MBR | Separate crate, but **fleet-owned**, and the fixture is hand-built | That a synthetic protective-MBR + GPT disk round-trips through the GPT parser (`forensic/tests/gpt_integration_tests.rs:44`) | 2 |
| **`forensicnomicon::bootkit` markers** | Fleet-owned knowledge crate (not third-party) | Boot-code matching logic against our own marker table (`forensic/src/bootkit.rs:8`, `forensic/tests/bootkit_tests.rs`) | 3 |

### Recommended oracles to close the remaining gap

The primary-table parse is now Tier 1. To lift the still-synthetic capabilities
(EBR chain, CHS↔LBA, bootkit, wipe/gap) the next steps are:

- **TSK `mmls` on an extended-partition image** — to back the EBR logical-chain
  walk against an independent reading of real logical partitions.
- **`fdisk -l` / `sfdisk --dump`** — `fdisk` prints both CHS and LBA, giving an
  independent answer key for CHS↔LBA consistency on a real table.
- **Real captured bootkit / wiped-region samples** — to move the bootkit-marker
  and wipe-pattern rows off their hand-authored marker tables.

## Independent test corpora

One real third-party corpus is committed; the rest of the suite still uses
in-code synthetic byte buffers (helpers such as `make_sector`, `disk()`,
`gpt_disk()`, `disk_with_boot_code()`).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| `tests/data/dftt_mmls_1_mbr.dd` | Real MBR sector of `imageformat_mmls_1`, a Brian-Carrier **DFTT** corpus image (sector 0, byte-identical to the parent E01) | Primary partition-table parse vs `mmls`/`fdisk` (`forensic/tests/real_mbr_oracle.rs`) | Public DFTT test data; only the 512-byte boot sector committed |
| *(synthetic)* | In-code byte buffers | All other capability tests | — |

Provenance detail (source, hashes, extraction command, oracle output) is in
[`tests/data/README.md`](https://github.com/SecurityRonin/mbr-partition-forensic/blob/main/tests/data/README.md). **Recommended next:** add an
extended/EBR real image so the logical-chain walk also reaches Tier 1, and
register the corpus in `issen/docs/corpus-catalog.md`.

## Per-capability validation

The primary partition-table parse is **Tier 1** (real image + independent
`mmls`/`fdisk` oracle). Every other capability is **Tier 3** (synthetic fixture
authored alongside its expected answer). The backing test file is named for each
so the exact construction is re-checkable, and the recommended independent oracle
is noted.

| Capability | Tier | Backing test | Independent oracle |
|---|---|---|---|
| Boot-sector / partition-table parse (signature, entries, start/end/length LBA, type, bootable) | **1** | `forensic/tests/real_mbr_oracle.rs` (real DFTT image) | TSK `mmls` + `fdisk` (wired in) |
| Synthetic primary-table edge cases (overlaps, duplicates, OOB, status) | 3 | `forensic/tests/tier_a_table_tests.rs`, `forensic/tests/mbr_tests.rs` | TSK `mmls`, `sfdisk --dump` |
| CHS ↔ LBA decode and consistency (`MBR-PART-CHSLBA`) | 3 | `forensic/tests/chs_lba_tests.rs` | `fdisk -l` (prints both CHS and LBA) |
| EBR logical-partition chain walk (cycle / depth / slack) | 3 | `forensic/tests/tier_a_logical_tests.rs` | TSK `mmls` on an extended-partition image |
| Boot-code identification (`BootCodeId`) | 3 | `forensic/tests/mbr_tests.rs` (`identify_*`) | Real GRUB/Windows MBR samples |
| Known-bootkit marker detection | 3 | `forensic/tests/bootkit_tests.rs` (markers from `forensicnomicon`) | Real captured bootkit MBR samples |
| GPT / protective-MBR cross-validation | 2 | `forensic/tests/gpt_integration_tests.rs`, `forensic/tests/gpt_tests.rs` | TSK `mmls -t gpt`, real UEFI disk image |
| NT disk-signature checks (`MBR-DISKSIG-ZERO`) | 3 | `forensic/tests/disk_signature_tests.rs` | Real Windows disk image |
| Filesystem fingerprinting / type-vs-magic mismatch (`MBR-PART-SIGMISMATCH`) | 3 | `forensic/tests/fs_fingerprint_tests.rs` | Real NTFS/FAT/ext partition |
| VBR / BPB hidden-sector cross-check (`MBR-VBR-HIDDEN`) | 3 | `forensic/tests/vbr_tests.rs` | Real VBR from a mounted volume |
| Gap / slack carving and entropy (`MBR-GAP-*`, `MBR-SLACK-ENTROPY`) | 3 | `forensic/tests/carve_tests.rs`, `forensic/tests/boot_entropy_tests.rs` | Image with known carved artifact |
| Wipe-pattern recognition (`MBR-GAP-WIPED`, `MBR-BOOT-WIPED`) | 3 | `forensic/tests/wipe_tests.rs` | Real wiped disk region |
| Partitioner / era attribution from alignment | 3 | `forensic/tests/provenance_tests.rs` | Disks partitioned by known tools/versions |
| Unknown-boot-code evidence surfacing (raw bytes) | 3 | `forensic/tests/boot_unknown_evidence_tests.rs` | — (robustness behaviour, not a decode claim) |
| Canonical `Finding` / serde output shape | 3 | `forensic/tests/canonical_finding_tests.rs`, `forensic/tests/serde_tests.rs` | — (output-format contract, not a decode claim) |

The GPT cross-validation row is the one capability above Tier 3: the protective
MBR is parsed by `mbr-partition-core` and the real GPT is then parsed by the
**separate `gpt-forensic` crate** — an independent code path — but the disk it
runs on is still a hand-built fixture, so it is Tier 2, not an independent
oracle on real data.

## Reproducing the validation

All tests are committed and always-on (no env-gating, no external corpus):

```bash
# Whole workspace
cargo test --workspace

# Reader only
cargo test -p mbr-partition-core

# Analyzer only (all capability tests above live here)
cargo test -p mbr-partition-forensic

# The Tier-1 real-image oracle check
cargo test -p mbr-partition-forensic --test real_mbr_oracle

# A single synthetic capability, e.g. CHS↔LBA consistency or the GPT cross-check
cargo test -p mbr-partition-forensic --test chs_lba_tests
cargo test -p mbr-partition-forensic --test gpt_integration_tests
```

Re-deriving the oracle answer key for `real_mbr_oracle.rs` (the values are
`mmls`/`fdisk` output, not computed by this crate):

```bash
# mmls reads the parent E01 directly (or a sparse raw image rebuilt from sector 0)
mmls imageformat_mmls_1.E01   # start / end / length / type per partition
fdisk <raw-image>             # active (*) flag — absent here, so neither is bootable
```

## Coverage & fuzzing as backstops

Robustness is enforced by fuzzing and coverage, which are **backstops, not the
correctness claim** — they prove the parser is exercised and does not panic, not
that it decodes real-world bytes correctly (only an independent oracle on real
data does that):

- **Fuzzing** — two `cargo-fuzz` targets, `fuzz_parse` (the pure 512-byte sector
  parser) and `fuzz_forensic` (the full analysis pipeline), each with the
  invariant "must not panic" (`fuzz/fuzz_targets/`), built and smoke-run by
  `.github/workflows/fuzz.yml`.
- **Panic-free production code** — `clippy::unwrap_used` / `clippy::expect_used`
  are `deny`; reads are bounds-checked and arithmetic is checked/saturating; EBR
  traversal is bounded by a visited-LBA set, `checked_add`, and a 64-level depth
  cap.
- **Coverage** — line coverage is enforced in CI; it is a regression backstop
  that proves behaviour is exercised, not a correctness claim.

The primary partition-table parse is now proven against real-world bytes (TSK
`mmls` + `fdisk` on a DFTT image). The remaining capabilities — CHS↔LBA, the EBR
logical-chain walk, bootkit markers, wipe/gap carving, VBR cross-check, era
attribution — are still proven only for internal consistency and robustness;
extending the real-image corpus to cover them (an extended/EBR image, a bootkit
sample) is the recommended next step.
