# Validation

`mbr-partition-forensic` parses untrusted MBR partition tables, EBR chains, and
boot-sector bytes from potentially compromised disk images. Correctness for
forensic tooling is established the way it must be: against **independent
oracles** (a different tool, or a different code path, that already decodes the
same bytes correctly) on **real third-party corpora** with known ground truth —
never against fixtures we hand-encoded and then graded ourselves.

This page records, honestly, what backs each capability today — so the claim is
independently re-checkable. **The current test suite is built entirely from
in-code synthetic fixtures: there is no `tests/data/` corpus, no
`include_bytes!` real image, and no external partition-table oracle wired in.**
That is stated plainly below rather than dressed up, and the gap — validating
against `fdisk`-produced tables and The Sleuth Kit's `mmls` on real disk images
— is recorded as recommended future work. Honesty about a synthetic-only gap is
the point of this page.

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
> evidence tiers defined here. By the evidence-tier definition above, every test
> in the suite is **Tier 3** today, because every fixture and its expected answer
> are authored in the same repo.

## Independent oracles

**None at present.** No external tool (`fdisk`, `parted`, The Sleuth Kit
`mmls`/`fsstat`) and no third-party reference parser is invoked by any test in
this repo. The closest thing to an independent check is an internal
*cross-crate code path* (see below), which is genuinely separate code but still
runs on a fixture we authored — so it is Tier 2 at best, not an independent
oracle on real data.

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **`gpt-forensic` (sibling crate)** — auto-invoked on a protective MBR | Separate crate, but **fleet-owned**, and the fixture is hand-built | That a synthetic protective-MBR + GPT disk round-trips through the GPT parser (`forensic/tests/gpt_integration_tests.rs:44`) | 2 |
| **`forensicnomicon::bootkit` markers** | Fleet-owned knowledge crate (not third-party) | Boot-code matching logic against our own marker table (`forensic/src/bootkit.rs:8`, `forensic/tests/bootkit_tests.rs`) | 3 |

### Recommended oracles to close the gap

These would lift the core capabilities from Tier 3 to Tier 1 and are the
recommended next step:

- **The Sleuth Kit `mmls`** — the standard independent partition-table walker.
  Run `mmls disk.img` and reconcile partition start LBA, length, and type code
  against `analyse(...)` on the same image. This is the natural ground-truth
  oracle for primary entries and EBR logical partitions.
- **`fdisk -l` / `sfdisk --dump`** — generate real MBR and extended/EBR layouts
  with `fdisk` (legacy CHS-aligned and modern 1 MiB-aligned), then validate the
  parser against `fdisk`'s own readout of the table it wrote. `sfdisk --dump`
  gives a machine-parseable answer key.
- **A real disk image with a known partition table** — e.g. a CFReDS / public
  CTF image, committed (first sectors only) with provenance, to back the boot
  sector and partition-geometry fields the way `ntfs-forensic` backs its boot
  sector against TSK `fsstat`.

## Independent test corpora

**None at present.** There is no `tests/` directory at the repo root and no
`tests/data/README.md`; every test fixture is constructed in Rust inside the
test files (helpers such as `make_sector`, `disk()`, `gpt_disk()`,
`disk_with_boot_code()`). No real disk image is committed or fetched.

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| *(none)* | — | All tests use in-code synthetic byte buffers | — |

**Recommended:** add a repo-root `tests/data/` plus `tests/data/README.md`
(per the fleet Test-Data Provenance standard) holding the first sectors of a
real `fdisk`/`mmls`-validated disk image, and register it in
`issen/docs/corpus-catalog.md`.

## Per-capability validation

Every capability below is currently **Tier 3** (synthetic fixture authored
alongside its expected answer). The backing test file is named for each so the
exact construction is re-checkable, and the recommended independent oracle is
noted.

| Capability | Tier | Backing test | Recommended independent oracle |
|---|---|---|---|
| Boot-sector / partition-table parse (signature, entries, LBA, status) | 3 | `forensic/tests/tier_a_table_tests.rs`, `forensic/tests/mbr_tests.rs` | TSK `mmls`, `sfdisk --dump` |
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

# A single capability, e.g. CHS↔LBA consistency or the GPT cross-check
cargo test -p mbr-partition-forensic --test chs_lba_tests
cargo test -p mbr-partition-forensic --test gpt_integration_tests
```

To add the recommended independent-oracle check (not yet in the repo), the shape
would be:

```bash
# Generate a real MBR table and read back the ground truth
fdisk -l disk.img            # or: sfdisk --dump disk.img
mmls disk.img                # TSK partition walk

# then assert analyse(disk.img) matches mmls/sfdisk start-LBA, length, type
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

Until an independent oracle on real disk images is wired in, treat the suite as
**proof of internal consistency and robustness, not yet proof of real-world
decode correctness**. Closing that gap with `mmls` / `fdisk` is the recommended
next step.
