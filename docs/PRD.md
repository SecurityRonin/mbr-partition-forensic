# mbr-partition-forensic — Purpose & Scope

This is a **library**, not a runnable tool. It has no PRD: examiners never invoke
it directly. The examiner-facing command line is the `disk4n6` orchestrator
(`disk-forensic`), which auto-detects the partitioning scheme and dispatches to
this crate for MBR disks. This document records what the library is for, what it
covers, and what it deliberately leaves out. The rationale behind each structural
decision lives in [`docs/decisions/`](decisions/).

## Purpose

Most MBR crates enumerate the partitions that exist. This one analyzes what was
done to the disk: structural anomalies, gap and slack-space content, wipe and
bootkit indicators, and CHS/LBA/GPT/VBR cross-checks — each returned as a graded,
machine-readable `forensicnomicon::report::Finding`. It is the MBR node in the
fleet's partition-scheme parser family (siblings: `gpt-partition-forensic`,
`apm-forensic`), all composable with the container readers (`ewf`, `vmdk`,
`vhdx`, `vhd`, `qcow2`, `dd`) and reconciled by `disk4n6`.

## Consumers

- **`disk4n6` / `disk-forensic`** — the orchestrator that renders findings for an
  examiner and reconciles MBR/GPT/APM results.
- **`forensic-vfs-engine`** — composes the MBR as a `VolumeSystem` (behind the
  `vfs` feature, ADR 0004) so a stack like `E01 → MBR → NTFS` reads as one
  `ImageSource`.
- **Rust developers** who need a read-only MBR decoder (`mbr-partition-core`) or a
  graded MBR analyzer (`mbr-partition-forensic`) inside their own tool.

## What it does

Two crates, one dependency (ADR 0001):

- **`mbr-partition-core`** (imported as `mbr`) — pure, read-only decode over
  `Read + Seek`: the 512-byte boot sector, four primary entries, EBR chains,
  CHS/LBA geometry, GPT and VBR cross-validation primitives, boot-code identity,
  and filesystem fingerprints. No findings.
- **`mbr-partition-forensic`** — layers anomaly detection on top and emits graded
  findings (ADR 0005). It re-exports every reader type, so one dependency yields
  both. When a protective MBR is found, the real GPT is parsed and cross-checked
  automatically via `gpt-partition-forensic` (ADR 0007).

Detection surface (the stable `code` contract is tabulated in the README): reserved
and status-byte anomalies, boot-flag issues, deleted-partition residue, duplicate
and overlapping and out-of-bounds ranges, CHS↔LBA disagreement, declared-type vs
detected-filesystem mismatch, hybrid/undersized/hidden/spoofed GPT protective-MBR
conditions, EBR cycles/depth/slack, pre/mid/post gaps and wiped gaps, carved slack
artifacts, VBR hidden-sector disagreement, wiped/erased/unknown boot code, and
high-entropy slack. Partitioner-era attribution (LBA-63 vs 1 MiB alignment) is
exposed as a conservative inference, not an anomaly (`forensic/src/provenance.rs`).

## Artifact family

MBR / MS-DOS partition tables and their extensions: the master boot record and its
446-byte boot code, the four primary partition entries, Extended Boot Record (EBR)
chains for logical partitions, Volume Boot Records (VBR) for hidden-sector
cross-checks, and the protective/hybrid MBR that fronts a GPT. Logical (4Kn)
sector sizes are supported via `analyse_with_options` (`AnalyseOptions`,
`forensic/src/analyse.rs`).

## Scope

- Decode every documented on-disk MBR structure robustly over untrusted input.
- Grade each detectable condition as a `forensicnomicon::report::Finding` with a
  stable code and severity, phrased as an observation, never a legal conclusion.
- Cross-check against GPT and VBR where the MBR points at them.
- Compose into the universal container/VFS abstraction (ADR 0004).

## Non-goals

- **No command-line tool of its own** — rendering and scheme dispatch belong to
  `disk4n6` (ADR 0002).
- **No filesystem parsing** — reading the data inside a partition is the job of
  the filesystem crates (`ntfs-forensic`, `ext4fs-forensic`, …); this library
  fingerprints the first sector only.
- **No full GPT/APM analysis** — those are the sibling crates; this library
  calls `gpt-partition-forensic` for the protective-MBR cross-check and stops
  there.
- **No mutation** — the library is read-only; it never writes to the source
  image.

## Validation approach

Correctness is established against independent oracles on real corpora, tiered by
who confirms the check (full detail in [`validation.md`](validation.md)). The
primary partition-table parse is validated at **Tier 1**: a real Brian-Carrier
DFTT disk image (`tests/data/dftt_mmls_1_mbr.dd`) is parsed and reconciled against
The Sleuth Kit's `mmls` and `fdisk` (`forensic/tests/real_mbr_oracle.rs`). The
remaining capabilities (CHS↔LBA, EBR chain, bootkit, wipe/gap, VBR, era) are
currently backed by in-code synthetic fixtures (**Tier 3**); extending the
real-image corpus to cover them is the recorded next step. Robustness is enforced
by `forbid(unsafe)`, panic-free lints, and two `cargo-fuzz` targets (ADR 0006).
