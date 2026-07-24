# 7. GPT cross-check via the sibling `gpt-partition-forensic`, on by default

Date: 2026-07-24
Status: Accepted

## Context

A protective or hybrid MBR is a pointer to a GUID Partition Table: the real
partition layout lives in the GPT, and the forensically interesting conditions —
a protective entry smaller than the disk (`MBR-GPT-UNDERSIZED`), a GPT header with
no protective entry (`MBR-GPT-HIDDEN`), a spoofed protective layout
(`MBR-GPT-SPOOFED`), or a hybrid MBR (`MBR-GPT-HYBRID`) — can only be judged by
reading both. The fleet already publishes a dedicated GPT parser,
`gpt-partition-forensic`, and the constitution's Dependency Preference rule is to
prefer our own crates over reimplementing, while Batteries-Included says a
capability an examiner needs must be compiled in by default, not hidden behind a
feature they must know to enable.

## Decision

When a protective MBR is detected, parse the real GPT automatically via the
sibling `gpt-partition-forensic` and cross-check it (commits `19ace84`/`78243e8`,
"auto-parse GPT via gpt-forensic when detected"). Expose this behind a **default**
`gpt` feature (`forensic/Cargo.toml`: `default = ["gpt"]`,
`gpt = ["dep:gpt-partition-forensic"]`), so the zero-config path is the capable
one; a consumer that genuinely wants MBR-only analysis can opt out with
`default-features = false`. Consume the sibling from the crates.io registry once
published rather than by path (commit `50f7338`, "gpt-partition-forensic via
registry"), per the fleet's registry-over-path rule, and widen the requirement as
it releases (commits `27ab805`, `2faf23e` `0.5 → 0.6`; workspace pin
`gpt-partition-forensic = "0.6"`).

## Consequences

A GPT/UEFI disk is analyzed end to end from one call with no extra wiring, and MBR
and GPT findings are reconciled in one report. This crate does not reimplement GPT
parsing — the one audited GPT parser serves the whole fleet, and its fixes flow in
on a version bump. The default feature pulls `gpt-partition-forensic` (and its
`forensicnomicon` transitive) into the default graph; opting out is available but
non-default, keeping the safe, capable behavior for the reader who configures
nothing.
