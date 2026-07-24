# 1. Reader/analyzer split into a two-crate workspace

Date: 2026-07-24
Status: Accepted

## Context

MBR analysis has two separable concerns: decoding the on-disk structures (the
512-byte boot sector, four primary entries, EBR chains, CHS/LBA geometry, GPT and
VBR cross-validation primitives, boot-code and filesystem fingerprints) and
turning those structures into graded forensic findings. A single crate would
force a consumer that only wants a read-only partition-table parser to compile the
whole anomaly-detection surface, and would prevent the analyzer from being reused
against structures other tools already hold.

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates one workspace repo named
`<x>-forensic` with a `core/` reader crate (`<x>-core`) and a `forensic/`
analyzer crate (`<x>-forensic`). The bare `mbr` name is a generic, taken
namespace on crates.io, so the reader cannot publish as `mbr`; the naming grammar
resolves this by publishing the reader as `mbr-partition-core` while keeping the
import path `mbr`.

## Decision

Split the repository into a two-member Cargo workspace
(`Cargo.toml` `members = ["core", "forensic"]`, commit `0c872c5`,
"refactor!: split into mbr-partition-core + mbr-partition-forensic workspace"):

- **`core/` → `mbr-partition-core`** — the pure, read-only decoder over
  `Read + Seek`, emitting structures only and no findings
  (`core/src/lib.rs`: "This crate is the structure-decode layer. It deliberately
  contains **no** anomaly findings"). It publishes as `mbr-partition-core` but
  sets `[lib] name = "mbr"` (`core/Cargo.toml`), so consumers write `use mbr::…`
  and the taken bare name is sidestepped without hijacking a popular import path.
- **`forensic/` → `mbr-partition-forensic`** — the anomaly auditor. It re-exports
  every reader type (`forensic/src/lib.rs`: `pub use mbr::{…}`), so a single
  dependency gives a caller both the reader and the analyzer.

Shared package fields (version, edition, MSRV, license, repository) and
dependency versions are declared once in `[workspace.package]` /
`[workspace.dependencies]` and inherited by both members (commit `89480d3`,
"workspace dependency/version inheritance (DRY)").

## Consequences

A downstream Rust tool that only needs to read an MBR depends on
`mbr-partition-core` alone and never compiles the analyzer. The analyzer keeps a
single entry-point surface via re-exports, so existing call sites such as
`mbr_partition_forensic::partition::TypeCode` keep working. The split obliges the
analyzer to depend on the reader (the default arrow) unless a finding genuinely
needs lower-level access; today the analyzer builds entirely on
`mbr-partition-core`. Version and MSRV bumps touch one workspace table instead of
every member.
