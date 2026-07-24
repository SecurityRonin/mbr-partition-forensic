# 4. `forensic-vfs` `VolumeSystem` adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS standard (`ronin-issen/CLAUDE.md`, "VFS & Universal Container
Abstraction") requires that a consumer reading an evidence image not special-case
one partitioning scheme against another: a stack such as
`E01 → GPT → BitLocker → NTFS` should compose as one `Arc<dyn ImageSource>`.
`forensic-vfs` is the KNOWLEDGE-leaf contract crate for that composition — the
`ImageSource` positioned-byte edge plus the `VolumeSystem` trait. For MBR to
participate as a volume system, it must expose its primary partitions as
composable byte windows.

Wiring that in unconditionally would drag the whole `forensic-vfs` dependency
graph into every consumer of the bare parser — including the many that only want
to decode a 512-byte sector and never touch the VFS.

## Decision

Implement `forensic-vfs`'s `VolumeSystem` for the MBR as `core::vfs::MbrVolumes`,
gated behind an optional, non-default `vfs` feature (`core/Cargo.toml`:
`vfs = ["dep:forensic-vfs"]`, `forensic-vfs = { version = "0.2", optional = true }`;
commits `4682432`/`82f173d`, "MbrVolumes implements forensic-vfs VolumeSystem",
validated against the `mmls`/`fdisk` oracle). The adapter wraps a parent
`ImageSource` and exposes the four MBR **primary** partitions as `VolumeDesc`s,
each openable as a `SubRange` byte window; LBAs are addressed in the disk's
512-byte logical sectors, matching what `mmls`/`fdisk` assume
(`core/src/vfs.rs`). The bare parser (`default = []`) carries none of this. The
`Cargo.toml` comment records this feature-gating decision by number ("ADR 0004").

## Consequences

MBR plugs into the universal container abstraction, so a stack over an MBR disk
composes through `forensic-vfs-engine` like any other scheme, and no consumer
special-cases `if mbr { … }`. Consumers who only decode sectors pay nothing: the
VFS dependency is absent unless `vfs` is enabled. Logical partitions inside an
extended partition (the EBR chain) are not yet exposed as volumes — only the four
primary slots — and are a recorded follow-up (`core/src/vfs.rs` module doc).
`forensic-vfs` is pinned at `0.2`; a contract major bump is a coordinated fleet
update.
