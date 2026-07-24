# 6. Panic-free, `forbid(unsafe)`, fuzzed parsing of untrusted images

Date: 2026-07-24
Status: Accepted

## Context

This crate parses untrusted, attacker-controllable disk images from potentially
compromised systems: a lying length field, a truncated sector, an EBR
next-pointer that loops, or a CHS/LBA pair engineered to overflow must never crash
the tool or, worse, produce silently wrong output. The fleet's Paranoid Gatekeeper
standard (`ronin-issen/CLAUDE.md`, "Security & Robustness Standard") requires
never panicking, never reading out of bounds, and never trusting a length field.
Unlike the mmap-backed container readers (`ewf`, `memory-forensic`), this parser
works over `Read + Seek` and needs no `unsafe` at all, so it can take the stronger
`forbid` rather than `deny` + a bounded allow.

## Decision

Enforce the panic-free posture both statically and dynamically:

- **Static** (`Cargo.toml` `[workspace.lints]`): `unsafe_code = "forbid"`,
  `clippy::unwrap_used` and `expect_used` denied in production code (tests are
  exempted via `clippy.toml` `allow-unwrap-in-tests`), with `correctness` and
  `suspicious` denied.
- **Bounds- and overflow-safe reads**: integer fields are read from bounded
  slices; EBR traversal uses `checked_mul` for the byte offset and
  `saturating_add` for absolute LBAs so a malicious entry cannot overflow
  (`core/src/ebr.rs`).
- **EBR hardening**: a visited-LBA set breaks next-pointer loops
  (`MBR-EBR-CYCLE`) and a `MAX_DEPTH = 64` cap stops runaway chains
  (`MBR-EBR-DEPTH`, `core/src/ebr.rs`).
- **Dynamic**: two `cargo-fuzz` targets — `fuzz_parse` (the pure sector parser)
  and `fuzz_forensic` (the full analysis pipeline) — each with the invariant "must
  not panic" (`fuzz/fuzz_targets/`, `README.md` "Trust but verify"). CI runs them
  on nightly (`cargo +nightly fuzz`, commit `966db3f`, since `+nightly` beats the
  `rust-toolchain.toml` pin).

## Consequences

Malformed evidence degrades to an error or a partial result, never a crash or a
raw-pointer path, so a crafted image cannot deny an investigation. `forbid(unsafe)`
earns the memory-safety badge outright — there is no `unsafe` site to audit. The
static lints occasionally demand more verbose bounds-checked code than a quick
`unwrap` would; that verbosity is the point. The two fuzz targets are part of the
maintained surface and must keep building and smoke-running in CI.
