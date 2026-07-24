# 2. Pure library — no shipped binary; the front-end is `disk4n6`

Date: 2026-07-24
Status: Accepted

## Context

Early versions shipped a `mbr-forensic` binary with a `text_report` renderer
(commit `ceac0e3`, "feat(cli): GREEN — mbr-forensic binary + text_report
renderer"). In the fleet's layer architecture (`ronin-issen/CLAUDE.md`,
"Multi-Repo Architecture"), a partition-scheme parser is a CONTAINER/PARSER-tier
library: it is *linked*, not *run*. The examiner-facing command line is the
unified `disk4n6` orchestrator (`disk-forensic`), which auto-detects the
partitioning scheme and dispatches to the right parser — MBR, GPT, or APM. A
per-crate CLI duplicates that surface, drags a rendering concern into a data
library, and inflates the compile graph for every consumer.

## Decision

Remove the binary and the text renderer; make this repo a pure data library
(commits `bee614c`, "refactor!: drop the CLI binary — mbr-forensic is now a pure
library"; `098ef2c`, "refactor!: remove text_report — mbr-forensic is a pure data
library"). The only remaining binaries in the workspace are the two `cargo-fuzz`
targets (`fuzz/fuzz_targets/fuzz_parse.rs`, `fuzz_forensic.rs`), which are test
harnesses, not a shipped tool. Human-readable rendering of the analyzer's output
is owned by `disk4n6`; the library returns structured data
(`MbrAnalysis`, graded `forensicnomicon::report::Finding` values) for that
orchestrator to render.

## Consequences

This repo is **library tier**: it has no examiner-runnable artifact of its own.
Its purpose and scope are captured in [`docs/PRD.md`](../PRD.md), which records
what the library is for rather than a product spec. Callers
get a stable data API and choose their own presentation; the one canonical CLI
rendering lives in `disk4n6`, so there is one place to fix a formatting bug
instead of N. The trade-off is that anyone wanting a quick command line must
install `disk-forensic` rather than this crate — an accepted cost, since the
scheme auto-detection belongs at the orchestration layer anyway.
