# 5. Normalize findings onto `forensicnomicon::report::Finding`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet must emit findings in one shared vocabulary so that
ORCHESTRATION (`disk4n6`, Issen) and a future GUI can render them uniformly
instead of handling N bespoke `XxxAnalysis` types (`ronin-issen/CLAUDE.md`, "The
Reporting Model — `forensicnomicon::report`"). Before this change the MBR analyzer
returned a private anomaly type that no other layer understood.

## Decision

Keep the typed, MBR-specific `AnomalyKind` (the domain knowledge — one variant per
detectable condition, `forensic/src/findings.rs`) but convert it to the canonical
`forensicnomicon::report::Finding` model (commits `02297b5`/`4da3ba7`,
"normalize onto forensicnomicon::report"). Each condition carries a stable,
scheme-prefixed SCREAMING-KEBAB `code` (`MBR-PART-OVERLAP`, `MBR-GPT-SPOOFED`,
`MBR-EBR-CYCLE`, …; the full table is the published contract in `README.md`) and a
graded `Severity` (`Info < Low < Medium < High < Critical`). Findings are
observations, never legal conclusions — the anomaly notes use "consistent with"
phrasing and leave the conclusion to the examiner or tribunal (`README.md`,
"Findings are observations, never legal conclusions"). The offset of each anomaly
is surfaced via the finding's evidence (commit `ab12d06`), and `MBR-BOOT-UNKNOWN`
carries the raw leading boot-code bytes so an unrecognised loader can be
identified rather than merely reported as "unknown" (commits `117ee45`/`1fc0c92`,
matching the constitution's "show the unrecognized value" rule).

## Consequences

MBR findings aggregate into one `forensicnomicon::report::Report` alongside every
other analyzer's, so the orchestrator renders them without MBR-specific code. The
`code` strings are a permanent contract: a shipped code is never repurposed, and
new conditions get new codes. Because knowledge lives in `AnomalyKind` and only
the *shape* is canonical, `forensicnomicon` never has to enumerate every MBR
anomaly. Consumers matching the shared enums must carry a `_` arm, since the model
is `#[non_exhaustive]` and evolves additively.
