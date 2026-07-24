# 3. `forensicnomicon` as the single knowledge leaf

Date: 2026-07-24
Status: Accepted

## Context

Both crates need format facts that are shared across the fleet: MBR partition
type-code names, boot-loader fingerprints, known bootkit markers, and filesystem
magic-byte signatures with their byte offsets. Re-deriving these tables per crate
is the recurring DRY-plus-robustness failure the constitution warns against —
copies drift, and an offset transcribed by hand (the APFS/Btrfs/LVM case, commit
`9b9f8c5`, "correct APFS/Btrfs/LVM offsets via forensicnomicon
(libblkid-verified)") ships wrong. `forensicnomicon` is the fleet's KNOWLEDGE
leaf: zero-dep, compile-time artifact specs and format constants, depended on
*down* by every analyzer and depending on no one (`ronin-issen/CLAUDE.md`,
"forensicnomicon" and "Dependency direction").

## Decision

Source all cross-fleet format knowledge from `forensicnomicon` and let both
crates depend down onto it (`core/Cargo.toml` and `forensic/Cargo.toml`:
`forensicnomicon.workspace = true`; workspace pin `forensicnomicon = "1.6"`):

- `TypeCode::name` is sourced from `forensicnomicon`
  (commits `5ee5729`/`f4fa5cd`, "TypeCode names from forensicnomicon").
- Bootkit markers (`5d980f3`), boot-code fingerprints (`d48f729`), and filesystem
  magics (`dd36269`) are all deduplicated onto the leaf rather than kept as local
  literals.

The dependency arrow is strictly one way: `mbr-partition-core` and
`mbr-partition-forensic` depend on `forensicnomicon`; `forensicnomicon` never
depends back.

## Consequences

A correction to a magic offset or a new type code lands once in `forensicnomicon`
and every analyzer inherits it, rather than N crates each carrying a stale copy.
The crates track `forensicnomicon`'s major line (the workspace floats `"1.6"` and
has moved 0.3 → 0.5 → 0.11 → 1.x across the history, commits `c30ccf9`,
`697661f`, `09f3af0`), so a `forensicnomicon` bump is a coordinated fleet event.
Local knowledge is limited to what is genuinely MBR-specific and not shared.
