# 8. Declared MSRV floor below the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet's MSRV policy (`ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain") keeps
two numbers separate: the **dev toolchain** everyone builds/fmt/clippy with (one
pinned current stable across the fleet, `rust-toolchain.toml`) and the **declared
MSRV** (`rust-version`, a downstream-facing promise). Both crates here are
*published libraries* — third parties link them — so the declared MSRV is a real
compatibility feature and must stay a low, CI-verified floor, not track the dev
pin. Raising a library's MSRV narrows its crates.io audience and is treated as a
near-breaking change.

## Decision

Pin the dev toolchain to the fleet's current stable — `channel = "1.96.0"` with
`rustfmt` and `clippy` components declared in `rust-toolchain.toml` (commit
`d29c884`, "pin rust-toolchain 1.96.0 with rustfmt+clippy components") — while
declaring a lower MSRV floor of `rust-version = "1.85"` in `[workspace.package]`,
inherited by both members (`Cargo.toml`). Develop on the newest stable; promise
only the older floor the libraries actually need.

## Consequences

Contributors and CI share one toolchain, ending fmt/clippy drift, while downstream
consumers on an older-than-1.96 toolchain can still build the crates down to
1.85. The gap must be maintained deliberately: a bump to the declared floor is a
conscious, documented change, and CI is the only thing that keeps 1.85 honest.

The specific choice of **1.85** (rather than the fleet's more common 1.75/1.80
library floors) is the minimum the current dependency graph resolves under, raised
to whatever the transitive requirements demand. Rationale reconstructed from
structure; original intent not recovered in available history — the exact reason
the floor sits at 1.85 rather than lower is not documented in the commit history.
