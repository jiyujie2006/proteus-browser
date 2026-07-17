# Architecture Decision Records

ADRs capture the *load-bearing* decisions — the ones that are expensive to
reverse and that shape everything downstream. Each records the context, the
options weighed, the decision, and the consequences, so future contributors
understand *why*, not just *what*. New significant decisions should add an ADR
here and be referenced from the relevant doc/PR.

Format: lightweight [MADR](https://adr.github.io/madr/)-style.

## Index

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-license-apache-2.md) | Apache-2.0 for our code (over MIT) | Accepted |
| [0002](0002-dual-engine-no-cross-family.md) | Dual native engine; never impersonate across families | Accepted |
| [0003](0003-tunnel-not-mitm.md) | Preserve network fingerprint by tunneling, not MITM | Accepted |
| [0004](0004-tauri-manager.md) | Tauri (Rust + OS webview) for the Manager | Accepted |
| [0005](0005-native-over-injection.md) | Native engine production over JS injection | Accepted |
| [0006](0006-config-driven-single-binary.md) | One engine binary, N identities via signed config | Accepted |

## Proposed / future ADRs (not yet written — flagged where the doc calls for them)

- **Sync cryptographic protocol** — required *before* implementing
  [tdd/08](../tdd/08-sync-and-collaboration.md); must include external crypto
  review. (Principle IV honesty about our own limits.)
- **Config propagation mechanism** — Mojo interface vs. serialized blob for
  getting the config into renderers ([tdd/01](../tdd/01-chromium-engine.md) §3);
  decide after M0/M1 prototyping.
- **Build infrastructure** — hosted runners vs. self-hosted farm, once M0 measures
  real build/rebase times ([tdd/05](../tdd/05-build-and-tracking.md)).
