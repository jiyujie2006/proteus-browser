# ADR 0004 — Tauri (Rust + OS webview) for the Manager

**Status:** Accepted · **Date:** 2026 · **Serves:** Principles V, IX

## Context

The Manager is the desktop control plane: profile/proxy libraries, encrypted
storage, engine+sidecar orchestration, verification-lab UI, RPA. It needs a rich
UI, cross-platform packaging, and a secure, capable core (crypto, process
management, embedding the Rust fingerprint engine). We must choose an app
framework.

## Options

1. **Electron** — Chromium + Node. Ubiquitous, rich ecosystem. **Bundles a full
   Chromium** for the UI, heavy memory/disk, JS core.
2. **Tauri** — Rust core + the **OS's native webview** for UI. Small binaries,
   memory-safe core, good packaging.
3. **Native per-OS UI** (e.g., Qt/SwiftUI/WinUI) — maximal fit, maximal effort,
   poor cross-platform reuse.
4. **A web app** — no; we need local process orchestration, OS keychain, and
   filesystem-level encryption that a sandboxed web app can't do.

## Decision

**Tauri** (Rust core + OS webview + web UI).

## Rationale

- **Don't ship a second Chromium.** Electron would bundle a whole Chromium *just
  for the UI* — confusing next to our *fingerprint* Chromium engine, and heavy
  when users manage hundreds of profiles. Tauri uses the OS webview, keeping the
  app light ([05-product-ux.md](../05-product-ux.md) §12).
- **Memory-safe core.** The Manager handles the crown jewels (session keys,
  cookies) and orchestrates processes. A **Rust** core aligns with our security
  posture (Principles V, IX) and lets us **embed the fingerprint engine**
  (also Rust, [tdd/02](../tdd/02-fingerprint-engine.md)) directly, no IPC/FFI
  seam.
- **Rich UI without native-UI cost.** A web UI (React/Svelte) gives us the polished
  UX that is the second battleground, cross-platform, without writing three native
  frontends.
- **Good packaging & updater** for Win/mac/Linux, fitting the signed-update flow
  ([tdd/05](../tdd/05-build-and-tracking.md) §7).

## Consequences

- UI is built with web tech (TS + a framework) over a Rust core; the fingerprint
  engine links in-process.
- **OS-webview variance** across platforms is a known cost — we keep the UI to
  well-supported webview features and maintain a test matrix
  ([tdd/07](../tdd/07-manager-and-storage.md) §13).
- Storage uses SQLCipher + OS keychain from the Rust core
  ([07-security-privacy.md](../07-security-privacy.md)).
- The Manager launches the engine and sidecar as separate processes (it is *not*
  the browser), preserving per-profile isolation.
- Contributors need Rust (core) and TS/web (UI) skills; documented in
  [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Notes

If a specific platform's webview proves too limiting for a critical view, the
fallback is a targeted native component for that view — not abandoning Tauri.
Revisit only if webview limitations block a core workflow.
