# 04 — System Architecture

This document defines the components, their boundaries, the data that flows
between them, and the contracts that hold them together. Subsystem internals live
in the [TDDs](tdd/); this is the map that shows how they connect.

> **Implementation status:** this document describes the target system. Today,
> the bounded M1A Rust signed-config core and independent Node conformance checks
> are implemented. The Chromium M0 contracts and GitHub-hosted reference
> workflow are implemented, but its production runner/controller backend is not
> and no authenticated engine binary has passed the six-build hard gate; native
> config ingest, fingerprint surfaces, cross-context
> propagation, Manager, sidecar, and UI do not exist. One real
> Proteus-authored layer0 patch is the active M0 input; it only defaults
> Google-backed Network Time querying off and is not a complete de-Google
> claim. Sixteen later-milestone specifications are held in separate backlogs.
> The hard M0 build exit is still evidence-gated;
> see [M0.md](../M0.md) and [M1A.md](../M1A.md).

## 1. Design constraints that shape the architecture

- **One engine binary, N identities.** We must *not* compile a binary per
  profile — that would make the build/tracking treadmill impossible. All
  per-identity difference is injected at launch via configuration. (Principle
  VIII.)
- **Native values, set before first script.** The config must be parsed and
  applied in the engine *before any page JavaScript runs*, in every process
  (browser + all renderers + workers). (Principle III.)
- **Tunnel, don't MITM.** The network component must not terminate TLS, so the
  origin sees the real engine handshake. (Principle II/bet 3.)
- **Local-first, encrypted.** Sensitive data stays on device; sync is
  zero-knowledge. (Principle V.)
- **Process isolation per profile.** A crash, leak, or compromise in one profile
  must not touch another.

## 2. Component overview

```
┌───────────────────────────────────────────────────────────────────────┐
│  MANAGER  (Tauri: Rust core + Web UI)                                   │
│  ───────────────────────────────────────────────────────────────────   │
│  • Profile library      • Proxy library        • Team/collab (opt)      │
│  • Fingerprint engine (embedded lib, runs fully local)                  │
│  • Verification lab launcher                    • No-code RPA runtime    │
│  • Encrypted storage (SQLCipher + OS keychain)  • Importers             │
└───────┬───────────────────────────────────────────────┬────────────────┘
        │ (1) generate/resolve profile                   │ (5) E2E-encrypted
        │     → signed config blob                        │     ciphertext only
        ▼                                                 ▼
┌───────────────────────────┐                   ┌──────────────────────────┐
│ FINGERPRINT ENGINE (lib)   │                   │ SYNC BACKEND (optional,   │
│ • real-distribution data   │                   │ self-hostable, Rust)      │
│ • constraint sampler       │                   │ • zero-knowledge blobs    │
│ • rule validator           │                   │ • object storage          │
│ • rarity scorer            │                   └──────────────────────────┘
│ • deterministic from seed  │
└───────────────────────────┘
        │ (2) signed per-profile config JSON (schema-versioned)
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│  ENGINE PROCESS  (one per launched profile)                            │
│  ┌──────────────────────────────┐   ┌───────────────────────────────┐  │
│  │ MODIFIED ENGINE               │   │ NETWORK SIDECAR (Go, per      │  │
│  │ (Chromium-mod OR Firefox-mod) │   │ profile)                      │  │
│  │ • applies config pre-script   │   │ • upstream proxy chain        │  │
│  │ • native fp surfaces          │◀─▶│   (HTTP/SOCKS5/SSH/WireGuard) │  │
│  │ • anti-CDP                     │(3)│ • DoH resolver (no DNS leak)  │  │
│  │ • stealth CDP endpoint ───────┼──▶│ • WebRTC-leak guard           │  │
│  │ • encrypted profile data dir  │(4)│ • tunnel passthrough (no MITM)│  │
│  └──────────────────────────────┘   │ • QUIC/H3 policy              │  │
│                 ▲                     └───────────────────────────────┘  │
└─────────────────┼───────────────────────────────────────────────────────┘
                  │ (4) automation: Playwright/Puppeteer/Selenium/RPA
                  ▼
          Automation clients
```

## 3. Components and responsibilities

### Manager (Rust core + Web UI, packaged with Tauri)
The user-facing control plane and the only long-lived process besides sync.
Owns the profile and proxy libraries, embeds the fingerprint engine as a library,
manages encrypted storage and OS-keychain keys, launches engine processes and
their sidecars, hosts the no-code RPA runtime, and drives the verification lab.
Chosen as Tauri for a small, memory-safe (Rust) core with a web UI and good
cross-platform packaging, without shipping a second Chromium just for the UI.
Detail: [tdd/07](tdd/07-manager-and-storage.md).

### Fingerprint engine (embedded Rust library)
Pure, local, no network required. The target library samples a coherent identity
from real-world distributions, validates it, scores its rarity, and emits a
deterministic per-profile config. M1A currently implements that pipeline for
Chrome 150 on Windows 11 desktop/laptop using a transparent versioned **seed
heuristic** dataset; its rarity score is not calibrated population telemetry.
Being a library (not a service) keeps generation offline and reproducible.
Detail: [tdd/02](tdd/02-fingerprint-engine.md).

### Modified engine (Chromium-family or Firefox-family)
The heart. A patched browser that reads the signed config at startup and produces
all fingerprint surfaces natively, applies anti-CDP measures, exposes a stealth
CDP endpoint for automation, and stores its profile data in an encrypted
directory. One binary per engine family serves all profiles of that family.
This remains target architecture, not current implementation. The active M0
layer0 file is a real, bounded Network Time default-off patch; it implements no
signed-config ingest or fingerprint/automation surface. The other 16 authored
files remain M1/M3 metadata-only backlog specifications and are not current
build inputs. Detail: [tdd/01](tdd/01-chromium-engine.md) and the
Firefox/Camoufox integration notes therein.

### Network sidecar (Go, one per profile)
A per-profile local proxy the engine points at. It builds the upstream proxy
chain, resolves DNS over HTTPS to prevent leaks, guards against WebRTC leaks,
applies QUIC/H3 policy, and — critically — **tunnels** rather than terminating
TLS, preserving the engine's real handshake. Go for the mature uTLS/uquic
ecosystem and easy cross-compilation. Detail:
[tdd/03](tdd/03-network-layer.md).

### Sync backend (optional, self-hostable Rust service)
Stores only end-to-end-encrypted blobs the user holds keys to; never sees
plaintext. Ships as a Docker Compose one-liner for self-hosting. Detail:
[tdd/08](tdd/08-sync-and-collaboration.md).

## 4. Key data flows

**(1)–(2) Profile launch (target).** User clicks "launch." Manager resolves the profile:
if fingerprint fields are unset, the fingerprint engine samples+validates+scores
them from the persona + seed; the result is serialized to the **profile config**
(§6), signed, and handed to the engine via a launch channel. The engine parses it
*before* any script runs and configures all processes.

**(3) Engine ↔ sidecar.** The engine is launched pointing at the sidecar's local
listener as its proxy. All engine traffic egresses through the sidecar's chain;
DNS is forced through DoH; WebRTC is constrained. TLS is never terminated by the
sidecar.

**(4) Automation.** Clients (Playwright/Puppeteer/Selenium or the RPA runtime)
attach to the engine's stealth CDP endpoint. The endpoint avoids the
`Runtime.enable` leak and exposes no automation tells.

**(5) Sync.** If enabled, encrypted profile blobs replicate to the sync backend
as ciphertext; keys never leave the client.

## 5. Trust & isolation boundaries

- **Per-profile process + data isolation.** Each launched profile is its own
  engine process, its own sidecar, and its own encrypted data directory. No
  shared renderer, no shared cookie jar, no shared cache.
- **Config is signed.** M1A implements Ed25519 signing and fail-closed library
  verification against a strict trust-store abstraction; its CLI loads a JSON
  public-key store. The target browser engine will perform equivalent
  verification before ingest. Protected installation-scoped trust-anchor
  provisioning and that native path are not implemented yet.
- **Sidecar is local-only.** The sidecar binds to loopback (or an isolated
  namespace) and is reachable only by its paired engine.
- **Sync sees ciphertext only.** The boundary between client and sync backend is
  a zero-knowledge boundary; see [tdd/08](tdd/08-sync-and-collaboration.md).
- **Keys in OS keychain.** Master keys live in the platform keychain, not in the
  database.

## 6. The central contract: the profile config

Everything hinges on a versioned, signed JSON document the fingerprint engine
produces and the engine consumes. It is the API between "what identity to
present" and "the browser that presents it." Its schema is the most important
interface in the system and is versioned independently so engine and Manager can
evolve on the treadmill.

Illustrative shape (full JSON Schema in [schemas/](schemas/) — this is a
readable digest, not the normative spec):

```jsonc
{
  "schemaVersion": "1.0.0",
  "profileId": "uuid",
  "seed": "base64-32-bytes",          // deterministic noise/derivation root
  "engine": {
    "family": "chromium",             // "chromium" | "firefox" — never crossed
    "brand": "Chrome",                // Chrome|Edge|Brave|Opera (chromium) / Firefox
    "majorVersion": 126,
    "fullVersion": "126.0.6478.127"
  },
  "persona": {                        // the coherent "one real device"
    "os": { "name": "Windows", "version": "10", "arch": "x86_64" },
    "device": { "class": "desktop", "model": null }
  },
  "navigator": {
    "userAgent": "…",                 // derived from engine+persona, not free-typed
    "platform": "Win32",
    "languages": ["en-US", "en"],
    "hardwareConcurrency": 8,
    "deviceMemory": 8,
    "vendor": "Google Inc."
  },
  "clientHints": {                    // must derive from userAgent/persona
    "brands": [ /* Sec-CH-UA */ ],
    "fullVersionList": [ /* … */ ],
    "platform": "Windows",
    "platformVersion": "10.0.0",
    "bitness": "64",
    "model": "",
    "mobile": false
  },
  "screen": {
    "width": 1920, "height": 1080,
    "availWidth": 1920, "availHeight": 1040,
    "colorDepth": 24, "devicePixelRatio": 1.0
  },
  "gpu": {
    "webglVendor": "Google Inc. (NVIDIA)",
    "webglRenderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 …)",
    "webgpuAdapter": { /* vendor/arch/limits */ }
  },
  "fonts": { "set": ["…"], "policy": "os-superset-restricted" },
  "media": {
    "devices": [ /* enumerateDevices shape, OS-appropriate */ ],
    "speechVoices": [ /* OS-appropriate TTS voices */ ]
  },
  "locale": {
    "timezone": "America/New_York",   // must match proxy geo
    "acceptLanguage": "en-US,en;q=0.9",
    "intlLocale": "en-US"
  },
  "noise": {                          // deterministic from seed, bounded
    "canvas": { "mode": "perturb", "amplitude": "hw-natural" },
    "webgl":  { "mode": "perturb", "amplitude": "hw-natural" },
    "audio":  { "mode": "perturb", "amplitude": "hw-natural" },
    "clientRects": { "mode": "subpixel" }
  },
  "network": {                        // hints for the sidecar
    "quicPolicy": "match-brand",
    "webrtcPolicy": "proxy-only"
  },
  "performance": { "timerPrecisionMicros": 100 },
  "rarity": {                         // M1A: informational seed heuristic
    "score": 0.87, "verdict": "blends-in", "reasons": []
  },
  "provenance": {
    "datasetVersion": "…", "datasetSha256": "…", "engineVersion": "…",
    "rulesVersion": "…", "generatorVersion": "…"
  },
  "signature": {
    "algorithm": "Ed25519",
    "canonicalization": "RFC8785",
    "domain": "proteus-profile-config/v1",
    "keyId": "installation-key-id",
    "value": "base64-signature"
  }
}
```

Design notes on the contract:
- **Derived, not free-form.** UA, Client Hints, and locale are *derived* by the
  fingerprint engine from engine+persona+proxy so they cannot drift into
  incoherence. The Manager UI exposes persona-level choices, not raw fields, to
  prevent users from hand-crafting contradictions (Principle I).
- **Seed-deterministic.** `seed` roots all per-profile noise and derivations.
  Reproduction requires the complete versioned input set: request/persona,
  seed, engine target, dataset, rules, schema, and generator.
- **Versioned + signed.** `schemaVersion` lets engine/Manager evolve
  independently. The signature covers the v1 domain prefix, UTF-8 `keyId`, a
  NUL separator, and the canonical Profile Config body; binding the routing ID prevents alias
  substitution. `keyId` selects a protected installation trust anchor.
- **Constrained canonical JSON.** M1A implements canonicalization for the strict
  Profile Config value domain and locks it with Rust↔Node vectors. The
  envelope's `RFC8785` label is not a claim of a general-purpose arbitrary-JSON
  RFC 8785 library.
- **Sidecar hints, not sidecar config.** Network-relevant fields (QUIC/WebRTC
  policy) are hints the Manager also passes to the sidecar so the two stay
  consistent; the sidecar's proxy credentials come from the proxy library, not
  this document (secrets stay out of the fingerprint config).

## 7. Cross-cutting concerns

- **Versioning:** engine, config schema, and dataset each version
  independently; the Manager records which triple produced a profile.
- **Observability:** local, private structured logs per component; no data
  leaves the machine. The verification lab is the primary correctness signal.
- **Failure handling:** if the sidecar dies, the engine's network fails
  closed (no direct-egress fallback that would leak the real IP). If config
  signature verification fails, the target engine refuses to launch. M1A
  already enforces fail-closed behavior in its standalone reload/verifier; the
  Chromium launch path remains to be implemented.
- **Portability:** because a profile is `{persona, seed, versions, data dir}`,
  export/import is well-defined and competitor-import maps onto the same shape.

## 8. Where each concern is specified

| Concern | Document |
|---|---|
| Engine patches & surfaces | [tdd/01-chromium-engine.md](tdd/01-chromium-engine.md) |
| Config generation, rules, rarity | [tdd/02-fingerprint-engine.md](tdd/02-fingerprint-engine.md) |
| Sidecar, proxy, TLS/H2, leaks | [tdd/03-network-layer.md](tdd/03-network-layer.md) |
| Anti-CDP & automation | [tdd/04-anti-automation.md](tdd/04-anti-automation.md) |
| Build, tracking, reproducibility | [tdd/05-build-and-tracking.md](tdd/05-build-and-tracking.md) |
| Verification & regression | [tdd/06-verification-lab.md](tdd/06-verification-lab.md) |
| Manager & storage | [tdd/07-manager-and-storage.md](tdd/07-manager-and-storage.md) |
| Sync & collaboration | [tdd/08-sync-and-collaboration.md](tdd/08-sync-and-collaboration.md) |
| Config schema (normative) | [schemas/profile-config.schema.json](schemas/profile-config.schema.json) |
