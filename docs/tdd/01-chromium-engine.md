# TDD 01 — Chromium Engine Modification

**Status:** Design; native implementation not started · **Serves principles:**
II, III, VIII, IX · **Threat vectors:** V1, V2, V3, V5

This is the flagship engineering effort. It specifies how we turn stock Chromium
into an engine that natively produces a coherent, configurable fingerprint with
no injection traces, controlled entirely by the signed profile config, with one
binary serving all profiles.

> **Firefox note.** The Firefox-family engine is delivered by integrating and
> contributing to **Camoufox** (native MPL-2.0 Firefox patching), not by
> reimplementing this work in Gecko. This TDD is Chromium-specific; the Firefox
> integration is covered in §11.

> **Current boundary:** M1A implements the non-UI Rust generator, strict
> validator, Ed25519 envelope, standalone fail-closed verifier, and independent
> Node conformance vectors. It does **not** implement this TDD's Chromium path.
> Every listed Chromium patch remains a metadata-only placeholder, and no
> pre-script ingest, native surface, worker propagation, or engine runtime test
> exists.

## 1. Goals & non-goals

**Goals**
- Native production of every fingerprint surface in the threat model, set before
  any page script runs, consistent across main frame, iframes, dedicated/shared
  Web Workers, and Service Workers.
- One binary, N identities, via the signed config (Principle VIII).
- Zero injection traces: correct `toString`, descriptors, prototype chains.
- Rebase-friendly patch set that the tracking bot can carry forward.
- Never weaken the sandbox (Principle IX).

**Non-goals**
- Cross-family impersonation (Principle II) — no Safari costume.
- Per-profile compilation.
- Defeating behavioral (V6) or reputation (V7) vectors — out of engine scope.

## 2. Patch architecture: three layers

We maintain a layered, individually-rationalized patch series (methodology
borrowed from ungoogled-chromium and Camoufox — small patches, a series file, a
rationale header per patch).

```
patches/
  series                      # ordered list, applied top-to-bottom
  layer0-degoogle/            # remove Google telemetry/integration (ungoogled-derived)
  layer1-fingerprint/         # the config plumbing + native surfaces
    0001-config-ingest.patch
    0002-navigator-surfaces.patch
    0003-screen-surfaces.patch
    0004-canvas-noise.patch
    0005-webgl-surfaces.patch
    0006-webgpu-surfaces.patch
    0007-audio-noise.patch
    0008-font-policy.patch
    0009-timezone-locale.patch
    0010-client-hints.patch
    0011-media-devices.patch
    0012-speech-voices.patch
    0013-misc-surfaces.patch   # clientRects, performance.now, battery, gamepad…
  layer2-antiautomation/       # see TDD 04
    0001-remove-webdriver.patch
    0002-no-automation-switches.patch
    0003-stealth-cdp.patch
```

Each patch carries:
```
# Rationale: <why>
# Surface: <fingerprint surface / threat vector>
# Upstream-risk: <how likely to conflict on rebase; notes for the bot>
# Tests: <verification-lab probes that must stay green>
```

**Why layered:** layer 0 is upstream-ish and stable; layer 1 is our core IP and
changes with detection research; layer 2 is automation. The tracking bot rebases
in order and reports the first failing patch precisely (see
[tdd/05](05-build-and-tracking.md)).

## 3. The config-ingest mechanism (the linchpin)

The single most important patch. Everything else reads from it.

**Requirements**
- Parse the signed config **before** the first script executes, in the **browser
  process**, and propagate the relevant subset to **every renderer and worker
  process**.
- Values must be available synchronously to Blink surface code at first access.
- Reject an unsigned/invalid config (fail closed, Principle VI-adjacent).

**Design**
1. **Delivery:** Manager passes the config path + a launch nonce via a dedicated
   command-line switch and environment variable. At startup, the browser process
   resolves the signature envelope's `keyId` through an installation-scoped
   protected trust store, verifies the Ed25519 signature, and enforces nonce
   freshness/replay policy. A per-installation Manager public key cannot be baked
   into the shared engine binary. This native provisioning and replay path
   remains to be implemented.
2. **In-process store:** parsed into an immutable `FingerprintConfig` struct held
   in the browser process; a validated, *minimized* per-renderer view is derived
   (a renderer only needs its surfaces, not e.g. sidecar hints).
3. **Propagation:** Chromium already passes configuration to renderers via
   command-line and Mojo IPC at process creation. We add a `FingerprintConfig`
   Mojo interface / a serialized blob delivered at `RenderProcessHost` init so
   the value set is present *before* Blink initializes script. Workers inherit
   from their creating renderer through the existing worker bootstrap so
   `Worker`/`ServiceWorker` contexts see identical values (closing the V3
   cross-context leak by construction).
4. **Access:** a `blink::FingerprintConfig` accessor (thread-safe, immutable)
   that surface code queries. No global mutable state; no late injection.

**Files (illustrative, will drift with upstream):**
- `//chrome/browser` startup: switch parsing + signature verify.
- `//content/browser/renderer_host/render_process_host_impl.cc`: attach config
  to renderer init.
- `//content/renderer` + a new `blink/renderer/core/fingerprint/` module holding
  the accessor and the config mojom.
- `//third_party/blink/renderer/platform`: worker bootstrap propagation.

**Why not JS injection or an extension:** both run *after* context creation and
in *some* contexts only — they cannot satisfy "before first script, in every
context," and they leave V3 traces. Native ingest is the only path that meets the
requirement (Principle III).

## 4. Surface-by-surface specification

For each surface: what we change, where, and the consistency/trace rule it must
satisfy. Values always come from the config; noise always derives from
`config.seed`.

### 4.1 navigator.*
- **Fields:** `userAgent`, `platform`, `languages`, `vendor`,
  `hardwareConcurrency`, `deviceMemory`, `appVersion`, `oscpu` (where present).
- **Where:** `blink/renderer/core/frame/navigator.cc`,
  `navigator_ua_data.cc`, `navigator_concurrent_hardware.cc`,
  `navigator_device_memory.cc`, `navigator_language.cc`.
- **Rules:** all must derive from `engine`+`persona`; `platform` ∈ OS-appropriate
  set; `languages[0]` matches `locale.acceptLanguage` head; concurrency/memory a
  plausible *pair* for the device class (enforced upstream by the fingerprint
  engine, re-asserted here as a debug assert in dev builds).

### 4.2 Client Hints
- **Fields:** `Sec-CH-UA`, `Sec-CH-UA-Platform`, `-Platform-Version`,
  `-Full-Version-List`, `-Model`, `-Mobile`, `-Arch`, `-Bitness`.
- **Where:** the UA-CH plumbing in `//content` +
  `navigator_ua_data.cc` (the JS `navigator.userAgentData` and the HTTP request
  headers must agree).
- **Rules:** **both** the JS `userAgentData` object **and** the outgoing request
  headers derive from the same config values — a classic V1 mismatch is a UA that
  disagrees with CH. Full-version-list must be internally consistent with
  `engine.fullVersion`.

### 4.3 screen / window
- **Fields:** `width/height`, `availWidth/availHeight`, `colorDepth`,
  `pixelDepth`, `devicePixelRatio`, and the derived `window.outerWidth/Height`,
  `innerWidth/Height` relationships.
- **Where:** `core/frame/screen.cc`, and window sizing in the frame/widget.
- **Rules:** resolution+DPR must be a real, shipped combination for the persona's
  device class (dataset-backed); avail dimensions leave OS-appropriate room for
  taskbar/menubar; the *actual window* opened must be consistent with reported
  inner sizes (a headless-style 800×600 with claimed 1920×1080 is a V5 tell).

### 4.4 Canvas 2D
- **Surface:** pixel readback via `toDataURL`, `toBlob`, `getImageData`.
- **Where:** `blink/renderer/core/html/canvas/html_canvas_element.cc`
  (`ToDataURLInternal`, `toBlob`) and the 2D context's `getImageData`.
- **Design:** apply a **deterministic, per-profile, bounded** perturbation on the
  readback path, seeded by `HMAC(seed, "canvas")`. Perturbation is
  *stable across a session and across sessions for the same profile* (so the site
  sees a consistent ID, as a real device would), *different across profiles*, and
  small enough to sit inside natural driver/hardware variation (Principle I: not
  so unique it becomes an ID — coordinated with the rarity model).
- **Rule:** identical readback in main frame, worker, and offscreen canvas for
  the same profile; noise must not create impossible pixel values.

### 4.5 WebGL / WebGL2
- **Fields:** `getParameter(UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL)`,
  `VENDOR`, `RENDERER`, `VERSION`, `SHADING_LANGUAGE_VERSION`, supported
  extensions list, `getShaderPrecisionFormat`, and `readPixels` output.
- **Where:** `blink/renderer/modules/webgl/webgl_rendering_context_base.cc`
  (+ WebGL2 subclass).
- **Design:** vendor/renderer strings come from the config's `gpu` block (a real
  GPU string matched to the persona from the dataset). Extension list and
  precision are made consistent with that GPU family (a real RTX card doesn't
  expose a mobile-GPU extension set). `readPixels` gets seeded bounded noise like
  canvas.
- **Rule (critical V1):** the WebGL GPU must be *possible* on the persona's OS —
  no Apple renderer under `Win32`, no NVIDIA under an iOS persona. This pairing is
  enforced by the fingerprint engine and asserted here.

### 4.6 WebGPU (often-missed vector)
- **Fields:** `GPUAdapter` info (`vendor`, `architecture`, `device`,
  `description`), `GPUSupportedLimits`, feature set.
- **Where:** `blink/renderer/modules/webgpu/`.
- **Design:** derive adapter info/limits consistently from the same `gpu` block as
  WebGL, or report WebGPU unavailable where the persona wouldn't have it — but
  *consistently* (if WebGL says RTX 3060, WebGPU must not say Intel).
- **Why:** emerging fingerprint surface many tools ignore; an inconsistent or
  absent-where-it-should-exist WebGPU is a growing V1/V2 signal.

### 4.7 AudioContext
- **Surface:** `OfflineAudioContext` render output, `AnalyserNode` readback,
  `AudioBuffer` float data used for audio fingerprinting.
- **Where:** `blink/renderer/modules/webaudio/`.
- **Design:** seeded, extremely small perturbation on the float output
  (`HMAC(seed,"audio")`), within the natural variation of real audio stacks.
- **Rule:** deterministic per profile, consistent across contexts.

### 4.8 Fonts (hardest on Linux hosts)
- **Surface:** font enumeration via CSS `local()` matching, `document.fonts`,
  measurement-based probing (offsetWidth of rendered strings), and canvas text
  metrics.
- **Where:** `blink/renderer/platform/fonts/font_cache*.cc`, the platform
  `FontManager`, and text-metrics paths.
- **Design:** present the persona OS's **font set** — a curated superset for that
  OS version — and restrict matching so only those fonts resolve, regardless of
  what the *host* has installed. This means **bundling per-OS font packages**
  (same approach Camoufox takes) so a Linux host can convincingly present a
  Windows/macOS font profile. Metrics must reflect the *presented* fonts, not the
  host's.
- **Rule (V1):** font set ⊇ OS core set and ⊆ OS superset; metrics-based probing
  and `local()` probing agree; no host-font leakage.
- **Risk:** licensing of bundled fonts must be checked per font (see NOTICE);
  where a font can't be redistributed, use a metric-compatible substitute or omit
  and adjust the presented set coherently.

### 4.9 Timezone & locale
- **Fields:** `Intl.DateTimeFormat().resolvedOptions().timeZone`,
  `Date.prototype.getTimezoneOffset`, `Date` string rendering, `Intl` locale,
  `navigator.language(s)`, `Accept-Language`.
- **Where:** ICU timezone plumbing, V8 `Date`/`Intl` bridge, and the Accept-
  Language header path. The config's `locale.timezone` flows to all three.
- **Rule (V1, and ties to network):** `Intl` timezone == `Date` offset behavior
  == config, **and** the timezone must match the **proxy IP geolocation** (the
  Manager sets `locale.timezone` from the proxy by default — see
  [tdd/03](03-network-layer.md) and [tdd/07](07-manager-and-storage.md)).

### 4.10 WebRTC
- **Surface:** ICE candidate gathering exposing local/private IPs and the real
  public IP; mDNS `.local` candidates; device enumeration via RTP.
- **Where:** `blink/renderer/modules/peerconnection/`, plus the
  `--force-webrtc-ip-handling-policy` behavior and mDNS handling.
- **Design:** force candidate gathering through the proxy path; suppress
  host/local candidate leakage; keep behavior *consistent with a real browser
  behind a NAT/proxy* (not obviously stripped). Coordinated with the sidecar
  (tdd/03) which enforces at the network layer too — defense in depth.
- **Rule:** no real-IP leak; but the WebRTC object surface must still look normal
  (over-sanitizing is itself a tell).

### 4.11 Media devices & speech voices
- **`enumerateDevices`:** present an OS-appropriate set of audio/video
  input/output devices with stable, seed-derived `deviceId`s and labels behavior
  matching permission state. Where: `modules/mediastream/`.
- **`speechSynthesis.getVoices`:** present the OS-appropriate TTS voice list (a
  classic, high-signal surface). Where: `modules/speech/`.
- **Rule (V1):** device/voice sets match the persona OS; empty-where-real-
  browsers-aren't is a tell.

### 4.12 Miscellaneous surfaces
- `getClientRects`/`getBoundingClientRect`: optional seeded sub-pixel jitter.
- `performance.now()` and `performance.timeOrigin`: clamp/quantize resolution to
  match the claimed browser's real behavior (don't expose higher precision than
  the real build).
- `Battery`, `Gamepad`, `Sensors`, `Network Information`: present persona-
  appropriate values or availability; consistency over richness.

## 5. Consistency enforcement inside the engine

Even though the fingerprint engine (tdd/02) guarantees a coherent config, the
engine adds **dev-build assertions** that fail loudly if any surface is asked to
emit a value inconsistent with the persona (e.g., Apple GPU under Win32). These
are compiled out of release builds but run in CI against the verification lab —
a second net under Principle I.

## 6. Anti-trace requirements (V3) — acceptance tests

Every modified surface must pass, in CI:
- `Function.prototype.toString` on any exposed function returns
  `function X() { [native code] }` (native by construction).
- `Object.getOwnPropertyDescriptor(proto, prop)` matches stock Chrome's shape
  (accessor vs data, `enumerable`, `configurable`, `writable`).
- `Reflect.ownKeys` order and prototype-chain position match stock.
- Values are identical across main frame, same-origin iframe, cross-origin
  iframe (where applicable), dedicated Worker, shared Worker, and Service Worker.
- No new global, no residual switch, no `cdc_`-style artifact (see tdd/04).

These are encoded as verification-lab probes and gate every engine PR (Principle
VII).

## 7. The one-binary-N-identities guarantee

- No fingerprint value is a compile-time constant; all come from the config.
- The dataset (GPU strings, font sets, distributions) is *data*, updated out of
  band (signed bundle), not compiled in — so refreshing distributions doesn't
  require an engine rebuild (Principle VIII).
- A debug switch dumps the effective config a running engine is using, for
  support/audit.

## 8. Build & tracking hooks

This TDD produces the patch series; [tdd/05](05-build-and-tracking.md) owns
building and rebasing it. Contract between them:
- Patches are minimal and rationale-headed (§2).
- Each patch declares its `Upstream-risk` and its guarding probes.
- The tracking bot rebases the series onto new Chromium stable, runs the
  verification lab, and reports the first failing patch + failing probes.

## 9. Testing strategy

- **Unit (C++):** per-surface tests that the accessor returns config values and
  noise is deterministic from seed.
- **Web-platform probes:** the verification lab's headless run asserts §6 across
  all contexts.
- **Differential:** compare a Proteus profile configured to "stock Chrome N on
  Win10" against a *real* stock Chrome N on Win10 for byte-level parity on
  non-noised surfaces and distributional parity on noised ones.
- **Regression:** all of the above in the public dashboard (tdd/06).

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Upstream refactors a surface file each release | Small patches + rationale + bot reports exact failure; surface accessor centralizes access to reduce blast radius |
| Font bundling licensing | Per-font license check; substitute/omit with coherent set adjustment |
| Noise too unique → becomes an ID (V2) | Amplitude bounded to hw-natural; coordinated with rarity model (tdd/02) |
| Over-sanitized surface is itself a tell | "Look normal, not stripped" rule; differential tests vs real browser |
| Sandbox regressions from our patches | Principle IX; sandbox-touching patches get extra review + tests |
| WebGPU/新 surfaces appear upstream | Surface backlog tracked against threat model; add patch + probe |

## 11. Firefox-family via Camoufox (integration, not reimplementation)

- Use Camoufox as the Firefox engine; contribute fixes upstream (MPL-2.0).
- Map the **same profile config** onto Camoufox's configuration mechanism so a
  Proteus profile is engine-agnostic at the Manager level (the Manager emits the
  shared config; a thin adapter translates to Camoufox's launch interface).
- The verification lab runs the same probe suite against both engines so quality
  is comparable and tracked on one dashboard.
- Divergences (surfaces Camoufox covers differently) are documented in the
  adapter, not hidden.

## 12. Open questions

- Exact Mojo interface vs. serialized-blob trade-off for config propagation
  (perf vs. rebase stability) — prototype both in M0/M1.
- Whether to quantize `performance.now()` globally or per-surface.
- Font strategy on Linux hosts for macOS personas where key fonts aren't
  redistributable — how large a coherent substitute set we can present.
- WebGPU coverage depth for M1 vs. deferring richer limits modeling to M4.
