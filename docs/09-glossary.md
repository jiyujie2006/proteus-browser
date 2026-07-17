# 09 — Glossary

Terms of art used across the Proteus docs. Where a term maps to a threat vector,
the vector is noted (see [01-threat-model.md](01-threat-model.md)).

### Anti-detect browser / fingerprint browser
A browser designed to present controllable, coherent device identities so that
many isolated profiles don't all look like the same automated client. Proteus is
one; Multilogin, Kameleo, AdsPower, Camoufox are others.

### Blend-in score
Proteus's measure (0–1) of how *common* a profile's coarse observable fingerprint
is in the real population — i.e., how large a crowd it disappears into. High =
good. Directly attacks the rarity vector (V2). See
[tdd/02](tdd/02-fingerprint-engine.md) §6.

### Client Hints (UA-CH)
HTTP request headers (`Sec-CH-UA`, `Sec-CH-UA-Platform`, `-Full-Version-List`,
etc.) and the JS `navigator.userAgentData` object that convey browser/OS/version
in a structured way, gradually replacing the User-Agent string. Must agree with
the UA or it's a V1 incoherence.

### Coherence / consistency
The property that every fingerprint field agrees with every other field and with
the network layer (e.g., platform ↔ GPU, UA ↔ Client Hints, timezone ↔ proxy geo).
The #1 thing Proteus optimizes (Principle I); its absence is the #1 detection
vector (V1).

### CDP (Chrome DevTools Protocol)
The protocol automation tools (Puppeteer, Playwright, Selenium-via-CDP) use to
drive Chromium. Naive use leaks automation signals (V5); see `Runtime.enable`.

### CreepJS
A well-known open-source fingerprinting/detection test that surfaces
inconsistencies and spoofing traces. Proteus ships a bundled, offline suite
modeled on its techniques so users can test without transmitting their
fingerprint. See [tdd/06](tdd/06-verification-lab.md).

### Differential privacy (DP)
A formal method for aggregating data such that individual contributions can't be
re-identified, by adding calibrated noise. Used (opt-in, locally) for Proteus's
dataset-improvement loop. See [tdd/02](tdd/02-fingerprint-engine.md) §8.

### Fail-closed
A safety property: if the proxy/sidecar is unavailable, traffic stops rather than
falling back to direct egress (which would leak the real IP). See
[tdd/03](tdd/03-network-layer.md).

### Fingerprint aging
Proteus's technique of migrating profiles onto newer engine versions along a
*realistic* cadence (as a real user updates over time), instead of snapping every
profile to the newest build at once (a fleet-wide anomaly). See
[tdd/07](tdd/07-manager-and-storage.md) §10.

### JA3 / JA4 / JARM
Fingerprints of a TLS client derived from its ClientHello (cipher suites,
extensions, curves, ordering). JA4 is the newer successor to JA3; JARM is an
active TLS-server-ish fingerprint. If your JS says Chrome but your JA3 says a Go
client, that's a V4 cross-layer mismatch. Proteus preserves the real engine's
JA3/JA4 by tunneling, not MITM-ing. See [tdd/03](tdd/03-network-layer.md).

### HTTP/2 fingerprint (Akamai-style)
A client fingerprint derived from HTTP/2 behavior: SETTINGS frame values, window
updates, header priority, and pseudo-header ordering. Another V4 layer that must
match the claimed browser.

### MITM (Man-in-the-middle, of TLS)
Terminating TLS at an intermediary so it can read/modify traffic. **Proteus
deliberately does *not* do this** — MITM would replace the browser's TLS
fingerprint with the proxy's, creating a V4 mismatch. See
[tdd/03](tdd/03-network-layer.md) §3.

### Persona
Proteus's model of "one plausible real device" — an OS+version, device class,
browser, GPU, screen, region, and hardware profile from which all fingerprint
fields are *derived* coherently, rather than sampled independently. The mechanism
that makes incoherence structurally impossible. See
[tdd/02](tdd/02-fingerprint-engine.md) §3.

### p0f / TCP-IP stack fingerprint
Passive OS inference from TCP/IP characteristics (TTL, window size, MSS). Reflects
the *proxy exit host's* OS, not the browser's — something Proteus honestly cannot
fix from the browser (V4/V7 boundary). See [tdd/03](tdd/03-network-layer.md) §9.

### Provenance (SLSA)
Cryptographically-signed metadata describing exactly how a build artifact was
produced (source, patch hash, toolchain, flags). Combined with reproducible
builds, it lets users verify the binary matches the public source (Principle VI).
See [tdd/05](tdd/05-build-and-tracking.md) §5.

### Rarity (uniqueness)
How uncommon a fingerprint is. A coherent-but-unique fingerprint is itself a
signal *and* makes you trackable (V2). Proteus scores and rejects over-unique
profiles — the opposite of tools that "randomize everything." See blend-in score.

### Reproducible build
A build that produces bit-for-bit identical output from the same source, so an
independent party can rebuild and confirm the released binary. See
[tdd/05](tdd/05-build-and-tracking.md) §5.

### `Runtime.enable` leak
A specific CDP detection: enabling the `Runtime` domain to get execution-context
info causes page-observable side effects, revealing automation (V5). Proteus's
stealth endpoint obtains contexts without this leak. See
[tdd/04](tdd/04-anti-automation.md) §3.

### Sidecar
Proteus's per-profile Go network helper: builds the upstream proxy chain, forces
DoH, guards WebRTC, applies QUIC policy, and tunnels (never MITM). See
[tdd/03](tdd/03-network-layer.md).

### Spoofing trace
Evidence that a value was *overridden* rather than natively produced — wrong
`toString`, wrong property descriptor, prototype anomaly, or a value that differs
across main frame / iframe / Worker. The V3 vector; native production (Principle
III) eliminates the class.

### Stealth CDP endpoint
Proteus's automation attach point that speaks enough CDP for existing frameworks
while exposing no automation identity and avoiding the `Runtime.enable` leak. See
[tdd/04](tdd/04-anti-automation.md) §4.

### Tunnel (vs. MITM)
Moving encrypted bytes through at the TCP/CONNECT level without decrypting them, so
the origin completes the handshake with the *browser's* TLS stack. Proteus's
default network mode and the reason its TLS fingerprint is genuinely correct. See
[tdd/03](tdd/03-network-layer.md) §3.

### uTLS / uquic
Go libraries that can actively present a chosen, real browser's TLS/QUIC
ClientHello. Proteus uses them only in an opt-in fallback for exact version
pinning — never to cross engine families. See [tdd/03](tdd/03-network-layer.md) §6.

### Warm-up
Optionally letting a profile browse organically to accumulate plausible
cookies/history/age before real use, so a "new" profile looks lived-in (for
legitimate multi-account scenarios). See [tdd/07](tdd/07-manager-and-storage.md)
§10.

### WebGL vendor/renderer strings
`UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` — strings identifying the GPU.
A very high-signal surface; must be a real string that's *possible on the persona's
OS* (no Apple renderer under `Win32`). See [tdd/01](tdd/01-chromium-engine.md) §4.5.

### Zero-knowledge (sync)
A server design where the operator learns nothing about the data it stores —
Proteus's sync server holds only ciphertext the user holds keys to. See
[tdd/08](tdd/08-sync-and-collaboration.md).

### Vectors V1–V7
The threat model's ranked detection vectors: V1 incoherence, V2 rarity, V3
spoofing traces, V4 cross-layer mismatch, V5 automation/CDP, V6 behavior, V7
reputation/account graph. Defined in [01-threat-model.md](01-threat-model.md) §2.
