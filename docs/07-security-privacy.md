# 07 — Security & Privacy

> **Normative target posture, not a claim about the current pre-alpha.** The
> repository currently implements the bounded M1A signed-config core and local
> verification tooling. It does not yet ship a Manager, encrypted storage,
> network sidecar, sync service, plugin runtime, product UI, or modified engine.
> Controls below become release requirements as their subsystems are built.

Proteus is designed to handle the most sensitive data a browser can hold — live
sessions, cookies, credentials-in-flight — across many identities, and to ship a
modified browser engine. This document defines the required security and privacy
posture. It serves
[Principles V (data belongs to the user), VI (trust the binary), and IX (never
weaken the sandbox)](02-design-principles.md).

## 1. Data classification

| Data | Sensitivity | Handling |
|---|---|---|
| Cookies / live sessions | **Critical** | Encrypted at rest; never plaintext on disk; E2E-only if synced |
| Proxy credentials | High | Encrypted at rest; never in the fingerprint config |
| Fingerprint configs | Medium | Encrypted at rest; signed; regenerable from provenance |
| Persona params + seed | Medium | Encrypted; reproducibility inputs |
| Verification-lab results | Low | Local; no off-device transmission by default |
| Telemetry | None by default | Off; opt-in only; DP-aggregated if on |

## 2. Data at rest

- **Encrypted metadata DB** via SQLCipher; **encrypted per-profile data
  directories** for browser data (the cookie jar is inside this).
- **Key hierarchy:** a master key in the **OS keychain** (Keychain / DPAPI /
  libsecret) wraps per-profile data keys and the DB key. Keys are not stored in
  the database they protect.
- **No plaintext cookies on disk** is an explicit, tested invariant (tdd/07 §12).

## 3. Data in transit

- Profile traffic egresses only through the per-profile sidecar (tdd/03),
  **fail-closed** — a dead proxy means no traffic, never a leak to the real IP.
- DNS is forced through DoH; WebRTC is leak-guarded (engine + sidecar).
- Sync (if enabled) transmits **only ciphertext** the user holds keys to; the
  server is zero-knowledge (tdd/08).

## 4. Key management

- Master keys in the OS keychain; hardware-backed keys supported where available.
- Per-profile data keys enable sharing (via key-wrapping, tdd/08) and isolation
  without a shared secret.
- **Passphrase/recovery:** E2E means we can't recover a lost passphrase; the UX
  makes this explicit and offers a user-controlled recovery key export. Honest
  trade-off (Principle IV): true E2E security means the user holds the risk of key
  loss.

## 5. The sandbox is sacred (Principle IX)

- We **never** disable or weaken the Chromium/Firefox security sandbox to make
  fingerprinting easier. Some tools do this for convenience; we treat it as
  unacceptable because users run untrusted web content across sensitive sessions.
- Any patch that touches sandbox-relevant code gets extra review and dedicated
  tests (see [SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md)).
- Per-profile process isolation means a compromise in one profile's renderer is
  contained by the same sandbox model as upstream, and does not reach another
  profile's data (separate processes + data dirs + keys).

## 6. Trust the binary (Principle VI)

- **Reproducible builds** + **SLSA provenance** + **signed releases** + **SBOM**
  (tdd/05 §5). A third party can rebuild and confirm the artifact hash and verify
  provenance.
- A **Trust panel** in the Manager surfaces the running build's provenance so the
  user can check it in-app (tdd/07 §11).
- This directly answers the strongest rational objection to *any* anti-detect
  browser: "this binary can read all my cookies — why should I trust it?" Our
  answer is verification, not a promise.

## 7. Telemetry & privacy (Principle V)

- **Off by default. No telemetry** unless the user explicitly opts in.
- If opted in, contributions to the fingerprint dataset use **local differential
  privacy**: calibrated noise added on-device, only coarse aggregate deltas
  submitted, no raw fingerprints, no per-user identifiers, documented privacy
  budget (tdd/02 §8).
- No analytics SDKs, no phone-home, no crash reports without consent.

## 8. Update security

- Engine and dataset updates are **signed**; the Manager verifies signatures (and
  provenance) before applying (tdd/05 §7).
- A compromised update channel cannot ship an unsigned/altered binary that clients
  accept.

## 9. Plugin security

- Plugins (tdd/07 §9) are **sandboxed and permissioned**; they cannot silently
  access profile data or sessions. A proxy-provider plugin sees proxy config, not
  cookies; a probe plugin sees test results, not the session.

## 10. Threats we explicitly address vs. don't

**Addressed**
- Server compromise (zero-knowledge sync), disk theft (encryption at rest),
  network leaks (fail-closed sidecar, DoH, WebRTC guard), supply-chain trust
  (reproducible builds + provenance), cross-profile data leakage (isolation).

**Not our threat model (stated honestly)**
- A **compromised host OS** (keylogger, malware with keychain access) — we protect
  at-rest and in-transit, but a compromised endpoint defeats any application.
- **Anti-forensics** — Proteus is not a tool for hiding activity from someone with
  full control of your machine.
- **The account graph & behavior** (V6/V7) — security of *identities* against a
  platform's own history/behavioral signals is out of scope for a browser (see
  [01-threat-model.md](01-threat-model.md) §4).

## 11. Vulnerability handling

Two surfaces — classic vulnerabilities and detection/leak defects — handled per
[SECURITY.md](../SECURITY.md): private reporting for sensitive issues, coordinated
disclosure for classic vulns, and detection-leak reports welcomed (publicly unless
they reveal a novel broad-impact vector). Upstream engine CVEs are addressed by
prompt tracking (tdd/05).

## 12. Privacy principles summary

1. Your data is on your machine, encrypted (Principle V).
2. Anything synced is ciphertext you hold the keys to (zero-knowledge).
3. No telemetry unless you ask for it; then it's differentially private.
4. You can verify the binary rather than trust it (Principle VI).
5. We never trade your exploit-safety for a fingerprint gain (Principle IX).
