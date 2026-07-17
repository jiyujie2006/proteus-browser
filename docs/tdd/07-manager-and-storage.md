# TDD 07 — Manager & Encrypted Storage

**Status:** Design · **Serves principles:** IV, V, IX · **Threat vectors:**
operational support for all; owns the user's ability to *do it right*

The Manager is the control plane and the face of Proteus. Good UX is the second
battleground (after fingerprint quality). This TDD covers the desktop app,
encrypted storage, the profile/proxy libraries, importers, and how it orchestrates
engines and sidecars.

## 1. Goals & non-goals

**Goals**
- A fast, cross-platform desktop app to create/manage/launch/automate profiles.
- **Encrypted-at-rest** storage of profiles, cookies, and proxies; keys in the OS
  keychain (Principle V).
- Make the *coherent* thing the *easy* thing (persona-level choices, auto
  timezone-from-proxy, blend-in feedback) so users don't hand-craft V1 mistakes.
- Frictionless import from competitors (don't lose sessions when switching).
- Orchestrate per-profile engine + sidecar lifecycle with isolation and
  fail-closed networking.

**Non-goals**
- Being the fingerprint engine or the browser (it embeds/launches them).
- Cloud-hosting profiles (local-first; sync is optional and zero-knowledge,
  tdd/08).

## 2. Technology

- **Tauri** (Rust core + web UI). Rationale: small, memory-safe core; web UI for
  rich UX; cross-platform packaging; crucially, it does **not** bundle a second
  Chromium just to render the UI (it uses the OS webview), keeping the app light
  and avoiding confusion with the fingerprint engine. See
  [adr/0004](../adr/0004-tauri-manager.md).
- **Storage:** SQLite via **SQLCipher** (encrypted DB) for metadata; encrypted
  per-profile data directories for browser data; **OS keychain**
  (Keychain/DPAPI/libsecret) for master keys.
- **Embedded:** the fingerprint engine (tdd/02) as a Rust library.

## 3. Data model (encrypted)

```
Profile
├─ id, name, tags[], group, notes, customFields{}
├─ personaParams        (pins + free factors for the fp engine)
├─ seed                 (roots determinism; tdd/02)
├─ generatedConfig      (the signed profile config; regenerable from provenance)
├─ provenance           {seed, datasetVersion, engineVersion, rulesVersion}
├─ engineTarget         {family, brand, versionWindow}
├─ proxyRef             → Proxy.id (nullable)
├─ dataDir              (encrypted path to browser profile data)
├─ blendInScore, rarityReasons[]
└─ timestamps, lastLaunched

Proxy
├─ id, label, type {http|socks5|ssh|wireguard|chain}
├─ endpoint(s), credentials  (encrypted)
├─ geo {country, region, city, lat/lon}   (from lookup)
├─ reputation {residential?|datacenter?, asn, blocklist flags}
├─ health {lastCheck, status, rttMs}
└─ stickiness, rotation policy

Team (optional, tdd/08)
└─ RBAC, shares, audit log (all E2E-encrypted)
```

**Key management:** a master key in the OS keychain wraps per-profile data keys;
the SQLCipher DB is encrypted with a key also protected by the keychain. Cookies
and sessions — the crown jewels — never sit in plaintext on disk (Principle V).

## 4. Profile lifecycle

**Create:** user picks persona-level options (OS, browser, region, or "surprise
me / most-common"); the Manager calls the fingerprint engine → gets config +
blend-in score + rarity reasons; shows the score and *why* if rare; user can
reroll or pin toward a more common persona. **Users choose personas, not raw
fields**, so incoherence is hard to create by hand (Principle I).

**Launch:** Manager (1) spawns the profile's **sidecar** (tdd/03) with upstream
creds from the proxy library; (2) launches the **engine** (correct family binary)
pointed at the sidecar, handing it the **signed config**; (3) engine applies config
pre-script; (4) network fails closed if the sidecar dies. Each launch is an
isolated process + data dir.

**Automate:** Manager authorizes an automation client / RPA flow to attach to the
profile's stealth CDP endpoint (tdd/04); the session inherits the same
fingerprint + sidecar.

**Edit/attach proxy:** attaching a proxy triggers a **coherence re-check**
(R-TZ-GEO): the Manager offers to set the timezone/locale from the proxy geo and
warns about anything it can't auto-fix (e.g., a datacenter exit under a "macOS"
persona — a TCP/IP-layer mismatch it must be honest about, tdd/03 §9).

**Clone:** duplicate persona with a *new independent seed* (so noise/derivations
don't correlate — tdd/02 §9), optionally a fresh data dir.

**Export/Import:** a profile is fully described by `{personaParams, seed,
provenance, engineTarget, data dir}`, so export/import is well-defined and
portable (and auditable/reproducible).

## 5. Making coherence effortless (the UX thesis)

Every UX affordance is aimed at Principle I:
- **Persona-first UI**, not a raw-field editor: you can't set `platform=Win32`
  with an Apple GPU because you don't set those directly.
- **Blend-in score** shown at create time with rare-attribute callouts (tdd/02
  §6) — actively steers users toward the crowd.
- **Auto timezone/locale from proxy geo** by default; contradiction warnings.
- **Proxy quality surfacing:** residential/datacenter, geo, RTT, blocklist flags,
  so the user picks IPs that don't undercut the browser (tdd/03 §9, V7 honesty).
- **One-click "Test this profile"** into the verification lab (tdd/06), with the
  inconsistency list front-and-center.

The Manager's job is to make the *coherent, common, well-proxied* choice the
*default and easiest* one.

## 6. Proxy library

- Store/organize proxies (encrypted creds), tag, group, assign to profiles with
  stickiness or rotation.
- **Health checks:** liveness, RTT, exit IP + geo lookup, residential/datacenter
  heuristic, blocklist checks — surfaced per proxy.
- **Provider plugins:** residential/mobile proxy providers integrate via the
  plugin SDK to auto-populate the library; the sidecar treats all upstreams
  uniformly (tdd/03 §10).

## 7. Importers (lower the switching cost)

Map competitor and standard formats into the Proteus profile model, then run
`validate` + `rescore` (tdd/02) and warn about any incoherence/rarity the import
carries in:
- Multilogin, GoLogin, AdsPower, Dolphin{anty} profile exports (as feasible from
  their formats).
- Netscape/`cookies.txt` and JSON cookie jars (so live sessions survive the
  move).
- A documented mapping per source; where a source is incoherent, the import flags
  it rather than silently shipping a V1 problem.

**Why this matters:** the biggest barrier to adoption is the fear of losing
existing sessions/profiles. Frictionless, session-preserving import removes it.

## 8. No-code RPA (with tdd/04)

- Visual flow builder embedded in the Manager; flows bound to a profile; plugin
  nodes via the SDK; parity with the code API. Detail in tdd/04 §6.

## 9. Plugin SDK (extensibility as a moat)

A stable extension surface so the community can add value without forking:
- **Detection probes** (into the verification lab, tdd/06).
- **Fingerprint data sources / rules** (into the fp engine dataset/rules, tdd/02).
- **Proxy providers** (into the proxy library).
- **RPA nodes** (into the RPA runtime).
- **Importers** (new source formats).

Plugins are sandboxed and permissioned; a plugin can't silently exfiltrate profile
data (Principle V). This turns the ecosystem into a community-maintained surface
that keeps pace with detection faster than any single team (Principle VIII).

## 10. Innovative lifecycle features

- **Fingerprint aging:** profiles migrate onto newer engine versions along a
  *realistic* cadence (a real user updates over days/weeks, not instantly), rather
  than snapping all profiles to the newest build simultaneously (which is itself a
  fleet-wide anomaly). Ties to tdd/05 §7.
- **Profile warm-up:** optional automated, organic browsing to accumulate
  plausible cookies/history/age *before* a profile is used for its real purpose
  (for legitimate multi-account scenarios) — makes a "new" profile look lived-in.
- **Deterministic rebuild:** because a profile = `{persona, seed, versions}`, a
  teammate can reconstruct the *same* environment from provenance (audit, support,
  collaboration).

## 11. Interaction summary

| With | Contract |
|---|---|
| Fingerprint engine (tdd/02) | Embeds it; generate/validate/rescore; shows blend-in |
| Engine (tdd/01) | Launches correct-family binary with signed config; isolated per profile |
| Network (tdd/03) | Spawns/tears down sidecar; supplies proxy creds; shows quality/geo |
| Anti-automation (tdd/04) | Authorizes stealth-endpoint attach; hosts RPA runtime |
| Verification lab (tdd/06) | One-click test; renders score + inconsistency list |
| Sync (tdd/08) | Optional E2E-encrypted replication; keys never leave client |
| Build (tdd/05) | Receives signed engine + dataset updates; verifies provenance |

## 12. Testing strategy

- **Storage:** encryption-at-rest verified (no plaintext cookies on disk);
  keychain integration per platform; corruption/recovery.
- **Lifecycle:** launch/teardown isolation (no cross-profile leakage of data dir,
  cookies, sidecar); fail-closed on sidecar death.
- **Import fidelity:** round-trip and session-survival tests per source format.
- **Coherence UX:** attaching a contradictory proxy surfaces the R-TZ-GEO warning;
  persona-first UI can't emit a known-incoherent config.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Plaintext session data leaks to disk | Encrypted data dirs + SQLCipher + keychain; on-disk plaintext test |
| Users still create incoherent profiles | Persona-first UI (no raw fields); blend-in feedback; proxy coherence check |
| Import loses sessions (adoption blocker) | Session-preserving cookie import; round-trip tests; per-source mapping |
| Plugin exfiltrates profile data | Sandboxed, permissioned plugins; no ambient data access |
| OS-webview differences across platforms (Tauri) | Test matrix; keep UI to well-supported webview features |
| Sidecar/engine orchestration races | Deterministic spawn order; health gating; fail-closed |

## 14. Open questions

- Exact competitor import formats feasible at v1 (depends on their export
  fidelity) — prioritize the most-requested in M3.
- Whether warm-up ships in M3 or M5 (it borders on operational automation).
- Plugin permission model granularity — start conservative, expand with demand.
- Team features in the Manager vs. wholly in the sync service (tdd/08) — keep
  RBAC UI in Manager, enforcement E2E in sync.
