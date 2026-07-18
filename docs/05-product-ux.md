# 05 — Product & UX

Fingerprint quality wins the fight; UX wins the users. This document describes
the product experience. Its guiding thesis, from [Principle I](02-design-principles.md):

> **Make the coherent, common, well-proxied choice the default and the easiest
> one.** The user should have to go out of their way to create something
> detectable — and the app should warn them when they do.

The engineering that backs each screen lives in
[tdd/07 (Manager)](tdd/07-manager-and-storage.md); this is the experience view.

## 1. Who uses it, and what they need

| User | Primary need | What the product must nail |
|---|---|---|
| Privacy researcher | Understand & resist fingerprinting | Verification lab, transparency, local-only |
| QA / test engineer | Many device profiles, automated | Automation compat, coherent profiles, CI-friendly |
| Ad-verification analyst | See ads as different audiences | Fast profile+proxy switching, geo coherence |
| Market researcher | Lawful multi-region data collection | Proxy quality, coherence, RPA |
| Multi-account operator (legit) | Isolated, durable identities | Isolation, warm-up, session safety, import |
| Team lead | Share/hand-off without leaking | ZK sync, RBAC, audit |

## 2. First-run experience

- **No account required.** The app works fully local on first launch — a direct
  contrast to cloud tools that gate you behind sign-up. (Principle V.)
- **Honest onboarding.** A short, skippable primer that states what Proteus does
  and — importantly — what it *cannot* do (behavior, reputation, proxy ground
  truth), so expectations are calibrated from minute one (Principle IV).
- **"Create your first profile"** with the persona-first flow (§3), ending in a
  one-click verification-lab test so the user *sees* it's coherent.

## 3. Creating a profile (the core flow)

Persona-first, never raw-field:
1. **Choose a persona** — OS, browser family, and region — or hit **"Most common"**
   (samples a high-blend-in persona for the chosen region) or **"Surprise me."**
2. The fingerprint engine generates a coherent config and returns a **Blend-in
   score** with **rare-attribute callouts** if applicable ("this GPU+resolution
   pair is uncommon — reroll?").
3. **Attach a proxy** (optional now, anytime later). On attach, the app **sets
   timezone/locale from the proxy geo** and flags any contradiction it can't fix
   (e.g., datacenter exit under a macOS persona — honest V4/V7 warning).
4. **Test** → the verification lab opens with the score and, front-and-center, the
   **inconsistency list** (empty, ideally). Green means launch with confidence.

The user never types `platform=Win32`. They can't create the classic incoherence
because the UI doesn't expose the raw contradiction surface (Principle I).

## 4. The profile library

- Grid/list of profiles with **tags, groups, search, batch actions** (launch,
  stop, assign proxy, move group, export).
- Per-profile card shows: persona summary, engine version, proxy + geo + health,
  blend-in score, last launched.
- **Quick launch** and **quick automate**.
- **Notes & custom fields** per profile (operators track a lot of context).

## 5. The proxy library

- Add/import proxies; organize with tags/groups; assign with **stickiness or
  rotation**.
- **Health & quality at a glance:** live/dead, RTT, exit IP + geo,
  residential/datacenter heuristic, blocklist flags — the signals that decide
  whether the network undercuts the browser (tdd/03 §9).
- **Provider plugins** auto-populate residential/mobile pools.

## 6. Launch & the browsing session

- Launching opens the modified engine as a normal, headful browser window — it
  looks and feels like Chrome/Firefox because it *is* (modified). No weird
  chrome, no automation banner.
- Behind the scenes: isolated process + data dir + its own sidecar; network fails
  closed if the proxy drops (the user is told, rather than silently leaking).
- A subtle status affordance shows proxy/geo/coherence health for the live
  session.

## 7. Automation & no-code RPA

- **Bring your scripts:** Playwright/Puppeteer/Selenium attach to the profile's
  stealth endpoint; existing scripts run, now stealthy and coherent (tdd/04).
- **No-code RPA:** a visual flow builder for users who don't code — nodes for
  navigate/click/type/extract/conditional/loop, humanized input, plugin nodes.
- **Parity:** no-code and code do the same things; graduate without a wall.

## 8. The verification lab in the product

- **"Test this profile"** anywhere → scored report with the **inconsistency list**
  as the hero element (actionable, not a bare number).
- Optional external testers (opt-in, since they transmit the fingerprint).
- This is also the trust surface: the user can *see* effectiveness, and the public
  dashboard (tdd/06) lets them see it hasn't regressed across releases.

## 9. Teams (optional)

- Share profiles and **hand off live sessions** with lease semantics (no
  two-writer session corruption), RBAC, and an audit log — all **E2E encrypted**;
  the server can't read anything (tdd/08).
- Self-host with one command, or use an optional hosted instance that runs the
  same zero-knowledge code.

## 10. Migration in (removing the switching barrier)

- **Importers** for Multilogin/GoLogin/AdsPower/Dolphin plus cookie formats, so
  users **don't lose sessions** switching to Proteus — then `validate`+`rescore`
  flags any incoherence the import carried in (tdd/07 §7). The fear of losing
  existing profiles is the #1 switching barrier; this removes it.

## 11. Signature UX touches (differentiators users feel)

- **Blend-in score** — a visible measure of how well you disappear into the
  crowd. A few open generators estimate plausibility internally; surfacing it to
  the user as an actionable number is uncommon.
- **"Too clean" nudge** — if a profile is *implausibly* tidy (freshly updated,
  zero quirks), the app can say so and offer a realistic imperfection, because
  real devices aren't perfect (tdd/02 §6a).
- **Coherence warnings in context** — the app tells you *before* you get flagged
  that your timezone fights your proxy.
- **Fleet spread, not clones** — creating many profiles gives you a crowd that
  spreads across the real distribution rather than N copies of the same "safe"
  persona; the app never silently hands everyone the same fingerprint (tdd/02 §9).
- **Trust panel** — verify the build's provenance/signature from inside the app
  (Principle VI made tangible).
- **Fingerprint aging & warm-up** — profiles that update and mature like real
  ones, not static fakes.
- **Local-first badge** — a visible, honest reminder that your data is on your
  machine.

## 12. Accessibility, i18n, performance

- Keyboard-navigable, screen-reader-friendly web UI; respects OS theme.
- Internationalized UI (the user base is global; anti-detect tooling is heavily
  used outside the US).
- Lightweight (Tauri + OS webview, not a bundled Chromium for the UI) so managing
  hundreds of profiles stays responsive.

## 13. What we deliberately *don't* do in the UI

- No raw-field fingerprint editor that lets users hand-craft incoherence
  (Principle I) — advanced overrides exist but are gated, validated, and warn.
- No "undetectable" claims anywhere (Principle IV).
- No dark-pattern upsell; the core is free and local (open-core boundaries are
  honest — see [08-sustainability.md](08-sustainability.md)).
