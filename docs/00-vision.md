# 00 — Vision

> **Target architecture, not current product status.** Proteus is pre-alpha.
> Today the repository contains a local verification scaffold and the bounded
> non-UI M1A signed-config core; it does not ship modified browser engines,
> Manager/storage, a network sidecar, sync, or a product UI. Current status and
> hard exits are tracked in the [roadmap](06-roadmap.md).

## The one-sentence version

> Proteus aims to be a **local-first, reproducibly built** open-source anti-detect
> browser: a **natively modified dual engine** (Chromium-family and
> Firefox-family) driven by a **consistency-first fingerprint engine** that
> samples from real-world distributions to make a profile "blend into the
> crowd," and keeps that identity coherent across **four layers — JavaScript,
> TLS, HTTP/2, and behavior**, with automation, a verification lab, and
> continuous anti-detection regression built in.

## Why this project exists

People who need to run multiple isolated browser identities from one machine —
privacy researchers, QA engineers, ad-verification and brand-safety teams,
market researchers, and businesses with legitimate multiple accounts — are
served today by two unsatisfying classes of tool:

- **Expensive, closed, high-end** (Multilogin, Kameleo, Octo Browser). Good
  native-engine quality, but closed source (you cannot verify what the binary
  does with your cookies), cloud-hosted (your sessions live on their servers),
  and costly.
- **Cheap, closed, high-volume** (AdsPower, GoLogin, Dolphin{anty}). Accessible
  and feature-rich UX, but frequently rely on JavaScript injection that leaves
  detectable traces, produce randomly-combined fingerprints that are either
  incoherent or improbably unique, and rarely address the network layer at all.

There is excellent open-source work at the engine level — most notably
**Camoufox** (a natively-patched Firefox) and **fingerprint-chromium** — but no
project ties native dual-engine quality, a rigorous consistency engine, network-
layer alignment, first-class automation, honest verifiable effectiveness, and a
genuinely good product together.

Proteus is the attempt to be that: the **集大成者** — the synthesis — done in the
open.

## The thesis

Winning an anti-detect browser is **not** primarily a UI problem. It is, in
order:

1. **A consistency problem.** The dominant way these tools get caught is
   *incoherence*: a profile that claims macOS but exposes Windows fonts, an
   Apple GPU behind a `Win32` platform, Client Hints that disagree with the User
   Agent, a timezone that contradicts the proxy's IP geolocation. If every field
   agrees with every other field and with the network, you have already beaten
   most detection.
2. **A native-engine problem.** Values must be produced by the engine, not
   pasted over it by JavaScript. Native production makes `toString`, property
   descriptors, and prototype chains correct *for free*, and keeps them correct
   in iframes, Workers, and Service Workers — contexts where injection leaks.
3. **A cross-layer problem.** The fingerprint the page's JavaScript sees, the
   TLS ClientHello (JA3/JA4), the HTTP/2 settings, and the user's behavior must
   all describe the same being. Perfect JS with a mismatched TLS handshake still
   dies.
4. **A treadmill problem.** Chromium and Firefox ship every few weeks. A
   fingerprint that lags the real browser population is, by definition,
   anomalous. Staying current is the difference between a project that works and
   a project that worked once.

Everything in Proteus's design is downstream of these four facts. The UX, which
matters for adoption, comes *after* they are solved — because a beautiful UI over
a detectable engine is the crowded red ocean the high-volume tools already
occupy, and it is not the battleground we can win.

## The bets we are making

These are explicit, falsifiable bets. If one is wrong, the plan changes.

- **Bet 1 — Native beats injection, decisively, and it is worth the maintenance
  cost.** We accept the Chromium-fork treadmill as the price of eliminating an
  entire class of detection. We de-risk it with heavy build automation and a
  version-tracking bot (see [tdd/05](tdd/05-build-and-tracking.md)).
- **Bet 2 — Never impersonating across engine families is a feature, not a
  limitation.** By refusing to make Chromium pretend to be Safari, we get TLS,
  HTTP/2, and JS-engine behavior that are *genuinely* consistent, because they
  come from the real stack. See [adr/0002](adr/0002-dual-engine-no-cross-family.md).
- **Bet 3 — Tunneling, not MITM, is the right way to preserve the network
  fingerprint.** By never terminating TLS in our sidecar, the origin sees the
  real engine's handshake. Many tools get this exactly backwards. See
  [tdd/03](tdd/03-network-layer.md).
- **Bet 4 — "Blend in" beats "be perfect."** Sampling from real distributions
  and actively rejecting over-unique fingerprints defeats the second-biggest
  detection vector (rarity), which most tools ignore entirely. See
  [tdd/02](tdd/02-fingerprint-engine.md).
- **Bet 5 — Verifiable honesty is a moat.** A public, continuous regression
  dashboard and reproducible builds convert "trust us" into "check for
  yourself." Closed competitors structurally cannot match this. See
  [tdd/06](tdd/06-verification-lab.md) and [tdd/05](tdd/05-build-and-tracking.md).
- **Bet 6 — Local-first with zero-knowledge sync is what users actually want.**
  Your cookies are the crown jewels; they should be on your machine, encrypted,
  and only ever leave it as ciphertext you hold the keys to.

## What "success" looks like

- A single profile passes the full local verification suite (CreepJS-class,
  Sannysoft, pixelscan, browserleaks, CoverYourTracks) **green and with zero
  consistency warnings**, and its JA3/JA4 and HTTP/2 fingerprints match a real
  browser of the same claimed identity.
- The version-tracking bot rebases patches onto a new Chromium stable and
  publishes a green build with minimal human intervention.
- The public regression dashboard shows non-degrading scores across releases.
- A non-expert can create, launch, proxy, and automate a coherent profile in
  minutes, and import their profiles from a competitor without losing sessions.
- The project has a funding model that pays for the treadmill (see
  [08-sustainability.md](08-sustainability.md)), so it does not join the
  graveyard of abandoned open-source anti-detect browsers.

## What we are explicitly deferring

- **WebKit/Safari as a true third engine.** Correct Safari impersonation
  requires WebKit, not Chromium. It is a large separate effort; it is on the
  long-term roadmap as research, not a v1 promise.
- **Mobile engines.** Same reasoning; later.
- **A hosted/managed cloud product.** May exist as an optional revenue stream
  (see sustainability), but the open, local product is always the primary
  artifact and is always fully functional on its own.

## Reading next

The vision only makes sense against the adversary. Read
[01-threat-model.md](01-threat-model.md) next.
