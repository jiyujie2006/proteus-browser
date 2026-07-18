# 02 — Design Principles

These are the non-negotiable rules. They exist to make hard trade-offs
*already decided* so that thousands of small implementation choices stay
coherent. When a design question arises, resolve it by these principles in
order. A change that violates a principle is rejected regardless of other merit.

---

## Principle I — Consistency > hiding uniqueness > erasing traces

The ordered priority of the whole project, straight from the threat model's
vector ranking (V1 > V2 > V3).

- **First**, make every field agree with every other field and with the network
  layer (defeat V1 incoherence).
- **Then**, make the coherent whole *common* rather than rare (defeat V2).
- **Then**, ensure no field bears a mark of being overridden (defeat V3).

**Practical test:** if improving one value (say, a fancier canvas noise)
introduces any contradiction with another value, the change is wrong. A boring,
coherent, common profile beats an impressive, incoherent one every time.

**Read at the fleet level too.** The same ordering applies to the *population* of
profiles Proteus emits, not just one profile. A profile must blend into the real
crowd (V2), *and* the crowd of Proteus profiles must blend into the real world
rather than cluster into a recognizable cohort (V2b). This extends "hiding
uniqueness" from the individual to the fleet and is a load-bearing commitment in
its own right — see [adr/0007](adr/0007-fleet-de-correlation.md) and
[tdd/02](tdd/02-fingerprint-engine.md) §9. It also means coherence is a
*distribution* to match, not a maximum to hit: an implausibly perfect profile is
its own rarity signal (tdd/02 §6a).

---

## Principle II — Never impersonate across engine families

Chromium-family engines may present **only** as Chromium-family browsers
(Chrome, Edge, Brave, Opera). Firefox-family may present **only** as Firefox.
**We never make Chromium claim to be Safari**, or vice versa.

**Why:** the moment you cross families, the TLS ClientHello, HTTP/2 settings, and
JS-engine observable behaviors (from the *real* underlying engine) contradict the
claim — an unwinnable V4 cross-layer mismatch. Staying in-family means those
lower layers are *genuinely* correct because they come from the real stack.

Corollary: true Safari support requires a real WebKit engine and is a separate,
deferred effort — not a costume worn by Chromium.

Full rationale: [adr/0002](adr/0002-dual-engine-no-cross-family.md).

---

## Principle III — Native production over JavaScript injection

Fingerprint-affecting values are produced by the C++ engine, not overridden by
injected JavaScript, unless there is a *documented* reason no native path exists
(and then the injection must survive the trace tests below).

**Why:** native getters make `Function.prototype.toString`, property descriptors,
and prototype chains correct automatically, and — critically — remain consistent
across **main frame, iframes, Web Workers, and Service Workers**, the contexts
where injection reliably leaks (V3).

**Practical test:** any override must be indistinguishable under
`Object.getOwnPropertyDescriptor`, `toString`, `Reflect.ownKeys`, Proxy traps,
and cross-context (Worker/iframe) comparison. If it cannot pass, it goes native
or it does not ship.

---

## Principle IV — Honesty in every claim

No documentation, marketing, or UI copy asserts undetectability or overstates
protection. Where a boundary exists (V6 behavior, V7 reputation, proxy quality),
the product states it, ideally in-context at the moment it is relevant.

**Why:** the trust that open source earns is the project's core asset and the
whole reason to prefer Proteus over a closed tool that *could* claim anything.
One dishonest guarantee that gets a user's accounts banned destroys that asset.
Honesty is also a competitive weapon: closed tools dare not admit their limits.

**Practical test:** every protective claim in the product is backed by a probe in
the [verification lab](tdd/06-verification-lab.md) or is stated as a limitation.

---

## Principle V — Local-first; data belongs to the user

Profiles, cookies, and sessions live on the user's machine, encrypted at rest.
Anything that leaves the machine (optional sync) leaves only as ciphertext the
user holds the keys to (zero-knowledge). No telemetry by default; any telemetry
is opt-in and differentially-private in aggregate.

**Why:** the sensitive data here (live sessions) is exactly what closed
cloud-hosted competitors put on their own servers. Local-first is both a security
posture and a trust differentiator (Principle IV).

---

## Principle VI — Trust the binary, verifiably

Because the binary can read every cookie, users must be able to trust it without
taking our word. We deliver reproducible builds and SLSA provenance so a third
party can confirm the released binary corresponds to the public source.

**Why:** "it's open source" is hollow if the shipped binary can't be tied to that
source. This closes the single largest rational objection to using *any*
anti-detect browser, open or closed.

---

## Principle VII — Effectiveness must be measurable and non-degrading

Every engine-surface change keeps the verification-lab suite green and does not
lower the public regression dashboard. New surfaces ship with new probes.

**Why:** an anti-detect browser silently regressing is worse than useless — it
gives false confidence (violating Principle IV). Measurement is the immune
system that lets us move fast on the treadmill without rotting.

---

## Principle VIII — Design for the treadmill

Every subsystem is designed assuming Chromium/Firefox will release again in
weeks, and that detection techniques will evolve continuously. Patches are small,
individually-rationalized, and rebase-friendly; datasets are refreshable;
tracking and regression are automated.

**Why:** the graveyard of open-source anti-detect browsers is full of projects
that worked once and could not keep up. Sustainability against upstream churn is
an architectural requirement, not an afterthought. See
[tdd/05](tdd/05-build-and-tracking.md) and [08-sustainability.md](08-sustainability.md).

---

## Principle IX — Do not weaken the sandbox

We never disable or degrade the Chromium/Firefox security sandbox to make
fingerprinting easier. If a fingerprint goal appears to require weakening the
sandbox, the goal is achieved another way or dropped.

**Why:** users run untrusted web content across many sensitive sessions.
Trading their exploit-safety for a marginal fingerprint gain is unacceptable and
would betray Principle V's security promise. Some cheap tools do this; we never
will.

---

## Using these principles

- ADRs cite the principle(s) they serve or trade off.
- PR review checks changes against I, III, VII explicitly for engine work.
- When two principles appear to conflict, the lower Roman numeral wins for
  fingerprint-quality questions (I–IV), but IX (sandbox) and V (data safety) are
  hard floors that are never traded for fingerprint quality.
