# 08 — Sustainability & Governance

This is the document that decides whether Proteus becomes a durable project or
joins the graveyard of open-source anti-detect browsers that worked once and died.
The technical moat (native engine, coherence, network layer) is worthless if
nobody keeps it current with Chromium. **Sustainability is an architectural
requirement, not an afterthought** ([Principle VIII](02-design-principles.md)).

## 1. The core problem: the treadmill costs money

- Chromium ships a new stable every few weeks. Firefox too.
- Keeping the patch set rebased, built on all platforms, and verified green is
  ongoing, skilled labor — and Chromium builds are computationally expensive.
- Class-A closed competitors keep pace because they have paid engineers. Class-C
  open projects sometimes lag and lose users to detection.
- **Therefore:** Proteus needs a funding model that pays for the treadmill, or it
  will fall behind and die regardless of how good v1.0 is. Being better on day one
  is not the moat; being *maintained* is.

## 2. The model: open-core, honest boundaries

**Everything that makes Proteus effective is free, open, and local, forever:**
- Both engines (Chromium-mod, Firefox/Camoufox).
- The fingerprint engine (persona, consistency, rarity).
- The network sidecar.
- Anti-automation, stealth CDP, RPA.
- The Manager, encrypted storage, importers.
- The verification lab and the public dashboard.
- Zero-knowledge sync **software** (self-hostable).

**Optional paid conveniences fund the treadmill** — never gating the core, never a
trust downgrade:
- **Hosted sync / team cloud** — the *same* zero-knowledge code we open-source, run
  for you. You pay for convenience, not for the ability to read your own data
  (you always can self-host).
- **Managed proxy marketplace / integrations** — optional, via the provider
  plugin system.
- **Enterprise support & SLAs** — priority support, deployment help,
  compliance/audit assistance.
- **Prebuilt binaries convenience tier** — builds are always reproducible and the
  recipe is public; a paid tier can offer convenience/priority, but anyone can
  build from source.

The boundary rule (Principle IV honesty): **paid features are conveniences and
services, never the effectiveness of the tool.** If a feature makes you *harder to
detect*, it is free and open. If it makes your life *more convenient*, it may be
paid. We state this boundary publicly and hold to it.

## 3. Why open-core and not donations-only

Donations rarely cover sustained, expensive infra (Chromium build farms) and
skilled maintainership. A modest recurring revenue from conveniences that
enterprises and teams gladly pay for is what buys the engineer-hours and build
compute that keep the whole free core alive. The alternative — hoping volunteers
rebase Chromium forever — is exactly how the graveyard filled up.

## 4. Governance

- **License:** Apache-2.0 for our code (patent grant matters for a
  circumvention-adjacent project — [adr/0001](adr/0001-license-apache-2.md)).
  Future engine distributions retain all applicable upstream licenses and bind
  an artifact-specific notice bundle
  ([third-party licensing](10-third-party-licensing.md)).
- **Contribution:** DCO sign-off, Apache-2.0 inbound=outbound
  ([CONTRIBUTING.md](../CONTRIBUTING.md)).
- **Decision-making:** ADRs (`docs/adr/`) record load-bearing decisions in the
  open. Major changes reference or add an ADR.
- **Maintainership:** a `MAINTAINERS.md` (at first release) names owners per
  subsystem (engine, fingerprint, network, manager, sync). Engine and crypto/sync
  changes require a subsystem-familiar maintainer.
- **Neutral home (aspiration):** as the project matures, moving trademark/assets
  to a neutral foundation avoids single-vendor capture and reassures the community
  that open-core boundaries won't be eroded.

## 5. Community as a moat (Principle VIII)

The plugin SDK (tdd/07 §9) turns the community into a distributed maintenance
force that keeps pace with detection faster than any single team:
- **Detection probes** — every contributed probe strengthens everyone and feeds
  the public dashboard.
- **Fingerprint data/rules** — community-sourced heuristics and (opt-in, DP)
  distribution data improve blend-in for all.
- **Proxy providers, RPA nodes, importers** — ecosystem breadth without core
  bloat.
- **Open fingerprint schema standard** — if Proteus's config schema becomes a
  reference other tools interoperate with, that's a durable community moat and a
  standards position no closed tool can occupy.

An open, verifiable, community-extended project can out-iterate closed tools on
the detection arms race *if* it's funded enough to stay on the treadmill — hence
§2.

## 6. Legal & ethical sustainability

- **Dual-use posture:** positioned for lawful use (privacy, QA, ad-verification,
  legitimate multi-account) with a clear [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md);
  open source provides capability, not endorsement — like a browser, a VPN, or
  curl.
- **Honesty as risk management:** never claiming undetectability (Principle IV)
  protects both users (calibrated expectations) and the project (no false
  advertising, no liability for guarantees we can't make; Apache-2.0 "AS IS").
- **Reproducibility as trust:** open + reproducible builds (Principle VI) is also
  a *reputational* sustainability asset — it's the answer to "why trust an
  anti-detect binary," and closed competitors can't match it.

## 7. Key risks to sustainability

| Risk | Mitigation |
|---|---|
| Can't fund the Chromium treadmill | Open-core revenue from hosted sync/enterprise; tracking-bot automation lowers labor; community probes share load |
| Maintainer burnout / bus factor | Subsystem maintainers; automation; neutral-foundation aspiration; funded roles |
| Open-core boundary erodes (enshittification) | Public boundary rule (§2); neutral governance; effectiveness always free |
| Fork risk (someone takes the free core) | Apache-2.0 permits it; our moat is *maintenance + verification + community + brand trust*, not code secrecy |
| Legal pressure on the project | Lawful-use positioning; honesty; no undetectability claims; standard dual-use footing |
| Losing the arms race despite funding | Public dashboard makes regressions visible fast; community iterates; honest about the perpetual nature of the race |

## 8. The one-paragraph sustainability thesis

Give away everything that makes you effective — engines, coherence, network layer,
verification, self-hostable sync — because openness and verifiability are the
trust moat and the community is the maintenance force. Charge only for
conveniences and services that teams and enterprises are happy to pay for, and use
that revenue to fund the one thing that actually kills projects like this: staying
current with Chromium. Automate that treadmill as hard as possible so the funding
goes further. Never let the paid boundary touch effectiveness, say so publicly, and
let reproducible builds prove you mean it.
