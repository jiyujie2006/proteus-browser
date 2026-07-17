# Contributing to Proteus

Thank you for considering a contribution. Proteus is an ambitious,
maintenance-heavy project (keeping a Chromium fork current is real work), so
clear process matters.

## Licensing of contributions

By submitting a separate first-party contribution, you agree that your
licensable first-party portion is provided under **Apache-2.0** (the project
license), consistent with §5 of the license. Material already governed by an
upstream license remains under that license. We use the
[Developer Certificate of Origin](https://developeropensource.org/) (DCO): sign
off every commit with `git commit -s`, which adds a
`Signed-off-by: Your Name <you@example.com>` line certifying you have the right
to submit the work under its applicable license.

Contributions to the engine subtrees that modify MPL-2.0 (Firefox/Camoufox)
files remain under MPL-2.0 for those files. Chromium files retain their
applicable upstream licenses, including required notices. Patch files that quote
or modify upstream source must preserve the target file's licensing context;
they are not made Apache-2.0 merely by being stored in this repository. New,
separate first-party files containing no upstream covered code are Apache-2.0.
When in doubt, ask in the PR.

The DCO sign-off is a certification that the contributor has the right to
submit the work. It does not erase or relicense third-party code.

## Ground rules specific to this project

These come straight from [`docs/02-design-principles.md`](docs/02-design-principles.md);
read it before contributing to the engine or fingerprint code.

1. **Consistency beats hiding uniqueness beats erasing traces.** A change that
   makes one value "better" but breaks cross-field coherence will be rejected.
2. **Never impersonate across engine families.** Chromium may present as
   Chrome/Edge/Brave/Opera only; Firefox as Firefox only. No Chromium-as-Safari.
   Rationale in [`docs/adr/0002-dual-engine-no-cross-family.md`](docs/adr/0002-dual-engine-no-cross-family.md).
3. **Native over injection.** Fingerprint changes go in the C++ engine, not JS
   overrides, unless there is a documented reason no native path exists.
4. **No silent detectability regressions.** Any change touching an engine
   surface must keep the verification-lab suite green and must not lower the
   public regression dashboard scores. Add a test when you add a surface.
5. **Honesty in claims.** Documentation and UI must not claim undetectability or
   overstate protection. See the threat model's boundary section.

## Workflow

1. **Discuss first for anything non-trivial.** Open an issue or a design
   discussion, especially for engine-surface changes or new ADRs. Large work
   should reference or add an ADR under `docs/adr/`.
2. **Branch, implement, sign off, PR.** Keep PRs focused. Engine patches live as
   individual files under the engine subtree's `patches/` with a one-line
   rationale header (see the build TDD).
3. **CI must pass**, including: build of affected components, unit tests,
   licence/SBOM check, and — for engine/fingerprint changes — the verification
   lab regression job.
4. **Review.** At least one maintainer approval; engine-surface and crypto/sync
   changes require a maintainer familiar with that subsystem.

## Good first areas

- Verification-lab detection tests (each new probe strengthens everyone).
- Fingerprint dataset tooling and validators.
- Manager UX, importers from other tools, documentation.
- Network sidecar proxy-protocol coverage and leak tests.

Engine C++ changes and cross-layer consistency work are the highest-value and
highest-difficulty areas; coordinate early.

## Code of Conduct

Participation is governed by the [Contributor Covenant](https://www.contributor-covenant.org/)
v2.1. Be respectful; harassment is not tolerated. Report concerns to the
maintainers listed in `MAINTAINERS.md` (added at first release).
