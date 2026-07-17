# Security Policy

## Two kinds of "security" for this project

Proteus has an unusual dual security surface:

1. **Classic software security** — Proteus handles highly sensitive data
   (cookies, sessions, credentials-in-browser) and ships a modified browser
   engine. Memory-safety, sandbox integrity, encryption-at-rest, and the sync
   protocol are all in scope.
2. **Detection resistance** — a "vulnerability" here can also mean a *fingerprint
   leak or inconsistency* that lets a site distinguish a Proteus profile. These
   are tracked as defects against the threat model and verification lab, not
   usually as embargoed CVEs, but high-impact novel detection vectors may be
   handled under coordinated disclosure so a fix can ship first.

## Reporting a vulnerability

**Do not open a public issue for sensitive reports.** Use GitHub's private
"Report a vulnerability" (Security Advisories) on the repository, or email the
security contact published in `MAINTAINERS.md` (PGP key attached there) once the
project has a first release.

Please include: affected component and version/build hash, reproduction steps or
PoC, impact assessment, and whether the issue is a classic vulnerability or a
detection/leak issue.

## Our commitments

- Acknowledge within a target of 72 hours.
- Provide an assessment and remediation plan for confirmed issues.
- Credit reporters who wish to be credited.
- For classic vulnerabilities: coordinated disclosure, typically 90 days or on
  fix availability, whichever is sooner.
- Never weaken the Chromium/Firefox sandbox as a shortcut; sandbox-affecting
  changes get extra scrutiny (see [`docs/07-security-privacy.md`](docs/07-security-privacy.md)).

## Scope notes

- **Upstream engine vulnerabilities** are addressed by tracking upstream
  releases promptly (see the build/tracking TDD); report engine-origin CVEs to
  Chromium/Mozilla as well.
- **Detection/leak reports** are extremely welcome and can be filed publicly
  unless they reveal a novel, not-yet-mitigated vector with broad impact — in
  that case prefer the private channel so a fix can land first.
