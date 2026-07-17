# Acceptable Use Policy

Proteus is a **dual-use** tool. The same capability that protects a
privacy-conscious user, lets a QA engineer test across device profiles, or
enables a business to run legitimate separate accounts, can also be misused.
This document states the project's position. It is not legal advice, and it does
not create any warranty or obligation on the part of the authors (see the
Apache-2.0 "AS IS" disclaimer).

## Intended, encouraged uses

- **Privacy and anti-tracking research** — studying and resisting browser
  fingerprinting.
- **Web application QA and testing** — exercising a site as many different
  device/browser profiles, including automated test suites.
- **Ad verification and brand safety** — checking how ads render for different
  audiences and detecting fraud.
- **Market, price, and availability research** — lawful data collection that
  respects target sites' technical limits and applicable law.
- **Legitimate multi-account operations** — managing multiple accounts a person
  or business is *entitled* to operate, kept properly isolated.
- **Journalism, OSINT, and safety research** by qualified practitioners.

## Uses this project does not condone

- Fraud, payment fraud, account-takeover, or credential stuffing.
- Creating accounts to evade a lawful ban, or to violate laws (not merely a
  site's Terms of Service).
- Mass fake-account creation, spam, astroturfing, or manipulation of reviews,
  votes, or ratings.
- Circumventing sanctions, KYC/AML controls, or age verification required by
  law.
- Harassment, stalking, or targeting of individuals.
- Any use prohibited by applicable law in your jurisdiction or the target's.

## Important distinctions

- **ToS vs. law.** Violating a website's Terms of Service is generally a civil
  contract matter, not a crime, but it can still carry consequences (account
  loss, liability). Violating the *law* is different and out of scope for any
  legitimate use of this tool. You are responsible for knowing which is which in
  your context.
- **Tool vs. endorsement.** Open source provides *capability*, not
  *endorsement*. Publishing Proteus is not encouragement to break any agreement
  or law, exactly as publishing a web browser, a VPN, or `curl` is not.
- **Your risk.** If you use Proteus to operate multiple accounts on a service,
  you accept the risk that the service may detect it, may prohibit it, and may
  act on your accounts. No fingerprint tool can promise otherwise; ours
  explicitly does not (see [`docs/01-threat-model.md`](docs/01-threat-model.md)).

## Reporting abuse / vulnerabilities

Security vulnerabilities: see [`SECURITY.md`](SECURITY.md). This project does not
operate a service and cannot police how the software is used, but design changes
that would meaningfully reduce potential for abuse without crippling legitimate
use are welcome via the normal contribution process.
