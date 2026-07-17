# TDD 08 — Sync & Team Collaboration (Zero-Knowledge)

**Status:** Design · **Serves principles:** IV, V · **Threat vectors:** protects
the crown jewels (sessions) in transit and at rest on any server

Teams need to share profiles and hand off sessions; individuals want their
profiles on more than one machine. The catch: profiles contain live cookies —
exactly the data that must never sit readable on someone else's server. This TDD
specifies **zero-knowledge, end-to-end-encrypted** sync where the (self-hostable)
server stores only ciphertext.

## 1. Goals & non-goals

**Goals**
- Optional sync of profiles (including sessions) across a user's devices.
- Team collaboration: share profiles, hand off sessions, RBAC, audit — all E2E
  encrypted.
- **Zero-knowledge server:** the backend never sees plaintext profile data or
  keys (Principle V).
- **Self-hostable** with a one-command deploy; also viable as an optional hosted
  service (sustainability, but always optional and always zero-knowledge).

**Non-goals**
- Being required (Proteus is fully functional local-only; sync is opt-in).
- Server-side profile execution or inspection (it's dumb encrypted storage +
  coordination).
- Being a general file-sync product.

## 2. Threat model for sync specifically

Assume the server is **honest-but-curious at best, compromised at worst**. The
design must ensure that a fully-compromised server (or a malicious host operator)
learns **nothing** about profile contents, and cannot inject a malicious profile a
client would trust. Concretely, an attacker with full server access should get
only: ciphertext blobs, their sizes, and sync timing/metadata — never cookies,
never keys, never fingerprint configs in the clear.

## 3. Cryptographic design (E2E, zero-knowledge)

Principles first; exact primitives finalized in an ADR before implementation
(and reviewed by someone with crypto expertise — Principle IV honesty about our
own limits).

- **Client-side encryption:** all profile data is encrypted on the client with
  keys derived from user/team secrets **before** it ever touches the network. The
  server stores opaque blobs.
- **Key hierarchy:**
  - A user's identity key (from a strong passphrase via a memory-hard KDF, and/or
    a hardware-backed key).
  - Per-profile data keys (as in tdd/07) wrapped for each principal authorized to
    access them.
  - **Team sharing via key-wrapping:** to share a profile with a teammate, the
    profile's data key is wrapped to the teammate's public key — the server
    facilitates delivery of wrapped keys but never holds an unwrapped one
    (public-key/"sealed-sender"-style distribution).
- **Integrity/authenticity:** authenticated encryption + signatures so a client
  can verify a synced profile came from an authorized principal and wasn't
  tampered with (defends against a malicious server injecting profiles).
- **Rotation/revocation:** removing a teammate re-wraps affected profile keys and
  rotates as needed; the design accounts for the fact that anyone who *had* access
  saw the data (honest limitation — revocation is forward-looking).

## 4. Sync semantics

- **Object model:** profiles (and their encrypted data) sync as versioned
  encrypted objects; the server does content-agnostic blob storage + ordering.
- **Conflict handling:** session data is stateful and dangerous to merge blindly
  (two devices using one cookie jar can invalidate sessions). We use explicit
  **ownership/lease** semantics for "who has the session live right now" (a
  session hand-off is a deliberate transfer, not a silent multi-writer merge),
  with last-writer-wins only for non-session metadata and clear conflict surfacing
  otherwise.
- **Selective sync:** users choose which profiles/groups sync; local-only
  profiles never leave the device.

## 5. Team collaboration features

- **RBAC:** roles (owner/admin/member/viewer) scoped to profiles/groups; UI in the
  Manager (tdd/07), enforcement via key-wrapping (a viewer simply isn't given
  write keys; access control is cryptographic, not just server-policy).
- **Session hand-off:** transfer a live profile (its encrypted session) to a
  teammate as a first-class action, with the lease semantics of §4 so two people
  don't clobber one session.
- **Audit log:** who accessed/launched/handed-off what, itself E2E-encrypted and
  visible to authorized team admins — accountability without exposing contents to
  the server.
- **Deterministic rebuild:** because a profile carries provenance (tdd/07 §10), a
  teammate can also *reconstruct* the environment, not just receive it.

## 6. Deployment

- **Self-host:** a small Rust service + S3-compatible object storage, shipped as a
  **Docker Compose** one-command deploy. The service is intentionally simple
  (blobs, wrapped-key delivery, ordering, auth) — the less it does, the less it
  can leak.
- **Hosted (optional):** may be offered as a managed convenience (see
  [08-sustainability.md](../08-sustainability.md)); it runs the *same*
  zero-knowledge code, so choosing hosted vs. self-host is a convenience decision,
  not a trust downgrade — the server can't read data either way.

## 7. Why this is a differentiator

Closed competitors that cloud-host profiles hold your sessions in a form *they* can
read. Proteus's sync, by construction, cannot — and because it's open and
reproducibly built (Principle VI), that claim is checkable, not just stated
(Principle IV). "Your cookies, encrypted with your keys, on a server that's blind
by design (and you can run it yourself)" is a message no closed cloud tool can
honestly make.

## 8. Interaction summary

| With | Contract |
|---|---|
| Manager (tdd/07) | Client-side encryption, key hierarchy, RBAC UI; keys in OS keychain |
| Fingerprint engine (tdd/02) | Provenance travels with the profile for deterministic rebuild |
| Security/privacy (07 doc) | Shares the key-management and data-at-rest model |

## 9. Testing strategy

- **Zero-knowledge assertion:** a test harness playing "malicious server" captures
  everything the server sees and asserts no plaintext profile data or key is
  recoverable.
- **Sharing/revocation:** key-wrapping delivers access to authorized principals
  only; revocation prevents *future* access; tamper/inject attempts are rejected
  by clients (signature/authenticity checks).
- **Session-safety:** lease/hand-off prevents two-writer session corruption;
  conflict surfacing for metadata.
- **Self-host deploy:** the Compose deploy comes up and interops with clients.

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Rolling our own crypto → subtle break | Standard primitives; pre-implementation crypto-review ADR; honest about limits (Principle IV) |
| Malicious server injects a profile | Authenticity/signatures; clients verify authorized origin |
| Two devices corrupt one session | Ownership/lease semantics; explicit hand-off; no blind multi-writer merge |
| Revocation misunderstood as retroactive | UX states revocation is forward-looking; anyone who had access saw it |
| Metadata leakage (sizes/timing) | Minimize; document what the server *can* infer; pad where warranted |
| Passphrase loss = data loss (E2E tradeoff) | Clear UX; optional hardware-backed keys; recovery-key export the user controls |

## 11. Open questions

- Exact cryptographic primitives and protocol — **requires a dedicated ADR with
  external crypto review before any implementation** (this is where honesty about
  our own expertise limits matters most).
- Whether to adopt an existing audited E2E protocol/library vs. compose primitives
  ourselves — strongly prefer reusing audited building blocks.
- Metadata-privacy level (do we pad blob sizes / add timing defenses in v1?).
- Group-key rotation strategy at team scale.
- This whole subsystem is **M5** — it must not distract from the M0–M2 engine/
  fingerprint/network work that is the actual moat.
