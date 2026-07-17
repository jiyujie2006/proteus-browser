# Schemas

Machine-readable contracts for Proteus. These are normative for each implemented
boundary. M1A currently validates the generator side; browser-engine and Manager
consumers remain planned and must validate before their boundaries can ship.

## Files

- **[profile-config.schema.json](profile-config.schema.json)** — the single most
  important interface in the system: the signed JSON the fingerprint engine
  produces ([tdd/02](../tdd/02-fingerprint-engine.md)) and the browser engine
  consumes ([tdd/01](../tdd/01-chromium-engine.md)). It is the API between "what
  identity to present" and "the browser that presents it." Versioned independently
  (`schemaVersion`) so engine and Manager can evolve on the treadmill. See
  [04-architecture.md](../04-architecture.md) §6 for the design discussion and
  [ADR 0006](../adr/0006-config-driven-single-binary.md) for why it exists.

## Conventions

- **SemVer-shaped, explicitly supported versions** on `schemaVersion`.
  Consumers reject unsupported versions and unknown fields; they do not infer
  compatibility or silently ignore fields merely because the major version
  matches.
- **Derived fields are marked** in descriptions (UA, Client Hints, locale are
  derived by the fingerprint engine from persona+engine+proxy, never hand-typed —
  the mechanism that prevents V1 incoherence).
- **Secrets are excluded by design.** Proxy credentials are *not* in this schema;
  they are intended to live in a future encrypted proxy library rather than the
  signed config. That separation lets a config be signed, shared, and audited
  without leaking secrets; the proxy library itself is not implemented yet.
- **Determinism inputs are explicit** (`seed`, `provenance`) so a profile is
  reconstructible from its inputs.
- **Signature envelope:** Ed25519 signs the v1 domain prefix, UTF-8 `keyId`, a
  NUL separator, and the canonical Profile Config body. Binding `keyId` prevents unsigned
  trust-store alias substitution. M1A resolves the ID through an in-memory or
  JSON trust-store abstraction and fails closed on any parse, lookup, signature,
  schema, deterministic-replay, or semantic error. Installation-scoped
  protected trust-store provisioning is the browser-integration target and is
  not implemented yet.
- **Canonicalization scope is deliberately narrow.** The implemented M1A writer
  canonicalizes the strict Profile Config value domain and is locked by fixed
  Rust↔Node vectors. Although the envelope labels this contract `RFC8785`, this
  is not a claim that Proteus ships a general-purpose RFC 8785 implementation
  for arbitrary JSON.

## Validation points

| Where | Validates | Current status |
|---|---|---|
| Fingerprint generator/CLI (emit/reload) | Generation validates strict typed shape + semantics before signing; reload rejects duplicate keys, unknown fields, unsupported versions, tampering, and invalid signatures ([tdd/02](../tdd/02-fingerprint-engine.md)). The low-level `sign_config` primitive signs a typed body; callers must use the validated generation/ingest boundary. | Implemented in M1A |
| Independent Node conformance | Canonical hashes, fixed Ed25519 vector, tamper rejection, provenance, and V1/V2 config-scope output | Implemented in M1A |
| Modified browser engine (ingest) | Shape + signature + semantics before first script, else fail closed ([tdd/01](../tdd/01-chromium-engine.md) §3) | Planned for M1; its patch remains a backlog placeholder (the real active M0 layer0 patch is unrelated Network Time hardening) |
| Manager (import) | Imported/edited profiles re-validated + coherence-checked ([tdd/07](../tdd/07-manager-and-storage.md) §7) | Planned for M3 |
| Verification lab runtime | Rule catalog and cross-context/runtime coherence probes ([tdd/06](../tdd/06-verification-lab.md)) | Local/config checks exist; artifact-driven runtime gate is not complete |

Additional schemas (proxy library entries, dataset bundle manifest, sync objects)
will be added here as those subsystems are implemented; they are described in
their TDDs in the interim.
