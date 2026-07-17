# Proteus fingerprint engine — M1A

This Rust crate is the non-UI, locally executable core of the first M1 vertical
slice:

```text
persona request + 32-byte seed + versioned seed dataset
  → domain-separated deterministic sampling
  → derived coherent Profile Config
  → strict semantic validation
  → transparent seed rarity heuristic
  → canonical payload for the strict Profile Config value domain
  → Ed25519 signature envelope
  → independent fail-closed reload + verify
```

It intentionally stops at the honest boundary: the Chromium-native M1 patch
specifications are still backlog placeholders until they are implemented and
built against a real Chromium checkout. Passing these tests proves config
generation plus standalone
reload/verification contract conformance; it does not prove Chromium ingest,
native browser surfaces, or cross-context propagation.

The signature envelope labels its canonicalization contract `RFC8785`, and the
supported Profile Config domain is locked by fixed Rust↔Node vectors. This crate
does not claim to be a general-purpose RFC 8785 implementation for arbitrary
JSON.

## Test

```bash
npm run m1a

# Or run the Rust checks separately with the locked dependency graph:
cargo test --manifest-path fingerprint/Cargo.toml --locked
cargo clippy --manifest-path fingerprint/Cargo.toml --locked --all-targets -- -D warnings
```

The shared seed dataset is
[`../verify-lab/data/reference.json`](../verify-lab/data/reference.json). Its
exact bytes are bound into every config by `provenance.datasetSha256`; changing
the data without regenerating and resigning the config fails closed. Its weights
are explicitly heuristic; real population distributions and calibrated rarity
arrive in M4.

Reload verification checks the raw signed JSON before typed conversion, binds
the trust-store routing `keyId` into the Ed25519 input, validates the strict
schema and semantics, and deterministically rebuilds the body from its
seed/persona/engine/region inputs. A valid signature over a hand-edited derived
field is therefore rejected rather than accepted as a new identity.
Generation requests require an explicit engine major version, so replay keeps
the same target constraint when the exact bound dataset contains multiple live
majors. Any later dataset-byte change first requires explicit regeneration and
resigning because `datasetSha256` fails closed.

The request's region is not copied into the signed body as a separate field.
Replay recovers it from the exact bound dataset's `timezoneToRegion` mapping;
the mapping must therefore be one-to-one for emitted timezones.

## CLI

```bash
cargo run --manifest-path fingerprint/Cargo.toml -- \
  generate \
  --request fingerprint/fixtures/request-windows-chrome.json \
  --dataset verify-lab/data/reference.json \
  --signing-key fingerprint/fixtures/test-signing-key.json

cargo run --manifest-path fingerprint/Cargo.toml -- \
  verify \
  --config /path/to/signed-profile.json \
  --dataset verify-lab/data/reference.json \
  --trust-store fingerprint/fixtures/test-trust-store.json
```

Signing-key fixtures are test-only. The implemented M1A verifier accepts an
in-memory or JSON trust-store abstraction. Production Manager keys are intended
to live in the OS keychain, with the engine receiving their public trust anchor
through a future installation-scoped protected trust store; that provisioning
path is not implemented yet. A single shared engine binary cannot have each
user's local Manager public key baked into it.
