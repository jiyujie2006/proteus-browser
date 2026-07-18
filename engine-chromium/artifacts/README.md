# M0 build evidence

This directory keeps schemas and, during the aggregate/hard-gate workflows,
the downloaded records for six real builds. The current hard format is
`m0-evidence-v2.schema.json` /
`m0-build-evidence-v2.json`, with assurance
`full-bundle-builder-attested/v2`. `scripts/m0-evidence-v2.mjs` recomputes the
complete bundle tree, package/runtime closure, dependency and toolchain locks,
effective GN args, artifact licenses/SBOM, live V1–V5 report, raw Sigstore
statements, and GitHub repository/run/job/check/artifact identities. A and B
must match for each of Windows x64, macOS universal, and Linux x64.

The older `m0-build-evidence.json` format is a deliberately bounded
**entrypoint evidence layer**, not sufficient evidence for the hard M0 exit.
`scripts/m0-evidence.mjs`
recomputes every referenced digest, compares two declared entrypoint files,
checks in-toto/SLSA-shaped subject and source fields, re-scores a
release-signed runtime baseline report, and verifies its Ed25519 evidence
signature against the expected repository-pinned key at
`.github/keys/m0-release-ed25519.pub`. That governed release key has not been
provisioned yet, so real assembly remains unavailable; tests use isolated
fixture keys only.

The legacy verifier reports assurance
`entrypoint-release-signed-scaffold/v1`. The roadmap gate requires
`full-bundle-builder-attested/v2`, so this layer can never make M0 green by
itself. The implemented v2 workflow covers the complete engine bundle,
independently authenticated builder attestations/workflow runs, effective GN
args, resolved inputs, the complete toolchain, and an artifact-driven live run.

Each platform record (`windows-x64`, `macos-universal`, `linux-x64`) contains:

- `buildA` / `buildB`: distinct artifact paths, CI run IDs, expected platform
  runners, and independently hashed SLSA provenance records;
- `artifact`: `{ "path", "sha256" }`;
- `verificationReport`: `{ "path", "sha256" }`;
- `releaseSignature`: standard-base64 Ed25519 signature over the versioned
  evidence input defined by `evidenceSigningInput`.

The required report is exactly the artifact-runtime
`proteus-verify-lab-v1-v5` baseline with the current rule version, explicit
V1–V5 measured/unavailable results, a bounded aggregate, verdict/gate state, and
a structured inconsistency list. It need not be green: eliminating the stock
baseline's fingerprint inconsistencies is M1, and V4 network parity is M2.
The report carries the collected observation and scoring context; verification
re-runs the current versioned Node normalizer/rule catalog and exact-compares
coverage, vectors, aggregate, verdict, gate state, and inconsistencies.
It also binds the exact four-file controlled probe bundle. The machine producer
launches the declared executable over Chromium's process-bound debugging pipe,
self-hosts those frozen probe bytes on an OS-assigned IPv4 loopback port, and
checks the executable hash/stat before and after collection.
The release-signed report records
`proteus-executable-header-inspector/v1`. The verifier parses the referenced
artifact's PE32+/ELF64/Mach-O fat headers directly and rejects a declared
architecture that is absent from the bytes, including either missing x86_64 or
arm64 slice in macOS universal.

The legacy checks establish internal consistency; a release signer can still supply a
synthetic observation or self-asserted provenance. They do not prove that an
independent builder produced the bytes or that the live harness ran. Platform
builder/OIDC attestations, full-bundle reproducibility, effective generated
`args.gn`, and complete pinned toolchain validation are therefore enforced by
the v2 aggregate and hard gate instead.

The report records only
`runner=external-ephemeral-claimed`, `attestation=none`, and
`localProcessCleanup=best-effort`. This prevents a caller-supplied isolation
claim from being mistaken for trusted containment. Process-group/`taskkill`
cleanup cannot contain a deliberately escaping artifact; the build orchestrator
must provide and eventually attest an independently enforced disposable
VM/container/job.

The non-UI live harness can produce this report directly from a built engine:

```bash
node verify-lab/tools/drive-chrome.mjs --json --external-containment \
  --chrome /path/to/engine-executable \
  --platform linux-x64 \
  --linux-sandbox /root-owned/mode-4755/chrome_sandbox \
  > engine-chromium/artifacts/linux-x64.verification.json
```

Linux machine mode validates that the sandbox path is canonical, is an
ordinary non-symlink file owned by uid 0, and has exact mode `4755`. The
GitHub-hosted M0 builder installs the sandbox into a root-controlled directory
before running the live report; it never disables the Chromium sandbox.
Machine mode also starts Chromium with full NetLog capture, sends the root
`Browser.close` command, requires a successful command write and normal process
exit, then reads the flushed log through one bounded stable file descriptor.
The report is rejected if it observes
`clients2.google.com/time/1/current`.

All paths are relative to this directory.
Absolute paths, traversal, symlinks, missing files, cross-platform digest reuse,
digest mismatches, unknown runners/platforms, malformed/no-op reports, and
invalid signatures fail closed. The pinned private key is never stored here.

## Assemble the signed entrypoint-evidence document

The bounded assembler accepts a strict, path-only draft. It rejects duplicate
JSON keys, unknown fields, caller-supplied hashes/signatures, unsafe artifact
paths (including aliases and hardlinks used as fake independent builds),
non-exact runner names, duplicate build IDs, provenance whose builder or
invocation does not match the draft, and a private key that does not match the
repository-pinned public key. It recomputes every digest, signs each platform,
runs the same entrypoint verifier used by the local evidence layer, and writes
only the finished JSON to stdout. The hard M0 gate then rejects this lower
assurance level until the build-farm layer described above exists.

From the repository root, capture stdout in a staging file and only install it
after the command succeeds:

```bash
node engine-chromium/scripts/assemble-m0-evidence.mjs \
  --draft /secure/staging/m0-evidence-draft.json \
  --private-key /secure/keys/m0-release-ed25519.pkcs8.pem \
  > engine-chromium/artifacts/m0-build-evidence.json.tmp \
  && mv engine-chromium/artifacts/m0-build-evidence.json.tmp \
    engine-chromium/artifacts/m0-build-evidence.json
```

Both input files must be ordinary, non-symlink files. The private key is an
external, unencrypted Ed25519 PKCS#8 PEM file; its raw input buffer is cleared
after Node imports the key object and is never included in output or written by
the assembler. The imported key object remains process memory until the
short-lived assembler exits. The pinned public key must already exist at
`.github/keys/m0-release-ed25519.pub`.

The draft has exactly this shape; every referenced path is relative to this
`artifacts` directory:

```json
{
  "schemaVersion": "1.0.0",
  "chromiumCommit": "9261fd0a595ac4964ea84e6bd4a025c1173a2ffa",
  "platforms": {
    "windows-x64": {
      "buildA": {
        "path": "windows-x64/build-a/proteus.exe",
        "runId": "windows-build-a-12345",
        "runner": "windows-latest",
        "provenance": {
          "path": "windows-x64/build-a/provenance.json"
        }
      },
      "buildB": {
        "path": "windows-x64/build-b/proteus.exe",
        "runId": "windows-build-b-12346",
        "runner": "windows-latest",
        "provenance": {
          "path": "windows-x64/build-b/provenance.json"
        }
      },
      "artifact": {
        "path": "windows-x64/release/proteus.exe"
      },
      "verificationReport": {
        "path": "windows-x64/release/verification.json"
      }
    },
    "macos-universal": {
      "buildA": {
        "path": "macos-universal/build-a/Proteus",
        "runId": "macos-build-a-22345",
        "runner": "macos-latest",
        "provenance": {
          "path": "macos-universal/build-a/provenance.json"
        }
      },
      "buildB": {
        "path": "macos-universal/build-b/Proteus",
        "runId": "macos-build-b-22346",
        "runner": "macos-latest",
        "provenance": {
          "path": "macos-universal/build-b/provenance.json"
        }
      },
      "artifact": {
        "path": "macos-universal/release/Proteus"
      },
      "verificationReport": {
        "path": "macos-universal/release/verification.json"
      }
    },
    "linux-x64": {
      "buildA": {
        "path": "linux-x64/build-a/proteus",
        "runId": "linux-build-a-32345",
        "runner": "ubuntu-latest",
        "provenance": {
          "path": "linux-x64/build-a/provenance.json"
        }
      },
      "buildB": {
        "path": "linux-x64/build-b/proteus",
        "runId": "linux-build-b-32346",
        "runner": "ubuntu-latest",
        "provenance": {
          "path": "linux-x64/build-b/provenance.json"
        }
      },
      "artifact": {
        "path": "linux-x64/release/proteus"
      },
      "verificationReport": {
        "path": "linux-x64/release/verification.json"
      }
    }
  }
}
```

Each `runId` must be globally unique and must exactly match the corresponding
provenance `invocationId`; the provenance builder ID, observed toolchain, target
architectures, source commit, active patch-series digest (future backlog bytes
are excluded), GN args, and report contents remain subject to the verifier rules
described above.
