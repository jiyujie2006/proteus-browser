<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-party licensing and release compliance

This document separates the repository's **current contents** from dependencies
and engines that the roadmap may introduce later. It is operational guidance,
not an additional software license and not a substitute for the license texts
that must accompany a particular release artifact.

## Current repository status

The current pre-alpha repository contains first-party Proteus source,
documentation, tests, profile fixtures, an engine build scaffold, and one
Proteus-authored Chromium patch. The patch includes the minimum Chromium source
context needed to change the pinned Network Time feature default. That context
remains under Chromium's BSD 3-Clause License; the exact pinned license text is
stored at
[`LICENSES/Chromium-BSD-3-Clause.txt`](../LICENSES/Chromium-BSD-3-Clause.txt).
The patch header binds the exact Chromium commit, path, blob, and source-file
SHA-256.

The repository does **not** contain or distribute:

- a Chromium or Firefox source checkout;
- a modified Chromium, Firefox, or Camoufox binary;
- the ungoogled-chromium patch set or any copied ungoogled-chromium payload;
- uTLS, uquic, a Go network sidecar, or a Manager application; or
- a release `licenses/` directory or a build-derived production SBOM.

The one active file under `engine-chromium/patches/layer0-degoogle/` contains a
real Proteus-authored change plus BSD-licensed Chromium diff context. The M1/M3
files remain Proteus-authored metadata-only specifications. JavaScript and Rust
dependencies are resolved from their package-manager lockfiles and retain their
own licenses. The repository does not vendor their source trees.

The active patch only changes Chromium's Google-backed Network Time feature
from enabled-by-default to disabled-by-default on desktop and Android. An
explicit feature override can re-enable it. Neither the patch name nor its
directory is a claim that the repository has completed a general de-Googling
audit.

[`NOTICE`](../NOTICE) contains only current Proteus and Chromium attribution.
Planned dependencies must not be added to `NOTICE` in advance.

## Rules for future source and binary distributions

Before any engine or application artifact is published, its release job must:

1. derive an exact dependency inventory from the checked-out sources, lockfiles,
   build graph, and packaged bytes rather than from a hand-written allow-list;
2. preserve every applicable upstream copyright, patent, trademark, attribution,
   and license notice;
3. include the exact license texts and required notices for the revisions that
   were actually built;
4. mark modified upstream files when their governing license requires it;
5. provide source-code availability, relinking material, or other compliance
   artifacts required by file-level or library copyleft licenses;
6. generate an artifact-specific SBOM and third-party notice bundle, then bind
   both to the signed build provenance and artifact digest; and
7. perform a separate trademark review of names, icons, and product branding.

A license identifier on an allow-list is not proof that redistribution
obligations have been met. The release gate must evaluate the actual component,
version, linkage/packaging form, notices, and required accompanying materials.

## Planned upstreams are not current contents

The architecture currently anticipates Chromium-family and Firefox-family
engines and may evaluate projects such as ungoogled-chromium, Camoufox, uTLS, or
uquic. Their exact revisions, contents, licenses, and trademark requirements
must be re-audited when they are introduced. This document deliberately makes no
present-tense claim that Proteus distributes them.

## Authority

For a release, the authoritative compliance inputs are:

- the license and notice files inside the pinned upstream source revisions;
- per-file headers and component metadata;
- the build-derived SBOM and packaged-byte inventory; and
- the artifact-specific license/notice bundle.

This planning document and the current component-manifest scaffold are not
substitutes for those inputs.
