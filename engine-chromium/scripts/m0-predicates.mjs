// Canonical hard-M0 attestation predicates shared by the builder and verifier.
//
// Keep this module pure: builders may serialize these objects before the
// attestations exist, while the hard gate independently reconstructs them from
// downloaded bundle bytes and GitHub API facts.

export const M0_EVIDENCE_V2_SCHEMA_VERSION = '2.0.0';
export const M0_EVIDENCE_V2_ASSURANCE_LEVEL =
  'full-bundle-builder-attested/v2';

function exactObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function validateInputs(buildFacts, policy) {
  exactObject(buildFacts, 'build facts');
  exactObject(policy, 'M0 predicate policy');
  exactObject(buildFacts.repository, 'build repository');
  exactObject(buildFacts.outputs, 'build outputs');
  exactObject(policy.buildContract, 'M0 build contract');
  exactObject(policy.buildContract.source, 'M0 source contract');
  exactObject(policy.predicateTypes, 'M0 predicate types');

  for (const [label, value] of [
    ['platform', buildFacts.platform],
    ['slot', buildFacts.slot],
    ['sourceDigest', buildFacts.sourceDigest],
    ['signerDigest', buildFacts.signerDigest],
    ['workflow', buildFacts.workflow],
    ['repository.nameWithOwner', buildFacts.repository.nameWithOwner],
    ['repository.repositoryId', buildFacts.repository.repositoryId],
    ['repository.ownerId', buildFacts.repository.ownerId],
    ['repository.visibility', buildFacts.repository.visibility],
    ['buildContractSha256', buildFacts.buildContractSha256],
    ['trustContractSha256', buildFacts.trustContractSha256],
    ['artifactName', buildFacts.artifactName],
    ['artifactDigest', buildFacts.artifactDigest],
    ['artifactInnerSha256', buildFacts.artifactInnerSha256],
    ['sourceRef', policy.sourceRef],
    ['predicateTypes.build', policy.predicateTypes.build],
  ]) {
    nonEmptyString(value, label);
  }
  positiveInteger(buildFacts.runAttempt, 'runAttempt');
  positiveInteger(buildFacts.artifactSize, 'artifactSize');
  positiveInteger(buildFacts.artifactInnerSize, 'artifactInnerSize');
  for (const [label, value] of [
    ['runId', buildFacts.runId],
    ['checkRunId', buildFacts.checkRunId],
    ['artifactId', buildFacts.artifactId],
  ]) {
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(value)) {
      throw new TypeError(`${label} must be a positive decimal GitHub ID`);
    }
  }
}

export function createM0BuildPredicate(buildFacts, policy) {
  validateInputs(buildFacts, policy);
  return {
    schemaVersion: M0_EVIDENCE_V2_SCHEMA_VERSION,
    assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
    platform: buildFacts.platform,
    buildSlot: buildFacts.slot,
    repository: {
      nameWithOwner: buildFacts.repository.nameWithOwner,
      repositoryId: buildFacts.repository.repositoryId,
      ownerId: buildFacts.repository.ownerId,
      visibility: buildFacts.repository.visibility,
    },
    source: {
      digest: buildFacts.sourceDigest,
      ref: policy.sourceRef,
    },
    workflow: {
      path: buildFacts.workflow,
      digest: buildFacts.signerDigest,
    },
    github: {
      runId: buildFacts.runId,
      runAttempt: buildFacts.runAttempt,
      checkRunId: buildFacts.checkRunId,
      artifactId: buildFacts.artifactId,
      artifactName: buildFacts.artifactName,
      artifactDigest: buildFacts.artifactDigest,
      artifactSize: buildFacts.artifactSize,
      artifactInnerSha256: buildFacts.artifactInnerSha256,
      artifactInnerSize: buildFacts.artifactInnerSize,
    },
    contracts: {
      buildContractSha256: buildFacts.buildContractSha256,
      trustContractSha256: buildFacts.trustContractSha256,
    },
    outputs: { ...buildFacts.outputs },
  };
}

export function createM0ProvenancePredicate(buildFacts, policy) {
  validateInputs(buildFacts, policy);
  const buildPredicate = createM0BuildPredicate(buildFacts, policy);
  return {
    buildDefinition: {
      buildType: policy.predicateTypes.build,
      externalParameters: buildPredicate,
      internalParameters: {
        assuranceLevel: M0_EVIDENCE_V2_ASSURANCE_LEVEL,
        buildContractSha256: buildFacts.buildContractSha256,
        trustContractSha256: buildFacts.trustContractSha256,
      },
      resolvedDependencies: [
        {
          uri: policy.buildContract.source.chromiumRepository,
          digest: {
            gitCommit: policy.buildContract.source.chromiumCommit,
          },
        },
        {
          uri: policy.buildContract.source.depotToolsRepository,
          digest: {
            gitCommit: policy.buildContract.source.depotToolsCommit,
          },
        },
      ],
    },
    runDetails: {
      builder: {
        id:
          `https://github.com/${buildFacts.repository.nameWithOwner}/`
          + `${buildFacts.workflow}@${buildFacts.signerDigest}`,
      },
      metadata: {
        invocationId: `${buildFacts.runId}/${buildFacts.runAttempt}`,
      },
    },
  };
}
