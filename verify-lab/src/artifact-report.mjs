import { isDeepStrictEqual } from 'node:util';
import {
  M0_ARTIFACT_REPORT_SCHEMA_VERSION,
  M0_ARTIFACT_INSPECTIONS,
  M0_EXTERNAL_EXECUTION_ISOLATION,
  inspectArtifactArchitectures,
  sha256File,
} from '../../scripts/m0-evidence.mjs';
import { loadReference } from './reference.mjs';
import { normalize } from './normalize.mjs';
import { score } from './score.mjs';
import { RULES_VERSION } from './rules.mjs';
import { validateNetworkTimeAudit } from './network-time-audit.mjs';

export function buildArtifactBaselineReport({
  artifactPath,
  context = {},
  executionIsolation,
  networkTimeAudit,
  observation,
  platform,
  probe,
}) {
  const inspection = M0_ARTIFACT_INSPECTIONS[platform];
  if (!inspection) {
    throw new TypeError(`unsupported M0 artifact platform ${String(platform)}`);
  }
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)) {
    throw new TypeError('artifact baseline requires a collected observation object');
  }
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw new TypeError('artifact baseline context must be an object');
  }
  if (!probe || typeof probe !== 'object' || Array.isArray(probe)) {
    throw new TypeError('artifact baseline requires a controlled probe binding');
  }
  if (!isDeepStrictEqual(
    executionIsolation,
    M0_EXTERNAL_EXECUTION_ISOLATION,
  )) {
    throw new TypeError(
      'artifact baseline requires the explicit unverified external-isolation claim',
    );
  }
  validateNetworkTimeAudit(networkTimeAudit);
  const scored = score(normalize(observation, context), loadReference());
  if (scored.scope !== 'runtime') {
    throw new TypeError('artifact baseline requires a runtime-scoped score');
  }
  const artifactSha256 = sha256File(artifactPath);
  const architectures = inspectArtifactArchitectures(artifactPath, platform);

  return {
    schemaVersion: M0_ARTIFACT_REPORT_SCHEMA_VERSION,
    platform,
    browserArtifactSha256: artifactSha256,
    artifactDriven: true,
    executionIsolation: { ...executionIsolation },
    networkTimeAudit: { ...networkTimeAudit },
    probe,
    observation,
    context,
    artifactInspection: {
      artifactSha256,
      tool: inspection.tool,
      architectures,
    },
    completed: true,
    suites: [{
      name: 'proteus-verify-lab-v1-v5',
      scope: 'artifact-runtime',
      rulesVersion: RULES_VERSION,
      completed: true,
      coverageComplete: scored.coverage?.complete === true,
      verdict: scored.verdict,
      gated: scored.gated,
      aggregate: scored.aggregate,
      inconsistencies: scored.inconsistencies,
      vectors: scored.vectors,
    }],
  };
}
