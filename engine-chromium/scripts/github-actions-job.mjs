#!/usr/bin/env node
// Resolve the current GitHub Actions job/check-run ID. The builder uses this
// only as a declaration; the hard gate later re-fetches and verifies the job,
// workflow run, runner labels, and artifact through the GitHub API.

import {
  appendFileSync,
  writeSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const ID_RE = /^[1-9][0-9]{0,19}$/u;

export function selectCurrentActionsJob(document, {
  runnerName,
  runAttempt,
} = {}) {
  if (!document || typeof document !== 'object'
      || !Array.isArray(document.jobs)) {
    throw new TypeError('GitHub jobs response is malformed');
  }
  const attempt = Number(runAttempt);
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new TypeError('GITHUB_RUN_ATTEMPT must be a positive integer');
  }
  const candidates = document.jobs.filter((job) =>
    job
    && typeof job === 'object'
    && ID_RE.test(String(job.id))
    && job.status === 'in_progress'
    && Number(job.run_attempt ?? attempt) === attempt
    && (
      typeof runnerName !== 'string'
      || runnerName.length === 0
      || job.runner_name === runnerName
    ));
  if (candidates.length !== 1) {
    throw new TypeError(
      `expected exactly one in-progress current runner job, found ${candidates.length}`,
    );
  }
  return String(candidates[0].id);
}

async function githubJson(path, token) {
  const api = process.env.GITHUB_API_URL ?? 'https://api.github.com';
  const response = await fetch(`${api}${path}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'proteus-m0-builder',
    },
    redirect: 'error',
  });
  if (!response.ok) {
    throw new TypeError(
      `GitHub API ${path} returned ${response.status}`,
    );
  }
  return response.json();
}

async function main() {
  const repository = process.env.GITHUB_REPOSITORY;
  const runId = process.env.GITHUB_RUN_ID;
  const token = process.env.GITHUB_TOKEN;
  if (typeof repository !== 'string'
      || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)
      || !ID_RE.test(runId ?? '')
      || typeof token !== 'string'
      || token.length === 0) {
    throw new TypeError(
      'GITHUB_REPOSITORY, GITHUB_RUN_ID, and GITHUB_TOKEN are required',
    );
  }
  const document = await githubJson(
    `/repos/${repository}/actions/runs/${runId}/jobs`
      + '?filter=latest&per_page=100',
    token,
  );
  const checkRunId = selectCurrentActionsJob(document, {
    runnerName: process.env.RUNNER_NAME,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
  });
  const output = process.env.GITHUB_OUTPUT;
  if (output) {
    appendFileSync(output, `check-run-id=${checkRunId}\n`, {
      encoding: 'utf8',
    });
  }
  writeSync(process.stdout.fd, `${checkRunId}\n`);
}

const isDirect = import.meta.main ?? (
  process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
);
if (isDirect) {
  try {
    await main();
  } catch (error) {
    writeSync(process.stderr.fd, `ERROR: ${error.message}\n`);
    process.exitCode = 2;
  }
}
