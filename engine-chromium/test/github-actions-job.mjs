#!/usr/bin/env node

import assert from 'node:assert/strict';
import { selectCurrentActionsJob } from '../scripts/github-actions-job.mjs';

let passed = 0;
function check(label, body) {
  try {
    body();
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } catch (error) {
    process.stderr.write(`not ok - ${label}: ${error.stack || error}\n`);
    process.exitCode = 1;
  }
}

const response = {
  jobs: [
    {
      id: 1001,
      status: 'completed',
      conclusion: 'success',
      run_attempt: 1,
      runner_name: 'GitHub Actions 1',
    },
    {
      id: 1002,
      status: 'in_progress',
      conclusion: null,
      run_attempt: 2,
      runner_name: 'GitHub Actions 2',
    },
  ],
};

check('current job selection binds runner name and run attempt', () => {
  assert.equal(selectCurrentActionsJob(response, {
    runnerName: 'GitHub Actions 2',
    runAttempt: '2',
  }), '1002');
});

check('ambiguous in-progress jobs fail closed', () => {
  assert.throws(
    () => selectCurrentActionsJob({
      jobs: [
        ...response.jobs,
        {
          id: 1003,
          status: 'in_progress',
          run_attempt: 2,
          runner_name: 'GitHub Actions 2',
        },
      ],
    }, {
      runnerName: 'GitHub Actions 2',
      runAttempt: 2,
    }),
    /exactly one/u,
  );
});

check('wrong runner or attempt cannot select another job', () => {
  assert.throws(
    () => selectCurrentActionsJob(response, {
      runnerName: 'attacker',
      runAttempt: 2,
    }),
    /found 0/u,
  );
});

if (!process.exitCode) {
  process.stdout.write(`${passed} GitHub Actions job tests passed\n`);
}
