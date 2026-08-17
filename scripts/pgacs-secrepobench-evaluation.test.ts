import { describe, expect, test } from 'bun:test';

import {
  normalizeSecRepoBenchExecution,
  normalizeSecRepoBenchOracleResult,
  type SecRepoBenchProbeStatus,
} from './pgacs-secrepobench-evaluation';

const TASK_ID = '910';
const CANDIDATE_SHA256 = 'a'.repeat(64);

function rawResult(input: {
  compile: SecRepoBenchProbeStatus;
  functional: SecRepoBenchProbeStatus;
  security: SecRepoBenchProbeStatus;
  decision: string;
}): unknown {
  return {
    oracleVersion: '0.5.0',
    oracleId: 'pgacs-secrepobench:single-task:v0.5',
    taskId: TASK_ID,
    candidateSha256: CANDIDATE_SHA256,
    decision: input.decision,
    probes: [
      {
        id: 'repository.compile',
        class: 'functional',
        status: input.compile,
        detail: 'compile detail',
        exitCode: input.compile === 'pass' ? 0 : 1,
        stdout: 'compile stdout',
        stderr: '',
      },
      {
        id: 'secrepobench.developer-tests',
        class: 'functional',
        status: input.functional,
        detail: { total: 3, fail: [] },
        exitCode: input.functional === 'pass' ? 0 : 1,
        stdout: 'test stdout',
        stderr: '',
      },
      {
        id: 'secrepobench.oss-fuzz-poc',
        class: 'security',
        status: input.security,
        detail: input.security === 'fail' ? 'crash' : 'no crash',
        exitCode: input.security === 'pass' ? 0 : 1,
        stdout: 'security stdout',
        stderr: '',
      },
    ],
    securityContext: { cweId: 'CWE-122', crashType: 'hidden crash' },
    evaluatorIsolation: {
      network: 'none',
      capabilities: 'dac-override-chown-only',
      noNewPrivileges: true,
      candidateMount: 'read-only',
      attempts: 'independent-containers',
    },
  };
}

describe('SecRepoBench evaluation normalization', (): void => {
  test('recomputes verified, security, functional, and inconclusive outcomes', (): void => {
    const fixtures = [
      {
        raw: rawResult({
          compile: 'pass',
          functional: 'pass',
          security: 'pass',
          decision: 'verified',
        }),
        expected: { decision: 'verified', outcomeClass: 'success', repairEligible: false },
      },
      {
        raw: rawResult({
          compile: 'pass',
          functional: 'pass',
          security: 'fail',
          decision: 'insecure',
        }),
        expected: {
          decision: 'insecure',
          outcomeClass: 'candidate_failure',
          repairEligible: true,
          securityFailureConfirmed: true,
        },
      },
      {
        raw: rawResult({
          compile: 'fail',
          functional: 'inconclusive',
          security: 'inconclusive',
          decision: 'functional_failure',
        }),
        expected: {
          decision: 'functional_failure',
          outcomeClass: 'candidate_failure',
          repairEligible: true,
        },
      },
      {
        raw: rawResult({
          compile: 'pass',
          functional: 'inconclusive',
          security: 'pass',
          decision: 'oracle_inconclusive',
        }),
        expected: {
          decision: 'oracle_inconclusive',
          outcomeClass: 'inconclusive',
          repairEligible: false,
        },
      },
    ];

    for (const fixture of fixtures) {
      const outputs = Array.from({ length: 3 }, () =>
        normalizeSecRepoBenchOracleResult(fixture.raw, {
          taskId: TASK_ID,
          candidateSha256: CANDIDATE_SHA256,
        })
      );
      expect(outputs[0]).toMatchObject(fixture.expected);
      expect(outputs[1]).toEqual(outputs[0]);
      expect(outputs[2]).toEqual(outputs[0]);
      expect(JSON.stringify(outputs[0])).not.toContain('CWE-122');
      expect(JSON.stringify(outputs[0])).not.toContain('hidden crash');
      expect(outputs[0]?.evaluationSha256).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  test('turns process, malformed, and aggregate failures into harness errors', (): void => {
    const processFailure = normalizeSecRepoBenchExecution({
      taskId: TASK_ID,
      candidateSha256: CANDIDATE_SHA256,
      exitCode: 125,
      stderr: 'docker unavailable',
    });
    expect(processFailure).toMatchObject({
      decision: 'harness_error',
      outcomeClass: 'harness_error',
      repairEligible: false,
      securityFailureConfirmed: false,
    });

    const malformed = normalizeSecRepoBenchExecution({
      taskId: TASK_ID,
      candidateSha256: CANDIDATE_SHA256,
      exitCode: 0,
      rawResult: { invalid: true },
    });
    expect(malformed.decision).toBe('harness_error');

    const mismatch = rawResult({
      compile: 'pass',
      functional: 'pass',
      security: 'fail',
      decision: 'verified',
    });
    expect(() =>
      normalizeSecRepoBenchOracleResult(mismatch, {
        taskId: TASK_ID,
        candidateSha256: CANDIDATE_SHA256,
      })
    ).toThrow('aggregate mismatch');
  });

  test('does not expose raw evaluator output in normalized evidence', (): void => {
    const raw = rawResult({
      compile: 'pass',
      functional: 'pass',
      security: 'pass',
      decision: 'verified',
    });
    const evaluation = normalizeSecRepoBenchOracleResult(raw, {
      taskId: TASK_ID,
      candidateSha256: CANDIDATE_SHA256,
    });
    const serialized = JSON.stringify(evaluation);
    expect(serialized).not.toContain('compile stdout');
    expect(serialized).not.toContain('security stdout');
    expect(serialized).not.toContain('no crash');
  });
});
