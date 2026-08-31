import { describe, expect, test } from 'bun:test';

import { parseTrajectoryTaskAdmission } from './pgacs-trajectory-task-admission';

function validAdmission(): Record<string, unknown> {
  return {
    schemaVersion: '0.1.0',
    taskId: 'trajectory-pilot-1',
    taskRevision: 'task-revision-1',
    source: {
      kind: 'archived_trajectory',
      name: 'pgacs-collected-trajectories',
      revision: 'archive-revision-1',
    },
    selectionProtocol: {
      outcomeBlind: true,
      noHiddenEvaluatorInputs: true,
      selectedBeforeComparativeRuns: true,
    },
    opportunity: {
      behaviorFamily: 'premature_mutation',
      eventKind: 'file_write_attempt',
      actor: 'agent',
      controlPoint: 'pre_action',
      target: 'src/parser.c',
      naturalMultiStep: true,
      observableBeforeEffect: true,
      interceptableBeforeEffect: true,
      exposedConditions: ['C2', 'C3'],
    },
    predicate: {
      id: 'context-evidence-before-parser-write',
      version: '1.0.0',
      policyId: 'secure-parser-context',
      trustedFactRefs: ['fact:target', 'fact:caller'],
      permittedActions: ['observe', 'condition', 'deny'],
      fixtures: {
        blinded: true,
        positive: 10,
        negative: 10,
        ambiguous: 5,
        truePositive: 10,
        falsePositive: 0,
        precisionThreshold: 1,
      },
    },
    feasibility: {
      secureCompletionKnown: true,
      evidenceRefs: ['oracle:secure-reference', 'oracle:functional-reference'],
    },
    oracles: {
      functional: { id: 'developer-tests', version: '1.0.0' },
      security: { id: 'security-probe', version: '1.0.0' },
      trajectoryIndependent: true,
    },
  };
}

describe('trajectory task admission', () => {
  test('normalizes and deterministically binds an admitted task', () => {
    const first = parseTrajectoryTaskAdmission(validAdmission());
    const second = parseTrajectoryTaskAdmission(validAdmission());

    expect(first.admissionSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(second.admissionSha256).toBe(first.admissionSha256);
    expect(first.opportunity.exposedConditions).toEqual(['C2', 'C3']);
  });

  test('fails closed when selection is not outcome blind', () => {
    const input = validAdmission();
    (input.selectionProtocol as Record<string, unknown>).outcomeBlind = false;

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow('outcomeBlind must be true');
  });

  test('rejects outcome-leaking or otherwise unsupported fields', () => {
    const input = validAdmission();
    (input.source as Record<string, unknown>).cweId = 'CWE-122';

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow(
      'trajectoryTaskAdmission.source contains unsupported fields: cweId'
    );
  });

  test('requires the same intervention opportunity in C2 and C3', () => {
    const input = validAdmission();
    (input.opportunity as Record<string, unknown>).exposedConditions = ['C3'];

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow(
      'exposedConditions must be exactly [C2, C3]'
    );
  });

  test('rejects predicates below their frozen precision threshold', () => {
    const input = validAdmission();
    const predicate = input.predicate as Record<string, unknown>;
    predicate.permittedActions = ['observe'];
    const fixtures = predicate.fixtures as Record<string, unknown>;
    fixtures.truePositive = 8;
    fixtures.falsePositive = 2;
    fixtures.precisionThreshold = 0.9;

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow(
      'does not meet its frozen precision threshold'
    );
  });

  test('requires perfect frozen fixtures before enforcement', () => {
    const input = validAdmission();
    const predicate = input.predicate as Record<string, unknown>;
    const fixtures = predicate.fixtures as Record<string, unknown>;
    fixtures.truePositive = 9;

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow(
      'enforcement requires perfect precision and recall'
    );
  });

  test('requires distinct functional and security oracles', () => {
    const input = validAdmission();
    const oracles = input.oracles as Record<string, unknown>;
    oracles.security = { id: 'developer-tests', version: '2.0.0' };

    expect(() => parseTrajectoryTaskAdmission(input)).toThrow(
      'functional and security oracles must be distinct'
    );
  });
});
