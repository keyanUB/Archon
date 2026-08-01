import { createHash } from 'crypto';

import { expect, test } from 'bun:test';

import {
  fingerprintSelection,
  validateEvaluationIntegrity,
} from './evaluate-pgacs-semantic-selector';

const labels = {
  version: 'test',
  labelType: 'model_generated_silver',
  tasks: [
    {
      taskId: 'task-1',
      requiredPolicyIds: ['policy-required'],
      relevantPolicyIds: ['policy-relevant'],
    },
  ],
};
const labelsText = JSON.stringify(labels);
const labelsSha256 = createHash('sha256').update(labelsText).digest('hex');
const tasks = [
  {
    taskId: 'task-1',
    selected: [{ policyId: 'policy-required', importance: 'required', reason: 'required' }],
    coverageGaps: [],
  },
];
const selectionFingerprint = fingerprintSelection(tasks);

function selection() {
  return {
    configuredModel: 'test',
    reportedModelIds: ['test'],
    catalogSize: 1,
    sourceHashes: { labelsSha256 },
    selectionFingerprint,
    tasks,
  };
}

function adjudication() {
  return {
    version: 'test',
    adjudicatorRole: 'test',
    labelsSha256,
    selectionFingerprint,
    tasks: [
      {
        taskId: 'task-1',
        requiredAssessments: [
          {
            labeledPolicyId: 'policy-required',
            status: 'covered_exact' as const,
            coveredBySelectedPolicyIds: ['policy-required'],
          },
        ],
        selectedAssessments: [
          {
            selectedPolicyId: 'policy-required',
            verdict: 'covers_required' as const,
            matchedLabeledPolicyIds: ['policy-required'],
          },
        ],
      },
    ],
  };
}

test('accepts adjudication bound to the exact labels and selection', () => {
  expect(() =>
    validateEvaluationIntegrity(labels, labelsText, selection(), adjudication())
  ).not.toThrow();
});

test('rejects stale adjudication after selection changes', () => {
  const stale = adjudication();
  stale.selectionFingerprint = 'stale';
  expect(() => validateEvaluationIntegrity(labels, labelsText, selection(), stale)).toThrow(
    'does not match the current semantic selection'
  );
});
