import { expect, test } from 'bun:test';
import { createHash } from 'crypto';

import {
  fingerprintSelection,
  type SemanticSelection,
  validateSelectionIntegrity,
} from './run-pgacs-trajectory-prototype';

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function selection(corpusText: string): SemanticSelection {
  const tasks = [
    {
      taskId: 'file-parser-untrusted-archive',
      selected: [{ policyId: 'policy-1', importance: 'required', reason: 'test' }],
    },
  ];
  return {
    constraints: { taskFamilyProvided: false },
    sourceHashes: { corpusSha256: sha256(corpusText) },
    selectionFingerprint: fingerprintSelection(tasks),
    tasks,
  };
}

test('trajectory input accepts an intact corrected semantic selection', () => {
  const corpusText = '{"records":[]}';
  expect(() => validateSelectionIntegrity(corpusText, selection(corpusText))).not.toThrow();
});

test('trajectory input rejects a selection from another corpus', () => {
  const semanticSelection = selection('{"records":[]}');
  expect(() => validateSelectionIntegrity('{"records":[1]}', semanticSelection)).toThrow(
    'different policy corpus'
  );
});

test('trajectory input rejects historical task-family metadata', () => {
  const corpusText = '{"records":[]}';
  const semanticSelection = selection(corpusText);
  semanticSelection.constraints = { taskFamilyProvided: true };
  expect(() => validateSelectionIntegrity(corpusText, semanticSelection)).toThrow(
    'historical or missing input-integrity metadata'
  );
});

test('trajectory input rejects modified task selections', () => {
  const corpusText = '{"records":[]}';
  const semanticSelection = selection(corpusText);
  semanticSelection.tasks[0]?.selected.push({
    policyId: 'policy-2',
    importance: 'relevant',
    reason: 'modified',
  });
  expect(() => validateSelectionIntegrity(corpusText, semanticSelection)).toThrow(
    'fingerprint does not match'
  );
});
