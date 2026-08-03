import { describe, expect, test } from 'bun:test';

import { mergeExperimentResults } from './merge-pgacs-baxbench-c2-results';
import type { CellResult } from './run-pgacs-baxbench-c2';

function cell(condition: 'B0' | 'C0', decision: CellResult['terminal']['decision']): CellResult {
  return {
    schemaVersion: '0.1.0',
    taskId: 'Login-Python-FastAPI',
    condition,
    activationPlanSha256: 'activation',
    obligationProbeBindings: {},
    promptSha256: 'prompt',
    ledgerHeadSha256: 'ledger',
    initial: {} as CellResult['initial'],
    repairEligible: false,
    repairAttempted: false,
    terminalScope: {
      changedPaths: ['app.py'],
      runtimeArtifactPaths: [],
      scopeViolations: [],
      allowedMutationPaths: ['app.py'],
    },
    terminal: {
      decision,
      secureGeneration: decision === 'verified',
      functionalCorrectness: decision === 'verified',
      jointAccepted: decision === 'verified',
      correctSecurityBlock: false,
      safeSystemOutcome: decision === 'verified',
    },
  };
}

describe('PGACS experiment result merge', () => {
  test('replaces only primary harness errors and records provenance', () => {
    const merged = mergeExperimentResults(
      [cell('B0', 'verified'), cell('C0', 'blocked_harness_error')],
      [{ sourcePath: 'replacement.json', results: [cell('C0', 'observed_insecure')] }]
    );
    expect(merged.results.find(result => result.condition === 'C0')?.terminal.decision).toBe(
      'observed_insecure'
    );
    expect(merged.replacementReceipts).toEqual([
      {
        taskId: 'Login-Python-FastAPI',
        condition: 'C0',
        replacedDecision: 'blocked_harness_error',
        replacementDecision: 'observed_insecure',
        sourcePath: 'replacement.json',
      },
    ]);
  });

  test('refuses to replace a substantive outcome', () => {
    expect(() =>
      mergeExperimentResults(
        [cell('B0', 'verified')],
        [{ sourcePath: 'replacement.json', results: [cell('B0', 'observed_insecure')] }]
      )
    ).toThrow('Refusing to replace non-harness outcome');
  });
});
