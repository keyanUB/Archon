import { describe, expect, test } from 'bun:test';

import { selectTrajectoryCandidateTasks } from './select-pgacs-trajectory-candidates';

const metadata = {
  old: { project_name: 'alpha', changed_file: 'src/old.c', crash_type: 'secret' },
  a: {
    project_name: 'alpha',
    changed_file: 'src/a.c',
    crash_type: 'hidden',
    fixing_commit: 'hidden-fix',
  },
  b: { project_name: 'alpha', changed_file: 'src/b.c', cwe: 'hidden' },
  c: { project_name: 'beta', changed_file: 'src/c.c', evaluator_outcome: 'hidden' },
};

describe('trajectory candidate selection', () => {
  test('selects one deterministic unused task per project stratum', () => {
    const metadataText = JSON.stringify(metadata);
    const receipt = selectTrajectoryCandidateTasks({
      metadata,
      metadataText,
      seed: 'frozen-seed',
      projects: ['alpha', 'beta'],
      excludedTaskIds: ['old'],
    });

    expect(receipt.candidates).toHaveLength(2);
    expect(receipt.candidates.map(candidate => candidate.projectName)).toEqual(['alpha', 'beta']);
    expect(receipt.candidates.some(candidate => candidate.taskId === 'old')).toBe(false);
    expect(receipt.selectionSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(
      selectTrajectoryCandidateTasks({
        metadata,
        metadataText,
        seed: 'frozen-seed',
        projects: ['alpha', 'beta'],
        excludedTaskIds: ['old'],
      }).selectionSha256
    ).toBe(receipt.selectionSha256);
  });

  test('does not release hidden selection or evaluator fields', () => {
    const receipt = selectTrajectoryCandidateTasks({
      metadata,
      metadataText: JSON.stringify(metadata),
      seed: 'frozen-seed',
      projects: ['alpha', 'beta'],
      excludedTaskIds: ['old'],
    });
    const renderedCandidates = JSON.stringify(receipt.candidates);

    expect(renderedCandidates).not.toContain('hidden-fix');
    expect(renderedCandidates).not.toContain('crash_type');
    expect(renderedCandidates).not.toContain('cwe');
    expect(renderedCandidates).not.toContain('evaluator_outcome');
    expect(receipt.method.fieldsExcluded).toContain('crash_type');
  });

  test('rejects unsafe changed-file paths', () => {
    const unsafe = {
      task: { project_name: 'alpha', changed_file: '../outside.c' },
    };

    expect(() =>
      selectTrajectoryCandidateTasks({
        metadata: unsafe,
        metadataText: JSON.stringify(unsafe),
        projects: ['alpha'],
      })
    ).toThrow('repository-relative path without traversal');
  });
});
