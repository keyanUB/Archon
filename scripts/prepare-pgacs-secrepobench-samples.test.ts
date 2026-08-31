import { describe, expect, test } from 'bun:test';

import { resolveTrajectoryCandidateTasks } from './prepare-pgacs-secrepobench-samples';
import { selectTrajectoryCandidateTasks } from './select-pgacs-trajectory-candidates';

const metadata = {
  '42227': {
    project_name: 'lcms',
    fixing_commit: '1'.repeat(40),
    changed_file: 'src/cmscgats.c',
    crash_type: 'Global-buffer-overflow WRITE 4',
  },
  '9922': {
    project_name: 'file',
    fixing_commit: '2'.repeat(40),
    changed_file: 'src/is_json.c',
    crash_type: 'Heap-buffer-overflow READ 1',
  },
  '57672': {
    project_name: 'mruby',
    fixing_commit: '3'.repeat(40),
    changed_file: 'src/vm.c',
    crash_type: 'Heap-use-after-free READ 1',
  },
};

describe('SecRepoBench trajectory candidate preparation', () => {
  test('resolves hidden evaluator fields only after validating the frozen selection', () => {
    const metadataText = JSON.stringify(metadata);
    const selection = selectTrajectoryCandidateTasks({ metadata, metadataText });
    const resolved = resolveTrajectoryCandidateTasks({ metadata, metadataText, selection });

    expect(resolved.receipt.selectionSha256).toBe(selection.selectionSha256);
    expect(resolved.tasks.map(task => ({ id: task.id, cweId: task.cweId }))).toEqual([
      { id: '42227', cweId: 'CWE-787' },
      { id: '9922', cweId: 'CWE-125' },
      { id: '57672', cweId: 'CWE-416' },
    ]);
  });

  test('rejects a modified candidate receipt', () => {
    const metadataText = JSON.stringify(metadata);
    const selection = selectTrajectoryCandidateTasks({ metadata, metadataText });
    const modified = {
      ...selection,
      candidates: selection.candidates.map((candidate, index) =>
        index === 0 ? { ...candidate, taskId: 'different' } : candidate
      ),
    };

    expect(() =>
      resolveTrajectoryCandidateTasks({ metadata, metadataText, selection: modified })
    ).toThrow('does not match the pinned selection protocol');
  });

  test('rejects unsupported crash-to-CWE mappings', () => {
    const changedMetadata = {
      ...metadata,
      '42227': { ...metadata['42227'], crash_type: 'Unknown sanitizer finding' },
    };
    const metadataText = JSON.stringify(changedMetadata);
    const selection = selectTrajectoryCandidateTasks({ metadata: changedMetadata, metadataText });

    expect(() =>
      resolveTrajectoryCandidateTasks({
        metadata: changedMetadata,
        metadataText,
        selection,
      })
    ).toThrow('No reviewed CWE mapping exists');
  });
});
