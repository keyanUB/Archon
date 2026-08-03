import { describe, expect, test } from 'bun:test';

import { loadSmokeDataset, validateSmokeDataset } from './validate-pgacs-smoke-dataset';

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('PGACS smoke dataset', (): void => {
  test('accepts the frozen cohort', async (): Promise<void> => {
    const { manifest, sourceLock } = await loadSmokeDataset();
    expect(validateSmokeDataset(manifest, sourceLock)).toEqual([]);
  });

  test('rejects duplicate task IDs', async (): Promise<void> => {
    const loaded = await loadSmokeDataset();
    const manifest = cloneJson(loaded.manifest) as {
      tasks: Array<{ id: string }>;
    };
    manifest.tasks[1]!.id = manifest.tasks[0]!.id;

    expect(validateSmokeDataset(manifest, loaded.sourceLock)).toContain(
      'pgacs-custom-zip-inspector: duplicate task ID'
    );
  });

  test('rejects false runnable claims', async (): Promise<void> => {
    const loaded = await loadSmokeDataset();
    const manifest = cloneJson(loaded.manifest) as {
      tasks: Array<{
        id: string;
        status: string;
        evaluation: {
          adapter: { status: string };
          functionalOracle: { status: string };
          securityOracle: { status: string };
        };
      }>;
    };
    manifest.tasks[1]!.status = 'runnable';

    const errors = validateSmokeDataset(manifest, loaded.sourceLock);
    expect(errors).toContain(
      'swebench-django-10914: runnable task requires an implemented adapter'
    );
    expect(errors).toContain(
      'swebench-django-10914: runnable task requires a frozen functionalOracle'
    );
  });

  test('rejects gold patch fields', async (): Promise<void> => {
    const loaded = await loadSmokeDataset();
    const manifest = cloneJson(loaded.manifest) as Record<string, unknown>;
    manifest.gold_patch = 'must never be agent-visible';

    expect(validateSmokeDataset(manifest, loaded.sourceLock)).toContain(
      'manifest must not contain gold patches or reference completions'
    );
  });

  test('rejects a floating or malformed source lock', async (): Promise<void> => {
    const loaded = await loadSmokeDataset();
    const sourceLock = cloneJson(loaded.sourceLock) as {
      sources: Record<string, { revision: string; sha256: string }>;
    };
    sourceLock.sources.setupbench!.revision = 'main';
    sourceLock.sources.setupbench!.sha256 = 'not-a-digest';

    const errors = validateSmokeDataset(loaded.manifest, sourceLock);
    expect(errors).toContain('setupbench: source lock revision must be pinned');
    expect(errors).toContain('setupbench: source lock sha256 must be a SHA-256 digest');
  });
});
