import { describe, expect, test } from 'bun:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

import { verifySources } from './verify-pgacs-multibench-sources';

describe('verifySources', () => {
  test('reports absent benchmark sources without treating them as verified', async () => {
    const workRoot = await mkdtemp(resolve(tmpdir(), 'pgacs-source-verification-'));
    await mkdir(workRoot, { recursive: true });

    const receipt = await verifySources(workRoot, '2026-08-02T00:00:00.000Z');

    expect(receipt.status).toBe('fail');
    expect(receipt.checks).toHaveLength(6);
    expect(receipt.checks.every(check => check.actualSha256 === null)).toBe(true);
  });

  test('rejects a present artifact whose digest does not match', async () => {
    const workRoot = await mkdtemp(resolve(tmpdir(), 'pgacs-source-verification-'));
    const sourceDirectory = resolve(
      workRoot,
      'sources',
      'SetupBench-041a412f01348c2a6f8b1b6a910138fe01885aee',
      'setupbench/scenarios'
    );
    await mkdir(sourceDirectory, { recursive: true });
    await writeFile(resolve(sourceDirectory, 'database_setup.jsonl'), 'tampered\n', 'utf8');

    const receipt = await verifySources(workRoot, '2026-08-02T00:00:00.000Z');
    const databaseCheck = receipt.checks.find(
      check => check.id === 'setupbench:setupbench/scenarios/database_setup.jsonl'
    );

    expect(databaseCheck?.status).toBe('fail');
    expect(databaseCheck?.actualSha256).not.toBe(databaseCheck?.expectedSha256);
  });
});
