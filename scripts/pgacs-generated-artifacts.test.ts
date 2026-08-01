import { expect, test } from 'bun:test';
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';

async function readJson(relativePath: string): Promise<Record<string, unknown>> {
  const filePath = fileURLToPath(new URL(relativePath, import.meta.url));
  return JSON.parse(await readFile(filePath, 'utf-8')) as Record<string, unknown>;
}

test('generated task-surface artifacts expose uncertainty fields', async () => {
  const schema = await readJson('../.archon/data/research/pgacs/task-surface.schema.json');
  const example = await readJson('../.archon/data/research/pgacs/task-surface.example.json');
  const required = schema.required as string[];
  const properties = schema.properties as Record<string, unknown>;

  expect(required).toContain('surfaceStatus');
  expect(required).toContain('evidence');
  expect(required).toContain('unresolved');
  expect(properties).toHaveProperty('surfaceStatus');
  expect(example).toHaveProperty('surfaceStatus');
  expect(example).toHaveProperty('evidence');
  expect(example).toHaveProperty('unresolved');
});
