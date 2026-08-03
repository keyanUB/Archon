#!/usr/bin/env bun
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import {
  summarizeResults,
  type CellResult,
  type ConditionId,
  type ExperimentTaskId,
} from './run-pgacs-baxbench-c2';

interface ResultBundle {
  summary: unknown;
  results: CellResult[];
}

interface ReplacementReceipt {
  taskId: ExperimentTaskId;
  condition: ConditionId;
  replacedDecision: CellResult['terminal']['decision'];
  replacementDecision: CellResult['terminal']['decision'];
  sourcePath: string;
}

function key(result: CellResult): string {
  return `${result.taskId}\u0000${result.condition}`;
}

function validateUnique(results: CellResult[], label: string): void {
  const keys = results.map(key);
  if (new Set(keys).size !== keys.length) {
    throw new Error(`${label} contains duplicate task-condition cells`);
  }
}

export function mergeExperimentResults(
  primary: CellResult[],
  replacements: { sourcePath: string; results: CellResult[] }[]
): { results: CellResult[]; replacementReceipts: ReplacementReceipt[] } {
  validateUnique(primary, 'primary result bundle');
  const merged = new Map(primary.map(result => [key(result), result]));
  const replacementReceipts: ReplacementReceipt[] = [];
  for (const replacementBundle of replacements) {
    validateUnique(replacementBundle.results, `replacement ${replacementBundle.sourcePath}`);
    for (const replacement of replacementBundle.results) {
      const cellKey = key(replacement);
      const existing = merged.get(cellKey);
      if (!existing) {
        throw new Error(
          `Replacement has no primary cell: ${replacement.taskId}/${replacement.condition}`
        );
      }
      if (existing.terminal.decision !== 'blocked_harness_error') {
        throw new Error(
          `Refusing to replace non-harness outcome ${replacement.taskId}/${replacement.condition}`
        );
      }
      if (replacement.terminal.decision === 'blocked_harness_error') {
        throw new Error(
          `Replacement remains a harness error: ${replacement.taskId}/${replacement.condition}`
        );
      }
      merged.set(cellKey, replacement);
      replacementReceipts.push({
        taskId: replacement.taskId,
        condition: replacement.condition,
        replacedDecision: existing.terminal.decision,
        replacementDecision: replacement.terminal.decision,
        sourcePath: replacementBundle.sourcePath,
      });
    }
  }
  const results = [...merged.values()].sort((left, right) =>
    `${left.taskId}:${left.condition}`.localeCompare(`${right.taskId}:${right.condition}`)
  );
  return { results, replacementReceipts };
}

async function readBundle(path: string): Promise<ResultBundle> {
  const parsed = JSON.parse(await readFile(path, 'utf8')) as ResultBundle;
  if (!Array.isArray(parsed.results)) throw new Error(`${path} does not contain results`);
  return parsed;
}

async function main(): Promise<void> {
  const primaryIndex = process.argv.indexOf('--primary');
  const outputIndex = process.argv.indexOf('--output');
  const replacementPaths = process.argv.flatMap((argument, index): string[] =>
    argument === '--replacement' && process.argv[index + 1] ? [process.argv[index + 1]] : []
  );
  if (
    primaryIndex < 0 ||
    !process.argv[primaryIndex + 1] ||
    outputIndex < 0 ||
    !process.argv[outputIndex + 1]
  ) {
    throw new Error(
      'Usage: merge-pgacs-baxbench-c2-results.ts --primary <results.json> --replacement <results.json>... --output <merged.json>'
    );
  }
  if (replacementPaths.length === 0) throw new Error('At least one replacement is required');
  const primaryPath = resolve(process.argv[primaryIndex + 1]);
  const outputPath = resolve(process.argv[outputIndex + 1]);
  const primary = await readBundle(primaryPath);
  const replacementBundles = await Promise.all(
    replacementPaths.map(async path => ({
      sourcePath: resolve(path),
      results: (await readBundle(resolve(path))).results,
    }))
  );
  const merged = mergeExperimentResults(primary.results, replacementBundles);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(
    outputPath,
    `${JSON.stringify(
      {
        schemaVersion: '0.1.0',
        primaryPath,
        replacementReceipts: merged.replacementReceipts,
        summary: summarizeResults(merged.results),
        results: merged.results,
      },
      null,
      2
    )}\n`,
    'utf8'
  );
  console.log(outputPath);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
