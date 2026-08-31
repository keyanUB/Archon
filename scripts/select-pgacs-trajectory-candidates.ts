#!/usr/bin/env bun
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { stableSha256 } from './pgacs-runtime-policy-state';

export const TRAJECTORY_CANDIDATE_SELECTION_SCHEMA_VERSION = '0.1.0' as const;
export const TRAJECTORY_CANDIDATE_SELECTION_SEED = 'pgacs-trajectory-pilot-v0.1' as const;
export const SECREPOBENCH_REVISION = '7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76' as const;

const DEFAULT_PROJECT_STRATA = ['lcms', 'file', 'mruby'] as const;
const DEFAULT_EXCLUDED_TASK_IDS = ['910', '1065', '19902'] as const;

type JsonObject = Record<string, unknown>;

export interface TrajectoryCandidateSelectionReceipt {
  schemaVersion: typeof TRAJECTORY_CANDIDATE_SELECTION_SCHEMA_VERSION;
  selectionId: 'pgacs-trajectory-candidate-selection-v0.1';
  selectionRole: 'candidate_only_not_admitted';
  source: {
    benchmark: 'SecRepoBench';
    revision: typeof SECREPOBENCH_REVISION;
    metadataSha256: string;
  };
  method: {
    seed: string;
    ranking: 'sha256(seed:task_id)_ascending';
    fieldsRead: readonly ['task_id', 'project_name', 'changed_file'];
    fieldsExcluded: readonly [
      'crash_type',
      'cwe',
      'fixing_commit',
      'secure_code',
      'vulnerable_code',
      'evaluator_outcome',
    ];
    excludedTaskIds: string[];
  };
  candidates: {
    taskId: string;
    projectName: string;
    changedFile: string;
    rankSha256: string;
  }[];
  selectionSha256: string;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(object: JsonObject, key: string, label: string): string {
  const value = object[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
  return value.trim();
}

function requireRelativePath(value: string, label: string): string {
  const normalized = value.replaceAll('\\', '/');
  if (
    normalized.startsWith('/') ||
    normalized.includes('\0') ||
    normalized.split('/').some(segment => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new Error(`${label} must be a repository-relative path without traversal`);
  }
  return normalized;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function selectTrajectoryCandidateTasks(input: {
  metadata: unknown;
  metadataText: string;
  seed?: string;
  projects?: readonly string[];
  excludedTaskIds?: readonly string[];
}): TrajectoryCandidateSelectionReceipt {
  if (!isObject(input.metadata)) {
    throw new Error('SecRepoBench sample metadata must be an object keyed by task ID');
  }
  const metadata = input.metadata;
  const seed = input.seed?.trim() || TRAJECTORY_CANDIDATE_SELECTION_SEED;
  const projects = input.projects ?? DEFAULT_PROJECT_STRATA;
  const excludedTaskIds = [...(input.excludedTaskIds ?? DEFAULT_EXCLUDED_TASK_IDS)].sort();
  if (projects.length === 0 || new Set(projects).size !== projects.length) {
    throw new Error('Trajectory candidate project strata must be non-empty and unique');
  }
  const excluded = new Set(excludedTaskIds);
  const candidates = projects.map(projectName => {
    const ranked = Object.entries(metadata)
      .flatMap(([taskId, raw]): { taskId: string; changedFile: string }[] => {
        if (excluded.has(taskId) || !isObject(raw) || raw.project_name !== projectName) return [];
        return [
          {
            taskId,
            changedFile: requireRelativePath(
              requireString(raw, 'changed_file', `SecRepoBench task ${taskId}`),
              `SecRepoBench task ${taskId}.changed_file`
            ),
          },
        ];
      })
      .map(candidate => ({
        ...candidate,
        rankSha256: sha256(`${seed}:${candidate.taskId}`),
      }))
      .sort(
        (left, right) =>
          left.rankSha256.localeCompare(right.rankSha256) || left.taskId.localeCompare(right.taskId)
      );
    const selected = ranked[0];
    if (!selected) {
      throw new Error(`No unused SecRepoBench task is available for project ${projectName}`);
    }
    return { ...selected, projectName };
  });

  const core = {
    schemaVersion: TRAJECTORY_CANDIDATE_SELECTION_SCHEMA_VERSION,
    selectionId: 'pgacs-trajectory-candidate-selection-v0.1' as const,
    selectionRole: 'candidate_only_not_admitted' as const,
    source: {
      benchmark: 'SecRepoBench' as const,
      revision: SECREPOBENCH_REVISION,
      metadataSha256: sha256(input.metadataText),
    },
    method: {
      seed,
      ranking: 'sha256(seed:task_id)_ascending' as const,
      fieldsRead: ['task_id', 'project_name', 'changed_file'] as const,
      fieldsExcluded: [
        'crash_type',
        'cwe',
        'fixing_commit',
        'secure_code',
        'vulnerable_code',
        'evaluator_outcome',
      ] as const,
      excludedTaskIds,
    },
    candidates,
  };
  return { ...core, selectionSha256: stableSha256(core) };
}

async function main(): Promise<void> {
  const [metadataPath, outputPath] = process.argv.slice(2);
  if (!metadataPath || !outputPath || process.argv.length !== 4) {
    throw new Error(
      'Usage: select-pgacs-trajectory-candidates.ts SAMPLE_METADATA_JSON OUTPUT_JSON'
    );
  }
  const metadataText = await readFile(resolve(metadataPath), 'utf8');
  const metadata = JSON.parse(metadataText) as unknown;
  const receipt = selectTrajectoryCandidateTasks({ metadata, metadataText });
  await writeFile(resolve(outputPath), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  process.stdout.write(`Selected ${String(receipt.candidates.length)} trajectory candidates\n`);
}

if (import.meta.main) await main();
