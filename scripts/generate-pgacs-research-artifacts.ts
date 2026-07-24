#!/usr/bin/env bun
/**
 * Generate the first PGACS research artifacts from the existing Archon policy
 * corpus.
 *
 * Outputs:
 *   .archon/data/research/pgacs/policy-registry.normalized.json
 *   .archon/data/research/pgacs/task-surface.schema.json
 *   .archon/data/research/pgacs/policy-record.schema.json
 *
 * Usage:
 *   bun run scripts/generate-pgacs-research-artifacts.ts
 */
import { mkdir, writeFile } from 'fs/promises';
import { join, resolve } from 'path';

import { loadPolicyCorpus, normalizePolicyRegistry } from './pgacs-policy-registry';
import { extractTaskSurface } from './pgacs-task-surface';

const REPO_ROOT = resolve(import.meta.dir, '..');
const POLICY_SOURCE = join(
  REPO_ROOT,
  '.archon/data/research/secure-environment-setup/setup-environment-policies.json'
);
const OUTPUT_DIR = join(REPO_ROOT, '.archon/data/research/pgacs');

const POLICY_RECORD_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'PGACS PolicyRecord',
  type: 'object',
  additionalProperties: false,
  required: [
    'id',
    'title',
    'version',
    'sourcePrinciples',
    'normativeText',
    'riskTags',
    'cweTags',
    'taskTriggers',
    'inputChannels',
    'dangerousSinks',
    'assetTags',
    'trustBoundaryTags',
    'dependencyTags',
    'environmentTags',
    'phaseBindings',
    'validators',
    'evidenceRequirements',
    'forbiddenWorkarounds',
    'severity',
  ],
  properties: {
    id: { type: 'string' },
    title: { type: 'string' },
    version: { type: 'string' },
    sourcePrinciples: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['source', 'text'],
        properties: {
          source: { type: 'string' },
          ref: { type: 'string' },
          text: { type: 'string' },
        },
      },
    },
    normativeText: { type: 'string' },
    riskTags: { type: 'array', items: { type: 'string' } },
    cweTags: { type: 'array', items: { type: 'string' } },
    taskTriggers: { type: 'array', items: { type: 'string' } },
    inputChannels: { type: 'array', items: { type: 'string' } },
    dangerousSinks: { type: 'array', items: { type: 'string' } },
    assetTags: { type: 'array', items: { type: 'string' } },
    trustBoundaryTags: { type: 'array', items: { type: 'string' } },
    dependencyTags: { type: 'array', items: { type: 'string' } },
    environmentTags: { type: 'array', items: { type: 'string' } },
    phaseBindings: { type: 'array', items: { type: 'string' } },
    validators: { type: 'array', items: { type: 'string' } },
    evidenceRequirements: { type: 'array', items: { type: 'string' } },
    forbiddenWorkarounds: { type: 'array', items: { type: 'string' } },
    severity: { enum: ['advisory', 'required', 'fail_closed'] },
  },
} as const;

const TASK_SURFACE_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'PGACS TaskSurface',
  type: 'object',
  additionalProperties: false,
  required: [
    'taskId',
    'taskFamily',
    'languageFrameworks',
    'inputChannels',
    'dangerousSinks',
    'assets',
    'trustBoundaries',
    'runtimeExposure',
    'dependencies',
    'environmentConstraints',
    'likelyCwes',
    'missingSecurityInputs',
    'existingTests',
    'confidence',
  ],
  properties: {
    taskId: { type: 'string' },
    taskFamily: {
      enum: [
        'web_api',
        'file_parser',
        'database',
        'auth_session',
        'environment_setup',
        'cli_tool',
        'dependency_build',
        'agent_tooling',
        'unknown',
      ],
    },
    languageFrameworks: { type: 'array', items: { type: 'string' } },
    inputChannels: { type: 'array', items: { type: 'string' } },
    dangerousSinks: { type: 'array', items: { type: 'string' } },
    assets: { type: 'array', items: { type: 'string' } },
    trustBoundaries: { type: 'array', items: { type: 'string' } },
    runtimeExposure: { type: 'array', items: { type: 'string' } },
    dependencies: { type: 'array', items: { type: 'string' } },
    environmentConstraints: { type: 'array', items: { type: 'string' } },
    likelyCwes: { type: 'array', items: { type: 'string' } },
    missingSecurityInputs: { type: 'array', items: { type: 'string' } },
    existingTests: { type: 'array', items: { type: 'string' } },
    confidence: {
      type: 'object',
      additionalProperties: false,
      required: ['taskFamily', 'risks', 'missingInputs'],
      properties: {
        taskFamily: { type: 'number' },
        risks: { type: 'number' },
        missingInputs: { type: 'number' },
      },
    },
  },
} as const;

async function main(): Promise<void> {
  await mkdir(OUTPUT_DIR, { recursive: true });

  const corpus = await loadPolicyCorpus(POLICY_SOURCE);
  const normalizedRegistry = normalizePolicyRegistry(corpus);
  const exampleSurface = extractTaskSurface(
    'secure-environment-setup-example',
    'Install autossh and configure it as a persistent supervised process. The tunnel should connect remote port 9000 to localhost:22. Use AUTOSSH_LOGFILE to write logs to /var/log/autossh.log and AUTOSSH_POLL to enable health monitoring. The process must restart automatically if the tunnel fails.',
    ['Dockerfile', 'systemd', 'autossh', 'root access', 'headless', 'minimal environment']
  );

  await Promise.all([
    writeFile(
      join(OUTPUT_DIR, 'policy-registry.normalized.json'),
      `${JSON.stringify(normalizedRegistry, null, 2)}\n`,
      'utf-8'
    ),
    writeFile(
      join(OUTPUT_DIR, 'policy-record.schema.json'),
      `${JSON.stringify(POLICY_RECORD_SCHEMA, null, 2)}\n`,
      'utf-8'
    ),
    writeFile(
      join(OUTPUT_DIR, 'task-surface.schema.json'),
      `${JSON.stringify(TASK_SURFACE_SCHEMA, null, 2)}\n`,
      'utf-8'
    ),
    writeFile(
      join(OUTPUT_DIR, 'task-surface.example.json'),
      `${JSON.stringify(exampleSurface, null, 2)}\n`,
      'utf-8'
    ),
  ]);

  console.log(`Wrote PGACS research artifacts to ${OUTPUT_DIR}`);
  console.log(`Normalized policies: ${normalizedRegistry.length}`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
