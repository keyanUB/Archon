#!/usr/bin/env bun
import { resolve } from 'node:path';

import {
  loadFrozenTaskRegistry,
  resolveEvaluatorAdapter,
  resolveWorkspaceAdapter,
  type FrozenTaskManifest,
} from './pgacs-task-adapters';

function usage(): never {
  throw new Error(
    'Usage: pgacs-task-adapter-cli.ts prepare REGISTRY TASK_ID ROOT | ' +
      'stage REGISTRY TASK_ID EVALUATOR_ROOT CANDIDATE_ROOT RESULTS_ROOT LABEL'
  );
}

function findManifest(registryPath: string, taskId: string): FrozenTaskManifest {
  const registry = loadFrozenTaskRegistry(resolve(registryPath));
  const manifest = registry.tasks.find(
    task => task.id === taskId || task.provenance?.sourceTaskId === taskId
  );
  if (!manifest) throw new Error(`Task registry does not contain ${taskId}`);
  return manifest;
}

async function main(args: string[]): Promise<void> {
  const [command, registryPath, taskId, ...rest] = args;
  if (!command || !registryPath || !taskId) usage();
  const manifest = findManifest(registryPath, taskId);
  if (command === 'prepare') {
    const [repositoryRoot] = rest;
    if (!repositoryRoot || rest.length !== 1) usage();
    const receipt = await resolveWorkspaceAdapter(manifest).prepare(
      manifest,
      resolve(repositoryRoot)
    );
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
    return;
  }
  if (command === 'stage') {
    const [evaluatorRoot, candidateRoot, resultsRoot, evaluationLabel] = rest;
    if (!evaluatorRoot || !candidateRoot || !resultsRoot || !evaluationLabel || rest.length !== 4) {
      usage();
    }
    const invocation = await resolveEvaluatorAdapter(manifest).prepareInvocation({
      manifest,
      repositoryRoot: process.cwd(),
      frozenEvaluatorPath: resolve(evaluatorRoot),
      candidatePath: resolve(candidateRoot),
      outputRoot: resolve(resultsRoot),
      evaluationLabel,
    });
    process.stdout.write(`${JSON.stringify(invocation)}\n`);
    return;
  }
  usage();
}

await main(process.argv.slice(2));
