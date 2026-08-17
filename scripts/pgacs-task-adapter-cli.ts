#!/usr/bin/env bun
import { mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

import {
  loadFrozenTaskRegistry,
  resolveEvaluatorAdapter,
  resolveWorkspaceAdapter,
  type FrozenTaskManifest,
} from './pgacs-task-adapters';
import {
  assertFreshSanitizedWorkspace,
  createSecRepoBenchTaskViews,
  materializeSecRepoBenchWorkspace,
} from './pgacs-secrepobench-materializer';

function usage(): never {
  throw new Error(
    'Usage: pgacs-task-adapter-cli.ts prepare REGISTRY TASK_ID ROOT | ' +
      'materialize REGISTRY TASK_ID SOURCE_REPO MASKED_TARGET RUN_ROOT CONTROL_ROOT | ' +
      'stage REGISTRY TASK_ID EVALUATOR_ROOT CANDIDATE_ROOT RESULTS_ROOT LABEL'
  );
}

function isContainedBy(root: string, candidate: string): boolean {
  const fromRoot = relative(root, candidate);
  return fromRoot === '' || (!fromRoot.startsWith('..') && !isAbsolute(fromRoot));
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
  if (command === 'materialize') {
    const [sourceRepositoryRoot, maskedTargetPath, rawRepositoryRoot, rawControlRoot] = rest;
    if (
      !sourceRepositoryRoot ||
      !maskedTargetPath ||
      !rawRepositoryRoot ||
      !rawControlRoot ||
      rest.length !== 4
    ) {
      usage();
    }
    const repositoryRoot = resolve(rawRepositoryRoot);
    const controlRoot = resolve(rawControlRoot);
    const receipt = await materializeSecRepoBenchWorkspace({
      manifest,
      sourceRepositoryRoot: resolve(sourceRepositoryRoot),
      maskedTargetPath: resolve(maskedTargetPath),
      repositoryRoot,
    });
    const workspaceRoot = resolve(repositoryRoot, receipt.workspaceRoot);
    if (isContainedBy(workspaceRoot, controlRoot)) {
      throw new Error('SecRepoBench control artifacts must remain outside the agent workspace');
    }
    await assertFreshSanitizedWorkspace(workspaceRoot);
    await mkdir(controlRoot, { recursive: false });
    const views = createSecRepoBenchTaskViews(manifest, receipt);
    const receiptPath = resolve(controlRoot, 'materialization-receipt.json');
    const generationTaskPath = resolve(controlRoot, 'generation-task.json');
    const evaluatorTaskPath = resolve(controlRoot, 'evaluator-task.json');
    await Promise.all([
      writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8'),
      writeFile(generationTaskPath, `${JSON.stringify(views.generation, null, 2)}\n`, 'utf8'),
      writeFile(evaluatorTaskPath, `${JSON.stringify(views.evaluator, null, 2)}\n`, 'utf8'),
    ]);
    process.stdout.write(
      `${JSON.stringify({ receipt, receiptPath, generationTaskPath, evaluatorTaskPath })}\n`
    );
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
