#!/usr/bin/env bun
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

import {
  loadFrozenTaskRegistry,
  verifySecRepoBenchBenchmarkSurface,
  type FrozenTaskManifest,
} from './pgacs-task-adapters';
import { SecRepoBenchClaudeAgentDriver } from './pgacs-secrepobench-claude-driver';
import { SecRepoBenchOpenHandsAgentDriver } from './pgacs-secrepobench-openhands-driver';
import {
  runSecRepoBenchCell,
  type SecRepoBenchAgentDriver,
  type SecRepoBenchCondition,
  type SecRepoBenchEvaluatorDriver,
} from './pgacs-secrepobench-controller';
import {
  evaluateSecRepoBenchCandidateOfficially,
  inspectNativeEvaluatorImage,
  type NativeEvaluatorImageIdentity,
} from './pgacs-secrepobench-official-evaluator';
import {
  assertFreshSanitizedWorkspace,
  materializeSecRepoBenchWorkspace,
} from './pgacs-secrepobench-materializer';
import {
  assertPgacsEvaluatorMatchesQualification,
  PGACS_QUALIFICATION_RECEIPT_PATH,
  requirePgacsQualifiedEnvironment,
} from './pgacs-secrepobench-qualification';

interface CliArguments {
  registryPath: string;
  taskId: string;
  sourceRepositoryRoot: string;
  maskedTargetPath: string;
  frozenEvaluatorPath: string;
  outputRoot: string;
  conditions: SecRepoBenchCondition[];
  agent: 'claude' | 'openhands';
  model?: string;
  maxTurns?: number;
  maxBudgetUsd?: number;
}

function usage(): never {
  throw new Error(
    'Usage: run-pgacs-secrepobench.ts REGISTRY TASK_ID SOURCE_REPO MASKED_TARGET ' +
      'FROZEN_EVALUATOR OUTPUT_ROOT [--conditions=C0,C1,C2,C3] [--model=MODEL] ' +
      '[--max-turns=N] [--max-budget-usd=AMOUNT] [--agent=claude|openhands]'
  );
}

function parseConditions(value: string): SecRepoBenchCondition[] {
  const conditions = [...new Set(value.split(',').map(item => item.trim()))];
  if (
    conditions.length === 0 ||
    conditions.some(item => !['C0', 'C1', 'C2', 'C3'].includes(item))
  ) {
    throw new Error('Conditions must be a comma-separated subset of C0,C1,C2,C3');
  }
  return conditions as SecRepoBenchCondition[];
}

function uniqueOption(args: string[], prefix: string): string | undefined {
  const matches = args.filter(value => value.startsWith(prefix));
  if (matches.length > 1) throw new Error(`Duplicate option: ${prefix.slice(0, -1)}`);
  return matches[0];
}

function parseArgs(args: string[]): CliArguments {
  const positional = args.filter(value => !value.startsWith('--'));
  if (positional.length !== 6) usage();
  const conditionsArg = uniqueOption(args, '--conditions=');
  const modelArg = uniqueOption(args, '--model=');
  const maxTurnsArg = uniqueOption(args, '--max-turns=');
  const maxBudgetArg = uniqueOption(args, '--max-budget-usd=');
  const agentArg = uniqueOption(args, '--agent=');
  const unknown = args.filter(
    value =>
      value.startsWith('--') &&
      !value.startsWith('--conditions=') &&
      !value.startsWith('--model=') &&
      !value.startsWith('--max-turns=') &&
      !value.startsWith('--max-budget-usd=') &&
      !value.startsWith('--agent=')
  );
  if (unknown.length > 0) throw new Error(`Unknown options: ${unknown.join(', ')}`);
  const [
    registryPath,
    taskId,
    sourceRepositoryRoot,
    maskedTargetPath,
    frozenEvaluatorPath,
    outputRoot,
  ] = positional;
  if (
    !registryPath ||
    !taskId ||
    !sourceRepositoryRoot ||
    !maskedTargetPath ||
    !frozenEvaluatorPath ||
    !outputRoot
  ) {
    usage();
  }
  const conditions = parseConditions(conditionsArg?.slice('--conditions='.length) ?? 'C0,C1,C2,C3');
  const model = modelArg?.slice('--model='.length) || undefined;
  const maxTurns = maxTurnsArg ? Number(maxTurnsArg.slice('--max-turns='.length)) : undefined;
  const maxBudgetUsd = maxBudgetArg
    ? Number(maxBudgetArg.slice('--max-budget-usd='.length))
    : undefined;
  const agentValue = agentArg?.slice('--agent='.length) ?? 'claude';
  if (agentValue !== 'claude' && agentValue !== 'openhands') {
    throw new Error('agent must be claude or openhands');
  }
  if (
    maxTurns !== undefined &&
    (!Number.isSafeInteger(maxTurns) || maxTurns < 1 || maxTurns > 100)
  ) {
    throw new Error('max-turns must be an integer from 1 to 100');
  }
  if (maxBudgetUsd !== undefined && (!Number.isFinite(maxBudgetUsd) || maxBudgetUsd <= 0)) {
    throw new Error('max-budget-usd must be a positive number');
  }
  if (
    conditions.some(condition => condition !== 'C0') &&
    (!model || maxTurns === undefined || maxBudgetUsd === undefined)
  ) {
    throw new Error(
      'Comparative conditions require explicit --model, --max-turns, and --max-budget-usd'
    );
  }
  if (
    agentValue === 'openhands' &&
    (!model || maxTurns === undefined || maxBudgetUsd === undefined)
  ) {
    throw new Error('OpenHands requires explicit --model, --max-turns, and --max-budget-usd');
  }
  return {
    registryPath: resolve(registryPath),
    taskId,
    sourceRepositoryRoot: resolve(sourceRepositoryRoot),
    maskedTargetPath: resolve(maskedTargetPath),
    frozenEvaluatorPath: resolve(frozenEvaluatorPath),
    outputRoot: resolve(outputRoot),
    conditions,
    agent: agentValue,
    model,
    maxTurns,
    maxBudgetUsd,
  };
}

function createAgent(args: CliArguments): SecRepoBenchAgentDriver {
  if (args.agent === 'openhands') {
    if (!args.model || args.maxTurns === undefined || args.maxBudgetUsd === undefined) {
      throw new Error('OpenHands requires explicit model, turn limit, and budget');
    }
    return new SecRepoBenchOpenHandsAgentDriver({
      model: args.model,
      maxTurns: args.maxTurns,
      maxBudgetUsd: args.maxBudgetUsd,
    });
  }
  return new SecRepoBenchClaudeAgentDriver({
    model: args.model,
    maxTurns: args.maxTurns,
    maxBudgetUsd: args.maxBudgetUsd,
  });
}

function findManifest(registryPath: string, taskId: string): FrozenTaskManifest {
  const manifest = loadFrozenTaskRegistry(registryPath).tasks.find(
    task => task.id === taskId || task.provenance?.sourceTaskId === taskId
  );
  if (!manifest) throw new Error(`Task registry does not contain ${taskId}`);
  if (manifest.provenance?.benchmark !== 'SecRepoBench') {
    throw new Error('The selected task is not an admitted SecRepoBench task');
  }
  return manifest;
}

async function assertContainedOutput(repositoryRoot: string, outputRoot: string): Promise<void> {
  const fromRoot = relative(repositoryRoot, outputRoot);
  if (fromRoot === '' || fromRoot.startsWith('..') || isAbsolute(fromRoot)) {
    throw new Error('OUTPUT_ROOT must be a new directory contained by the Archon repository');
  }
}

async function assertDockerReady(): Promise<void> {
  const subprocess = Bun.spawn(['docker', 'info', '--format', '{{.ServerVersion}}'], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0 || stdout.trim().length === 0) {
    throw new Error(`Docker is not ready: ${stderr.trim() || 'server version unavailable'}`);
  }
}

async function commandOutput(command: string[], cwd?: string): Promise<string> {
  const subprocess = Bun.spawn(command, { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(stderr.trim() || `${command.join(' ')} failed`);
  return stdout.trim();
}

async function assertEvaluatorReady(input: {
  manifest: FrozenTaskManifest;
  frozenEvaluatorPath: string;
  repositoryRoot: string;
  registryPath: string;
}): Promise<NativeEvaluatorImageIdentity> {
  const benchmark = input.manifest.evaluator.secRepoBench;
  if (!benchmark) throw new Error('SecRepoBench evaluator metadata is missing');
  await verifySecRepoBenchBenchmarkSurface(input.manifest, input.frozenEvaluatorPath);
  const oracleSource = resolve(input.repositoryRoot, input.manifest.evaluator.sourcePath);
  const sourceStatus = await lstat(oracleSource);
  await commandOutput(['python3', '--version']);
  if (!sourceStatus.isFile() || sourceStatus.isSymbolicLink()) {
    throw new Error('PGACS SecRepoBench oracle source is invalid');
  }
  const [receiptText, oracleText, registryText] = await Promise.all([
    readFile(resolve(input.repositoryRoot, PGACS_QUALIFICATION_RECEIPT_PATH), 'utf8'),
    readFile(oracleSource, 'utf8'),
    readFile(input.registryPath, 'utf8'),
  ]);
  const qualifiedEnvironment = requirePgacsQualifiedEnvironment({
    receiptText,
    oracleText,
    registryText,
  });
  const qualifiedImage = qualifiedEnvironment.images.find(
    image => image.reference === benchmark.arvoImage
  );
  if (!qualifiedImage) {
    throw new Error(`Qualification receipt does not bind evaluator image ${benchmark.arvoImage}`);
  }
  const currentImage = await inspectNativeEvaluatorImage(benchmark.arvoImage);
  assertPgacsEvaluatorMatchesQualification({
    current: currentImage,
    qualified: qualifiedImage,
    qualifiedHostOs: qualifiedEnvironment.host.os,
  });
  return currentImage;
}

async function assertEvaluatorImageUnchanged(
  manifest: FrozenTaskManifest,
  qualifiedImage: NativeEvaluatorImageIdentity
): Promise<void> {
  const image = manifest.evaluator.secRepoBench?.arvoImage;
  if (!image) throw new Error('SecRepoBench evaluator metadata is missing');
  const currentImage = await inspectNativeEvaluatorImage(image);
  if (JSON.stringify(currentImage) !== JSON.stringify(qualifiedImage)) {
    throw new Error(`ARVO image binding changed during the experiment: ${image}`);
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const repositoryRoot = await realpath(process.cwd());
  await assertContainedOutput(repositoryRoot, args.outputRoot);
  await assertDockerReady();
  const manifest = findManifest(args.registryPath, args.taskId);
  const evaluatorImage = await assertEvaluatorReady({
    manifest,
    frozenEvaluatorPath: args.frozenEvaluatorPath,
    repositoryRoot,
    registryPath: args.registryPath,
  });
  await mkdir(args.outputRoot, { recursive: false });
  const agent = createAgent(args);
  const results = [];
  for (const condition of args.conditions) {
    const cellRoot = resolve(args.outputRoot, condition);
    const runRoot = resolve(cellRoot, 'run');
    const controlRoot = resolve(cellRoot, 'control');
    await mkdir(runRoot, { recursive: true });
    await mkdir(controlRoot, { recursive: true });
    const materialization = await materializeSecRepoBenchWorkspace({
      manifest,
      sourceRepositoryRoot: args.sourceRepositoryRoot,
      maskedTargetPath: args.maskedTargetPath,
      repositoryRoot: runRoot,
    });
    const workspaceRoot = resolve(runRoot, materialization.workspaceRoot);
    await assertFreshSanitizedWorkspace(workspaceRoot);
    const evaluator: SecRepoBenchEvaluatorDriver = {
      id: 'secrepobench-official-isolated-v0.2',
      evaluate: async ({ candidate, attempt }) => {
        await assertEvaluatorImageUnchanged(manifest, evaluatorImage);
        return evaluateSecRepoBenchCandidateOfficially({
          manifest,
          candidate,
          workspaceRoot,
          repositoryRoot,
          frozenEvaluatorPath: args.frozenEvaluatorPath,
          outputRoot: resolve(controlRoot, `evaluation-${attempt}`),
        });
      },
    };
    const result = await runSecRepoBenchCell({
      condition,
      manifest,
      materialization,
      workspaceRoot,
      agent,
      evaluator,
    });
    results.push(result);
    await writeFile(
      resolve(controlRoot, 'cell-result.json'),
      `${JSON.stringify(result, null, 2)}\n`,
      'utf8'
    );
    process.stdout.write(
      `${condition}: ${result.terminalDecision} security=${String(result.securitySuccess)} functional=${String(result.functionalSuccess)}\n`
    );
  }
  await writeFile(
    resolve(args.outputRoot, 'experiment-summary.json'),
    `${JSON.stringify(
      {
        schemaVersion: '0.6.0',
        taskId: manifest.id,
        executionContract: {
          agent: args.agent,
          driverId: agent.id,
          requestedModel: args.model ?? null,
          maxTurns: args.maxTurns ?? 30,
          maxBudgetUsd: args.maxBudgetUsd ?? null,
          evaluatorImage: {
            reference: evaluatorImage.reference,
            imageId: evaluatorImage.imageId,
            repoDigests: evaluatorImage.repoDigests,
            hostOs: evaluatorImage.hostOs,
            hostArchitecture: evaluatorImage.hostArchitecture,
            imageOs: evaluatorImage.imageOs,
            imageArchitecture: evaluatorImage.imageArchitecture,
          },
        },
        results,
      },
      null,
      2
    )}\n`,
    'utf8'
  );
}

await main();
