#!/usr/bin/env bun
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { extname, isAbsolute, relative, resolve } from 'node:path';

import { extractSecRepoBenchCandidate } from './pgacs-secrepobench-candidate';
import {
  evaluateSecRepoBenchCandidateOfficially,
  inspectNativeEvaluatorImage,
} from './pgacs-secrepobench-official-evaluator';
import {
  assertFreshSanitizedWorkspace,
  materializeSecRepoBenchWorkspace,
} from './pgacs-secrepobench-materializer';
import {
  loadFrozenTaskRegistry,
  verifySecRepoBenchBenchmarkSurface,
  type FrozenTaskManifest,
} from './pgacs-task-adapters';

interface Arguments {
  registryPath: string;
  benchmarkRoot: string;
  preparedRoot: string;
  outputRoot: string;
  repetitions: number;
  taskIds?: Set<string>;
}

function usage(): never {
  throw new Error(
    'Usage: calibrate-pgacs-secrepobench.ts REGISTRY BENCHMARK_ROOT PREPARED_ROOT ' +
      'NEW_OUTPUT_ROOT [--repetitions=N] [--tasks=910,1065,19902]'
  );
}

function parseArguments(values: string[]): Arguments {
  const positional = values.filter(value => !value.startsWith('--'));
  if (positional.length !== 4) usage();
  const repetitionOption = values.find(value => value.startsWith('--repetitions='));
  const taskOption = values.find(value => value.startsWith('--tasks='));
  const unknown = values.filter(
    value =>
      value.startsWith('--') && !value.startsWith('--repetitions=') && !value.startsWith('--tasks=')
  );
  if (unknown.length > 0) throw new Error(`Unknown options: ${unknown.join(', ')}`);
  const repetitions = Number(repetitionOption?.slice('--repetitions='.length) ?? '1');
  if (!Number.isSafeInteger(repetitions) || repetitions < 1 || repetitions > 10) {
    throw new Error('Repetitions must be an integer from 1 to 10');
  }
  const tasks = taskOption?.slice('--tasks='.length).split(',').filter(Boolean);
  if (tasks?.length === 0) throw new Error('Tasks must not be empty');
  return {
    registryPath: resolve(positional[0]),
    benchmarkRoot: resolve(positional[1]),
    preparedRoot: resolve(positional[2]),
    outputRoot: resolve(positional[3]),
    repetitions,
    taskIds: tasks ? new Set(tasks) : undefined,
  };
}

function requireBenchmark(
  manifest: FrozenTaskManifest
): NonNullable<FrozenTaskManifest['evaluator']['secRepoBench']> {
  const benchmark = manifest.evaluator.secRepoBench;
  if (manifest.provenance?.benchmark !== 'SecRepoBench' || !benchmark) {
    throw new Error(`${manifest.id} is not a SecRepoBench task`);
  }
  return benchmark;
}

async function main(): Promise<void> {
  const args = parseArguments(process.argv.slice(2));
  const repositoryRoot = await realpath(process.cwd());
  const outputFromRepository = relative(repositoryRoot, args.outputRoot);
  if (
    outputFromRepository === '' ||
    outputFromRepository.startsWith('..') ||
    isAbsolute(outputFromRepository)
  ) {
    throw new Error('NEW_OUTPUT_ROOT must be contained by the Archon repository');
  }
  try {
    await lstat(args.outputRoot);
    throw new Error('NEW_OUTPUT_ROOT already exists');
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || error.code !== 'ENOENT') throw error;
  }

  const manifests = loadFrozenTaskRegistry(args.registryPath).tasks.filter(
    manifest => !args.taskIds || args.taskIds.has(requireBenchmark(manifest).taskId)
  );
  if (manifests.length === 0) throw new Error('No selected calibration tasks were found');
  if (args.taskIds && manifests.length !== args.taskIds.size) {
    throw new Error('At least one requested calibration task is absent from the registry');
  }
  const imageReferences = [
    ...new Set(manifests.map(manifest => requireBenchmark(manifest).arvoImage)),
  ].sort();
  const evaluatorImages = await Promise.all(
    imageReferences.map(reference => inspectNativeEvaluatorImage(reference))
  );
  if (
    evaluatorImages.some(
      identity => identity.hostArchitecture !== 'amd64' || identity.imageArchitecture !== 'amd64'
    )
  ) {
    throw new Error('SecRepoBench qualification requires a native amd64 Docker environment');
  }
  const hostIdentities = new Set(
    evaluatorImages.map(identity => `${identity.hostOs}:${identity.hostArchitecture}`)
  );
  if (hostIdentities.size !== 1) {
    throw new Error('Calibration images did not observe one stable Docker host identity');
  }
  const evaluatorHost = evaluatorImages[0];
  if (!evaluatorHost) throw new Error('Calibration did not inspect an evaluator image');
  await mkdir(args.outputRoot);
  const results = [];
  for (const manifest of manifests) {
    const benchmark = requireBenchmark(manifest);
    await verifySecRepoBenchBenchmarkSurface(manifest, args.benchmarkRoot);
    const extension = extname(benchmark.changedFile);
    for (const variant of ['secure', 'vulnerable'] as const) {
      for (let repetition = 1; repetition <= args.repetitions; repetition += 1) {
        const attemptRoot = resolve(args.outputRoot, benchmark.taskId, variant, String(repetition));
        const runRoot = resolve(attemptRoot, 'run');
        const controlRoot = resolve(attemptRoot, 'control');
        await mkdir(runRoot, { recursive: true });
        await mkdir(controlRoot, { recursive: true });
        const materialization = await materializeSecRepoBenchWorkspace({
          manifest,
          sourceRepositoryRoot: resolve(args.preparedRoot, 'sources', benchmark.taskId),
          maskedTargetPath: resolve(args.preparedRoot, 'masks', `${benchmark.taskId}${extension}`),
          repositoryRoot: runRoot,
        });
        const workspaceRoot = resolve(runRoot, materialization.workspaceRoot);
        await assertFreshSanitizedWorkspace(workspaceRoot);
        const referenceName =
          variant === 'secure'
            ? `sec_code_block_base${extension}`
            : `vul_code_block_base${extension}`;
        const referencePath = resolve(
          args.benchmarkRoot,
          'descriptions',
          benchmark.taskId,
          referenceName
        );
        const referenceStatus = await lstat(referencePath);
        if (!referenceStatus.isFile() || referenceStatus.isSymbolicLink()) {
          throw new Error(`Invalid calibration reference ${referencePath}`);
        }
        const targetPath = resolve(workspaceRoot, benchmark.changedFile);
        const [maskedSource, replacement] = await Promise.all([
          readFile(targetPath, 'utf8'),
          readFile(referencePath, 'utf8'),
        ]);
        if (maskedSource.split(benchmark.completionMarker).length !== 2) {
          throw new Error(`Calibration target for ${benchmark.taskId} has an ambiguous mask`);
        }
        await writeFile(targetPath, maskedSource.replace(benchmark.completionMarker, replacement));
        const candidate = await extractSecRepoBenchCandidate({
          manifest,
          materialization,
          workspaceRoot,
          attemptId: `calibration-${variant}-${String(repetition)}`,
        });
        const evaluation = await evaluateSecRepoBenchCandidateOfficially({
          manifest,
          candidate,
          workspaceRoot,
          repositoryRoot,
          frozenEvaluatorPath: args.benchmarkRoot,
          outputRoot: resolve(controlRoot, 'evaluation'),
        });
        const expectedDecision = variant === 'secure' ? 'verified' : 'insecure';
        const passed = evaluation.decision === expectedDecision;
        const result = {
          taskId: benchmark.taskId,
          variant,
          repetition,
          expectedDecision,
          passed,
          candidateSha256: candidate.completedFileSha256,
          evaluation,
        };
        results.push(result);
        await writeFile(
          resolve(controlRoot, 'calibration-result.json'),
          `${JSON.stringify(result, null, 2)}\n`,
          'utf8'
        );
        process.stdout.write(
          `${benchmark.taskId} ${variant} #${String(repetition)}: ${evaluation.decision}\n`
        );
        if (!passed) {
          throw new Error(
            `Calibration failed for ${benchmark.taskId} ${variant}: ` +
              `expected ${expectedDecision}, observed ${evaluation.decision}`
          );
        }
      }
    }
  }
  await writeFile(
    resolve(args.outputRoot, 'calibration-summary.json'),
    `${JSON.stringify(
      {
        schemaVersion: '0.2.0',
        repetitions: args.repetitions,
        passed: results.every(result => result.passed),
        environment: {
          host: {
            os: evaluatorHost.hostOs,
            architecture: evaluatorHost.hostArchitecture,
          },
          images: evaluatorImages.map(identity => ({
            reference: identity.reference,
            imageId: identity.imageId,
            repoDigests: identity.repoDigests,
            os: identity.imageOs,
            architecture: identity.imageArchitecture,
          })),
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
