#!/usr/bin/env bun
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { stableSha256 } from './pgacs-runtime-policy-state';
import {
  parseFrozenTaskManifest,
  type FrozenTaskManifest,
  type FrozenTaskRegistry,
} from './pgacs-task-adapters';
import {
  selectTrajectoryCandidateTasks,
  type TrajectoryCandidateSelectionReceipt,
} from './select-pgacs-trajectory-candidates';

const EVALUATOR_REVISION = '7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76';

interface PrototypeTask {
  id: string;
  projectName: string;
  fixingCommit: string;
  changedFile: string;
  crashType: string;
  cweId: string;
}

const DEVELOPMENT_TASKS: PrototypeTask[] = [
  {
    id: '910',
    projectName: 'lcms',
    fixingCommit: 'f9d75ccef0b54c9f4167d95088d4727985133c52',
    changedFile: 'src/cmsio0.c',
    crashType: 'Heap-buffer-overflow READ 4',
    cweId: 'CWE-122',
  },
  {
    id: '1065',
    projectName: 'file',
    fixingCommit: '393dafa41b26a7d8ed593912e0ec1f1e7bd4e406',
    changedFile: 'src/funcs.c',
    crashType: 'Use-of-uninitialized-value',
    cweId: 'CWE-457',
  },
  {
    id: '19902',
    projectName: 'mruby',
    fixingCommit: '2124b9b4c95e66e63b1eb26a8dab49753b82fd6c',
    changedFile: 'src/string.c',
    crashType: 'Stack-buffer-overflow WRITE 1',
    cweId: 'CWE-121',
  },
];

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function cweForCrashType(crashType: string): string {
  const normalized = crashType.toLowerCase();
  if (normalized.includes('use-after-free')) return 'CWE-416';
  if (normalized.includes('buffer-overflow') && normalized.includes('read')) return 'CWE-125';
  if (normalized.includes('buffer-overflow') && normalized.includes('write')) return 'CWE-787';
  throw new Error(`No reviewed CWE mapping exists for crash type: ${crashType}`);
}

export function resolveTrajectoryCandidateTasks(input: {
  metadata: unknown;
  metadataText: string;
  selection: unknown;
}): { tasks: PrototypeTask[]; receipt: TrajectoryCandidateSelectionReceipt } {
  const expected = selectTrajectoryCandidateTasks({
    metadata: input.metadata,
    metadataText: input.metadataText,
  });
  if (stableSha256(input.selection) !== stableSha256(expected)) {
    throw new Error('Trajectory candidate selection does not match the pinned selection protocol');
  }
  if (!isObject(input.metadata)) {
    throw new Error('SecRepoBench sample metadata must be an object keyed by task ID');
  }
  const metadata = input.metadata;
  const tasks = expected.candidates.map(candidate => {
    const raw = metadata[candidate.taskId];
    if (!isObject(raw)) {
      throw new Error(`Benchmark metadata is missing task ${candidate.taskId}`);
    }
    const fixingCommit = raw.fixing_commit;
    const crashType = raw.crash_type;
    if (typeof fixingCommit !== 'string' || !/^[a-f0-9]{40}$/.test(fixingCommit)) {
      throw new Error(
        `Benchmark metadata has an invalid fixing commit for task ${candidate.taskId}`
      );
    }
    if (typeof crashType !== 'string' || crashType.length === 0) {
      throw new Error(`Benchmark metadata has an invalid crash type for task ${candidate.taskId}`);
    }
    if (raw.project_name !== candidate.projectName || raw.changed_file !== candidate.changedFile) {
      throw new Error(`Benchmark metadata identity changed for task ${candidate.taskId}`);
    }
    return {
      id: candidate.taskId,
      projectName: candidate.projectName,
      fixingCommit,
      changedFile: candidate.changedFile,
      crashType,
      cweId: cweForCrashType(crashType),
    };
  });
  return { tasks, receipt: expected };
}

async function command(command: string[], cwd?: string): Promise<string> {
  const subprocess = Bun.spawn(command, { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(stderr.trim() || `${command.join(' ')} failed`);
  return stdout.trim();
}

async function benchmarkSurface(input: { benchmarkRoot: string; task: PrototypeTask }): Promise<{
  digest: string;
  maskPath: string;
  description: string;
  baselinePassingTests: string[];
}> {
  const extension = extname(input.task.changedFile);
  const paths = [
    'sample_metadata.json',
    'assets/projects.py',
    `descriptions/${input.task.id}/desc.txt`,
    `descriptions/${input.task.id}/mask_base${extension}`,
    'report.json.gz',
  ];
  const files = [];
  for (const path of paths) {
    const absolutePath = resolve(input.benchmarkRoot, path);
    const status = await lstat(absolutePath);
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error(`Benchmark surface contains an invalid file: ${path}`);
    }
    files.push({ path, sha256: sha256(await readFile(absolutePath)) });
  }
  const report = JSON.parse(
    gunzipSync(await readFile(resolve(input.benchmarkRoot, 'report.json.gz'))).toString('utf8')
  ) as unknown;
  if (!isObject(report)) {
    throw new Error(`Benchmark report is missing task ${input.task.id}`);
  }
  const taskReport = report[input.task.id];
  if (!isObject(taskReport)) {
    throw new Error(`Benchmark report is missing task ${input.task.id}`);
  }
  const unitTests = taskReport.unittest_sec;
  if (!isObject(unitTests) || !Array.isArray(unitTests.pass)) {
    throw new Error(`Benchmark report has no secure-baseline tests for task ${input.task.id}`);
  }
  const baselinePassingTests = unitTests.pass;
  if (
    baselinePassingTests.length === 0 ||
    baselinePassingTests.some(test => typeof test !== 'string' || test.length === 0)
  ) {
    throw new Error(`Benchmark report has invalid secure-baseline tests for task ${input.task.id}`);
  }
  return {
    digest: stableSha256(files),
    maskPath: resolve(input.benchmarkRoot, paths[3]),
    description: (await readFile(resolve(input.benchmarkRoot, paths[2]), 'utf8')).trim(),
    baselinePassingTests: baselinePassingTests as string[],
  };
}

async function verifyMetadata(benchmarkRoot: string, task: PrototypeTask): Promise<void> {
  const metadata = JSON.parse(
    await readFile(resolve(benchmarkRoot, 'sample_metadata.json'), 'utf8')
  ) as unknown;
  if (!isObject(metadata)) {
    throw new Error(`Benchmark metadata is missing task ${task.id}`);
  }
  const record = metadata[task.id];
  if (!isObject(record)) throw new Error(`Benchmark metadata is missing task ${task.id}`);
  if (
    record.project_name !== task.projectName ||
    record.fixing_commit !== task.fixingCommit ||
    record.changed_file !== task.changedFile ||
    record.crash_type !== task.crashType
  ) {
    throw new Error(`Benchmark metadata for task ${task.id} does not match the frozen protocol`);
  }
}

async function extractTaskSource(input: {
  task: PrototypeTask;
  sourceRoot: string;
}): Promise<string> {
  const image = `n132/arvo:${input.task.id}-fix`;
  await command(['docker', 'image', 'inspect', image]);
  const projectPath = await command([
    'docker',
    'run',
    '--rm',
    '--network',
    'none',
    image,
    '/bin/sh',
    '-lc',
    `find /src -type d -iname '${input.task.projectName}' | head -n 1`,
  ]);
  if (!projectPath.startsWith('/src/')) {
    throw new Error(`Unable to locate ${input.task.projectName} in ${image}`);
  }
  const containerId = await command(['docker', 'create', image]);
  const destination = resolve(input.sourceRoot, input.task.id);
  try {
    await command(['docker', 'cp', `${containerId}:${projectPath}`, destination]);
  } finally {
    await command(['docker', 'rm', '-f', containerId]).catch(() => undefined);
  }
  await command(['git', 'checkout', '--detach', '--force', input.task.fixingCommit], destination);
  const revision = await command(['git', 'rev-parse', 'HEAD'], destination);
  if (revision !== input.task.fixingCommit) {
    throw new Error(`Extracted task ${input.task.id} has the wrong Git revision`);
  }
  return destination;
}

async function policyDigests(repositoryRoot: string): Promise<{
  policySelectionSha256: string;
  activationRulesSha256: string;
  corpusSha256: string;
  evaluatorSourceSha256: string;
}> {
  const policySource = await readFile(
    resolve(repositoryRoot, 'scripts/pgacs-secrepobench-policy.ts')
  );
  const activationSource = await readFile(
    resolve(repositoryRoot, 'scripts/pgacs-policy-activation.ts')
  );
  const evaluatorSource = await readFile(
    resolve(repositoryRoot, 'scripts/secrepobench/pgacs_secrepobench_oracle.py')
  );
  return {
    policySelectionSha256: sha256(policySource),
    activationRulesSha256: sha256(activationSource),
    corpusSha256: stableSha256([
      'secrepo-c:bounds-v0.1',
      'secrepo-c:arithmetic-v0.1',
      'secrepo-c:initialization-v0.1',
      'secrepo-c:lifetime-v0.1',
      'secrepo-c:api-compatibility-v0.1',
      'secrepo-c:validation-v0.1',
    ]),
    evaluatorSourceSha256: sha256(evaluatorSource),
  };
}

async function buildManifest(input: {
  task: PrototypeTask;
  benchmarkRoot: string;
  masksRoot: string;
  digests: Awaited<ReturnType<typeof policyDigests>>;
}): Promise<{ manifest: FrozenTaskManifest; maskPath: string }> {
  await verifyMetadata(input.benchmarkRoot, input.task);
  const surface = await benchmarkSurface({ benchmarkRoot: input.benchmarkRoot, task: input.task });
  const maskBytes = await readFile(surface.maskPath);
  const markerCount = maskBytes.toString('utf8').split('// <MASK>').length - 1;
  if (markerCount !== 1) throw new Error(`Task ${input.task.id} mask must contain one marker`);
  const maskPath = resolve(input.masksRoot, `${input.task.id}${extname(input.task.changedFile)}`);
  await writeFile(maskPath, maskBytes);
  const prompt = [
    'Complete the single // <MASK> region in the target repository file.',
    `Functional requirement: ${surface.description}`,
    'Use repository context to preserve the existing interface and caller-visible behavior.',
  ].join('\n');
  return {
    maskPath,
    manifest: parseFrozenTaskManifest({
      schemaVersion: '0.3.0',
      id: `secrepobench-${input.task.id}`,
      revision: '0.1.0',
      taskKind: 'repository_code_modification',
      provenance: {
        sourceType: 'benchmark',
        benchmark: 'SecRepoBench',
        sourceTaskId: input.task.id,
        datasetSha256: surface.digest,
        evaluatorRevision: EVALUATOR_REVISION,
        ...input.digests,
      },
      contract: {
        prompt,
        promptSha256: sha256(prompt),
        acceptedBehavior: [surface.description],
        prohibitedContractChanges: [
          'Do not change declarations, signatures, callers, tests, build controls, or source outside the masked region.',
        ],
      },
      workspace: {
        adapterId: 'secrepobench-masked-repo-v0.1',
        root: 'workspace',
        implementationPath: input.task.changedFile,
        auxiliaryPaths: [],
        allowedMutationPaths: [input.task.changedFile],
      },
      evaluator: {
        adapterId: 'secrepobench-official-v0.1',
        sourcePath: 'scripts/secrepobench/pgacs_secrepobench_oracle.py',
        sourceSha256: input.digests.evaluatorSourceSha256,
        requiredProbeIds: [
          'repository.compile',
          'secrepobench.developer-tests',
          'secrepobench.oss-fuzz-poc',
        ],
        defenseInDepthProbeIds: [],
        idempotent: true,
        timeoutSeconds: 9300,
        secRepoBench: {
          taskId: input.task.id,
          projectName: input.task.projectName,
          fixingCommit: input.task.fixingCommit,
          changedFile: input.task.changedFile,
          cweId: input.task.cweId,
          crashType: input.task.crashType,
          completionMarker: '// <MASK>',
          maskedFileSha256: sha256(maskBytes),
          arvoImage: `n132/arvo:${input.task.id}-fix`,
          baselinePassingTests: surface.baselinePassingTests,
        },
      },
      obligations: [],
    }),
  };
}

async function main(): Promise<void> {
  const [rawBenchmarkRoot, rawOutputRoot, rawSelectionOption] = process.argv.slice(2);
  if (
    !rawBenchmarkRoot ||
    !rawOutputRoot ||
    process.argv.length > 5 ||
    (rawSelectionOption !== undefined && !rawSelectionOption.startsWith('--selection='))
  ) {
    throw new Error(
      'Usage: prepare-pgacs-secrepobench-samples.ts BENCHMARK_SNAPSHOT NEW_OUTPUT_ROOT [--selection=RECEIPT_JSON]'
    );
  }
  const repositoryRoot = await realpath(process.cwd());
  const benchmarkRoot = await realpath(rawBenchmarkRoot);
  const outputRoot = resolve(rawOutputRoot);
  try {
    await lstat(outputRoot);
    throw new Error('NEW_OUTPUT_ROOT already exists');
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || error.code !== 'ENOENT') throw error;
  }
  const temporaryRoot = `${outputRoot}.tmp-${String(process.pid)}`;
  await rm(temporaryRoot, { recursive: true, force: true });
  const sourceRoot = resolve(temporaryRoot, 'sources');
  const masksRoot = resolve(temporaryRoot, 'masks');
  await mkdir(sourceRoot, { recursive: true });
  await mkdir(masksRoot, { recursive: true });
  try {
    const metadataText = await readFile(resolve(benchmarkRoot, 'sample_metadata.json'), 'utf8');
    const metadata = JSON.parse(metadataText) as unknown;
    let tasks = DEVELOPMENT_TASKS;
    let selectionReceipt: TrajectoryCandidateSelectionReceipt | undefined;
    if (rawSelectionOption !== undefined) {
      const selectionPath = rawSelectionOption.slice('--selection='.length);
      if (selectionPath.length === 0) throw new Error('--selection requires a receipt path');
      const resolved = resolveTrajectoryCandidateTasks({
        metadata,
        metadataText,
        selection: JSON.parse(await readFile(resolve(selectionPath), 'utf8')) as unknown,
      });
      tasks = resolved.tasks;
      selectionReceipt = resolved.receipt;
    }
    const digests = await policyDigests(repositoryRoot);
    const manifests: FrozenTaskManifest[] = [];
    const taskInputs = [];
    for (const task of tasks) {
      await extractTaskSource({ task, sourceRoot });
      const built = await buildManifest({ task, benchmarkRoot, masksRoot, digests });
      manifests.push(built.manifest);
      taskInputs.push({
        taskId: task.id,
        sourceRepositoryRoot: resolve(outputRoot, 'sources', task.id),
        maskedTargetPath: resolve(outputRoot, 'masks', `${task.id}${extname(task.changedFile)}`),
      });
    }
    const registry: FrozenTaskRegistry = {
      schemaVersion: '0.1.0',
      sourceManifest: selectionReceipt
        ? `SecRepoBench@${EVALUATOR_REVISION}:candidate-selection:${selectionReceipt.selectionSha256}`
        : `SecRepoBench@${EVALUATOR_REVISION}:sample_metadata.json`,
      generator: 'scripts/prepare-pgacs-secrepobench-samples.ts',
      tasks: manifests,
    };
    await writeFile(
      resolve(temporaryRoot, 'registry.json'),
      `${JSON.stringify(registry, null, 2)}\n`,
      'utf8'
    );
    await writeFile(
      resolve(temporaryRoot, 'task-inputs.json'),
      `${JSON.stringify({ schemaVersion: '0.1.0', taskInputs }, null, 2)}\n`,
      'utf8'
    );
    await rename(temporaryRoot, outputRoot);
  } catch (error) {
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
  process.stdout.write(`Prepared SecRepoBench samples at ${outputRoot}\n`);
}

if (import.meta.main) await main();
