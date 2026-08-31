import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

import { resolveEvaluatorAdapter, type FrozenTaskManifest } from './pgacs-task-adapters';
import type { SecRepoBenchCandidate } from './pgacs-secrepobench-candidate';
import {
  normalizeSecRepoBenchExecution,
  type SecRepoBenchEvaluation,
} from './pgacs-secrepobench-evaluation';

export interface SecRepoBenchOfficialEvaluatorInput {
  manifest: FrozenTaskManifest;
  candidate: SecRepoBenchCandidate;
  workspaceRoot: string;
  repositoryRoot: string;
  frozenEvaluatorPath: string;
  outputRoot: string;
}

export interface NativeEvaluatorImageIdentity {
  reference: string;
  imageId: string;
  repoDigests: string[];
  hostArchitecture: string;
  imageArchitecture: string;
  hostOs: string;
  imageOs: string;
}

function normalizeDockerArchitecture(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'aarch64') return 'arm64';
  if (normalized === 'x86_64') return 'amd64';
  return normalized;
}

export function assertNativeEvaluatorArchitecture(input: {
  hostArchitecture: string;
  imageArchitecture: string;
}): void {
  const host = normalizeDockerArchitecture(input.hostArchitecture);
  const image = normalizeDockerArchitecture(input.imageArchitecture);
  if (!host || !image || host !== image) {
    throw new Error(
      `SecRepoBench sanitizer evaluation requires a native image: host=${host || 'unknown'}, image=${image || 'unknown'}`
    );
  }
}

async function dockerArchitecture(command: string[]): Promise<string> {
  const process = Bun.spawn(command, { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  if (exitCode !== 0 || stdout.trim().length === 0) {
    throw new Error(stderr.trim() || `${command.join(' ')} did not report an architecture`);
  }
  return stdout;
}

function parseDockerInspect(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} did not return a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

function requiredInspectString(value: Record<string, unknown>, key: string, label: string): string {
  const item = value[key];
  if (typeof item !== 'string' || item.length === 0) {
    throw new Error(`${label}.${key} is missing`);
  }
  return item;
}

export async function inspectNativeEvaluatorImage(
  image: string
): Promise<NativeEvaluatorImageIdentity> {
  const [hostText, imageText] = await Promise.all([
    dockerArchitecture(['docker', 'info', '--format', '{{json .}}']),
    dockerArchitecture(['docker', 'image', 'inspect', image, '--format', '{{json .}}']),
  ]);
  const host = parseDockerInspect(hostText, 'Docker host');
  const inspectedImage = parseDockerInspect(imageText, 'Docker image');
  const hostArchitecture = requiredInspectString(host, 'Architecture', 'Docker host');
  const imageArchitecture = requiredInspectString(inspectedImage, 'Architecture', 'Docker image');
  assertNativeEvaluatorArchitecture({ hostArchitecture, imageArchitecture });
  const imageId = requiredInspectString(inspectedImage, 'Id', 'Docker image');
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) {
    throw new Error('Docker image ID is not content addressed');
  }
  const rawRepoDigests = inspectedImage.RepoDigests;
  const repoDigests = Array.isArray(rawRepoDigests)
    ? rawRepoDigests.filter((value): value is string => typeof value === 'string').sort()
    : [];
  if (
    repoDigests.length === 0 ||
    repoDigests.some(value => !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(value))
  ) {
    throw new Error('Docker image must expose immutable repository digests');
  }
  return {
    reference: image,
    imageId,
    repoDigests,
    hostArchitecture: normalizeDockerArchitecture(hostArchitecture),
    imageArchitecture: normalizeDockerArchitecture(imageArchitecture),
    hostOs: requiredInspectString(host, 'OSType', 'Docker host'),
    imageOs: requiredInspectString(inspectedImage, 'Os', 'Docker image'),
  };
}

async function executeWithTimeout(input: {
  command: string[];
  cwd: string;
  timeoutSeconds: number;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const subprocess = Bun.spawn(input.command, {
    cwd: input.cwd,
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env },
  });
  let timedOut = false;
  const timer = setTimeout((): void => {
    timedOut = true;
    subprocess.kill('SIGKILL');
  }, input.timeoutSeconds * 1000);
  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(subprocess.stdout).text(),
      new Response(subprocess.stderr).text(),
      subprocess.exited,
    ]);
    return {
      exitCode: timedOut ? 124 : exitCode,
      stdout,
      stderr: timedOut ? `${stderr}\nPGACS evaluator timeout`.trim() : stderr,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function evaluateSecRepoBenchCandidateOfficially(
  input: SecRepoBenchOfficialEvaluatorInput
): Promise<SecRepoBenchEvaluation> {
  const benchmark = input.manifest.evaluator.secRepoBench;
  if (!benchmark) throw new Error('Official SecRepoBench evaluation requires benchmark metadata');
  await inspectNativeEvaluatorImage(benchmark.arvoImage);
  const targetName = basename(input.manifest.workspace.implementationPath);
  const candidateRoot = resolve(input.outputRoot, 'candidate');
  const evaluationRoot = resolve(input.outputRoot, 'oracle');
  await rm(input.outputRoot, { recursive: true, force: true });
  await mkdir(candidateRoot, { recursive: true });
  const completedTarget = await readFile(resolve(input.workspaceRoot, input.candidate.targetPath));
  await writeFile(resolve(candidateRoot, targetName), completedTarget);

  const invocation = await resolveEvaluatorAdapter(input.manifest).prepareInvocation({
    manifest: input.manifest,
    repositoryRoot: input.repositoryRoot,
    frozenEvaluatorPath: input.frozenEvaluatorPath,
    candidatePath: candidateRoot,
    outputRoot: evaluationRoot,
  });
  if (invocation.preparation?.candidateSha256 !== input.candidate.completedFileSha256) {
    throw new Error('Official evaluator staged bytes do not match the admitted completed file');
  }
  const execution = await executeWithTimeout(invocation);
  let rawResult: unknown;
  try {
    rawResult = JSON.parse(await readFile(invocation.resultPath, 'utf8')) as unknown;
  } catch {
    rawResult = undefined;
  }
  return normalizeSecRepoBenchExecution({
    taskId: input.manifest.evaluator.secRepoBench?.taskId ?? input.manifest.id,
    candidateSha256: input.candidate.completedFileSha256,
    exitCode: execution.exitCode,
    rawResult,
    stdout: execution.stdout,
    stderr: execution.stderr,
  });
}
