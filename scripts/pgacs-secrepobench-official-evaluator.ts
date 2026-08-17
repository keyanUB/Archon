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
