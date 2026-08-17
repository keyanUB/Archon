import { createHash } from 'node:crypto';
import type { Stats } from 'node:fs';
import { lstat, readFile, readlink, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';

import type { FrozenTaskManifest } from './pgacs-task-adapters';
import {
  createSecRepoBenchTaskViews,
  type SecRepoBenchMaterializationReceipt,
} from './pgacs-secrepobench-materializer';
import { stableSha256 } from './pgacs-runtime-policy-state';

interface BaselineTreeEntry {
  mode: '100644' | '100755' | '120000';
  objectId: string;
  path: string;
}

interface ProtectedTreeEntry {
  path: string;
  mode: BaselineTreeEntry['mode'];
  sha256: string;
}

export interface SecRepoBenchCandidate {
  schemaVersion: '0.1.0';
  taskId: string;
  attemptId: string;
  parentCandidateSha256?: string;
  baseTreeSha256: string;
  baselineCommit: string;
  targetPath: string;
  scopeProof: 'byte-bound-prefix-suffix-v0.1';
  replacementText: string;
  replacementSha256: string;
  replacementBytes: number;
  completedFileSha256: string;
  normalizedPatch: string;
  patchSha256: string;
  changedTrackedPaths: string[];
  untrackedPaths: string[];
  protectedTreeSha256: string;
  candidateSha256: string;
}

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function assertContainedPath(root: string, candidate: string, label: string): void {
  const fromRoot = relative(root, candidate);
  if (fromRoot === '' || fromRoot.startsWith('..') || isAbsolute(fromRoot)) {
    throw new Error(`${label} must be contained by its root`);
  }
}

async function requireLstat(path: string, missingMessage: string): Promise<Stats> {
  try {
    return await lstat(path);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new Error(missingMessage);
    }
    throw error;
  }
}

async function runGitText(args: string[], cwd: string): Promise<string> {
  const subprocess = Bun.spawn(['git', ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(
      stderr.trim() || `git ${args.join(' ')} exited with status ${String(exitCode)}`
    );
  }
  return stdout;
}

async function runGitBytes(args: string[], cwd: string): Promise<Uint8Array> {
  const subprocess = Bun.spawn(['git', ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).arrayBuffer(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(
      stderr.trim() || `git ${args.join(' ')} exited with status ${String(exitCode)}`
    );
  }
  return new Uint8Array(stdout);
}

function parseNulPaths(bytes: Uint8Array): string[] {
  return new TextDecoder('utf-8', { fatal: true })
    .decode(bytes)
    .split('\0')
    .filter(value => value.length > 0)
    .sort();
}

async function readBaselineTree(
  workspaceRoot: string,
  baselineCommit: string
): Promise<BaselineTreeEntry[]> {
  const bytes = await runGitBytes(['ls-tree', '-r', '-z', baselineCommit], workspaceRoot);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return text
    .split('\0')
    .filter(value => value.length > 0)
    .map((value): BaselineTreeEntry => {
      const match = /^(\d{6}) (blob|commit) ([a-f0-9]{40,64})\t([\s\S]+)$/.exec(value);
      if (!match) throw new Error('Unable to parse the sanitized baseline tree');
      const [, rawMode, kind, objectId, path] = match;
      if (kind !== 'blob' || !['100644', '100755', '120000'].includes(rawMode)) {
        throw new Error(`Unsupported sanitized baseline entry ${rawMode} ${path}`);
      }
      return {
        mode: rawMode as BaselineTreeEntry['mode'],
        objectId,
        path,
      };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
}

function locateMarker(bytes: Uint8Array, marker: string): { start: number; end: number } {
  const source = Buffer.from(bytes);
  const markerBytes = Buffer.from(marker, 'utf8');
  const start = source.indexOf(markerBytes);
  if (start < 0 || source.indexOf(markerBytes, start + markerBytes.length) >= 0) {
    throw new Error('Sanitized baseline must contain exactly one completion marker');
  }
  return { start, end: start + markerBytes.length };
}

async function hashProtectedTree(input: {
  workspaceRoot: string;
  entries: BaselineTreeEntry[];
  targetPath: string;
}): Promise<string> {
  const protectedEntries: ProtectedTreeEntry[] = [];
  for (const entry of input.entries) {
    if (entry.path === input.targetPath) continue;
    const path = resolve(input.workspaceRoot, entry.path);
    assertContainedPath(input.workspaceRoot, path, 'protected path');
    const status = await requireLstat(path, `Protected path is missing: ${entry.path}`);
    if (entry.mode === '120000') {
      if (!status.isSymbolicLink()) {
        throw new Error(`Protected symbolic link changed type: ${entry.path}`);
      }
      const linkTarget = await readlink(path);
      const resolvedTarget = resolve(dirname(path), linkTarget);
      assertContainedPath(input.workspaceRoot, resolvedTarget, 'protected symbolic link target');
      protectedEntries.push({ path: entry.path, mode: entry.mode, sha256: sha256(linkTarget) });
      continue;
    }
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error(`Protected file changed type: ${entry.path}`);
    }
    const expectedExecutable = entry.mode === '100755';
    const actualExecutable = (status.mode & 0o111) !== 0;
    if (expectedExecutable !== actualExecutable) {
      throw new Error(`Protected file mode changed: ${entry.path}`);
    }
    protectedEntries.push({
      path: entry.path,
      mode: entry.mode,
      sha256: sha256(await readFile(path)),
    });
  }
  return stableSha256(protectedEntries);
}

export async function extractSecRepoBenchCandidate(input: {
  manifest: FrozenTaskManifest;
  materialization: SecRepoBenchMaterializationReceipt;
  workspaceRoot: string;
  attemptId: string;
  parentCandidateSha256?: string;
  maxReplacementBytes?: number;
}): Promise<SecRepoBenchCandidate> {
  const views = createSecRepoBenchTaskViews(input.manifest, input.materialization);
  if (input.attemptId.trim().length === 0) throw new Error('Candidate attemptId must be non-empty');
  const maxReplacementBytes = input.maxReplacementBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maxReplacementBytes) || maxReplacementBytes <= 0) {
    throw new Error('Candidate maxReplacementBytes must be a positive safe integer');
  }

  const workspaceRoot = await realpath(input.workspaceRoot);
  const gitStatus = await lstat(resolve(workspaceRoot, '.git'));
  if (!gitStatus.isDirectory() || gitStatus.isSymbolicLink()) {
    throw new Error('Candidate workspace .git must be a regular directory');
  }
  const head = (await runGitText(['rev-parse', 'HEAD'], workspaceRoot)).trim();
  if (head !== input.materialization.baselineCommit) {
    throw new Error('Candidate workspace HEAD does not match the sanitized baseline');
  }
  const commitCount = Number(
    (await runGitText(['rev-list', '--count', '--all'], workspaceRoot)).trim()
  );
  if (commitCount !== 1) {
    throw new Error('Candidate workspace contains unauthorized Git history');
  }
  if ((await runGitText(['remote'], workspaceRoot)).trim() !== '') {
    throw new Error('Candidate workspace contains an unauthorized Git remote');
  }

  const changedTrackedPaths = parseNulPaths(
    await runGitBytes(['diff', '--name-only', '-z', head, '--'], workspaceRoot)
  );
  const untrackedPaths = parseNulPaths(
    await runGitBytes(['ls-files', '--others', '--exclude-standard', '-z'], workspaceRoot)
  );
  if (untrackedPaths.length > 0) {
    throw new Error(`Candidate contains untracked paths: ${untrackedPaths.join(', ')}`);
  }
  if (
    changedTrackedPaths.length !== 1 ||
    changedTrackedPaths[0] !== views.generation.workspace.targetPath
  ) {
    throw new Error(
      `Candidate must change only ${views.generation.workspace.targetPath}; changed=${changedTrackedPaths.join(', ')}`
    );
  }

  const baselineTree = await readBaselineTree(workspaceRoot, head);
  const targetEntry = baselineTree.find(
    entry => entry.path === views.generation.workspace.targetPath
  );
  if (!targetEntry || targetEntry.mode === '120000') {
    throw new Error('Candidate target is not a regular baseline file');
  }
  const targetPath = resolve(workspaceRoot, targetEntry.path);
  assertContainedPath(workspaceRoot, targetPath, 'candidate target');
  const targetStatus = await requireLstat(
    targetPath,
    'Candidate target must remain a regular, non-symlinked file'
  );
  if (!targetStatus.isFile() || targetStatus.isSymbolicLink()) {
    throw new Error('Candidate target must remain a regular, non-symlinked file');
  }
  const expectedExecutable = targetEntry.mode === '100755';
  if (((targetStatus.mode & 0o111) !== 0) !== expectedExecutable) {
    throw new Error('Candidate target file mode changed');
  }

  const baselineBytes = await runGitBytes(['show', `${head}:${targetEntry.path}`], workspaceRoot);
  const completedBytes = await readFile(targetPath);
  const marker = locateMarker(baselineBytes, views.generation.workspace.completionMarker);
  const prefix = baselineBytes.subarray(0, marker.start);
  const suffix = baselineBytes.subarray(marker.end);
  if (!Buffer.from(completedBytes).subarray(0, prefix.length).equals(Buffer.from(prefix))) {
    throw new Error('Candidate changed bytes before the completion region');
  }
  if (
    completedBytes.length < prefix.length + suffix.length ||
    !Buffer.from(completedBytes)
      .subarray(completedBytes.length - suffix.length)
      .equals(Buffer.from(suffix))
  ) {
    throw new Error('Candidate changed bytes after the completion region');
  }
  const replacementBytes = completedBytes.subarray(
    prefix.length,
    completedBytes.length - suffix.length
  );
  if (replacementBytes.length === 0 || replacementBytes.length > maxReplacementBytes) {
    throw new Error('Candidate replacement is empty or exceeds the byte limit');
  }
  const replacementText = new TextDecoder('utf-8', { fatal: true }).decode(replacementBytes);
  if (replacementText.trim().length === 0) {
    throw new Error('Candidate replacement must contain non-whitespace source');
  }
  if (replacementText.includes(views.generation.workspace.completionMarker)) {
    throw new Error('Candidate replacement retains the completion marker');
  }

  const protectedTreeSha256 = await hashProtectedTree({
    workspaceRoot,
    entries: baselineTree,
    targetPath: targetEntry.path,
  });
  if (protectedTreeSha256 !== input.materialization.protectedTreeSha256) {
    throw new Error('Candidate protected-tree digest does not match materialization');
  }
  const normalizedPatch = await runGitText(
    ['diff', '--binary', '--no-ext-diff', head, '--', targetEntry.path],
    workspaceRoot
  );
  if (normalizedPatch.length === 0) throw new Error('Candidate normalized patch is empty');

  const candidateCore = {
    taskId: input.manifest.id,
    attemptId: input.attemptId,
    parentCandidateSha256: input.parentCandidateSha256,
    baseTreeSha256: input.materialization.sanitizedTreeSha256,
    baselineCommit: head,
    targetPath: targetEntry.path,
    replacementSha256: sha256(replacementBytes),
    completedFileSha256: sha256(completedBytes),
    patchSha256: sha256(normalizedPatch),
    protectedTreeSha256,
  };
  return {
    schemaVersion: '0.1.0',
    ...candidateCore,
    scopeProof: 'byte-bound-prefix-suffix-v0.1',
    replacementText,
    replacementBytes: replacementBytes.length,
    normalizedPatch,
    changedTrackedPaths,
    untrackedPaths,
    candidateSha256: stableSha256(candidateCore),
  };
}

export function assertSecRepoBenchCandidateLineage(candidates: SecRepoBenchCandidate[]): void {
  if (candidates.length === 0) throw new Error('Candidate lineage must not be empty');
  const [initial] = candidates;
  if (!initial) throw new Error('Candidate lineage must have an initial candidate');
  for (const [index, candidate] of candidates.entries()) {
    if (
      candidate.taskId !== initial.taskId ||
      candidate.baseTreeSha256 !== initial.baseTreeSha256 ||
      candidate.baselineCommit !== initial.baselineCommit ||
      candidate.targetPath !== initial.targetPath ||
      candidate.protectedTreeSha256 !== initial.protectedTreeSha256
    ) {
      throw new Error(`Candidate lineage binding changed at attempt ${String(index)}`);
    }
    if (index === 0 && candidate.parentCandidateSha256 !== undefined) {
      throw new Error('Initial candidate must not declare a parent');
    }
    if (index > 0 && candidate.parentCandidateSha256 !== candidates[index - 1]?.candidateSha256) {
      throw new Error(`Candidate lineage parent mismatch at attempt ${String(index)}`);
    }
  }
}
