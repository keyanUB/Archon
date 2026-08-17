import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';

import type { FrozenTaskManifest } from './pgacs-task-adapters';
import { stableSha256 } from './pgacs-runtime-policy-state';

interface GitIndexEntry {
  mode: '100644' | '100755' | '120000';
  objectId: string;
  path: string;
}

interface MaterializedTreeEntry {
  path: string;
  mode: GitIndexEntry['mode'];
  sha256: string;
}

export interface SecRepoBenchMaterializationReceipt {
  schemaVersion: '0.1.0';
  taskId: string;
  manifestSha256: string;
  sourceRevision: string;
  sourceTrackedTreeSha256: string;
  sanitizedTreeSha256: string;
  protectedTreeSha256: string;
  maskedTargetSha256: string;
  targetPrefixSha256: string;
  targetSuffixSha256: string;
  targetPath: string;
  completionMarker: string;
  trackedPathCount: number;
  omittedUntrackedPathCount: number;
  baselineCommit: string;
  workspaceRoot: string;
}

export interface SecRepoBenchGenerationTaskView {
  schemaVersion: '0.1.0';
  taskId: string;
  taskRevision: string;
  taskKind: 'repository_code_modification';
  contract: FrozenTaskManifest['contract'];
  workspace: {
    root: string;
    targetPath: string;
    completionMarker: string;
    allowedMutationPaths: string[];
    sanitizedTreeSha256: string;
  };
  obligations: FrozenTaskManifest['obligations'];
}

export interface SecRepoBenchEvaluatorTaskView {
  schemaVersion: '0.1.0';
  taskId: string;
  manifestSha256: string;
  provenance: NonNullable<FrozenTaskManifest['provenance']>;
  evaluator: FrozenTaskManifest['evaluator'];
  materialization: SecRepoBenchMaterializationReceipt;
}

export interface SecRepoBenchTaskViews {
  generation: SecRepoBenchGenerationTaskView;
  evaluator: SecRepoBenchEvaluatorTaskView;
}

function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function requireSecRepoBenchManifest(
  manifest: FrozenTaskManifest
): NonNullable<FrozenTaskManifest['evaluator']['secRepoBench']> {
  const benchmark = manifest.evaluator.secRepoBench;
  if (
    manifest.schemaVersion !== '0.3.0' ||
    manifest.taskKind !== 'repository_code_modification' ||
    manifest.provenance?.benchmark !== 'SecRepoBench' ||
    benchmark === undefined
  ) {
    throw new Error('SecRepoBench materialization requires a schema 0.3.0 repository task');
  }
  return benchmark;
}

function requireRelativeGitPath(path: string): string {
  const normalized = path.replaceAll('\\', '/');
  if (
    normalized.length === 0 ||
    normalized.includes('\0') ||
    normalized.startsWith('/') ||
    /^[A-Za-z]:/.test(normalized) ||
    normalized.split('/').some(segment => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new Error(`Git index contains an unsafe path: ${JSON.stringify(path)}`);
  }
  return normalized;
}

async function runGitText(args: string[], cwd: string): Promise<string> {
  const subprocess = Bun.spawn(['git', ...args], {
    cwd,
    stdout: 'pipe',
    stderr: 'pipe',
  });
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
  const subprocess = Bun.spawn(['git', ...args], {
    cwd,
    stdout: 'pipe',
    stderr: 'pipe',
  });
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

async function gitDiffIsClean(args: string[], cwd: string): Promise<boolean> {
  const subprocess = Bun.spawn(['git', ...args], {
    cwd,
    stdout: 'ignore',
    stderr: 'pipe',
  });
  const [stderr, exitCode] = await Promise.all([
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode === 0) return true;
  if (exitCode === 1) return false;
  throw new Error(stderr.trim() || `git ${args.join(' ')} exited with status ${String(exitCode)}`);
}

async function assertFrozenTrackedState(sourceRoot: string): Promise<void> {
  const [worktreeClean, indexClean] = await Promise.all([
    gitDiffIsClean(['diff', '--quiet', '--no-ext-diff', '--exit-code'], sourceRoot),
    gitDiffIsClean(['diff', '--cached', '--quiet', '--no-ext-diff', '--exit-code'], sourceRoot),
  ]);
  if (!worktreeClean || !indexClean) {
    throw new Error('SecRepoBench source tracked state must exactly match the frozen commit');
  }
}

async function readGitIndex(sourceRoot: string): Promise<GitIndexEntry[]> {
  const raw = await runGitBytes(['ls-files', '--stage', '-z'], sourceRoot);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  const entries = text
    .split('\0')
    .filter(value => value.length > 0)
    .map((value): GitIndexEntry => {
      const match = /^(\d{6}) ([a-f0-9]{40,64}) (\d)\t([\s\S]+)$/.exec(value);
      if (!match) {
        throw new Error('Unable to parse the frozen source Git index');
      }
      const [, rawMode, objectId, stage, rawPath] = match;
      if (stage !== '0') {
        throw new Error(`Frozen source has an unresolved Git index entry: ${rawPath}`);
      }
      if (rawMode !== '100644' && rawMode !== '100755' && rawMode !== '120000') {
        throw new Error(`Unsupported Git index mode ${rawMode} for ${rawPath}`);
      }
      return {
        mode: rawMode,
        objectId,
        path: requireRelativeGitPath(rawPath),
      };
    });
  entries.sort((left, right) => left.path.localeCompare(right.path));
  if (entries.length === 0) {
    throw new Error('Frozen source repository has no tracked files');
  }
  return entries;
}

function markerOffsets(targetBytes: Uint8Array, marker: string): { start: number; end: number } {
  const markerBytes = Buffer.from(marker, 'utf8');
  const target = Buffer.from(targetBytes);
  const start = target.indexOf(markerBytes);
  if (start < 0 || target.indexOf(markerBytes, start + markerBytes.length) >= 0) {
    throw new Error('SecRepoBench masked target must contain exactly one completion marker');
  }
  return { start, end: start + markerBytes.length };
}

function assertContainedPath(root: string, candidate: string, label: string): void {
  const fromRoot = relative(root, candidate);
  if (fromRoot === '' || fromRoot.startsWith('..') || isAbsolute(fromRoot)) {
    throw new Error(`${label} must be contained by its root`);
  }
}

async function copyIndexEntry(input: {
  entry: GitIndexEntry;
  sourceRoot: string;
  destinationRoot: string;
  targetPath: string;
  maskedTargetBytes: Uint8Array;
}): Promise<MaterializedTreeEntry> {
  const destination = resolve(input.destinationRoot, input.entry.path);
  assertContainedPath(input.destinationRoot, destination, 'tracked path');
  await mkdir(dirname(destination), { recursive: true });

  const bytes =
    input.entry.path === input.targetPath
      ? input.maskedTargetBytes
      : await runGitBytes(['cat-file', 'blob', input.entry.objectId], input.sourceRoot);

  if (input.entry.mode === '120000') {
    const linkTarget = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (linkTarget.length === 0 || isAbsolute(linkTarget)) {
      throw new Error(`Tracked symbolic link has an unsafe target: ${input.entry.path}`);
    }
    const resolvedTarget = resolve(dirname(destination), linkTarget);
    assertContainedPath(input.destinationRoot, resolvedTarget, 'symbolic link target');
    await symlink(linkTarget, destination);
  } else {
    await writeFile(destination, bytes);
    await chmod(destination, input.entry.mode === '100755' ? 0o755 : 0o644);
  }

  return {
    path: input.entry.path,
    mode: input.entry.mode,
    sha256: sha256(bytes),
  };
}

async function initializeDeterministicBaseline(workspaceRoot: string): Promise<string> {
  await runGitText(['init', '-q', '--initial-branch=pgacs-baseline'], workspaceRoot);
  // The source index is already the admission boundary; preserve tracked files even
  // when an upstream .gitignore pattern would hide them in this new repository.
  await runGitText(['add', '--force', '--all'], workspaceRoot);
  const subprocess = Bun.spawn(
    [
      'git',
      '-c',
      'user.name=PGACS Materializer',
      '-c',
      'user.email=pgacs@example.invalid',
      'commit',
      '-q',
      '-m',
      'Sanitized PGACS baseline',
    ],
    {
      cwd: workspaceRoot,
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
        GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    }
  );
  const [stderr, exitCode] = await Promise.all([
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(stderr.trim() || `git commit exited with status ${String(exitCode)}`);
  }
  return (await runGitText(['rev-parse', 'HEAD'], workspaceRoot)).trim();
}

export async function materializeSecRepoBenchWorkspace(input: {
  manifest: FrozenTaskManifest;
  sourceRepositoryRoot: string;
  maskedTargetPath: string;
  repositoryRoot: string;
}): Promise<SecRepoBenchMaterializationReceipt> {
  const benchmark = requireSecRepoBenchManifest(input.manifest);
  const suppliedSourceStatus = await lstat(input.sourceRepositoryRoot);
  if (!suppliedSourceStatus.isDirectory() || suppliedSourceStatus.isSymbolicLink()) {
    throw new Error('SecRepoBench source repository must be a regular directory');
  }
  const sourceRoot = await realpath(input.sourceRepositoryRoot);

  const repositoryRoot = await realpath(input.repositoryRoot);
  const workspaceRoot = resolve(repositoryRoot, input.manifest.workspace.root);
  assertContainedPath(repositoryRoot, workspaceRoot, 'workspace');
  const destinationFromSource = relative(sourceRoot, workspaceRoot);
  if (!destinationFromSource.startsWith('..') && !isAbsolute(destinationFromSource)) {
    throw new Error('Sanitized workspace must not be created inside the source repository');
  }
  try {
    await stat(workspaceRoot);
    throw new Error('Sanitized workspace already exists');
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || error.code !== 'ENOENT') {
      throw error;
    }
  }

  const sourceRevision = (await runGitText(['rev-parse', 'HEAD'], sourceRoot)).trim();
  if (sourceRevision !== benchmark.fixingCommit) {
    throw new Error(
      `SecRepoBench source revision mismatch: expected=${benchmark.fixingCommit} actual=${sourceRevision}`
    );
  }

  await assertFrozenTrackedState(sourceRoot);
  const entries = await readGitIndex(sourceRoot);
  const targetEntry = entries.find(entry => entry.path === benchmark.changedFile);
  if (!targetEntry || targetEntry.mode === '120000') {
    throw new Error('SecRepoBench target must be a tracked regular file');
  }
  const maskedTargetStatus = await lstat(input.maskedTargetPath);
  if (!maskedTargetStatus.isFile() || maskedTargetStatus.isSymbolicLink()) {
    throw new Error('SecRepoBench masked input must be a regular, non-symlinked file');
  }
  const maskedTargetBytes = await readFile(input.maskedTargetPath);
  if (sha256(maskedTargetBytes) !== benchmark.maskedFileSha256) {
    throw new Error('SecRepoBench masked target digest does not match the manifest');
  }
  const offsets = markerOffsets(maskedTargetBytes, benchmark.completionMarker);

  const untracked = await runGitBytes(
    ['ls-files', '--others', '--exclude-standard', '-z'],
    sourceRoot
  );
  const omittedUntrackedPathCount = new TextDecoder('utf-8', { fatal: true })
    .decode(untracked)
    .split('\0')
    .filter(value => value.length > 0).length;

  const temporaryRoot = await mkdtemp(resolve(repositoryRoot, '.pgacs-materialize-'));
  let promoted = false;
  try {
    const materializedEntries: MaterializedTreeEntry[] = [];
    for (const entry of entries) {
      materializedEntries.push(
        await copyIndexEntry({
          entry,
          sourceRoot,
          destinationRoot: temporaryRoot,
          targetPath: benchmark.changedFile,
          maskedTargetBytes,
        })
      );
    }

    const protectedEntries = materializedEntries.filter(
      entry => entry.path !== benchmark.changedFile
    );
    const baselineCommit = await initializeDeterministicBaseline(temporaryRoot);
    const sourceTrackedTreeSha256 = stableSha256(
      entries.map(entry => ({ path: entry.path, mode: entry.mode, objectId: entry.objectId }))
    );
    await rename(temporaryRoot, workspaceRoot);
    promoted = true;

    return {
      schemaVersion: '0.1.0',
      taskId: input.manifest.id,
      manifestSha256: stableSha256(input.manifest),
      sourceRevision,
      sourceTrackedTreeSha256,
      sanitizedTreeSha256: stableSha256(materializedEntries),
      protectedTreeSha256: stableSha256(protectedEntries),
      maskedTargetSha256: sha256(maskedTargetBytes),
      targetPrefixSha256: sha256(maskedTargetBytes.subarray(0, offsets.start)),
      targetSuffixSha256: sha256(maskedTargetBytes.subarray(offsets.end)),
      targetPath: benchmark.changedFile,
      completionMarker: benchmark.completionMarker,
      trackedPathCount: materializedEntries.length,
      omittedUntrackedPathCount,
      baselineCommit,
      workspaceRoot: relative(repositoryRoot, workspaceRoot),
    };
  } finally {
    if (!promoted) {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
}

export function createSecRepoBenchTaskViews(
  manifest: FrozenTaskManifest,
  materialization: SecRepoBenchMaterializationReceipt
): SecRepoBenchTaskViews {
  const benchmark = requireSecRepoBenchManifest(manifest);
  const manifestSha256 = stableSha256(manifest);
  if (
    materialization.taskId !== manifest.id ||
    materialization.manifestSha256 !== manifestSha256 ||
    materialization.targetPath !== benchmark.changedFile ||
    materialization.maskedTargetSha256 !== benchmark.maskedFileSha256
  ) {
    throw new Error('SecRepoBench materialization receipt does not match the manifest');
  }
  if (!manifest.provenance) {
    throw new Error('SecRepoBench task requires benchmark provenance');
  }
  return {
    generation: {
      schemaVersion: '0.1.0',
      taskId: manifest.id,
      taskRevision: manifest.revision,
      taskKind: 'repository_code_modification',
      contract: structuredClone(manifest.contract),
      workspace: {
        root: materialization.workspaceRoot,
        targetPath: benchmark.changedFile,
        completionMarker: benchmark.completionMarker,
        allowedMutationPaths: [...manifest.workspace.allowedMutationPaths],
        sanitizedTreeSha256: materialization.sanitizedTreeSha256,
      },
      obligations: structuredClone(manifest.obligations),
    },
    evaluator: {
      schemaVersion: '0.1.0',
      taskId: manifest.id,
      manifestSha256,
      provenance: structuredClone(manifest.provenance),
      evaluator: structuredClone(manifest.evaluator),
      materialization: structuredClone(materialization),
    },
  };
}

export async function assertFreshSanitizedWorkspace(workspaceRoot: string): Promise<void> {
  const root = await realpath(workspaceRoot);
  const gitDirectory = await lstat(resolve(root, '.git'));
  if (!gitDirectory.isDirectory() || gitDirectory.isSymbolicLink()) {
    throw new Error('Sanitized workspace .git must be a regular directory');
  }
  const remotes = (await runGitText(['remote'], root)).trim();
  if (remotes !== '') {
    throw new Error('Sanitized workspace must not retain Git remotes');
  }
  const commitCount = Number((await runGitText(['rev-list', '--count', '--all'], root)).trim());
  if (commitCount !== 1) {
    throw new Error('Sanitized workspace must contain exactly one baseline commit');
  }
  const statusOutput = (await runGitText(['status', '--porcelain'], root)).trim();
  if (statusOutput !== '') {
    throw new Error('Sanitized workspace baseline must be clean');
  }

  const trackedSymlinks = await runGitText(['ls-files', '-s'], root);
  for (const line of trackedSymlinks.split('\n')) {
    if (!line.startsWith('120000 ')) continue;
    const separator = line.indexOf('\t');
    if (separator < 0) throw new Error('Unable to parse sanitized symbolic link');
    const linkPath = line.slice(separator + 1);
    const linkTarget = await readlink(resolve(root, linkPath));
    const resolvedTarget = resolve(dirname(resolve(root, linkPath)), linkTarget);
    assertContainedPath(root, resolvedTarget, 'sanitized symbolic link target');
  }
}
