import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  assertSecRepoBenchCandidateLineage,
  extractSecRepoBenchCandidate,
  type SecRepoBenchCandidate,
} from './pgacs-secrepobench-candidate';
import {
  materializeSecRepoBenchWorkspace,
  type SecRepoBenchMaterializationReceipt,
} from './pgacs-secrepobench-materializer';
import { parseFrozenTaskManifest, type FrozenTaskManifest } from './pgacs-task-adapters';

async function run(command: string[], cwd: string): Promise<string> {
  const subprocess = Bun.spawn(command, { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(stderr);
  return stdout.trim();
}

interface CandidateFixture {
  root: string;
  workspaceRoot: string;
  targetPath: string;
  manifest: FrozenTaskManifest;
  receipt: SecRepoBenchMaterializationReceipt;
}

async function createFixture(): Promise<CandidateFixture> {
  const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-candidate-'));
  const sourceRoot = join(root, 'source');
  const repositoryRoot = join(root, 'run');
  const maskedTargetPath = join(root, 'mask.c');
  const masked = 'int parse(int value) {\n  // <MASK>\n}\n';
  await run(['git', 'init', '-q', sourceRoot], root);
  await mkdir(join(sourceRoot, 'src'), { recursive: true });
  await mkdir(join(sourceRoot, 'include'), { recursive: true });
  await writeFile(join(sourceRoot, 'src/parse.c'), 'int parse(int value) { return value; }\n');
  await writeFile(join(sourceRoot, 'include/parse.h'), 'int parse(int value);\n');
  await run(['git', '-C', sourceRoot, 'add', '--all'], root);
  await run(
    [
      'git',
      '-C',
      sourceRoot,
      '-c',
      'user.name=PGACS Test',
      '-c',
      'user.email=pgacs@example.invalid',
      'commit',
      '-q',
      '-m',
      'fixture',
    ],
    root
  );
  const fixingCommit = await run(['git', '-C', sourceRoot, 'rev-parse', 'HEAD'], root);
  await writeFile(maskedTargetPath, masked);
  await mkdir(repositoryRoot);
  const prompt = 'Complete the marked region without changing repository interfaces.';
  const manifest = parseFrozenTaskManifest({
    schemaVersion: '0.3.0',
    id: 'secrepobench-fixture',
    revision: '0.1.0',
    taskKind: 'repository_code_modification',
    provenance: {
      sourceType: 'benchmark',
      benchmark: 'SecRepoBench',
      sourceTaskId: 'fixture',
      datasetSha256: '1'.repeat(64),
      evaluatorRevision: 'a'.repeat(40),
      policySelectionSha256: '2'.repeat(64),
      activationRulesSha256: '3'.repeat(64),
      corpusSha256: '4'.repeat(64),
    },
    contract: {
      prompt,
      promptSha256: createHash('sha256').update(prompt).digest('hex'),
      acceptedBehavior: ['Return the input value.'],
      prohibitedContractChanges: ['Do not change the public signature.'],
    },
    workspace: {
      adapterId: 'secrepobench-masked-repo-v0.1',
      root: 'workspace',
      implementationPath: 'src/parse.c',
      auxiliaryPaths: [],
      allowedMutationPaths: ['src/parse.c'],
    },
    evaluator: {
      adapterId: 'secrepobench-official-v0.1',
      sourcePath: 'scripts/secrepobench/pgacs_secrepobench_oracle.py',
      sourceSha256: '5'.repeat(64),
      requiredProbeIds: ['repository.compile', 'repository.oss-fuzz-poc'],
      defenseInDepthProbeIds: [],
      idempotent: true,
      timeoutSeconds: 300,
      secRepoBench: {
        taskId: 'fixture',
        projectName: 'fixture',
        fixingCommit,
        changedFile: 'src/parse.c',
        cweId: 'CWE-129',
        crashType: 'fixture-crash',
        completionMarker: '// <MASK>',
        maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
        arvoImage: 'n132/arvo:fixture-fix',
        baselinePassingTests: ['fixture-test'],
      },
    },
    obligations: [],
  });
  const receipt = await materializeSecRepoBenchWorkspace({
    manifest,
    sourceRepositoryRoot: sourceRoot,
    maskedTargetPath,
    repositoryRoot,
  });
  const workspaceRoot = join(repositoryRoot, 'workspace');
  return {
    root,
    workspaceRoot,
    targetPath: join(workspaceRoot, 'src/parse.c'),
    manifest,
    receipt,
  };
}

async function extract(
  fixture: CandidateFixture,
  input?: { attemptId?: string; parentCandidateSha256?: string }
): Promise<SecRepoBenchCandidate> {
  return extractSecRepoBenchCandidate({
    manifest: fixture.manifest,
    materialization: fixture.receipt,
    workspaceRoot: fixture.workspaceRoot,
    attemptId: input?.attemptId ?? 'initial',
    parentCandidateSha256: input?.parentCandidateSha256,
  });
}

describe('SecRepoBench candidate integrity', (): void => {
  test('extracts a deterministic replacement and normalized patch', async (): Promise<void> => {
    const fixture = await createFixture();
    await writeFile(fixture.targetPath, 'int parse(int value) {\n  return value;\n}\n');

    const candidate = await extract(fixture);
    expect(candidate).toMatchObject({
      taskId: fixture.manifest.id,
      attemptId: 'initial',
      targetPath: 'src/parse.c',
      replacementText: 'return value;',
      changedTrackedPaths: ['src/parse.c'],
      untrackedPaths: [],
      protectedTreeSha256: fixture.receipt.protectedTreeSha256,
      scopeProof: 'byte-bound-prefix-suffix-v0.1',
    });
    expect(candidate.normalizedPatch).toContain('-  // <MASK>');
    expect(candidate.normalizedPatch).toContain('+  return value;');
    expect(candidate.candidateSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  test('rejects prefix, protected-file, and untracked mutations', async (): Promise<void> => {
    const prefixFixture = await createFixture();
    await writeFile(
      prefixFixture.targetPath,
      'static int parse(int value) {\n  return value;\n}\n'
    );
    await expect(extract(prefixFixture)).rejects.toThrow('before the completion region');

    const protectedFixture = await createFixture();
    await writeFile(protectedFixture.targetPath, 'int parse(int value) {\n  return value;\n}\n');
    await writeFile(join(protectedFixture.workspaceRoot, 'include/parse.h'), 'changed\n');
    await expect(extract(protectedFixture)).rejects.toThrow('must change only src/parse.c');

    const untrackedFixture = await createFixture();
    await writeFile(untrackedFixture.targetPath, 'int parse(int value) {\n  return value;\n}\n');
    await writeFile(join(untrackedFixture.workspaceRoot, 'bypass.txt'), 'bypass\n');
    await expect(extract(untrackedFixture)).rejects.toThrow('contains untracked paths');
  });

  test('binds repair candidates into a cumulative lineage', async (): Promise<void> => {
    const fixture = await createFixture();
    await writeFile(fixture.targetPath, 'int parse(int value) {\n  return value + 1;\n}\n');
    const initial = await extract(fixture);
    await writeFile(fixture.targetPath, 'int parse(int value) {\n  return value;\n}\n');
    const repair = await extract(fixture, {
      attemptId: 'repair-1',
      parentCandidateSha256: initial.candidateSha256,
    });

    expect(() => assertSecRepoBenchCandidateLineage([initial, repair])).not.toThrow();
    expect(() =>
      assertSecRepoBenchCandidateLineage([
        initial,
        { ...repair, parentCandidateSha256: '0'.repeat(64) },
      ])
    ).toThrow('parent mismatch');
    expect(await readFile(fixture.targetPath, 'utf8')).toContain('return value;');
  });
});
