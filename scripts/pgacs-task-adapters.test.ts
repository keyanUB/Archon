import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  parseFrozenTaskManifest,
  loadFrozenTaskRegistry,
  resolveEvaluatorAdapter,
  resolveWorkspaceAdapter,
  ZIP_TASK_MANIFEST,
  ZIP_TASK_MANIFEST_SHA256,
} from './pgacs-task-adapters';
import {
  assertFreshSanitizedWorkspace,
  createSecRepoBenchTaskViews,
  materializeSecRepoBenchWorkspace,
} from './pgacs-secrepobench-materializer';
import { stableSha256 } from './pgacs-runtime-policy-state';

const BAXBENCH_REGISTRY_PATH = new URL('./baxbench/task-manifests.v0.1.json', import.meta.url)
  .pathname;

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

function cloneManifest(): unknown {
  return JSON.parse(JSON.stringify(ZIP_TASK_MANIFEST)) as unknown;
}

function secRepoBenchManifest(input: {
  evaluatorRevision: string;
  maskedFileSha256: string;
  fixingCommit?: string;
  datasetSha256?: string;
}): ReturnType<typeof parseFrozenTaskManifest> {
  const prompt = 'Complete the marked region while preserving the surrounding function contract.';
  return parseFrozenTaskManifest({
    schemaVersion: '0.3.0',
    id: 'secrepobench-910',
    revision: '0.1.0',
    taskKind: 'repository_code_modification',
    provenance: {
      sourceType: 'benchmark',
      benchmark: 'SecRepoBench',
      sourceTaskId: '910',
      datasetSha256: input.datasetSha256 ?? '1'.repeat(64),
      evaluatorRevision: input.evaluatorRevision,
      policySelectionSha256: '2'.repeat(64),
      activationRulesSha256: '3'.repeat(64),
      corpusSha256: '4'.repeat(64),
    },
    contract: {
      prompt,
      promptSha256: createHash('sha256').update(prompt).digest('hex'),
      acceptedBehavior: ['The completion compiles and preserves relevant developer tests.'],
      prohibitedContractChanges: ['Do not modify code outside the masked target file.'],
    },
    workspace: {
      adapterId: 'secrepobench-masked-repo-v0.1',
      root: 'workspace',
      implementationPath: 'src/cmsio0.c',
      auxiliaryPaths: [],
      allowedMutationPaths: ['src/cmsio0.c'],
    },
    evaluator: {
      adapterId: 'secrepobench-official-v0.1',
      sourcePath: 'oracle.py',
      sourceSha256: createHash('sha256').update('fixture').digest('hex'),
      requiredProbeIds: ['secrepobench.developer-tests', 'secrepobench.oss-fuzz-poc'],
      defenseInDepthProbeIds: [],
      idempotent: true,
      timeoutSeconds: 3600,
      secRepoBench: {
        taskId: '910',
        projectName: 'lcms',
        fixingCommit: input.fixingCommit ?? 'f9d75ccef0b54c9f4167d95088d4727985133c52',
        changedFile: 'src/cmsio0.c',
        cweId: 'CWE-122',
        crashType: 'Heap-buffer-overflow READ 4',
        completionMarker: '// <MASK>',
        maskedFileSha256: input.maskedFileSha256,
        arvoImage: 'n132/arvo:910-fix',
        baselinePassingTests: ['Base types'],
      },
    },
    obligations: [],
  });
}

async function createSecRepoBenchSourceFixture(
  root: string,
  masked: string
): Promise<{
  sourceRoot: string;
  fixingCommit: string;
  maskedTargetPath: string;
}> {
  const sourceRoot = join(root, 'source');
  await run(['git', 'init', '-q', sourceRoot], root);
  await mkdir(join(sourceRoot, 'src'), { recursive: true });
  await mkdir(join(sourceRoot, 'include'), { recursive: true });
  await mkdir(join(sourceRoot, 'generated'), { recursive: true });
  await writeFile(join(sourceRoot, 'src/cmsio0.c'), 'int parse(void) { return 1; }\n', 'utf8');
  await writeFile(join(sourceRoot, 'include/api.h'), 'int parse(void);\n', 'utf8');
  await writeFile(join(sourceRoot, '.gitignore'), 'generated/\n', 'utf8');
  await writeFile(join(sourceRoot, 'generated/tracked.dat'), 'tracked upstream\n', 'utf8');
  await run(['git', '-C', sourceRoot, 'add', 'src/cmsio0.c', 'include/api.h', '.gitignore'], root);
  await run(['git', '-C', sourceRoot, 'add', '--force', 'generated/tracked.dat'], root);
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
      'secure fixture',
    ],
    root
  );
  const fixingCommit = await run(['git', '-C', sourceRoot, 'rev-parse', 'HEAD'], root);
  const maskedTargetPath = join(root, 'mask_desc_perturbed.c');
  await writeFile(maskedTargetPath, masked, 'utf8');
  await mkdir(join(sourceRoot, '.pgacs'), { recursive: true });
  await writeFile(join(sourceRoot, '.pgacs/developer-fix.patch'), 'hidden fix\n', 'utf8');
  await mkdir(join(sourceRoot, '__pycache__'), { recursive: true });
  await writeFile(join(sourceRoot, '__pycache__/oracle.pyc'), 'hidden evaluator cache\n', 'utf8');
  return { sourceRoot, fixingCommit, maskedTargetPath };
}

describe('frozen task manifest', (): void => {
  test('loads the source-pinned ZIP contract and adapter boundaries', (): void => {
    expect(ZIP_TASK_MANIFEST).toMatchObject({
      id: 'file-parser-untrusted-archive',
      workspace: {
        adapterId: 'local-fixture-v0.1',
        implementationPath: '.pgacs-c2/zip/zip_inspector.py',
      },
      evaluator: {
        adapterId: 'python-json-v0.1',
        idempotent: true,
      },
    });
    expect(ZIP_TASK_MANIFEST_SHA256).toMatch(/^[a-f0-9]{64}$/);
    expect(ZIP_TASK_MANIFEST.obligations).toHaveLength(3);
  });

  test('rejects prompt and workspace-boundary drift', (): void => {
    const promptDrift = cloneManifest() as {
      contract: { prompt: string };
    };
    promptDrift.contract.prompt += ' changed';
    expect(() => parseFrozenTaskManifest(promptDrift)).toThrow(
      'promptSha256 does not match prompt'
    );

    const pathDrift = cloneManifest() as {
      workspace: { implementationPath: string };
    };
    pathDrift.workspace.implementationPath = '../outside.py';
    expect(() => parseFrozenTaskManifest(pathDrift)).toThrow(
      'must be a repository-relative path without traversal'
    );

    for (const unsafePath of ['..\\outside.py', 'C:\\outside.py']) {
      const platformDrift = cloneManifest() as {
        workspace: { implementationPath: string };
      };
      platformDrift.workspace.implementationPath = unsafePath;
      expect(() => parseFrozenTaskManifest(platformDrift)).toThrow(
        'must be a repository-relative path without traversal'
      );
    }
  });
});

describe('task adapters', (): void => {
  test('prepares the local fixture and emits a manifest-bound receipt', async (): Promise<void> => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), 'pgacs-task-adapter-'));
    const adapter = resolveWorkspaceAdapter(ZIP_TASK_MANIFEST);
    const receipt = await adapter.prepare(ZIP_TASK_MANIFEST, repositoryRoot);

    expect(receipt).toMatchObject({
      adapterId: 'local-fixture-v0.1',
      taskId: ZIP_TASK_MANIFEST.id,
      manifestSha256: ZIP_TASK_MANIFEST_SHA256,
      workspaceCreated: true,
    });
    expect((await stat(join(repositoryRoot, ZIP_TASK_MANIFEST.workspace.root))).isDirectory()).toBe(
      true
    );
  });

  test('builds evaluator invocation without executing candidate code', async (): Promise<void> => {
    const adapter = resolveEvaluatorAdapter(ZIP_TASK_MANIFEST);
    const outputRoot = await mkdtemp(join(tmpdir(), 'pgacs-zip-evaluator-'));
    const staleResult = join(outputRoot, 'evaluation.json');
    await writeFile(staleResult, '{"stale":true}\n', 'utf8');
    const invocation = await adapter.prepareInvocation({
      manifest: ZIP_TASK_MANIFEST,
      repositoryRoot: '/repo',
      frozenEvaluatorPath: '/artifacts/evaluator.py',
      candidatePath: '/artifacts/candidate.py',
      outputRoot,
    });

    expect(invocation).toEqual({
      adapterId: 'python-json-v0.1',
      command: ['python3', '/artifacts/evaluator.py', '/artifacts/candidate.py', staleResult],
      cwd: '/repo',
      resultPath: staleResult,
      timeoutSeconds: 30,
      idempotent: true,
    });
    await expect(stat(staleResult)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('BaxBench task adapters', (): void => {
  test('loads three source-pinned public task contracts without evaluator-only fields', (): void => {
    const registry = loadFrozenTaskRegistry(BAXBENCH_REGISTRY_PATH);
    expect(registry.tasks.map(task => task.provenance?.sourceTaskId)).toEqual([
      'Login-Python-FastAPI',
      'RegexSearch-Python-FastAPI',
      'ZipToTxt-Python-FastAPI',
    ]);
    expect(registry.tasks.map(task => task.contract.promptSha256)).toEqual([
      'a9f1a60302f77362919372d4e3f0aaf3a10ac5a616cf6b583e14ad192c28f4c3',
      'e654ff23dd2e30706efac81786933e66af5d19df4bcda971eeb837171bd13aa6',
      '466bf36260c6ebaf8241075cd596ed9a7312c71583fe4129974cea4a712a1e67',
    ]);
    const serialized = JSON.stringify(registry);
    expect(serialized).not.toContain('functional_tests');
    expect(serialized).not.toContain('security_tests');
    expect(serialized).not.toContain('exploits');
  });

  test('prepares the BaxBench workspace from the frozen prompt', async (): Promise<void> => {
    const manifest = loadFrozenTaskRegistry(BAXBENCH_REGISTRY_PATH).tasks[0];
    if (!manifest) throw new Error('Missing BaxBench task manifest');
    const sampleRoot = await mkdtemp(join(tmpdir(), 'pgacs-bax-workspace-'));
    const receipt = await resolveWorkspaceAdapter(manifest).prepare(manifest, sampleRoot);

    expect(receipt.adapterId).toBe('baxbench-fastapi-v0.1');
    expect(receipt.allowedMutationPaths).toEqual(['workspace/app.py']);
    expect(await readFile(join(sampleRoot, 'workspace/TASK.md'), 'utf8')).toBe(
      manifest.contract.prompt
    );
    expect((await stat(join(sampleRoot, 'workspace/.git'))).isDirectory()).toBe(true);
  });

  test('rejects a workspace symlink that escapes the sample root', async (): Promise<void> => {
    const manifest = loadFrozenTaskRegistry(BAXBENCH_REGISTRY_PATH).tasks[0];
    if (!manifest) throw new Error('Missing BaxBench task manifest');
    const sampleRoot = await mkdtemp(join(tmpdir(), 'pgacs-bax-boundary-'));
    const outside = await mkdtemp(join(tmpdir(), 'pgacs-bax-outside-'));
    await symlink(outside, join(sampleRoot, 'workspace'));

    await expect(resolveWorkspaceAdapter(manifest).prepare(manifest, sampleRoot)).rejects.toThrow(
      'workspace resolves outside its repository root'
    );
  });

  test('rejects a symlinked Git control directory', async (): Promise<void> => {
    const manifest = loadFrozenTaskRegistry(BAXBENCH_REGISTRY_PATH).tasks[0];
    if (!manifest) throw new Error('Missing BaxBench task manifest');
    const sampleRoot = await mkdtemp(join(tmpdir(), 'pgacs-bax-git-boundary-'));
    const workspace = join(sampleRoot, 'workspace');
    const outside = await mkdtemp(join(tmpdir(), 'pgacs-bax-git-outside-'));
    await mkdir(workspace);
    await symlink(outside, join(workspace, '.git'));

    await expect(resolveWorkspaceAdapter(manifest).prepare(manifest, sampleRoot)).rejects.toThrow(
      'workspace .git must be a regular directory'
    );
  });

  test('stages only app.py and preserves official evaluator coordinates', async (): Promise<void> => {
    const source = loadFrozenTaskRegistry(BAXBENCH_REGISTRY_PATH).tasks[1];
    if (!source?.provenance) throw new Error('Missing BaxBench task manifest');
    const root = await mkdtemp(join(tmpdir(), 'pgacs-bax-evaluator-'));
    const evaluatorRoot = join(root, 'evaluator');
    const candidateRoot = join(root, 'candidate');
    const resultsRoot = join(root, 'results');
    await run(['git', 'init', '-q', evaluatorRoot], root);
    await mkdir(join(evaluatorRoot, '.venv/bin'), { recursive: true });
    await mkdir(join(evaluatorRoot, 'src'), { recursive: true });
    await writeFile(join(evaluatorRoot, '.venv/bin/python'), 'fixture', 'utf8');
    await chmod(join(evaluatorRoot, '.venv/bin/python'), 0o755);
    await writeFile(join(evaluatorRoot, 'src/main.py'), 'fixture', 'utf8');
    await writeFile(join(evaluatorRoot, 'README'), 'fixture', 'utf8');
    await run(['git', '-C', evaluatorRoot, 'add', 'README'], root);
    await run(
      [
        'git',
        '-C',
        evaluatorRoot,
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
    const revision = await run(['git', '-C', evaluatorRoot, 'rev-parse', 'HEAD'], root);
    await mkdir(candidateRoot, { recursive: true });
    await writeFile(join(candidateRoot, 'app.py'), 'print("candidate")\n', 'utf8');
    await writeFile(join(candidateRoot, 'hidden-test.py'), 'secret\n', 'utf8');
    const manifest = {
      ...source,
      provenance: { ...source.provenance, evaluatorRevision: revision },
    };
    const staleResult = join(
      resultsRoot,
      'pgacs-adapter-test/RegexSearch/Python-FastAPI/temp0.2-openapi-none/sample0/test_results.json'
    );
    await mkdir(dirname(staleResult), { recursive: true });
    await writeFile(staleResult, '{"stale":true}\n', 'utf8');

    const invocation = await resolveEvaluatorAdapter(manifest).prepareInvocation({
      manifest,
      repositoryRoot: root,
      frozenEvaluatorPath: evaluatorRoot,
      candidatePath: candidateRoot,
      outputRoot: resultsRoot,
      evaluationLabel: 'pgacs-adapter-test',
    });

    expect(invocation.command).toContain('RegexSearch');
    expect(invocation.command).toContain('Python-FastAPI');
    expect(invocation.resultPath).toEndWith(
      'pgacs-adapter-test/RegexSearch/Python-FastAPI/temp0.2-openapi-none/sample0/test_results.json'
    );
    expect(await readFile(invocation.preparation?.stagedPath ?? '', 'utf8')).toBe(
      'print("candidate")\n'
    );
    expect(invocation.preparation?.candidateSha256).toMatch(/^[a-f0-9]{64}$/);
    await expect(stat(staleResult)).rejects.toMatchObject({ code: 'ENOENT' });

    await writeFile(join(evaluatorRoot, 'README'), 'modified', 'utf8');
    await expect(
      resolveEvaluatorAdapter(manifest).prepareInvocation({
        manifest,
        repositoryRoot: root,
        frozenEvaluatorPath: evaluatorRoot,
        candidatePath: candidateRoot,
        outputRoot: resultsRoot,
        evaluationLabel: 'pgacs-adapter-test',
      })
    ).rejects.toThrow('modified tracked files');

    await writeFile(join(evaluatorRoot, 'README'), 'fixture', 'utf8');
    await rm(join(candidateRoot, 'app.py'));
    await symlink(join(candidateRoot, 'hidden-test.py'), join(candidateRoot, 'app.py'));
    await expect(
      resolveEvaluatorAdapter(manifest).prepareInvocation({
        manifest,
        repositoryRoot: root,
        frozenEvaluatorPath: evaluatorRoot,
        candidatePath: candidateRoot,
        outputRoot: resultsRoot,
        evaluationLabel: 'pgacs-adapter-test',
      })
    ).rejects.toThrow('regular, non-symlinked file');
  });
});

describe('SecRepoBench task adapters', (): void => {
  test('binds the task, CWE, changed file, and ARVO image consistently', (): void => {
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      maskedFileSha256: 'b'.repeat(64),
    });
    expect(manifest.evaluator.secRepoBench).toMatchObject({
      taskId: '910',
      cweId: 'CWE-122',
      changedFile: 'src/cmsio0.c',
      arvoImage: 'n132/arvo:910-fix',
    });

    const drifted = JSON.parse(JSON.stringify(manifest)) as {
      evaluator: { secRepoBench: { arvoImage: string } };
    };
    drifted.evaluator.secRepoBench.arvoImage = 'n132/arvo:other-fix';
    expect(() => parseFrozenTaskManifest(drifted)).toThrow(
      'arvoImage must bind the task-specific fixed image'
    );
  });

  test('admits only the exact one-marker masked repository target', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-workspace-'));
    const targetPath = join(root, 'workspace/src/cmsio0.c');
    const masked = 'int parse(void) {\n  // <MASK>\n}\n';
    await mkdir(dirname(targetPath), { recursive: true });
    await writeFile(targetPath, masked, 'utf8');
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
    });

    const receipt = await resolveWorkspaceAdapter(manifest).prepare(manifest, root);
    expect(receipt).toMatchObject({
      adapterId: 'secrepobench-masked-repo-v0.1',
      workspaceCreated: false,
      implementationPath: 'src/cmsio0.c',
    });

    await writeFile(targetPath, masked.replace('// <MASK>', '// changed'), 'utf8');
    await expect(resolveWorkspaceAdapter(manifest).prepare(manifest, root)).rejects.toThrow(
      'masked target digest does not match'
    );
  });

  test('materializes a history-free tracked tree and structurally redacted task view', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-materializer-'));
    const repositoryRoot = join(root, 'run');
    const masked = 'int parse(void) {\n  // <MASK>\n}\n';
    const source = await createSecRepoBenchSourceFixture(root, masked);
    await mkdir(repositoryRoot);
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
    });

    const receipt = await materializeSecRepoBenchWorkspace({
      manifest,
      sourceRepositoryRoot: source.sourceRoot,
      maskedTargetPath: source.maskedTargetPath,
      repositoryRoot,
    });
    const workspaceRoot = join(repositoryRoot, 'workspace');
    await assertFreshSanitizedWorkspace(workspaceRoot);
    expect(await readFile(join(workspaceRoot, 'src/cmsio0.c'), 'utf8')).toBe(masked);
    expect(await readFile(join(workspaceRoot, 'include/api.h'), 'utf8')).toBe('int parse(void);\n');
    expect(await readFile(join(workspaceRoot, 'generated/tracked.dat'), 'utf8')).toBe(
      'tracked upstream\n'
    );
    await expect(stat(join(workspaceRoot, '.pgacs/developer-fix.patch'))).rejects.toThrow();
    await expect(stat(join(workspaceRoot, '__pycache__/oracle.pyc'))).rejects.toThrow();
    expect(receipt).toMatchObject({
      sourceRevision: source.fixingCommit,
      trackedPathCount: 4,
      omittedUntrackedPathCount: 2,
      workspaceRoot: 'workspace',
      targetPath: 'src/cmsio0.c',
    });
    expect(receipt.baselineCommit).toMatch(/^[a-f0-9]{40}$/);
    expect(receipt.sanitizedTreeSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(receipt.protectedTreeSha256).toMatch(/^[a-f0-9]{64}$/);

    const views = createSecRepoBenchTaskViews(manifest, receipt);
    const generationJson = JSON.stringify(views.generation);
    expect(generationJson).not.toContain('evaluator');
    expect(generationJson).not.toContain('CWE-122');
    expect(generationJson).not.toContain('Heap-buffer-overflow');
    expect(generationJson).not.toContain(source.fixingCommit);
    expect(generationJson).not.toContain('n132/arvo:910-fix');
    expect(views.generation.workspace.sanitizedTreeSha256).toBe(receipt.sanitizedTreeSha256);
    expect(views.evaluator.evaluator.secRepoBench).toMatchObject({
      cweId: 'CWE-122',
      fixingCommit: source.fixingCommit,
      arvoImage: 'n132/arvo:910-fix',
    });
  });

  test('replays materialization deterministically from the same frozen source', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-replay-'));
    const masked = 'int parse(void) {\n  // <MASK>\n}\n';
    const source = await createSecRepoBenchSourceFixture(root, masked);
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
    });
    const firstRoot = join(root, 'first');
    const secondRoot = join(root, 'second');
    await mkdir(firstRoot);
    await mkdir(secondRoot);

    const first = await materializeSecRepoBenchWorkspace({
      manifest,
      sourceRepositoryRoot: source.sourceRoot,
      maskedTargetPath: source.maskedTargetPath,
      repositoryRoot: firstRoot,
    });
    const second = await materializeSecRepoBenchWorkspace({
      manifest,
      sourceRepositoryRoot: source.sourceRoot,
      maskedTargetPath: source.maskedTargetPath,
      repositoryRoot: secondRoot,
    });

    expect(second).toEqual(first);
  });

  test('rejects tracked source drift even when HEAD still matches the frozen revision', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-source-drift-'));
    const masked = 'int parse(void) {\n  // <MASK>\n}\n';
    const source = await createSecRepoBenchSourceFixture(root, masked);
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
    });
    await writeFile(join(source.sourceRoot, 'include/api.h'), 'int parse(int value);\n', 'utf8');
    await run(['git', '-C', source.sourceRoot, 'add', 'include/api.h'], root);
    const repositoryRoot = join(root, 'run');
    await mkdir(repositoryRoot);

    await expect(
      materializeSecRepoBenchWorkspace({
        manifest,
        sourceRepositoryRoot: source.sourceRoot,
        maskedTargetPath: source.maskedTargetPath,
        repositoryRoot,
      })
    ).rejects.toThrow('tracked state must exactly match the frozen commit');
  });

  test('writes generation and evaluator views to a control directory through the CLI', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-cli-'));
    const masked = 'int parse(void) {\n  // <MASK>\n}\n';
    const source = await createSecRepoBenchSourceFixture(root, masked);
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(masked).digest('hex'),
    });
    const registryPath = join(root, 'registry.json');
    const repositoryRoot = join(root, 'run');
    const controlRoot = join(repositoryRoot, 'control');
    await mkdir(repositoryRoot);
    await writeFile(
      registryPath,
      `${JSON.stringify({
        schemaVersion: '0.1.0',
        sourceManifest: 'fixture',
        generator: 'test',
        tasks: [manifest],
      })}\n`,
      'utf8'
    );

    const stdout = await run(
      [
        'bun',
        join(import.meta.dir, 'pgacs-task-adapter-cli.ts'),
        'materialize',
        registryPath,
        manifest.id,
        source.sourceRoot,
        source.maskedTargetPath,
        repositoryRoot,
        controlRoot,
      ],
      root
    );
    const output = JSON.parse(stdout) as {
      generationTaskPath: string;
      evaluatorTaskPath: string;
      receiptPath: string;
    };
    const generation = JSON.parse(await readFile(output.generationTaskPath, 'utf8')) as Record<
      string,
      unknown
    >;
    const evaluator = JSON.parse(await readFile(output.evaluatorTaskPath, 'utf8')) as {
      evaluator: { secRepoBench: { cweId: string } };
    };
    expect(generation.evaluator).toBeUndefined();
    expect(JSON.stringify(generation)).not.toContain('CWE-122');
    expect(evaluator.evaluator.secRepoBench.cweId).toBe('CWE-122');
    expect((await stat(output.receiptPath)).isFile()).toBe(true);
    await assertFreshSanitizedWorkspace(join(repositoryRoot, 'workspace'));
  });

  test('fails closed on ambiguous masks, source drift, and existing destinations', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-fail-closed-'));
    const ambiguous = 'int parse(void) { // <MASK>\n// <MASK>\n}\n';
    const source = await createSecRepoBenchSourceFixture(root, ambiguous);
    const manifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(ambiguous).digest('hex'),
    });
    const repositoryRoot = join(root, 'run');
    await mkdir(repositoryRoot);
    await expect(
      materializeSecRepoBenchWorkspace({
        manifest,
        sourceRepositoryRoot: source.sourceRoot,
        maskedTargetPath: source.maskedTargetPath,
        repositoryRoot,
      })
    ).rejects.toThrow('exactly one completion marker');

    const validMasked = 'int parse(void) {\n  // <MASK>\n}\n';
    await writeFile(source.maskedTargetPath, validMasked, 'utf8');
    const driftedManifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: 'f'.repeat(40),
      maskedFileSha256: createHash('sha256').update(validMasked).digest('hex'),
    });
    await expect(
      materializeSecRepoBenchWorkspace({
        manifest: driftedManifest,
        sourceRepositoryRoot: source.sourceRoot,
        maskedTargetPath: source.maskedTargetPath,
        repositoryRoot,
      })
    ).rejects.toThrow('source revision mismatch');

    const validManifest = secRepoBenchManifest({
      evaluatorRevision: 'a'.repeat(40),
      fixingCommit: source.fixingCommit,
      maskedFileSha256: createHash('sha256').update(validMasked).digest('hex'),
    });
    await mkdir(join(repositoryRoot, 'workspace'));
    await expect(
      materializeSecRepoBenchWorkspace({
        manifest: validManifest,
        sourceRepositoryRoot: source.sourceRoot,
        maskedTargetPath: source.maskedTargetPath,
        repositoryRoot,
      })
    ).rejects.toThrow('workspace already exists');
  });

  test('emits a revision-bound single-task evaluator request', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-evaluator-'));
    const evaluatorRoot = join(root, 'evaluator');
    const candidateRoot = join(root, 'candidate');
    const outputRoot = join(root, 'results');
    const surfaceFiles = [
      { path: 'sample_metadata.json', content: '{}' },
      { path: 'assets/projects.py', content: 'commands = {}\n' },
      { path: 'descriptions/910/desc.txt', content: 'Read one tag.\n' },
      { path: 'descriptions/910/mask_base.c', content: 'void read(void) { // <MASK> }\n' },
      { path: 'report.json.gz', content: 'frozen baseline report' },
    ];
    for (const file of surfaceFiles) {
      await mkdir(dirname(join(evaluatorRoot, file.path)), { recursive: true });
      await writeFile(join(evaluatorRoot, file.path), file.content, 'utf8');
    }
    const datasetSha256 = stableSha256(
      surfaceFiles.map(file => ({
        path: file.path,
        sha256: createHash('sha256').update(file.content).digest('hex'),
      }))
    );
    const revision = 'a'.repeat(40);
    await writeFile(join(root, 'oracle.py'), 'fixture', 'utf8');
    await mkdir(candidateRoot);
    await writeFile(join(candidateRoot, 'cmsio0.c'), 'int parse(void) { return 1; }\n', 'utf8');
    const manifest = secRepoBenchManifest({
      evaluatorRevision: revision,
      maskedFileSha256: 'b'.repeat(64),
      datasetSha256,
    });

    const invocation = await resolveEvaluatorAdapter(manifest).prepareInvocation({
      manifest,
      repositoryRoot: root,
      frozenEvaluatorPath: evaluatorRoot,
      candidatePath: candidateRoot,
      outputRoot,
    });
    const request = JSON.parse(await readFile(join(outputRoot, 'request.json'), 'utf8')) as {
      taskId: string;
      candidateSha256: string;
      changedFile: string;
      cweId: string;
      baselinePassingTests: string[];
    };
    expect(request).toMatchObject({
      taskId: '910',
      changedFile: 'src/cmsio0.c',
      cweId: 'CWE-122',
      baselinePassingTests: ['Base types'],
    });
    expect(request.candidateSha256).toMatch(/^[a-f0-9]{64}$/);
    const pythonPath = Bun.which('python3');
    expect(pythonPath).not.toBeNull();
    expect(invocation.command).toEqual([
      pythonPath as string,
      join(root, 'oracle.py'),
      join(outputRoot, 'request.json'),
    ]);
    expect(invocation.resultPath).toBe(join(outputRoot, 'evaluation.json'));

    const outsideCandidate = await mkdtemp(join(tmpdir(), 'pgacs-srb-outside-'));
    await writeFile(join(outsideCandidate, 'cmsio0.c'), 'outside\n', 'utf8');
    await expect(
      resolveEvaluatorAdapter(manifest).prepareInvocation({
        manifest,
        repositoryRoot: root,
        frozenEvaluatorPath: evaluatorRoot,
        candidatePath: outsideCandidate,
        outputRoot,
      })
    ).rejects.toThrow('candidate resolves outside its repository root');

    await writeFile(join(root, 'oracle.py'), 'modified fixture', 'utf8');
    await expect(
      resolveEvaluatorAdapter(manifest).prepareInvocation({
        manifest,
        repositoryRoot: root,
        frozenEvaluatorPath: evaluatorRoot,
        candidatePath: candidateRoot,
        outputRoot,
      })
    ).rejects.toThrow('oracle wrapper digest does not match the manifest');
  });
});
