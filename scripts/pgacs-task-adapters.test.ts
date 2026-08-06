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
      datasetSha256: '1'.repeat(64),
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
      requiredProbeIds: ['secrepobench.developer-tests', 'secrepobench.oss-fuzz-poc'],
      defenseInDepthProbeIds: [],
      idempotent: true,
      timeoutSeconds: 3600,
      secRepoBench: {
        taskId: '910',
        projectName: 'lcms',
        fixingCommit: 'f9d75ccef0b54c9f4167d95088d4727985133c52',
        changedFile: 'src/cmsio0.c',
        cweId: 'CWE-122',
        crashType: 'Heap-buffer-overflow READ 4',
        completionMarker: '// <MASK>',
        maskedFileSha256: input.maskedFileSha256,
        arvoImage: 'n132/arvo:910-fix',
      },
    },
    obligations: [],
  });
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

  test('emits a revision-bound single-task evaluator request', async (): Promise<void> => {
    const root = await mkdtemp(join(tmpdir(), 'pgacs-srb-evaluator-'));
    const evaluatorRoot = join(root, 'evaluator');
    const candidateRoot = join(root, 'candidate');
    const outputRoot = join(root, 'results');
    await run(['git', 'init', '-q', evaluatorRoot], root);
    await mkdir(join(evaluatorRoot, '.venv/bin'), { recursive: true });
    await writeFile(join(evaluatorRoot, '.venv/bin/python'), 'fixture', 'utf8');
    await chmod(join(evaluatorRoot, '.venv/bin/python'), 0o755);
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
    await writeFile(join(root, 'oracle.py'), 'fixture', 'utf8');
    await mkdir(candidateRoot);
    await writeFile(join(candidateRoot, 'cmsio0.c'), 'int parse(void) { return 1; }\n', 'utf8');
    const manifest = secRepoBenchManifest({
      evaluatorRevision: revision,
      maskedFileSha256: 'b'.repeat(64),
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
    };
    expect(request).toMatchObject({
      taskId: '910',
      changedFile: 'src/cmsio0.c',
      cweId: 'CWE-122',
    });
    expect(request.candidateSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(invocation.command).toEqual([
      join(evaluatorRoot, '.venv/bin/python'),
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
  });
});
