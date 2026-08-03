import { describe, expect, test } from 'bun:test';
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
