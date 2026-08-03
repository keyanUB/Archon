import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { SelectedPolicyObligation } from './pgacs-policy-activation';
import { stableSha256 } from './pgacs-runtime-policy-state';

type JsonObject = Record<string, unknown>;

export interface FrozenTaskManifest {
  schemaVersion: '0.1.0' | '0.2.0';
  id: string;
  revision: string;
  taskKind: 'repository_code_generation' | 'repository_code_modification';
  provenance?: {
    sourceType: 'benchmark';
    benchmark: string;
    sourceTaskId: string;
    datasetSha256: string;
    evaluatorRevision: string;
    policySelectionSha256: string;
    activationRulesSha256: string;
    corpusSha256: string;
  };
  contract: {
    prompt: string;
    promptSha256: string;
    acceptedBehavior: string[];
    prohibitedContractChanges: string[];
  };
  workspace: {
    adapterId: string;
    root: string;
    implementationPath: string;
    auxiliaryPaths: string[];
    allowedMutationPaths: string[];
  };
  evaluator: {
    adapterId: string;
    sourcePath: string;
    requiredProbeIds: string[];
    defenseInDepthProbeIds: string[];
    idempotent: boolean;
    timeoutSeconds: number;
    native?: {
      scenarioId: string;
      environmentId: string;
      specType: string;
      safetyPrompt: string;
      temperature: number;
      sampleId: string;
      outputVariant: string;
    };
  };
  obligations: SelectedPolicyObligation[];
}

export interface WorkspacePreparationReceipt {
  adapterId: string;
  taskId: string;
  taskRevision: string;
  manifestSha256: string;
  workspaceRoot: string;
  workspaceCreated: boolean;
  implementationPath: string;
  auxiliaryPaths: string[];
  allowedMutationPaths: string[];
}

export interface TaskWorkspaceAdapter {
  readonly id: string;
  prepare(
    manifest: FrozenTaskManifest,
    repositoryRoot: string
  ): Promise<WorkspacePreparationReceipt>;
}

export interface EvaluatorInvocation {
  adapterId: string;
  command: string[];
  cwd: string;
  resultPath: string;
  timeoutSeconds: number;
  idempotent: boolean;
  preparation?: {
    candidateSha256: string;
    stagedPath: string;
    evaluatorRevision: string;
  };
}

export interface EvaluatorAdapter {
  readonly id: string;
  prepareInvocation(input: {
    manifest: FrozenTaskManifest;
    repositoryRoot: string;
    frozenEvaluatorPath: string;
    candidatePath: string;
    outputRoot: string;
    evaluationLabel?: string;
  }): Promise<EvaluatorInvocation>;
}

export interface FrozenTaskRegistry {
  schemaVersion: '0.1.0';
  sourceManifest: string;
  generator: string;
  tasks: FrozenTaskManifest[];
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireObject(value: unknown, label: string): JsonObject {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(object: JsonObject, key: string, label: string): string {
  const value = object[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(object: JsonObject, key: string, label: string): string[] {
  const value = object[key];
  if (
    !Array.isArray(value) ||
    value.some((item: unknown): boolean => typeof item !== 'string' || item.length === 0)
  ) {
    throw new Error(`${label}.${key} must be an array of non-empty strings`);
  }
  return value as string[];
}

function requireRelativePath(path: string, label: string): string {
  const normalized = path.replaceAll('\\', '/');
  if (
    normalized.includes('\0') ||
    normalized.startsWith('/') ||
    /^[A-Za-z]:/.test(normalized) ||
    normalized.split('/').includes('..')
  ) {
    throw new Error(`${label} must be a repository-relative path without traversal`);
  }
  return normalized;
}

function requirePathSegment(value: string, label: string): string {
  if (value === '.' || value === '..' || value.includes('/') || value.includes('\\')) {
    throw new Error(`${label} must be one path segment`);
  }
  return value;
}

async function requireContainedDirectory(
  repositoryRoot: string,
  directory: string,
  label: string
): Promise<void> {
  const [canonicalRoot, canonicalDirectory] = await Promise.all([
    realpath(repositoryRoot),
    realpath(directory),
  ]);
  const pathFromRoot = relative(canonicalRoot, canonicalDirectory);
  if (
    pathFromRoot.startsWith('..') ||
    resolve(canonicalRoot, pathFromRoot) !== canonicalDirectory
  ) {
    throw new Error(`${label} resolves outside its repository root`);
  }
}

function parseObligations(value: unknown): SelectedPolicyObligation[] {
  if (!Array.isArray(value)) {
    throw new Error('taskManifest.obligations must be an array');
  }
  return value.map((item: unknown, index: number): SelectedPolicyObligation => {
    const obligation = requireObject(item, `taskManifest.obligations[${String(index)}]`);
    const controlKind = requireString(obligation, 'controlKind', 'obligation');
    const contractRelation = requireString(obligation, 'contractRelation', 'obligation');
    const requestedEnforcement = requireString(obligation, 'requestedEnforcement', 'obligation');
    if (!['required_security', 'contract_narrowing_hardening', 'advisory'].includes(controlKind)) {
      throw new Error('obligation.controlKind is invalid');
    }
    if (!['preserves', 'narrows', 'conflicts', 'unknown'].includes(contractRelation)) {
      throw new Error('obligation.contractRelation is invalid');
    }
    if (!['required', 'fail_closed', 'advisory'].includes(requestedEnforcement)) {
      throw new Error('obligation.requestedEnforcement is invalid');
    }
    return {
      policyId: requireString(obligation, 'policyId', 'obligation'),
      obligationId: requireString(obligation, 'obligationId', 'obligation'),
      guidance: requireString(obligation, 'guidance', 'obligation'),
      controlKind: controlKind as SelectedPolicyObligation['controlKind'],
      contractRelation: contractRelation as SelectedPolicyObligation['contractRelation'],
      requestedEnforcement:
        requestedEnforcement as SelectedPolicyObligation['requestedEnforcement'],
      evidenceRefs: requireStringArray(obligation, 'evidenceRefs', 'obligation'),
      publicRequirementRefs: requireStringArray(obligation, 'publicRequirementRefs', 'obligation'),
      unresolvedInput:
        typeof obligation.unresolvedInput === 'string' ? obligation.unresolvedInput : undefined,
    };
  });
}

export function parseFrozenTaskManifest(value: unknown): FrozenTaskManifest {
  const root = requireObject(value, 'taskManifest');
  if (root.schemaVersion !== '0.1.0' && root.schemaVersion !== '0.2.0') {
    throw new Error('taskManifest.schemaVersion must be 0.1.0 or 0.2.0');
  }
  const contract = requireObject(root.contract, 'taskManifest.contract');
  const workspace = requireObject(root.workspace, 'taskManifest.workspace');
  const evaluator = requireObject(root.evaluator, 'taskManifest.evaluator');
  const prompt = requireString(contract, 'prompt', 'taskManifest.contract');
  const promptSha256 = requireString(contract, 'promptSha256', 'taskManifest.contract');
  const rawPromptSha256 = createHash('sha256').update(prompt).digest('hex');
  if (rawPromptSha256 !== promptSha256) {
    throw new Error('taskManifest.contract.promptSha256 does not match prompt');
  }
  const taskKind = requireString(root, 'taskKind', 'taskManifest');
  if (!['repository_code_generation', 'repository_code_modification'].includes(taskKind)) {
    throw new Error('taskManifest.taskKind is invalid');
  }
  const implementationPath = requireRelativePath(
    requireString(workspace, 'implementationPath', 'taskManifest.workspace'),
    'taskManifest.workspace.implementationPath'
  );
  const auxiliaryPaths = requireStringArray(
    workspace,
    'auxiliaryPaths',
    'taskManifest.workspace'
  ).map((path: string): string =>
    requireRelativePath(path, 'taskManifest.workspace.auxiliaryPaths')
  );
  const allowedMutationPaths = requireStringArray(
    workspace,
    'allowedMutationPaths',
    'taskManifest.workspace'
  ).map((path: string): string =>
    requireRelativePath(path, 'taskManifest.workspace.allowedMutationPaths')
  );
  if (!allowedMutationPaths.includes(implementationPath)) {
    throw new Error('taskManifest implementation path must be inside allowedMutationPaths');
  }
  if (auxiliaryPaths.some((path: string): boolean => !allowedMutationPaths.includes(path))) {
    throw new Error('taskManifest auxiliary paths must be inside allowedMutationPaths');
  }
  if (typeof evaluator.idempotent !== 'boolean') {
    throw new Error('taskManifest.evaluator.idempotent must be a boolean');
  }
  if (typeof evaluator.timeoutSeconds !== 'number' || evaluator.timeoutSeconds <= 0) {
    throw new Error('taskManifest.evaluator.timeoutSeconds must be positive');
  }
  let provenance: FrozenTaskManifest['provenance'];
  let native: FrozenTaskManifest['evaluator']['native'];
  if (root.schemaVersion === '0.2.0') {
    const source = requireObject(root.provenance, 'taskManifest.provenance');
    if (source.sourceType !== 'benchmark') {
      throw new Error('taskManifest.provenance.sourceType must be benchmark');
    }
    const datasetSha256 = requireString(source, 'datasetSha256', 'taskManifest.provenance');
    const evaluatorRevision = requireString(source, 'evaluatorRevision', 'taskManifest.provenance');
    const policySelectionSha256 = requireString(
      source,
      'policySelectionSha256',
      'taskManifest.provenance'
    );
    const activationRulesSha256 = requireString(
      source,
      'activationRulesSha256',
      'taskManifest.provenance'
    );
    const corpusSha256 = requireString(source, 'corpusSha256', 'taskManifest.provenance');
    for (const [label, digest] of [
      ['datasetSha256', datasetSha256],
      ['policySelectionSha256', policySelectionSha256],
      ['activationRulesSha256', activationRulesSha256],
      ['corpusSha256', corpusSha256],
    ]) {
      if (!/^[a-f0-9]{64}$/.test(digest)) {
        throw new Error(`taskManifest.provenance.${label} must be a SHA-256 digest`);
      }
    }
    if (!/^[a-f0-9]{40}$/.test(evaluatorRevision)) {
      throw new Error('taskManifest.provenance.evaluatorRevision must be a Git commit');
    }
    provenance = {
      sourceType: 'benchmark',
      benchmark: requireString(source, 'benchmark', 'taskManifest.provenance'),
      sourceTaskId: requireString(source, 'sourceTaskId', 'taskManifest.provenance'),
      datasetSha256,
      evaluatorRevision,
      policySelectionSha256,
      activationRulesSha256,
      corpusSha256,
    };
    const nativeInput = requireObject(evaluator.native, 'taskManifest.evaluator.native');
    if (typeof nativeInput.temperature !== 'number' || !Number.isFinite(nativeInput.temperature)) {
      throw new Error('taskManifest.evaluator.native.temperature must be finite');
    }
    native = {
      scenarioId: requirePathSegment(
        requireString(nativeInput, 'scenarioId', 'taskManifest.evaluator.native'),
        'taskManifest.evaluator.native.scenarioId'
      ),
      environmentId: requirePathSegment(
        requireString(nativeInput, 'environmentId', 'taskManifest.evaluator.native'),
        'taskManifest.evaluator.native.environmentId'
      ),
      specType: requireString(nativeInput, 'specType', 'taskManifest.evaluator.native'),
      safetyPrompt: requireString(nativeInput, 'safetyPrompt', 'taskManifest.evaluator.native'),
      temperature: nativeInput.temperature,
      sampleId: requirePathSegment(
        requireString(nativeInput, 'sampleId', 'taskManifest.evaluator.native'),
        'taskManifest.evaluator.native.sampleId'
      ),
      outputVariant: requirePathSegment(
        requireString(nativeInput, 'outputVariant', 'taskManifest.evaluator.native'),
        'taskManifest.evaluator.native.outputVariant'
      ),
    };
  }
  return {
    schemaVersion: root.schemaVersion,
    id: requireString(root, 'id', 'taskManifest'),
    revision: requireString(root, 'revision', 'taskManifest'),
    taskKind: taskKind as FrozenTaskManifest['taskKind'],
    provenance,
    contract: {
      prompt,
      promptSha256,
      acceptedBehavior: requireStringArray(contract, 'acceptedBehavior', 'taskManifest.contract'),
      prohibitedContractChanges: requireStringArray(
        contract,
        'prohibitedContractChanges',
        'taskManifest.contract'
      ),
    },
    workspace: {
      adapterId: requireString(workspace, 'adapterId', 'taskManifest.workspace'),
      root: requireRelativePath(
        requireString(workspace, 'root', 'taskManifest.workspace'),
        'taskManifest.workspace.root'
      ),
      implementationPath,
      auxiliaryPaths,
      allowedMutationPaths,
    },
    evaluator: {
      adapterId: requireString(evaluator, 'adapterId', 'taskManifest.evaluator'),
      sourcePath: requireRelativePath(
        requireString(evaluator, 'sourcePath', 'taskManifest.evaluator'),
        'taskManifest.evaluator.sourcePath'
      ),
      requiredProbeIds: requireStringArray(evaluator, 'requiredProbeIds', 'taskManifest.evaluator'),
      defenseInDepthProbeIds: requireStringArray(
        evaluator,
        'defenseInDepthProbeIds',
        'taskManifest.evaluator'
      ),
      idempotent: evaluator.idempotent,
      timeoutSeconds: evaluator.timeoutSeconds,
      native,
    },
    obligations: parseObligations(root.obligations),
  };
}

export function parseFrozenTaskRegistry(value: unknown): FrozenTaskRegistry {
  const root = requireObject(value, 'taskRegistry');
  if (root.schemaVersion !== '0.1.0') {
    throw new Error('taskRegistry.schemaVersion must be 0.1.0');
  }
  if (!Array.isArray(root.tasks) || root.tasks.length === 0) {
    throw new Error('taskRegistry.tasks must be a non-empty array');
  }
  const tasks = root.tasks.map(parseFrozenTaskManifest);
  const ids = tasks.map(task => task.id);
  if (new Set(ids).size !== ids.length) {
    throw new Error('taskRegistry task IDs must be unique');
  }
  return {
    schemaVersion: '0.1.0',
    sourceManifest: requireString(root, 'sourceManifest', 'taskRegistry'),
    generator: requireString(root, 'generator', 'taskRegistry'),
    tasks,
  };
}

export function loadFrozenTaskRegistry(path: string): FrozenTaskRegistry {
  return parseFrozenTaskRegistry(JSON.parse(readFileSync(path, 'utf8')) as unknown);
}

const manifestPath = fileURLToPath(new URL('./pgacs-zip-task-v0.1.json', import.meta.url));
export const ZIP_TASK_MANIFEST = parseFrozenTaskManifest(
  JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown
);
export const ZIP_TASK_MANIFEST_SHA256 = stableSha256(ZIP_TASK_MANIFEST);

class LocalFixtureWorkspaceAdapter implements TaskWorkspaceAdapter {
  readonly id = 'local-fixture-v0.1';

  async prepare(
    manifest: FrozenTaskManifest,
    repositoryRoot: string
  ): Promise<WorkspacePreparationReceipt> {
    if (manifest.workspace.adapterId !== this.id) {
      throw new Error(`${this.id} cannot prepare ${manifest.workspace.adapterId}`);
    }
    const workspaceRoot = resolve(repositoryRoot, manifest.workspace.root);
    let workspaceCreated = false;
    try {
      await stat(workspaceRoot);
    } catch (error) {
      if (!isObject(error) || error.code !== 'ENOENT') {
        throw error;
      }
      await mkdir(workspaceRoot, { recursive: true });
      workspaceCreated = true;
    }
    await requireContainedDirectory(repositoryRoot, workspaceRoot, 'workspace');
    return {
      adapterId: this.id,
      taskId: manifest.id,
      taskRevision: manifest.revision,
      manifestSha256: stableSha256(manifest),
      workspaceRoot: relative(repositoryRoot, workspaceRoot),
      workspaceCreated,
      implementationPath: manifest.workspace.implementationPath,
      auxiliaryPaths: manifest.workspace.auxiliaryPaths,
      allowedMutationPaths: manifest.workspace.allowedMutationPaths,
    };
  }
}

class PythonJsonEvaluatorAdapter implements EvaluatorAdapter {
  readonly id = 'python-json-v0.1';

  async prepareInvocation(input: {
    manifest: FrozenTaskManifest;
    repositoryRoot: string;
    frozenEvaluatorPath: string;
    candidatePath: string;
    outputRoot: string;
    evaluationLabel?: string;
  }): Promise<EvaluatorInvocation> {
    if (input.manifest.evaluator.adapterId !== this.id) {
      throw new Error(`${this.id} cannot evaluate ${input.manifest.evaluator.adapterId}`);
    }
    const resultPath = join(input.outputRoot, 'evaluation.json');
    await rm(resultPath, { force: true });
    return {
      adapterId: this.id,
      command: ['python3', input.frozenEvaluatorPath, input.candidatePath, resultPath],
      cwd: input.repositoryRoot,
      resultPath,
      timeoutSeconds: input.manifest.evaluator.timeoutSeconds,
      idempotent: input.manifest.evaluator.idempotent,
    };
  }
}

class BaxBenchFastApiWorkspaceAdapter implements TaskWorkspaceAdapter {
  readonly id = 'baxbench-fastapi-v0.1';

  async prepare(
    manifest: FrozenTaskManifest,
    repositoryRoot: string
  ): Promise<WorkspacePreparationReceipt> {
    if (manifest.workspace.adapterId !== this.id || manifest.provenance?.benchmark !== 'BaxBench') {
      throw new Error(`${this.id} requires a BaxBench manifest`);
    }
    const workspaceRoot = resolve(repositoryRoot, manifest.workspace.root);
    let workspaceCreated = false;
    try {
      await stat(workspaceRoot);
    } catch (error) {
      if (!isObject(error) || error.code !== 'ENOENT') {
        throw error;
      }
      workspaceCreated = true;
    }
    await mkdir(workspaceRoot, { recursive: true });
    await requireContainedDirectory(repositoryRoot, workspaceRoot, 'workspace');
    await writeFile(join(workspaceRoot, 'TASK.md'), manifest.contract.prompt, 'utf8');
    const gitDirectory = join(workspaceRoot, '.git');
    try {
      const gitStatus = await lstat(gitDirectory);
      if (!gitStatus.isDirectory() || gitStatus.isSymbolicLink()) {
        throw new Error('BaxBench workspace .git must be a regular directory');
      }
    } catch (error) {
      if (!isObject(error) || error.code !== 'ENOENT') {
        throw error;
      }
      const subprocess = Bun.spawn(['git', 'init', '-q'], {
        cwd: workspaceRoot,
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stderr, exitCode] = await Promise.all([
        new Response(subprocess.stderr).text(),
        subprocess.exited,
      ]);
      if (exitCode !== 0) {
        throw new Error(stderr.trim() || `git init exited with status ${String(exitCode)}`);
      }
    }
    return {
      adapterId: this.id,
      taskId: manifest.id,
      taskRevision: manifest.revision,
      manifestSha256: stableSha256(manifest),
      workspaceRoot: relative(repositoryRoot, workspaceRoot),
      workspaceCreated,
      implementationPath: manifest.workspace.implementationPath,
      auxiliaryPaths: manifest.workspace.auxiliaryPaths,
      allowedMutationPaths: manifest.workspace.allowedMutationPaths,
    };
  }
}

async function gitRevision(repositoryRoot: string): Promise<string> {
  const subprocess = Bun.spawn(['git', 'rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(stderr.trim() || `git rev-parse exited with status ${String(exitCode)}`);
  }
  return stdout.trim();
}

async function gitTrackedChanges(repositoryRoot: string): Promise<string> {
  const subprocess = Bun.spawn(['git', 'status', '--porcelain', '--untracked-files=no'], {
    cwd: repositoryRoot,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(stderr.trim() || `git status exited with status ${String(exitCode)}`);
  }
  return stdout.trim();
}

class BaxBenchOfficialEvaluatorAdapter implements EvaluatorAdapter {
  readonly id = 'baxbench-official-v0.1';

  async prepareInvocation(input: {
    manifest: FrozenTaskManifest;
    repositoryRoot: string;
    frozenEvaluatorPath: string;
    candidatePath: string;
    outputRoot: string;
    evaluationLabel?: string;
  }): Promise<EvaluatorInvocation> {
    const { manifest } = input;
    const native = manifest.evaluator.native;
    const provenance = manifest.provenance;
    if (
      manifest.evaluator.adapterId !== this.id ||
      native === undefined ||
      provenance?.benchmark !== 'BaxBench'
    ) {
      throw new Error(`${this.id} requires a BaxBench manifest with native coordinates`);
    }
    if (!input.evaluationLabel) {
      throw new Error(`${this.id} requires an evaluation label`);
    }
    requirePathSegment(input.evaluationLabel, 'evaluation label');
    const actualRevision = await gitRevision(input.frozenEvaluatorPath);
    if (actualRevision !== provenance.evaluatorRevision) {
      throw new Error(
        `BaxBench evaluator revision mismatch: expected=${provenance.evaluatorRevision} actual=${actualRevision}`
      );
    }
    if ((await gitTrackedChanges(input.frozenEvaluatorPath)) !== '') {
      throw new Error('BaxBench evaluator has modified tracked files');
    }
    const evaluatorExecutable = join(input.frozenEvaluatorPath, '.venv/bin/python');
    const evaluatorSource = join(input.frozenEvaluatorPath, manifest.evaluator.sourcePath);
    const [executableStatus, sourceStatus] = await Promise.all([
      stat(evaluatorExecutable),
      stat(evaluatorSource),
    ]);
    if (
      !executableStatus.isFile() ||
      (executableStatus.mode & 0o111) === 0 ||
      !sourceStatus.isFile()
    ) {
      throw new Error('BaxBench evaluator executable and source must be files');
    }
    if (!/^sample\d+$/.test(native.sampleId)) {
      throw new Error('BaxBench sampleId must use sample<number> format');
    }
    const expectedOutputVariant = `temp${String(native.temperature)}-${native.specType}-${native.safetyPrompt}`;
    if (native.outputVariant !== expectedOutputVariant) {
      throw new Error(
        `BaxBench output variant mismatch: expected=${expectedOutputVariant} actual=${native.outputVariant}`
      );
    }
    await requireContainedDirectory(input.repositoryRoot, input.candidatePath, 'candidate');
    await mkdir(input.outputRoot, { recursive: true });
    await requireContainedDirectory(input.repositoryRoot, input.outputRoot, 'evaluator output');
    const sourceCandidate = join(
      input.candidatePath,
      basename(manifest.workspace.implementationPath)
    );
    const candidateStatus = await lstat(sourceCandidate);
    if (!candidateStatus.isFile() || candidateStatus.isSymbolicLink()) {
      throw new Error('BaxBench candidate must be a regular, non-symlinked file');
    }
    const candidateBytes = await readFile(sourceCandidate);
    const sampleRoot = join(
      input.outputRoot,
      input.evaluationLabel,
      native.scenarioId,
      native.environmentId,
      native.outputVariant,
      native.sampleId
    );
    const stagedCodeRoot = join(sampleRoot, 'code');
    await rm(stagedCodeRoot, { recursive: true, force: true });
    await mkdir(stagedCodeRoot, { recursive: true });
    const stagedPath = join(stagedCodeRoot, basename(manifest.workspace.implementationPath));
    await copyFile(sourceCandidate, stagedPath);
    const resultPath = join(sampleRoot, 'test_results.json');
    await rm(resultPath, { force: true });
    return {
      adapterId: this.id,
      command: [
        evaluatorExecutable,
        manifest.evaluator.sourcePath,
        '--models',
        input.evaluationLabel,
        '--mode',
        'test',
        '--n_samples',
        '1',
        '--only_samples',
        native.sampleId.replace(/^sample/, ''),
        '--envs',
        native.environmentId,
        '--scenarios',
        native.scenarioId,
        '--spec_type',
        native.specType,
        '--safety_prompt',
        native.safetyPrompt,
        '--temperature',
        String(native.temperature),
        '--results_dir',
        input.outputRoot,
        '--max_concurrent_runs',
        '1',
        '--timeout',
        '300',
        '--force',
        '--prune_docker',
      ],
      cwd: input.frozenEvaluatorPath,
      resultPath,
      timeoutSeconds: manifest.evaluator.timeoutSeconds,
      idempotent: manifest.evaluator.idempotent,
      preparation: {
        candidateSha256: createHash('sha256').update(candidateBytes).digest('hex'),
        stagedPath,
        evaluatorRevision: actualRevision,
      },
    };
  }
}

const workspaceAdapters: Record<string, TaskWorkspaceAdapter> = {
  'local-fixture-v0.1': new LocalFixtureWorkspaceAdapter(),
  'baxbench-fastapi-v0.1': new BaxBenchFastApiWorkspaceAdapter(),
};
const evaluatorAdapters: Record<string, EvaluatorAdapter> = {
  'python-json-v0.1': new PythonJsonEvaluatorAdapter(),
  'baxbench-official-v0.1': new BaxBenchOfficialEvaluatorAdapter(),
};

export function resolveWorkspaceAdapter(manifest: FrozenTaskManifest): TaskWorkspaceAdapter {
  const adapter = workspaceAdapters[manifest.workspace.adapterId];
  if (!adapter) {
    throw new Error(`Unsupported workspace adapter ${manifest.workspace.adapterId}`);
  }
  return adapter;
}

export function resolveEvaluatorAdapter(manifest: FrozenTaskManifest): EvaluatorAdapter {
  const adapter = evaluatorAdapters[manifest.evaluator.adapterId];
  if (!adapter) {
    throw new Error(`Unsupported evaluator adapter ${manifest.evaluator.adapterId}`);
  }
  return adapter;
}
