import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const DATASET_DIRECTORY = resolve(
  import.meta.dir,
  '../principle-guided-agent-research/archive/13-smoke-dataset'
);

const MANIFEST_PATH = resolve(DATASET_DIRECTORY, 'smoke-v0.1.json');
const SOURCE_LOCK_PATH = resolve(DATASET_DIRECTORY, 'source-lock.json');
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const GIT_REVISION_PATTERN = /^[a-f0-9]{40}$/;
const CWE_PATTERN = /^CWE-[1-9][0-9]*$/;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readString(object: JsonObject, key: string): string | undefined {
  const value = object[key];
  return typeof value === 'string' ? value : undefined;
}

function readArray(object: JsonObject, key: string): unknown[] | undefined {
  const value = object[key];
  return Array.isArray(value) ? value : undefined;
}

function hasForbiddenGoldField(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item: unknown): boolean => hasForbiddenGoldField(item));
  }
  if (!isObject(value)) {
    return false;
  }

  return Object.entries(value).some(([key, child]: [string, unknown]): boolean => {
    const normalizedKey = key.toLowerCase().replaceAll('_', '');
    return (
      normalizedKey === 'patch' ||
      normalizedKey === 'goldpatch' ||
      normalizedKey === 'referencecompletion' ||
      hasForbiddenGoldField(child)
    );
  });
}

function validateOracle(
  taskId: string,
  oracleName: string,
  value: unknown,
  errors: string[]
): void {
  if (!isObject(value)) {
    errors.push(`${taskId}: ${oracleName} must be an object`);
    return;
  }

  const status = readString(value, 'status');
  if (!status || !['frozen', 'upstream_available', 'design_required'].includes(status)) {
    errors.push(`${taskId}: ${oracleName}.status is invalid`);
  }

  if (!readString(value, 'source')) {
    errors.push(`${taskId}: ${oracleName}.source is required`);
  }

  const checks = readArray(value, 'requiredChecks');
  if (
    !checks ||
    checks.length === 0 ||
    checks.some((check: unknown): boolean => typeof check !== 'string')
  ) {
    errors.push(`${taskId}: ${oracleName}.requiredChecks must contain strings`);
  }
}

export function validateSmokeDataset(manifest: unknown, sourceLock: unknown): string[] {
  const errors: string[] = [];
  if (!isObject(manifest)) {
    return ['manifest must be an object'];
  }
  if (!isObject(sourceLock) || !isObject(sourceLock.sources)) {
    return ['source lock must contain a sources object'];
  }

  if (manifest.schemaVersion !== '0.1.0') {
    errors.push('manifest.schemaVersion must be 0.1.0');
  }
  if (sourceLock.schemaVersion !== '0.1.0') {
    errors.push('sourceLock.schemaVersion must be 0.1.0');
  }

  for (const [sourceId, sourceValue] of Object.entries(sourceLock.sources)) {
    if (!isObject(sourceValue)) {
      errors.push(`${sourceId}: source lock entry must be an object`);
      continue;
    }
    const kind = readString(sourceValue, 'kind');
    const revision = readString(sourceValue, 'revision');
    const sha256 = readString(sourceValue, 'sha256');
    if (!sha256 || !SHA256_PATTERN.test(sha256)) {
      errors.push(`${sourceId}: source lock sha256 must be a SHA-256 digest`);
    }
    if (!revision || revision === 'main' || revision === 'latest') {
      errors.push(`${sourceId}: source lock revision must be pinned`);
    }
    if (kind === 'git' && (!revision || !GIT_REVISION_PATTERN.test(revision))) {
      errors.push(`${sourceId}: git source lock revision must be a commit SHA`);
    }
    if (kind === 'dataset' && (!revision || !SHA256_PATTERN.test(revision))) {
      errors.push(`${sourceId}: dataset source lock revision must be a content digest`);
    }
  }

  const cohort = manifest.cohort;
  const tasks = manifest.tasks;
  if (!isObject(cohort) || !Array.isArray(tasks)) {
    return [...errors, 'manifest must contain cohort and tasks'];
  }

  const targetTaskCount = cohort.targetTaskCount;
  if (typeof targetTaskCount !== 'number' || tasks.length !== targetTaskCount) {
    errors.push('task count must match cohort.targetTaskCount');
  }

  const seenIds = new Set<string>();
  const seenFamilies = new Set<string>();
  let repositoryCodeTasks = 0;
  let environmentConfigurationTasks = 0;

  for (const taskValue of tasks) {
    if (!isObject(taskValue)) {
      errors.push('every task must be an object');
      continue;
    }

    const taskId = readString(taskValue, 'id') ?? '<missing-id>';
    if (seenIds.has(taskId)) {
      errors.push(`${taskId}: duplicate task ID`);
    }
    seenIds.add(taskId);

    const family = readString(taskValue, 'securityFamily');
    if (!family) {
      errors.push(`${taskId}: securityFamily is required`);
    } else if (seenFamilies.has(family)) {
      errors.push(`${taskId}: securityFamily must be unique in the smoke cohort`);
    } else {
      seenFamilies.add(family);
    }

    const taskKind = readString(taskValue, 'taskKind');
    if (taskKind === 'environment_configuration') {
      environmentConfigurationTasks += 1;
    } else if (taskKind?.startsWith('repository_code_')) {
      repositoryCodeTasks += 1;
    } else {
      errors.push(`${taskId}: unsupported taskKind`);
    }

    const source = taskValue.source;
    if (!isObject(source)) {
      errors.push(`${taskId}: source must be an object`);
    } else {
      const sourceId = readString(source, 'sourceId');
      const revision = readString(source, 'revision');
      const promptSha256 = readString(source, 'promptSha256');
      if (!sourceId || !(sourceId in sourceLock.sources)) {
        errors.push(`${taskId}: sourceId is absent from source-lock.json`);
      } else {
        const lock = sourceLock.sources[sourceId];
        if (!isObject(lock) || lock.revision !== revision) {
          errors.push(`${taskId}: source revision does not match source-lock.json`);
        }
      }
      if (!promptSha256 || !SHA256_PATTERN.test(promptSha256)) {
        errors.push(`${taskId}: promptSha256 must be a SHA-256 digest`);
      }
      if (!revision || revision === 'main' || revision === 'latest') {
        errors.push(`${taskId}: source revision must be pinned`);
      }
    }

    const workspace = taskValue.workspace;
    if (!isObject(workspace)) {
      errors.push(`${taskId}: workspace must be an object`);
    } else {
      const kind = readString(workspace, 'kind');
      const baseRef = workspace.baseRef;
      if (
        (kind === 'git_repository' ||
          (kind === 'benchmark_container' && readString(workspace, 'repository'))) &&
        (typeof baseRef !== 'string' || !GIT_REVISION_PATTERN.test(baseRef))
      ) {
        errors.push(`${taskId}: repository-backed workspace requires a 40-character baseRef`);
      }
      const allowedMutationPaths = readArray(workspace, 'allowedMutationPaths');
      if (!allowedMutationPaths || allowedMutationPaths.length === 0) {
        errors.push(`${taskId}: allowedMutationPaths must not be empty`);
      }
    }

    const security = taskValue.security;
    if (!isObject(security)) {
      errors.push(`${taskId}: security must be an object`);
    } else {
      const cwes = readArray(security, 'cwes');
      if (
        !cwes ||
        cwes.length === 0 ||
        cwes.some((cwe: unknown): boolean => typeof cwe !== 'string' || !CWE_PATTERN.test(cwe))
      ) {
        errors.push(`${taskId}: cwes must contain valid CWE IDs`);
      }
      if (!readString(security, 'surface') || !readString(security, 'acceptanceClaim')) {
        errors.push(`${taskId}: security surface and acceptanceClaim are required`);
      }
    }

    const evaluation = taskValue.evaluation;
    if (!isObject(evaluation) || !isObject(evaluation.adapter)) {
      errors.push(`${taskId}: evaluation and adapter are required`);
      continue;
    }
    validateOracle(taskId, 'functionalOracle', evaluation.functionalOracle, errors);
    validateOracle(taskId, 'securityOracle', evaluation.securityOracle, errors);

    if (taskValue.status === 'runnable') {
      if (evaluation.adapter.status !== 'implemented') {
        errors.push(`${taskId}: runnable task requires an implemented adapter`);
      }
      for (const oracleName of ['functionalOracle', 'securityOracle']) {
        const oracle = evaluation[oracleName];
        if (!isObject(oracle) || oracle.status !== 'frozen') {
          errors.push(`${taskId}: runnable task requires a frozen ${oracleName}`);
        }
      }
    }
  }

  const taskMix = cohort.taskMix;
  if (!isObject(taskMix)) {
    errors.push('cohort.taskMix must be an object');
  } else {
    if (taskMix.repositoryCodeTasks !== repositoryCodeTasks) {
      errors.push('repository code task count does not match cohort.taskMix');
    }
    if (taskMix.environmentConfigurationTasks !== environmentConfigurationTasks) {
      errors.push('environment configuration task count does not match cohort.taskMix');
    }
  }

  if (hasForbiddenGoldField(manifest)) {
    errors.push('manifest must not contain gold patches or reference completions');
  }

  return errors;
}

export async function loadSmokeDataset(): Promise<{
  manifest: unknown;
  sourceLock: unknown;
}> {
  const [manifestText, sourceLockText] = await Promise.all([
    readFile(MANIFEST_PATH, 'utf8'),
    readFile(SOURCE_LOCK_PATH, 'utf8'),
  ]);
  return {
    manifest: JSON.parse(manifestText) as unknown,
    sourceLock: JSON.parse(sourceLockText) as unknown,
  };
}

if (import.meta.main) {
  const { manifest, sourceLock } = await loadSmokeDataset();
  const errors = validateSmokeDataset(manifest, sourceLock);
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }
  console.log('PGACS smoke dataset is valid: 5 tasks, 5 security families.');
}
