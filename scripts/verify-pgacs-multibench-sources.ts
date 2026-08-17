import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '..');
const DEFAULT_WORK_ROOT = resolve(REPO_ROOT, '.pgacs-multibench');
const SETUP_MANIFEST = resolve(
  REPO_ROOT,
  'principle-guided-agent-research/archive/15-multibench-prototype/setupbench-selection-v0.1.json'
);

type JsonObject = Record<string, unknown>;

interface VerificationCheck {
  id: string;
  path: string;
  expectedSha256: string;
  actualSha256: string | null;
  status: 'pass' | 'fail';
}

export interface SourceVerificationReceipt {
  schemaVersion: '0.1.0';
  receiptType: 'source_verification';
  generatedAt: string;
  workRoot: string;
  checks: VerificationCheck[];
  status: 'pass' | 'fail';
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
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
  return value;
}

async function loadJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8')) as unknown;
}

async function sha256(path: string): Promise<string | null> {
  try {
    return createHash('sha256')
      .update(await readFile(path))
      .digest('hex');
  } catch (error) {
    if (isObject(error) && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function checkFile(
  id: string,
  path: string,
  expectedSha256: string
): Promise<VerificationCheck> {
  const actualSha256 = await sha256(path);
  return {
    id,
    path,
    expectedSha256,
    actualSha256,
    status: actualSha256 === expectedSha256 ? 'pass' : 'fail',
  };
}

function checkText(
  id: string,
  source: string,
  text: string,
  expectedSha256: string
): VerificationCheck {
  const actualSha256 = createHash('sha256').update(text).digest('hex');
  return {
    id,
    path: source,
    expectedSha256,
    actualSha256,
    status: actualSha256 === expectedSha256 ? 'pass' : 'fail',
  };
}

async function loadJsonLines(path: string): Promise<JsonObject[] | null> {
  try {
    return (await readFile(path, 'utf8'))
      .split('\n')
      .filter((line: string): boolean => line.trim().length > 0)
      .map((line: string): JsonObject => requireObject(JSON.parse(line) as unknown, path));
  } catch (error) {
    if (error instanceof SyntaxError || (isObject(error) && error.code === 'ENOENT')) {
      return null;
    }
    throw error;
  }
}

function setupSourceDirectory(workRoot: string, revision: string): string {
  return resolve(workRoot, 'sources', `SetupBench-${revision}`);
}

export async function verifySources(
  workRoot = DEFAULT_WORK_ROOT,
  generatedAt = new Date().toISOString()
): Promise<SourceVerificationReceipt> {
  const setupManifest = requireObject(await loadJson(SETUP_MANIFEST), 'setup manifest');
  const setupSource = requireObject(setupManifest.source, 'setup manifest.source');
  const setupRevision = requireString(setupSource, 'revision', 'setup manifest.source');
  const setupDirectory = setupSourceDirectory(workRoot, setupRevision);
  const setupArtifacts = setupSource.artifacts;
  if (!Array.isArray(setupArtifacts)) {
    throw new Error('setup manifest.source.artifacts must be an array');
  }

  const checks: VerificationCheck[] = [];
  for (const artifactValue of setupArtifacts) {
    const artifact = requireObject(artifactValue, 'setup source artifact');
    const relativePath = requireString(artifact, 'path', 'setup source artifact');
    checks.push(
      await checkFile(
        `setupbench:${relativePath}`,
        resolve(setupDirectory, relativePath),
        requireString(artifact, 'sha256', 'setup source artifact')
      )
    );
  }

  const setupTasks = setupManifest.tasks;
  if (!Array.isArray(setupTasks)) {
    throw new Error('setup manifest.tasks must be an array');
  }
  const setupScenariosByArtifact = new Map<string, JsonObject[] | null>();
  for (const taskValue of setupTasks) {
    const task = requireObject(taskValue, 'setup task');
    const taskId = requireString(task, 'id', 'setup task');
    const artifact = requireString(task, 'artifact', taskId);
    let scenarios = setupScenariosByArtifact.get(artifact);
    if (!scenarios) {
      scenarios = await loadJsonLines(resolve(setupDirectory, artifact));
      setupScenariosByArtifact.set(artifact, scenarios);
    }
    const expectedPromptSha256 = requireString(task, 'promptSha256', taskId);
    const source = `${resolve(setupDirectory, artifact)}#${taskId}.problem_statement`;
    if (!scenarios) {
      checks.push({
        id: `setupbench:${taskId}:prompt`,
        path: source,
        expectedSha256: expectedPromptSha256,
        actualSha256: null,
        status: 'fail',
      });
      continue;
    }
    const scenario = scenarios.find(
      (candidate: JsonObject): boolean => candidate.instance_id === taskId
    );
    if (!scenario) {
      checks.push({
        id: `setupbench:${taskId}:prompt`,
        path: source,
        expectedSha256: expectedPromptSha256,
        actualSha256: null,
        status: 'fail',
      });
      continue;
    }
    checks.push(
      checkText(
        `setupbench:${taskId}:prompt`,
        source,
        requireString(scenario, 'problem_statement', taskId),
        expectedPromptSha256
      )
    );
  }

  const sweDatasetPath = resolve(workRoot, 'swebench-verified.parquet');
  checks.push(
    await checkFile(
      'swebench_verified:dataset',
      sweDatasetPath,
      'a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd'
    )
  );

  return {
    schemaVersion: '0.1.0',
    receiptType: 'source_verification',
    generatedAt,
    workRoot,
    checks,
    status: checks.every((check: VerificationCheck): boolean => check.status === 'pass')
      ? 'pass'
      : 'fail',
  };
}

async function main(): Promise<void> {
  const workRoot = resolve(process.env.PGACS_MULTIBENCH_ROOT ?? DEFAULT_WORK_ROOT);
  const receipt = await verifySources(workRoot);
  const outputPath = resolve(workRoot, 'source-verification.json');
  await writeFile(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  console.log(
    JSON.stringify(
      {
        status: receipt.status,
        receipt: outputPath,
        checks: receipt.checks.map((check: VerificationCheck) => ({
          id: check.id,
          status: check.status,
          source: basename(check.path),
        })),
      },
      null,
      2
    )
  );
  if (receipt.status !== 'pass') {
    process.exitCode = 1;
  }
}

if (import.meta.main) {
  await main();
}
