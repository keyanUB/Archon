import { constants } from 'node:fs';
import { access, readFile, readdir } from 'node:fs/promises';
import { delimiter, resolve } from 'node:path';
import {
  PGACS_QUALIFICATION_RECEIPT_PATH,
  verifyPgacsQualificationReceipt,
} from './pgacs-secrepobench-qualification';

type CheckStatus = 'pass' | 'warn' | 'fail';
type Readiness = 'ready' | 'not-ready';

export interface PgacsDoctorCheck {
  id: string;
  label: string;
  status: CheckStatus;
  requiredFor: 'offline' | 'live' | 'optional';
  detail: string;
}

export interface PgacsDoctorReport {
  schemaVersion: '0.1.0';
  offlineDevelopment: Readiness;
  liveOpenHandsExperiment: Readiness;
  checks: PgacsDoctorCheck[];
}

interface DoctorOptions {
  repoRoot?: string;
  environment?: NodeJS.ProcessEnv;
  architecture?: NodeJS.Architecture;
}

const REQUIRED_PATHS = [
  'bun.lock',
  'principle-guided-agent-research/README.md',
  'principle-guided-agent-research/current-secrepobench/README.md',
  'principle-guided-agent-research/current-secrepobench/technical-design.md',
  'principle-guided-agent-research/current-secrepobench/feasibility-results.md',
  'principle-guided-agent-research/current-secrepobench/evidence/oracle-v0.6-qualification.json',
  'scripts/pgacs-task-adapters.ts',
  'scripts/pgacs-secrepobench-candidate.ts',
  'scripts/pgacs-secrepobench-controller.ts',
  'scripts/pgacs-secrepobench-evaluation.ts',
  'scripts/pgacs-secrepobench-materializer.ts',
  'scripts/pgacs-secrepobench-policy.ts',
  'scripts/pgacs-secrepobench-trajectory.ts',
  'scripts/run-pgacs-secrepobench.ts',
  'scripts/openhands/pgacs_secrepobench_agent.py',
  'scripts/openhands/pgacs_workspace_policy.py',
  'scripts/openhands/requirements.txt',
] as const;

const BENCHMARK_REVISION = '7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76';

async function validateQualificationReceipt(repoRoot: string): Promise<PgacsDoctorCheck> {
  try {
    const receiptText = await readFile(resolve(repoRoot, PGACS_QUALIFICATION_RECEIPT_PATH), 'utf8');
    const oracleText = await readFile(
      resolve(repoRoot, 'scripts/secrepobench/pgacs_secrepobench_oracle.py'),
      'utf8'
    );
    const errors = verifyPgacsQualificationReceipt({ receiptText, oracleText });
    return check(
      'qualification-receipt',
      'Tracked oracle qualification',
      errors.length === 0 ? 'pass' : 'warn',
      'live',
      errors.length === 0
        ? 'current native-amd64 receipt binds the oracle, registry, and immutable evaluator images'
        : `historical evidence only; ${errors.join('; ')}`
    );
  } catch (error) {
    return check(
      'qualification-receipt',
      'Tracked oracle qualification',
      'warn',
      'live',
      error instanceof Error ? error.message : String(error)
    );
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function findExecutable(
  name: string,
  environment: NodeJS.ProcessEnv
): Promise<string | null> {
  const path = environment.PATH;
  if (!path) return null;

  for (const directory of path.split(delimiter)) {
    const candidate = resolve(directory, name);
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue searching PATH for an executable candidate.
    }
  }
  return null;
}

function check(
  id: string,
  label: string,
  status: CheckStatus,
  requiredFor: PgacsDoctorCheck['requiredFor'],
  detail: string
): PgacsDoctorCheck {
  return { id, label, status, requiredFor, detail };
}

function hasCredential(environment: NodeJS.ProcessEnv): boolean {
  return Boolean(environment.HF_TOKEN || (environment.LLM_API_KEY && environment.LLM_BASE_URL));
}

export function explicitRatesConfigured(environment: NodeJS.ProcessEnv): boolean {
  const input = environment.LLM_INPUT_COST_PER_TOKEN_USD;
  const output = environment.LLM_OUTPUT_COST_PER_TOKEN_USD;
  if (!input || !output) return false;
  const inputRate = Number(input);
  const outputRate = Number(output);
  return (
    Number.isFinite(inputRate) && Number.isFinite(outputRate) && inputRate >= 0 && outputRate >= 0
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function registryContainsTask910(value: unknown): boolean {
  if (!isRecord(value) || !Array.isArray(value.tasks)) return false;
  return value.tasks.some((task: unknown): boolean => {
    if (!isRecord(task)) return false;
    if (task.id === 'secrepobench-910') return true;
    return isRecord(task.provenance) && task.provenance.sourceTaskId === '910';
  });
}

async function validatePreparedRegistry(repoRoot: string): Promise<PgacsDoctorCheck> {
  const registryPath = resolve(repoRoot, '.pgacs-secrepobench/registry.json');
  if (!(await pathExists(registryPath))) {
    return check(
      'prepared-registry',
      'Prepared task registry',
      'warn',
      'live',
      'missing; acquire the pinned benchmark and run the sample-preparation command in the current runbook'
    );
  }

  try {
    const value = JSON.parse(await readFile(registryPath, 'utf8')) as unknown;
    if (!registryContainsTask910(value)) {
      return check(
        'prepared-registry',
        'Prepared task registry',
        'warn',
        'live',
        'registry exists but does not contain qualification task 910'
      );
    }
    return check(
      'prepared-registry',
      'Prepared task registry',
      'pass',
      'live',
      'registry is valid JSON and contains task 910'
    );
  } catch (error) {
    return check(
      'prepared-registry',
      'Prepared task registry',
      'warn',
      'live',
      `invalid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

function dockerCheck(executable: string | null, environment: NodeJS.ProcessEnv): PgacsDoctorCheck {
  if (!executable) {
    return check(
      'docker',
      'Docker evaluator runtime',
      'warn',
      'live',
      'Docker CLI not found; evaluator containers cannot run'
    );
  }

  const receipt = Bun.spawnSync([executable, 'version', '--format', '{{.Server.Version}}'], {
    env: environment,
    stderr: 'pipe',
    stdout: 'pipe',
    timeout: 10_000,
  });
  const version = receipt.stdout.toString().trim();
  return check(
    'docker',
    'Docker evaluator runtime',
    receipt.exitCode === 0 && version.length > 0 ? 'pass' : 'warn',
    'live',
    receipt.exitCode === 0 && version.length > 0
      ? `daemon reachable; server ${version}`
      : 'Docker CLI is installed but the daemon is not reachable'
  );
}

function normalizeDockerArchitecture(value: string): string {
  const architecture = value.trim().toLowerCase();
  if (architecture === 'x86_64' || architecture === 'x64') return 'amd64';
  if (architecture === 'aarch64') return 'arm64';
  return architecture;
}

function evaluatorArchitectureCheck(
  executable: string | null,
  environment: NodeJS.ProcessEnv,
  architectureOverride?: NodeJS.Architecture
): PgacsDoctorCheck {
  let architecture = architectureOverride ? normalizeDockerArchitecture(architectureOverride) : '';
  if (!architecture && executable) {
    const receipt = Bun.spawnSync([executable, 'info', '--format', '{{.Architecture}}'], {
      env: environment,
      stderr: 'pipe',
      stdout: 'pipe',
      timeout: 10_000,
    });
    if (receipt.exitCode === 0) {
      architecture = normalizeDockerArchitecture(receipt.stdout.toString());
    }
  }
  return check(
    'evaluator-architecture',
    'Native evaluator architecture',
    architecture === 'amd64' ? 'pass' : 'warn',
    'live',
    architecture === 'amd64'
      ? 'active Docker daemon is native amd64 and eligible for ARVO qualification'
      : architecture
        ? `active Docker daemon is ${architecture}; ARVO qualification requires native amd64`
        : 'Docker daemon architecture is unavailable'
  );
}

function openHandsPythonCheck(
  pythonPath: string,
  available: boolean,
  expectedVersions: string
): PgacsDoctorCheck {
  if (!available) {
    return check(
      'openhands-python',
      'OpenHands Python environment',
      'warn',
      'live',
      `missing: ${pythonPath}`
    );
  }

  const probe = [
    'import importlib.metadata as m',
    "print(', '.join(f'{p}={m.version(p)}' for p in ('openhands-sdk', 'openhands-tools', 'openai')))",
  ].join('; ');
  const receipt = Bun.spawnSync([pythonPath, '-c', probe], {
    stderr: 'pipe',
    stdout: 'pipe',
    timeout: 10_000,
  });
  const versions = receipt.stdout.toString().trim();
  const pinned = receipt.exitCode === 0 && versions === expectedVersions;
  return check(
    'openhands-python',
    'OpenHands Python environment',
    pinned ? 'pass' : 'warn',
    'live',
    pinned
      ? versions
      : receipt.exitCode === 0 && versions.length > 0
        ? `version mismatch; expected ${expectedVersions}; observed ${versions}`
        : 'Python exists but the pinned OpenHands dependencies cannot be imported'
  );
}

async function benchmarkSourceAvailable(repoRoot: string): Promise<boolean> {
  const sources = resolve(repoRoot, '.pgacs-multibench/sources');
  try {
    return (await readdir(sources)).includes(`SecRepoBench-${BENCHMARK_REVISION}`);
  } catch {
    return false;
  }
}

export async function collectPgacsDoctorReport(
  options: DoctorOptions = {}
): Promise<PgacsDoctorReport> {
  const repoRoot = options.repoRoot ?? resolve(import.meta.dir, '..');
  const environment = options.environment ?? process.env;
  const checks: PgacsDoctorCheck[] = [];

  const [major, minor] = Bun.version.split('.').map(Number);
  const supportedBun = major > 1 || (major === 1 && minor >= 3);
  checks.push(
    check(
      'bun-version',
      'Bun runtime',
      supportedBun ? 'pass' : 'fail',
      'offline',
      `${Bun.version}; PGACS requires Bun 1.3 or newer`
    )
  );

  checks.push(await validateQualificationReceipt(repoRoot));

  const missingPaths: string[] = [];
  for (const relativePath of REQUIRED_PATHS) {
    if (!(await pathExists(resolve(repoRoot, relativePath)))) missingPaths.push(relativePath);
  }
  checks.push(
    check(
      'source-layout',
      'Active source and documentation',
      missingPaths.length === 0 ? 'pass' : 'fail',
      'offline',
      missingPaths.length === 0
        ? 'all required paths are present'
        : `missing: ${missingPaths.join(', ')}`
    )
  );

  checks.push(await validatePreparedRegistry(repoRoot));

  const taskAssets = await Promise.all(
    ['.pgacs-secrepobench/sources/910', '.pgacs-secrepobench/masks/910.c'].map(
      (path: string): Promise<boolean> => pathExists(resolve(repoRoot, path))
    )
  );
  checks.push(
    check(
      'qualification-assets',
      'Task 910 generation assets',
      taskAssets.every(Boolean) ? 'pass' : 'warn',
      'live',
      taskAssets.every(Boolean) ? 'source and mask are present' : 'source or mask is missing'
    )
  );

  const sourceAvailable = await benchmarkSourceAvailable(repoRoot);
  checks.push(
    check(
      'benchmark-source',
      'Pinned SecRepoBench source',
      sourceAvailable ? 'pass' : 'warn',
      'live',
      sourceAvailable
        ? `revision ${BENCHMARK_REVISION} is present`
        : `revision ${BENCHMARK_REVISION} is missing; use the acquisition commands in the current runbook`
    )
  );

  const dockerExecutable = await findExecutable('docker', environment);
  checks.push(dockerCheck(dockerExecutable, environment));
  checks.push(evaluatorArchitectureCheck(dockerExecutable, environment, options.architecture));

  const configuredPython = environment.PGACS_OPENHANDS_PYTHON;
  const defaultPython = resolve(repoRoot, '.pgacs-openhands/bin/python');
  const pythonPath = configuredPython ? resolve(repoRoot, configuredPython) : defaultPython;
  const pythonAvailable = await pathExists(pythonPath);
  let requirements = 'pinned requirements unavailable';
  try {
    requirements = (await readFile(resolve(repoRoot, 'scripts/openhands/requirements.txt'), 'utf8'))
      .trim()
      .split('\n')
      .map((requirement: string): string => requirement.replace('==', '='))
      .join(', ');
  } catch {
    // The required-path check already reports the missing requirements file.
  }
  checks.push(openHandsPythonCheck(pythonPath, pythonAvailable, requirements));

  const credential = hasCredential(environment);
  checks.push(
    check(
      'model-credential',
      'OpenHands model credential',
      credential ? 'pass' : 'warn',
      'live',
      credential
        ? 'configured through the environment (value hidden)'
        : 'configure HF_TOKEN or LLM_API_KEY with LLM_BASE_URL'
    )
  );

  const rates = explicitRatesConfigured(environment);
  checks.push(
    check(
      'token-rates',
      'Explicit model token rates',
      rates ? 'pass' : 'warn',
      'live',
      rates
        ? 'input and output rates are configured (values hidden)'
        : 'set both LLM_INPUT_COST_PER_TOKEN_USD and LLM_OUTPUT_COST_PER_TOKEN_USD'
    )
  );

  const offlineDevelopment = checks.some(
    (item: PgacsDoctorCheck): boolean => item.requiredFor === 'offline' && item.status === 'fail'
  )
    ? 'not-ready'
    : 'ready';
  const liveOpenHandsExperiment = checks.every(
    (item: PgacsDoctorCheck): boolean => item.requiredFor !== 'live' || item.status === 'pass'
  )
    ? 'ready'
    : 'not-ready';

  return {
    schemaVersion: '0.1.0',
    offlineDevelopment,
    liveOpenHandsExperiment,
    checks,
  };
}

function renderReport(report: PgacsDoctorReport): string {
  const lines = report.checks.map((item: PgacsDoctorCheck): string => {
    const status = item.status.toUpperCase().padEnd(4);
    return `${status}  ${item.label}: ${item.detail}`;
  });
  lines.push('');
  lines.push(`Offline development: ${report.offlineDevelopment.toUpperCase()}`);
  lines.push(`Live OpenHands experiment: ${report.liveOpenHandsExperiment.toUpperCase()}`);
  return lines.join('\n');
}

async function main(): Promise<void> {
  const json = process.argv.slice(2).includes('--json');
  const unknown = process.argv
    .slice(2)
    .filter((argument: string): boolean => argument !== '--json');
  if (unknown.length > 0) throw new Error(`Unknown option: ${unknown[0]}`);

  const report = await collectPgacsDoctorReport();
  console.log(json ? JSON.stringify(report, null, 2) : renderReport(report));
  if (report.offlineDevelopment === 'not-ready') process.exitCode = 1;
}

if (import.meta.main) {
  await main();
}
