import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const PGACS_QUALIFICATION_SCHEMA_VERSION = '0.1.0' as const;
export const PGACS_QUALIFICATION_RECEIPT_PATH =
  'principle-guided-agent-research/current-secrepobench/evidence/oracle-v0.6-qualification.json';
const EXPECTED_BENCHMARK_REVISION = '7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76';
const EXPECTED_TASKS = {
  '910': { manifestId: 'secrepobench-910', projectName: 'lcms', arvoImage: 'n132/arvo:910-fix' },
  '1065': {
    manifestId: 'secrepobench-1065',
    projectName: 'file',
    arvoImage: 'n132/arvo:1065-fix',
  },
  '19902': {
    manifestId: 'secrepobench-19902',
    projectName: 'mruby',
    arvoImage: 'n132/arvo:19902-fix',
  },
} as const;

interface QualificationTask {
  taskId: string;
  manifestId: string;
  projectName: string;
  arvoImage: string;
  datasetSha256: string;
}

export interface PgacsQualificationReceipt {
  schemaVersion: typeof PGACS_QUALIFICATION_SCHEMA_VERSION;
  qualificationId: 'pgacs-secrepobench-oracle-v0.6';
  qualifiedOn: string;
  benchmark: {
    name: 'SecRepoBench';
    repository: 'ai-sec-lab/SecRepoBench';
    revision: string;
  };
  oracle: {
    id: string;
    version: string;
    sourcePath: string;
    sourceSha256: string;
  };
  inputs: {
    calibrationSummarySha256: string;
    preparedRegistrySha256: string;
  };
  calibration: {
    summarySchemaVersion: string;
    repetitions: number;
    resultCount: number;
    allPassed: boolean;
    decisionCounts: Record<string, number>;
    variantCounts: Record<string, number>;
    probeCount: number;
    probeDurationMs: { min: number; max: number };
    tasks: QualificationTask[];
  };
}

interface BuildQualificationOptions {
  summaryText: string;
  registryText: string;
  oracleText: string;
  qualifiedOn: string;
}

interface VerifyQualificationOptions {
  receiptText: string;
  oracleText: string;
  summaryText?: string;
  registryText?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseRecord(text: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(text) as unknown;
  if (!isRecord(parsed)) throw new Error(`${label} must be a JSON object`);
  return parsed;
}

function requireString(record: Record<string, unknown>, key: string, label: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
  return value;
}

function requireNumber(record: Record<string, unknown>, key: string, label: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label}.${key} must be a finite number`);
  }
  return value;
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function increment(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

function sortedRecord(counts: Record<string, number>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(counts).sort(([left], [right]) => left.localeCompare(right))
  );
}

function validSha256(value: unknown): boolean {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

export function buildPgacsQualificationReceipt(
  options: BuildQualificationOptions
): PgacsQualificationReceipt {
  const summary = parseRecord(options.summaryText, 'calibration summary');
  const registry = parseRecord(options.registryText, 'prepared registry');
  const results = summary.results;
  const registryTasks = registry.tasks;
  if (!Array.isArray(results) || results.length === 0) {
    throw new Error('calibration summary.results must be a non-empty array');
  }
  if (!Array.isArray(registryTasks) || registryTasks.length === 0) {
    throw new Error('prepared registry.tasks must be a non-empty array');
  }
  if (summary.passed !== true) throw new Error('calibration summary is not passing');

  const repetitions = requireNumber(summary, 'repetitions', 'calibration summary');
  const decisionCounts: Record<string, number> = {};
  const variantCounts: Record<string, number> = {};
  const taskIds = new Set<string>();
  const oracleIds = new Set<string>();
  const oracleVersions = new Set<string>();
  const durations: number[] = [];
  let probeCount = 0;

  for (const [index, value] of results.entries()) {
    if (!isRecord(value)) throw new Error(`calibration result ${index} must be an object`);
    if (value.passed !== true) throw new Error(`calibration result ${index} is not passing`);
    const taskId = requireString(value, 'taskId', `calibration result ${index}`);
    const variant = requireString(value, 'variant', `calibration result ${index}`);
    const expectedDecision = requireString(
      value,
      'expectedDecision',
      `calibration result ${index}`
    );
    if (!isRecord(value.evaluation)) {
      throw new Error(`calibration result ${index}.evaluation must be an object`);
    }
    const evaluation = value.evaluation;
    const decision = requireString(
      evaluation,
      'decision',
      `calibration result ${index}.evaluation`
    );
    if (decision !== expectedDecision) {
      throw new Error(`calibration result ${index} decision does not match its expectation`);
    }
    taskIds.add(taskId);
    oracleIds.add(requireString(evaluation, 'oracleId', `calibration result ${index}.evaluation`));
    oracleVersions.add(
      requireString(evaluation, 'oracleVersion', `calibration result ${index}.evaluation`)
    );
    increment(decisionCounts, decision);
    increment(variantCounts, variant);
    if (!Array.isArray(evaluation.probes) || evaluation.probes.length === 0) {
      throw new Error(`calibration result ${index} has no probes`);
    }
    for (const [probeIndex, probe] of evaluation.probes.entries()) {
      if (!isRecord(probe))
        throw new Error(`result ${index} probe ${probeIndex} must be an object`);
      const duration = requireNumber(probe, 'durationMs', `result ${index} probe ${probeIndex}`);
      if (duration < 0)
        throw new Error(`result ${index} probe ${probeIndex} has negative duration`);
      durations.push(duration);
      probeCount += 1;
    }
  }

  if (oracleIds.size !== 1 || oracleVersions.size !== 1) {
    throw new Error('calibration results do not use one oracle identity and version');
  }

  const tasks: QualificationTask[] = registryTasks.map(
    (value: unknown, index: number): QualificationTask => {
      if (!isRecord(value)) throw new Error(`prepared registry task ${index} must be an object`);
      if (!isRecord(value.provenance) || !isRecord(value.evaluator)) {
        throw new Error(`prepared registry task ${index} lacks provenance or evaluator`);
      }
      if (!isRecord(value.evaluator.secRepoBench)) {
        throw new Error(`prepared registry task ${index} lacks SecRepoBench coordinates`);
      }
      const sourceSha256 = requireString(
        value.evaluator,
        'sourceSha256',
        `registry task ${index}.evaluator`
      );
      if (sourceSha256 !== sha256(options.oracleText)) {
        throw new Error(`prepared registry task ${index} binds a different oracle source`);
      }
      return {
        taskId: requireString(
          value.provenance,
          'sourceTaskId',
          `registry task ${index}.provenance`
        ),
        manifestId: requireString(value, 'id', `registry task ${index}`),
        projectName: requireString(
          value.evaluator.secRepoBench,
          'projectName',
          `registry task ${index}.evaluator.secRepoBench`
        ),
        arvoImage: requireString(
          value.evaluator.secRepoBench,
          'arvoImage',
          `registry task ${index}.evaluator.secRepoBench`
        ),
        datasetSha256: requireString(
          value.provenance,
          'datasetSha256',
          `registry task ${index}.provenance`
        ),
      };
    }
  );
  tasks.sort((left: QualificationTask, right: QualificationTask): number =>
    left.taskId.localeCompare(right.taskId, undefined, { numeric: true })
  );
  const registeredIds = new Set(tasks.map((task: QualificationTask): string => task.taskId));
  if (
    registeredIds.size !== taskIds.size ||
    [...taskIds].some((taskId: string): boolean => !registeredIds.has(taskId))
  ) {
    throw new Error('calibration task identities do not match the prepared registry');
  }

  const revision = /^SecRepoBench@([0-9a-f]{40}):/.exec(
    requireString(registry, 'sourceManifest', 'prepared registry')
  )?.[1];
  if (!revision) throw new Error('prepared registry sourceManifest does not bind a commit');
  const [oracleId] = oracleIds;
  const [oracleVersion] = oracleVersions;
  if (!oracleId || !oracleVersion) throw new Error('calibration oracle identity is missing');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(options.qualifiedOn)) {
    throw new Error('qualifiedOn must use YYYY-MM-DD');
  }

  return {
    schemaVersion: PGACS_QUALIFICATION_SCHEMA_VERSION,
    qualificationId: 'pgacs-secrepobench-oracle-v0.6',
    qualifiedOn: options.qualifiedOn,
    benchmark: {
      name: 'SecRepoBench',
      repository: 'ai-sec-lab/SecRepoBench',
      revision,
    },
    oracle: {
      id: oracleId,
      version: oracleVersion,
      sourcePath: 'scripts/secrepobench/pgacs_secrepobench_oracle.py',
      sourceSha256: sha256(options.oracleText),
    },
    inputs: {
      calibrationSummarySha256: sha256(options.summaryText),
      preparedRegistrySha256: sha256(options.registryText),
    },
    calibration: {
      summarySchemaVersion: requireString(summary, 'schemaVersion', 'calibration summary'),
      repetitions,
      resultCount: results.length,
      allPassed: true,
      decisionCounts: sortedRecord(decisionCounts),
      variantCounts: sortedRecord(variantCounts),
      probeCount,
      probeDurationMs: { min: Math.min(...durations), max: Math.max(...durations) },
      tasks,
    },
  };
}

export function verifyPgacsQualificationReceipt(options: VerifyQualificationOptions): string[] {
  const receipt = parseRecord(options.receiptText, 'qualification receipt');
  const errors: string[] = [];
  if (receipt.schemaVersion !== PGACS_QUALIFICATION_SCHEMA_VERSION)
    errors.push('unsupported receipt schema');
  if (receipt.qualificationId !== 'pgacs-secrepobench-oracle-v0.6')
    errors.push('unexpected qualification identity');
  if (typeof receipt.qualifiedOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(receipt.qualifiedOn)) {
    errors.push('invalid qualification date');
  }
  if (
    !isRecord(receipt.benchmark) ||
    receipt.benchmark.name !== 'SecRepoBench' ||
    receipt.benchmark.repository !== 'ai-sec-lab/SecRepoBench' ||
    receipt.benchmark.revision !== EXPECTED_BENCHMARK_REVISION
  ) {
    errors.push('unexpected benchmark identity');
  }
  if (!isRecord(receipt.oracle)) {
    errors.push('oracle receipt is missing');
  } else {
    if (
      receipt.oracle.id !== 'pgacs-secrepobench:single-task:v0.6' ||
      receipt.oracle.version !== '0.6.0' ||
      receipt.oracle.sourcePath !== 'scripts/secrepobench/pgacs_secrepobench_oracle.py'
    ) {
      errors.push('unexpected oracle identity');
    }
    if (receipt.oracle.sourceSha256 !== sha256(options.oracleText)) {
      errors.push('oracle source digest no longer matches the qualified source');
    }
  }
  if (!isRecord(receipt.calibration)) {
    errors.push('calibration receipt is missing');
  } else {
    const calibration = receipt.calibration;
    if (
      calibration.summarySchemaVersion !== '0.1.0' ||
      calibration.repetitions !== 3 ||
      calibration.resultCount !== 18 ||
      calibration.allPassed !== true ||
      calibration.probeCount !== 54 ||
      JSON.stringify(calibration.decisionCounts) !== JSON.stringify({ insecure: 9, verified: 9 }) ||
      JSON.stringify(calibration.variantCounts) !== JSON.stringify({ secure: 9, vulnerable: 9 })
    ) {
      errors.push('receipt does not record the frozen 18-case passing calibration');
    }
    if (
      !isRecord(calibration.probeDurationMs) ||
      typeof calibration.probeDurationMs.min !== 'number' ||
      typeof calibration.probeDurationMs.max !== 'number' ||
      calibration.probeDurationMs.min < 0 ||
      calibration.probeDurationMs.max < calibration.probeDurationMs.min
    ) {
      errors.push('invalid probe duration aggregate');
    }
    if (!Array.isArray(calibration.tasks) || calibration.tasks.length !== 3) {
      errors.push('receipt does not bind the three qualified tasks');
    } else {
      for (const [taskId, expected] of Object.entries(EXPECTED_TASKS)) {
        const task = calibration.tasks.find(
          (value: unknown): boolean => isRecord(value) && value.taskId === taskId
        );
        if (
          !isRecord(task) ||
          task.manifestId !== expected.manifestId ||
          task.projectName !== expected.projectName ||
          task.arvoImage !== expected.arvoImage ||
          !validSha256(task.datasetSha256)
        ) {
          errors.push(`invalid qualification identity for task ${taskId}`);
        }
      }
    }
  }
  if (!isRecord(receipt.inputs)) {
    errors.push('qualification input digests are missing');
  } else {
    if (
      !validSha256(receipt.inputs.calibrationSummarySha256) ||
      !validSha256(receipt.inputs.preparedRegistrySha256)
    ) {
      errors.push('qualification input digests are invalid');
    }
    if (
      options.summaryText !== undefined &&
      receipt.inputs.calibrationSummarySha256 !== sha256(options.summaryText)
    ) {
      errors.push('local calibration summary does not match the tracked receipt');
    }
    if (
      options.registryText !== undefined &&
      receipt.inputs.preparedRegistrySha256 !== sha256(options.registryText)
    ) {
      errors.push('local prepared registry does not match the tracked receipt');
    }
  }
  return errors;
}

async function readIfPresent(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if (isRecord(error) && error.code === 'ENOENT') return undefined;
    throw error;
  }
}

async function main(): Promise<void> {
  const repoRoot = resolve(import.meta.dir, '..');
  const args = process.argv.slice(2);
  const checkOnly = args.includes('--check');
  const unknown = args.filter((argument: string): boolean => argument !== '--check');
  if (unknown.length > 0) throw new Error(`Unknown option: ${unknown[0]}`);

  const receiptPath = resolve(repoRoot, PGACS_QUALIFICATION_RECEIPT_PATH);
  const oraclePath = resolve(repoRoot, 'scripts/secrepobench/pgacs_secrepobench_oracle.py');
  const summaryPath = resolve(
    repoRoot,
    '.pgacs-secrepobench-calibration-v06/calibration-summary.json'
  );
  const registryPath = resolve(repoRoot, '.pgacs-secrepobench/registry.json');
  const oracleText = await readFile(oraclePath, 'utf8');

  if (checkOnly) {
    const errors = verifyPgacsQualificationReceipt({
      receiptText: await readFile(receiptPath, 'utf8'),
      oracleText,
      summaryText: await readIfPresent(summaryPath),
      registryText: await readIfPresent(registryPath),
    });
    if (errors.length > 0) throw new Error(errors.join('; '));
    console.log('PGACS SecRepoBench qualification receipt is current.');
    return;
  }

  const receipt = buildPgacsQualificationReceipt({
    summaryText: await readFile(summaryPath, 'utf8'),
    registryText: await readFile(registryPath, 'utf8'),
    oracleText,
    qualifiedOn: new Date().toISOString().slice(0, 10),
  });
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  console.log(`Wrote ${PGACS_QUALIFICATION_RECEIPT_PATH}`);
}

if (import.meta.main) await main();
