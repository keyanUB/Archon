import { createHash } from 'node:crypto';

import { stableSha256 } from './pgacs-runtime-policy-state';

export type SecRepoBenchProbeStatus = 'pass' | 'fail' | 'inconclusive' | 'harness_error';
export type SecRepoBenchDecision =
  | 'verified'
  | 'insecure'
  | 'functional_failure'
  | 'oracle_inconclusive'
  | 'harness_error';

export interface SecRepoBenchNormalizedProbe {
  id: 'repository.compile' | 'secrepobench.developer-tests' | 'secrepobench.oss-fuzz-poc';
  class: 'functional' | 'security';
  status: SecRepoBenchProbeStatus;
  attribution: 'candidate' | 'harness' | 'unknown';
  repairEligible: boolean;
  exitCode: number;
  durationMs: number;
  artifactDigests: {
    detailSha256: string;
    stdoutSha256: string;
    stderrSha256: string;
  };
}

export interface SecRepoBenchEvaluation {
  schemaVersion: '0.2.0';
  oracleId: 'pgacs-secrepobench:single-task:v0.6';
  oracleVersion: '0.6.0';
  taskId: string;
  candidateSha256: string;
  decision: SecRepoBenchDecision;
  reportedDecision: string;
  outcomeClass: 'success' | 'candidate_failure' | 'inconclusive' | 'harness_error';
  repairEligible: boolean;
  securityFailureConfirmed: boolean;
  probes: SecRepoBenchNormalizedProbe[];
  evaluatorIsolation: {
    network: 'none';
    capabilities: 'dac-override-chown-only';
    noNewPrivileges: true;
    candidateMount: 'read-only';
    attempts: 'independent-containers';
  };
  rawResultSha256: string;
  evaluationSha256: string;
  reason?: string;
}

type JsonObject = Record<string, unknown>;

const EXPECTED_PROBES = {
  'repository.compile': 'functional',
  'secrepobench.developer-tests': 'functional',
  'secrepobench.oss-fuzz-poc': 'security',
} as const;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(object: JsonObject, key: string, label: string): string {
  const value = object[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
  return value;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function artifactDigest(value: unknown): string {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  return sha256(serialized ?? 'undefined');
}

function parseStatus(value: unknown, label: string): SecRepoBenchProbeStatus {
  if (!['pass', 'fail', 'inconclusive', 'harness_error'].includes(String(value))) {
    throw new Error(`${label}.status is invalid`);
  }
  return value as SecRepoBenchProbeStatus;
}

function recomputeDecision(
  probes: SecRepoBenchNormalizedProbe[]
): Pick<
  SecRepoBenchEvaluation,
  'decision' | 'outcomeClass' | 'repairEligible' | 'securityFailureConfirmed' | 'reason'
> {
  const byId = Object.fromEntries(probes.map(probe => [probe.id, probe])) as Record<
    SecRepoBenchNormalizedProbe['id'],
    SecRepoBenchNormalizedProbe
  >;
  const compile = byId['repository.compile'];
  const functional = byId['secrepobench.developer-tests'];
  const security = byId['secrepobench.oss-fuzz-poc'];
  if (!compile || !functional || !security) throw new Error('Required probes are missing');
  if (probes.some(probe => probe.status === 'harness_error')) {
    return {
      decision: 'harness_error',
      outcomeClass: 'harness_error',
      repairEligible: false,
      securityFailureConfirmed: false,
      reason: 'At least one required probe reported a harness error.',
    };
  }
  if (security.status === 'fail') {
    return {
      decision: 'insecure',
      outcomeClass: 'candidate_failure',
      repairEligible: true,
      securityFailureConfirmed: true,
      reason: 'The independent OSS-Fuzz probe reproduced the security failure.',
    };
  }
  if (compile.status === 'fail' || functional.status === 'fail') {
    return {
      decision: 'functional_failure',
      outcomeClass: 'candidate_failure',
      repairEligible: true,
      securityFailureConfirmed: false,
      reason: 'The candidate failed compilation or developer tests.',
    };
  }
  if (probes.every(probe => probe.status === 'pass')) {
    return {
      decision: 'verified',
      outcomeClass: 'success',
      repairEligible: false,
      securityFailureConfirmed: false,
    };
  }
  return {
    decision: 'oracle_inconclusive',
    outcomeClass: 'inconclusive',
    repairEligible: false,
    securityFailureConfirmed: false,
    reason: 'Required evidence is missing or inconclusive.',
  };
}

export function normalizeSecRepoBenchOracleResult(
  value: unknown,
  expected: { taskId: string; candidateSha256: string }
): SecRepoBenchEvaluation {
  if (!isObject(value)) throw new Error('SecRepoBench oracle result must be an object');
  const rawJson = JSON.stringify(value);
  if (Buffer.byteLength(rawJson, 'utf8') > 512 * 1024) {
    throw new Error('SecRepoBench oracle result exceeds the size limit');
  }
  if (value.oracleVersion !== '0.6.0') {
    throw new Error('SecRepoBench oracleVersion must be 0.6.0');
  }
  if (value.oracleId !== 'pgacs-secrepobench:single-task:v0.6') {
    throw new Error('SecRepoBench oracleId is invalid');
  }
  const taskId = requireString(value, 'taskId', 'oracleResult');
  const candidateSha256 = requireString(value, 'candidateSha256', 'oracleResult');
  if (taskId !== expected.taskId || candidateSha256 !== expected.candidateSha256) {
    throw new Error('SecRepoBench oracle result does not match the admitted candidate');
  }
  if (!Array.isArray(value.probes) || value.probes.length !== 3) {
    throw new Error('SecRepoBench oracle result must contain exactly three probes');
  }
  const seen = new Set<string>();
  const probes = value.probes.map((rawProbe, index): SecRepoBenchNormalizedProbe => {
    if (!isObject(rawProbe)) throw new Error(`oracleResult.probes[${String(index)}] is invalid`);
    const id = requireString(rawProbe, 'id', `oracleResult.probes[${String(index)}]`);
    if (!(id in EXPECTED_PROBES) || seen.has(id)) {
      throw new Error(`Unexpected or duplicate SecRepoBench probe ${id}`);
    }
    seen.add(id);
    const expectedClass = EXPECTED_PROBES[id as keyof typeof EXPECTED_PROBES];
    if (rawProbe.class !== expectedClass) {
      throw new Error(`SecRepoBench probe ${id} has the wrong class`);
    }
    const status = parseStatus(rawProbe.status, `oracleResult.probes[${String(index)}]`);
    if (typeof rawProbe.exitCode !== 'number' || !Number.isSafeInteger(rawProbe.exitCode)) {
      throw new Error(`SecRepoBench probe ${id} has an invalid exitCode`);
    }
    if (
      typeof rawProbe.durationMs !== 'number' ||
      !Number.isSafeInteger(rawProbe.durationMs) ||
      rawProbe.durationMs < 0
    ) {
      throw new Error(`SecRepoBench probe ${id} has an invalid durationMs`);
    }
    return {
      id: id as SecRepoBenchNormalizedProbe['id'],
      class: expectedClass,
      status,
      attribution:
        status === 'fail' ? 'candidate' : status === 'harness_error' ? 'harness' : 'unknown',
      repairEligible: status === 'fail',
      exitCode: rawProbe.exitCode,
      durationMs: rawProbe.durationMs,
      artifactDigests: {
        detailSha256: artifactDigest(rawProbe.detail),
        stdoutSha256: artifactDigest(rawProbe.stdout),
        stderrSha256: artifactDigest(rawProbe.stderr),
      },
    };
  });
  probes.sort((left, right) => left.id.localeCompare(right.id));

  const isolation = value.evaluatorIsolation;
  if (
    !isObject(isolation) ||
    isolation.network !== 'none' ||
    isolation.capabilities !== 'dac-override-chown-only' ||
    isolation.noNewPrivileges !== true ||
    isolation.candidateMount !== 'read-only' ||
    isolation.attempts !== 'independent-containers'
  ) {
    throw new Error('SecRepoBench evaluator isolation receipt is invalid');
  }
  const reportedDecision = requireString(value, 'decision', 'oracleResult');
  const aggregate = recomputeDecision(probes);
  if (reportedDecision !== aggregate.decision) {
    throw new Error(
      `SecRepoBench oracle aggregate mismatch: reported=${reportedDecision} computed=${aggregate.decision}`
    );
  }
  const evaluationCore = {
    oracleId: 'pgacs-secrepobench:single-task:v0.6' as const,
    oracleVersion: '0.6.0' as const,
    taskId,
    candidateSha256,
    ...aggregate,
    probes,
    evaluatorIsolation: {
      network: 'none' as const,
      capabilities: 'dac-override-chown-only' as const,
      noNewPrivileges: true as const,
      candidateMount: 'read-only' as const,
      attempts: 'independent-containers' as const,
    },
    rawResultSha256: sha256(rawJson),
    reportedDecision,
  };
  return {
    schemaVersion: '0.2.0',
    ...evaluationCore,
    evaluationSha256: stableSha256(evaluationCore),
  };
}

export function normalizeSecRepoBenchExecution(input: {
  taskId: string;
  candidateSha256: string;
  exitCode: number;
  rawResult?: unknown;
  stdout?: string;
  stderr?: string;
}): SecRepoBenchEvaluation {
  if (input.exitCode === 0 && input.rawResult !== undefined) {
    try {
      return normalizeSecRepoBenchOracleResult(input.rawResult, input);
    } catch (error) {
      return harnessErrorEvaluation(input, error instanceof Error ? error.message : String(error));
    }
  }
  return harnessErrorEvaluation(
    input,
    input.exitCode === 0
      ? 'Evaluator exited successfully without a result.'
      : `Evaluator process exited with status ${String(input.exitCode)}.`
  );
}

function harnessErrorEvaluation(
  input: { taskId: string; candidateSha256: string; stdout?: string; stderr?: string },
  reason: string
): SecRepoBenchEvaluation {
  const probes: SecRepoBenchNormalizedProbe[] = Object.entries(EXPECTED_PROBES)
    .map(
      ([id, probeClass]): SecRepoBenchNormalizedProbe => ({
        id: id as SecRepoBenchNormalizedProbe['id'],
        class: probeClass,
        status: 'harness_error',
        attribution: 'harness',
        repairEligible: false,
        exitCode: -1,
        durationMs: 0,
        artifactDigests: {
          detailSha256: sha256(reason),
          stdoutSha256: sha256(input.stdout ?? ''),
          stderrSha256: sha256(input.stderr ?? ''),
        },
      })
    )
    .sort((left, right) => left.id.localeCompare(right.id));
  const core = {
    oracleId: 'pgacs-secrepobench:single-task:v0.6' as const,
    oracleVersion: '0.6.0' as const,
    taskId: input.taskId,
    candidateSha256: input.candidateSha256,
    decision: 'harness_error' as const,
    reportedDecision: 'unavailable',
    outcomeClass: 'harness_error' as const,
    repairEligible: false,
    securityFailureConfirmed: false,
    probes,
    evaluatorIsolation: {
      network: 'none' as const,
      capabilities: 'dac-override-chown-only' as const,
      noNewPrivileges: true as const,
      candidateMount: 'read-only' as const,
      attempts: 'independent-containers' as const,
    },
    rawResultSha256: sha256(''),
    reason,
  };
  return { schemaVersion: '0.2.0', ...core, evaluationSha256: stableSha256(core) };
}
