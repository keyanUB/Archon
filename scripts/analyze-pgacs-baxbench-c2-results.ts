#!/usr/bin/env bun
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

import {
  CONDITION_IDS,
  FROZEN_MODEL_ID,
  assertRunnableExperimentTasks,
  deriveTerminalOutcome,
  mergeScopeAssessments,
  repairEligible,
  summarizeResults,
  TASK_IDS,
  verifyEvidenceLedger,
  type CellResult,
  type ConditionId,
  type ExperimentTaskId,
  type TerminalOutcome,
} from './run-pgacs-baxbench-c2';
import {
  loadPrototypeInputs,
  summarizeReadiness,
  validatePrototypeRegistry,
} from './validate-pgacs-multibench-prototype';
import { stableSha256 } from './pgacs-runtime-policy-state';
import { loadFrozenTaskRegistry, type FrozenTaskManifest } from './pgacs-task-adapters';

const REPO_ROOT = resolve(import.meta.dir, '..');
const CONTRACT_PATH = join(
  REPO_ROOT,
  'principle-guided-agent-research/15-multibench-prototype/baxbench-c2-experiment.v0.1.json'
);
const METRICS = [
  'secureGeneration',
  'functionalCorrectness',
  'jointAccepted',
  'correctSecurityBlock',
  'safeSystemOutcome',
] as const;

type Metric = (typeof METRICS)[number];
type MetricCounts = Record<Metric, number>;

interface AnalysisCell {
  taskId: ExperimentTaskId;
  condition: ConditionId;
  resolvedModelIds: string[];
  decision: TerminalOutcome['decision'];
  secureGeneration: boolean;
  functionalCorrectness: boolean;
  jointAccepted: boolean;
  correctSecurityBlock: boolean;
  safeSystemOutcome: boolean;
  initialDecision: TerminalOutcome['decision'];
  repairAttempted: boolean;
  requiredProbeFailures: string[];
  advisoryProbeFailures: string[];
  scopeViolations: string[];
  finalCandidateSha256?: string;
  ledgerHeadSha256: string;
}

interface ResultsDocument {
  summary: unknown;
  results: CellResult[];
}

interface RunManifest {
  contractSha256: string;
  configuredModelId: string;
  archonCommit: string;
  boundaryReceiptSha256: string;
  readinessRegistrySha256: string;
  tasks: string[];
  conditions: string[];
  executionOrder: { taskId: string; condition: string }[];
}

interface AnalysisContract {
  executionOrder: { taskId: ExperimentTaskId; condition: ConditionId }[];
  frozenInputs: Record<string, { path: string; sha256: string }>;
}

interface IntegrityReceipt {
  analyzerSha256: string;
  resultsSha256: string;
  runManifestSha256: string;
  contractSha256: string;
  boundaryReceiptSha256: string;
  readinessRegistrySha256: string;
  cellResultsVerified: number;
  taskManifestsVerified: number;
  evidenceLedgersVerified: number;
  finalCandidatesVerified: number;
}

export interface ExperimentAnalysis {
  schemaVersion: '0.1.0';
  claimLevel: 'preliminary_mechanism_evidence';
  integrity: IntegrityReceipt;
  protocol: {
    expectedCells: number;
    observedCells: number;
    exactDesignComplete: boolean;
    validForEffectivenessComparison: boolean;
    excludedOutcomeCells: { taskId: ExperimentTaskId; condition: ConditionId; decision: string }[];
    interpretation: string;
  };
  perTask: Record<ExperimentTaskId, Record<ConditionId, AnalysisCell>>;
  byCondition: Record<ConditionId, MetricCounts & { cells: number }>;
  c2Contrasts: Record<'B0' | 'C0' | 'C1', MetricCounts>;
  repair: {
    eligible: number;
    attempted: number;
    jointRecoveries: number;
    jointRegressions: number;
    securityRecoveries: number;
    functionalRecoveries: number;
    safeSystemRecoveries: number;
    securityRegressions: number;
    functionalRegressions: number;
    safeSystemRegressions: number;
    terminalCorrectSecurityBlocks: number;
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256(content: Uint8Array | string): string {
  return createHash('sha256').update(content).digest('hex');
}

function parseAnalysisContract(raw: unknown): AnalysisContract {
  if (!isObject(raw) || !Array.isArray(raw.executionOrder) || !isObject(raw.frozenInputs)) {
    throw new Error('Experiment contract is missing analysis-critical fields');
  }
  for (const [name, value] of Object.entries(raw.frozenInputs)) {
    if (
      !isObject(value) ||
      typeof value.path !== 'string' ||
      value.path.length === 0 ||
      typeof value.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(value.sha256)
    ) {
      throw new Error(`Experiment contract frozen input ${name} is invalid`);
    }
  }
  return raw as unknown as AnalysisContract;
}

async function verifyFrozenInputHashes(contract: AnalysisContract): Promise<void> {
  for (const input of Object.values(contract.frozenInputs)) {
    const actual = sha256(await readFile(join(REPO_ROOT, input.path)));
    if (actual !== input.sha256) {
      throw new Error(`Frozen input hash mismatch during analysis for ${input.path}`);
    }
  }
}

export function verifyArchivedTaskManifest(
  taskId: ExperimentTaskId,
  archived: unknown,
  expected: FrozenTaskManifest
): string {
  if (
    !isObject(archived) ||
    !isObject(archived.provenance) ||
    archived.provenance.sourceTaskId !== taskId
  ) {
    throw new Error(`${taskId}: archived task manifest is invalid`);
  }
  if (stableSha256(archived) !== stableSha256(expected)) {
    throw new Error(`${taskId}: archived task manifest differs from the frozen registry`);
  }
  return stableSha256(archived);
}

function isTaskId(value: unknown): value is ExperimentTaskId {
  return typeof value === 'string' && TASK_IDS.includes(value as ExperimentTaskId);
}

function isConditionId(value: unknown): value is ConditionId {
  return typeof value === 'string' && CONDITION_IDS.includes(value as ConditionId);
}

function metricCounts(cells: CellResult[]): MetricCounts {
  return Object.fromEntries(
    METRICS.map(metric => [metric, cells.filter(cell => cell.terminal[metric]).length])
  ) as MetricCounts;
}

function metricDelta(left: MetricCounts, right: MetricCounts): MetricCounts {
  return Object.fromEntries(
    METRICS.map(metric => [metric, left[metric] - right[metric]])
  ) as MetricCounts;
}

function finalOracle(cell: CellResult): CellResult['initial']['oracle'] {
  return cell.repair?.oracle ?? cell.initial.oracle;
}

function analysisCell(cell: CellResult): AnalysisCell {
  const oracle = finalOracle(cell);
  const initial = deriveTerminalOutcome(cell.condition, cell.initial.oracle, cell.initial.scope);
  return {
    taskId: cell.taskId,
    condition: cell.condition,
    resolvedModelIds: [
      ...new Set([...cell.initial.resolvedModelIds, ...(cell.repair?.resolvedModelIds ?? [])]),
    ].sort(),
    decision: cell.terminal.decision,
    secureGeneration: cell.terminal.secureGeneration,
    functionalCorrectness: cell.terminal.functionalCorrectness,
    jointAccepted: cell.terminal.jointAccepted,
    correctSecurityBlock: cell.terminal.correctSecurityBlock,
    safeSystemOutcome: cell.terminal.safeSystemOutcome,
    initialDecision: initial.decision,
    repairAttempted: cell.repairAttempted,
    requiredProbeFailures: oracle.probes
      .filter(probe => probe.kind === 'required_security' && probe.status === 'fail')
      .map(probe => probe.probe_id),
    advisoryProbeFailures: oracle.probes
      .filter(probe => probe.kind === 'advisory_security' && probe.status === 'fail')
      .map(probe => probe.probe_id),
    scopeViolations: cell.terminalScope.scopeViolations,
    ...(cell.finalCandidateSha256 ? { finalCandidateSha256: cell.finalCandidateSha256 } : {}),
    ledgerHeadSha256: cell.ledgerHeadSha256,
  };
}

export function verifyCellConsistency(cell: CellResult): void {
  for (const attempt of [cell.initial, ...(cell.repair ? [cell.repair] : [])]) {
    if (
      attempt.agentExecutionError === undefined &&
      stableSha256(attempt.resolvedModelIds) !== stableSha256([FROZEN_MODEL_ID])
    ) {
      throw new Error(`${cell.taskId}:${cell.condition}: runtime model evidence is inconsistent`);
    }
  }
  const expectedScope = mergeScopeAssessments([
    cell.initial.scope,
    ...(cell.repair ? [cell.repair.scope] : []),
  ]);
  if (stableSha256(expectedScope) !== stableSha256(cell.terminalScope)) {
    throw new Error(`${cell.taskId}:${cell.condition}: terminal scope is inconsistent`);
  }
  const expectedRepairEligible =
    cell.condition === 'C2' &&
    cell.initial.scope.scopeViolations.length === 0 &&
    repairEligible(cell.initial.oracle);
  if (
    cell.repairEligible !== expectedRepairEligible ||
    cell.repairAttempted !== expectedRepairEligible ||
    cell.repairAttempted !== (cell.repair !== undefined) ||
    (cell.repair !== undefined && !expectedRepairEligible)
  ) {
    throw new Error(`${cell.taskId}:${cell.condition}: repair state is inconsistent`);
  }
  const oracle = finalOracle(cell);
  const expectedTerminal = deriveTerminalOutcome(cell.condition, oracle, expectedScope);
  if (stableSha256(expectedTerminal) !== stableSha256(cell.terminal)) {
    throw new Error(`${cell.taskId}:${cell.condition}: terminal outcome is inconsistent`);
  }
  if (oracle.candidateSha256 !== cell.finalCandidateSha256) {
    throw new Error(`${cell.taskId}:${cell.condition}: final oracle/candidate digest mismatch`);
  }
}

function ledgerPayload(event: Record<string, unknown>): Record<string, unknown> {
  const payload = { ...event };
  delete payload.priorSha256;
  delete payload.eventSha256;
  return payload;
}

export function verifyLedgerMatchesCell(
  events: Record<string, unknown>[],
  cell: CellResult,
  expectedTaskManifestSha256: string
): void {
  const expectedLength = cell.repair ? 4 : 3;
  if (events.length !== expectedLength) {
    throw new Error(
      `${cell.taskId}:${cell.condition}: evidence ledger event count is inconsistent`
    );
  }
  const started = ledgerPayload(events[0] ?? {});
  const taskManifestSha256 = started.taskManifestSha256;
  if (taskManifestSha256 !== expectedTaskManifestSha256) {
    throw new Error(`${cell.taskId}:${cell.condition}: task manifest ledger binding is invalid`);
  }
  const startedComparable = { ...started };
  delete startedComparable.taskManifestSha256;
  if (
    stableSha256(startedComparable) !==
    stableSha256({
      type: 'cell_started',
      taskId: cell.taskId,
      condition: cell.condition,
      activationSha256: cell.activationPlanSha256,
      obligationProbeBindings: cell.obligationProbeBindings,
      promptSha256: cell.promptSha256,
    })
  ) {
    throw new Error(`${cell.taskId}:${cell.condition}: cell-start ledger event is inconsistent`);
  }

  const attempts = [cell.initial, ...(cell.repair ? [cell.repair] : [])];
  for (const [attemptIndex, attempt] of attempts.entries()) {
    const event = ledgerPayload(events[attemptIndex + 1] ?? {});
    if (
      stableSha256(event) !==
      stableSha256({
        type: 'attempt_evaluated',
        phase: attempt.phase,
        promptSha256: attempt.promptSha256,
        attemptSha256: stableSha256(attempt),
        scope: attempt.scope,
        oracle: attempt.oracle,
        behavior: attempt.annotationSummary,
        resolvedModelIds: attempt.resolvedModelIds,
      })
    ) {
      throw new Error(
        `${cell.taskId}:${cell.condition}: ${attempt.phase} ledger event is inconsistent`
      );
    }
  }

  const terminal = ledgerPayload(events.at(-1) ?? {});
  if (
    stableSha256(terminal) !==
    stableSha256({
      type: 'terminal_decision',
      terminal: cell.terminal,
      terminalScope: cell.terminalScope,
      repairEligible: cell.repairEligible,
      repairAttempted: cell.repairAttempted,
      finalCandidateSha256: cell.finalCandidateSha256,
    })
  ) {
    throw new Error(`${cell.taskId}:${cell.condition}: terminal ledger event is inconsistent`);
  }
}

function assertExactCellDesign(results: CellResult[]): void {
  const expected = new Set(
    TASK_IDS.flatMap(taskId => CONDITION_IDS.map(condition => `${taskId}:${condition}`))
  );
  const observed = new Set<string>();
  for (const cell of results) {
    if (!isTaskId(cell.taskId) || !isConditionId(cell.condition)) {
      throw new Error('Results contain an unknown task or condition');
    }
    const key = `${cell.taskId}:${cell.condition}`;
    if (observed.has(key)) throw new Error(`Duplicate result cell: ${key}`);
    observed.add(key);
  }
  const missing = [...expected].filter(key => !observed.has(key));
  if (missing.length > 0 || observed.size !== expected.size) {
    throw new Error(
      `Results do not contain the exact frozen 12-cell design: missing ${missing.join(', ')}`
    );
  }
}

function validateResultsDocument(raw: unknown): ResultsDocument {
  if (!isObject(raw) || !Array.isArray(raw.results) || !('summary' in raw)) {
    throw new Error('results.json must contain summary and results');
  }
  const results = raw.results as CellResult[];
  assertExactCellDesign(results);
  if (stableSha256(raw.summary) !== stableSha256(summarizeResults(results))) {
    throw new Error('Stored aggregate summary does not match recomputed cell outcomes');
  }
  return { summary: raw.summary, results };
}

function validateRunManifest(
  raw: unknown,
  contractSha256: string,
  executionOrder: unknown
): RunManifest {
  if (!isObject(raw)) throw new Error('run-manifest.json must be an object');
  if (
    raw.contractSha256 !== contractSha256 ||
    raw.configuredModelId !== FROZEN_MODEL_ID ||
    typeof raw.archonCommit !== 'string' ||
    !/^[0-9a-f]{40}$/u.test(raw.archonCommit) ||
    typeof raw.boundaryReceiptSha256 !== 'string' ||
    typeof raw.readinessRegistrySha256 !== 'string' ||
    JSON.stringify(raw.tasks) !== JSON.stringify(TASK_IDS) ||
    JSON.stringify(raw.conditions) !== JSON.stringify(CONDITION_IDS) ||
    JSON.stringify(raw.executionOrder) !== JSON.stringify(executionOrder)
  ) {
    throw new Error('Run manifest does not match the frozen experiment design');
  }
  return raw as unknown as RunManifest;
}

async function verifyRawArtifacts(
  runRoot: string,
  results: CellResult[],
  expectedTaskManifests: ReadonlyMap<ExperimentTaskId, FrozenTaskManifest>
): Promise<
  Pick<
    IntegrityReceipt,
    | 'cellResultsVerified'
    | 'taskManifestsVerified'
    | 'evidenceLedgersVerified'
    | 'finalCandidatesVerified'
  >
> {
  let cellResultsVerified = 0;
  let taskManifestsVerified = 0;
  let evidenceLedgersVerified = 0;
  let finalCandidatesVerified = 0;
  for (const cell of results) {
    verifyCellConsistency(cell);
    const cellRoot = join(runRoot, cell.taskId, cell.condition);
    const storedCell = JSON.parse(
      await readFile(join(cellRoot, 'cell-result.json'), 'utf8')
    ) as unknown;
    if (stableSha256(storedCell) !== stableSha256(cell)) {
      throw new Error(
        `${cell.taskId}:${cell.condition}: aggregate cell differs from cell-result.json`
      );
    }
    cellResultsVerified += 1;
    const taskManifest = JSON.parse(
      await readFile(join(cellRoot, 'task-manifest.json'), 'utf8')
    ) as unknown;
    const expectedTaskManifest = expectedTaskManifests.get(cell.taskId);
    if (!expectedTaskManifest) {
      throw new Error(`${cell.taskId}:${cell.condition}: frozen task manifest is missing`);
    }
    const taskManifestSha256 = verifyArchivedTaskManifest(
      cell.taskId,
      taskManifest,
      expectedTaskManifest
    );
    taskManifestsVerified += 1;
    const ledgerEvents = verifyEvidenceLedger(
      await readFile(join(cellRoot, 'evidence-ledger.jsonl'), 'utf8'),
      cell.ledgerHeadSha256
    );
    verifyLedgerMatchesCell(ledgerEvents, cell, taskManifestSha256);
    evidenceLedgersVerified += 1;
    if (cell.finalCandidateSha256) {
      const candidate = await readFile(join(cellRoot, 'workspace/app.py'));
      if (sha256(candidate) !== cell.finalCandidateSha256) {
        throw new Error(`${cell.taskId}:${cell.condition}: final candidate digest mismatch`);
      }
      finalCandidatesVerified += 1;
    }
  }
  return {
    cellResultsVerified,
    taskManifestsVerified,
    evidenceLedgersVerified,
    finalCandidatesVerified,
  };
}

export function buildExperimentAnalysis(
  results: CellResult[],
  integrity: IntegrityReceipt
): ExperimentAnalysis {
  assertExactCellDesign(results);
  const perTask = {} as Record<ExperimentTaskId, Record<ConditionId, AnalysisCell>>;
  for (const taskId of TASK_IDS) {
    perTask[taskId] = {} as Record<ConditionId, AnalysisCell>;
    for (const condition of CONDITION_IDS) {
      const cell = results.find(
        result => result.taskId === taskId && result.condition === condition
      );
      if (!cell) throw new Error(`Missing result cell: ${taskId}:${condition}`);
      perTask[taskId][condition] = analysisCell(cell);
    }
  }

  const byCondition = {} as Record<ConditionId, MetricCounts & { cells: number }>;
  for (const condition of CONDITION_IDS) {
    const cells = results.filter(result => result.condition === condition);
    byCondition[condition] = { cells: cells.length, ...metricCounts(cells) };
  }
  const c2Counts = metricCounts(results.filter(result => result.condition === 'C2'));
  const c2Contrasts = Object.fromEntries(
    (['B0', 'C0', 'C1'] as const).map(condition => [
      condition,
      metricDelta(c2Counts, metricCounts(results.filter(result => result.condition === condition))),
    ])
  ) as ExperimentAnalysis['c2Contrasts'];

  const c2 = results.filter(result => result.condition === 'C2');
  const initial = (cell: CellResult): TerminalOutcome =>
    deriveTerminalOutcome(cell.condition, cell.initial.oracle, cell.initial.scope);
  const excludedOutcomeCells = results
    .filter(cell =>
      ['blocked_harness_error', 'blocked_inconclusive'].includes(cell.terminal.decision)
    )
    .map(cell => ({
      taskId: cell.taskId,
      condition: cell.condition,
      decision: cell.terminal.decision,
    }));
  return {
    schemaVersion: '0.1.0',
    claimLevel: 'preliminary_mechanism_evidence',
    integrity,
    protocol: {
      expectedCells: TASK_IDS.length * CONDITION_IDS.length,
      observedCells: results.length,
      exactDesignComplete: true,
      validForEffectivenessComparison: excludedOutcomeCells.length === 0,
      excludedOutcomeCells,
      interpretation:
        'One development sample per task-condition cell; contrasts are descriptive mechanism evidence, not inferential evidence of population-level superiority.',
    },
    perTask,
    byCondition,
    c2Contrasts,
    repair: {
      eligible: c2.filter(cell => cell.repairEligible).length,
      attempted: c2.filter(cell => cell.repairAttempted).length,
      jointRecoveries: c2.filter(
        cell => !initial(cell).jointAccepted && cell.terminal.jointAccepted
      ).length,
      jointRegressions: c2.filter(
        cell => initial(cell).jointAccepted && !cell.terminal.jointAccepted
      ).length,
      securityRecoveries: c2.filter(
        cell => !initial(cell).secureGeneration && cell.terminal.secureGeneration
      ).length,
      functionalRecoveries: c2.filter(
        cell => !initial(cell).functionalCorrectness && cell.terminal.functionalCorrectness
      ).length,
      safeSystemRecoveries: c2.filter(
        cell => !initial(cell).safeSystemOutcome && cell.terminal.safeSystemOutcome
      ).length,
      securityRegressions: c2.filter(
        cell => initial(cell).secureGeneration && !cell.terminal.secureGeneration
      ).length,
      functionalRegressions: c2.filter(
        cell => initial(cell).functionalCorrectness && !cell.terminal.functionalCorrectness
      ).length,
      safeSystemRegressions: c2.filter(
        cell => initial(cell).safeSystemOutcome && !cell.terminal.safeSystemOutcome
      ).length,
      terminalCorrectSecurityBlocks: c2.filter(cell => cell.terminal.correctSecurityBlock).length,
    },
  };
}

async function main(): Promise<void> {
  const inputIndex = process.argv.indexOf('--input');
  const outputIndex = process.argv.indexOf('--output');
  const input = inputIndex >= 0 ? process.argv[inputIndex + 1] : undefined;
  const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : undefined;
  if (!input)
    throw new Error(
      'Usage: analyze-pgacs-baxbench-c2-results.ts --input <run-root> [--output <json>]'
    );
  const runRoot = resolve(input);
  const resultsPath = join(runRoot, 'results.json');
  const manifestPath = join(runRoot, 'run-manifest.json');
  const archivedContractPath = join(runRoot, 'experiment-contract.json');
  const boundaryReceiptPath = join(runRoot, 'agent-boundary-receipt.json');
  const readinessRegistryPath = join(runRoot, 'readiness-registry.json');
  const [
    resultsBytes,
    manifestBytes,
    contractBytes,
    currentContractBytes,
    boundaryReceiptBytes,
    readinessRegistryBytes,
  ] = await Promise.all([
    readFile(resultsPath),
    readFile(manifestPath),
    readFile(archivedContractPath),
    readFile(CONTRACT_PATH),
    readFile(boundaryReceiptPath),
    readFile(readinessRegistryPath),
  ]);
  if (sha256(contractBytes) !== sha256(currentContractBytes)) {
    throw new Error('Archived experiment contract does not match the current frozen contract');
  }
  const document = validateResultsDocument(JSON.parse(resultsBytes.toString('utf8')) as unknown);
  const contractSha256 = sha256(contractBytes);
  const contract = parseAnalysisContract(JSON.parse(contractBytes.toString('utf8')) as unknown);
  await verifyFrozenInputHashes(contract);
  const observedOrder = document.results.map(cell => ({
    taskId: cell.taskId,
    condition: cell.condition,
  }));
  if (JSON.stringify(observedOrder) !== JSON.stringify(contract.executionOrder)) {
    throw new Error('Result cell order does not match the frozen executionOrder');
  }
  const runManifest = validateRunManifest(
    JSON.parse(manifestBytes.toString('utf8')) as unknown,
    contractSha256,
    contract.executionOrder
  );
  const boundaryReceipt = JSON.parse(boundaryReceiptBytes.toString('utf8')) as unknown;
  const readinessRegistry = JSON.parse(readinessRegistryBytes.toString('utf8')) as unknown;
  if (
    stableSha256(boundaryReceipt) !== runManifest.boundaryReceiptSha256 ||
    stableSha256(readinessRegistry) !== runManifest.readinessRegistrySha256
  ) {
    throw new Error('Archived readiness evidence does not match the run manifest');
  }
  const currentInputs = await loadPrototypeInputs();
  const readinessErrors = validatePrototypeRegistry({
    ...currentInputs,
    registry: readinessRegistry,
    agentBoundaryReceipt: boundaryReceipt,
  });
  if (readinessErrors.length > 0) {
    throw new Error(`Archived readiness evidence is invalid:\n- ${readinessErrors.join('\n- ')}`);
  }
  assertRunnableExperimentTasks(summarizeReadiness(readinessRegistry));
  if (!isObject(boundaryReceipt) || boundaryReceipt.archonCommit !== runManifest.archonCommit) {
    throw new Error('Archived boundary receipt does not match the run Archon commit');
  }
  const taskRegistryInput = contract.frozenInputs.taskManifestRegistry;
  if (!taskRegistryInput) {
    throw new Error('Experiment contract does not freeze the task manifest registry');
  }
  const taskRegistry = loadFrozenTaskRegistry(join(REPO_ROOT, taskRegistryInput.path));
  const expectedTaskManifests = new Map<ExperimentTaskId, FrozenTaskManifest>();
  for (const taskId of TASK_IDS) {
    const manifest = taskRegistry.tasks.find(task => task.provenance?.sourceTaskId === taskId);
    if (!manifest) throw new Error(`Frozen task manifest is missing for ${taskId}`);
    expectedTaskManifests.set(taskId, manifest);
  }
  const artifactIntegrity = await verifyRawArtifacts(
    runRoot,
    document.results,
    expectedTaskManifests
  );
  const analysis = buildExperimentAnalysis(document.results, {
    analyzerSha256: sha256(await readFile(import.meta.path)),
    resultsSha256: sha256(resultsBytes),
    runManifestSha256: sha256(manifestBytes),
    contractSha256,
    boundaryReceiptSha256: runManifest.boundaryReceiptSha256,
    readinessRegistrySha256: runManifest.readinessRegistrySha256,
    ...artifactIntegrity,
  });
  const text = `${JSON.stringify(analysis, null, 2)}\n`;
  if (output) {
    const outputPath = resolve(output);
    if (dirname(outputPath) === outputPath) throw new Error('Output must be a file path');
    await writeFile(outputPath, text, { flag: 'wx' });
  }
  console.log(text.trimEnd());
  if (!analysis.protocol.validForEffectivenessComparison) process.exitCode = 2;
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exit(1);
  });
}
