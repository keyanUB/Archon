import { describe, expect, test } from 'bun:test';

import { summarizeBehaviorAnnotations } from './pgacs-behavior-taxonomy';
import { stableSha256 } from './pgacs-runtime-policy-state';
import type { FrozenTaskManifest } from './pgacs-task-adapters';
import {
  buildExperimentAnalysis,
  verifyArchivedTaskManifest,
  verifyCellConsistency,
  verifyLedgerMatchesCell,
} from './analyze-pgacs-baxbench-c2-results';
import {
  CONDITION_IDS,
  deriveTerminalOutcome,
  TASK_IDS,
  type CellResult,
  type ConditionId,
  type ExperimentTaskId,
  type OracleEvaluation,
} from './run-pgacs-baxbench-c2';

const scope = {
  changedPaths: ['app.py'],
  runtimeArtifactPaths: [],
  scopeViolations: [],
  allowedMutationPaths: ['app.py'],
};

function oracle(
  taskId: ExperimentTaskId,
  functionalPass: boolean,
  securityPass: boolean
): OracleEvaluation {
  return {
    oracleVersion: '0.5.0',
    taskId,
    decision: !securityPass
      ? 'rejected_insecure'
      : functionalPass
        ? 'verified'
        : 'rejected_functional',
    functionalPass,
    securityPass,
    correctSecurityBlock: !securityPass,
    probes: [
      {
        probe_id: 'functional',
        kind: 'functional',
        status: functionalPass ? 'pass' : 'fail',
        reason: 'fixture',
        evidence: [],
      },
      {
        probe_id: 'security',
        kind: 'required_security',
        status: securityPass ? 'pass' : 'fail',
        reason: 'fixture',
        evidence: [],
      },
    ],
  };
}

function attempt(evaluation: OracleEvaluation, phase: 'initial' | 'repair-1') {
  return {
    phase,
    promptSha256: `${phase}-prompt`,
    process: {
      command: ['agent'],
      exitCode: 0,
      timedOut: false,
      durationMs: 1,
      stdoutPath: 'stdout.log',
      stderrPath: 'stderr.log',
    },
    resolvedModelIds: ['claude-sonnet-5'],
    infrastructureAttempts: 1,
    scope,
    oracle: evaluation,
    observations: [],
    annotations: [],
    annotationSummary: summarizeBehaviorAnnotations([], 0),
  };
}

function cell(
  taskId: ExperimentTaskId,
  condition: ConditionId,
  initialSecurity: boolean,
  finalSecurity = initialSecurity
): CellResult {
  const initialOracle = oracle(taskId, true, initialSecurity);
  const finalOracle = oracle(taskId, true, finalSecurity);
  const repaired = initialSecurity !== finalSecurity;
  return {
    schemaVersion: '0.1.0',
    taskId,
    condition,
    activationPlanSha256: 'activation',
    obligationProbeBindings: {},
    promptSha256: 'prompt',
    initial: attempt(initialOracle, 'initial'),
    ...(repaired ? { repair: attempt(finalOracle, 'repair-1') } : {}),
    repairEligible: condition === 'C2' && !initialSecurity,
    repairAttempted: condition === 'C2' && repaired,
    terminalScope: scope,
    terminal: deriveTerminalOutcome(condition, finalOracle, scope),
    finalCandidateSha256: 'candidate',
    ledgerHeadSha256: 'ledger',
  };
}

function frozenDesign(): CellResult[] {
  return TASK_IDS.flatMap((taskId, taskIndex) =>
    CONDITION_IDS.map(condition => {
      if (condition === 'C2' && taskIndex === 0) return cell(taskId, condition, false, true);
      if (condition === 'C2' && taskIndex === 1) return cell(taskId, condition, false, false);
      if (condition === 'C2') return cell(taskId, condition, true, true);
      return cell(taskId, condition, false, false);
    })
  );
}

const integrity = {
  analyzerSha256: 'analyzer',
  resultsSha256: 'results',
  runManifestSha256: 'manifest',
  contractSha256: 'contract',
  cellResultsVerified: 12,
  taskManifestsVerified: 12,
  evidenceLedgersVerified: 12,
  finalCandidatesVerified: 12,
};

describe('PGACS BaxBench result analysis', () => {
  test('requires archived task manifests to match the frozen registry', () => {
    const frozen: FrozenTaskManifest = {
      schemaVersion: '0.2.0',
      id: 'baxbench:Login-Python-FastAPI',
      revision: 'fixture',
      taskKind: 'repository_code_generation',
      provenance: {
        sourceType: 'benchmark',
        benchmark: 'baxbench',
        sourceTaskId: 'Login-Python-FastAPI',
        datasetSha256: 'dataset',
        evaluatorRevision: 'evaluator',
        policySelectionSha256: 'selection',
        activationRulesSha256: 'activation',
        corpusSha256: 'corpus',
      },
      contract: {
        prompt: 'task',
        promptSha256: 'prompt',
        acceptedBehavior: [],
        prohibitedContractChanges: [],
      },
      workspace: {
        adapterId: 'adapter',
        root: 'workspace',
        implementationPath: 'workspace/app.py',
        auxiliaryPaths: [],
        allowedMutationPaths: ['workspace/app.py'],
      },
      evaluator: {
        adapterId: 'oracle',
        sourcePath: 'src/main.py',
        requiredProbeIds: [],
        defenseInDepthProbeIds: [],
        idempotent: false,
        timeoutSeconds: 60,
      },
      obligations: [],
    };
    expect(() => verifyArchivedTaskManifest('Login-Python-FastAPI', frozen, frozen)).not.toThrow();
    expect(() =>
      verifyArchivedTaskManifest(
        'Login-Python-FastAPI',
        { ...frozen, revision: 'tampered' },
        frozen
      )
    ).toThrow('archived task manifest differs from the frozen registry');
  });

  test('computes security-first C2 contrasts and repair attribution', () => {
    const analysis = buildExperimentAnalysis(frozenDesign(), integrity);
    expect(analysis.perTask['Login-Python-FastAPI'].C2.resolvedModelIds).toEqual([
      'claude-sonnet-5',
    ]);
    expect(analysis.byCondition.C2).toMatchObject({
      cells: 3,
      secureGeneration: 2,
      functionalCorrectness: 3,
      jointAccepted: 2,
      correctSecurityBlock: 1,
      safeSystemOutcome: 3,
    });
    expect(analysis.c2Contrasts.B0).toMatchObject({
      secureGeneration: 2,
      functionalCorrectness: 0,
      jointAccepted: 2,
      correctSecurityBlock: 1,
      safeSystemOutcome: 3,
    });
    expect(analysis.repair).toMatchObject({
      eligible: 2,
      attempted: 1,
      jointRecoveries: 1,
      securityRecoveries: 1,
      securityRegressions: 0,
      terminalCorrectSecurityBlocks: 1,
    });
  });

  test('rejects a duplicate cell instead of silently pooling an incomplete design', () => {
    const results = frozenDesign();
    results[results.length - 1] = results[0];
    expect(() => buildExperimentAnalysis(results, integrity)).toThrow('Duplicate result cell');
  });

  test('rejects a terminal outcome that disagrees with final typed evidence', () => {
    const result = cell('Login-Python-FastAPI', 'C2', true, true);
    result.terminal.secureGeneration = false;
    expect(() => verifyCellConsistency(result)).toThrow('terminal outcome is inconsistent');
  });

  test('rejects successful cells with missing runtime model evidence', () => {
    const result = cell('Login-Python-FastAPI', 'C0', true, true);
    result.initial.resolvedModelIds = [];
    expect(() => verifyCellConsistency(result)).toThrow('runtime model evidence is inconsistent');
  });

  test('requires ledger events to describe the same cell attempts and terminal result', () => {
    const result = cell('Login-Python-FastAPI', 'C0', true, true);
    const events: Record<string, unknown>[] = [
      {
        type: 'cell_started',
        taskId: result.taskId,
        condition: result.condition,
        taskManifestSha256: 'a'.repeat(64),
        activationSha256: result.activationPlanSha256,
        obligationProbeBindings: result.obligationProbeBindings,
        promptSha256: result.promptSha256,
      },
      {
        type: 'attempt_evaluated',
        phase: result.initial.phase,
        promptSha256: result.initial.promptSha256,
        attemptSha256: stableSha256(result.initial),
        scope: result.initial.scope,
        oracle: result.initial.oracle,
        behavior: result.initial.annotationSummary,
        resolvedModelIds: result.initial.resolvedModelIds,
      },
      {
        type: 'terminal_decision',
        terminal: result.terminal,
        terminalScope: result.terminalScope,
        repairEligible: result.repairEligible,
        repairAttempted: result.repairAttempted,
        finalCandidateSha256: result.finalCandidateSha256,
      },
    ];

    expect(() => verifyLedgerMatchesCell(events, result, 'a'.repeat(64))).not.toThrow();
    events[1] = { ...events[1], attemptSha256: '0'.repeat(64) };
    expect(() => verifyLedgerMatchesCell(events, result, 'a'.repeat(64))).toThrow(
      'initial ledger event is inconsistent'
    );
  });
});
