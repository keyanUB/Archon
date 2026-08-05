import { describe, expect, test } from 'bun:test';

import {
  loadPrototypeInputs,
  summarizeReadiness,
  validatePrototypeRegistry,
} from './validate-pgacs-multibench-prototype';

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function validBoundaryCell(condition: 'B0' | 'C0' | 'C2'): Record<string, unknown> {
  return {
    condition,
    processSuccess: true,
    agentExecutionErrorAbsent: true,
    allowedWriteSucceeded: true,
    safeModeCanaryAbsent: true,
    controlSecretAbsent: true,
    crossCellSecretAbsent: true,
    deniedOperationAttempted: true,
    crossCellReadAttempted: true,
    networkAttempted: condition !== 'C2',
    externalContentAbsent: true,
    deniedReadNonDisclosureObserved: true,
    c2BashToolAbsent: condition === 'C2' ? true : null,
    resolvedModelIds: ['claude-sonnet-5'],
  };
}

describe('PGACS multi-benchmark prototype registry', (): void => {
  test('accepts the frozen small prototype cohort', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    expect(validatePrototypeRegistry(inputs)).toEqual([]);
    expect(summarizeReadiness(inputs.registry)).toMatchObject({
      total: 9,
      runnable: 3,
      adapterReady: 0,
      selected: 6,
    });
  });

  test('rejects a task absent from its source manifest', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      tasks: Array<{ sourceTaskId: string }>;
    };
    registry.tasks[0]!.sourceTaskId = 'not-a-frozen-task';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'prototype-baxbench-login: sourceTaskId is absent from the frozen source manifest'
    );
  });

  test('rejects a false runnable claim', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      tasks: Array<{
        id: string;
        status: string;
        readiness: { knownSecureAccepted: string };
      }>;
    };
    registry.tasks[0]!.status = 'runnable';
    registry.tasks[0]!.readiness.knownSecureAccepted = 'not_recorded';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'prototype-baxbench-login: runnable status requires every readiness gate and no blockers'
    );
  });

  test('rejects a recorded agent boundary without a live receipt', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      tasks: Array<{
        status: string;
        readiness: { agentBoundaryValidation: string; blockers: string[] };
      }>;
    };
    registry.tasks[0]!.readiness.agentBoundaryValidation = 'recorded';

    expect(
      validatePrototypeRegistry({ ...inputs, registry, agentBoundaryReceipt: null })
    ).toContain('Recorded agent-boundary validation requires a validated live receipt');
  });

  test('rejects a boundary receipt that is stale or omits a condition', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const agentBoundaryReceipt = {
      schemaVersion: '0.1.0',
      verified: true,
      verifierSha256: '0'.repeat(64),
      experimentContractSha256: inputs.agentBoundaryExpectedHashes.experimentContractSha256,
      experimentRunnerSha256: inputs.agentBoundaryExpectedHashes.experimentRunnerSha256,
      claudeVersion: '2.1.206',
      archonCommit: 'a'.repeat(40),
      cells: [],
    };

    const errors = validatePrototypeRegistry({ ...inputs, agentBoundaryReceipt });
    expect(errors).toContain(
      'Agent-boundary receipt verifierSha256 does not match the current frozen input'
    );
    expect(errors).toContain('Agent-boundary receipt is missing the B0 cell');
    expect(errors).toContain('Agent-boundary receipt is missing the C0 cell');
    expect(errors).toContain('Agent-boundary receipt is missing the C2 cell');
  });

  test('accepts a complete boundary receipt bound to the current control plane', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const agentBoundaryReceipt = {
      schemaVersion: '0.1.0',
      verified: true,
      ...inputs.agentBoundaryExpectedHashes,
      claudeVersion: '2.1.206 (Claude Code)',
      archonCommit: 'a'.repeat(40),
      cells: (['B0', 'C0', 'C2'] as const).map(validBoundaryCell),
    };

    expect(validatePrototypeRegistry({ ...inputs, agentBoundaryReceipt })).toEqual([]);
  });

  test('rejects an adapter-ready BaxBench task without a shared task manifest', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchTaskRegistry = cloneJson(inputs.baxbenchTaskRegistry) as {
      tasks: Array<{ provenance: { sourceTaskId: string } }>;
    };
    baxbenchTaskRegistry.tasks = baxbenchTaskRegistry.tasks.filter(
      task => task.provenance.sourceTaskId !== 'Login-Python-FastAPI'
    );

    expect(validatePrototypeRegistry({ ...inputs, baxbenchTaskRegistry })).toContain(
      'prototype-baxbench-login: sourceTaskId is absent from the BaxBench adapter registry'
    );
  });

  test('rejects a BaxBench adapter registry with prompt drift', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchTaskRegistry = cloneJson(inputs.baxbenchTaskRegistry) as {
      tasks: Array<{ contract: { prompt: string } }>;
    };
    baxbenchTaskRegistry.tasks[0]!.contract.prompt += ' drift';

    expect(
      validatePrototypeRegistry({ ...inputs, baxbenchTaskRegistry }).some(error =>
        error.includes('promptSha256 does not match prompt')
      )
    ).toBe(true);
  });

  test('rejects a recorded calibration claim absent from the v0.5 receipt', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchOracleReceipt = cloneJson(inputs.baxbenchOracleReceipt) as {
      receipts: Array<{ taskId: string }>;
    };
    baxbenchOracleReceipt.receipts = baxbenchOracleReceipt.receipts.filter(
      receipt => receipt.taskId !== 'Login-Python-FastAPI'
    );

    expect(validatePrototypeRegistry({ ...inputs, baxbenchOracleReceipt })).toContain(
      'prototype-baxbench-login: recorded calibration is absent from the validated v0.5 receipt'
    );
  });

  test('rejects a vulnerable calibration that is not functionally valid', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchOracleReceipt = cloneJson(inputs.baxbenchOracleReceipt) as {
      receipts: Array<{ taskId: string; knownVulnerable: { functionalPass: boolean } }>;
    };
    const loginReceipt = baxbenchOracleReceipt.receipts.find(
      receipt => receipt.taskId === 'Login-Python-FastAPI'
    );
    if (!loginReceipt) throw new Error('Missing Login calibration fixture');
    loginReceipt.knownVulnerable.functionalPass = false;

    expect(validatePrototypeRegistry({ ...inputs, baxbenchOracleReceipt })).toContain(
      'Login-Python-FastAPI: oracle calibration receipt does not satisfy the admission contract'
    );
  });

  test('rejects calibration with a weakened evaluator isolation receipt', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchOracleReceipt = cloneJson(inputs.baxbenchOracleReceipt) as {
      evaluatorIsolation: { supervisorCapabilities: string[] };
    };
    baxbenchOracleReceipt.evaluatorIsolation.supervisorCapabilities = ['SETUID'];

    expect(validatePrototypeRegistry({ ...inputs, baxbenchOracleReceipt })).toContain(
      'BaxBench oracle receipt must bind the exact evaluator isolation contract'
    );
  });

  test('rejects calibration against a different digest-pinned image', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchOracleReceipt = cloneJson(inputs.baxbenchOracleReceipt) as {
      environmentImage: string;
    };
    baxbenchOracleReceipt.environmentImage = `other@sha256:${'a'.repeat(64)}`;

    expect(validatePrototypeRegistry({ ...inputs, baxbenchOracleReceipt })).toContain(
      'BaxBench oracle receipt must bind the exact digest-pinned evaluator image'
    );
  });

  test('rejects calibration generated by a stale oracle implementation', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const baxbenchOracleReceipt = cloneJson(inputs.baxbenchOracleReceipt) as {
      receipts: Array<{ taskId: string; oracleSha256: string }>;
    };
    const loginReceipt = baxbenchOracleReceipt.receipts.find(
      receipt => receipt.taskId === 'Login-Python-FastAPI'
    );
    if (!loginReceipt) throw new Error('Missing Login calibration fixture');
    loginReceipt.oracleSha256 = '0'.repeat(64);

    expect(validatePrototypeRegistry({ ...inputs, baxbenchOracleReceipt })).toContain(
      'Login-Python-FastAPI: calibration receipt oracle digest is stale'
    );
  });

  test('rejects benchmark mix drift', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      study: { benchmarkMix: Record<string, number> };
    };
    registry.study.benchmarkMix.baxbench = 4;

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'baxbench: task count does not match study.benchmarkMix'
    );
  });

  test('rejects drift from the security-first primary endpoint', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      study: { primaryOutcome: string };
    };
    registry.study.primaryOutcome = 'joint_functional_and_required_security_success';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'study.primaryOutcome must be safe_system_security_outcome'
    );
  });

  test('rejects drift from the PGACS system version', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      study: { systemVersion: string };
    };
    registry.study.systemVersion = '0.1.0';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'study.systemVersion must be 0.3.0'
    );
  });

  test('rejects benchmarks outside the frozen prototype cohort', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      tasks: Array<{ id: string; benchmark: string }>;
    };
    registry.tasks[0]!.benchmark = 'unsupported_benchmark';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'prototype-baxbench-login: unsupported benchmark'
    );
  });

  test('does not permit held-out labeling in the prototype cohort', async (): Promise<void> => {
    const inputs = await loadPrototypeInputs();
    const registry = cloneJson(inputs.registry) as {
      tasks: Array<{ id: string; studyRole: string }>;
    };
    registry.tasks[0]!.studyRole = 'held_out';

    expect(validatePrototypeRegistry({ ...inputs, registry })).toContain(
      'prototype-baxbench-login: studyRole must be integration or development'
    );
  });
});
