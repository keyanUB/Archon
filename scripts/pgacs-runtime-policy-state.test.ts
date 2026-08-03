import { describe, expect, test } from 'bun:test';

import {
  createPolicyRuntimeState,
  extractTrajectorySecurityFacts,
  reducePolicyRuntimeState,
  replayPolicyRuntime,
  stableSha256,
  type RuntimeObservationEvent,
} from './pgacs-runtime-policy-state';

const TASK_ID = 'runtime-test-task';

function initialState() {
  return createPolicyRuntimeState(TASK_ID, [
    {
      policyId: 'policy:path',
      obligationId: 'policy:path:path-validation',
      requiredEvidence: ['absolute', 'traversal'],
    },
    {
      policyId: 'policy:resource',
      obligationId: 'policy:resource:size-limit',
      requiredEvidence: ['size'],
    },
  ]);
}

function obligationId(policyId: string): string {
  return policyId === 'policy:path' ? 'policy:path:path-validation' : 'policy:resource:size-limit';
}

function probe(
  sequence: number,
  policyId: string,
  evidenceRef: string,
  outcome: 'pass' | 'fail' | 'inconclusive' | 'harness_error'
): RuntimeObservationEvent {
  return {
    version: '0.1.0',
    taskId: TASK_ID,
    sequence,
    phase: 'evaluate',
    kind: 'probe_result',
    policyId,
    obligationId: obligationId(policyId),
    evidenceRef,
    outcome,
  };
}

describe('policy runtime reducer', (): void => {
  test('extracts stable security facts from trajectory metadata without raw tool input', (): void => {
    const input = {
      phase: 'repair',
      toolCalls: [
        { toolName: 'Bash', inputSha256: 'a'.repeat(64) },
        { toolName: 'Write', inputSha256: 'b'.repeat(64) },
      ],
      changedPaths: ['deploy/autossh.service', 'src/zip_inspector.py', 'package.json'],
    };

    const first = extractTrajectorySecurityFacts(input);
    const reordered = extractTrajectorySecurityFacts({
      ...input,
      toolCalls: [...input.toolCalls].reverse(),
      changedPaths: [...input.changedPaths].reverse(),
    });

    expect(first).toEqual(reordered);
    expect(first.map(fact => fact.factId)).toEqual([
      'archive_processing_modified',
      'dependency_manifest_modified',
      'process_execution_requested',
      'repair_modified_artifact',
      'service_configuration_modified',
    ]);
    expect(JSON.stringify(first)).not.toContain('tool_input');
  });

  test('activates a pre-adjudicated dormant obligation and requests its probe', (): void => {
    const state = createPolicyRuntimeState(TASK_ID, [
      {
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        requiredEvidence: ['traversal-probe'],
        activationFactIds: ['archive_processing_modified'],
      },
    ]);
    const fact = extractTrajectorySecurityFacts({
      phase: 'implement',
      toolCalls: [],
      changedPaths: ['src/zip_inspector.py'],
    })[0]!;
    const events: RuntimeObservationEvent[] = [
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 0,
        phase: 'implement',
        kind: 'security_fact',
        ...fact,
      },
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 1,
        phase: 'implement',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];

    expect(state.obligations[0]?.status).toBe('dormant');
    const replay = replayPolicyRuntime(state, events);
    expect(replay.state.activePolicyIds).toEqual(['policy:archive']);
    expect(replay.state.observedSecurityFacts).toMatchObject([
      { factId: 'archive_processing_modified', phase: 'implement' },
    ]);
    expect(replay.deltas[0]?.changedPolicies).toEqual([
      {
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        previous: 'dormant',
        current: 'active',
      },
    ]);
    expect(replay.deltas.at(-1)?.interventions).toMatchObject([
      {
        action: 'run_required_probe',
        policyIds: ['policy:archive'],
        evidenceRefs: ['traversal-probe'],
      },
    ]);
  });

  test('closes the trajectory loop from fact to probe failure to bounded repair', (): void => {
    const state = createPolicyRuntimeState(TASK_ID, [
      {
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        requiredEvidence: ['traversal-probe'],
        activationFactIds: ['archive_processing_modified'],
      },
    ]);
    const fact = extractTrajectorySecurityFacts({
      phase: 'implement',
      toolCalls: [],
      changedPaths: ['src/zip_inspector.py'],
    })[0]!;
    const events: RuntimeObservationEvent[] = [
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 0,
        phase: 'implement',
        kind: 'security_fact',
        ...fact,
      },
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 1,
        phase: 'implement',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 2,
        phase: 'evaluate',
        kind: 'probe_result',
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        evidenceRef: 'traversal-probe',
        outcome: 'fail',
      },
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 3,
        phase: 'evaluate',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];
    const replay = replayPolicyRuntime(state, events);

    expect(replay.deltas[1]?.interventions).toMatchObject([
      { action: 'run_required_probe', evidenceRefs: ['traversal-probe'] },
    ]);
    expect(replay.state.obligations[0]?.status).toBe('violated');
    expect(replay.deltas[3]?.interventions).toMatchObject([
      { action: 'repair_guidance', policyIds: ['policy:archive'] },
    ]);
  });

  test('does not activate dormant obligations from unrelated facts', (): void => {
    const state = createPolicyRuntimeState(TASK_ID, [
      {
        policyId: 'policy:dependency',
        obligationId: 'policy:dependency:provenance',
        requiredEvidence: ['lockfile-probe'],
        activationFactIds: ['dependency_manifest_modified'],
      },
    ]);
    const fact = extractTrajectorySecurityFacts({
      phase: 'implement',
      toolCalls: [],
      changedPaths: ['src/zip_inspector.py'],
    })[0]!;
    const reduced = reducePolicyRuntimeState(state, {
      version: '0.1.0',
      taskId: TASK_ID,
      sequence: 0,
      phase: 'implement',
      kind: 'security_fact',
      ...fact,
    });

    expect(reduced.state.obligations[0]?.status).toBe('dormant');
    expect(reduced.state.activePolicyIds).toEqual([]);
    expect(reduced.delta.changedPolicies).toEqual([]);
  });

  test('rejects probe evidence for an obligation that has not been activated', (): void => {
    const state = createPolicyRuntimeState(TASK_ID, [
      {
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        requiredEvidence: ['traversal-probe'],
        activationFactIds: ['archive_processing_modified'],
      },
    ]);

    expect(() =>
      reducePolicyRuntimeState(state, {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 0,
        phase: 'evaluate',
        kind: 'probe_result',
        policyId: 'policy:archive',
        obligationId: 'policy:archive:path-safety',
        evidenceRef: 'traversal-probe',
        outcome: 'pass',
      })
    ).toThrow('probe event targets a non-active policy obligation');
  });

  test('rejects unknown trigger IDs and security facts with false subject hashes', (): void => {
    expect(() =>
      createPolicyRuntimeState(TASK_ID, [
        {
          policyId: 'policy:unknown',
          obligationId: 'policy:unknown:trigger',
          requiredEvidence: ['probe'],
          activationFactIds: ['unknown_fact' as never],
        },
      ])
    ).toThrow('unknown activation security fact');

    const state = createPolicyRuntimeState(TASK_ID, []);
    expect(() =>
      reducePolicyRuntimeState(state, {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 0,
        phase: 'implement',
        kind: 'security_fact',
        factId: 'archive_processing_modified',
        source: 'trajectory_monitor',
        evidenceRef: 'fact:bad-hash',
        subjectRefs: ['src/zip_inspector.py'],
        subjectSha256: '0'.repeat(64),
      })
    ).toThrow('does not match its fact and subject references');
  });

  test('replays identical evidence to byte-stable state and deltas', (): void => {
    const events: RuntimeObservationEvent[] = [
      probe(0, 'policy:path', 'absolute', 'pass'),
      probe(1, 'policy:path', 'traversal', 'pass'),
      probe(2, 'policy:resource', 'size', 'pass'),
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 3,
        phase: 'evaluate',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];

    const first = replayPolicyRuntime(initialState(), events);
    const second = replayPolicyRuntime(initialState(), events);

    expect(stableSha256(first)).toBe(stableSha256(second));
    expect(first.state.obligations.map(obligation => obligation.status)).toEqual([
      'satisfied',
      'satisfied',
    ]);
    expect(first.deltas.at(-1)?.interventions).toMatchObject([{ action: 'continue' }]);
  });

  test('turns failed required evidence into bounded repair guidance', (): void => {
    const events: RuntimeObservationEvent[] = [
      probe(0, 'policy:path', 'absolute', 'fail'),
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 1,
        phase: 'evaluate',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];
    const replay = replayPolicyRuntime(initialState(), events);

    expect(replay.state.obligations[0]?.status).toBe('violated');
    expect(replay.deltas.at(-1)?.interventions).toMatchObject([
      { action: 'repair_guidance', policyIds: ['policy:path'] },
    ]);
  });

  test('blocks inconclusive or harness-failure evidence', (): void => {
    const events: RuntimeObservationEvent[] = [
      probe(0, 'policy:resource', 'size', 'harness_error'),
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 1,
        phase: 'evaluate',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];
    const replay = replayPolicyRuntime(initialState(), events);

    expect(replay.state.obligations[1]?.status).toBe('uncertain');
    expect(replay.deltas.at(-1)?.interventions).toMatchObject([{ action: 'block' }]);
  });

  test('blocks a workspace boundary violation independently of probe state', (): void => {
    const events: RuntimeObservationEvent[] = [
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 0,
        phase: 'implement',
        kind: 'workspace_boundary',
        logAvailable: true,
        changedPaths: ['allowed.py', 'control-plane.ts'],
        scopeViolations: ['control-plane.ts'],
      },
      {
        version: '0.1.0',
        taskId: TASK_ID,
        sequence: 1,
        phase: 'implement',
        kind: 'loop_boundary',
        boundary: 'post_implementation',
        repairAvailable: true,
      },
    ];
    const replay = replayPolicyRuntime(initialState(), events);

    expect(replay.state.runtimeViolations).toEqual(['control-plane.ts']);
    expect(replay.deltas.at(-1)?.interventions).toMatchObject([{ action: 'block' }]);
  });

  test('rejects out-of-order, cross-task, and unknown-evidence events', (): void => {
    expect(() =>
      reducePolicyRuntimeState(initialState(), probe(1, 'policy:path', 'absolute', 'pass'))
    ).toThrow('does not match expected 0');

    expect(() =>
      reducePolicyRuntimeState(initialState(), {
        ...probe(0, 'policy:path', 'absolute', 'pass'),
        taskId: 'other-task',
      })
    ).toThrow('does not match runtime-test-task');

    expect(() =>
      reducePolicyRuntimeState(initialState(), probe(0, 'policy:path', 'unknown', 'pass'))
    ).toThrow('policy:path:path-validation: unknown evidence reference unknown');

    const first = reducePolicyRuntimeState(
      initialState(),
      probe(0, 'policy:path', 'absolute', 'pass')
    );
    expect(() =>
      reducePolicyRuntimeState(first.state, probe(1, 'policy:path', 'absolute', 'fail'))
    ).toThrow('policy:path:path-validation: duplicate evidence reference absolute');
  });

  test('tracks multiple obligations from one policy independently', (): void => {
    const state = createPolicyRuntimeState(TASK_ID, [
      {
        policyId: 'policy:shared',
        obligationId: 'policy:shared:first',
        requiredEvidence: ['first-probe'],
      },
      {
        policyId: 'policy:shared',
        obligationId: 'policy:shared:second',
        requiredEvidence: ['second-probe'],
      },
    ]);
    const first = reducePolicyRuntimeState(state, {
      version: '0.1.0',
      taskId: TASK_ID,
      sequence: 0,
      phase: 'evaluate',
      kind: 'probe_result',
      policyId: 'policy:shared',
      obligationId: 'policy:shared:first',
      evidenceRef: 'first-probe',
      outcome: 'pass',
    });

    expect(first.state.activePolicyIds).toEqual(['policy:shared']);
    expect(first.state.obligations).toMatchObject([
      { obligationId: 'policy:shared:first', status: 'satisfied' },
      { obligationId: 'policy:shared:second', status: 'active' },
    ]);
  });
});
