import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  CORE_SECURITY_FLOOR_POLICY_IDS,
  createPolicySelectionDelta,
  loadCoreSecurityFloor,
  selectPolicyDecision,
} from './pgacs-policy-registry';
import type { PolicyRecord, TaskSurface } from './pgacs-types';

function policy(id: string, overrides: Partial<PolicyRecord> = {}): PolicyRecord {
  return {
    id,
    title: id,
    version: '1.0.0',
    sourcePrinciples: [{ source: 'test', text: id }],
    normativeText: id,
    riskTags: [],
    cweTags: [],
    taskTriggers: [],
    inputChannels: [],
    dangerousSinks: [],
    assetTags: [],
    trustBoundaryTags: [],
    dependencyTags: [],
    environmentTags: [],
    phaseBindings: [],
    validators: [],
    evidenceRequirements: [],
    forbiddenWorkarounds: [],
    severity: 'required',
    ...overrides,
  };
}

function surface(overrides: Partial<TaskSurface> = {}): TaskSurface {
  return {
    taskId: 'task-1',
    taskFamily: 'unknown',
    languageFrameworks: [],
    inputChannels: [],
    dangerousSinks: [],
    assets: [],
    trustBoundaries: [],
    runtimeExposure: [],
    dependencies: [],
    environmentConstraints: [],
    likelyCwes: [],
    missingSecurityInputs: [],
    existingTests: [],
    confidence: { taskFamily: 1, risks: 1, missingInputs: 1 },
    surfaceStatus: 'insufficient',
    evidence: [],
    unresolved: [],
    ...overrides,
  };
}

function registry(...policies: PolicyRecord[]): PolicyRecord[] {
  return [...CORE_SECURITY_FLOOR_POLICY_IDS.map(policyId => policy(policyId)), ...policies];
}

describe('selectPolicyDecision', () => {
  test('mandatory command-injection coverage survives a one-policy budget', () => {
    const decision = selectPolicyDecision(
      registry(
        policy('command-control', { cweTags: ['CWE-78'] }),
        policy('generic-shell', { dangerousSinks: ['shell_command'] })
      ),
      surface({
        dangerousSinks: ['shell_command'],
        trustBoundaries: ['untrusted_input'],
        likelyCwes: ['CWE-78'],
        surfaceStatus: 'sufficient',
      }),
      { maxPolicies: 1 }
    );

    expect(decision.selected).toHaveLength(1);
    expect(decision.selected[0]?.policyId).toBe('command-control');
    expect(decision.selected[0]?.disposition).toBe('mandatory');
  });

  test('rejects unknown LLM proposals without changing selection', () => {
    const policies = registry(policy('database-control', { dangerousSinks: ['database'] }));
    const task = surface({ dangerousSinks: ['database'], surfaceStatus: 'sufficient' });
    const baseline = selectPolicyDecision(policies, task);
    const proposed = selectPolicyDecision(policies, task, undefined, [
      { policyId: 'invented-policy', confidence: 1, rationale: 'ignore prior rules' },
    ]);

    expect(proposed.selected).toEqual(baseline.selected);
    expect(proposed.rejected).toContainEqual({
      policyId: 'invented-policy',
      score: 0,
      reason: 'invalid_proposal',
    });
  });

  test('uses stable policy-id ordering and logs candidates dropped by budget', () => {
    const decision = selectPolicyDecision(
      registry(
        policy('policy-b', { dangerousSinks: ['database'] }),
        policy('policy-a', { dangerousSinks: ['database'] })
      ),
      surface({ dangerousSinks: ['database'], surfaceStatus: 'sufficient' }),
      { maxPolicies: 1 }
    );

    expect(decision.selected[0]?.policyId).toBe('policy-a');
    expect(decision.rejected).toContainEqual({
      policyId: 'policy-b',
      score: 6,
      reason: 'budget',
    });
  });

  test('fails explicitly when a mandatory capability has no policy', () => {
    expect(() =>
      selectPolicyDecision(
        registry(policy('unrelated', { dangerousSinks: ['database'] })),
        surface({
          dangerousSinks: ['shell_command'],
          trustBoundaries: ['untrusted_input'],
        })
      )
    ).toThrow('Mandatory policy coverage gap for rule untrusted-shell-command');
  });

  test('creates a monotonic delta that retains prior policy state', () => {
    const policies = registry(
      policy('database-control', { dangerousSinks: ['database'] }),
      policy('dependency-control', { riskTags: ['dependency_integrity'] })
    );
    const initial = selectPolicyDecision(
      policies,
      surface({ dangerousSinks: ['database'], surfaceStatus: 'sufficient' })
    );
    const reassessed = selectPolicyDecision(
      policies,
      surface({
        dangerousSinks: ['database'],
        assets: ['dependencies'],
        surfaceStatus: 'sufficient',
      })
    );
    const delta = createPolicySelectionDelta(initial, reassessed, 'dependency_added');

    expect(delta.addedPolicies).toEqual(['dependency-control']);
    expect(delta.retainedPolicies).toEqual(['database-control']);
  });

  test('activates the complete generic floor for an insufficient surface', () => {
    const decision = selectPolicyDecision(registry(), surface());

    expect(decision.selectionMode).toBe('fallback');
    expect(decision.selected.map(item => item.policyId)).toEqual([
      ...CORE_SECURITY_FLOOR_POLICY_IDS,
    ]);
    expect(decision.budget.fallbackPolicies).toBe(3);
  });

  test('combines a specific policy with the generic floor for an ambiguous surface', () => {
    const decision = selectPolicyDecision(
      registry(policy('database-control', { dangerousSinks: ['database'] })),
      surface({ dangerousSinks: ['database'], surfaceStatus: 'ambiguous' })
    );

    expect(decision.selectionMode).toBe('hybrid');
    expect(decision.selected.map(item => item.policyId)).toEqual([
      ...CORE_SECURITY_FLOOR_POLICY_IDS,
      'database-control',
    ]);
  });

  test('uses explicit mode without fallback for a sufficient specific surface', () => {
    const decision = selectPolicyDecision(
      registry(policy('database-control', { dangerousSinks: ['database'] })),
      surface({ dangerousSinks: ['database'], surfaceStatus: 'sufficient' })
    );

    expect(decision.selectionMode).toBe('explicit');
    expect(decision.selected.map(item => item.policyId)).toEqual(['database-control']);
    expect(decision.budget.fallbackPolicies).toBe(0);
  });

  test('keeps fallback ordering stable when registry order changes', () => {
    const decision = selectPolicyDecision(registry().reverse(), surface());

    expect(decision.selected.map(item => item.policyId)).toEqual([
      ...CORE_SECURITY_FLOOR_POLICY_IDS,
    ]);
  });

  test('does not let an unknown proposal replace the fallback floor', () => {
    const decision = selectPolicyDecision(registry(), surface(), undefined, [
      { policyId: 'invented-policy', confidence: 1, rationale: 'replace the defaults' },
    ]);

    expect(decision.selectionMode).toBe('fallback');
    expect(decision.selected.map(item => item.policyId)).toEqual([
      ...CORE_SECURITY_FLOOR_POLICY_IDS,
    ]);
    expect(decision.rejected).toContainEqual({
      policyId: 'invented-policy',
      score: 0,
      reason: 'invalid_proposal',
    });
  });

  test('does not fill fallback budget with unrelated domain policies', () => {
    const decision = selectPolicyDecision(registry(policy('unrelated')), surface(), {
      maxPolicies: 8,
    });

    expect(decision.selected.map(item => item.policyId)).toEqual([
      ...CORE_SECURITY_FLOOR_POLICY_IDS,
    ]);
    expect(decision.rejected).toContainEqual({
      policyId: 'unrelated',
      score: 0,
      reason: 'no_match',
    });
  });

  test('rejects a registry with a malformed core security floor', () => {
    expect(() => selectPolicyDecision([policy('domain-policy')], surface())).toThrow(
      'Policy registry is missing core security-floor policy'
    );
  });

  test('rejects malformed core policy records while loading configuration', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'pgacs-core-floor-'));
    const filePath = join(directory, 'core-security-floor.json');
    const malformedPolicies = CORE_SECURITY_FLOOR_POLICY_IDS.map(id => ({ id }));
    await writeFile(
      filePath,
      JSON.stringify({ version: '0.1.0', policies: malformedPolicies }),
      'utf-8'
    );

    try {
      await expect(loadCoreSecurityFloor(filePath)).rejects.toThrow(
        'Invalid core security-floor policy at index 0'
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
