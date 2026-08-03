import { describe, expect, test } from 'bun:test';

import {
  buildPolicyActivationPlan,
  compileActivationBindings,
  type CompatibilityEnvelope,
  type SelectedPolicyObligation,
} from './pgacs-policy-activation';
import { stableSha256 } from './pgacs-runtime-policy-state';

function envelope(taskId = 'Login-Python-FastAPI'): CompatibilityEnvelope {
  return {
    taskId,
    taskContractSha256: stableSha256(`public contract:${taskId}`),
    acceptedBehavior: ['Preserve documented successful inputs.'],
    prohibitedContractChanges: ['Do not add unrequested rejection rules.'],
  };
}

function loginObligations(): SelectedPolicyObligation[] {
  return [
    {
      policyId: 'password-hashing',
      obligationId: 'password-hashing:store-verifier',
      guidance: 'Store a one-way password verifier rather than plaintext credentials.',
      controlKind: 'required_security',
      contractRelation: 'preserves',
      requestedEnforcement: 'required',
      evidenceRefs: ['password-storage-probe'],
      publicRequirementRefs: [],
    },
    {
      policyId: 'minimum-password',
      obligationId: 'minimum-password:new-minimum',
      guidance: 'Require a new minimum password length.',
      controlKind: 'contract_narrowing_hardening',
      contractRelation: 'narrows',
      requestedEnforcement: 'required',
      evidenceRefs: ['minimum-length-probe'],
      publicRequirementRefs: [],
    },
  ];
}

describe('PolicyActivationPlan', (): void => {
  test('keeps Login hashing required while making unrequested minimum length advisory', (): void => {
    const plan = buildPolicyActivationPlan(envelope(), loginObligations());
    const decisions = new Map(plan.decisions.map(decision => [decision.obligationId, decision]));

    expect(plan.status).toBe('ready');
    expect(decisions.get('password-hashing:store-verifier')).toMatchObject({
      compatibility: 'compatible',
      enforcement: 'required',
    });
    expect(decisions.get('minimum-password:new-minimum')).toMatchObject({
      compatibility: 'advisory',
      enforcement: 'advisory',
    });
  });

  test('keeps UserCreation file-type narrowing advisory without public authorization', (): void => {
    const taskEnvelope = envelope('UserCreation-Python-FastAPI');
    const plan = buildPolicyActivationPlan(taskEnvelope, [
      {
        policyId: 'file-type-allowlist',
        obligationId: 'file-type-allowlist:narrow-types',
        guidance: 'Reject file types outside a narrower allowlist.',
        controlKind: 'contract_narrowing_hardening',
        contractRelation: 'narrows',
        requestedEnforcement: 'fail_closed',
        evidenceRefs: ['file-type-probe'],
        publicRequirementRefs: [],
      },
    ]);

    expect(plan.status).toBe('ready');
    expect(plan.decisions[0]).toMatchObject({
      compatibility: 'advisory',
      enforcement: 'advisory',
    });
  });

  test('activates narrowing only when the public contract explicitly requires it', (): void => {
    const obligation = loginObligations()[1]!;
    const plan = buildPolicyActivationPlan(envelope(), [
      {
        ...obligation,
        publicRequirementRefs: ['task-contract:minimum-password-length'],
      },
    ]);

    expect(plan.status).toBe('ready');
    expect(plan.decisions[0]).toMatchObject({
      compatibility: 'compatible',
      enforcement: 'required',
    });
  });

  test('blocks required security that narrows behavior without public authorization', (): void => {
    const obligation = loginObligations()[0]!;
    const plan = buildPolicyActivationPlan(envelope(), [
      {
        ...obligation,
        contractRelation: 'narrows',
        publicRequirementRefs: [],
      },
    ]);

    expect(plan.status).toBe('blocked');
    expect(plan.decisions[0]).toMatchObject({
      compatibility: 'conflicting',
      enforcement: 'inactive',
    });
  });

  test('produces stable plans independent of obligation and reference ordering', (): void => {
    const first = buildPolicyActivationPlan(envelope(), loginObligations());
    const reversed = loginObligations()
      .reverse()
      .map(obligation => ({
        ...obligation,
        evidenceRefs: [...obligation.evidenceRefs].reverse(),
      }));
    const second = buildPolicyActivationPlan(envelope(), reversed);

    expect(first.activationSha256).toBe(second.activationSha256);
    expect(first).toEqual(second);
  });

  test('blocks a required contract conflict before binding compilation', (): void => {
    const plan = buildPolicyActivationPlan(envelope(), [
      {
        ...loginObligations()[0]!,
        contractRelation: 'conflicts',
      },
    ]);

    expect(plan.status).toBe('blocked');
    expect(plan.blockingDecisionIds).toEqual(['password-hashing:store-verifier']);
    expect(() => compileActivationBindings(plan)).toThrow('Cannot compile blocked activation plan');
  });

  test('blocks a required obligation when compatibility input is missing', (): void => {
    const plan = buildPolicyActivationPlan(envelope(), [
      {
        ...loginObligations()[0]!,
        contractRelation: 'unknown',
        unresolvedInput: 'Whether an external identity provider owns password storage.',
      },
    ]);

    expect(plan.status).toBe('blocked');
    expect(plan.unresolvedInputs).toEqual([
      'Whether an external identity provider owns password storage.',
    ]);
    expect(plan.decisions[0]).toMatchObject({
      compatibility: 'input_required',
      enforcement: 'inactive',
    });
  });

  test('compiles terminal evidence only for required activated obligations', (): void => {
    const bindings = compileActivationBindings(
      buildPolicyActivationPlan(envelope(), loginObligations())
    );

    expect(bindings.requiredObligationIds).toEqual(['password-hashing:store-verifier']);
    expect(bindings.advisoryObligationIds).toEqual(['minimum-password:new-minimum']);
    expect(bindings.evidenceRequirements).toEqual([
      {
        obligationId: 'password-hashing:store-verifier',
        policyId: 'password-hashing',
        evidenceRefs: ['password-storage-probe'],
        activationFactIds: [],
      },
    ]);
  });

  test('preserves deterministic trajectory triggers only after compatibility adjudication', (): void => {
    const obligation = loginObligations()[0]!;
    const bindings = compileActivationBindings(
      buildPolicyActivationPlan(envelope(), [
        {
          ...obligation,
          activationFactIds: ['dependency_manifest_modified'],
        },
      ])
    );

    expect(bindings.evidenceRequirements).toMatchObject([
      {
        obligationId: 'password-hashing:store-verifier',
        activationFactIds: ['dependency_manifest_modified'],
      },
    ]);
  });

  test('rejects unknown trajectory trigger IDs before activation', (): void => {
    expect(() =>
      buildPolicyActivationPlan(envelope(), [
        {
          ...loginObligations()[0]!,
          activationFactIds: ['unknown_fact' as never],
        },
      ])
    ).toThrow('unknown security fact');
  });
});
