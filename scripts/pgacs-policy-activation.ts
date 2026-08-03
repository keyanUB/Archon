import {
  RUNTIME_SECURITY_FACT_IDS,
  stableSha256,
  type RuntimeSecurityFactId,
} from './pgacs-runtime-policy-state';

export type ActivationControlKind =
  | 'required_security'
  | 'contract_narrowing_hardening'
  | 'advisory';
export type ContractRelation = 'preserves' | 'narrows' | 'conflicts' | 'unknown';
export type RequestedEnforcement = 'required' | 'fail_closed' | 'advisory';
export type ActivationCompatibility = 'compatible' | 'conflicting' | 'input_required' | 'advisory';
export type ActivatedEnforcement = RequestedEnforcement | 'inactive';

export interface CompatibilityEnvelope {
  taskId: string;
  taskContractSha256: string;
  acceptedBehavior: string[];
  prohibitedContractChanges: string[];
}

export interface SelectedPolicyObligation {
  policyId: string;
  obligationId: string;
  guidance: string;
  controlKind: ActivationControlKind;
  contractRelation: ContractRelation;
  requestedEnforcement: RequestedEnforcement;
  evidenceRefs: string[];
  activationFactIds?: RuntimeSecurityFactId[];
  publicRequirementRefs: string[];
  unresolvedInput?: string;
}

export interface PolicyActivationDecision {
  policyId: string;
  obligationId: string;
  guidance: string;
  controlKind: ActivationControlKind;
  contractRelation: ContractRelation;
  requestedEnforcement: RequestedEnforcement;
  compatibility: ActivationCompatibility;
  enforcement: ActivatedEnforcement;
  evidenceRefs: string[];
  activationFactIds: RuntimeSecurityFactId[];
  publicRequirementRefs: string[];
  rationale: string;
}

export interface PolicyActivationPlan {
  version: '0.1.0';
  taskId: string;
  taskContractSha256: string;
  selectionSha256: string;
  compatibilityEnvelope: CompatibilityEnvelope;
  decisions: PolicyActivationDecision[];
  unresolvedInputs: string[];
  blockingDecisionIds: string[];
  status: 'ready' | 'blocked';
  activationSha256: string;
}

export interface ActivationBindings {
  version: '0.1.0';
  taskId: string;
  activationSha256: string;
  requiredObligationIds: string[];
  advisoryObligationIds: string[];
  promptBindings: {
    obligationId: string;
    policyId: string;
    enforcement: Exclude<ActivatedEnforcement, 'inactive'>;
    guidance: string;
  }[];
  evidenceRequirements: {
    obligationId: string;
    policyId: string;
    evidenceRefs: string[];
    activationFactIds: RuntimeSecurityFactId[];
  }[];
}

type ActiveActivationDecision = PolicyActivationDecision & {
  enforcement: Exclude<ActivatedEnforcement, 'inactive'>;
};

function requireNonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${label} must be non-empty`);
  }
  return normalized;
}

function requireSha256(value: string, label: string): string {
  const normalized = requireNonEmpty(value, label);
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return normalized;
}

function normalizeStrings(values: string[], label: string): string[] {
  const normalized = values.map((value: string): string => requireNonEmpty(value, label));
  return [...new Set(normalized)].sort();
}

function normalizeSecurityFactIds(values: RuntimeSecurityFactId[]): RuntimeSecurityFactId[] {
  const normalized = [...new Set(values)].sort();
  if (normalized.some(factId => !RUNTIME_SECURITY_FACT_IDS.includes(factId))) {
    throw new Error('obligation.activationFactIds contains an unknown security fact');
  }
  return normalized;
}

function normalizeEnvelope(envelope: CompatibilityEnvelope): CompatibilityEnvelope {
  return {
    taskId: requireNonEmpty(envelope.taskId, 'compatibilityEnvelope.taskId'),
    taskContractSha256: requireSha256(
      envelope.taskContractSha256,
      'compatibilityEnvelope.taskContractSha256'
    ),
    acceptedBehavior: normalizeStrings(
      envelope.acceptedBehavior,
      'compatibilityEnvelope.acceptedBehavior'
    ),
    prohibitedContractChanges: normalizeStrings(
      envelope.prohibitedContractChanges,
      'compatibilityEnvelope.prohibitedContractChanges'
    ),
  };
}

function normalizeObligation(obligation: SelectedPolicyObligation): SelectedPolicyObligation {
  const normalized: SelectedPolicyObligation = {
    ...obligation,
    policyId: requireNonEmpty(obligation.policyId, 'obligation.policyId'),
    obligationId: requireNonEmpty(obligation.obligationId, 'obligation.obligationId'),
    guidance: requireNonEmpty(obligation.guidance, 'obligation.guidance'),
    evidenceRefs: normalizeStrings(obligation.evidenceRefs, 'obligation.evidenceRefs'),
    activationFactIds: normalizeSecurityFactIds(obligation.activationFactIds ?? []),
    publicRequirementRefs: normalizeStrings(
      obligation.publicRequirementRefs,
      'obligation.publicRequirementRefs'
    ),
    unresolvedInput: obligation.unresolvedInput?.trim() || undefined,
  };
  if (normalized.requestedEnforcement !== 'advisory' && normalized.evidenceRefs.length === 0) {
    throw new Error(`${normalized.obligationId}: required activation needs evidence references`);
  }
  if (normalized.contractRelation === 'unknown' && !normalized.unresolvedInput) {
    throw new Error(`${normalized.obligationId}: unknown contract relation needs unresolved input`);
  }
  return normalized;
}

function adjudicate(obligation: SelectedPolicyObligation): PolicyActivationDecision {
  let compatibility: ActivationCompatibility;
  let enforcement: ActivatedEnforcement;
  let rationale: string;

  if (obligation.contractRelation === 'conflicts') {
    compatibility = 'conflicting';
    enforcement = 'inactive';
    rationale = 'The obligation conflicts with the frozen public task contract.';
  } else if (obligation.contractRelation === 'unknown') {
    compatibility = 'input_required';
    enforcement = 'inactive';
    rationale = 'Compatibility requires a missing public security input.';
  } else if (obligation.controlKind === 'advisory') {
    compatibility = 'advisory';
    enforcement = 'advisory';
    rationale = 'The selected obligation is advisory and cannot affect terminal success.';
  } else if (obligation.controlKind === 'contract_narrowing_hardening') {
    if (obligation.contractRelation === 'narrows' && obligation.publicRequirementRefs.length > 0) {
      compatibility = 'compatible';
      enforcement = obligation.requestedEnforcement;
      rationale = 'The public task contract explicitly authorizes this narrowing control.';
    } else {
      compatibility = 'advisory';
      enforcement = 'advisory';
      rationale =
        'Contract-narrowing hardening defaults to advisory without an explicit public requirement.';
    }
  } else if (obligation.contractRelation === 'narrows') {
    if (obligation.publicRequirementRefs.length > 0) {
      compatibility = 'compatible';
      enforcement = obligation.requestedEnforcement;
      rationale = 'The public task contract explicitly requires the narrowing security behavior.';
    } else {
      compatibility = 'conflicting';
      enforcement = 'inactive';
      rationale =
        'A required security obligation cannot narrow accepted behavior without public authorization.';
    }
  } else {
    compatibility = 'compatible';
    enforcement = obligation.requestedEnforcement;
    rationale = 'The obligation preserves the frozen public task contract.';
  }

  return {
    policyId: obligation.policyId,
    obligationId: obligation.obligationId,
    guidance: obligation.guidance,
    controlKind: obligation.controlKind,
    contractRelation: obligation.contractRelation,
    requestedEnforcement: obligation.requestedEnforcement,
    compatibility,
    enforcement,
    evidenceRefs: obligation.evidenceRefs,
    activationFactIds: obligation.activationFactIds ?? [],
    publicRequirementRefs: obligation.publicRequirementRefs,
    rationale,
  };
}

export function buildPolicyActivationPlan(
  envelopeInput: CompatibilityEnvelope,
  obligationInputs: SelectedPolicyObligation[]
): PolicyActivationPlan {
  const envelope = normalizeEnvelope(envelopeInput);
  const obligations = obligationInputs
    .map(normalizeObligation)
    .sort((left, right): number => left.obligationId.localeCompare(right.obligationId));
  const obligationIds = obligations.map(
    (obligation: SelectedPolicyObligation): string => obligation.obligationId
  );
  if (new Set(obligationIds).size !== obligationIds.length) {
    throw new Error('Policy activation input contains duplicate obligation IDs');
  }

  const decisions = obligations.map(adjudicate);
  const unresolvedInputs = normalizeStrings(
    obligations.flatMap((obligation: SelectedPolicyObligation): string[] =>
      obligation.contractRelation === 'unknown' && obligation.unresolvedInput
        ? [obligation.unresolvedInput]
        : []
    ),
    'unresolvedInputs'
  );
  const blockingDecisionIds = decisions
    .filter(
      (decision: PolicyActivationDecision): boolean =>
        decision.enforcement === 'inactive' && decision.requestedEnforcement !== 'advisory'
    )
    .map((decision: PolicyActivationDecision): string => decision.obligationId);
  const unsignedPlan = {
    version: '0.1.0' as const,
    taskId: envelope.taskId,
    taskContractSha256: envelope.taskContractSha256,
    selectionSha256: stableSha256(obligations),
    compatibilityEnvelope: envelope,
    decisions,
    unresolvedInputs,
    blockingDecisionIds,
    status: blockingDecisionIds.length === 0 ? ('ready' as const) : ('blocked' as const),
  };
  return {
    ...unsignedPlan,
    activationSha256: stableSha256(unsignedPlan),
  };
}

export function compileActivationBindings(plan: PolicyActivationPlan): ActivationBindings {
  if (plan.status !== 'ready') {
    throw new Error(
      `Cannot compile blocked activation plan: ${plan.blockingDecisionIds.join(', ')}`
    );
  }
  const active = plan.decisions.filter(
    (decision: PolicyActivationDecision): decision is ActiveActivationDecision =>
      decision.enforcement !== 'inactive'
  );
  const required = active.filter(
    (decision: PolicyActivationDecision): boolean =>
      decision.enforcement === 'required' || decision.enforcement === 'fail_closed'
  );
  const advisory = active.filter(
    (decision: PolicyActivationDecision): boolean => decision.enforcement === 'advisory'
  );
  return {
    version: '0.1.0',
    taskId: plan.taskId,
    activationSha256: plan.activationSha256,
    requiredObligationIds: required.map(
      (decision: PolicyActivationDecision): string => decision.obligationId
    ),
    advisoryObligationIds: advisory.map(
      (decision: PolicyActivationDecision): string => decision.obligationId
    ),
    promptBindings: active.map(decision => ({
      obligationId: decision.obligationId,
      policyId: decision.policyId,
      enforcement: decision.enforcement,
      guidance: decision.guidance,
    })),
    evidenceRequirements: required.map(decision => ({
      obligationId: decision.obligationId,
      policyId: decision.policyId,
      evidenceRefs: decision.evidenceRefs,
      activationFactIds: decision.activationFactIds,
    })),
  };
}
