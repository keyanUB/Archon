import { createHash } from 'node:crypto';

export type PolicyRuntimeStatus =
  | 'dormant'
  | 'active'
  | 'satisfied'
  | 'violated'
  | 'uncertain'
  | 'inapplicable';

export type RuntimeEvidenceOutcome = 'pass' | 'fail' | 'inconclusive' | 'harness_error';

export const RUNTIME_SECURITY_FACT_IDS = [
  'archive_processing_modified',
  'dependency_manifest_modified',
  'process_execution_requested',
  'repair_modified_artifact',
  'service_configuration_modified',
] as const;

export type RuntimeSecurityFactId = (typeof RUNTIME_SECURITY_FACT_IDS)[number];
const runtimeSecurityFactIds = new Set<string>(RUNTIME_SECURITY_FACT_IDS);

export type RuntimeSecurityFactSource =
  | 'command_monitor'
  | 'diff_monitor'
  | 'runtime_monitor'
  | 'trajectory_monitor';

export interface RuntimePolicyDefinition {
  policyId: string;
  obligationId: string;
  requiredEvidence: string[];
  activationFactIds?: RuntimeSecurityFactId[];
  applicable?: boolean;
}

export interface RuntimePolicyObligation {
  policyId: string;
  obligationId: string;
  requiredEvidence: string[];
  activationFactIds: RuntimeSecurityFactId[];
  evidence: Record<string, RuntimeEvidenceOutcome>;
  status: PolicyRuntimeStatus;
}

export interface PolicyRuntimeState {
  version: '0.1.0';
  taskId: string;
  revision: number;
  nextSequence: number;
  activePolicyIds: string[];
  activeObligationIds: string[];
  obligations: RuntimePolicyObligation[];
  observedSecurityFacts: RuntimeObservedSecurityFact[];
  runtimeViolations: string[];
  runtimeUncertainties: string[];
  lastEventSha256: string | null;
}

interface RuntimeEventBase {
  version: '0.1.0';
  taskId: string;
  sequence: number;
  phase: string;
}

export interface RuntimeToolCallEvent extends RuntimeEventBase {
  kind: 'tool_call';
  toolName: string;
  inputSha256: string;
}

export interface RuntimeWorkspaceBoundaryEvent extends RuntimeEventBase {
  kind: 'workspace_boundary';
  logAvailable: boolean;
  changedPaths: string[];
  scopeViolations: string[];
}

export interface RuntimeProbeResultEvent extends RuntimeEventBase {
  kind: 'probe_result';
  policyId: string;
  obligationId: string;
  evidenceRef: string;
  outcome: RuntimeEvidenceOutcome;
}

export interface RuntimeSecurityFactEvent extends RuntimeEventBase {
  kind: 'security_fact';
  factId: RuntimeSecurityFactId;
  source: RuntimeSecurityFactSource;
  evidenceRef: string;
  subjectRefs: string[];
  subjectSha256: string;
}

export interface RuntimeObservedSecurityFact {
  factId: RuntimeSecurityFactId;
  source: RuntimeSecurityFactSource;
  evidenceRef: string;
  subjectRefs: string[];
  subjectSha256: string;
  phase: string;
}

export interface RuntimeLoopBoundaryEvent extends RuntimeEventBase {
  kind: 'loop_boundary';
  boundary: 'post_implementation' | 'post_repair' | 'pre_terminal';
  repairAvailable: boolean;
}

export type RuntimeObservationEvent =
  | RuntimeToolCallEvent
  | RuntimeWorkspaceBoundaryEvent
  | RuntimeSecurityFactEvent
  | RuntimeProbeResultEvent
  | RuntimeLoopBoundaryEvent;

export interface RuntimeIntervention {
  action: 'continue' | 'run_required_probe' | 'repair_guidance' | 'block';
  reason: string;
  policyIds: string[];
  obligationIds: string[];
  evidenceRefs: string[];
}

export interface PolicyStatusChange {
  policyId: string;
  obligationId: string;
  previous: PolicyRuntimeStatus;
  current: PolicyRuntimeStatus;
}

export interface PolicyDelta {
  eventSha256: string;
  priorStateSha256: string;
  nextStateSha256: string;
  changedPolicies: PolicyStatusChange[];
  interventions: RuntimeIntervention[];
}

export interface PolicyReductionResult {
  state: PolicyRuntimeState;
  delta: PolicyDelta;
}

export interface TrajectoryFactInput {
  phase: string;
  toolCalls: { toolName: string; inputSha256: string }[];
  changedPaths: string[];
}

export interface ExtractedSecurityFact {
  factId: RuntimeSecurityFactId;
  source: 'trajectory_monitor';
  evidenceRef: string;
  subjectRefs: string[];
  subjectSha256: string;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item: unknown): unknown => canonicalize(item));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]): number => left.localeCompare(right))
        .map(([key, item]): [string, unknown] => [key, canonicalize(item)])
    );
  }
  return value;
}

export function stableSha256(value: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(canonicalize(value)))
    .digest('hex');
}

function extractedFact(
  factId: RuntimeSecurityFactId,
  subjectRefs: string[],
  phase: string
): ExtractedSecurityFact {
  const normalizedRefs = [...new Set(subjectRefs)].sort();
  const subjectSha256 = stableSha256({ factId, subjectRefs: normalizedRefs });
  return {
    factId,
    source: 'trajectory_monitor',
    evidenceRef: `trajectory-fact:${factId}:${stableSha256({ phase, subjectSha256 }).slice(0, 16)}`,
    subjectRefs: normalizedRefs,
    subjectSha256,
  };
}

/** Extracts only facts supported by stable path and tool metadata. */
export function extractTrajectorySecurityFacts(
  input: TrajectoryFactInput
): ExtractedSecurityFact[] {
  const changedPaths = [...new Set(input.changedPaths)].sort();
  const toolCalls = [...input.toolCalls].sort((left, right): number =>
    `${left.toolName}:${left.inputSha256}`.localeCompare(`${right.toolName}:${right.inputSha256}`)
  );
  const facts: ExtractedSecurityFact[] = [];
  const archivePaths = changedPaths.filter((path: string): boolean =>
    /(?:^|[._/-])(archive|tar|zip)(?:[._/-]|$)/i.test(path)
  );
  if (archivePaths.length > 0) {
    facts.push(extractedFact('archive_processing_modified', archivePaths, input.phase));
  }
  const dependencyPaths = changedPaths.filter((path: string): boolean =>
    /(?:^|\/)(?:package\.json|bun\.lockb?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|pyproject\.toml|requirements[^/]*\.txt|poetry\.lock|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock)$/i.test(
      path
    )
  );
  if (dependencyPaths.length > 0) {
    facts.push(extractedFact('dependency_manifest_modified', dependencyPaths, input.phase));
  }
  const servicePaths = changedPaths.filter((path: string): boolean =>
    /(?:\.service|docker-compose[^/]*\.ya?ml|compose\.ya?ml|nginx[^/]*\.conf|supervisord?[^/]*\.conf)$/i.test(
      path
    )
  );
  if (servicePaths.length > 0) {
    facts.push(extractedFact('service_configuration_modified', servicePaths, input.phase));
  }
  const processCalls = toolCalls.filter((call): boolean =>
    /^(?:bash|shell|process|terminal)$/i.test(call.toolName)
  );
  if (processCalls.length > 0) {
    facts.push(
      extractedFact(
        'process_execution_requested',
        processCalls.map((call): string => `${call.toolName}:${call.inputSha256}`),
        input.phase
      )
    );
  }
  if (/repair/i.test(input.phase) && changedPaths.length > 0) {
    facts.push(extractedFact('repair_modified_artifact', changedPaths, input.phase));
  }
  return facts.sort((left, right): number => left.factId.localeCompare(right.factId));
}

function derivePolicyStatus(obligation: RuntimePolicyObligation): PolicyRuntimeStatus {
  if (obligation.status === 'dormant' || obligation.status === 'inapplicable') {
    return obligation.status;
  }
  const outcomes = obligation.requiredEvidence.map(
    (evidenceRef: string): RuntimeEvidenceOutcome | undefined => obligation.evidence[evidenceRef]
  );
  if (outcomes.includes('fail')) {
    return 'violated';
  }
  if (outcomes.includes('inconclusive') || outcomes.includes('harness_error')) {
    return 'uncertain';
  }
  if (outcomes.length > 0 && outcomes.every((outcome): boolean => outcome === 'pass')) {
    return 'satisfied';
  }
  return 'active';
}

export function createPolicyRuntimeState(
  taskId: string,
  definitions: RuntimePolicyDefinition[]
): PolicyRuntimeState {
  if (taskId.length === 0) {
    throw new Error('Policy runtime state requires a task ID');
  }
  const policyIds = definitions.map((definition: RuntimePolicyDefinition): string =>
    definition.policyId.trim()
  );
  const obligationIds = definitions.map((definition: RuntimePolicyDefinition): string =>
    definition.obligationId.trim()
  );
  if (policyIds.some((policyId: string): boolean => policyId.length === 0)) {
    throw new Error('Policy runtime definitions require non-empty policy IDs');
  }
  if (obligationIds.some((obligationId: string): boolean => obligationId.length === 0)) {
    throw new Error('Policy runtime definitions require non-empty obligation IDs');
  }
  if (new Set(obligationIds).size !== obligationIds.length) {
    throw new Error('Policy runtime definitions contain duplicate obligation IDs');
  }

  const obligations = definitions
    .map((definition: RuntimePolicyDefinition): RuntimePolicyObligation => {
      const requiredEvidence = [...new Set(definition.requiredEvidence)].sort();
      const activationFactIds = [...new Set(definition.activationFactIds ?? [])].sort();
      if (activationFactIds.some(factId => !runtimeSecurityFactIds.has(factId))) {
        throw new Error(`${definition.obligationId}: unknown activation security fact`);
      }
      if (definition.applicable !== false && requiredEvidence.length === 0) {
        throw new Error(`${definition.policyId}: active policy requires evidence`);
      }
      return {
        policyId: definition.policyId,
        obligationId: definition.obligationId,
        requiredEvidence,
        activationFactIds,
        evidence: {},
        status:
          definition.applicable === false
            ? 'inapplicable'
            : activationFactIds.length > 0
              ? 'dormant'
              : 'active',
      };
    })
    .sort((left, right): number => left.obligationId.localeCompare(right.obligationId));

  return {
    version: '0.1.0',
    taskId,
    revision: 0,
    nextSequence: 0,
    activePolicyIds: [
      ...new Set(
        obligations
          .filter((obligation: RuntimePolicyObligation): boolean => obligation.status === 'active')
          .map((obligation: RuntimePolicyObligation): string => obligation.policyId)
      ),
    ].sort(),
    activeObligationIds: obligations
      .filter((obligation: RuntimePolicyObligation): boolean => obligation.status === 'active')
      .map((obligation: RuntimePolicyObligation): string => obligation.obligationId),
    obligations,
    observedSecurityFacts: [],
    runtimeViolations: [],
    runtimeUncertainties: [],
    lastEventSha256: null,
  };
}

function loopInterventions(
  state: PolicyRuntimeState,
  repairAvailable: boolean
): RuntimeIntervention[] {
  if (state.runtimeViolations.length > 0) {
    return [
      {
        action: 'block',
        reason: 'Runtime boundary violation requires terminal blocking.',
        policyIds: [],
        obligationIds: [],
        evidenceRefs: [...state.runtimeViolations],
      },
    ];
  }
  if (state.runtimeUncertainties.length > 0) {
    return [
      {
        action: 'block',
        reason: 'Runtime evidence is unavailable or untrusted.',
        policyIds: [],
        obligationIds: [],
        evidenceRefs: [...state.runtimeUncertainties],
      },
    ];
  }

  const uncertain = state.obligations.filter(
    (obligation: RuntimePolicyObligation): boolean => obligation.status === 'uncertain'
  );
  if (uncertain.length > 0) {
    return [
      {
        action: 'block',
        reason: 'Required policy evidence is inconclusive or the harness failed.',
        policyIds: uncertain.map(
          (obligation: RuntimePolicyObligation): string => obligation.policyId
        ),
        obligationIds: uncertain.map(
          (obligation: RuntimePolicyObligation): string => obligation.obligationId
        ),
        evidenceRefs: uncertain.flatMap(
          (obligation: RuntimePolicyObligation): string[] => obligation.requiredEvidence
        ),
      },
    ];
  }

  const violated = state.obligations.filter(
    (obligation: RuntimePolicyObligation): boolean => obligation.status === 'violated'
  );
  if (violated.length > 0) {
    return [
      {
        action: repairAvailable ? 'repair_guidance' : 'block',
        reason: repairAvailable
          ? 'Required policy evidence is violated and one bounded repair is available.'
          : 'Required policy evidence is violated and no repair remains.',
        policyIds: violated.map(
          (obligation: RuntimePolicyObligation): string => obligation.policyId
        ),
        obligationIds: violated.map(
          (obligation: RuntimePolicyObligation): string => obligation.obligationId
        ),
        evidenceRefs: violated.flatMap(
          (obligation: RuntimePolicyObligation): string[] => obligation.requiredEvidence
        ),
      },
    ];
  }

  const active = state.obligations.filter(
    (obligation: RuntimePolicyObligation): boolean => obligation.status === 'active'
  );
  if (active.length > 0) {
    return [
      {
        action: 'run_required_probe',
        reason: 'Required policy evidence is missing.',
        policyIds: active.map((obligation: RuntimePolicyObligation): string => obligation.policyId),
        obligationIds: active.map(
          (obligation: RuntimePolicyObligation): string => obligation.obligationId
        ),
        evidenceRefs: active.flatMap((obligation: RuntimePolicyObligation): string[] =>
          obligation.requiredEvidence.filter(
            (evidenceRef: string): boolean => obligation.evidence[evidenceRef] === undefined
          )
        ),
      },
    ];
  }

  return [
    {
      action: 'continue',
      reason: 'All active policy obligations are satisfied.',
      policyIds: [...state.activePolicyIds],
      obligationIds: [...state.activeObligationIds],
      evidenceRefs: [],
    },
  ];
}

export function reducePolicyRuntimeState(
  state: PolicyRuntimeState,
  event: RuntimeObservationEvent
): PolicyReductionResult {
  if (event.taskId !== state.taskId) {
    throw new Error(`Runtime event task ${event.taskId} does not match ${state.taskId}`);
  }
  if (event.sequence !== state.nextSequence) {
    throw new Error(
      `Runtime event sequence ${String(event.sequence)} does not match expected ${String(state.nextSequence)}`
    );
  }

  const priorStateSha256 = stableSha256(state);
  const obligations = state.obligations.map(
    (obligation: RuntimePolicyObligation): RuntimePolicyObligation => ({
      ...obligation,
      requiredEvidence: [...obligation.requiredEvidence],
      activationFactIds: [...obligation.activationFactIds],
      evidence: { ...obligation.evidence },
    })
  );
  let runtimeViolations = [...state.runtimeViolations];
  let runtimeUncertainties = [...state.runtimeUncertainties];
  let observedSecurityFacts = state.observedSecurityFacts.map(
    (fact: RuntimeObservedSecurityFact): RuntimeObservedSecurityFact => ({
      ...fact,
      subjectRefs: [...fact.subjectRefs],
    })
  );

  if (event.kind === 'probe_result') {
    const obligation = obligations.find(
      (candidate: RuntimePolicyObligation): boolean => candidate.obligationId === event.obligationId
    );
    if (
      obligation?.policyId !== event.policyId ||
      obligation.status === 'dormant' ||
      obligation.status === 'inapplicable'
    ) {
      throw new Error(`${event.obligationId}: probe event targets a non-active policy obligation`);
    }
    if (!obligation.requiredEvidence.includes(event.evidenceRef)) {
      throw new Error(`${event.obligationId}: unknown evidence reference ${event.evidenceRef}`);
    }
    if (obligation.evidence[event.evidenceRef] !== undefined) {
      throw new Error(`${event.obligationId}: duplicate evidence reference ${event.evidenceRef}`);
    }
    obligation.evidence[event.evidenceRef] = event.outcome;
    obligation.status = derivePolicyStatus(obligation);
  } else if (event.kind === 'security_fact') {
    if (!runtimeSecurityFactIds.has(event.factId)) {
      throw new Error(`Unknown runtime security fact ${event.factId}`);
    }
    if (event.evidenceRef.trim().length === 0) {
      throw new Error('Security fact evidence reference must be non-empty');
    }
    if (!/^[a-f0-9]{64}$/.test(event.subjectSha256)) {
      throw new Error('Security fact subjectSha256 must be a lowercase SHA-256 digest');
    }
    const normalizedRefs = [...new Set(event.subjectRefs)].sort();
    if (
      normalizedRefs.length === 0 ||
      stableSha256(normalizedRefs) !== stableSha256(event.subjectRefs)
    ) {
      throw new Error('Security fact subject references must be non-empty, unique, and sorted');
    }
    if (
      event.subjectSha256 !== stableSha256({ factId: event.factId, subjectRefs: normalizedRefs })
    ) {
      throw new Error('Security fact subjectSha256 does not match its fact and subject references');
    }
    const existingFact = observedSecurityFacts.find(fact => fact.evidenceRef === event.evidenceRef);
    if (existingFact) {
      const repeatedFact = {
        factId: event.factId,
        source: event.source,
        evidenceRef: event.evidenceRef,
        subjectRefs: normalizedRefs,
        subjectSha256: event.subjectSha256,
        phase: event.phase,
      };
      if (stableSha256(existingFact) !== stableSha256(repeatedFact)) {
        throw new Error(`Security fact evidence reference collision ${event.evidenceRef}`);
      }
    } else {
      observedSecurityFacts = [
        ...observedSecurityFacts,
        {
          factId: event.factId,
          source: event.source,
          evidenceRef: event.evidenceRef,
          subjectRefs: normalizedRefs,
          subjectSha256: event.subjectSha256,
          phase: event.phase,
        },
      ];
    }
    for (const obligation of obligations) {
      if (obligation.status === 'dormant' && obligation.activationFactIds.includes(event.factId)) {
        obligation.status = 'active';
      }
    }
  } else if (event.kind === 'workspace_boundary') {
    runtimeViolations = [...new Set([...runtimeViolations, ...event.scopeViolations])].sort();
    if (!event.logAvailable) {
      runtimeUncertainties = [
        ...new Set([...runtimeUncertainties, 'trajectory_log_unavailable']),
      ].sort();
    }
  }

  const eventSha256 = stableSha256(event);
  const activeObligations = obligations.filter(
    (obligation: RuntimePolicyObligation): boolean =>
      obligation.status !== 'dormant' && obligation.status !== 'inapplicable'
  );
  const nextState: PolicyRuntimeState = {
    ...state,
    revision: state.revision + 1,
    nextSequence: state.nextSequence + 1,
    activePolicyIds: [...new Set(activeObligations.map(obligation => obligation.policyId))].sort(),
    activeObligationIds: activeObligations.map(obligation => obligation.obligationId).sort(),
    obligations,
    observedSecurityFacts,
    runtimeViolations,
    runtimeUncertainties,
    lastEventSha256: eventSha256,
  };
  const changedPolicies = state.obligations.flatMap(
    (previous: RuntimePolicyObligation, index: number): PolicyStatusChange[] => {
      const current = nextState.obligations[index];
      return current && current.status !== previous.status
        ? [
            {
              policyId: previous.policyId,
              obligationId: previous.obligationId,
              previous: previous.status,
              current: current.status,
            },
          ]
        : [];
    }
  );
  const interventions =
    event.kind === 'loop_boundary' ? loopInterventions(nextState, event.repairAvailable) : [];

  return {
    state: nextState,
    delta: {
      eventSha256,
      priorStateSha256,
      nextStateSha256: stableSha256(nextState),
      changedPolicies,
      interventions,
    },
  };
}

export function replayPolicyRuntime(
  initialState: PolicyRuntimeState,
  events: RuntimeObservationEvent[]
): { state: PolicyRuntimeState; deltas: PolicyDelta[] } {
  let state = initialState;
  const deltas: PolicyDelta[] = [];
  for (const event of events) {
    const result = reducePolicyRuntimeState(state, event);
    state = result.state;
    deltas.push(result.delta);
  }
  return { state, deltas };
}
