import { readFile } from 'fs/promises';

import type {
  PolicyProposal,
  PolicyRecord,
  PolicySelectionBudget,
  PolicySelectionDecision,
  PolicySelectionDelta,
  SelectedPolicyDecision,
  TaskSurface,
} from './pgacs-types.ts';

interface RawPolicy {
  policy_id: string;
  source: string;
  setup_env_theme?: string;
  scope?: string;
  policy_description: string;
  definition?: string[];
  reference?: string[];
}

interface RawPolicyCorpus {
  _metadata?: Record<string, unknown>;
  policies: RawPolicy[];
}

interface CoreSecurityFloorCorpus {
  version: string;
  policies: PolicyRecord[];
}

const POLICY_RECORD_ARRAY_FIELDS = [
  'sourcePrinciples',
  'riskTags',
  'cweTags',
  'taskTriggers',
  'inputChannels',
  'dangerousSinks',
  'assetTags',
  'trustBoundaryTags',
  'dependencyTags',
  'environmentTags',
  'phaseBindings',
  'validators',
  'evidenceRequirements',
  'forbiddenWorkarounds',
] as const;

export const CORE_SECURITY_FLOOR_POLICY_IDS = [
  'core:security-surface-discovery',
  'core:fail-safe-implementation',
  'core:evidence-based-validation',
] as const;

const THEME_TAGS: Record<string, string[]> = {
  dependency_supply_chain: ['supply_chain', 'dependency_integrity'],
  build_release_integrity: ['build_integrity', 'release_integrity'],
  config_hardening: ['configuration_hardening', 'secure_defaults'],
  secrets_key_management: ['secrets', 'key_management'],
  least_privilege_access: ['least_privilege', 'access_control'],
  transport_network_config: ['network_hardening', 'transport_security'],
  endpoint_runtime_hardening: ['runtime_hardening', 'sandboxing'],
  logging_monitoring_setup: ['logging', 'monitoring', 'auditability'],
  process_lifecycle: ['process_controls', 'process_lifecycle'],
  other_setup_env: ['setup_security'],
};

const KEYWORD_TAGS: { keywords: string[]; tags: string[] }[] = [
  {
    keywords: ['sandbox', 'jail', 'isolation', 'container'],
    tags: ['sandboxing', 'process_isolation', 'filesystem_isolation'],
  },
  {
    keywords: ['dependency', 'package', 'sbom', 'provenance', 'pin'],
    tags: ['supply_chain', 'dependency_management'],
  },
  {
    keywords: ['secret', 'key', 'credential', 'token', 'password'],
    tags: ['secrets', 'credential_protection'],
  },
  {
    keywords: ['allowlist', 'deny', 'default deny', 'acl', 'access control'],
    tags: ['access_control', 'least_privilege'],
  },
  {
    keywords: ['tls', 'ssh', 'http', 'network', 'port', 'bind', 'listen'],
    tags: ['network_security', 'runtime_exposure'],
  },
  {
    keywords: ['logging', 'monitoring', 'audit', 'telemetry'],
    tags: ['observability', 'auditability'],
  },
  {
    keywords: ['build', 'release', 'pipeline', 'artifact', 'provenance'],
    tags: ['build_integrity', 'release_integrity'],
  },
];

const DIFFUSE_PHASES = ['inspection', 'implementation', 'verification'];
const RUNTIME_PHASES = ['inspection', 'verification_runtime', 'final_reporting'];
const TASK_FAMILY_TRIGGER_HINTS: Partial<Record<TaskSurface['taskFamily'], string[]>> = {
  environment_setup: [
    'endpoint_runtime_hardening',
    'least_privilege_access',
    'transport_network_config',
    'config_hardening',
    'dependency_supply_chain',
    'secrets_key_management',
    'logging_monitoring_setup',
    'build_release_integrity',
    'process_lifecycle',
  ],
  dependency_build: ['dependency_supply_chain', 'build_release_integrity', 'process_lifecycle'],
  web_api: ['config_hardening', 'transport_network_config', 'least_privilege_access'],
  auth_session: ['secrets_key_management', 'least_privilege_access', 'config_hardening'],
  agent_tooling: ['endpoint_runtime_hardening', 'least_privilege_access', 'process_lifecycle'],
};

const SELECTOR_VERSION = '0.2.0';

const REASSESSMENT_TRIGGERS = [
  'authentication_or_secret_handling_observed',
  'dependency_added',
  'filesystem_operation_observed',
  'network_request_observed',
  'service_exposure_observed',
  'shell_or_process_execution_observed',
  'sql_or_database_operation_observed',
];

interface MandatoryRule {
  id: string;
  applies: (surface: TaskSurface) => boolean;
  policyMatches: (policy: PolicyRecord) => boolean;
  rationale: string;
}

interface ScoredPolicy {
  policy: PolicyRecord;
  score: number;
  matchedSurface: string[];
  rationale: string[];
}

const MANDATORY_RULES: MandatoryRule[] = [
  {
    id: 'untrusted-shell-command',
    applies: surface =>
      surface.trustBoundaries.includes('untrusted_input') &&
      surface.dangerousSinks.includes('shell_command'),
    policyMatches: policy =>
      policy.riskTags.includes('command_injection') || policy.cweTags.includes('CWE-78'),
    rationale: 'untrusted input reaches a shell-command sink',
  },
  {
    id: 'untrusted-filesystem',
    applies: surface =>
      surface.trustBoundaries.includes('untrusted_input') &&
      surface.dangerousSinks.includes('filesystem'),
    policyMatches: policy =>
      policy.riskTags.includes('path_traversal') || policy.cweTags.includes('CWE-22'),
    rationale: 'untrusted input reaches a filesystem sink',
  },
  {
    id: 'runtime-network-exposure',
    applies: surface =>
      surface.runtimeExposure.some(value =>
        ['port_binding', 'remote_access', 'service_start'].includes(value)
      ),
    policyMatches: policy =>
      policy.taskTriggers.includes('runtime_network') ||
      policy.riskTags.some(tag =>
        [
          'network_hardening',
          'network_security',
          'runtime_hardening',
          'transport_security',
        ].includes(tag)
      ),
    rationale: 'the task starts or exposes a network-accessible runtime service',
  },
  {
    id: 'secret-boundary',
    applies: surface =>
      surface.assets.includes('secrets') || surface.trustBoundaries.includes('secret_boundary'),
    policyMatches: policy =>
      policy.riskTags.some(tag =>
        ['credential_protection', 'key_management', 'secrets'].includes(tag)
      ),
    rationale: 'the task handles credentials or crosses a secret boundary',
  },
  {
    id: 'dependency-integrity',
    applies: surface =>
      surface.taskFamily === 'dependency_build' ||
      surface.assets.includes('dependencies') ||
      surface.dependencies.length > 0,
    policyMatches: policy =>
      policy.riskTags.some(tag =>
        ['dependency_integrity', 'dependency_management', 'supply_chain'].includes(tag)
      ),
    rationale: 'the task changes or builds dependencies',
  },
];

function unique(values: string[]): string[] {
  return [...new Set(values.filter(value => value.length > 0))].sort();
}

function normalizeText(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
}

function keywordMatches(text: string, keywords: string[]): boolean {
  const paddedText = ` ${normalizeText(text)} `;
  return keywords.some(keyword => paddedText.includes(` ${normalizeText(keyword)} `));
}

function inferThemeTags(theme: string | undefined): string[] {
  if (!theme) return [];
  return THEME_TAGS[theme] ?? [theme];
}

function inferKeywordTags(description: string): string[] {
  const lower = normalizeText(description);
  const tags: string[] = [];
  for (const { keywords, tags: mappedTags } of KEYWORD_TAGS) {
    if (keywordMatches(lower, keywords)) tags.push(...mappedTags);
  }
  return tags;
}

function inferDangerousSinks(description: string): string[] {
  const lower = normalizeText(description);
  const sinks: string[] = [];
  if (keywordMatches(lower, ['shell', 'command', 'exec', 'spawn'])) sinks.push('shell_command');
  if (keywordMatches(lower, ['path', 'file', 'filesystem', 'directory'])) sinks.push('filesystem');
  if (keywordMatches(lower, ['sql', 'database', 'query'])) sinks.push('database');
  if (keywordMatches(lower, ['http', 'ssh', 'tls', 'port', 'network'])) sinks.push('network');
  if (keywordMatches(lower, ['secret', 'key', 'token', 'credential'])) sinks.push('secrets');
  return unique(sinks);
}

function inferAssetTags(description: string): string[] {
  const lower = normalizeText(description);
  const assets: string[] = [];
  if (keywordMatches(lower, ['secret', 'key', 'token', 'credential'])) assets.push('secrets');
  if (keywordMatches(lower, ['file', 'path', 'filesystem', 'directory'])) assets.push('filesystem');
  if (keywordMatches(lower, ['network', 'port', 'http', 'ssh', 'tls'])) assets.push('network');
  if (keywordMatches(lower, ['build', 'package', 'sbom', 'provenance']))
    assets.push('build_artifacts');
  if (keywordMatches(lower, ['log', 'monitor', 'audit'])) assets.push('observability');
  return unique(assets);
}

function inferTrustBoundaries(description: string): string[] {
  const lower = normalizeText(description);
  const boundaries: string[] = [];
  if (keywordMatches(lower, ['user input', 'input', 'external']))
    boundaries.push('untrusted_input');
  if (keywordMatches(lower, ['network', 'http', 'ssh', 'port']))
    boundaries.push('network_boundary');
  if (keywordMatches(lower, ['filesystem', 'path', 'file'])) boundaries.push('workspace_boundary');
  if (keywordMatches(lower, ['secret', 'key', 'credential'])) boundaries.push('secret_boundary');
  if (keywordMatches(lower, ['build', 'release', 'artifact']))
    boundaries.push('supply_chain_boundary');
  return unique(boundaries);
}

function inferEnvironmentTags(description: string, theme: string | undefined): string[] {
  const lower = normalizeText(description);
  const tags: string[] = [];
  if (theme) tags.push(theme);
  if (keywordMatches(lower, ['sandbox', 'jail', 'container'])) tags.push('sandboxed_execution');
  if (keywordMatches(lower, ['dependency', 'package', 'provenance']))
    tags.push('dependency_management');
  if (keywordMatches(lower, ['tls', 'ssh', 'network', 'port'])) tags.push('runtime_network');
  if (keywordMatches(lower, ['logging', 'monitoring'])) tags.push('operational_observability');
  return unique(tags);
}

function inferTaskTriggers(description: string, theme: string | undefined): string[] {
  const lower = normalizeText(description);
  const triggers: string[] = [];
  if (theme) triggers.push(theme);
  if (keywordMatches(lower, ['sandbox', 'jail', 'isolation'])) triggers.push('runtime_isolation');
  if (keywordMatches(lower, ['dependency', 'package', 'sbom', 'provenance']))
    triggers.push('dependency_change');
  if (keywordMatches(lower, ['secret', 'key', 'token'])) triggers.push('secret_handling');
  if (keywordMatches(lower, ['port', 'network', 'ssh', 'http', 'tls']))
    triggers.push('runtime_network');
  if (keywordMatches(lower, ['logging', 'monitoring'])) triggers.push('observability');
  if (keywordMatches(lower, ['restart', 'persistent', 'supervised', 'lifecycle'])) {
    triggers.push('process_lifecycle');
  }
  return unique(triggers);
}

function inferSeverity(description: string, theme: string | undefined): PolicyRecord['severity'] {
  const lower = normalizeText(description);
  if (
    keywordMatches(lower, ['default deny', 'least privilege', 'sandbox', 'jail', 'secret', 'key'])
  ) {
    return 'fail_closed';
  }
  if (
    theme &&
    ['endpoint_runtime_hardening', 'least_privilege_access', 'secrets_key_management'].includes(
      theme
    )
  ) {
    return 'fail_closed';
  }
  if (keywordMatches(lower, ['dependency', 'build', 'release', 'tls', 'monitor'])) {
    return 'required';
  }
  return 'advisory';
}

function inferForbiddenWorkarounds(description: string): string[] {
  const lower = normalizeText(description);
  const forbiddens: string[] = [];
  if (keywordMatches(lower, ['sandbox', 'jail', 'isolation'])) {
    forbiddens.push('disable sandboxing to make the task pass');
  }
  if (keywordMatches(lower, ['least privilege', 'access control', 'default deny'])) {
    forbiddens.push('broaden privileges instead of fixing authorization');
  }
  if (keywordMatches(lower, ['dependency', 'provenance'])) {
    forbiddens.push('install unpinned or untrusted dependencies');
  }
  if (keywordMatches(lower, ['secret', 'key', 'token'])) {
    forbiddens.push('hardcode secrets in source or logs');
  }
  if (keywordMatches(lower, ['tls', 'ssh', 'network', 'port'])) {
    forbiddens.push('fall back to insecure transport or open bindings');
  }
  return unique(forbiddens);
}

function inferEvidenceRequirements(description: string): string[] {
  const lower = normalizeText(description);
  const evidence: string[] = ['diff', 'command'];
  if (keywordMatches(lower, ['build', 'release', 'dependency'])) evidence.push('build');
  if (keywordMatches(lower, ['test', 'monitor', 'runtime', 'network', 'service']))
    evidence.push('probe');
  if (keywordMatches(lower, ['secret', 'key', 'credential'])) evidence.push('static_scan');
  return unique(evidence);
}

function inferPhaseBindings(description: string, theme: string | undefined): string[] {
  const lower = normalizeText(description);
  const phases = new Set<string>(DIFFUSE_PHASES);
  if (keywordMatches(lower, ['sandbox', 'jail', 'network', 'service', 'port'])) {
    RUNTIME_PHASES.forEach(phase => phases.add(phase));
  }
  if (keywordMatches(lower, ['dependency', 'build', 'release'])) {
    phases.add('verification_build');
  }
  if (keywordMatches(lower, ['test', 'monitor', 'audit'])) {
    phases.add('verification_test');
  }
  if (theme === 'endpoint_runtime_hardening' || theme === 'transport_network_config') {
    phases.add('verification_runtime');
  }
  return [...phases].sort();
}

export async function loadPolicyCorpus(filePath: string): Promise<RawPolicyCorpus> {
  const raw = await readFile(filePath, 'utf-8');
  const parsed = JSON.parse(raw) as RawPolicyCorpus;
  if (!parsed || !Array.isArray(parsed.policies)) {
    throw new Error(`Invalid policy corpus at ${filePath}: expected { policies: [] }`);
  }
  return parsed;
}

export async function loadCoreSecurityFloor(filePath: string): Promise<PolicyRecord[]> {
  const raw = await readFile(filePath, 'utf-8');
  const parsed = JSON.parse(raw) as Partial<CoreSecurityFloorCorpus>;
  if (!parsed || typeof parsed.version !== 'string' || !Array.isArray(parsed.policies)) {
    throw new Error(`Invalid core security floor at ${filePath}`);
  }
  for (const [index, policy] of parsed.policies.entries()) {
    const validScalarFields =
      typeof policy?.id === 'string' &&
      typeof policy.title === 'string' &&
      typeof policy.version === 'string' &&
      typeof policy.normativeText === 'string' &&
      ['advisory', 'required', 'fail_closed'].includes(policy.severity);
    const validArrayFields = POLICY_RECORD_ARRAY_FIELDS.every(field =>
      Array.isArray(policy?.[field])
    );
    const validSources =
      Array.isArray(policy?.sourcePrinciples) &&
      policy.sourcePrinciples.length > 0 &&
      policy.sourcePrinciples.every(
        source => typeof source.source === 'string' && typeof source.text === 'string'
      );
    if (!validScalarFields || !validArrayFields || !validSources) {
      throw new Error(`Invalid core security-floor policy at index ${index} in ${filePath}`);
    }
  }
  const ids = new Set(parsed.policies.map(policy => policy.id));
  for (const policyId of CORE_SECURITY_FLOOR_POLICY_IDS) {
    if (!ids.has(policyId)) {
      throw new Error(`Core security floor is missing policy ${policyId}`);
    }
  }
  if (
    parsed.policies.length !== CORE_SECURITY_FLOOR_POLICY_IDS.length ||
    ids.size !== CORE_SECURITY_FLOOR_POLICY_IDS.length
  ) {
    throw new Error('Core security floor must contain exactly the three required policies');
  }
  return parsed.policies;
}

export function normalizePolicyRegistry(corpus: RawPolicyCorpus): PolicyRecord[] {
  return corpus.policies.map(policy => {
    const description = policy.policy_description.trim();
    const sourcePrinciples = [
      {
        source: policy.source,
        ref: policy.policy_id,
        text: description,
      },
    ];
    const riskTags = unique([
      ...inferThemeTags(policy.setup_env_theme),
      ...inferKeywordTags(description),
    ]);
    const cweTags = unique(
      (policy.reference ?? []).filter(reference => /^CWE-\d+$/u.test(reference))
    );

    return {
      id: policy.policy_id,
      title: `${policy.policy_id}: ${description.slice(0, 72)}`,
      version: '1.0.0',
      sourcePrinciples,
      normativeText: description,
      riskTags,
      cweTags,
      taskTriggers: inferTaskTriggers(description, policy.setup_env_theme),
      inputChannels: unique(
        inferAssetTags(description).flatMap(tag => {
          switch (tag) {
            case 'network':
              return ['network'];
            case 'filesystem':
              return ['filesystem'];
            case 'secrets':
              return ['env', 'filesystem'];
            case 'build_artifacts':
              return ['package', 'build'];
            case 'observability':
              return ['logs', 'metrics'];
            default:
              return [];
          }
        })
      ),
      dangerousSinks: inferDangerousSinks(description),
      assetTags: inferAssetTags(description),
      trustBoundaryTags: inferTrustBoundaries(description),
      dependencyTags:
        policy.setup_env_theme === 'dependency_supply_chain' ? ['dependency_integrity'] : [],
      environmentTags: inferEnvironmentTags(description, policy.setup_env_theme),
      phaseBindings: inferPhaseBindings(description, policy.setup_env_theme),
      validators: [],
      evidenceRequirements: inferEvidenceRequirements(description),
      forbiddenWorkarounds: inferForbiddenWorkarounds(description),
      severity: inferSeverity(description, policy.setup_env_theme),
    };
  });
}

function addOverlap(
  label: string,
  policyValues: string[],
  surfaceValues: string[],
  weight: number,
  matchedSurface: string[],
  rationale: string[]
): number {
  const matches = unique(policyValues.filter(value => surfaceValues.includes(value)));
  if (matches.length === 0) return 0;
  matchedSurface.push(...matches.map(value => `${label}:${value}`));
  rationale.push(`${label} match: ${matches.join(', ')}`);
  return matches.length * weight;
}

function scorePolicy(
  policy: PolicyRecord,
  surface: TaskSurface,
  proposal: PolicyProposal | undefined
): ScoredPolicy {
  const familyHints = TASK_FAMILY_TRIGGER_HINTS[surface.taskFamily] ?? [];
  const matchedSurface: string[] = [];
  const rationale: string[] = [];
  let score = 0;

  score += addOverlap('cwe', policy.cweTags, surface.likelyCwes, 8, matchedSurface, rationale);
  score += addOverlap(
    'sink',
    policy.dangerousSinks,
    surface.dangerousSinks,
    6,
    matchedSurface,
    rationale
  );
  score += addOverlap(
    'trust_boundary',
    policy.trustBoundaryTags,
    surface.trustBoundaries,
    5,
    matchedSurface,
    rationale
  );
  score += addOverlap('asset', policy.assetTags, surface.assets, 4, matchedSurface, rationale);
  score += addOverlap(
    'input_channel',
    policy.inputChannels,
    surface.inputChannels,
    3,
    matchedSurface,
    rationale
  );
  score += addOverlap(
    'environment',
    [...policy.taskTriggers, ...policy.environmentTags],
    [...surface.environmentConstraints, ...surface.runtimeExposure],
    3,
    matchedSurface,
    rationale
  );
  score += addOverlap(
    'task_family',
    [...policy.riskTags, ...policy.taskTriggers, ...policy.environmentTags],
    familyHints,
    4,
    matchedSurface,
    rationale
  );

  if (policy.phaseBindings.includes('verification_runtime') && surface.runtimeExposure.length > 0) {
    score += 2;
    matchedSurface.push('phase:verification_runtime');
    rationale.push('runtime exposure requires runtime verification');
  }
  if (
    policy.phaseBindings.includes('verification_build') &&
    surface.taskFamily === 'dependency_build'
  ) {
    score += 2;
    matchedSurface.push('phase:verification_build');
    rationale.push('dependency/build task requires build verification');
  }
  if (proposal) {
    const boundedConfidence = Math.max(0, Math.min(1, proposal.confidence));
    score += boundedConfidence * 2;
    rationale.push(
      `LLM proposed candidate (${boundedConfidence.toFixed(2)}): ${proposal.rationale}`
    );
  }

  return {
    policy,
    score,
    matchedSurface: unique(matchedSurface),
    rationale,
  };
}

function validateSelectionInputs(
  policies: PolicyRecord[],
  budget: PolicySelectionBudget
): Map<string, PolicyRecord> {
  if (!Number.isInteger(budget.maxPolicies) || budget.maxPolicies < 1) {
    throw new Error('Policy selection maxPolicies must be a positive integer');
  }
  const registry = new Map<string, PolicyRecord>();
  for (const policy of policies) {
    if (registry.has(policy.id)) {
      throw new Error(`Duplicate policy id in registry: ${policy.id}`);
    }
    registry.set(policy.id, policy);
  }
  for (const policyId of CORE_SECURITY_FLOOR_POLICY_IDS) {
    if (!registry.has(policyId)) {
      throw new Error(`Policy registry is missing core security-floor policy ${policyId}`);
    }
  }
  return registry;
}

export function selectPolicyDecision(
  policies: PolicyRecord[],
  surface: TaskSurface,
  budget: PolicySelectionBudget = { maxPolicies: 8 },
  proposals: PolicyProposal[] = []
): PolicySelectionDecision {
  const registry = validateSelectionInputs(policies, budget);
  const fallbackPolicies = CORE_SECURITY_FLOOR_POLICY_IDS.map(policyId => {
    const policy = registry.get(policyId);
    if (!policy)
      throw new Error(`Policy registry is missing core security-floor policy ${policyId}`);
    return policy;
  });
  const specificPolicies = policies.filter(
    policy =>
      !CORE_SECURITY_FLOOR_POLICY_IDS.includes(
        policy.id as (typeof CORE_SECURITY_FLOOR_POLICY_IDS)[number]
      )
  );
  const proposalById = new Map<string, PolicyProposal>();
  const rejected: PolicySelectionDecision['rejected'] = [];

  for (const proposal of proposals) {
    if (!registry.has(proposal.policyId)) {
      rejected.push({ policyId: proposal.policyId, score: 0, reason: 'invalid_proposal' });
      continue;
    }
    const existing = proposalById.get(proposal.policyId);
    if (!existing || proposal.confidence > existing.confidence) {
      proposalById.set(proposal.policyId, proposal);
    }
  }

  const scored = specificPolicies
    .map(policy => scorePolicy(policy, surface, proposalById.get(policy.id)))
    .sort(
      (left, right) => right.score - left.score || left.policy.id.localeCompare(right.policy.id)
    );
  const scoredById = new Map(scored.map(candidate => [candidate.policy.id, candidate]));
  const mandatoryRationales = new Map<string, string[]>();

  for (const rule of MANDATORY_RULES) {
    if (!rule.applies(surface)) continue;
    const matches = scored.filter(candidate => rule.policyMatches(candidate.policy));
    if (matches.length === 0) {
      throw new Error(`Mandatory policy coverage gap for rule ${rule.id}: ${rule.rationale}`);
    }
    const winner = matches[0];
    const reasons = mandatoryRationales.get(winner.policy.id) ?? [];
    reasons.push(`mandatory rule ${rule.id}: ${rule.rationale}`);
    mandatoryRationales.set(winner.policy.id, reasons);
  }

  const mandatorySelected: SelectedPolicyDecision[] = [...mandatoryRationales.entries()]
    .map(([policyId, mandatoryReasons]) => {
      const candidate = scoredById.get(policyId);
      if (!candidate) throw new Error(`Selected policy is missing from registry: ${policyId}`);
      return {
        policyId,
        score: candidate.score,
        disposition: 'mandatory' as const,
        matchedSurface: candidate.matchedSurface,
        rationale: [...mandatoryReasons, ...candidate.rationale],
      };
    })
    .sort((left, right) => right.score - left.score || left.policyId.localeCompare(right.policyId));

  const hasSpecificCandidate =
    mandatorySelected.length > 0 || scored.some(candidate => candidate.score > 0);
  const selectionMode = !hasSpecificCandidate
    ? 'fallback'
    : surface.surfaceStatus === 'sufficient'
      ? 'explicit'
      : 'hybrid';
  const usesFallback = selectionMode !== 'explicit';
  const fallbackSelected: SelectedPolicyDecision[] = usesFallback
    ? fallbackPolicies.map(policy => ({
        policyId: policy.id,
        score: 0,
        disposition: 'fallback' as const,
        matchedSurface: [`surface_status:${surface.surfaceStatus}`],
        rationale: [
          selectionMode === 'fallback'
            ? 'no reliable task-specific policy match exists'
            : 'material task-surface uncertainty remains',
        ],
      }))
    : [];
  const selected = [...mandatorySelected, ...fallbackSelected];
  const selectedIds = new Set(selected.map(selection => selection.policyId));
  const remainingSlots = Math.max(0, budget.maxPolicies - selected.length);
  const rankedCandidates = scored.filter(candidate => !selectedIds.has(candidate.policy.id));
  const rankedSelected = rankedCandidates
    .filter(candidate => candidate.score > 0)
    .slice(0, remainingSlots);

  selected.push(
    ...rankedSelected.map(candidate => ({
      policyId: candidate.policy.id,
      score: candidate.score,
      disposition: 'ranked' as const,
      matchedSurface: candidate.matchedSurface,
      rationale: candidate.rationale,
    }))
  );
  rankedSelected.forEach(candidate => selectedIds.add(candidate.policy.id));

  for (const candidate of rankedCandidates) {
    if (selectedIds.has(candidate.policy.id)) continue;
    rejected.push({
      policyId: candidate.policy.id,
      score: candidate.score,
      reason: candidate.score > 0 ? 'budget' : 'no_match',
    });
  }

  return {
    taskId: surface.taskId,
    selectionMode,
    surfaceStatus: surface.surfaceStatus,
    selected,
    rejected,
    coverageGaps:
      selectionMode === 'fallback' ? ['No reliable task-specific policy match was found.'] : [],
    unresolved: surface.unresolved,
    reassessmentTriggers: usesFallback ? REASSESSMENT_TRIGGERS : [],
    budget: {
      ...budget,
      mandatoryPolicies: mandatoryRationales.size,
      rankedPolicies: rankedSelected.length,
      fallbackPolicies: fallbackSelected.length,
      budgetExceededByMandatory: mandatoryRationales.size > budget.maxPolicies,
      budgetExceededBySafetyFloor:
        mandatoryRationales.size + fallbackSelected.length > budget.maxPolicies,
    },
    selectorVersion: SELECTOR_VERSION,
  };
}

export function createPolicySelectionDelta(
  previous: PolicySelectionDecision,
  current: PolicySelectionDecision,
  trigger: string
): PolicySelectionDelta {
  if (previous.taskId !== current.taskId) {
    throw new Error('Cannot create a policy delta for different tasks');
  }

  const previousIds = new Set(previous.selected.map(selection => selection.policyId));
  const currentIds = new Set(current.selected.map(selection => selection.policyId));
  const addedPolicies = [...currentIds].filter(policyId => !previousIds.has(policyId)).sort();

  return {
    trigger,
    addedPolicies,
    retainedPolicies: [...previousIds].sort(),
    rationale:
      addedPolicies.length > 0
        ? `new surface evidence selected: ${addedPolicies.join(', ')}`
        : 'new surface evidence did not require additional policies',
  };
}
