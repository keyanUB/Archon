import { readFile } from 'fs/promises';

import type { PolicyRecord, PolicySelection, TaskSurface } from './pgacs-types.ts';

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

const THEME_TAGS: Record<string, string[]> = {
  dependency_integrity: ['supply_chain', 'dependency_integrity'],
  build_release_integrity: ['build_integrity', 'release_integrity'],
  configuration_hardening: ['configuration_hardening', 'secure_defaults'],
  secrets_key_management: ['secrets', 'key_management'],
  least_privilege_access: ['least_privilege', 'access_control'],
  transport_network_configuration: ['network_hardening', 'transport_security'],
  endpoint_runtime_hardening: ['runtime_hardening', 'sandboxing'],
  logging_monitoring_setup: ['logging', 'monitoring', 'auditability'],
  secure_sdld_process: ['secure_sdlc', 'process_controls'],
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
    'transport_network_configuration',
    'configuration_hardening',
    'dependency_integrity',
    'secrets_key_management',
    'logging_monitoring_setup',
    'build_release_integrity',
    'secure_sdld_process',
  ],
  dependency_build: ['dependency_integrity', 'build_release_integrity', 'secure_sdld_process'],
  web_api: ['configuration_hardening', 'transport_network_configuration', 'least_privilege_access'],
  auth_session: ['secrets_key_management', 'least_privilege_access', 'configuration_hardening'],
  agent_tooling: ['endpoint_runtime_hardening', 'least_privilege_access', 'secure_sdld_process'],
};

function unique(values: string[]): string[] {
  return [...new Set(values.filter(value => value.length > 0))].sort();
}

function normalizeText(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
}

function keywordMatches(text: string, keywords: string[]): boolean {
  return keywords.some(keyword => text.includes(keyword));
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
  if (theme === 'endpoint_runtime_hardening' || theme === 'transport_network_configuration') {
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
        policy.setup_env_theme === 'dependency_integrity' ? ['dependency_integrity'] : [],
      environmentTags: inferEnvironmentTags(description, policy.setup_env_theme),
      phaseBindings: inferPhaseBindings(description, policy.setup_env_theme),
      validators: [],
      evidenceRequirements: inferEvidenceRequirements(description),
      forbiddenWorkarounds: inferForbiddenWorkarounds(description),
      severity: inferSeverity(description, policy.setup_env_theme),
    };
  });
}

function scoreOverlap(values: string[], surfaceValues: string[], weight: number): number {
  const surface = new Set(surfaceValues);
  return values.reduce((score, value) => (surface.has(value) ? score + weight : score), 0);
}

export function selectPolicies(
  policies: PolicyRecord[],
  surface: TaskSurface,
  maxPolicies = 8
): PolicySelection[] {
  const familyHints = TASK_FAMILY_TRIGGER_HINTS[surface.taskFamily] ?? [];
  const ranked = policies
    .map(policy => {
      const rationale: string[] = [];
      let score = 0;

      score += scoreOverlap(policy.riskTags, surface.likelyCwes, 4);
      score += scoreOverlap(policy.cweTags, surface.likelyCwes, 5);
      score += scoreOverlap(policy.assetTags, surface.assets, 3);
      score += scoreOverlap(policy.trustBoundaryTags, surface.trustBoundaries, 3);
      score += scoreOverlap(policy.dangerousSinks, surface.dangerousSinks, 5);
      score += scoreOverlap(policy.taskTriggers, surface.environmentConstraints, 2);
      score += scoreOverlap(policy.environmentTags, surface.environmentConstraints, 2);
      score += scoreOverlap(policy.taskTriggers, familyHints, 4);

      if (
        policy.phaseBindings.includes('verification_runtime') &&
        surface.runtimeExposure.length > 0
      ) {
        score += 2;
      }
      if (
        policy.phaseBindings.includes('verification_build') &&
        surface.taskFamily === 'dependency_build'
      ) {
        score += 2;
      }
      if (policy.severity === 'fail_closed') score += 1;

      if (score > 0) {
        const matchedTags = unique([
          ...policy.riskTags.filter(tag => surface.likelyCwes.includes(tag)),
          ...policy.cweTags.filter(tag => surface.likelyCwes.includes(tag)),
          ...policy.assetTags.filter(tag => surface.assets.includes(tag)),
          ...policy.trustBoundaryTags.filter(tag => surface.trustBoundaries.includes(tag)),
          ...policy.dangerousSinks.filter(tag => surface.dangerousSinks.includes(tag)),
        ]);
        if (matchedTags.length > 0) {
          rationale.push(`matched tags: ${matchedTags.join(', ')}`);
        }
        if (policy.severity === 'fail_closed') {
          rationale.push('policy severity is fail_closed');
        }
        if (
          policy.phaseBindings.includes('verification_runtime') &&
          surface.runtimeExposure.length > 0
        ) {
          rationale.push('runtime exposure requires runtime verification');
        }
      }

      return { policy, score, rationale };
    })
    .filter(selection => selection.score > 0)
    .sort(
      (left, right) => right.score - left.score || left.policy.id.localeCompare(right.policy.id)
    );

  return ranked.slice(0, maxPolicies);
}
