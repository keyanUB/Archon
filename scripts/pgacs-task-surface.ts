import type {
  SurfaceEvidence,
  SurfaceStatus,
  TaskFamily,
  TaskSurface,
  UnresolvedSurfaceQuestion,
} from './pgacs-types.ts';

const LANGUAGE_HINTS: [RegExp, string][] = [
  [/package\.json|bun\.lock|tsconfig\.json|\.tsx?$/i, 'TypeScript'],
  [/\bpyproject\.toml\b|requirements\.txt|\.py$/i, 'Python'],
  [/\bgo\.mod\b|\.go$/i, 'Go'],
  [/\bCargo\.toml\b|\.rs$/i, 'Rust'],
  [/\bDockerfile\b|docker-compose/i, 'Docker'],
  [/\b\.sh\b|systemd|autossh/i, 'Shell'],
];

const TASK_FAMILY_RULES: [TaskFamily, RegExp[]][] = [
  ['environment_setup', [/docker/i, /systemd/i, /autossh/i, /setup/i, /install/i, /configure/i]],
  ['web_api', [/http/i, /api/i, /route/i, /endpoint/i, /server/i, /webhook/i]],
  ['file_parser', [/parse/i, /csv/i, /json/i, /yaml/i, /xml/i, /file/i]],
  ['database', [/sql/i, /postgres/i, /sqlite/i, /db/i, /migration/i]],
  ['auth_session', [/auth/i, /oauth/i, /login/i, /session/i, /jwt/i, /cookie/i]],
  ['cli_tool', [/cli/i, /command/i, /terminal/i, /flags?/i]],
  ['dependency_build', [/dependency/i, /package/i, /build/i, /install/i, /lockfile/i]],
  ['agent_tooling', [/agent/i, /workflow/i, /harness/i, /tool/i, /hook/i]],
];

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function normalize(text: string): string {
  return text.toLowerCase();
}

function countMatches(text: string, needles: RegExp[]): number {
  return needles.reduce((count, pattern) => count + (pattern.test(text) ? 1 : 0), 0);
}

function inferTaskFamily(prompt: string): TaskFamily {
  const lower = normalize(prompt);
  let best: { family: TaskFamily; score: number } = { family: 'unknown', score: 0 };
  for (const [family, rules] of TASK_FAMILY_RULES) {
    const score = countMatches(lower, rules);
    if (score > best.score) best = { family, score };
  }
  return best.family;
}

function inferLanguageFrameworks(prompt: string, repoHints: string[]): string[] {
  const text = normalize([prompt, ...repoHints].join('\n'));
  return unique(LANGUAGE_HINTS.filter(([pattern]) => pattern.test(text)).map(([, label]) => label));
}

function inferInputChannels(prompt: string): string[] {
  const lower = normalize(prompt);
  const channels: string[] = [];
  if (
    lower.includes('http') ||
    lower.includes('api') ||
    lower.includes('webhook') ||
    lower.includes('ssh') ||
    lower.includes('tunnel') ||
    lower.includes('port')
  )
    channels.push('network');
  if (lower.includes('file') || lower.includes('directory') || lower.includes('path'))
    channels.push('filesystem');
  if (lower.includes('cli') || lower.includes('terminal') || lower.includes('command'))
    channels.push('stdin');
  if (lower.includes('env') || lower.includes('variable')) channels.push('env');
  return unique(channels);
}

function inferDangerousSinks(prompt: string): string[] {
  const lower = normalize(prompt);
  const sinks: string[] = [];
  if (lower.includes('shell') || lower.includes('command') || lower.includes('spawn'))
    sinks.push('shell_command');
  if (lower.includes('sql') || lower.includes('database')) sinks.push('database');
  if (lower.includes('path') || lower.includes('file')) sinks.push('filesystem');
  if (lower.includes('http') || lower.includes('port') || lower.includes('network'))
    sinks.push('network');
  if (lower.includes('secret') || lower.includes('token') || lower.includes('key'))
    sinks.push('secrets');
  return unique(sinks);
}

function inferAssets(prompt: string): string[] {
  const lower = normalize(prompt);
  const assets: string[] = [];
  if (lower.includes('secret') || lower.includes('token') || lower.includes('key'))
    assets.push('secrets');
  if (lower.includes('file') || lower.includes('path')) assets.push('filesystem');
  if (lower.includes('service') || lower.includes('port') || lower.includes('ssh'))
    assets.push('runtime_service');
  if (lower.includes('service') || lower.includes('port') || lower.includes('ssh'))
    assets.push('network');
  if (lower.includes('dependency') || lower.includes('package') || lower.includes('install'))
    assets.push('dependencies');
  if (lower.includes('log')) assets.push('observability');
  return unique(assets);
}

function inferTrustBoundaries(prompt: string): string[] {
  const lower = normalize(prompt);
  const boundaries: string[] = [];
  if (lower.includes('user input') || lower.includes('untrusted'))
    boundaries.push('untrusted_input');
  if (
    lower.includes('network') ||
    lower.includes('http') ||
    lower.includes('ssh') ||
    lower.includes('tunnel') ||
    lower.includes('port')
  )
    boundaries.push('network_boundary');
  if (lower.includes('file') || lower.includes('path')) boundaries.push('workspace_boundary');
  if (lower.includes('secret') || lower.includes('credential')) boundaries.push('secret_boundary');
  if (lower.includes('root') || lower.includes('privilege')) boundaries.push('privilege_boundary');
  return unique(boundaries);
}

function inferRuntimeExposure(prompt: string): string[] {
  const lower = normalize(prompt);
  const exposure: string[] = [];
  if (lower.includes('service') || lower.includes('daemon')) exposure.push('service_start');
  if (lower.includes('port') || lower.includes('bind')) exposure.push('port_binding');
  if (lower.includes('ssh') || lower.includes('tunnel')) exposure.push('remote_access');
  if (lower.includes('docker')) exposure.push('container_runtime');
  return unique(exposure);
}

function inferEnvironmentConstraints(prompt: string, repoHints: string[]): string[] {
  const text = normalize([prompt, ...repoHints].join('\n'));
  const constraints: string[] = [];
  if (text.includes('minimal environment')) constraints.push('minimal_environment');
  if (text.includes('headless')) constraints.push('headless');
  if (text.includes('sandbox')) constraints.push('sandbox');
  if (text.includes('no network')) constraints.push('no_network');
  if (text.includes('no human gate')) constraints.push('fully_automated');
  if (text.includes('root')) constraints.push('root_privileges');
  if (text.includes('install') || text.includes('package')) constraints.push('dependency_change');
  if (text.includes('ssh') || text.includes('tunnel') || text.includes('port'))
    constraints.push('runtime_network');
  if (text.includes('log') || text.includes('monitor')) constraints.push('observability');
  if (text.includes('restart') || text.includes('persistent') || text.includes('supervised'))
    constraints.push('process_lifecycle');
  return unique(constraints);
}

function inferLikelyCwes(prompt: string): string[] {
  const lower = normalize(prompt);
  const cwes: string[] = [];
  if (lower.includes('path')) cwes.push('CWE-22');
  if (lower.includes('shell') || lower.includes('command')) cwes.push('CWE-78');
  if (lower.includes('sql')) cwes.push('CWE-89');
  if (lower.includes('secret') || lower.includes('key') || lower.includes('token'))
    cwes.push('CWE-798');
  if (lower.includes('port') || lower.includes('bind')) cwes.push('CWE-284');
  if (lower.includes('dependency') || lower.includes('package')) cwes.push('CWE-494');
  return unique(cwes);
}

function inferMissingSecurityInputs(prompt: string): string[] {
  const lower = normalize(prompt);
  const missing: string[] = [];
  if (!lower.includes('threat model')) missing.push('explicit threat model');
  if (!lower.includes('tests')) missing.push('validation criteria');
  if (!lower.includes('security')) missing.push('security acceptance criteria');
  return unique(missing);
}

function inferExistingTests(repoHints: string[]): string[] {
  const text = normalize(repoHints.join('\n'));
  const tests: string[] = [];
  if (text.includes('test')) tests.push('tests_present');
  if (text.includes('spec')) tests.push('spec_files_present');
  if (text.includes('pytest')) tests.push('pytest');
  if (text.includes('bun test')) tests.push('bun_test');
  return unique(tests);
}

function determineSurfaceStatus(surface: {
  inputChannels: string[];
  dangerousSinks: string[];
  assets: string[];
  trustBoundaries: string[];
  runtimeExposure: string[];
  likelyCwes: string[];
}): SurfaceStatus {
  const hasInputToSinkRelation =
    surface.dangerousSinks.length > 0 &&
    (surface.inputChannels.length > 0 || surface.trustBoundaries.length > 0);
  const hasExplicitRisk =
    surface.likelyCwes.length > 0 &&
    (surface.dangerousSinks.length > 0 || surface.runtimeExposure.length > 0);
  const hasRuntimeRelation =
    surface.runtimeExposure.length > 0 &&
    (surface.inputChannels.includes('network') ||
      surface.trustBoundaries.includes('network_boundary'));

  if (hasInputToSinkRelation || hasExplicitRisk || hasRuntimeRelation) return 'sufficient';

  const factCount =
    surface.inputChannels.length +
    surface.dangerousSinks.length +
    surface.assets.length +
    surface.trustBoundaries.length +
    surface.runtimeExposure.length +
    surface.likelyCwes.length;
  return factCount === 0 ? 'insufficient' : 'ambiguous';
}

function buildSurfaceEvidence(prompt: string, fields: Record<string, string[]>): SurfaceEvidence[] {
  const promptEvidence = prompt.replace(/\s+/gu, ' ').trim().slice(0, 240);
  return Object.entries(fields).flatMap(([field, values]) =>
    values.map(value => ({
      field,
      value,
      source: 'task_prompt' as const,
      evidence: promptEvidence,
    }))
  );
}

function buildUnresolvedQuestions(surface: {
  inputChannels: string[];
  dangerousSinks: string[];
  trustBoundaries: string[];
  missingSecurityInputs: string[];
}): UnresolvedSurfaceQuestion[] {
  const unresolved: UnresolvedSurfaceQuestion[] = [];
  if (surface.inputChannels.length === 0) {
    unresolved.push({
      field: 'inputChannels',
      question: 'Which external or untrusted inputs can reach the implementation?',
      reason: 'No input channel was supported by the task prompt.',
    });
  }
  if (surface.dangerousSinks.length === 0) {
    unresolved.push({
      field: 'dangerousSinks',
      question: 'Which security-sensitive operations or sinks are in scope?',
      reason: 'No dangerous sink was supported by the task prompt.',
    });
  }
  if (surface.trustBoundaries.length === 0) {
    unresolved.push({
      field: 'trustBoundaries',
      question: 'Where does data or authority cross a trust boundary?',
      reason: 'No trust boundary was supported by the task prompt.',
    });
  }
  if (surface.missingSecurityInputs.includes('validation criteria')) {
    unresolved.push({
      field: 'existingTests',
      question: 'What positive and negative validation demonstrates correct security behavior?',
      reason: 'The task prompt does not state validation criteria.',
    });
  }
  return unresolved;
}

export function extractTaskSurface(
  taskId: string,
  prompt: string,
  repoHints: string[] = []
): TaskSurface {
  const taskFamily = inferTaskFamily(prompt);
  const languageFrameworks = inferLanguageFrameworks(prompt, repoHints);
  const inputChannels = inferInputChannels(prompt);
  const dangerousSinks = inferDangerousSinks(prompt);
  const assets = inferAssets(prompt);
  const trustBoundaries = inferTrustBoundaries(prompt);
  const runtimeExposure = inferRuntimeExposure(prompt);
  const dependencies = unique(
    repoHints.filter(hint => /package|lockfile|mod|toml|json$/i.test(hint))
  );
  const environmentConstraints = inferEnvironmentConstraints(prompt, repoHints);
  const likelyCwes = inferLikelyCwes(prompt);
  const missingSecurityInputs = inferMissingSecurityInputs(prompt);
  const existingTests = inferExistingTests(repoHints);
  const surfaceStatus = determineSurfaceStatus({
    inputChannels,
    dangerousSinks,
    assets,
    trustBoundaries,
    runtimeExposure,
    likelyCwes,
  });
  const evidence = buildSurfaceEvidence(prompt, {
    inputChannels,
    dangerousSinks,
    assets,
    trustBoundaries,
    runtimeExposure,
    likelyCwes,
  });
  const unresolved = buildUnresolvedQuestions({
    inputChannels,
    dangerousSinks,
    trustBoundaries,
    missingSecurityInputs,
  });

  return {
    taskId,
    taskFamily,
    languageFrameworks,
    inputChannels,
    dangerousSinks,
    assets,
    trustBoundaries,
    runtimeExposure,
    dependencies,
    environmentConstraints,
    likelyCwes,
    missingSecurityInputs,
    existingTests,
    confidence: {
      taskFamily: taskFamily === 'unknown' ? 0.35 : 0.85,
      risks: likelyCwes.length > 0 || dangerousSinks.length > 0 ? 0.8 : 0.45,
      missingInputs: missingSecurityInputs.length > 0 ? 0.75 : 0.4,
    },
    surfaceStatus,
    evidence,
    unresolved,
  };
}
