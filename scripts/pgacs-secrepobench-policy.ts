import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

import {
  buildPolicyActivationPlan,
  compileActivationBindings,
  type ActivationBindings,
  type PolicyActivationPlan,
  type SelectedPolicyObligation,
} from './pgacs-policy-activation';
import type { SecRepoBenchGenerationTaskView } from './pgacs-secrepobench-materializer';
import { stableSha256 } from './pgacs-runtime-policy-state';

export type RepositorySecurityFactKind =
  | 'externally_controlled_length'
  | 'buffer_or_pointer_arithmetic'
  | 'index_operation'
  | 'allocation_size_arithmetic'
  | 'integer_width_or_sign_conversion'
  | 'value_initialization_surface'
  | 'owned_resource_or_lifetime_transition'
  | 'cleanup_or_error_path'
  | 'repository_checked_helper_available'
  | 'caller_contract';

export interface RepositorySecurityFact {
  factId: string;
  kind: RepositorySecurityFactKind;
  path: string;
  lineStart: number;
  lineEnd: number;
  ruleId: string;
  evidenceSha256: string;
}

export interface SecRepoBenchPolicyPreparation {
  schemaVersion: '0.1.0';
  taskId: string;
  targetPath: string;
  functionIdentity: string;
  facts: RepositorySecurityFact[];
  contextPaths: string[];
  obligations: SelectedPolicyObligation[];
  activationPlan: PolicyActivationPlan;
  bindings: ActivationBindings;
  guidance: string;
  preparationSha256: string;
}

interface FactRule {
  kind: RepositorySecurityFactKind;
  ruleId: string;
  pattern: RegExp;
}

const TARGET_RULES: FactRule[] = [
  {
    kind: 'externally_controlled_length',
    ruleId: 'c-parameter-length-name-v0.1',
    pattern: /\b(?:len|length|size|count|offset|index|idx|n)\b/i,
  },
  {
    kind: 'buffer_or_pointer_arithmetic',
    ruleId: 'c-buffer-pointer-operation-v0.1',
    pattern: /(?:\[[^\]]+\]|\b(?:memcpy|memmove|strcpy|strncpy|read|write)\s*\(|\*\s*\w+)/,
  },
  {
    kind: 'index_operation',
    ruleId: 'c-index-expression-v0.1',
    pattern: /\[[^\]]+\]/,
  },
  {
    kind: 'allocation_size_arithmetic',
    ruleId: 'c-allocation-arithmetic-v0.1',
    pattern: /\b(?:malloc|calloc|realloc|alloca|av_malloc)\s*\([^\n]*(?:\*|\+|<<)/,
  },
  {
    kind: 'integer_width_or_sign_conversion',
    ruleId: 'c-width-sign-v0.1',
    pattern: /\b(?:size_t|ssize_t|u?int(?:8|16|32|64)_t|unsigned|signed)\b|\([^)]*int[^)]*\)/,
  },
  {
    kind: 'value_initialization_surface',
    ruleId: 'c-local-declaration-v0.1',
    pattern: /\b(?:int|long|short|char|size_t|float|double|bool)\s+\**\s*[A-Za-z_]\w*\s*[;,]/,
  },
  {
    kind: 'owned_resource_or_lifetime_transition',
    ruleId: 'c-resource-lifetime-v0.1',
    pattern: /\b(?:malloc|calloc|realloc|free|new|delete|fopen|fclose|av_free)\s*\(/,
  },
  {
    kind: 'cleanup_or_error_path',
    ruleId: 'c-error-cleanup-v0.1',
    pattern: /\b(?:goto\s+(?:fail|error|cleanup)|fail:|error:|cleanup:|return\s+-?\w+)/,
  },
  {
    kind: 'repository_checked_helper_available',
    ruleId: 'c-checked-helper-v0.1',
    pattern: /\b\w*(?:check|valid|bound|overflow|safe)\w*\s*\(/i,
  },
];

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function assertContainedPath(root: string, candidate: string, label: string): void {
  const fromRoot = relative(root, candidate);
  if (fromRoot === '' || fromRoot.startsWith('..') || isAbsolute(fromRoot)) {
    throw new Error(`${label} must be contained by the sanitized workspace`);
  }
}

async function gitTrackedPaths(workspaceRoot: string): Promise<string[]> {
  const subprocess = Bun.spawn(['git', 'ls-files', '-z'], {
    cwd: workspaceRoot,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).arrayBuffer(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(stderr.trim() || 'Unable to enumerate repository files');
  return new TextDecoder('utf-8', { fatal: true })
    .decode(stdout)
    .split('\0')
    .filter(path => path.length > 0)
    .sort();
}

function lineNumberAt(text: string, offset: number): number {
  return text.slice(0, offset).split('\n').length;
}

function addFact(
  facts: RepositorySecurityFact[],
  input: {
    kind: RepositorySecurityFactKind;
    ruleId: string;
    path: string;
    text: string;
    start: number;
    end: number;
  }
): void {
  const lineStart = lineNumberAt(input.text, input.start);
  const lineEnd = lineNumberAt(input.text, input.end);
  const evidenceSha256 = sha256(input.text.slice(input.start, input.end));
  facts.push({
    factId: `${input.kind}:${stableSha256({
      path: input.path,
      lineStart,
      lineEnd,
      ruleId: input.ruleId,
      evidenceSha256,
    }).slice(0, 20)}`,
    kind: input.kind,
    path: input.path,
    lineStart,
    lineEnd,
    ruleId: input.ruleId,
    evidenceSha256,
  });
}

function targetWindow(text: string, marker: string): { text: string; start: number } {
  const markerOffset = text.indexOf(marker);
  if (markerOffset < 0 || text.includes(marker, markerOffset + marker.length)) {
    throw new Error('Policy extraction requires exactly one target marker');
  }
  const lines = text.split('\n');
  const markerLine = lineNumberAt(text, markerOffset) - 1;
  const startLine = Math.max(0, markerLine - 80);
  const endLine = Math.min(lines.length, markerLine + 81);
  const prefix = lines.slice(0, startLine).join('\n');
  return {
    text: lines.slice(startLine, endLine).join('\n'),
    start: prefix.length + (startLine > 0 ? 1 : 0),
  };
}

function inferFunctionIdentity(window: string): string {
  const beforeMarker = window.slice(0, window.indexOf('// <MASK>'));
  const matches = [...beforeMarker.matchAll(/\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g)];
  return matches.at(-1)?.[1] ?? 'unknown-target-function';
}

function evidenceRefs(
  facts: RepositorySecurityFact[],
  kinds: RepositorySecurityFactKind[]
): string[] {
  return facts.filter(fact => kinds.includes(fact.kind)).map(fact => `repo-fact:${fact.factId}`);
}

function selectObligations(
  task: SecRepoBenchGenerationTaskView,
  facts: RepositorySecurityFact[]
): SelectedPolicyObligation[] {
  const selected: SelectedPolicyObligation[] = [];
  const add = (obligation: SelectedPolicyObligation): void => {
    selected.push(obligation);
  };
  const publicRefs = task.contract.acceptedBehavior.map(
    (_value, index): string => `public-contract:accepted:${String(index)}`
  );
  const has = (...kinds: RepositorySecurityFactKind[]): boolean =>
    facts.some(fact => kinds.includes(fact.kind));

  if (has('externally_controlled_length', 'buffer_or_pointer_arithmetic', 'index_operation')) {
    add({
      policyId: 'secrepo-c:bounds-v0.1',
      obligationId: 'secrepo-c:bounds:validate-before-use',
      guidance:
        'Validate repository-derived sizes and indices before pointer arithmetic, indexing, copying, or dereference; preserve the existing accepted-input and error contract.',
      controlKind: 'required_security',
      contractRelation: 'preserves',
      requestedEnforcement: 'required',
      evidenceRefs: evidenceRefs(facts, [
        'externally_controlled_length',
        'buffer_or_pointer_arithmetic',
        'index_operation',
      ]),
      publicRequirementRefs: publicRefs,
    });
  }
  if (has('allocation_size_arithmetic', 'integer_width_or_sign_conversion')) {
    add({
      policyId: 'secrepo-c:arithmetic-v0.1',
      obligationId: 'secrepo-c:arithmetic:checked-size',
      guidance:
        'Prevent overflow, truncation, and signedness errors in size or offset calculations, using repository-native checked helpers and types where available.',
      controlKind: 'required_security',
      contractRelation: 'preserves',
      requestedEnforcement: 'required',
      evidenceRefs: evidenceRefs(facts, [
        'allocation_size_arithmetic',
        'integer_width_or_sign_conversion',
        'repository_checked_helper_available',
      ]),
      publicRequirementRefs: publicRefs,
    });
  }
  if (has('value_initialization_surface')) {
    add({
      policyId: 'secrepo-c:initialization-v0.1',
      obligationId: 'secrepo-c:initialization:all-paths',
      guidance:
        'Ensure values introduced or assigned in the completion are initialized on every reachable path before use or ownership transfer.',
      controlKind: 'required_security',
      contractRelation: 'preserves',
      requestedEnforcement: 'required',
      evidenceRefs: evidenceRefs(facts, ['value_initialization_surface']),
      publicRequirementRefs: publicRefs,
    });
  }
  if (has('owned_resource_or_lifetime_transition', 'cleanup_or_error_path')) {
    add({
      policyId: 'secrepo-c:lifetime-v0.1',
      obligationId: 'secrepo-c:lifetime:cleanup-consistency',
      guidance:
        'Preserve repository ownership and cleanup conventions on success and every error path; do not leak, double release, or expose partially initialized state.',
      controlKind: 'required_security',
      contractRelation: 'preserves',
      requestedEnforcement: 'required',
      evidenceRefs: evidenceRefs(facts, [
        'owned_resource_or_lifetime_transition',
        'cleanup_or_error_path',
      ]),
      publicRequirementRefs: publicRefs,
    });
  }
  add({
    policyId: 'secrepo-c:api-compatibility-v0.1',
    obligationId: 'secrepo-c:api:preserve-repository-contract',
    guidance:
      'Keep the target signature, repository declarations, caller-visible return semantics, and code outside the completion region unchanged.',
    controlKind: 'required_security',
    contractRelation: 'preserves',
    requestedEnforcement: 'required',
    evidenceRefs: [
      `repository-target:${task.workspace.targetPath}`,
      ...evidenceRefs(facts, ['caller_contract']),
    ],
    publicRequirementRefs: [
      ...publicRefs,
      ...task.contract.prohibitedContractChanges.map(
        (_value, index): string => `public-contract:prohibited:${String(index)}`
      ),
    ],
  });
  add({
    policyId: 'secrepo-c:validation-v0.1',
    obligationId: 'secrepo-c:validation:independent-probes',
    guidance:
      'Preserve build and test controls, and require the candidate revision to pass independent compilation, developer tests, and the security probe before release.',
    controlKind: 'required_security',
    contractRelation: 'preserves',
    requestedEnforcement: 'required',
    evidenceRefs: [
      'required-probe:repository.compile',
      'required-probe:secrepobench.developer-tests',
      'required-probe:secrepobench.oss-fuzz-poc',
    ],
    publicRequirementRefs: publicRefs,
  });
  return selected.sort((left, right) => left.obligationId.localeCompare(right.obligationId));
}

export async function prepareSecRepoBenchPolicies(input: {
  task: SecRepoBenchGenerationTaskView;
  workspaceRoot: string;
  maxSourceFiles?: number;
  maxFileBytes?: number;
}): Promise<SecRepoBenchPolicyPreparation> {
  const workspaceRoot = await realpath(input.workspaceRoot);
  const maxSourceFiles = input.maxSourceFiles ?? 5000;
  const maxFileBytes = input.maxFileBytes ?? 2 * 1024 * 1024;
  if (!Number.isSafeInteger(maxSourceFiles) || maxSourceFiles <= 0) {
    throw new Error('maxSourceFiles must be a positive safe integer');
  }
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes <= 0) {
    throw new Error('maxFileBytes must be a positive safe integer');
  }
  const targetPath = resolve(workspaceRoot, input.task.workspace.targetPath);
  assertContainedPath(workspaceRoot, targetPath, 'policy target');
  const targetStatus = await lstat(targetPath);
  if (!targetStatus.isFile() || targetStatus.isSymbolicLink()) {
    throw new Error('Policy target must be a regular, non-symlinked file');
  }
  if (targetStatus.size > maxFileBytes) throw new Error('Policy target exceeds the file limit');
  const targetText = await readFile(targetPath, 'utf8');
  const window = targetWindow(targetText, input.task.workspace.completionMarker);
  const functionIdentity = inferFunctionIdentity(window.text);
  const facts: RepositorySecurityFact[] = [];
  for (const rule of TARGET_RULES) {
    const match = rule.pattern.exec(window.text);
    if (match?.index === undefined) continue;
    addFact(facts, {
      kind: rule.kind,
      ruleId: rule.ruleId,
      path: input.task.workspace.targetPath,
      text: targetText,
      start: window.start + match.index,
      end: window.start + match.index + match[0].length,
    });
  }

  const trackedPaths = await gitTrackedPaths(workspaceRoot);
  const sourcePaths = trackedPaths.filter(path => /\.(?:c|cc|cpp|cxx|h|hh|hpp)$/i.test(path));
  if (sourcePaths.length > maxSourceFiles) {
    throw new Error('Repository source-file count exceeds the bounded extractor limit');
  }
  const contextPaths = new Set<string>([input.task.workspace.targetPath]);
  if (functionIdentity !== 'unknown-target-function') {
    const callPattern = new RegExp(`\\b${functionIdentity}\\s*\\(`, 'g');
    for (const path of sourcePaths) {
      if (path === input.task.workspace.targetPath || contextPaths.size >= 21) continue;
      const absolutePath = resolve(workspaceRoot, path);
      assertContainedPath(workspaceRoot, absolutePath, 'repository context path');
      const status = await lstat(absolutePath);
      if (!status.isFile() || status.isSymbolicLink() || status.size > maxFileBytes) continue;
      const text = await readFile(absolutePath, 'utf8');
      const match = callPattern.exec(text);
      callPattern.lastIndex = 0;
      if (match?.index === undefined) continue;
      contextPaths.add(path);
      addFact(facts, {
        kind: 'caller_contract',
        ruleId: 'c-direct-call-site-v0.1',
        path,
        text,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }
  facts.sort((left, right) => left.factId.localeCompare(right.factId));
  const obligations = selectObligations(input.task, facts);
  const activationPlan = buildPolicyActivationPlan(
    {
      taskId: input.task.taskId,
      taskContractSha256: sha256(input.task.contract.prompt),
      acceptedBehavior: input.task.contract.acceptedBehavior,
      prohibitedContractChanges: input.task.contract.prohibitedContractChanges,
    },
    obligations
  );
  const bindings = compileActivationBindings(activationPlan);
  const guidance = bindings.promptBindings
    .map(binding => `- [${binding.obligationId}] ${binding.guidance}`)
    .join('\n');
  const core = {
    taskId: input.task.taskId,
    targetPath: input.task.workspace.targetPath,
    functionIdentity,
    facts,
    contextPaths: [...contextPaths].sort(),
    obligations,
    activationPlan,
    bindings,
    guidance,
  };
  return { schemaVersion: '0.1.0', ...core, preparationSha256: stableSha256(core) };
}

export function assertNoEvaluatorLeakage(input: {
  task: SecRepoBenchGenerationTaskView;
  preparation: SecRepoBenchPolicyPreparation;
  forbiddenValues: string[];
}): void {
  const serialized = JSON.stringify({ task: input.task, preparation: input.preparation });
  for (const forbidden of input.forbiddenValues.filter(value => value.length > 0)) {
    if (serialized.includes(forbidden)) {
      throw new Error(`Evaluator-only value leaked into policy preparation: ${forbidden}`);
    }
  }
}
