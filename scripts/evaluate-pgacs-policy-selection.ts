#!/usr/bin/env bun
import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { format, resolveConfig } from 'prettier';

import {
  loadPolicyCorpus,
  loadCoreSecurityFloor,
  normalizePolicyRegistry,
  selectPolicyDecision,
} from './pgacs-policy-registry';
import { extractTaskSurface } from './pgacs-task-surface';
import type { TaskFamily } from './pgacs-types';

interface SilverLabelTask {
  taskId: string;
  taskFamily: TaskFamily;
  prompt: string;
  repoHints: string[];
  requiredPolicyIds: string[];
  relevantPolicyIds: string[];
}

interface SilverLabelSet {
  version: string;
  labelType: 'model_generated_silver';
  tasks: SilverLabelTask[];
}

interface TaskEvaluation {
  taskId: string;
  expectedFamily: TaskFamily;
  extractedFamily: TaskFamily;
  selectedPolicyIds: string[];
  foundRequiredPolicyIds: string[];
  missingRequiredPolicyIds: string[];
  foundRelevantPolicyIds: string[];
  unexpectedPolicyIds: string[];
  selectorError?: string;
}

const REPO_ROOT = resolve(import.meta.dir, '..');
const LABELS_PATH = join(
  REPO_ROOT,
  'principle-guided-agent-research/archive/07-prototype-evaluation/silver-policy-selection-labels.json'
);
const OUTPUT_PATH = join(
  REPO_ROOT,
  'principle-guided-agent-research/archive/07-prototype-evaluation/selector-evaluation.generated.json'
);
const POLICY_SOURCE = join(
  REPO_ROOT,
  '.archon/data/research/secure-environment-setup/setup-environment-policies.json'
);
const CORE_SECURITY_FLOOR_PATH = join(
  REPO_ROOT,
  '.archon/data/research/pgacs/core-security-floor.json'
);

function parseLabels(value: unknown): SilverLabelSet {
  if (!value || typeof value !== 'object') throw new Error('Label set must be an object');
  const candidate = value as Partial<SilverLabelSet>;
  if (candidate.labelType !== 'model_generated_silver' || !Array.isArray(candidate.tasks)) {
    throw new Error('Invalid silver label set');
  }
  for (const task of candidate.tasks) {
    if (
      !task ||
      typeof task.taskId !== 'string' ||
      typeof task.prompt !== 'string' ||
      !Array.isArray(task.repoHints) ||
      !Array.isArray(task.requiredPolicyIds) ||
      !Array.isArray(task.relevantPolicyIds)
    ) {
      throw new Error('Invalid task in silver label set');
    }
  }
  return candidate as SilverLabelSet;
}

function intersection(values: string[], expected: Set<string>): string[] {
  return values.filter(value => expected.has(value)).sort();
}

function evaluateTask(
  task: SilverLabelTask,
  policies: ReturnType<typeof normalizePolicyRegistry>
): TaskEvaluation {
  const surface = extractTaskSurface(task.taskId, task.prompt, task.repoHints);
  const required = new Set(task.requiredPolicyIds);
  const relevant = new Set(task.relevantPolicyIds);
  const acceptable = new Set([...required, ...relevant]);

  try {
    const decision = selectPolicyDecision(policies, surface);
    const selectedPolicyIds = decision.selected.map(selection => selection.policyId);
    return {
      taskId: task.taskId,
      expectedFamily: task.taskFamily,
      extractedFamily: surface.taskFamily,
      selectedPolicyIds,
      foundRequiredPolicyIds: intersection(selectedPolicyIds, required),
      missingRequiredPolicyIds: task.requiredPolicyIds
        .filter(policyId => !selectedPolicyIds.includes(policyId))
        .sort(),
      foundRelevantPolicyIds: intersection(selectedPolicyIds, relevant),
      unexpectedPolicyIds: selectedPolicyIds.filter(policyId => !acceptable.has(policyId)).sort(),
    };
  } catch (error: unknown) {
    return {
      taskId: task.taskId,
      expectedFamily: task.taskFamily,
      extractedFamily: surface.taskFamily,
      selectedPolicyIds: [],
      foundRequiredPolicyIds: [],
      missingRequiredPolicyIds: [...task.requiredPolicyIds].sort(),
      foundRelevantPolicyIds: [],
      unexpectedPolicyIds: [],
      selectorError: error instanceof Error ? error.message : String(error),
    };
  }
}

function ratio(numerator: number, denominator: number): number | null {
  return denominator === 0 ? null : Number((numerator / denominator).toFixed(4));
}

async function main(): Promise<void> {
  const labels = parseLabels(JSON.parse(await readFile(LABELS_PATH, 'utf-8')) as unknown);
  const [corpus, coreSecurityFloor] = await Promise.all([
    loadPolicyCorpus(POLICY_SOURCE),
    loadCoreSecurityFloor(CORE_SECURITY_FLOOR_PATH),
  ]);
  const policies = [...normalizePolicyRegistry(corpus), ...coreSecurityFloor];
  const knownPolicyIds = new Set(policies.map(policy => policy.id));

  for (const task of labels.tasks) {
    for (const policyId of [...task.requiredPolicyIds, ...task.relevantPolicyIds]) {
      if (!knownPolicyIds.has(policyId)) {
        throw new Error(`Unknown labeled policy ${policyId} in task ${task.taskId}`);
      }
    }
  }

  const tasks = labels.tasks.map(task => evaluateTask(task, policies));
  const totalRequired = labels.tasks.reduce((sum, task) => sum + task.requiredPolicyIds.length, 0);
  const foundRequired = tasks.reduce((sum, task) => sum + task.foundRequiredPolicyIds.length, 0);
  const totalSelected = tasks.reduce((sum, task) => sum + task.selectedPolicyIds.length, 0);
  const acceptableSelected = tasks.reduce(
    (sum, task) => sum + task.foundRequiredPolicyIds.length + task.foundRelevantPolicyIds.length,
    0
  );

  const result = {
    labelVersion: labels.version,
    labelType: labels.labelType,
    caution: 'Model-generated silver labels are provisional and are not expert ground truth.',
    metrics: {
      taskCount: tasks.length,
      selectorCompletedTasks: tasks.filter(task => !task.selectorError).length,
      familyClassificationAccuracy: ratio(
        tasks.filter(task => task.expectedFamily === task.extractedFamily).length,
        tasks.length
      ),
      requiredPolicyRecall: ratio(foundRequired, totalRequired),
      acceptableSelectionPrecision: ratio(acceptableSelected, totalSelected),
      averageSelectedPolicies: ratio(totalSelected, tasks.length),
    },
    tasks,
  };

  const prettierConfig = await resolveConfig(OUTPUT_PATH);
  const output = await format(JSON.stringify(result), {
    ...prettierConfig,
    filepath: OUTPUT_PATH,
  });
  await writeFile(OUTPUT_PATH, output, 'utf-8');
  console.log(`Wrote PGACS silver-label evaluation to ${OUTPUT_PATH}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
