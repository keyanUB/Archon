#!/usr/bin/env bun
import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { createHash } from 'crypto';
import { format, resolveConfig } from 'prettier';

interface LabeledTask {
  taskId: string;
  requiredPolicyIds: string[];
  relevantPolicyIds: string[];
}

interface SilverLabels {
  version: string;
  labelType: string;
  tasks: LabeledTask[];
}

interface SelectedTask {
  taskId: string;
  selected: { policyId: string; importance: string; reason: string }[];
  coverageGaps: { control: string; reason: string }[];
}

interface SemanticSelection {
  configuredModel: string;
  reportedModelIds: string[];
  catalogSize: number;
  sourceHashes: {
    labelsSha256: string;
  };
  selectionFingerprint: string;
  tasks: SelectedTask[];
}

interface BaselineEvaluation {
  metrics: Record<string, number | null>;
}

interface SemanticAdjudication {
  version: string;
  adjudicatorRole: string;
  labelsSha256: string;
  selectionFingerprint: string;
  tasks: {
    taskId: string;
    requiredAssessments: {
      labeledPolicyId: string;
      status: 'covered_exact' | 'covered_equivalent' | 'missing';
      coveredBySelectedPolicyIds: string[];
    }[];
    selectedAssessments: {
      selectedPolicyId: string;
      verdict: 'covers_required' | 'covers_relevant' | 'additional_relevant' | 'irrelevant';
      matchedLabeledPolicyIds: string[];
    }[];
  }[];
}

const REPO_ROOT = resolve(import.meta.dir, '..');
const EVALUATION_DIR = 'principle-guided-agent-research/09-semantic-selector-evaluation';
const LABELS_PATH = join(REPO_ROOT, EVALUATION_DIR, 'expanded-silver-labels.json');
const SELECTION_PATH = join(REPO_ROOT, EVALUATION_DIR, 'semantic-selection.generated.json');
const ADJUDICATION_PATH = join(REPO_ROOT, EVALUATION_DIR, 'semantic-adjudication.json');
const BASELINE_PATH = join(
  REPO_ROOT,
  'principle-guided-agent-research/07-prototype-evaluation/selector-evaluation.generated.json'
);
const OUTPUT_PATH = join(REPO_ROOT, EVALUATION_DIR, 'semantic-selector-comparison.generated.json');

function ratio(numerator: number, denominator: number): number | null {
  return denominator === 0 ? null : Number((numerator / denominator).toFixed(4));
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function fingerprintSelection(tasks: SelectedTask[]): string {
  const normalized = [...tasks]
    .sort((left, right) => left.taskId.localeCompare(right.taskId))
    .map(task => ({
      taskId: task.taskId,
      selected: task.selected
        .map(item => ({ policyId: item.policyId, importance: item.importance }))
        .sort((left, right) => left.policyId.localeCompare(right.policyId)),
    }));
  return sha256(JSON.stringify(normalized));
}

function assertSameIds(label: string, actual: string[], expected: string[]): void {
  const normalizedActual = [...actual].sort();
  const normalizedExpected = [...expected].sort();
  if (JSON.stringify(normalizedActual) !== JSON.stringify(normalizedExpected)) {
    throw new Error(
      `${label} mismatch: expected [${normalizedExpected.join(', ')}], received [${normalizedActual.join(', ')}]`
    );
  }
}

export function validateEvaluationIntegrity(
  labels: SilverLabels,
  labelsText: string,
  selection: SemanticSelection,
  adjudication: SemanticAdjudication
): void {
  const labelsSha256 = sha256(labelsText);
  if (selection.sourceHashes.labelsSha256 !== labelsSha256) {
    throw new Error('Semantic selection was produced from a different silver-label artifact');
  }
  if (adjudication.labelsSha256 !== labelsSha256) {
    throw new Error('Semantic adjudication was produced from a different silver-label artifact');
  }
  const selectionFingerprint = fingerprintSelection(selection.tasks);
  if (selection.selectionFingerprint !== selectionFingerprint) {
    throw new Error('Semantic selection fingerprint does not match its task selections');
  }
  if (adjudication.selectionFingerprint !== selectionFingerprint) {
    throw new Error('Semantic adjudication does not match the current semantic selection');
  }

  assertSameIds(
    'semantic selection task IDs',
    selection.tasks.map(task => task.taskId),
    labels.tasks.map(task => task.taskId)
  );
  assertSameIds(
    'semantic adjudication task IDs',
    adjudication.tasks.map(task => task.taskId),
    labels.tasks.map(task => task.taskId)
  );

  const selectionByTask = new Map(selection.tasks.map(task => [task.taskId, task]));
  const adjudicationByTask = new Map(adjudication.tasks.map(task => [task.taskId, task]));
  for (const label of labels.tasks) {
    const selectedTask = selectionByTask.get(label.taskId);
    const adjudicatedTask = adjudicationByTask.get(label.taskId);
    if (!selectedTask || !adjudicatedTask) throw new Error(`Missing task ${label.taskId}`);
    const selectedIds = selectedTask.selected.map(item => item.policyId);
    assertSameIds(
      `selected assessments for ${label.taskId}`,
      adjudicatedTask.selectedAssessments.map(item => item.selectedPolicyId),
      selectedIds
    );
    assertSameIds(
      `required assessments for ${label.taskId}`,
      adjudicatedTask.requiredAssessments.map(item => item.labeledPolicyId),
      label.requiredPolicyIds
    );
    const selectedIdSet = new Set(selectedIds);
    for (const assessment of adjudicatedTask.requiredAssessments) {
      if (assessment.coveredBySelectedPolicyIds.some(id => !selectedIdSet.has(id))) {
        throw new Error(`Required assessment for ${label.taskId} references an unselected policy`);
      }
    }
    const labeledIdSet = new Set([...label.requiredPolicyIds, ...label.relevantPolicyIds]);
    for (const assessment of adjudicatedTask.selectedAssessments) {
      if (assessment.matchedLabeledPolicyIds.some(id => !labeledIdSet.has(id))) {
        throw new Error(`Selected assessment for ${label.taskId} references an unknown label`);
      }
    }
  }
}

async function writeFormattedJson(path: string, value: unknown): Promise<void> {
  const prettierConfig = await resolveConfig(path);
  const output = await format(JSON.stringify(value), { ...prettierConfig, filepath: path });
  await writeFile(path, output, 'utf-8');
}

async function main(): Promise<void> {
  const [labelsText, selection, baseline, adjudication] = await Promise.all([
    readFile(LABELS_PATH, 'utf-8'),
    readFile(SELECTION_PATH, 'utf-8').then(text => JSON.parse(text) as SemanticSelection),
    readFile(BASELINE_PATH, 'utf-8').then(text => JSON.parse(text) as BaselineEvaluation),
    readFile(ADJUDICATION_PATH, 'utf-8').then(text => JSON.parse(text) as SemanticAdjudication),
  ]);
  const labels = JSON.parse(labelsText) as SilverLabels;
  validateEvaluationIntegrity(labels, labelsText, selection, adjudication);
  const selectionByTask = new Map(selection.tasks.map(task => [task.taskId, task]));

  const tasks = labels.tasks.map(label => {
    const selectedTask = selectionByTask.get(label.taskId);
    if (!selectedTask) throw new Error(`Missing semantic selection for ${label.taskId}`);
    const selectedPolicyIds = selectedTask.selected.map(item => item.policyId);
    const required = new Set(label.requiredPolicyIds);
    const relevant = new Set(label.relevantPolicyIds);
    const acceptable = new Set([...required, ...relevant]);
    return {
      taskId: label.taskId,
      selectedPolicyIds,
      foundRequiredPolicyIds: selectedPolicyIds.filter(id => required.has(id)).sort(),
      missingRequiredPolicyIds: label.requiredPolicyIds
        .filter(id => !selectedPolicyIds.includes(id))
        .sort(),
      foundRelevantPolicyIds: selectedPolicyIds.filter(id => relevant.has(id)).sort(),
      unexpectedPolicyIds: selectedPolicyIds.filter(id => !acceptable.has(id)).sort(),
      coverageGaps: selectedTask.coverageGaps,
    };
  });

  const totalRequired = labels.tasks.reduce((sum, task) => sum + task.requiredPolicyIds.length, 0);
  const foundRequired = tasks.reduce((sum, task) => sum + task.foundRequiredPolicyIds.length, 0);
  const totalSelected = tasks.reduce((sum, task) => sum + task.selectedPolicyIds.length, 0);
  const acceptableSelected = tasks.reduce(
    (sum, task) => sum + task.foundRequiredPolicyIds.length + task.foundRelevantPolicyIds.length,
    0
  );
  const requiredAssessments = adjudication.tasks.flatMap(task => task.requiredAssessments);
  const selectedAssessments = adjudication.tasks.flatMap(task => task.selectedAssessments);
  const semanticallyCoveredRequired = requiredAssessments.filter(
    assessment => assessment.status !== 'missing'
  ).length;
  const semanticallyRelevantSelected = selectedAssessments.filter(
    assessment => assessment.verdict !== 'irrelevant'
  ).length;

  const output = {
    caution: [
      'Both reference sets use independent model-generated silver labels, not expert ground truth.',
      'The baseline and expanded selector use different corpora and separately adapted labels, so the comparison demonstrates prototype progression rather than a controlled selector-only ablation.',
      'The preserved semantic selection received reference task-family metadata; rerun the corrected selector before making classification-independent performance claims.',
      'Exact policy-ID scoring does not credit an unlabelled but semantically equivalent policy.',
    ],
    deterministicBaseline: baseline.metrics,
    semanticExpanded: {
      configuredModel: selection.configuredModel,
      reportedModelIds: selection.reportedModelIds,
      catalogSize: selection.catalogSize,
      labelVersion: labels.version,
      labelType: labels.labelType,
      strictIdMetrics: {
        taskCount: tasks.length,
        requiredPolicyRecall: ratio(foundRequired, totalRequired),
        acceptableSelectionPrecision: ratio(acceptableSelected, totalSelected),
        averageSelectedPolicies: ratio(totalSelected, tasks.length),
        tasksReportingCoverageGaps: tasks.filter(task => task.coverageGaps.length > 0).length,
      },
      adjudicatedControlMetrics: {
        adjudicationVersion: adjudication.version,
        adjudicatorRole: adjudication.adjudicatorRole,
        requiredControlRecall: ratio(semanticallyCoveredRequired, requiredAssessments.length),
        relevantControlPrecision: ratio(semanticallyRelevantSelected, selectedAssessments.length),
        exactRequiredMatches: requiredAssessments.filter(
          assessment => assessment.status === 'covered_exact'
        ).length,
        equivalentRequiredMatches: requiredAssessments.filter(
          assessment => assessment.status === 'covered_equivalent'
        ).length,
        missingRequiredControls: requiredAssessments.filter(
          assessment => assessment.status === 'missing'
        ).length,
        irrelevantSelections: selectedAssessments.filter(
          assessment => assessment.verdict === 'irrelevant'
        ).length,
      },
    },
    tasks,
  };

  await writeFormattedJson(OUTPUT_PATH, output);
  console.log(`Wrote semantic-selector comparison to ${OUTPUT_PATH}`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
