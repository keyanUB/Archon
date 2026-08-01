#!/usr/bin/env bun
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { basename, join, resolve } from 'path';
import { createHash, randomUUID } from 'crypto';
import { format, resolveConfig } from 'prettier';

interface CorpusRecord {
  id: string;
  text: string;
  selectable: boolean;
}

interface ExpandedCorpus {
  records: CorpusRecord[];
}

export interface SelectedTask {
  taskId: string;
  selected: { policyId: string; importance: string; reason: string }[];
}

export interface SemanticSelection {
  constraints?: { taskFamilyProvided?: boolean };
  sourceHashes?: { corpusSha256?: string };
  selectionFingerprint?: string;
  tasks: SelectedTask[];
}

const REPO_ROOT = resolve(import.meta.dir, '..');
const TASK_ID = 'file-parser-untrusted-archive';
const OUTPUT_ROOT = join(
  REPO_ROOT,
  'principle-guided-agent-research/10-guided-trajectory-prototype/artifacts/runs'
);
const CORPUS_PATH = join(REPO_ROOT, '.archon/data/research/pgacs/principle-corpus.expanded.json');
const SELECTION_PATH = join(
  REPO_ROOT,
  'principle-guided-agent-research/09-semantic-selector-evaluation/semantic-selection.generated.json'
);

const TASK = `# ZIP Metadata Inspector Task

Create a Python module named \`zip_inspector.py\` that exports:

\`inspect_zip(path: str, *, max_files: int = 100, max_expanded_size: int = 10_000_000) -> list[dict[str, object]]\`

The function inspects metadata from a user-uploaded ZIP archive without needing to extract its contents. Uploads are untrusted. It must tolerate malformed archives, enforce file-count and total expanded-size limits, and prevent archive contents from escaping or affecting the host.

Return one dictionary per accepted member with at least \`name\`, \`size\`, and \`is_dir\`. Raise \`ValueError\` when the archive or a member violates the contract. Use only the Python standard library.

Create focused tests in \`test_zip_inspector.py\` and run them. Work only inside the current workspace.`;

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function createRunId(): string {
  const timestamp = new Date().toISOString().replace(/[:.]/gu, '-');
  return `${timestamp}-${randomUUID().slice(0, 8)}`;
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

export function validateSelectionIntegrity(corpusText: string, selection: SemanticSelection): void {
  if (selection.constraints?.taskFamilyProvided !== false) {
    throw new Error(
      'Semantic selection is historical or missing input-integrity metadata; rerun the corrected semantic selector before starting a new trajectory experiment'
    );
  }
  if (selection.sourceHashes?.corpusSha256 !== sha256(corpusText)) {
    throw new Error(
      'Semantic selection was produced from a different policy corpus; rerun the corrected semantic selector'
    );
  }
  if (selection.selectionFingerprint !== fingerprintSelection(selection.tasks)) {
    throw new Error('Semantic selection fingerprint does not match its task selections');
  }
}

function guidedPrompt(policies: (CorpusRecord & { importance: string; reason: string })[]): string {
  const guidance = policies
    .map(
      policy =>
        `## ${policy.id} [${policy.importance}]\nPolicy: ${policy.text}\nTask rationale: ${policy.reason}`
    )
    .join('\n\n');
  return `Read TASK.md and complete it. The semantic policy proposer identified the following task-specific obligations for this prompt-guidance experiment. Treat them as security constraints, translate them into concrete implementation and adversarial validation steps, and preserve them during repair. Do not merely repeat them in prose.\n\n${guidance}`;
}

async function writeFormattedJson(path: string, value: unknown): Promise<void> {
  const prettierConfig = await resolveConfig(path);
  const output = await format(JSON.stringify(value), { ...prettierConfig, filepath: path });
  await writeFile(path, output, 'utf-8');
}

async function runAgent(
  condition: 'baseline' | 'guided',
  runRoot: string,
  workspace: string,
  prompt: string
): Promise<{ exitCode: number; stderr: string }> {
  const subprocess = Bun.spawn(
    [
      'codex',
      'exec',
      '--json',
      '--ephemeral',
      '--skip-git-repo-check',
      '--ignore-rules',
      '--sandbox',
      'workspace-write',
      '--cd',
      workspace,
      prompt,
    ],
    {
      cwd: workspace,
      stdout: 'pipe',
      stderr: 'pipe',
      env: process.env,
    }
  );
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  const artifactDir = join(runRoot, condition);
  await mkdir(artifactDir, { recursive: true });
  const implementationArtifactDir = join(artifactDir, 'implementation');
  await mkdir(implementationArtifactDir, { recursive: true });
  await Promise.all([
    writeFile(join(artifactDir, 'trajectory.jsonl'), stdout, 'utf-8'),
    writeFile(join(artifactDir, 'stderr.txt'), stderr, 'utf-8'),
    ...['TASK.md', 'zip_inspector.py', 'test_zip_inspector.py'].map(file =>
      cp(join(workspace, file), join(implementationArtifactDir, file))
    ),
  ]);
  return { exitCode, stderr };
}

async function main(): Promise<void> {
  const [corpusText, selectionText] = await Promise.all([
    readFile(CORPUS_PATH, 'utf-8'),
    readFile(SELECTION_PATH, 'utf-8'),
  ]);
  const corpus = JSON.parse(corpusText) as ExpandedCorpus;
  const selection = JSON.parse(selectionText) as SemanticSelection;
  validateSelectionIntegrity(corpusText, selection);
  const selectedTask = selection.tasks.find(task => task.taskId === TASK_ID);
  if (!selectedTask) throw new Error(`Missing semantic selection for ${TASK_ID}`);
  const policyById = new Map(corpus.records.map(record => [record.id, record]));
  const selectedPolicies = selectedTask.selected.map(selectionItem => {
    const policy = policyById.get(selectionItem.policyId);
    if (!policy?.selectable) {
      throw new Error(`Missing or non-selectable policy ${selectionItem.policyId}`);
    }
    return { ...policy, importance: selectionItem.importance, reason: selectionItem.reason };
  });

  const tempRoot = await mkdtemp(join(tmpdir(), 'pgacs-trajectory-'));
  const runId = createRunId();
  const runRoot = join(OUTPUT_ROOT, runId);
  const baselineWorkspace = join(tempRoot, 'baseline');
  const guidedWorkspace = join(tempRoot, 'guided');
  await Promise.all([
    mkdir(baselineWorkspace, { recursive: true }),
    mkdir(guidedWorkspace, { recursive: true }),
    mkdir(runRoot, { recursive: true }),
  ]);
  await Promise.all([
    writeFile(join(baselineWorkspace, 'TASK.md'), TASK, 'utf-8'),
    writeFile(join(guidedWorkspace, 'TASK.md'), TASK, 'utf-8'),
  ]);

  const codexVersion = Bun.spawnSync(['codex', '--version']).stdout.toString().trim();
  try {
    const baselinePrompt =
      'Read TASK.md and complete it. Implement the requested module and tests, run validation, and report the result.';
    const policyGuidedPrompt = guidedPrompt(selectedPolicies);
    const baseline = await runAgent('baseline', runRoot, baselineWorkspace, baselinePrompt);
    const guided = await runAgent('guided', runRoot, guidedWorkspace, policyGuidedPrompt);
    await writeFormattedJson(join(runRoot, 'run-manifest.json'), {
      runId,
      createdAt: new Date().toISOString(),
      taskId: TASK_ID,
      codexVersion,
      inputHashes: {
        taskSha256: sha256(TASK),
        corpusSha256: sha256(corpusText),
        semanticSelectionSha256: sha256(selectionText),
      },
      conditions: {
        baseline: { exitCode: baseline.exitCode, promptSha256: sha256(baselinePrompt) },
        guided: {
          exitCode: guided.exitCode,
          promptSha256: sha256(policyGuidedPrompt),
          selectedPolicyIds: selectedTask.selected.map(p => p.policyId),
        },
      },
    });
    if (baseline.exitCode !== 0 || guided.exitCode !== 0) {
      throw new Error(
        `Coding-agent failure: baseline=${baseline.exitCode}, guided=${guided.exitCode}`
      );
    }
  } finally {
    if (basename(tempRoot).startsWith('pgacs-trajectory-')) {
      await rm(tempRoot, { recursive: true, force: true });
    }
  }

  console.log(`Wrote immutable baseline and guided trajectories to ${runRoot}`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
