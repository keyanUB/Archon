#!/usr/bin/env bun
import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { format, resolveConfig } from 'prettier';

type CorpusRecordKind = 'principle' | 'policy' | 'category_summary' | 'quick_reference';

interface PrincipleCorpusRecord {
  id: string;
  source: string;
  sourceRef: string;
  kind: CorpusRecordKind;
  category?: string;
  text: string;
  cweTags: string[];
  selectable: boolean;
  provenance: {
    path: string;
    recordId: string;
  };
}

interface GraspNode {
  id: string;
  category: string;
  is_category_node?: boolean;
  principle: string;
  cwe_tags?: string[];
}

interface GraspGraph {
  nodes: GraspNode[];
}

interface SetupPolicy {
  policy_id: string;
  source: string;
  setup_env_theme?: string;
  policy_description: string;
  reference?: string[];
}

interface SetupPolicyCorpus {
  policies: SetupPolicy[];
}

const REPO_ROOT = resolve(import.meta.dir, '..');
const GRASP_GRAPH_PATH = '.archon/data/research/grasp-secure-coding/scp-graph.json';
const OWASP_QUICK_REFERENCE_PATH = '.archon/data/research/grasp-secure-coding/owasp-scp.md';
const SETUP_POLICY_PATH =
  '.archon/data/research/secure-environment-setup/setup-environment-policies.json';
const OUTPUT_PATH = '.archon/data/research/pgacs/principle-corpus.expanded.json';

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-|-$/gu, '');
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

export function recordsFromGraspGraph(graph: GraspGraph): PrincipleCorpusRecord[] {
  return graph.nodes.map(node => ({
    id: `grasp-scp:${node.id}`,
    source: 'OWASP Secure Coding Practices / GRASP graph',
    sourceRef: node.id,
    kind: node.is_category_node ? 'category_summary' : 'principle',
    category: node.category,
    text: node.principle.trim(),
    cweTags: unique(node.cwe_tags ?? []),
    selectable: !node.is_category_node,
    provenance: {
      path: GRASP_GRAPH_PATH,
      recordId: node.id,
    },
  }));
}

export function recordsFromSetupPolicies(corpus: SetupPolicyCorpus): PrincipleCorpusRecord[] {
  return corpus.policies.map(policy => ({
    id: `setup:${policy.policy_id}`,
    source: policy.source,
    sourceRef: policy.policy_id,
    kind: 'policy',
    category: policy.setup_env_theme,
    text: policy.policy_description.trim(),
    cweTags: unique((policy.reference ?? []).filter(reference => /^CWE-\d+$/u.test(reference))),
    selectable: true,
    provenance: {
      path: SETUP_POLICY_PATH,
      recordId: policy.policy_id,
    },
  }));
}

export function recordsFromQuickReference(markdown: string): PrincipleCorpusRecord[] {
  const records: PrincipleCorpusRecord[] = [];
  let category = '';
  let categoryIndex = 0;

  for (const rawLine of markdown.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.startsWith('## ')) {
      category = line.slice(3).trim();
      categoryIndex = 0;
      continue;
    }
    if (!category || !line.startsWith('- ')) continue;

    categoryIndex += 1;
    const sourceRef = `${slug(category)}-${String(categoryIndex).padStart(2, '0')}`;
    records.push({
      id: `owasp-scp-quick:${sourceRef}`,
      source: 'OWASP Secure Coding Practices Quick Reference',
      sourceRef,
      kind: 'quick_reference',
      category,
      text: line.slice(2).trim(),
      cweTags: [],
      selectable: false,
      provenance: {
        path: OWASP_QUICK_REFERENCE_PATH,
        recordId: sourceRef,
      },
    });
  }

  return records;
}

function countBy<T extends string>(values: T[]): Record<T, number> {
  const counts = {} as Record<T, number>;
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function validateRecords(records: PrincipleCorpusRecord[]): void {
  const ids = new Set<string>();
  for (const record of records) {
    if (!record.id || !record.text || !record.source || !record.sourceRef) {
      throw new Error(`Invalid corpus record: ${record.id || '<missing id>'}`);
    }
    if (ids.has(record.id)) throw new Error(`Duplicate corpus record id: ${record.id}`);
    ids.add(record.id);
  }
}

async function main(): Promise<void> {
  const [graphText, setupText, quickReference] = await Promise.all([
    readFile(join(REPO_ROOT, GRASP_GRAPH_PATH), 'utf-8'),
    readFile(join(REPO_ROOT, SETUP_POLICY_PATH), 'utf-8'),
    readFile(join(REPO_ROOT, OWASP_QUICK_REFERENCE_PATH), 'utf-8'),
  ]);
  const graph = JSON.parse(graphText) as GraspGraph;
  const setupCorpus = JSON.parse(setupText) as SetupPolicyCorpus;
  if (!Array.isArray(graph.nodes) || !Array.isArray(setupCorpus.policies)) {
    throw new Error('Invalid prepared principle source');
  }

  const records = [
    ...recordsFromGraspGraph(graph),
    ...recordsFromSetupPolicies(setupCorpus),
    ...recordsFromQuickReference(quickReference),
  ].sort((left, right) => left.id.localeCompare(right.id));
  validateRecords(records);

  const corpus = {
    metadata: {
      version: '0.1.0',
      purpose: 'Compact semantic catalog of all principle and policy sources prepared in Archon.',
      sourcePaths: [GRASP_GRAPH_PATH, SETUP_POLICY_PATH, OWASP_QUICK_REFERENCE_PATH],
      totalRecords: records.length,
      selectableRecords: records.filter(record => record.selectable).length,
      contextOnlyRecords: records.filter(record => !record.selectable).length,
      countsByKind: countBy(records.map(record => record.kind)),
      countsBySource: countBy(records.map(record => record.source)),
    },
    records,
  };

  const absoluteOutputPath = join(REPO_ROOT, OUTPUT_PATH);
  const prettierConfig = await resolveConfig(absoluteOutputPath);
  const output = await format(JSON.stringify(corpus), {
    ...prettierConfig,
    filepath: absoluteOutputPath,
  });
  await writeFile(absoluteOutputPath, output, 'utf-8');
  console.log(
    `Wrote ${records.length} records (${corpus.metadata.selectableRecords} selectable) to ${absoluteOutputPath}`
  );
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
