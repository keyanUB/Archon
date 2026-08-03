import { describe, expect, test } from 'bun:test';
import { readFile } from 'fs/promises';
import { resolve } from 'path';

interface PromptNodeContract {
  id: string;
  allowed_tools?: string[];
  denied_tools?: string[];
}

interface WorkflowIsolationContract {
  sandbox?: {
    enabled?: boolean;
    failIfUnavailable?: boolean;
    autoAllowBashIfSandboxed?: boolean;
    allowUnsandboxedCommands?: boolean;
    network?: {
      allowedDomains?: string[];
      deniedDomains?: string[];
    };
    filesystem?: {
      denyRead?: string[];
      denyWrite?: string[];
    };
  };
  nodes?: PromptNodeContract[];
}

const WORKFLOW_PATH = resolve('.archon/workflows/pgacs-zip-c2.yaml');
const AGENT_PHASES: string[] = ['implement', 'repair-once'];
const PROTECTED_ROOTS = [
  'scripts',
  'packages',
  'principle-guided-agent-research',
  '.archon',
  '.git',
  '.codex',
] as const;

async function loadWorkflow(): Promise<WorkflowIsolationContract> {
  const source = await readFile(WORKFLOW_PATH, 'utf8');
  return Bun.YAML.parse(source) as WorkflowIsolationContract;
}

describe('PGACS ZIP workflow isolation contract', () => {
  test('fails closed when the provider Bash sandbox is unavailable', async () => {
    const workflow = await loadWorkflow();

    expect(workflow.sandbox).toMatchObject({
      enabled: true,
      failIfUnavailable: true,
      autoAllowBashIfSandboxed: false,
      allowUnsandboxedCommands: false,
      network: {
        allowedDomains: [],
        deniedDomains: ['*'],
      },
    });
  });

  test('protects control-plane roots in the subprocess sandbox', async () => {
    const workflow = await loadWorkflow();
    const expectedPaths = PROTECTED_ROOTS.map(root => `./${root}`);

    expect(workflow.sandbox?.filesystem?.denyRead).toEqual(expectedPaths);
    expect(workflow.sandbox?.filesystem?.denyWrite).toEqual(expectedPaths);
  });

  test.each(AGENT_PHASES)(
    '%s exposes only file tools and denies control-plane paths',
    async phase => {
      const workflow = await loadWorkflow();
      const node = workflow.nodes?.find(candidate => candidate.id === phase);

      expect(node).toBeDefined();
      expect(node?.allowed_tools).toEqual(['Read', 'Write', 'Edit']);
      for (const root of PROTECTED_ROOTS) {
        expect(node?.denied_tools).toContain(`Read(/${root}/**)`);
        expect(node?.denied_tools).toContain(`Edit(/${root}/**)`);
      }
    }
  );
});
