import { describe, expect, test } from 'bun:test';

async function invoke(options: string[]): Promise<{ exitCode: number; stderr: string }> {
  const subprocess = Bun.spawn(
    [
      'bun',
      'run',
      new URL('./run-pgacs-secrepobench.ts', import.meta.url).pathname,
      'registry.json',
      '910',
      'source',
      'mask.c',
      'evaluator',
      'output',
      ...options,
    ],
    { stdout: 'pipe', stderr: 'pipe' }
  );
  const [stderr, exitCode] = await Promise.all([
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  return { exitCode, stderr };
}

describe('SecRepoBench runner execution contract', (): void => {
  test('rejects comparative conditions without an explicit model and budget', async () => {
    const result = await invoke(['--conditions=C1']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(
      'Comparative conditions require explicit --model, --max-turns, and --max-budget-usd'
    );
  });

  test('rejects invalid turn and cost limits before preflight', async () => {
    const turns = await invoke([
      '--conditions=C1',
      '--model=claude-sonnet-5',
      '--max-turns=0',
      '--max-budget-usd=5',
    ]);
    expect(turns.exitCode).not.toBe(0);
    expect(turns.stderr).toContain('max-turns must be an integer from 1 to 100');

    const budget = await invoke([
      '--conditions=C1',
      '--model=claude-sonnet-5',
      '--max-turns=30',
      '--max-budget-usd=0',
    ]);
    expect(budget.exitCode).not.toBe(0);
    expect(budget.stderr).toContain('max-budget-usd must be a positive number');
  });

  test('rejects duplicate execution-contract options', async () => {
    const result = await invoke(['--conditions=C0', '--conditions=C1']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('Duplicate option: --conditions');
  });

  test('rejects unknown agents and incomplete OpenHands contracts', async () => {
    const unknown = await invoke(['--conditions=C0', '--agent=other']);
    expect(unknown.exitCode).not.toBe(0);
    expect(unknown.stderr).toContain('agent must be claude or openhands');

    const incomplete = await invoke(['--conditions=C0', '--agent=openhands']);
    expect(incomplete.exitCode).not.toBe(0);
    expect(incomplete.stderr).toContain(
      'OpenHands requires explicit --model, --max-turns, and --max-budget-usd'
    );
  });
});
