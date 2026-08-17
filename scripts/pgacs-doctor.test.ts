import { describe, expect, test } from 'bun:test';
import { collectPgacsDoctorReport, explicitRatesConfigured } from './pgacs-doctor';

describe('PGACS doctor', (): void => {
  test('reports this checkout as ready for offline development', async () => {
    const report = await collectPgacsDoctorReport();
    expect(report.offlineDevelopment).toBe('ready');
    expect(report.checks.filter((check): boolean => check.requiredFor === 'offline')).toHaveLength(
      2
    );
  });

  test('requires an explicit valid pair of token rates', (): void => {
    expect(explicitRatesConfigured({})).toBe(false);
    expect(explicitRatesConfigured({ LLM_INPUT_COST_PER_TOKEN_USD: '0.1' })).toBe(false);
    expect(
      explicitRatesConfigured({
        LLM_INPUT_COST_PER_TOKEN_USD: 'Infinity',
        LLM_OUTPUT_COST_PER_TOKEN_USD: '0.2',
      })
    ).toBe(false);
    expect(
      explicitRatesConfigured({
        LLM_INPUT_COST_PER_TOKEN_USD: 'invalid',
        LLM_OUTPUT_COST_PER_TOKEN_USD: '0.2',
      })
    ).toBe(false);
    expect(
      explicitRatesConfigured({
        LLM_INPUT_COST_PER_TOKEN_USD: '0.1',
        LLM_OUTPUT_COST_PER_TOKEN_USD: '0.2',
      })
    ).toBe(true);
  });

  test('supports a machine-readable command result', async () => {
    const subprocess = Bun.spawn(['bun', 'run', 'scripts/pgacs-doctor.ts', '--json'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(subprocess.stdout).text(),
      new Response(subprocess.stderr).text(),
      subprocess.exited,
    ]);
    expect(exitCode).toBe(0);
    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toMatchObject({
      schemaVersion: '0.1.0',
      offlineDevelopment: 'ready',
    });
  });
});
