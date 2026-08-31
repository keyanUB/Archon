import { describe, expect, test } from 'bun:test';
import { join } from 'node:path';

import { assertNativeEvaluatorArchitecture } from './pgacs-secrepobench-official-evaluator';

async function parseSecurity(stderr: string): Promise<string> {
  const source = join(import.meta.dir, 'secrepobench/pgacs_secrepobench_oracle.py');
  const program = [
    'import importlib.util, subprocess, sys',
    'spec = importlib.util.spec_from_file_location("oracle", sys.argv[1])',
    'module = importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(module)',
    'process = subprocess.CompletedProcess([], 1, stdout=b"", stderr=sys.argv[2].encode())',
    'try:',
    '    print(module.parse_security(process))',
    'except module.ParseException:',
    '    print("inconclusive")',
  ].join('\n');
  const subprocess = Bun.spawn(['python3', '-c', program, source, stderr], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, processStderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(processStderr);
  return stdout.trim();
}

async function parseDeveloperTests(stdout: string, project: string): Promise<unknown> {
  const source = join(import.meta.dir, 'secrepobench/pgacs_secrepobench_oracle.py');
  const program = [
    'import importlib.util, json, subprocess, sys',
    'spec = importlib.util.spec_from_file_location("oracle", sys.argv[1])',
    'module = importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(module)',
    'process = subprocess.CompletedProcess([], 1, stdout=sys.argv[2].encode(), stderr=b"")',
    'print(json.dumps(module.parse_developer_tests(process, sys.argv[3])))',
  ].join('\n');
  const subprocess = Bun.spawn(['python3', '-c', program, source, stdout, project], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [result, processStderr, exitCode] = await Promise.all([
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
    subprocess.exited,
  ]);
  if (exitCode !== 0) throw new Error(processStderr);
  return JSON.parse(result) as unknown;
}

describe('SecRepoBench security parser', (): void => {
  test('does not treat a fixing commit subject as sanitizer evidence', async (): Promise<void> => {
    expect(
      await parseSecurity('HEAD is now at d9051f8 Fix runtime error: index out of bounds')
    ).toBe('inconclusive');
  });

  test('recognizes structured ASan and UBSan evidence', async (): Promise<void> => {
    expect(await parseSecurity('==42==ERROR: AddressSanitizer: heap-buffer-overflow')).toBe(
      'crash'
    );
    expect(
      await parseSecurity('/src/project/file.c:12:4: runtime error: index out of bounds')
    ).toBe('crash');
    expect(await parseSecurity('==42==WARNING: MemorySanitizer: use-of-uninitialized-value')).toBe(
      'crash'
    );
  });

  test('classifies MRuby dot and F statuses without ambiguity', async (): Promise<void> => {
    expect(await parseDeveloperTests('String#safe : .\nString#unsafe : F\n', 'mruby')).toEqual({
      pass: ['String#safe'],
      fail: ['String#unsafe'],
      skip: [],
      total: 2,
    });
  });
});

describe('SecRepoBench evaluator platform', (): void => {
  test('accepts canonical architecture aliases', (): void => {
    expect(() =>
      assertNativeEvaluatorArchitecture({
        hostArchitecture: 'aarch64',
        imageArchitecture: 'arm64',
      })
    ).not.toThrow();
    expect(() =>
      assertNativeEvaluatorArchitecture({
        hostArchitecture: 'x86_64',
        imageArchitecture: 'amd64',
      })
    ).not.toThrow();
  });

  test('rejects emulated sanitizer execution', (): void => {
    expect(() =>
      assertNativeEvaluatorArchitecture({
        hostArchitecture: 'aarch64',
        imageArchitecture: 'amd64',
      })
    ).toThrow('requires a native image');
  });
});
