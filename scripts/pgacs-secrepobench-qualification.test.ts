import { describe, expect, test } from 'bun:test';
import {
  assertPgacsEvaluatorMatchesQualification,
  buildPgacsQualificationReceipt,
  verifyPgacsQualificationReceipt,
} from './pgacs-secrepobench-qualification';

const oracleText = 'qualified oracle\n';
const taskFixtures = [
  { taskId: '910', projectName: 'lcms' },
  { taskId: '1065', projectName: 'file' },
  { taskId: '19902', projectName: 'mruby' },
] as const;
const registryText = JSON.stringify({
  schemaVersion: '0.1.0',
  sourceManifest: 'SecRepoBench@7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76:sample_metadata.json',
  tasks: taskFixtures.map(task => ({
    id: `secrepobench-${task.taskId}`,
    provenance: { sourceTaskId: task.taskId, datasetSha256: 'a'.repeat(64) },
    evaluator: {
      sourceSha256: new Bun.CryptoHasher('sha256').update(oracleText).digest('hex'),
      secRepoBench: {
        projectName: task.projectName,
        arvoImage: `n132/arvo:${task.taskId}-fix`,
      },
    },
  })),
});
const summaryText = JSON.stringify({
  schemaVersion: '0.2.0',
  repetitions: 3,
  passed: true,
  environment: {
    host: { os: 'linux', architecture: 'amd64' },
    images: taskFixtures.map(task => ({
      reference: `n132/arvo:${task.taskId}-fix`,
      imageId: `sha256:${task.taskId.padStart(64, '0')}`,
      repoDigests: [`n132/arvo@sha256:${task.taskId.padStart(64, '1')}`],
      os: 'linux',
      architecture: 'amd64',
    })),
  },
  results: taskFixtures.flatMap(task =>
    ['secure', 'vulnerable'].flatMap(variant =>
      [1, 2, 3].map(() => {
        const decision = variant === 'secure' ? 'verified' : 'insecure';
        return {
          taskId: task.taskId,
          variant,
          expectedDecision: decision,
          passed: true,
          evaluation: {
            oracleId: 'pgacs-secrepobench:single-task:v0.6',
            oracleVersion: '0.6.0',
            decision,
            probes: [{ durationMs: 10 }, { durationMs: 20 }, { durationMs: 30 }],
          },
        };
      })
    )
  ),
});

describe('PGACS SecRepoBench qualification receipt', (): void => {
  test('builds and verifies a digest-bound receipt', (): void => {
    const receipt = buildPgacsQualificationReceipt({
      summaryText,
      registryText,
      oracleText,
      qualifiedOn: '2026-08-18',
    });
    expect(receipt.calibration).toMatchObject({
      resultCount: 18,
      allPassed: true,
      decisionCounts: { insecure: 9, verified: 9 },
      probeCount: 54,
    });
    expect(receipt.environment).toMatchObject({
      host: { os: 'linux', architecture: 'amd64' },
    });
    expect(
      verifyPgacsQualificationReceipt({
        receiptText: JSON.stringify(receipt),
        oracleText,
        summaryText,
        registryText,
      })
    ).toEqual([]);
  });

  test('detects oracle and local evidence drift', (): void => {
    const receipt = buildPgacsQualificationReceipt({
      summaryText,
      registryText,
      oracleText,
      qualifiedOn: '2026-08-18',
    });
    expect(
      verifyPgacsQualificationReceipt({
        receiptText: JSON.stringify(receipt),
        oracleText: 'changed oracle\n',
        summaryText: `${summaryText}\n`,
        registryText,
      })
    ).toEqual([
      'oracle source digest no longer matches the qualified source',
      'local calibration summary does not match the tracked receipt',
    ]);
  });

  test('rejects calibration evidence from a non-native environment', (): void => {
    const summary = JSON.parse(summaryText) as Record<string, unknown>;
    summary.environment = {
      host: { os: 'linux', architecture: 'arm64' },
      images: [],
    };
    expect(() =>
      buildPgacsQualificationReceipt({
        summaryText: JSON.stringify(summary),
        registryText,
        oracleText,
        qualifiedOn: '2026-08-18',
      })
    ).toThrow('calibration summary was not produced on native amd64');
  });

  test('rejects evaluator image identities without immutable digests', (): void => {
    const summary = JSON.parse(summaryText) as {
      environment: { images: Array<Record<string, unknown>> };
    };
    summary.environment.images[0] = {
      ...summary.environment.images[0],
      repoDigests: [],
    };
    expect(() =>
      buildPgacsQualificationReceipt({
        summaryText: JSON.stringify(summary),
        registryText,
        oracleText,
        qualifiedOn: '2026-08-18',
      })
    ).toThrow('lacks immutable repository digests');
  });

  test('rejects runtime evaluator digest drift', (): void => {
    const receipt = buildPgacsQualificationReceipt({
      summaryText,
      registryText,
      oracleText,
      qualifiedOn: '2026-08-18',
    });
    const qualified = receipt.environment.images[0];
    if (!qualified) throw new Error('fixture image is missing');
    expect(() =>
      assertPgacsEvaluatorMatchesQualification({
        current: {
          reference: qualified.reference,
          imageId: qualified.imageId,
          repoDigests: ['n132/arvo@sha256:' + 'f'.repeat(64)],
          hostArchitecture: 'amd64',
          imageArchitecture: 'amd64',
          hostOs: 'linux',
          imageOs: 'linux',
        },
        qualified,
        qualifiedHostOs: 'linux',
      })
    ).toThrow('does not match its native qualification');
  });
});
