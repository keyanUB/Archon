import { describe, expect, test } from 'bun:test';

import { parseOpenHandsBridgeResponse } from './pgacs-secrepobench-openhands-driver';

const HASH = 'a'.repeat(64);

describe('OpenHands PGACS bridge protocol', (): void => {
  test('accepts a capability-bound response after log lines', () => {
    const response = parseOpenHandsBridgeResponse(
      `sdk log\n${JSON.stringify({
        protocolVersion: '1.1',
        submitted: true,
        transcriptSha256: HASH,
        observedEvents: [],
        modelIds: ['openrouter/qwen/qwen3-coder'],
        runtimeReceipt: {
          framework: 'openhands-sdk',
          versions: { openhandsSdk: '1.42.1', openhandsTools: '1.42.1' },
          toolSurface: ['PgacsWorkspaceTool'],
          shellEnabled: false,
          browserEnabled: false,
          mcpEnabled: false,
          targetOnlyWrites: true,
          repositoryOnlyReads: true,
          postWriteConditioning: true,
          costAccounting: 'unavailable',
          costSource: 'unavailable',
          monetaryBudgetEnforced: false,
        },
      })}\n`
    );
    expect(response.submitted).toBe(true);
    expect(response.runtimeReceipt?.shellEnabled).toBe(false);
  });

  test('rejects protocol drift and malformed receipts', () => {
    expect(() =>
      parseOpenHandsBridgeResponse(
        JSON.stringify({
          protocolVersion: '2.0',
          submitted: false,
          transcriptSha256: HASH,
          observedEvents: [],
        })
      )
    ).toThrow('Unsupported OpenHands bridge protocol');
    expect(() =>
      parseOpenHandsBridgeResponse(
        JSON.stringify({
          protocolVersion: '1.1',
          submitted: true,
          transcriptSha256: HASH,
          observedEvents: [],
          runtimeReceipt: {
            framework: 'openhands-sdk',
            versions: {},
            toolSurface: ['pgacs_workspace'],
            costAccounting: 'unavailable',
            costSource: 'unavailable',
            monetaryBudgetEnforced: false,
          },
        })
      )
    ).toThrow('shellEnabled');
  });

  test('rejects contradictory or fabricated cost observations', () => {
    const base = {
      protocolVersion: '1.1',
      submitted: true,
      transcriptSha256: HASH,
      observedEvents: [],
      runtimeReceipt: {
        framework: 'openhands-sdk',
        versions: {},
        toolSurface: ['pgacs_workspace'],
        shellEnabled: false,
        browserEnabled: false,
        mcpEnabled: false,
        targetOnlyWrites: true,
        repositoryOnlyReads: true,
        postWriteConditioning: false,
        costAccounting: 'unavailable',
        costSource: 'unavailable',
        monetaryBudgetEnforced: false,
      },
    };
    expect(() =>
      parseOpenHandsBridgeResponse(JSON.stringify({ ...base, totalCostUsd: 0 }))
    ).toThrow('reported cost while cost accounting is unavailable');
    expect(() =>
      parseOpenHandsBridgeResponse(
        JSON.stringify({
          ...base,
          runtimeReceipt: {
            ...base.runtimeReceipt,
            costAccounting: 'available',
            costSource: 'litellm_model_map',
          },
        })
      )
    ).toThrow('inconsistent cost accounting receipt');

    expect(() =>
      parseOpenHandsBridgeResponse(
        JSON.stringify({
          ...base,
          totalCostUsd: 0.001,
          runtimeReceipt: {
            ...base.runtimeReceipt,
            costAccounting: 'available',
            costSource: 'explicit',
            monetaryBudgetEnforced: true,
            inputCostPerTokenUsd: 0.000001,
            outputCostPerTokenUsd: 0.000002,
          },
        })
      )
    ).not.toThrow();
  });
});
