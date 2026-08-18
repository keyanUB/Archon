import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import type {
  SecRepoBenchAgentAttemptInput,
  SecRepoBenchAgentAttemptResult,
  SecRepoBenchAgentDriver,
  SecRepoBenchAgentEventDraft,
  SecRepoBenchAgentRuntimeReceipt,
} from './pgacs-secrepobench-controller';

const PROTOCOL_VERSION = '1.2';
const MAX_BRIDGE_OUTPUT_BYTES = 2_000_000;

type JsonObject = Record<string, unknown>;

interface OpenHandsBridgeResponse {
  protocolVersion: string;
  submitted: boolean;
  transcriptSha256: string;
  observedEvents: SecRepoBenchAgentEventDraft[];
  reason?: string;
  modelIds?: string[];
  numTurns?: number;
  durationMs?: number;
  totalCostUsd?: number;
  runtimeReceipt?: SecRepoBenchAgentRuntimeReceipt;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optionalFiniteNumber(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new Error(`OpenHands bridge returned invalid ${name}`);
  }
  return value;
}

function stringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) {
    throw new Error(`OpenHands bridge returned invalid ${name}`);
  }
  const result: string[] = [];
  for (const item of value as unknown[]) {
    if (typeof item !== 'string') {
      throw new Error(`OpenHands bridge returned invalid ${name}`);
    }
    result.push(item);
  }
  return result;
}

function requiredBoolean(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') {
    throw new Error(`OpenHands bridge returned invalid runtime receipt field ${name}`);
  }
  return value;
}

function parseCostAccounting(value: unknown): SecRepoBenchAgentRuntimeReceipt['costAccounting'] {
  if (value !== 'available' && value !== 'unavailable') {
    throw new Error('OpenHands bridge returned invalid runtime receipt field costAccounting');
  }
  return value;
}

function parseCostSource(value: unknown): SecRepoBenchAgentRuntimeReceipt['costSource'] {
  if (value !== 'explicit' && value !== 'litellm_model_map' && value !== 'unavailable') {
    throw new Error('OpenHands bridge returned invalid runtime receipt field costSource');
  }
  return value;
}

function parseRuntimeReceipt(value: unknown): SecRepoBenchAgentRuntimeReceipt | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value) || !isObject(value.versions)) {
    throw new Error('OpenHands bridge returned an invalid runtime receipt');
  }
  const versions = Object.fromEntries(
    Object.entries(value.versions).map(([key, version]) => {
      if (typeof version !== 'string') {
        throw new Error('OpenHands bridge returned an invalid runtime version');
      }
      return [key, version];
    })
  );
  const toolSurface = stringArray(value.toolSurface, 'toolSurface');
  if (typeof value.framework !== 'string' || !toolSurface) {
    throw new Error('OpenHands bridge returned an invalid runtime receipt identity');
  }
  const costAccounting = parseCostAccounting(value.costAccounting);
  const costSource = parseCostSource(value.costSource);
  const monetaryBudgetEnforced = requiredBoolean(
    value.monetaryBudgetEnforced,
    'monetaryBudgetEnforced'
  );
  const inputCostPerTokenUsd = optionalFiniteNumber(
    value.inputCostPerTokenUsd,
    'inputCostPerTokenUsd'
  );
  const outputCostPerTokenUsd = optionalFiniteNumber(
    value.outputCostPerTokenUsd,
    'outputCostPerTokenUsd'
  );
  if (
    (costAccounting === 'available') !== monetaryBudgetEnforced ||
    (costAccounting === 'unavailable') !== (costSource === 'unavailable') ||
    (costAccounting === 'available') !==
      (inputCostPerTokenUsd !== undefined && outputCostPerTokenUsd !== undefined) ||
    (costAccounting === 'unavailable' &&
      (inputCostPerTokenUsd !== undefined || outputCostPerTokenUsd !== undefined))
  ) {
    throw new Error('OpenHands bridge returned inconsistent cost accounting receipt');
  }
  return {
    framework: value.framework,
    versions,
    toolSurface,
    shellEnabled: requiredBoolean(value.shellEnabled, 'shellEnabled'),
    browserEnabled: requiredBoolean(value.browserEnabled, 'browserEnabled'),
    mcpEnabled: requiredBoolean(value.mcpEnabled, 'mcpEnabled'),
    targetOnlyWrites: requiredBoolean(value.targetOnlyWrites, 'targetOnlyWrites'),
    repositoryOnlyReads: requiredBoolean(value.repositoryOnlyReads, 'repositoryOnlyReads'),
    preActionConditioning: requiredBoolean(value.preActionConditioning, 'preActionConditioning'),
    costAccounting,
    costSource,
    monetaryBudgetEnforced,
    ...(inputCostPerTokenUsd !== undefined ? { inputCostPerTokenUsd } : {}),
    ...(outputCostPerTokenUsd !== undefined ? { outputCostPerTokenUsd } : {}),
  };
}

function parseObservedEvents(value: unknown): SecRepoBenchAgentEventDraft[] {
  if (!Array.isArray(value)) {
    throw new Error('OpenHands bridge returned invalid observedEvents');
  }
  return value.map(item => {
    if (!isObject(item) || typeof item.eventId !== 'string' || typeof item.kind !== 'string') {
      throw new Error('OpenHands bridge returned an invalid observed event');
    }
    const rawArtifactSha256 = item.rawArtifactSha256;
    if (
      rawArtifactSha256 !== undefined &&
      (typeof rawArtifactSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(rawArtifactSha256))
    ) {
      throw new Error('OpenHands bridge returned an invalid event artifact digest');
    }
    const base = {
      eventId: item.eventId,
      ...(typeof rawArtifactSha256 === 'string' ? { rawArtifactSha256 } : {}),
    };
    if (item.kind === 'file_read' || item.kind === 'symbol_search') {
      if (typeof item.path !== 'string') throw new Error('Observed path must be a string');
      return { ...base, kind: item.kind, path: item.path };
    }
    if (item.kind === 'file_write_attempt') {
      if (typeof item.path !== 'string') throw new Error('Observed path must be a string');
      return { ...base, kind: item.kind, path: item.path };
    }
    if (item.kind === 'file_write_result') {
      if (
        typeof item.path !== 'string' ||
        typeof item.attemptEventId !== 'string' ||
        typeof item.applied !== 'boolean'
      ) {
        throw new Error('OpenHands bridge returned an invalid write result');
      }
      return {
        ...base,
        kind: item.kind,
        path: item.path,
        attemptEventId: item.attemptEventId,
        applied: item.applied,
      };
    }
    if (item.kind === 'command_attempt') {
      if (typeof item.commandClass !== 'string') {
        throw new Error('OpenHands bridge returned an invalid command attempt');
      }
      return { ...base, kind: item.kind, commandClass: item.commandClass };
    }
    if (item.kind === 'command_result') {
      if (typeof item.commandClass !== 'string' || !Number.isSafeInteger(item.exitCode)) {
        throw new Error('OpenHands bridge returned an invalid command result');
      }
      return {
        ...base,
        kind: item.kind,
        commandClass: item.commandClass,
        exitCode: item.exitCode as number,
      };
    }
    if (item.kind === 'diagnostic_observed') {
      if (typeof item.diagnosticClass !== 'string') {
        throw new Error('OpenHands bridge returned an invalid diagnostic event');
      }
      return { ...base, kind: item.kind, diagnosticClass: item.diagnosticClass };
    }
    throw new Error(`OpenHands bridge returned unknown event kind ${item.kind}`);
  });
}

export function parseOpenHandsBridgeResponse(output: string): OpenHandsBridgeResponse {
  if (Buffer.byteLength(output, 'utf8') > MAX_BRIDGE_OUTPUT_BYTES) {
    throw new Error('OpenHands bridge output exceeded the admitted size');
  }
  const lines = output
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const lastLine = lines.at(-1);
  if (!lastLine) throw new Error('OpenHands bridge returned no protocol response');
  const value: unknown = JSON.parse(lastLine);
  if (!isObject(value)) throw new Error('OpenHands bridge response must be a JSON object');
  if (value.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported OpenHands bridge protocol: ${String(value.protocolVersion)}`);
  }
  if (typeof value.submitted !== 'boolean') {
    throw new Error('OpenHands bridge returned invalid submitted status');
  }
  if (
    typeof value.transcriptSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.transcriptSha256)
  ) {
    throw new Error('OpenHands bridge returned invalid transcriptSha256');
  }
  const reason = value.reason;
  if (reason !== undefined && reason !== null && typeof reason !== 'string') {
    throw new Error('OpenHands bridge returned invalid reason');
  }
  const totalCostUsd = optionalFiniteNumber(value.totalCostUsd, 'totalCostUsd');
  const runtimeReceipt = parseRuntimeReceipt(value.runtimeReceipt);
  if (runtimeReceipt?.costAccounting === 'unavailable' && totalCostUsd !== undefined) {
    throw new Error('OpenHands bridge reported cost while cost accounting is unavailable');
  }
  if (runtimeReceipt?.costAccounting === 'available' && totalCostUsd === undefined) {
    throw new Error('OpenHands bridge omitted cost while cost accounting is available');
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    submitted: value.submitted,
    transcriptSha256: value.transcriptSha256,
    observedEvents: parseObservedEvents(value.observedEvents),
    ...(typeof reason === 'string' ? { reason } : {}),
    modelIds: stringArray(value.modelIds, 'modelIds'),
    numTurns: optionalFiniteNumber(value.numTurns, 'numTurns'),
    durationMs: optionalFiniteNumber(value.durationMs, 'durationMs'),
    totalCostUsd,
    runtimeReceipt,
  };
}

function failureTranscript(reason: string): string {
  return createHash('sha256').update(reason).digest('hex');
}

export class SecRepoBenchOpenHandsAgentDriver implements SecRepoBenchAgentDriver {
  readonly id = 'openhands-sdk-qwen-secrepobench-v0.1';
  readonly preActionControl = true;

  constructor(
    private readonly config: {
      model: string;
      maxTurns: number;
      maxBudgetUsd: number;
      pythonExecutable?: string;
      bridgePath?: string;
      timeoutMs?: number;
    }
  ) {}

  async runAttempt(input: SecRepoBenchAgentAttemptInput): Promise<SecRepoBenchAgentAttemptResult> {
    const pythonExecutable =
      this.config.pythonExecutable ??
      process.env.PGACS_OPENHANDS_PYTHON ??
      resolve('.pgacs-openhands/bin/python');
    const bridgePath =
      this.config.bridgePath ?? resolve('scripts/openhands/pgacs_secrepobench_agent.py');
    const request = {
      protocolVersion: PROTOCOL_VERSION,
      workspaceRoot: input.workspaceRoot,
      targetPath: input.task.workspace.targetPath,
      prompt: input.prompt,
      condition: input.condition,
      guidance: input.policyPreparation.guidance,
      preActionControl: input.preActionControl,
      model: this.config.model,
      maxTurns: this.config.maxTurns,
      maxBudgetUsd: this.config.maxBudgetUsd,
    };
    const subprocess = Bun.spawn([pythonExecutable, bridgePath], {
      cwd: process.cwd(),
      stdin: new Blob([JSON.stringify(request)]),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      subprocess.kill();
    }, this.config.timeoutMs ?? 1_200_000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(subprocess.stdout).text(),
        new Response(subprocess.stderr).text(),
        subprocess.exited,
      ]);
      if (timedOut) {
        const reason = 'OpenHands bridge exceeded the attempt timeout';
        return { submitted: false, transcriptSha256: failureTranscript(reason), reason };
      }
      let response: OpenHandsBridgeResponse;
      try {
        response = parseOpenHandsBridgeResponse(stdout);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        const reason = `OpenHands bridge protocol failure: ${detail}`;
        return { submitted: false, transcriptSha256: failureTranscript(reason), reason };
      }
      if (exitCode !== 0 && response.submitted) {
        const reason = `OpenHands bridge exited ${exitCode} after claiming submission`;
        return { submitted: false, transcriptSha256: response.transcriptSha256, reason };
      }
      if (exitCode !== 0 && !response.reason) {
        response.reason = stderr.trim() || `OpenHands bridge exited ${exitCode}`;
      }
      if (response.submitted) {
        const target = await readFile(
          resolve(input.workspaceRoot, input.task.workspace.targetPath),
          'utf8'
        );
        if (target.includes(input.task.workspace.completionMarker)) {
          response.submitted = false;
          response.reason = 'Agent completed without replacing the benchmark marker.';
        }
      }
      return response;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { submitted: false, transcriptSha256: failureTranscript(reason), reason };
    } finally {
      clearTimeout(timeout);
    }
  }
}
