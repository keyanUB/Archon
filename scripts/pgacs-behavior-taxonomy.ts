export const BEHAVIOR_TAXONOMY_VERSION = '0.1.0' as const;

export const PRIMARY_AGENT_BEHAVIORS = [
  'orientation',
  'inspection',
  'planning',
  'implementation_writing',
  'refinement',
  'verification_static',
  'verification_build',
  'verification_test',
  'verification_runtime',
  'failure_observation_diagnosis',
  'adaptation',
  'final_reporting',
] as const;

export type PrimaryAgentBehavior = (typeof PRIMARY_AGENT_BEHAVIORS)[number];

export type AgentCommandClass = 'static' | 'build' | 'test' | 'runtime';

export type AgentBehaviorObservation =
  | { kind: 'tool_call'; eventRef: string; toolName: string }
  | { kind: 'command_run'; eventRef: string; commandClass: AgentCommandClass }
  | { kind: 'repair_boundary'; eventRef: string }
  | { kind: 'final_response'; eventRef: string };

export interface BehaviorAnnotation {
  taxonomyVersion: typeof BEHAVIOR_TAXONOMY_VERSION;
  primary: PrimaryAgentBehavior;
  source: 'deterministic_rule';
  ruleId: string;
  eventRef: string;
}

export interface BehaviorAnnotationSummary {
  taxonomyVersion: typeof BEHAVIOR_TAXONOMY_VERSION;
  observedEvents: number;
  classifiedEvents: number;
  unclassifiedEvents: number;
  counts: Record<PrimaryAgentBehavior, number>;
}

export interface BehaviorPromptRoute {
  taxonomyVersion: typeof BEHAVIOR_TAXONOMY_VERSION;
  behavior: 'adaptation';
  authority: 'soft_prompt_routing';
  guidance: string;
}

function annotation(
  eventRef: string,
  primary: PrimaryAgentBehavior,
  ruleId: string
): BehaviorAnnotation {
  if (eventRef.trim().length === 0) {
    throw new Error('Behavior annotation eventRef must be non-empty');
  }
  return {
    taxonomyVersion: BEHAVIOR_TAXONOMY_VERSION,
    primary,
    source: 'deterministic_rule',
    ruleId,
    eventRef,
  };
}

export function classifyAgentBehavior(event: AgentBehaviorObservation): BehaviorAnnotation | null {
  if (event.kind === 'tool_call') {
    if (/^(?:read|glob|grep|ls|search)$/i.test(event.toolName)) {
      return annotation(event.eventRef, 'inspection', 'tool-inspection-v1');
    }
    if (/^(?:write|edit|multiedit|apply_patch)$/i.test(event.toolName)) {
      return annotation(event.eventRef, 'implementation_writing', 'tool-write-v1');
    }
    return null;
  }
  if (event.kind === 'command_run') {
    const behaviorByCommand: Record<AgentCommandClass, PrimaryAgentBehavior> = {
      static: 'verification_static',
      build: 'verification_build',
      test: 'verification_test',
      runtime: 'verification_runtime',
    };
    return annotation(
      event.eventRef,
      behaviorByCommand[event.commandClass],
      `command-${event.commandClass}-v1`
    );
  }
  if (event.kind === 'repair_boundary') {
    return annotation(event.eventRef, 'adaptation', 'repair-boundary-v1');
  }
  return annotation(event.eventRef, 'final_reporting', 'terminal-response-v1');
}

export function annotateAgentBehavior(events: AgentBehaviorObservation[]): BehaviorAnnotation[] {
  const eventRefs = events.map(event => event.eventRef);
  if (new Set(eventRefs).size !== eventRefs.length) {
    throw new Error('Agent behavior observations contain duplicate event references');
  }
  return events.flatMap((event): BehaviorAnnotation[] => {
    const result = classifyAgentBehavior(event);
    return result ? [result] : [];
  });
}

export function summarizeBehaviorAnnotations(
  annotations: BehaviorAnnotation[],
  observedEvents: number
): BehaviorAnnotationSummary {
  if (!Number.isSafeInteger(observedEvents) || observedEvents < annotations.length) {
    throw new Error('Observed behavior event count must cover every annotation');
  }
  const counts = Object.fromEntries(
    PRIMARY_AGENT_BEHAVIORS.map(behavior => [behavior, 0])
  ) as Record<PrimaryAgentBehavior, number>;
  for (const item of annotations) {
    if (item.taxonomyVersion !== BEHAVIOR_TAXONOMY_VERSION) {
      throw new Error(`Unsupported behavior taxonomy version ${item.taxonomyVersion}`);
    }
    counts[item.primary] += 1;
  }
  return {
    taxonomyVersion: BEHAVIOR_TAXONOMY_VERSION,
    observedEvents,
    classifiedEvents: annotations.length,
    unclassifiedEvents: observedEvents - annotations.length,
    counts,
  };
}

export function buildAdaptationPromptRoute(): BehaviorPromptRoute {
  return {
    taxonomyVersion: BEHAVIOR_TAXONOMY_VERSION,
    behavior: 'adaptation',
    authority: 'soft_prompt_routing',
    guidance:
      'Adapt only to the failed candidate evidence. Preserve every passing security control. The harness will rerun the required trusted probes after the repair.',
  };
}
