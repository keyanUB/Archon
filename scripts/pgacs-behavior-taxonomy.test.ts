import { describe, expect, test } from 'bun:test';

import {
  annotateAgentBehavior,
  BEHAVIOR_TAXONOMY_VERSION,
  buildAdaptationPromptRoute,
  classifyAgentBehavior,
  PRIMARY_AGENT_BEHAVIORS,
  summarizeBehaviorAnnotations,
  type AgentBehaviorObservation,
  type PrimaryAgentBehavior,
} from './pgacs-behavior-taxonomy';

describe('PGACS agent behavior taxonomy', (): void => {
  test('freezes the complete primary behavior vocabulary', (): void => {
    expect(BEHAVIOR_TAXONOMY_VERSION).toBe('0.1.0');
    expect(PRIMARY_AGENT_BEHAVIORS).toEqual([
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
    ]);
  });

  test('classifies only unambiguous normalized agent events', (): void => {
    const events: AgentBehaviorObservation[] = [
      { kind: 'tool_call', eventRef: 'event:read', toolName: 'Read' },
      { kind: 'tool_call', eventRef: 'event:write', toolName: 'Write' },
      { kind: 'command_run', eventRef: 'event:static', commandClass: 'static' },
      { kind: 'command_run', eventRef: 'event:build', commandClass: 'build' },
      { kind: 'command_run', eventRef: 'event:test', commandClass: 'test' },
      { kind: 'command_run', eventRef: 'event:runtime', commandClass: 'runtime' },
      { kind: 'repair_boundary', eventRef: 'event:repair' },
      { kind: 'final_response', eventRef: 'event:final' },
    ];

    const expected: PrimaryAgentBehavior[] = [
      'inspection',
      'implementation_writing',
      'verification_static',
      'verification_build',
      'verification_test',
      'verification_runtime',
      'adaptation',
      'final_reporting',
    ];
    expect(
      annotateAgentBehavior(events)
        .map(item => item.primary)
        .sort()
    ).toEqual(expected.sort());
  });

  test('leaves unsupported tool events unclassified instead of guessing', (): void => {
    expect(
      classifyAgentBehavior({ kind: 'tool_call', eventRef: 'event:unknown', toolName: 'AskUser' })
    ).toBeNull();
  });

  test('preserves event order and produces complete zero-inclusive summaries', (): void => {
    const events: AgentBehaviorObservation[] = [
      { kind: 'tool_call', eventRef: 'event:write', toolName: 'Edit' },
      { kind: 'tool_call', eventRef: 'event:read', toolName: 'Read' },
    ];
    const forward = annotateAgentBehavior(events);
    const replay = annotateAgentBehavior(events);
    const summary = summarizeBehaviorAnnotations(forward, events.length);

    expect(forward).toEqual(replay);
    expect(forward.map(item => item.eventRef)).toEqual(['event:write', 'event:read']);
    expect(summary.observedEvents).toBe(2);
    expect(summary.classifiedEvents).toBe(2);
    expect(summary.unclassifiedEvents).toBe(0);
    expect(summary.counts.inspection).toBe(1);
    expect(summary.counts.implementation_writing).toBe(1);
    expect(summary.counts.planning).toBe(0);
  });

  test('reports unclassified-event coverage without inventing labels', (): void => {
    const events: AgentBehaviorObservation[] = [
      { kind: 'tool_call', eventRef: 'event:read', toolName: 'Read' },
      { kind: 'tool_call', eventRef: 'event:unknown', toolName: 'AskUser' },
    ];
    const annotations = annotateAgentBehavior(events);

    expect(summarizeBehaviorAnnotations(annotations, events.length)).toMatchObject({
      observedEvents: 2,
      classifiedEvents: 1,
      unclassifiedEvents: 1,
    });
    expect(() => summarizeBehaviorAnnotations(annotations, 0)).toThrow(
      'must cover every annotation'
    );
  });

  test('rejects duplicate event references', (): void => {
    expect(() =>
      annotateAgentBehavior([
        { kind: 'tool_call', eventRef: 'event:duplicate', toolName: 'Read' },
        { kind: 'tool_call', eventRef: 'event:duplicate', toolName: 'Write' },
      ])
    ).toThrow('duplicate event references');
  });

  test('routes adaptation guidance without granting enforcement authority', (): void => {
    expect(buildAdaptationPromptRoute()).toMatchObject({
      taxonomyVersion: '0.1.0',
      behavior: 'adaptation',
      authority: 'soft_prompt_routing',
    });
  });
});
