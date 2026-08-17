# Milestone 1: Policy Registry and Task-Surface Extraction

Date: 2026-07-24

## Purpose

This document defines the first implementation step for PGACS.

Before the harness can select policies, distribute them across phases, or
enforce anything at runtime, it needs two shared objects:

1. a normalized **Policy Registry**; and
2. a normalized **Task Surface**.

The goal of this milestone is to make policy selection possible without
hard-coding special cases into the controller.

## What This Step Must Produce

The system should be able to:

1. read a principle source and represent it as a policy record;
2. read a user task plus repository context and represent it as a task surface;
3. match the task surface against the registry;
4. return a small, explainable policy set with a rationale for each match.

This is still a research milestone, not the final harness. It is the minimum
data layer that later enforcement layers depend on.

## Policy Registry

The registry is the source of truth for executable policies.

### Minimal PolicyRecord

```ts
type PolicyRecord = {
  id: string;
  title: string;
  version: string;
  sourcePrinciples: Array<{
    source: string;
    ref?: string;
    text: string;
  }>;
  normativeText: string;
  riskTags: string[];
  cweTags: string[];
  taskTriggers: string[];
  inputChannels: string[];
  dangerousSinks: string[];
  assetTags: string[];
  trustBoundaryTags: string[];
  dependencyTags: string[];
  environmentTags: string[];
  phaseBindings: string[];
  validators: string[];
  evidenceRequirements: string[];
  forbiddenWorkarounds: string[];
  severity: 'advisory' | 'required' | 'fail_closed';
};
```

### Why these fields come first

- `sourcePrinciples` preserves provenance.
- `riskTags`, `cweTags`, and `taskTriggers` make retrieval possible.
- `inputChannels`, `dangerousSinks`, `assetTags`, and `trustBoundaryTags`
  connect principles to the actual task surface.
- `phaseBindings` and `validators` defer enforcement detail without losing the
  policy structure.
- `evidenceRequirements` and `forbiddenWorkarounds` make the registry usable for
  security research, not just prompt decoration.

## Task Surface

The task surface is the normalized representation of what the agent is being
asked to do and what security-relevant structures already exist in the repo.

### Minimal TaskSurface

```ts
type TaskSurface = {
  taskId: string;
  taskFamily:
    | 'web_api'
    | 'file_parser'
    | 'database'
    | 'auth_session'
    | 'environment_setup'
    | 'cli_tool'
    | 'dependency_build'
    | 'agent_tooling'
    | 'unknown';
  languageFrameworks: string[];
  inputChannels: string[];
  dangerousSinks: string[];
  assets: string[];
  trustBoundaries: string[];
  runtimeExposure: string[];
  dependencies: string[];
  environmentConstraints: string[];
  likelyCwes: string[];
  missingSecurityInputs: string[];
  existingTests: string[];
  confidence: {
    taskFamily: number;
    risks: number;
    missingInputs: number;
  };
  surfaceStatus: 'sufficient' | 'ambiguous' | 'insufficient';
  evidence: Array<{
    field: string;
    value: string;
    source: 'task_prompt' | 'repo_hint' | 'repo_scan' | 'semantic_proposal';
    evidence: string;
  }>;
  unresolved: Array<{
    field: string;
    question: string;
    reason: string;
  }>;
};
```

The status/evidence fields were added after prototype evaluation showed that a
structurally complete surface can still be semantically empty or incorrect.
Downstream selection must treat insufficient evidence as uncertainty, not as
evidence that no security risk exists.

### Extraction inputs

The extractor should use:

- the user request;
- repository files and manifests;
- benchmark metadata, when available;
- environment facts;
- prior run evidence, when resuming.

## Extraction Flow

The first-step pipeline should be deterministic where possible.

```text
Task request + repo scan + benchmark hints
  -> task-surface extraction
  -> candidate policy retrieval
  -> policy deduplication and ranking
  -> compact selected policy set
```

Recommended implementation split:

1. **Deterministic scan** for obvious signals such as package names, config
   files, sink patterns, service startup commands, and exposed ports.
2. **Structured LLM extraction** for ambiguous task classification and missing
   security inputs.
3. **Rule-based retrieval** from the registry using tags and surface matches.
4. **Budgeted ranking** to keep the final policy set compact.

## Initial Seed Policy Set

The first registry should not try to cover everything.

Start with a small set of policies that appear repeatedly in the benchmark and
in the external reports:

1. input validation;
2. authentication and authorization;
3. path traversal prevention;
4. command injection prevention;
5. safe parsing / deserialization;
6. secret handling and disclosure limits;
7. dependency pinning and provenance;
8. runtime exposure / bind-address safety;
9. validation-before-release;
10. insecure-workaround rejection.

These policies are enough to test whether selection and phase binding actually
change the agent trajectory.

## Acceptance Criteria

This step is complete when the system can:

1. produce a TaskSurface from a real task prompt and repository;
2. map that surface to a compact policy subset;
3. explain why each policy was selected;
4. avoid selecting irrelevant policies by default;
5. preserve provenance from source principle to policy record.
6. mark insufficient or ambiguous extraction explicitly and provide evidence
   for populated security-bearing fields.

## Why This Is the Right First Step

Without the registry and surface, the harness has nothing stable to select
from. Every other layer would collapse back into ad hoc prompting.

This step creates the shared vocabulary that the rest of PGACS depends on.

When the vocabulary cannot support a reliable specific match, milestone 2.1
activates a compact generic security floor. See
[`04-generic-security-floor-and-implementation-plan.md`](./04-generic-security-floor-and-implementation-plan.md).

## Current Implementation Status

The Archon repo now has a working prototype for this step:

- `scripts/generate-pgacs-research-artifacts.ts` normalizes the existing
  secure-environment-setup policy corpus;
- `scripts/pgacs-policy-registry.ts` builds `PolicyRecord` objects and a
  compact selector;
- `scripts/pgacs-task-surface.ts` extracts a deterministic `TaskSurface` from
  a prompt plus repo hints;
- `.archon/data/research/pgacs/` stores the generated registry, schemas, and an
  example task surface.

The current implementation includes `surfaceStatus`, source evidence, unresolved
questions, explicit/hybrid/fallback selection modes, and the three-policy core
security floor. Generated schemas and examples under
`.archon/data/research/pgacs/` exercise the same contract.
