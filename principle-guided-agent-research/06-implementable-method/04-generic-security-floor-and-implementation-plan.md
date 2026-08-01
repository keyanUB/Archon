# Generic Security Floor and Implementation Record

Date: 2026-07-27

Status: Implemented in the deterministic research prototype on 2026-08-01.

## Decision

PGACS must not interpret a sparse task surface as evidence that a task is safe.
When extraction cannot support task-specific policy matching, the selector
activates a compact **generic security floor** and records the uncertainty that
caused it.

```text
Missing surface evidence means unknown, not safe.
```

The generic floor is a set of normal, provenance-linked core policies. It is
not an unstructured "be secure" suffix and not a full secure-coding checklist.

## Why the Design Needs This

The current deterministic extractor always returns a structurally complete
`TaskSurface`, but many fields can be empty or wrong. The current selector can
therefore return an empty ranked set when no policy scores above zero.

This creates a silent false-negative path:

```text
Extractor misses risk
  -> no surface trigger
  -> no mandatory rule
  -> no specific policy
  -> agent runs without security guidance
```

The semantic selector improves recall but cannot eliminate uncertainty. It can
also time out, return malformed output, or fail to connect an observed risk to a
catalog policy.

The fallback design provides useful behavior without requiring the system to
predict every vulnerability before coding starts.

## Selection Modes

Every selection decision records one mode:

```ts
type PolicySelectionMode = 'explicit' | 'hybrid' | 'fallback';
```

| Mode       | Meaning                                                                 | Selected policy behavior                                                 |
| ---------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `explicit` | Surface evidence supports task-specific controls                        | Select mandatory and ranked specific policies                            |
| `hybrid`   | Some specific controls are supported, but material uncertainty remains  | Select specific policies plus only the applicable generic floor policies |
| `fallback` | No reliable specific match exists or surface extraction is insufficient | Activate the complete compact generic floor                              |

Mode describes how selection was constructed. It does not change policy
severity or give an LLM authority.

## Surface Status

The extractor must distinguish missing evidence from low risk:

```ts
type SurfaceStatus = 'sufficient' | 'ambiguous' | 'insufficient';

type SurfaceEvidence = {
  field: string;
  value: string;
  source: 'task_prompt' | 'repo_hint' | 'repo_scan' | 'semantic_proposal';
  evidence: string;
};

type UnresolvedSurfaceQuestion = {
  field: string;
  question: string;
  reason: string;
};
```

`TaskSurface` gains:

```ts
surfaceStatus: SurfaceStatus;
evidence: SurfaceEvidence[];
unresolved: UnresolvedSurfaceQuestion[];
```

### Prototype sufficiency rules

Version 0 should remain simple:

- `insufficient`: no evidence-backed security-bearing facts exist in input
  channels, sinks, assets, trust boundaries, actions, runtime exposure, or
  likely CWEs.
- `ambiguous`: facts exist, but they do not form a usable risk relation, such as
  input/trust-boundary to sink, action to asset, or runtime exposure.
- `sufficient`: at least one usable relation or an explicit high-confidence
  risk is supported by evidence.

These statuses are heuristic research signals, not calibrated probabilities.
The decision log must preserve the evidence and unresolved questions.

## Generic Core Policies

The initial floor contains exactly three policies.

### `core:security-surface-discovery`

**Obligation:** Before or during implementation, identify external inputs,
sensitive assets, dangerous operations, trust boundaries, and relevant failure
behavior. Treat unresolved external data as untrusted.

**Phase bindings:**

- orientation/inspection: discover inputs, sinks, assets, and boundaries;
- planning: record unresolved security assumptions;
- reporting: disclose unresolved surface gaps.

**Evidence:**

- harness-owned task-surface record;
- repository references or observed trajectory events;
- explicit unresolved questions.

### `core:fail-safe-implementation`

**Obligation:** Use secure defaults, least privilege, explicit rejection
behavior, and fail-closed handling where the task's behavior is uncertain. Do
not weaken controls to obtain a passing result.

**Phase bindings:**

- implementation: prefer restrictive, reversible behavior;
- repair: forbid bypassing validation or broadening permissions;
- reporting: state any accepted residual risk.

**Evidence:**

- diff and configuration observations;
- repair deltas;
- recorded forbidden-workaround checks where applicable.

### `core:evidence-based-validation`

**Obligation:** Validate expected and rejected behavior using tests, static
checks, or bounded runtime evidence appropriate to the implemented behavior. Do
not treat model prose as proof.

**Phase bindings:**

- planning: define positive and negative validation;
- verification: execute available evidence-producing checks;
- reporting: derive claims from recorded results.

**Evidence:**

- commands and exit codes;
- test/static/probe results;
- explicit residual uncertainty when a check is unavailable.

## Authority and Severity

Fallback policies provide a process-security floor, not vulnerability-specific
proof.

- They can require discovery, negative validation, and evidence recording.
- They cannot claim that command injection, path traversal, authorization, or
  another concrete risk has been prevented.
- They do not satisfy a known mandatory capability requirement.
- If the surface triggers a mandatory rule but the registry lacks its specific
  policy, selection still reports a mandatory coverage failure.
- If the core fallback pack itself is missing or malformed, the harness fails
  configuration validation.

In the prototype, fallback prompt obligations may be treated as `required`
process controls, but terminal security claims remain `unknown` until specific
controls have applicable evidence.

## Budget Semantics

Mandatory and fallback policies form the safety floor and are never truncated.
Ranked specific policies use only the remaining ordinary slots:

```text
remaining ranked slots =
  max(0, maxPolicies - mandatoryPolicies - fallbackPolicies)
```

If mandatory plus fallback policies exceed `maxPolicies`, the decision keeps
them and records `budgetExceededBySafetyFloor: true`. Phase-local rendering
still controls prompt tokens. This avoids allowing a small relevance budget to
erase the uncertainty fallback.

## Selection Algorithm

```text
1. Validate task-surface structure and evidence.
2. Determine surfaceStatus.
3. Apply known mandatory safety triggers.
4. Retrieve and rank specific policy candidates.
5. Determine selectionMode:
   - specific policies + sufficient surface       -> explicit
   - specific policies + unresolved material gaps -> hybrid
   - no reliable specific policies                -> fallback
6. Add generic floor policies required by the mode.
7. Record coverage gaps and reassessment triggers.
8. Render only phase-relevant fragments.
```

Generic policies do not justify silently continuing through known mandatory
coverage gaps.

## Prompt and State Behavior

Fallback policies remain active in monotonic policy state. When later evidence
activates a specific policy, the umbrella policy need not be removed:

```text
generic policy remains active in state
  -> specific policy supplies concrete control and checks
  -> renderer suppresses redundant generic text for that phase
```

This preserves monotonic state without increasing prompt pressure.

Initial rendering remains compact:

| Phase          | Generic rendering                                                      |
| -------------- | ---------------------------------------------------------------------- |
| Inspection     | Identify inputs, sinks, assets, boundaries, and unresolved assumptions |
| Implementation | Use fail-safe defaults and do not trust unresolved external data       |
| Validation     | Test expected and rejected behavior and record evidence                |
| Repair         | Do not remove checks or weaken controls to obtain a pass               |
| Reporting      | Report verified evidence and unresolved risks                          |

## Reassessment

Fallback selection is not terminal. The decision records triggers such as:

- shell/process execution observed;
- filesystem path operation observed;
- SQL/database operation observed;
- outbound network request observed;
- service exposure observed;
- authentication, credential, or secret handling observed;
- dependency addition observed.

An event can produce a monotonic `PolicyDelta` that adds specific policies and
their monitors/invariants.

## Revised Decision Shape

```ts
interface PolicySelectionDecision {
  taskId: string;
  selectionMode: PolicySelectionMode;
  surfaceStatus: SurfaceStatus;
  selected: Array<{
    policyId: string;
    disposition: 'mandatory' | 'ranked' | 'fallback';
    score: number;
    matchedSurface: string[];
    rationale: string[];
  }>;
  rejected: Array<{
    policyId: string;
    score: number;
    reason: 'no_match' | 'budget' | 'invalid_proposal';
  }>;
  coverageGaps: string[];
  unresolved: UnresolvedSurfaceQuestion[];
  reassessmentTriggers: string[];
  budget: {
    maxPolicies: number;
    mandatoryPolicies: number;
    rankedPolicies: number;
    fallbackPolicies: number;
    budgetExceededByMandatory: boolean;
    budgetExceededBySafetyFloor: boolean;
  };
  selectorVersion: string;
}
```

## Implementation Record

The prototype was revised in five small steps.

### Step 1: Extend typed contracts

Modify `scripts/pgacs-types.ts`:

- add `SurfaceStatus`;
- add `SurfaceEvidence`;
- add `UnresolvedSurfaceQuestion`;
- extend `TaskSurface`;
- add `PolicySelectionMode`;
- add `fallback` selection disposition;
- extend decision budget and decision metadata.

Do not add runtime-controller or adapter types in this step.

### Step 2: Make surface uncertainty explicit

Modify `scripts/pgacs-task-surface.ts`:

- make each inferred fact carry short source evidence;
- calculate `surfaceStatus` with the simple version-0 rules;
- produce unresolved questions for missing sink, trust-boundary, or validation
  information;
- retain the existing fields for compatibility;
- replace the current hard-coded confidence interpretation with documented
  heuristic values, without claiming calibration.

This step does not add a repository AST scanner or another LLM call.

### Step 3: Add the immutable core fallback pack

Add a small generated or source-controlled policy file under:

```text
.archon/data/research/pgacs/core-security-floor.json
```

It contains the three policy IDs and their source, normative text, phase
bindings, evidence requirements, and forbidden workarounds.

Update corpus construction so:

- IDs are namespaced and collision-checked;
- fallback policies are always available to the selector;
- provenance identifies them as PGACS core research policies derived from the
  project's prepared secure-development sources;
- they are not duplicated into semantic labels as task-specific controls.

### Step 4: Revise selection behavior

Modify `scripts/pgacs-policy-registry.ts`:

- compute `selectionMode`;
- add fallback policies when the surface is insufficient or no specific policy
  is selected;
- use `hybrid` when specific policies exist but material uncertainty remains;
- keep mandatory coverage failures fail-fast;
- record unresolved questions, coverage gaps, and reassessment triggers;
- count fallback selections separately;
- reserve the safety floor before allocating ranked-policy slots and record
  `budgetExceededBySafetyFloor`;
- preserve stable ordering and monotonic deltas.

Increment `selectorVersion` because decision semantics change.

### Step 5: Revise generated artifacts and evaluation

Update:

- schemas generated by `scripts/generate-pgacs-research-artifacts.ts`;
- example task-surface and policy-selection artifacts;
- deterministic selector evaluator;
- semantic selector comparison only where fallback metadata is applicable;
- research reports describing selector behavior.

Do not rerun model-backed experiments merely to update schemas. First validate
the deterministic behavior with frozen artifacts.

## Required Tests

Add focused tests for:

1. an empty/unknown surface activates all three fallback policies;
2. an ambiguous surface with one specific match produces `hybrid`;
3. a sufficient surface with specific policies produces `explicit`;
4. fallback policies are stable and deterministic under policy reordering;
5. unknown LLM proposals cannot replace or suppress the fallback floor;
6. a known mandatory trigger with missing specific coverage still fails;
7. later discovery adds a specific policy while retaining fallback policies;
8. fallback policies do not cause unrelated domain policies to fill the budget;
9. malformed or missing core fallback policies fail configuration validation;
10. generated schemas and examples include the new fields.

## Prototype Acceptance Criteria

The revision is complete when:

- every valid task that does not hit an explicit mandatory/configuration error
  produces a non-empty policy decision;
- insufficient surfaces are explicitly marked rather than treated as safe;
- fallback selection contains exactly the compact core floor;
- specific policy selection behavior remains unchanged for known sufficient
  surfaces except for new metadata;
- mandatory coverage failures cannot be masked by generic policies;
- the decision explains why fallback was used and what can trigger
  reassessment;
- focused tests, TypeScript checks, lint, formatting, and artifact generation
  pass.

## Deferred Work

This revision deliberately does not implement:

- full repository AST/data-flow analysis;
- automatic semantic surface extraction;
- runtime event adapters;
- continuous monitor execution;
- tool denial;
- multi-step repair loops;
- learned ranking.

The generic floor closes the empty-selection failure safely enough for the next
cross-task experiment without making the prototype heavy.
