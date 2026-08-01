# Milestone 2: Explainable Policy Selection

Date: 2026-07-27

## Purpose

Milestone 1 produces a normalized `PolicyRecord[]` and a `TaskSurface`. This
milestone turns those inputs into a compact, replayable policy decision for one
agent run.

The selector is part of the harness, not part of the coding agent. The coding
agent receives the selected phase-local obligations but cannot choose, remove,
or weaken them.

## Prototype Scope

This milestone is intentionally a feasibility prototype. It implements only:

- deterministic matching and a small mandatory-rule floor;
- a compact generic security floor when surface evidence is insufficient;
- compact budgeted selection with rationales;
- an optional, already-structured LLM proposal input;
- a monotonic delta helper for newly observed risks;
- one generated autossh example and focused unit tests.

It does not integrate with the Archon runtime, call an LLM, enforce selected
policies, learn ranking weights, or claim complete policy coverage. Those are
separate milestones and should be attempted only after this selector shows
useful precision and recall.

## Research Claim

PGACS uses a split-authority selector:

```text
deterministic safety rules  -> mandatory policies
deterministic retrieval     -> relevant candidates
optional LLM proposer       -> ambiguous candidates only
budgeted deterministic rank -> selected policy set
insufficient/no match       -> compact generic security floor
decision log                -> replay and evaluation
```

The core rule is **LLM proposes, rules dispose**. An LLM may improve recall over
messy task descriptions, but only deterministic harness logic can include a
mandatory policy, exclude an invalid candidate, apply a budget, or change
severity.

## Inputs and Outputs

```ts
type PolicySelectionRequest = {
  surface: TaskSurface;
  policies: PolicyRecord[];
  budget: {
    maxPolicies: number;
  };
  proposals?: Array<{
    policyId: string;
    confidence: number;
    rationale: string;
  }>;
};

type PolicySelectionDecision = {
  taskId: string;
  selectionMode: 'explicit' | 'hybrid' | 'fallback';
  surfaceStatus: 'sufficient' | 'ambiguous' | 'insufficient';
  selected: Array<{
    policyId: string;
    score: number;
    disposition: 'mandatory' | 'ranked' | 'fallback';
    matchedSurface: string[];
    rationale: string[];
  }>;
  rejected: Array<{
    policyId: string;
    score: number;
    reason: 'no_match' | 'budget' | 'invalid_proposal';
  }>;
  budget: {
    maxPolicies: number;
    mandatoryPolicies: number;
    rankedPolicies: number;
    fallbackPolicies: number;
    budgetExceededByMandatory: boolean;
    budgetExceededBySafetyFloor: boolean;
  };
  coverageGaps: string[];
  unresolved: Array<{
    field: string;
    question: string;
    reason: string;
  }>;
  reassessmentTriggers: string[];
  selectorVersion: string;
};
```

The decision contains policy IDs rather than copies of policy records. The
registry remains the source of truth, and a run records the registry version or
digest beside the decision.

## Selection Pipeline

### 1. Validate and canonicalize

- Reject duplicate policy IDs and malformed budgets.
- Require surface terms from the milestone 1 vocabulary.
- Discard LLM proposals for unknown policy IDs.
- Treat proposal text as untrusted data; it never becomes a prompt instruction.

### 2. Apply mandatory safety rules

Mandatory rules encode known high-risk combinations where budget pressure must
not reduce recall. Initial rules include:

| Surface condition                    | Required policy capability                           |
| ------------------------------------ | ---------------------------------------------------- |
| untrusted input + shell command sink | command-injection prevention                         |
| untrusted input + filesystem sink    | path-boundary enforcement                            |
| network exposure or remote access    | runtime/network hardening                            |
| credentials or secret boundary       | secret handling and disclosure limits                |
| authentication/session task          | authentication, authorization, and session integrity |
| dependency change/build              | dependency pinning and provenance                    |

The prototype targets inferred policy tags rather than corpus-specific policy
IDs. If no policy satisfies a mandatory tag, selection fails explicitly with a
coverage gap. It must not silently continue. An explicit capability vocabulary
is future work because inferred tags are still noisy.

Mandatory policies are outside the ordinary count budget. If their count alone
exceeds the configured budget, the decision records `budgetExceededByMandatory`
and keeps them all. Safety coverage is not truncated to satisfy prompt size;
phase-local rendering controls prompt pressure later.

### 3. Retrieve candidates

Each policy receives an additive relevance score. Version 0 uses explicit
overlap features:

| Match                                | Weight |
| ------------------------------------ | -----: |
| exact CWE                            |      8 |
| dangerous sink                       |      6 |
| trust boundary                       |      5 |
| asset                                |      4 |
| input channel                        |      3 |
| environment/task trigger             |      3 |
| task-family capability hint          |      4 |
| runtime/build verification relevance |      2 |
| valid LLM proposal                   |    0-2 |

Severity is not relevance and therefore does not add score. It affects how a
selected policy is enforced, not whether an unrelated policy should be chosen.

Every score contribution creates a `matchedSurface` entry and a rationale. This
makes the same input replay to the same output and permits feature-level error
analysis.

### 4. Apply the generic security floor when needed

Sparse extraction must not produce an empty, implicitly safe decision.

After specific candidate retrieval, PGACS records one selection mode:

- `explicit`: evidence supports specific mandatory/ranked policies;
- `hybrid`: specific policies exist, but material surface uncertainty remains;
- `fallback`: no reliable specific match exists.

`hybrid` and `fallback` decisions activate applicable policies from a
three-policy core floor:

1. `core:security-surface-discovery`;
2. `core:fail-safe-implementation`;
3. `core:evidence-based-validation`.

The floor guides discovery, fail-safe behavior, negative validation, and
evidence-based reporting. It does not prove a vulnerability-specific control
and cannot satisfy a missing mandatory capability. Missing core fallback
policies are a harness configuration error.

Fallback policies stay active when later evidence adds specific policies, but
the renderer suppresses redundant generic text. Policy state remains monotonic
without turning the prompt into a cumulative checklist.

Mandatory and fallback policies are never truncated. They reserve the safety
floor before ranked policies fill remaining slots. The decision records
`budgetExceededBySafetyFloor` if the configured budget is smaller than that
floor.

The complete decision and implementation plan is in
[`04-generic-security-floor-and-implementation-plan.md`](./04-generic-security-floor-and-implementation-plan.md).

### 5. Suppress redundancy and apply budget

Mandatory policies are selected first. Ranked candidates then fill remaining
slots in descending `(score, policyId)` order. Exact duplicate policy IDs are
removed.

Semantic redundancy suppression is deferred. Similar policy prose is not
enough to prove equivalence, and an LLM must not remove a security control based
on a semantic guess.

Candidates dropped by the budget remain in `rejected`. Recording these near
misses is important for later selector learning and false-negative analysis.

### 6. Materialize policy state

The controller resolves selected IDs against the immutable registry snapshot,
creates phase bindings, and arms monitors/invariants. Prompt rendering remains
separate: a policy can stay active without consuming prompt tokens in every
phase.

## Dynamic Selection

Selection runs at intake and again when trajectory events change the task
surface. Examples include `dependency_added`, `service_started`, a new network
sink, or discovery of credential handling.

Dynamic adoption is monotonic within a run:

- active policies may be added;
- severity may be raised;
- monitors and probes may be armed;
- an active policy may not be removed or weakened.

Each reselection produces a `PolicyDelta` that records the triggering event,
new surface facts, added policies, and rationale. The same delta updates prompt
bindings, runtime monitors, and loop invariants atomically.

## Role of the LLM

An optional proposer can receive a bounded representation of the task surface
and policy catalog. The prototype accepts an already-structured proposal and
contributes only a small ranking bonus. A later integration must schema-validate
the model output. The proposer cannot:

- invent a policy;
- mark a policy mandatory;
- alter a policy or its severity;
- remove a deterministic match;
- waive required evidence;
- decide the final run status.

Version 0 must work without any LLM call. This deterministic baseline is needed
to measure whether adding a proposer improves recall enough to justify its
cost, latency, and injection risk.

## Failure Behavior

The selector fails fast when:

- a mandatory tag has no policy implementation;
- the core generic security-floor pack is missing or malformed;
- registry IDs are duplicated;
- budgets are invalid;
- a selected ID cannot be resolved in the registry snapshot.

LLM timeout, malformed output, or unknown proposals are recorded and ignored;
deterministic selection continues. This is a safe fallback because the LLM has
no authority, the mandatory rule floor remains intact, and an insufficient
surface activates the generic security floor.

## Validation Plan

The first implementation should include deterministic tests for:

1. the autossh setup task selects network/runtime and dependency controls;
2. untrusted input reaching a shell sink hard-includes command-injection
   prevention even under a one-policy budget;
3. a database-only task does not select environment-setup controls without
   matching repo evidence;
4. an unknown LLM proposal is rejected without changing the selected set;
5. equal-score candidates have stable policy-ID ordering;
6. budget-dropped candidates appear in the decision log;
7. dynamic discovery of a dependency adds policy state but never removes an
   existing policy;
8. missing mandatory coverage returns an explicit error;
9. an empty surface selects the three core fallback policies;
10. an ambiguous surface with a specific match produces a `hybrid` decision;
11. fallback policies cannot mask a known mandatory coverage gap.

Evaluation should report selection precision/recall against expert labels,
mandatory-rule recall, average active-policy count, prompt tokens by phase,
decision stability, and downstream secure-coding outcomes.

## Completion Criteria

This milestone is complete when PGACS can:

1. generate a typed `PolicySelectionDecision` from a real registry and task
   surface;
2. distinguish mandatory, ranked, and fallback inclusion;
3. explain every inclusion and consequential exclusion;
4. replay decisions deterministically;
5. continue safely when the optional LLM proposer fails;
6. emit monotonic policy deltas when the trajectory exposes new risks;
7. produce a non-empty generic-floor decision when surface evidence is
   insufficient.

## Concrete Future Updates

The next research iterations, in order, are:

1. implement and test the generic security floor described in milestone 2.1;
2. run the frozen cross-task C0/C1/C2 experiment and measure security-adjusted
   correctness, overconstraint, and cost;
3. add an explicit `controlCapabilities` field only where observed mandatory
   matching still depends on broad inferred tags;
4. bind selected policies to phase-local prompt fragments after prompt-only
   versus check-and-repair effects are measured;
5. add evidence monitors only for policies that demonstrate downstream value;
6. consider a learned ranker only after enough labeled decisions exist.

This ordering keeps the research falsifiable: each added mechanism must improve
selection quality or secure-coding outcomes before the prototype grows.

## Current Observation

The generated autossh example proves that the pipeline runs end to end: it
extracts network exposure, dependency installation, logging, lifecycle, and
privilege signals; hard-includes network and dependency controls; ranks the
remaining policies; and records budget exclusions.

It also reveals the main limitation of milestone 1 data. Several broad ASVS
policies receive similar scores because their inferred network tags do not say
which concrete control they implement. The subsequent semantic-selection
prototype improved compactness and control recall, but neither method guarantees
a usable match for sparse or ambiguous surfaces. The generic floor closes that
empty-selection path while preserving uncertainty; it does not make the
selector precise enough for full enforcement by itself.
