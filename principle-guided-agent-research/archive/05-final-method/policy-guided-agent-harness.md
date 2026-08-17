# Ultimate Method: Policy-Guided Agent Harness for Secure Code Generation

Date: 2026-07-09

## Executive Summary

This document defines the recommended final methodology for the research
project.

The method is:

```text
Policy-Guided Agent Harness (PGAH)
```

PGAH is a harness-centered method for guiding coding agents to produce code
that is both correct and secure. It does not simply prompt an agent to "follow
secure coding principles." Instead, it converts software engineering and
security principles into executable policies that are selected for the task,
distributed across coding-agent behavior phases, enforced by a harness,
dynamically updated during execution, and evaluated through both trajectory and
outcome metrics.

The method is designed to answer two research questions:

1. **Policy selection:** How can the system select the smallest useful set of
   security/correctness policies for a task?
2. **Policy distribution and enforcement:** How can selected policies be
   applied across the agent trajectory so they actually shape behavior and
   improve secure/correct outcomes?

## Main Research Claim

The central claim is:

```text
Principle-derived policies improve secure code generation when they are
selected from task risk, bound to agent behavior phases, enforced by an
external harness, dynamically hardened as new risks appear, and validated with
independent evidence.
```

This is stronger than a secure prompt because it changes the control structure
around the agent.

## Why This Method Is Promising for the Security Community

Security researchers and practitioners are unlikely to accept a method that
only says "we added more security instructions." PGAH is more compelling
because it is:

- **operational:** policies become executable objects with triggers,
  validators, and evidence requirements;
- **auditable:** every selected policy has a rationale, phase binding, and
  evidence ledger;
- **measurable:** trajectory and outcome metrics can show what changed;
- **security-aware:** the harness controls tools, runtime probes, evidence,
  and unsafe adaptations;
- **extensible:** policy packs and validators can be plugged in for new task
  families;
- **empirically testable:** the design supports ablations and cross-task
  generalization studies.

## Terminology

### Principle

A human-readable rule or norm from a source such as OWASP, GRASP, CWE, NIST,
project coding standards, or a benchmark-specific security guide.

Example:

```text
Validate all untrusted input server-side.
```

### Policy

An executable harness object derived from one or more principles.

A policy includes:

- source principles;
- triggers;
- risk tags;
- phase bindings;
- required controls;
- forbidden workarounds;
- validators;
- evidence requirements;
- blocking level.

### Control

A concrete obligation produced by a policy.

Example:

```text
Reject path traversal sequences before filesystem access.
```

### Evidence

Harness-observed proof that a control was inspected, implemented, tested, or
validated.

Examples:

- file diff;
- command output;
- test result;
- runtime probe;
- static scan result;
- validator finding;
- artifact hash.

## System Overview

PGAH has five pillars.

```text
1. Policy Registry
2. Policy Selector
3. Phase Distributor
4. Policy Harness
5. Evaluation Layer
```

The complete pipeline is:

```text
Task Request
  -> Task Surface Extraction
  -> Candidate Policy Generation
  -> Policy Selection
  -> Phase Distribution
  -> Policy-Guided Agent Execution
  -> Tool Brokering
  -> Validation and Runtime Probing
  -> Loop Conditioning and Dynamic Hardening
  -> Evidence Ledger and Final Claim Gate
  -> Trajectory and Outcome Evaluation
```

## Pillar 1: Policy Registry

The policy registry is the normalized source of executable policies.

It combines principles from:

- OWASP Secure Coding Practices;
- GRASP graph;
- setup/environment policies;
- CWE mappings;
- benchmark-specific risk hints;
- project-specific coding standards;
- future domain policy packs.

### PolicyRecord Schema

```ts
type PolicyRecord = {
  id: string;
  version: string;
  title: string;
  sourcePrinciples: Array<{
    source: string;
    sourceId?: string;
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
  languageFrameworkHints: string[];
  graphLinks: Array<{
    targetPolicyId: string;
    relation: 'parent' | 'child' | 'requires' | 'supports' | 'conflicts' | 'near_duplicate';
    weight: number;
  }>;
  phaseBindings: PhaseBindingTemplate[];
  validators: PolicyValidatorRef[];
  evidenceRequirements: EvidenceRequirement[];
  forbiddenWorkarounds: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  enforceability: 'prompt_only' | 'inspectable' | 'testable' | 'probeable' | 'statically_checkable';
  defaultBlockingLevel: 'advisory' | 'required' | 'fail_closed';
  expectedCost: {
    tokenCost: number;
    runtimeCost: number;
    implementationComplexity: number;
  };
};
```

### Key Design Choice: Policy as Operational Unit

Principles are too vague for enforcement. Policies are specific enough for a
harness to select, distribute, validate, and score.

Rationale:

```text
The harness cannot enforce a paragraph.
It can enforce a policy object.
```

## Pillar 2: Task Surface Extraction

Before selecting policies, the harness extracts the task surface.

### TaskSurface Schema

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
};
```

### Extractor Sources

The extractor should combine:

- task prompt;
- benchmark metadata;
- codebase scan;
- package/config files;
- API specification;
- environment information;
- previous trajectory events;
- LLM structured extraction;
- deterministic scanners.

### Key Design Choice: Extract Before Coding

Risk recognition should happen before implementation.

Rationale:

Baseline agent trajectories show agents inspect and build often, but not
necessarily the right security surfaces. Early surface extraction creates a
structured target for policy selection.

## Pillar 3: Policy Selection

The selector chooses a compact set of policies for the task.

### Candidate Generation

Candidate generation should use four sources.

1. **Rule triggers**
   - High precision mappings.
   - Example: `filesystem sink + untrusted filename -> path traversal policy`.

2. **Retrieval**
   - Sparse and dense retrieval over policy text.
   - Useful for recall and messy task language.

3. **Graph expansion**
   - Expand from seed policies to prerequisites, supporting policies, and
     related controls.
   - Use GRASP/security graph structure.

4. **LLM-assisted extraction**
   - Use structured LLM output to identify task surfaces and likely risk
     categories.
   - The LLM helps interpret, but does not own selection authority.

### Selection Score

```text
score(policy, task) =
  rule_trigger_score
  + retrieval_similarity
  + graph_proximity
  + severity
  + enforceability
  + local_framework_match
  - implementation_cost
  - conflict_penalty
  - redundancy_penalty
```

### Selection Constraints

The selector must optimize coverage, not only similarity.

Required constraints:

- cover every critical input/sink/asset surface;
- include hard-triggered critical policies;
- avoid redundant near-duplicates;
- avoid wrong-domain policies;
- prefer enforceable policies;
- keep the selected set compact;
- log rejected high-score candidates.

Typical initial budget:

```text
3-8 selected policies per ordinary task
8-12 for high-risk, multi-surface tasks
```

### Selection Output

```ts
type SelectedPolicySet = {
  taskId: string;
  selected: Array<{
    policyId: string;
    version: string;
    selectedBecause: string[];
    matchedSurfaces: string[];
    blockingLevel: 'advisory' | 'required' | 'fail_closed';
    confidence: number;
  }>;
  rejectedHighScoreCandidates: Array<{
    policyId: string;
    reason: string;
  }>;
  selectionBudget: {
    maxPolicies: number;
    tokenBudget: number;
  };
};
```

### Key Design Choice: Transparent Hybrid First

The first implementation should not use end-to-end RL.

Rationale:

- The project does not yet have enough labels.
- Security-sensitive exploration is risky.
- A transparent selector is easier to debug, publish, and improve.

### Later ML Roadmap

1. Transparent hybrid selector.
2. Human-labeled policy relevance dataset.
3. Supervised learning-to-rank.
4. Offline policy evaluation.
5. Constrained contextual bandit over safe policy bundles.

Unconstrained RL should not be used until strong safety constraints and
outcome labels exist.

## Pillar 4: Phase Distribution

Selected policies are converted into behavior-phase obligations.

### Behavior Phases

The current behavior vocabulary comes from the BaxBench trajectory taxonomy:

- `orientation`;
- `inspection`;
- `planning`;
- `implementation_writing`;
- `refinement`;
- `verification_static`;
- `verification_build`;
- `verification_test`;
- `verification_runtime`;
- `failure_observation_diagnosis`;
- `adaptation`;
- `final_reporting`.

### PhaseBinding Schema

```ts
type PhaseBinding = {
  policyId: string;
  phase: string;
  instruction: string;
  requiredEvidence: string[];
  validators: string[];
  forbiddenWorkarounds: string[];
  blockingLevel: 'advisory' | 'required' | 'fail_closed';
  triggerCondition?: string;
};
```

### Example: Input Validation Policy

| Phase             | Binding                                                                                 |
| ----------------- | --------------------------------------------------------------------------------------- |
| Orientation       | Identify untrusted input sources and dangerous sinks.                                   |
| Inspection        | Locate request parameters, body fields, file names, CLI args, headers, and sink usage.  |
| Planning          | Define validation strategy: type, length, format, range, allowlist, rejection behavior. |
| Implementation    | Validate at trust boundary before sink usage.                                           |
| Verification test | Add invalid, malicious, oversized, malformed, and boundary tests.                       |
| Failure diagnosis | Do not weaken validation to satisfy functional tests.                                   |
| Final reporting   | Cite validation code and tests.                                                         |

### Example: Persistent SSH Tunnel Setup Policy

| Phase             | Binding                                                                          |
| ----------------- | -------------------------------------------------------------------------------- |
| Orientation       | Classify task as high-risk persistent remote access.                             |
| Inspection        | Check for remote host, user, identity key, known_hosts, bind address.            |
| Planning          | Decide fail-safe scaffold if trust inputs are missing.                           |
| Implementation    | Use non-root user, strict host-key checking, pinned known_hosts, preflight gate. |
| Runtime probing   | Confirm activation is blocked without required inputs.                           |
| Failure diagnosis | Do not invent localhost root SSH or disable host-key checking.                   |
| Final reporting   | Report required operator inputs and fail-safe status.                            |

### Key Design Choice: Phase-Specific Rendering

The same policy should not be pasted unchanged into every prompt.

Rationale:

Policy pressure should occur where it can change behavior. Repeating the same
text everywhere creates overload without control.

## Pillar 5: Policy Harness

The harness is the external control plane.

### Harness Responsibilities

| Responsibility      | Description                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| State ownership     | Stores task surface, selected policies, phase bindings, evidence, and policy deltas. |
| Prompt shaping      | Sends compact phase-specific policy slices to the LLM.                               |
| Tool brokering      | Mediates high-risk tool calls.                                                       |
| Validation          | Runs deterministic checks, tests, and probes.                                        |
| Evidence collection | Records evidence from observed artifacts, not self-reports.                          |
| Loop conditioning   | Preserves security controls during repair.                                           |
| Dynamic hardening   | Adds stricter policies when new risks appear.                                        |
| Final claim gate    | Allows final success only when evidence supports claims.                             |

### Tool Broker

The tool broker classifies tool calls:

- read;
- write;
- dependency install;
- network fetch;
- secret access;
- process control;
- service startup;
- credential creation;
- filesystem deletion;
- git mutation;
- permission change;
- privileged operation.

Broker decisions:

```text
allow
deny
require_evidence
escalate
dry_run_first
```

Examples:

- `StrictHostKeyChecking=no` in an SSH setup task: deny or fail validation.
- Generating root credentials for an underspecified tunnel: deny.
- Adding a new dependency: require dependency policy and lockfile/provenance
  evidence.
- Starting a public service: require runtime exposure policy and probe plan.

### Evidence Ledger

The evidence ledger is append-only and harness-owned.

```ts
type EvidenceLedgerEntry = {
  policyId: string;
  requiredControl: string;
  expectedEvidence: string[];
  observedEvidence: Array<{
    type: 'diff' | 'command' | 'test' | 'probe' | 'static_scan' | 'file_read';
    reference: string;
    summary: string;
    timestamp: string;
  }>;
  status: 'pass' | 'fail' | 'unknown' | 'blocked';
  residualRisk?: string;
};
```

Final claims must be derived from this ledger.

Rule:

```text
No evidence means no claim.
```

### Validation and Probe Engine

Validator types:

- static scans;
- AST/rule checks;
- dangerous API searches;
- build/type/lint checks;
- functional tests;
- adversarial tests;
- runtime HTTP probes;
- service/process probes;
- filesystem/permission probes;
- dependency/provenance checks;
- secret leakage scans.

Runtime probes are first-class because backend and environment security often
depends on runtime behavior.

## Dynamic Policy Hardening

Policy selection must update during the trajectory.

### Dynamic Triggers

| Trigger                              | Action                                                |
| ------------------------------------ | ----------------------------------------------------- |
| New dependency added                 | Add dependency/supply-chain policy.                   |
| Shell/process execution appears      | Add command-injection and environment-control policy. |
| File path handling appears           | Add path traversal and file-permission policy.        |
| Service starts or port binds         | Add runtime exposure and access-control probe policy. |
| Auth/session code touched            | Add authentication/session/access-control policy.     |
| Database query appears               | Add SQL injection and transaction policy.             |
| Missing trust input discovered       | Add fail-safe blocking policy.                        |
| Agent proposes insecure shortcut     | Add anti-shortcut repair policy.                      |
| Build passes without tests           | Add verification-test requirement.                    |
| Runtime service exists without probe | Add verification-runtime requirement.                 |
| Final report starts without evidence | Add final evidence table requirement.                 |

### Policy Delta

```ts
type PolicyDelta = {
  trigger: string;
  newSurface: string;
  addedPolicies: string[];
  addedPhaseBindings: PhaseBinding[];
  newBlockingLevel?: 'advisory' | 'required' | 'fail_closed';
  rationale: string;
};
```

### Key Design Choice: Monotonic Hardening

During a run, policy state may become stricter by default. The model cannot
relax policies. Relaxation requires an external audited decision.

Rationale:

Agents often adapt under failure pressure. Monotonic hardening prevents the
agent from solving build/runtime problems by weakening security.

## Loop Conditioning

Repair loops are high-risk.

Each loop iteration should carry:

- selected policies;
- active phase bindings;
- controls already implemented;
- evidence still missing;
- failing validator output;
- forbidden workarounds;
- maximum retry budget.

### Repair Invariants

The agent must not:

- skip or weaken security tests;
- remove validation to satisfy functional tests;
- disable TLS, host-key checking, authentication, authorization, or logging;
- broaden permissions;
- generate unmanaged credentials;
- invent trust anchors;
- replace runtime probes with self-reports;
- mark provider failures or malformed outputs as success.

### Stop Conditions

Loops should stop with:

- `SUCCESS_VERIFIED`;
- `FAILED_VALIDATION`;
- `BLOCKED_INPUT_REQUIRED`;
- `BLOCKED_ENVIRONMENT`;
- `BLOCKED_POLICY_CONFLICT`;
- `ESCALATION_REQUIRED`.

## Plugin Extensibility

PGAH should support policy plugins.

### Plugin Contract

```ts
interface PolicyPlugin {
  id: string;
  version: string;
  policySources(): PolicyRecord[];
  classify?(context: TaskContext): SurfaceSignal[];
  select?(surface: TaskSurface): PolicyCandidate[];
  phaseBindings(policy: PolicyRecord): PhaseBinding[];
  renderPrompt(binding: PhaseBinding): string;
  authorizeTool?(call: ToolCall, state: PolicyState): ToolDecision;
  validators(policy: PolicyRecord): PolicyValidator[];
  generateProbes?(state: PolicyState): Probe[];
  validateEvidence?(evidence: Evidence): PolicyFinding[];
  trajectoryLabels?(event: TrajectoryEvent): BehaviorLabel[];
  outcomeScorers?(artifact: FinalArtifact): OutcomeScore[];
}
```

### Plugin Trust

Plugins should be:

- versioned;
- allowlisted;
- sandboxed when executing code;
- prevented from disabling core policies silently;
- required to declare tool permissions;
- required to declare evidence semantics.

Trust tiers:

| Tier         | Capability                                       |
| ------------ | ------------------------------------------------ |
| Core         | Built-in non-negotiable policies and validators. |
| Trusted      | Can add policies, validators, and probes.        |
| Experimental | Can recommend policies but not hard-gate runs.   |
| Untrusted    | Documentation/reference only.                    |

## Final Status Semantics

The harness should not collapse all runs into success/failure.

Recommended terminal states:

| State                          | Meaning                                                              |
| ------------------------------ | -------------------------------------------------------------------- |
| `SUCCESS_VERIFIED`             | Functional and required policy validation passed.                    |
| `SUCCESS_WITH_RESIDUAL_RISK`   | Required validation passed but residual non-blocking risks remain.   |
| `BLOCKED_INPUT_REQUIRED`       | Security-critical inputs are missing; safe completion is impossible. |
| `BLOCKED_POLICY_CONFLICT`      | Task request conflicts with required policy.                         |
| `FAILED_FUNCTIONAL_VALIDATION` | Functional checks failed.                                            |
| `FAILED_POLICY_VALIDATION`     | Security/policy checks failed.                                       |
| `FAILED_HARNESS_ERROR`         | Provider/tool/harness failure invalidated the run.                   |

Key design choice:

```text
Safe blocking can be a positive security outcome.
```

Rationale:

For high-risk underspecified tasks, unsafe liveness is worse than fail-safe
incompletion.

## Evaluation Methodology

The empirical unit is:

```text
task x agent/provider x policy condition x run replicate
```

### Conditions

| Condition                           | Purpose                               |
| ----------------------------------- | ------------------------------------- |
| Baseline direct agent               | Ordinary behavior.                    |
| Generic security reminder           | Prompt-only broad nudge.              |
| Full flat policy dump               | More policy text without selection.   |
| Selected policies injected once     | Selection without phase distribution. |
| Phase-distributed selected policies | Distribution effect.                  |
| Dynamic policy harness              | Full PGAH method.                     |
| Human oracle policies               | Upper bound for selection quality.    |

### Core Metrics

Policy selection:

- precision against human policy labels;
- recall of critical policies;
- selected-policy count;
- redundancy rate;
- token/runtime cost.

Trajectory:

- phase coverage;
- phase ordering;
- time-to-risk-recognition;
- policy-to-action conversion;
- verification-test frequency;
- verification-runtime frequency;
- unsafe adaptation rate;
- final evidence support;
- behavior transition shifts.

Outcome:

- functional pass rate;
- security pass rate;
- exploit/adversarial test pass rate;
- severe vulnerability rate;
- fail-safe blocking rate where appropriate;
- false-completion rate;
- cost per verified success.

### Causal Claim

The strongest publication claim should be:

```text
PGAH improves secure/correct outcomes, and this improvement is mediated by
trajectory changes such as earlier risk recognition, more adversarial tests,
more runtime probing, fewer insecure adaptations, and stronger evidence
discipline.
```

## Implementation Roadmap

### Stage 0: Preserve Current Research Artifacts

- Keep current foundation document.
- Keep BaxBench summary.
- Keep five-agent proposals and review.
- Do not mix raw trajectories into this repo unless intentionally curated.

### Stage 1: Define Schemas

Create schemas for:

- `PolicyRecord`;
- `TaskSurface`;
- `SelectedPolicySet`;
- `PhaseBinding`;
- `PolicyDelta`;
- `EvidenceLedger`;
- `ValidationResult`;
- `TrajectoryIntervention`.

### Stage 2: Build Minimum Policy Registry

Start with 20-40 policies:

- input validation;
- file/path handling;
- error handling/logging;
- command execution;
- SQL/database;
- access control;
- dependency/supply-chain;
- environment setup;
- agent-process security.

Each policy must have:

- triggers;
- phase bindings;
- forbidden workarounds;
- evidence requirements;
- at least one validator/probe where possible.

### Stage 3: Build Transparent Selector

Implement:

- deterministic triggers;
- retrieval over policy text;
- small graph expansion;
- severity/enforceability ranking;
- redundancy suppression;
- selection rationale logging.

### Stage 4: Build Phase Distributor

Generate phase-specific:

- inspection checklists;
- planning constraints;
- implementation guardrails;
- adversarial test requirements;
- runtime probe requirements;
- repair invariants;
- final evidence table.

### Stage 5: Build Prototype Harness Workflow

Prototype nodes:

```text
classify-surface
select-policies
distribute-policies
inspect
plan
implement
validate-functional
validate-policy
repair-loop
final-evidence-report
```

### Stage 6: Add Tool Broker and Evidence Ledger

Implement:

- tool risk classes;
- broker decisions;
- evidence records;
- final claim gate;
- failed/unknown evidence semantics.

### Stage 7: Add Dynamic Hardening

Start with simple triggers:

- new dependency;
- shell command;
- file path handling;
- service bind;
- missing trust input;
- final report without evidence.

### Stage 8: Pilot Evaluation

Run 10-20 tasks:

- file parser;
- web API;
- database;
- environment setup;
- dependency-heavy backend task.

Compare:

- baseline;
- generic reminder;
- selected policies;
- phase-distributed policies;
- full PGAH.

### Stage 9: Scale to BaxBench

Use matched task batches and frozen behavior codebook.

Add:

- trajectory labels;
- outcome labels;
- human annotation;
- statistical analysis.

### Stage 10: Learn Selection

Only after sufficient labels:

- train supervised ranker;
- evaluate held-out tasks;
- introduce constrained contextual bandit if justified.

## Key Design Choices and Rationales

### 1. Harness Over Prompt

Security-critical state must live outside the LLM.

Rationale:

LLMs can forget, rationalize, or be influenced by untrusted context. A harness
can persist policy state, enforce gates, and reject unsupported claims.

### 2. Policy Objects Over Principle Text

Principles must be normalized into policies.

Rationale:

Selection, enforcement, validation, and evaluation need structured metadata,
not prose alone.

### 3. Compact Selection Over Full Corpus

Select a small relevant set of policies.

Rationale:

Full policy dumps are expensive and may dilute attention. Compact selected
sets are easier to follow, validate, and study.

### 4. Phase Distribution Over One-Time Injection

Bind policies to behavior phases.

Rationale:

The same policy has different operational meaning during inspection,
planning, implementation, validation, repair, and reporting.

### 5. Evidence Ledger Over Self-Report

The model's final report is not evidence.

Rationale:

Security claims must be supported by observed files, commands, tests, probes,
and validator results.

### 6. Runtime Probes as First-Class

Runtime validation should be required when task semantics involve services,
auth, networking, or environment setup.

Rationale:

BaxBench evidence shows runtime probing is rare by default, yet many security
properties only appear at runtime.

### 7. Dynamic Hardening Over Static Selection

Policies should update when new risks appear.

Rationale:

Agents introduce new dependencies, sinks, services, and workarounds during
implementation. Initial selection cannot foresee all risks.

### 8. Tool Brokering Over Unrestricted Autonomy

Risky tool calls should be mediated.

Rationale:

Security failures become real through tool use: network fetches, package
installs, service starts, credential creation, and permission changes.

### 9. Fail-Safe Blocking Over Unsafe Completion

Some tasks should not complete without missing trust inputs.

Rationale:

For persistent remote access, credentials, host authenticity, and deployment
facts are security-critical. Inventing them creates security debt.

### 10. Trajectory and Outcome Evaluation Together

Measure both behavior and final artifacts.

Rationale:

Security-looking behavior is not security success. The research contribution
must show behavior changes that correlate with independently validated
outcome improvements.

## Expected Contributions

PGAH can contribute to the security community in four ways.

1. **Methodological contribution**
   - A framework for converting principles into executable policy controls
     for coding agents.

2. **Systems contribution**
   - A harness architecture for selecting, distributing, enforcing, and
     validating policies during agentic coding.

3. **Empirical contribution**
   - A trajectory-and-outcome evaluation method for secure code generation.

4. **Practical contribution**
   - A plugin-friendly architecture that can adapt to new task families,
     benchmarks, languages, and security domains.

## Final Definition

Policy-Guided Agent Harness is:

```text
A secure coding-agent control method that converts human-readable principles
into executable policies, selects compact policy sets from task and trajectory
evidence, distributes them across coding behavior phases, enforces them through
a harness with tool brokering and validation, dynamically hardens policy state
as risks emerge, and evaluates both trajectory changes and final
correctness/security outcomes.
```

This is the recommended ultimate design for the next phase of the project.
