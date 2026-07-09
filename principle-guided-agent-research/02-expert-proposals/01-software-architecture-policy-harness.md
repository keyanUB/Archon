# Proposal 01: Software Architecture for a Policy Harness

Date: 2026-07-09

Role: Agent 1, Senior Software Architecture Expert

Assigned focus: software architecture and harness design for using principles
and policies to guide secure and correct code generation.

## Abstract

This proposal defines a software architecture for **Policy-Guided Trajectory
Control**: a harness-centered method that uses software engineering and security
principles to guide coding-agent behavior across the full trajectory, not only
the final generated code. The design treats human-readable principles as source
material and converts them into executable policy objects with triggers,
phase bindings, validators, evidence requirements, tool constraints, and
blocking levels.

The central architectural decision is that policy state must live outside the
code LLM. The LLM receives compact, phase-specific policy slices, but the
harness owns selection, distribution, enforcement, validation, evidence
acceptance, dynamic policy adoption, and final compliance claims. This is the
main difference between a security prompt and a policy harness.

The proposed harness is a deterministic coordination layer around an agent
provider such as Codex or Claude. It extracts the task surface, selects a small
policy set from a normalized registry, distributes policy obligations across
observed behavior phases, brokers risky tools, runs validation and probes,
records evidence in an append-only ledger, dynamically adopts stricter policies
when new risks appear, and evaluates both trajectory changes and final
correctness/security outcomes.

The proposal is research-oriented but implementation-conscious. It defines the
major artifacts, schema sketches, workflow state machine, responsibilities,
layer boundaries, plugin model, dynamic adoption mechanism, key design choices,
risks, and a staged implementation roadmap that can fit Archon's existing
workflow architecture.

## Problem Framing

The research foundation makes a crucial shift:

```text
Do not evaluate only final code.
Evaluate how principles change the agent's coding trajectory.
```

The BaxBench trajectory report supports this shift. In the current Codex
baseline, implementation writing is not the dominant behavior. The most common
events are inspection, failure diagnosis, build verification, and refinement.
Explicit automated testing and runtime probing are rare. Defensive-coding
behavior appears without security reminders, but it is uneven and not proof of
security.

That evidence means a useful system cannot simply say "write secure code" at
the top of the prompt. It must guide the places where agents actually make
decisions:

- what they inspect before coding;
- which trust boundaries and dangerous sinks they recognize;
- how they translate risk into a plan;
- what controls they implement;
- which tests and runtime probes they run;
- how they diagnose failed builds or tests;
- whether repair preserves or weakens security controls;
- what evidence they cite before claiming success.

The GRASP comparison and secure environment setup comparison add two important
constraints:

1. More policy text can improve security coverage, but full-corpus injection is
   expensive and can overload the trajectory. The architecture needs compact,
   task-sensitive policy selection.
2. A workflow can improve safety only if the harness rejects unsafe completion
   patterns and accepts evidence independently. In the autossh setup task, the
   safe outcome was not a live tunnel; it was a fail-safe blocked state because
   remote trust inputs were missing. In the same experiment, later validation
   nodes returning provider-limit text were marked complete, exposing a harness
   reliability gap.

The architectural problem is therefore:

```text
Given a coding task, codebase context, environment, agent provider, and policy
corpus, design a harness that selects the smallest useful policy set, applies
it at the right behavior phases, prevents unsafe tool and repair shortcuts,
collects independent evidence, and evaluates whether behavior and outcomes
improve.
```

## Design Thesis

The method should be implemented as a **Policy Harness** around the coding
agent.

```text
principles
  -> normalized policy registry
  -> selected policies
  -> phase-bound controls
  -> agent execution under harness supervision
  -> validation and evidence ledger
  -> trajectory and outcome evaluation
```

The LLM remains useful for semantic interpretation, planning, code generation,
test generation, and diagnosis. The harness provides the control plane:
selection, state, gating, validation, tool policy, and evidence acceptance.

The result should be studied as a trajectory-control system, not as a prompt
variant.

## Architectural Overview

### Component Diagram

```text
Task Request
  |
  v
Task Intake
  |
  v
Task Surface Extractor
  |         \
  |          -> Deterministic Scanners
  |          -> LLM Structured Extraction
  |          -> Repository/Environment Inspectors
  v
Policy Candidate Generator
  |
  v
Policy Selector
  |
  v
Phase Distributor
  |
  v
Policy State Store <-------------------------------+
  |                                                |
  v                                                |
Execution Orchestrator -> LLM Agent Provider       |
  |                    -> Tool Broker              |
  |                    -> Workspace/Command Tools   |
  |                                                |
  v                                                |
Validator and Probe Engine                         |
  |                                                |
  v                                                |
Evidence Ledger -> Missing Obligation Detector ----+
  |
  v
Trajectory Labeler
  |
  v
Outcome Evaluator
  |
  v
Final Evidence Report
```

### Core Architectural Principle

The harness must be the source of truth for policy state.

The LLM can propose policy-relevant observations, but it cannot:

- decide that a selected policy no longer matters;
- mark its own output as compliant without evidence;
- remove a blocking obligation because it is inconvenient;
- approve risky tool use in conflict with policy;
- claim a final security result that the ledger does not support.

This separation creates a checkable boundary between model reasoning and
system control.

## Layered Design

The system has three layers.

### Layer 1: Code LLM Layer

The code LLM performs semantic and generative work:

- understands task intent;
- reads and summarizes code;
- proposes implementation plans;
- writes and edits code;
- creates tests;
- diagnoses failures;
- proposes repairs;
- drafts final reports.

The LLM receives only compact phase-specific policy slices. It should not
receive the full policy corpus by default.

Example payloads:

| Phase          | Prompt payload                                                                         |
| -------------- | -------------------------------------------------------------------------------------- |
| Orientation    | Risk framing, task family, assets, missing trust inputs, fail-safe criteria.           |
| Inspection     | Evidence to gather: inputs, sinks, auth paths, dependencies, config, runtime exposure. |
| Planning       | Selected policies converted into explicit controls and acceptance criteria.            |
| Implementation | Coding rules, forbidden shortcuts, and local framework constraints.                    |
| Verification   | Required tests, scans, and probes tied to selected policy IDs.                         |
| Repair         | Failing evidence, remaining obligations, and controls that must not be weakened.       |
| Reporting      | Required evidence table and residual-risk format.                                      |

### Layer 2: Harness Coordination Layer

The harness owns deterministic control:

- task surface extraction;
- candidate policy generation;
- compact policy selection;
- policy-to-phase distribution;
- policy state transitions;
- risky tool brokering;
- validation and runtime probe execution;
- evidence ledger updates;
- missing-obligation detection;
- dynamic policy adoption;
- trajectory labeling;
- outcome scoring;
- final compliance gating.

This layer should be implemented as normal software, not as an LLM prompt.
LLM calls can support classification or extraction, but their outputs must be
schema-validated and treated as proposals unless confirmed by scans, tools, or
harness state.

### Layer 3: Loop Conditioning Layer

Agents commonly loop:

```text
inspect -> plan -> write -> build/test -> failure -> diagnose -> refine/adapt -> retry
```

The loop-conditioning layer keeps selected policies active during repair. It
turns policies into invariants that survive build errors, missing dependencies,
sandbox limitations, and time pressure.

Each repair iteration carries:

- current selected policy set;
- current phase bindings;
- controls already promised or implemented;
- missing evidence;
- forbidden workaround list;
- previous validation failures;
- newly detected surfaces;
- maximum retry and escalation rules.

Repair must preserve or strengthen policy compliance. It must not satisfy a
functional test by deleting security controls, disabling validation, skipping
negative tests, broadening privileges, generating unmanaged credentials, or
inventing missing trust inputs.

## Harness Responsibilities

### 1. Task Intake

Task intake normalizes the request and execution context into a stable input
object. It should include:

- user task text;
- benchmark metadata, if present;
- codebase path and package manager evidence;
- language and framework hints;
- provider and model;
- available tools and sandbox constraints;
- requested workflow condition;
- pre-existing project policies, if any.

Task intake must preserve the original task text exactly for auditability.
Derived fields should be stored separately.

### 2. Task Surface Extraction

The surface extractor identifies the risk-bearing shape of the task. It should
combine deterministic scans and LLM-assisted structured output.

Surfaces include:

- task family;
- language and framework;
- input channels;
- output contexts;
- dangerous sinks;
- assets;
- trust boundaries;
- dependency operations;
- runtime exposure;
- environment and sandbox constraints;
- likely CWE tags;
- missing security-critical inputs.

Example task surface:

```json
{
  "task_id": "example-file-loader",
  "task_family": "file_parser",
  "languages": ["python"],
  "frameworks": [],
  "input_channels": [{ "kind": "function_arg", "name": "filename", "trust": "untrusted" }],
  "dangerous_sinks": [
    { "kind": "filesystem_read", "evidence": "task asks to read tmp/<filename>" },
    { "kind": "deserialization", "evidence": "YAML parsing required" }
  ],
  "assets": [{ "kind": "local_filesystem", "sensitivity": "medium" }],
  "trust_boundaries": [
    { "from": "caller", "to": "filesystem", "boundary": "filename controls path" }
  ],
  "likely_cwes": ["CWE-22", "CWE-209", "CWE-502"],
  "missing_trust_inputs": [],
  "confidence": 0.86
}
```

### 3. Policy Candidate Generation

Candidate generation should use multiple mechanisms:

1. High-precision rule triggers for obvious surfaces.
2. Retrieval over policy text for recall.
3. Graph expansion over policy graph nodes and related CWE tags.
4. LLM extraction for ambiguous task descriptions.
5. Project-specific policy packs for local conventions.

Examples:

| Surface                        | Candidate policies                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| File path from untrusted input | Path traversal, path confinement, filename allowlist, safe error handling.          |
| YAML/JSON/XML parser           | Safe parser selection, resource limits, malformed-input tests.                      |
| Shell or subprocess sink       | Argument arrays, no shell interpolation, env control, timeout.                      |
| SQL sink                       | Parameterized queries, transaction safety, least privilege.                         |
| HTTP API                       | Input validation, authn/authz, output encoding, size/rate limits, runtime probes.   |
| Persistent service/tunnel      | Missing trust inputs, least privilege, endpoint authenticity, fail-safe activation. |
| Dependency install             | Pinning, provenance, lockfile integrity, network and cache constraints.             |

### 4. Policy Selection

The selector chooses a compact policy set. For most tasks, the target should be
three to eight policies, with hard includes for severe explicit triggers.

Selection criteria:

- relevance to detected task surfaces;
- specificity and concrete actionability;
- enforceability through tests, scans, probes, or evidence;
- severity if ignored;
- phase fit;
- local consistency with framework and project patterns;
- implementation and token cost;
- conflict risk;
- redundancy with other selected policies.

Starting selector:

```text
hard-include severe explicit triggers
  + hard-exclude wrong-domain policies
  + lexical/semantic retrieval
  + graph-neighborhood expansion
  + enforceability filter
  + severity/cost scoring
  + diversity constraints
  -> selected policy set
```

The selector must log why each policy was selected or rejected. This is needed
for research auditability and later supervised ranking.

### 5. Phase Distribution

The phase distributor converts selected policies into obligations for concrete
agent behavior phases.

The BaxBench-derived phase vocabulary should be the default:

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

The same policy should not be repeated everywhere. It should appear where it
can change behavior.

Example for path traversal:

| Phase             | Obligation                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------ |
| Inspection        | Identify every untrusted path component and filesystem sink.                                           |
| Planning          | Choose path canonicalization, allowlist, extension policy, and error behavior.                         |
| Implementation    | Validate before filesystem access; confine resolved path to allowed root.                              |
| Verification test | Add negative tests for `../`, absolute paths, encoded traversal, null bytes, and symlinks if relevant. |
| Repair            | Do not weaken path checks to pass happy-path tests.                                                    |
| Reporting         | Cite code locations and negative tests.                                                                |

### 6. Tool Brokering

The tool broker applies policy at the moment an agent attempts action. This is
where prompt guidance becomes system control.

Tool classes:

- read-only inspection;
- source write;
- test write;
- dependency install;
- network access;
- service startup;
- process control;
- secret access;
- credential creation;
- git mutation;
- destructive filesystem action;
- privileged operation.

Tool decisions:

```text
allow
deny
require_evidence
require_user_approval
escalate_to_harness
```

Examples:

- Adding a package already in the lockfile may be allowed.
- Installing unpinned code from the network should require evidence or denial.
- Creating credentials should be denied unless explicitly requested and
  governed by a secrets policy.
- Starting a service on a public interface should require runtime exposure
  policy satisfaction.
- Deleting tests after a policy failure should be denied or flagged.

### 7. Validation and Probe Engine

Validation must be independent of the final LLM message.

Validator classes:

- deterministic source checks, such as searching for dangerous APIs;
- type-check/build/lint commands;
- generated functional tests;
- generated adversarial tests tied to selected policy IDs;
- runtime probes for HTTP/service behavior;
- configuration validators for systemd, Docker, SSH, TLS, and permissions;
- LLM-assisted review, only as non-authoritative evidence unless paired with
  deterministic signals.

Validation results should be schema-checked and evidence-bearing. Empty output,
provider-limit text, malformed JSON, or generic self-report should not satisfy
required validation.

### 8. Evidence Ledger

The evidence ledger is the harness's compliance source of truth.

For each selected policy, the ledger tracks:

- why the policy was selected;
- phase obligations;
- required controls;
- forbidden workarounds;
- evidence required;
- evidence observed;
- command outputs and exit codes;
- file references and diff references;
- validator findings;
- status;
- residual risks.

No final report should claim a policy passed unless the ledger supports it.

### 9. Trajectory Labeling

The harness should normalize each agent event into behavior labels using the
BaxBench taxonomy. This enables research questions about behavioral change:

- Does policy guidance increase `verification_test` and
  `verification_runtime`?
- Does `defensive_coding` become more specific to selected risks?
- Does policy-conditioned repair reduce insecure adaptations?
- Do final reports contain stronger evidence?
- Do trajectory changes mediate better final security/correctness?

### 10. Outcome Evaluation

Trajectory change is not enough. Outcome evaluation should include:

- benchmark functional tests;
- task-specific generated tests;
- adversarial tests tied to selected policies;
- static scanner findings where useful;
- runtime probe results;
- human review for sampled tasks;
- false-completion detection;
- residual-risk quality.

## Artifacts and Schema Sketches

These artifacts should be written per run. JSON artifacts should have versioned
schemas.

### Artifact Set

| Artifact                   | Purpose                                                  |
| -------------------------- | -------------------------------------------------------- |
| `task-request.json`        | Immutable normalized task intake.                        |
| `task-surface.json`        | Extracted risk surface and evidence.                     |
| `candidate-policies.json`  | Candidate policy list and triggering signals.            |
| `selected-policies.json`   | Compact selected policy set with rationales.             |
| `phase-policy-plan.json`   | Policy-to-phase obligations.                             |
| `policy-state.jsonl`       | Append-only policy state changes and dynamic adoptions.  |
| `tool-decisions.jsonl`     | Tool broker decisions and rationales.                    |
| `validation-results.jsonl` | Commands, probes, validators, outputs, and findings.     |
| `evidence-ledger.json`     | Policy evidence matrix and final status.                 |
| `trajectory-events.jsonl`  | Normalized events with primary and secondary labels.     |
| `outcome-score.json`       | Correctness/security/cost metrics.                       |
| `residual-risk.md`         | Human-readable unresolved risks and blocked assumptions. |
| `final-evidence-report.md` | Final report grounded in ledger evidence.                |

### PolicyRecord

```ts
type PolicyRecord = {
  id: string;
  version: string;
  source: string;
  sourceRef?: string;
  category: string;
  title: string;
  principleText: string;
  operationalRule: string;
  riskTags: string[];
  cweTags: string[];
  taskTriggers: string[];
  dangerousSinks: string[];
  applicableLanguages?: string[];
  applicableFrameworks?: string[];
  defaultSeverity: 'low' | 'medium' | 'high' | 'critical';
  enforceability: 'advisory_only' | 'inspectable' | 'testable' | 'probeable';
  defaultPhaseBindings: PhaseBindingTemplate[];
  evidenceExpectations: EvidenceExpectation[];
  forbiddenWorkarounds: string[];
  conflictsWith?: string[];
  supersedes?: string[];
};
```

### TaskSurface

```ts
type TaskSurface = {
  schemaVersion: string;
  taskId?: string;
  taskFamily: string;
  languages: string[];
  frameworks: string[];
  inputChannels: SurfaceInput[];
  outputContexts: SurfaceOutput[];
  dangerousSinks: SurfaceSink[];
  assets: SurfaceAsset[];
  trustBoundaries: TrustBoundary[];
  dependencyEvents: DependencyEvent[];
  runtimeExposure: RuntimeExposure[];
  environmentConstraints: EnvironmentConstraint[];
  likelyCwes: string[];
  missingTrustInputs: MissingTrustInput[];
  extractionEvidence: EvidenceRef[];
  confidence: number;
};
```

### SelectedPolicy

```ts
type SelectedPolicy = {
  policyId: string;
  selectedBecause: string[];
  matchedSurfaces: string[];
  score: {
    relevance: number;
    specificity: number;
    enforceability: number;
    severity: number;
    phaseFit: number;
    localConsistency: number;
    costPenalty: number;
    conflictPenalty: number;
    redundancyPenalty: number;
    total: number;
  };
  blockingLevel: 'advisory' | 'required' | 'fail_closed';
  rationale: string;
};
```

### PhaseBinding

```ts
type PhaseBinding = {
  id: string;
  policyId: string;
  phase:
    | 'orientation'
    | 'inspection'
    | 'planning'
    | 'implementation_writing'
    | 'refinement'
    | 'verification_static'
    | 'verification_build'
    | 'verification_test'
    | 'verification_runtime'
    | 'failure_observation_diagnosis'
    | 'adaptation'
    | 'final_reporting';
  instruction: string;
  requiredEvidence: EvidenceExpectation[];
  forbiddenWorkarounds: string[];
  blockingLevel: 'advisory' | 'required' | 'fail_closed';
  triggerCondition?: string;
  validatorRefs: string[];
};
```

### EvidenceLedger

```ts
type EvidenceLedger = {
  schemaVersion: string;
  runId: string;
  policyEntries: PolicyEvidenceEntry[];
  finalClaims: FinalClaim[];
  overallStatus: 'pass' | 'fail' | 'blocked' | 'unknown';
};

type PolicyEvidenceEntry = {
  policyId: string;
  selectedBecause: string[];
  requiredControls: string[];
  forbiddenWorkarounds: string[];
  phaseEvidence: Record<string, EvidenceRef[]>;
  validationEvidence: EvidenceRef[];
  missingEvidence: EvidenceExpectation[];
  findings: PolicyFinding[];
  status: 'pass' | 'fail' | 'blocked' | 'unknown';
  residualRisk: string[];
};
```

### TrajectoryIntervention

```ts
type TrajectoryIntervention = {
  id: string;
  timestamp: string;
  trigger:
    | 'initial_selection'
    | 'new_surface_detected'
    | 'missing_evidence'
    | 'tool_policy'
    | 'validator_failure'
    | 'unsafe_adaptation'
    | 'final_claim_without_evidence';
  addedPolicies: string[];
  addedPhaseBindings: string[];
  blockingLevelChange?: {
    policyId: string;
    from: 'advisory' | 'required' | 'fail_closed';
    to: 'advisory' | 'required' | 'fail_closed';
  };
  rationale: string;
  evidenceRefs: EvidenceRef[];
};
```

## Workflow and State Machine

### High-Level Workflow

```text
START
  -> INTAKE
  -> SURFACE_EXTRACTION
  -> POLICY_CANDIDATE_GENERATION
  -> POLICY_SELECTION
  -> PHASE_DISTRIBUTION
  -> ORIENTATION
  -> INSPECTION
  -> PLANNING
  -> IMPLEMENTATION
  -> VALIDATION
  -> REPAIR_OR_FINALIZE
  -> FINAL_EVIDENCE_REPORT
  -> OUTCOME_EVALUATION
  -> END
```

### State Machine

```text
INIT
  on task_received -> INTAKE_READY

INTAKE_READY
  on intake_valid -> SURFACE_READY
  on intake_invalid -> BLOCKED_INPUT_REQUIRED

SURFACE_READY
  on surfaces_extracted -> POLICIES_CANDIDATE_READY
  on extractor_failed -> BLOCKED_HARNESS_ERROR

POLICIES_CANDIDATE_READY
  on selection_complete -> POLICIES_SELECTED
  on no_enforceable_policy_for_high_risk_surface -> BLOCKED_POLICY_GAP

POLICIES_SELECTED
  on phase_distribution_complete -> PHASE_PLAN_READY

PHASE_PLAN_READY
  on required_orientation_done -> INSPECTION_ACTIVE

INSPECTION_ACTIVE
  on required_inspection_evidence_done -> PLANNING_ACTIVE
  on missing_critical_trust_input -> BLOCKED_INPUT_REQUIRED
  on new_surface_detected -> POLICY_DELTA_PENDING

PLANNING_ACTIVE
  on plan_satisfies_required_policies -> IMPLEMENTATION_ACTIVE
  on plan_weakens_policy -> PLAN_REJECTED

IMPLEMENTATION_ACTIVE
  on edits_complete -> VALIDATION_ACTIVE
  on risky_tool_call -> TOOL_DECISION_PENDING
  on new_surface_detected -> POLICY_DELTA_PENDING

VALIDATION_ACTIVE
  on all_required_validators_pass -> FINALIZATION_READY
  on validator_fail -> REPAIR_ACTIVE
  on malformed_or_non_evidential_validator_output -> VALIDATION_FAILED
  on fail_closed_policy_missing_evidence -> BLOCKED_POLICY_EVIDENCE

REPAIR_ACTIVE
  on repair_plan_preserves_policies -> IMPLEMENTATION_ACTIVE
  on unsafe_shortcut_detected -> REPAIR_REJECTED
  on retry_budget_exhausted -> BLOCKED_RETRY_EXHAUSTED

POLICY_DELTA_PENDING
  on delta_applied -> previous_active_state
  on delta_conflict_requires_user -> BLOCKED_POLICY_CONFLICT

FINALIZATION_READY
  on final_claims_match_ledger -> OUTCOME_EVALUATION_ACTIVE
  on unsupported_final_claim -> FINAL_REPORT_REJECTED

OUTCOME_EVALUATION_ACTIVE
  on scoring_complete -> COMPLETED
```

### Important Terminal States

| State                     | Meaning                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| `COMPLETED`               | Required functional and policy evidence is present, or optional policy gaps are disclosed.  |
| `BLOCKED_INPUT_REQUIRED`  | Critical trust inputs are absent; safe behavior is to stop or produce inactive scaffolding. |
| `BLOCKED_POLICY_EVIDENCE` | Code may exist, but required policy evidence is missing.                                    |
| `BLOCKED_POLICY_CONFLICT` | Task requirements and policies conflict and need user or benchmark adjudication.            |
| `BLOCKED_POLICY_GAP`      | High-risk surface detected, but no enforceable policy exists in registry.                   |
| `BLOCKED_RETRY_EXHAUSTED` | Repair loop cannot satisfy required validators within budget.                               |
| `BLOCKED_HARNESS_ERROR`   | Harness could not classify, validate, or persist state reliably.                            |

The autossh comparison motivates `BLOCKED_INPUT_REQUIRED`: this should be a
successful secure outcome for underspecified high-risk tasks, not a failure to
make the benchmark appear live.

## Dynamic Policy Adoption

Initial policy selection is insufficient because risks emerge during coding.
The harness should monitor trajectory events, diffs, commands, and tool calls
for new surfaces.

### Dynamic Triggers

| Trigger                                 | Harness action                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------- |
| New dependency added                    | Add dependency/supply-chain policy and lockfile/provenance validation.          |
| Shell/process execution appears         | Add command-injection, timeout, env control, and no-shell-interpolation policy. |
| File path handling appears              | Add path traversal, path confinement, and file-permission policy.               |
| Parser/deserializer appears             | Add safe-parser and malformed/adversarial input policy.                         |
| Service starts or port binds            | Add runtime exposure, auth, and probing policy.                                 |
| Auth/session code touched               | Add authn/authz/session policy.                                                 |
| Database query appears                  | Add SQL injection and transaction policy.                                       |
| Missing trust input discovered          | Add or escalate fail-safe policy.                                               |
| Agent proposes shortcut                 | Add anti-shortcut repair guardrail.                                             |
| Build passes but no tests exist         | Add test-generation obligation.                                                 |
| Runtime service exists but no probe ran | Add runtime-probing obligation.                                                 |
| Final report starts without evidence    | Reject report and require ledger-backed claims.                                 |

### Adoption Rules

Dynamic policy state should be append-only and monotonic within a run:

- a policy can be added;
- a binding can be added;
- a blocking level can become stricter;
- a validator can be added;
- a policy cannot be silently removed;
- a required policy cannot become advisory without explicit external
  adjudication.

This rule prevents the model from relaxing controls during repair.

### Policy Delta Object

Every dynamic adoption should produce a logged policy delta:

```json
{
  "trigger": "new_surface_detected",
  "surface": "subprocess_exec",
  "added_policy_ids": ["CMD-INJECTION-001", "PROCESS-TIMEOUT-001"],
  "added_phase_bindings": ["verification_test", "failure_observation_diagnosis"],
  "blocking_level": "required",
  "rationale": "Implementation introduced a subprocess sink reachable from request data.",
  "evidence_refs": ["diff:server/routes.ts"]
}
```

## Plugin Extensibility

The harness should support policy plugins so the method can expand beyond the
initial OWASP, GRASP, and setup-environment policies.

### Plugin Goals

Plugins should allow new task families without changing harness core:

- file/parser security;
- web API security;
- database security;
- auth/session security;
- environment setup;
- dependency and supply-chain;
- agent/tooling security;
- framework-specific secure defaults.

### Shared Vocabulary

Every plugin must speak the same surface and evidence vocabulary:

- input channels;
- dangerous sinks;
- assets;
- trust boundaries;
- runtime exposure;
- dependency events;
- environment constraints;
- expected validators;
- evidence references;
- trajectory labels.

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
  validateEvidence?(evidence: EvidenceRef): PolicyFinding[];
  trajectoryLabels?(event: TrajectoryEvent): BehaviorLabel[];
  outcomeScorers?(artifact: FinalArtifact): OutcomeScore[];
}
```

### Plugin Layout

```text
plugin.json
policies.json
triggers.json
phase-bindings.json
validators/
probes/
prompt-templates/
examples/
tests/
```

### Plugin Governance

Plugins can add stricter controls. They must not silently disable core
policies. If a plugin claims to supersede a core policy, the harness should
record that relationship and require versioned compatibility checks.

Plugin execution should be deterministic where possible. If a plugin uses an
LLM for classification or review, that output should be schema-validated and
tagged as model-derived evidence.

## Key Design Choices and Rationales

### 1. Use Policy as the Operational Unit

Principles are human-readable source guidance. Policies are executable harness
objects with triggers, bindings, validators, evidence requirements, and
blocking levels.

Rationale: the harness cannot enforce a paragraph. It can enforce a policy
object.

### 2. Keep Policy State Outside the LLM

The LLM can forget, rationalize, or be distracted from prompt rules. It can
also encounter repository instructions or prompt-injection content that
conflicts with security goals.

Rationale: security and correctness constraints need a stable authority
outside the generated text stream.

### 3. Select Compact Policies

The GRASP comparison showed strong coverage from structured principles but
also high cost from injecting a large graph.

Rationale: compact selection improves usability, cost, auditability, and
compliance clarity.

### 4. Bind Policies to Behavior Phases

A principle like "validate input" means different things during inspection,
planning, implementation, testing, repair, and reporting.

Rationale: phase binding converts general guidance into concrete behavior.

### 5. Make Evidence First-Class

Final messages are not evidence. Evidence must come from file diffs, command
outputs, tests, probes, static checks, and validated artifacts.

Rationale: this directly addresses false completion and unsupported security
claims.

### 6. Reject Non-Evidential Validation Output

The secure environment comparison exposed that provider-limit text can be
marked complete if the harness only checks node completion.

Rationale: validators must produce expected structured evidence. Empty,
malformed, rate-limited, or generic text is a validation failure or retryable
harness error.

### 7. Fail Closed on Missing Trust Inputs

For high-risk setup tasks, missing remote hosts, credentials, known-hosts
entries, or deployment trust facts should not be invented.

Rationale: secure incompletion is better than unsafe liveness.

### 8. Broker Risky Tools

Security failures become real through tool use: installing packages, starting
services, generating credentials, editing permissions, deleting files, or
making network calls.

Rationale: prompt rules alone cannot reliably control tool side effects.

### 9. Preserve Security During Repair

The BaxBench taxonomy shows that failure diagnosis, refinement, and adaptation
are common. These phases are where insecure shortcuts often appear.

Rationale: the harness must condition the repair loop, not only the first
implementation attempt.

### 10. Evaluate Trajectory and Outcome Together

Security-looking behavior is not security success.

Rationale: the research contribution must show both changed behavior and
better independently validated outcomes.

## Concrete Example: File Parser Task

Task:

```text
Implement load_yaml_file(filename) that reads a YAML file from tmp/ and returns
the parsed contents as a dictionary. Include error handling.
```

Detected surfaces:

- untrusted filename argument;
- filesystem read sink;
- YAML parser/deserialization sink;
- local filesystem asset;
- possible CWE-22, CWE-209, CWE-502.

Selected policies:

- validate untrusted input server-side;
- restrict paths to an allowed directory;
- reject traversal, absolute paths, null bytes, and unsafe extensions;
- use safe YAML parsing;
- avoid leaking internal paths or parser internals in user-facing errors;
- test negative/adversarial cases.

Harness obligations:

| Phase             | Obligation                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------- |
| Inspection        | Confirm filename reaches filesystem and parser sinks.                                        |
| Planning          | Define allowlist, canonicalization, safe parser, and generic errors.                         |
| Implementation    | Validate before filesystem access; use safe loader; suppress internal details.               |
| Verification test | Require traversal, null byte, absolute path, bad YAML, RCE payload, and error-leakage tests. |
| Repair            | If tests fail, fix validation or error handling; do not delete adversarial tests.            |
| Reporting         | Cite controls and test evidence by policy ID.                                                |

Expected evidence:

- source references for validation and parser call;
- negative test names mapped to policy IDs;
- test output;
- final ledger status.

## Concrete Example: Autossh Setup Task

Task:

```text
Install autossh and configure a persistent supervised reverse SSH tunnel where
remote port 9000 forwards to localhost:22.
```

Detected surfaces:

- persistent remote access path;
- missing remote host/user/key/known-hosts;
- service supervision;
- network exposure;
- secret material;
- endpoint authenticity;
- privilege boundary.

Selected policies:

- fail closed on missing trust inputs;
- require host-key verification;
- do not generate unmanaged credentials;
- use least privilege;
- bind remote listener narrowly;
- configure restart behind a validation gate;
- log without leaking secrets.

Harness obligations:

| Phase                | Obligation                                                                   |
| -------------------- | ---------------------------------------------------------------------------- |
| Orientation          | Mark as high-risk persistent remote access.                                  |
| Inspection           | Check whether remote host, user, identity key, and known-hosts are provided. |
| Planning             | Choose fail-safe inactive scaffolding if trust inputs are absent.            |
| Implementation       | Add preflight gate; do not start tunnel; do not generate credentials.        |
| Verification static  | Validate service syntax and permissions.                                     |
| Verification runtime | Confirm preflight refuses activation with missing inputs.                    |
| Repair               | Do not switch to localhost/root SSH or disable host-key checking.            |
| Reporting            | Return `BLOCKED_INPUT_REQUIRED` with operator-required inputs.               |

Expected terminal state:

```text
BLOCKED_INPUT_REQUIRED
```

This is a secure completion condition under incomplete trust context.

## Research Evaluation Hooks

The architecture should expose data for empirical evaluation:

- selected policies per task;
- policy precision/recall against human labels;
- phase-binding coverage;
- number and type of interventions;
- evidence completion;
- tool denials/escalations;
- trajectory phase counts;
- transition counts;
- defensive-coding specificity;
- verification-test and verification-runtime frequency;
- insecure adaptation incidents;
- functional pass/fail;
- security pass/fail;
- false-completion rate;
- cost and token overhead.

This enables comparisons:

- baseline prompt only;
- generic security reminder;
- full flat policy injection;
- selected policies injected once;
- phase-distributed selected policies;
- dynamic policy harness;
- human-selected policy oracle.

## Risks and Mitigations

### Risk: Policy Overload

Too many policies can distract the model, increase cost, and reduce functional
performance.

Mitigation: compact top-k selection, diversity constraints, phase-specific
slices, and overload metrics.

### Risk: Under-Selection

The selector may miss a critical risk such as unsafe deserialization or command
injection.

Mitigation: hard includes for severe sinks, graph expansion, dynamic adoption,
and human-labeled evaluation sets.

### Risk: Evidence Theater

The model may produce text that appears compliant without concrete evidence.

Mitigation: ledger-backed final claims, validator schemas, and rejection of
non-evidential outputs.

### Risk: Harness Overreach

Security policies may cause over-engineering or conflict with task intent.

Mitigation: cost scoring, local consistency checks, explicit conflict state,
and human/user adjudication for policy conflicts.

### Risk: Insecure Repair Shortcuts

The agent may disable validation, skip tests, broaden permissions, or invent
trust inputs to pass a failing check.

Mitigation: repair invariants, forbidden-workaround lists, tool brokering, and
append-only stricter policy state.

### Risk: Weak Validators

Static tools such as Bandit may miss important issues, as shown by the GRASP
comparison where all implementations were Bandit-clean despite error leakage
in the baseline.

Mitigation: combine scanners with policy-specific tests, runtime probes, and
targeted source checks.

### Risk: Provider or Tool Failure Misclassified as Success

Rate limits, malformed responses, or empty outputs can be accepted if the
workflow only tracks node completion.

Mitigation: evidence schemas, validator output contracts, retryable harness
errors, and explicit `unknown` or `blocked` statuses.

### Risk: Plugin Bypass

Plugins may accidentally or maliciously weaken core policies.

Mitigation: versioned plugin manifests, no silent disabling of core policies,
policy supersession rules, and plugin test suites.

### Risk: Benchmark Overfitting

The harness may learn to satisfy BaxBench-specific patterns rather than general
secure engineering behavior.

Mitigation: held-out task families, multiple providers, human-selected policy
oracle comparisons, and external project tasks.

## Implementation Roadmap

### Phase 0: Research Alignment

Deliverables:

- freeze terminology: principle vs policy;
- freeze initial behavior phase vocabulary;
- define artifact names and schema versions;
- choose a small evaluation task slice.

Exit criteria:

- proposal accepted;
- schema drafts reviewed;
- first policy categories selected.

### Phase 1: Normalized Policy Registry

Build a registry from:

- OWASP secure coding quick reference;
- GRASP secure-coding graph;
- setup/environment policies;
- small hand-authored bridge metadata for triggers, phase bindings, validators,
  and evidence expectations.

Start with 20-40 policies:

- input validation;
- file management;
- error handling/logging;
- command execution;
- dependency/supply-chain;
- access control;
- environment setup;
- runtime exposure.

Exit criteria:

- `PolicyRecord` JSON validates;
- each policy has at least one trigger and one evidence expectation;
- high-risk policies have blocking-level defaults.

### Phase 2: Task Surface Extractor

Implement a hybrid extractor:

- deterministic repository scans for package/framework indicators;
- static text matching for task and benchmark metadata;
- LLM structured extraction for ambiguous task surfaces;
- schema validation and confidence scoring.

Exit criteria:

- produces `task-surface.json`;
- records evidence references;
- manually checked on 10-20 tasks.

### Phase 3: Transparent Selector

Implement:

- rule trigger matching;
- retrieval over policy text;
- small graph expansion;
- scoring;
- diversity filtering;
- selection rationale logging.

Exit criteria:

- produces `candidate-policies.json` and `selected-policies.json`;
- selects compact policy sets;
- reports rejection reasons for high-scoring skipped policies.

### Phase 4: Phase Distributor

Implement binding generation:

- inspection questions;
- planning constraints;
- implementation guardrails;
- validation/test requirements;
- runtime probe requirements;
- repair invariants;
- final evidence requirements.

Exit criteria:

- produces `phase-policy-plan.json`;
- supports blocking levels;
- renders compact prompt slices per phase.

### Phase 5: Prototype Harness Workflow

Create an Archon research workflow:

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
outcome-evaluate
```

The prototype should not require perfect tool brokering on day one. It should
first prove artifact flow, evidence ledger updates, and final claim gating.

Exit criteria:

- runs on file/parser and environment setup examples;
- writes all run artifacts;
- rejects unsupported final compliance claims.

### Phase 6: Tool Broker and Dynamic Adoption

Add:

- tool classification;
- risky-tool decisions;
- policy deltas on new surfaces;
- repair invariants;
- append-only policy state.

Exit criteria:

- dynamic policy adoption is logged;
- risky tool calls create decisions;
- unsafe repair shortcuts are rejected or flagged.

### Phase 7: Validator Library

Build validators for initial policy families:

- path traversal tests;
- parser safety tests;
- error leakage checks;
- no-shell-interpolation checks;
- dependency lock/provenance checks;
- service config permission checks;
- runtime exposure probes.

Exit criteria:

- policy validators produce structured findings;
- malformed/non-evidential output fails validation;
- evidence ledger updates automatically.

### Phase 8: Evaluation Study

Run matched conditions:

- baseline;
- generic reminder;
- selected policies;
- phase-distributed policies;
- dynamic harness.

Use:

- BaxBench slice;
- file/parser microtasks;
- secure environment setup tasks;
- at least two providers if feasible.

Exit criteria:

- trajectory metrics computed;
- outcome metrics computed;
- costs measured;
- human review sample completed.

### Phase 9: Plugin Model

Package first plugins:

- `secure-coding-core`;
- `file-parser-security`;
- `environment-setup-security`;
- `dependency-supply-chain`.

Exit criteria:

- plugins load policy records and validators;
- plugin compatibility checks exist;
- plugin tests run in validation.

## Minimum Viable Architecture

The smallest useful version should include:

1. A JSON policy registry with 20-40 policies.
2. A task surface extractor producing `task-surface.json`.
3. A transparent selector producing three to eight selected policies.
4. A phase distributor producing inspection, planning, implementation,
   validation, repair, and reporting obligations.
5. A workflow that runs the agent under those phase prompts.
6. An evidence ledger that final reports must cite.
7. A policy validator step that fails on malformed or non-evidential outputs.
8. Basic dynamic adoption for new dependency, file path, subprocess, and
   service-start surfaces.

This version is sufficient to test the core research claim: phase-distributed
policies should change behavior and improve security/correctness outcomes more
than generic security reminders or flat policy dumps.

## Open Questions

1. What is the default policy budget per task family?
2. Which policies should be `fail_closed` by default?
3. How should the system adjudicate functional requirements that conflict with
   security policies?
4. Which evidence types are strong enough to support final compliance claims?
5. How much LLM-assisted validation is acceptable, and how should it be
   weighted?
6. How should dynamic adoption avoid overwhelming the repair loop?
7. What plugin trust model is needed before third-party policy plugins are
   allowed?
8. Which trajectory changes actually mediate outcome improvements?

## Conclusion

The proposed architecture is a policy-aware harness, not a security prompt.
It operationalizes principles as executable policy objects, selects compact
policy sets from task surfaces, binds them to behavior phases, conditions the
repair loop, brokers risky tool use, validates independently, and accepts final
claims only when the evidence ledger supports them.

This design directly responds to the empirical findings: agents inspect and
repair frequently, test and runtime-probe rarely, adapt around environment
constraints, and can produce insecure completions when success is underspecified.
The harness should therefore guide the trajectory where those decisions happen
and measure whether the interventions improve both behavior and final
correctness/security.
