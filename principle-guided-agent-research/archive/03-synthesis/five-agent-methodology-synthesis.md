# Five-Agent Methodology Synthesis: Policy-Guided Secure Code Generation

Date: 2026-07-09

## Purpose

This document synthesizes five independent expert proposals on how to use
principles or policies to guide coding agents toward secure and correct code
generation.

The five expert roles were:

1. Senior software architecture expert.
2. Software security expert.
3. Machine learning expert.
4. AI agent security expert.
5. Empirical software engineering / benchmark evaluation expert.

All five read the foundation document:

`principle-guided-agent-research/archive/01-foundation/research-foundation.md`

They also used the existing reports and policy resources where relevant:

- `reports/baxbench_agent_behavior_codex.md`
- `reports/grasp-secure-coding/workflow-comparison.md`
- `reports/secure-environment-setup/docker-comparison.md`
- `reports/agent-behavior-comparison/swebench-django-sonnet-vs-archon.md`
- `.archon/data/research/grasp-secure-coding/owasp-scp.md`
- `.archon/data/research/grasp-secure-coding/scp-graph.json`
- `.archon/data/research/secure-environment-setup/setup-environment-policies.json`

## Terminology Decision: Policy vs Principle

The research should use both terms, but with different meanings.

| Term      | Meaning                                                                                                                                                   |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Principle | Human-readable secure software engineering rule or norm. Example: "Validate untrusted input before use."                                                  |
| Policy    | Executable harness object derived from one or more principles. It has triggers, phase bindings, validators, evidence requirements, and enforcement level. |

Rationale:

- "Principle" is the right term for source material from OWASP, GRASP, NIST,
  CWE, and project rules.
- "Policy" is the right term for the operational object that a harness can
  select, distribute, enforce, and evaluate.

The method should therefore be described as:

```text
principles -> normalized policy registry -> selected policies -> phase-bound controls
```

This avoids the weak design of merely telling the model to "follow secure
coding principles."

## Shared Conclusion

All five agents converged on the same core idea:

```text
Policies must live outside the code LLM as executable harness state.
The LLM receives compact phase-specific policy slices, but the harness owns
selection, distribution, enforcement, validation, and evidence acceptance.
```

The method is not a single prompt. It is a trajectory control system:

```text
task/context
  -> task surface extraction
  -> candidate policy generation
  -> compact policy selection
  -> phase-specific policy distribution
  -> LLM execution under harness checks
  -> dynamic policy adoption during trajectory
  -> independent validation and evidence ledger
  -> trajectory/outcome evaluation
```

## Integrated Method: Policy-Guided Trajectory Control

The proposed method is **Policy-Guided Trajectory Control**.

It treats coding-agent work as a sequence of observable behaviors:

```text
orientation
inspection
planning
implementation_writing
verification_static
verification_build
verification_test
verification_runtime
failure_observation_diagnosis
refinement
adaptation
final_reporting
```

These behaviors come from the BaxBench trajectory taxonomy. The key design
move is to bind selected policies to the phases where they can actually change
agent behavior.

For example:

```text
Input validation policy
  inspection: find untrusted inputs and dangerous sinks
  planning: define validation and rejection behavior
  implementation: validate at trust boundary
  testing: generate invalid/adversarial input tests
  repair: never bypass validation to pass tests
  reporting: cite validation code and test evidence
```

The harness should not force every phase for every task. Instead, selected
policies determine which phases and validators are required.

## Layered System Design

The experts converged on a three-layer design.

### Layer 1: Code LLM Layer

This is the prompt/context layer where the coding model operates.

The LLM should receive compact, phase-specific policy slices:

| Phase          | Prompt payload                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------ |
| Orientation    | Risk framing, task type, likely assets, missing trust inputs, fail-safe criteria.                |
| Inspection     | Specific evidence to gather: inputs, sinks, auth paths, dependencies, configs, runtime exposure. |
| Planning       | Selected policies converted into concrete controls and validation criteria.                      |
| Implementation | Coding rules and forbidden shortcuts.                                                            |
| Verification   | Required tests/probes tied to selected policy IDs.                                               |
| Repair         | Failing evidence, selected policies, and rule to preserve or strengthen controls.                |
| Reporting      | Evidence table and residual-risk requirements.                                                   |

Design choice:

```text
Do not inject the full policy corpus into every prompt.
```

Rationale:

- The GRASP comparison showed that broader policy context can improve control
  coverage, but full graph injection is expensive.
- The BaxBench report shows agents already perform many inspection and repair
  behaviors, but rarely do explicit tests or runtime probes. Phase-specific
  policy injection targets those weak points more directly.

### Layer 2: Harness Coordination Layer

The harness coordinates agents, tools, artifacts, and validators.

It owns:

- task surface extraction;
- policy selection;
- policy-to-phase binding;
- tool authorization;
- workflow phase gating;
- runtime probing;
- static/build/test/security validation;
- evidence collection;
- final status.

The harness should produce and maintain these artifacts:

| Artifact                  | Purpose                                                                                                                     |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `task-surface.json`       | Task type, language/framework, inputs, sinks, assets, trust boundaries, dependencies, environment constraints, likely CWEs. |
| `selected-policies.json`  | Compact selected policy set with selection rationale.                                                                       |
| `phase-policy-plan.json`  | Mapping from selected policies to phase-specific obligations.                                                               |
| `evidence-ledger.json`    | Policy ID -> expected evidence -> observed evidence -> pass/fail/unknown.                                                   |
| `validation-results.json` | Commands, probes, tests, exit codes, and findings.                                                                          |
| `residual-risk.md`        | Remaining risks and blocked assumptions.                                                                                    |

Design choice:

```text
The model may implement and reason, but it cannot self-certify success.
```

Rationale:

- The secure environment report showed that model-generated completion can be
  unsafe when the model invents missing trust inputs.
- The same report showed a workflow problem where downstream validation nodes
  returned provider-limit text but were still marked complete. The harness must
  treat malformed, empty, rate-limited, or non-evidential outputs as failed or
  retryable, not as passed validation.

### Layer 3: Loop Conditioning Layer

Coding agents often loop:

```text
write -> build/test -> failure -> diagnosis -> refinement/adaptation -> retry
```

BaxBench evidence shows that failure diagnosis, refinement, adaptation, and
build verification are common. This is where policies must remain active.

Loop conditioning means every retry loop carries:

- selected policies;
- controls already promised;
- forbidden workaround list;
- failing evidence;
- evidence still missing;
- rule to preserve or strengthen security controls.

Common failure classes:

- build/dependency failure;
- test failure;
- runtime startup failure;
- sandbox/network limitation;
- policy compliance failure;
- missing external trust input;
- repeated diagnosis without progress.

Policy-conditioned repair rules:

- do not skip or weaken security tests;
- do not disable TLS, host-key checking, auth, validation, or permission checks;
- do not generate credentials to satisfy an underspecified task;
- do not broaden privileges to make runtime checks pass;
- do not replace missing trust input with invented defaults;
- do not treat a live process as secure success without validation.

Design choice:

```text
Policy state is append-only stricter during a run unless an external controller
or user explicitly relaxes it.
```

Rationale:

- New risks can appear during implementation.
- The model should not be able to relax policies it finds inconvenient.
- This directly addresses insecure adaptations and benchmark-completion
  shortcuts.

## Policy-Harness Architecture

The architecture expert and AI-agent security expert both proposed a
Policy-Harness.

The harness should be a deterministic control layer surrounding the coding
agent.

### Core Components

```text
Task Intake
  -> Surface Extractor
  -> Policy Candidate Generator
  -> Policy Selector
  -> Phase Distributor
  -> Tool Broker
  -> Execution Orchestrator
  -> Probe/Validator Engine
  -> Evidence Ledger
  -> Trajectory Labeler
  -> Outcome Evaluator
```

### Task Surface Extractor

The surface extractor identifies:

- task family;
- language/framework;
- input channels;
- output contexts;
- dangerous sinks;
- assets;
- trust boundaries;
- dependencies;
- runtime exposure;
- environment constraints;
- benchmark metadata;
- likely CWE/security themes;
- missing security-critical inputs.

This can be built first as an LLM-assisted structured-output step plus
deterministic scans. Later it can be evaluated against human labels.

### Policy Candidate Generator

Candidate generation should be layered:

1. Rule-based triggers for high-precision safety cases.
2. Retrieval over policy text for recall.
3. Graph expansion over GRASP/security-policy graphs.
4. LLM extraction for messy task descriptions.
5. Project-specific policy packs for local conventions.

Candidate examples:

| Surface                       | Candidate policies                                                   |
| ----------------------------- | -------------------------------------------------------------------- |
| `file_path + untrusted_input` | path traversal, safe parsing, error disclosure                       |
| `subprocess/shell sink`       | command injection, argument array, environment control, timeout      |
| `SQL sink`                    | parameterized query, transaction integrity, least privilege          |
| `HTTP API`                    | input validation, authz/authn, output encoding, size/rate limits     |
| `persistent tunnel/service`   | least privilege, host authenticity, secrets, fail-safe activation    |
| `dependency install`          | version pinning, provenance, reproducible build, network constraints |

### Policy Selector

The selector should choose a compact policy set, not a full corpus.

Selection criteria:

| Criterion         | Role                                                     |
| ----------------- | -------------------------------------------------------- |
| Relevance         | Matches detected task surfaces.                          |
| Specificity       | Concrete enough to guide implementation.                 |
| Enforceability    | Has tests, probes, scans, or evidence.                   |
| Severity          | Prevents high-impact failure.                            |
| Phase fit         | Can influence a real behavior phase.                     |
| Local consistency | Fits the framework/project conventions.                  |
| Cost              | Avoids excessive token/runtime burden.                   |
| Conflict risk     | Avoids contradictory controls or unnecessary complexity. |
| Redundancy        | Avoids selecting many near-duplicate policies.           |

Recommended starting strategy:

```text
transparent hybrid selector
  hard-include severe explicit triggers
  hard-exclude wrong-domain or unenforceable policies
  retrieve for recall
  expand small graph neighborhoods
  rank by score
  apply diversity/coverage constraints
  output 3-8 policy objects for most tasks
```

Rationale:

- Rule-only selection may miss subtle risks.
- Retrieval-only selection may be noisy.
- LLM-only selection is hard to audit.
- Full RL is premature before reliable labels and outcomes exist.

### Phase Distributor

The distributor converts policies into behavior-phase obligations.

Each phase binding should contain:

```ts
type PhaseBinding = {
  policyId: string;
  phase: string;
  instruction: string;
  requiredEvidence: string[];
  blockingLevel: 'advisory' | 'required' | 'fail_closed';
  triggerCondition?: string;
};
```

Blocking levels:

| Level         | Meaning                                                             |
| ------------- | ------------------------------------------------------------------- |
| `advisory`    | Prompt guidance; useful but not required to continue.               |
| `required`    | Must produce evidence before phase completion.                      |
| `fail_closed` | Missing evidence blocks or stops the run. Used for high-risk cases. |

### Tool Broker

The AI-agent security expert emphasized tool brokering.

The harness should classify tool calls by risk:

- read;
- write;
- dependency install;
- network;
- secret access;
- process control;
- git mutation;
- destructive filesystem action;
- credential creation;
- service startup;
- privileged operation.

The broker should return:

```text
allow | deny | require_evidence | escalate
```

Examples:

- Installing a known locked dependency may be allowed.
- Fetching unpinned code from the network may require evidence or denial.
- Generating credentials should be denied unless explicitly requested.
- Starting a service exposed on a public interface should require runtime
  exposure policy satisfaction.

Rationale:

- Prompt-level policy cannot reliably prevent tool misuse.
- Tool calls are the moment where unsafe behavior becomes real.

### Evidence Ledger

The evidence ledger is central.

For every selected policy:

```text
policy_id
selected_because
required_controls
forbidden_workarounds
inspection_evidence
implementation_evidence
validation_evidence
runtime_probe_evidence
final_report_claims
status: pass | fail | unknown | blocked
```

No final report should claim compliance unless the evidence ledger has
supporting evidence.

Design choice:

```text
No evidence means no claim.
```

Rationale:

- Final messages are not evidence.
- Evidence must come from harness-collected logs, diffs, commands, tests, and
  probes.

## Dynamic Policy Adoption

The ML expert and AI-agent security expert both emphasized that policies should
be updated during the trajectory.

Initial selection is not enough because risks emerge as code changes.

### Dynamic Triggers

| Trigger                                 | Policy action                                               |
| --------------------------------------- | ----------------------------------------------------------- |
| New dependency added                    | Add supply-chain/dependency policy.                         |
| Shell/process execution appears         | Add command-injection and environment-control policy.       |
| File path handling appears              | Add path traversal and file-permission policy.              |
| Deserialization/parser appears          | Add safe parser and resource-limit policy.                  |
| Service starts or port binds            | Add runtime exposure and access-control probing policy.     |
| Auth/session code touched               | Add authentication/session/access-control policies.         |
| Database query appears                  | Add SQL injection and transaction/least-privilege policies. |
| Missing trust input discovered          | Add fail-safe/blocking policy.                              |
| Agent proposes shortcut                 | Activate anti-shortcut policy and repair guardrails.        |
| Build passes but no tests exist         | Activate test-generation policy.                            |
| Runtime service exists but no probe ran | Activate runtime-probing policy.                            |
| Final report begins without evidence    | Require evidence table and residual-risk report.            |

### Controller Model

```text
Phase Detector
  -> Evidence Tracker
  -> Missing Obligation Detector
  -> Policy Delta Calculator
  -> Intervention Selector
  -> Prompt/Tool/Workflow Action
```

Policy deltas should be logged:

```text
new_surface_detected
new_policy_added
phase_binding_added
evidence_required
blocking_level
selector_rationale
```

Rationale:

- The system needs to explain why guidance changed.
- Later ML training needs selection propensities and policy deltas.

## ML / Decision Methodology

The ML expert proposed a staged approach.

### Stage 1: Transparent Hybrid Selector

Use rules, retrieval, graph expansion, and LLM-assisted extraction.

Candidate score:

```text
candidate_score =
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

This is the right first version because it is auditable and does not require a
large labeled dataset.

### Stage 2: Supervised Ranking

Train after human-labeled data exists.

Labels:

- essential policy;
- useful optional policy;
- irrelevant policy;
- missing critical policy.

Features:

- semantic similarity;
- risk tag overlap;
- graph distance;
- language/framework match;
- historical outcome lift;
- phase coverage;
- policy cost;
- evidence success history.

Candidate models:

- logistic/ordinal model for small data;
- gradient-boosted trees for interpretability;
- cross-encoder reranker later if enough data exists.

### Stage 3: Constrained Contextual Bandit

Use only after reliable trajectory and outcome labels exist.

```text
context = task features + early trajectory features
action = selected policy bundle + phase distribution profile
reward = correctness + security + evidence - cost - overload
```

Recommended algorithms:

- Thompson sampling;
- LinUCB;
- offline policy evaluation before deployment.

Do not use unconstrained RL early.

Rationale:

- Rewards are sparse and noisy.
- Unsafe exploration is unacceptable.
- The policy action space must be constrained to safe policy bundles.

### Reward Design

Composite reward:

```text
R =
  functional_pass
  + security_pass
  - critical_vulnerability
  - false_completion
  + required_evidence_completion
  + adversarial_tests_run
  - runtime_cost
  - principle_overload
```

Hard constraints must come before reward optimization:

- never reward insecure workaround success;
- never trade mandatory trust-boundary controls for lower cost;
- never let functional pass override critical security failure.

## Policy Plugin Model

The method should be extensible across task families.

### Shared Surface Vocabulary

Every plugin should speak the same basic vocabulary:

- input channels;
- dangerous sinks;
- assets;
- trust boundaries;
- runtime exposure;
- dependency events;
- environment constraints;
- expected validators;
- policy evidence.

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

Plugin file layout:

```text
plugin.json
policies.json
triggers.json
phase-bindings.json
validators/
probes/
prompt-templates/
examples/
```

### Plugin Families

| Plugin family           | Examples                                                          |
| ----------------------- | ----------------------------------------------------------------- |
| File/parser security    | path traversal, safe parser, file permissions, error leakage      |
| Web API security        | input validation, authz, output encoding, rate/size limits        |
| Database security       | SQL injection, transaction safety, migration safety               |
| Environment setup       | least privilege, host authenticity, secrets, service hardening    |
| Dependency/supply-chain | pinning, provenance, lockfile integrity, network control          |
| Agent-process security  | prompt injection, tool misuse, evidence spoofing, autonomy limits |

Design choice:

```text
Plugins can add stricter controls but must not silently disable core policies.
```

Rationale:

- Extensibility should not create policy bypass.
- Plugin behavior must be auditable and versioned.

## Cross-Task Adaptation

The method should support different task families without redesigning the
system.

### Task-Family Priors

| Task family           | Policy priors                                                                            |
| --------------------- | ---------------------------------------------------------------------------------------- |
| File/parser task      | input validation, path traversal, safe parsing, error disclosure                         |
| Backend API           | input validation, authn/authz, output encoding, size/rate limits, runtime probing        |
| Database feature      | parameterized queries, transaction integrity, least privilege, migration safety          |
| Auth/session feature  | secure token handling, session rotation, cookie flags, access control                    |
| Environment setup     | least privilege, trusted endpoints, secrets, host-key verification, fail-safe activation |
| Dependency-heavy task | reproducible install, version pinning, package provenance, sandbox-safe build            |
| Agent/tooling task    | prompt injection, tool authorization, audit logging, unsafe autonomy controls            |

### Hierarchical Selector

The ML expert proposed:

```text
global selector
  -> task-family adapter
  -> language/framework adapter
  -> trajectory-state adapter
```

Rationale:

- A single global selector may underfit domain-specific risks.
- Separate per-task selectors will not have enough data.
- Hierarchical adaptation balances transfer and specialization.

## Evaluation Methodology

The empirical evaluation expert proposed the unit of experiment:

```text
task x agent/provider x policy condition x run replicate
```

Control:

- identical workspace;
- pinned model/provider version;
- fixed tool permissions;
- container/worktree isolation;
- full trajectory logging.

### Experimental Conditions

| Condition                                        | Purpose                              |
| ------------------------------------------------ | ------------------------------------ |
| Baseline direct agent, no safety prompt          | Observe ordinary behavior.           |
| Generic security reminder                        | Test broad security nudge.           |
| Full flat policy dump                            | Test whether more policy text helps. |
| Retrieved relevant policies, injected once       | Test selection without distribution. |
| Retrieved policies distributed by behavior phase | Test phase distribution.             |
| Graph/dependency-aware policy selection          | Test GRASP-like structure.           |
| Dynamic phase-distributed controller             | Test full trajectory control.        |
| Human-selected policy oracle                     | Upper-bound comparison.              |

### Ablations

- no policy selection, only workflow phases;
- policy selection without phase distribution;
- phase distribution without enforced validation nodes;
- validation nodes without policy-specific adversarial tests;
- static policy list vs retrieved compact set;
- graph-aware policy selection vs flat retrieval;
- final-report evidence requirement removed;
- dynamic policy selection disabled after initial prompt;
- human-selected policy oracle vs automatic selector.

### Trajectory Metrics

Use the BaxBench behavior taxonomy.

Metrics:

- phase coverage;
- phase order;
- time-to-risk-recognition;
- policy-to-action conversion;
- validation depth;
- unsafe adaptation rate;
- evidence quality;
- behavior transition shifts;
- frequency of `verification_test` and `verification_runtime`;
- frequency and specificity of `defensive_coding`;
- repeated failure loop count.

Normalize by:

- task;
- number of substantive events;
- token budget;
- wall time;
- model/provider.

### Outcome Metrics

Correctness:

- public/hidden benchmark tests;
- generated regression tests;
- task-spec behavioral checks;
- patch minimality and integration quality.

Security:

- CWE-specific exploit tests;
- policy control coverage matrix;
- static scanners where useful;
- manual secure-code review for sampled tasks;
- negative/adversarial tests tied to selected policies;
- fail-safe behavior on underspecified high-risk tasks.

Important rule:

```text
Security-looking behavior is not security success.
```

The trajectory label `defensive_coding` means the agent did something
security-relevant. It does not prove the final artifact is secure.

### Human Annotation

Sample trajectories for expert annotation.

Annotators should label:

- risk identification quality;
- policy relevance;
- whether each policy produced concrete behavior;
- insecure adaptation incidents;
- final claim evidence support;
- residual vulnerabilities.

Use double annotation, adjudication, and inter-rater agreement.

### Proving the Method Works

The claim should be statistical, not anecdotal:

- improve correctness/security over baselines;
- show trajectory changes mediate outcome changes;
- show gains across held-out task families and providers;
- show lower policy overload than flat dumps;
- report failure modes honestly.

## Key Design Choices and Rationales

### 1. Use "Policy" as the Operational Unit

Rationale:

Principles are useful for humans, but the harness needs executable objects:
triggers, validators, phase bindings, and evidence requirements.

### 2. Keep Policy State Outside the LLM

Rationale:

Prompt-only rules can be ignored, forgotten, rationalized away, or overridden
by task/repo/prompt-injection content. The harness must own policy state.

### 3. Select Compact Policies

Rationale:

Full-corpus injection causes overload and cost. Compact selected policies are
more likely to be followed and easier to validate.

### 4. Bind Policies to Behavior Phases

Rationale:

The same policy means different things during inspection, planning,
implementation, validation, repair, and reporting. Phase binding turns policy
text into behavior control.

### 5. Make Evidence First-Class

Rationale:

Final reports are not evidence. Evidence must come from logs, diffs, commands,
tests, probes, and file inspection.

### 6. Dynamically Adopt Policies

Rationale:

Risks emerge during implementation. New dependencies, sinks, services, or
workarounds should trigger new policies and validation requirements.

### 7. Fail Closed on Missing Trust Inputs

Rationale:

The autossh comparison showed that agents can satisfy benchmarks by inventing
unsafe infrastructure. For high-risk tasks, missing trust inputs should produce
`BLOCKED_INPUT_REQUIRED`, not fabricated credentials or disabled verification.

### 8. Broker High-Risk Tools

Rationale:

Security failures often become real through tools: package installs, network
calls, service starts, credential generation, filesystem deletion, or process
control. The harness should authorize risky tool use through policy.

### 9. Treat Runtime Probes as First-Class

Rationale:

BaxBench trajectories show tests and runtime probes are rare. Backend and
environment tasks often fail securely or insecurely only at runtime.

### 10. Evaluate Trajectory and Outcome Together

Rationale:

The research contribution is not just a better final pass rate. It is showing
that policy guidance changes agent behavior in ways that explain improved
correctness and security.

## Recommended Next Implementation Plan

### Phase 1: Define Schemas

Create draft schemas for:

- `PolicyRecord`;
- `TaskSurface`;
- `PolicyCandidate`;
- `SelectedPolicySet`;
- `PhaseBinding`;
- `EvidenceLedger`;
- `PolicyValidationResult`;
- `TrajectoryIntervention`.

### Phase 2: Build a Small Policy Registry

Start with 20-40 high-value policies from:

- input validation;
- file management;
- error handling/logging;
- access control;
- command execution;
- dependency/supply-chain;
- environment setup.

Each policy should include triggers, phase bindings, and at least one
validator/evidence expectation.

### Phase 3: Build a Transparent Selector

Implement:

- rule-trigger matching;
- retrieval over policy text;
- small GRASP graph expansion;
- scoring and diversity constraints;
- selection rationale logging.

### Phase 4: Build Phase Distributor

Generate:

- inspection checklist;
- planning constraints;
- implementation guardrails;
- adversarial test requirements;
- runtime/static probe requirements;
- repair invariants;
- final evidence table.

### Phase 5: Prototype Harness Workflow

Create a workflow with nodes:

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

### Phase 6: Evaluate on Small Task Set

Use 10-20 tasks first:

- file/parser tasks;
- web API tasks;
- dependency/setup tasks;
- one or two known SecurityDebt-style risky setup tasks.

Compare:

- baseline;
- generic reminder;
- selected policies;
- phase-distributed policies;
- dynamic controller.

### Phase 7: Scale to BaxBench

Apply to a BaxBench slice with matched task batches and trajectory labeling.

## Open Design Questions

1. What is the right default top-k policy budget per task?
2. When should a policy be `advisory`, `required`, or `fail_closed`?
3. How much dynamic policy adoption should happen before the agent experiences
   overload?
4. Which validators should be deterministic, and where is LLM review acceptable?
5. How should the system handle conflict between functional task requirements
   and security policies?
6. What is the minimum human annotation set needed to train/evaluate a selector?
7. How should policy plugins be versioned and trusted?
8. How should the harness avoid overfitting to BaxBench while still using
   BaxBench trajectory data?

## Bottom Line

The five-agent discussion supports a clear methodology:

```text
Use policies as executable harness controls.
Select compact policies from task and trajectory evidence.
Distribute them across real coding-agent behavior phases.
Enforce them through tool brokering, validation, probes, and evidence ledgers.
Dynamically adopt stricter policies when new risks appear.
Evaluate both trajectory changes and final correctness/security outcomes.
```

This is substantially stronger than a secure-coding prompt. It is a design for
a policy-aware agent harness that can be extended across task families and
studied empirically.
