# Agent 3 Proposal: ML Policy Selection and Dynamic Adoption

Date: 2026-07-09

Role: Machine Learning Expert

Assigned focus: automatic policy selection and dynamic adoption for
principle-guided coding agents.

## Executive Summary

The core ML problem is not "which security reminder should we paste into a
prompt?" It is a sequential decision problem under safety constraints:

```text
Given a task, codebase, environment, policy registry, and partial trajectory,
select a compact policy bundle, bind it to behavior phases, update it when new
risk surfaces appear, and optimize for correctness, security, evidence, and
cost without allowing unsafe exploration.
```

The immediate system should be a transparent hybrid selector, not an end-to-end
RL agent. It should combine deterministic safety rules, sparse/dense retrieval,
graph expansion, LLM-assisted structured extraction, and an interpretable
ranking layer. Learned ranking should be added after there are human labels and
outcome labels. Contextual bandits or RL should only be used later, behind hard
safety constraints and offline policy evaluation.

The strongest design is:

```text
task/context features
  -> surface extraction
  -> high-recall candidate generation
  -> constrained policy ranking
  -> phase distribution
  -> trajectory monitoring
  -> dynamic policy adoption
  -> evidence-aware validation
  -> logged training examples for future learning
```

This proposal treats policies as executable harness objects derived from
principles. The LLM receives only phase-specific slices; the harness owns
selection, policy state, phase obligations, evidence requirements, uncertainty,
and intervention decisions.

## Research Position

The BaxBench trajectory summary shows that baseline coding agents already do a
lot of inspection, build verification, failure diagnosis, and refinement. They
rarely run tests or runtime probes. The observed counts make the ML target
clear:

- Use selection to make security guidance specific instead of generic.
- Use phase distribution to move policy influence into the phases that already
  occur frequently.
- Use dynamic adoption to catch risks that were not visible in the initial
  prompt.
- Use reward and evaluation metrics that distinguish security-looking behavior
  from actual security success.

The selector should optimize for a compact set of high-value policies. Too many
policies create prompt overload and reduce enforceability. Too few policies
miss task-specific risks. The optimization target is therefore not top-k
semantic similarity; it is constrained coverage of the task's risk surface.

## Policy Representation

Each policy should be represented as an operational record, not just prose.
This record is the unit selected by ML models and enforced by the harness.

```ts
type PolicyRecord = {
  id: string;
  version: string;
  sourcePrinciples: Array<{
    source: 'owasp-scp' | 'grasp' | 'setup-environment' | 'project' | 'cwe' | 'other';
    sourceId?: string;
    text: string;
  }>;
  title: string;
  normativeText: string;
  riskTags: string[];
  cweTags: string[];
  taskTriggers: string[];
  languageFrameworkHints: string[];
  inputChannels: string[];
  dangerousSinks: string[];
  assetTags: string[];
  trustBoundaryTags: string[];
  dependencyTags: string[];
  environmentTags: string[];
  graphLinks: Array<{
    targetPolicyId: string;
    relation: 'parent' | 'child' | 'requires' | 'supports' | 'conflicts' | 'near_duplicate';
    weight: number;
  }>;
  phaseBindings: PhasePolicyTemplate[];
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

Key representation choices:

1. Policy identity must be stable and versioned. If policy wording or evidence
   requirements change, evaluations need to know which version was used.
2. Source principles should be preserved for auditability, but model selection
   should operate on normalized policy metadata.
3. Policies need graph links. Some controls are prerequisites, some are
   alternatives, and some are near duplicates that should not all be selected.
4. Enforceability must be explicit. A critical but non-testable policy may
   still be selected, but the harness should not pretend it has been verified.
5. Forbidden workarounds are part of the policy. This is important during
   failure diagnosis and adaptation.

## Phase Binding Representation

The same policy should not be rendered the same way in every phase. Each policy
should contain phase templates that can be activated conditionally.

```ts
type PhasePolicyTemplate = {
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
  applicabilityCondition?: string;
  instructionTemplate: string;
  requiredEvidence: string[];
  validatorRefs: string[];
  blockingLevel: 'advisory' | 'required' | 'fail_closed';
  reminderCadence: 'once' | 'on_phase_entry' | 'on_failure' | 'until_evidence';
};
```

The `reminderCadence` field matters because repetition has a cost. A high-risk
policy such as "do not disable host-key verification" should persist through
repair loops. A lower-risk documentation policy may be shown once at planning
or reporting.

## Task and Trajectory Features

Policy selection should use both initial task features and trajectory features.
Initial selection handles known risks. Dynamic adoption handles risks that
emerge after the agent starts inspecting or editing code.

### Initial Task Surface Features

The task surface extractor should produce a structured `TaskSurface`:

```ts
type TaskSurface = {
  taskFamily:
    | 'backend_api'
    | 'file_parser'
    | 'database_feature'
    | 'auth_session'
    | 'environment_setup'
    | 'dependency_setup'
    | 'cli_tool'
    | 'agent_tooling'
    | 'unknown';
  languages: string[];
  frameworks: string[];
  inputChannels: string[];
  outputContexts: string[];
  dangerousSinks: string[];
  assets: string[];
  trustBoundaries: string[];
  dependencies: string[];
  runtimeExposure: {
    service: boolean;
    ports: number[];
    publicBindLikely: boolean;
    longRunningProcess: boolean;
  };
  environmentConstraints: string[];
  cweHints: string[];
  missingTrustInputs: string[];
  existingTests: string[];
  existingSecurityControls: string[];
  uncertainty: Record<string, number>;
};
```

Important feature groups:

- Lexical and semantic task text features: endpoints, verbs, assets, file
  names, framework names, API specification fields, BaxBench CWE hints.
- Codebase scan features: package manifests, route files, auth middleware,
  query construction, subprocess use, file access, serializers, parsers.
- Environment features: sandbox limits, missing binaries, ports, network
  access, root/non-root state, Docker/systemd/supervisor presence.
- Project convention features: existing validation style, framework idioms,
  test framework, dependency manager, logging conventions.

### Trajectory Features

Dynamic adoption needs event-level features from the behavior taxonomy:

```ts
type TrajectoryState = {
  currentPhase: string;
  phaseHistory: string[];
  secondaryAttributesSeen: string[];
  filesRead: string[];
  filesModified: string[];
  commandsRun: Array<{
    commandClass: string;
    exitCode: number;
    failed: boolean;
    riskTags: string[];
  }>;
  newSurfaces: SurfaceSignal[];
  selectedPolicyIds: string[];
  evidenceStatusByPolicy: Record<string, 'missing' | 'partial' | 'pass' | 'fail' | 'blocked'>;
  repeatedFailureLoopCount: number;
  unsafeShortcutSignals: string[];
  finalReportStarted: boolean;
};
```

Useful dynamic signals include:

- New dependency added or package manifest edited.
- Shell/process execution introduced.
- File path construction or parser use introduced.
- Deserialization, template rendering, SQL, or network calls introduced.
- Service start, port binding, or runtime probing attempted.
- Auth/session/access-control code touched.
- Agent proposes skipping tests, disabling validation, relaxing TLS, running as
  root, using broad file permissions, or inventing credentials.
- Final reporting begins while required evidence is missing.

These signals are more reliable when derived from tool logs and diffs than when
derived from the agent's own summary.

## Candidate Generation

Candidate generation should favor recall. Ranking and constraints can remove
noise later. I recommend five candidate sources.

### 1. Deterministic Rule Triggers

Rules should hard-include policies for high-precision, high-severity surfaces.

Examples:

| Surface signal                              | Candidate policy                                        |
| ------------------------------------------- | ------------------------------------------------------- |
| untrusted file path + filesystem read/write | path traversal prevention                               |
| SQL query construction                      | parameterized queries and query boundary validation     |
| subprocess or shell command                 | command injection prevention and environment control    |
| persistent service or tunnel                | least privilege, trusted endpoint, fail-safe activation |
| missing remote trust input                  | fail closed rather than invent credentials              |
| auth/session files touched                  | authentication/session/access-control controls          |
| dependency added                            | pinning/provenance/lockfile integrity policy            |

These rules should produce rationales such as:

```json
{
  "policyId": "POLICY-FILE-PATH-TRAVERSAL",
  "source": "rule_trigger",
  "trigger": "detected untrusted filename parameter used with filesystem sink",
  "confidence": 0.93
}
```

### 2. Sparse and Dense Retrieval

Retrieval should run over normalized policy text, risk tags, source principles,
examples, and phase instructions.

Use both:

- sparse retrieval for exact terms like "SQL", "host key", "pickle", "cookie";
- dense retrieval for semantic matches like "user-provided filename" to
  "path traversal".

The retrieval query should include the task prompt, extracted surface summary,
framework, detected sinks, and known CWE hints. It should not include long raw
files unless compressed into structured features.

### 3. Graph Expansion

The GRASP graph and policy graph should be used for local expansion from seed
policies. Expansion should be shallow and typed:

- include required prerequisites;
- include direct children when the seed is too broad;
- include parent categories for explanation, not necessarily selection;
- suppress near duplicates;
- flag conflicts.

For example, "filesystem sink" may retrieve a broad file management policy.
Graph expansion should add specific path traversal, safe parser, permission,
and error disclosure policies, then the ranker should choose the compact subset
that covers the detected task surface.

### 4. LLM-Assisted Structured Extraction

The LLM should not be the sole selector. It should help extract messy surfaces
and propose missing candidates in a structured format. The harness should
validate its output against known policy IDs and feature schemas.

Good use:

```text
"Given this task and code scan, list untrusted inputs, dangerous sinks, assets,
and missing trust inputs. Return only schema-valid JSON."
```

Risky use:

```text
"Choose the policies and decide whether they passed."
```

The LLM can propose candidate IDs with rationales, but ranking and enforcement
must remain harness-owned.

### 5. Historical Similarity

Once the project has enough runs, retrieve prior tasks with similar surfaces:

- same task family and framework;
- similar input/sink/asset structure;
- similar CWE hints;
- similar trajectory failures.

Historical candidates should be weighted by observed outcome lift, not just
frequency. If a policy was often selected but rarely produced evidence or
security improvement, it should not be over-prioritized.

## Ranking and Selection

The first selector should be a transparent scoring and constrained optimization
system.

### Candidate Score

Use an additive score with calibrated components:

```text
score(policy, context) =
  w_rule * rule_trigger_score
  + w_sparse * sparse_retrieval_score
  + w_dense * dense_retrieval_score
  + w_graph * graph_proximity_score
  + w_tag * risk_tag_overlap
  + w_cwe * cwe_match
  + w_framework * language_framework_match
  + w_severity * severity_score
  + w_enforce * enforceability_score
  + w_phase * phase_fit_score
  + w_history * historical_lift
  - w_cost * expected_cost
  - w_conflict * conflict_penalty
  - w_redundancy * redundancy_penalty
```

The output should include the score breakdown. This makes the system debuggable
and produces training data for later supervised models.

### Selection as Constrained Coverage

Top-k ranking alone is insufficient because near-duplicate input-validation
policies can crowd out a missing runtime or dependency policy. Use constrained
coverage:

```text
maximize:
  sum(selected policy utility)
  + coverage(task risk surfaces)
  + coverage(required phases)
  - redundancy
  - total cost

subject to:
  selected_count between min_k and max_k
  all critical hard-trigger policies included
  no unresolved conflicts
  at least one enforceable policy for each high-severity risk surface
  prompt/runtime budget not exceeded
```

For most coding tasks, the target should be 3-8 selected policies. Very small
tasks may need 1-3. High-risk environment or auth tasks may need more, but the
selector should justify every extra policy by coverage or severity.

### Selection Output

The selector should emit a `SelectedPolicySet`:

```ts
type SelectedPolicySet = {
  runId: string;
  selectorVersion: string;
  taskSurfaceHash: string;
  selected: Array<{
    policyId: string;
    score: number;
    selectionReason: string;
    triggeredBy: string[];
    expectedRiskSurfaceCoverage: string[];
    expectedPhaseCoverage: string[];
    blockingLevel: 'advisory' | 'required' | 'fail_closed';
  }>;
  rejectedHighScoringCandidates: Array<{
    policyId: string;
    reason: 'duplicate' | 'wrong_domain' | 'too_costly' | 'conflict' | 'low_enforceability';
  }>;
  uncertainty: {
    overall: number;
    missingSurfaceRisk: number;
    selectorConfidence: number;
  };
};
```

Rejected candidates are important. They support audit, later human review, and
offline policy evaluation.

## Dynamic Policy Adoption

Initial selection should be treated as provisional. Code-generation tasks are
partially observable: the initial task prompt rarely reveals all sinks, hidden
framework behavior, dependency constraints, or environment failures.

### Adoption Loop

The dynamic controller should run at phase boundaries and after high-risk
events:

```text
observe trajectory event
  -> update surface state
  -> update evidence ledger
  -> detect new risks or missing obligations
  -> generate candidate policy deltas
  -> rank/admit deltas under constraints
  -> update phase bindings and prompt/tool controls
  -> log intervention and rationale
```

Policy state should be monotonic within a run:

- Policies may be added.
- Blocking levels may be strengthened.
- Evidence requirements may be added when new surfaces appear.
- Policies may be marked irrelevant only with explicit, logged evidence.
- The agent should not be allowed to relax a selected policy by argument.

Human or external controller override can relax policy, but that should be a
separate audited action.

### Adoption Actions

Dynamic adoption is not just adding text to the prompt. Actions include:

| Action                   | Use case                                                           |
| ------------------------ | ------------------------------------------------------------------ |
| `add_policy`             | New sink, asset, dependency, or trust boundary appears.            |
| `add_phase_binding`      | Existing policy needs a test, runtime probe, or repair guardrail.  |
| `raise_blocking_level`   | Missing trust input or unsafe workaround appears.                  |
| `request_inspection`     | Surface is uncertain and needs file/line evidence.                 |
| `require_test`           | Build passes but policy-specific behavioral tests are absent.      |
| `require_runtime_probe`  | Service starts or API endpoint exists without live validation.     |
| `deny_tool`              | Tool call would violate policy, such as disabling host-key checks. |
| `interrupt_final_report` | Agent is reporting success without required evidence.              |

### Dynamic Trigger Examples

| Trigger                                               | Adoption decision                                                                                |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Agent edits `package.json` or lockfile                | Add dependency integrity policy and build reproducibility evidence.                              |
| Agent introduces `subprocess(..., shell=True)`        | Add command-injection policy, block unsafe shell invocation, require argument-array remediation. |
| Agent reads a user-provided path                      | Add path traversal and file disclosure policies, require negative tests.                         |
| Agent starts HTTP server                              | Add runtime exposure policy, require local endpoint probe and bind-address check.                |
| Agent sees missing SSH host/user/key                  | Add fail-safe missing-trust-input policy, block invented credentials.                            |
| Agent skips tests due to environment issue            | Add adaptation guardrail, require alternative evidence rather than false success.                |
| Agent begins final answer with missing ledger entries | Require evidence table and residual-risk disclosure.                                             |

## Uncertainty Handling

Uncertainty is central because policy selection errors have asymmetric costs.
Missing a critical security policy is worse than selecting one extra advisory
policy. However, over-selection can reduce correctness and increase cost.

### Types of Uncertainty

| Uncertainty type             | Example                                                  | Response                                                               |
| ---------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------- |
| Surface uncertainty          | Unsure whether a filename is user-controlled.            | Ask inspection phase to locate caller/input source.                    |
| Policy relevance uncertainty | Path policy may or may not apply.                        | Select as advisory until sink/input link is confirmed.                 |
| Evidence uncertainty         | Agent claims validation but no test or diff supports it. | Mark unknown; do not allow success claim.                              |
| Environment uncertainty      | Runtime probe failed due to sandbox, not code.           | Require residual-risk disclosure and alternative static/test evidence. |
| Model uncertainty            | Ranker confidence is low or candidates disagree.         | Escalate to high-recall conservative selection.                        |

### Calibration

Every selector score should be calibrated against human labels:

- probability policy is essential;
- probability policy is useful optional;
- probability policy is irrelevant;
- probability task contains an unseen critical risk.

Calibration should be tracked with reliability diagrams and expected
calibration error after enough labeled tasks exist. Before enough labels exist,
confidence values should be treated as heuristic and should not be overclaimed.

### Abstention and Fail-Closed Rules

The selector should abstain or fail closed when:

- high-risk environment setup lacks trust inputs;
- credential, tunnel, authentication, or public exposure decisions are
  underspecified;
- no enforceable policy can cover a detected critical sink;
- the final artifact cannot be validated but would expose security-sensitive
  behavior.

Abstention is a valid output:

```text
BLOCKED_INPUT_REQUIRED: remote host identity and known-host verification data
are required before activating the tunnel.
```

This is preferable to fabricating safe-looking but unsafe infrastructure.

## Supervised Ranking

Supervised ranking should be introduced after collecting labeled examples from
the transparent selector.

### Labels

Human reviewers should label candidate policies per task:

- `essential`: should be selected; missing it is a serious selection failure.
- `useful`: helpful but not mandatory.
- `irrelevant`: should not be selected.
- `harmful`: likely to distract, conflict, or over-constrain.
- `missing_critical`: policy absent from candidate set but needed.

Additional phase labels:

- phase binding useful;
- phase binding unnecessary;
- evidence requirement appropriate;
- evidence requirement too costly;
- blocking level too weak or too strong.

### Training Examples

Each training example should preserve:

- task surface features;
- candidate policy features;
- retrieval/rule/graph score components;
- selected and rejected candidates;
- phase bindings;
- dynamic policy deltas;
- model/provider;
- final outcomes;
- human judgments.

The selector must log propensities or score distributions from the beginning so
future offline evaluation is possible.

### Model Choices

Start simple:

1. Ordinal logistic regression or calibrated one-vs-rest classifiers for small
   data.
2. Gradient-boosted trees for non-linear feature interactions and
   interpretability.
3. Pairwise/listwise learning-to-rank once there are enough labeled candidate
   sets.
4. Cross-encoder reranker only after the registry and labels are stable.

The learned model should rerank candidates, not bypass hard rules. Hard
security triggers remain mandatory.

### Features for Ranking

Useful model features:

- task-family and policy-category match;
- risk tag overlap;
- input-channel/sink/asset overlap;
- CWE tag match;
- language/framework compatibility;
- graph distance from triggered seed nodes;
- retrieval scores;
- historical policy outcome lift;
- evidence completion rate for the policy;
- average implementation cost;
- conflict/duplicate indicators;
- phase coverage;
- selector disagreement between rule, retrieval, graph, and LLM proposal.

### Evaluation of Ranker

Ranker metrics:

- recall@k for essential policies;
- precision@k for selected policies;
- mean reciprocal rank of first essential policy;
- coverage of high-severity surfaces;
- missing critical policy rate;
- average selected policy count;
- human-rated overload;
- calibration error.

Because security misses are asymmetric, recall of essential policies should be
weighted more heavily than raw precision.

## Contextual Bandits and RL Constraints

Bandits or RL should not be the first implementation. They become appropriate
only after the project has:

- stable policy registry;
- trajectory labels;
- independent correctness/security outcomes;
- logged selection propensities;
- enough repeated or comparable tasks;
- hard constraints that prevent unsafe exploration.

### Bandit Formulation

```text
context:
  task surface + codebase features + early trajectory state + provider/model

action:
  selected policy bundle + phase distribution profile + intervention cadence

reward:
  correctness + security + evidence completion - cost - overload
```

The action space must be constrained to safe bundles. The bandit should choose
among vetted policy bundles or distribution profiles, not arbitrary policy
subsets.

Recommended algorithms:

- LinUCB for interpretable linear uncertainty.
- Thompson sampling over a calibrated reward model.
- Conservative contextual bandits with baseline constraints.
- Offline doubly robust evaluation before online deployment.

### RL Formulation

Full RL would treat policy adoption as a sequential decision problem:

```text
state_t = task surface + phase + trajectory + evidence ledger
action_t = add/remind/block/request-evidence/allow
reward_t = evidence progress + validation success - cost - unsafe behavior
```

This is attractive but risky. Rewards are delayed, sparse, and confounded by
model/provider behavior. Unsafe exploration is unacceptable. If RL is used, it
should be offline or conservative, with hard-coded constraints for critical
security policies.

### Hard Constraints Before Reward

The optimizer must never learn to trade away:

- validation at untrusted trust boundaries;
- authentication/authorization controls required by task semantics;
- host authenticity for remote access;
- secret safety;
- evidence requirements for final claims;
- fail-safe behavior when trust inputs are missing.

These are constraints, not reward terms.

## Reward Design

Reward should be multi-objective and evidence-aware:

```text
R =
  + functional_pass
  + security_pass
  + policy_evidence_completion
  + adversarial_tests_run
  + runtime_probe_success_when_relevant
  + validated_fail_safe_block_when_required
  - critical_vulnerability
  - false_completion_claim
  - insecure_adaptation
  - policy_overload
  - unnecessary_runtime_cost
  - correctness_regression
```

Important reward principles:

1. Functional success cannot compensate for critical security failure.
2. Security-looking code cannot receive full reward without independent
   evidence.
3. Blocking unsafe completion can be a positive outcome when the task is
   underspecified.
4. Runtime and token costs matter, but only after safety constraints are met.
5. Repair loops should be penalized only when they are unproductive or weaken
   controls; productive diagnosis should not be discouraged.

Reward should be decomposed for analysis:

- task correctness reward;
- policy compliance reward;
- evidence reward;
- trajectory quality reward;
- cost penalty;
- unsafe behavior penalty.

This decomposition helps determine whether a selector improves final outcomes
through better trajectory behavior or merely adds overhead.

## Phase Distribution Learning

Phase distribution can be modeled as a policy-phase matrix:

```text
D[policy_id, phase] -> obligation strength and reminder cadence
```

Initial values should come from expert-authored templates. Later, the system
can learn refinements from trajectories.

### Phase Distribution Objectives

For each selected policy, decide:

- which phases should receive it;
- whether the binding is advisory, required, or fail-closed;
- what evidence is expected in that phase;
- whether the binding should persist through repair loops;
- when to stop reminding because evidence is complete.

### Learning Signals

Useful labels and outcomes:

- policy was selected but never acted on;
- policy produced inspection evidence;
- policy produced implementation changes;
- policy produced tests/probes;
- repair loop preserved or weakened the policy;
- final report claim was supported or unsupported;
- policy binding caused overload or irrelevant work.

### Practical Distribution Heuristics

Initial heuristics should be strong:

- Input and sink policies need inspection, planning, implementation,
  verification_test, repair, and reporting bindings.
- Environment trust policies need orientation, inspection, planning,
  implementation, runtime/static verification, adaptation, and reporting.
- Dependency policies need inspection, implementation, verification_build,
  adaptation, and reporting.
- Runtime exposure policies need planning, implementation,
  verification_runtime, adaptation, and reporting.
- Evidence/reporting policies bind mostly to final_reporting, but should
  interrupt earlier if the agent starts claiming success prematurely.

The system should measure whether a phase binding changes behavior. A binding
that is repeatedly shown but never produces action or evidence should be
rewritten, moved to another phase, or removed.

## Cross-Task Adaptation

The selector should be hierarchical:

```text
global selector
  -> task-family adapter
  -> language/framework adapter
  -> trajectory-state adapter
```

### Global Selector

The global selector learns cross-cutting patterns:

- untrusted input to dangerous sink;
- missing trust input;
- dependency change;
- runtime exposure;
- final claims requiring evidence.

These transfer across languages and task families.

### Task-Family Adapter

Task-family priors specialize selection:

| Task family       | Policy priors                                                                        |
| ----------------- | ------------------------------------------------------------------------------------ |
| File/parser       | path traversal, safe parsing, file permissions, error disclosure, resource limits    |
| Backend API       | input validation, authn/authz, output encoding, size/rate limits, runtime probes     |
| Database feature  | parameterized queries, transaction integrity, migration safety, least privilege      |
| Auth/session      | token handling, cookie flags, session rotation, access control, secret handling      |
| Environment setup | least privilege, host authenticity, secrets, fail-safe activation, service hardening |
| Dependency-heavy  | pinning, provenance, lockfile integrity, reproducible build, sandbox-safe install    |
| Agent/tooling     | prompt injection, tool authorization, evidence spoofing, autonomy limits             |

### Language/Framework Adapter

Language and framework adapters convert generic policies into idiomatic
evidence:

- Django/FastAPI/Express route validation patterns.
- Rails strong parameters and CSRF/session conventions.
- Go `net/http`, Fiber, and Actix request parsing differences.
- SQL driver parameterization idioms.
- Python safe YAML/JSON/parser choices.
- Node package lockfile and script execution risks.

The adapter should affect rendering and validation, not silently remove a core
policy.

### Trajectory-State Adapter

The trajectory-state adapter handles what the agent actually did:

- If tests are absent, activate test-generation obligations.
- If runtime service exists, activate runtime probing.
- If a workaround appears, activate anti-shortcut guardrails.
- If evidence is complete, stop repeating the same reminder.

This layer makes policy guidance adaptive without losing auditability.

## Data Requirements

The current BaxBench trajectory pipeline is a good starting point, but ML
selection needs richer labels and logged decisions.

### Required Data Artifacts

For each run:

- task prompt and benchmark metadata;
- task surface extraction output;
- codebase scan features;
- candidate policies with all score components;
- selected policies and rejected high-scoring candidates;
- phase distribution plan;
- dynamic policy deltas;
- prompts or prompt slices delivered to the LLM;
- tool calls, command outputs, file edits, and final artifact;
- evidence ledger;
- behavior taxonomy labels;
- correctness/security outcome labels;
- human annotations for a sampled subset.

### Human Annotation

Human labels are needed for:

- whether the task surface extraction is correct;
- whether selected policies are essential/useful/irrelevant/harmful;
- whether any critical policy was missing;
- whether phase bindings were appropriate;
- whether policy evidence is real or merely claimed;
- whether adaptations preserved security constraints;
- whether final residual risk reporting is accurate.

Start with 10-20 tasks across file/parser, backend API, and environment setup.
Then expand to stratified BaxBench slices by framework and CWE hint.

### Counterfactual Data

For selection learning, the system needs to know not only selected policies but
also plausible alternatives. Log the top 20-50 candidate policies per task,
their scores, and why they were rejected. This makes later offline evaluation
and supervised ranking much stronger.

## Evaluation Plan

Evaluation should test selection quality, trajectory effects, and final
outcomes.

### Experimental Conditions

Compare:

1. Baseline BaxBench prompt, no security reminder.
2. Generic security reminder.
3. Specific CWE/risk reminder.
4. Flat policy dump.
5. Selected policies injected once.
6. Selected policies distributed by behavior phase.
7. Dynamic phase-distributed controller.
8. Human-selected policy oracle.

The human oracle is important because it separates "policy guidance cannot
help" from "automatic selector chose poorly."

### Selection Metrics

- essential policy recall;
- selected policy precision;
- missing critical policy rate;
- selected policy count;
- selected policy enforceability;
- risk surface coverage;
- phase coverage;
- token/runtime cost;
- human-rated overload;
- selector calibration.

### Dynamic Adoption Metrics

- new risk surfaces detected;
- time from new surface to policy adoption;
- useful policy delta rate;
- spurious policy delta rate;
- evidence obligations completed after adoption;
- unsafe shortcut interruptions;
- final-report interruptions due to missing evidence.

### Trajectory Metrics

Use the BaxBench taxonomy:

- increased `verification_test` and `verification_runtime` when relevant;
- increased task-specific `defensive_coding`;
- reduced unsupported final reporting;
- fewer insecure adaptation events;
- more policy-linked inspection before implementation;
- more plan-to-test and build-to-test transitions;
- fewer repeated unproductive failure loops.

Normalize by task, provider/model, token budget, wall time, and number of
substantive events.

### Outcome Metrics

Correctness:

- benchmark tests;
- public/hidden tests where available;
- generated regression tests;
- integration quality;
- minimality and maintainability.

Security:

- CWE-specific exploit tests;
- adversarial tests tied to selected policies;
- static checks where useful;
- manual secure-code review for sampled tasks;
- fail-safe behavior for underspecified high-risk tasks;
- final claim evidence support.

Trajectory improvement without outcome improvement is not enough. Outcome
improvement without interpretable trajectory change is weaker evidence for the
research thesis.

### Ablations

Run ablations for:

- no graph expansion;
- no deterministic hard triggers;
- retrieval-only selection;
- LLM-only selection;
- no dynamic adoption;
- no evidence ledger gating;
- no phase distribution;
- no runtime probes;
- no repair guardrails;
- compact top-k vs constrained coverage.

These ablations identify which parts of the selector matter.

## Key Design Choices and Rationales

### 1. Start With a Transparent Hybrid Selector

Rationale: The project does not yet have enough labels for reliable learned
selection. A transparent hybrid gives immediate utility, auditability, and
training data.

### 2. Treat Hard Security Rules as Constraints

Rationale: Optimizers can learn unsafe shortcuts if reward is sparse or
mis-specified. Critical policies must be constraints before they are reward
terms.

### 3. Optimize Coverage, Not Top-k Similarity

Rationale: Semantic similarity over-selects obvious policies and misses
coverage diversity. Security requires covering surfaces, assets, sinks, and
phases.

### 4. Use Dynamic Adoption

Rationale: Risks emerge during implementation. Initial task prompts rarely
expose all dependencies, sinks, services, or workaround behavior.

### 5. Separate Selection From Evidence Acceptance

Rationale: The selector predicts which policies matter. The evidence ledger
determines whether the run satisfied them. These must not collapse into an LLM
self-certification step.

### 6. Log Rejected Candidates

Rationale: Future supervised ranking and offline bandit evaluation need
counterfactual alternatives. Without rejected candidates, the dataset only
records what the first selector happened to choose.

### 7. Prefer Conservative Bandits Over Unconstrained RL

Rationale: The environment is safety-sensitive, rewards are delayed, and
exploration can produce insecure code. Bandits should only choose among vetted
safe bundles.

### 8. Reward Fail-Safe Blocking When Appropriate

Rationale: Some tasks cannot be safely completed without missing trust inputs.
For those, "blocked with evidence" is better than unsafe apparent completion.

## Failure Modes to Watch

1. Policy overload: too many selected policies reduce adherence and correctness.
2. Under-selection: selector misses a critical risk because it relied on prompt
   text rather than code surfaces.
3. Retrieval noise: semantically similar but wrong-domain policies crowd out
   useful controls.
4. Graph drift: graph expansion pulls in broad parent policies but not concrete
   enforceable children.
5. LLM overconfidence: extractor invents surfaces or certifies compliance.
6. Evidence spoofing: final report claims policy satisfaction without logs,
   tests, diffs, or probes.
7. Unsafe adaptation: agent disables a control to pass build/runtime checks.
8. Reward hacking: learned selector favors cheap policies that improve evidence
   metrics without reducing vulnerabilities.
9. Provider overfitting: selector learns behavior specific to one model or CLI.
10. Benchmark overfitting: policies match BaxBench labels but fail on real
    project tasks.

## Implementation Roadmap

### Phase 1: Registry and Feature Schema

- Define `PolicyRecord`, `TaskSurface`, `PolicyCandidate`,
  `SelectedPolicySet`, `PhaseBinding`, `PolicyDelta`, and `EvidenceLedger`.
- Normalize 20-40 high-value policies across input validation, file handling,
  command execution, dependency integrity, runtime exposure, error disclosure,
  and environment setup.
- Add graph links for requires/conflicts/near-duplicates.

### Phase 2: Transparent Selector

- Implement deterministic hard triggers.
- Add sparse and dense retrieval.
- Add shallow graph expansion.
- Score candidates with decomposed features.
- Select with coverage/diversity constraints.
- Emit selection rationales and rejected candidates.

### Phase 3: Dynamic Adoption Controller

- Classify trajectory events into surface signals.
- Detect new sinks, dependencies, services, and unsafe shortcuts.
- Add policy deltas at phase boundaries and high-risk events.
- Update evidence obligations and blocking levels.
- Log intervention timing and rationale.

### Phase 4: Evaluation Harness

- Run matched tasks under baseline, generic reminder, selected-once, phase
  distributed, and dynamic-controller conditions.
- Use the BaxBench behavior taxonomy for trajectory metrics.
- Add independent correctness/security outcome evaluation where available.
- Human-label a stratified sample for selection and evidence quality.

### Phase 5: Learned Ranking

- Train calibrated supervised rankers from human-labeled candidate sets.
- Compare against transparent score-only selection.
- Keep hard triggers and fail-closed rules outside the learned model.

### Phase 6: Conservative Online Adaptation

- Use offline policy evaluation first.
- Allow bandit selection only among safe pre-vetted bundles.
- Monitor missing-critical-policy rate, overload, and security regressions.

## Minimal First Experiment

A strong first experiment can be small:

- 12 tasks total:
  - 4 file/parser tasks;
  - 4 backend API tasks;
  - 2 dependency-heavy tasks;
  - 2 environment setup tasks.
- 4 conditions:
  - baseline;
  - generic security reminder;
  - selected policies injected once;
  - dynamic phase-distributed policies.
- Metrics:
  - essential policy recall by human judgment;
  - selected policy count and overload;
  - `verification_test` and `verification_runtime` frequency;
  - policy evidence completion;
  - insecure adaptation incidents;
  - final correctness/security outcomes.

Expected hypothesis:

```text
Dynamic phase-distributed policy control will improve policy evidence
completion, increase relevant test/runtime verification, and reduce insecure
adaptations compared with generic reminders or one-shot selected policy
injection, while selecting fewer policies than a flat policy dump.
```

## Bottom Line

The ML contribution should be framed as constrained sequential policy
selection, not unconstrained agent optimization. The first system should be
transparent and evidence-producing. It should learn only after it has reliable
labels, logged counterfactuals, and independent outcome metrics.

The design principle is:

```text
Use ML to prioritize, adapt, and calibrate policy guidance;
use deterministic harness constraints to prevent unsafe behavior;
use evidence to decide whether guidance actually worked.
```
