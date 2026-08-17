# Agent 5 Proposal: Empirical Evaluation Methodology

Date: 2026-07-09

Role: Empirical Software Engineering / Benchmark Evaluation Expert

## Executive Summary

The research contribution should be evaluated as a causal trajectory-control
method, not as a prompt variant. The core empirical question is:

```text
Do selected, phase-bound policies change coding-agent behavior in ways that
improve independently measured correctness and security outcomes?
```

The evaluation must therefore measure both:

1. **Trajectory effects:** whether the agent inspects the right context,
   recognizes risks earlier, plans with explicit controls, writes safer code,
   tests adversarial cases, probes runtime behavior, repairs without insecure
   shortcuts, and reports only evidence-backed claims.
2. **Outcome effects:** whether final artifacts pass functional tests, security
   tests, exploit probes, static/manual review, and fail-safe requirements.

The unit of experiment should be:

```text
task x agent/provider x policy condition x run replicate
```

Every run should preserve the exact prompt, selected policies, phase bindings,
interventions, tool calls, command outputs, file edits, validation results,
final artifacts, and final report. This makes the method reproducible and
allows trajectory-level analysis, mediation tests, and failure-mode auditing.

## What Prior Evidence Implies

The current evidence base already shows why outcome-only evaluation is
insufficient.

`reports/baxbench_agent_behavior_codex.md` shows that baseline Codex behavior
on 90 BaxBench runs is dominated by inspection, failure diagnosis, build
verification, refinement, and implementation. Explicit tests and runtime probes
are rare:

| Behavior               | Baseline count |
| ---------------------- | -------------: |
| `verification_build`   |            260 |
| `verification_static`  |             90 |
| `verification_test`    |              9 |
| `verification_runtime` |              2 |

This means a method can plausibly improve security not by making the model
"know more", but by changing which behaviors occur and when they occur.

The existing comparison reports add four evaluation lessons:

1. `reports/agent-behavior-comparison/archon-vs-codex-python-task.md` shows
   that workflow phases create persistent artifacts, fresh context boundaries,
   deterministic validation, and replayable logs. These are measurable
   intervention mechanisms.
2. `reports/agent-behavior-comparison/archon-chat-bundled-python-task.md`
   shows that Archon chat without an explicit workflow may behave like a
   normal coding agent. Experiments must separate "Archon as chat wrapper" from
   "Archon as policy harness".
3. `reports/agent-behavior-comparison/swebench-django-sonnet-vs-archon.md`
   shows that stronger validation behavior can change patch quality, not just
   final narration. A committed regression test and broader focused validation
   are outcome-relevant trajectory differences.
4. `reports/secure-environment-setup/docker-comparison.md` and
   `reports/grasp-secure-coding/workflow-comparison.md` show that security
   evaluation requires controls and adversarial checks beyond scanner output.
   Bandit-clean code can still leak sensitive information, and a live setup can
   be less secure than a fail-safe blocked setup.

These reports motivate a matched, multi-condition experiment with independent
outcome scoring and a validated behavior codebook.

## Research Questions

### RQ1: Selection Quality

Does compact policy selection choose the policies that human experts consider
relevant, specific, enforceable, and cost-effective for each task?

Primary measures:

- selected-policy precision against human labels;
- recall of critical policies;
- selected-policy count;
- token/runtime overhead;
- duplicate or irrelevant policy rate;
- missing severe-risk rate.

### RQ2: Phase Distribution

Does distributing policies across behavior phases produce stronger trajectory
changes than injecting the same selected policies once?

Primary measures:

- phase obligation completion rate;
- policy-to-action conversion rate;
- earlier risk recognition;
- increase in targeted `verification_test` and `verification_runtime`;
- reduction in unsupported final claims;
- fewer insecure adaptations during repair.

### RQ3: Outcome Lift

Do policy-guided runs produce more correct and secure artifacts than baseline,
generic reminders, flat policy dumps, and selected-policy-only conditions?

Primary measures:

- functional pass rate;
- security pass rate;
- severe vulnerability rate;
- exploit/adversarial test pass rate;
- fail-safe behavior rate on underspecified high-risk tasks;
- false-completion rate.

### RQ4: Mechanism

Are outcome improvements mediated by trajectory changes such as earlier risk
recognition, more adversarial tests, better runtime probing, and fewer insecure
workarounds?

Primary measures:

- direct effect of condition on outcomes;
- indirect effect through trajectory mediators;
- per-task and per-provider heterogeneity;
- sensitivity of mediation claims to annotation uncertainty.

### RQ5: Generalization

Do the effects hold across task families, languages/frameworks, providers, and
benchmarks?

Primary measures:

- held-out task-family performance;
- provider-by-condition interaction;
- language/framework interaction;
- cross-benchmark transfer from curated tasks to BaxBench/SWE-bench-like tasks.

## Experimental Unit and Controls

Each run should be uniquely identified by:

```text
benchmark_id
task_id
task_family
language_framework
provider
model_version
policy_condition
replicate_id
workspace_seed
tool_permission_profile
container_image_digest
time_budget
token_budget
```

The controlled setup should enforce:

- identical starting workspace per task and condition;
- isolated worktree or container per run;
- pinned dependency lockfiles or package-cache snapshots where possible;
- fixed tool permissions per condition;
- fixed wall-clock, token, and cost budgets;
- no network access except where the task explicitly requires it;
- exact recording of model/provider version and CLI/SDK version;
- randomized condition order to reduce time/provider drift bias;
- blinded outcome review where human assessment is required.

Replicates are necessary because coding agents are stochastic even when the
prompt and workspace are fixed. At minimum, use 3 replicates per
`task x provider x condition` cell for pilot experiments and 5-10 replicates
for confirmatory studies on the final task set.

## Experimental Conditions

The conditions should isolate selection, phase distribution, harness structure,
and dynamic control.

| Condition                                  | Description                                                                                  | Purpose                                           |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| C0 Baseline                                | Original benchmark prompt only, equivalent to BaxBench `safety_prompt=none`.                 | Observe normal agent behavior.                    |
| C1 Generic reminder                        | Original prompt plus generic secure-coding reminder.                                         | Estimate effect of broad security nudge.          |
| C2 Specific risk reminder                  | Prompt includes task-specific CWE/risk hints, but no policy objects.                         | Estimate effect of explicit risk information.     |
| C3 Flat policy dump                        | Inject broad OWASP/SCP policy text once.                                                     | Test whether more policy text helps or overloads. |
| C4 Selected policies once                  | Compact relevant policies injected once at start.                                            | Test selection without phase distribution.        |
| C5 Phase-distributed selected policies     | Compact policies rendered as phase-specific obligations.                                     | Test RQ2.                                         |
| C6 Phase-distributed plus validation gates | C5 plus deterministic functional/security validators and evidence ledger gates.              | Test harness enforcement beyond prompting.        |
| C7 Dynamic policy controller               | C6 plus mid-run policy adoption when new sinks, dependencies, services, or shortcuts appear. | Test full trajectory control.                     |
| C8 Human oracle policy set                 | Human experts select policies and phase bindings, harness enforces them.                     | Upper bound for automatic selection.              |

For Archon-specific experiments, include two structurally important baselines:

| Condition                           | Description                                                     | Why needed                                                      |
| ----------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------- |
| A0 Direct agent                     | Provider CLI/SDK runs outside Archon with the same task prompt. | Separates harness effects from provider capability.             |
| A1 Archon chat/no explicit workflow | Archon direct chat path with no policy workflow.                | Prevents attributing chat-wrapper behavior to workflow control. |

The main comparison should be `C0` vs `C4` vs `C5` vs `C6` vs `C7`, with
`C1-C3` retained as prompt-only baselines and `C8` retained as an oracle
ceiling.

## Ablation Design

The ablation matrix should remove one mechanism at a time from the full
policy-guided controller.

| Ablation                      | Removed mechanism                                                              | Expected diagnostic value                                |
| ----------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------- |
| No workflow phases            | Policies are selected but agent runs in one free-form session.                 | Tests whether phase structure matters.                   |
| No compact selector           | Full policy corpus or broad flat list is injected.                             | Tests policy overload and cost.                          |
| No graph/risk expansion       | Only retrieval over policy text is used.                                       | Tests whether structured security knowledge adds recall. |
| No phase distribution         | Selected policies are injected only once.                                      | Tests behavioral placement.                              |
| No validation gates           | Agent receives policy obligations but harness does not block missing evidence. | Tests enforcement vs advice.                             |
| No adversarial tests          | Functional validation remains, policy-specific negative tests are disabled.    | Tests security test contribution.                        |
| No runtime probes             | Static/build/test checks remain, live endpoint/service probes disabled.        | Tests backend/runtime coverage.                          |
| No repair guardrails          | Repair loops do not carry forbidden workaround constraints.                    | Tests insecure adaptation control.                       |
| No evidence report gate       | Final report can be produced without ledger-backed evidence.                   | Tests false-completion control.                          |
| No dynamic adoption           | Only initial policy set is used; new risks do not add policies.                | Tests whether emerging risks matter.                     |
| Auto selector vs human oracle | Replace automatic policies with expert-selected policies.                      | Estimates headroom and selector error cost.              |

Each ablation should be run on a smaller but stratified task set first. Only
high-signal ablations should be carried into the full confirmatory experiment.

## Task Set Design

The task set should support both high internal validity and cross-task
generalization.

### Pilot Set

Use 20-30 tasks to iterate on schemas, logging, validators, and annotation.
Include:

- file/parser tasks similar to the YAML loader comparison;
- backend API tasks from BaxBench-style suites;
- database/query tasks;
- authentication/session or access-control tasks;
- dependency-heavy build tasks;
- environment/setup tasks similar to autossh;
- one or two SWE-bench-style bug fixes where regression tests matter.

### Confirmatory Set

Use at least 100 tasks, stratified by task family and framework:

| Task family                           | Minimum target |
| ------------------------------------- | -------------: |
| File/parser/security utility          |             15 |
| Backend HTTP API                      |             30 |
| Database/data access                  |             15 |
| Auth/session/access control           |             10 |
| Dependency/build/runtime service      |             15 |
| Environment/setup/security operations |             10 |
| Real bug-fix/regression tasks         |             15 |

The exact counts can change based on available benchmark data, but the final
set must include tasks where security success is not equivalent to functional
success.

### Held-Out Generalization Set

Reserve 20-30% of tasks as held out by task family or framework. For example:

- train/tune selector thresholds on Python/JavaScript/Go API tasks;
- hold out Ruby/PHP/Rust API tasks;
- tune file security policies on YAML/JSON tasks;
- hold out archive extraction, image metadata, or template rendering tasks;
- tune environment setup on autossh-like tasks;
- hold out a different persistent-service setup task.

Do not tune policy-selection thresholds on the held-out set.

## Policy Selection Metrics

The selector should produce a structured record per run:

```json
{
  "task_id": "string",
  "surface_signals": ["http_request", "file_path", "yaml_parser"],
  "candidate_policies": ["..."],
  "selected_policies": ["..."],
  "selection_rationale": { "policy_id": "trigger and score explanation" },
  "rejected_policies": { "policy_id": "reason" },
  "selection_version": "string"
}
```

Selection should be evaluated against human labels:

| Metric              | Definition                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------- |
| Critical recall     | Fraction of expert-labeled critical policies selected.                                        |
| Useful precision    | Fraction of selected policies labeled critical or useful.                                     |
| Irrelevant rate     | Fraction of selected policies labeled irrelevant or wrong-domain.                             |
| Overload index      | Selected policies plus rendered prompt tokens, normalized by task complexity.                 |
| Enforceability rate | Fraction of selected policies with validators or evidence expectations.                       |
| Coverage diversity  | Number of distinct risk surfaces covered without near duplicates.                             |
| Conflict rate       | Fraction of runs where selected policies conflict with task requirements or framework idioms. |

Human labels should use four classes:

```text
critical
useful_optional
irrelevant
missing_critical
```

`missing_critical` is not a policy label in the selected set. It is assigned
when reviewers identify a policy that should have been selected but was absent.

## Phase Distribution Metrics

Each selected policy should be mapped to expected behavior-phase obligations:

```text
policy_id
phase
instruction
required_evidence
blocking_level
validator_or_probe
```

Evaluate distribution with:

| Metric                      | Definition                                                                |
| --------------------------- | ------------------------------------------------------------------------- |
| Phase fit precision         | Fraction of phase bindings judged useful by experts.                      |
| Phase obligation completion | Fraction of required phase obligations with evidence.                     |
| Over-distribution rate      | Fraction of policy-phase bindings judged irrelevant or repetitive.        |
| Under-distribution rate     | Fraction of policies missing a needed phase binding.                      |
| Blocking appropriateness    | Fraction of fail-closed/required/advisory levels judged correct.          |
| Evidence specificity        | Fraction of obligations with concrete, inspectable evidence requirements. |

The distributor should be penalized for repeating the same generic policy text
in every phase. A good phase binding changes the action requested from the
agent. For example, path traversal policy should become inspection of input and
sinks, planning of confinement strategy, implementation of canonicalization and
allowlists, adversarial tests, repair invariants, and residual-risk reporting.

## Trajectory Metrics

Use the BaxBench two-axis taxonomy as the primary codebook:

- one primary process label per substantive event;
- zero or more secondary attribute labels.

### Primary Behavior Frequency

Report event counts and normalized rates for:

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

Normalize by:

- substantive event count;
- wall-clock time;
- token budget;
- task family;
- provider/model.

### Targeted Trajectory Metrics

| Metric                       | Definition                                                                                                        |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Time to risk recognition     | Number of events until first correct security/risk identification.                                                |
| Risk recognition quality     | Expert score for whether recognized risks match the task surface.                                                 |
| Inspection relevance         | Fraction of inspection events tied to selected policy evidence.                                                   |
| Policy-to-action conversion  | Fraction of selected policies that lead to concrete code, test, probe, or config evidence.                        |
| Defensive coding specificity | Fraction of `defensive_coding` events tied to the correct risk surface rather than generic validation.            |
| Security test count          | Number of adversarial/negative tests tied to selected policy IDs.                                                 |
| Runtime probe count          | Number of live endpoint/service probes tied to selected policy IDs.                                               |
| Repair preservation          | Whether repair edits preserve or strengthen selected controls after failures.                                     |
| Unsafe adaptation rate       | Count of adaptations that weaken auth, validation, host checks, permissions, TLS, secrets, or fail-safe behavior. |
| Failure loop burden          | Number and length of repeated fail-diagnose-refine loops.                                                         |
| Evidence-backed final claims | Fraction of final report claims supported by ledger evidence.                                                     |
| False completion             | Run reports success despite failed/missing required evidence.                                                     |

### Transition Metrics

Compare condition-level transition probabilities such as:

- `inspection -> planning`;
- `planning -> implementation_writing`;
- `implementation_writing -> verification_test`;
- `implementation_writing -> verification_runtime`;
- `verification_build -> failure_observation_diagnosis`;
- `failure_observation_diagnosis -> refinement`;
- `failure_observation_diagnosis -> adaptation`;
- `adaptation -> verification_test`;
- `adaptation -> final_reporting`;
- `verification_test -> final_reporting`;

The expected signature of the full method is not simply "more security words".
It should produce:

- earlier risk recognition;
- more relevant inspection before implementation;
- more policy-specific tests and probes;
- fewer unsupported success claims;
- fewer insecure adaptations;
- final reports backed by evidence.

## Outcome Metrics

Outcome scoring must be independent of the agent's final report.

### Correctness Outcomes

| Metric                            | Source                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------ |
| Public test pass                  | Benchmark or task-provided tests.                                              |
| Hidden test pass                  | Held-out evaluator tests where available.                                      |
| Generated regression test quality | Human or automated review of generated tests.                                  |
| Spec conformance                  | Checklist derived from task specification.                                     |
| Patch minimality                  | Diff size, touched files, and human assessment of unnecessary changes.         |
| Integration quality               | Uses framework idioms, preserves existing API contracts, avoids brittle hacks. |

### Security Outcomes

| Metric                       | Source                                                                                                                             |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| CWE-specific exploit tests   | Negative tests/probes generated by evaluator, not by the agent under test.                                                         |
| Policy control coverage      | Matrix of required controls vs observed implementation/validation evidence.                                                        |
| Vulnerability count/severity | Human review plus targeted static/dynamic checks.                                                                                  |
| Error disclosure checks      | Tests for internal path, stack trace, secret, or parser-detail leakage.                                                            |
| Dangerous shortcut checks    | Host-key disabling, generated credentials, root execution, public binds, unsafe deserialization, shell interpolation, auth bypass. |
| Fail-safe correctness        | On underspecified high-risk tasks, run blocks activation rather than inventing trust inputs.                                       |
| Security regression pass     | Existing or generated security tests retained and passing.                                                                         |

### Cost and Practicality Outcomes

| Metric              | Definition                                                      |
| ------------------- | --------------------------------------------------------------- |
| Wall-clock time     | Total run time and phase time.                                  |
| Token cost          | Input/output tokens by phase and condition.                     |
| Tool-call count     | Commands, file reads, writes, installs, service starts.         |
| Human-review burden | Time for reviewers to adjudicate evidence.                      |
| Policy overhead     | Added prompt tokens and validation runtime per selected policy. |
| Flake rate          | Runs affected by transient environment/provider failures.       |

Security and correctness should be reported jointly. A run that passes
functional tests but introduces a critical vulnerability is not a success. A
run that blocks unsafe activation because trust inputs are missing can be a
security success even if a naive liveness check would fail.

## Correctness and Security Evaluation Protocol

For each task, create a task-specific evaluator bundle:

```text
functional_tests/
security_tests/
runtime_probes/
static_checks/
control_matrix.json
review_guide.md
```

The evaluator bundle should be written before condition results are inspected
where possible. For benchmark tasks with official evaluators, use the official
tests as correctness anchors and add security-specific tests only when they do
not leak into the agent prompt.

Security review should follow a two-stage protocol:

1. **Automated first pass:** run tests, probes, scanners, dangerous-pattern
   searches, and policy validators.
2. **Human review pass:** review sampled final artifacts and all cases where
   automated checks disagree with final reports or where severe security
   controls are ambiguous.

Human reviewers should score:

```text
functional_correctness: pass | partial | fail | unknown
security_correctness: pass | partial | fail | blocked_safe | unknown
critical_vulnerability_present: yes | no | unknown
false_completion: yes | no
evidence_support: complete | partial | unsupported
```

The `blocked_safe` category is important for environment/setup tasks. It
captures cases where secure behavior is to preserve missing trust inputs and
refuse unsafe activation.

## Human Annotation Plan

### Annotation Targets

Human annotation should cover:

- trajectory event labels;
- risk identification quality;
- selected-policy relevance;
- phase-binding quality;
- policy-to-action conversion;
- insecure adaptation incidents;
- evidence support for final claims;
- residual vulnerabilities in final artifacts.

### Sampling

Use stratified sampling:

- 15-20% of runs for taxonomy validation during pilot;
- all severe or ambiguous security failures;
- all provider/tool failures that might be mistaken for success;
- at least 5 runs per task family and condition in confirmatory analysis;
- oversample rare behaviors such as runtime probes and unsafe adaptations.

### Annotator Workflow

1. Train annotators on the frozen codebook and 5-10 calibration trajectories.
2. Annotators independently label the same sampled events and artifacts.
3. Compute agreement separately for primary process labels and secondary
   attributes.
4. Adjudicate disagreements and revise the codebook once during pilot only.
5. Freeze the codebook before confirmatory labeling.
6. Keep an adjudication log with examples and rule changes.

### Agreement Metrics

Use:

- Cohen's kappa or Krippendorff's alpha for primary process labels;
- F1 and prevalence-adjusted agreement for multi-label secondary attributes;
- weighted kappa for ordinal quality ratings;
- raw agreement for rare severe incidents, reported with counts.

Do not hide low agreement. If annotators cannot reliably identify a metric, the
metric should be simplified or treated as exploratory.

## Reproducibility Requirements

Every run should produce a reproducibility package:

```text
run.json
prompt.txt
task.json
workspace_initial_manifest.json
workspace_final_manifest.json
provider_metadata.json
selected_policies.json
phase_policy_plan.json
interventions.jsonl
steps.jsonl
tool_calls.jsonl
file_diffs.patch
validation_results.json
evidence_ledger.json
final_message.txt
outcome_scores.json
```

`run.json` should include:

- commit SHA of Archon and evaluator code;
- benchmark version and task ID;
- container image digest or environment fingerprint;
- provider/model version;
- random seed if supported;
- tool permission profile;
- budgets and timeout settings;
- condition ID and selector/distributor version;
- hashes of prompt and policy artifacts.

The analysis pipeline should be executable from raw artifacts:

```text
raw trajectories -> normalized events -> labels -> metrics -> statistical report
```

The final paper/report should distinguish between:

- raw data that can be released;
- generated code that can be released;
- logs that may contain secrets or proprietary content and require redaction;
- evaluator code that must be versioned for replication.

## Statistical Analysis

### Primary Confirmatory Endpoints

Pre-register a small number of primary endpoints:

1. Security pass rate.
2. Functional pass rate.
3. False-completion rate.
4. Policy-to-action conversion rate.
5. `verification_test` and `verification_runtime` rate.

All other metrics can be secondary or exploratory.

### Models

Use hierarchical models because observations are nested by task, provider, and
replicate.

For binary outcomes:

```text
logit(P(pass)) =
  condition
  + provider
  + task_family
  + condition:task_family
  + condition:provider
  + random_intercept(task_id)
```

For count outcomes:

```text
negative_binomial(count) =
  condition
  + provider
  + task_family
  + offset(log(substantive_events or tokens))
  + random_intercept(task_id)
```

For ordinal human ratings, use ordinal logistic mixed models or report
non-parametric paired tests in the pilot.

### Pairing and Blocking

Primary comparisons should be paired by task and provider. For example, compare
baseline and policy-guided outcomes on the same task/provider cells. This
reduces variance caused by task difficulty.

### Effect Sizes

Report effect sizes, not only p-values:

- absolute percentage-point lift in pass rates;
- odds ratios with confidence/credible intervals;
- rate ratios for trajectory behaviors;
- mean/median cost overhead;
- number needed to guide: tasks requiring policy guidance to prevent one
  severe security failure;
- security lift per 1,000 prompt tokens or per minute of runtime overhead.

### Multiple Comparisons

Control false discoveries for secondary metrics using Benjamini-Hochberg or
report them as exploratory. Keep the confirmatory endpoint set small.

### Power Planning

Before the full study, use pilot variance to estimate required task/replicate
counts. The study should be powered to detect:

- a 10-15 percentage-point security pass-rate lift;
- a 10 percentage-point false-completion reduction;
- a 2x increase in rare but important runtime/test verification behaviors.

Rare severe vulnerabilities may require aggregation across task families and
careful confidence intervals rather than overconfident per-family claims.

## Causal and Mediation Claims

The strongest defensible causal claim comes from randomized assignment of
policy conditions within matched task/provider cells:

```text
same task + same provider + same workspace + randomized condition
```

This supports claims that condition changes caused observed average differences
under the controlled experimental setup.

Mediation claims require additional caution. The proposed causal path is:

```text
policy condition
  -> trajectory change
  -> outcome improvement
```

Candidate mediators:

- time to risk recognition;
- inspection relevance;
- policy-to-action conversion;
- adversarial test count;
- runtime probe count;
- unsafe adaptation rate;
- evidence-backed final claim rate.

Recommended mediation approach:

1. Show condition affects the mediator.
2. Show mediator predicts outcome after controlling for task/provider.
3. Estimate indirect effects with hierarchical mediation or bootstrap paired
   mediation.
4. Run sensitivity analysis for unmeasured mediator-outcome confounding.
5. Phrase conclusions as "consistent with mediation" unless the design
   includes explicit intervention on the mediator.

To strengthen mediation evidence, add micro-randomized interventions in a
small follow-up study. For example, among phase-distributed runs, randomly
enable or disable the runtime-probe obligation when the task surface requires a
runtime service. This directly tests whether the mediator-like behavior has
causal effect.

## Cross-Task and Cross-Provider Generalization

Generalization should be evaluated along four axes:

1. **Task family:** file/parser, web API, database, auth/session, environment
   setup, dependency/build, bug-fix.
2. **Language/framework:** Python, JavaScript/TypeScript, Go, Ruby, PHP, Rust,
   Java where available.
3. **Provider/model:** Codex, Claude, and at least one additional provider if
   feasible.
4. **Benchmark source:** BaxBench-style code generation, SWE-bench-style bug
   fixes, curated security tasks, and environment setup tasks.

The analysis should report:

- pooled effect;
- per-task-family effect;
- provider-by-condition interactions;
- failures where guidance helps one provider but hurts another;
- held-out family performance without retuning selector thresholds.

Do not claim general security improvement from a single family such as YAML
file loading. The method must show that policy selection and phase distribution
adapt across surfaces.

## Failure Mode Taxonomy

Every failed or partial run should be assigned one or more failure modes:

| Failure mode            | Example                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| Selector miss           | Did not select path traversal policy for untrusted filename.           |
| Selector overload       | Selected too many broad policies and agent ignored key ones.           |
| Wrong phase binding     | Runtime exposure policy only appeared in final report, not validation. |
| Harness enforcement gap | Provider rate-limit text treated as successful validation.             |
| Agent noncompliance     | Agent ignored required test/probe obligation.                          |
| Insecure adaptation     | Disabled host-key checking or validation to make a command pass.       |
| Functional regression   | Security control broke expected behavior.                              |
| Evidence spoofing       | Final report claims tests/probes without logs.                         |
| Environment artifact    | Sandbox or missing dependency invalidated comparison.                  |
| Evaluator gap           | Automated tests missed a vulnerability found by review.                |

This taxonomy makes failures actionable. It also prevents overclaiming: a
policy-guided method can fail because selection is wrong, distribution is
wrong, enforcement is weak, or validators are incomplete.

## Data Artifacts and Schemas

The empirical study needs stable machine-readable schemas. At minimum:

```ts
type ExperimentRun = {
  runId: string;
  taskId: string;
  conditionId: string;
  provider: string;
  modelVersion: string;
  replicateId: number;
  workspaceSeed: string;
  startedAt: string;
  completedAt?: string;
  status: 'completed' | 'failed' | 'blocked' | 'timeout';
};

type TrajectoryEvent = {
  runId: string;
  eventIndex: number;
  timestamp: string;
  source: 'agent' | 'tool' | 'harness' | 'validator';
  eventType: string;
  text?: string;
  command?: string;
  exitCode?: number;
  filesTouched?: string[];
};

type BehaviorLabel = {
  runId: string;
  eventIndex: number;
  primaryProcess: string;
  secondaryAttributes: string[];
  labelSource: 'rule' | 'human' | 'adjudicated';
  confidence?: number;
};

type OutcomeScore = {
  runId: string;
  functionalStatus: 'pass' | 'partial' | 'fail' | 'unknown';
  securityStatus: 'pass' | 'partial' | 'fail' | 'blocked_safe' | 'unknown';
  criticalVulnerability: boolean | 'unknown';
  falseCompletion: boolean;
  evaluatorVersion: string;
};
```

Use the repository's Zod conventions when implementing these later:
`z.infer<typeof schema>`, camelCase schema names, explicit key type for
records, and `z` from `@hono/zod-openapi` outside provider leaf packages.

## Key Design Choices and Rationales

### 1. Evaluate Conditions as Interventions

Rationale: The method changes prompts, phases, validators, tool authorization,
and evidence gates. Treating it as a prompt-only comparison would hide the
actual intervention.

### 2. Pair Trajectory Metrics With Outcome Metrics

Rationale: A `defensive_coding` label means the agent did something
security-relevant. It does not mean the final code is secure. Outcome scoring
must independently test whether the control works.

### 3. Include Prompt-Only and Harness Conditions

Rationale: Generic reminders, specific reminders, selected policies, and
phase-distributed harness enforcement are different mechanisms. The experiment
must show which mechanism contributes the lift.

### 4. Use Human Oracle Policies

Rationale: If the automatic selector performs poorly but the human oracle
succeeds, the method is sound but selector quality is the bottleneck. If the
oracle also fails, the phase/harness design or validators are likely weak.

### 5. Treat Fail-Safe Blocking as a Valid Security Outcome

Rationale: In tasks like persistent tunnel setup, the secure answer may be
`BLOCKED_INPUT_REQUIRED`. Evaluators that reward only liveness will reward
unsafe fabrication of trust inputs.

### 6. Require Evidence-Ledger Support for Final Claims

Rationale: Final reports are cheap to fake or overstate. Claims should be
linked to logs, diffs, tests, probes, or validator outputs.

### 7. Measure Cost Explicitly

Rationale: The GRASP comparison showed security depth can be expensive.
Selection and phase distribution should improve security per token and per
minute, not only absolute security.

### 8. Keep the Codebook Frozen for Confirmatory Analysis

Rationale: Iterating labels after seeing condition effects biases results.
Revise the codebook during pilot, then freeze it before the confirmatory run.

### 9. Report Negative Interactions

Rationale: Security guidance can overconstrain agents, cause overengineering,
or reduce functional correctness. The method must report where it hurts.

### 10. Separate Agent, Harness, and Evaluator Failures

Rationale: A provider limit, malformed validation output, or evaluator blind
spot is not the same as agent implementation failure. The secure environment
comparison shows this distinction matters.

## Staged Evaluation Plan

### Stage 0: Instrumentation Readiness

Goal: ensure every condition logs comparable artifacts.

Exit criteria:

- run metadata schema exists;
- normalized trajectory logs exist;
- selected policies and phase plans are saved;
- evidence ledger exists;
- validation outputs are machine-readable;
- provider failures are not marked as validation success.

### Stage 1: Pilot Study

Goal: test feasibility on 20-30 tasks.

Questions:

- Are policies selectable with acceptable precision?
- Do phase obligations produce observable behavior?
- Are validators too weak or too expensive?
- Can annotators reliably label trajectories?
- Which ablations are worth full evaluation?

Exit criteria:

- codebook revised once and frozen;
- evaluator bundles stable for pilot tasks;
- pilot variance estimates available;
- failure-mode taxonomy populated.

### Stage 2: Confirmatory Matched Experiment

Goal: estimate primary effects on 100+ tasks.

Required:

- pre-registered primary endpoints;
- randomized condition order;
- paired task/provider comparisons;
- fixed selector/distributor versions;
- blinded human outcome review where feasible;
- full cost and failure reporting.

### Stage 3: Generalization and Stress Testing

Goal: test transfer across held-out task families, frameworks, and providers.

Required:

- held-out task family or framework split;
- provider-by-condition interaction analysis;
- security-stress tasks with missing trust inputs;
- runtime-heavy tasks where probes matter.

### Stage 4: Mechanism Follow-Up

Goal: strengthen mediation and causal mechanism claims.

Examples:

- randomly enable/disable runtime probes for runtime-service tasks;
- randomly require/not require adversarial tests for selected policies;
- compare repair loops with and without anti-shortcut guardrails;
- compare final report with and without evidence-ledger gating.

## Minimum Viable First Experiment

The smallest useful empirical study should be:

```text
tasks: 24
providers: Codex CLI first, optional Claude second
conditions: C0, C1, C4, C5, C6
replicates: 3
total runs: 24 x 1 x 5 x 3 = 360
```

Task mix:

- 6 file/parser tasks;
- 8 backend API tasks;
- 4 database/auth tasks;
- 3 dependency/runtime-service tasks;
- 3 environment/setup tasks.

Primary endpoints:

- functional pass;
- security pass;
- false completion;
- policy-to-action conversion;
- adversarial test/probe rate.

This design is large enough to detect obvious trajectory shifts and severe
security differences while still being practical for tooling iteration.

## Reporting Template

Every empirical report should include:

1. Task set and selection criteria.
2. Providers, model versions, and budgets.
3. Conditions and exact prompts/policy renderers.
4. Replicate counts and randomization procedure.
5. Missing/excluded run policy.
6. Trajectory codebook version and agreement metrics.
7. Outcome evaluator versions.
8. Primary endpoint results with effect sizes.
9. Secondary trajectory and cost results.
10. Failure-mode breakdown.
11. Representative qualitative trajectories.
12. Reproducibility artifact manifest.
13. Limitations and known threats to validity.

## Threats to Validity

### Internal Validity

- provider/model drift over time;
- stochastic run variance;
- condition prompts differing in unintended ways;
- evaluator leakage into agent prompts;
- workflow overhead confounded with policy content;
- provider failures mistakenly treated as success;
- human reviewers not blinded to condition.

Mitigations:

- randomize condition order;
- pin model/provider versions where possible;
- use paired comparisons;
- use blinded artifact review;
- store exact prompts and policy renderings;
- classify provider/tool failures separately.

### Construct Validity

- `defensive_coding` may capture superficial security-looking behavior;
- static scanners miss relevant vulnerabilities;
- benchmark tests may reward insecure liveness;
- final reports may overclaim;
- generated tests may reflect agent assumptions rather than true correctness.

Mitigations:

- pair trajectory labels with independent outcome tests;
- include human security review;
- use exploit-oriented tests and fail-safe scoring;
- require evidence-ledger support for claims.

### External Validity

- BaxBench tasks may not represent real repositories;
- curated security tasks may overrepresent known CWEs;
- provider-specific behavior may not transfer;
- small task artifacts may not reflect large codebases.

Mitigations:

- use multiple task families and benchmarks;
- hold out frameworks/task families;
- include SWE-bench-style bug fixes;
- evaluate at least two providers before broad claims.

### Conclusion Validity

- too many metrics can create false positives;
- rare severe vulnerabilities may be underpowered;
- annotation uncertainty can affect mediation claims;
- cost/security tradeoffs may be hidden by pooled scores.

Mitigations:

- pre-register primary endpoints;
- report confidence/credible intervals;
- correct exploratory comparisons;
- report cost-adjusted effects;
- run sensitivity analysis for mediation.

## Bottom Line

The empirical claim should be deliberately narrow and defensible:

```text
Under matched task/provider/workspace conditions, policy-guided trajectory
control improves secure and correct coding outcomes because it changes
observable agent behavior: earlier risk recognition, more relevant inspection,
policy-specific implementation, adversarial validation, safer repair, and
evidence-backed reporting.
```

The method should not claim that policies make agents intrinsically secure.
It should claim that an external harness can select, distribute, enforce, and
measure policy obligations in ways that improve both trajectories and final
artifacts.
