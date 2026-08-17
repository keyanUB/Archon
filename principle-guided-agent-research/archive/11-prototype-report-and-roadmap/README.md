# PGACS Prototype: Comprehensive Experiment Report and Research Roadmap

Date: 2026-07-27

Status: Historical synthesis. For the current generic three-task C2
implementation, readiness state, and frozen experiment protocol, use
[`../15-multibench-prototype/technical-design.md`](../15-multibench-prototype/technical-design.md)
and [`../15-multibench-prototype/README.md`](../15-multibench-prototype/README.md).
Statements below such as "only ZIP is runnable" and "no model-backed C2 run"
describe the July milestone and are retained for provenance.

## Executive Summary

This report consolidates the current prototype of the **Policy-Guided Agent
Control System (PGACS)**, the experiments conducted so far, the evidence they
produce, and the next research steps.

PGACS investigates whether software-engineering and security principles can be
converted into operational policies that alter coding-agent behavior toward
secure and correct outcomes. Its central premise is:

> Secure coding is not only a model-knowledge problem. It is also a trajectory
> control problem involving what the agent inspects, plans, implements, tests,
> repairs, and claims as complete.

The prototype has progressed through five stages:

1. A typed policy registry and task-surface representation.
2. A deterministic, explainable selector over 84 domain policies plus a
   three-policy generic security floor.
3. A constrained LLM semantic-selector experiment over 298 selectable records;
   its preserved run included reference task-family metadata and is now treated
   as historical/confounded evidence.
4. A paired baseline-versus-policy-guided coding experiment on an untrusted ZIP
   parser task.
5. An implemented Archon C2 workflow for the same task with a frozen policy
   pack, Claude-native pre-tool controls, phase-attributed tool observations, a
   deterministic write boundary, trusted isolated probes, one bounded repair,
   an append-only evidence ledger, and a terminal gate. The mechanism is tested,
   but an agent-backed C2 run has not yet been recorded.

The evidence currently supports four limited conclusions:

1. A policy pipeline can be made structured, provenance-preserving,
   explainable, and replayable.
2. The preserved semantic run produced a smaller, better-aligned policy set than
   the first tag-overlap run, but task-family metadata and corpus changes prevent
   attributing that difference to classification-independent semantic selection.
3. Injecting three semantically proposed policies changed one coding trajectory and added
   defense-in-depth behavior, but also nearly doubled token use, increased code
   size, narrowed compatibility, and introduced private-API maintenance risk.
4. Existing Archon DAG and Claude-hook primitives are sufficient to express a
   fixed C2 harness with pre-action tool-class controls, phase-boundary scope
   enforcement, isolated checks, one repair boundary, an evidence ledger, and a
   deterministic terminal decision.

The work does **not** yet establish that PGACS generally improves secure coding
or that the corrected semantic selector outperforms the deterministic baseline.
The downstream study contains one task and one run per condition. The first
cross-task cohort is now frozen as `pgacs-smoke-v0.1`: seven repository code
tasks and one environment-configuration task across eight security families.
Only the ZIP task is currently runnable. The immediate research priority is to
promote the remaining tasks through shared workspace/evaluator contracts, then
run a controlled experiment separating:

- ordinary coding-agent behavior;
- selected-policy prompt guidance; and
- selected-policy guidance plus deterministic checking and one repair loop.

## 1. Research Objective

The project asks how to use a prepared corpus of principles to guide coding
agents without dumping an entire security handbook into every prompt.

Two research questions organize the work.

### RQ1: Policy selection

How should the system select the smallest useful policy set for the current
task, repository, environment, and emerging trajectory?

Selection must balance:

- coverage of critical risks;
- relevance and specificity;
- enforceability;
- policy redundancy;
- task compatibility;
- prompt and execution cost;
- provenance and explainability.

### RQ2: Policy distribution and enforcement

How should selected policies be delivered across the coding trajectory so they
affect the right behaviors at the right time?

A policy can serve different purposes in different phases:

- inspection: identify inputs, sinks, assets, and trust boundaries;
- planning: become a design constraint and acceptance criterion;
- implementation: become a concrete coding obligation;
- validation: generate static, test, or runtime evidence;
- repair: prevent insecure shortcuts when failures occur;
- reporting: constrain completion claims to verified evidence.

The final design proposes three enforcement layers:

1. **Proactive:** phase-local context injected into the code LLM.
2. **Detective:** harness monitors and runtime probes over observed behavior.
3. **Corrective:** loop conditioning, invariants, and targeted repair.

Only the first layer has been tested downstream in the current prototype.

## 2. Terminology

This project uses **principle** for source guidance and **policy** for its
operational form.

```text
Principle
  broad normative guidance from OWASP, ASVS, CWE, SSDF, or another source

Policy
  a provenance-linked control that can be selected, rendered, checked,
  evidenced, and assigned an enforcement disposition
```

For example:

```text
Principle: Validate untrusted file names.

Policy:
  trigger = untrusted archive reaches filesystem semantics
  obligation = accept only normalized relative member names
  evidence = adversarial traversal and platform-path tests
  repair invariant = validation may not be removed to make tests pass
```

This distinction matters because asking an agent to "follow principles" is not a
harness. The research contribution is the compilation from guidance to
task-specific behavioral controls.

## 3. Empirical Motivation

The behavior vocabulary comes from a separate BaxBench trajectory study
summarized in `reports/baxbench_agent_behavior_codex.md`.

That study reports:

- 90 Codex runs;
- 2,131 behavior-bearing events before filtering;
- 2,052 substantive behavior events after filtering.

The most frequent behaviors were inspection (416 events), failure diagnosis
(355), build verification (260), and refinement (238). Automated test
verification appeared only nine times and runtime verification only twice.
Defensive-coding behavior appeared 202 times, showing that agents sometimes add
security-relevant logic without explicit guidance, but not consistently enough
to treat it as complete security behavior.

This evidence motivates phase-aware intervention:

- agents already inspect and react to failures frequently;
- testing and runtime validation are sparse;
- security guidance should target missing or failure-prone behaviors;
- final code and self-reported success are insufficient trajectory evidence.

The taxonomy currently contains 12 primary behaviors:

`orientation`, `inspection`, `planning`, `implementation_writing`,
`refinement`, `verification_static`, `verification_build`,
`verification_test`, `verification_runtime`,
`failure_observation_diagnosis`, `adaptation`, and `final_reporting`.

## 4. Prototype Architecture

The current end-to-end research pipeline is:

```text
Prepared principle sources
  -> normalized corpus and provenance
  -> task and repository surface
  -> compact policy proposal
  -> deterministic output validation
  -> policy-guided coding prompt
  -> captured agent trajectory and implementation
  -> independent functional/security evaluation
```

The intended full PGACS architecture extends this to:

```text
frozen task manifest + source lock
  -> TaskWorkspaceAdapter verifies and prepares subject workspace
  -> task + repository/container surface
  -> initial PolicyState
  -> phase-local prompt fragments
  -> observation events from an agent adapter
  -> deterministic monitors and evidence
  -> monotonic policy deltas as new risks emerge
  -> EvaluatorAdapter runs isolated functional/security oracles
  -> targeted repair or stop decisions
```

The ZIP C2 prototype implements one Archon runtime vertical slice. It stops
short of cross-task integration: generic task workspace/evaluator adapters,
seven task promotions, and the multi-seed smoke study remain to be implemented.
The adapter split keeps agent capability translation, subject preparation, and
verdict authority in separate trust domains.

## 5. Implemented Components

### 5.1 Policy registry

The first registry normalizes 84 setup and environment policies into typed
`PolicyRecord` objects. Each record carries source provenance and structured
selection/enforcement fields such as risk tags, task triggers, phase bindings,
validators, evidence requirements, forbidden workarounds, and severity.

This establishes a stable data contract, but many tags are inferred from broad
text. They should not be treated as expert annotations.

### 5.2 Task-surface extraction

`TaskSurface` represents security-relevant task and repository facts:

- task family;
- input channels and dangerous sinks;
- assets and trust boundaries;
- dependencies and runtime exposure;
- likely CWEs;
- missing security inputs;
- confidence and existing tests.

The prototype uses deterministic prompt/repository signals. It is replayable,
but keyword competition can misclassify the task's dominant action.

### 5.3 Explainable deterministic selection

The first selector:

- validates registry and surface inputs;
- applies mandatory safety rules;
- scores explicit surface overlap;
- accepts optional structured LLM proposals with limited ranking influence;
- applies a policy budget;
- records selected and rejected candidates;
- emits monotonic deltas when new task facts appear.

Its governing rule is:

> LLM proposes; deterministic rules dispose.

An LLM cannot invent a valid policy, make it mandatory, weaken it, remove a
deterministic match, or decide successful completion.

### 5.4 Expanded semantic corpus

The semantic-selection corpus used by the preserved historical run contains:

| Source | Selectable | Context-only |
| --- | ---: | ---: |
| OWASP SCP / GRASP graph | 214 | 14 |
| Setup/environment policies | 84 | 0 |
| OWASP SCP quick reference | 0 | 55 |
| **Total** | **298** | **69** |

All 367 records preserve source text and provenance. Category summaries and
quick-reference records provide context but cannot be returned as selected
policy IDs.

### 5.5 Constrained semantic selector

The corrected semantic selector receives:

- 298 selectable policy records;
- frozen task prompts and repository hints, without reference task-family
  metadata;
- a maximum of six non-redundant selections per task;
- a structured schema for IDs, importance, rationales, and coverage gaps.

It runs without tools. The local deterministic shell checks task completeness,
ID validity, selectability, rationales, duplicates, and budget compliance.
Selection and adjudication artifacts are bound to their exact inputs with hashes
and normalized fingerprints.

### 5.6 Paired trajectory runner and evaluator

The coding experiment creates isolated baseline and guided workspaces, invokes
the same Codex CLI under the same sandbox, and preserves:

- task text;
- selected policy IDs;
- raw JSONL trajectories;
- generated source and tests;
- stderr and run metadata;
- independent evaluation outputs;
- generated comparison metrics.

The independent evaluator separates explicit task requirements from optional
defense-in-depth choices.

## 6. Experiment 1: Deterministic Selector Evaluation

### Question

Can the initial registry, task-surface extractor, and deterministic overlap
selector choose compact, relevant policies across task families?

### Sample

Twelve frozen tasks, two from each family:

- environment setup;
- web API;
- authentication/session;
- file parsing;
- dependency/build;
- agent tooling.

An independent security-focused subagent created model-generated silver labels
without inspecting selector outputs.

### Results

| Metric | Result |
| --- | ---: |
| Completed tasks | 12/12 |
| Task-family accuracy | 83.33% |
| Required-policy recall | 26.92% |
| Acceptable-selection precision | 15.63% |
| Average selected policies | 8.0 |

Every task filled the eight-policy budget.

### Interpretation

The experiment established determinism and explainability, but selection quality
was not adequate for enforcement. Four causes dominated:

1. Keyword-based surface extraction misclassified both file-parser tasks.
2. Broad inferred tags made semantically different policies appear equivalent.
3. Additive scoring favored generic policies and lacked a useful stopping
   threshold.
4. The narrow corpus lacked direct controls for several application-security
   risks.

This negative result was productive: it ruled out integrating the first
selector into runtime enforcement.

## 7. Experiment 2: Expanded-Corpus Semantic Selection

### Question

Can a tool-less LLM select policies directly from prepared policy text more
effectively than the first tag-overlap prototype without first building a large
manual capability ontology?

### Independence and controls

- The same 12 task shapes were relabeled against the expanded corpus.
- Labels contained 33 required and 25 relevant policy IDs.
- The selector did not receive label fields.
- A regression test prevents labels or label values from entering the prompt.
- A separate semantic adjudication credited control-equivalent selections while
  keeping the frozen labels unchanged.

These remain model-generated silver labels, not human ground truth.

An initial invalid trial accidentally included the silver-label fields in the
serialized task objects and produced a meaningless perfect result. That run was
overwritten and excluded. The selector now constructs fresh, narrow task-input
objects, and the regression test checks both field names and secret label values
are absent from the prompt.

The selector was configured through the Claude CLI `sonnet` alias. CLI usage
reported `claude-sonnet-5` and `claude-haiku-4-5-20251001`; the experiment is
therefore not represented as a pure single-model call.

### Results

| Metric | Deterministic prototype | Semantic prototype |
| --- | ---: | ---: |
| Required-policy recall, exact ID | 26.92% | 54.55% |
| Acceptable precision, exact ID | 15.63% | 47.62% |
| Average selected policies | 8.0 | 3.5 |
| Required-control recall, adjudicated | Not measured | 75.76% |
| Relevant-control precision, adjudicated | Not measured | 100.00% |
| Tasks reporting coverage gaps | Not supported | 3 |

The preserved semantic-selector run produced 18 exact required matches and seven
control-equivalent matches. Eight required controls remained missing.

### Important qualification

This table demonstrates prototype progression, not a controlled selector-only
ablation:

- the corpora differ in size and scope;
- the reference labels were separately adapted;
- the preserved semantic run received the reference `taskFamily` value for each
  task, even though it did not receive policy labels;
- semantic equivalence was judged by a model;
- the reported perfect adjudicated precision is provisional.

### Interpretation

In the preserved run, semantic proposal was more selective and better aligned
with concrete task meaning. It also exposed corpus gaps rather than silently
filling the budget. Because task-family metadata was present, these observations
do not establish the behavior of the corrected selector.

The result supports a lightweight hybrid:

```text
LLM semantic proposal
  -> schema and catalog validation
  -> deterministic authority and logging
```

It does not support letting the model enforce policies or waive controls.

## 8. Experiment 3: Policy-Guided Coding Trajectory

### Question

Does injecting semantically proposed policies change actual coding and validation behavior?

### Task

The task required a Python, metadata-only inspector for untrusted ZIP archives.
The task itself already required malformed-input handling, file-count and
expanded-size limits, path safety, and tests. This made the baseline
security-aware and reduced the chance of measuring a trivial reminder effect.

### Conditions

| Condition | Input |
| --- | --- |
| Baseline | Frozen task plus ordinary implementation instruction |
| Policy-guided | Same task plus three semantically proposed policies and task-specific rationales |

Selected policies covered file-name/type validation, input-size validation, and
sandbox boundaries. Both conditions ran under the same `workspace-write`
sandbox; the sandbox policy therefore changed guidance, not permissions.

The run manifest records Codex CLI `0.145.0`. It does not contain a resolved
model identifier, so the experiment must not be presented as a
model-version-specific comparison.

### Independent evaluation

- 11 required probes represented the explicit contract.
- Six additional probes represented a conservative defense-in-depth posture.
- The agents' own tests were recorded but were not the sole outcome measure.

### Results

| Measure | Baseline | Policy-guided |
| --- | ---: | ---: |
| Agent-authored tests | 9/9 | 9/9 |
| Required external probes | 11/11 | 11/11 |
| Defense-in-depth probes | 0/6 | 6/6 |
| Source lines | 96 | 158 |
| Private `zipfile` API references | 0 | 3 |
| Commands completed | 4 | 6 |
| Failed commands | 0 | 1 |
| Input tokens | 111,865 | 220,102 |
| Output tokens | 4,470 | 8,496 |
| Reasoning-output tokens | 1,767 | 4,389 |

The guided condition used 1.968 times the input tokens and 1.901 times the
output tokens.

### Observed trajectory effect

Both agents implemented the required controls. The guided agent additionally:

- rejected duplicate and non-normalized names;
- rejected control characters and alternate-stream syntax;
- refused a final-component archive symlink where supported;
- required a regular archive file;
- inspected Python's ZIP implementation;
- added a central-directory preflight;
- refined its implementation and tests after the first passing suite.

It also attempted a git check in a non-git workspace, failed, and recovered.

### Security and engineering tradeoff

Some guided changes were plausible hardening improvements. Others may be
overconstraints for applications that only inspect rather than extract
archives. The central-directory mitigation also used private Python APIs,
creating version and maintenance risk.

The result therefore supports:

> Policies changed concrete implementation, validation, and refinement
> behavior in this run.

It does not support:

> The guided implementation was unconditionally better, or the effect
> generalizes to other tasks or runs.

## 9. Cross-Experiment Synthesis

### Evidence for RQ1

The current best selection design is:

1. Preserve an immutable, provenance-linked policy corpus.
2. Record whether the extracted surface is sufficient, ambiguous, or
   insufficient, with evidence and unresolved questions.
3. Let an LLM propose a compact set based on policy meaning and task context.
4. Validate all output against deterministic schemas, IDs, budgets, and
   authority rules.
5. Activate a compact generic security floor when no reliable specific match
   exists.
6. Record explicit coverage gaps and reassessment triggers.
7. Evaluate at the control level as well as the exact-policy-ID level.

The evidence argues against:

- relying only on broad inferred tags;
- always filling a policy budget;
- using task-family classification as the sole retrieval key;
- treating near-duplicate source IDs as distinct security outcomes;
- giving the selector model enforcement authority.

### Generic-floor design revision

The current deterministic implementation can return an empty specific
selection when extraction produces no matching evidence. PGACS now defines
three decision modes:

- `explicit`: evidence supports specific controls;
- `hybrid`: specific controls exist but material uncertainty remains;
- `fallback`: no reliable specific match exists.

`hybrid` and `fallback` decisions activate applicable policies from a compact
core floor: security-surface discovery, fail-safe implementation, and
evidence-based validation. These policies prevent silence under uncertainty but
cannot satisfy a missing known-mandatory capability. Later trajectory evidence
adds specific policies monotonically while redundant generic text can stop
being rendered.

This revision is implemented in the deterministic prototype. The registry now
contains the three core policies, task surfaces record status/evidence/unresolved
questions, and decisions report explicit/hybrid/fallback mode and safety-floor
budget accounting. The design and implementation record is in
`06-implementable-method/04-generic-security-floor-and-implementation-plan.md`.

### Evidence for RQ2

Evidence for phase distribution remains preliminary. The guided ZIP run used
one initial policy injection rather than phase-specific delivery. Nevertheless,
the effect appeared in several trajectory locations:

- initial threat framing;
- implementation constraints;
- adversarial test generation;
- post-test refinement;
- final security reporting.

This suggests selected policies can persist across a coding loop, but it does
not identify which delivery point caused which change. RQ2 requires a controlled
comparison between prompt-only guidance and harness-mediated checking/repair.

### Main methodological lesson

More defensive behavior is not automatically a better outcome. PGACS must
optimize **security-adjusted correctness**, which includes:

- required functional behavior;
- required security controls;
- useful defense in depth;
- compatibility;
- maintainability and public-API use;
- code and trajectory cost;
- evidence quality.

### BaxBench ten-task pilot revision

The completed prompt-only BaxBench pilot compared direct Claude, ordinary
Archon, and semantic policy-guided Archon on ten Python/FastAPI tasks. Under the
conservative joint criterion, results were 3/10, 5/10, and 4/10 respectively.
PGACS uniquely passed ImageTransfer and RegexSearch and prevented the ZipToTxt
CWE-400 exploit, but minimum-password hardening broke Login and UserCreation
functional fixtures. Several other cells were inconclusive because evaluators
assumed specific response fields, database paths, or temporary files.

This changes the prototype design in four ways:

1. selection and activation are separate stages;
2. contract-narrowing hardening defaults to advisory unless explicitly required;
3. evaluators return typed candidate/oracle outcomes; and
4. only candidate failures can consume the bounded repair attempt.

The full result and per-task adjudication are in
[`../14-baxbench-pilot/results.md`](../14-baxbench-pilot/results.md).

## 10. Current Claims and Non-Claims

### Supported claims

- The policy and task abstractions are implementable.
- Selection decisions can preserve provenance and be replayed.
- The first deterministic selector is measurable and explainable.
- The preserved semantic run produced a smaller selection and provides a
  concrete confounded baseline for the corrected rerun.
- Selected policies altered one observed coding trajectory.
- Independent probes reveal differences hidden by agent-authored tests.
- The fixed C2 pre-tool controls, trajectory observer, checker, repair boundary,
  evidence ledger, and terminal gate can be represented using existing Archon
  workflow primitives plus node-attributed tool logs.

### Unsupported claims

- PGACS improves security across coding tasks.
- The semantic selector has publication-grade precision or recall.
- The corrected selector outperforms the deterministic baseline without
  task-family metadata.
- The guided ZIP implementation is categorically superior.
- Prompt injection is sufficient enforcement.
- Dynamic policy adoption works.
- The fixed C2 repair mechanism improves outcomes; it has not yet been tested in
  an agent-backed run.
- The current corpus covers all important controls.
- The effects transfer across models, agents, repositories, or languages.

## 11. Threats to Validity

### Construct validity

- Exact policy IDs may undercount control-equivalent selections.
- Defense-in-depth probes can reward conservative incompatibility.
- Behavior labels indicate actions, not necessarily secure outcomes.
- Source-line and token counts measure cost imperfectly.

### Internal validity

- Selection comparisons changed both corpus and method.
- The trajectory comparison has one sample per condition.
- The task contained explicit security requirements.
- Model randomness was not estimated.
- The selected sandbox policy was operationally redundant.
- The trajectory run did not capture a resolved model identifier.

### External validity

- The trajectory task used Python and the standard library.
- No real existing codebase was modified.
- No multi-file application or live service was evaluated.
- No cross-model or cross-agent replication has been performed.

### Evaluation bias

- Policy labels and semantic adjudication are model-generated silver evidence.
- Evaluators encode researcher-selected expectations.
- Human security and maintainability review remains necessary before stronger
  claims.

## 12. Immediate Next Experiment

The next milestone should test whether the observed effect repeats and whether a
minimal harness adds value beyond prompt injection.

### 12.1 Experimental sample

**Current status: selected and source-pinned.** The sample is
[`../15-multibench-prototype/prototype-v0.1.json`](../15-multibench-prototype/prototype-v0.1.json):

| Source | Tasks | Role |
| --- | ---: | --- |
| BaxBench | 3 | Standalone backend generation and adapter regression |
| SWE-bench Verified | 3 | Django permissions, token invalidation, and authorization modification |
| SetupBench | 3 | Secure service, database, and persistent-tunnel configuration |

The task families cover credential storage and authentication, regex and
archive resource safety, password-recovery token invalidation, administrative
authorization, uploaded-file permissions, and secure service/database/tunnel
configuration.

The cohort was adjudicated before B0/C0/C1/C2 outputs. Prompt digests, source
revisions, mutation boundaries, security claims, and oracle requirements are
frozen. `selected` is not synonymous with `runnable`: six tasks still require
adapters and/or independent PGACS security oracles, while three BaxBench tasks
have concrete adapters but remain selected pending calibration receipts and an
OS-enforced agent/evaluator leakage boundary.

### 12.2 Conditions

Run four conditions with the same model, provider configuration, sandbox, task
artifact, and execution budget:

| Condition | Mechanism | Research purpose |
| --- | --- | --- |
| B0: Direct agent | Task only, without Archon | Measure provider behavior and isolate orchestration effects |
| C0: Archon baseline | Task only through ordinary Archon | Measure ordinary orchestrated-agent behavior |
| C1: Compatible policy prompt | Only activated obligations rendered at intake | Measure policy-information effect without known overconstraint |
| C2: Minimal harness | C1 plus typed checks and at most one candidate repair | Measure enforcement value beyond prompting |

First run one deterministic adapter/evaluator dry run per promoted task. Once
all nine tasks are runnable and the generation, repository-modification, and
environment-configuration adapter paths are stable, use at least three
independent runs per task and condition. The full four-condition study then
yields 108 trajectories. Report task-level
paired results; aggregate results must also be stratified by task and security
family.

### 12.3 Freeze before execution

For each task, freeze:

- source-lock entry and prompt digest;
- task text and repository snapshot;
- task workspace adapter version and preparation receipt;
- selected policy set and rationales;
- required functional tests;
- required security probes;
- optional defense-in-depth probes;
- compatibility cases;
- a public compatibility envelope and per-obligation activation plan;
- prohibited implementation shortcuts;
- allowed mutation paths without exposing exact gold-patch scope;
- execution and token budget;
- evaluator adapter version and container/image digest.

Keep gold patches, reference completions, task-specific vulnerability labels,
and evaluator implementations hidden from the coding agent. Upstream functional
tests, upstream security tests, and PGACS-authored independent probes are
separate evidence classes. Agent-authored tests remain trajectory evidence, not
the oracle. Before promotion, each required security oracle must fail a known-
insecure candidate and pass the trusted reference behavior.

### 12.4 Independent outcome classification

For every policy-induced change, assign one of:

- `beneficial`: improves a relevant control without material regression;
- `neutral`: reasonable but has no measured outcome effect;
- `overconstraining`: rejects required or reasonably compatible behavior;
- `brittle`: relies on unstable APIs, fragile assumptions, or narrow tests;
- `harmful`: introduces a functional or security regression.

The classification should be based on tests and review evidence, not the
agent's explanation.

### 12.5 Primary metrics

#### Outcome metrics

- functional pass rate;
- required-security probe pass rate;
- security-adjusted correctness;
- functional regression rate;
- overconstraint and brittle-change rates;
- activation conflict, advisory downgrade, and unresolved-input rates;
- residual vulnerability count and severity.

#### Trajectory metrics

- policy-relevant inspection and planning events;
- adversarial tests authored;
- static, test, and runtime verification attempts;
- failed-command recovery;
- insecure or security-preserving adaptations;
- evidence-backed completion claims.

#### Efficiency metrics

- selected-policy count;
- explicit, hybrid, and fallback selection rates;
- unresolved surface-question and later-resolution rates;
- prompt, input, output, and reasoning tokens;
- commands and repair iterations;
- elapsed time;
- source-size and complexity delta.

### 12.6 Analysis

Use the task as the pairing unit:

- compare C1-C0 to estimate policy-information effect;
- compare C2-C1 to estimate deterministic-enforcement effect;
- report per-family results instead of only aggregate means;
- report all runs, including failures and timeouts;
- use bootstrap confidence intervals where the sample supports them;
- perform qualitative error analysis for every regression.

Do not collapse required controls and optional hardening into one score.

### 12.7 Prototype decision rule

Advance the minimal harness only if:

1. C1 or C2 improves required-security outcomes across more than one task
   family;
2. improvements are not explained mainly by overconstraint;
3. functional regressions are uncommon and diagnosable;
4. C2 adds measurable value over C1;
5. token and iteration overhead remain proportionate to the observed benefit.

If C1 improves outcomes but C2 does not, continue researching selection and
phase rendering rather than adding runtime control. If neither improves
outcomes, revisit policy specificity and task matching before expanding the
harness.

## 13. Minimal Harness Implementation After Task Freezing

The first enforcement prototype should contain only four pieces.

### 13.1 Phase-local policy renderer

Render selected policies into three compact forms:

- implementation obligations;
- adversarial validation obligations;
- forbidden repair shortcuts.

Render only obligations admitted by the activation plan. Contract-narrowing
hardening remains advisory unless explicitly authorized. Avoid a full workflow
or continuous phase classifier. Intake rendering is enough for C1; C2 can
inject one corrective message after evaluation.

### 13.2 Deterministic policy checker

Each selected policy may contribute zero or more checks:

```ts
type PolicyCheck = {
  id: string;
  policyId: string;
  run: (workspace: string) => Promise<{
    status: 'pass' | 'fail' | 'inconclusive' | 'harness_error';
    evidence: string[];
  }>;
};
```

Checks should use existing tests, AST/static queries, configuration inspection,
or bounded runtime probes. They must not accept model prose as evidence.

### 13.3 One bounded repair loop

If an admissible required check reports a candidate failure:

1. provide the failed policy ID, observed evidence, and expected invariant;
2. allow one repair attempt;
3. rerun functional and policy checks;
4. record whether repair fixed the control, caused a regression, or attempted a
   forbidden shortcut.

An inconclusive idempotent oracle may be retried once by the harness. Persistent
inconclusive results and harness errors terminate without consuming the agent
repair budget.

One loop is enough to test the mechanism without building a heavy controller.

### 13.4 Evidence record

Persist:

- task and condition IDs;
- registry/corpus version;
- selected policies and rationales;
- rendered policy fragments;
- trajectory events;
- check results before and after repair;
- final functional/security outcome;
- token and command cost.

This record becomes the unit for later trajectory analysis.

## 14. Later Research Stages

Only after the nine-task prototype experiment should the prototype expand.

### Stage A: Phase distribution

Compare:

- all selected policies at intake;
- implementation/test-specific rendering;
- event-triggered reminders.

This directly addresses RQ2 without confounding it with tool denial.

### Stage B: Dynamic adoption

Add policies only when concrete events reveal new risks, such as:

- a dependency is added;
- a shell or SQL sink appears;
- a service begins listening;
- credentials enter scope;
- an insecure workaround is attempted.

Within a run, policy state should be monotonic: add or strengthen controls, but
do not silently remove them.

### Stage C: Runtime monitoring

Introduce passive diff/command monitors, followed by selected active probes.
Measure false positives and operational cost before any fail-closed behavior.

### Stage D: Loop conditioning

Test whether a targeted pre-repair reminder and invariant reduce insecure
adaptation after failures. This requires tasks designed to induce realistic
repair pressure.

### Stage E: Cross-agent replication

Repeat stable experiments with at least two coding-agent harnesses and more than
one model family. Separate model effects from PGACS effects.

### Stage F: Learned ranking

Consider an interpretable ranker only after collecting enough task, policy,
trajectory, and outcome records. Learning may rank within a deterministic safe
candidate set; it should not control enforcement or waive required policies.

## 15. Artifact Map

| Artifact | Location |
| --- | --- |
| Research foundation and behavior taxonomy | `01-foundation/research-foundation.md` |
| Implementable PGACS design | `06-implementable-method/` |
| Deterministic selector evaluation | `07-prototype-evaluation/` |
| Expanded policy corpus report | `08-expanded-principle-corpus/` |
| Semantic selector evaluation | `09-semantic-selector-evaluation/` |
| Paired coding trajectory experiment | `10-guided-trajectory-prototype/` |
| Normalized/generated policy data | `.archon/data/research/pgacs/` |
| Prototype implementation scripts | `scripts/*pgacs*` |

## 16. Reproduction

Run commands from the Archon repository root.

### Registry and deterministic selector

```bash
bun run scripts/generate-pgacs-research-artifacts.ts
bun run scripts/evaluate-pgacs-policy-selection.ts
```

### Expanded corpus and semantic selector

```bash
bun run scripts/build-pgacs-principle-corpus.ts
bun run scripts/run-pgacs-semantic-selector.ts
bun run scripts/evaluate-pgacs-semantic-selector.ts
```

The semantic-selection command invokes the configured model and can vary or
incur cost. Its evaluator is deterministic for frozen artifacts.

### Paired coding trajectory

```bash
# The runner requires a corrected semantic selection with integrity metadata.
bun run scripts/run-pgacs-semantic-selector.ts
bun run scripts/evaluate-pgacs-semantic-selector.ts
bun run scripts/run-pgacs-trajectory-prototype.ts

# The runner prints the new immutable run directory. To reevaluate the
# preserved historical implementation instead:
RUN_DIR=principle-guided-agent-research/archive/10-guided-trajectory-prototype/artifacts/runs/2026-07-27-zip-prototype

python3 principle-guided-agent-research/archive/10-guided-trajectory-prototype/evaluator/evaluate_zip_inspector.py \
  "$RUN_DIR/baseline/implementation/zip_inspector.py" \
  "$RUN_DIR/baseline/external-evaluation.json"

python3 principle-guided-agent-research/archive/10-guided-trajectory-prototype/evaluator/evaluate_zip_inspector.py \
  "$RUN_DIR/guided/implementation/zip_inspector.py" \
  "$RUN_DIR/guided/external-evaluation.json"

python3 principle-guided-agent-research/archive/10-guided-trajectory-prototype/evaluator/summarize_trajectories.py \
  "$RUN_DIR" \
  "$RUN_DIR/comparison.generated.json"
```

Running agent-backed commands creates new observations rather than reproducing
the exact stochastic trajectory. Frozen generated artifacts preserve the runs
reported here.

## 17. Recommended Immediate Work Order

1. Implement the compatibility envelope and per-obligation activation plan,
   using Login and UserCreation as regression fixtures.
2. Implement typed oracle outcomes and candidate-only repair routing, using
   Monitor, SecretStorage, and ZipToTxt exceptions as fixtures.
3. Route the existing ZIP task through `pgacs-smoke-v0.1` without changing its
   existing C2 behavior or evidence semantics.
4. Define minimal, separate `TaskWorkspaceAdapter` and `EvaluatorAdapter`
   contracts using ZIP and the existing BaxBench adapters as concrete callers.
5. Verify source locks and isolate evaluator material for all nine tasks.
6. Implement the SWE-bench workspace adapter and independent security oracles
   one task at a time.
7. Implement the SetupBench adapter and prove that its security oracle rejects
   a functional-but-insecure tunnel configuration.
8. Freeze semantic policy selections, activation plans, evaluator images,
   budgets, and analysis
   rules before any condition run.
9. Extend the runner to B0/C0/C1/C2 and three seeds, then execute all 108
    trajectories under identical budgets.
10. Generate task-level, family-stratified, and aggregate metrics.
11. Conduct blinded review of overconstraining, brittle, and harmful changes.
12. Decide whether evidence justifies PGACS-50, phase distribution, and dynamic
    adoption.

The cross-task experiment specification now begins with the frozen dataset
manifest, source lock, adjudication record, and readiness gates in
[`../13-smoke-dataset/`](../13-smoke-dataset/). The next deliverable is the
minimal shared task/evaluator implementation, not further task selection.
