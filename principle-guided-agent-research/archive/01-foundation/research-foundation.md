# Principle-Guided Agent Research Foundation

Date: 2026-07-09

## Purpose

This folder is the starting point for the next stage of the research project.

The project goal is to design a method that uses software engineering and
security principles to guide coding-agent behavior so agents produce code that
is both correct and secure.

The key research shift is:

```text
Do not evaluate only final code.
Evaluate how principles change the agent's coding trajectory.
```

The work already has two major inputs:

1. A principle/policy corpus collected from multiple security and engineering
   sources.
2. A behavior taxonomy derived from observed coding-agent trajectories on
   BaxBench-style code-generation tasks.

The next method should connect these two inputs:

```text
task context
  -> select relevant principles
  -> distribute selected principles across agent behavior phases
  -> enforce or remind at the right phase
  -> observe trajectory changes
  -> evaluate correctness and security outcomes
```

## Research Thesis

Coding agents fail at secure and correct coding not only because they lack
knowledge. They also fail because their behavior is weakly structured:

- they may inspect the wrong context;
- they may plan without explicit security constraints;
- they may implement before identifying trust boundaries;
- they may validate only builds, not behavior or security;
- they may repair failures using insecure shortcuts;
- they may report success without evidence.

Principles should therefore be treated as behavioral controls, not just prompt
content.

The proposed direction is:

```text
Principle-Guided Trajectory Control
```

This means principles are selected and placed where they can change a concrete
agent behavior, such as inspection, planning, implementation, validation,
failure diagnosis, refinement, adaptation, or reporting.

## Core Research Questions

### RQ1: How should the system optimize principle selection?

The system should choose the smallest useful principle set for a task. It
should not paste every principle into every prompt.

The selection problem is:

```text
Given a task, code context, API/environment specification, language/framework,
and risk hints, which principles are most relevant, specific, enforceable, and
cost-effective?
```

The output of selection should be a compact set of principles with metadata:

- why each principle was selected;
- which risk or task feature triggered it;
- which behavior phase should use it;
- how compliance can be checked;
- what evidence should be produced.

### RQ2: How should selected principles be distributed across coding phases?

The same principle should not always be repeated everywhere. A principle should
be applied where it can affect the agent's behavior.

For example, an input-validation principle should affect:

- inspection: find untrusted inputs and dangerous sinks;
- planning: define validation strategy and rejection behavior;
- implementation: add validation at trust boundaries;
- testing: add invalid/adversarial input tests;
- repair: avoid bypassing validation to make tests pass;
- reporting: show evidence of validation and tests.

The distribution problem is:

```text
Given a selected principle, which agent behavior phases should receive it, and
what should the agent do with it in each phase?
```

## Existing Inputs

### 1. Principle and Policy Resources

The repository already contains several principle/policy sources.

| Resource                                      | Path                                                                             | Current role                                                                                                        |
| --------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| OWASP Secure Coding Practices quick reference | `.archon/data/research/grasp-secure-coding/owasp-scp.md`                         | Flat secure-coding guidance used by the `secure-coding` workflow.                                                   |
| GRASP secure-coding graph                     | `.archon/data/research/grasp-secure-coding/scp-graph.json`                       | Structured principle graph used by the GRASP workflow for selecting and ordering principles.                        |
| Setup/environment security policies           | `.archon/data/research/secure-environment-setup/setup-environment-policies.json` | 84 setup/environment policies selected from a larger 869-policy source corpus.                                      |
| Secure environment setup workflow             | `.archon/workflows/research/secure-environment-setup.yaml`                       | Demonstrates policy selection, planning, implementation, functional validation, security validation, and reporting. |
| Secure coding workflow                        | `.archon/workflows/research/secure-coding.yaml`                                  | Injects the OWASP SCP reference into implementation and test-generation phases.                                     |
| GRASP workflow comparison                     | `reports/grasp-secure-coding/workflow-comparison.md`                             | Compares direct assist, flat secure-coding, and graph-based GRASP behavior.                                         |
| Secure environment setup comparison           | `reports/secure-environment-setup/docker-comparison.md`                          | Shows direct, default Archon, and secure workflow behavior on an autossh setup task.                                |

The setup/environment policy file records 84 selected policies across themes:

- endpoint/runtime hardening;
- least-privilege access;
- dependency and supply-chain integrity;
- process lifecycle;
- build/release integrity;
- configuration hardening;
- transport/network configuration;
- secrets/key management;
- logging/monitoring setup.

The OWASP secure coding reference covers categories including:

- input validation;
- output encoding;
- authentication and password management;
- session management;
- access control;
- cryptographic practices;
- error handling and logging;
- data protection;
- communication security;
- database security;
- file management;
- general coding practices.

The GRASP graph provides a structured form of the secure-coding principles. In
the current repo it contains 228 nodes, including high-level groups such as:

- Access Control;
- Authentication and Password Management;
- Communication Security;
- Cryptographic Practices;
- Data Protection;
- Database Security;
- Error Handling and Logging;
- File Management;
- General Coding Practices;
- Input Validation;
- Memory Management;
- Output Encoding;
- Session Management;
- System Configuration.

### 2. Agent Behavior Evidence

The new BaxBench summary report is:

`reports/baxbench_agent_behavior_codex.md`

It summarizes a separate recent study using BaxBench to observe coding-agent
trajectories during backend code-generation tasks.

Important note: this report currently references scripts, raw trajectories, and
taxonomy artifacts from another/local work area. The summary is useful for this
research repository, but the referenced BaxBench runner files and raw data are
not currently present in this checkout.

The BaxBench summary says the current baseline used:

- benchmark: BaxBench;
- agent: Codex CLI;
- model: `gpt-5.4-mini`;
- prompt condition: BaxBench task prompt, equivalent to `safety_prompt=none`;
- analyzed runs: 90;
- observed behavior-bearing events before filtering: 2131;
- analyzed substantive behavior events: 2052;
- excluded non-substantive residual events: 79.

The BaxBench report is valuable because it gives an empirical behavior model.
It tells us what coding agents commonly do, so principles can be placed into
real behavior slots rather than arbitrary prompt sections.

### 3. Existing Archon Comparison Evidence

The repository also contains smaller comparison reports:

| Report                                                | Path                                                                    | Relevance                                                                                           |
| ----------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Direct Codex vs manual Archon workflow on Python task | `reports/agent-behavior-comparison/archon-vs-codex-python-task.md`      | Shows how workflow phases create artifacts, fresh context boundaries, and deterministic validation. |
| Archon chat without explicit workflow                 | `reports/agent-behavior-comparison/archon-chat-bundled-python-task.md`  | Shows that Archon chat may behave like a normal coding agent when no workflow is selected.          |
| SWE-bench Django direct Sonnet vs Archon assist       | `reports/agent-behavior-comparison/swebench-django-sonnet-vs-archon.md` | Shows differences in validation and regression-test behavior on a real bug-fix task.                |
| Secure environment setup Docker comparison            | `reports/secure-environment-setup/docker-comparison.md`                 | Shows how a security workflow prevents unsafe completion behavior on a risky setup task.            |
| GRASP secure-coding comparison                        | `reports/grasp-secure-coding/workflow-comparison.md`                    | Shows how principle structure changes security-control coverage and runtime cost.                   |

These reports suggest that workflow structure changes the trajectory, not just
the final answer.

## Agent Behavior Taxonomy

The behavior taxonomy from the BaxBench summary should be treated as the
current phase vocabulary.

Each event gets exactly one primary process label and zero or more secondary
attribute labels.

### Primary Process Behaviors

| Behavior                        | Description                                                                                              | Why it matters for principle guidance                                                                                                                       |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `orientation`                   | The agent establishes task or workspace context.                                                         | Principles can guide early recognition of assets, trust boundaries, security-sensitive operations, and success criteria.                                    |
| `inspection`                    | The agent gathers information from files, directories, commands, package metadata, or environment state. | Principles can tell the agent what evidence to inspect before coding: inputs, sinks, auth paths, dependencies, config, secrets, logs, and runtime exposure. |
| `planning`                      | The agent states or selects an implementation strategy.                                                  | Principles can become explicit design constraints and acceptance criteria.                                                                                  |
| `implementation_writing`        | The agent creates, updates, or deletes implementation artifacts.                                         | Principles can be converted into concrete coding rules and required controls.                                                                               |
| `refinement`                    | The agent revises generated code for correctness, robustness, or edge cases.                             | Principles can guide hardening and prevent partial fixes.                                                                                                   |
| `verification_static`           | The agent runs formatting, syntax, lint, or source-level checks.                                         | Principles can require static checks relevant to the task, such as no dangerous APIs or no raw string interpolation.                                        |
| `verification_build`            | The agent builds, compiles, installs, or performs build-like validation.                                 | Principles can prevent unsafe build-time workarounds and preserve reproducibility.                                                                          |
| `verification_test`             | The agent runs automated tests or test commands.                                                         | Principles can require functional and adversarial tests tied to selected risks.                                                                             |
| `verification_runtime`          | The agent starts services or probes live endpoint behavior.                                              | Principles can require runtime checks for authentication, authorization, exposure, error behavior, and unsafe defaults.                                     |
| `failure_observation_diagnosis` | The agent observes or explains failed commands, errors, missing tools, or mismatches.                    | Principles can guide diagnosis toward root cause and prevent unsafe shortcuts.                                                                              |
| `adaptation`                    | The agent changes strategy in response to constraints or failed assumptions.                             | Principles can ensure strategy changes preserve security constraints.                                                                                       |
| `final_reporting`               | The agent summarizes completed artifacts, validation, and limitations.                                   | Principles can force evidence-based reporting and residual-risk disclosure.                                                                                 |

### Secondary Attribute Behaviors

| Attribute                           | Description                                                                                                                            | Why it matters                                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `defensive_coding`                  | Behavior concerns validation, escaping, normalization, limits, permission checks, secret handling, or other robustness/security logic. | This is the central attribute for measuring whether principle guidance increases security-relevant behavior. |
| `dependency_related`                | Behavior concerns packages, modules, frameworks, compilers, runtime libraries, or package metadata.                                    | Many secure/correct outcomes depend on dependency choice, versioning, and supply-chain handling.             |
| `environment_or_sandbox_constraint` | Behavior concerns network, permissions, cache, missing binaries, filesystem, or sandbox limits.                                        | Agents often adapt around environment constraints; guidance should prevent insecure environment workarounds. |
| `runtime_service_constraint`        | Behavior concerns service startup, port binding, HTTP probing, process lifetime, or live server behavior.                              | Backend/security tasks often fail or become unsafe at runtime, not only in source code.                      |

### Current BaxBench Behavior Counts

From the 90-run Codex baseline in the BaxBench summary:

| Primary process                 | Event count |
| ------------------------------- | ----------: |
| `inspection`                    |         416 |
| `failure_observation_diagnosis` |         355 |
| `verification_build`            |         260 |
| `refinement`                    |         238 |
| `implementation_writing`        |         158 |
| `orientation`                   |         148 |
| `final_reporting`               |         146 |
| `planning`                      |         135 |
| `adaptation`                    |          95 |
| `verification_static`           |          90 |
| `verification_test`             |           9 |
| `verification_runtime`          |           2 |

Secondary attributes:

| Secondary attribute                 | Event count |
| ----------------------------------- | ----------: |
| `dependency_related`                |         426 |
| `environment_or_sandbox_constraint` |         277 |
| `runtime_service_constraint`        |         217 |
| `defensive_coding`                  |         202 |

Important interpretation:

- agents inspect and diagnose failures frequently;
- build verification is common;
- explicit automated tests and runtime probes are rare;
- defensive coding appears even without explicit security reminders, but it is
  not necessarily complete or sufficient;
- principle-guided workflows should amplify useful behaviors and fill missing
  behaviors, especially security testing and runtime validation.

## Principle Selection Problem

Principle selection should be optimized for relevance, specificity, and
enforceability.

### Inputs for Selection

The selector should use as much task evidence as is available:

| Input                      | Examples                                                                           | Why it matters                                                               |
| -------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Task type                  | backend API, file parser, auth flow, environment setup, CLI tool, database feature | Different task types imply different risk surfaces.                          |
| Language and framework     | Django, FastAPI, Express, Rails, Go Fiber, Actix, Lumen                            | Frameworks imply different secure defaults, idioms, and validation patterns. |
| External inputs            | request params, JSON body, files, headers, env vars, CLI args                      | Untrusted input is the source of many security risks.                        |
| Dangerous sinks            | SQL, shell, filesystem, template rendering, deserialization, network calls         | Risks depend on where data flows.                                            |
| Assets                     | secrets, tokens, credentials, PII, auth state, local files, service ports          | Asset sensitivity should raise principle priority.                           |
| Trust boundaries           | client/server, remote/local, user/admin, public/private network                    | Determines where validation, auth, and logging controls belong.              |
| Dependencies               | package manager, external libraries, system packages, services                     | Determines supply-chain and environment hardening principles.                |
| Benchmark metadata         | CWE hints, security labels, BaxBench potential CWEs, SecurityDebt labels           | Useful risk hints, but should not be the only selector input.                |
| Existing codebase evidence | current patterns, tests, configs, previous vulnerabilities                         | Helps avoid generic principles and choose locally relevant ones.             |
| Runtime environment        | sandbox, Docker, root/non-root, ports, missing tools, network limits               | Determines whether environment principles are needed.                        |

### Selection Criteria

Each candidate principle should be scored or filtered by:

| Criterion         | Question                                                            |
| ----------------- | ------------------------------------------------------------------- |
| Relevance         | Does the principle address a risk surface present in this task?     |
| Specificity       | Is it concrete enough to guide code or validation?                  |
| Enforceability    | Can compliance be tested, inspected, or evidenced?                  |
| Phase fit         | Which behavior phase can use it?                                    |
| Severity          | What happens if the principle is ignored?                           |
| Cost              | Does it add complexity, runtime overhead, or implementation burden? |
| Conflict risk     | Does it conflict with task requirements or another principle?       |
| Local consistency | Does it match existing framework/project conventions?               |

The selector should avoid two failure modes:

1. **Principle overload:** injecting too many generic principles, causing the
   agent to ignore or shallowly satisfy them.
2. **Principle under-selection:** selecting only obvious principles and missing
   task-specific risks such as path traversal, insecure deserialization, or
   unsafe process execution.

### Candidate Principle Metadata

Principles should eventually be represented with metadata like:

```json
{
  "id": "OWASP-IV-001",
  "source": "OWASP Secure Coding Practices",
  "category": "Input Validation",
  "principle": "Validate all input server-side; never trust client-supplied data.",
  "risk_tags": ["input-validation", "injection", "trust-boundary"],
  "task_triggers": ["http_request", "json_body", "query_param", "file_upload", "cli_arg"],
  "dangerous_sinks": ["sql", "shell", "filesystem", "template", "deserialization"],
  "enforceability": "testable",
  "phase_bindings": [
    "inspection",
    "planning",
    "implementation_writing",
    "verification_test",
    "failure_observation_diagnosis",
    "final_reporting"
  ],
  "evidence_expectations": [
    "identified input sources",
    "validation code",
    "negative tests",
    "report of rejected cases"
  ]
}
```

This metadata makes principles selectable and distributable rather than static
prompt text.

## Principle Distribution Problem

Distribution means deciding where and how a selected principle should affect
the agent.

The same principle should appear differently in different phases:

- as an inspection checklist;
- as a planning constraint;
- as an implementation rule;
- as a test requirement;
- as a repair guardrail;
- as final evidence.

### Behavior-Phase Distribution Map

| Agent behavior                  | Principle role                                                                                                       | Expected agent evidence                                                              |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `orientation`                   | Identify the task class, asset sensitivity, and likely risk families.                                                | Short risk framing and success criteria.                                             |
| `inspection`                    | Direct evidence gathering: inputs, sinks, dependencies, configs, auth checks, file paths, logging, runtime exposure. | File/line references, commands, discovered surfaces.                                 |
| `planning`                      | Convert principles into design constraints and validation criteria.                                                  | Plan section listing selected principles and concrete controls.                      |
| `implementation_writing`        | Apply principles as coding rules.                                                                                    | Source changes implementing controls close to trust boundaries.                      |
| `refinement`                    | Harden edge cases and repair incomplete controls.                                                                    | Diffs that close bypasses, improve error behavior, or reduce risk.                   |
| `verification_static`           | Check source-level compliance.                                                                                       | Lint/static/security scan output, dangerous API search, generated type/build checks. |
| `verification_build`            | Confirm reproducible build/install without unsafe shortcuts.                                                         | Build logs and dependency/install evidence.                                          |
| `verification_test`             | Run functional and adversarial tests tied to selected principles.                                                    | Test names, commands, pass/fail results.                                             |
| `verification_runtime`          | Probe live service behavior when relevant.                                                                           | HTTP/runtime checks for auth, validation, exposure, and error behavior.              |
| `failure_observation_diagnosis` | Diagnose root cause while preserving security constraints.                                                           | Explanation that avoids bypassing selected principles.                               |
| `adaptation`                    | Ensure any workaround still satisfies selected principles.                                                           | Revised plan and reason why security constraints still hold.                         |
| `final_reporting`               | Report principle compliance and residual risks.                                                                      | Evidence table: principle, control, validation, residual risk.                       |

### Example: File Parsing Task

Task shape:

```text
Implement a function that loads a YAML file from a tmp directory using a
filename parameter.
```

Likely selected principles:

- validate untrusted input;
- restrict file paths to an allowed directory;
- reject path traversal and null bytes;
- allowlist file extensions;
- use safe YAML parsing;
- avoid leaking internal filesystem paths in error messages;
- add negative tests for traversal and invalid content.

Phase distribution:

| Phase                           | Principle use                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------------- |
| `inspection`                    | Identify filename as untrusted input and filesystem/YAML parser as dangerous sinks.               |
| `planning`                      | Decide on allowlist, path canonicalization, safe loader, and generic errors.                      |
| `implementation_writing`        | Implement `safe_load`, `realpath`/`relative_to`, extension allowlist, and controlled exceptions.  |
| `verification_test`             | Add tests for `../`, null byte, absolute path, wrong extension, non-mapping YAML, malformed YAML. |
| `failure_observation_diagnosis` | If tests fail, fix validation logic, not tests.                                                   |
| `final_reporting`               | List controls and tests.                                                                          |

This task corresponds to the GRASP comparison in
`reports/grasp-secure-coding/workflow-comparison.md`.

### Example: Environment Setup Task

Task shape:

```text
Install autossh and configure a persistent reverse tunnel from remote port 9000
to localhost:22.
```

Likely selected principles:

- require explicit trust inputs before activation;
- enforce host-key verification;
- avoid generating unmanaged credentials;
- use least privilege;
- bind remote listener narrowly;
- configure supervision only after validation;
- log without leaking secrets;
- fail closed on missing inputs.

Phase distribution:

| Phase                           | Principle use                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `orientation`                   | Recognize persistent remote access path as high risk.                             |
| `inspection`                    | Check whether remote host, user, identity key, and known-hosts are provided.      |
| `planning`                      | Decide fail-safe static configuration if trust inputs are missing.                |
| `implementation_writing`        | Create service/user/preflight gate; do not start tunnel.                          |
| `verification_static`           | Verify unit syntax and environment file permissions.                              |
| `verification_runtime`          | Confirm preflight blocks activation when inputs are missing.                      |
| `failure_observation_diagnosis` | Do not invent localhost/root SSH as a substitute for missing remote trust inputs. |
| `final_reporting`               | Report fail-safe status and operator-required inputs.                             |

This task corresponds to
`reports/secure-environment-setup/docker-comparison.md`.

## Proposed Method Architecture

The future workflow should be designed around a principle-to-behavior pipeline:

```text
1. Task Intake
   Parse task, benchmark metadata, codebase context, and environment.

2. Risk and Surface Classification
   Identify task type, inputs, sinks, assets, trust boundaries, dependencies,
   runtime exposure, and likely CWEs.

3. Principle Retrieval
   Retrieve candidate principles from OWASP, GRASP, setup policies, and other
   policy sources.

4. Principle Ranking and Selection
   Score candidates by relevance, specificity, enforceability, severity, cost,
   and phase fit.

5. Principle-to-Phase Distribution
   Convert selected principles into phase-specific instructions and evidence
   requirements.

6. Agent Execution
   Run coding phases with the right principles injected at the right time.

7. Validation and Repair
   Run functional, build, static, test, runtime, and security checks as
   appropriate.

8. Trajectory Logging and Labeling
   Capture normalized steps and label them with the behavior taxonomy.

9. Outcome Evaluation
   Evaluate correctness and security with benchmark tests, scans, or human
   review.

10. Analysis
   Compare baseline vs principle-guided trajectories and outcomes.
```

## What Needs To Be Built Next

### 1. Unified Principle Registry

Create a normalized registry that combines principles from:

- OWASP SCP;
- GRASP graph;
- setup/environment policies;
- future BaxBench/CWE-specific policy mappings;
- project-specific engineering rules.

The registry should include:

- principle ID;
- source;
- category/theme;
- text;
- risk tags;
- task triggers;
- dangerous sinks;
- applicable languages/frameworks if known;
- phase bindings;
- validation strategies;
- evidence requirements.

### 2. Task Surface Extractor

Build a task/context classifier that extracts:

- task type;
- language/framework;
- input channels;
- output contexts;
- dangerous sinks;
- assets;
- trust boundaries;
- dependencies;
- environment constraints;
- likely CWE categories.

This can begin as an LLM-assisted structured-output step and later be evaluated
against manually labeled tasks.

### 3. Principle Selector

Build a selector that maps task surfaces to principles.

Possible selection strategies:

1. rule-based tags;
2. retrieval over principle text;
3. graph traversal from risk seed nodes;
4. hybrid scoring;
5. learned ranking after enough annotated data exists.

The immediate research version should start with a transparent hybrid:

```text
rule-based trigger match
  + source/risk tag match
  + graph-neighborhood expansion
  + enforceability filter
  + compact top-k selection
```

### 4. Phase Distributor

Build a phase-binding generator that converts selected principles into:

- inspection questions;
- planning constraints;
- implementation rules;
- validation tests;
- repair guardrails;
- reporting evidence.

This is the central answer to RQ2.

### 5. Trajectory Measurement

Use the BaxBench behavior taxonomy to measure:

- whether principle guidance increases targeted behaviors;
- whether `verification_test` and `verification_runtime` become more common;
- whether `defensive_coding` becomes more task-specific;
- whether repeated failure loops decrease;
- whether adaptation preserves security constraints;
- whether final reporting includes stronger evidence.

### 6. Outcome Measurement

Trajectory changes are not enough. The method must also measure final outcomes:

- functional correctness;
- benchmark pass/fail;
- security test pass/fail;
- vulnerability scan results where applicable;
- human security review for sampled tasks.

## Hypotheses

The next experiments can test hypotheses such as:

1. Principle-guided workflows increase `defensive_coding` events compared with
   baseline BaxBench prompts.
2. Principle-guided workflows increase `verification_test` and
   `verification_runtime` events, which are rare in the baseline.
3. Phase-distributed principles produce better security outcomes than a flat
   "secure coding principles" prompt.
4. Over-selection of principles increases runtime and may reduce correctness by
   distracting the agent.
5. Graph-based or risk-based selection improves security-control coverage
   compared with injecting a full flat principle list.
6. Repair guardrails reduce insecure adaptations after build/runtime failures.

## Experimental Conditions To Compare

The research should compare at least these conditions:

| Condition                             | Description                                           | Purpose                                                 |
| ------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------- |
| Baseline                              | Original benchmark prompt only.                       | Observe normal agent behavior.                          |
| Generic security reminder             | Benchmark prompt plus generic secure-coding reminder. | Test whether broad security nudges help.                |
| Specific risk reminder                | Prompt includes task-specific risks or CWE hints.     | Test whether explicit risk hints help.                  |
| Flat principle injection              | Inject a broad secure-coding list.                    | Compare against existing `secure-coding` style.         |
| Selected principles only              | Select compact relevant principles.                   | Test RQ1.                                               |
| Phase-distributed selected principles | Apply selected principles across behavior phases.     | Test RQ2 and full method.                               |
| Archon workflow/harness               | Enforce phases, artifacts, validation, and reporting. | Test whether structure changes trajectory and outcomes. |

## Metrics

### Selection Metrics

- number of principles selected per task;
- precision of selected principles against human judgment;
- recall of critical missing principles;
- prompt/token cost;
- source diversity;
- selected principle enforceability.

### Distribution Metrics

- phase coverage: how many selected principles are bound to useful phases;
- behavior coverage: whether relevant phases receive guidance;
- evidence completion: whether the agent produces expected artifacts;
- over-distribution: whether principles are repeated in phases where they do not
  matter.

### Trajectory Metrics

- primary behavior frequency shifts;
- secondary attribute shifts;
- transition changes, such as fewer failure-refine loops or more plan-test
  transitions;
- number of verification attempts;
- number of security/adversarial tests;
- number of insecure adaptations;
- evidence quality in final reports.

### Outcome Metrics

- functional pass rate;
- security pass rate;
- vulnerability count/severity;
- false sense of completion rate;
- runtime/cost overhead;
- human review findings.

## Risks and Design Constraints

### Avoid Principle Dumping

The method should not simply add a long policy list to every prompt. The GRASP
comparison already suggests that full graph or full policy injection can be
expensive. Selection must be compact and task-sensitive.

### Avoid Measuring Only Self-Reports

Agent final messages are not reliable evidence by themselves. The system must
record commands, file edits, tests, and independent validation results.

### Avoid Treating Security Behavior as Security Success

An event labeled `defensive_coding` means the agent performed a
security-relevant behavior. It does not prove the generated code is secure.
Trajectory metrics must be paired with outcome metrics.

### Avoid Unsafe Benchmark Completion

The secure environment setup comparison showed that a model can complete a
task by inventing unsafe missing inputs, disabling host-key checks, or creating
root credentials. Workflows must prefer fail-safe behavior when required trust
inputs are absent.

### Preserve Correctness

Security guidance should not make the agent over-engineer, break framework
idioms, or fail normal functional requirements. Correctness and security must
be jointly evaluated.

## Immediate Next Steps

1. Move or link the BaxBench summary into the organized agent-behavior report
   area, or explicitly keep it as an external-study note.
2. Normalize the current principle resources into a single principle registry
   schema.
3. Add phase-binding metadata for a first small set of principle categories:
   input validation, file management, error handling/logging, access control,
   dependency/supply-chain, and environment setup.
4. Build a small manual benchmark of 10-20 tasks with human-selected principle
   sets to evaluate selection quality.
5. Implement a prototype selector and phase distributor.
6. Run matched experiments on a BaxBench slice:
   baseline vs generic reminder vs selected principles vs phase-distributed
   principles.
7. Label trajectories using the BaxBench behavior taxonomy.
8. Compare behavior changes and final correctness/security outcomes.

## Working Definition

For this project, a principle-guided agent method is successful only if it can
show both:

```text
1. Better behavior:
   The agent more consistently performs useful secure/correct coding behaviors
   at the right phases.

2. Better outcomes:
   The generated artifacts are more correct and secure under independent
   validation.
```

The central contribution is therefore not "a better security prompt." It is a
method for selecting principles, distributing them across real agent behaviors,
and measuring whether those interventions improve secure and correct coding.
