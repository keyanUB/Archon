# PGACS — Detailed Design & Decision Record

Implementation status (2026-08-03): this remains the full-system conceptual
specification. The narrower, as-built prototype authority is
[`../15-multibench-prototype/technical-design.md`](../15-multibench-prototype/technical-design.md).
Unimplemented capabilities in this document, including continuous event-level
probing and live dynamic policy selection, must not be inferred from the
prototype.

This document is the authoritative, build-from specification for the **Policy-Guided Agent Control System (PGACS)**. It systematically explains the approach, defines every component and interface, walks the runtime behavior, and records each significant design decision with its rationale, alternatives, consequences, and the conditions under which it should be revisited.

---

<!-- ## Table of Contents

1. Purpose, Audience, Scope
2. Problem Statement, Goals, Non-Goals
3. Design Principles (the constraints we hold ourselves to)
4. Conceptual Model & Terminology
5. System Overview
6. Component Design
7. Data Model & Interfaces
8. Runtime Behavior (control flow)
9. Decision Records (ADRs)
10. Failure Modes & Mitigations
11. Threat Model: Securing the Harness Itself
12. Extensibility Guide
13. Deliberately Out of Scope (YAGNI)
14. Build Plan & Milestones
15. Open Questions
16. Glossary

--- -->

## 1. Purpose, Audience, Scope

**Purpose.** Define a system that improves the _security_ of code produced by AI coding agents by converting security/engineering principles into executable policies and enforcing them across the agent's coding lifecycle — without depending on any single agent, LLM, or benchmark.

**Audience.** Engineers building the system; researchers designing the evaluation; reviewers assessing the approach.

**In scope.** The methodology and system architecture: the policy model, the enforcement layers, the controller, adapters, packs, and the interfaces between them.

**Out of scope (handled elsewhere).** Experimental design (benchmarks, datasets,multi-agent/multi-LLM comparisons,statistics); the specific content of any security policy corpus beyond illustrative examples; production deployment and ops.

---

## 2. Problem Statement, Goals, Non-Goals

### 2.1 Problem

Coding agents produce measurably insecure code (see the pitch's evidence base). The security knowledge needed to catch these issues is increasingly _not_ in the human operator's head, and it is _not reliably_ in the model either. Existing mitigations are **advisory** (a secure-coding prompt) or **post-hoc** (a scanner after the run) and do not control the agent's trajectory. Security fails at specific _moments_ — writing to a sink without validation, weakening a control under failure pressure, claiming success without evidence — and nothing today intervenes at those moments in an agent-agnostic, auditable way.

### 2.2 Goals

- **G1 — Behavioral enforcement.** Bind the right principle to the specific agent behavior/moment where it can change the outcome, and enforce it from outside the model.
- **G2 — Agent- and LLM-agnostic.** Work across Claude Code, Codex, SWE-Agent, Aider, and raw SDK loops, adapting enforcement strength to what each exposes.
- **G3 — Auditable & reproducible.** Every security decision and claim traces to a deterministic rule and observed evidence.
- **G4 — Compact & targeted.** Apply a small, task-relevant policy set; avoid full-corpus prompt dumping.
- **G5 — Dynamic.** Adapt the active policy set as new risks appear mid-run.
- **G6 — Extensible.** Support new task families (including non-code-generation) by writing plug-ins, not editing the core.
<!-- - **G7 — Buildable incrementally.** A thin core delivers value in weeks; every
  later capability is an addition at a stable seam. -->

<!-- ### 2.3 Non-Goals

- **NG1.** Not a fine-tuned or RL-trained "secure model." We change the control
  structure around the model, not the model's weights.
- **NG2.** Not a replacement for human security review; it raises the floor and
  produces evidence for review.
- **NG3.** Not a general correctness prover. Functional correctness is measured
  and protected, but the primary contribution is security enforcement.
- **NG4.** Not tied to one benchmark. Benchmarks are evaluation instruments,
  not part of the method. -->

<!-- ### 2.4 Success Criteria (method-level)

The method succeeds if, holding the agent fixed, PGACS (a) produces a complete
evidence ledger, (b) prevents at least the classes of unsafe shortcut we observe
in baselines, and (c) does so **beyond what simply running every validator would
achieve** — i.e., selection and binding add value over a "run everything"
baseline. (The full evaluation lives in a separate document.) -->

---

## 3. Design Principles

These are the constraints we hold ourselves to. Each maps to decisions in §9.

- **P1 — The harness owns security state, never the model.** LLMs advise; they do not decide enforcement.
- **P2 — Separate declaration from mechanism.** _What_ a policy requires is data; _how_ it is enforced is code. One policy feeds all enforcement channels.
- **P3 — Assume nothing about the agent's internals.** Communicate only through a normalized event/intervention bus; adapt to declared capabilities.
- **P4 — Evidence over assertion.** No security claim without harness-observed evidence.
- **P5 — Monotonic safety within a run.** Policy state can only tighten during a run; relaxation requires a human.
- **P6 — Fail safe, not fail open.** For high-risk ambiguity, safe blocking is a correct outcome.
- **P7 — Compact over comprehensive.** Prefer a small enforceable set to a large advisory one.
- **P8 — Determinism at the gate.** Enforcement decisions are reproducible and explainable; only perception may be probabilistic.
- **P9 — Extend by plug-in, not by fork.** The core is stable; domains are packs.
- **P10 — Graceful degradation.** Reduced agent capability reduces enforcement strength, never correctness of what _is_ enforced.

---

## 4. Terminology & Agent Coding Lifecycle

| Term                   | Definition                                                                                                                                                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Principle**          | A human-readable secure-engineering rule (OWASP, GRASP, CWE, NIST, project standard). Source material.                                                                  |
| **Policy**             | An executable object derived from ≥1 principle: activation conditions + per-layer handlers + severity + evidence requirements. The operational unit.                    |
| **Control**            | A concrete obligation a policy imposes ("reject `../` before filesystem access").                                                                                       |
| **Intervention point** | A moment in the agent's run where a policy can change behavior (a tool call, an edit, a phase transition, a repair boundary).                                           |
| **Surface**            | The security-relevant shape of a task/trajectory: input channels, sinks, assets, trust boundaries, actions, runtime exposure. The vocabulary packs and selection speak. |
| **Phase**              | A behavior category (orientation, inspection, planning, implementation, verification, repair, reporting). A _soft signal_, not a rigid gate.                            |
| **Evidence**           | A harness-observed fact (diff, command result, test outcome, probe result, static finding).                                                                             |
| **Adapter**            | A translator between one agent and the bus; declares capabilities.                                                                                                      |
| **Pack**               | A plug-in bundle of policies + monitors + probes + invariants for a task family.                                                                                        |
| **PolicyState**        | The controller's live, monotonic set of active policies + their bindings + evidence status for one run.                                                                 |

Relationship: `principles → (compiled into) policies → (grouped into) packs`; at runtime `task/trajectory → surface → selected PolicyState → enforced via three layers → evidence → terminal status`.

### Agent Behavior Taxonomy

Each behavior-bearing event admitted to the taxonomy gets exactly one primary
process label and zero or more secondary attribute labels. Events without
sufficient deterministic evidence remain explicitly unclassified rather than
receiving a guessed label.

The v0.3 C2 prototype implements a versioned deterministic subset for inspection,
implementation writing, verification command classes, repair-boundary
adaptation, and final reporting. Its current Archon adapter emits tool calls and
repair boundaries only. Labels are observational metadata and may select prompt
wording; they do not activate policy, satisfy evidence, or decide the gate.

This process taxonomy is distinct from **security behavior predicates**. A
security predicate is a narrow, versioned rule over normalized events and typed
repository facts, is bound to a pre-adjudicated policy, and has a frozen set of
permitted interventions. Such predicates may activate dormant obligations,
require probes, or deny explicit capability/scope violations under ADR-18. They
still cannot satisfy outcome evidence or decide that a candidate is correct.

#### Primary Process Behaviors

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

#### Secondary Attribute Behaviors

| Attribute                           | Description                                                                                                                            | Why it matters                                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `defensive_coding`                  | Behavior concerns validation, escaping, normalization, limits, permission checks, secret handling, or other robustness/security logic. | This is the central attribute for measuring whether principle guidance increases security-relevant behavior. |
| `dependency_related`                | Behavior concerns packages, modules, frameworks, compilers, runtime libraries, or package metadata.                                    | Many secure/correct outcomes depend on dependency choice, versioning, and supply-chain handling.             |
| `environment_or_sandbox_constraint` | Behavior concerns network, permissions, cache, missing binaries, filesystem, or sandbox limits.                                        | Agents often adapt around environment constraints; guidance should prevent insecure environment workarounds. |
| `runtime_service_constraint`        | Behavior concerns service startup, port binding, HTTP probing, process lifetime, or live server behavior.                              | Backend/security tasks often fail or become unsafe at runtime, not only in source code.                      |

---

## 5. System Overview

```text
                      ┌──────────────────────────────────────────────-┐
     task (+ repo)───►│              PolicyController                 │
                      │  • select()  → PolicyState v0                 │
                      │  • ingest(event) → reassess() → deltas        │
                      │  • drives Layers A/B/C from PolicyState        │
                      │  • owns EvidenceLedger                         │
                      │  • gate() → TerminalStatus                     │
                      └──────▲───────────────────────────┬────────────┘
                             │ ObservationEvent           │ Intervention
                      ┌──────┴───────────────────────────▼────────────┐
                      │                 AgentAdapter                   │
                      │   capabilities {inject, interceptTools,        │
                      │                 driveSteps}                    │
                      └──────▲───────────────────────────┬────────────┘
                             │                            │
                   ANY CODING AGENT (Claude Code · Codex · Cursor · Aider · SDK)

     Packs ──► register Policies into the Selector & Layers.
     Layers A (prompt) / B (monitor+probe) / C (loop conditioning) subscribe to PolicyState.
```

The design is a **hub-and-spokes**: the controller is the hub holding all state
and authority; adapters, packs, and layers are spokes with narrow contracts.

---

## 6. Component Design

### 6.1 The Bus

Two message families flow over the bus. The bus itself is transport-agnostic (in-process function calls for a driver adapter; a socket/log tail for others).

- **ObservationEvent** — normalized facts the adapter extracts from the agent.
- **Intervention** — actions the controller asks the adapter to apply.

The bus is the _only_ coupling point between the controller and any agent. This is what makes the controller reusable across agents (G2, P3).

### 6.2 AgentAdapter

An adapter wraps exactly one agent runtime and declares three boolean capabilities:

- `inject` — can add context to the agent mid-run (system prompt, file, message).
- `interceptTools` — can see and gate tool calls _before_ they execute.
- `driveSteps` — can pause/resume the agent between phases (full control).

**Adapter catalog** (cheapest → strongest):

| Adapter     | inject | interceptTools | driveSteps | Notes                                                                                           |
| ----------- | :----: | :------------: | :--------: | ----------------------------------------------------------------------------------------------- |
| Log/diff    |   ✗    |       ✗        |     ✗      | Tails logs / reads final diff. Works for _anything_. Enforcement = post-hoc verify + re-prompt. |
| Context     |   ✓    |       ✗        |     ✗      | Writes `AGENTS.md`/`CLAUDE.md`/system prompt.                                                   |
| Hook/broker |   ✓    |       ✓        |     ✗      | Claude Code hooks, an MCP tool-proxy, or a shell/PTY shim. Real-time gating.                    |
| Driver      |   ✓    |       ✓        |     ✓      | Archon workflow. Full phase gating.                                                             |

The controller queries `capabilities` and each layer degrades accordingly (P10).
A layer that needs a capability the adapter lacks announces the reduced
enforcement in the run metadata (so it is measurable, never silent).

### 6.3 PolicyController

The single authority. Responsibilities:

1. **Surface extraction** → build the initial `TaskSurface`.
2. **Selection** → propose a compact `SelectedPolicySet`.
3. **Compatibility adjudication** → produce a frozen per-obligation
   `PolicyActivationPlan`; contract-narrowing hardening is advisory by default.
4. **Distribution** → materialize bindings only for activated obligations.
5. **Event ingestion** → route every `ObservationEvent` to Layer B monitors and
   to `reassess()`.
6. **Dynamic adoption** → compute `PolicyDelta`s; tighten `PolicyState`
   (monotonic).
7. **Loop conditioning** → run the predict-then-condition step at repair
   boundaries (Layer C).
8. **Evidence ledger** → append observed evidence; never accept model prose as
   evidence.
9. **Gate** → compute the deterministic `TerminalStatus`.

The controller is a **pure reducer** at heart: `(PolicyState, Event) → (PolicyState', Intervention[])`.
Purity makes it testable and replayable (P8, G3).

### 6.4 Policy & the Three Handlers

A `Policy` is declaration + three optional handlers, one per layer (P2):

- `prompt(ctx)` → a `PromptFragment` rendered for the current phase (Layer A).
- `monitors[]` → per-event classifiers producing `Signal`s + evidence (Layer B).
- `invariants[]` → predicates over repo state that must hold across repairs
  (Layer C).

A policy need not implement all three; a purely advisory policy has only
`prompt`. A policy with strong detective coverage has `monitors` + `invariants`.

### 6.5 Layer A — Prompt (proactive/preventive)

- Renders **phase-appropriate slices** of the active policies into whatever channel the adapter supports.
- **Phase-conditioned**: the same policy renders as an inspection question early and an implementation rule later. Phase comes from `phase_hint` events or a lightweight classifier; it is advisory routing, not a gate.
- If `inject:false`, Layer A front-loads all guidance into the initial context.
- Budgeted: policies active in state are not all re-rendered every turn.

### 6.6 Layer B — Monitor & Probe (detective; the evidence source)

- **Passive monitors** (always on, cheap): deterministic regex/AST/heuristic over each `file_edit`/`command_run`/`dependency_added` event. Emit `safe|suspicious|violation` + an `EvidenceItem`.
- **Active probes** (armed on demand, expensive): actually exercise the artifact — start the service and issue an unauthenticated request, feed a traversal
  payload, run the security test, check a fail-safe preflight. Scheduled by
  Layer C, not run blindly.
- All monitor/probe output lands in the `EvidenceLedger`. Model prose never does (P4).

### 6.7 Layer C — Loop Conditioning (corrective/predictive)

The controller runs this at each **loop boundary** (a failure→retry transition, or an adapter-signaled step boundary):

```text
1. STATE   gather: events so far, active policies, satisfied vs missing
           evidence, recent failure signals, retry count.
2. PREDICT estimate next-step risk (rules now; learned predictor later).
           e.g. "build failed + required validation policy unsatisfied
                 → high risk the agent weakens validation."
3. CONDITION emit interventions BEFORE the agent acts:
           reinforce a policy, arm a probe, harden severity, or
           (broker) pre-deny the tool it is about to use.
4. INVARIANT after the step, evaluate each active invariant on the diff.
           A violated invariant → rollback / re-prompt, never silent.
```

Combined with **monotonic hardening** (P5), this closes the most damaging failure mode: insecure adaptation under failure pressure.

### 6.8 Evidence Ledger

Append-only, harness-owned. One entry per (policy, required control), tracking expected vs observed evidence and a status in `pass | fail | unknown | blocked | not_applicable`. The final report and the gate read **only** from the ledger. Provider errors (rate limits, empty output, malformed JSON) map to `unknown`/`blocked`/`fail` — never `pass` (P4).

### 6.9 Selector & Mechanism Split

Selection is a pipeline (§7.4). The mechanism is split by function (ADR-7):

- **Perception/proposal** — LLM structured-output + retrieval + graph expansion.
- **Safety-critical triggers** — deterministic rules (100% recall on the
  known-critical set).
- **Uncertainty floor** — deterministic activation of compact core fallback
  policies when no reliable specific match exists (ADR-14).
- **Enforcement** — deterministic only.
- **Semantic checks** — critic LLM, output = evidence, gated by rules.
- **Optimization (later)** — decision-tree/GBDT ranker over the safe candidate
  set.

### 6.10 Packs & Surface Vocabulary

A pack contributes domain content over a **fixed surface vocabulary**, so the core never changes when a new domain is added (P9, G6). Packs carry a trust tier (ADR-11).

---

## 7. Data Model & Interfaces

TypeScript-flavored; illustrative, not final. Naming follows the repo's Zod conventions when implemented (`z.infer`, camelCase).

### 7.1 Bus messages

```ts
type BehaviorPhase =
  | 'orientation'
  | 'inspection'
  | 'planning'
  | 'implementation'
  | 'verification'
  | 'repair'
  | 'reporting';

type ObservationEvent =
  | { kind: 'tool_call'; tool: string; args: unknown }
  | {
      kind: 'security_fact';
      factId: SecurityFactId;
      source: SecurityFactSource;
      evidenceRef: string;
      subjectRefs: string[];
      subjectSha256: string;
    }
  | { kind: 'file_edit'; path: string; diff: string }
  | { kind: 'command_run'; cmd: string; exitCode: number; stdout: string; stderr: string }
  | { kind: 'message'; role: 'agent'; text: string }
  | { kind: 'phase_hint'; phase: BehaviorPhase }
  | { kind: 'dependency_added'; manifest: string; packages: string[] }
  | { kind: 'service_started'; bindAddress: string; port: number }
  | { kind: 'loop_boundary'; retryCount: number; lastFailure?: string };

type Intervention =
  | { kind: 'inject_context'; text: string; scope: 'system' | 'message' | 'file' }
  | { kind: 'tool_decision'; decision: 'allow' | 'deny' | 'require_evidence'; reason: string }
  | { kind: 'loop_directive'; directive: LoopDirective }
  | { kind: 'demand_evidence'; policyId: string; expected: string[] }
  | { kind: 'terminal_status'; status: TerminalStatus; rationale: string };

type LoopDirective =
  | { kind: 'reinforce'; policyId: string; text: string }
  | { kind: 'arm_probe'; probeId: string }
  | { kind: 'harden'; policyId: string; to: 'required' | 'fail_closed' }
  | { kind: 'rollback'; reason: string }
  | { kind: 'stop'; status: TerminalStatus };
```

### 7.2 Adapter

```ts
interface AgentAdapter {
  id: string;
  capabilities: { inject: boolean; interceptTools: boolean; driveSteps: boolean };
  onEvent(cb: (e: ObservationEvent) => void): void;
  apply(i: Intervention): Promise<void>;
}
```

### 7.3 Policy, Surface, Pack

```ts
type Severity = 'advisory' | 'required' | 'fail_closed';

interface Policy {
  id: string;
  packId: string;
  sourcePrinciples: { source: string; ref?: string; text: string }[];
  activation: Matcher; // predicate over TaskSurface + trajectory
  severity: Severity;
  requiredControls: string[];
  forbiddenWorkarounds: string[];
  evidenceRequirements: string[];
  prompt?: (ctx: RenderCtx) => PromptFragment; // Layer A
  monitors?: Monitor[]; // Layer B
  invariants?: Invariant[]; // Layer C
}

type Monitor = (e: ObservationEvent, s: PolicyState) => Signal | null;
type Signal = { level: 'safe' | 'suspicious' | 'violation'; evidence: EvidenceItem };
interface Invariant {
  id: string;
  check: (before: RepoState, after: RepoState) => boolean;
  message: string;
}

interface TaskSurface {
  taskFamily: string;
  languageFrameworks: string[];
  inputChannels: string[];
  sinks: string[];
  assets: string[];
  trustBoundaries: string[];
  actions: string[];
  runtimeExposure: string[];
  missingTrustInputs: string[];
  likelyCwes: string[];
  confidence: Record<string, number>;
  surfaceStatus: 'sufficient' | 'ambiguous' | 'insufficient';
  evidence: {
    field: string;
    value: string;
    source: 'task_prompt' | 'repo_hint' | 'repo_scan' | 'semantic_proposal';
    evidence: string;
  }[];
  unresolved: {
    field: string;
    question: string;
    reason: string;
  }[];
}

interface PolicyPack {
  id: string;
  version: string;
  trustTier: 'core' | 'trusted' | 'experimental' | 'advisory';
  policies: Policy[];
  matchers: Matcher[]; // surface → candidate policies
  probes?: ProbeTemplate[];
}
```

### 7.4 Selection & state

```ts
interface SelectedPolicySet {
  selectionMode: 'explicit' | 'hybrid' | 'fallback';
  surfaceStatus: TaskSurface['surfaceStatus'];
  selected: {
    policyId: string;
    because: string[];
    matchedSurfaces: string[];
    severity: Severity;
    disposition: 'mandatory' | 'ranked' | 'fallback';
  }[];
  rejectedHighScore: { policyId: string; reason: string }[]; // logged for later learning
  coverageGaps: string[];
  reassessmentTriggers: string[];
  budget: { maxPolicies: number; tokenBudget: number };
}

interface PolicyActivationDecision {
  policyId: string;
  obligationId: string;
  controlKind: 'required_security' | 'contract_narrowing_hardening' | 'advisory';
  compatibility: 'compatible' | 'conflicting' | 'input_required' | 'advisory';
  enforcement: 'required' | 'fail_closed' | 'advisory' | 'inactive';
  evidenceRefs: string[];
  activationFactIds: SecurityFactId[];
  rationale: string;
}

interface CompatibilityEnvelope {
  taskContractSha256: string;
  acceptedBehavior: string[];
  prohibitedContractChanges: string[];
}

interface PolicyActivationPlan {
  taskContractSha256: string;
  selectionSha256: string;
  decisions: PolicyActivationDecision[];
  unresolvedInputs: string[];
}

interface PolicyDelta {
  trigger: string;
  newSurface?: string;
  addedPolicies: string[];
  raisedSeverity?: { policyId: string; to: Severity }[];
  activationDecisions: PolicyActivationDecision[];
  rationale: string;
}

interface PolicyState {
  surface: TaskSurface;
  activation: PolicyActivationPlan;
  active: Policy[]; // monotonic within a run
  bindings: PhaseBinding[];
  ledger: EvidenceLedger;
}
```

### 7.5 Evidence & terminal status

```ts
interface EvidenceItem {
  source: 'diff' | 'command' | 'test' | 'probe' | 'static_scan' | 'model' | 'human';
  reference: string;
  summary: string;
  harnessObserved: boolean;
}
interface EvidenceLedgerEntry {
  policyId: string;
  requiredControl: string;
  expected: string[];
  observed: EvidenceItem[];
  status: 'pass' | 'fail' | 'unknown' | 'blocked' | 'not_applicable';
  rationale: string;
}
type EvidenceLedger = EvidenceLedgerEntry[];

interface OracleOutcome {
  oracleId: string;
  kind: 'functional' | 'required_security' | 'defense_in_depth';
  status: 'pass' | 'fail' | 'inconclusive' | 'harness_error';
  evidence: EvidenceItem[];
  candidateFailure?: string;
  oracleFailure?: string;
  attempt: 1 | 2;
}

type TerminalStatus =
  | 'SUCCESS_VERIFIED'
  | 'SUCCESS_WITH_RESIDUAL_RISK'
  | 'BLOCKED_INPUT_REQUIRED'
  | 'BLOCKED_POLICY_CONFLICT'
  | 'FAILED_FUNCTIONAL_VALIDATION'
  | 'FAILED_POLICY_VALIDATION'
  | 'FAILED_ORACLE_INCONCLUSIVE'
  | 'FAILED_HARNESS_ERROR';
```

### 7.6 Controller

```ts
interface PolicyController {
  state: PolicyState;
  select(surface: TaskSurface): SelectedPolicySet;
  activate(selection: SelectedPolicySet, envelope: CompatibilityEnvelope): PolicyState;
  ingest(e: ObservationEvent): Intervention[]; // Layer B + reassess + Layer C
  reassess(e: ObservationEvent): PolicyDelta | null; // dynamic adoption
  gate(): { status: TerminalStatus; rationale: string }; // deterministic
}
```

---

## 8. Runtime Behavior

### 8.1 End-to-end sequence (driver/broker adapter)

```text
1. Intake        controller receives task + repo; adapter attaches to agent.
2. Surface       LLM structured-output + deterministic repo scan → TaskSurface
                 with status, evidence, and unresolved questions.
3. Select        rules (hard-include) + retrieval + graph → specific policies;
                 if evidence/matches are insufficient, add the compact generic
                 security floor → SelectedPolicySet.
4. Adjudicate    classify each obligation against the frozen public task
                 contract → PolicyActivationPlan → PolicyState v0.
5. Distribute    materialize phase bindings for each activated obligation.
6. Prime (A)     inject orientation/inspection guidance via adapter.
7. Loop:
   a. agent emits ObservationEvent(s).
   b. controller.ingest():
        • Layer B monitors run → Signals + evidence to ledger.
        • reassess() → PolicyDelta? → tighten state; arm monitors/probes;
          add prompt fragments (all three layers updated by ONE delta).
        • tool_call + interceptTools → deterministic tool_decision.
   c. at loop_boundary → Layer C predict-then-condition + invariant check.
8. Validate      run functional and required policy oracles (Layer B active tier).
9. Classify      admit pass/fail; retry an idempotent inconclusive oracle once;
                 never send harness_error to the agent for repair.
10. Initial gate reads activation + ledger → terminal or repairable candidate failure.
11. Repair       at most once, and only for that admissible candidate failure.
12. Revalidate   rerun functional and security oracles; preserve passing invariants.
13. Final gate   select the terminal attempt deterministically.
14. Report       final report generated FROM the ledger, not from model prose.
```

### 8.2 Degraded sequence (log/diff adapter, `inject:false, interceptTools:false`)

```text
Surface → Select → Adjudicate → (no live injection: guidance front-loaded once
if any inject path exists, else none) → agent runs freely → controller consumes
the final diff + logs as ObservationEvents → Layer B monitors + active probes
run post-hoc → Gate → Report. Enforcement = detect + verify + re-prompt loop;
run metadata records "enforcement: detective-only".
```

Same policies, same ledger, weaker enforcement — measurable, not silent (P10).

### 8.3 Dynamic adoption example

```text
event: dependency_added(manifest=package.json, packages=[jsonwebtoken])
reassess():
  surface += action:dependency_install, asset:auth_state (jwt)
  delta: add supply-chain-pinning policy + auth-token policy
         → Layer A: inject "pin & verify provenance; validate token handling"
         → Layer B: arm lockfile-diff monitor + secret-in-log monitor
         → Layer C: add invariant "no unpinned dependency in manifest"
  monotonic: state only grows; severity may rise, never fall.
```

### 8.4 Gate logic (deterministic)

```text
if activation has unresolved fail_closed input  → BLOCKED_INPUT_REQUIRED
elif activation has required conflict           → BLOCKED_POLICY_CONFLICT
elif any required oracle == harness_error        → FAILED_HARNESS_ERROR
elif any required oracle == inconclusive         → FAILED_ORACLE_INCONCLUSIVE
elif any fail_closed policy status == fail       → FAILED_POLICY_VALIDATION
elif any fail_closed policy status == unknown   → BLOCKED_INPUT_REQUIRED | FAILED_POLICY_VALIDATION
elif functional checks failed                   → FAILED_FUNCTIONAL_VALIDATION
elif any required policy status == fail         → FAILED_POLICY_VALIDATION
elif required evidence missing                  → BLOCKED_INPUT_REQUIRED | FAILED_POLICY_VALIDATION
elif known accepted residual risk               → SUCCESS_WITH_RESIDUAL_RISK
else                                            → SUCCESS_VERIFIED
```

Functional success is an _input_ to the gate, never an override of a security failure (P6).

---

## 9. Decision Records (ADRs)

Each record: **Context → Options → Decision → Rationale → Consequences → Revisit if**.

### ADR-1 — Separate policy (data) from enforcement channels (mechanism)

- **Context.** A policy must influence prompting, runtime checking, and repair guardrails. These could be one coupled engine or a declaration + handlers.
- **Options.** (a) Monolithic policy engine with hardcoded behavior; (b) policy as data with three per-layer handlers.
- **Decision.** (b).
- **Rationale.** Dynamic adoption, plug-in extensibility, and independent per-layer testing all follow from it: one `PolicyDelta` updates prompt + monitors + invariants atomically. It also keeps the core small (P2, G1, G6).
- **Consequences.** Policies are more verbose to author; a pack authoring guide and templates are needed. Layers must tolerate policies that omit their handler.
- **Revisit if.** Handlers turn out to need cross-layer shared state beyond `PolicyState` (would argue for a richer policy runtime).

### ADR-2 — The harness is an event/intervention bus, not a workflow DAG

- **Context.** The obvious substrate (Archon) is a workflow engine that drives the agent node-by-node.
- **Options.** (a) DAG-only harness; (b) event/intervention bus with adapters, where a DAG is one adapter.
- **Decision.** (b).
- **Rationale.** A DAG can only wrap agents you fully drive and confounds "policy effect" with "forced workflow structure." The bus subsumes the DAG and also works when all we can do is tail a log — the only way to be genuinely agent-agnostic (G2, P3).
- **Consequences.** More upfront abstraction; adapters must normalize heterogeneous agent outputs into `ObservationEvent`s.
- **Revisit if.** Every target agent turns out to support full driving (then the bus is over-general — unlikely).

### ADR-3 — Capability-based graceful degradation

- **Context.** Agents expose very different control surfaces.
- **Options.** (a) Require a minimum capability (e.g., tool interception); (b) degrade per declared capability.
- **Decision.** (b).
- **Rationale.** Requiring a minimum would exclude most real agents and make the method non-general. Degradation keeps the _correctness_ of what is enforced
  while varying _strength_ (P10, G2). Degradation is also a clean experimental knob later.
- **Consequences.** Run metadata must record enforcement level so results are comparable and degradation is never silent.
- **Revisit if.** Detective-only enforcement proves too weak to matter — then we gate the method on at least a context adapter.

### ADR-4 — Three enforcement layers (proactive / detective / corrective)

- **Context.** Security fails in three distinct ways: principle never stated, bad behavior never caught, control undone during repair.
- **Options.** (a) prompt-only; (b) scanner-only; (c) all three layers.
- **Decision.** (c).
- **Rationale.** Each failure mode needs a different mechanism; prompt-only is advisory, scanner-only is post-hoc. Layer C (loop conditioning) is the novel, highest-value piece and is absent from existing tools (G1).
- **Consequences.** More components; the layers must be independently testable (they are, as subscribers to `PolicyState`).
- **Revisit if.** Ablations show a layer contributes no lift on any task family.

### ADR-5 — Loop conditioning = predict-then-condition + monotonic hardening

- **Context.** The most dangerous moments are adaptations under failure pressure.
- **Options.** (a) post-hoc detection only; (b) intervene before the retry and forbid relaxation.
- **Decision.** (b).
- **Rationale.** Detecting a weakened control after the fact still let it happen; conditioning the _next_ iteration prevents it, and monotonicity stops the model from relaxing an inconvenient policy (P5).
- **Consequences.** Requires a loop-boundary signal (native for driver/broker adapters; approximated for others). Prediction starts rule-based.
- **Revisit if.** Rule-based prediction has too many false positives; upgrade to a learned predictor trained on logged trajectories.

### ADR-6 — Dynamic selection that touches all three layers

- **Context.** Initial selection cannot foresee mid-run risks (new deps, sinks, services).
- **Options.** (a) static one-shot selection; (b) event-driven re-selection.
- **Decision.** (b), with monotonic tightening.
- **Rationale.** Most vulnerabilities are introduced by something that appears mid-run. Because a policy carries all three handlers, one delta updates all layers coherently (G5, ADR-1).
- **Consequences.** Risk of overload; mitigated by budget + redundancy suppression + phase-local injection (ADR-8).
- **Revisit if.** Overload persists despite budgeting — cap deltas per run.

### ADR-7 — "LLM proposes, rules dispose, learning ranks"

- **Context.** Selection and enforcement have opposite requirements (recall vs auditability).
- **Options.** (a) LLM decides everything; (b) rules decide everything; (c) split by function.
- **Decision.** (c): LLM for perception/proposal + semantic evidence; deterministic rules for safety triggers and _all_ enforcement; learned ranker later for optimization; no RL as the core mechanism.
- **Rationale.** A probabilistic gate is not a gate; enforcement must be reproducible and injection-resistant (P1, P8, G3). LLM recall is valuable for interpreting messy tasks but must have no authority. RL is premature: sparse, noisy rewards and unacceptable unsafe exploration; a black box is not a defensible claim.
- **Consequences.** Two-track engineering (deterministic core + LLM advisors); the critic LLM's output must be schema-checked and rule-gated.
- **Revisit if.** We accumulate enough labeled outcomes to justify a _constrained_ ranker (offline-evaluated) — and even then only over a rules-vetted candidate set.

### ADR-8 — Compact selection + phase-local injection (state ≠ prompt pressure)

- **Context.** Full-corpus injection is expensive and dilutes attention; dynamic adoption can pile on obligations.
- **Options.** (a) inject everything active every turn; (b) keep policies active in state but render only phase-relevant slices under a budget.
- **Decision.** (b). Target 3–8 active policies for ordinary tasks.
- **Rationale.** Enforcement breadth (monitors/invariants armed) should not equal prompt cost. Compact, targeted prompts are more likely followed (P7, G4).
- **Consequences.** Need a renderer that maps (policy, phase) → fragment and a budget policy.
- **Revisit if.** Larger models make injection cost negligible — could relax the budget.

### ADR-9 — Evidence ledger; "no evidence, no claim"

- **Context.** Agents overclaim; provider errors can masquerade as success.
- **Options.** (a) trust the model's final report; (b) derive claims only from a harness-owned ledger.
- **Decision.** (b), append-only, with strict acceptance rules.
- **Rationale.** Auditability and reproducibility (G3, P4). Also the backbone of any later measurement.
- **Consequences.** Every policy needs evidence requirements; validators must emit structured, harness-observed results.
- **Revisit if.** Never (this is foundational).

### ADR-10 — Plug-in packs over a fixed surface vocabulary

- **Context.** New task families (incl. non-code) must be addable without core edits.
- **Options.** (a) hardcode per-domain logic; (b) packs over a fixed vocabulary.
- **Decision.** (b).
- **Rationale.** Extensibility is the difference between a demo and a platform; a fixed vocabulary is the stable seam that lets a data-pipeline or ML-training pack reuse the same machinery (G6, P9).
- **Consequences.** The vocabulary must be carefully designed and versioned; expanding it is a core change (rare, deliberate).
- **Revisit if.** A domain cannot express its surface in the vocabulary — extend the vocabulary (a governed core change), don't fork.

### ADR-11 — Pack trust tiers

- **Context.** Third-party/experimental packs should extend without weakening core
  guarantees.
- **Options.** (a) all packs equal; (b) tiers (core/trusted/experimental/advisory).
- **Decision.** (b).
- **Rationale.** An experimental pack may _recommend_ but must not _hard-gate_; only core/trusted packs can set `fail_closed`. Prevents extensibility from becoming a bypass (P1).
- **Consequences.** The controller enforces tier→max-severity caps.
- **Revisit if.** Governance shows tiers are too coarse — add per-capability grants.

### ADR-12 — Fail-safe terminal states; blocking can be success

- **Context.** For high-risk underspecified tasks (e.g., persistent remote access with missing trust inputs), "make it run" is the _insecure_ outcome.
- **Options.** (a) binary pass/fail; (b) a status set including `BLOCKED_INPUT_REQUIRED`.
- **Decision.** (b).
- **Rationale.** Unsafe liveness is worse than safe incompletion; the harness must be able to say "correctly refused" (P6).
- **Consequences.** Evaluation must treat warranted blocking as success and adjudicate whether a block was justified (avoid gaming by refusal).
- **Revisit if.** Blocking is abused as task-avoidance — add a block-justification check (planned in evaluation).

### ADR-13 — Phases are soft signals, not rigid gates

- **Context.** Real agents interleave inspection/writing/repair; clean phase sequencing is unrealistic outside a driver adapter.
- **Options.** (a) enforce a strict phase DAG; (b) treat phase as advisory routing for prompt rendering and probe timing.
- **Decision.** (b).
- **Rationale.** Rigid phases would only work for driver adapters and would confound structure with policy (see ADR-2). Soft phases keep Layer A useful without over-constraining the agent (G2).
- **Consequences.** Phase detection is best-effort; nothing critical depends on perfect phase labels (enforcement lives in B/C, which are event-driven).
- **Revisit if.** Phase misclassification measurably degrades Layer A — invest in a better classifier, not in hard gating.

### ADR-14 — Insufficient surface activates a generic security floor

- **Context.** An extractor can return a structurally valid but empty or wrong
  surface. Treating no match as no risk creates a silent false-negative path.
- **Options.** (a) allow an empty selection; (b) dump a broad security
  checklist; (c) activate a compact, auditable core fallback pack and continue
  reassessment.
- **Decision.** (c). Use
  `core:security-surface-discovery`, `core:fail-safe-implementation`, and
  `core:evidence-based-validation`; record selection mode, uncertainty,
  coverage gaps, and reassessment triggers.
- **Rationale.** Missing evidence means unknown, not safe. Three behavioral
  policies provide a useful floor without pretending to cover an unidentified
  vulnerability or recreating full-corpus prompt overload.
- **Consequences.** Every valid task has a non-empty decision. Generic policies
  remain active monotonically but may be suppressed from phase rendering when
  specific policies supersede their text. They never satisfy a missing known
  mandatory control.
- **Revisit if.** Cross-task experiments show that the floor adds cost or
  overconstraint without improving discovery, validation, or evidence quality.

### ADR-15 — Separate agent, workspace, and evaluator adapters

- **Context.** Cross-task execution must control an agent, prepare heterogeneous
  benchmark workspaces, and execute trusted verdict logic. A single benchmark
  adapter would combine three trust domains and make evaluator authority depend
  on agent integration details.
- **Options.** (a) one benchmark/agent adapter; (b) separate `AgentAdapter`,
  `TaskWorkspaceAdapter`, and `EvaluatorAdapter` contracts bound by a frozen
  task manifest.
- **Decision.** (b). `AgentAdapter` translates events/interventions;
  `TaskWorkspaceAdapter` verifies and prepares the subject; `EvaluatorAdapter`
  executes functional and security oracles outside agent control.
- **Rationale.** The split preserves SRP and keeps source acquisition, agent
  capabilities, and decision authority independently testable. It also permits
  one SWE-bench workspace adapter to serve different agents and one agent
  adapter to serve different task sources.
- **Consequences.** Every task has an explicit readiness state. `selected`
  freezes source identity and oracle requirements; `runnable` additionally
  requires source/workspace receipts, frozen functional and security oracles,
  isolation, and resource boundaries. Gold patches, reference completions,
  exact gold file scope, and hidden probes stay outside the agent workspace.
- **Revisit if.** Two concrete callers demonstrate that workspace and evaluator
  lifecycle cannot be separated without duplicated isolation state; merge only
  their shared lifecycle object, not their authority.

### ADR-16 — Adjudicate policy obligations before activation

- **Context.** BaxBench showed that a relevant security policy can still narrow
  the task contract: minimum-password enforcement broke valid functional
  fixtures even though password protection was relevant.
- **Decision.** Selection produces candidates; a separate deterministic stage
  classifies each obligation against a frozen compatibility envelope. Controls
  that narrow accepted inputs or public APIs default to advisory unless the
  task contract explicitly authorizes them.
- **Consequences.** Required security controls remain enforceable, but generic
  hardening cannot silently redefine correctness. Genuine contradictions stop
  as `BLOCKED_POLICY_CONFLICT`; the agent cannot resolve them by weakening
  either side.
- **Revisit if.** A task family cannot express a useful compatibility envelope
  without leaking hidden test or exploit material.

### ADR-17 — Repair candidate failures, never oracle failures

- **Context.** BaxBench probes crashed on response-schema, database-path, and
  temporary-file assumptions even when the candidate rejected the attack.
- **Decision.** Evaluators return typed `pass | fail | inconclusive |
harness_error` outcomes. Only `fail` can trigger the one agent repair;
  idempotent inconclusive oracles may be retried once by the harness.
- **Consequences.** Evaluator defects cannot be misreported as security wins or
  consume model budget. Persistent inconclusive/error states fail closed and
  remain distinguishable in analysis.
- **Revisit if.** Repeated experiments show that the four states cannot separate
  candidate, adapter, and infrastructure failures reliably.

### ADR-18 — Typed facts may activate only pre-adjudicated obligations

- **Context.** Runtime observations must change enforcement state without
  allowing agent-controlled logs, paths, or model prose to invent policies or
  bypass the compatibility boundary.
- **Options.** (a) let each observation propose arbitrary policy objects; (b)
  rerun unconstrained selection on raw events; (c) extract a small typed fact and
  match it only against trigger IDs compiled into compatible dormant
  obligations.
- **Decision.** (c). Deterministic monitors emit content-hashed facts over stable
  metadata. A matching fact changes a dormant obligation to `active`; the next
  loop boundary requests its required probe. Probe failure may consume the one
  candidate repair. Facts never satisfy probe evidence by themselves.
- **Rationale.** This creates a replayable trajectory-control loop while keeping
  policy authority in the frozen control plane and evidence authority in trusted
  probes.
- **Consequences.** The first vocabulary is deliberately small: archive changes,
  dependency manifests, process requests, repair-time modifications, and service
  configuration. New facts require deterministic extraction tests and a concrete
  policy/probe caller. Live selection of entirely new candidates, severity
  hardening, phase-local reinjection, and learned prediction remain separate
  milestones.
- **Revisit if.** Held-out tasks show that stable metadata cannot provide useful
  trigger precision; add AST/diff monitors before considering probabilistic
  activation.

### ADR-19 — Behavior taxonomy is observational before it is authoritative

- **Context.** Historical trajectories provide useful process labels, but a
  behavior classifier can be ambiguous, agent-controlled, or confounded with
  harness-owned validation. Treating those labels as security evidence would
  make the gate depend on an unvalidated measurement instrument.
- **Options.** (a) use labels directly for policy activation and gate decisions;
  (b) omit taxonomy from the prototype; (c) record deterministic primary labels
  and permit only soft prompt routing until classifier validity is established.
- **Decision.** (c). The prototype freezes the full primary vocabulary, labels
  only unambiguous normalized agent events, records rule and event provenance,
  excludes harness probes, and uses `adaptation` only to select bounded repair
  guidance. Unsupported events remain unclassified.
- **Rationale.** This makes trajectory structure measurable without introducing
  a new source of security authority. Typed security facts and trusted probes
  retain their separate activation and evidence roles.
- **Consequences.** Behavior distributions can support coverage analysis,
  ablations, and later policy-refinement research. They cannot change severity,
  activate obligations, satisfy evidence, consume repair, or alter terminal
  status. This restriction applies to generic taxonomy labels, not to the
  separately specified deterministic security predicates governed by ADR-18.
  Secondary labels and probabilistic classification remain deferred.
- **Revisit if.** A labeled held-out corpus demonstrates acceptable inter-rater
  agreement, coverage, and classification precision for a concrete control
  decision.

### ADR-20 — Represent the candidate according to the task form

- **Context.** The first active prototype generated a complete `app.py`, but
  repository code completion contributes a replacement block inside a pinned
  tree. Treating both as an unconstrained whole-file candidate loses source
  identity, protected context, region scope, and repository contract evidence.
- **Options.** (a) force every task into a whole-file artifact; (b) treat the
  complete mutable workspace as the candidate; (c) define a task-form-specific
  candidate envelope under one generic candidate contract.
- **Decision.** (c). A standalone-generation candidate binds complete artifact
  bytes. A repository-completion candidate binds base-tree identity, target
  file, frozen prefix/suffix or parser-derived region identity, replacement,
  normalized patch, protected-tree digest, and cumulative changed paths.
  Evaluator adapters may derive whole files or workspaces from that envelope,
  but the derived staging format is not the controlled candidate identity.
- **Rationale.** Security policy and mutation authority apply to the agent's
  actual contribution. Task-form-specific envelopes preserve this boundary
  without moving benchmark logic into the generic controller.
- **Consequences.** Workspace adapters must expose a redacted generation view
  and a separately trusted evaluator view. Repository-completion adapters must
  sanitize source history, prove region integrity, and distinguish runtime
  artifacts from candidate source. Hidden gold scope still cannot be disclosed;
  the allowed region must come from the public task definition.

### ADR-21 — Trajectory control is core; outcome correctness remains independent

- **Context.** The original PGACS hypothesis is that observable insecure agent
  behavior can contribute to insecure output and can be conditioned during
  generation. Prompt guidance plus a final gate cannot test that mechanism, but
  treating trajectory labels as correctness evidence would make the evaluation
  circular.
- **Decision.** Every full PGACS specialization defines a normalized agent-event
  stream, a small frozen registry of deterministic security predicates, and a
  proportional intervention ladder. Repository facts select obligations;
  trajectory predicates may add requirements or constrain actions; independent
  functional and security probes determine outcomes. Harness-owned actions are
  excluded from agent-behavior statistics.
- **Rationale.** This preserves the behavior-control contribution while keeping
  the final claim grounded in an oracle independent of the monitored process.
- **Consequences.** Artifact-only PGACS remains a useful ablation, not the full
  mechanism. Experiments must compare guidance, artifact enforcement, and online
  trajectory control separately and report signal/intervention validity as well
  as final outcomes.
- **Revisit if.** A task form cannot expose useful agent events. In that case the
  adapter must declare degraded enforcement and the run cannot support a claim
  about trajectory control.
- **Revisit if.** A benchmark requires legitimate multi-file modification. Add
  a frozen patch-set envelope with explicit public path/region authority rather
  than broadening repository-completion scope implicitly.

---

<!--
## 10. Failure Modes & Mitigations

| Failure mode | Mitigation in the design |
| --- | --- |
| Gains are just "run a scanner" | Dumb-harness baseline (run all validators, no selection) as a comparison; the method must beat it (§2.4). |
| Over-blocking tanks functional correctness | Severity levels; joint functional-AND-security gate; block-justification adjudication (ADR-12). |
| Structure, not policy, drives results | Bus runs the *same* policies with/without forced structure (ADR-2/13). |
| Prompt injection subverts enforcement | Enforcement authority is deterministic; LLMs advise only; repo content is context, not policy (ADR-7, P1). |
| Dynamic adoption overload | Budget + redundancy suppression + phase-local injection (ADR-6/8). |
| Provider error read as success | Ledger acceptance rules map errors to unknown/blocked/fail (ADR-9). |
| Loop-boundary signal unavailable | Approximate boundaries from event patterns; degrade Layer C to invariant-check-on-diff (P10). |
| Pack weakens a core gate | Trust-tier severity caps (ADR-11). |
| Scope creep rebuilds the cathedral | Minimal core first; additions at stable seams (G7, §13). |

---

## 11. Threat Model: Securing the Harness Itself

The harness is an attack surface. Assumptions:

- **Repository/issue/dependency content is untrusted input**, not policy
  authority. Only `core`/`trusted` packs and human operators set enforcement.
- **The LLM may be manipulated** (prompt injection). Therefore no LLM output can
  relax a gate, mutate `PolicyState` downward, or mark a policy `pass`. LLM
  outputs enter only as *proposals* (schema-checked) or *evidence* (rule-gated).
- **Adapters run with the agent's privileges**; the broker's deny/allow decisions
  are deterministic and logged as interventions.
- **Benchmark control material is not agent context.** Source locks and task
  manifests are verified before execution; gold patches, reference
  completions, vulnerability labels, and hidden probes remain in the separate
  control plane.
- **The ledger is append-only**; no run may rewrite prior evidence.
- **Probes must not create the risk they check** (e.g., for a persistent-tunnel
  task, prefer negative preflight checks over live activation).

---

## 12. Extensibility Guide

**Add an adapter** (new agent): implement `AgentAdapter` — map the agent's
output to `ObservationEvent`s (`onEvent`) and apply `Intervention`s (`apply`);
declare honest `capabilities`. No controller/pack changes.

**Add a task source** (new benchmark/custom fixture): add source-pinned
`FrozenTaskManifest` entries and implement `TaskWorkspaceAdapter` for source
verification, preparation, mutation boundaries, and artifact collection. Do
not expose gold-patch scope through those boundaries.

For repository code completion, the public task itself defines the masked
region. Materialize a history-free repository, expose a structurally redacted
generation view, bind protected context and region identity, and model the
candidate as a replacement plus normalized patch. Repository context may feed
surface facts but remains untrusted data, not policy authority. The concrete
SecRepoBench specialization is documented in
`principle-guided-agent-research/current-secrepobench/technical-design.md`.

**Add an evaluator**: implement `EvaluatorAdapter`; keep functional and security
oracles distinct, run them outside agent control, and attest isolation plus
control-plane hashes. A required security oracle must reject a known-insecure
candidate before the task becomes `runnable`.

**Add a pack** (new task family): author `Policy` objects (declaration + any of
the three handlers), `matchers` (surface → candidates), and optional
`probes`; set a `trustTier`. Speak only the surface vocabulary. No core changes.

**Add a validator/probe**: register a probe template in a pack; Layer B invokes
it when armed by Layer C. Deterministic validators preferred; a critic-LLM check
is allowed but its output is evidence, not a verdict.

**Extend the surface vocabulary** (rare): a governed core change with a version
bump; all packs remain compatible because they reference vocabulary terms by
name.

---

## 13. Deliberately Out of Scope (YAGNI)

Explicitly *not* in the first system, to keep the core shippable:

- Learned/RL selection (ADR-7 defers it).
- The full 25-field policy registry schema from PGAH (start with §7.3's lean
  shape).
- Plugin marketplace / remote pack distribution.
- Cross-run learning and outcome-history features.
- A bespoke UI (use existing Archon surfaces / logs initially).
- More than one dynamic trigger class beyond a small starter set.

Each is an addition at a stable seam once the core is validated.

---

## 14. Build Plan & Milestones

**Minimal core (weeks):**

1. Bus + `EvidenceLedger` + `PolicyController` (pure reducer).
2. One agent adapter on Archon (context + hook/broker → inject +
   interceptTools).
3. Frozen task manifests plus minimal workspace/evaluator adapters, using the
   existing ZIP task first and then one caller from each active development
   source: BaxBench, SWE-bench Verified, and SetupBench.
4. Compatibility envelope plus per-obligation activation plan.
5. Typed oracle outcomes and candidate-only bounded repair routing.
6. One pack, ~6 policies (path traversal, input validation, safe parse, error
   disclosure, command injection, dependency pinning) — each with a prompt
   fragment + ≥1 passive monitor + ≥1 invariant.
7. Deterministic controller: typed trajectory facts, pre-adjudicated dormant
   obligations, probe scheduling, and monotonic activation. Severity hardening
   follows only after this loop is evaluated.
8. One active probe + one critic-LLM check (prove the expensive path).

**Then widen:** promote the source-pinned nine-task development cohort in
`15-multibench-prototype`, run B0/C0/C1/C2, then add more agent adapters (Codex
driver, raw-Claude-Code hook, log/diff), more packs, and the learned ranker.

**Milestones (gate on these):**

- **M0** — ZIP plus one BaxBench, one SWE-bench Verified, and one SetupBench task
  execute through the same frozen-manifest, workspace-adapter, and
  evaluator-adapter contracts without changing native oracle semantics.
- **M1** — On the nine-task development cohort, the harness fills an evidence
  ledger and blocks at least one real unsafe shortcut a baseline agent takes.
- **M2** — The same policies run on a second agent via a different adapter with
  no policy changes (agent-agnosticism).
- **M3** — A new task family works by writing a pack only (extensibility).

---

## 15. Open Questions

1. Default top-k policy budget per task family, and how aggressively to raise it
   on `fail_closed` surfaces.
2. Loop-boundary detection heuristics for adapters without a native signal.
3. How much semantic checking to delegate to a critic LLM vs deterministic AST
   analysis, per policy family.
4. Minimum human-labeled set needed before a learned ranker beats the transparent
   selector.
5. Vocabulary coverage: which surface terms are missing for non-code-generation
   domains.
6. How to represent and adjudicate "warranted block" so fail-safe isn't gamed.
7. How to measure benchmark contamination and solution-scope leakage without
   exposing hidden control material to the agent.
8. What is the minimum compatibility-envelope vocabulary that prevents
   overconstraint without encoding hidden functional fixtures.

--- -->

<!-- ## 16. Glossary

See §4 for the core terms. Additional:

- **Reducer** — the controller's core function `(state, event) → (state',
  interventions)`; pure, replayable.
- **Passive monitor** — always-on, cheap, deterministic per-event classifier.
- **Active probe** — on-demand, expensive check that exercises the artifact.
- **Loop boundary** — a failure→retry (or step) transition where Layer C runs.
- **Monotonic hardening** — within a run, `PolicyState` only tightens.
- **Dumb-harness baseline** — run all validators with no selection/binding; the
  control the method must beat.
``` -->
